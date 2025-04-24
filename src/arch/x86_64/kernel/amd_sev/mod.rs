
macro_rules! sev_exit {
    ($code:expr) => {{
        log::error!();
        crate::arch::x86_64::kernel::amd_sev::ghcb_msr_protocol::ghcb_request_exit($code)
    }};
    ($code:expr, $($arg:tt)*) => {{
        log::error!($($arg)+);
        crate::arch::x86_64::kernel::amd_sev::ghcb_msr_protocol::ghcb_request_exit($code)
    }};
}

pub mod instruction_parser;
pub mod handler_ioio;
mod opcodes;
pub(crate) mod handler;
mod exitcodes;
pub(crate) mod paravirt_uart;
pub mod ioio_explicit;
mod handler_cpuid;
mod handler_msr;
mod handler_mmio;
mod handler_vmmcall;
pub mod handler_ap;
mod ghcb_msr_protocol;
mod ghcb_protocol;

use core::arch::asm;
use align_address::Align;
use hermit_sync::{InterruptTicketMutex, Lazy};
use x86_64::instructions::tlb;
pub use handler::vmm_interrupt_exception;

use x86_64::structures::paging::{Mapper, Page, PageSize, Size4KiB, Translate};
use ghcb_msr_protocol::{GhcbMsrRequest, GhcbMsrResponse, GHCB_MSR};
use ghcb_protocol::Ghcb;
use crate::arch::{BasePageSize};
use crate::arch::mm::paging::{HugePageSize, PageTableEntryFlags, PageTableEntryFlagsExt};
use crate::arch;

/* 
#define GHCB_SHARED_BUF_SIZE	2032

struct ghcb {
	struct ghcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct ghcb_save_area)];

	u8 shared_buffer[GHCB_SHARED_BUF_SIZE];

	u8 reserved_0xff0[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
} __packed;
 */

pub use ghcb_msr_protocol::ghcb_request_exit;
use x86_64::structures::amd_sev::sev_state;
use x86_64::VirtAddr;
use memory_addresses::PhysAddr;
use crate::arch::kernel::amd_sev::handler_vmmcall::Hypercalls;
use crate::arch::mm::{paging, virtualmem};
use crate::env::kernel::amd_sev::handler::error_exit_codes;
use crate::env::kernel::amd_sev::handler_vmmcall::HYPERCALLS;

const MAX_GHCB_PROTOCOL_VERSION: u16 = 1;

pub fn ghcb_negotiate_protocol() -> u16 {
    let data = GHCB_MSR.read_state();
    info!("Read GHCB MSR : {data:?}");
;
    let GhcbMsrResponse::SevInformation { max_proto, min_proto, c_bit_pos } =
        GHCB_MSR.send_request_restore(GhcbMsrRequest::SevRequest) else {
        sev_exit!(error_exit_codes::EXIT_VC_INVALID_EXIT_CODE, "Invalid GHCB MSR response"); };

    info!("Got GHCB protocol versions: max={max_proto}, min={min_proto} - c_bit_pos={c_bit_pos}");

    if max_proto < MAX_GHCB_PROTOCOL_VERSION || min_proto > MAX_GHCB_PROTOCOL_VERSION {
        sev_exit!(error_exit_codes::EXIT_OTHER, "GHCB version negotiation failed: wrong protocol version");
    }

    if MAX_GHCB_PROTOCOL_VERSION > max_proto {
        max_proto
    } else {
        MAX_GHCB_PROTOCOL_VERSION
    }
}


pub fn print_current_ghcb() {
    with_ghcb(|ghcb| {
        info!("Current GHCB: {ghcb:?}");
        info!("GHCB size: {}", size_of::<Ghcb>());
    });
}

pub fn with_ghcb<F, R>(f: F) -> R
where F: FnOnce(&mut Ghcb) -> R {
    let state = GHCB_STATE;
    let guard = state.lock();
    let ptr = guard.get_ghcb();

    let ghcb = unsafe {
        ptr.as_mut().unwrap()
    };
    f(ghcb)
}

enum GhcbState {
    /// The GHCB is still the one allocated by the bootloader for us
    EfiGHCB,

    /// The GHCB is the one allocated by the kernel
    KernelAllocated(PhysAddr, VirtAddr)
}

impl GhcbState {
    fn get_ghcb(&self) -> *mut Ghcb {
        // Read address from the GHCB
        let GhcbMsrResponse::GhcbPhysicalAddress(current_ghcb_addr) = GHCB_MSR.read_state() else {
            sev_exit!(error_exit_codes::EXIT_VC_INVALID_EXIT_CODE, "Invalid GHCB MSR response"); };
        let current_ghcb_addr = current_ghcb_addr.as_u64();

        let addr = match self {
            GhcbState::EfiGHCB => current_ghcb_addr,
            GhcbState::KernelAllocated(pa, va) => {
                // Ensure the address is set in the GHCB
                if pa.as_u64() != current_ghcb_addr {
                    // Set the correct GHCB address
                    unsafe {
                        GHCB_MSR.write_request(GhcbMsrRequest::SetGhcbPhysicalAddress(x86_64::PhysAddr::new(pa.as_u64())))
                    }
                }

                va.as_u64()
            }
        };

        addr as *mut Ghcb
    }
}

const GHCB_STATE: InterruptTicketMutex<GhcbState> = InterruptTicketMutex::new(GhcbState::EfiGHCB);

fn allocate_ghcb() -> (PhysAddr, VirtAddr) {
    let size = (Size4KiB::SIZE as usize).align_up(BasePageSize::SIZE as usize);

    let physical_address = arch::mm::physicalmem::allocate(size).unwrap();
    let virt_addr= virtualmem::allocate(size).unwrap();
    let mut flags = PageTableEntryFlags::empty();
    flags.normal().writable().execute_disable();
    // No encryption flag!
    paging::map::<BasePageSize>(
        virt_addr,
        physical_address.align_down(BasePageSize::SIZE),
        1,
        flags,
    );

    (PhysAddr::new(physical_address.as_u64()), VirtAddr::new(virt_addr.as_u64()))
}

pub fn init_ghcb() {
    let ghcb_version = ghcb_negotiate_protocol();
    let (ghcb_phys_addr, ghcb_virt_addr) = allocate_ghcb();

    let ptr: *mut Ghcb = ghcb_virt_addr.as_mut_ptr();
    let mut ghcb = Ghcb::default();
    ghcb.protocol_version = ghcb_version;
    unsafe {
        *ptr = ghcb;
    }

    let state = GHCB_STATE;
    let mut state = state.lock();
    *state = GhcbState::KernelAllocated(ghcb_phys_addr, ghcb_virt_addr);
}



fn flush_cache(start_addr: VirtAddr, size: u64) {
    // TODO: check feature availability
    // https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/special_insns.h#L177
    // https://www.felixcloutier.com/x86/clflushopt


    /* The aligned cache line size affected is also indicated with the CPUID instruction (bits 8 through 15 of the EBX register when the initial value in the EAX register is 1). */
    let start = start_addr.as_u64();
    let end = start + size;

    let cache_size = 1; // TODO

    if crate::processor::supports_clflush() {
        for pos in (start..end).step_by(cache_size) {
            unsafe {
                core::arch::x86_64::_mm_clflush(pos as *const u8);
            }
        }
    } else {
        panic!("not implemented: no clflush on CPU")
    }

}

// A mask that selects the 52 MSbs
const GHCB_ADDR_MASK: u64 = 0x0f_ffff_ffff_ffff;

#[inline]
/// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56421.pdf
fn ghcb_set_request_value(address: u64, request_value: u64) -> u64 {
    (address & GHCB_ADDR_MASK) << 12 | request_value & 0x0fff
}