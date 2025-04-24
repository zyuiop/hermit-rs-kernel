
macro_rules! sev_exit {
    ($code:expr) => {{
        log::error!();
        x86_64::structures::amd_sev::ghcb_msr_protocol::ghcb_request_exit($code)
    }};
    ($code:expr, $($arg:tt)*) => {{
        log::error!($($arg)+);
        x86_64::structures::amd_sev::ghcb_msr_protocol::ghcb_request_exit($code)
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

use core::arch::asm;
use align_address::Align;
use hermit_sync::{InterruptTicketMutex, Lazy};
use x86_64::instructions::tlb;
pub use handler::vmm_interrupt_exception;

use x86_64::structures::paging::{Mapper, Page, PageSize, Size4KiB, Translate};
use x86_64::structures::paging::mapper::TranslateResult;
use x86_64::structures::amd_sev::ghcb_msr_protocol::{vmgexit, GhcbMsrRequest, GhcbMsrResponse, GHCB_MSR};
use x86_64::structures::amd_sev::ghcb_protocol::Ghcb;
use x86_64::structures::idt::{InterruptDescriptorTable};
use crate::arch::interrupts::{ExceptionStackFrame};
use crate::arch::{BasePageSize};
use crate::arch::mm::paging::{identity_mapped_page_table, HugePageSize, PageTableEntryFlags, PageTableEntryFlagsExt};
use crate::{arch, mm};

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

pub use x86_64::structures::amd_sev::ghcb_msr_protocol::ghcb_request_exit;
use x86_64::structures::amd_sev::sev_state;
use x86_64::VirtAddr;
use memory_addresses::PhysAddr;
use crate::arch::kernel::amd_sev::handler_vmmcall::Hypercalls;
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
    let GhcbMsrResponse::GhcbPhysicalAddress(current_ghcb_addr) = GHCB_MSR.read_state() else {
        sev_exit!(error_exit_codes::EXIT_VC_INVALID_EXIT_CODE, "Invalid GHCB MSR response"); };
    let ptr: *mut Ghcb = current_ghcb_addr.as_u64() as *mut Ghcb;
    let ghcb = unsafe {
        ptr.as_mut().unwrap()
    };
    f(ghcb)
}

fn allocate_ghcb() -> memory_addresses::VirtAddr {
    let size = (Size4KiB::SIZE as usize).align_up(BasePageSize::SIZE as usize);

    let physical_address = arch::mm::physicalmem::allocate(size).unwrap();
    let virtual_address = memory_addresses::VirtAddr::new(physical_address.as_u64());

    let count = size / BasePageSize::SIZE as usize;
    let mut flags = PageTableEntryFlags::empty();
    flags.normal().writable();

    if sev_state().is_some() {
        flags.set_encrypted(true);
    }

    arch::mm::paging::map::<BasePageSize>(virtual_address, physical_address, count, flags);

    virtual_address
}

pub fn init_ghcb() {
    info!("enter init_ghcb");
    let ghcb_version = ghcb_negotiate_protocol();
    let ghcb_page = allocate_ghcb();

    info!("GHCB memory allocated.");
    // TODO: make the page not encrypted
    let mut page_table = unsafe { identity_mapped_page_table() };
    let page: Page<BasePageSize> = Page::from_start_address(ghcb_page.into()).expect("invalid page address!");

    info!("GHCB memory address page resolved.");
    let TranslateResult::Mapped { frame, mut flags, offset } = page_table.translate(ghcb_page.into()) else { panic!("invalid page address!") };
    assert_eq!(offset, 0);
    info!("GHCB memory address page translated. Current flags: {flags:x} {flags:?}. Frame: {:x}. Size: {:x}.", frame.start_address().as_u64(), frame.size());
    flags.set_encrypted(false);
    unsafe {
        page_table.update_flags(page, flags)
            .expect("failed to update page flags!")
            .flush()
    }

    tlb::flush_all();

    info!("GHCB flags updated. Assigning GHCB...");
    flush_cache(page.start_address(), page.size());
    info!("Cache cleared");

    let ptr: *mut Ghcb = ghcb_page.as_mut_ptr();
    let mut ghcb = Ghcb::default();
    ghcb.protocol_version = ghcb_version;
    unsafe {
        *ptr = ghcb;
    }

    info!("GHCB physical address (other way): {:x}", ptr as u64);

    unsafe {
        (ptr.as_mut()).unwrap().clear();
    }

    HYPERCALLS.map_gpa_range.call(
        (u16::from(page.p4_index()) as u64) << 12,
        1,
        0
    ).unwrap();

    info!("GHCB address: {:x}", frame.start_address().as_u64());
    info!("GHCB contents: (exit info 1): {:x}", unsafe { (ptr.as_ref().unwrap()).save.sw_exit_info_1 });

    unsafe {
        GHCB_MSR.write_request(GhcbMsrRequest::SetGhcbPhysicalAddress(frame.start_address()))
    }

    info!("MSR written.");
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