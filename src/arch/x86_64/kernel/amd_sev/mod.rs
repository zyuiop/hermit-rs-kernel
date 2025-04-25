
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

use align_address::Align;
use hermit_sync::{InterruptSpinMutex, InterruptTicketMutex, Lazy};
pub use handler::vmm_interrupt_exception;
use alloc::boxed::Box;
use core::alloc::{Allocator, Layout};
use x86_64::structures::paging::{Mapper, Page, PageSize, Size4KiB, Translate};
use ghcb_msr_protocol::{GhcbMsrRequest, GhcbMsrResponse, GHCB_MSR};
use ghcb_protocol::Ghcb;
use crate::arch::{BasePageSize};
use crate::arch::mm::paging::{HugePageSize, PageTableEntryFlags, PageTableEntryFlagsExt};
use crate::{arch, mm};


pub use ghcb_msr_protocol::ghcb_request_exit;
use x86_64::VirtAddr;
use memory_addresses::PhysAddr;
use crate::arch::mm::{paging, virtualmem};
use crate::env::kernel::amd_sev::handler::error_exit_codes;
use crate::mm::device_alloc::DeviceAlloc;

const MAX_GHCB_PROTOCOL_VERSION: u16 = 1;

pub fn ghcb_negotiate_protocol() -> u16 {
    let GhcbMsrResponse::SevInformation { max_proto, min_proto, c_bit_pos } =
        GHCB_MSR.send_request_restore(GhcbMsrRequest::SevRequest) else {
        sev_exit!(error_exit_codes::EXIT_VC_INVALID_EXIT_CODE, "Invalid GHCB MSR response"); };

    // info!("Got GHCB protocol versions: max={max_proto}, min={min_proto} - c_bit_pos={c_bit_pos}");

    if max_proto < MAX_GHCB_PROTOCOL_VERSION || min_proto > MAX_GHCB_PROTOCOL_VERSION {
        sev_exit!(error_exit_codes::EXIT_OTHER, "GHCB version negotiation failed: wrong protocol version");
    }

    if MAX_GHCB_PROTOCOL_VERSION > max_proto {
        max_proto
    } else {
        MAX_GHCB_PROTOCOL_VERSION
    }
}

pub fn with_ghcb<F, R>(f: F) -> R
where F: FnOnce(&mut Ghcb) -> R {
    let state = unsafe { (&raw mut GHCB_STATE).as_mut().unwrap() };
    let mut guard = state.lock();
    let ghcb = guard.get_ghcb();
    f(ghcb)
}

enum GhcbState {
    /// The GHCB is still the one allocated by the bootloader for us
    EfiGHCB,

    /// The GHCB is the one allocated by the kernel
    KernelAllocated(AllocatedGhcb)
}

impl GhcbState {
    fn get_ghcb(&mut self) -> &mut Ghcb {
        // Read address from the GHCB
        let GhcbMsrResponse::GhcbPhysicalAddress(current_ghcb_addr) = GHCB_MSR.read_state() else {
            sev_exit!(error_exit_codes::EXIT_VC_INVALID_EXIT_CODE, "Invalid GHCB MSR response"); };
        let current_ghcb_addr = current_ghcb_addr.as_u64();

        let (ghcb, current_ghcb_addr) = match self {
            GhcbState::EfiGHCB => {
                let addr = current_ghcb_addr as *mut Ghcb;
                (unsafe { addr.as_mut().unwrap() }, current_ghcb_addr)
            },
            GhcbState::KernelAllocated(AllocatedGhcb(pa, boxed)) => {
                // Ensure the address is set in the GHCB
                if pa.as_u64() != current_ghcb_addr {
                    // Set the correct GHCB address
                    unsafe {
                        GHCB_MSR.write_request(GhcbMsrRequest::SetGhcbPhysicalAddress(x86_64::PhysAddr::new(pa.as_u64())))
                    }
                }

                (boxed.as_mut(), pa.as_u64())
            }
        };

        ghcb.save.sw_scratch = current_ghcb_addr + GHCB_SCRATCH_OFFSET;
        ghcb
    }
}

static mut GHCB_STATE: InterruptTicketMutex<GhcbState> = InterruptTicketMutex::new(GhcbState::EfiGHCB);

struct AllocatedGhcb(PhysAddr, Box<Ghcb, DeviceAlloc>);

fn allocate_ghcb() -> AllocatedGhcb {
    // let physical_address = arch::mm::physicalmem::allocate(size).unwrap();
    // let virt_addr = virtualmem::allocate(size).unwrap();
    // let virt_addr = mm::allocate(size, true);
    // let physical_address = mm::virtual_to_physical(virt_addr).unwrap();
    let virt_addr = DeviceAlloc.allocate(Layout::new::<Ghcb>()).unwrap();
    let virt_addr = memory_addresses::VirtAddr::new(virt_addr.addr().get() as u64);
    let physical_address = mm::virtual_to_physical(virt_addr).unwrap();


    let mut flags = PageTableEntryFlags::empty();
    flags.normal().writable().execute_disable();
    // No encryption flag!
    paging::map::<BasePageSize>(
        virt_addr,
        physical_address.align_down(BasePageSize::SIZE),
        1,
        flags,
    );

    let boxed = unsafe { Box::from_raw_in(virt_addr.as_mut_ptr(), DeviceAlloc) };
    AllocatedGhcb(PhysAddr::new(physical_address.as_u64()), boxed)
}

const GHCB_SCRATCH_OFFSET: u64 = core::mem::offset_of!(Ghcb, shared_buffer) as u64;

pub fn init_ghcb() {
    let ghcb_version = ghcb_negotiate_protocol();
    let mut allocated = allocate_ghcb();

    allocated.1.protocol_version = ghcb_version;

    let state = unsafe { (&raw mut GHCB_STATE).as_mut().unwrap() };
    let mut state = state.lock();
    *state = GhcbState::KernelAllocated(allocated);
}