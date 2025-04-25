
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
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU8, Ordering};
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

#[allow(static_mut_refs)]
pub fn with_ghcb<F, R>(f: F) -> R
where F: FnOnce(&mut Ghcb) -> R {
    let GhcbMsrResponse::GhcbPhysicalAddress(current_ghcb_addr) = GHCB_MSR.read_state() else {
        sev_exit!(error_exit_codes::EXIT_VC_INVALID_EXIT_CODE, "Invalid GHCB MSR response"); };
    let current_ghcb_addr = current_ghcb_addr.as_u64();

    match unsafe { ALLOCATED_GHCB.get_mut() } {
        None => {
            let addr = current_ghcb_addr as *mut Ghcb;
            let ghcb = (unsafe { addr.as_mut().unwrap() });
            ghcb.save.sw_scratch = current_ghcb_addr + GHCB_SCRATCH_OFFSET;
            f(ghcb)
        },
        Some(ghcb) => {
            let physical_address = ghcb.physical_address.as_u64();
            // Ensure the address is set in the GHCB
            if physical_address != current_ghcb_addr {
                // Set the correct GHCB address
                unsafe {
                    GHCB_MSR.write_request(GhcbMsrRequest::SetGhcbPhysicalAddress(x86_64::PhysAddr::new(ghcb.physical_address.as_u64())))
                }
            }

            // let mut lock = ghcb.lock();
            let ghcb = ghcb.deref_mut();
            ghcb.save.sw_scratch = current_ghcb_addr + GHCB_SCRATCH_OFFSET;
            f(ghcb)
        }
    }
}


static mut ALLOCATED_GHCB: hermit_sync::OnceCell<AllocatedGhcb> = hermit_sync::OnceCell::new();

struct AllocatedGhcb{
    pub physical_address: PhysAddr,
    inner: *mut Ghcb,
    instance_count: AtomicU8,
    backup: hermit_sync::RwSpinLock<Box<Option<Ghcb>>>
}

struct GhcbLock<'a> {
    parent: &'a AllocatedGhcb,
    instance_number: u8
}

impl<'a> Drop for GhcbLock<'a> {
    fn drop(&mut self) {
        let previous_instances = self.parent.instance_count.fetch_sub(1, Ordering::AcqRel);

        if previous_instances != self.instance_number {
            self.parent.critical_failure("out-of-order GHCB usage")
        }

        if self.instance_number > 1 {
            // Restore the copy of the GHCB before returning
            let mut lock = self.parent.backup.write();
            match lock.take() {
                None => self.parent.critical_failure("GHCB copy is missing"),
                Some(copy) => *self.deref_mut() = copy
            }
        }
    }
}

impl<'a> Deref for GhcbLock<'a> {
    type Target = Ghcb;

    fn deref(&self) -> &Self::Target {
        unsafe { self.parent.inner.as_ref().unwrap() }
    }
}

impl<'a> DerefMut for GhcbLock<'a> {
    // TOOD: temporary - replace with safer locking mechanism
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.parent.inner.as_mut().unwrap() }
    }
}

impl AllocatedGhcb {
    pub fn new() -> Self {
        let virt_addr = mm::allocate(size_of::<Ghcb>(), true);
        let physical_address = mm::virtual_to_physical(virt_addr).unwrap();
        Self {
            physical_address: physical_address,
            inner: virt_addr.as_mut_ptr(),
            instance_count: AtomicU8::new(0),
            backup: hermit_sync::RwSpinLock::new(Box::new(None))
        }
    }

    pub fn lock(&mut self) -> GhcbLock {
        let instance_number = self.instance_count.fetch_add(1, Ordering::AcqRel) + 1;
        if instance_number > 2 {
            self.critical_failure("too many nested GHCB uses");
        }

        let lock = GhcbLock { instance_number, parent: self };

        if instance_number > 1 {
            // Nested call: we need to make a copy of the current GHCB
            let mut backup_lock = self.backup.write();
            if backup_lock.is_some() {
                self.critical_failure("GHCB backup already present!")
            }

            backup_lock.insert(lock.deref().clone());
            drop(backup_lock);
        }

        lock
    }

    fn critical_failure(&self, msg: &str) -> ! {
        // Resets the state, calls panic, and quits
        self.instance_count.fetch_and(0, Ordering::AcqRel);
        panic!("GHCB Manager Failure: {msg}");
    }
}


impl Deref for AllocatedGhcb {
    type Target = Ghcb;

    fn deref(&self) -> &Self::Target {
        unsafe { self.inner.as_ref().unwrap() }
    }
}

impl DerefMut for AllocatedGhcb {
    // TOOD: temporary - replace with safer locking mechanism
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.inner.as_mut().unwrap() }
    }
}


const GHCB_SCRATCH_OFFSET: u64 = core::mem::offset_of!(Ghcb, shared_buffer) as u64;

#[allow(static_mut_refs)]
pub fn init_ghcb() {
    let ghcb_version = ghcb_negotiate_protocol();
    let mut allocated = AllocatedGhcb::new();

    allocated.lock().deref_mut().protocol_version = ghcb_version;

    unsafe {
        if let Err(e) = ALLOCATED_GHCB.set(allocated) {
            panic!("GHCB is already initialized!");
        }
    }
}