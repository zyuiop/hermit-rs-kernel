use memory_addresses::PhysAddr;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::ops::{Deref, DerefMut};
use core::alloc::Layout;
use crate::arch::kernel::amd_sev::decrypted_allocator::SharedPagesAllocator;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb_msr::{GhcbMsrRequest, GhcbMsrResponse, GHCB_MSR};
use crate::arch::kernel::amd_sev::sev_state;
use crate::env::kernel::amd_sev::ghcb_protocol::ghcb_msr;
use super::error_exit_codes;

#[allow(static_mut_refs)]
pub fn with_ghcb<F, R>(f: F) -> R
where
	F: FnOnce(&mut Ghcb) -> R,
{
	let GhcbMsrResponse::GhcbPhysicalAddress(current_ghcb_addr) = GHCB_MSR.read_state() else {
		sev_exit!(
			error_exit_codes::EXIT_VC_INVALID_EXIT_CODE,
			"Invalid GHCB MSR response"
		);
	};
	let current_ghcb_addr = current_ghcb_addr.as_u64();

	match ALLOCATED_GHCB.get() {
		None => {
			let addr = current_ghcb_addr as *mut Ghcb;
			let ghcb = (unsafe { addr.as_mut().unwrap() });
			ghcb.save.sw_scratch = current_ghcb_addr + GHCB_SCRATCH_OFFSET;
			f(ghcb)
		}
		Some(ghcb) => {
			let physical_address = ghcb.physical_address.as_u64();
			// Ensure the address is set in the GHCB
			if physical_address != current_ghcb_addr {
				// Set the correct GHCB address
				unsafe {
					GHCB_MSR.write_request(GhcbMsrRequest::SetGhcbPhysicalAddress(
						x86_64::PhysAddr::new(ghcb.physical_address.as_u64()),
					))
				}
			}

			let mut lock = ghcb.lock();
			let ghcb = lock.deref_mut();
			ghcb.save.sw_scratch = current_ghcb_addr + GHCB_SCRATCH_OFFSET;
			f(ghcb)
		}
	}
}

static ALLOCATED_GHCB: hermit_sync::OnceCell<AllocatedGhcb> = hermit_sync::OnceCell::new();

struct AllocatedGhcb {
	pub physical_address: PhysAddr,
	inner: *mut Ghcb,
	instance_count: AtomicU8,

	backup_present: AtomicBool,
	backup: *mut Ghcb,
}

/// We have handled safety in the type
unsafe impl Send for AllocatedGhcb {}

struct GhcbLock<'a> {
	parent: &'a AllocatedGhcb,
	instance_number: u8,
}

impl<'a> Drop for GhcbLock<'a> {
	fn drop(&mut self) {
		let previous_instances = self.parent.instance_count.fetch_sub(1, Ordering::AcqRel);

		if previous_instances != self.instance_number {
			self.parent.critical_failure("out-of-order GHCB usage")
		}

		if self.instance_number > 1 {
			// Restore the copy of the GHCB before returning
			let backup_present = self.parent.backup_present.fetch_and(false, Ordering::AcqRel);
			if !backup_present {
				self.parent.critical_failure("GHCB copy is missing")
			} else {
				unsafe {
					core::ptr::copy(self.parent.backup, self.parent.inner, 1);
				}
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
		let (ghcb_ptr, physical_address) = SharedPagesAllocator.allocate_with_physical(Layout::new::<Ghcb>()).expect("failed to allocate memory for GHCB");
		let (backup_ghcb_ptr, _) = SharedPagesAllocator.allocate_with_physical(Layout::new::<Ghcb>()).expect("failed to allocate memory for GHCB backup");

		Self {
			physical_address: physical_address,
			inner: ghcb_ptr.as_mut_ptr(),
			instance_count: AtomicU8::new(0),
			backup: backup_ghcb_ptr.as_mut_ptr(),
			backup_present: AtomicBool::new(false)
		}
	}

	pub fn lock(&self) -> GhcbLock {
		let instance_number = self.instance_count.fetch_add(1, Ordering::AcqRel) + 1;
		if instance_number > 2 {
			self.critical_failure("too many nested GHCB uses");
		}

		let lock = GhcbLock {
			instance_number,
			parent: self,
		};

		if instance_number > 1 {
			// Nested call: we need to make a copy of the current GHCB
			let backup_present = self.backup_present.fetch_or(true, Ordering::AcqRel);
			if backup_present {
				self.critical_failure("GHCB backup already present!")
			}
			unsafe {
				core::ptr::copy(self.inner, self.backup, 1);
			}
		}

		lock
	}

	fn critical_failure(&self, msg: &str) -> ! {
		// Resets the state, calls panic, and quits
		self.instance_count.fetch_and(0, Ordering::AcqRel);
		panic!("GHCB Manager Failure: {msg}");
	}
}

const GHCB_SCRATCH_OFFSET: u64 = core::mem::offset_of!(Ghcb, shared_buffer) as u64;

#[allow(static_mut_refs)]
pub fn init_ghcb() {
	let Some(sev_status) = sev_state() else { panic!("sev is not initialized") };

	let ghcb_version = ghcb_msr::ghcb_negotiate_protocol();
	let mut allocated = AllocatedGhcb::new();

	if sev_status.sev_snp_enabled {
		let req = GhcbMsrRequest::RegisterGhcbGPA(x86_64::addr::PhysAddr::new(allocated.physical_address.as_u64()));
		unsafe {
			let resp = GHCB_MSR.send_request_restore(req);

			let GhcbMsrResponse::RegisterGhcbGPA(rep) = resp else {
				sev_exit!(error_exit_codes::EXIT_OTHER, "invalid GHCB MSR response code")
			};

			if rep.is_none() {
				sev_exit!(error_exit_codes::EXIT_OTHER, "hypervisor rejected our GHCB address")
			}
		}
	}

	allocated.lock().deref_mut().protocol_version = ghcb_version;

	unsafe {
		if let Err(e) = ALLOCATED_GHCB.set(allocated) {
			panic!("GHCB is already initialized!");
		}
	}
}