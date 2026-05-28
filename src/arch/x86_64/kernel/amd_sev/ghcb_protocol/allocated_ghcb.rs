use super::error_exit_codes;
use crate::arch::core_local::core_id;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::{Ghcb, GHCB_SCRATCH_OFFSET};
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb_msr;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb_msr::ghcb_request_exit;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb_msr::{GhcbMsrRequest, GhcbMsrResponse, GHCB_MSR};
use alloc::boxed::Box;
use core::alloc::Layout;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU8, Ordering};
use virtio::pci::CapCfgType::Device;
use crate::mm::device_alloc::DeviceAlloc;
use hermit_sync::InterruptOneShotMutex;
use memory_addresses::PhysAddr;

static EFI_GHCB_LOCK: InterruptOneShotMutex<EfiGhcb> = InterruptOneShotMutex::new(EfiGhcb);

struct EfiGhcb;

impl EfiGhcb {
	fn get_efi_ghcb(&mut self) -> &mut Ghcb {
		let current_ghcb_addr = get_current_ghcb_addr();
		let addr = current_ghcb_addr as *mut Ghcb;
		let ghcb = unsafe { addr.as_mut().unwrap() };

		ghcb.set_scratch_addr(current_ghcb_addr + GHCB_SCRATCH_OFFSET);

		ghcb
	}
}

fn get_current_ghcb_addr() -> u64 {
	let GhcbMsrResponse::GhcbPhysicalAddress(current_ghcb_addr) = GHCB_MSR.read_state() else {
		sev_exit!(
			error_exit_codes::EXIT_GHCB_INVALID_MSR,
			"Invalid GHCB MSR response"
		);
	};
	current_ghcb_addr.as_u64()
}

#[allow(static_mut_refs)]
pub fn with_ghcb<F, R>(f: F) -> R
where
	F: FnOnce(&mut Ghcb) -> R,
{
	let core_id = core_id() as usize;
	assert!(core_id < 255);

	match ALLOCATED_GHCB[core_id].get() {
		None if core_id == 0 => {
			let mut efi_ghcb_lock = EFI_GHCB_LOCK.lock();
			let ghcb = efi_ghcb_lock.get_efi_ghcb();
			f(ghcb)
		}
		None => ghcb_request_exit(error_exit_codes::EXIT_GHCB_NOT_INITIALIZED_FOR_CORE),
		Some(ghcb) => {
			let physical_address = ghcb.physical_address.as_u64();

			// Ensure the address is set in the GHCB
			if physical_address != get_current_ghcb_addr() {
				// Set the correct GHCB address
				unsafe {
					GHCB_MSR.write_request(GhcbMsrRequest::SetGhcbPhysicalAddress(
						x86_64::PhysAddr::new(ghcb.physical_address.as_u64()),
					))
				}
			}

			let mut lock = ghcb.lock();
			let ghcb = lock.deref_mut();
			// The scratch area pointer must contain the physical address of the scratch area, not the virtual one
			ghcb.set_scratch_addr(physical_address + GHCB_SCRATCH_OFFSET);
			f(ghcb)
		}
	}
}

// Allocated GHCB per GPU
static ALLOCATED_GHCB: [hermit_sync::OnceCell<AllocatedGhcb>; 256] =
	[const { hermit_sync::OnceCell::new() }; 256];

struct AllocatedGhcb {
	pub physical_address: PhysAddr,
	inner: *mut Ghcb,
	instance_count: AtomicU8,
}

/// We have handled safety in the type
unsafe impl Send for AllocatedGhcb {}

struct GhcbLock<'a> {
	parent: &'a AllocatedGhcb,
	instance_number: u8,
	previous_instance: Option<Box<Ghcb>>,
}

impl Drop for GhcbLock<'_> {
	fn drop(&mut self) {
		let previous_instances = self.parent.instance_count.fetch_sub(1, Ordering::AcqRel);

		if previous_instances != self.instance_number {
			ghcb_request_exit(error_exit_codes::EXIT_BACKUP_RESTORE_NOT_IN_ORDER);
		}

		if self.instance_number > 1 {
			if let Some(backup) = self.previous_instance.take() {
				unsafe {
					self.parent.inner.write(*backup)
				}
			} else {
				ghcb_request_exit(error_exit_codes::EXIT_BACKUP_RESTORE_NOT_IN_ORDER);
			}
		}
	}
}

impl Deref for GhcbLock<'_> {
	type Target = Ghcb;

	fn deref(&self) -> &Self::Target {
		unsafe { self.parent.inner.as_ref().unwrap() }
	}
}

impl DerefMut for GhcbLock<'_> {
	// TOOD: temporary - replace with safer locking mechanism
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { self.parent.inner.as_mut().unwrap() }
	}
}

impl AllocatedGhcb {
	pub fn new() -> Self {
		let (ghcb_ptr, physical_address) = DeviceAlloc
			.allocate_with_physical(
				Layout::from_size_align(size_of::<Ghcb>(), Size4KiB::SIZE as usize).unwrap(),
			)
			.expect("failed to allocate memory for GHCB");

		info!("Allocated GHCB at {ghcb_ptr:x} (GFN: {physical_address:x})");

		Self {
			physical_address: physical_address,
			inner: ghcb_ptr.as_mut_ptr(),
			instance_count: AtomicU8::new(0),
		}
	}

	pub fn lock<'a>(&'a self) -> GhcbLock<'a> {
		let instance_number = self.instance_count.fetch_add(1, Ordering::AcqRel) + 1;
		if instance_number > 2 {
			ghcb_request_exit(error_exit_codes::EXIT_TOO_MANY_CONCURRENT_USES);
		}

		let previous_instance = if instance_number == 1 {
			None
		} else {
			let ghcb = unsafe { self.inner.as_mut().unwrap() };
			let copy = Box::new(mem::take(ghcb));
			Some(copy)
		};

		let lock = GhcbLock {
			instance_number,
			parent: self,
			previous_instance,
		};

		lock
	}
}

pub fn init_ghcb_for_core() {
	let core = core_id();
	assert!(core < 255);

	let ghcb_version = ghcb_msr::ghcb_negotiate_protocol();
	assert_eq!(ghcb_version, 2);

	let allocated = AllocatedGhcb::new();

	// Register the GHCB
	let req = GhcbMsrRequest::RegisterGhcbGPA(x86_64::addr::PhysAddr::new(
		allocated.physical_address.as_u64(),
	));
	unsafe {
		let resp = GHCB_MSR.send_request(req);

		let GhcbMsrResponse::RegisterGhcbGPA(rep) = resp else {
			sev_exit!(
				error_exit_codes::EXIT_OTHER,
				"invalid GHCB MSR response code"
			)
		};

		if rep.is_none() {
			sev_exit!(
				error_exit_codes::EXIT_OTHER,
				"hypervisor rejected our GHCB address"
			)
		}
	}

	unsafe {
		// Write the address for next time
		GHCB_MSR.write_request(GhcbMsrRequest::SetGhcbPhysicalAddress(
			x86_64::PhysAddr::new(allocated.physical_address.as_u64()),
		));
	}

	allocated
		.lock()
		.deref_mut()
		.set_protocol_version(ghcb_version);

	let core_id = core as usize;
	if let Err(_) = ALLOCATED_GHCB[core_id].set(allocated) {
		panic!("GHCB is already initialized!");
	}

	assert!(ALLOCATED_GHCB[core_id].get().is_some());
}
