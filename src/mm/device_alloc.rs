use core::alloc::{AllocError, Allocator, Layout};
use core::ptr::{self, NonNull};

use align_address::Align;
use free_list::{FreeList, PageLayout, PageRange};
use hermit_sync::InterruptTicketMutex;
use memory_addresses::{PhysAddr, VirtAddr};
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size2MiB};
#[cfg(feature = "amd-sev")]
use crate::arch::kernel::amd_sev::ghcb_protocol::protocol_page_state_change::{change_page_states, PageStateChangeEntry, PageStateChangeOperation};
use crate::arch::mm::paging;
use crate::arch::mm::paging::{BasePageSize, PageSize, PageTableEntryFlags, PageTableEntryFlagsExt};
use crate::mm::{FrameAlloc, PageRangeAllocator, virtualmem};
use crate::mm::physicalmem::IdentityPageSize;

/// An [`Allocator`] for memory that is used to communicate with devices.
///
/// Allocations from this allocator always correspond to contiguous physical memory.
pub struct DeviceAlloc;

pub const ENABLE_PHYS_OFFSET: bool = cfg!(any(careful, feature = "amd-sev"));

static DEVICE_FREE_LIST: InterruptTicketMutex<DeviceFreeList> =
	InterruptTicketMutex::new(DeviceFreeList::new());

struct DeviceFreeList(FreeList<16>);

impl DeviceFreeList {
	const fn new() -> DeviceFreeList {
		DeviceFreeList(FreeList::new())
	}

	fn add_page(&mut self) -> Result<(), AllocError> {
		let allocated_frame: PhysFrame<Size2MiB> =
			FrameAlloc::allocate_frame(&mut FrameAlloc).ok_or_else(|| AllocError)?;

		if IdentityPageSize::SIZE > Size2MiB::SIZE {
			panic!("IdentityPageSize is too large!")
		}

		if ENABLE_PHYS_OFFSET {
			self.map_device_page(allocated_frame);
		}

		unsafe {
			self.0
				.deallocate(allocated_frame.into())
				.map_err(|_| AllocError)
		}
	}

	fn map_device_page(&self, frame: PhysFrame<Size2MiB>) {
		// 1. Remove page table entry in identity mapped table for this page
		paging::unmap::<IdentityPageSize>(
			VirtAddr::new(frame.start_address().as_u64()),
			(Size2MiB::SIZE / IdentityPageSize::SIZE) as usize,
		);

		// 2. Update the RMP
		#[cfg(feature = "amd-sev")]
		if IdentityPageSize::SIZE == Size2MiB::SIZE {
			change_page_states(&[PageStateChangeEntry::new_for_frame(
				frame,
				PageStateChangeOperation::PageAssignShared,
			)])
				.expect("failed to update RMP");
		} else {
			change_page_states(&[
				PageStateChangeEntry::new_for_frame(
					frame,
					PageStateChangeOperation::PageUnsmash,
				),
				PageStateChangeEntry::new_for_frame(
					frame,
					PageStateChangeOperation::PageAssignShared,
				),
			])
				.expect("failed to update RMP");
		}

		// 3. Add an entry at the device offset
		let flags = {
			let mut flags = PageTableEntryFlags::empty();
			// TODO: we should in theory set .device() here, but this disables cache and slows down
			// operations on shared memory. Maybe we can get away with this???
			flags.normal().writable().execute_disable();
			flags
		};

		let phys_addr = frame.start_address().into();
		let virt_addr = VirtAddr::from_ptr(DeviceAlloc.ptr_from::<()>(phys_addr));
		paging::map::<Size2MiB>(virt_addr, phys_addr, 1, flags);
	}

	fn allocate(&mut self, frame_layout: PageLayout) -> Result<PageRange, AllocError> {
		let allocation = self.0.allocate(frame_layout).map_err(|_| AllocError);

		match allocation {
			Err(_) => {
				self.add_page()?;
				self.0.allocate(frame_layout).map_err(|_| AllocError)
			}
			ok => ok,
		}
	}

	fn deallocate(&mut self, range: PageRange) -> Result<(), AllocError> {
		// OPTIONAL: if we have too much memory in the list we may return it to the physical free list
		// In this case, we MUST set it to private again
		unsafe { self.0.deallocate(range).map_err(|_| AllocError) }
	}
}

unsafe impl Allocator for DeviceAlloc {
	fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
		assert!(layout.align() <= BasePageSize::SIZE as usize);
		let size = layout.size().align_up(BasePageSize::SIZE as usize);
		let frame_layout = PageLayout::from_size(size).unwrap();

		let frame_range = DEVICE_FREE_LIST
			.lock()
			.allocate(frame_layout)
			.map_err(|_| AllocError)?;

		let phys_addr = PhysAddr::from(frame_range.start());
		let ptr = self.ptr_from(phys_addr);
		let slice = ptr::slice_from_raw_parts_mut(ptr, size);
		Ok(NonNull::new(slice).unwrap())
	}

	unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
		assert!(layout.align() <= BasePageSize::SIZE as usize);
		let size = layout.size().align_up(BasePageSize::SIZE as usize);

		let phys_addr = self.phys_addr_from(ptr.as_ptr());
		let range = PageRange::from_start_len(phys_addr.as_usize(), size).unwrap();

		unsafe {
			DEVICE_FREE_LIST.lock().deallocate(range).unwrap();
		}
	}
}

impl DeviceAlloc {
	/// Returns a pointer corresponding to `phys_addr`.
	#[inline]
	pub fn ptr_from<T>(&self, phys_addr: PhysAddr) -> *mut T {
		let addr = phys_addr.as_usize() + self.phys_offset().as_usize();
		ptr::with_exposed_provenance_mut(addr)
	}

	/// Returns a VirtAddr corresponding to `phys_addr`.
	#[inline]
	pub fn virt_addr_from(&self, phys_addr: PhysAddr) -> VirtAddr {
		let addr = phys_addr.as_usize() + self.phys_offset().as_usize();
		VirtAddr::from(addr)
	}

	/// Returns the physical address of `ptr`.
	///
	/// The address is only correct if `ptr` has been allocated by this allocator.
	#[inline]
	pub fn phys_addr_from<T: ?Sized>(&self, ptr: *mut T) -> PhysAddr {
		let addr = u64::try_from(ptr.expose_provenance()).unwrap() - self.phys_offset().as_u64();
		PhysAddr::new(addr)
	}

	/// Returns the physical address offset.
	///
	/// This device allocator expects the complete physical memory to be mapped device-readable at this offset.
	#[inline]
	pub fn phys_offset(&self) -> VirtAddr {
		if ENABLE_PHYS_OFFSET {
			virtualmem::kernel_heap_end().as_u64().div_ceil(4).into()
		} else {
			0u64.into()
		}
	}
}
