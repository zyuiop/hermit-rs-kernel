use core::alloc::{Allocator, Layout};
use core::alloc::AllocError;
use core::ptr;
use core::ptr::NonNull;
use align_address::Align;
use free_list::{PageLayout, PageRange};
use x86_64::structures::paging::PageSize;
use memory_addresses::{PhysAddr, VirtAddr};
use crate::arch::BasePageSize;
use crate::mm;
use crate::mm::{FrameAlloc, PageRangeAllocator};

/// A variant of DeviceAlloc that maps to a different virtual address, with shared flags set
///
/// TODO: maybe we can just use DeviceAlloc :)
pub(crate) struct SharedPagesAllocator;

impl SharedPagesAllocator {
    pub fn allocate_with_physical(&self, layout: Layout) -> Option<(VirtAddr, PhysAddr)> {
        assert!(layout.align() <= BasePageSize::SIZE as usize);
        let size = layout.size().align_up(BasePageSize::SIZE as usize);
        let frame_layout = PageLayout::from_size(size).unwrap();

        let frame_range = FrameAlloc::allocate(frame_layout)
            .ok()?;

        let allocated_physical = PhysAddr::from(frame_range.start());
        let virtual_addr = mm::device_map(allocated_physical, size, true, true, false);

        Some((virtual_addr, allocated_physical))
    }
}

unsafe impl Allocator for SharedPagesAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let size = layout.size().align_up(BasePageSize::SIZE as usize);
        let (addr, _) = self.allocate_with_physical(layout).ok_or(AllocError)?;

        let ptr = ptr::with_exposed_provenance_mut(addr.as_usize());
        let slice = ptr::slice_from_raw_parts_mut(ptr, size);
        Ok(NonNull::new(slice).unwrap())
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        assert!(layout.align() <= BasePageSize::SIZE as usize);
        let size = layout.size().align_up(BasePageSize::SIZE as usize);

        let virt_addr = ptr.as_ptr().expose_provenance();
        let phys_addr = mm::virtual_to_physical(VirtAddr::new(virt_addr as u64)).expect("address not mapped");

        mm::unmap(VirtAddr::new(virt_addr as u64), size);

        unsafe {
            let range = PageRange::from_start_len(phys_addr.as_usize(), size).unwrap();
            FrameAlloc::deallocate(range);
        }
    }
}