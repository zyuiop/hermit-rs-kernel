use core::alloc::Layout;
use hermit_sync::{InterruptSpinMutex, Lazy};
use x86_64::structures::paging::{PageSize, Size4KiB};
use memory_addresses::{PhysAddr, VirtAddr};
use crate::arch::kernel::amd_sev::decrypted_allocator::SharedPagesAllocator;
use super::protocol_page_state_change::{PageStateChangeEntry, PageStateChangeOperation, change_page_states};

type RequestPageMutex = InterruptSpinMutex<SNPRequestPage>;

static REQUEST_PAGE: Lazy<RequestPageMutex> = Lazy::new(|| SNPRequestPage::allocate());
static RESPONSE_PAGE: Lazy<RequestPageMutex> = Lazy::new(|| SNPRequestPage::allocate());

struct SNPRequestPage(VirtAddr, PhysAddr);

impl SNPRequestPage {
    pub fn allocate() -> RequestPageMutex {
        let layout = Layout::from_size_align(Size4KiB::SIZE as usize, Size4KiB::SIZE as usize).unwrap();
        let (ghcb_ptr, physical_address) = SharedPagesAllocator.allocate_with_physical(layout)
            .expect("failed to allocate memory for communication page");

        // Mark the allocated memory as shared
        change_page_states(&[
            PageStateChangeEntry::new_for_address(x86_64::PhysAddr::new(physical_address.as_u64()), layout.size() as u64, PageStateChangeOperation::PageAssignShared)
        ]).expect("failed to change page state");

        InterruptSpinMutex::new(SNPRequestPage(ghcb_ptr, physical_address))
    }
}

enum SNPGuestRequest {
    
}