use x86_64::registers::control::Cr2;
use x86_64::structures::paging::mapper::TranslateResult;
use x86_64::structures::paging::{PageSize, Size2MiB, Size4KiB, Translate};
use crate::arch::kernel::amd_sev::ghcb_protocol::protocol_page_state_change::PageStateChangePageSize;
use crate::arch::kernel::amd_sev::vc_handler::InterruptStackFrame;
use crate::arch::mm::paging::identity_mapped_page_table;

pub fn handle_rmp_invalid(_: &mut InterruptStackFrame) {
	// See AMD Programmer's Manual vol. 2 (doc id 24593), section §15.36.10
	// > A failure of the page validation check results in a #VC with error code PAGE_NOT_VALIDATED
	// > (0x404). The faulting guest virtual address is saved to CR2 when this error occurs.

	/* The VM may use the PVALIDATE instruction to either set or clear the Validated flag of a page. It is
	expected that VMs would use PVALIDATE to set the Validated flag during VM startup to gain access
	to the memory the hypervisor has assigned. The VM may later use PVALIDATE to clear the Validated
	flag if its memory space is being reduced, such as after a memory hot-plug event.
	Page validation allows a VM to detect an unexpected remapping of its pages by the hypervisor. Before
	accessing a page, the VM must validate the page. Once validated, any use of RMPUPDATE by the
	hypervisor to unassign, reassign, or remap the page will cause the page to become unvalidated. The
	VM can then detect tampering with the page mapping via the #VC that occurs from accessing
	unvalidated pages. */

	let va = Cr2::read().unwrap();
	error!("Invalid RMP entry when accessing 0x{va:x}");

	let translate_result = unsafe { identity_mapped_page_table() }.translate(va);

	match translate_result {
		TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => {
			error!("Has no page table mapping");
			sev_exit!(0x42, "Invalid RMP entry");
		}
		TranslateResult::Mapped { frame, offset, flags } => {
			error!(" -> Is mapped to physical frame: {:?}", frame);
			error!(" -> Offset within frame: {:x}", offset);
			error!(" -> Flags: {:?}", flags);

			if frame.size() == Size2MiB::SIZE {
				PageStateChangePageSize::PageSize2MB
			} else if frame.size() == Size4KiB::SIZE {
				PageStateChangePageSize::PageSize4KB
			} else {
				PageStateChangePageSize::PageSize2MB
			}
		}
	};

	sev_exit!(0x42, "Invalid RMP entry");
}
