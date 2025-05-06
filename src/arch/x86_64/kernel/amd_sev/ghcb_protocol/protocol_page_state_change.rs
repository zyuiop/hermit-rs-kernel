use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use x86_64::structures::paging::{PageSize, PhysFrame, Size4KiB, Size2MiB};
use x86_64::addr::PhysAddr;
use x86_64::instructions::interrupts::without_interrupts;
use crate::arch::kernel::amd_sev::ghcb_protocol::GhcbProtocolError;
use crate::env::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;
use crate::env::kernel::amd_sev::ghcb_protocol::{checked_vmgexit, GhcbExitCode};
use crate::env::kernel::amd_sev::ghcb_protocol::protocol_page_state_change::PageStateChangePageSize::{PageSize2MB, PageSize4KB};

#[repr(C)]
struct PageStateChangeHeader {
    pub cur_entry: u16,
    pub end_entry: u16,
    _reserved: u32,
}

impl PageStateChangeHeader {
    pub fn new(num_entries: u16) -> Self {
        Self {
            cur_entry: 0,
            end_entry: num_entries,
            _reserved: 0
        }
    }
}

impl From<u64> for PageStateChangeHeader {
    fn from(value: u64) -> Self {
        Self {
            cur_entry: ((value >> 48) & 0xffff) as u16,
            end_entry: ((value >> 32) & 0xffff) as u16,
            _reserved: 0,
        }
    }
}

impl From<PageStateChangeHeader> for u64 {
    fn from(value: PageStateChangeHeader) -> Self {
        (value.cur_entry as u64) << 48 |
            (value.end_entry as u64) << 32
    }
}


pub struct PageStateChangeEntry(u64);

#[derive(PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum PageStateChangeOperation {
    PageAssignPrivate = 0x1,
    PageAssignShared = 0x2,
    PageSmash = 0x3,
    PageUnsmash = 0x4,
}

#[derive(PartialEq, Eq, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum PageStateChangePageSize {
    PageSize4KB = 0,
    PageSize2MB = 1,
}

impl PageStateChangeEntry {
    pub fn new_for_address(
        physical_address: PhysAddr,
        page_size: u64,
        operation: PageStateChangeOperation
    ) -> PageStateChangeEntry {
        let size = match page_size {
            Size4KiB::SIZE => PageSize4KB,
            Size2MiB::SIZE => PageSize2MB,
            other => panic!("unsupported page size: {other:x}")
        };

        unsafe {
            Self::from_raw_components(
                0, physical_address, operation, size
            )
        }
    }
    pub fn new_for_frame(
        physical_address: PhysFrame,
        operation: PageStateChangeOperation
    ) -> PageStateChangeEntry {
        let size = physical_address.size();
        let size = match size {
            Size4KiB::SIZE => PageSize4KB,
            Size2MiB::SIZE => PageSize2MB,
            other => panic!("unsupported page size: {other:x}")
        };

        unsafe {
            Self::from_raw_components(
                0, physical_address.start_address(), operation, size
            )
        }
    }

    pub unsafe fn from_raw_components(
        offset: u16,
        physical_address: PhysAddr,
        operation: PageStateChangeOperation,
        size: PageStateChangePageSize
    ) -> PageStateChangeEntry {
        let gfn: u64 = (physical_address.as_u64() >> 12) & 0xff_ffff_ffff; // 40 bits

        if size == PageStateChangePageSize::PageSize4KB {
            assert_eq!(offset, 0);
        }

        PageStateChangeEntry(
            (size.to_u64().unwrap() & 0x1) << 56 |
                (operation.to_u64().unwrap() & 0xf) << 52 |
                (gfn) << 12 |
                (offset as u64 & 0xfff)
        )
    }

    /// For 2MB page entries, the offset will be modified by the hypervisor
    pub fn offset(&self) -> u16 {
        (self.0 & 0xfff) as u16
    }

    pub fn operation(&self) -> Option<PageStateChangeOperation> {
        PageStateChangeOperation::from_u64((self.0 >> 52) & 0xf)
    }

    pub fn size(&self) -> Option<PageStateChangePageSize> {
        PageStateChangePageSize::from_u64((self.0 >> 56) & 0x1)
    }

    pub fn physical_address(&self) -> PhysAddr {
        let address = self.0 & 0xf_ffff_ffff_f000;

        PhysAddr::new(address)
    }
}

pub fn change_page_states(changes: &[PageStateChangeEntry]) -> Result<(), GhcbProtocolError> {
    assert!(changes.len() < 254); // The shared buffer of the GHCB cannot hold more than 254 entries

    let header_new = PageStateChangeHeader::new(changes.len() as u16);

    without_interrupts(|| with_ghcb(|ghcb| {
        ghcb.clear();
        ghcb.use_shared_buffer();

        let shared_buffer = &mut ghcb.shared_buffer;

        // SAFETY: ensure the array is big enough before transmuting it
        assert_eq!(shared_buffer.len(), 254 * 8);
        let shared_buffer: &mut [u64; 254] = unsafe { core::mem::transmute(shared_buffer) };

        shared_buffer[0] = header_new.into();

        let mut index = 1;
        for change in changes {
            shared_buffer[index] = change.0;
            index += 1;
        }

        // Write the request in the GHCB
        checked_vmgexit(ghcb, GhcbExitCode::PageStateChange, 0, 0)?;

        // TODO: verify the response in SW_EXITINFO2 (it may not be a full success!)

        Ok(())
    }))
}