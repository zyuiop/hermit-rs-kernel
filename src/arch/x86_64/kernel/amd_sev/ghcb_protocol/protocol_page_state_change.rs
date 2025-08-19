use bitfield_struct::bitfield;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use x86_64::structures::paging::{PageSize, PhysFrame, Size4KiB, Size2MiB};
use x86_64::addr::PhysAddr;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::VirtAddr;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::GhcbU64Field;
use crate::arch::kernel::amd_sev::ghcb_protocol::GhcbProtocolError;
use crate::arch::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;
use crate::arch::kernel::amd_sev::ghcb_protocol::{checked_vmgexit, GhcbExitCode};
use crate::arch::kernel::amd_sev::ghcb_protocol::protocol_page_state_change::PageStateChangePageSize::{PageSize2MB, PageSize4KB};
use crate::arch::kernel::amd_sev::pvalidate::pvalidate_for_state_change;
use crate::fs::ioctl::IoCtlDirection;

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

#[bitfield(u64)]
pub struct PageStateChangeEntry {
    #[bits(12)]
    pub current_page: u16,
    #[bits(40)]
    pub frame_number: u64,
    #[bits(4, default = PageStateChangeOperation::PageAssignPrivate)]
    pub page_operation: PageStateChangeOperation,
    #[bits(1)]
    pub page_size: PageStateChangePageSize,
    #[bits(7, default = 0)]
    _mbz: u8,
}

#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum PageStateChangeOperation {
    PageAssignPrivate = 0x1,
    PageAssignShared = 0x2,
    PageSmash = 0x3,
    PageUnsmash = 0x4,
}

impl PageStateChangeOperation {
    const fn into_bits(self) -> u8 {
        self as _
    }

    const fn from_bits(value: u8) -> Self {
        match value {
            1 => Self::PageAssignPrivate,
            2 => Self::PageAssignShared,
            3 => Self::PageSmash,
            4 => Self::PageUnsmash,
            _ => panic!()
        }
    }
}

#[derive(Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum PageStateChangePageSize {
    PageSize4KB = 0,
    PageSize2MB = 1,
}

impl PageStateChangePageSize {
    const fn into_bits(self) -> u8 {
        self as _
    }

    const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::PageSize4KB,
            1 => Self::PageSize2MB,
            _ => panic!()
        }
    }
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
            other => panic!("unsupported page size: 0x{other:x}")
        };

        unsafe {
            Self::from_raw_components(
                0, physical_address, operation, size
            )
        }
    }
    pub fn new_for_frame<S: PageSize>(
        physical_address: PhysFrame<S>,
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

        PageStateChangeEntry::new()
            .with_page_size(size)
            .with_page_operation(operation)
            .with_frame_number(gfn)
            .with_current_page(offset)
    }

    pub fn address(&self) -> u64 {
        self.frame_number() << 12
    }

    pub fn physical_address(&self) -> PhysAddr {
        PhysAddr::new(self.address())
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ChangePageStateError {
    GhcbProtocolError(GhcbProtocolError),
    /// The page state change request was interrupted. Retry the request.
    Interrupted,
    /// The header of the page change structure is invalid
    InvalidHeader,
    /// The change entry is invalid
    InvalidEntry(PageStateChangeEntry),

    /// Unsmash error for the given entry
    UnsmashError(PageStateChangeEntry, u32),

    RMPOverlap(PageStateChangeEntry),

    UnknownError(PageStateChangeEntry)
}

pub fn change_page_states(changes: &[PageStateChangeEntry]) -> Result<(), ChangePageStateError> {
    assert!(changes.len() < 254); // The shared buffer of the GHCB cannot hold more than 254 entries

    let mut chg_header = PageStateChangeHeader::new(changes.len() as u16);

    let (exit1, exit2, chg_header) = without_interrupts(|| with_ghcb(|ghcb| {
        ghcb.clear();
        ghcb.use_shared_buffer();

        // SAFETY: ensure the array is big enough before transmuting it
        assert_eq!(ghcb.shared_buffer_size(), 254 * 8);


        unsafe {
            let shared_buffer = ghcb.shared_buffer_raw_mut();
            let mut shared_buffer: *mut u64 = shared_buffer as *mut u64;

            shared_buffer.write_volatile(chg_header.into());
            shared_buffer = shared_buffer.add(1);

            for change in changes {
                shared_buffer.write_volatile(change.0);
                shared_buffer = shared_buffer.add(1);
            }
        }

        // Write the request in the GHCB
        checked_vmgexit(ghcb, GhcbExitCode::PageStateChange, 0, 0)?;

        unsafe {
            let shared_buffer = ghcb.shared_buffer_raw_mut();
            let mut shared_buffer: *mut u64 = shared_buffer as *mut u64;

            let read = shared_buffer.read_volatile();
            chg_header = read.into();
        }

        Ok((ghcb.get_field_if_valid(GhcbU64Field::SwExitInfo1)?, ghcb.get_field_if_valid(GhcbU64Field::SwExitInfo2)?, chg_header))
    })).map_err(|e| ChangePageStateError::GhcbProtocolError(e))?;

    if exit2 == 0 {
        // warn!("Page State Change error: interrupted");
        // This seems to happen all the time
        return Ok(())
    };

    let high_bytes = (exit2 >> 32) as u32;
    let low_bytes = (exit2 & 0xffff_ffff) as u32;

    info!("{exit2} ==> {high_bytes} {low_bytes}");
    if high_bytes == 1 {
        if low_bytes == 1 {
            Err(ChangePageStateError::InvalidHeader)
        } else if low_bytes == 2 {
            Err(ChangePageStateError::InvalidEntry(changes[chg_header.cur_entry as usize].clone()))
        } else {
            panic!("unknown error code")
        }
    } else if high_bytes == 2 {
        return Err(ChangePageStateError::UnsmashError(changes[chg_header.cur_entry as usize].clone(), low_bytes))
    } else if high_bytes == 3 {
        let entry = &changes[chg_header.cur_entry as usize];
        if low_bytes == 0x1 {
            warn!("SNP: requested a page state change at physical address {:?} to state {:?}, but the hypervisor signaled that the page was already in that state", entry.physical_address(), entry.page_operation());
            Ok(())
        } else if low_bytes == 0x2 {
            error!("SNP: RMP overlap - 4kB/3MB at physical address {:?}", entry.physical_address());
            Err(ChangePageStateError::RMPOverlap(entry.clone()))
        } else {
            panic!("unknown error code")
        }
    } else if high_bytes == 0x100 {
        Err(ChangePageStateError::UnknownError(changes[chg_header.cur_entry as usize].clone()))
    } else {
        warn!("Unknown error code: {exit2:x}");
        Err(ChangePageStateError::UnknownError(changes[chg_header.cur_entry as usize].clone()))
    }
}

#[cfg(all(test))]
mod tests {
    use crate::arch::kernel::amd_sev::ghcb_protocol::protocol_page_state_change::{PageStateChangeEntry, PageStateChangePageSize};
    use crate::arch::kernel::amd_sev::ghcb_protocol::protocol_page_state_change::PageStateChangeOperation;

    #[test]
    fn page_state_change_bitfield_is_correct() {
        let offset = 0;
        let size = PageStateChangePageSize::PageSize4KB;
        let operation = PageStateChangeOperation::PageAssignShared;

        let physical_address = 0xc000000000u64;
        let gfn: u64 = (physical_address >> 12) & 0xff_ffff_ffff; // 40 bits

        if size == PageStateChangePageSize::PageSize4KB {
            assert_eq!(offset, 0);
        }

        let entry = PageStateChangeEntry::new()
            .with_page_size(size)
            .with_page_operation(operation)
            .with_frame_number(gfn)
            .with_current_page(offset);


        let size = u8::from(size) as u64;
        let operation = u8::from(operation) as u64;

        let expected =
            (size & 0x1) << 56 |
                (operation & 0xf) << 52 |
                (gfn) << 12 |
                (offset as u64 & 0xfff);

        assert_eq!(entry.0, expected);
    }
}