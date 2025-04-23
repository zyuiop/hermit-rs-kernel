pub mod instruction_parser;
pub mod ioio_protocol;
mod opcodes;
pub(crate) mod vc_handler;
mod exitcodes;

pub use vc_handler::vmm_interrupt_exception;

use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::paging::{Mapper, Page, PageSize, Size4KiB, Translate};
use x86_64::structures::paging::mapper::TranslateResult;
use x86_64::structures::amd_sev::ghcb_msr_protocol::{vmgexit, GhcbMsrRequest, GhcbMsrResponse, GHCB_MSR};
use x86_64::structures::amd_sev::ghcb_protocol::Ghcb;
use x86_64::structures::idt::{InterruptDescriptorTable};
use crate::arch::interrupts::{ExceptionStackFrame};
use crate::arch::{BasePageSize};
use crate::arch::mm::paging::{identity_mapped_page_table};
use crate::{mm};

#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum SvmExitCodes {
    IOIO = 0x7b
}

pub struct IoIoExplicitProtocolExit<'a> {
    io_port: u16,
    data: IoIoExplicitProtocolExitData<'a>
}

pub enum IoIoExplicitProtocolExitData<'a> {
    StringOut(&'a [u8]),
    StringIn(&'a mut [u8]),

    ByteOut(u8),
    WordOut(u16),
    DblWordOut(u32),

    ByteIn(&'a mut u8),
    WordIn(&'a mut u16),
    DblWordIn(&'a mut u32),
}

pub enum VmgExitError {}


impl <'a> IoIoExplicitProtocolExit<'a> {
    pub fn new(io_port: u16, data: IoIoExplicitProtocolExitData<'a>) -> Self {
        Self { io_port, data }
    }

    pub fn write_to_ghcb(&self, ghcb: &mut Ghcb) {
        ghcb.clear();


    }

    pub fn read_response_from_ghcb(&self, ghcb: &Ghcb) {

    }

    pub fn execute(&self) -> Result<(), VmgExitError> {
        without_interrupts(|| {
            with_ghcb(|ghcb| {
                self.write_to_ghcb(ghcb);

                unsafe {
                    vmgexit();
                }

                self.read_response_from_ghcb(ghcb);

                Ok(())
            })
        })
    }
}

pub fn hyper_outb(io_line: u16, byte: u8) -> Result<(), VmgExitError> {
    IoIoExplicitProtocolExit::new(io_line, IoIoExplicitProtocolExitData::ByteOut(byte)).execute()
}

pub fn hyper_outw(io_line: u16, word: u16) -> Result<(), VmgExitError> {
    IoIoExplicitProtocolExit::new(io_line, IoIoExplicitProtocolExitData::WordOut(word)).execute()
}

pub fn hyper_outdw(io_line: u16, dword: u32) -> Result<(), VmgExitError> {
    IoIoExplicitProtocolExit::new(io_line, IoIoExplicitProtocolExitData::DblWordOut(dword)).execute()
}


pub fn hyper_inb_ref(io_line: u16, byte: &mut u8) -> Result<(), VmgExitError> {
    IoIoExplicitProtocolExit::new(io_line, IoIoExplicitProtocolExitData::ByteIn(byte)).execute()
}

pub fn hyper_inw_ref(io_line: u16, word: &mut u16) -> Result<(), VmgExitError> {
    IoIoExplicitProtocolExit::new(io_line, IoIoExplicitProtocolExitData::WordIn(word)).execute()
}

pub fn hyper_indw_ref(io_line: u16, dword: &mut u32) -> Result<(), VmgExitError> {
    IoIoExplicitProtocolExit::new(io_line, IoIoExplicitProtocolExitData::DblWordIn(dword)).execute()
}






/* 
#define GHCB_SHARED_BUF_SIZE	2032

struct ghcb {
	struct ghcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct ghcb_save_area)];

	u8 shared_buffer[GHCB_SHARED_BUF_SIZE];

	u8 reserved_0xff0[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
} __packed;
 */

pub use x86_64::structures::amd_sev::ghcb_msr_protocol::ghcb_request_exit;

const MAX_GHCB_PROTOCOL_VERSION: u16 = 1;

pub fn ghcb_negotiate_protocol() -> u64 {
    let data = GHCB_MSR.read_state();
    info!("Read GHCB MSR : {data:?}");
;
    let GhcbMsrResponse::SevInformation { max_proto, min_proto, c_bit_pos } =
        GHCB_MSR.send_request_restore(GhcbMsrRequest::SevRequest) else { panic!("Invalid GHCB MSR response"); };

    info!("Got GHCB protocol versions: max={max_proto}, min={min_proto} - c_bit_pos={c_bit_pos}");

    if max_proto < MAX_GHCB_PROTOCOL_VERSION || min_proto > MAX_GHCB_PROTOCOL_VERSION {
        panic!("GHCB version negotiation failed: wrong protocol version");
    }

    if MAX_GHCB_PROTOCOL_VERSION > max_proto {
        max_proto as u64
    } else {
        MAX_GHCB_PROTOCOL_VERSION as u64
    }
}


pub fn print_current_ghcb() {
    with_ghcb(|ghcb| {
        info!("Current GHCB: {ghcb:?}");
        info!("GHCB size: {}", size_of::<Ghcb>());
    });
}

pub fn with_ghcb<F, R>(f: F) -> R
where F: FnOnce(&mut Ghcb) -> R {
    let GhcbMsrResponse::GhcbPhysicalAddress(current_ghcb_addr) = GHCB_MSR.read_state() else { panic!("Invalid GHCB MSR response"); };
    let ptr: *mut Ghcb = current_ghcb_addr.as_u64() as *mut Ghcb;
    let ghcb = unsafe {
        ptr.as_mut().unwrap()
    };
    f(ghcb)
}

pub fn init_ghcb() {
    print_current_ghcb();

    info!("enter init_ghcb");
    // let ghcb_version = ghcb_negotiate_protocol();

    let ghcb_page = mm::allocate(Size4KiB::SIZE as usize, true);

    info!("GHCB memory allocated.");
    // TODO: make the page not encrypted
    let mut page_table = unsafe { identity_mapped_page_table() };
    let page: Page<BasePageSize> = Page::from_start_address(ghcb_page.into()).expect("invalid page address!");

    info!("GHCB memory address page resolved.");
    let TranslateResult::Mapped { frame, mut flags, offset } = page_table.translate(ghcb_page.into()) else { panic!("invalid page address!") };
    assert_eq!(offset, 0);

    info!("GHCB memory address page translated. Current flags: {flags:x} {flags:?}. Frame: {:x}", frame.start_address().as_u64());

    flags.set_encrypted(false);
    unsafe {
        page_table.update_flags(page, flags)
            .expect("failed to update page flags!")
            .flush()
    }

    info!("GHCB flags updated. Assigning GHCB...");

    let ptr: *mut Ghcb = ghcb_page.as_mut_ptr();
    let mut ghcb = Ghcb::default();
    ghcb.protocol_version = 1;
    unsafe {
        *ptr = ghcb;
    }

    info!("GHCB address: {:x}", frame.start_address().as_u64());
    unsafe {
        let address = frame.start_address().as_u64() >> 12;
        let ghcb_msr_v = ghcb_set_request_value(address, 0);
        info!("GHCB value: {:x}", ghcb_msr_v);
        // The value to set in the GHCB MSR is weird
        // info!("Write GHCB value: {ghcb_msr_v:x}.");
        GHCB_MSR.inner().write(ghcb_msr_v);

    }

    info!("MSR written.");

}

// A mask that selects the 52 MSbs
const GHCB_ADDR_MASK: u64 = 0x0f_ffff_ffff_ffff;

#[inline]
/// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56421.pdf
fn ghcb_set_request_value(address: u64, request_value: u64) -> u64 {
    (address & GHCB_ADDR_MASK) << 12 | request_value & 0x0fff
}