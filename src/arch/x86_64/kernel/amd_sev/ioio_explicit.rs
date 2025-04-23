use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::amd_sev::ghcb_protocol::{checked_vmgexit, error_exit_codes, Ghcb, GhcbExitCode, GhcbProtocolError};
use super::ioio_handler::{IoIoExitInfo,IoIoExitFlags};
use super::with_ghcb;

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

impl <'a> From<&IoIoExplicitProtocolExit<'a>> for IoIoExitInfo {
    fn from(value: &IoIoExplicitProtocolExit<'a>) -> Self {
        let mut info = IoIoExitInfo {
            port: value.io_port,
            segment_number: 0,
            flags: IoIoExitFlags::empty(),
        };

        match value.data {
            IoIoExplicitProtocolExitData::StringOut(_) => {
                info.flags.insert(IoIoExitFlags::STRING);
            }
            IoIoExplicitProtocolExitData::StringIn(_) => {
                info.flags.insert(IoIoExitFlags::STRING);
                info.flags.insert(IoIoExitFlags::INPUT);
            }
            IoIoExplicitProtocolExitData::ByteOut(_) => {
                info.flags.insert(IoIoExitFlags::DATA_8B);
            }
            IoIoExplicitProtocolExitData::WordOut(_) => {
                info.flags.insert(IoIoExitFlags::DATA_16B);
            }
            IoIoExplicitProtocolExitData::DblWordOut(_) => {
                info.flags.insert(IoIoExitFlags::DATA_32B);
            }
            IoIoExplicitProtocolExitData::ByteIn(_) => {
                info.flags.insert(IoIoExitFlags::DATA_8B);
                info.flags.insert(IoIoExitFlags::INPUT);
            }
            IoIoExplicitProtocolExitData::WordIn(_) => {
                info.flags.insert(IoIoExitFlags::DATA_16B);
                info.flags.insert(IoIoExitFlags::INPUT);
            }
            IoIoExplicitProtocolExitData::DblWordIn(_) => {
                info.flags.insert(IoIoExitFlags::DATA_32B);
                info.flags.insert(IoIoExitFlags::INPUT);
            }
        }

        info
    }
}
impl <'a> IoIoExplicitProtocolExit<'a> {
    pub fn new(io_port: u16, data: IoIoExplicitProtocolExitData<'a>) -> Self {
        Self { io_port, data }
    }

    fn write_to_ghcb(&self, ghcb: &mut Ghcb) {
        ghcb.clear();

        ghcb.save.rax = match &self.data {
            IoIoExplicitProtocolExitData::ByteOut(b) => *b as u64,
            IoIoExplicitProtocolExitData::WordOut(w) => *w as u64,
            IoIoExplicitProtocolExitData::DblWordOut(dw) => *dw as u64,
            IoIoExplicitProtocolExitData::ByteIn(_) | IoIoExplicitProtocolExitData::WordIn(_) | IoIoExplicitProtocolExitData::DblWordIn(_) => {
                0
            }
            _ => sev_exit!(error_exit_codes::EXIT_OTHER, "not implemented: string operations are not implemented in the explicit IOIO handler")
        };
        ghcb.save.set_valid_field(& ghcb.save.rax);
    }

    fn read_response_from_ghcb(&mut self, ghcb: &Ghcb) {
        if !ghcb.save.is_valid_field(&ghcb.save.rax) {
            sev_exit!(error_exit_codes::EXIT_VC_ERROR, "invalid VMM response: rax is invalid");
        }

        let rax = ghcb.save.rax;
        match &mut self.data {
            IoIoExplicitProtocolExitData::ByteIn(b) => **b = (rax & 0xff) as u8,
            IoIoExplicitProtocolExitData::WordIn(w) => **w = (rax & 0xffff) as u16,
            IoIoExplicitProtocolExitData::DblWordIn(dw) => **dw = (rax & 0xffff_ffff) as u32,
            IoIoExplicitProtocolExitData::ByteOut(_) | IoIoExplicitProtocolExitData::WordOut(_) | IoIoExplicitProtocolExitData::DblWordOut(_) => {
                /* nothing to do */
            }
            _ => sev_exit!(error_exit_codes::EXIT_OTHER, "not implemented: string operations are not implemented in the explicit IOIO handler")
        };
    }

    pub fn execute(mut self) -> Result<(), GhcbProtocolError> {
        without_interrupts(|| {
            with_ghcb(|ghcb| {
                let info: IoIoExitInfo = (&self).into();

                self.write_to_ghcb(ghcb);

                checked_vmgexit(ghcb, GhcbExitCode::IoIoProtocol, u32::from(&info) as u64, 0)?;

                if info.flags.contains(IoIoExitFlags::INPUT) {
                    self.read_response_from_ghcb(ghcb);
                }

                Ok(())
            })
        })
    }
}


#[inline]
pub fn outb(port: u16, val: u8) {
    IoIoExplicitProtocolExit::new(port, IoIoExplicitProtocolExitData::ByteOut(val)).execute().unwrap()
}

/// Read 8 bits from port
///
/// # Safety
/// Needs IO privileges.
#[inline]
pub fn inb(port: u16) -> u8 {
    let mut ret: u8 = 0;
    IoIoExplicitProtocolExit::new(port, IoIoExplicitProtocolExitData::ByteIn(&mut ret)).execute().unwrap();
    ret
}
