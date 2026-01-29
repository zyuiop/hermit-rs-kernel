use x86_64::instructions::interrupts::without_interrupts;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::GhcbU64Field;
use crate::arch::kernel::amd_sev::vc_handler::SavedRegisters;
use crate::arch::kernel::amd_sev::instruction_parser::{InstructionData, Size};
use crate::arch::kernel::amd_sev::opcodes::opcode::KnownOpcode;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use super::{checked_vmgexit, error_exit_codes, GhcbExitCode, GhcbProtocolError};
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;

pub struct IoIoExplicitProtocolExit<'a> {
    io_port: u16,
    data: IoIoExplicitProtocolExitData<'a>
}

#[derive(Debug)]
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

        ghcb.set_field(GhcbU64Field::Rax, match &self.data {
            IoIoExplicitProtocolExitData::ByteOut(b) => *b as u64,
            IoIoExplicitProtocolExitData::WordOut(w) => *w as u64,
            IoIoExplicitProtocolExitData::DblWordOut(dw) => *dw as u64,
            IoIoExplicitProtocolExitData::ByteIn(_) | IoIoExplicitProtocolExitData::WordIn(_) | IoIoExplicitProtocolExitData::DblWordIn(_) => {
                0
            }
            _ => sev_exit!(error_exit_codes::EXIT_OTHER, "not implemented: string operations are not implemented in the explicit IOIO handler")
        });
    }

    fn read_response_from_ghcb(&mut self, ghcb: &Ghcb) {
        let Ok(rax) = ghcb.get_field_if_valid(GhcbU64Field::Rax) else {
            sev_exit!(error_exit_codes::EXIT_VC_ERROR, "invalid VMM response: rax is invalid");
        };

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

#[inline]
pub fn out_u32(port: u16, val: u32) {
    IoIoExplicitProtocolExit::new(port, IoIoExplicitProtocolExitData::DblWordOut(val)).execute().unwrap()
}


#[inline]
pub fn in_u32(port: u16) -> u32 {
    let mut ret: u32 = 0;
    IoIoExplicitProtocolExit::new(port, IoIoExplicitProtocolExitData::DblWordIn(&mut ret)).execute().unwrap();
    ret
}

#[inline]
pub fn inb(port: u16) -> u8 {
    let mut ret: u8 = 0;
    IoIoExplicitProtocolExit::new(port, IoIoExplicitProtocolExitData::ByteIn(&mut ret)).execute().unwrap();
    ret
}

bitflags! {
	#[derive(Debug, Copy, Clone, Default)]
	pub(crate) struct IoIoExitFlags: u16 {
		const INPUT = 1 << 0;
		const STRING = 1 << 2;
		const REPEAT = 1 << 3;

		const DATA_8B = 1 << 4;
		const DATA_16B = 1 << 5;
		const DATA_32B = 1 << 6;

		const ADDR_16B = 1 << 7;
		const ADDR_32B = 1 << 8;
		const ADDR_64B = 1 << 9;
	}
}

impl IoIoExitFlags {
    pub fn data_mask(&self) -> u64 {
        if self.contains(Self::DATA_8B) {
            0xff
        } else if self.contains(Self::DATA_16B) {
            0xff_ff
        } else if self.contains(Self::DATA_32B) {
            0xff_ff_ff_ff
        } else {
            sev_exit!(error_exit_codes::EXIT_OTHER, "invalid exit flags structure")
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct IoIoExitInfo {
	pub(crate) port: u16,
	pub(crate) segment_number: u8,
	pub(crate) flags: IoIoExitFlags,
}

impl IoIoExitInfo {
	/// Parse an instruction into IoIo exit information
	pub fn from_instruction(idata: &mut InstructionData, registers_data: &SavedRegisters) -> IoIoExitInfo {
		let mut out = IoIoExitInfo {
			port: 0,
			segment_number: 0,
			flags: IoIoExitFlags::empty(),
		};
        
		match idata.operation() {
            KnownOpcode::IoInsByte | KnownOpcode::IoInsWords => {
				out.flags.insert(IoIoExitFlags::INPUT);
				out.flags.insert(IoIoExitFlags::STRING);
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			KnownOpcode::IoOutsByte | KnownOpcode::IoOutsWords => {
				out.flags.insert(IoIoExitFlags::STRING);
				out.segment_number = 0x3; // DS segment
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			KnownOpcode::IoInByteImm | KnownOpcode::IoInWordsImm => {
				out.flags.insert(IoIoExitFlags::INPUT);

				// Read immediate value
				out.port = unsafe { idata.read_immediate(1)[0] as u16 };
			}
			KnownOpcode::IoOutByteImm | KnownOpcode::IoOutWordsImm => {
				// Read immediate value
				out.port = unsafe { idata.read_immediate(1)[0] as u16 };
			}
			KnownOpcode::IoInByteDx | KnownOpcode::IoInWordsDx => {
				out.flags.insert(IoIoExitFlags::INPUT);
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			KnownOpcode::IoOutByteDx | KnownOpcode::IoOutWordsDx => {
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			other => {
				sev_exit!(error_exit_codes::EXIT_VC_INVALIDOP, "invalid ioio opcode {other:?}");
			},
		};

		// Determine data size
		out.flags.insert(match idata.operation() {
			KnownOpcode::IoOutByteImm
			| KnownOpcode::IoOutByteDx
			| KnownOpcode::IoOutsByte
			| KnownOpcode::IoInByteImm
			| KnownOpcode::IoInByteDx
			| KnownOpcode::IoInsByte => IoIoExitFlags::DATA_8B,
			_ => {
				if idata.operand_size() == Size::Size16Bits {
					IoIoExitFlags::DATA_16B
				} else {
					IoIoExitFlags::DATA_32B
				}
			}
		});

		// Determine address size
		out.flags.insert(match idata.address_size() {
			Size::Size16Bits => IoIoExitFlags::ADDR_16B,
			Size::Size32Bits => IoIoExitFlags::ADDR_32B,
			Size::Size64Bits => IoIoExitFlags::ADDR_64B,
		});

		if idata.repetition_mode().is_some() {
			out.flags.insert(IoIoExitFlags::REPEAT)
		}

		out
	}
}