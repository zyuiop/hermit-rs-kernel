use super::ghcb_protocol::{checked_vmgexit, Ghcb, GhcbExitCode, GhcbProtocolError};
use crate::env::kernel::amd_sev::ghcb_request_exit;
use crate::env::kernel::amd_sev::handler::{error_exit_codes, InterruptStackFrame, SavedRegisters, VcHandler};
use super::instruction_parser::{InstructionData, InstructionRepetitionMode, Size};
use super::opcodes::io_opcode;

#[derive(Debug)]
pub struct IoIoHandler;

impl VcHandler for IoIoHandler {
	fn handle(&self, frame: &mut InterruptStackFrame, ghcb: &mut Ghcb, instruction_data: &mut InstructionData) -> Result<(), GhcbProtocolError> {
		ghcb.clear();

		// Reference: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/CcExitLib/CcExitVcHandler.c#L910

		let info = IoIoExitInfo::from_instruction(instruction_data, &frame.registers);

		if info.flags.contains(IoIoExitFlags::STRING) {
			ghcb_request_exit(error_exit_codes::EXIT_VC_NOT_IMPLEMENTED);
			todo!("string mode")
		} else {
			/* is not in string mode */
			ghcb.save.rax = if info.flags.contains(IoIoExitFlags::INPUT) {
				0
			} else {
				let mask = info.flags.data_mask();
				frame.registers.rax & mask
			};

			ghcb.save.set_valid_field(& ghcb.save.rax);

			checked_vmgexit(ghcb, GhcbExitCode::IoIoProtocol, u32::from(&info) as u64, 0)?;

			if info.flags.contains(IoIoExitFlags::INPUT) {
				if !ghcb.save.is_valid_field(& ghcb.save.rax) {
					sev_exit!(error_exit_codes::EXIT_VC_ERROR, "invalid VMM response: rax is invalid");
				}
				frame.registers.rax = ghcb.save.rax;
			}

			Ok(())
		}
	}
}


#[derive(Copy, Clone)]
pub(super) struct IoIoExitInfo {
	pub(super) port: u16,
	pub(super) segment_number: u8,
	pub(super) flags: IoIoExitFlags,
}

impl From<&IoIoExitInfo> for u32 {
	fn from(value: &IoIoExitInfo) -> Self {
		(value.port as u32) << 16
			| ((value.segment_number & 0x7) as u32) << 10
			| (value.flags.bits() & 0x3f) as u32
	}
}

impl IoIoExitInfo {
	/// Parse an instruction into IoIo exit information
	pub fn from_instruction(idata: &mut InstructionData, registers_data: &SavedRegisters) -> IoIoExitInfo {
		let mut out = IoIoExitInfo {
			port: 0,
			segment_number: 0,
			flags: IoIoExitFlags::empty(),
		};

		let opcode = unsafe { idata.read_opcode() };
		let opcode = if opcode & 0xff == opcode {
			opcode as u8
		} else {
			sev_exit!(error_exit_codes::EXIT_VC_INVALIDOP, "invalid ioio opcode {opcode:x}")
		};

		match opcode {
			io_opcode::INS_BYTE | io_opcode::INS_WORDS => {
				out.flags.insert(IoIoExitFlags::INPUT);
				out.flags.insert(IoIoExitFlags::STRING);
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			io_opcode::OUTS_BYTE | io_opcode::OUTS_WORDS => {
				out.flags.insert(IoIoExitFlags::STRING);
				out.segment_number = 0x3; // DS segment
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			io_opcode::IN_BYTE_IMM | io_opcode::IN_WORDS_IMM => {
				out.flags.insert(IoIoExitFlags::INPUT);

				// Read immediate value
				out.port = unsafe { idata.read_byte() as u16 };
			}
			io_opcode::OUT_BYTE_IMM | io_opcode::OUT_WORDS_IMM => {
				// Read immediate value
				out.port = unsafe { idata.read_byte() as u16 };
			}
			io_opcode::IN_BYTE_DX | io_opcode::IN_WORDS_DX => {
				out.flags.insert(IoIoExitFlags::INPUT);
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			io_opcode::OUT_BYTE_DX | io_opcode::OUT_WORDS_DX => {
				out.port = (registers_data.rdx & 0xffff) as u16;
			}
			_ => {
				sev_exit!(error_exit_codes::EXIT_VC_INVALIDOP, "invalid ioio opcode {opcode:x}");
			},
		};

		// Determine data size
		out.flags.insert(match opcode {
			io_opcode::OUT_BYTE_IMM
			| io_opcode::OUT_BYTE_DX
			| io_opcode::OUTS_BYTE
			| io_opcode::IN_BYTE_IMM
			| io_opcode::IN_BYTE_DX
			| io_opcode::INS_BYTE => IoIoExitFlags::DATA_8B,
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

		if idata.repetition_mode() != InstructionRepetitionMode::None {
			out.flags.insert(IoIoExitFlags::REPEAT)
		}

		out
	}
}

bitflags! {
	#[derive(Debug, Copy, Clone, Default)]
	pub(super) struct IoIoExitFlags: u16 {
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
