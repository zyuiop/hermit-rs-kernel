use super::super::ghcb_protocol::ghcb::{Ghcb, GhcbU64Field};
use super::super::ghcb_protocol::protocol_ioio::{IoIoExitFlags, IoIoExitInfo};
use super::super::ghcb_protocol::{
	checked_vmgexit, error_exit_codes, GhcbExitCode, GhcbProtocolError,
};
use super::super::vc_handler::{InterruptStackFrame, VcHandler};
use super::instruction_parser::InstructionData;

#[derive(Debug)]
pub struct IoIoHandler;

impl VcHandler for IoIoHandler {
	fn handle(
		&self,
		frame: &mut InterruptStackFrame,
		ghcb: &mut Ghcb,
		instruction_data: &mut InstructionData,
	) -> Result<(), GhcbProtocolError> {
		ghcb.clear();

		// Reference: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/CcExitLib/CcExitVcHandler.c#L910

		let info = IoIoExitInfo::from_instruction(instruction_data, &frame.registers);

		if info.flags.contains(IoIoExitFlags::STRING) {
			sev_exit!(
				error_exit_codes::EXIT_VC_NOT_IMPLEMENTED,
				"string based ioio is not implemented yet"
			);
		} else {
			/* is not in string mode */
			let rax = if info.flags.contains(IoIoExitFlags::INPUT) {
				0
			} else {
				let mask = info.flags.data_mask();
				frame.registers.rax & mask
			};
			ghcb.set_field(GhcbU64Field::Rax, rax);

			checked_vmgexit(ghcb, GhcbExitCode::IoIoProtocol, u32::from(&info) as u64, 0)?;

			if info.flags.contains(IoIoExitFlags::INPUT) {
				frame.registers.rax = ghcb.get_field_if_valid(GhcbU64Field::Rax)?;
			}

			Ok(())
		}
	}
}

impl From<&IoIoExitInfo> for u32 {
	fn from(value: &IoIoExitInfo) -> Self {
		(value.port as u32) << 16
			| ((value.segment_number & 0x7) as u32) << 10
			| (value.flags.bits() & 0x3f) as u32
	}
}
