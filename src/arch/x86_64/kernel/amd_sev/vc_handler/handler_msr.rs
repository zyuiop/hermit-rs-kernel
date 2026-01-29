use crate::arch::kernel::amd_sev::ghcb_protocol::error_exit_codes;
use super::super::ghcb_protocol::{protocol_msr, GhcbProtocolError};

use crate::arch::kernel::amd_sev::vc_handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::InstructionData;
use crate::arch::kernel::amd_sev::opcodes::opcode::KnownOpcode;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::arch::kernel::amd_sev::vc_handler::VcHandler;

#[derive(Debug)]
pub struct MsrHandler;

impl VcHandler for MsrHandler {
	fn handle(
		&self,
		frame: &mut InterruptStackFrame,
		ghcb: &mut Ghcb,
		instruction_data: &mut InstructionData,
	) -> Result<(), GhcbProtocolError> {
		let opcode = instruction_data.operation();
        if opcode == KnownOpcode::WRMSR {
			protocol_msr::wrmsr(ghcb, frame.registers.rcx as u32, frame.registers.rax, frame.registers.rdx)
        } else if opcode == KnownOpcode::RDMSR {
			protocol_msr::rdmsr(ghcb, frame.registers.rcx as u32, &mut frame.registers.rax, &mut frame.registers.rdx)
        } else {
			sev_exit!(error_exit_codes::EXIT_VC_INVALIDOP, "invalid MSR opcode {opcode:?}")
        }
	}
}