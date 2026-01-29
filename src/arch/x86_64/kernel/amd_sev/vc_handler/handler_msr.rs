use super::super::ghcb_protocol::{protocol_msr, error_exit_codes, GhcbProtocolError};

use super::InterruptStackFrame;
use super::VcHandler;
use super::super::instruction_parser::InstructionData;
use super::super::opcodes::opcode::KnownOpcode;
use super::super::ghcb_protocol::ghcb::Ghcb;

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