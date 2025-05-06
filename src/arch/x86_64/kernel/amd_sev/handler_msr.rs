use x86_64::instructions::interrupts::without_interrupts;
use super::ghcb_protocol::{checked_vmgexit, protocol_msr, GhcbExitCode, GhcbProtocolError};

use crate::arch::kernel::amd_sev::handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::InstructionData;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::env::kernel::amd_sev::handler::{error_exit_codes, VcHandler};
use crate::env::kernel::amd_sev::with_ghcb;

const OPCODE_WRMSR: u16 = 0x0f_30;
const OPCODE_RDMSR: u16 = 0x0f_32;

#[derive(Debug)]
pub struct MsrHandler;

impl VcHandler for MsrHandler {
	fn handle(
		&self,
		frame: &mut InterruptStackFrame,
		ghcb: &mut Ghcb,
		instruction_data: &mut InstructionData,
	) -> Result<(), GhcbProtocolError> {
        let opcode = unsafe { instruction_data.read_opcode() };

        if opcode == OPCODE_WRMSR {
			unsafe {
				protocol_msr::wrmsr(ghcb, frame.registers.rcx as u32, frame.registers.rax, frame.registers.rdx)
			}
        } else if opcode == OPCODE_RDMSR {
			unsafe {
				protocol_msr::rdmsr(ghcb, frame.registers.rcx as u32, &mut frame.registers.rax, &mut frame.registers.rdx)
			}
        } else {
			sev_exit!(error_exit_codes::EXIT_VC_INVALIDOP, "invalid MSR opcode {opcode:x}")
        }


	}
}