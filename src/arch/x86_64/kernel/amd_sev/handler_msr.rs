use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::amd_sev::ghcb_protocol::{checked_vmgexit, Ghcb, GhcbExitCode, GhcbProtocolError};

use crate::arch::kernel::amd_sev::handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::InstructionData;
use crate::env::kernel::amd_sev::handler::{error_exit_codes, VcHandler};
use crate::env::kernel::amd_sev::with_ghcb;

#[derive(Debug)]
pub struct MsrHandler;

const OPCODE_WRMSR: u16 = 0x0f_30;
const OPCODE_RDMSR: u16 = 0x0f_32;

const INFO1_READ: u64 = 0;
const INFO1_WRITE: u64 = 1;

pub unsafe fn ghcb_rdmsr(msr: u32) -> u64 {
	without_interrupts(|| {
		with_ghcb(|ghcb| {
			let (mut high, mut low): (u64, u64) = (0, 0);
			unsafe { rdmsr(ghcb, msr, &mut low, &mut high).unwrap() };

			(high << 32) | low
		})
	})
}

pub unsafe fn ghcb_wrmsr(msr: u32, value: u64) {
	without_interrupts(|| {
		with_ghcb(|ghcb| {
			let (high, low) = (value >> 32 & 0xffff_ffff, value & 0xffff_ffff);
			unsafe { wrmsr(ghcb, msr, low, high).unwrap() }
		});
	})
}

unsafe fn rdmsr(ghcb: &mut Ghcb, msr: u32, out_rax: &mut u64, out_rdx: &mut u64) -> Result<(), GhcbProtocolError> {
	ghcb.save.rcx = msr as u64;
	ghcb.save.set_valid_field(&ghcb.save.rcx);

	checked_vmgexit(ghcb, GhcbExitCode::MsrProtocol, INFO1_READ, 0)?;

	// Read results
	if !ghcb.save.is_valid_field(&ghcb.save.rax) || !ghcb.save.is_valid_field(&ghcb.save.rdx) {
		sev_exit!(error_exit_codes::EXIT_VC_ERROR, "invalid VMM response: registers rax and rdx should be valid")
	}

	*out_rax = ghcb.save.rax & 0xffff_ffff;
	*out_rdx = ghcb.save.rdx & 0xffff_ffff;

	Ok(())
}

unsafe fn wrmsr(ghcb: &mut Ghcb, msr: u32, rax: u64, rdx: u64) -> Result<(), GhcbProtocolError> {
	ghcb.save.rax = rax & 0xffff_ffff;
	ghcb.save.rcx = msr as u64;
	ghcb.save.rdx = rdx & 0xffff_ffff;

	ghcb.save.set_valid_field(&ghcb.save.rax);
	ghcb.save.set_valid_field(&ghcb.save.rcx);
	ghcb.save.set_valid_field(&ghcb.save.rdx);

	checked_vmgexit(ghcb, GhcbExitCode::MsrProtocol, INFO1_WRITE, 0)?;

	Ok(())
}

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
				wrmsr(ghcb, frame.registers.rcx as u32, frame.registers.rax, frame.registers.rdx)
			}
        } else if opcode == OPCODE_RDMSR {
			unsafe {
				rdmsr(ghcb, frame.registers.rcx as u32, &mut frame.registers.rax, &mut frame.registers.rdx)
			}
        } else {
			sev_exit!(error_exit_codes::EXIT_VC_INVALIDOP, "invalid MSR opcode {opcode:x}")
        }


	}
}