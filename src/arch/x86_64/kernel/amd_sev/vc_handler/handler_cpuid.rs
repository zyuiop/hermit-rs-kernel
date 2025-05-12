use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::registers::xcontrol::XCr0;
use crate::arch::core_local::core_id;
use super::super::ghcb_protocol::{
	checked_vmgexit, GhcbExitCode, GhcbProtocolError,
};

use crate::arch::kernel::amd_sev::vc_handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::InstructionData;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::env::kernel::amd_sev::vc_handler::{error_exit_codes, VcHandler};

#[derive(Debug)]
pub struct CpuIdHandler;

impl VcHandler for CpuIdHandler {
	fn handle(
		&self,
		frame: &mut InterruptStackFrame,
		ghcb: &mut Ghcb,
		idata: &mut InstructionData,
	) -> Result<(), GhcbProtocolError> {
        // TODO(SNP): v2 request is different

        assert_eq!(unsafe { idata.read_opcode() }, 0x0f_a2);
		if core_id() > 1 {
			info!("CPU ID HANDLE {:p}", ghcb as *const Ghcb);
		}

		ghcb.clear();
		ghcb.save.rax = frame.registers.rax;
		ghcb.save.rcx = frame.registers.rcx;

		ghcb.save.set_valid_field(&ghcb.save.rax);
		ghcb.save.set_valid_field(&ghcb.save.rcx);

		// Need XCR0 if CPUID 0000_000d
		if frame.registers.rax == 0x0000_000d {
			let cr4_flags = Cr4::read();

			if cr4_flags.contains(Cr4Flags::OSXSAVE) {
				ghcb.save.xcr0 = XCr0::read_raw();
			}
			ghcb.save.set_valid_field(&ghcb.save.xcr0);
		}

		checked_vmgexit(ghcb, GhcbExitCode::CPUID, 0, 0)?;

		// Check that all values are valid
		if !ghcb.save.is_valid_field(&ghcb.save.rax)
			|| !ghcb.save.is_valid_field(&ghcb.save.rbx)
			|| !ghcb.save.is_valid_field(&ghcb.save.rcx)
			|| !ghcb.save.is_valid_field(&ghcb.save.rdx)
		{
            sev_exit!(error_exit_codes::EXIT_VC_ERROR, "invalid VMM response: registers rax/rbx/rcx/rdx should all be valid")
        }

        frame.registers.rax = ghcb.save.rax & 0xffff_ffff;
        frame.registers.rbx = ghcb.save.rbx & 0xffff_ffff;
        frame.registers.rcx = ghcb.save.rcx & 0xffff_ffff;
        frame.registers.rdx = ghcb.save.rdx & 0xffff_ffff;

        Ok(())
	}
}
