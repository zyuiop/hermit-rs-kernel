use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::registers::xcontrol::XCr0;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::GhcbU64Field;
use super::super::ghcb_protocol::{
	checked_vmgexit, GhcbExitCode, GhcbProtocolError,
};

use crate::arch::kernel::amd_sev::vc_handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::InstructionData;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::env::kernel::amd_sev::cc_blob::CC_BLOB;
use crate::env::kernel::amd_sev::opcodes::opcode::KnownOpcode;
use crate::env::kernel::amd_sev::vc_handler::VcHandler;

#[derive(Debug)]
pub struct CpuIdHandler;

// Restricted CPUID calls

impl VcHandler for CpuIdHandler {
	fn handle(
		&self,
		frame: &mut InterruptStackFrame,
		ghcb: &mut Ghcb,
		idata: &mut InstructionData,
	) -> Result<(), GhcbProtocolError> {
		assert_eq!(unsafe { idata.operation() }, KnownOpcode::CPUID);

		// XCr0 is not always accessible: it must be enabled by a special Cr4 flag
		// Check the flag (and the need to use Xcr0) before accessing it
		let xcr0 = if frame.registers.rax == 0x0000_000d {
			let cr4_flags = Cr4::read();

			if cr4_flags.contains(Cr4Flags::OSXSAVE) {
				XCr0::read_raw()
			} else {
				0
			}
		} else {
			0
		};

		let existing = CC_BLOB.cpuid().get_cpuid((frame.registers.rax & 0xffff_ffff) as u32, (frame.registers.rcx & 0xffff_ffff) as u32, xcr0);
		if let Some(existing) = existing {
			frame.registers.rax = existing.eax as u64;
			frame.registers.rbx = existing.ebx as u64;
			frame.registers.rcx = existing.ecx as u64;
			frame.registers.rdx = existing.edx as u64;

			return Ok(());
		}

		if frame.registers.rax == 0x8000_001F {
			// This frame regulates the AMD SEV features - we don't want to get it in an insecure way
			panic!("Encrypted memory capabilities CPUID function must be secured by hypervisor in CPUID page!");
		}

		ghcb.clear();
		ghcb.set_field(GhcbU64Field::Rax, frame.registers.rax);
		ghcb.set_field(GhcbU64Field::Rcx, frame.registers.rcx);

		// Need XCR0 if CPUID 0000_000d
		if frame.registers.rax == 0x0000_000d {
			ghcb.set_field(GhcbU64Field::XCr0, xcr0);
		}

		checked_vmgexit(ghcb, GhcbExitCode::CPUID, 0, 0)?;

        frame.registers.rax = ghcb.get_field_if_valid(GhcbU64Field::Rax)? & 0xffff_ffff;
        frame.registers.rbx = ghcb.get_field_if_valid(GhcbU64Field::Rbx)? & 0xffff_ffff;
        frame.registers.rcx = ghcb.get_field_if_valid(GhcbU64Field::Rcx)? & 0xffff_ffff;
        frame.registers.rdx = ghcb.get_field_if_valid(GhcbU64Field::Rdx)? & 0xffff_ffff;

        Ok(())
	}
}
