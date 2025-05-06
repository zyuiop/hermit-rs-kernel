use x86_64::instructions::interrupts::without_interrupts;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::arch::kernel::amd_sev::ghcb_protocol::{checked_vmgexit, GhcbExitCode, GhcbProtocolError};
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;

use super::error_exit_codes;

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

pub unsafe fn rdmsr(ghcb: &mut Ghcb, msr: u32, out_rax: &mut u64, out_rdx: &mut u64) -> Result<(), GhcbProtocolError> {
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

pub unsafe fn wrmsr(ghcb: &mut Ghcb, msr: u32, rax: u64, rdx: u64) -> Result<(), GhcbProtocolError> {
	ghcb.save.rax = rax & 0xffff_ffff;
	ghcb.save.rcx = msr as u64;
	ghcb.save.rdx = rdx & 0xffff_ffff;

	ghcb.save.set_valid_field(&ghcb.save.rax);
	ghcb.save.set_valid_field(&ghcb.save.rcx);
	ghcb.save.set_valid_field(&ghcb.save.rdx);

	checked_vmgexit(ghcb, GhcbExitCode::MsrProtocol, INFO1_WRITE, 0)?;

	Ok(())
}