use x86_64::instructions::interrupts::without_interrupts;

use super::allocated_ghcb::with_ghcb;
use super::ghcb::{Ghcb, GhcbU64Field};
use super::{checked_vmgexit, GhcbExitCode, GhcbProtocolError};

const INFO1_READ: u64 = 0;
const INFO1_WRITE: u64 = 1;

pub unsafe fn ghcb_rdmsr(msr: u32) -> u64 {
	without_interrupts(|| {
		with_ghcb(|ghcb| {
			let (mut high, mut low): (u64, u64) = (0, 0);
			rdmsr(ghcb, msr, &mut low, &mut high).unwrap();

			(high << 32) | low
		})
	})
}

pub unsafe fn ghcb_wrmsr(msr: u32, value: u64) {
	without_interrupts(|| {
		with_ghcb(|ghcb| {
			let (high, low) = (value >> 32 & 0xffff_ffff, value & 0xffff_ffff);
			wrmsr(ghcb, msr, low, high).unwrap();
		});
	})
}

pub fn rdmsr(
	ghcb: &mut Ghcb,
	msr: u32,
	out_rax: &mut u64,
	out_rdx: &mut u64,
) -> Result<(), GhcbProtocolError> {
	ghcb.set_field(GhcbU64Field::Rcx, msr.into());

	checked_vmgexit(ghcb, GhcbExitCode::MsrProtocol, INFO1_READ, 0)?;

	*out_rax = ghcb.get_field_if_valid(GhcbU64Field::Rax)? & 0xffff_ffff;
	*out_rdx = ghcb.get_field_if_valid(GhcbU64Field::Rdx)? & 0xffff_ffff;

	Ok(())
}

pub fn wrmsr(ghcb: &mut Ghcb, msr: u32, rax: u64, rdx: u64) -> Result<(), GhcbProtocolError> {
	ghcb.set_field(GhcbU64Field::Rcx, msr.into());

	ghcb.set_field(GhcbU64Field::Rax, rax & 0xffff_ffff);
	ghcb.set_field(GhcbU64Field::Rdx, rdx & 0xffff_ffff);

	checked_vmgexit(ghcb, GhcbExitCode::MsrProtocol, INFO1_WRITE, 0)?;

	Ok(())
}
