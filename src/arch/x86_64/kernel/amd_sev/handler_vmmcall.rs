use x86_64::instructions::interrupts::without_interrupts;
use super::ghcb_protocol::{checked_vmgexit, Ghcb, GhcbExitCode, GhcbProtocolError};
use crate::arch::kernel::amd_sev::handler::{error_exit_codes, InterruptStackFrame};
use crate::arch::kernel::amd_sev::instruction_parser::InstructionData;
use crate::env::kernel::amd_sev::with_ghcb;
use super::handler::VcHandler;

pub struct VmmCallHandler;

pub struct Hypercalls {
    pub map_gpa_range: Hypercall3Args
}

pub const HYPERCALLS: Hypercalls = Hypercalls::new();

impl Hypercalls {
    const fn new() -> Self {
        Hypercalls {
            map_gpa_range: Hypercall3Args(12)
        }
    }

    pub fn get(&self, index: u64) -> Option<&dyn HypercallRaw> {
        match index {
            12 => Some(&self.map_gpa_range),
            _ => None
        }
    }
}

trait HypercallRaw {
    unsafe fn send_raw(&self, frame: &mut InterruptStackFrame, ghcb: &mut Ghcb) -> Result<(), GhcbProtocolError> {
        frame.registers.rax = self.send_raw_values(ghcb, frame.registers.rbx, frame.registers.rcx, frame.registers.rdx, frame.registers.rsi)?;

        Ok(())
    }

    unsafe fn send_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, rdx: u64, rsi: u64) -> Result<u64, GhcbProtocolError> {
        self.write_raw_values(ghcb, rbx, rcx, rdx, rsi);

        // CPL ?
        ghcb.save.set_valid_field(&ghcb.save.cpl);

        checked_vmgexit(ghcb, GhcbExitCode::VmmCall, 0, 0)?;

        if !ghcb.save.is_valid_field(&ghcb.save.rax) {
            sev_exit!(error_exit_codes::EXIT_VC_ERROR, "expected valid value in RAX register");
        }

        Ok(ghcb.save.rax)
    }

    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, rdx: u64, rsi: u64);
}

#[repr(transparent)]
pub struct HypercallNoArg(u64);
#[repr(transparent)]
pub struct Hypercall1Arg(u64);
#[repr(transparent)]
pub struct Hypercall2Args(u64);
#[repr(transparent)]
pub struct Hypercall3Args(u64);
#[repr(transparent)]
pub struct Hypercall4Args(u64);

impl HypercallRaw for HypercallNoArg {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, _rbx: u64, _rcx: u64, _rdx: u64, _rsi: u64) {
        ghcb.save.rax = self.0;
        ghcb.save.set_valid_field(&ghcb.save.rax);
    }
}

impl HypercallRaw for Hypercall1Arg {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, _rcx: u64, _rdx: u64, _rsi: u64) {
        ghcb.save.rax = self.0;
        ghcb.save.rbx = rbx;
        ghcb.save.set_valid_field(&ghcb.save.rax);
        ghcb.save.set_valid_field(&ghcb.save.rbx);
    }
}

impl HypercallRaw for Hypercall2Args {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, _rdx: u64, _rsi: u64) {
        ghcb.save.rax = self.0;
        ghcb.save.rbx = rbx;
        ghcb.save.rcx = rcx;
        ghcb.save.set_valid_field(&ghcb.save.rax);
        ghcb.save.set_valid_field(&ghcb.save.rbx);
        ghcb.save.set_valid_field(&ghcb.save.rcx);
    }
}

impl HypercallRaw for Hypercall3Args {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, rdx: u64, _rsi: u64) {
        ghcb.save.rax = self.0;
        ghcb.save.rbx = rbx;
        ghcb.save.rcx = rcx;
        ghcb.save.rdx = rdx;
        ghcb.save.set_valid_field(&ghcb.save.rax);
        ghcb.save.set_valid_field(&ghcb.save.rbx);
        ghcb.save.set_valid_field(&ghcb.save.rcx);
        ghcb.save.set_valid_field(&ghcb.save.rdx);
    }
}

impl HypercallRaw for Hypercall4Args {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, rdx: u64, rsi: u64) {
        ghcb.save.rax = self.0;
        ghcb.save.rbx = rbx;
        ghcb.save.rcx = rcx;
        ghcb.save.rdx = rdx;
        ghcb.save.rsi = rsi;
        ghcb.save.set_valid_field(&ghcb.save.rax);
        ghcb.save.set_valid_field(&ghcb.save.rbx);
        ghcb.save.set_valid_field(&ghcb.save.rcx);
        ghcb.save.set_valid_field(&ghcb.save.rdx);
        ghcb.save.set_valid_field(&ghcb.save.rsi);
    }
}


impl HypercallNoArg {
    pub fn call(&self) -> Result<u64, GhcbProtocolError> {
        without_interrupts(|| {
            with_ghcb(|ghcb| {
                unsafe { self.send_raw_values(ghcb, 0, 0, 0, 0) }
            })
        })
    }
}

impl Hypercall1Arg {
    pub fn call(&self, arg1: u64) -> Result<u64, GhcbProtocolError> {
        without_interrupts(|| {
            with_ghcb(|ghcb| {
                unsafe { self.send_raw_values(ghcb, arg1, 0, 0, 0) }
            })
        })
    }
}

impl Hypercall2Args {
    pub fn call(&self, arg1: u64, arg2: u64) -> Result<u64, GhcbProtocolError> {
        without_interrupts(|| {
            with_ghcb(|ghcb| {
                unsafe { self.send_raw_values(ghcb, arg1, arg2, 0, 0) }
            })
        })
    }
}

impl Hypercall3Args {
    pub fn call(&self, arg1: u64, arg2: u64, arg3: u64) -> Result<u64, GhcbProtocolError> {
        without_interrupts(|| {
            with_ghcb(|ghcb| {
                unsafe { self.send_raw_values(ghcb, arg1, arg2, arg3, 0) }
            })
        })
    }
}

impl Hypercall4Args {
    pub fn call(&self, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> Result<u64, GhcbProtocolError> {
        without_interrupts(|| {
            with_ghcb(|ghcb| {
                unsafe { self.send_raw_values(ghcb, arg1, arg2, arg3, arg4) }
            })
        })
    }
}

impl VcHandler for VmmCallHandler {
    fn handle(&self, frame: &mut InterruptStackFrame, ghcb: &mut Ghcb, instruction_data: &mut InstructionData) -> Result<(), GhcbProtocolError> {
        todo!()
    }
}