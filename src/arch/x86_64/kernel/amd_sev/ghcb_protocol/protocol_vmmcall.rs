use x86_64::instructions::interrupts::without_interrupts;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::GhcbU64Field;
use super::{checked_vmgexit, GhcbExitCode, GhcbProtocolError};
use crate::arch::kernel::amd_sev::vc_handler::InterruptStackFrame;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;


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
        frame.registers.rax = unsafe { self.send_raw_values(ghcb, frame.registers.rbx, frame.registers.rcx, frame.registers.rdx, frame.registers.rsi)? };

        Ok(())
    }

    unsafe fn send_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, rdx: u64, rsi: u64) -> Result<u64, GhcbProtocolError> {
        unsafe {
            self.write_raw_values(ghcb, rbx, rcx, rdx, rsi);
        }

        checked_vmgexit(ghcb, GhcbExitCode::VmmCall, 0, 0)?;

        ghcb.get_field_if_valid(GhcbU64Field::Rax)
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
        ghcb.set_field(GhcbU64Field::Rax, self.0);
    }
}

impl HypercallRaw for Hypercall1Arg {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, _rcx: u64, _rdx: u64, _rsi: u64) {
        ghcb.set_field(GhcbU64Field::Rax, self.0);
        ghcb.set_field(GhcbU64Field::Rbx, rbx);
    }
}

impl HypercallRaw for Hypercall2Args {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, _rdx: u64, _rsi: u64) {
        ghcb.set_field(GhcbU64Field::Rax, self.0);
        ghcb.set_field(GhcbU64Field::Rbx, rbx);
        ghcb.set_field(GhcbU64Field::Rcx, rcx);
    }
}

impl HypercallRaw for Hypercall3Args {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, rdx: u64, _rsi: u64) {
        ghcb.set_field(GhcbU64Field::Rax, self.0);
        ghcb.set_field(GhcbU64Field::Rbx, rbx);
        ghcb.set_field(GhcbU64Field::Rcx, rcx);
        ghcb.set_field(GhcbU64Field::Rdx, rdx);
    }
}

impl HypercallRaw for Hypercall4Args {
    unsafe fn write_raw_values(&self, ghcb: &mut Ghcb, rbx: u64, rcx: u64, rdx: u64, rsi: u64) {
        ghcb.set_field(GhcbU64Field::Rax, self.0);
        ghcb.set_field(GhcbU64Field::Rbx, rbx);
        ghcb.set_field(GhcbU64Field::Rcx, rcx);
        ghcb.set_field(GhcbU64Field::Rdx, rdx);
        ghcb.set_field(GhcbU64Field::Rsi, rsi);
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