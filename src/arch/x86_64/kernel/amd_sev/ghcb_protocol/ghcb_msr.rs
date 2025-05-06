use core::arch::asm;
use x86_64::PhysAddr;
use x86_64::registers::model_specific::Msr;

pub const GHCB_MSR: GhcbMsr = GhcbMsr::new();

#[derive(Debug)]
pub struct GhcbMsr(Msr);

#[derive(Copy, Clone, Debug)]
pub enum GhcbMsrRequest {
    SetGhcbPhysicalAddress(PhysAddr),
    SevRequest,
    RequestTermination {
        source: u8,
        reason: u8
    },
    PreferredGhcbGPA,
    RegisterGhcbGPA(PhysAddr),
}

impl Into<u64> for GhcbMsrRequest {
    fn into(self) -> u64 {
        match self {
            GhcbMsrRequest::SetGhcbPhysicalAddress(addr) =>
            // Request code: 0x000 ; parameters: address bits 63..12
                addr.as_u64() & 0xffff_ffff_ffff_f000,
            GhcbMsrRequest::SevRequest =>
            // Request code: 0x002, no parameters
                0x002,
            GhcbMsrRequest::RequestTermination { source, reason } =>
                0x100u64 | (source as u64 & 0xf) << 12 | (reason as u64) << 16,
            GhcbMsrRequest::PreferredGhcbGPA => 0x010,
            GhcbMsrRequest::RegisterGhcbGPA(addr) =>
                0x012 | (addr.as_u64() & 0xffff_ffff_ffff_f000)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GhcbMsrResponse {
    SevInformation {
        max_proto: u16,
        min_proto: u16,
        c_bit_pos: u8,
    },
    GhcbPhysicalAddress(PhysAddr),
    UnknownResponse(u64),
    PreferredGhcbGPA(Option<PhysAddr>),
    RegisterGhcbGPA(Option<PhysAddr>),
}

impl From<u64> for GhcbMsrResponse {
    fn from(value: u64) -> Self {
        let resp_code = value & 0xfff;

        match resp_code {
            0x000 => GhcbMsrResponse::GhcbPhysicalAddress(PhysAddr::new(value)),
            0x001 => {
                let max_proto = ((value >> 48) & 0xffff) as u16;
                let min_proto = ((value >> 32) & 0xffff) as u16;
                let c_bit_pos = ((value >> 24) & 0xff) as u8;

                GhcbMsrResponse::SevInformation {
                    c_bit_pos, max_proto, min_proto
                }
            }
            0x011 => GhcbMsrResponse::PreferredGhcbGPA(
                if value & 0xffff_ffff_ffff_f000 == 0xffff_ffff_ffff_f000 { None }
                else { Some(PhysAddr::new(value & 0xffff_ffff_ffff_f000)) }
            ),
            0x013 => GhcbMsrResponse::RegisterGhcbGPA(
                if value & 0xffff_ffff_ffff_f000 == 0xffff_ffff_ffff_f000 { None }
                else { Some(PhysAddr::new(value & 0xffff_ffff_ffff_f000)) }
            ),
            _ => GhcbMsrResponse::UnknownResponse(value)
        }
    }
}

pub fn ghcb_request_exit(exit_code: u8) -> ! {
    GHCB_MSR.send_request_noret(GhcbMsrRequest::RequestTermination {
        reason: exit_code,
        source: 2,
    });
}

pub unsafe fn vmgexit() {
    /*
    KVM Hypercalls have a three-byte sequence of either the vmcall or the vmmcall
     instruction. The hypervisor can replace it with instructions that are
     guaranteed to be supported.

    Up to four arguments may be passed in rbx, rcx, rdx, and rsi respectively.
     The hypercall number should be placed in rax and the return value will be
     placed in rax.  No other registers will be clobbered unless explicitly stated
     by the particular hypercall.
    */

    unsafe {
        asm!("rep; vmmcall\n\r");
    }
}

impl GhcbMsr {
    const fn new() -> Self {
        Self(Msr::new(0xC001_0130))
    }

    pub unsafe fn send_request(&self, request: GhcbMsrRequest) -> GhcbMsrResponse {
        let mut msr = Msr::new(0xC001_0130);
        unsafe {
            msr.write(request.into());
            vmgexit();
            msr.read().into()
        }
    }

    pub unsafe fn write_request(&self, request: GhcbMsrRequest) {
        let mut msr = Msr::new(0xC001_0130);
        unsafe {
            msr.write(request.into());
        }
    }

    pub fn send_request_noret(&self, request: GhcbMsrRequest) -> ! {
        let mut msr = Msr::new(0xC001_0130);
        unsafe {
            msr.write(request.into());
            vmgexit();
            unreachable!("execution should have stopped")
        }
    }

    /// Writes a command using the GHCB protocol and restores the value that was previously set
    /// This makes sure that EFI GHCB handlers can still access the GHCB page
    pub fn send_request_restore(&self, request: GhcbMsrRequest) -> GhcbMsrResponse {
        let mut msr = Msr::new(0xC001_0130);
        unsafe {
            let orig = msr.read();
            msr.write(request.into());
            vmgexit();
            let ret = msr.read().into();
            msr.write(orig);
            ret
        }
    }

    pub fn inner(&mut self) -> &mut Msr {
        &mut self.0
    }

    pub fn read_state(&self) -> GhcbMsrResponse {
        unsafe {
            self.0.read().into()
        }
    }
}