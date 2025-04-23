use core::arch::asm;
use core::arch::naked_asm;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::amd_sev::ghcb_msr_protocol::{vmgexit, GhcbMsrRequest, GHCB_MSR};
use x86_64::structures::amd_sev::ghcb_protocol::{Ghcb, GhcbExitCode, GhcbProtocolError, GhcbSaveArea};
use x86_64::structures::idt::InterruptStackFrameValue;
use crate::arch::interrupts::ExceptionStackFrame;
use crate::arch::kernel::amd_sev::{ghcb_request_exit, instruction_parser, with_ghcb};
use crate::arch::kernel::amd_sev::handler_cpuid::CpuIdHandler;
use crate::env::kernel::amd_sev::handler_ioio::IoIoHandler;
use crate::env::kernel::amd_sev::handler_msr::MsrHandler;
use crate::env::kernel::amd_sev::instruction_parser::InstructionData;

#[naked]
pub extern "x86-interrupt" fn vmm_interrupt_exception(
    _stack_frame: ExceptionStackFrame,
    _code: u64
) {
    // https://github.com/llvm/llvm-project/issues/10965
    // 1. push all registers
    // 2. call the real function using normal conventions, with a ptr to the stack structure
    // 3. upon return, re-set the values from the stack structure (they can be modified!)

    unsafe {
        naked_asm!(
            // Save general purpose registers
            // Scratch registers (x64)
            "push r11",
            "push r10",
            "push r9",
            "push r8",

            // Scratch registers (x86)
            "push rdi",
            "push rsi",

            "push rdx",
            "push rcx",
            "push rbx",
            "push rax",

            // Provide stack address in the argument register
            "mov rdi, rsp",

            // Call the real handler
            "sub rsp, 0x20",
            "cld",
            "call {}",
            "add rsp, 0x20",

            // Restore registers
            // Scratch registers (x86)
            "pop rax",
            "pop rbx",
            "pop rcx",
            "pop rdx",

            "pop rsi",
            "pop rdi",

            "pop r8",
            "pop r9",
            "pop r10",
            "pop r11",

            // Skip error code! iretq expects the error code to have been popped
            "add rsp, 0x8",

            // Call iret
            "iretq",

            sym vmm_interrupt_exception_inner
        )
    }
}


#[repr(C)]
struct DebugDataStruct {
    pub error_code: u64,
    pub exception: InterruptStackFrameValue
}

extern "C" fn dump_data(data: &DebugDataStruct) {
    ghcb_debug_data(data.exception.instruction_pointer.as_u64(), (data as *const _ as *const ()) as u64);
}

pub extern "C" fn ghcb_debug_data(inf1: u64, inf2: u64) {
    with_ghcb(|ghcb| {
        ghcb.clear();
        ghcb.save.sw_exit_info_1 = inf1;
        ghcb.save.sw_exit_info_2 = inf2;
    });

    unsafe {
        vmgexit();
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct SavedRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct InterruptStackFrame {
    pub registers: SavedRegisters,
    pub error_code: u64,
    pub exception: InterruptStackFrameValue
}

static CTR: AtomicU64 = AtomicU64::new(0);

extern "C" fn vmm_interrupt_exception_inner(
    stack_frame: &mut InterruptStackFrame
) {
    debug!("VC# HANDLE: {stack_frame:#?}");
    without_interrupts(|| {
        with_ghcb(|ghcb| {
            let mut instruction = InstructionData::new(stack_frame.exception.instruction_pointer.as_ptr());

            do_handle(stack_frame, &mut instruction, stack_frame.error_code, ghcb);

            stack_frame.exception.instruction_pointer += instruction.offset() as u64;
        });
    });
    debug!("VC# handle done - return address: {:#?}", stack_frame.exception.instruction_pointer);
}

/// Custom exit codes to help with debugging
pub mod error_exit_codes {
    pub const EXIT_VC_INVALIDOP: u8 = 0x70;

    pub const EXIT_VC_UNHANDLED: u8 = 0x80;
    pub const EXIT_VC_ERROR: u8 = 0x81;
    pub const EXIT_VC_NOT_IMPLEMENTED: u8 = 0x82;

    // Errors
    pub const EXIT_VC_INVALID_EXCEPTION: u8 = 0x90;
    pub const EXIT_VC_MALFORMED_ERROR_INFO: u8 = 0x91;
    pub const EXIT_VC_INVALID_EXIT_CODE: u8 = 0x92;
    
    pub const EXIT_PARSE_ERROR: u8 = 0xa0;
    pub const EXIT_PARSE_UNHANDLED: u8 = 0xa1;

    pub const EXIT_OTHER: u8 = 0xff;
}

pub trait VcHandler {
    fn handle(&self,
              frame: &mut InterruptStackFrame,
              ghcb: &mut Ghcb,
              instruction_data: &mut InstructionData) -> Result<(), GhcbProtocolError>;
}

const HANDLERS: [Option<&'static dyn VcHandler>; 0xB0] = {
    let mut base: [Option<&'static dyn VcHandler>; 0xB0] = [None; 0xB0];

    base[GhcbExitCode::IoIoProtocol as usize] = Some(&IoIoHandler);
    base[GhcbExitCode::CPUID as usize] = Some(&CpuIdHandler);
    base[GhcbExitCode::MsrProtocol as usize] = Some(&MsrHandler);

    base
};

fn do_handle(stack_frame: &mut InterruptStackFrame,
             instruction_data: &mut InstructionData,
             code: u64,
             ghcb: &mut Ghcb) {

    // TODO: read per-cpu "vc exception count" ; if this is second, copy the ghcb
    // see backup routine in edk2: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/CcExitLib/SecCcExitVcHandler.c#L66

    // Read the exception information
    let exit_code = (code & 0xffff) as u16;
    let handler = HANDLERS.get(exit_code as usize);

    let result = match handler {
        Some(Some(handler)) => handler.handle(stack_frame, ghcb, instruction_data),
        _ => sev_exit!(error_exit_codes::EXIT_VC_UNHANDLED, "unhandled #VC event 0x{:x}", exit_code)
    };

    if let Err(e) = result {
        sev_exit!(error_exit_codes::EXIT_VC_ERROR, "protocol error while handling #VC event 0x{:x}: {:?}", code, e)
    }
}
