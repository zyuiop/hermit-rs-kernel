use core::arch::naked_asm;
use core::sync::atomic::AtomicU64;
use x86_64::instructions::interrupts::without_interrupts;
use super::ghcb_protocol::{GhcbExitCode, GhcbProtocolError};
use x86_64::structures::idt::InterruptStackFrameValue;
use crate::arch::interrupts::ExceptionStackFrame;
use super::ghcb_protocol::error_exit_codes;
use super::instruction_parser;
use super::ghcb_protocol::allocated_ghcb::with_ghcb;
use super::ghcb_protocol::ghcb::Ghcb;
use super::ghcb_protocol::checked_vmgexit;
use super::instruction_parser::InstructionData;

mod handler_cpuid;
mod handler_ioio;
mod handler_mmio;
mod handler_msr;
mod handler_rmp_invalid;

#[unsafe(naked)]
pub extern "x86-interrupt" fn vmm_interrupt_exception(
    _stack_frame: ExceptionStackFrame,
    _code: u64
) {
    // https://github.com/llvm/llvm-project/issues/10965
    // 1. push all registers
    // 2. call the real function using normal conventions, with a ptr to the stack structure
    // 3. upon return, re-set the values from the stack structure (they can be modified!)
    naked_asm!(
        // Save general purpose registers
        "push rbp",

        // Scratch registers (x64)
        "push r15",
        "push r14",
        "push r13",
        "push r12",
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
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "pop rbp",

        // Skip error code! iretq expects the error code to have been popped
        "add rsp, 0x8",

        // Call iret
        "iretq",

        sym vmm_interrupt_exception_inner
    )
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
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rbp: u64,
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
    if stack_frame.error_code == FAULT_RMP_NOT_VALIDATED as u64 {
        handler_rmp_invalid::handle_rmp_invalid(stack_frame);
        return;
    }


    without_interrupts(|| {
        with_ghcb(|ghcb| {
            let mut instruction = InstructionData::new(stack_frame.exception.instruction_pointer.as_ptr());

            do_handle(stack_frame, &mut instruction, stack_frame.error_code, ghcb);

            stack_frame.exception.instruction_pointer += instruction.size() as u64;
        });
    });
    debug!("VC# handle done - return address: {:#?}", stack_frame.exception.instruction_pointer);
}

pub trait VcHandler {
    fn handle(&self,
              frame: &mut InterruptStackFrame,
              ghcb: &mut Ghcb,
              instruction_data: &mut InstructionData) -> Result<(), GhcbProtocolError>;
}

const HANDLERS: [Option<&'static dyn VcHandler>; 0xB0] = {
    let mut base: [Option<&'static dyn VcHandler>; 0xB0] = [None; 0xB0];

    base[GhcbExitCode::IoIoProtocol as usize] = Some(&handler_ioio::IoIoHandler);
    base[GhcbExitCode::CPUID as usize] = Some(&handler_cpuid::CpuIdHandler);
    base[GhcbExitCode::MsrProtocol as usize] = Some(&handler_msr::MsrHandler);

    base
};

const FAULT_NPF: usize = 0x400;
const FAULT_RMP_NOT_VALIDATED: usize = 0x404;

const FAULT_HANDLERS: [Option<&'static dyn VcHandler>; 0x4] = {
    let mut base: [Option<&'static dyn VcHandler>; 0x4] = [None; 0x4];

    base[FAULT_NPF & 0xff] = Some(&handler_mmio::MmioHandler);

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
    let handler = if exit_code & 0x400 != 0 { FAULT_HANDLERS.get((exit_code as usize) & 0xff) } else { HANDLERS.get(exit_code as usize) };

    let result = match handler {
        Some(Some(handler)) => handler.handle(stack_frame, ghcb, instruction_data),
        _ => {
            error!("unhandled #VC event 0x{:x} at instruction 0x{:x}", exit_code, stack_frame.exception.instruction_pointer);
            unsupported_exit(ghcb, code)
        }
    };

    if let Err(e) = result {
        sev_exit!(error_exit_codes::EXIT_VC_ERROR, "protocol error while handling #VC event 0x{:x}: {:?}", code, e)
    }
}

fn unsupported_exit(ghcb: &mut Ghcb, exit_code: u64) -> Result<(), GhcbProtocolError> {
    checked_vmgexit(ghcb, GhcbExitCode::UnsupportedEvent, exit_code, 0)
}
