use core::arch::asm;
use core::arch::naked_asm;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::amd_sev::ghcb_protocol::Ghcb;
use x86_64::structures::idt::InterruptStackFrameValue;
use crate::arch::interrupts::ExceptionStackFrame;
use crate::arch::kernel::amd_sev::{ghcb_request_exit, instruction_parser, with_ghcb};
use crate::arch::kernel::amd_sev::ioio_protocol::handle_ioio;
use crate::env::kernel::amd_sev::instruction_parser::InstructionData;
use crate::env::kernel::amd_sev::SvmExitCodes;

pub struct RegistersData {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rip: u64
}

impl RegistersData {
    pub fn new() -> Self {
        let mut rax = 0;
        let mut rcx = 0;
        let mut rdx = 0;
        let mut rip = 0; // is already on the stack (TODO)

        unsafe {
            asm!(
                "mov eax, {:e}",
                "mov ecx, {:e}",
                "mov edx, {:e}",
                out(reg) rax,
                out(reg) rcx,
                out(reg) rdx,
            )
        }

        Self { rax, rcx, rdx, rip }
    }
}


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
            // Only save the scratch registers, as the preserved ones will be saved by the CALL
            // In addition, save RSP,  RBP (will be modified)

            // Scratch registers (x64)
            "mov [rsp - 0x08], r11",
            "mov [rsp - 0x10], r10",
            "mov [rsp - 0x18], r9",
            "mov [rsp - 0x20], r8",

            // Preserved registers (modified by this code)
            "mov [rsp - 0x28], rbp",

            // Scratch registers (x86)
            "mov [rsp - 0x30], rdx",
            "mov [rsp - 0x38], rcx",
            "mov [rsp - 0x40], rbx",
            "mov [rsp - 0x48], rax",

            "mov [rsp - 0x50], rdi",
            "mov [rsp - 0x58], rsi",

            // Save segment registers
            "mov ax, fs",
            "mov [rsp - 0x5a], ax",
            "mov ax, gs",
            "mov [rsp - 0x5c], ax",

            // Save the stack pointer & move it
            "sub rsp, 0x60",

            // Provide stack address in the argument register
            "mov rcx, rsp",

            // Call the real handler
            "sub rsp, 0x20",
            "cld",
            "call {}",
            "add rsp, 0x20",

            // Restore the stack
            "add rsp, 0x60",

            // Restore segment registers
            "mov ax, [rsp - 0x5a]",
            "mov gs, ax",
            "mov ax, [rsp - 0x5c]",
            "mov fs, ax",

            // Restore registers
            // Scratch registers (x64)
            "mov r11, [rsp - 0x08]",
            "mov r10, [rsp - 0x10]",
            "mov r9, [rsp - 0x18]",
            "mov r8, [rsp - 0x20]",

            // Preserved registers (modified by this code)
            "mov rbp, [rsp - 0x28]",

            // Scratch registers (x86)
            "mov rdx, [rsp - 0x30]",
            "mov rcx, [rsp - 0x38]",
            "mov rbx, [rsp - 0x40]",
            "mov rax, [rsp - 0x48]",
            "mov rdi, [rsp - 0x50]",
            "mov rsi, [rsp - 0x58]",

            // Call iret
            "iretq",

            sym vmm_interrupt_exception_inner,
        )
    }
}

#[repr(C)]
pub struct SavedRegisters {
    /* for stack alignment, stack must be 16 byte aligned */
    _reserved: [u8; 8],
    // Manually pushed stack frame
    //pub gs: u16,
    //pub fs: u16,

    pub rsi: u64,
    pub rdi: u64,

    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,

    pub rbp: u64,

    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
}

#[repr(C)]
pub struct InterruptStackFrame {
    pub registers: SavedRegisters,
    pub error_code: u64,
    pub exception: InterruptStackFrameValue
}

extern "efiapi" fn vmm_interrupt_exception_inner(
    stack_frame: &mut InterruptStackFrame
) {

    without_interrupts(|| {
        with_ghcb(|ghcb| {
            let mut instruction = InstructionData::new(stack_frame.exception.instruction_pointer.as_ptr());

            do_handle(stack_frame, &mut instruction, stack_frame.error_code, ghcb);

            stack_frame.exception.instruction_pointer += instruction.offset() as u64;

            // ghcb_request_exit(instruction.offset() as u8);
        });
    });


}

pub mod error_exit_codes {
    pub const EXIT_VC_INVALIDOP: u8 = 0x70;

    pub const EXIT_VC_UNHANDLED: u8 = 0x80;
    pub const EXIT_VC_ERROR: u8 = 0x81;
    pub const EXIT_VC_NOT_IMPLEMENTED: u8 = 0x82;

    // Errors
    pub const EXIT_VC_INVALID_EXCEPTION: u8 = 0x90;
    pub const EXIT_VC_MALFORMED_ERROR_INFO: u8 = 0x91;
    pub const EXIT_VC_INVALID_EXIT_CODE: u8 = 0x92;

    pub const EXIT_OTHER: u8 = 0xff;
}

fn do_handle(registers_data: &mut InterruptStackFrame,
             instruction_data: &mut InstructionData,
             code: u64,
             ghcb: &mut Ghcb) {

    // TODO: read per-cpu "vc exception count" ; if this is second, copy the ghcb
    // see backup routine in edk2: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/CcExitLib/SecCcExitVcHandler.c#L66

    // Read the exception information
    let exit_code = (code & 0xffff) as u16;

    let result = match exit_code {
        x if x == SvmExitCodes::IOIO as u16 => {
            handle_ioio(ghcb, instruction_data, registers_data)
        },
        other => {
            ghcb_request_exit(error_exit_codes::EXIT_VC_UNHANDLED);
            // panic!("unhandled #VC event {:x} ({:?})", code, other)
        }
    };

    if let Err(e) = result {
        ghcb_request_exit(error_exit_codes::EXIT_VC_ERROR);
        // panic!("protocol error while handling #VC event {:x} ({:?}): {:?}", code, exit_code, e)
    }
}