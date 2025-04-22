use core::arch::asm;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::amd_sev::ghcb_protocol::Ghcb;
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


/* #[naked]
pub extern "x86-interrupt" fn vmm_interrupt_exception(
    stack_frame: ExceptionStackFrame,
    code: u64
) {
    // https://github.com/llvm/llvm-project/issues/10965
    // 1. push all registers
    // 2. call the real function using normal conventions, with a ptr to the stack structure
    // 3. upon return, re-set the values from the stack structure (they can be modified!)
} */

pub extern "x86-interrupt" fn vmm_interrupt_exception(
    stack_frame: ExceptionStackFrame,
    code: u64
) {
    let mut data = RegistersData::new();

    without_interrupts(|| {
        with_ghcb(|ghcb| {
            let mut instruction = instruction_parser::InstructionData::new(stack_frame.instruction_pointer.as_ptr());

            do_handle(&mut data, &mut instruction, code, stack_frame, ghcb);

            data.rip += instruction.offset() as u64;
        });
    });

    ghcb_request_exit(42);
}

pub mod error_exit_codes {
    pub const EXIT_VC_INVALIDOP: u8 = 0x70;
    
    pub const EXIT_VC_UNHANDLED: u8 = 0x80;
    pub const EXIT_VC_ERROR: u8 = 0x81;
    pub const EXIT_VC_NOT_IMPLEMENTED: u8 = 0x82;

    pub const EXIT_OTHER: u8 = 0xff;
}

fn do_handle(registers_data: &mut RegistersData,
             instruction_data: &mut InstructionData,
             code: u64,
             stack_frame: ExceptionStackFrame,
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