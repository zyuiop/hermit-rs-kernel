use x86_64::structures::idt::InterruptStackFrameValue;
use memory_addresses::VirtAddr;
use crate::arch::kernel::amd_sev::handler::InterruptStackFrame;
use crate::env::kernel::amd_sev::instruction_parser::InstructionData;

enum OpCode {

}

pub mod io_opcode {
    /// Read a byte in the AL register from the port specified by an 8-bit immediate value
    pub const IN_BYTE_IMM: u8 = 0xE4;

    /// Read a (double) word in the (E)AX register from the port specified by an 8-bit immediate value
    pub const IN_BYTE_DX: u8 = 0xEC;


    /// Read a byte in the AL register from the port specified in the DX register
    pub const IN_WORDS_IMM: u8 = 0xE5;


    /// Read a (double) word in the (E)AX register from the port specified in the DX register
    pub const IN_WORDS_DX: u8 = 0xED;

    pub const INS_BYTE: u8 = 0x6C;
    pub const INS_WORDS: u8 = 0x6D;

    /// Writes the byte in the AL register to the port specified by an 8-bit immediate value
    pub const OUT_BYTE_IMM: u8 = 0xE6;

    /// Writes the (double) word in the AL register to the port specified by an 8-bit immediate value
    pub const OUT_WORDS_IMM: u8 = 0xE7;

    /// Writes the byte in the AL register to the port specified in the DX register
    pub const OUT_BYTE_DX: u8 = 0xEE;

    /// Writes the (double) word in the AL register to the port specified in the DX register
    pub const OUT_WORDS_DX: u8 = 0xEF;


    pub const OUTS_BYTE: u8 = 0x6E;
    pub const OUTS_WORDS: u8 = 0x6F;
}


pub mod opcode_prefix {
    pub const OVERRIDE_SEGMENT_CS: u8 = 0x2E;
    pub const OVERRIDE_SEGMENT_DS: u8 = 0x3E;
    pub const OVERRIDE_SEGMENT_ES: u8 = 0x26;
    pub const OVERRIDE_SEGMENT_SS: u8 = 0x36;
    pub const OVERRIDE_SEGMENT_FS: u8 = 0x64;
    pub const OVERRIDE_SEGMENT_GS: u8 = 0x65;

    pub const OVERRIDE_OPERAND_SIZE: u8 = 0x66;
    pub const OVERRIDE_ADDRESS_SIZE: u8 = 0x67;

    pub const REP_NZ: u8 = 0xF2;
    pub const REP_Z: u8 = 0xF3;

    pub const TWO_BYTE_ESCAPE: u8 = 0x0F;

    pub const LOCK: u8 = 0xF0;
}

bitflags! {
    #[derive(Clone, Copy)]
    pub struct RegisterExtensions: u8 {
        const BitB = 1 << 0;
        const ExtendSibIndex = 1 << 1;
        const ExtendModRmReg = 1 << 2;

        /// If enabled, operand size is 64-niz
        const BitW = 1 << 3;
    }
}


const REX_PREFIX_START: u8 = 0x40;
const REX_PREFIX_END: u8 = 0x4F;
impl RegisterExtensions {
    pub fn from_opcode(opcode: u8) -> Option<RegisterExtensions> {
        if opcode >= REX_PREFIX_START && opcode <= REX_PREFIX_END {
            Some(RegisterExtensions::from_bits_truncate(opcode))
        } else {
            None
        }
    }
}


/// See AMD programmers manual volume 3, section 1.4
#[repr(transparent)]
pub struct InstructionModRMData(pub u8);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ModRmMode {
    MemoryNoDisplacement,
    Memory8BitsDisplacement,
    Memory32BitsDisplacement,
    Register
}

const MODES: [ModRmMode; 4] = [
    ModRmMode::MemoryNoDisplacement, // 00
    ModRmMode::Memory8BitsDisplacement, // 01
    ModRmMode::Memory32BitsDisplacement, // 10
    ModRmMode::Register, // 11
];


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Register {
    Rax, Rcx, Rdx, Rbx,
    Rsp, Rbp, Rsi, Rdi
}

impl Register {
    fn get_register(&self, frame: &InterruptStackFrame) -> u64 {
        match self {
            Register::Rax => frame.registers.rax,
            Register::Rcx => frame.registers.rcx,
            Register::Rdx => frame.registers.rdx,
            Register::Rbx => frame.registers.rbx,
            Register::Rsp => frame.exception.stack_pointer.as_u64(),
            Register::Rbp => frame.registers.rbp,
            Register::Rsi => frame.registers.rsi,
            Register::Rdi => frame.registers.rdi
        }
    }

    fn as_ptr(&self, frame: &InterruptStackFrame) -> *const u8 {
        match self {
            Register::Rax => &frame.registers.rax as *const _ as *const u8,
            Register::Rcx => &frame.registers.rcx as *const _ as *const u8,
            Register::Rdx => &frame.registers.rdx as *const _ as *const u8,
            Register::Rbx => &frame.registers.rbx as *const _ as *const u8,
            Register::Rsp => &frame.exception.stack_pointer as *const _ as *const u8,
            Register::Rbp => &frame.registers.rbp as *const _ as *const u8,
            Register::Rsi => &frame.registers.rsi as *const _ as *const u8,
            Register::Rdi => &frame.registers.rdi as *const _ as *const u8
        }
    }

    fn as_mut_ptr(&self, frame: &mut InterruptStackFrame) -> *mut u8 {
        let reference = self.get_register_mut(frame);
        reference as *mut _ as *mut u8
    }

    fn get_register_mut<'a>(&self, frame: &'a mut InterruptStackFrame) -> &'a mut u64 {
        match self {
            Register::Rax => &mut frame.registers.rax,
            Register::Rcx => &mut frame.registers.rcx,
            Register::Rdx => &mut frame.registers.rdx,
            Register::Rbx => &mut frame.registers.rbx,
            Register::Rsp => unsafe { ((&mut frame.exception.stack_pointer) as *mut _ as *mut u64).as_mut().unwrap() },
            Register::Rbp => &mut frame.registers.rbp,
            Register::Rsi => &mut frame.registers.rsi,
            Register::Rdi => &mut frame.registers.rdi
        }
    }

}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum RegisterOrMemory {
    Register(Register),
    MemoryOffset(Register),
    RelativeToInstruction,
    SIB
}

const REGISTERS: [Register; 8] = [
    Register::Rax, Register::Rcx, Register::Rdx, Register::Rbx,
    Register::Rsp, Register::Rbp, Register::Rsi, Register::Rdi
];

impl InstructionModRMData {

    /// Returns the mode of this modifier
    pub fn modrm_mode(&self) -> ModRmMode {
        MODES[(self.0 >> 6 & 0x3) as usize]
    }

    /// Returns the register indicated by this modifier
    pub fn register(&self) -> Register  {
        REGISTERS[(self.0 >> 3 & 0x7) as usize]
    }

    /// Returns the 3 least significant bits of the ModRM operand modifier ("r/m")
    pub fn register_or_memory(&self) -> RegisterOrMemory {
        let mode = self.modrm_mode();
        let bits = self.0 & 0x7;
        let register = REGISTERS[bits as usize];

        if mode == ModRmMode::Register {
            RegisterOrMemory::Register(register)
        } else if mode == ModRmMode::MemoryNoDisplacement && bits == 0b101 {
            RegisterOrMemory::RelativeToInstruction
        } else if bits == 0b100 {
            RegisterOrMemory::SIB
        } else {
            RegisterOrMemory::MemoryOffset(register)
        }
    }
}


/// See AMD programmers manual volume 3, section 1.4
#[repr(transparent)]
pub struct InstructionSIBData(pub u8);

impl InstructionSIBData {
    pub fn scale(&self) -> u8 {
        let bits = (self.0 >> 6) & 0b11;

        match bits {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!()
        }
    }
    pub fn index(&self) -> Register {
        REGISTERS[(self.0 >> 3 & 0x7) as usize]
    }

    pub fn base(&self) -> Register {
        REGISTERS[self.base_raw() as usize]
    }

    pub fn base_raw(&self) -> u8 {
        self.0 & 0x7
    }
}

/// Represents a register which may have been "increased" via a x64 register extension command
pub struct ExtendedRegister(pub Register, pub bool);

impl ExtendedRegister {
    pub fn get_register(&self, frame: &InterruptStackFrame) -> u64 {
        // TODO: implement extended mode
        self.0.get_register(frame)
    }

    pub fn as_ptr(&self, frame: &InterruptStackFrame) -> *const u8 {
        // TODO: implement extended mode
        self.0.as_ptr(frame)
    }

    pub fn as_mut_ptr(&self, frame: &mut InterruptStackFrame) -> *mut u8 {
        // TODO: implement extended mode
        self.0.as_mut_ptr(frame)
    }

    pub fn get_register_mut<'a>(&self, frame: &'a mut InterruptStackFrame) -> &'a mut u64 {
        // TODO: implement extended mode
        self.0.get_register_mut(frame)
    }
}

pub struct DisplacedMemoryLocation {
    pub displacement_bytes: u8,
    pub base_register: Option<ExtendedRegister>
}

pub enum BaseMemoryLocation {
    RelativeToInstruction,
    Register(ExtendedRegister),
    SIB {
        /// If absent, relative to instruction
        base_register: Option<ExtendedRegister>,
        /// If absent, use 0 as value
        index: Option<ExtendedRegister>,

    }
}

pub enum SibMode {}

pub enum OperandsMode {
    TwoRegisters(ExtendedRegister, ExtendedRegister),
    RegisterAndMemory(ExtendedRegister, VirtAddr)
}

pub struct ModRmInfo(InstructionModRMData, Option<InstructionSIBData>);

impl OperandsMode {
    pub unsafe fn read_from_instruction(instruction_data: &mut InstructionData, frame: &InterruptStackFrame) -> Self {
        let rm_info = ModRmInfo::read_from_instruction(instruction_data);
        rm_info.finalize_from_instruction(instruction_data, frame)
    }
}

impl ModRmInfo {
    pub unsafe fn read_from_instruction(instruction_data: &mut InstructionData) -> ModRmInfo {
        let modrm = InstructionModRMData(unsafe { instruction_data.read_byte() });

        let sib = if modrm.register_or_memory() == RegisterOrMemory::SIB {
            // Parse SIB byte
            Some(InstructionSIBData(unsafe { instruction_data.read_byte() }))
        } else {
            None
        };

        ModRmInfo(modrm, sib)
    }

    fn get_displacement_bytes(&self) -> u8 {
        match self.0.modrm_mode() {
            ModRmMode::MemoryNoDisplacement if
            self.0.register_or_memory() == RegisterOrMemory::RelativeToInstruction ||
            self.1.as_ref().is_some_and(|sib| sib.base_raw() == 0b101) => 4,
            ModRmMode::MemoryNoDisplacement => 0,
            ModRmMode::Memory8BitsDisplacement => 1,
            ModRmMode::Memory32BitsDisplacement => 4,
            ModRmMode::Register => 0,
        }
    }

    pub unsafe fn finalize_from_instruction(self, instruction_data: &mut InstructionData, frame: &InterruptStackFrame) -> OperandsMode {
        let source = Self::extend_reg(instruction_data, self.0.register());
        let target = self.0.register_or_memory();

        if let RegisterOrMemory::Register(target) = target {
            return OperandsMode::TwoRegisters(
                source, Self::extend_reg(instruction_data, target),
            )
        };

        let displacement_bytes = self.get_displacement_bytes();
        let displacement = if self.get_displacement_bytes() > 0 {
            let bytes = unsafe { instruction_data.read_bytes(displacement_bytes as usize) };

            if displacement_bytes == 1 {
                bytes[0] as u64
            } else if displacement_bytes == 2 {
                (bytes[1] as u64) << 8 | (bytes[0] as u64)
            } else if displacement_bytes == 4 {
                (bytes[3] as u64) << 24 | (bytes[2] as u64) << 16 | (bytes[1] as u64) << 8 | (bytes[1] as u64)
            } else {
                panic!("invalid displacement bytes");
            }
        } else { 0 };

        let target_addr: u64 = if let Some(sib) = self.1 {
            let base = Self::extend_base_or_rm(instruction_data, sib.base());
            let base = if base.0 == Register::Rbp && !base.1 {
                if self.0.modrm_mode() == ModRmMode::MemoryNoDisplacement {
                    frame.exception.instruction_pointer.as_u64()
                } else {
                    frame.registers.rbp
                }
            } else {
                base.get_register(frame)
            };

            let index = Self::extend_sib_index(instruction_data, sib.index());
            let index = index.get_register(frame);

            let scale = sib.scale() as u64;

            (scale * index) + base + displacement

        } else {
            // Simple mode
            displacement + match target {
                RegisterOrMemory::MemoryOffset(reg) => {
                    reg.get_register(frame)
                }
                RegisterOrMemory::RelativeToInstruction => {
                    frame.exception.instruction_pointer.as_u64()
                }
                RegisterOrMemory::Register(_) => unreachable!(),
                RegisterOrMemory::SIB => unreachable!(),
            }
        };

        OperandsMode::RegisterAndMemory(source, VirtAddr::new(target_addr))
    }

    fn extend_reg(instruction_data: &InstructionData, base: Register) -> ExtendedRegister {
        ExtendedRegister(base, instruction_data.rex_prefix().as_ref().is_some_and(|rex| rex.contains(RegisterExtensions::ExtendModRmReg)))
    }
    fn extend_sib_index(instruction_data: &InstructionData, base: Register) -> ExtendedRegister {
        ExtendedRegister(base, instruction_data.rex_prefix().as_ref().is_some_and(|rex| rex.contains(RegisterExtensions::ExtendSibIndex)))
    }
    fn extend_base_or_rm(instruction_data: &InstructionData, base: Register) -> ExtendedRegister {
        ExtendedRegister(base, instruction_data.rex_prefix().as_ref().is_some_and(|rex| rex.contains(RegisterExtensions::BitB)))
    }
}

