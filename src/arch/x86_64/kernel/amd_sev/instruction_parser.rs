use core::arch::asm;
use core::slice;
use crate::env::kernel::amd_sev::opcodes::{opcode_prefix, RegisterExtensions};

const MAX_INSTRUCTION_LENGTH: usize = 15;

/// The instruction that caused the exception to be raised
pub struct InstructionData {
    base_ptr: *const u8,
    offset: usize,

    opcode_offset: usize,
    opcode_bytes: u8,

    // Parsed data
    repetition_mode: InstructionRepetitionMode,
    rex_prefix: Option<RegisterExtensions>,
    operand_size: Size,
    address_size: Size,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum InstructionRepetitionMode {
    None,
    RepZ,
    RepNZ
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Size {
    Size16Bits, Size32Bits, Size64Bits
}


pub struct InstructionPrefixes {
}

impl InstructionData {
    pub fn new(instr_ptr: *const ()) -> Self {
        let mut res = Self {
            base_ptr: instr_ptr as *const u8,
            offset: 0,

            repetition_mode: InstructionRepetitionMode::None,
            rex_prefix: None,
            operand_size: Size::Size32Bits,
            address_size: Size::Size64Bits,
            opcode_bytes: 1,
            opcode_offset: 0
        };

        res.parse_prefixes();

        res
    }

    fn parse_prefixes(&mut self) {
        // Liberally inspired by EDK2: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/CcExitLib/CcInstruction.c#L307
        while self.offset < MAX_INSTRUCTION_LENGTH {
            let opcode = unsafe { self.peek_byte() };

            // Parse 64-bit register extension prefix
            if let Some(prefix) = RegisterExtensions::from_opcode(opcode) {
                if prefix.contains(RegisterExtensions::BitW) {
                    self.operand_size = Size::Size64Bits;
                }

                self.rex_prefix = Some(prefix);

                self.next();
                continue;
            }

            // Parse other opcodes
            match opcode {
                opcode_prefix::OVERRIDE_SEGMENT_CS | opcode_prefix::OVERRIDE_SEGMENT_DS | opcode_prefix::OVERRIDE_SEGMENT_ES | opcode_prefix::OVERRIDE_SEGMENT_FS | opcode_prefix::OVERRIDE_SEGMENT_GS | opcode_prefix::OVERRIDE_SEGMENT_SS => {
                    panic!("unhandled override segment prefix!")
                }
                opcode_prefix::OVERRIDE_OPERAND_SIZE => {
                    // Always in 64bits mode
                    self.operand_size = Size::Size16Bits;
                }
                opcode_prefix::OVERRIDE_ADDRESS_SIZE => {
                    // Always in 64bits mode
                    self.address_size = Size::Size32Bits;
                }
                opcode_prefix::LOCK => { /* No OP */ }
                opcode_prefix::REP_NZ => {
                    self.repetition_mode = InstructionRepetitionMode::RepNZ
                }
                opcode_prefix::REP_Z => {
                    self.repetition_mode = InstructionRepetitionMode::RepZ
                }
                opcode_prefix::TWO_BYTE_ESCAPE => {
                    self.offset += 1; // Skip the current opcode
                    self.opcode_bytes = 2;
                    self.opcode_offset = self.offset;
                    return;
                }
                _ => {
                    self.opcode_offset = self.offset;
                    // Other instruction, return
                    return;
                }
            }

            self.next();
        }

        panic!("could not complete instruction parsing")
    }

    #[inline(always)]
    pub fn next(&mut self) {
        self.advance(1)
    }

    #[inline(always)]
    pub unsafe fn read_byte(&mut self) -> u8 {
        let value = unsafe { self.peek_byte() };
        self.advance(1);
        value
    }

    #[inline(always)]
    pub unsafe fn read_bytes(&mut self, len: usize) -> &[u8] {
        assert!(len + self.offset <= MAX_INSTRUCTION_LENGTH);

        let value = unsafe { slice::from_raw_parts(self.current_ptr(), len) };
        self.advance(len);
        value
    }

    pub unsafe fn peek_opcode(&self) -> u16 {
        let opcode_ptr = unsafe { self.base_ptr.add(self.offset) };

        if self.opcode_bytes == 1 {
            unsafe { (*opcode_ptr) as u16 }
        } else {
            unsafe { *opcode_ptr.cast() }
        }
    }

    pub unsafe fn read_opcode(&mut self) -> u16 {
        let opcode_ptr = unsafe { self.base_ptr.add(self.offset) };

        let result = if self.opcode_bytes == 1 {
            unsafe { (*opcode_ptr) as u16 }
        } else {
            unsafe { *opcode_ptr.cast() }
        };

        self.advance(self.opcode_bytes as usize);
        result
    }

    pub fn advance(&mut self, offset: usize) {
        assert!(self.offset + offset <= MAX_INSTRUCTION_LENGTH);
        self.offset += offset;
    }

    pub fn backtrack(&mut self, offset: usize) {
        assert!(self.offset >= offset);
        self.offset -= offset;
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn set_offset(&mut self, offset: usize) {
        assert!(offset <= MAX_INSTRUCTION_LENGTH);
        self.offset = offset;
    }

    pub unsafe fn current_ptr(&self) -> *const u8 {
        assert!(self.offset < MAX_INSTRUCTION_LENGTH);
        unsafe {
            self.base_ptr.add(self.offset)
        }
    }

    pub unsafe fn peek_byte(&self) -> u8 {
        unsafe { *self.current_ptr() }
    }

    pub unsafe fn get_word(&self) -> u16 {
        unsafe { *self.current_ptr().cast() }
    }

    pub fn repetition_mode(&self) -> InstructionRepetitionMode {
        self.repetition_mode
    }

    pub fn rex_prefix(&self) -> &Option<RegisterExtensions> {
        &self.rex_prefix
    }

    pub fn operand_size(&self) -> Size {
        self.operand_size
    }

    pub fn address_size(&self) -> Size {
        self.address_size
    }
}