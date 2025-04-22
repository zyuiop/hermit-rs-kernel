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
    pub struct RegisterExtensions: u8 {
        const BitB = 1 << 0;
        const BitX = 1 << 1;
        const BitR = 1 << 2;

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