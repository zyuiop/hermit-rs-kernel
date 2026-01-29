use core::arch::asm;
use core::fmt::Debug;
use x86_64::registers::rflags::RFlags;
use super::super::ghcb_protocol::{protocol_mmio, GhcbProtocolError};
use memory_addresses::{PhysAddr, VirtAddr};
use crate::arch::kernel::amd_sev::vc_handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::{InstructionData, Size};
use crate::arch::kernel::amd_sev::opcodes::opcode::KnownOpcode;
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::arch::kernel::amd_sev::vc_handler::VcHandler;
#[derive(Debug)]
pub struct MmioHandler;

macro_rules! util_asm_test {
    ($typ:ty, $rc:tt, $imm:expr, $rv:expr, $out:expr) => {{
        let sz = size_of::<$typ>();
        let temp = <$typ>::from_le_bytes(($rv[0..sz]).try_into().unwrap());
        let imm = <$typ>::from_le_bytes(($imm[0..sz]).try_into().unwrap());
        unsafe { asm!(
            "pushfq",
            "test {}, {}",
            "pushfq",
            "pop {}",
            "popfq",
            in($rc) temp,
            in($rc) imm,
            out(reg) $out,
            options(preserves_flags)
        ) };
    }};
}

macro_rules! util_asm_cmp_imm8 {
    ($typ:ty, $imm8:expr, $rv:expr, $out:expr) => {{
        let sz = size_of::<$typ>();
        let rv = <$typ>::from_le_bytes(($rv[0..sz]).try_into().unwrap());
        let imm = $imm8 as $typ; // Sign extend immediate value
        unsafe { asm!(
            "pushfq",
            "cmp {}, {}",
            "pushfq",
            "pop {}",
            "popfq",
            in(reg) rv,
            in(reg) imm,
            out(reg) $out,
            options(preserves_flags)
        ) };
    }};
}



impl VcHandler for MmioHandler {
    fn handle(&self, frame: &mut InterruptStackFrame, ghcb: &mut Ghcb, instruction_data: &mut InstructionData) -> Result<(), GhcbProtocolError> {
        // Read opcode, ignoring first byte (0f) if present
        let opcode = instruction_data.operation();

        // Reference in Edk2: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/CcExitLib/CcExitVcHandler.c#L163
        let mut size = match instruction_data.operand_size() {
            Size::Size16Bits => 2,
            Size::Size32Bits => 4,
            Size::Size64Bits => 8
        };

        // Check for 8bit opcodes
        if (opcode as u8) & 1 == 0 {
            // 8 bit opcodes are always even, non-8bit opcodes are never even (see below)
            size = 1;
        }

        match opcode {
            KnownOpcode::MovRmRegByte | KnownOpcode::MovRmReg => {
                // MOV reg/mem to reg (write)
                let (register, address) = unsafe { instruction_data.parse_modrm_data(frame) };

                protocol_mmio::mmio_write(ghcb, map_address(address), register.as_slice(frame, size))
            }
            KnownOpcode::MovRegRmByte | KnownOpcode::MovRegRm => {
                // MOV reg to reg/mem (read)
                let (register, address) = unsafe { instruction_data.parse_modrm_data(frame) };

                protocol_mmio::mmio_read(ghcb, map_address(address), register.as_mut_slice(frame, size))
            }
            KnownOpcode::MovzRegRmByte | KnownOpcode::MovzRegRm => {
                // MOVZX regx, reg/memX
                // Read with zero extension
                let (register, address) = unsafe { instruction_data.parse_modrm_data(frame) };
                let size = if opcode == KnownOpcode::MovzRegRmByte { 1 } else { 2 };
                
                protocol_mmio::mmio_read(ghcb, map_address(address), register.as_mut_slice(frame, size))?;

                if size == 1 {
                    *register.get_register_mut(frame) &= 0xff;
                } else {
                    *register.get_register_mut(frame) &= 0xffff;
                }
                
                Ok(())
            }
            KnownOpcode::MovRmImmByte | KnownOpcode::MovRmImm => {
                // MOV imm to reg/mem (write)
                let (_, address) = unsafe { instruction_data.parse_modrm_data(frame) };
                let immediate = unsafe { instruction_data.read_immediate(size) };

                protocol_mmio::mmio_write(ghcb, map_address(address), immediate)
            }
            KnownOpcode::OrRmImmByte | KnownOpcode::OrRmImm => {
                // OR operation: we will need both a read and a write... this looks a bit inefficient :(
                let (_, address) = unsafe { instruction_data.parse_modrm_data(frame) };
                let address = map_address(address);

                let immediate = unsafe { instruction_data.read_immediate(size) };
                let mut temp = [0u8; 8];

                protocol_mmio::mmio_read(ghcb, address, &mut temp[0..size])?;
                for offset in 0..size {
                    temp[offset] |= immediate[offset]
                }

                // Update flags manually
                frame.exception.cpu_flags.set(RFlags::OVERFLOW_FLAG, false);
                frame.exception.cpu_flags.set(RFlags::CARRY_FLAG, false);
                frame.exception.cpu_flags.set(RFlags::ZERO_FLAG, u64::from_le_bytes(temp) == 0);
                frame.exception.cpu_flags.set(RFlags::PARITY_FLAG, temp[0].count_ones() & 0x1 == 0); // parity: least significant byte has even number of ones
                frame.exception.cpu_flags.set(RFlags::SIGN_FLAG, temp[size - 1] >> 7 == 1); // sign: most significant bit is 1

                protocol_mmio::mmio_write(ghcb, address, &temp[0..size])
            }
            KnownOpcode::TestRmByte | KnownOpcode::TestRm => {
                // TEST operation: we read the value and compte the results of the TEST instruction
                let (_, address) = unsafe { instruction_data.parse_modrm_data(frame) };
                let immediate = unsafe { instruction_data.read_immediate(size) };

                let mut temp = [0u8; 8];
                protocol_mmio::mmio_read(ghcb, map_address(address), &mut temp[0..size])?;

                let mut flags = frame.exception.cpu_flags.bits();
                // Delegate the computation to assembly to make sure we do it correctly
                match size {
                    1 => util_asm_test!(i8, reg_byte, &immediate, &temp, flags),
                    2 => util_asm_test!(i16, reg, &immediate, &temp, flags),
                    4 => util_asm_test!(i32, reg, &immediate, &temp, flags),
                    8 => util_asm_test!(i64, reg, &immediate, &temp, flags),
                    _ => unreachable!()
                }
                frame.exception.cpu_flags = RFlags::from_bits_retain(flags);

                Ok(())
            }
            KnownOpcode::CmpImm => {
                // TEST operation: we read the value and compte the results of the TEST instruction
                let (_, address) = unsafe { instruction_data.parse_modrm_data(frame) };
                let immediate = unsafe { instruction_data.read_immediate(1)[0].cast_signed() };

                let mut temp = [0u8; 8];
                protocol_mmio::mmio_read(ghcb, map_address(address), &mut temp[0..size])?;

                let mut flags = frame.exception.cpu_flags.bits();
                // Delegate the computation to assembly to make sure we do it correctly
                match size {
                    2 => util_asm_cmp_imm8!(i16, immediate, &temp, flags),
                    4 => util_asm_cmp_imm8!(i32, immediate, &temp, flags),
                    8 => util_asm_cmp_imm8!(i64, immediate, &temp, flags),
                    _ => unreachable!()
                }
                frame.exception.cpu_flags = RFlags::from_bits_retain(flags);

                Ok(())
            }
            other => {
                panic!("unhandled mmio opcode {other:?}")
            }
        }

    }
}

#[inline(always)]
fn map_address(va: VirtAddr) -> PhysAddr {
    // TODO: for performance reason we likely want to use faster methods here
    // if va >= DeviceAlloc.phys_offset() && va < virtualmem::kernel_heap_end() {
    //    DeviceAlloc.phys_addr_from(va.as_mut_ptr::<u8>())
    // } else {
        crate::mm::virtual_to_physical(va).unwrap()
    // }
}
