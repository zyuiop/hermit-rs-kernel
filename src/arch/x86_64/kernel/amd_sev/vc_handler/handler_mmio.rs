use super::super::ghcb_protocol::{protocol_mmio, GhcbProtocolError};
use memory_addresses::PhysAddr;
use crate::arch::kernel::amd_sev::vc_handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::{InstructionData, Size};
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::env::kernel::amd_sev::vc_handler::VcHandler;
#[derive(Debug)]
pub struct MmioHandler;

impl VcHandler for MmioHandler {
    fn handle(&self, frame: &mut InterruptStackFrame, ghcb: &mut Ghcb, instruction_data: &mut InstructionData) -> Result<(), GhcbProtocolError> {
        // Read opcode, ignoring first byte (0f) if present
        let opcode = unsafe { instruction_data.read_opcode() & 0xff };

        // Reference in Edk2: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Library/CcExitLib/CcExitVcHandler.c#L163
        let mut size = match instruction_data.operand_size() {
            Size::Size16Bits => 2,
            Size::Size32Bits => 4,
            Size::Size64Bits => 8
        };

        // Check for 8bit opcodes
        if opcode & 1 == 0 {
            // 8 bit opcodes are always even, non-8bit opcodes are never even (see below)
            size = 1;
        }

        match opcode {
            0x88 | 0x89 => {
                // MOV reg/mem to reg (write)
                let (register, address) = unsafe { protocol_mmio::read_operand_mode(instruction_data, frame) };

                unsafe {
                    // TODO: do we need to translate the address here?
                    protocol_mmio::mmio_write(ghcb, PhysAddr::new(address.as_u64()), register.as_ptr(frame), size)
                }
            }
            0x8a | 0x8b => {
                // MOV reg to reg/mem (read)
                let (register, address) = unsafe { protocol_mmio::read_operand_mode(instruction_data, frame) };

                unsafe {
                    // TODO: do we need to translate the address here?
                    protocol_mmio::mmio_read(ghcb, PhysAddr::new(address.as_u64()), register.as_mut_ptr(frame), size)
                }
            }
            0xb6 | 0xb7 => {
                // MOVZX regx, reg/memX
                // Read with zero extension

                let (register, address) = unsafe { protocol_mmio::read_operand_mode(instruction_data, frame) };
                let size = if opcode == 0xb6 { 1 } else { 2 };
                
                unsafe {
                    // TODO: do we need to translate the address here?
                    protocol_mmio::mmio_read(ghcb, PhysAddr::new(address.as_u64()), register.as_mut_ptr(frame), size)?;
                }
                
                if size == 1 {
                    *register.get_register_mut(frame) &= 0xff;
                } else {
                    *register.get_register_mut(frame) &= 0xffff;
                }
                
                Ok(())
            }
            other => panic!("unhandled mmio opcode {other:x}")
        }

    }
}

