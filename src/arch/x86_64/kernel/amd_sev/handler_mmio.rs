use core::ops::Add;
use x86_64::instructions::interrupts::without_interrupts;
use super::ghcb_protocol::{checked_vmgexit, Ghcb, GhcbExitCode, GhcbProtocolError};
use super::ghcb_protocol::error_exit_codes::EXIT_VC_INVALIDOP;
use memory_addresses::{PhysAddr, VirtAddr};
use crate::arch::kernel::amd_sev::handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::{InstructionData, Size};
use crate::arch::kernel::amd_sev::opcodes::ExtendedRegister;
use crate::env::kernel::amd_sev::handler::VcHandler;
use crate::env::kernel::amd_sev::opcodes::OperandsMode;
use crate::env::kernel::amd_sev::with_ghcb;

#[derive(Debug)]
pub struct MmioHandler;

pub fn ghcb_mmio_read(source_addr: PhysAddr, output: &mut [u8]) -> Result<(), GhcbProtocolError> {
    without_interrupts(|| {
        with_ghcb(|ghcb| {
            unsafe  {
                mmio_read(ghcb, source_addr, output.as_mut_ptr(), output.len())
            }
        })
    })
}

pub fn ghcb_mmio_write(input: &[u8], target_addr: PhysAddr) -> Result<(), GhcbProtocolError> {
    without_interrupts(|| {
        with_ghcb(|ghcb| {
            unsafe  {
                mmio_write(ghcb, target_addr, input.as_ptr(), input.len())
            }
        })
    })
}

// TODO: making a safer API is likely possible (use slices)
unsafe fn mmio_read(ghcb: &mut Ghcb, source_addr: PhysAddr, destination: *mut u8, read_size: usize) -> Result<(), GhcbProtocolError> {
    let buff_size = ghcb.shared_buffer.len();

    // If the data is too big for a single MMIO instruction, call recursively
    if read_size > buff_size {
        let final_address = source_addr.add(read_size);
        let mut source_addr = source_addr;
        let mut destination = destination;

        while source_addr.lt(&final_address) {
            let sz = final_address.as_usize() - source_addr.as_usize();
            let sz = if sz < buff_size { sz } else { buff_size };

            unsafe { mmio_read(ghcb, source_addr, destination, sz)? };

            source_addr = source_addr.add(sz);
            destination = unsafe { destination.add(sz) };
        }

        return Ok(())
    }

    // Issue the VMExit.
    ghcb.use_shared_buffer();
    checked_vmgexit(ghcb, GhcbExitCode::MmioRead, source_addr.as_u64(), read_size as u64)?;

    // Copy the read data from the buffer to the destination
    for i in 0..read_size {
        unsafe {
            *destination.add(i) = ghcb.shared_buffer[i];
        };

        // info!("debug: mmio_read at {}: copy byte {i}: {}", source_addr.as_u64(), ghcb.shared_buffer[i]);
    }

    Ok(())
}

unsafe fn mmio_write(ghcb: &mut Ghcb, dest_addr: PhysAddr, source: *const u8, write_size: usize) -> Result<(), GhcbProtocolError> {
    let buff_size = ghcb.shared_buffer.len();

    // If the data is too big for a single MMIO instruction, call recursively
    if write_size > buff_size {
        let final_address = dest_addr.add(write_size);
        let mut dest_addr = dest_addr;
        let mut source = source;

        while dest_addr.lt(&final_address) {
            let sz = final_address.as_usize() - dest_addr.as_usize();
            let sz = if sz < buff_size { sz } else { buff_size };

            unsafe { mmio_write(ghcb, dest_addr, source, sz)? };

            dest_addr = dest_addr.add(sz);
            source = unsafe { source.add(sz) };
        }

        return Ok(())
    }

    // Copy the data to the buffer
    ghcb.use_shared_buffer();
    for i in 0..write_size {
        ghcb.shared_buffer[i] = unsafe { *(source.add(i)) };

        // info!("debug: mmio_write at {}: copy byte {i}: {}", dest_addr.as_u64(), ghcb.shared_buffer[i]);
    }

    // Issue the call
    checked_vmgexit(ghcb, GhcbExitCode::MmioWrite, dest_addr.as_u64(), write_size as u64)
}

unsafe fn read_operand_mode(instruction_data: &mut InstructionData, frame: &InterruptStackFrame) -> (ExtendedRegister, VirtAddr) {
    if let OperandsMode::RegisterAndMemory(reg, mem) = unsafe { OperandsMode::read_from_instruction(instruction_data, frame) } {
        (reg, mem)
    } else {
        sev_exit!(EXIT_VC_INVALIDOP, "page fault on register-to-register operation?")
    }
}

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
                let (register, address) = unsafe { read_operand_mode(instruction_data, frame) };

                unsafe {
                    // TODO: do we need to translate the address here?
                    mmio_write(ghcb, PhysAddr::new(address.as_u64()), register.as_ptr(frame), size)
                }
            }
            0x8a | 0x8b => {
                // MOV reg to reg/mem (read)
                let (register, address) = unsafe { read_operand_mode(instruction_data, frame) };

                unsafe {
                    // TODO: do we need to translate the address here?
                    mmio_read(ghcb, PhysAddr::new(address.as_u64()), register.as_mut_ptr(frame), size)
                }
            }
            0xb6 | 0xb7 => {
                // MOVZX regx, reg/memX
                // Read with zero extension

                let (register, address) = unsafe { read_operand_mode(instruction_data, frame) };
                let size = if opcode == 0xb6 { 1 } else { 2 };
                
                unsafe {
                    // TODO: do we need to translate the address here?
                    mmio_read(ghcb, PhysAddr::new(address.as_u64()), register.as_mut_ptr(frame), size)?;
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

