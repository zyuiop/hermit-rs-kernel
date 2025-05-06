use memory_addresses::{PhysAddr, VirtAddr};
use x86_64::instructions::interrupts::without_interrupts;
use core::ops::Add;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::arch::kernel::amd_sev::ghcb_protocol::{checked_vmgexit, GhcbExitCode, GhcbProtocolError};
use crate::arch::kernel::amd_sev::handler::InterruptStackFrame;
use crate::arch::kernel::amd_sev::instruction_parser::InstructionData;
use crate::arch::kernel::amd_sev::opcodes::{ExtendedRegister, OperandsMode};
use crate::arch::kernel::amd_sev::with_ghcb;

use super::error_exit_codes::EXIT_VC_INVALIDOP;

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
pub unsafe fn mmio_read(ghcb: &mut Ghcb, source_addr: PhysAddr, destination: *mut u8, read_size: usize) -> Result<(), GhcbProtocolError> {
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

pub unsafe fn mmio_write(ghcb: &mut Ghcb, dest_addr: PhysAddr, source: *const u8, write_size: usize) -> Result<(), GhcbProtocolError> {
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

pub unsafe fn read_operand_mode(instruction_data: &mut InstructionData, frame: &InterruptStackFrame) -> (ExtendedRegister, VirtAddr) {
    if let OperandsMode::RegisterAndMemory(reg, mem) = unsafe { OperandsMode::read_from_instruction(instruction_data, frame) } {
        (reg, mem)
    } else {
        sev_exit!(EXIT_VC_INVALIDOP, "page fault on register-to-register operation?")
    }
}