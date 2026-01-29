use memory_addresses::PhysAddr;
use x86_64::instructions::interrupts::without_interrupts;
use core::ops::Add;
use core::{ptr, slice};
use core::mem::MaybeUninit;
use super::ghcb::Ghcb;
use super::{checked_vmgexit, GhcbExitCode, GhcbProtocolError};
use super::allocated_ghcb::with_ghcb;

/// SAFETY: the source_addr must be valid
pub unsafe fn mmio_read_volatile<T>(source_addr: PhysAddr) -> Result<T, GhcbProtocolError> {
    let mut output = MaybeUninit::<T>::uninit();
    let output_ptr = output.as_mut_ptr().cast::<u8>();
    unsafe {
        let output_slice = slice::from_raw_parts_mut(output_ptr, size_of::<T>());
        ghcb_mmio_read(source_addr, output_slice)?;
        Ok(output.assume_init())
    }
}

/// SAFETY: the source_addr must be valid
pub unsafe fn mmio_write_volatile<T>(input: T, target: PhysAddr) -> Result<(), GhcbProtocolError> {
    let ptr = ptr::from_ref(&input).cast::<u8>();
    unsafe {
        let slice = slice::from_raw_parts(ptr, size_of::<T>());
        ghcb_mmio_write(slice, target)
    }
}

/// SAFETY: the source_addr must be valid
pub fn ghcb_mmio_read(source_addr: PhysAddr, output: &mut [u8]) -> Result<(), GhcbProtocolError> {
    without_interrupts(|| {
        with_ghcb(|ghcb| {
            mmio_read(ghcb, source_addr, output)
        })
    })
}

/// SAFETY: the target_addr must be valid
pub fn ghcb_mmio_write(input: &[u8], target_addr: PhysAddr) -> Result<(), GhcbProtocolError> {
    without_interrupts(|| {
        with_ghcb(|ghcb| {
            mmio_write(ghcb, target_addr, input)
        })
    })
}

// TODO: making a safer API is likely possible (use slices)
pub fn mmio_read(ghcb: &mut Ghcb, source_addr: PhysAddr, destination: &mut [u8]) -> Result<(), GhcbProtocolError> {
    let buff_size = ghcb.shared_buffer_size();

    // If the data is too big for a single MMIO instruction, call recursively
    if destination.len() > buff_size {
        for offset in (0..destination.len()).step_by(buff_size) {
            let end = if offset + buff_size > destination.len() {
                destination.len()
            } else {
                offset + buff_size
            };

            mmio_read(ghcb, source_addr.add(offset), &mut destination[offset..end])?;
        }
        return Ok(())
    }

    // Issue the VMExit.
    ghcb.use_shared_buffer();
    checked_vmgexit(ghcb, GhcbExitCode::MmioRead, source_addr.as_u64(), destination.len() as u64)?;

    // Copy the read data from the buffer to the destination
    ghcb.copy_from_shared_buffer(destination);

    Ok(())
}

pub fn mmio_write(ghcb: &mut Ghcb, dest_addr: PhysAddr, source: &[u8]) -> Result<(), GhcbProtocolError> {
    let buff_size = ghcb.shared_buffer_size();

    // If the data is too big for a single MMIO instruction, call recursively
    if source.len() > buff_size {
        for offset in (0..source.len()).step_by(buff_size) {
            let end = if offset + buff_size > source.len() {
                source.len()
            } else {
                offset + buff_size
            };

            mmio_write(ghcb, dest_addr.add(offset), &source[offset..end])?;
        }
        return Ok(())
    }

    // Copy the data to the buffer
    ghcb.use_shared_buffer();
    ghcb.copy_to_shared_buffer(source);

    // Issue the call
    checked_vmgexit(ghcb, GhcbExitCode::MmioWrite, dest_addr.as_u64(), source.len() as u64)
}