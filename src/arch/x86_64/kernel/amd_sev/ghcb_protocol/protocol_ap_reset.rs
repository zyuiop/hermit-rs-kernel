use x86_64::instructions::interrupts::without_interrupts;
use super::{checked_vmgexit, GhcbExitCode, GhcbProtocolError};
use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;

#[repr(C)]
pub struct ApResetAddress {
    pub reset_ip: u16,
    pub reset_cs: u16
}

impl ApResetAddress {
    pub fn set_addr(&mut self, addr: u32) {
        assert!(addr <= 1 << 20);

        // CS:IP addressing mode: actual address is 16 * CS + IP
        self.reset_cs = (addr >> 4) as u16;
        self.reset_ip = (addr & 0xff) as u16;
    }
}

pub unsafe fn ap_jump_table_get() -> Result<*mut ApResetAddress, GhcbProtocolError> {
    without_interrupts(|| {
        with_ghcb(|ghcb| {
            ghcb.clear();
            checked_vmgexit(ghcb, GhcbExitCode::ApJumpTable, 1, 0)?;

            let addr = ghcb.save.get_field_if_valid(&ghcb.save.sw_exit_info_2)?;

            info!("AP_RESET_ADDRESS: {addr:x}");

            Ok(addr as *mut ApResetAddress)
        })
    })
}