use crate::arch::kernel::amd_sev::ghcb_protocol::{GhcbExitCode, GhcbProtocolError, PostProcessingError};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GhcbSaveArea {
    reserved_0x0: [u8; 203],
    pub cpl: u8,
    reserved_0xcc: [u8; 116],
    pub xss: u64,
    reserved_0x148: [u8; 24],
    pub dr7: u64,
    reserved_0x168: [u8; 16],
    pub rip: u64,
    reserved_0x180: [u8; 88],
    pub rsp: u64,
    reserved_0x1e0: [u8; 24],
    pub rax: u64,
    reserved_0x200: [u8; 264],
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    reserved_0x320: [u8; 8],
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    reserved_0x380: [u8; 16],
    pub sw_exit_code: GhcbExitCode,
    pub sw_exit_info_1: u64,
    pub sw_exit_info_2: u64,
    pub sw_scratch: u64,
    reserved_0x3b0: [u8; 56],
    pub xcr0: u64,
    pub valid_bitmap: [u8; 16],
    pub x87_state_gpa: u64,
}

impl GhcbSaveArea {
    fn field_offset<T>(&self, field_ptr: *const T) -> usize {
        let base: *const Self = self;
        let field_ptr: *const T = field_ptr;

        let offset = (field_ptr as u64 - base as u64) >> 3;

        offset as usize
    }

    pub fn set_valid_field<T>(&mut self, field_ptr: *const T) {
        let mask_offset = self.field_offset(field_ptr);
        self.valid_bitmap[mask_offset / 8] |= 1 << (mask_offset % 8) as u8;
    }

    pub fn is_valid_field<T>(&self, field_ptr: *const T) -> bool {
        let mask_offset = self.field_offset(field_ptr);
        self.valid_bitmap[mask_offset / 8] & 1 << (mask_offset % 8) as u8 != 0
    }

    pub fn get_field_if_valid<T: Copy>(&self, field_ref: & T) -> Result<T, GhcbProtocolError> {
        let mask_offset = self.field_offset(field_ref);
        if self.valid_bitmap[mask_offset / 8] & 1 << (mask_offset % 8) as u8 != 0 {
            Ok(*field_ref)
        } else {
            Err(GhcbProtocolError::PostProcessingError(PostProcessingError::MissingExpectedResponseField))
        }
    }
}

impl Default for GhcbSaveArea {
    fn default() -> Self {
        Self {
            reserved_0x0: [0; 203],
            cpl: 0,
            reserved_0xcc: [0; 116],
            xss: 0,
            reserved_0x148: [0; 24],
            dr7: 0,
            reserved_0x168: [0; 16],
            rip: 0,
            reserved_0x180: [0; 88],
            rsp: 0,
            reserved_0x1e0: [0; 24],
            rax: 0,
            reserved_0x200: [0; 264],
            rcx: 0,
            rdx: 0,
            rbx: 0,
            reserved_0x320: [0; 8],
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            reserved_0x380: [0; 16],
            sw_exit_code: GhcbExitCode::UnsupportedEvent,
            sw_exit_info_1: 0,
            sw_exit_info_2: 0,
            sw_scratch: 0,
            reserved_0x3b0: [0; 56],
            xcr0: 0,
            valid_bitmap: [0; 16],
            x87_state_gpa: 0,
        }
    }
}

const GHCB_SHARED_BUF_SIZE: usize =	2032;

#[repr(C, align(0x1000))]
#[derive(Debug, Clone)]
pub struct Ghcb {
    pub save: GhcbSaveArea,

    reserved_save: [u8; 2048 - size_of::<GhcbSaveArea>()],

    pub shared_buffer: [u8; GHCB_SHARED_BUF_SIZE],

    reserved_0xff0: [u8; 10],
    pub protocol_version: u16,	/* negotiated SEV-ES/GHCB protocol version */
    pub ghcb_usage: u32,
}

impl Default for Ghcb {
    fn default() -> Self {
        Self {
            save: GhcbSaveArea::default(),
            reserved_save: [0; 2048 - size_of::<GhcbSaveArea>()],
            shared_buffer: [0; GHCB_SHARED_BUF_SIZE],
            reserved_0xff0: [0; 10],
            protocol_version: 0,
            ghcb_usage: 0,
        }
    }
}

impl Ghcb {
    pub fn clear(&mut self) {
        // Preserve scratch address (set by the manager)
        let scratch = self.save.sw_scratch;
        self.save = Default::default();
        self.save.sw_scratch = scratch;

        self.shared_buffer = [0; GHCB_SHARED_BUF_SIZE];
        // self.protocol_version = 0;
        // self.ghcb_usage = 0;
    }

    /// Copies the address of the shared buffer in the SW_SCRATCH field of the saved data and marks
    /// that field valid.
    pub fn use_shared_buffer(&mut self) {
        // let ptr: *const u8 = &self.shared_buffer[0];
        // self.save.sw_scratch = ptr as u64;
        self.save.set_valid_field(& self.save.sw_scratch);
    }
}

#[cfg(test)]
mod tests {
    use crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb::GhcbSaveArea;

    #[test]
    fn offset_is_correct() {
        let mut base = GhcbSaveArea::default();
        base.set_valid_field(&base.cpl);
        base.set_valid_field(&base.sw_exit_code);
        base.set_valid_field(&base.sw_exit_info_1);
        base.set_valid_field(&base.sw_exit_info_2);

        assert_eq!(base.is_valid_field(&base.cpl), true);
        assert_eq!(base.is_valid_field(&base.sw_exit_code), true);
        assert_eq!(base.is_valid_field(&base.sw_exit_info_1), true);
        assert_eq!(base.is_valid_field(&base.sw_exit_info_2), true);

    }
}
