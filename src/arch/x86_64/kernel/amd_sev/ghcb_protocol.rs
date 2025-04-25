use super::ghcb_msr_protocol::{ghcb_request_exit, vmgexit};

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum GhcbExitCode {
    DR7Read = 0x27,
    DR7Write = 0x37,

    RdTsc = 0x6e,
    RdPmc = 0x6f,

    CPUID = 0x72,

    Invd = 0x76,

    IoIoProtocol = 0x7b,
    MsrProtocol = 0x7c,
    VmmCall = 0x81,
    RdTscp = 0x87,
    WbInvd = 0x89,

    Monitor = 0x8a,
    MWait = 0x8b,

    MmioRead = 0x8000_0001,
    MmioWrite = 0x8000_0002,
    NmiComplete = 0x8000_0003,
    ApResetHold = 0x8000_0004,
    ApJumpTable = 0x8000_0005,
    PageStateChange = 0x8000_0010,

    SnpGuestRequest = 0x8000_0011,
    SnpGuestExtendedRequest = 0x8000_0012,
    SnpApCreation = 0x8000_0013,

    HvDoorbellPages = 0x8000_0014,
    HvIpi = 0x8000_0015,
    HvTimer = 0x8000_0016,

    ApicIdList = 0x8000_0017,

    SnpRunVmpl = 0x8000_0018,
    SnpTioGuestRequest = 0x8000_0019,
    SecureAvic= 0x8000_001a,

    HypervisorFeatureSupport = 0x8000_fffd,

    TerminationRequest = 0x8000_fffe,
    UnsupportedEvent = 0x8000_ffff
}

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
        self.save = Default::default();
        self.shared_buffer = [0; GHCB_SHARED_BUF_SIZE];
        // self.protocol_version = 0;
        // self.ghcb_usage = 0;
    }

    /// Copies the address of the shared buffer in the SW_SCRATCH field of the saved data and marks
    /// that field valid.
    pub fn use_shared_buffer(&mut self) {
        let ptr: *const u8 = &self.shared_buffer[0];
        self.save.sw_scratch = ptr as u64;
        self.save.set_valid_field(& self.save.sw_scratch);
    }
}


#[derive(Debug, Copy, Clone)]
pub enum RequestedException {
    GeneralProtectionFault, UndefinedInstruction,
}

#[derive(Debug, Copy, Clone)]
pub enum InvalidGhcbError {
    UnregisteredGhcbAddress,
    InvalidGhcbUsageValue,
    InvalidScratchField,
    MissingValidFields,
    InvalidNAEEventInput,
    InvalidNAEEvent,
}

#[derive(Debug, Copy, Clone)]
pub enum PostProcessingError {
    /// A field in the GHCB save area was supposed to be set but is not
    MissingExpectedResponseField
}

#[derive(Debug, Copy, Clone)]
pub enum GhcbProtocolError {
    RequestException(RequestedException),
    InvalidGhcb(InvalidGhcbError),
    HypervisorSpecific(u64),

    /// Custom error when processing the GHCB response
    PostProcessingError(PostProcessingError)
}


pub mod error_exit_codes {
    pub const EXIT_VC_INVALIDOP: u8 = 0x70;

    pub const EXIT_VC_UNHANDLED: u8 = 0x80;
    pub const EXIT_VC_ERROR: u8 = 0x81;
    pub const EXIT_VC_NOT_IMPLEMENTED: u8 = 0x82;

    // Errors
    pub const EXIT_VC_INVALID_EXCEPTION: u8 = 0x90;
    pub const EXIT_VC_MALFORMED_ERROR_INFO: u8 = 0x91;
    pub const EXIT_VC_INVALID_EXIT_CODE: u8 = 0x92;

    pub const EXIT_OTHER: u8 = 0xff;
}

pub fn checked_vmgexit(ghcb: &mut Ghcb, exitcode: GhcbExitCode, exit_info1: u64, exit_info2: u64) -> Result<(), GhcbProtocolError> {
    ghcb.save.sw_exit_code = exitcode;
    ghcb.save.sw_exit_info_1 = exit_info1;
    ghcb.save.sw_exit_info_2 = exit_info2;

    ghcb.save.set_valid_field(& ghcb.save.sw_exit_code);
    ghcb.save.set_valid_field(& ghcb.save.sw_exit_info_1);
    ghcb.save.set_valid_field(& ghcb.save.sw_exit_info_2);

    unsafe { vmgexit(); }

    // Check error code
    match ghcb.save.sw_exit_info_1 {
        0x0000 => { Ok(()) }
        0x0001 => {
            Err(GhcbProtocolError::RequestException(
                match ghcb.save.sw_exit_info_2 & 0xff {
                    6 => RequestedException::UndefinedInstruction,
                    13 => RequestedException::GeneralProtectionFault,
                    v => {
                        ghcb_request_exit(error_exit_codes::EXIT_VC_MALFORMED_ERROR_INFO);
                        panic!("invalid exception vector received: {v}")
                    }
                }
            ))
        }
        0x0002 => {
            Err(match ghcb.save.sw_exit_info_2 {
                0x0001 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::UnregisteredGhcbAddress),
                0x0002 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidGhcbUsageValue),
                0x0003 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidScratchField),
                0x0004 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::MissingValidFields),
                0x0005 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidNAEEventInput),
                0x0006 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidNAEEvent),
                v if v >= 0x1_0000 => GhcbProtocolError::HypervisorSpecific(v),
                v => {
                    ghcb_request_exit(error_exit_codes::EXIT_VC_MALFORMED_ERROR_INFO);
                    panic!("invalid malformed error info: {v}")
                },
            })
        }
        other => {
            ghcb_request_exit(error_exit_codes::EXIT_VC_INVALID_EXIT_CODE);
            panic!("invalid ghcb exit response: {other}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GhcbSaveArea;

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
