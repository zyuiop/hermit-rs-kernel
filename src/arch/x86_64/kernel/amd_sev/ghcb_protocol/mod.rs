pub mod ghcb;
pub mod protocol_ioio;
pub mod protocol_mmio;
pub mod protocol_msr;
pub mod protocol_ap_reset;
pub mod protocol_vmmcall;
pub mod ghcb_msr;
pub mod allocated_ghcb;
mod protocol_guest_request;
mod protocol_page_state_change;

use ghcb::Ghcb;
use ghcb_msr::{ghcb_request_exit, vmgexit};
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
