pub mod ghcb;
pub mod protocol_ioio;
pub mod protocol_mmio;
pub mod protocol_msr;
pub mod protocol_vmmcall;
pub mod ghcb_msr;
pub mod allocated_ghcb;
pub mod guest_request;
pub mod protocol_page_state_change;
pub mod protocol_ap_creation;

use ghcb::{Ghcb, GhcbU64Field};
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
    MissingExpectedResponseField,

    /// An error occurred while parsing the response data
    ParseError
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
    pub const EXIT_TOO_MANY_CONCURRENT_USES: u8 = 0x10;
    pub const EXIT_BACKUP_RESTORE_NOT_IN_ORDER: u8 = 0x11;
    pub const EXIT_GHCB_NOT_INITIALIZED_FOR_CORE: u8 = 0x13;

    pub const EXIT_VC_INVALIDOP: u8 = 0x70;
    pub const EXIT_VC_ERROR: u8 = 0x81;
    pub const EXIT_VC_NOT_IMPLEMENTED: u8 = 0x82;

    // Errors
    pub const EXIT_VC_MALFORMED_ERROR_INFO: u8 = 0x91;
    pub const EXIT_VC_UNHANDLED_GHCB_ERORR_CODE: u8 = 0x92;
    pub const EXIT_GHCB_INVALID_MSR: u8 = 0x93;
    pub const EXIT_PROTOCOL_NEGOTIATION_INVALID_MSR: u8 = 0x94;

    pub const EXIT_PARSE_ERROR: u8 = 0xa0;
    pub const EXIT_PARSE_UNHANDLED: u8 = 0xa1;

    pub const EXIT_OTHER: u8 = 0xff;
}

pub fn checked_vmgexit(ghcb: &mut Ghcb, exitcode: GhcbExitCode, exit_info1: u64, exit_info2: u64) -> Result<(), GhcbProtocolError> {
    // ghcb.save.sw_exit_code = exitcode;
    ghcb.set_exit_code(exitcode);
    ghcb.set_field(GhcbU64Field::SwExitInfo1, exit_info1);
    ghcb.set_field(GhcbU64Field::SwExitInfo2, exit_info2);

    unsafe { vmgexit(); }

    // Check error code
    match ghcb.get_field_if_valid(GhcbU64Field::SwExitInfo1)? & 0xffff_ffff {
        0x0000 => { Ok(()) }
        0x0001 => {
            Err(GhcbProtocolError::RequestException(
                match ghcb.get_field_if_valid(GhcbU64Field::SwExitInfo2)? & 0xff {
                    6 => RequestedException::UndefinedInstruction,
                    13 => RequestedException::GeneralProtectionFault,
                    _ => {
                        ghcb_request_exit(error_exit_codes::EXIT_VC_MALFORMED_ERROR_INFO);
                    }
                }
            ))
        }
        0x0002 => {
            Err(match ghcb.get_field_if_valid(GhcbU64Field::SwExitInfo2)? {
                0x0001 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::UnregisteredGhcbAddress),
                0x0002 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidGhcbUsageValue),
                0x0003 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidScratchField),
                0x0004 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::MissingValidFields),
                0x0005 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidNAEEventInput),
                0x0006 => GhcbProtocolError::InvalidGhcb(InvalidGhcbError::InvalidNAEEvent),
                v if v >= 0x1_0000 => GhcbProtocolError::HypervisorSpecific(v),
                _ => {
                    ghcb_request_exit(error_exit_codes::EXIT_VC_MALFORMED_ERROR_INFO);
                },
            })
        }
        other => {
            // TEMP: debug
            ghcb.set_exit_code(GhcbExitCode::TerminationRequest);
            ghcb.set_field(GhcbU64Field::SwExitInfo1, other);
            ghcb.set_field(GhcbU64Field::SwExitInfo2, exitcode as u64);

            unsafe { vmgexit(); }

            sev_exit!(error_exit_codes::EXIT_VC_UNHANDLED_GHCB_ERORR_CODE, "Invalid error code {other:x}!");
        }
    }
}
