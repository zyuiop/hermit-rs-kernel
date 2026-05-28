macro_rules! sev_exit {
    ($code:expr) => {{
        crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb_msr::ghcb_request_exit($code)
    }};
    ($code:expr, $($arg:tt)*) => {{
        log::error!($($arg)+);
        crate::arch::x86_64::kernel::amd_sev::ghcb_protocol::ghcb_msr::ghcb_request_exit($code)
    }};
}

pub(crate) mod ghcb_protocol;
pub(crate) mod vc_handler;
pub mod instruction_parser;
mod opcodes;
pub(crate) mod paravirt_uart;
pub(crate) mod sev_guest_ioctl;

mod cc_blob;
pub mod sev_status;
pub mod pvalidate;
mod rmpadjust;

use bit_field::BitField;
use x86_64::structures::mem_encrypt::MemoryEncryptionConfiguration;
use crate::console;
use crate::arch::kernel::amd_sev::cc_blob::CC_BLOB;
use crate::arch::kernel::amd_sev::sev_status::{SevStatusFlags, MSR_AMD_SEV};

/// Initializes AMD Secure Encrypted Virtualization, if enabled.
///
/// It is required to call this function in an SEV enabled guest, as it sets-up a dynamic page table
/// flag for memory encryption. If this is not set, page table operations may cause panics due to
/// invalid canonical addresses.
pub fn enable_sev<'a>() {
	// https://github.com/torvalds/linux/blob/900241a5cc15e6e0709a012051cc72d224cd6a6e/arch/x86/mm/mem_encrypt_identity.c#L566
	// Check for SME support
	let (cpuid_max, _) = unsafe { core::arch::x86_64::__get_cpuid_max(0x8000_0000) };
	if cpuid_max < 0x8000_001F {
		hermit_sync::Lazy::force(&console::CONSOLE);
		panic!("cpuidid_max is too low for an SEV supporting CPU!\nThis kernel was compiled with the `amd-sev` feature, so it can ONLY boot on an AMD SEV-SNP VM!")
	}

	// Check if SME is available on the current CPU then read the C-Bit position and define the mask
	let sme_features = unsafe { core::arch::x86_64::__cpuid(0x8000_001F) };
	let sme_available = (sme_features.eax & 0x3) != 0; // either SME or SEV bit is set
	if !sme_available {
		hermit_sync::Lazy::force(&console::CONSOLE);
		panic!("Secure Memory Encryption is not enabled on the VCPU!\nThis kernel was compiled with the `amd-sev` feature, so it can ONLY boot on an AMD SEV-SNP VM!")
	}

	let c_bit_pos: u8 = sme_features.ebx.get_bits(0..=5) as u8;
	unsafe {
		x86_64::structures::mem_encrypt::enable_memory_encryption(MemoryEncryptionConfiguration::EncryptedBit(c_bit_pos));
	}

	// Check the MSR to see if SME is currently enabled
	let sev_status = MSR_AMD_SEV.read();
	let sev_enabled = sev_status.contains(SevStatusFlags::SEV_ENABLED);
	let snp_enabled = sev_status.contains(SevStatusFlags::SEV_SNP_ACTIVE);

	if !sev_enabled || !snp_enabled {
		hermit_sync::Lazy::force(&console::CONSOLE);
		panic!("SEV/SEV-SNP is not enabled!\nThis kernel was compiled with the `amd-sev` feature, so it can ONLY boot on an AMD SEV-SNP VM!")
	}
}

/// Finish initialization of AMD SEV, once memory mapping has been setup, just after the interrupt
/// descriptor table is set
pub fn post_init() {
	ghcb_protocol::allocated_ghcb::init_ghcb_for_core();
	hermit_sync::Lazy::force(&CC_BLOB);
}

pub fn init_application_processor() {
	ghcb_protocol::allocated_ghcb::init_ghcb_for_core();
}