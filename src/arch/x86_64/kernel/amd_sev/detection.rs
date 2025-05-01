use bit_field::BitField;
use hermit_sync::OnceCell;
use x86_64::registers::model_specific::Msr;
use x86_64::structures::mem_encrypt::MemoryEncryptionConfiguration;

const MSR_AMD_SEV: Msr = Msr::new(0xc0010131);

/// Represents the current enablement state of AMD Secure Encrypted Virtualization features
#[derive(Copy, Clone, Debug)]
pub struct SevState {
    /// True if Secure Encrypted Virtualization is enabled
    pub sev_enabled: bool,

    /// True if Secure Nested Paging is enabled.
    ///
    /// Implies `sev_es_enabled` = true and `sev_enabled` = true
    pub snp_enabled: bool,

    /// True if Encrypted State is enabled.
    ///
    /// Implies `sev_enabled` = true
    pub sev_es_enabled: bool,

    /// Custom flag used to set the encryption bit in page table entries
    pub c_bit_mask: u64,
}

pub(crate) static SEV_STATUS: OnceCell<SevState> = OnceCell::new();

pub fn sev_state<'a>() -> Option<&'a SevState> {
    SEV_STATUS.get()
}

/// Initializes AMD Secure Encrypted Virtualization, if enabled.
///
/// It is required to call this function in an SEV enabled guest, as it sets-up a dynamic page table
/// flag for memory encryption. If this is not set, page table operations may cause panics due to
/// invalid canonical addresses.
pub fn init<'a>() -> Option<&'a SevState> {
    if let Some(state) = sev_state() {
        return Some(state)
    }


    // https://github.com/torvalds/linux/blob/900241a5cc15e6e0709a012051cc72d224cd6a6e/arch/x86/mm/mem_encrypt_identity.c#L566
    // Check for SME support
    let (cpuid_max, _) = unsafe { core::arch::x86_64::__get_cpuid_max(0x8000_0000) };
    if cpuid_max < 0x8000_001F {
        return None;
    }

    // Check if SME is available on the current CPU then read the C-Bit position and define the mask
    let sme_features = unsafe { core::arch::x86_64::__cpuid(0x8000_001F) };
    let sme_available = (sme_features.eax & 0x3) != 0; // either SME or SEV bit is set
    if !sme_available {
        return None;
    }

    let c_bit_pos: u8 = sme_features.ebx.get_bits(0..=5) as u8;
    unsafe {
        x86_64::structures::mem_encrypt::enable_memory_encryption(MemoryEncryptionConfiguration::EncryptedBit(c_bit_pos));
    }
    let c_bit_mask = (1u64) << c_bit_pos;

    // Check the MSR to see if SME is currently enabled
    let sme_status = unsafe { MSR_AMD_SEV.read() };
    let sev_enabled = (sme_status & 0x1) == 1;
    let sev_es_enabled = (sme_status & 0x2) == 0x2;
    let snp_enabled = (sme_status & 0x4) == 0x4;

    if !sev_enabled && !snp_enabled {
        return None;
    }

    SEV_STATUS.set(SevState {
        sev_enabled,
        snp_enabled,
        sev_es_enabled,
        c_bit_mask
    }).expect("SEV status was already initialized!");

    sev_state()
}
