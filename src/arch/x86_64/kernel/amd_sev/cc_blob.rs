//! This module loads and exposes the Confidential Computing Blob, as built in memory by firmware.
//!
//! The structure is defined in Edk2 here: https://github.com/tianocore/edk2/blob/master/OvmfPkg/Include/Guid/ConfidentialComputingSevSnpBlob.h#L21
//! It is exposed in a specific configuration UUID, which is read by the bootloader and exposed in the FDT.
//!
//! The different pages are defined in AMD SEV Secure Nested Paging Firmware ABI Specification (doc ID 56860).
//! https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf

use crate::arch::kernel::amd_sev::cc_blob::CommunicationKeyNumber::{VmPck0, VmPck1, VmPck2, VmPck3};
use crate::env;
use aes_gcm::aes::Aes256;
use aes_gcm::Key;
use core::ptr;
use hermit_sync::{Lazy, OnceCell, RwSpinLock, SpinMutex};
use async_lock::RwLock;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use core::ptr::NonNull;
use core::cmp::min;
use volatile::{map_field, VolatilePtr, VolatileRef};

pub type VMCommunicationKey = Key<Aes256>;

pub struct ConfidentialComputingBlob {
    secrets: SNPSecrets,
    cpuid: SNPCpuIdValues
}

impl ConfidentialComputingBlob {
    fn new() -> Option<ConfidentialComputingBlob> {
        let cc_blob: &SNPCCBlob = env::cc_blob().and_then(|cc_blob| {
            info!("AMD-SEV: EFI CC Blob detected at {cc_blob:#x}");
            let p = ptr::with_exposed_provenance::<SNPCCBlob>(cc_blob.get());
			unsafe { p.as_ref() }
        })?;

        assert_eq!(size_of::<SNPSecretsPage>(), cc_blob.secrets_page_size as usize);
		let secrets = SNPSecrets(RwSpinLock::new(unsafe {
            cc_blob.secrets_page_pa.as_mut()?
        }));

        assert_eq!(size_of::<CPUIDPage>(), cc_blob.cpuid_page_size as usize);
		let cpuid = SNPCpuIdValues(unsafe {
            cc_blob.cpuid_page_pa.as_mut()?
        });

		Some(Self { secrets, cpuid })
    }

    pub fn secrets(&self) -> &SNPSecrets {
        &self.secrets
    }

    pub fn cpuid(&self) -> &SNPCpuIdValues {
        &self.cpuid
    }
}

pub struct SNPSecrets(RwSpinLock<&'static mut SNPSecretsPage>);

pub struct SNPCpuIdValues(&'static CPUIDPage);

impl SNPCpuIdValues {
    pub fn get_cpuid(&self, eax: u32, ecx: u32, xcr0: u64) -> Option<& CPUIDFunction> {
        if eax & 0x8000_FFFF != eax {
            // Only standard range is checked: 0000_0000 to 0000_FFFF and 8000_0000 to 8000_FFFF
            return None;
        }

        let count = min(self.0.count as usize, MAX_CPUID_FUNCTIONS);
        for page in self.0.cpuid.iter().take(count) {
            if page.eax_in == eax && page.ecx_in == ecx {
                if eax == 0xD {
                    // Check XCR0
                    if page.xcr0_in != xcr0 {
                        continue;
                    }
                }
                return Some(page);
            }
        }

        None
    }
}

impl SNPSecrets {
    pub fn get_key(&self, no: CommunicationKeyNumber) -> VMCommunicationKey {
        let page = self.0.read();
        page.vmpck[usize::from(no)]
    }

    pub fn get_sequence_number(&self, no: CommunicationKeyNumber) -> u32 {
        let page = self.0.read();
        page.guest_area.msg_seqno[usize::from(no)]
    }

    pub fn increase_sequence_number(&self, no: CommunicationKeyNumber) {
        let mut page = self.0.write();
        page.guest_area.msg_seqno[usize::from(no)] += 1;
    }

    pub fn get_next_available_key(&self) -> Option<(CommunicationKeyNumber, VMCommunicationKey, u32)> {
        let page = self.0.read();
        for key_no in [VmPck0, VmPck1, VmPck2, VmPck3] {
            let seqno = page.guest_area.msg_seqno[usize::from(key_no)];

            if seqno < u32::MAX - 1 {
                let key = page.vmpck[usize::from(key_no)];
                return Some((key_no, key, seqno));
            }
        }

        None
    }
}

#[derive(Copy, Clone, Debug, IntoPrimitive, TryFromPrimitive)]
#[repr(usize)]
pub enum CommunicationKeyNumber {
    VmPck0 = 0,
    VmPck1 = 1,
    VmPck2 = 2,
    VmPck3 = 3,
}

#[derive(Debug)]
#[repr(C)]
struct SNPSecretsPage {
    version: u32,
    imi_en: u32,
    fms: u32,
    _reserved: u32,
    gosvw: [u8; 16],
    vmpck: [VMCommunicationKey; 4],
    guest_area: OSSecretsArea,
    vmsa_tweak_bitmap: [u8; 64],
    guest_area_2: [u8; 32],
    tsc_factor: u32,
    _reserved2: u32,
    launch_mit_vector: u64,
    _reserved3: [u8; 3728],
}

#[derive(Debug)]
#[repr(C)]
struct SNPCCBlob {
    header: u32,
    version: u16,
    reserved1: u16,
    secrets_page_pa: *mut SNPSecretsPage,
    secrets_page_size: u32,
    reserved2: u32,
    cpuid_page_pa: *mut CPUIDPage,
    cpuid_page_size: u32,
    reserved3: u32,
}

const MAX_CPUID_FUNCTIONS: usize = 64;

struct CPUIDPage {
    count: u32,
    _padding: u32,
    _padding2: u64,
    cpuid: [CPUIDFunction; MAX_CPUID_FUNCTIONS],
    _padding3: [u8; 1008]
}

pub struct CPUIDFunction {
    eax_in: u32,
    ecx_in: u32,
    xcr0_in: u64,
    xss_in: u64,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    _padding: u64
}

#[derive(Debug)]
#[repr(C)]
struct OSSecretsArea {
    msg_seqno: [u32; 4],
    ap_jump_table_phys_addr: u64,
    reserved: [u8; 40],
    guest_usage: [u8; 20],
    _padding: [u8; 12]
}

const _: () = {
    // Compile time assertions
    const_assert_eq!(size_of::<OSSecretsArea>(), 96);
    const_assert_eq!(size_of::<SNPSecretsPage>(), 4096);
    const_assert_eq!(size_of::<CPUIDFunction>(), 48);
    const_assert_eq!(size_of::<CPUIDPage>(), 4096);
};

pub(crate) static CC_BLOB: Lazy<ConfidentialComputingBlob> = Lazy::new(|| {
    ConfidentialComputingBlob::new().expect("missing AMD confidential computing blob - are you using a compatible bootloader?")
});
