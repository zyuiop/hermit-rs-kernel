use x86_64::registers::model_specific::Msr;

pub struct SevStatusMsr(Msr);

impl SevStatusMsr {
    const fn new() -> Self {
        Self(Msr::new(0xc0010131))
    }

    pub fn read_raw(&self) -> u64 {
        unsafe {
            self.0.read()
        }
    }

    pub fn read(&self) -> SevStatusFlags {
        SevStatusFlags::from_bits_truncate(self.read_raw())
    }
}

pub const MSR_AMD_SEV: SevStatusMsr = SevStatusMsr::new();

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SevStatusFlags: u64 {
        const SEV_ENABLED = 1 << 0;
        const SEV_ES_ENABLED = 1 << 1;
        const SEV_SNP_ACTIVE = 1 << 2;
        const V_TOM_ACTIVE = 1 << 3;
        const REFLECT_VC_ACTIVE = 1 << 4;
        const RESTRICTED_INJECTION_ACTIVE = 1 << 5;
        const ALTERNATE_INJECTION_ACTIVE = 1 << 6;
        const DEBUG_VIRTUALIZATION_ACTIVE = 1 << 7;
        const PREVENT_HOST_IBS_ACTIVE = 1 << 8;
        const BTB_ISOLATION_ACTIVE = 1 << 9;
        const VMP_ISSS_ACTIVE = 1 << 10;
        const SEURE_TSC_ACTIVE = 1 << 11;
        const VMGEXIT_PARAMETER_ACTIVE = 1 << 12;
        const PMC_VIRTUALIZATION_ACTIVE = 1 << 13;
        const IBS_VIRTUALIZATION_ACTIVE = 1 << 14;
        const VMSA_REGISTER_PROTECTION_ACTIVE = 1 << 15;
        const SMT_PROTECTION_ACTIVE = 1 << 16;
        const SECURE_AVIC_ACTIVE = 1 << 17;
        const IBPB_ON_ENTRY_ACTIVE = 1 << 23;
    }
}