use crate::arch::kernel::amd_sev::decrypted_allocator::SharedPagesAllocator;
use crate::env::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;
use crate::env::kernel::amd_sev::ghcb_protocol::{checked_vmgexit, GhcbExitCode};
use crate::env::kernel::amd_sev::sev_status::{SevStatusFlags, MSR_AMD_SEV};
use aes_gcm::aes::cipher::typenum::Bit;
use alloc::boxed::Box;
use bitflags::Flags;
use core::alloc::{Allocator, Layout};
use core::arch::asm;
use core::ops::Add;
use core::ops::BitAnd;
use core::ptr;
use core::slice;
use core::mem::offset_of;
use align_address::Align;
use memory_addresses::{PhysAddr, VirtAddr};
use x86_64::registers::control::{Cr0Flags, Cr3Flags, Cr4, Cr4Flags, EferFlags};
use x86_64::registers::debug::{Dr6Flags, Dr7Flags};
use x86_64::registers::rflags::RFlags;
use x86_64::registers::xcontrol::XCr0Flags;
use x86_64::structures::paging::{PageSize, PageTableFlags, Size2MiB, Size4KiB};
use crate::arch::BasePageSize;
use crate::arch::mm::paging::{PageTableEntryFlags, PageTableEntryFlagsExt};
use crate::mm;
use crate::mm::{virtual_to_physical, EncryptedDeviceAllocator};

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct SegmentRegister {
    selector: u16,
    attribute: u16,
    limit: u32,
    _reserved: u32,
    base: u32
}

impl Default for SegmentRegister {
    fn default() -> Self {
        Self {
            // Default values from the AMD Programmers' Manual
            selector: 0, base: 0, _reserved: 0,
            limit: 0xffff,
            attribute: CS_ATTR_PRESENT | 0b10010
        }
    }
}

#[repr(C, packed)]
#[derive(Default, Debug, Copy, Clone)]
struct PerfCtl {
    perf_ctl: u64,
    perf_ctr: u64
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
struct FlagsWithDefault<T: Flags>(T);
impl <T: Flags<Bits=u64>> Default for FlagsWithDefault<T> {
    fn default() -> Self {
        Self(T::from_bits_truncate(0))
    }
}

#[repr(C)]
#[derive(Default, Debug)]
struct VMSaveArea {
    es: SegmentRegister,
    cs: SegmentRegister,
    ss: SegmentRegister,
    ds: SegmentRegister,
    fs: SegmentRegister,
    gs: SegmentRegister,
    gdtr: SegmentRegister,
    ldtr: SegmentRegister,
    idtr: SegmentRegister,
    tr: SegmentRegister,

    pl_ssp: [u64; 4],
    u_cet: u64,
    _reserved_0: u16, // Documentation is wrong: this is a word and not a dword!

    vmpl: u8,
    cpl: u8,
    _reserved_1: u32,

    efer: FlagsWithDefault<EferFlags>,
    _reserved_2: u64,

    perf_ctls: [PerfCtl; 6],
    xss: u64,
    cr4: FlagsWithDefault<Cr4Flags>,
    cr3: FlagsWithDefault<Cr3Flags>,
    cr0: FlagsWithDefault<Cr0Flags>,
    dr7: FlagsWithDefault<Dr7Flags>,
    dr6: FlagsWithDefault<Dr6Flags>,
    rflags: FlagsWithDefault<RFlags>,

    rip: u64,
    /// DR0 to DR3
    dr: [u64; 4],
    /// DR0 to DR3
    dr_addr_mask: [u64; 4],

    instr_retired_ctr: u64,
    perf_ctr_global_stats: u64,
    perf_ctr_global_ctl: u32,
    _reserved_3: u32,

    rsp: u64,
    s_cet: u64,
    ssp: u64,
    isst_addr: u64,
    rax: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    kernel_gs_base: u64,

    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,

    cr2: u64,

    _reserved_4: [u64; 4], // 32 bytes

    g_pat: u64,
    dbgctl: u64,
    br_from: u64,
    br_to: u64,

    last_except_from: u64,
    last_except_to: u64,
    dbg_extn_cfg: u64,

    // 64 bytes - not 72, the documentation is once again wrong
    _reserved_5: [u64; 8],

    spec_ctrl: u64,
    pkru: u32,
    tsc_aux: u32,
    guest_tsc_scale: u64,
    guest_tsc_offset: u64,
    reg_prot_nonce: u64,

    rcx: u64,
    rdx: u64,
    rbx: u64,

    secure_avic_ctl: u64,

    rbp: u64,
    rsi: u64,
    rdi: u64,
    /// registers r8 to r15
    x64_registers: [u64; 8],
    _reserved_6: u128,

    guest_exitinfo1: u64,
    guest_exitinfo2: u64,
    guest_exitintinfo: u64,
    guest_nrip: u64,

    sev_features: SevFeatures,
    vintr_ctrl: u64,
    guest_exit_code: u64,
    virtual_tom: u64,
    tlb_id: u64,
    pcpu_id: u64,
    event_inj: u64,
    xcr0: FlagsWithDefault<XCr0Flags>,
    _reserved_7: u128,
    x87_dp: u64,
    mx_csr: u32,
    x87_ftw: u16,
    x87_fsw: u16,
    x87_fcw: u16,
    x87_fop: u16,
    x87_ds: u16,
    x87_cs: u16,
    x87_rip: u64,

    fpreg_x87: [u64; 10],
    fpreg_xmm: [u64; 32],
    fpreg_ymm: [u64; 32],
    lbr_stack: [u64; 32],
    lbr_select: u64,
    ibs_fetch_ctl: u64,
    ibs_fetch_linaddr: u64,
    ibs_op_ctl: u64,
    ibs_op_rip: u64,
    ibs_op_data: [u64; 3],
    ibs_dc_linaddr: u64,
    bp_ibstgt_rip: u64,
    ic_ibs_extd_ctl: u64
}

// Some assertions to help debugging the VMSave area
const_assert_eq!(offset_of!(VMSaveArea, cs), 0x10);
const_assert_eq!(offset_of!(VMSaveArea, efer), 0xD0);
const_assert_eq!(offset_of!(VMSaveArea, pl_ssp), 0xA0);
const_assert_eq!(offset_of!(VMSaveArea, u_cet), 0xC0);
const_assert_eq!(offset_of!(VMSaveArea, vmpl), 0xCA);
const_assert_eq!(offset_of!(VMSaveArea, cpl), 0xCB);
const_assert_eq!(offset_of!(VMSaveArea, efer), 0xD0);
const_assert_eq!(offset_of!(VMSaveArea, xss), 0x140);
const_assert_eq!(offset_of!(VMSaveArea, rip), 0x178);
const_assert_eq!(offset_of!(VMSaveArea, rsp), 0x1D8);
const_assert_eq!(offset_of!(VMSaveArea, cr2), 0x240);
const_assert_eq!(offset_of!(VMSaveArea, g_pat), 0x268);
const_assert_eq!(offset_of!(VMSaveArea, br_to), 0x280);
const_assert_eq!(offset_of!(VMSaveArea, dbg_extn_cfg), 0x298);
const_assert_eq!(offset_of!(VMSaveArea, spec_ctrl), 0x2E0);
const_assert_eq!(offset_of!(VMSaveArea, rbp), 0x328);
const_assert_eq!(offset_of!(VMSaveArea, guest_exitinfo1), 0x390);
// const_assert_eq!(size_of::<VMSaveArea>(), 0x7C8);

const CS_ATTR_PRESENT: u16 = 1 << 7;

impl VMSaveArea {
    /// Sets the values of the save area from the current CPU data
    pub fn init_default_values(&mut self) {
        // AMD Programmers Manual, vol 2, 14.1.3, Processor Initialization State
        // See linux kernel: coco/sev/core.c, wakeup_cpu_via_vmgexit (https://github.com/torvalds/linux/blob/master/arch/x86/coco/sev/core.c#L1180)
        self.cr0.0 = Cr0Flags::from_bits_retain(0x6000_0010);
        self.dr7.0 = Dr7Flags::from_bits_retain(0x400);
        self.dr6.0 = Dr6Flags::from_bits_retain(0xffff_0ff0);
        self.rflags.0 = RFlags::from_bits_retain(0x2);
        self.xcr0.0 = XCr0Flags::from_bits_retain(1);
        self.cr4.0 = unsafe { Cr4::read().bitand(Cr4Flags::MACHINE_CHECK_EXCEPTION) };
        self.efer.0.set(EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE, true);

        // All segment registers are already almost set thanks to their default values
        self.gdtr.attribute = 0;
        self.idtr.attribute = 0;
        self.ldtr.attribute = CS_ATTR_PRESENT | 0b0010;
        self.tr.attribute = CS_ATTR_PRESENT | 0b0011;

        // x87 FP state
        self.x87_fcw = 0x0040; // control word
        self.x87_ftw = 0x5555; // tag word

        // SSE state
        self.mx_csr = 0x1f80;

        self.sev_features = SevFeatures::from_status(MSR_AMD_SEV.read());
    }

    pub fn set_start_instr_ptr(&mut self, ip: u64) {
        // See linux kernel: coco/sev/core.c, wakeup_cpu_via_vmgexit (https://github.com/torvalds/linux/blob/master/arch/x86/coco/sev/core.c#L1180)

        // Set code segment register
        let sipi_vector = ip >> 16;
        self.cs.base = (sipi_vector << 16) as u32;
        self.cs.selector = 8u16;
        self.cs.limit = 0xffff;
        self.cs.attribute = CS_ATTR_PRESENT | 0b11010; // SVM_S, CODE, READ
        
        // Set RIP
        self.rip = ip & 0xffff; // 16 last bits of selected segment
    }
}

struct AllocatedVmsa(*mut VMSaveArea, PhysAddr);

impl AllocatedVmsa {
    fn allocate_not_2mib_aligned() -> (VirtAddr, PhysAddr) {
        let size = Size4KiB::SIZE as usize;
        let phys = mm::physicalmem::allocate(size).ok().expect("failed to allocate memory");

        if phys.is_aligned_to(Size2MiB::SIZE) {
            let (new_virt, new_phys) = Self::allocate_not_2mib_aligned();
            mm::physicalmem::deallocate(phys, size);
            return (new_virt, new_phys);
        }

        let mut flags = PageTableEntryFlags::empty()
            .union(PageTableEntryFlags::NO_EXECUTE | PageTableEntryFlags::WRITABLE);
        flags.set_encrypted(true);

        let virt = mm::map_with_flags(phys, size, flags);
        (virt, phys)
    }

    pub fn data(&mut self) -> &mut VMSaveArea {
        unsafe {
            self.0.as_mut().unwrap()
        }
    }

    pub fn allocate() -> Self {
        // There is a bug where we must not have a 2Mib aligned page
        // We use the technique from the linux kernel to solve this:
        // We allocate two pages and free the first one which MAY be 2M/1G aligned
        let (virt, phys) = Self::allocate_not_2mib_aligned();
        let ptr: *mut VMSaveArea = ptr::with_exposed_provenance_mut(virt.as_usize());
        unsafe {
            *ptr = VMSaveArea::default();
        }
        Self(ptr, phys)
    }

    /// Register the page as a VMSA page
    ///
    /// ## Safety
    ///
    /// Caller must ensure that the page has been correctly filled
    pub unsafe fn register(&self) {
        // Declare as a VMSA page
        unsafe {
            let virt = VirtAddr::from_ptr(self.0);
            let rmpadjust = (1 << 16) | 1;
            let mut guest_addr_ret = virt.as_usize();
            asm!("rmpadjust",
            inout("rax") guest_addr_ret,
            in("rcx") Size4KiB::SIZE,
            in("rdx") rmpadjust,
            );

            assert_eq!(guest_addr_ret, 0);
        };

    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct SevFeatures: u64 {
        const SNP_ACTIVE = 1 << 0;
        const V_TOM = 1 << 1;
        const REFLECT_VC = 1 << 2;
        const RESTRICTED_INJECTION = 1 << 3;
        const ALTERNATE_INJECTION = 1 << 4;
        const DEBUG_VIRTUALIZATION = 1 << 5;
        const PREVENT_HOST_IBS = 1 << 6;
        const BTB_ISOLATION = 1 << 7;
        const VMP_ISSS = 1 << 8;
        const SEURE_TSC = 1 << 9;
        const VMGEXIT_PARAMETER = 1 << 10;
        const PMC_VIRTUALIZATION = 1 << 11;
        const IBS_VIRTUALIZATION = 1 << 12;
        const VMSA_REGISTER_PROTECTION = 1 << 14;
        const SMT_PROTECTION = 1 << 15;
        const SECURE_AVIC = 1 << 16;
        const IBPB_ON_ENTRY = 1 << 21;
    }
}

impl SevFeatures {
    pub fn from_status(status: SevStatusFlags) -> SevFeatures {
        SevFeatures::from_bits_truncate(status.bits() >> 2)
    }
}

pub fn snp_ap_create(
    processor_number: u32,
    start_addr: VirtAddr
) {
    with_ghcb(|ghcb| {
        let mut page = AllocatedVmsa::allocate();
        let data = page.data();
        let rax = data.sev_features.bits();
        data.init_default_values();
        data.set_start_instr_ptr(start_addr.as_u64());
        // info!("Page status: {:x?}", data);
        unsafe {
            page.register();
        }

        // Start the AP
        ghcb.clear();
        ghcb.save.rax = rax;
        ghcb.save.set_valid_field(&ghcb.save.rax);
        checked_vmgexit(ghcb, GhcbExitCode::SnpApCreation, ((processor_number as u64) << 32) | 1, page.1.as_u64()).expect("failed to start application processor!");
    })
}