use core::arch::asm;
use bitfield_struct::bitfield;
use memory_addresses::VirtAddr;
use x86_64::structures::paging::PageSize;

#[bitfield(u64)]
pub struct RmpAdjustment {
    #[bits(8)]
    pub target_vmpl: u8,

    #[bits(8)]
    pub target_permissions_mask: u8,

    #[bits(1)]
    pub vmsa: bool,

    #[bits(47)]
    _reserved: u64
}

pub fn rmpadjust<S: PageSize>(virt_addr: VirtAddr, adjustment: RmpAdjustment) {
    unsafe {
        let rmpadjust = adjustment.0;
        let mut guest_addr_ret = virt_addr.as_usize();
        asm!("rmpadjust",
            inout("rax") guest_addr_ret,
            in("rcx") S::SIZE,
            in("rdx") rmpadjust,
        );
    }
}


#[cfg(test)]
mod tests {
    use crate::arch::kernel::amd_sev::rmpadjust::RmpAdjustment;

    #[test]
    fn check_bitfield_is_correct() {
        let expected = (1 << 16) | 1u64;
        let check = RmpAdjustment::new()
            .with_vmsa(true)
            .with_target_vmpl(1);

        assert_eq!(check.0, expected);
    }
}