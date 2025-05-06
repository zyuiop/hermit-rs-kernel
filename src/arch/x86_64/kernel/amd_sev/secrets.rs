use core::ptr;
use aes_gcm::aes::Aes256;
use aes_gcm::Key;
use hermit_sync::{OnceCell, SpinMutex};
use num_traits::ToPrimitive;
use crate::arch::kernel::amd_sev::secrets::CommunicationKeyNumber::{VmPck0, VmPck1, VmPck2, VmPck3};
use crate::env;

pub type VMCommunicationKey = Key<Aes256>;

#[derive(Copy, Clone, Debug, ToPrimitive, FromPrimitive)]
#[repr(usize)]
pub enum CommunicationKeyNumber {
	VmPck0 = 0,
	VmPck1 = 1,
	VmPck2 = 2,
	VmPck3 = 3,
}

#[derive(Debug)]
#[repr(C)] //maybe align, finden wir später raus
pub struct SNPSecretsPage {
	version: u32,
	imi_en: u32,
	fms: u32, //Family, model, and stepping information as reported in CPUID Fn0000_0001_EAX.
	reserved: u32,
	gosvw: [u8; 16],
	vmpck: [VMCommunicationKey; 4],
	guest_area: OSSecretsArea,
	reserved2: [u8; 3840],
}

#[derive(Debug)]
#[repr(C)]
pub struct SNPCCBlob {
	header: u32,
	version: u16,
	reserved1: u16,
	secrets_page_pa: u64,
	secrets_page_size: u32,
	reserved2: u32,
	cpuid_page_pa: u64,
	cpuid_page_size: u32,
	reserved3: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct OSSecretsArea {
	msg_seqno: [u32; 4],
	ap_jump_table_phys_addr: u64,
	reserved: [u8; 40],
	guest_usage: [u8; 20],
}

pub(crate) static CC_BLOB: OnceCell<&SNPCCBlob> = OnceCell::new();
pub(crate) static SECRETS_PAGE: SpinMutex<Option<&mut SNPSecretsPage>> = SpinMutex::new(None); //TODO: volatile crate von Martin hier nutzen, dann kann ich die keys readonly setzen

pub fn init() {
	let Some(cc_blob) = detect_cc_blob() else {
		error!("No CC blob found: SNP specific features will be unavailable. Are you sure you are using a compatible bootloader ?");
		return;
	};

	if let Err(_) = CC_BLOB.set(cc_blob) {
		warn!("CC blob already initialized");
	}

	let mut guard = SECRETS_PAGE.lock();
	let secrets_page: *mut u64 = CC_BLOB.get().unwrap().secrets_page_pa as *mut u64;
	let secrets_ptr = unsafe { secrets_page.cast::<SNPSecretsPage>().as_mut() };
	*guard = secrets_ptr;
}

fn detect_cc_blob() -> Option<&'static SNPCCBlob> {
	env::cc_blob().map(|cc_blob| {
		info!("AMD-SEV: EFI CC Blob detected at {cc_blob:#x}");

		unsafe {
			ptr::with_exposed_provenance::<SNPCCBlob>(cc_blob.get())
				.as_ref()
				.unwrap()
		}
	})
}

pub fn get_key(no: CommunicationKeyNumber) -> VMCommunicationKey {
	let guard = SECRETS_PAGE.lock();
	let page = guard.as_ref().expect("could not lock secrets page");

	page.vmpck[no.to_usize().unwrap()]
}

pub fn get_sequence_number(no: CommunicationKeyNumber) -> u32 {
	let guard = SECRETS_PAGE.lock();
	let page = guard.as_ref().expect("could not lock secrets page");

	page.guest_area.msg_seqno[no.to_usize().unwrap()]
}

pub fn increase_sequence_number(no: CommunicationKeyNumber) {
	let mut guard = SECRETS_PAGE.lock();
	let page = guard.as_mut().expect("could not lock secrets page");

	page.guest_area.msg_seqno[no.to_usize().unwrap()] += 1;
}

pub fn get_next_available_key() -> Option<(CommunicationKeyNumber, VMCommunicationKey, u32)> {
	let guard = SECRETS_PAGE.lock();
	let page = guard.as_ref().expect("could not lock secrets page");

	for key_no in [VmPck0, VmPck1, VmPck2, VmPck3] {
		let seqno = page.guest_area.msg_seqno[key_no.to_usize().unwrap()];

		if seqno < u32::MAX - 1 {
			let key = page.vmpck[key_no.to_usize().unwrap()];
			return Some((key_no, key, seqno))
		}
	}

	None
}
