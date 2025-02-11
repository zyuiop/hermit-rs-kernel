use core::ptr;

use hermit_sync::{OnceCell, SpinMutex};

use crate::env;

#[derive(Debug)]
#[repr(C)] //maybe align, finden wir später raus
pub struct SNPSecretsPage {
	version: u32,
	imi_en: u32,
	fms: u32, //Family, model, and stepping information as reported in CPUID Fn0000_0001_EAX.
	reserved: u32,
	gosvw: [u8; 16],
	vmpck0: [u8; 32],
	vmpck1: [u8; 32],
	vmpck2: [u8; 32],
	vmpck3: [u8; 32],
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
	msg_seqno0: u32,
	msg_seqno1: u32,
	msg_seqno2: u32,
	msg_seqno3: u32,
	ap_jump_table_phys_addr: u64,
	reserved: [u8; 40],
	guest_usage: [u8; 20],
}

pub(crate) static CCBLOB: OnceCell<&SNPCCBlob> = OnceCell::new();
pub(crate) static SECRETSPAGE: SpinMutex<Option<&mut SNPSecretsPage>> = SpinMutex::new(None); //TODO: volatile crate von Martin hier nutzen, dann kann ich die keys readonly setzen

pub fn init() {
	CCBLOB.set(detect_cc_blob().unwrap()).unwrap();
	let mut guard = SECRETSPAGE.lock();
	let mut secrets_page: *mut u64 = CCBLOB.get().unwrap().secrets_page_pa as *mut u64;
	let secrets_ptr = unsafe { secrets_page.cast::<SNPSecretsPage>().as_mut() };
	*guard = secrets_ptr;
}

fn detect_cc_blob() -> Result<&'static SNPCCBlob, ()> {
	if let Some(cc_blob) = env::cc_blob() {
		debug!("EFI CC Blob detected at {cc_blob:#x}");
		let cc_blob = unsafe {
			ptr::with_exposed_provenance::<SNPCCBlob>(cc_blob.get())
				.as_ref()
				.unwrap()
		};
		trace!("{cc_blob:#x?}");
		return Ok(cc_blob);
	}
	Err(())
}

pub fn get_vmpck0() -> [u8; 32] {
	let mut guard = SECRETSPAGE.lock();
	let secrets_page = guard.as_mut().unwrap();
	secrets_page.vmpck0
}

pub fn get_msgseqno0() -> u64 {
	let mut guard = SECRETSPAGE.lock();
	let mut secrets_page = guard.as_mut().unwrap();
	secrets_page.guest_area.msg_seqno0 as u64
}

pub fn inc_msgseqno0() {
	let mut guard = SECRETSPAGE.lock();
	let mut secrets_page = guard.as_mut().unwrap();
	secrets_page.guest_area.msg_seqno0 = secrets_page.guest_area.msg_seqno0.checked_add(1).unwrap();
}
