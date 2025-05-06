use alloc::alloc::Allocator;
use core::slice;

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};

use crate::arch::kernel::{ghcb, secrets};
use crate::mm::device_alloc;

// See SEV-SNP ABI Specification 7.3 Attestation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SNPMessageReportRequest {
	pub report_data: [u8; 64], // Guest-provided data to be included in the attestation report.
	pub vmpl: u32, // The VMPL to put in the attestation report. Must be greater than or equal to the current VMPL and, at most, three. Will probably always be 0.
	pub key_sel: u32, // Selects which key to use for generating the signature. Must be either 0, 1 or 2.
	reserved: [u8; 24], // Reserved, must be 0.
}

impl SNPMessageReportRequest {
	pub fn new(report_data: [u8; 64]) -> Self {
		Self {
			report_data: report_data,
			vmpl: 0,
			key_sel: 0, // If VLEK is installed, sign with VLEK. Otherwise, sign with VCEK
			reserved: [0; 24],
		}
	}
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SNPMessageReportResponse {
	pub status: Status,
	pub report_size: u32,
	reserved: [u8; 24],
	pub report: AttestationReport,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Status {
	Success = 0,
	InvalidParameters = 0x16,
	InvalidKeySelection = 0x27,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AttestationReport {
	version: u32,
	guest_svn: u32,
	policy: u64,
	family_id: u128,
	image_id: u128,
	vmpl: u32,
	signature_algo: u32,
	current_tcb: u64,
	platform_info: u64,
	keys: u32,
	reserved0: u32,
	report_data: [u8; 64], // If added by guest, the report_data from SNPMessageReportRequest will be here
	measurement: [u8; 48],
	host_data: [u8; 32],
	id_key_digest: [u8; 48],
	author_key_digest: [u8; 48],
	report_id: [u8; 32],
	report_id_ma: [u8; 32],
	reported_tcb: u64,
	cpuid_fam_id: u8,
	cpuid_mod_id: u8,
	cpuid_step: u8,
	reserved1: [u8; 20],
	chip_id: [u8; 64],
	committed_tcb: u64,
	current_build: u8,
	current_minor: u8,
	current_major: u8,
	reserved2: u8,
	committed_build: u8,
	committed_minor: u8,
	committed_major: u8,
	reserved3: u8,
	launch_tcb: u64,
	reserved4: [u8; 168],
	signature: [u8; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(0x1000))]
pub struct SNPMessageHeader {
	authtag: [u8; 32],
	msg_seqno: u64,
	reserved0: u64,
	algo: u8,
	hdr_version: u8,
	hdr_size: u16,
	msg_type: u8,
	msg_version: u8,
	msg_size: u16,
	reserved1: u32,
	msg_vmpck: u8,
	reserved2: [u8; 35],
	payload: SNPMessageReportRequest,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(0x1000))]
pub struct SNPMessageResponseHeader {
	authtag: [u8; 32],
	msg_seqno: u64,
	reserved0: u64,
	algo: u8,
	hdr_version: u8,
	hdr_size: u16,
	msg_type: u8,
	msg_version: u8,
	msg_size: u16,
	reserved1: u32,
	msg_vmpck: u8,
	reserved2: [u8; 35],
	payload: SNPMessageReportResponse,
}
const HEADERSIZE: u16 = size_of::<SNPMessageHeader>() as u16;

impl SNPMessageHeader {
	fn encrypt_message(&mut self, message: &mut SNPMessageReportRequest) {
		let key = secrets::get_vmpck0();
		let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

		let mut seqno_vector = [0u8; 12]; // 96 bit IV
		seqno_vector[0..8].copy_from_slice(unsafe {
			slice::from_raw_parts(&self.msg_seqno as *const u64 as *const u8, 8)
		}); // first 64 bits are msg_seqno and rest are 0
		let seqno_iv = Nonce::from_slice(&seqno_vector);

		let mut associated_data = [0u8; 48]; // this contains the headerdata from 0x30 to 0x5f
		associated_data[0] = self.algo;
		associated_data[1] = self.hdr_version;
		associated_data[2..4].copy_from_slice(unsafe {
			slice::from_raw_parts(&self.hdr_size as *const u16 as *const u8, 2)
		});
		associated_data[4] = self.msg_type;
		associated_data[5] = self.msg_version;
		associated_data[6..8].copy_from_slice(unsafe {
			slice::from_raw_parts(&self.msg_size as *const u16 as *const u8, 2)
		});
		//rest of associated_data needs to be 0 (actually if we were to attest from a different privilege level than 0 then there is another byte to set but we don't need this)

		let mut payload = unsafe {
			slice::from_raw_parts_mut(message as *mut _ as *mut u8, self.msg_size as usize)
		};
		let authtag = cipher
			.encrypt_in_place_detached(seqno_iv, &associated_data, payload)
			.unwrap();
		self.payload = unsafe {
			*payload
				.as_mut_ptr()
				.cast::<SNPMessageReportRequest>()
				.as_ref()
				.unwrap()
		};
		self.authtag[0..16].copy_from_slice(&authtag.as_slice());
	}
}

impl SNPMessageResponseHeader {
	fn decrypt_message(&mut self, message: &mut SNPMessageReportResponse) {
		let key = secrets::get_vmpck0();
		let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

		let mut seqno_vector = [0u8; 12]; // 96 bit IV
		seqno_vector[0..8].copy_from_slice(unsafe {
			slice::from_raw_parts(&self.msg_seqno as *const u64 as *const u8, 8)
		}); // first 64 bits are msg_seqno and rest are 0
		let seqno_iv = Nonce::from_slice(&seqno_vector);

		let mut associated_data = [0u8; 48]; // this contains the headerdata from 0x30 to 0x5f
		associated_data[0] = self.algo;
		associated_data[1] = self.hdr_version;
		associated_data[2..4].copy_from_slice(unsafe {
			slice::from_raw_parts(&self.hdr_size as *const u16 as *const u8, 2)
		});
		associated_data[4] = self.msg_type;
		associated_data[5] = self.msg_version;
		associated_data[6..8].copy_from_slice(unsafe {
			slice::from_raw_parts(&self.msg_size as *const u16 as *const u8, 2)
		});
		let mut payload = unsafe {
			slice::from_raw_parts_mut(message as *mut _ as *mut u8, self.msg_size as usize)
		};
		let tag = Tag::from_slice(&self.authtag[0..16]);
		cipher
			.decrypt_in_place_detached(seqno_iv, &associated_data, payload, tag)
			.unwrap();
		self.payload = unsafe {
			*payload
				.as_mut_ptr()
				.cast::<SNPMessageReportResponse>()
				.as_ref()
				.unwrap()
		};
	}
}

pub fn request_attestation() {
	debug!("Requesting attestation from PSP");

	let allocator = device_alloc::DeviceAlloc;
	let layout = core::alloc::Layout::from_size_align(0x1000, 0x1000).unwrap();

	let gpa_req = allocator.allocate(layout).unwrap();

	let gpa_resp = allocator.allocate(layout).unwrap();

	unsafe { gpa_resp.as_mut_ptr().write_bytes(0, 0x1000) };

	drop(allocator);
	drop(layout);

	let snp_msg_hdr = unsafe {
		gpa_req
			.as_mut_ptr()
			.cast::<SNPMessageHeader>()
			.as_mut()
			.unwrap()
	};
	snp_msg_hdr.algo = 1;
	snp_msg_hdr.msg_vmpck = 0; // vmpl 0
	snp_msg_hdr.msg_version = 1;
	snp_msg_hdr.hdr_version = 0x1;
	snp_msg_hdr.hdr_size = 0x60;
	snp_msg_hdr.msg_size = size_of::<SNPMessageReportRequest>() as u16;
	snp_msg_hdr.msg_type = 5;
	secrets::inc_msgseqno0();
	snp_msg_hdr.msg_seqno = secrets::get_msgseqno0();

	let mut message = SNPMessageReportRequest::new([
		0x89, 0x2a, 0xdb, 0x53, 0xc9, 0x37, 0x70, 0x6, 0xf5, 0x12, 0x5e, 0xa7, 0x21, 0xd2, 0x4c,
		0x95, 0x16, 0xbc, 0x3d, 0x86, 0x7, 0xfc, 0x63, 0xad, 0x2e, 0x76, 0xe7, 0xe, 0x57, 0xcd,
		0xa0, 0x27, 0x66, 0x45, 0xd8, 0x3, 0x91, 0x1c, 0xbf, 0x39, 0xea, 0xa, 0xb4, 0x5f, 0x80,
		0x3e, 0xf7, 0x10, 0x59, 0xcb, 0x24, 0xab, 0x5, 0xee, 0x7c, 0x43, 0x98, 0x14, 0xc4, 0x49,
		0x6d, 0xfe, 0x29, 0xd6,
	]);

	snp_msg_hdr.encrypt_message(&mut message);

	unsafe {
		ghcb::vmgexit(
			0x8000_0011,
			gpa_req.as_ptr().addr() as u64,
			gpa_resp.as_ptr().addr() as u64,
		);
	}
	secrets::inc_msgseqno0();
	trace!("Attestation request posted at physical address {gpa_req:?}, response will be available at physical address {gpa_resp:?}.");
	let snp_msg_resp_hdr = unsafe {
		gpa_resp
			.as_mut_ptr()
			.cast::<SNPMessageResponseHeader>()
			.as_mut()
			.unwrap()
	};
	let mut response = snp_msg_resp_hdr.payload;
	snp_msg_resp_hdr.decrypt_message(&mut response);
	let report = snp_msg_resp_hdr.payload;
	debug!("PSP report is {report:x?}");
}
