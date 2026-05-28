pub mod attestation_request;
mod error;

use super::protocol_page_state_change::{
    change_page_states, PageStateChangeEntry, PageStateChangeOperation,
};
use crate::arch::kernel::amd_sev::ghcb_protocol::GhcbProtocolError;
use crate::arch::kernel::amd_sev::ghcb_protocol::allocated_ghcb::with_ghcb;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::Ghcb;
use crate::arch::kernel::amd_sev::ghcb_protocol::{checked_vmgexit, GhcbExitCode, PostProcessingError};
use crate::arch::kernel::amd_sev::cc_blob::{CommunicationKeyNumber, CC_BLOB};
use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::slice;
use hermit_sync::{InterruptSpinMutex, InterruptSpinMutexGuard, Lazy};
use memory_addresses::PhysAddr;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::structures::paging::{PageSize, Size4KiB};
use zerocopy::{FromBytes, Immutable, IntoBytes};
use error::GuestProtocolError;
use crate::arch::kernel::amd_sev::ghcb_protocol::ghcb::GhcbU64Field;
use crate::mm::device_alloc::DeviceAlloc;

type RequestPageMutex = InterruptSpinMutex<SNPSharedPage>;

#[derive(PartialEq, Eq, Debug)]
#[repr(u8)]
enum AeadAlgorithm {
    AesGcm = 1
}

#[derive(PartialEq, Eq, Debug)]
#[repr(u8)]
enum HeaderVersion {
    Version1 = 1
}

#[derive(Debug, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum MessageType {
    CpuidRequest = 1,
    CpuidResponse = 2,
    KeyRequest = 3,
    KeyResponse = 4,
    ReportRequest = 5,
    ReportResponse = 6,
    ExportRequest = 7,
    ExportResponse = 8,
    ImportRequest = 9,
    ImportResponse = 10,
    AbsorbRequest = 11,
    AbsorbResponse = 12,
    VmrkRequest = 13,
    VmrkResponse = 14,
    AbsorbNomaRequest = 15,
    AbsorbNomaResponse = 16,
    TscInfoRequest = 17,
    TscInfoResponse = 18,
}

#[repr(C)]
struct RequestPageHeader {
    /// Authentication tag for this message
    pub authentication_tag: [u8; 0x20], // 32 bytes authentication tag

    /// Message sequence number. Used to construct the IV.
    pub seqno: u64,

    _reserved1: u64,

    /// Algorithm to use to encrypt the message
    pub algo: AeadAlgorithm,

    /// Header version
    pub header_version: HeaderVersion,

    /// Header size in bytes
    pub header_size: u16,

    pub message_type: MessageType,

    /// Message version - protocol dependent, currently always 1
    pub message_version: u8,

    /// Payload size in bytes
    pub payload_size: u16,

    _reserved2: u32,

    /// The key number used for this message. See [`super::super::cc_blob::CommunicationKeyNumber`]
    pub vmkey: u8,

    _reserved3: u8,
    _reserved4: u16,
    _reserved5: [u8; 0x20]
}

impl Default for RequestPageHeader {
    fn default() -> Self {
        Self::new(MessageType::AbsorbNomaRequest, 0, 0, CommunicationKeyNumber::VmPck0)
    }
}

impl RequestPageHeader {
    pub fn new(
        message_type: MessageType,
        payload_size: u16,
        sequence_number: u32,
        vmkey: CommunicationKeyNumber
    ) -> Self {
        Self {
            authentication_tag: [0u8; 0x20],
            _reserved1: 0,
            seqno: sequence_number as u64,
            algo: AeadAlgorithm::AesGcm,
            header_version: HeaderVersion::Version1,
            header_size: size_of::<RequestPageHeader>() as u16,
            message_type,
            message_version: 1,
            payload_size,
            _reserved2: 0,
            vmkey: usize::from(vmkey) as u8,
            _reserved3: 0,
            _reserved4: 0,
            _reserved5: [0u8; 0x20],
        }
    }

    pub fn associated_data(&self) -> &[u8] {
        unsafe {
            let self_ptr = self as *const _ as *const u8;
            let authenticated_data_start = self_ptr.add(0x30);

            // From reference: authenticate bytes 0x30 to 0x5f (inclusive) of the header
            slice::from_raw_parts(authenticated_data_start, 0x30)
        }
    }

    pub fn nonce(&self) -> Nonce<U12> {
        let mut iv: Nonce<U12> = Default::default();
        iv[0..8].copy_from_slice(self.seqno.to_le_bytes().as_ref());

        iv
    }
}

static REQUEST_PAGE: Lazy<RequestPageMutex> = Lazy::new(|| SNPSharedPage::allocate());
static RESPONSE_PAGE: Lazy<RequestPageMutex> = Lazy::new(|| SNPSharedPage::allocate());
/* static CRYPTO_BUFFER: Lazy<InterruptSpinMutex<Box<[u8; 0x1000]>>> = Lazy::new(|| {
    InterruptSpinMutex::new(Box::new([0; 0x1000]))
}); */

struct SNPSharedPage(&'static mut SNPSharedPageInner, PhysAddr);

#[repr(C, align(0x1000))]
struct SNPSharedPageInner {
    header: RequestPageHeader,
    payload: [u8; 0x1000 - size_of::<RequestPageHeader>()],
}

impl Default for SNPSharedPageInner {
    fn default() -> Self {
        Self {
            header: RequestPageHeader::default(),
            payload: [0; 0x1000 - size_of::<RequestPageHeader>()],
        }
    }
}

impl SNPSharedPage {
    pub fn allocate() -> RequestPageMutex {
        let layout =
            Layout::from_size_align(Size4KiB::SIZE as usize, Size4KiB::SIZE as usize).unwrap();
        let (ptr, physical_address) = DeviceAlloc
            .allocate_with_physical(layout)
            .expect("failed to allocate memory for communication page");

        // Mark the allocated memory as shared
        change_page_states(&[PageStateChangeEntry::new_for_address(
            x86_64::PhysAddr::new(physical_address.as_u64()),
            layout.size() as u64,
            PageStateChangeOperation::PageAssignShared,
        )])
            .expect("failed to change page state");

        // Set the content of the memory
        let ptr = ptr.as_mut_ptr::<SNPSharedPageInner>();
        let reference = unsafe {
            ptr.write(SNPSharedPageInner::default());
            ptr.as_mut().unwrap()
        };

        InterruptSpinMutex::new(SNPSharedPage(reference, physical_address))
    }

    fn header_mut(&mut self) -> &mut RequestPageHeader {
        &mut self.0.header
    }

    fn header(&self) -> &RequestPageHeader {
        &self.0.header
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        assert_ne!(self.0.header.payload_size, 0);
        assert!(self.0.header.payload_size < self.0.payload.len() as u16);

        &mut self.0.payload[0..self.0.header.payload_size as usize]
    }

    fn payload(&self) -> &[u8] {
        assert_ne!(self.0.header.payload_size, 0);
        assert!(self.0.header.payload_size < self.0.payload.len() as u16);

        &self.0.payload[0..self.0.header.payload_size as usize]
    }

    fn clear(&mut self) {
        self.0.payload = [0; 0x1000 - size_of::<RequestPageHeader>()];
        self.0.header = RequestPageHeader::default();
    }

    fn reset(&mut self, header: RequestPageHeader) {
        self.0.payload = [0; 0x1000 - size_of::<RequestPageHeader>()];
        self.0.header = header;
    }
}


pub trait SNPGuestRequest: Sized + IntoBytes + Immutable {
	type ResponseType: Sized + FromBytes;

    fn message_type() -> MessageType;

    fn send(self) -> Result<Self::ResponseType, GuestProtocolError> {
        send_request(self)
    }
}

pub trait SNPGuestResponse: Sized + FromBytes {
    fn message_type() -> MessageType;
}

pub struct RequestAttestation {
	report_data: Option<[u8; 64]>,
}

pub fn send_request<R: SNPGuestRequest>(request: R) -> Result<R::ResponseType, GuestProtocolError> {
    // Ensure pages are set before entering the GHCB mode
    Lazy::force(&REQUEST_PAGE);
    Lazy::force(&RESPONSE_PAGE);

    without_interrupts(|| {
        with_ghcb(|ghcb| {
            send_request_typed(ghcb, request)
        })
    })
}

pub fn send_bin_request(request: Vec<u8>, code: MessageType) -> Result<Vec<u8>, GuestProtocolError> {
    // Ensure pages are set before entering the GHCB mode
    Lazy::force(&REQUEST_PAGE);
    Lazy::force(&RESPONSE_PAGE);

    without_interrupts(|| {
        with_ghcb(|ghcb| {
            send_request_raw(ghcb, code, request)
        })
    })
}

fn write_request_raw(req_page: &mut InterruptSpinMutexGuard<'_, SNPSharedPage>, message_type: MessageType, mut request: Vec<u8>) {
    // Read request as bytes
    let request_size = request.len();

    // Make sure the request is not too big
    assert!(request_size <= 0x1000 - size_of::<RequestPageHeader>());

    // Get the next key
    let (key_no, key, seqno) = CC_BLOB.secrets().get_next_available_key().expect("key space exhausted");
    CC_BLOB.secrets().increase_sequence_number(key_no);
    let seqno = seqno + 1;

    // Prepare the header
    let header = RequestPageHeader::new(
        message_type,
        request_size as u16,
        seqno,
        key_no
    );
    req_page.reset(header);
    let header = req_page.header_mut();

    // Encrypt the payload
    let mut payload = request.as_mut_slice();
    let aes = Aes256Gcm::new(&key);
    let tag: Tag<U16> = aes.encrypt_in_place_detached(&header.nonce(), header.associated_data(), &mut payload).unwrap();
    header.authentication_tag[0..16].copy_from_slice(tag.as_slice());

    // Set the payload
    req_page.payload_mut().clone_from_slice(payload);
}

fn read_response_raw(rep_page: &InterruptSpinMutexGuard<'_, SNPSharedPage>) -> Result<Vec<u8>, GuestProtocolError> {
    // Verify header
    let header = rep_page.header();

    assert_eq!(header.header_version, HeaderVersion::Version1);
    assert_eq!(header.algo, AeadAlgorithm::AesGcm);
    assert_eq!(header.header_size, size_of::<RequestPageHeader>() as u16);

    let key_used = CommunicationKeyNumber::try_from(header.vmkey as usize).expect("invalid VMKey number");
    CC_BLOB.secrets().increase_sequence_number(key_used);
    let seqno = CC_BLOB.secrets().get_sequence_number(key_used);

    assert_eq!(header.seqno, seqno as u64);

    // Decrypt payload
    let payload = rep_page.payload();
    let key = CC_BLOB.secrets().get_key(key_used);
    let tag: &Tag = Tag::from_slice(&header.authentication_tag[0..16]);
    let aes = Aes256Gcm::new(&key);
    let mut decrypted = Vec::from(payload);
    aes.decrypt_in_place_detached(&header.nonce(), header.associated_data(), &mut decrypted, tag)
        .map_err(|_| GuestProtocolError::CryptoError)?;

    Ok(decrypted)
}

fn send_request_raw(ghcb: &mut Ghcb, request_type: MessageType, request: Vec<u8>) -> Result<Vec<u8>, GuestProtocolError>{
    ghcb.clear();
    let mut req_page = (&*REQUEST_PAGE).lock();

    write_request_raw(&mut req_page, request_type, request);

    // Write and send the request
    let mut resp_page = (&*RESPONSE_PAGE).lock();
    resp_page.clear();
    checked_vmgexit(ghcb, GhcbExitCode::SnpGuestRequest, req_page.1.as_u64(), resp_page.1.as_u64())?;
    drop(req_page);

    let exit2 = ghcb.get_field_if_valid(GhcbU64Field::SwExitInfo2)?;
    if exit2 != 0 {
        Err(GuestProtocolError::from_fw_error(exit2))
    } else {
        // Read the response
        read_response_raw(&resp_page)
    }
}

fn send_request_typed<R: SNPGuestRequest>(ghcb: &mut Ghcb, request: R) -> Result<R::ResponseType, GuestProtocolError> {
    let decrypted = send_request_raw(ghcb, R::message_type(), Vec::from(request.as_bytes()))?;

    // Return result
    R::ResponseType::read_from_bytes(&decrypted)
        .map_err(|_| GuestProtocolError::GhcbProtocolError(GhcbProtocolError::PostProcessingError(
            PostProcessingError::ParseError
        )))
}