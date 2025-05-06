use core::fmt::{Debug};
use alloc::sync::Arc;
use core::ffi::c_void;
use core::ops::Deref;
use hermit_sync::Lazy;
use memory_addresses::VirtAddr;
use crate::fd::{AccessPermission, ObjectInterface, OpenOption};
use crate::fs::ioctl::{CustomIoctl, IOCTL_REGISTRY};
use super::ghcb_protocol::guest_request;

static SEV_GUEST_IOCTL: Lazy<SevGuestIoCtlManager> = Lazy::new(|| SevGuestIoCtlManager::new());

pub fn init() {
    let reg = IOCTL_REGISTRY.get().expect("could not get IOCTL registry");
    reg.register("/dev/sev-guest", SEV_GUEST_IOCTL.deref())
}

pub struct SevGuestIoCtlManager {
    inner: Arc<SevGuestIoCtl>
}

impl SevGuestIoCtlManager {
    pub fn new() -> Self {
        Self { inner: Arc::new(SevGuestIoCtl) }
    }
}

impl CustomIoctl for SevGuestIoCtlManager {
    fn open(&self, opt: OpenOption, mode: AccessPermission) -> Arc<dyn ObjectInterface> {
        self.inner.clone()
    }
}

#[derive(Debug)]
pub struct SevGuestIoCtl;

#[repr(C)]
struct IoCtlRequest {
    msg_version: u32,
    req_data: VirtAddr,
    resp_data: VirtAddr,
    fw_error: u32,
    vmm_error: u32
}

impl ObjectInterface for SevGuestIoCtl {
    fn handle_ioctl(&self, cmd: crate::fs::ioctl::IoCtlCall, argp: *mut c_void) -> crate::io::Result<()> {
        assert_eq!(cmd.call_type(), 0x53, "this call is not handled by this IOCTL");

        info!("sev-ioctl: command called: {cmd:x?}");

        let arg = argp as *mut IoCtlRequest;

        match cmd.call_nr() {
            0x00 /* GetReport */ => {
                info!("sev-ioctl: req_data: {:p}, resp_data: {:p}",
                    unsafe { (*arg).req_data.as_ptr::<u8>() },
                    unsafe { (*arg).resp_data.as_ptr::<u8>() },
                );

                // TODO: ensure addresses are valid
                // TODO: reduce data copies
                let attestation_request = unsafe {
                    (*arg).req_data.as_ptr::<guest_request::attestation_request::AttestationRequest>()
                };

                let attestation_request = unsafe {
                    (*attestation_request).clone()
                };

                info!("!! will print attestation request");
                info!("sev-ioctl: attestation_request: {:x?}", &attestation_request);

                let attestation_response = guest_request::send_request(
                    attestation_request
                ).unwrap();

                info!("!! will print attestation response");
                info!("sev-ioctl: attestation_response: {:x?}", &attestation_response);

                unsafe {
                    let target_ptr = (*arg).resp_data.as_mut_ptr::<guest_request::attestation_request::AttestationResponse>();
                    target_ptr.write(attestation_response);

                    // TODO
                    (*arg).fw_error = 0;
                    (*arg).vmm_error = 0;
                }
            }
            0x01 /* GetDerivedKey */ => {}
            0x02 /* GetExtReport */ => {}
            _ => panic!("this call is not handled by this IOCTL"),
        }

        Ok(())
    }
}