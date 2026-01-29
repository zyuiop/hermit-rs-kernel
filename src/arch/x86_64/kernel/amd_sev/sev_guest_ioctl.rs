use core::fmt::{Debug, Formatter};
use alloc::sync::Arc;
use core::ffi::c_void;
use hermit_sync::Lazy;
use memory_addresses::VirtAddr;
use crate::fd::{Fd, ObjectInterface, OpenOption};
use crate::fs::ioctl::register_ioctl;
use super::ghcb_protocol::guest_request;

pub fn init() {
    register_ioctl("/dev/sev-guest", Arc::new(async_lock::RwLock::new(Fd::SevGuest(SevGuestIoCtl))))
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
    fn handle_ioctl(&mut self, cmd: crate::fs::ioctl::IoCtlCall, argp: *mut c_void) -> crate::io::Result<()> {
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