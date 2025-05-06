use core::fmt::{Debug};
use alloc::sync::Arc;
use core::ffi::c_void;
use core::ops::Deref;
use hermit_sync::Lazy;
use crate::fd::{AccessPermission, ObjectInterface, OpenOption};
use crate::fs::ioctl::{CustomIoctl, IOCTL_REGISTRY};

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

impl ObjectInterface for SevGuestIoCtl {
    fn handle_ioctl(&self, cmd: crate::fs::ioctl::IoCtlCall, argp: *mut c_void) -> crate::io::Result<()> {
        assert_eq!(cmd.call_type(), 0x53, "this call is not handled by this IOCTL");

        info!("sev-ioctl: command called: {cmd:x?}");

        match cmd.call_nr() {
            0x00 /* GetReport */ => {}
            0x01 /* GetDerivedKey */ => {}
            0x02 /* GetExtReport */ => {}
            _ => panic!("this call is not handled by this IOCTL"),
        }

        Ok(())
    }
}