use alloc::boxed::Box;
use alloc::sync::Arc;
use async_lock::RwLock;
use crate::errno::Errno;
use crate::fd::{Fd, ObjectInterface};
use crate::fs::{NodeKind, VfsNode};

#[derive(Debug)]
pub(crate) struct RandomDevice;

impl VfsNode for RandomDevice {
    fn get_kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn get_object(&self) -> crate::io::Result<Arc<RwLock<Fd>>> {
        Ok(Arc::new(RwLock::new(Fd::RandomDevice(RandomDevice))))
    }
}

impl ObjectInterface for RandomDevice {
    async fn read(&self, buf: &mut [u8]) -> crate::io::Result<usize> {
        let mut written = 0usize;
        while written < buf.len() {
            let res = crate::entropy::read(&mut buf[written..], crate::entropy::Flags::empty());

            if res < 0 {
                return Err(Errno::try_from(res as i32).unwrap())
            } else {
                written += res as usize;
            }
        }

        Ok(written)
    }
}

pub fn init() {
    let fs = super::FILESYSTEM
        .get()
        .expect("Failed to mount random devices: filesystem is not yet initialized");

    fs.mount("/dev/urandom", Box::new(RandomDevice))
        .expect("could not mount /dev/urandom");
    fs.mount("/dev/random", Box::new(RandomDevice))
        .expect("could not mount /dev/random");
}