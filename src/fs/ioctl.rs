//! A module for custom IOCTLS

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Debug;
use ahash::RandomState;
use async_lock::RwLock;
use hashbrown::HashMap;
use hermit_sync::OnceCell;
use crate::fd::{insert_object, AccessPermission, FileDescriptor, ObjectInterface, OpenOption};
use crate::io;
use crate::io::Error::{ENOENT, EBUSY};

#[derive(Copy, Clone)]
pub struct IoCtlCall(pub u32);

impl Debug for IoCtlCall {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("IoCtlCall")
			.field("call_nr", &self.call_nr())
			.field("call_type", &self.call_type())
			.field("call_size", &self.call_size())
			.field("call_dir", &self.call_dir())
			.field(".0", &self.0)
			.finish()
	}
}

bitflags! {
	#[derive(Debug, Copy, Clone, Default)]
	pub struct IoCtlDirection: u8 {
		const IOC_WRITE = 1;
		const IOC_READ = 2;
	}
}

impl IoCtlCall {
	pub fn call_nr(&self) -> u8 {
		(self.0 & 0xff) as u8
	}

	pub fn call_type(&self) -> u8 {
		((self.0 >> 8) & 0xff) as u8
	}

	pub fn call_dir(&self) -> IoCtlDirection {
		let dir = (self.0 >> 30) & 0x3;
		IoCtlDirection::from_bits_truncate(dir as u8)
	}

	pub fn call_size(&self) -> u16 {
		((self.0 >> 16) & 0x3fff) as u16
	}
}

pub static IOCTL_REGISTRY: OnceCell<IoCtlRegistry> = OnceCell::new();

pub fn open(name: &str, flags: OpenOption, mode: AccessPermission) -> io::Result<FileDescriptor> {
	if let Some(ioctl_registry) = IOCTL_REGISTRY.get() {
		if let Ok(obj) = ioctl_registry.open(name, flags, mode) {
			insert_object(obj)
		} else {
			Err(io::Error::EINVAL)
		}
	} else {
		Err(io::Error::EINVAL)
	}
}

pub fn init() {
	if let Err(_) = IOCTL_REGISTRY.set(IoCtlRegistry {
		paths: RwLock::new(HashMap::with_hasher(RandomState::with_seeds(0, 0, 0, 0))),
	}) {
		panic!("IOCTL registry is already initialized")
	}
}

pub trait CustomIoctl: Sync {
	fn open(&self, opt: OpenOption, mode: AccessPermission) -> Arc<dyn ObjectInterface>;
}

pub struct IoCtlRegistry {
	paths: RwLock<HashMap<String, &'static dyn CustomIoctl, RandomState>>,
}

impl IoCtlRegistry {
	pub(crate) fn open(
		&self,
		path: &str,
		opt: OpenOption,
		mode: AccessPermission,
	) -> io::Result<Arc<dyn ObjectInterface>> {
        let lock = self.paths.try_read().ok_or(EBUSY)?; /* ETXTBSY ? */

        lock.get(path)
			.map(|p| p.open(opt, mode))
			.ok_or(ENOENT)
	}

    pub(crate) fn register(&self, path: &str, ioctl: &'static dyn CustomIoctl) {
        let mut lock = self.paths.try_write().unwrap();
        lock.insert(path.into(), ioctl);
    }
}
