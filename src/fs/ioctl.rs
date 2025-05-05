//! A module for custom IOCTL objects

use alloc::sync::Arc;
use core::fmt::{Debug, Formatter};

use crate::fd::Fd;
use crate::fs::{NodeKind, VfsNode};
use crate::io;

struct IoCtlNode(Arc<async_lock::RwLock<Fd>>);

impl Debug for IoCtlNode {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		f.write_str("IoCtlNode(..)")
	}
}

impl VfsNode for IoCtlNode {
	fn get_kind(&self) -> NodeKind {
		NodeKind::File
	}

	fn get_object(&self) -> io::Result<Arc<async_lock::RwLock<Fd>>> {
		Ok(self.0.clone())
	}
}
