use alloc::collections::VecDeque;
#[cfg(feature = "amd-sev")]
use crate::arch::kernel::amd_sev;

use embedded_io::{ErrorType, Read, ReadReady, Write};
use hermit_sync::{InterruptTicketMutex, Lazy};
use uart_16550::backend::PioBackend;
use uart_16550::{Config, Uart16550};

#[cfg(feature = "pci")]
use crate::arch::x86_64::kernel::interrupts;
#[cfg(feature = "pci")]
use crate::drivers::InterruptLine;
use crate::errno::Errno;

#[cfg(feature = "pci")]
const SERIAL_IRQ: u8 = 4;

enum SerialInner {
	Uart(Uart16550<PioBackend>),
	#[cfg(feature = "amd-sev")]
	SevUart(amd_sev::paravirt_uart::SerialPort)
}

impl SerialInner {
}

impl SerialInner {
	fn new(port: u16) -> Self {
		#[cfg(feature = "amd-sev")]
		{
			let mut serial = unsafe { amd_sev::paravirt_uart::SerialPort::new(port) };
			serial.init();
			return Self::SevUart(serial)
		}

		let mut uart = unsafe { Uart16550::new_port(port).unwrap() };
		uart.init(Config::default()).ok();
		Self::Uart(uart)
	}

	fn write(&mut self, buf: &[u8]) -> Result<usize, Errno> {
		match self {
			SerialInner::Uart(inner) => Ok(inner.write(buf)?),
			#[cfg(feature = "amd-sev")]
			SerialInner::SevUart(inner) => {
				for byte in buf {
					inner.send(*byte);
				}
				Ok(buf.len())
			}
		}
	}

	fn read(&mut self, out: &mut [u8]) -> Result<usize, Errno> {
		match self {
			SerialInner::Uart(inner) => Ok(inner.read(out)?),
			#[cfg(feature = "amd-sev")]
			SerialInner::SevUart(inner) => {
				let mut index = 0;
				while index < out.len() {
					let Some(byte) = inner.try_receive().ok() else {
						break;
					};
					out[index] = byte;
					index += 1;
				}
				Ok(index)
			}
		}
	}

	fn read_ready(&mut self) -> Result<bool, Errno> {
		match self {
			SerialInner::Uart(inner) => Ok(inner.read_ready()?),
			#[cfg(feature = "amd-sev")]
			SerialInner::SevUart(inner) => {
				Ok(inner.is_read_ready())
			}
		}
	}
}

static UART_DEVICE: Lazy<InterruptTicketMutex<UartDevice>> =
	Lazy::new(|| unsafe { InterruptTicketMutex::new(UartDevice::new()) });

struct UartDevice {
	pub uart: SerialInner,
	pub buffer: VecDeque<u8>,
}

impl UartDevice {
	pub unsafe fn new() -> Self {
		let base = crate::env::boot_info()
			.hardware_info
			.serial_port_base
			.unwrap()
			.get();

		Self {
			uart: SerialInner::new(base),
			buffer: VecDeque::new(),
		}
	}
}

pub(crate) struct SerialDevice;

impl SerialDevice {
	pub fn new() -> Self {
		Self {}
	}
}

impl ErrorType for SerialDevice {
	type Error = Errno;
}

impl Read for SerialDevice {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
		Ok(UART_DEVICE.lock().buffer.read(buf)?)
	}
}

impl ReadReady for SerialDevice {
	fn read_ready(&mut self) -> Result<bool, Self::Error> {
		Ok(!UART_DEVICE.lock().buffer.is_empty())
	}
}

impl Write for SerialDevice {
	fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
		let mut guard = UART_DEVICE.lock();
		let n = guard.uart.write(buf)?;
		Ok(n)
	}

	fn flush(&mut self) -> Result<(), Self::Error> {
		Ok(())
	}
}

#[cfg(feature = "pci")]
pub(crate) fn get_serial_handler() -> (InterruptLine, fn()) {
	fn serial_handler() {
		let mut guard = UART_DEVICE.lock();

		while guard.uart.read_ready().unwrap() {
			let mut buf = [0; 256];
			let n = guard.uart.read(&mut buf).unwrap();
			guard.buffer.write_all(&buf[..n]).unwrap();
		}

		drop(guard);
		crate::console::CONSOLE_WAKER.lock().wake();
	}

	interrupts::add_irq_name(SERIAL_IRQ, "COM1");

	(SERIAL_IRQ, serial_handler)
}
