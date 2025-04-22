#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum SvmExitCode {
    IoIo = 0x7b
}