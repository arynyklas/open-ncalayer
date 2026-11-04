//! CLI-only terminal ownership; no global SDK prompter or secret reallocations.
use oncl_core::{OperationContext, OperationError};
use oncl_pki::resource::ProcessingError;
use std::io::{self, Read};
use zeroize::{Zeroize, Zeroizing};
const MAX: usize = 4096;

pub fn finish(bytes: &[u8]) -> Result<Zeroizing<String>, OperationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| OperationError::SecretRequired)?;
    let mut result = Zeroizing::new(String::new());
    result
        .try_reserve_exact(text.len())
        .map_err(|_| ProcessingError::MemoryLimit)?;
    // The only owned string allocation happens before copying any secret byte.
    // zeroize 1.9.1 String delegates to Vec::zeroize, including spare capacity.
    result.push_str(text);
    Ok(result)
}
fn pop(bytes: &mut [u8; MAX], len: &mut usize) {
    if *len == 0 {
        return;
    }
    let start = std::str::from_utf8(&bytes[..*len])
        .expect("editor retains UTF-8")
        .char_indices()
        .next_back()
        .map(|(i, _)| i)
        .unwrap_or(0);
    bytes[start..*len].zeroize();
    *len = start;
}
/// `ERROR_OPERATION_ABORTED`: what `ReadConsoleW` reports when a control event
/// interrupts it.
fn is_console_abort(error: &io::Error) -> bool {
    cfg!(windows) && error.raw_os_error() == Some(995)
}
pub fn read_bounded(
    reader: &mut impl Read,
    ctx: &mut OperationContext,
) -> Result<Zeroizing<String>, OperationError> {
    let mut password = Zeroizing::new([0u8; MAX]);
    let mut scalar = Zeroizing::new([0u8; 4]);
    let mut len = 0;
    let mut scalar_len = 0;
    let mut raw = 0usize;
    loop {
        ctx.resources().checkpoint()?;
        if raw > MAX {
            return Err(OperationError::SecretRequired);
        }
        let read = reader.read(&mut scalar[scalar_len..scalar_len + 1]);
        ctx.resources().checkpoint()?;
        let count = match read {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            // Ctrl-C/Ctrl-Break aborts a console read before the handler thread
            // is guaranteed to have latched the control; the abort itself is the
            // cancellation, not an I/O failure.
            Err(error) if is_console_abort(&error) => return Err(ProcessingError::Cancelled.into()),
            result => result.map_err(ProcessingError::from)?,
        };
        if count == 0 {
            return Err(OperationError::SecretRequired);
        }
        raw = raw
            .checked_add(count)
            .ok_or(OperationError::SecretRequired)?;
        scalar_len += count;
        let character = match std::str::from_utf8(&scalar[..scalar_len]) {
            Ok(text) => text.chars().next().ok_or(OperationError::SecretRequired)?,
            Err(error) if error.error_len().is_none() && scalar_len < 4 => continue,
            Err(_) => return Err(OperationError::SecretRequired),
        };
        match character {
            '\n' | '\r' => return finish(&password[..len]),
            '\x03' => return Err(ProcessingError::Cancelled.into()),
            '\x04' => return Err(OperationError::SecretRequired),
            '\x08' | '\x7f' => pop(&mut password, &mut len),
            '\x15' => {
                password[..len].zeroize();
                len = 0;
            }
            '\x17' => {
                while len > 0
                    && std::str::from_utf8(&password[..len])
                        .expect("UTF-8")
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)
                {
                    pop(&mut password, &mut len);
                }
                while len > 0
                    && std::str::from_utf8(&password[..len])
                        .expect("UTF-8")
                        .chars()
                        .next_back()
                        .is_some_and(|c| !c.is_whitespace())
                {
                    pop(&mut password, &mut len);
                }
            }
            c if c.is_control() => return Err(OperationError::SecretRequired),
            _ => {
                let end = len
                    .checked_add(scalar_len)
                    .filter(|n| *n <= MAX)
                    .ok_or(OperationError::SecretRequired)?;
                password[len..end].copy_from_slice(&scalar[..scalar_len]);
                len = end;
            }
        }
        scalar.zeroize();
        scalar_len = 0;
    }
}
pub fn read(ctx: &mut OperationContext) -> Result<Zeroizing<String>, OperationError> {
    let mut terminal = platform::Terminal::open(ctx.resources()).map_err(ProcessingError::from)?;
    std::io::Write::write_all(
        &mut std::io::stderr().lock(),
        b"Key secret (input hidden): ",
    )
    .map_err(ProcessingError::from)?;
    let result = read_bounded(&mut terminal, ctx);
    let restore = terminal.restore();
    crate::diagnostic(format_args!(""));
    if restore.is_err() {
        crate::diagnostic(format_args!("oncl: TerminalRestoreFailed"));
    }
    match result {
        Err(error) => Err(error),
        Ok(secret) => {
            restore.map_err(ProcessingError::from)?;
            Ok(secret)
        }
    }
}
#[cfg(windows)]
mod platform {
    use super::*;
    use std::{fs::File, os::windows::io::AsRawHandle};
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, ReadConsoleW, SetConsoleMode,
    };
    pub struct Terminal {
        file: File,
        scope: oncl_pki::resource::ResourceScope,
        mode: u32,
        restored: bool,
        pending: Zeroizing<[u8; 4]>,
        start: usize,
        end: usize,
    }
    impl Terminal {
        pub fn open(scope: &oncl_pki::resource::ResourceScope) -> io::Result<Self> {
            let file = File::options().read(true).write(true).open("CONIN$")?;
            let mut mode = 0;
            // SAFETY: the owned explicit console handle is live; output is valid.
            if unsafe { GetConsoleMode(file.as_raw_handle(), &mut mode) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let terminal = Self {
                file,
                scope: scope.shared_view(),
                mode,
                restored: false,
                pending: Zeroizing::new([0; 4]),
                start: 0,
                end: 0,
            };
            // SAFETY: affect only this console input handle, preserving all other bits.
            if unsafe { SetConsoleMode(terminal.file.as_raw_handle(), mode & !ENABLE_ECHO_INPUT) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(terminal)
        }
        fn unit(&self) -> io::Result<u16> {
            self.scope.checkpoint().map_err(io::Error::other)?;
            let mut unit = Zeroizing::new([0u16; 1]);
            let mut count = 0;
            // SAFETY: one UTF-16 slot, exact declared count, live owned console handle.
            let succeeded = unsafe {
                ReadConsoleW(
                    self.file.as_raw_handle(),
                    unit.as_mut_ptr().cast(),
                    1,
                    &mut count,
                    std::ptr::null(),
                )
            };
            self.scope.checkpoint().map_err(io::Error::other)?;
            if succeeded == 0 {
                return Err(io::Error::last_os_error());
            }
            if count != 1 {
                // Ctrl-C/Ctrl-Break with processed input completes the read with
                // zero units (observed on a ConPTY): report it as the console
                // abort it is, never as a terminal I/O failure.
                return Err(io::Error::from_raw_os_error(995));
            }
            Ok(unit[0])
        }
        pub fn restore(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            // SAFETY: handle remains owned and live through restoration.
            if unsafe { SetConsoleMode(self.file.as_raw_handle(), self.mode) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
            Ok(())
        }
    }
    impl Read for Terminal {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if output.is_empty() {
                return Ok(0);
            }
            if self.start == self.end {
                self.pending.zeroize();
                self.start = 0;
                let mut units = Zeroizing::new([0u16; 2]);
                units[0] = self.unit()?;
                let count = if (0xd800..=0xdbff).contains(&units[0]) {
                    units[1] = self.unit()?;
                    2
                } else {
                    1
                };
                let mut chars = char::decode_utf16(units[..count].iter().copied());
                let character = chars
                    .next()
                    .ok_or_else(|| io::Error::other("invalid terminal scalar"))?
                    .map_err(|_| io::Error::other("invalid terminal scalar"))?;
                self.end = character.encode_utf8(&mut *self.pending).len();
            }
            let count = output.len().min(self.end - self.start);
            output[..count].copy_from_slice(&self.pending[self.start..self.start + count]);
            self.pending[self.start..self.start + count].zeroize();
            self.start += count;
            Ok(count)
        }
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            if self.restore().is_err() {
                crate::diagnostic(format_args!("oncl: TerminalRestoreFailed"));
            }
        }
    }
}
#[cfg(unix)]
mod platform {
    use super::*;
    use std::{fs::File, os::fd::AsRawFd};
    pub struct Terminal {
        file: File,
        original: libc::termios,
        restored: bool,
    }
    impl Terminal {
        pub fn open(_scope: &oncl_pki::resource::ResourceScope) -> io::Result<Self> {
            let file = File::options().read(true).write(true).open("/dev/tty")?;
            // SAFETY: zero is valid storage; tcgetattr initializes the complete structure.
            let mut original: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(file.as_raw_fd(), &mut original) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let terminal = Self {
                file,
                original,
                restored: false,
            };
            let mut mode = terminal.original;
            mode.c_lflag &= !libc::ECHO;
            // SAFETY: valid original-derived termios and live explicit terminal descriptor.
            if unsafe { libc::tcsetattr(terminal.file.as_raw_fd(), libc::TCSANOW, &mode) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(terminal)
        }
        pub fn restore(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            // SAFETY: restore exactly the saved structure while its descriptor lives.
            if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, &self.original) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
            Ok(())
        }
    }
    impl Read for Terminal {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.file.read(output)
        }
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            if self.restore().is_err() {
                crate::diagnostic(format_args!("oncl: TerminalRestoreFailed"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
    use oncl_pki::resource::{OperationControl, Progress, ResourceLimits};
    use std::sync::Arc;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            Ok(())
        }
    }
    fn context() -> OperationContext {
        Engine::new(EngineServices::hash_only(ResourceLimits::default()))
            .unwrap()
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap()
    }
    #[test]
    fn fixed_secret_editor_uses_utf8_byte_bound_and_never_truncates() {
        for input in ["a".repeat(4096), "\u{10348}".repeat(1024)] {
            let mut with_enter = input.as_bytes().to_vec();
            with_enter.push(b'\n');
            let secret = read_bounded(&mut with_enter.as_slice(), &mut context()).unwrap();
            assert_eq!(secret.as_bytes(), input.as_bytes());
            let mut too_long = input.as_bytes().to_vec();
            too_long.extend_from_slice(b"x\n");
            assert!(read_bounded(&mut too_long.as_slice(), &mut context()).is_err());
        }
        for mut input in [
            b"no enter".as_slice(),
            b"\xf0\x28\x8c\x28\n",
            b"\xed\xa0\x80\n",
        ] {
            assert!(read_bounded(&mut input, &mut context()).is_err());
        }
    }
    #[test]
    fn editing_removes_complete_scalars_and_clear_operations() {
        for (input, want) in [
            ("a\u{10348}\u{8}b\n", "ab"),
            ("discard\u{15}chosen\n", "chosen"),
            ("first second\u{17}last\n", "first last"),
        ] {
            let secret = read_bounded(&mut input.as_bytes(), &mut context()).unwrap();
            assert_eq!(secret.as_str(), want);
        }
        assert_eq!(
            read_bounded(&mut b"\x03".as_slice(), &mut context())
                .unwrap_err()
                .code(),
            oncl_core::ErrorCode::Cancelled
        );
    }
}
