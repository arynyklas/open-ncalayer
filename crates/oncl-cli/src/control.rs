use oncl_pki::resource::{OperationControl, ProcessingError, Progress};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
static CANCELLED: AtomicBool = AtomicBool::new(false);
pub struct Control {
    deadline: Instant,
}
impl Control {
    pub fn new(timeout: Duration) -> Result<Self, ProcessingError> {
        Ok(Self {
            deadline: Instant::now()
                .checked_add(timeout)
                .ok_or(ProcessingError::InvalidInput("timeout overflow"))?,
        })
    }
    pub fn remaining(&self) -> Result<Duration, ProcessingError> {
        self.check()?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(ProcessingError::DeadlineExceeded)
        } else {
            Ok(remaining)
        }
    }
    pub fn check(&self) -> Result<(), ProcessingError> {
        self.checkpoint(Progress::default())
    }
}
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if CANCELLED.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(ProcessingError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
}
#[cfg(windows)]
unsafe extern "system" fn signal(event: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT {
        CANCELLED.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}
#[cfg(windows)]
pub struct Signals;
#[cfg(windows)]
impl Signals {
    pub fn install() -> Result<Self, ProcessingError> {
        CANCELLED.store(false, Ordering::SeqCst);
        // SAFETY: static function pointer; handler only stores a lock-free atomic.
        if unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(signal), 1) }
            == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self)
    }
}
#[cfg(windows)]
impl Drop for Signals {
    fn drop(&mut self) {
        // SAFETY: unregister exactly our static handler, retaining others.
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(signal), 0);
        }
    }
}
#[cfg(unix)]
extern "C" fn signal(_: libc::c_int) {
    CANCELLED.store(true, Ordering::SeqCst);
}
#[cfg(unix)]
pub struct Signals {
    previous: libc::sigaction,
}
#[cfg(unix)]
impl Signals {
    pub fn install() -> Result<Self, ProcessingError> {
        CANCELLED.store(false, Ordering::SeqCst);
        // SAFETY: zero is a valid empty sigaction storage. sigemptyset initializes
        // the mask; sigaction copies these stack values before returning.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = signal as *const () as libc::sighandler_t;
        action.sa_flags = 0;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGINT, &action, &mut previous) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { previous })
    }
}
#[cfg(unix)]
impl Drop for Signals {
    fn drop(&mut self) {
        // SAFETY: restore exactly the copied original process handler.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.previous, std::ptr::null_mut());
        }
    }
}
