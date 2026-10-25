//! Windows: a dialog that was just shown takes the foreground and the keyboard focus.
//!
//! Windows' foreground lock lets a background process put a window on top but not activate
//! it. Without this, the first dialog after the daemon starts stays inactive and the
//! password the user types goes to the browser.

use slint::ComponentHandle;

/// Brings `ui`, just shown, to the foreground with the keyboard focus once its window
/// exists; logs a warning if Windows refuses. Does nothing on other systems.
pub(crate) fn take<C: ComponentHandle + 'static>(ui: &C) {
    #[cfg(windows)]
    win::take(ui.as_weak(), win::ATTEMPTS);
    #[cfg(not(windows))]
    let _ = ui;
}

#[cfg(windows)]
mod win {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use slint::{ComponentHandle, Timer, Weak};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{FALSE, HWND, TRUE};
    use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_KEYBOARD, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_KEYUP, SendInput,
        SetActiveWindow, SetFocus, VK_MENU,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, GetForegroundWindow, GetWindowThreadProcessId, IsWindowVisible,
        SetForegroundWindow,
    };

    /// How many times to look for the window before giving up.
    pub(super) const ATTEMPTS: u32 = 20;
    /// Pause between looks.
    const RETRY: Duration = Duration::from_millis(25);

    /// Activates `ui`'s window once it is visible, retrying [`ATTEMPTS`] times.
    pub(super) fn take<C: ComponentHandle + 'static>(ui: Weak<C>, left: u32) {
        let hwnd = {
            let Some(dialog) = ui.upgrade() else {
                return;
            };
            if !dialog.window().is_visible() {
                // Answered or closed meanwhile.
                return;
            }
            hwnd(dialog.window())
        };
        match hwnd {
            // SAFETY: `h` is the live top-level window of `ui`.
            Some(h) if unsafe { IsWindowVisible(h) } != FALSE => activate(h),
            _ if left > 0 => Timer::single_shot(RETRY, move || take(ui, left - 1)),
            _ => tracing::warn!("cannot find the dialog window to give it the keyboard focus"),
        }
    }

    /// The Win32 handle of `w`.
    fn hwnd(w: &slint::Window) -> Option<HWND> {
        let handle = slint::Window::window_handle(w);
        match handle.window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(h) => Some(h.hwnd.get() as HWND),
            _ => None,
        }
    }

    /// Makes `hwnd` the foreground window, from the least to the most intrusive way:
    /// plainly (allowed once this process has been in the foreground), with the ALT-key
    /// trick, then with the foreground thread's input attached.
    ///
    /// The ALT-key trick comes before attaching input: after an activation with attached
    /// input the window is in the foreground and keys reach the password field, but Slint's
    /// accessibility tree still reports the window as unfocused (no focused field for
    /// screen readers).
    fn activate(hwnd: HWND) {
        // SAFETY: plain user32 calls on our own live window.
        let plain = unsafe {
            SetForegroundWindow(hwnd);
            GetForegroundWindow() == hwnd
        };
        if plain {
            return;
        }
        if with_alt_key(hwnd) {
            tracing::debug!("dialog activated after a synthetic ALT key");
        } else if with_attached_input(hwnd) {
            tracing::debug!("dialog activated with the foreground thread's input attached");
        } else {
            tracing::warn!(
                "Windows refused the dialog the keyboard focus: it is on top but inactive"
            );
        }
    }

    /// Activates `hwnd` between a synthetic ALT press and release: the process that sent
    /// the last input may set the foreground window. Whether `hwnd` is now in the
    /// foreground.
    fn with_alt_key(hwnd: HWND) -> bool {
        // SAFETY: plain user32 calls on our own live window.
        unsafe {
            alt(0);
            SetForegroundWindow(hwnd);
            alt(KEYEVENTF_KEYUP);
            SetFocus(hwnd);
            GetForegroundWindow() == hwnd
        }
    }

    /// Activates `hwnd` while our thread shares input state with the foreground window's
    /// thread, which lifts the foreground lock. Whether `hwnd` is now in the foreground.
    fn with_attached_input(hwnd: HWND) -> bool {
        // SAFETY: plain user32/kernel32 calls on window handles; a stale foreground handle
        // only makes them fail.
        unsafe {
            let foreground = GetForegroundWindow();
            let ours = GetCurrentThreadId();
            let theirs = if foreground.is_null() {
                0
            } else {
                GetWindowThreadProcessId(foreground, std::ptr::null_mut())
            };
            let attached =
                theirs != 0 && theirs != ours && AttachThreadInput(ours, theirs, TRUE) != FALSE;
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            SetActiveWindow(hwnd);
            SetFocus(hwnd);
            if attached {
                AttachThreadInput(ours, theirs, FALSE);
            }
            GetForegroundWindow() == hwnd
        }
    }

    /// Sends an ALT key event with `flags`.
    fn alt(flags: KEYBD_EVENT_FLAGS) {
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VK_MENU,
                    wScan: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let size = i32::try_from(size_of::<INPUT>()).unwrap_or(i32::MAX);
        // SAFETY: one initialized `INPUT` of the size given.
        if unsafe { SendInput(1, &input, size) } != 1 {
            tracing::debug!("SendInput of ALT was blocked");
        }
    }
}
