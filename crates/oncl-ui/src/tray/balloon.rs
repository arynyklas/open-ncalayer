//! Balloons of the tray icon on Windows (Windows 10 and later show them as toasts) and the
//! clicks on them.
//!
//! `tray-icon` neither shows balloons nor reports their clicks, so this goes to the shell
//! itself: `Shell_NotifyIconW(NIM_MODIFY, NIF_INFO)` on the icon's window, and a subclass of
//! that window that sees `NIN_BALLOONUSERCLICK` before `tray-icon`'s window procedure does.
//! Both rely on tray-icon 0.26.1 internals, which is why the workspace pins `=0.26.1`.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::Shell::{
    NIF_INFO, NIIF_INFO, NIIF_RESPECT_QUIET_TIME, NIM_MODIFY, NIN_BALLOONUSERCLICK,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{CallWindowProcW, GWLP_WNDPROC, WNDPROC};

use super::{ActionTarget, Notification, TrayError, deliver_click};

/// The callback message `tray-icon` 0.26 registers its icon with (its private
/// `WM_USER_TRAYICON`): the shell reports balloon events with it.
const TRAY_CALLBACK: u32 = 6002;
/// The icon ids `tray-icon` hands out: a per-process counter from 1. The shell accepts a
/// balloon only for the id the icon has, so the first id it accepts is the icon's.
const ICON_IDS: std::ops::RangeInclusive<u32> = 1..=16;

/// `tray-icon`'s window procedure, which the subclass passes every message on to.
static ORIGINAL_PROC: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    /// What a click on the last balloon does.
    static CLICK: RefCell<Option<ActionTarget>> = const { RefCell::new(None) };
}

/// The balloons of the tray icon whose window is `hwnd`.
pub(super) struct Balloons {
    hwnd: HWND,
    /// The icon's id, once the shell has accepted it.
    id: Cell<Option<u32>>,
}

impl Balloons {
    /// Subclasses the icon's window `hwnd` (created by `tray-icon` on this thread, alive as
    /// long as the icon).
    pub(super) fn new(hwnd: HWND) -> Balloons {
        // SAFETY: `hwnd` is the live window of this thread's tray icon; `subclass_proc`
        // passes every message on to the procedure stored here before it can run.
        let original = unsafe { set_window_proc(hwnd, subclass_proc as *const () as isize) };
        ORIGINAL_PROC.store(original, Ordering::Release);
        Balloons {
            hwnd,
            id: Cell::new(None),
        }
    }

    pub(super) fn show(&self, notification: Notification) -> Result<(), TrayError> {
        let body = match &notification.action {
            // A balloon has no buttons: the whole balloon is the button.
            Some(action) => format!("{}\n{}", notification.body, action.label),
            None => notification.body.clone(),
        };
        // Fields by value: NOTIFYICONDATAW is packed on 32-bit Windows, which rules out
        // references to its fields.
        let mut data = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd,
            uFlags: NIF_INFO,
            dwInfoFlags: NIIF_INFO | NIIF_RESPECT_QUIET_TIME,
            szInfo: wide(&body),
            szInfoTitle: wide(&notification.title),
            ..Default::default()
        };
        let ids = self.id.get().map_or(ICON_IDS, |id| id..=id);
        for id in ids {
            data.uID = id;
            // SAFETY: `data` is a complete NOTIFYICONDATAW of the current size.
            if unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) } != 0 {
                self.id.set(Some(id));
                CLICK.set(notification.action.map(|a| a.target));
                return Ok(());
            }
        }
        Err(TrayError(
            "the shell does not accept a balloon for the tray icon".to_owned(),
        ))
    }
}

/// `text` as a NUL-terminated UTF-16 field, cut to fit (never within a surrogate pair).
fn wide<const N: usize>(text: &str) -> [u16; N] {
    let mut field = [0; N];
    let mut len = 0;
    for c in text.chars() {
        let mut units = [0; 2];
        let units = c.encode_utf16(&mut units);
        if len + units.len() >= N {
            break;
        }
        field[len..len + units.len()].copy_from_slice(units);
        len += units.len();
    }
    field
}

/// Sees balloon clicks, then hands every message to `tray-icon`'s procedure.
unsafe extern "system" fn subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Without NOTIFYICON_VERSION_4 (which tray-icon does not set) the event is `lparam`.
    if msg == TRAY_CALLBACK
        && (lparam as u32 & 0xffff) == NIN_BALLOONUSERCLICK
        && let Some(target) = CLICK.take()
    {
        deliver_click(target);
    }
    // SAFETY: the stored value is the window procedure `set_window_proc` replaced (or 0,
    // `None`, before it is stored: `CallWindowProcW` then does nothing).
    unsafe {
        let original: WNDPROC = std::mem::transmute(ORIGINAL_PROC.load(Ordering::Acquire));
        CallWindowProcW(original, hwnd, msg, wparam, lparam)
    }
}

/// Sets the window procedure of `hwnd`; returns the previous one.
#[cfg(target_pointer_width = "64")]
unsafe fn set_window_proc(hwnd: HWND, proc: isize) -> isize {
    // SAFETY: as the caller's.
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, proc)
    }
}

/// Sets the window procedure of `hwnd`; returns the previous one.
#[cfg(target_pointer_width = "32")]
unsafe fn set_window_proc(hwnd: HWND, proc: isize) -> isize {
    // SAFETY: as the caller's; pointers are 32 bits wide here.
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::SetWindowLongW(hwnd, GWLP_WNDPROC, proc as i32)
            as isize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_fields_are_cut_and_terminated() {
        let field: [u16; 6] = wide("ab");
        assert_eq!(field, [u16::from(b'a'), u16::from(b'b'), 0, 0, 0, 0]);
        let field: [u16; 6] = wide("abcdefgh");
        assert_eq!(field[5], 0);
        assert_eq!(String::from_utf16(&field[..5]).unwrap(), "abcde");
        // A surrogate pair that does not fit is left out whole.
        let field: [u16; 6] = wide("abcd😀");
        assert_eq!(String::from_utf16(&field[..4]).unwrap(), "abcd");
        assert_eq!(field[4], 0);
    }
}
