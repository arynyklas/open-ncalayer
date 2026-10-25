//! Default values of HKCU keys: where Chromium-family browsers and Firefox look up native
//! messaging host manifests on Windows.

use std::io;
use std::iter::once;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW,
};

/// `s` as a NUL-terminated UTF-16 string.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

fn check(status: u32) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        // Win32 error codes fit in i32.
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

/// Sets the default value of `HKCU\<key>` to the string `value`, creating the key and its
/// missing parents.
pub fn set_default(key: &str, value: &str) -> io::Result<()> {
    let key = wide(key);
    let mut hkey: HKEY = ptr::null_mut();
    // SAFETY: `key` is NUL-terminated and outlives the call; the class, security attributes
    // and disposition may be null; `hkey` receives the opened key.
    check(unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut hkey,
            ptr::null_mut(),
        )
    })?;
    let data = wide(value);
    let result = u32::try_from(data.len() * 2)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "registry value too long"))
        .and_then(|len| {
            // SAFETY: `hkey` is open with KEY_SET_VALUE; a null name is the default value;
            // `data` holds `len` bytes of a NUL-terminated UTF-16 string, as REG_SZ wants.
            check(unsafe {
                RegSetValueExW(hkey, ptr::null(), 0, REG_SZ, data.as_ptr().cast(), len)
            })
        });
    // SAFETY: `hkey` was opened above and is closed once.
    unsafe { RegCloseKey(hkey) };
    result
}

/// The default value of `HKCU\<key>`; `None` if the key or its default value does not exist.
pub fn get_default(key: &str) -> io::Result<Option<String>> {
    let key = wide(key);
    let mut buf: Vec<u16> = Vec::new();
    loop {
        let mut size = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
        let data = if buf.is_empty() {
            ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        // SAFETY: `key` is NUL-terminated; a null value name is the default value; `data` is
        // null (size query) or `buf`, whose size in bytes `size` holds.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                ptr::null(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                data,
                &mut size,
            )
        };
        match status {
            ERROR_FILE_NOT_FOUND => return Ok(None),
            ERROR_SUCCESS if !buf.is_empty() => {
                // `size` counts the bytes written, the terminating NUL included.
                buf.truncate(size as usize / 2);
                while buf.last() == Some(&0) {
                    buf.pop();
                }
                return String::from_utf16(&buf)
                    .map(Some)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
            // The size query, or the value grew since it.
            ERROR_SUCCESS | ERROR_MORE_DATA => buf = vec![0; (size as usize).div_ceil(2).max(1)],
            status => return check(status).map(|()| None),
        }
    }
}

/// Deletes `HKCU\<key>` with its subkeys and values; `false` if it did not exist.
pub fn delete_tree(key: &str) -> io::Result<bool> {
    let key = wide(key);
    // SAFETY: `key` is NUL-terminated and outlives the call.
    match unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr()) } {
        ERROR_FILE_NOT_FOUND => Ok(false),
        status => check(status).map(|()| true),
    }
}
