//! String values of `HKEY_CURRENT_USER` keys: our `Run` value and the keys where browsers
//! look up native messaging host manifests. The registry exists on Windows only: elsewhere
//! every function fails with [`io::ErrorKind::Unsupported`].
//!
//! `key` is a path under `HKEY_CURRENT_USER`; a `None` value name is the key's default value.

#[cfg(windows)]
pub use windows::{delete_tree, delete_value, get_string, set_string};

#[cfg(not(windows))]
pub use elsewhere::{delete_tree, delete_value, get_string, set_string};

#[cfg(windows)]
mod windows {
    use std::io;
    use std::iter::once;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW,
        RegSetValueExW,
    };

    /// `s` as a NUL-terminated UTF-16 string.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(once(0)).collect()
    }

    /// The value name for the API: null for the default value.
    fn name_ptr(name: Option<&Vec<u16>>) -> *const u16 {
        name.map_or(ptr::null(), |n| n.as_ptr())
    }

    fn check(status: u32) -> io::Result<()> {
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            // Win32 error codes fit in i32.
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    /// Sets value `name` of `HKCU\<key>` to the string `value`, creating the key and its
    /// missing parents.
    pub fn set_string(key: &str, name: Option<&str>, value: &str) -> io::Result<()> {
        let key = wide(key);
        let name = name.map(wide);
        let mut hkey: HKEY = ptr::null_mut();
        // SAFETY: `key` is NUL-terminated and outlives the call; the class, security
        // attributes and disposition may be null; `hkey` receives the opened key.
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
                // SAFETY: `hkey` is open with KEY_SET_VALUE; the name is null (the default
                // value) or NUL-terminated; `data` holds `len` bytes of a NUL-terminated
                // UTF-16 string, as REG_SZ wants.
                check(unsafe {
                    RegSetValueExW(
                        hkey,
                        name_ptr(name.as_ref()),
                        0,
                        REG_SZ,
                        data.as_ptr().cast(),
                        len,
                    )
                })
            });
        // SAFETY: `hkey` was opened above and is closed once.
        unsafe { RegCloseKey(hkey) };
        result
    }

    /// The string value `name` of `HKCU\<key>`; `None` if the key or the value does not
    /// exist.
    pub fn get_string(key: &str, name: Option<&str>) -> io::Result<Option<String>> {
        let key = wide(key);
        let name = name.map(wide);
        let mut buf: Vec<u16> = Vec::new();
        loop {
            let mut size = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
            let data = if buf.is_empty() {
                ptr::null_mut()
            } else {
                buf.as_mut_ptr().cast()
            };
            // SAFETY: `key` is NUL-terminated; the name is null (the default value) or
            // NUL-terminated; `data` is null (size query) or `buf`, whose size in bytes
            // `size` holds.
            let status = unsafe {
                RegGetValueW(
                    HKEY_CURRENT_USER,
                    key.as_ptr(),
                    name_ptr(name.as_ref()),
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
                ERROR_SUCCESS | ERROR_MORE_DATA => {
                    buf = vec![0; (size as usize).div_ceil(2).max(1)];
                }
                status => return check(status).map(|()| None),
            }
        }
    }

    /// Deletes value `name` of `HKCU\<key>`; `false` if it or the key did not exist.
    pub fn delete_value(key: &str, name: &str) -> io::Result<bool> {
        let (key, name) = (wide(key), wide(name));
        // SAFETY: `key` and `name` are NUL-terminated and outlive the call.
        match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => Ok(false),
            status => check(status).map(|()| true),
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
}

#[cfg(not(windows))]
mod elsewhere {
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the registry exists on Windows only",
        )
    }

    /// Fails: no registry.
    pub fn set_string(_key: &str, _name: Option<&str>, _value: &str) -> io::Result<()> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn get_string(_key: &str, _name: Option<&str>) -> io::Result<Option<String>> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn delete_value(_key: &str, _name: &str) -> io::Result<bool> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn delete_tree(_key: &str) -> io::Result<bool> {
        Err(unsupported())
    }
}

/// A key `HKCU\Software\OpenNCALayer-test-<pid>-<time>` for a test, deleted with its
/// subkeys when dropped (also when the test fails).
#[cfg(all(test, windows))]
pub(crate) struct TestKey(pub(crate) String);

#[cfg(all(test, windows))]
impl TestKey {
    pub(crate) fn new() -> TestKey {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        TestKey(format!(
            r"Software\OpenNCALayer-test-{:x}-{nanos:x}",
            std::process::id()
        ))
    }
}

#[cfg(all(test, windows))]
impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = delete_tree(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn named_and_default_values_under_a_test_key() {
        let base = TestKey::new();
        let key = format!(r"{}\Sub", base.0);
        assert_eq!(get_string(&key, Some("v")).unwrap(), None);
        assert!(!delete_value(&key, "v").unwrap());

        set_string(&key, Some("v"), "named").unwrap();
        set_string(&key, None, &"d".repeat(300)).unwrap();
        assert_eq!(
            get_string(&key, Some("v")).unwrap().as_deref(),
            Some("named")
        );
        assert_eq!(get_string(&key, None).unwrap(), Some("d".repeat(300)));

        assert!(delete_value(&key, "v").unwrap());
        assert_eq!(get_string(&key, Some("v")).unwrap(), None);
        assert!(get_string(&key, None).unwrap().is_some());

        assert!(delete_tree(&base.0).unwrap());
        assert!(!delete_tree(&base.0).unwrap());
    }

    #[cfg(not(windows))]
    #[test]
    fn no_registry_elsewhere() {
        use std::io;

        let unsupported = |e: io::Error| e.kind() == io::ErrorKind::Unsupported;
        assert!(set_string("k", None, "v").is_err_and(unsupported));
        assert!(get_string("k", None).is_err_and(unsupported));
        assert!(delete_value("k", "v").is_err_and(unsupported));
        assert!(delete_tree("k").is_err_and(unsupported));
    }
}
