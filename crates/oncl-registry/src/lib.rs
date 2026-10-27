//! Registry values for OpenNCALayer: string, DWORD and binary values read under
//! `HKEY_CURRENT_USER` or `HKEY_LOCAL_MACHINE`, written and deleted under
//! `HKEY_CURRENT_USER` only. The registry exists on Windows only: elsewhere every function
//! fails with [`std::io::ErrorKind::Unsupported`].
//!
//! `key` is a path under the hive; a `None` value name is the key's default value. A key or
//! value that does not exist reads as `None`.

/// A predefined root key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hive {
    /// `HKEY_CURRENT_USER`.
    CurrentUser,
    /// `HKEY_LOCAL_MACHINE`, read only here.
    LocalMachine,
}

#[cfg(windows)]
pub use windows::{
    delete_tree, delete_value, get_binary, get_dword, get_string, set_binary, set_dword, set_string,
};

#[cfg(not(windows))]
pub use elsewhere::{
    delete_tree, delete_value, get_binary, get_dword, get_string, set_binary, set_dword, set_string,
};

#[cfg(windows)]
mod windows {
    use super::Hive;
    use std::io;
    use std::iter::once;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_BINARY, REG_DWORD,
        REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RRF_RT_DWORD, RRF_RT_REG_BINARY,
        RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW,
        RegGetValueW, RegSetValueExW,
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

    fn root(hive: Hive) -> HKEY {
        match hive {
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }

    /// The bytes of value `name` of `<hive>\<key>`, of a type `flags` allows.
    fn get_bytes(
        hive: Hive,
        key: &str,
        name: Option<&str>,
        flags: u32,
    ) -> io::Result<Option<Vec<u8>>> {
        let key = wide(key);
        let name = name.map(wide);
        let name = name.as_ref().map_or(ptr::null(), |n| n.as_ptr());
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let mut size = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            let data = if buf.is_empty() {
                ptr::null_mut()
            } else {
                buf.as_mut_ptr().cast()
            };
            // SAFETY: `key` is NUL-terminated; `name` is null (the default value) or
            // NUL-terminated; `data` is null (size query) or `buf`, whose size in bytes
            // `size` holds.
            let status = unsafe {
                RegGetValueW(
                    root(hive),
                    key.as_ptr(),
                    name,
                    flags,
                    ptr::null_mut(),
                    data,
                    &mut size,
                )
            };
            match status {
                ERROR_FILE_NOT_FOUND => return Ok(None),
                ERROR_SUCCESS if !buf.is_empty() || size == 0 => {
                    // `size` counts the bytes written.
                    buf.truncate(size as usize);
                    return Ok(Some(buf));
                }
                // The size query, or the value grew since it.
                ERROR_SUCCESS | ERROR_MORE_DATA => buf = vec![0; size as usize],
                status => return check(status).map(|()| None),
            }
        }
    }

    /// The string (`REG_SZ`) value `name` of `<hive>\<key>`.
    pub fn get_string(hive: Hive, key: &str, name: Option<&str>) -> io::Result<Option<String>> {
        let Some(bytes) = get_bytes(hive, key, name, RRF_RT_REG_SZ)? else {
            return Ok(None);
        };
        let mut units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// The `REG_DWORD` value `name` of `<hive>\<key>`.
    pub fn get_dword(hive: Hive, key: &str, name: Option<&str>) -> io::Result<Option<u32>> {
        let Some(bytes) = get_bytes(hive, key, name, RRF_RT_DWORD)? else {
            return Ok(None);
        };
        let bytes = <[u8; 4]>::try_from(bytes.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a DWORD"))?;
        Ok(Some(u32::from_le_bytes(bytes)))
    }

    /// The `REG_BINARY` value `name` of `<hive>\<key>`.
    pub fn get_binary(hive: Hive, key: &str, name: Option<&str>) -> io::Result<Option<Vec<u8>>> {
        get_bytes(hive, key, name, RRF_RT_REG_BINARY)
    }

    /// Sets value `name` of `HKCU\<key>` to `data` of type `kind`, creating the key and its
    /// missing parents.
    fn set_bytes(
        key: &str,
        name: Option<&str>,
        kind: REG_VALUE_TYPE,
        data: &[u8],
    ) -> io::Result<()> {
        let key = wide(key);
        let name = name.map(wide);
        let len = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "registry value too long"))?;
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
        // SAFETY: `hkey` is open with KEY_SET_VALUE; the name is null (the default value)
        // or NUL-terminated; `data` holds `len` bytes.
        let result = check(unsafe {
            RegSetValueExW(
                hkey,
                name.as_ref().map_or(ptr::null(), |n| n.as_ptr()),
                0,
                kind,
                data.as_ptr(),
                len,
            )
        });
        // SAFETY: `hkey` was opened above and is closed once.
        unsafe { RegCloseKey(hkey) };
        result
    }

    /// Sets value `name` of `HKCU\<key>` to the string `value` (`REG_SZ`).
    pub fn set_string(key: &str, name: Option<&str>, value: &str) -> io::Result<()> {
        // A NUL-terminated UTF-16 string, as REG_SZ wants.
        let data: Vec<u8> = wide(value).into_iter().flat_map(u16::to_le_bytes).collect();
        set_bytes(key, name, REG_SZ, &data)
    }

    /// Sets value `name` of `HKCU\<key>` to `value` (`REG_DWORD`).
    pub fn set_dword(key: &str, name: Option<&str>, value: u32) -> io::Result<()> {
        set_bytes(key, name, REG_DWORD, &value.to_le_bytes())
    }

    /// Sets value `name` of `HKCU\<key>` to `value` (`REG_BINARY`).
    pub fn set_binary(key: &str, name: Option<&str>, value: &[u8]) -> io::Result<()> {
        set_bytes(key, name, REG_BINARY, value)
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
    use super::Hive;
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the registry exists on Windows only",
        )
    }

    /// Fails: no registry.
    pub fn get_string(_hive: Hive, _key: &str, _name: Option<&str>) -> io::Result<Option<String>> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn get_dword(_hive: Hive, _key: &str, _name: Option<&str>) -> io::Result<Option<u32>> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn get_binary(_hive: Hive, _key: &str, _name: Option<&str>) -> io::Result<Option<Vec<u8>>> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn set_string(_key: &str, _name: Option<&str>, _value: &str) -> io::Result<()> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn set_dword(_key: &str, _name: Option<&str>, _value: u32) -> io::Result<()> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn set_binary(_key: &str, _name: Option<&str>, _value: &[u8]) -> io::Result<()> {
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

/// A key `HKCU\Software\OpenNCALayer-test-<pid>-<n>-<time>` for a test (nothing is created
/// until a value is written), deleted with its subkeys when dropped, also when the test
/// fails.
#[cfg(all(windows, any(test, feature = "testing")))]
pub struct TestKey(String);

#[cfg(all(windows, any(test, feature = "testing")))]
impl TestKey {
    /// A key no other test uses.
    pub fn new() -> TestKey {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        TestKey(format!(
            r"Software\OpenNCALayer-test-{:x}-{}-{nanos:x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// The key's path under `HKEY_CURRENT_USER`.
    pub fn path(&self) -> &str {
        &self.0
    }
}

#[cfg(all(windows, any(test, feature = "testing")))]
impl Default for TestKey {
    fn default() -> Self {
        TestKey::new()
    }
}

#[cfg(all(windows, any(test, feature = "testing")))]
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
    fn values_under_a_test_key() {
        let base = TestKey::new();
        let key = format!(r"{}\Sub", base.path());
        let hkcu = Hive::CurrentUser;
        assert_eq!(get_string(hkcu, &key, Some("v")).unwrap(), None);
        assert_eq!(get_dword(hkcu, &key, Some("d")).unwrap(), None);
        assert_eq!(get_binary(hkcu, &key, Some("b")).unwrap(), None);
        assert!(!delete_value(&key, "v").unwrap());

        set_string(&key, Some("v"), "named").unwrap();
        set_string(&key, None, &"д".repeat(300)).unwrap();
        set_string(&key, Some("empty"), "").unwrap();
        set_dword(&key, Some("d"), 0x0102_0304).unwrap();
        set_binary(&key, Some("b"), &[3, 0, 0, 0, 9]).unwrap();
        set_binary(&key, Some("b0"), &[]).unwrap();
        assert_eq!(
            get_string(hkcu, &key, Some("v")).unwrap().as_deref(),
            Some("named")
        );
        assert_eq!(get_string(hkcu, &key, None).unwrap(), Some("д".repeat(300)));
        assert_eq!(
            get_string(hkcu, &key, Some("empty")).unwrap().as_deref(),
            Some("")
        );
        assert_eq!(get_dword(hkcu, &key, Some("d")).unwrap(), Some(0x0102_0304));
        assert_eq!(
            get_binary(hkcu, &key, Some("b")).unwrap(),
            Some(vec![3, 0, 0, 0, 9])
        );
        assert_eq!(get_binary(hkcu, &key, Some("b0")).unwrap(), Some(vec![]));
        // A value of another type is an error, not a misread.
        assert!(get_dword(hkcu, &key, Some("v")).is_err());
        assert!(get_string(hkcu, &key, Some("d")).is_err());

        assert!(delete_value(&key, "v").unwrap());
        assert_eq!(get_string(hkcu, &key, Some("v")).unwrap(), None);
        assert!(get_string(hkcu, &key, None).unwrap().is_some());

        assert!(delete_tree(base.path()).unwrap());
        assert!(!delete_tree(base.path()).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn local_machine_is_readable() {
        // Present on every Windows installation.
        let root = get_string(
            Hive::LocalMachine,
            r"Software\Microsoft\Windows NT\CurrentVersion",
            Some("SystemRoot"),
        )
        .unwrap();
        assert!(root.is_some_and(|r| !r.is_empty()));
    }

    #[cfg(not(windows))]
    #[test]
    fn no_registry_elsewhere() {
        use std::io;

        let unsupported = |e: io::Error| e.kind() == io::ErrorKind::Unsupported;
        let hkcu = Hive::CurrentUser;
        assert!(get_string(hkcu, "k", None).is_err_and(unsupported));
        assert!(get_dword(hkcu, "k", None).is_err_and(unsupported));
        assert!(get_binary(hkcu, "k", None).is_err_and(unsupported));
        assert!(set_string("k", None, "v").is_err_and(unsupported));
        assert!(set_dword("k", None, 1).is_err_and(unsupported));
        assert!(set_binary("k", None, b"").is_err_and(unsupported));
        assert!(delete_value("k", "v").is_err_and(unsupported));
        assert!(delete_tree("k").is_err_and(unsupported));
    }
}
