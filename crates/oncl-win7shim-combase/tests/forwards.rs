//! `combase.dll`: its only exports are forwards to the same functions of `ole32.dll`, and
//! loaded app-local they resolve to those functions.

#![cfg(windows)]

use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use oncl_testkit::dll::{AppLocalDll, build_cdylib, exports};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::w;

/// The exports, sorted by name.
const FORWARDED: &[&CStr] = &[c"CoCreateFreeThreadedMarshaler", c"CoTaskMemFree"];

/// The address of the system `ole32.dll`, never unloaded. Loaded before any app-local
/// `combase.dll`: once a module named `combase.dll` is in the process, the loader binds the
/// `combase.dll` imports of a newly loaded `ole32.dll` to it.
static OLE32: LazyLock<usize> = LazyLock::new(|| {
    // SAFETY: a NUL-terminated name of a system DLL.
    let module = unsafe { LoadLibraryW(w!("ole32.dll")) };
    assert!(!module.is_null(), "{}", std::io::Error::last_os_error());
    module as usize
});

fn ole32() -> HMODULE {
    *OLE32 as HMODULE
}

static BUILT: LazyLock<PathBuf> = LazyLock::new(|| {
    build_cdylib(
        "oncl-win7shim-combase",
        Path::new(env!("CARGO_TARGET_TMPDIR")),
    )
});

fn combase() -> AppLocalDll {
    ole32();
    AppLocalDll::load(&BUILT, "combase.dll")
}

#[test]
fn forwards_resolve_to_ole32() {
    let dll = combase();
    for name in FORWARDED {
        // SAFETY: `ole32()` stays loaded; `name` is NUL-terminated.
        let expected = unsafe { GetProcAddress(ole32(), name.as_ptr().cast()) }
            .unwrap_or_else(|| panic!("ole32.dll lacks {name:?}"));
        let forwarded = dll
            .proc(name)
            .unwrap_or_else(|| panic!("combase.dll lacks {name:?}"));
        assert_eq!(forwarded as usize, expected as usize, "{name:?}");
    }
}

#[test]
fn exports_only_the_forwards() {
    assert_eq!(
        exports(&BUILT),
        FORWARDED
            .iter()
            .map(|name| {
                let name = name.to_str().expect("an ASCII name");
                (name.to_owned(), Some(format!("ole32.{name}")))
            })
            .collect::<Vec<_>>()
    );
}
