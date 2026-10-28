//! `api-ms-win-core-winrt-error-l1-1-0.dll`: it exports only the error origination stubs,
//! and loaded app-local they report that no error was originated (`FALSE`).

#![cfg(windows)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use oncl_testkit::dll::{AppLocalDll, build_cdylib, exports};

/// `E_FAIL`.
const E_FAIL: i32 = 0x8000_4005_u32 as i32;

static BUILT: LazyLock<PathBuf> = LazyLock::new(|| {
    build_cdylib(
        "oncl-win7shim-winrt-error",
        Path::new(env!("CARGO_TARGET_TMPDIR")),
    )
});

fn winrt_error() -> AppLocalDll {
    AppLocalDll::load(&BUILT, "api-ms-win-core-winrt-error-l1-1-0.dll")
}

#[test]
fn ro_originate_error_w_reports_nothing() {
    let dll = winrt_error();
    let proc = dll.proc(c"RoOriginateErrorW").expect("RoOriginateErrorW");
    // SAFETY: the export has this signature: `BOOL RoOriginateErrorW(HRESULT, UINT, PCWSTR)`.
    let originate: unsafe extern "system" fn(i32, u32, *const u16) -> i32 =
        unsafe { std::mem::transmute(proc) };
    let message: Vec<u16> = "boom".encode_utf16().chain([0]).collect();
    // SAFETY: a NUL-terminated message of 4 characters.
    assert_eq!(unsafe { originate(E_FAIL, 4, message.as_ptr()) }, 0);
    // SAFETY: no message at all is allowed.
    assert_eq!(unsafe { originate(E_FAIL, 0, std::ptr::null()) }, 0);
}

#[test]
fn ro_originate_error_reports_nothing() {
    let dll = winrt_error();
    let proc = dll.proc(c"RoOriginateError").expect("RoOriginateError");
    // SAFETY: the export has this signature: `BOOL RoOriginateError(HRESULT, HSTRING)`.
    let originate: unsafe extern "system" fn(i32, *mut c_void) -> i32 =
        unsafe { std::mem::transmute(proc) };
    // SAFETY: a null HSTRING is the empty string.
    assert_eq!(unsafe { originate(E_FAIL, std::ptr::null_mut()) }, 0);
}

#[test]
fn exports_only_the_stubs() {
    assert_eq!(
        exports(&BUILT),
        [
            ("RoOriginateError".to_owned(), None),
            ("RoOriginateErrorW".to_owned(), None),
        ]
    );
}
