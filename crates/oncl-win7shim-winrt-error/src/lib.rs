//! `api-ms-win-core-winrt-error-l1-1-0.dll` for the Windows 7 builds of OpenNCALayer,
//! shipped next to the executables.
//!
//! `windows-result` imports `RoOriginateErrorW` from this API set, which Windows 7 does not
//! have. Windows 7 has no WinRT either, so nobody would receive an originated error: the
//! functions here do nothing and return `FALSE`: no error information was recorded.
//! `windows-result` ignores the result.
//!
//! Windows 8 and later never load it: the loader resolves `api-ms-win-*` names through the
//! system's API set schema.

#![cfg(windows)]

use std::ffi::c_void;

/// `BOOL RoOriginateErrorW(HRESULT error, UINT cchMax, PCWSTR message)`: returns `FALSE`.
#[unsafe(no_mangle)]
pub extern "system" fn RoOriginateErrorW(_error: i32, _cch_max: u32, _message: *const u16) -> i32 {
    0
}

/// `BOOL RoOriginateError(HRESULT error, HSTRING message)`: returns `FALSE`.
#[unsafe(no_mangle)]
pub extern "system" fn RoOriginateError(_error: i32, _message: *mut c_void) -> i32 {
    0
}
