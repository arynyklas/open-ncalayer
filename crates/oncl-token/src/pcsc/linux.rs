//! pcsc-lite on Linux, opened at run time: the program does not need `libpcsclite` to start,
//! and without it the smart card service is just not available.

use std::ffi::{c_char, c_long, c_ulong, c_void};
use std::sync::LazyLock;

pub(super) type Dword = c_ulong;
pub(super) type Long = c_long;
pub(super) type Handle = c_long;

/// A `DWORD` of flags or a protocol: 32 bits wide in every PC/SC.
pub(super) fn to_u32(d: Dword) -> u32 {
    d as u32
}

/// The libraries tried, in order.
const NAMES: [&str; 2] = ["libpcsclite.so.1", "libpcsclite.so"];

/// `SCARD_READERSTATE`.
#[repr(C)]
pub(super) struct ReaderState {
    pub reader: *const c_char,
    pub user_data: *mut c_void,
    pub current_state: Dword,
    pub event_state: Dword,
    pub atr_len: Dword,
    pub atr: [u8; 33],
}

/// `SCARD_IO_REQUEST`.
#[repr(C)]
pub(super) struct IoRequest {
    pub protocol: Dword,
    pub pci_length: Dword,
}

/// The pcsc-lite functions used.
pub(super) struct Api {
    pub establish: unsafe extern "C" fn(Dword, *const c_void, *const c_void, *mut Handle) -> Long,
    pub release: unsafe extern "C" fn(Handle) -> Long,
    pub list_readers: unsafe extern "C" fn(Handle, *const c_char, *mut c_char, *mut Dword) -> Long,
    pub get_status_change: unsafe extern "C" fn(Handle, Dword, *mut ReaderState, Dword) -> Long,
    pub connect:
        unsafe extern "C" fn(Handle, *const c_char, Dword, Dword, *mut Handle, *mut Dword) -> Long,
    pub begin: unsafe extern "C" fn(Handle) -> Long,
    pub end: unsafe extern "C" fn(Handle, Dword) -> Long,
    pub transmit: unsafe extern "C" fn(
        Handle,
        *const IoRequest,
        *const u8,
        Dword,
        *mut IoRequest,
        *mut u8,
        *mut Dword,
    ) -> Long,
    pub disconnect: unsafe extern "C" fn(Handle, Dword) -> Long,
}

/// The opened library and its functions.
pub(super) struct Lib {
    api: Api,
    // Kept open as long as the functions are used.
    _lib: libloading::Library,
}

impl Lib {
    /// Opens `name` and looks its functions up.
    pub(super) fn open(name: &str) -> Result<Lib, String> {
        // SAFETY: pcsc-lite's initialisers have no requirements of the caller.
        let lib = unsafe { libloading::Library::new(name) }.map_err(|e| format!("{name}: {e}"))?;
        macro_rules! function {
            ($name:literal) => {
                // SAFETY: the type is the function's prototype in pcsc-lite's headers.
                *unsafe { lib.get(concat!($name, "\0").as_bytes()) }
                    .map_err(|e| format!("{name}: {}: {e}", $name))?
            };
        }
        let api = Api {
            establish: function!("SCardEstablishContext"),
            release: function!("SCardReleaseContext"),
            list_readers: function!("SCardListReaders"),
            get_status_change: function!("SCardGetStatusChange"),
            connect: function!("SCardConnect"),
            begin: function!("SCardBeginTransaction"),
            end: function!("SCardEndTransaction"),
            transmit: function!("SCardTransmit"),
            disconnect: function!("SCardDisconnect"),
        };
        Ok(Lib { api, _lib: lib })
    }

    fn load() -> Result<Lib, String> {
        let mut errors = Vec::new();
        for name in NAMES {
            match Lib::open(name) {
                Ok(lib) => return Ok(lib),
                Err(e) => errors.push(e),
            }
        }
        Err(errors.join("; "))
    }
}

/// The library, opened on first use; the failure is logged once.
static LIB: LazyLock<Result<Lib, String>> = LazyLock::new(|| {
    Lib::load().inspect_err(|e| {
        tracing::warn!("no smart card service: pcsc-lite is not available ({e})");
    })
});

/// The functions, once the library is open; `None` without pcsc-lite.
pub(super) fn api() -> Option<&'static Api> {
    LIB.as_ref().ok().map(|lib| &lib.api)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_library_is_no_service() {
        let err = Lib::open("libdoes-not-exist-oncl.so.9").err().unwrap();
        assert!(err.contains("libdoes-not-exist-oncl.so.9"), "{err}");
        // A library without the functions is refused too.
        assert!(Lib::open("libc.so.6").is_err());
    }
}
