//! PC/SC on macOS: the system's PCSC.framework (32-bit `DWORD`, packed structures).

use std::ffi::{c_char, c_void};

pub(super) type Dword = u32;
pub(super) type Long = i32;
pub(super) type Handle = i32;

/// A `DWORD` of flags or a protocol.
pub(super) fn to_u32(d: Dword) -> u32 {
    d
}

/// `SCARD_READERSTATE`.
#[repr(C, packed)]
pub(super) struct ReaderState {
    pub reader: *const c_char,
    pub user_data: *mut c_void,
    pub current_state: Dword,
    pub event_state: Dword,
    pub atr_len: Dword,
    pub atr: [u8; 33],
}

/// `SCARD_IO_REQUEST`.
#[repr(C, packed)]
pub(super) struct IoRequest {
    pub protocol: Dword,
    pub pci_length: Dword,
}

#[link(name = "PCSC", kind = "framework")]
unsafe extern "C" {
    fn SCardEstablishContext(
        scope: Dword,
        reserved1: *const c_void,
        reserved2: *const c_void,
        context: *mut Handle,
    ) -> Long;
    fn SCardReleaseContext(context: Handle) -> Long;
    fn SCardListReaders(
        context: Handle,
        groups: *const c_char,
        readers: *mut c_char,
        len: *mut Dword,
    ) -> Long;
    fn SCardGetStatusChange(
        context: Handle,
        timeout: Dword,
        states: *mut ReaderState,
        count: Dword,
    ) -> Long;
    fn SCardConnect(
        context: Handle,
        reader: *const c_char,
        share: Dword,
        protocols: Dword,
        card: *mut Handle,
        active: *mut Dword,
    ) -> Long;
    fn SCardBeginTransaction(card: Handle) -> Long;
    fn SCardEndTransaction(card: Handle, disposition: Dword) -> Long;
    fn SCardTransmit(
        card: Handle,
        send_pci: *const IoRequest,
        send: *const u8,
        send_len: Dword,
        recv_pci: *mut IoRequest,
        recv: *mut u8,
        recv_len: *mut Dword,
    ) -> Long;
    fn SCardDisconnect(card: Handle, disposition: Dword) -> Long;
}

/// The PCSC.framework functions used.
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

static API: Api = Api {
    establish: SCardEstablishContext,
    release: SCardReleaseContext,
    list_readers: SCardListReaders,
    get_status_change: SCardGetStatusChange,
    connect: SCardConnect,
    begin: SCardBeginTransaction,
    end: SCardEndTransaction,
    transmit: SCardTransmit,
    disconnect: SCardDisconnect,
};

/// The functions: the framework is part of the system.
pub(super) fn api() -> Option<&'static Api> {
    Some(&API)
}
