//! The system's smart card service (PC/SC) as a [`Backend`]: `winscard.dll` on Windows,
//! `PCSC.framework` on macOS, `libpcsclite.so.1` opened at run time on Linux (no link-time
//! dependency: without pcsc-lite the service is just not available).
//!
//! A context is established for each [`Backend::readers`] and [`Backend::connect`] and
//! released after it (a connection keeps its own until it is dropped), so a restart of the
//! service never leaves a stale context behind.

use crate::MAX_RESPONSE;
use crate::backend::{Backend, BackendError, Connection, Protocol, ReaderState};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use unix as sys;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod none;
#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
use none as sys;

// PC/SC status codes: the same values on every platform.
pub(crate) const SCARD_S_SUCCESS: u32 = 0;
pub(crate) const SCARD_E_INSUFFICIENT_BUFFER: u32 = 0x8010_0008;
pub(crate) const SCARD_E_UNKNOWN_READER: u32 = 0x8010_0009;
pub(crate) const SCARD_E_TIMEOUT: u32 = 0x8010_000A;
pub(crate) const SCARD_E_SHARING_VIOLATION: u32 = 0x8010_000B;
pub(crate) const SCARD_E_NO_SMARTCARD: u32 = 0x8010_000C;
pub(crate) const SCARD_E_READER_UNAVAILABLE: u32 = 0x8010_0017;
pub(crate) const SCARD_E_NO_SERVICE: u32 = 0x8010_001D;
pub(crate) const SCARD_E_SERVICE_STOPPED: u32 = 0x8010_001E;
pub(crate) const SCARD_E_NO_READERS_AVAILABLE: u32 = 0x8010_002E;
pub(crate) const SCARD_W_RESET_CARD: u32 = 0x8010_0068;
pub(crate) const SCARD_W_REMOVED_CARD: u32 = 0x8010_0069;

// Flags and parameters: the same values on every platform.
pub(crate) const SCARD_SCOPE_USER: u32 = 0;
pub(crate) const SCARD_SHARE_SHARED: u32 = 2;
pub(crate) const SCARD_PROTOCOL_T0: u32 = 1;
pub(crate) const SCARD_PROTOCOL_T1: u32 = 2;
pub(crate) const SCARD_LEAVE_CARD: u32 = 0;
pub(crate) const SCARD_RESET_CARD: u32 = 1;
pub(crate) const SCARD_STATE_UNAWARE: u32 = 0;
pub(crate) const SCARD_STATE_PRESENT: u32 = 0x20;
pub(crate) const SCARD_STATE_MUTE: u32 = 0x200;

/// A failed call: the function and its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub function: &'static str,
    pub code: u32,
}

/// What a platform cannot do at all (its library is missing).
pub(crate) type SysResult<T> = Result<T, SysError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SysError {
    /// No PC/SC library.
    #[cfg_attr(
        all(windows, not(test)),
        expect(dead_code, reason = "winscard.dll is part of Windows")
    )]
    Unavailable,
    /// A call failed.
    Call(Failure),
}

impl From<Failure> for SysError {
    fn from(f: Failure) -> SysError {
        SysError::Call(f)
    }
}

/// The backend error of a PC/SC status.
pub(crate) fn map_error(function: &str, code: u32) -> BackendError {
    match code {
        SCARD_E_NO_SERVICE | SCARD_E_SERVICE_STOPPED => BackendError::NoService,
        SCARD_E_NO_READERS_AVAILABLE => BackendError::NoReaders,
        SCARD_E_UNKNOWN_READER | SCARD_E_READER_UNAVAILABLE => BackendError::UnknownReader,
        SCARD_E_NO_SMARTCARD => BackendError::NoCard,
        SCARD_W_REMOVED_CARD => BackendError::Removed,
        SCARD_W_RESET_CARD => BackendError::Reset,
        SCARD_E_SHARING_VIOLATION => BackendError::Sharing,
        code => BackendError::Failed(format!("{function} 0x{code:08X}")),
    }
}

fn backend_error(e: SysError) -> BackendError {
    match e {
        SysError::Unavailable => BackendError::NoService,
        SysError::Call(f) => map_error(f.function, f.code),
    }
}

/// Reader names of a UTF-16 multi-string (`a\0b\0\0`); a missing final NUL is tolerated.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "only Windows lists readers in UTF-16")
)]
pub(crate) fn parse_multi_string_w(raw: &[u16]) -> Vec<String> {
    raw.split(|&c| c == 0)
        .take_while(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// Reader names of a UTF-8 multi-string (`a\0b\0\0`); a missing final NUL is tolerated.
#[cfg_attr(
    all(windows, not(test)),
    expect(dead_code, reason = "Windows lists readers in UTF-16")
)]
pub(crate) fn parse_multi_string(raw: &[u8]) -> Vec<String> {
    raw.split(|&c| c == 0)
        .take_while(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// The reader's card ATR from its state: present and not mute.
pub(crate) fn atr_of(state: u32, atr: &[u8]) -> Option<Vec<u8>> {
    (state & SCARD_STATE_PRESENT != 0 && state & SCARD_STATE_MUTE == 0 && !atr.is_empty())
        .then(|| atr.to_vec())
}

/// The system's PC/SC service.
#[derive(Clone, Copy, Debug, Default)]
pub struct PcscBackend;

impl PcscBackend {
    /// The system's service; nothing is loaded or connected before it is used.
    pub fn new() -> PcscBackend {
        PcscBackend
    }
}

impl Backend for PcscBackend {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        let ctx = sys::Context::establish().map_err(backend_error)?;
        let names = ctx.list_readers().map_err(backend_error)?;
        if names.is_empty() {
            return Err(BackendError::NoReaders);
        }
        let atrs = ctx.states(&names).map_err(backend_error)?;
        Ok(names
            .into_iter()
            .zip(atrs)
            .map(|(name, atr)| ReaderState { name, atr })
            .collect())
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        let ctx = sys::Context::establish().map_err(backend_error)?;
        let (card, protocol) = ctx.connect(reader).map_err(backend_error)?;
        let atr = ctx
            .states(&[reader.to_owned()])
            .map_err(backend_error)?
            .pop()
            .flatten()
            .unwrap_or_default();
        let protocol = if protocol == SCARD_PROTOCOL_T0 {
            Protocol::T0
        } else {
            Protocol::T1
        };
        Ok(Box::new(PcscConnection {
            card,
            ctx,
            protocol,
            atr,
            buf: vec![0; MAX_RESPONSE],
        }))
    }
}

/// A connection; its context lives as long as it does.
struct PcscConnection {
    // Dropped first: the card is disconnected before its context is released.
    card: sys::Card,
    #[expect(dead_code, reason = "released on drop, after the card")]
    ctx: sys::Context,
    protocol: Protocol,
    atr: Vec<u8>,
    buf: Vec<u8>,
}

impl Connection for PcscConnection {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn atr(&self) -> &[u8] {
        &self.atr
    }

    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        self.card.begin_transaction().map_err(backend_error)
    }

    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.card.end_transaction().map_err(backend_error)
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        let protocol = match self.protocol {
            Protocol::T0 => SCARD_PROTOCOL_T0,
            Protocol::T1 => SCARD_PROTOCOL_T1,
        };
        let n = self
            .card
            .transmit(protocol, apdu, &mut self.buf)
            .map_err(backend_error)?;
        Ok(self.buf[..n].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_string_parsing() {
        let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert!(parse_multi_string_w(&[]).is_empty());
        assert!(parse_multi_string_w(&[0]).is_empty());
        assert!(parse_multi_string_w(&[0, 0]).is_empty());
        assert_eq!(parse_multi_string_w(&w("Reader A\0\0")), ["Reader A"]);
        assert_eq!(
            parse_multi_string_w(&w("Reader A\0Считыватель B\0\0")),
            ["Reader A", "Считыватель B"]
        );
        assert_eq!(parse_multi_string_w(&w("A\0B")), ["A", "B"]);
        assert!(parse_multi_string(b"").is_empty());
        assert!(parse_multi_string(b"\0\0").is_empty());
        assert_eq!(parse_multi_string(b"Reader A\0\0"), ["Reader A"]);
        assert_eq!(
            parse_multi_string("A 00\0Считыватель 01\0\0".as_bytes()),
            ["A 00", "Считыватель 01"]
        );
        assert_eq!(parse_multi_string(b"A\0B"), ["A", "B"]);
    }

    #[test]
    fn error_codes_map() {
        for (code, expected) in [
            (SCARD_E_NO_SERVICE, BackendError::NoService),
            (SCARD_E_SERVICE_STOPPED, BackendError::NoService),
            (SCARD_E_NO_READERS_AVAILABLE, BackendError::NoReaders),
            (SCARD_E_UNKNOWN_READER, BackendError::UnknownReader),
            (SCARD_E_READER_UNAVAILABLE, BackendError::UnknownReader),
            (SCARD_E_NO_SMARTCARD, BackendError::NoCard),
            (SCARD_W_REMOVED_CARD, BackendError::Removed),
            (SCARD_W_RESET_CARD, BackendError::Reset),
            (SCARD_E_SHARING_VIOLATION, BackendError::Sharing),
            (
                0x8010_0001,
                BackendError::Failed("SCardTransmit 0x80100001".to_owned()),
            ),
        ] {
            assert_eq!(map_error("SCardTransmit", code), expected);
        }
        assert_eq!(
            backend_error(SysError::Unavailable),
            BackendError::NoService
        );
    }

    #[test]
    fn atr_needs_a_present_card_that_answers() {
        assert_eq!(atr_of(SCARD_STATE_PRESENT, &[0x3B, 0]), Some(vec![0x3B, 0]));
        assert_eq!(
            atr_of(SCARD_STATE_PRESENT | SCARD_STATE_MUTE, &[0x3B]),
            None
        );
        assert_eq!(atr_of(0x10, &[0x3B]), None);
        assert_eq!(atr_of(SCARD_STATE_PRESENT, &[]), None);
    }
}
