//! PC/SC on Windows: `winscard.dll` (every function used exists since Windows XP).

use super::{
    Failure, SCARD_E_INSUFFICIENT_BUFFER, SCARD_E_TIMEOUT, SCARD_LEAVE_CARD, SCARD_PROTOCOL_T0,
    SCARD_PROTOCOL_T1, SCARD_RESET_CARD, SCARD_S_SUCCESS, SCARD_SCOPE_USER, SCARD_SHARE_SHARED,
    SCARD_STATE_UNAWARE, SysResult, atr_of, parse_multi_string_w,
};
use windows_sys::Win32::Security::Credentials::{
    SCARD_IO_REQUEST, SCARD_READERSTATEW, SCardBeginTransaction, SCardConnectW, SCardDisconnect,
    SCardEndTransaction, SCardEstablishContext, SCardGetStatusChangeW, SCardListReadersW,
    SCardReleaseContext, SCardTransmit,
};

fn check(function: &'static str, status: i32) -> Result<(), Failure> {
    match status as u32 {
        SCARD_S_SUCCESS => Ok(()),
        code => Err(Failure { function, code }),
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A PC/SC context, released on drop.
pub(super) struct Context(usize);

impl Context {
    pub(super) fn establish() -> SysResult<Context> {
        let mut ctx = 0;
        // SAFETY: the reserved pointers are null, `ctx` is a valid out pointer.
        check("SCardEstablishContext", unsafe {
            SCardEstablishContext(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut ctx,
            )
        })?;
        Ok(Context(ctx))
    }

    pub(super) fn list_readers(&self) -> SysResult<Vec<String>> {
        // The list may grow between the two calls: retry a few times.
        for _ in 0..4 {
            let mut len = 0;
            // SAFETY: a null buffer asks for the length only.
            let status = unsafe {
                SCardListReadersW(self.0, std::ptr::null(), std::ptr::null_mut(), &mut len)
            };
            check("SCardListReadersW", status)?;
            let mut buf = vec![0u16; len as usize];
            // SAFETY: `buf` holds `len` UTF-16 units.
            let status =
                unsafe { SCardListReadersW(self.0, std::ptr::null(), buf.as_mut_ptr(), &mut len) };
            if status as u32 == SCARD_E_INSUFFICIENT_BUFFER {
                continue;
            }
            check("SCardListReadersW", status)?;
            buf.truncate(len as usize);
            return Ok(parse_multi_string_w(&buf));
        }
        Err(Failure {
            function: "SCardListReadersW",
            code: SCARD_E_INSUFFICIENT_BUFFER,
        }
        .into())
    }

    pub(super) fn states(&self, readers: &[String]) -> SysResult<Vec<Option<Vec<u8>>>> {
        let names: Vec<Vec<u16>> = readers.iter().map(|r| wide(r)).collect();
        let mut states: Vec<SCARD_READERSTATEW> = names
            .iter()
            .map(|n| SCARD_READERSTATEW {
                szReader: n.as_ptr(),
                dwCurrentState: SCARD_STATE_UNAWARE,
                ..SCARD_READERSTATEW::default()
            })
            .collect();
        // SAFETY: `states` holds `len` entries whose names live in `names`.
        let status =
            unsafe { SCardGetStatusChangeW(self.0, 0, states.as_mut_ptr(), states.len() as u32) };
        if status as u32 != SCARD_E_TIMEOUT {
            check("SCardGetStatusChangeW", status)?;
        }
        Ok(states
            .iter()
            .map(|s| {
                let len = (s.cbAtr as usize).min(s.rgbAtr.len());
                atr_of(s.dwEventState, &s.rgbAtr[..len])
            })
            .collect())
    }

    pub(super) fn connect(&self, reader: &str) -> SysResult<(Card, u32)> {
        let name = wide(reader);
        let (mut card, mut protocol) = (0, 0);
        // SAFETY: `name` is NUL-terminated, the out pointers are valid.
        check("SCardConnectW", unsafe {
            SCardConnectW(
                self.0,
                name.as_ptr(),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                &mut card,
                &mut protocol,
            )
        })?;
        Ok((Card(card), protocol))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the context was established and is released once.
        unsafe { SCardReleaseContext(self.0) };
    }
}

/// A connected card, disconnected with a reset on drop.
pub(super) struct Card(usize);

impl Card {
    pub(super) fn begin_transaction(&mut self) -> SysResult<()> {
        // SAFETY: the handle is connected.
        Ok(check("SCardBeginTransaction", unsafe {
            SCardBeginTransaction(self.0)
        })?)
    }

    pub(super) fn end_transaction(&mut self) -> SysResult<()> {
        // SAFETY: the handle is connected.
        Ok(check("SCardEndTransaction", unsafe {
            SCardEndTransaction(self.0, SCARD_LEAVE_CARD)
        })?)
    }

    pub(super) fn transmit(
        &mut self,
        protocol: u32,
        apdu: &[u8],
        buf: &mut [u8],
    ) -> SysResult<usize> {
        let pci = SCARD_IO_REQUEST {
            dwProtocol: protocol,
            cbPciLength: size_of::<SCARD_IO_REQUEST>() as u32,
        };
        let mut len = buf.len() as u32;
        // SAFETY: the buffers are valid for the lengths given.
        check("SCardTransmit", unsafe {
            SCardTransmit(
                self.0,
                &pci,
                apdu.as_ptr(),
                apdu.len() as u32,
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                &mut len,
            )
        })?;
        Ok(len as usize)
    }
}

impl Drop for Card {
    fn drop(&mut self) {
        // SAFETY: the handle is connected and disconnected once; the reset ends the PIN
        // verification.
        unsafe { SCardDisconnect(self.0, SCARD_RESET_CARD) };
    }
}
