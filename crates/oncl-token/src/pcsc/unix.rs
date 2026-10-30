//! PC/SC through the pcsc-lite API (Linux, and macOS's PCSC.framework, which has the same
//! functions): contexts and cards over the platform's function table.

use super::platform::{Api, Dword, Handle, IoRequest, ReaderState, api, to_u32};
use super::{
    Failure, SCARD_E_INSUFFICIENT_BUFFER, SCARD_E_TIMEOUT, SCARD_LEAVE_CARD, SCARD_PROTOCOL_T0,
    SCARD_PROTOCOL_T1, SCARD_RESET_CARD, SCARD_S_SUCCESS, SCARD_SCOPE_USER, SCARD_SHARE_SHARED,
    SCARD_STATE_UNAWARE, SysError, SysResult, atr_of, parse_multi_string,
};
use std::ffi::CString;

fn check<L: TryInto<i64>>(function: &'static str, status: L) -> Result<(), Failure> {
    // Status codes are 32-bit values, sign-extended or not in the platform's LONG.
    let code = status.try_into().map_or(u32::MAX, |s: i64| s as u32);
    match code {
        SCARD_S_SUCCESS => Ok(()),
        code => Err(Failure { function, code }),
    }
}

fn c_name(reader: &str) -> SysResult<CString> {
    CString::new(reader).map_err(|_| {
        SysError::Call(Failure {
            function: "SCardConnect",
            code: super::SCARD_E_UNKNOWN_READER,
        })
    })
}

/// A PC/SC context, released on drop.
pub(super) struct Context {
    api: &'static Api,
    handle: Handle,
}

impl Context {
    pub(super) fn establish() -> SysResult<Context> {
        let api = api().ok_or(SysError::Unavailable)?;
        let mut handle: Handle = 0;
        // SAFETY: the reserved pointers are null, `handle` is a valid out pointer.
        check("SCardEstablishContext", unsafe {
            (api.establish)(
                SCARD_SCOPE_USER as Dword,
                std::ptr::null(),
                std::ptr::null(),
                &mut handle,
            )
        })?;
        Ok(Context { api, handle })
    }

    pub(super) fn list_readers(&self) -> SysResult<Vec<String>> {
        // The list may grow between the two calls: retry a few times.
        for _ in 0..4 {
            let mut len: Dword = 0;
            // SAFETY: a null buffer asks for the length only.
            let status = unsafe {
                (self.api.list_readers)(
                    self.handle,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    &mut len,
                )
            };
            check("SCardListReaders", status)?;
            let mut buf = vec![0u8; len as usize];
            // SAFETY: `buf` holds `len` bytes.
            let status = unsafe {
                (self.api.list_readers)(
                    self.handle,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if check("SCardListReaders", status)
                .is_err_and(|f| f.code == SCARD_E_INSUFFICIENT_BUFFER)
            {
                continue;
            }
            check("SCardListReaders", status)?;
            buf.truncate(len as usize);
            return Ok(parse_multi_string(&buf));
        }
        Err(Failure {
            function: "SCardListReaders",
            code: SCARD_E_INSUFFICIENT_BUFFER,
        }
        .into())
    }

    pub(super) fn states(&self, readers: &[String]) -> SysResult<Vec<Option<Vec<u8>>>> {
        let names = readers
            .iter()
            .map(|r| c_name(r))
            .collect::<SysResult<Vec<CString>>>()?;
        let mut states: Vec<ReaderState> = names
            .iter()
            .map(|n| ReaderState {
                reader: n.as_ptr(),
                user_data: std::ptr::null_mut(),
                current_state: SCARD_STATE_UNAWARE as Dword,
                event_state: 0,
                atr_len: 0,
                atr: [0; 33],
            })
            .collect();
        // SAFETY: `states` holds `len` entries whose names live in `names`.
        let status = unsafe {
            (self.api.get_status_change)(self.handle, 0, states.as_mut_ptr(), states.len() as Dword)
        };
        if check("SCardGetStatusChange", status).is_err_and(|f| f.code != SCARD_E_TIMEOUT) {
            check("SCardGetStatusChange", status)?;
        }
        Ok(states
            .iter()
            .map(|s| {
                let (event, len, atr) = (s.event_state, s.atr_len, s.atr);
                let len = (len as usize).min(atr.len());
                atr_of(to_u32(event), &atr[..len])
            })
            .collect())
    }

    pub(super) fn connect(&self, reader: &str) -> SysResult<(Card, u32)> {
        let name = c_name(reader)?;
        let (mut card, mut protocol): (Handle, Dword) = (0, 0);
        // SAFETY: `name` is NUL-terminated, the out pointers are valid.
        check("SCardConnect", unsafe {
            (self.api.connect)(
                self.handle,
                name.as_ptr(),
                SCARD_SHARE_SHARED as Dword,
                (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1) as Dword,
                &mut card,
                &mut protocol,
            )
        })?;
        Ok((
            Card {
                api: self.api,
                handle: card,
                reset: false,
            },
            to_u32(protocol),
        ))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the context was established and is released once.
        unsafe { (self.api.release)(self.handle) };
    }
}

/// A connected card, disconnected on drop: with a reset after
/// [`Card::reset_on_disconnect`], else leaving the card.
pub(super) struct Card {
    api: &'static Api,
    handle: Handle,
    reset: bool,
}

impl Card {
    pub(super) fn reset_on_disconnect(&mut self) {
        self.reset = true;
    }

    pub(super) fn begin_transaction(&mut self) -> SysResult<()> {
        // SAFETY: the handle is connected.
        Ok(check("SCardBeginTransaction", unsafe {
            (self.api.begin)(self.handle)
        })?)
    }

    pub(super) fn end_transaction(&mut self) -> SysResult<()> {
        // SAFETY: the handle is connected.
        Ok(check("SCardEndTransaction", unsafe {
            (self.api.end)(self.handle, SCARD_LEAVE_CARD as Dword)
        })?)
    }

    pub(super) fn transmit(
        &mut self,
        protocol: u32,
        apdu: &[u8],
        buf: &mut [u8],
    ) -> SysResult<usize> {
        let pci = IoRequest {
            protocol: protocol as Dword,
            pci_length: size_of::<IoRequest>() as Dword,
        };
        let mut len = buf.len() as Dword;
        // SAFETY: the buffers are valid for the lengths given.
        check("SCardTransmit", unsafe {
            (self.api.transmit)(
                self.handle,
                &pci,
                apdu.as_ptr(),
                apdu.len() as Dword,
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
        // A reset ends the PIN verification for every process; without a PIN sent, leaving
        // the card keeps the other connections to it working.
        let disposition = if self.reset {
            SCARD_RESET_CARD
        } else {
            SCARD_LEAVE_CARD
        };
        // SAFETY: the handle is connected and disconnected once.
        unsafe { (self.api.disconnect)(self.handle, disposition as Dword) };
    }
}
