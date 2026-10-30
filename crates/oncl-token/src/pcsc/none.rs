//! Systems without a supported PC/SC service: none is available.

use super::{SysError, SysResult};

pub(super) struct Context;

impl Context {
    pub(super) fn establish() -> SysResult<Context> {
        Err(SysError::Unavailable)
    }

    pub(super) fn list_readers(&self) -> SysResult<Vec<String>> {
        Err(SysError::Unavailable)
    }

    pub(super) fn states(&self, _readers: &[String]) -> SysResult<Vec<Option<Vec<u8>>>> {
        Err(SysError::Unavailable)
    }

    pub(super) fn connect(&self, _reader: &str) -> SysResult<(Card, u32)> {
        Err(SysError::Unavailable)
    }
}

pub(super) struct Card;

impl Card {
    pub(super) fn reset_on_disconnect(&mut self) {}

    pub(super) fn begin_transaction(&mut self) -> SysResult<()> {
        Err(SysError::Unavailable)
    }

    pub(super) fn end_transaction(&mut self) -> SysResult<()> {
        Err(SysError::Unavailable)
    }

    pub(super) fn transmit(
        &mut self,
        _protocol: u32,
        _apdu: &[u8],
        _buf: &mut [u8],
    ) -> SysResult<usize> {
        Err(SysError::Unavailable)
    }
}
