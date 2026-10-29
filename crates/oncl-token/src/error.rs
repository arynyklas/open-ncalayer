//! Errors of token operations.

use crate::backend::BackendError;

/// Error of a token operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// Token support is off.
    #[error("token support is off")]
    Disabled,
    /// The smart card service is not available.
    #[error("the smart card service is not available")]
    NoService,
    /// No token of that kind in the reader.
    #[error("no token in the reader")]
    NoDevice,
    /// The card in the reader is not the expected token.
    #[error("another card is in the reader")]
    WrongCard,
    /// The card was removed or reset during the operation.
    #[error("the token was removed")]
    CardRemoved,
    /// The PIN is wrong; the tries left when the token tells them.
    #[error("wrong PIN{}", tries_text(*tries_left))]
    WrongPin {
        /// Tries left before the PIN is blocked.
        tries_left: Option<u8>,
    },
    /// The PIN is blocked.
    #[error("the PIN is blocked")]
    PinBlocked,
    /// The PIN does not fit the token (empty, not ASCII, wrong length).
    #[error("the PIN does not fit this token")]
    InvalidPin,
    /// The card refused a command.
    #[error("the card refused {op}: status {sw:04X}")]
    Card {
        /// The operation.
        op: &'static str,
        /// Status word.
        sw: u16,
    },
    /// The card answered something unexpected.
    #[error("unexpected answer of the card: {0}")]
    Malformed(String),
    /// The exchange with the card failed.
    #[error("smart card exchange failed: {0}")]
    Transport(String),
}

fn tries_text(tries: Option<u8>) -> String {
    tries.map_or_else(String::new, |n| format!(", {n} tries left"))
}

impl From<BackendError> for TokenError {
    fn from(e: BackendError) -> TokenError {
        match e {
            BackendError::NoService => TokenError::NoService,
            BackendError::NoReaders | BackendError::UnknownReader | BackendError::NoCard => {
                TokenError::NoDevice
            }
            BackendError::Removed | BackendError::Reset => TokenError::CardRemoved,
            BackendError::Sharing | BackendError::Failed(_) => TokenError::Transport(e.to_string()),
        }
    }
}
