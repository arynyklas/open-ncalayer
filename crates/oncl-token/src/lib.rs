//! Hardware tokens and ID cards for OpenNCALayer: APDUs over a smart card service, the
//! token families of the Kazakhstan PKI and their ATRs.
//!
//! Token support is experimental: the drivers follow the documented byte formats of each
//! family and are checked against software cards only.

pub mod apdu;
pub mod backend;
pub mod card;
pub mod drivers;
#[cfg(feature = "emulator")]
pub mod emulator;
mod error;
mod gzip;
mod kind;

pub use drivers::IdCardInfo;
pub use error::TokenError;
pub use kind::{ATRS, TokenKind};

/// Environment variable that turns the APDU trace on (`1`). PINs never reach the trace.
pub const TRACE_VAR: &str = "ONCL_TOKEN_TRACE";

/// Most response bytes accepted for one command, GET RESPONSE chains joined.
pub const MAX_RESPONSE: usize = 65_538;

/// Most GET RESPONSE commands sent for one command.
pub const MAX_GET_RESPONSE: usize = 256;

/// Most bytes of a stored (compressed) certificate read from a token.
pub const MAX_GZ_CERT: usize = 4096;

/// Most bytes of a decompressed certificate.
pub const MAX_CERT: usize = 65_536;
