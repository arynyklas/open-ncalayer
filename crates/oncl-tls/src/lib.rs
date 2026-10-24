//! Local TLS wizard backend of OpenNCALayer.
//!
//! - [`generate`] issues a local CA name-constrained to `127.0.0.1`, `::1` and `localhost`
//!   and a server leaf under it; the CA private key is zeroized right after issuing and is
//!   never written anywhere.
//! - [`import`] checks a user-supplied leaf + chain and its private key.
//! - [`save`], [`load_info`] and [`server_config`] keep the material in [`TlsFiles`] and turn
//!   it into a `rustls` server configuration (ring, TLS 1.2 and 1.3, no client auth).
//! - [`instructions`] tells the user how to trust the CA. OpenNCALayer never writes to OS or
//!   browser trust stores itself.

mod files;
mod generate;
mod import;
mod instructions;

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

pub use files::{TlsFiles, load_info, save, server_config};
pub use generate::generate;
pub use import::import;
pub use instructions::{TargetOs, instructions, sha1_grouped};

/// Where the TLS material came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsSource {
    /// Issued by [`generate`] under a local CA.
    Generated,
    /// Supplied by the user via [`import`].
    Imported,
}

/// Metadata stored next to the TLS files (`tls.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    pub source: TlsSource,
    /// Lowercase hex SHA-1 of the local CA certificate (generated material only).
    pub ca_sha1: Option<String>,
    /// Lowercase hex SHA-256 of the local CA certificate (generated material only).
    pub ca_sha256: Option<String>,
    /// Lowercase hex SHA-256 of the leaf certificate.
    pub leaf_sha256: String,
    /// Leaf `notAfter`, RFC 3339.
    pub leaf_not_after: String,
    /// Creation time, RFC 3339.
    pub created_at: String,
    /// Product and version that produced the material.
    pub generator: String,
}

/// Non-fatal findings of [`import`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsWarning {
    /// The leaf is valid for more than 825 days, which some clients (Apple) refuse.
    ValidityOver825Days,
}

/// Server TLS material ready to be [`save`]d.
pub struct TlsMaterial {
    /// Leaf first, then intermediates (PEM).
    pub chain_pem: String,
    /// Leaf private key (PEM).
    pub key_pem: Zeroizing<String>,
    /// Local CA certificate (PEM), generated material only.
    pub ca_pem: Option<String>,
    /// Local CA certificate (DER), generated material only.
    pub ca_der: Option<Vec<u8>>,
    pub info: TlsInfo,
    pub warnings: Vec<TlsWarning>,
}

impl fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMaterial")
            .field("chain_pem", &self.chain_pem)
            .field("key_pem", &"[secret key elided]")
            .field("ca_pem", &self.ca_pem)
            .field("ca_der", &self.ca_der.as_ref().map(Vec::len))
            .field("info", &self.info)
            .field("warnings", &self.warnings)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    #[error("the certificate has no IP address 127.0.0.1 in subjectAltName")]
    MissingIpSan,
    #[error("the certificate has no serverAuth extended key usage")]
    MissingServerAuth,
    #[error("the key must be ECDSA P-256/P-384 or RSA of at least 2048 bits")]
    WeakKey,
    #[error("the certificate chain is signed with SHA-1")]
    Sha1Signature,
    #[error("the certificate has expired")]
    Expired,
    #[error("the private key does not match the certificate")]
    KeyMismatch,
    #[error("cannot parse TLS material: {0}")]
    Parse(String),
    #[error("cannot generate TLS material: {0}")]
    Gen(String),
}

/// Value of [`TlsInfo::generator`].
fn generator() -> String {
    concat!("OpenNCALayer ", env!("CARGO_PKG_VERSION")).to_owned()
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn sha1_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
}

fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

/// RFC 3339 in UTC; fails only for years outside 0000..=9999.
fn rfc3339(t: OffsetDateTime) -> Result<String, String> {
    t.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|e| format!("time {t}: {e}"))
}
