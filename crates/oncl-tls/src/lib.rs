//! Local TLS wizard backend of OpenNCALayer.
//!
//! - [`generate`] issues a local CA name-constrained to `127.0.0.1`, `::1` and `localhost`
//!   and a server leaf under it; the CA private key is zeroized right after issuing and is
//!   never written anywhere.
//! - [`issue_with_mkcert`] issues the server leaf with the CA of mkcert found by
//!   [`mkcert_caroot`], with the user's consent; mkcert's CA key is only read, never copied.
//! - [`import`] checks a user-supplied leaf + chain and its private key.
//! - [`save`], [`load_info`] and [`server_config`] keep the material in [`TlsFiles`] and turn
//!   it into a `rustls` server configuration (ring, TLS 1.2 and 1.3, no client auth); a
//!   local CA replaced by [`save`] is kept as a [`replaced_cas`] file until the user has
//!   removed it from the trust stores.
//! - [`needs_renewal`] tells when the server certificate is due.
//! - [`instructions`] tells the user how to trust the CA. OpenNCALayer writes to a trust
//!   store only when the user asks for it in the TLS wizard.
//! - [`SelftestReports`] are the browsers that opened the self-test page.

mod files;
mod generate;
mod import;
mod instructions;
mod mkcert;
mod selftest;

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

pub use files::{TlsFiles, forget_replaced_ca, load_info, replaced_cas, save, server_config};
pub use generate::generate;
pub use import::import;
pub use instructions::{TargetOs, instructions, nss_nickname, sha1_grouped};
pub use mkcert::{issue_with_mkcert, mkcert_caroot};
pub use selftest::{SelftestReport, SelftestReports};

/// Remind the user to re-issue the server certificate this long before it expires.
pub const RENEW_BEFORE: Duration = Duration::days(60);
/// A certificate issued with mkcert's CA is re-issued automatically this long before it
/// expires.
pub const AUTO_RENEW_BEFORE: Duration = Duration::days(30);

/// Where the TLS material came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsSource {
    /// Issued by [`generate`] under OpenNCALayer's own local CA (whose key is gone).
    // `generated`: the name before mkcert existed.
    #[serde(alias = "generated")]
    Own,
    /// Issued by [`issue_with_mkcert`] with the key of the mkcert CA in `caroot`. The user
    /// agreed at `consented_at` (RFC 3339) that this key is read at every renewal.
    Mkcert {
        caroot: PathBuf,
        consented_at: String,
    },
    /// Supplied by the user via [`import`].
    Imported,
}

/// Metadata stored next to the TLS files (`tls.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    pub source: TlsSource,
    /// Lowercase hex SHA-1 of the CA certificate (own or mkcert's; none when imported).
    pub ca_sha1: Option<String>,
    /// Lowercase hex SHA-256 of the CA certificate (own or mkcert's; none when imported).
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

/// What [`needs_renewal`] advises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewal {
    /// Not due yet.
    None,
    /// Ask the user to re-issue (the TLS wizard): the certificate expires in `days` whole
    /// days (0 or less: today or already).
    Remind { days: i64 },
    /// Re-issue with mkcert's CA now, without asking: the user agreed to it.
    AutoRenew,
}

/// Whether the server certificate of `info` is due for renewal at `now`: an mkcert one is
/// re-issued automatically within [`AUTO_RENEW_BEFORE`] of its end (and not reminded of
/// before), others are reminded of within [`RENEW_BEFORE`]. An unreadable end date counts
/// as due today.
pub fn needs_renewal(info: &TlsInfo, now: OffsetDateTime) -> Renewal {
    let Ok(not_after) = OffsetDateTime::parse(&info.leaf_not_after, &Rfc3339) else {
        return Renewal::Remind { days: 0 };
    };
    let left = not_after - now;
    match info.source {
        TlsSource::Mkcert { .. } if left <= AUTO_RENEW_BEFORE => Renewal::AutoRenew,
        TlsSource::Mkcert { .. } => Renewal::None,
        TlsSource::Own | TlsSource::Imported if left <= RENEW_BEFORE => Renewal::Remind {
            days: left.whole_days(),
        },
        TlsSource::Own | TlsSource::Imported => Renewal::None,
    }
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
    /// mkcert's CA cannot be used: its files are missing, unreadable or do not belong
    /// together, or the CA is not valid.
    #[error("cannot use the mkcert CA: {0}")]
    Mkcert(String),
}

/// The common name of the subject of the DER certificate `der`, if it parses and has one
/// (as UTF-8, PrintableString or IA5String).
pub fn subject_common_name(der: &[u8]) -> Option<String> {
    use der::{Decode, Tag, Tagged};
    const COMMON_NAME: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    let cert = x509_cert::Certificate::from_der(der).ok()?;
    let subject = cert.tbs_certificate().subject();
    let value = subject
        .iter()
        .filter(|attribute| attribute.oid == COMMON_NAME)
        .last()?
        .value
        .clone();
    match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String => {
            String::from_utf8(value.value().to_vec()).ok()
        }
        _ => None,
    }
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
