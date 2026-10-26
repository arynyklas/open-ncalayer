//! Certificate revocation lists (RFC 5280 §5) of a CA certificate's issuer, as the ades
//! engine of NCALayer checks the CAs of a chain.
//!
//! - The URLs are the `http://` and `https://` URIs of the certificate's
//!   CRLDistributionPoints, tried in order until one gives a valid CRL.
//! - A CRL comes over plain HTTP, so it is hostile input: its issuer must be the subject of
//!   the issuer certificate, its signature must verify with that certificate's key, it
//!   must have no critical extension other than the ones of a complete CRL (a delta CRL or
//!   a CRL with an issuing distribution point is refused), and it must be current:
//!   `thisUpdate ≤ now` and, if it has one, `now < nextUpdate`.
//! - Downloads go through [`CrlCache`]: `<dir>/<hex sha256(url)>.crl`, used without a
//!   request while it is a valid CRL with `now < nextUpdate`, written atomically.
//! - Every failure is a [`CrlError`], never a [`CrlStatus`]: callers decide what an
//!   unchecked certificate means.

#[cfg(feature = "testing")]
mod mock;

#[cfg(feature = "testing")]
pub use mock::MockCrl;

use crate::asn1util::{Enumerated, unsigned};
use crate::ber::{self, BerError};
use crate::cert::Certificate;
use crate::http::{GetOptions, HttpTransport};
use crate::key::{PublicKey, SigAlg};
use crate::pkix::time_of;
use der::asn1::{AnyRef, BitStringRef};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Sequence};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierRef;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, CrlDistributionPoints, CrlNumber, CrlReason,
    FreshestCrl, ID_CE_ISSUER_ALT_NAME,
};

pub use x509_cert::crl::CertificateList;

/// Timeout of a CRL download.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// Largest accepted CRL: 64 MiB. The NCA CRLs of end-entity certificates run to tens of
/// megabytes.
pub const MAX_CRL_LEN: u64 = 64 << 20;

/// Revocation status of a certificate in a CRL of its issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrlStatus {
    /// Not listed.
    Good,
    /// Listed: revoked at `time`, for the CRLReason `reason` if the entry gives one.
    Revoked {
        /// Revocation date.
        time: OffsetDateTime,
        /// CRLReason (RFC 5280 §5.3.1).
        reason: Option<u8>,
    },
}

/// Why no valid CRL is available.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CrlError {
    /// The certificate has no http(s) URI in CRLDistributionPoints.
    #[error("certificate has no CRL distribution point URL")]
    NoUrl,
    /// No HTTP response from the distribution point: connection, timeout or size limit.
    #[error("HTTP request to the CRL distribution point failed: {0}")]
    Http(String),
    /// The distribution point answered with an HTTP status other than 200.
    #[error("CRL distribution point answered HTTP status {0}")]
    HttpStatus(u16),
    /// The CRL is not a valid `CertificateList` of a complete CRL: what is wrong.
    #[error("malformed CRL: {0}")]
    Malformed(String),
    /// The CRL issuer is not the issuer of the certificate.
    #[error("CRL issuer is not the certificate issuer")]
    IssuerMismatch,
    /// The CRL signature does not verify with the issuer key: why.
    #[error("CRL signature does not verify: {0}")]
    BadSignature(String),
    /// thisUpdate is later than now.
    #[error("CRL thisUpdate is in the future")]
    NotYetValid,
    /// now is not before nextUpdate.
    #[error("CRL is outdated")]
    Outdated,
}

impl From<der::Error> for CrlError {
    fn from(e: der::Error) -> Self {
        CrlError::Malformed(e.to_string())
    }
}

impl From<BerError> for CrlError {
    fn from(e: BerError) -> Self {
        CrlError::Malformed(e.to_string())
    }
}

/// The `http://` and `https://` URIs of `cert`'s CRLDistributionPoints (fullName only), in
/// order; none without the extension (or with a malformed one).
pub fn crl_urls(cert: &Certificate) -> Vec<String> {
    let Ok(Some((_, points))) = cert
        .tbs_certificate()
        .get_extension::<CrlDistributionPoints>()
    else {
        return Vec::new();
    };
    points
        .0
        .iter()
        .filter_map(|point| match &point.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
            _ => None,
        })
        .filter(|uri| is_http(uri))
        .collect()
}

/// Whether `uri` starts with `http://` or `https://`, ignoring case.
fn is_http(uri: &str) -> bool {
    ["http://", "https://"].iter().any(|scheme| {
        uri.get(..scheme.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
    })
}

/// `CertificateList` with the `TBSCertList` kept raw: the signed bytes are the received
/// ones, not a re-encoding.
#[derive(Sequence)]
struct SignedCrl<'a> {
    tbs_cert_list: AnyRef<'a>,
    signature_algorithm: AlgorithmIdentifierRef<'a>,
    signature: BitStringRef<'a>,
}

/// CRL extensions of a complete CRL that may be critical without changing what the CRL
/// covers. Any other critical one (deltaCRLIndicator, issuingDistributionPoint, …) makes the
/// CRL unusable here.
const KNOWN_CRL_EXTENSIONS: [der::asn1::ObjectIdentifier; 5] = [
    CrlNumber::OID,
    AuthorityKeyIdentifier::OID,
    ID_CE_ISSUER_ALT_NAME,
    AuthorityInfoAccessSyntax::OID,
    FreshestCrl::OID,
];

/// Checks a DER or BER CRL of `issuer` at `now` (see the module documentation).
///
/// # Errors
///
/// [`CrlError::Malformed`], [`CrlError::IssuerMismatch`], [`CrlError::BadSignature`],
/// [`CrlError::NotYetValid`] or [`CrlError::Outdated`], checked in this order; an
/// unsupported critical extension, checked after the signature, is
/// [`CrlError::Malformed`].
pub fn verify_crl(
    crl_der: &[u8],
    issuer: &Certificate,
    now: OffsetDateTime,
) -> Result<CertificateList, CrlError> {
    let der = ber::to_der(crl_der)?;
    let signed = SignedCrl::from_der(&der)?;
    let crl = CertificateList::from_der(&der)?;
    let tbs = &crl.tbs_cert_list;
    if tbs.issuer != *issuer.tbs_certificate().subject() {
        return Err(CrlError::IssuerMismatch);
    }

    let oid = signed.signature_algorithm.oid;
    if tbs.signature.oid != oid {
        return Err(CrlError::Malformed(
            "signatureAlgorithm differs from tbsCertList.signature".to_owned(),
        ));
    }
    let alg = SigAlg::from_signature_oid(&oid)
        .ok_or_else(|| CrlError::BadSignature(format!("unsupported signature algorithm {oid}")))?;
    let key = PublicKey::from_spki(issuer.tbs_certificate().subject_public_key_info())
        .map_err(|e| CrlError::BadSignature(format!("issuer key: {e}")))?;
    let signature = signed
        .signature
        .as_bytes()
        .ok_or_else(|| CrlError::Malformed("signature BIT STRING has unused bits".to_owned()))?;
    key.verify(alg, &signed.tbs_cert_list.to_der()?, signature)
        .map_err(|e| CrlError::BadSignature(e.to_string()))?;

    if let Some(unknown) = tbs
        .crl_extensions
        .iter()
        .flatten()
        .find(|e| e.critical && !KNOWN_CRL_EXTENSIONS.contains(&e.extn_id))
    {
        return Err(CrlError::Malformed(format!(
            "unsupported critical CRL extension {}",
            unknown.extn_id
        )));
    }

    if time_of(&tbs.this_update) > now {
        return Err(CrlError::NotYetValid);
    }
    if tbs.next_update.is_some_and(|next| now >= time_of(&next)) {
        return Err(CrlError::Outdated);
    }
    Ok(crl)
}

/// Status of the serial number `serial` (unsigned big-endian bytes; leading zeros do not
/// matter) in `crl`.
pub fn lookup(crl: &CertificateList, serial: &[u8]) -> CrlStatus {
    let serial = unsigned(serial);
    let Some(entry) = crl
        .tbs_cert_list
        .revoked_certificates
        .iter()
        .flatten()
        .find(|entry| unsigned(entry.serial_number.as_bytes()) == serial)
    else {
        return CrlStatus::Good;
    };
    let reason = entry
        .crl_entry_extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == CrlReason::OID)
        .and_then(|e| Enumerated::from_der(e.extn_value.as_bytes()).ok())
        .map(|reason| reason.0);
    CrlStatus::Revoked {
        time: time_of(&entry.revocation_date),
        reason,
    }
}

/// CRLs downloaded before, on disk: `<dir>/<hex sha256(url)>.crl`, the body as received.
///
/// A file that is not a valid, current CRL of the issuer is ignored (and replaced by the
/// next successful download); failing to write one does not fail the download.
#[derive(Clone, Debug)]
pub struct CrlCache {
    dir: PathBuf,
}

impl CrlCache {
    /// A cache in `dir` (normally `<data_dir>/crl`), created on the first write.
    pub fn new(dir: impl Into<PathBuf>) -> CrlCache {
        CrlCache { dir: dir.into() }
    }

    /// The CRL at `url` of `issuer`, valid at `now`: the cached one while it has a
    /// nextUpdate after `now`, otherwise downloaded through `http` within [`TIMEOUT`] and
    /// [`MAX_CRL_LEN`], checked and, if it has a nextUpdate, cached.
    ///
    /// # Errors
    ///
    /// [`CrlError::Http`] or [`CrlError::HttpStatus`] if the download fails, the errors of
    /// [`verify_crl`] if the downloaded CRL is not valid.
    pub fn fetch(
        &self,
        url: &str,
        issuer: &Certificate,
        http: &dyn HttpTransport,
        now: OffsetDateTime,
    ) -> Result<CertificateList, CrlError> {
        let path = self.path(url);
        if let Some(crl) = cached(&path, issuer, now) {
            return Ok(crl);
        }
        let opts = GetOptions {
            timeout: TIMEOUT,
            max_len: MAX_CRL_LEN,
        };
        let reply = http.get_with(url, opts).map_err(|e| CrlError::Http(e.0))?;
        if reply.status != 200 {
            return Err(CrlError::HttpStatus(reply.status));
        }
        let crl = verify_crl(&reply.body, issuer, now)?;
        if crl.tbs_cert_list.next_update.is_some() {
            // A cache that cannot be written only costs a download next time.
            let _ = write_atomically(&self.dir, &path, &reply.body);
        }
        Ok(crl)
    }

    fn path(&self, url: &str) -> PathBuf {
        let mut name = String::with_capacity(68);
        for b in Sha256::digest(url.as_bytes()) {
            // Writing to a `String` cannot fail.
            let _ = write!(name, "{b:02x}");
        }
        name.push_str(".crl");
        self.dir.join(name)
    }
}

/// The CRL in `path` if it is a valid CRL of `issuer` with a nextUpdate after `now`.
fn cached(path: &Path, issuer: &Certificate, now: OffsetDateTime) -> Option<CertificateList> {
    let mut der = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_CRL_LEN + 1)
        .read_to_end(&mut der)
        .ok()?;
    if u64::try_from(der.len()).ok()? > MAX_CRL_LEN {
        return None;
    }
    let crl = verify_crl(&der, issuer, now).ok()?;
    crl.tbs_cert_list.next_update.is_some().then_some(crl)
}

/// Writes `body` to `path` in `dir` through a temporary file in `dir` and a rename, so that
/// a reader sees the old file or the new one, never a part.
fn write_atomically(dir: &Path, path: &Path, body: &[u8]) -> std::io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fs::create_dir_all(dir)?;
    let tmp = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let written = File::create_new(&tmp)
        .and_then(|mut file| file.write_all(body))
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// Status of `cert` in the CRL of `issuer` from the first of its distribution point URLs
/// that gives a valid CRL at `now` (through `cache` and `http`).
///
/// # Errors
///
/// [`CrlError::NoUrl`] without a URL, [`CrlError::IssuerMismatch`] if `issuer` did not
/// issue `cert`; when no URL gives a valid CRL, the error of the last one.
pub fn check(
    cert: &Certificate,
    issuer: &Certificate,
    cache: &CrlCache,
    http: &dyn HttpTransport,
    now: OffsetDateTime,
) -> Result<CrlStatus, CrlError> {
    let urls = crl_urls(cert);
    if urls.is_empty() {
        return Err(CrlError::NoUrl);
    }
    let tbs = cert.tbs_certificate();
    if tbs.issuer() != issuer.tbs_certificate().subject() {
        return Err(CrlError::IssuerMismatch);
    }
    let mut last = CrlError::NoUrl;
    for url in &urls {
        match cache.fetch(url, issuer, http, now) {
            Ok(crl) => return Ok(lookup(&crl, tbs.serial_number().as_bytes())),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_schemes() {
        assert!(is_http("http://a/b.crl"));
        assert!(is_http("HTTPS://a/b.crl"));
        assert!(!is_http("ldap://a/cn=b"));
        assert!(!is_http("http:/a"));
        assert!(!is_http("htt"));
        assert!(!is_http("ftp://ünïcode"));
    }

    #[test]
    fn cache_file_name_is_the_url_hash() {
        let cache = CrlCache::new("dir");
        assert_eq!(
            cache.path("http://crl.root.gov.kz/gost2015_2022.crl"),
            Path::new("dir")
                .join("f9ce723c2eadabfc7d0f66968bf0362b7602802b321d8f0b8565fcbab80ddceb.crl")
        );
    }

    #[test]
    fn error_messages_keep_their_cause() {
        assert_eq!(
            CrlError::BadSignature("bad".to_owned()).to_string(),
            "CRL signature does not verify: bad"
        );
        assert_eq!(
            CrlError::from(BerError::Truncated { offset: 3 }).to_string(),
            "malformed CRL: BER input is truncated at offset 3"
        );
    }
}
