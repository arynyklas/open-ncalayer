//! Certificate revocation lists (RFC 5280 §5) of a CA certificate's issuer, as the ades
//! engine of NCALayer checks the CAs of a chain.
//!
//! - The URLs are the `http://` and `https://` URIs of the certificate's
//!   CRLDistributionPoints, in order. Some NCA certificates (ncagost18, ncarsa18) pack two
//!   mirrors into one URI value, `http://a/x.crl\n    URL=http://b/x.crl`: a value is split
//!   on ASCII whitespace and a leading `URL=` is dropped.
//! - A cached CRL of any of the URLs is used first; otherwise the URLs are downloaded in
//!   order until one gives a valid CRL.
//! - A CRL comes over plain HTTP, so it is hostile input. Before the list is decoded, its
//!   issuer must be the subject of the issuer certificate, compared as DER bytes without
//!   decoding the name, and its signature must verify with that certificate's key over
//!   the signed `TBSCertList` bytes. Then it must be a complete CRL, so a delta CRL
//!   (deltaCRLIndicator) or a CRL with an issuing distribution point is refused, critical
//!   or not, and so is any other unknown critical extension; and it must be current:
//!   `thisUpdate ≤ now` and, if it has one, `now < nextUpdate`.
//! - A CRL is parsed as DER. A BER one is normalized to DER first ([`ber::to_der`]) only
//!   up to [`MAX_BER_CRL_LEN`]: normalization builds a tree of every element of the still
//!   unauthenticated body, so a bigger body that is not DER is [`CrlError::Malformed`].
//! - Downloads are not cached on disk: [`fetch_for`] asks the distribution points in order.
//! - Every failure is a [`CrlError`], never a [`CrlStatus`]: callers decide what an
//!   unchecked certificate means.

#[cfg(feature = "testing")]
mod mock;

#[cfg(feature = "testing")]
pub use mock::MockCrl;

use crate::asn1util::{Enumerated, unsigned};
use crate::ber::{self, BerError};
use crate::cert::Certificate;
use crate::http::{CONNECT_TIMEOUT, GetOptions, HttpError, HttpTransport, NetKind};
use crate::key::{PublicKey, SigAlg};
use crate::oid;
use crate::pkix::{Currency, time_of};
use der::asn1::{BitStringRef, IntRef, ObjectIdentifier};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Reader, SliceReader};
use spki::AlgorithmIdentifierRef;
use std::borrow::Cow;
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

/// Largest CRL normalized from BER, as big as an OCSP or TSP answer: 1 MiB. A bigger CRL
/// must be DER (see the module documentation).
pub const MAX_BER_CRL_LEN: usize = 1 << 20;

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
    Http(HttpError),
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

impl CrlError {
    /// What kind of network failure it is, as the plugins see it.
    pub fn kind(&self) -> NetKind {
        match self {
            CrlError::NoUrl => NetKind::Other,
            CrlError::Http(e) => e.kind.into(),
            CrlError::HttpStatus(status) => NetKind::Http(*status),
            _ => NetKind::InvalidResponse,
        }
    }
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

/// The `http://` and `https://` URLs of `cert`'s CRLDistributionPoints (fullName URIs
/// only), in order and without repeats; none without the extension (or with a malformed
/// one). A URI value is split on ASCII whitespace and a leading `URL=` of a part is
/// dropped (see the module documentation).
pub fn crl_urls(cert: &Certificate) -> Vec<String> {
    match cert
        .tbs_certificate()
        .get_extension::<CrlDistributionPoints>()
    {
        Ok(Some((_, points))) => point_urls(&points.0),
        _ => Vec::new(),
    }
}

/// The `http://` and `https://` URLs of `cert`'s FreshestCRL (delta CRLs), read as
/// [`crl_urls`] reads its distribution points.
pub fn freshest_urls(cert: &Certificate) -> Vec<String> {
    match cert.tbs_certificate().get_extension::<FreshestCrl>() {
        Ok(Some((_, points))) => point_urls(&points.0),
        _ => Vec::new(),
    }
}

/// The http(s) fullName URIs of distribution points, in order and without repeats.
fn point_urls(points: &[x509_cert::ext::pkix::crl::dp::DistributionPoint]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    let uris = points
        .iter()
        .filter_map(|point| match &point.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
            _ => None,
        });
    for part in uris.flat_map(str::split_ascii_whitespace) {
        let url = part.strip_prefix("URL=").unwrap_or(part);
        if is_http(url) && !urls.iter().any(|u| u == url) {
            urls.push(url.to_owned());
        }
    }
    urls
}

/// Whether `uri` starts with `http://` or `https://`, ignoring case.
fn is_http(uri: &str) -> bool {
    ["http://", "https://"].iter().any(|scheme| {
        uri.get(..scheme.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
    })
}

/// What is checked of a `CertificateList` before it is decoded, borrowed from the DER.
/// Nothing is decoded into owned structures: the body is not authenticated yet.
struct SignedCrl<'a> {
    /// The whole `TBSCertList` element: the signed bytes as received.
    tbs: &'a [u8],
    /// `tbsCertList.signature`.
    tbs_signature: AlgorithmIdentifierRef<'a>,
    /// The whole `tbsCertList.issuer` element, not decoded: it is compared byte for byte.
    issuer: &'a [u8],
    signature_algorithm: AlgorithmIdentifierRef<'a>,
    signature: BitStringRef<'a>,
}

impl<'a> SignedCrl<'a> {
    fn read(der: &'a [u8]) -> der::Result<Self> {
        let mut reader = SliceReader::new(der)?;
        let (tbs, signature_algorithm, signature) =
            reader.sequence(|r| Ok::<_, der::Error>((r.tlv_bytes()?, r.decode()?, r.decode()?)))?;
        reader.finish()?;
        let mut reader = SliceReader::new(tbs)?;
        let (tbs_signature, issuer) = reader.sequence(|r| {
            // version is not checked here: the full decode accepts v1 to v3 (0 to 2).
            let _version: Option<IntRef<'_>> = r.decode()?;
            let signature = r.decode()?;
            let issuer = r.tlv_bytes()?;
            r.read_slice(r.remaining_len())?;
            Ok::<_, der::Error>((signature, issuer))
        })?;
        reader.finish()?;
        Ok(SignedCrl {
            tbs,
            tbs_signature,
            issuer,
            signature_algorithm,
            signature,
        })
    }
}

/// CRL extensions that make a CRL other than a complete CRL of everything its issuer
/// issued, refused whether critical or not.
const REFUSED_CRL_EXTENSIONS: [ObjectIdentifier; 2] =
    [oid::DELTA_CRL_INDICATOR, oid::ISSUING_DISTRIBUTION_POINT];

/// CRL extensions of a complete CRL that may be critical without changing what the CRL
/// covers. Any other critical one makes the CRL unusable here.
const KNOWN_CRL_EXTENSIONS: [ObjectIdentifier; 5] = [
    CrlNumber::OID,
    AuthorityKeyIdentifier::OID,
    ID_CE_ISSUER_ALT_NAME,
    AuthorityInfoAccessSyntax::OID,
    FreshestCrl::OID,
];

/// Checks a DER CRL, or a BER one of at most [`MAX_BER_CRL_LEN`] bytes, of `issuer` at
/// `now` (see the module documentation). The issuer name (byte for byte, as DER) and the
/// signature are checked before the CRL is decoded.
///
/// # Errors
///
/// [`CrlError::Malformed`], [`CrlError::IssuerMismatch`], [`CrlError::BadSignature`],
/// [`CrlError::NotYetValid`] or [`CrlError::Outdated`], checked in this order; a CRL whose
/// list does not decode, or that is not a complete CRL, is [`CrlError::Malformed`] after
/// its signature is checked.
pub fn verify_crl(
    crl_der: &[u8],
    issuer: &Certificate,
    now: OffsetDateTime,
) -> Result<CertificateList, CrlError> {
    verify_any_crl(crl_der, issuer, now, false)
}

/// [`verify_crl`] of a complete CRL, or (`delta`) of a delta CRL, which must have a
/// deltaCRLIndicator.
fn verify_any_crl(
    crl_der: &[u8],
    issuer: &Certificate,
    now: OffsetDateTime,
    delta: bool,
) -> Result<CertificateList, CrlError> {
    let der = authenticated(crl_der, issuer)?;
    let crl = CertificateList::from_der(&der)?;
    let tbs = &crl.tbs_cert_list;
    let mut indicated = false;
    for extension in tbs.crl_extensions.iter().flatten() {
        check_extension(extension, delta, &mut indicated)?;
    }
    if delta && !indicated {
        return Err(CrlError::Malformed(
            "a delta CRL without deltaCRLIndicator".to_owned(),
        ));
    }
    check_times(
        &tbs.this_update,
        tbs.next_update.as_ref(),
        Currency::Now(now),
    )?;
    Ok(crl)
}

/// The CRL as DER (a BER one of at most [`MAX_BER_CRL_LEN`] bytes is normalized) once its
/// issuer name and signature are checked, before anything of it is decoded.
fn authenticated<'a>(crl_der: &'a [u8], issuer: &Certificate) -> Result<Cow<'a, [u8]>, CrlError> {
    let strict = crl_der.len() > MAX_BER_CRL_LEN;
    let der: Cow<'_, [u8]> = if strict {
        Cow::Borrowed(crl_der)
    } else {
        Cow::Owned(ber::to_der(crl_der)?)
    };
    let signed = SignedCrl::read(&der).map_err(|e| {
        if strict {
            CrlError::Malformed(format!(
                "{e} (a CRL over {MAX_BER_CRL_LEN} bytes must be DER)"
            ))
        } else {
            CrlError::from(e)
        }
    })?;
    let subject = issuer.tbs_certificate().subject().to_der()?;
    if signed.issuer != subject.as_slice() {
        return Err(CrlError::IssuerMismatch);
    }

    let oid = signed.signature_algorithm.oid;
    if signed.tbs_signature.oid != oid {
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
    key.verify(alg, signed.tbs, signature)
        .map_err(|e| CrlError::BadSignature(e.to_string()))?;
    Ok(der)
}

fn check_extension(
    extension: &x509_cert::ext::Extension,
    delta: bool,
    indicated: &mut bool,
) -> Result<(), CrlError> {
    check_extension_id(extension.extn_id, extension.critical, delta, indicated)
}

fn check_extension_id(
    id: ObjectIdentifier,
    critical: bool,
    delta: bool,
    indicated: &mut bool,
) -> Result<(), CrlError> {
    if delta && id == oid::DELTA_CRL_INDICATOR {
        *indicated = true;
        return Ok(());
    }
    if REFUSED_CRL_EXTENSIONS.contains(&id) {
        return Err(CrlError::Malformed(format!(
            "unsupported CRL extension {id}"
        )));
    }
    if critical && !KNOWN_CRL_EXTENSIONS.contains(&id) {
        return Err(CrlError::Malformed(format!(
            "unsupported critical CRL extension {id}"
        )));
    }
    Ok(())
}

/// Validate an Extensions sequence without retaining a list or copying extnValue.
fn scan_extensions<'a>(
    bytes: &'a [u8],
    mut visit: impl FnMut(ObjectIdentifier, bool, &'a [u8]) -> der::Result<()>,
) -> der::Result<()> {
    use der::asn1::OctetStringRef;
    let mut reader = SliceReader::new(bytes)?;
    reader.sequence(|extensions| {
        while !extensions.is_finished() {
            extensions.sequence(|extension| {
                let id: ObjectIdentifier = extension.decode()?;
                let critical: Option<bool> = extension.decode()?;
                let value: &OctetStringRef = extension.decode()?;
                visit(id, critical.unwrap_or(false), value.as_bytes())
            })?;
        }
        Ok::<_, der::Error>(())
    })?;
    reader.finish()
}

fn check_times(
    this_update: &x509_cert::time::Time,
    next_update: Option<&x509_cert::time::Time>,
    currency: Currency,
) -> Result<(), CrlError> {
    match currency {
        Currency::Now(now) => {
            if time_of(this_update) > now {
                return Err(CrlError::NotYetValid);
            }
            if next_update.is_some_and(|next| now >= time_of(next)) {
                return Err(CrlError::Outdated);
            }
        }
        Currency::AtProof { proof, now } => {
            // EN 319 102-1 5.2.5.4 with the proof time as validation time. nextUpdate is not
            // compared with the verifier's clock.
            if time_of(this_update) > now {
                return Err(CrlError::NotYetValid);
            }
            // With nextUpdate the maximum freshness is nextUpdate - thisUpdate (5.2.5.4
            // step 1 default), i.e. fresh iff the proof precedes nextUpdate: a 35-day CA CRL
            // issued hours before the proof is fine. Without it the skew is the freshness.
            let stale = match next_update {
                Some(next) => time_of(next) <= proof,
                None => time_of(this_update) <= proof - crate::ocsp::CLOCK_SKEW,
            };
            if stale {
                return Err(CrlError::Outdated);
            }
        }
    }
    Ok(())
}

/// Status of `serial` in a complete CRL of `issuer` at `now`, without decoding the list of
/// revoked certificates into memory. The issuer name and the signature are checked first,
/// exactly as [`verify_crl`] does; then the revoked list is walked once over the borrowed
/// DER, each entry's serial number and date decoded and only the entry of `serial` (the
/// first) kept. Every entry's extensions are structurally validated as borrowed DER,
/// including entries that do not match; none is retained. A CRL over
/// [`MAX_BER_CRL_LEN`] bytes must be DER. The CRL extensions and times are judged
/// as [`verify_crl`] does.
///
/// # Errors
///
/// The errors of [`verify_crl`].
pub fn serial_status(
    crl_der: &[u8],
    issuer: &Certificate,
    serial: &[u8],
    now: OffsetDateTime,
) -> Result<CrlStatus, CrlError> {
    serial_status_at(crl_der, issuer, serial, Currency::Now(now))
}

/// [`serial_status`] for a CRL a signature carries, once the signature's proof time (the
/// control time of ETSI EN 319 102-1) is verified: everything is checked as there except
/// currency. thisUpdate must not be before `proof` less [`crate::ocsp::CLOCK_SKEW`]
/// ([`CrlError::Outdated`]) nor after `now` ([`CrlError::NotYetValid`]); nextUpdate is not
/// compared with `now`.
///
/// # Errors
///
/// The errors of [`serial_status`].
pub fn serial_status_at_proof(
    crl_der: &[u8],
    issuer: &Certificate,
    serial: &[u8],
    proof: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<CrlStatus, CrlError> {
    serial_status_at(crl_der, issuer, serial, Currency::AtProof { proof, now })
}

fn serial_status_at(
    crl_der: &[u8],
    issuer: &Certificate,
    serial: &[u8],
    currency: Currency,
) -> Result<CrlStatus, CrlError> {
    use der::Tagged;
    use x509_cert::certificate::Version;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Time;

    let der = authenticated(crl_der, issuer)?;
    let serial = unsigned(serial);
    let mut reader = SliceReader::new(&der)?;
    let tbs = reader.sequence(|r| {
        let tbs = r.tlv_bytes()?;
        r.read_slice(r.remaining_len())?;
        Ok::<_, der::Error>(tbs)
    })?;
    let mut found = None;
    let mut reader = SliceReader::new(tbs)?;
    let (this_update, next_update, extensions) = reader.sequence(|r| {
        // Required, as in the full decode: a CRL without a version field is refused.
        let _version: Version = r.decode()?;
        let _signature: AlgorithmIdentifierRef<'_> = r.decode()?;
        let _issuer = r.tlv_bytes()?;
        let this_update: Time = r.decode()?;
        let next_update: Option<Time> = r.decode()?;
        if der::Tag::peek(r).is_ok_and(|tag| tag == der::Tag::Sequence) {
            r.sequence(|entries| {
                while !entries.is_finished() {
                    entries.sequence(|entry| {
                        let number: SerialNumber = entry.decode()?;
                        let date: Time = entry.decode()?;
                        let rest = entry.read_slice(entry.remaining_len())?;
                        let mut reason = None;
                        let mut seen_reason = false;
                        if !rest.is_empty() {
                            scan_extensions(rest, |id, _, value| {
                                // The first CrlReason decides, malformed or not.
                                if !seen_reason && id == CrlReason::OID {
                                    seen_reason = true;
                                    reason = Enumerated::from_der(value).ok().map(|v| v.0);
                                }
                                Ok(())
                            })?;
                        }
                        if found.is_none() && unsigned(number.as_bytes()) == serial {
                            found = Some(CrlStatus::Revoked {
                                time: time_of(&date),
                                reason,
                            });
                        }
                        Ok::<_, der::Error>(())
                    })?;
                }
                Ok::<_, der::Error>(())
            })?;
        }
        let extensions = if r.is_finished() {
            None
        } else {
            Some(r.tlv_bytes()?)
        };
        Ok::<_, der::Error>((this_update, next_update, extensions))
    })?;
    reader.finish()?;
    if let Some(extensions) = extensions {
        let mut reader = SliceReader::new(extensions)?;
        let outer: der::asn1::ContextSpecific<der::asn1::AnyRef<'_>> = reader.decode()?;
        reader.finish()?;
        if outer.tag_number != der::TagNumber(0) || outer.value.tag() != der::Tag::Sequence {
            return Err(CrlError::Malformed("CRL extensions tag".to_owned()));
        }
        let mut error = None;
        let wrapped = der::asn1::AnyRef::from_der(extensions)?;
        scan_extensions(wrapped.value(), |id, critical, _| {
            if error.is_none() {
                error = check_extension_id(id, critical, false, &mut false).err();
            }
            Ok(())
        })?;
        if let Some(error) = error {
            return Err(error);
        }
    }
    check_times(&this_update, next_update.as_ref(), currency)?;
    Ok(found.unwrap_or(CrlStatus::Good))
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

/// The CRLs of `cert`'s distribution points as received, without the cache: the first
/// complete CRL of `issuer` its CRLDistributionPoints give, then the first delta CRL its
/// FreshestCRL gives (if it has one), each downloaded within `timeout`; and `cert`'s
/// status in them at `now`. An entry of the delta CRL decides over the complete CRL; one
/// with the reason removeFromCRL (8) means good.
///
/// # Errors
///
/// [`CrlError::NoUrl`] without a distribution point URL, [`CrlError::IssuerMismatch`] if
/// `issuer` did not issue `cert`; the error of the last URL tried when none gives a valid
/// CRL (a delta CRL is never used without its complete CRL).
pub fn fetch_for(
    cert: &Certificate,
    issuer: &Certificate,
    http: &dyn HttpTransport,
    timeout: Duration,
    now: OffsetDateTime,
) -> Result<(Vec<Vec<u8>>, CrlStatus), CrlError> {
    fetch_for_impl(cert, issuer, http, timeout, now, true)
}

/// Status-only scoped consumer: response and decode storage never escape as
/// uncharged owning vectors. Legacy fetch_for still returns its original docs.
pub(crate) fn fetch_status_for(
    cert: &Certificate,
    issuer: &Certificate,
    http: &dyn HttpTransport,
    timeout: Duration,
    now: OffsetDateTime,
) -> Result<CrlStatus, CrlError> {
    fetch_for_impl(cert, issuer, http, timeout, now, false).map(|(_, status)| status)
}

struct DownloadedCrl<'a> {
    decoded: CertificateList,
    legacy: Option<Vec<u8>>,
    _response: Option<crate::http::ScopedHttpReply<'a>>,
    _decode: Option<crate::http::DecodeGuard<'a>>,
}
fn fetch_for_impl(
    cert: &Certificate,
    issuer: &Certificate,
    http: &dyn HttpTransport,
    timeout: Duration,
    now: OffsetDateTime,
    retain_documents: bool,
) -> Result<(Vec<Vec<u8>>, CrlStatus), CrlError> {
    let urls = crl_urls(cert);
    if urls.is_empty() {
        return Err(CrlError::NoUrl);
    }
    let tbs = cert.tbs_certificate();
    if tbs.issuer() != issuer.tbs_certificate().subject() {
        return Err(CrlError::IssuerMismatch);
    }
    let opts = GetOptions {
        timeout,
        connect_timeout: CONNECT_TIMEOUT,
        max_len: MAX_CRL_LEN,
        https_only: false,
        redirects: true,
    };
    let download = |url: &str, delta: bool| -> Result<DownloadedCrl<'_>, CrlError> {
        if retain_documents {
            let reply = http.get_with(url, opts).map_err(CrlError::Http)?;
            if reply.status != 200 {
                return Err(CrlError::HttpStatus(reply.status));
            }
            let decoded = verify_any_crl(&reply.body, issuer, now, delta)?;
            Ok(DownloadedCrl {
                decoded,
                legacy: Some(reply.body),
                _response: None,
                _decode: None,
            })
        } else {
            let reply = http
                .send_scoped(&crate::http::HttpRequest::get(url, opts))
                .map_err(CrlError::Http)?;
            if reply.status() != 200 {
                return Err(CrlError::HttpStatus(reply.status()));
            }
            let decode = reply.reserve_decode().map_err(CrlError::Http)?;
            let decoded = verify_any_crl(reply.body(), issuer, now, delta)?;
            Ok(DownloadedCrl {
                decoded,
                legacy: None,
                _response: Some(reply),
                _decode: decode,
            })
        }
    };
    let first = |urls: &[String], delta: bool| {
        let mut last = CrlError::NoUrl;
        for url in urls {
            match download(url, delta) {
                Ok(found) => return Ok(found),
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    let serial = tbs.serial_number().as_bytes();
    let mut base = first(&urls, false)?;
    let mut status = lookup(&base.decoded, serial);
    let mut crls = Vec::new();
    if let Some(document) = base.legacy.take() {
        crls.push(document);
    }
    drop(base);
    let deltas = freshest_urls(cert);
    if !deltas.is_empty() {
        let mut delta = first(&deltas, true)?;
        match lookup(&delta.decoded, serial) {
            CrlStatus::Revoked {
                reason: Some(REMOVE_FROM_CRL),
                ..
            } => status = CrlStatus::Good,
            revoked @ CrlStatus::Revoked { .. } => status = revoked,
            CrlStatus::Good => {}
        }
        if let Some(document) = delta.legacy.take() {
            crls.push(document);
        }
    }
    Ok((crls, status))
}

/// CRLReason removeFromCRL: a delta CRL's entry taking a certificate off the list.
const REMOVE_FROM_CRL: u8 = 8;

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
