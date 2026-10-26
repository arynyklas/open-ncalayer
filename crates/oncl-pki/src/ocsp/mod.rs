//! OCSP (RFC 6960) of a key's certificate, as NCALayer checks it (`KNCAOCSPChecker` of
//! kalkancrypt).
//!
//! - The responder is the id-ad-ocsp URI of the certificate's AuthorityInfoAccess.
//! - The request is one `CertID`: SHA-1 (with NULL parameters) of the issuer's DER subject
//!   and of the contents of its public key BIT STRING, and the certificate's serial number.
//!   It has no nonce and no signature.
//! - It goes by the NCA GET binding ([`get_url`]) within [`TIMEOUT`]; the reply must be
//!   HTTP 200 with `Content-Type: application/ocsp-response`.
//! - The response comes over plain HTTP, so it is hostile input, checked in this order:
//!   status successful; certificates present; the responder certificate found by the
//!   ResponderID (byName, or byKey, which the original does not support); the responder
//!   chains through the CA set and has the OCSPSigning extended key usage and
//!   id-pkix-ocsp-nocheck; the signature verifies with its key; the first `SingleResponse`
//!   is current and answers the requested `CertID`.
//! - Current means `thisUpdate ≤ now + CLOCK_SKEW` and then `now < nextUpdate`, or, without
//!   nextUpdate, `now < thisUpdate + ALLOWED_PERIOD`. The NCA responders stamp thisUpdate
//!   with their own clock at the moment they answer and send no nextUpdate, so a strict
//!   `thisUpdate < now` would fail for any client a second behind them (or whose request
//!   crosses a second boundary); [`CLOCK_SKEW`] absorbs that.
//! - Every failure is an [`OcspError`], never a [`CertStatus`]: callers decide what an
//!   unchecked certificate means.

mod asn1;
#[cfg(feature = "testing")]
mod mock;

#[cfg(feature = "testing")]
pub use mock::{MockOcsp, OcspTamper};

/// URL of the NCA GET binding: [`crate::http::nca_get_url`], which OCSP shares with
/// time-stamping.
pub use crate::http::nca_get_url as get_url;

use crate::asn1util::{TimeError, generalized_time};
use crate::ber::{self, BerError};
use crate::cert::Certificate;
use crate::http::{GetOptions, HttpTransport, MAX_RESPONSE_LEN};
use crate::key::{PublicKey, SigAlg};
use crate::oid;
use crate::pkix::{CaSet, PathError, build_path};
use der::asn1::{AnyRef, IntRef, OctetStringRef};
use der::{Decode, Encode, Tag, TagNumber};
use sha1::{Digest, Sha1};
use spki::AlgorithmIdentifierRef;
use std::time::Duration;
use time::OffsetDateTime;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, ExtendedKeyUsage};
use x509_cert::name::Name;

/// Timeout of an OCSP request, as in the original.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// How long a response without nextUpdate stays current after its thisUpdate.
pub const ALLOWED_PERIOD: Duration = Duration::from_secs(300);

/// How far a response's thisUpdate may be ahead of `now`: the responder's clock may run
/// ahead of ours, and it stamps the moment it answers.
pub const CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Media type of an `OCSPResponse` (RFC 6960 appendix C.2).
const OCSP_RESPONSE: &str = "application/ocsp-response";

/// Revocation status of a certificate, as its responder reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertStatus {
    /// Not revoked.
    Good,
    /// Revoked at `time`, for the CRLReason `reason` if the responder gives one.
    Revoked {
        /// Revocation time.
        time: OffsetDateTime,
        /// CRLReason (RFC 5280 §5.3.1).
        reason: Option<u8>,
    },
    /// The responder does not know the certificate.
    Unknown,
}

/// Why a certificate's status is not known.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OcspError {
    /// The certificate has no id-ad-ocsp URI in AuthorityInfoAccess.
    #[error("certificate has no OCSP responder URL")]
    NoUrl,
    /// No HTTP response from the responder: connection, timeout or size limit.
    #[error("HTTP request to the OCSP responder failed: {0}")]
    Http(String),
    /// The responder answered with an HTTP status other than 200.
    #[error("OCSP responder answered HTTP status {0}")]
    HttpStatus(u16),
    /// The responder answered with a content type other than `application/ocsp-response`.
    #[error("OCSP responder answered with content type {0:?}")]
    ContentType(Option<String>),
    /// The response is not a valid `OCSPResponse` with a `BasicOCSPResponse`: what is wrong.
    #[error("malformed OCSP response: {0}")]
    Malformed(String),
    /// The `OCSPResponseStatus` is not successful (0).
    #[error("OCSP response status {0}")]
    NotSuccessful(u8),
    /// The response carries no certificates.
    #[error("OCSP response carries no certificates")]
    NoCerts,
    /// No certificate of the response matches its ResponderID.
    #[error("OCSP responder certificate not found")]
    ResponderNotFound,
    /// The responder certificate does not chain through the CA set at `now`.
    #[error("OCSP responder certificate is not trusted: {0}")]
    ResponderNotTrusted(PathError),
    /// The responder certificate lacks the OCSPSigning extended key usage.
    #[error("OCSP responder certificate lacks the OCSPSigning extended key usage")]
    OcspSigningMissing,
    /// The responder certificate lacks id-pkix-ocsp-nocheck.
    #[error("OCSP responder certificate lacks id-pkix-ocsp-nocheck")]
    NoCheckMissing,
    /// The response signature does not verify with the responder key: why.
    #[error("OCSP response signature does not verify: {0}")]
    BadSignature(String),
    /// The response has no `SingleResponse`.
    #[error("OCSP response has no single response")]
    NoSingleResponse,
    /// thisUpdate is later than now + [`CLOCK_SKEW`].
    #[error(
        "OCSP response thisUpdate is more than {} s in the future",
        CLOCK_SKEW.as_secs()
    )]
    ThisUpdate,
    /// now is not before nextUpdate (or, without nextUpdate, thisUpdate + ALLOWED_PERIOD).
    #[error("OCSP response is outdated")]
    NextUpdate,
    /// The `SingleResponse` is about another `CertID` than the requested one.
    #[error("OCSP response is about another certificate")]
    CertIdMismatch,
}

impl From<der::Error> for OcspError {
    fn from(e: der::Error) -> Self {
        OcspError::Malformed(e.to_string())
    }
}

impl From<BerError> for OcspError {
    fn from(e: BerError) -> Self {
        OcspError::Malformed(e.to_string())
    }
}

impl From<TimeError> for OcspError {
    fn from(e: TimeError) -> Self {
        OcspError::Malformed(e.to_string())
    }
}

/// The first id-ad-ocsp URI of `cert`'s AuthorityInfoAccess; `None` without one (or with a
/// malformed extension).
pub fn ocsp_url(cert: &Certificate) -> Option<String> {
    let Ok(Some((_, aia))) = cert
        .tbs_certificate()
        .get_extension::<AuthorityInfoAccessSyntax>()
    else {
        return None;
    };
    aia.0
        .iter()
        .find_map(|access| match &access.access_location {
            GeneralName::UniformResourceIdentifier(uri) if access.access_method == oid::AD_OCSP => {
                Some(uri.to_string())
            }
            _ => None,
        })
}

/// DER `OCSPRequest` for `cert` issued by `issuer`: one `CertID` with SHA-1 hashes, no
/// nonce, no signature.
///
/// # Panics
///
/// If the issuer's subject does not re-encode (it was decoded, so it does).
pub fn request_der(cert: &Certificate, issuer: &Certificate) -> Vec<u8> {
    RequestedId::new(cert, issuer).request_der()
}

/// Asks the OCSP responder of `cert` (issued by `issuer`) for its status at `now`, through
/// `http` within `timeout` (normally [`TIMEOUT`]). The responder certificate must chain
/// through `cas` at `now`.
///
/// # Errors
///
/// [`OcspError::NoUrl`] without a responder URL; the other [`OcspError`]s when the request
/// fails or the response is not a valid, trusted and current answer about `cert`.
pub fn check(
    cert: &Certificate,
    issuer: &Certificate,
    cas: &CaSet,
    http: &dyn HttpTransport,
    now: OffsetDateTime,
    timeout: Duration,
) -> Result<CertStatus, OcspError> {
    let url = ocsp_url(cert).ok_or(OcspError::NoUrl)?;
    let requested = RequestedId::new(cert, issuer);
    let opts = GetOptions {
        timeout,
        max_len: MAX_RESPONSE_LEN,
    };
    let reply = http
        .get_with(&get_url(&url, &requested.request_der()), opts)
        .map_err(|e| OcspError::Http(e.0))?;
    if reply.status != 200 {
        return Err(OcspError::HttpStatus(reply.status));
    }
    if !is_ocsp_response(reply.content_type.as_deref()) {
        return Err(OcspError::ContentType(reply.content_type));
    }
    read_response(&reply.body, &requested, cas, now)
}

/// The `CertID` of a request.
struct RequestedId<'a> {
    name_hash: [u8; 20],
    key_hash: [u8; 20],
    serial: IntRef<'a>,
}

impl<'a> RequestedId<'a> {
    fn new(cert: &'a Certificate, issuer: &Certificate) -> Self {
        let subject = issuer
            .tbs_certificate()
            .subject()
            .to_der()
            .expect("decoded Name re-encodes");
        RequestedId {
            name_hash: Sha1::digest(subject).into(),
            key_hash: key_hash(issuer),
            serial: IntRef::new(cert.tbs_certificate().serial_number().as_bytes())
                .expect("decoded serial number fits DER"),
        }
    }

    fn cert_id(&self) -> asn1::CertId<'_> {
        asn1::CertId {
            hash_algorithm: AlgorithmIdentifierRef {
                oid: oid::SHA1,
                parameters: Some(AnyRef::NULL),
            },
            issuer_name_hash: OctetStringRef::new(&self.name_hash).expect("20 bytes fit DER"),
            issuer_key_hash: OctetStringRef::new(&self.key_hash).expect("20 bytes fit DER"),
            serial_number: self.serial,
        }
    }

    fn request_der(&self) -> Vec<u8> {
        asn1::OcspRequest {
            tbs_request: asn1::TbsRequest {
                version: None,
                requestor_name: None,
                request_list: vec![asn1::Request {
                    req_cert: self.cert_id(),
                    single_request_extensions: None,
                }],
                request_extensions: None,
            },
            optional_signature: None,
        }
        .to_der()
        .expect("OCSPRequest fits DER")
    }

    /// Whether `id` is this `CertID`; the hash parameters (NULL or absent) are not compared.
    fn matches(&self, id: &asn1::CertId<'_>) -> bool {
        id.hash_algorithm.oid == oid::SHA1
            && id.issuer_name_hash.as_bytes() == self.name_hash
            && id.issuer_key_hash.as_bytes() == self.key_hash
            && id.serial_number == self.serial
    }
}

/// SHA-1 of the contents of `cert`'s public key BIT STRING: `KeyHash` of a `CertID` and of
/// a byKey ResponderID.
fn key_hash(cert: &Certificate) -> [u8; 20] {
    let key = &cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key;
    Sha1::digest(key.raw_bytes()).into()
}

/// Whether a `Content-Type` is `application/ocsp-response`, ignoring case and parameters.
fn is_ocsp_response(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case(OCSP_RESPONSE))
}

/// Checks a DER or BER `OCSPResponse` (see the module documentation for the order).
fn read_response(
    body: &[u8],
    requested: &RequestedId<'_>,
    cas: &CaSet,
    now: OffsetDateTime,
) -> Result<CertStatus, OcspError> {
    let der = ber::to_der(body)?;
    let response = asn1::OcspResponse::from_der(&der)?;
    if response.response_status.0 != 0 {
        return Err(OcspError::NotSuccessful(response.response_status.0));
    }
    let bytes = response
        .response_bytes
        .ok_or_else(|| OcspError::Malformed("successful response without responseBytes".into()))?;
    if bytes.response_type != oid::OCSP_BASIC {
        return Err(OcspError::Malformed(format!(
            "response type {} is not id-pkix-ocsp-basic",
            bytes.response_type
        )));
    }
    let basic_der = ber::to_der(bytes.response.as_bytes())?;
    let basic = asn1::BasicOcspResponse::from_der(&basic_der)?;
    let data: asn1::ResponseData<'_> = basic.tbs_response_data.decode_as()?;
    let responder_id = ResponderId::read(data.responder_id)?;

    let certs = basic.certs.as_deref().unwrap_or_default();
    if certs.is_empty() {
        return Err(OcspError::NoCerts);
    }
    let responder = certs
        .iter()
        .find(|c| responder_id.identifies(c))
        .ok_or(OcspError::ResponderNotFound)?;
    check_responder(responder, cas, now)?;

    let oid = basic.signature_algorithm.oid;
    let alg = SigAlg::from_signature_oid(&oid)
        .ok_or_else(|| OcspError::BadSignature(format!("unsupported signature algorithm {oid}")))?;
    let key = PublicKey::from_spki(responder.tbs_certificate().subject_public_key_info())
        .map_err(|e| OcspError::BadSignature(format!("responder key: {e}")))?;
    let signature = basic
        .signature
        .as_bytes()
        .ok_or_else(|| OcspError::Malformed("signature BIT STRING has unused bits".into()))?;
    key.verify(alg, &basic.tbs_response_data.to_der()?, signature)
        .map_err(|e| OcspError::BadSignature(e.to_string()))?;

    let single = data.responses.first().ok_or(OcspError::NoSingleResponse)?;
    let this_update = generalized_time(single.this_update.0)?;
    if this_update > now + CLOCK_SKEW {
        return Err(OcspError::ThisUpdate);
    }
    let current = match single.next_update {
        Some(next_update) => now < generalized_time(next_update.0)?,
        // A thisUpdate ahead of now (within the skew) is a negative age: current.
        None => now - this_update < ALLOWED_PERIOD,
    };
    if !current {
        return Err(OcspError::NextUpdate);
    }
    if !requested.matches(&single.cert_id) {
        return Err(OcspError::CertIdMismatch);
    }
    cert_status(single.cert_status)
}

/// `ResponderID`.
enum ResponderId<'a> {
    /// `[1] EXPLICIT Name`.
    ByName(Name),
    /// `[2] EXPLICIT KeyHash`: SHA-1 of the responder's public key BIT STRING contents.
    ByKey(&'a [u8]),
}

impl<'a> ResponderId<'a> {
    fn read(any: AnyRef<'a>) -> Result<Self, OcspError> {
        match any.header().tag() {
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(1),
            } => Ok(ResponderId::ByName(Name::from_der(any.value())?)),
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(2),
            } => Ok(ResponderId::ByKey(
                <&OctetStringRef>::from_der(any.value())?.as_bytes(),
            )),
            tag => Err(OcspError::Malformed(format!("ResponderID tag {tag}"))),
        }
    }

    fn identifies(&self, cert: &Certificate) -> bool {
        match self {
            ResponderId::ByName(name) => cert.tbs_certificate().subject() == name,
            ResponderId::ByKey(hash) => key_hash(cert) == *hash,
        }
    }
}

/// The responder must chain through `cas` at `now` and be an OCSP responder whose own
/// status is not checked.
fn check_responder(
    responder: &Certificate,
    cas: &CaSet,
    now: OffsetDateTime,
) -> Result<(), OcspError> {
    build_path(responder, cas, now).map_err(OcspError::ResponderNotTrusted)?;
    let tbs = responder.tbs_certificate();
    let ocsp_signing = matches!(
        tbs.get_extension::<ExtendedKeyUsage>(),
        Ok(Some((_, eku))) if eku.0.contains(&oid::OCSP_SIGNING)
    );
    if !ocsp_signing {
        return Err(OcspError::OcspSigningMissing);
    }
    let no_check = tbs
        .extensions()
        .into_iter()
        .flatten()
        .any(|e| e.extn_id == oid::OCSP_NOCHECK);
    if !no_check {
        return Err(OcspError::NoCheckMissing);
    }
    Ok(())
}

/// `CertStatus`: `[0] IMPLICIT NULL`, `[1] IMPLICIT RevokedInfo` or `[2] IMPLICIT NULL`.
fn cert_status(any: AnyRef<'_>) -> Result<CertStatus, OcspError> {
    let empty = any.value().is_empty();
    match any.header().tag() {
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        } if empty => Ok(CertStatus::Good),
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(1),
        } => {
            let info: asn1::RevokedInfo<'_> =
                AnyRef::new(Tag::Sequence, any.value())?.decode_as()?;
            Ok(CertStatus::Revoked {
                time: generalized_time(info.revocation_time.0)?,
                reason: info.revocation_reason.map(|r| r.0),
            })
        }
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(2),
        } if empty => Ok(CertStatus::Unknown),
        tag => Err(OcspError::Malformed(format!("CertStatus tag {tag}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocsp_response_media_type() {
        assert!(is_ocsp_response(Some("application/ocsp-response")));
        assert!(is_ocsp_response(Some(" Application/OCSP-Response ; q=1")));
        assert!(!is_ocsp_response(Some("application/ocsp-request")));
        assert!(!is_ocsp_response(Some("")));
        assert!(!is_ocsp_response(None));
    }

    #[test]
    fn error_messages_keep_their_cause() {
        assert_eq!(
            OcspError::ResponderNotTrusted(PathError::IssuerNotFound).to_string(),
            "OCSP responder certificate is not trusted: issuer certificate not found"
        );
        assert_eq!(
            OcspError::ThisUpdate.to_string(),
            "OCSP response thisUpdate is more than 300 s in the future"
        );
        assert_eq!(
            OcspError::from(TimeError("x".to_owned())).to_string(),
            "malformed OCSP response: invalid GeneralizedTime \"x\""
        );
    }
}
