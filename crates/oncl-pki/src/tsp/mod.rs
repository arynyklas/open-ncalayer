//! RFC 3161 time-stamping of CMS signers, as NCALayer does it with the NCA TSA.
//!
//! - The request is `TimeStampReq { v1, messageImprint { hash with NULL parameters,
//!   H(SignerInfo.signature) }, reqPolicy, nonce, certReq TRUE }`; the nonce is 8 random
//!   bytes, an unsigned INTEGER.
//! - The NCA TSA takes it by GET: `url/` and the percent-encoded base64 of the DER request
//!   ([`TsaMethod::Get`]); RFC 3161 POST is supported too ([`TsaMethod::Post`]).
//! - The reply comes over plain HTTP, so it is hostile input: it must be HTTP 200 with
//!   `Content-Type: application/timestamp-reply`, status granted (0) or grantedWithMods (1),
//!   carry a token signed by a certificate with the timeStamping extended key usage, and
//!   echo the request's nonce, policy and message imprint. As in the original, the TSA
//!   certificate chain is not checked.
//! - The token goes into the signer's unsigned attributes as id-aa-timeStampToken.

mod asn1;
#[cfg(feature = "testing")]
mod mock;

#[cfg(feature = "testing")]
pub use mock::{MockTamper, MockTsa};

use crate::asn1util::{generalized_time, unsigned};
use crate::ber::{self, BerError};
use crate::cms::asn1::{
    Attribute, ContentInfo, RawSet, SignedContentInfo, SignedData, SignerInfo, der_set_contents,
};
use crate::cms::{self, CmsError};
use crate::http::{HttpError, HttpTransport, nca_get_url};
use crate::info::cert_info;
use crate::key::SigAlg;
use crate::oid;
use der::asn1::{AnyRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierRef;
use time::OffsetDateTime;

/// Policy `kz.gov.pki.knca.basics` asks the NCA TSA for.
const BASICS_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.3.2.6.4");

/// Media type of a POSTed `TimeStampReq` (RFC 3161 §3.4).
const TIMESTAMP_QUERY: &str = "application/timestamp-query";
/// Media type of a `TimeStampResp` (RFC 3161 §3.4).
const TIMESTAMP_REPLY: &str = "application/timestamp-reply";

/// How a request reaches the TSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsaMethod {
    /// `GET url/<percent-encoded base64 of the DER request>`, the NCA TSA binding.
    Get,
    /// `POST url` with `Content-Type: application/timestamp-query` (RFC 3161 §3.4).
    Post,
}

/// Hash of the message imprint we request. SHA-1 is deliberately absent: it is only
/// accepted when verifying tokens others requested (see [`verify_token_for`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TspHash {
    /// GOST 34.11-2015, 512 bits.
    Streebog512,
    /// SHA-256.
    Sha256,
    /// GOST 34.311-95.
    Gost34311,
}

impl TspHash {
    /// Algorithm OID.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            TspHash::Streebog512 => oid::STREEBOG_512,
            TspHash::Sha256 => oid::SHA256,
            TspHash::Gost34311 => oid::GOST_34311,
        }
    }

    /// The hash with algorithm OID `oid`.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<TspHash> {
        [TspHash::Streebog512, TspHash::Sha256, TspHash::Gost34311]
            .into_iter()
            .find(|h| h.oid() == *oid)
    }

    /// Hash of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let alg = match self {
            TspHash::Streebog512 => SigAlg::Gost2015_512,
            TspHash::Sha256 => SigAlg::RsaSha256,
            TspHash::Gost34311 => SigAlg::Gost2004,
        };
        alg.digest(data)
    }
}

/// Where and how to time-stamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsaProfile {
    /// TSA URL; with [`TsaMethod::Get`] the encoded request is appended after a `/`.
    pub url: String,
    /// HTTP binding.
    pub method: TsaMethod,
    /// Message imprint hash.
    pub hash: TspHash,
    /// Requested (and required) TSA policy.
    pub policy: ObjectIdentifier,
}

impl TsaProfile {
    /// The profile of `kz.gov.pki.knca.basics`: `GET http://tsp.pki.gov.kz`, GOST
    /// 34.11-2015 (512) imprint, policy 1.2.398.3.3.2.6.4.
    pub fn basics_default() -> Self {
        TsaProfile {
            url: "http://tsp.pki.gov.kz".to_owned(),
            method: TsaMethod::Get,
            hash: TspHash::Streebog512,
            policy: BASICS_POLICY,
        }
    }
}

/// Fields of a `TSTInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TstInfo {
    /// TSA policy.
    pub policy: ObjectIdentifier,
    /// Message imprint hash algorithm.
    pub imprint_alg: ObjectIdentifier,
    /// Message imprint.
    pub imprint: Vec<u8>,
    /// Nonce: unsigned big-endian bytes without leading zeros.
    pub nonce: Option<Vec<u8>>,
    /// Time of the stamp.
    pub gen_time: OffsetDateTime,
}

/// Error of time-stamping.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TspError {
    /// No HTTP response from the TSA.
    #[error("HTTP request to the TSA failed: {0}")]
    Http(#[from] HttpError),
    /// The TSA answered with an HTTP status other than 200.
    #[error("TSA answered HTTP status {0}")]
    Status(u16),
    /// The TSA answered with a content type other than `application/timestamp-reply`.
    #[error("TSA answered with content type {0:?}")]
    ContentType(Option<String>),
    /// The TSA refused the request: the PKIStatus.
    #[error("TSA rejected the request with status {0}")]
    Rejected(i64),
    /// The token's nonce differs from the request's.
    #[error("time-stamp nonce does not match the request")]
    NonceMismatch,
    /// The token's message imprint (algorithm or value) differs from the request's.
    #[error("time-stamp message imprint does not match the request")]
    ImprintMismatch,
    /// The token's message imprint uses a hash this implementation cannot compute.
    #[error("time-stamp message imprint algorithm {0} is not supported")]
    UnsupportedImprintAlgorithm(ObjectIdentifier),
    /// The token's policy differs from the requested one.
    #[error("time-stamp policy does not match the request")]
    PolicyMismatch,
    /// The token is not signed with a certificate it carries that has the timeStamping
    /// extended key usage.
    #[error("time-stamp token has no TSA certificate with the timeStamping key usage")]
    NoTsaCertificate,
    /// The token does not verify as a CMS, or the CMS to time-stamp is invalid.
    #[error("CMS: {0}")]
    Cms(#[from] CmsError),
    /// The TSA's response is not a valid `TimeStampResp`.
    #[error("malformed time-stamp response: {0}")]
    Malformed(String),
}

impl From<der::Error> for TspError {
    fn from(e: der::Error) -> Self {
        TspError::Malformed(e.to_string())
    }
}

impl From<BerError> for TspError {
    fn from(e: BerError) -> Self {
        TspError::Malformed(e.to_string())
    }
}

/// DER `TimeStampReq` for `imprint` (already hashed with `profile.hash`) and `nonce`, an
/// unsigned big-endian number (an empty slice is zero).
///
/// # Panics
///
/// If `imprint` or `nonce` is longer than DER allows (256 MiB).
pub fn request_der(profile: &TsaProfile, imprint: &[u8], nonce: &[u8]) -> Vec<u8> {
    let nonce = if nonce.is_empty() { &[0][..] } else { nonce };
    asn1::TimeStampReq {
        version: 1,
        message_imprint: asn1::MessageImprint {
            hash_algorithm: AlgorithmIdentifierRef {
                oid: profile.hash.oid(),
                parameters: Some(AnyRef::NULL),
            },
            hashed_message: OctetStringRef::new(imprint).expect("imprint fits DER"),
        },
        req_policy: Some(profile.policy),
        nonce: Some(UintRef::new(nonce).expect("nonce fits DER")),
        cert_req: Some(true),
        extensions: None,
    }
    .to_der()
    .expect("TimeStampReq fits DER")
}

/// Reads a DER or BER `TimeStampResp`: the status must be granted or grantedWithMods, and
/// the token must pass [`verify_token`]. Returns the token (a DER `ContentInfo`) and its
/// `TSTInfo`; matching them against the request is up to the caller.
///
/// # Errors
///
/// [`TspError::Rejected`] for another status; [`TspError::Malformed`] for a response that
/// cannot be read or has no token; errors of [`verify_token`].
pub fn parse_response(resp: &[u8]) -> Result<(Vec<u8>, TstInfo), TspError> {
    let der = ber::to_der(resp)?;
    let resp = asn1::TimeStampResp::from_der(&der)?;
    let status = resp.status.status;
    if !matches!(status, 0 | 1) {
        return Err(TspError::Rejected(status));
    }
    let token = resp
        .time_stamp_token
        .ok_or_else(|| TspError::Malformed("granted response without a token".to_owned()))?
        .to_der()?;
    let tst = verify_token(&token)?;
    Ok((token, tst))
}

/// Verifies a time-stamp token (a DER or BER `ContentInfo{SignedData}` of a `TSTInfo`): a
/// single signer whose signature verifies over the encapsulated `TSTInfo` and whose
/// certificate, carried in the token, has the timeStamping extended key usage. The TSA
/// certificate chain is not checked.
///
/// The structure (one signer, TSTInfo content) is checked before any signature, so a
/// hostile token with many signers costs no signature verification.
///
/// # Errors
///
/// [`TspError::NoTsaCertificate`] if the signer certificate is missing or lacks the key
/// usage; [`TspError::Cms`] if the signature does not verify; [`TspError::Malformed`] for
/// another number of signers, another content type or an invalid `TSTInfo`.
pub fn verify_token(token: &[u8]) -> Result<TstInfo, TspError> {
    let der = ber::to_der(token)?;
    let content_info = ContentInfo::from_der(&der)?;
    if content_info.content_type != oid::SIGNED_DATA {
        return Err(TspError::Malformed(format!(
            "time-stamp token content type is {}",
            content_info.content_type
        )));
    }
    let signed_data: SignedData<'_> = content_info.content.decode_as()?;
    let signer_count = signed_data.signer_infos.tlvs()?.len();
    if signer_count != 1 {
        return Err(TspError::Malformed(format!(
            "time-stamp token has {signer_count} signers"
        )));
    }
    let encap = signed_data.encap_content_info;
    if encap.e_content_type != oid::TST_INFO {
        return Err(TspError::Malformed(format!(
            "time-stamp token content type is {}",
            encap.e_content_type
        )));
    }
    let content = encap
        .e_content
        .ok_or(TspError::Cms(CmsError::NoEncapsulatedData))?;

    let signers = cms::verify(&der, None).map_err(|e| match e {
        CmsError::CertNotFound(_) => TspError::NoTsaCertificate,
        e => TspError::Cms(e),
    })?;
    let time_stamping = oid::TIME_STAMPING.to_string();
    if !signers
        .iter()
        .all(|s| cert_info(&s.cert).ext_key_usages.contains(&time_stamping))
    {
        return Err(TspError::NoTsaCertificate);
    }
    tst_info(content.as_bytes())
}

/// [`verify_token`] for the token of a CMS signer whose `SignerInfo.signature` value is
/// `signature`: the token's message imprint must also be the hash of `signature` (with the
/// token's own imprint algorithm), as [`timestamp_signer`] requests it.
///
/// Besides the [`TspHash`] algorithms, a SHA-1 imprint is accepted here: the NCA TSA stamps
/// SHA-1 imprints for clients that ask for them, and CAdES-T made by such clients must
/// verify. Requests never use SHA-1.
///
/// # Errors
///
/// Errors of [`verify_token`]; [`TspError::UnsupportedImprintAlgorithm`] if the imprint
/// algorithm is none of those; [`TspError::ImprintMismatch`] if the imprint is not the hash
/// of `signature`.
pub fn verify_token_for(token: &[u8], signature: &[u8]) -> Result<TstInfo, TspError> {
    let tst = verify_token(token)?;
    let expected = match TspHash::from_oid(&tst.imprint_alg) {
        Some(hash) => hash.digest(signature),
        None if tst.imprint_alg == oid::SHA1 => {
            use sha1::Digest as _;
            sha1::Sha1::digest(signature).to_vec()
        }
        None => return Err(TspError::UnsupportedImprintAlgorithm(tst.imprint_alg)),
    };
    if tst.imprint != expected {
        return Err(TspError::ImprintMismatch);
    }
    Ok(tst)
}

/// Time-stamps signer `signer_index` of a DER or BER `ContentInfo{SignedData}`: requests a
/// token for its signature from the TSA of `profile` and returns the CMS (DER) with the
/// token as that signer's id-aa-timeStampToken unsigned attribute, replacing an earlier
/// one. Other signers are kept byte for byte.
///
/// # Errors
///
/// [`TspError::Cms`] for an invalid CMS; [`TspError::Malformed`] if there is no such
/// signer; the transport's errors; [`TspError::Status`] or [`TspError::ContentType`] for an
/// unexpected HTTP reply; errors of [`parse_response`]; [`TspError::NonceMismatch`],
/// [`TspError::ImprintMismatch`] or [`TspError::PolicyMismatch`] if the token is not an
/// answer to this request.
pub fn timestamp_signer(
    cms: &[u8],
    signer_index: usize,
    profile: &TsaProfile,
    http: &dyn HttpTransport,
) -> Result<Vec<u8>, TspError> {
    let der = ber::to_der(cms).map_err(CmsError::from)?;
    let content_info = ContentInfo::from_der(&der).map_err(CmsError::from)?;
    if content_info.content_type != oid::SIGNED_DATA {
        return Err(CmsError::Malformed(format!(
            "content type {} is not signedData",
            content_info.content_type
        ))
        .into());
    }
    let signed_data: SignedData<'_> = content_info.content.decode_as().map_err(CmsError::from)?;
    let mut signers = signed_data.signer_infos.tlvs().map_err(CmsError::from)?;
    let target = *signers.get(signer_index).ok_or_else(|| {
        TspError::Malformed(format!(
            "no signer {signer_index} among {} signers",
            signers.len()
        ))
    })?;
    let info = SignerInfo::from_der(target).map_err(CmsError::from)?;

    let imprint = profile.hash.digest(info.signature.as_bytes());
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).expect("operating system RNG failed");
    let request = request_der(profile, &imprint, &nonce);
    let reply = match profile.method {
        TsaMethod::Get => http.get(&nca_get_url(&profile.url, &request))?,
        TsaMethod::Post => http.post(&profile.url, TIMESTAMP_QUERY, &request)?,
    };
    if reply.status != 200 {
        return Err(TspError::Status(reply.status));
    }
    if !is_timestamp_reply(reply.content_type.as_deref()) {
        return Err(TspError::ContentType(reply.content_type));
    }
    let (token, tst) = parse_response(&reply.body)?;
    check_answers(&tst, profile, &imprint, &nonce)?;

    let stamped = with_token(info, &token)?;
    signers[signer_index] = &stamped;
    let signer_infos = signers.concat();
    let signed_data = SignedData {
        signer_infos: RawSet(&signer_infos),
        ..signed_data
    };
    Ok(SignedContentInfo {
        signed_data: &signed_data,
    }
    .to_der()
    .map_err(CmsError::from)?)
}

/// Whether a `Content-Type` is `application/timestamp-reply`, ignoring case and parameters.
fn is_timestamp_reply(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case(TIMESTAMP_REPLY))
}

/// Whether `tst` answers a request with `imprint` (hashed with `profile.hash`), `nonce` and
/// `profile.policy`. Nonces compare as unsigned numbers.
fn check_answers(
    tst: &TstInfo,
    profile: &TsaProfile,
    imprint: &[u8],
    nonce: &[u8],
) -> Result<(), TspError> {
    if tst.nonce.as_deref() != Some(unsigned(nonce)) {
        return Err(TspError::NonceMismatch);
    }
    if tst.imprint_alg != profile.hash.oid() || tst.imprint != imprint {
        return Err(TspError::ImprintMismatch);
    }
    if tst.policy != profile.policy {
        return Err(TspError::PolicyMismatch);
    }
    Ok(())
}

/// DER `SignerInfo` with `token` as its only id-aa-timeStampToken unsigned attribute.
fn with_token(info: SignerInfo<'_>, token: &[u8]) -> Result<Vec<u8>, CmsError> {
    let mut attrs = vec![
        Attribute {
            attr_type: oid::TIME_STAMP_TOKEN,
            attr_values: RawSet(token),
        }
        .to_der()?,
    ];
    if let Some(existing) = info.unsigned_attrs {
        for tlv in existing.tlvs()? {
            if Attribute::from_der(tlv)?.attr_type != oid::TIME_STAMP_TOKEN {
                attrs.push(tlv.to_vec());
            }
        }
    }
    let attrs = der_set_contents(attrs);
    Ok(SignerInfo {
        unsigned_attrs: Some(RawSet(&attrs)),
        ..info
    }
    .to_der()?)
}

/// Reads a DER (or BER) `TSTInfo`.
fn tst_info(der: &[u8]) -> Result<TstInfo, TspError> {
    let der = ber::to_der(der)?;
    let tst = asn1::TstInfo::from_der(&der)?;
    if tst.version != 1 {
        return Err(TspError::Malformed(format!(
            "TSTInfo version {}",
            tst.version
        )));
    }
    Ok(TstInfo {
        policy: tst.policy,
        imprint_alg: tst.message_imprint.hash_algorithm.oid,
        imprint: tst.message_imprint.hashed_message.as_bytes().to_vec(),
        nonce: tst.nonce.map(|n| unsigned(n.as_bytes()).to_vec()),
        gen_time: generalized_time(tst.gen_time.0)
            .map_err(|e| TspError::Malformed(format!("genTime: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn tst(nonce: &[u8]) -> TstInfo {
        let profile = TsaProfile::basics_default();
        TstInfo {
            policy: profile.policy,
            imprint_alg: profile.hash.oid(),
            imprint: vec![7; 64],
            nonce: Some(nonce.to_vec()),
            gen_time: datetime!(2026-03-01 10:00 UTC),
        }
    }

    #[test]
    fn timestamp_reply_media_type() {
        assert!(is_timestamp_reply(Some("application/timestamp-reply")));
        assert!(is_timestamp_reply(Some(
            " APPLICATION/TimeStamp-Reply ; q=1"
        )));
        assert!(!is_timestamp_reply(Some("application/timestamp-query")));
        assert!(!is_timestamp_reply(Some("")));
        assert!(!is_timestamp_reply(None));
    }

    #[test]
    fn answers_must_match_the_request() {
        let p = TsaProfile::basics_default();
        let imprint = [7; 64];
        assert_eq!(
            check_answers(&tst(&[1, 2]), &p, &imprint, &[0, 0, 1, 2]),
            Ok(())
        );
        assert_eq!(
            check_answers(&tst(&[1, 3]), &p, &imprint, &[1, 2]),
            Err(TspError::NonceMismatch)
        );
        let no_nonce = TstInfo {
            nonce: None,
            ..tst(&[1])
        };
        assert_eq!(
            check_answers(&no_nonce, &p, &imprint, &[1]),
            Err(TspError::NonceMismatch)
        );
        assert_eq!(
            check_answers(&tst(&[1]), &p, &[8; 64], &[1]),
            Err(TspError::ImprintMismatch)
        );
        let other_alg = TstInfo {
            imprint_alg: oid::SHA256,
            ..tst(&[1])
        };
        assert_eq!(
            check_answers(&other_alg, &p, &imprint, &[1]),
            Err(TspError::ImprintMismatch)
        );
        let other_policy = TstInfo {
            policy: ObjectIdentifier::new_unwrap("1.2.398.3.3.2.6.1"),
            ..tst(&[1])
        };
        assert_eq!(
            check_answers(&other_policy, &p, &imprint, &[1]),
            Err(TspError::PolicyMismatch)
        );
    }
}
