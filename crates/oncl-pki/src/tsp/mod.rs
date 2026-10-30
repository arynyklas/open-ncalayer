//! RFC 3161 time-stamping of CMS signers, as NCALayer does it with the NCA TSA.
//!
//! - The request is `TimeStampReq { v1, messageImprint { hash with NULL parameters,
//!   H(SignerInfo.signature) }, reqPolicy, nonce, certReq TRUE }`; the nonce is 8 random
//!   bytes read as a non-negative INTEGER.
//! - The NCA TSA takes it by GET: `url/` and the percent-encoded base64 of the DER request
//!   ([`TsaMethod::Get`]); RFC 3161 POST is supported too ([`TsaMethod::Post`]).
//! - The reply comes over plain HTTP, so it is hostile input: it must be HTTP 200 with
//!   `Content-Type: application/timestamp-reply`, status granted (0) or grantedWithMods (1),
//!   carry a token signed by a certificate with the timeStamping extended key usage, and
//!   echo the request's nonce (the same INTEGER), policy and message imprint. As in the
//!   original, the TSA certificate chain is not checked. Tokens requested by others may
//!   carry any INTEGER as their nonce, negative ones included.
//! - The token goes into the signer's unsigned attributes as id-aa-timeStampToken.

mod asn1;
#[cfg(feature = "testing")]
mod mock;

#[cfg(feature = "testing")]
pub use mock::{MockTamper, MockTsa};

use crate::asn1util::{generalized_time, unsigned};
use crate::ber::{self, BerError};
use crate::cert::Certificate;
use crate::cms::asn1::{
    Attribute, ContentInfo, RawSet, SignedContentInfo, SignedData, SignerInfo, der_set_contents,
};
use crate::cms::{self, CmsError};
use crate::http::{GetOptions, HttpError, HttpTransport, NetKind, NonceSpec, PkiMethod, pki_send};
use crate::info::cert_info;
use crate::key::{HashAlg, SigAlg};
use crate::oid;
use der::asn1::{AnyRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{Decode, Encode};
use spki::AlgorithmIdentifierRef;
use std::time::Duration;
use time::OffsetDateTime;

/// Policy `kz.gov.pki.knca.basics` asks the NCA TSA for.
const BASICS_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.3.2.6.4");
/// Policy `TSA_RSA` of Kalkan's default `TSAProfile`.
const TSA_RSA_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.3.2.6.2");

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

    /// Kalkan's default `TSAProfile`, as `kz.gov.pki.knca.commonUtils` time-stamps:
    /// `GET http://tsp.pki.gov.kz`, SHA-256 imprint, policy `TSA_RSA` 1.2.398.3.3.2.6.2.
    pub fn kalkan_default() -> Self {
        TsaProfile {
            url: "http://tsp.pki.gov.kz".to_owned(),
            method: TsaMethod::Get,
            hash: TspHash::Sha256,
            policy: TSA_RSA_POLICY,
        }
    }
}

/// Where and how to time-stamp, as each client of the NCA TSA does it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsaSpec {
    /// TSA URL.
    pub url: String,
    /// HTTP binding; a POST is `application/timestamp-query` unless it names its own type.
    pub method: PkiMethod,
    /// Message imprint hash.
    pub hash: HashAlg,
    /// Requested (and then required) TSA policy; `None` asks for none and takes any.
    pub policy: Option<ObjectIdentifier>,
    /// The request's nonce, echoed by the token.
    pub nonce: NonceSpec,
    /// `certReq`.
    pub cert_req: bool,
    /// Requests repeated after a failure before the TSA answered (no reply, an HTTP status
    /// other than 200, another content type).
    pub retries: u8,
    /// Timeout of each request.
    pub timeout: Duration,
    /// The genTime may be at most this far from the core's clock.
    pub check_skew: Option<Duration>,
    /// The token's signer must have the timeStamping extended key usage.
    pub require_tsa_eku: bool,
}

impl From<TsaProfile> for TsaSpec {
    /// The requests of [`timestamp_signer`]: an 8-byte nonce, `certReq`, no retries, 10
    /// seconds, the TSA's key usage required.
    fn from(profile: TsaProfile) -> Self {
        TsaSpec {
            url: profile.url,
            method: match profile.method {
                TsaMethod::Get => PkiMethod::GetUrlEncoded,
                TsaMethod::Post => PkiMethod::Post { content_type: None },
            },
            hash: profile.hash.hash_alg(),
            policy: Some(profile.policy),
            nonce: NonceSpec::Random(8),
            cert_req: true,
            retries: 0,
            timeout: GetOptions::default().timeout,
            check_skew: None,
            require_tsa_eku: true,
        }
    }
}

/// The signers [`stamp`] time-stamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerSel {
    /// The last one.
    Last,
    /// The one at this index.
    Index(usize),
    /// Every signer without an id-aa-timeStampToken yet.
    AllUnstamped,
}

/// What [`stamp`] does with an earlier id-aa-timeStampToken of a signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StampMode {
    /// Replaces it.
    Replace,
    /// Keeps it, adding another attribute.
    Append,
}

/// What goes into the id-aa-timeStampToken attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenForm {
    /// The token (`ContentInfo`), as RFC 3161 says.
    Token,
    /// The whole `TimeStampResp`, as some clients put it.
    WholeResponse,
}

/// A time-stamp the TSA granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TspReply {
    /// The `TimeStampResp`, as received.
    pub response: Vec<u8>,
    /// Its token, DER.
    pub token: Vec<u8>,
    /// The token's `TSTInfo`.
    pub tst: TstInfo,
    /// The certificate that signed the token.
    pub tsa_cert: Certificate,
}

impl TspHash {
    /// The same hash.
    pub fn hash_alg(self) -> HashAlg {
        match self {
            TspHash::Streebog512 => HashAlg::Streebog512,
            TspHash::Sha256 => HashAlg::Sha256,
            TspHash::Gost34311 => HashAlg::Gost34311,
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
    /// Nonce: the contents octets of its DER INTEGER, i.e. minimal big-endian two's
    /// complement. A negative nonce starts with a set top bit; a non-negative one whose top
    /// bit is set has a leading `00` (as Java's `BigInteger.toByteArray()`).
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
    /// The token's genTime is further from the core's clock than the request allows.
    #[error("time-stamp genTime is too far from the local clock")]
    ClockSkew,
    /// The token does not verify as a CMS, or the CMS to time-stamp is invalid.
    #[error("CMS: {0}")]
    Cms(#[from] CmsError),
    /// The TSA's response is not a valid `TimeStampResp`.
    #[error("malformed time-stamp response: {0}")]
    Malformed(String),
}

impl TspError {
    /// What kind of network failure it is, as the plugins see it.
    pub fn kind(&self) -> NetKind {
        match self {
            TspError::Http(e) => e.kind.into(),
            TspError::Status(status) => NetKind::Http(*status),
            TspError::Rejected(status) => {
                NetKind::Rejected(u8::try_from(*status).unwrap_or(u8::MAX))
            }
            TspError::ClockSkew => NetKind::ClockSkew,
            TspError::ContentType(_)
            | TspError::NonceMismatch
            | TspError::ImprintMismatch
            | TspError::UnsupportedImprintAlgorithm(_)
            | TspError::PolicyMismatch
            | TspError::NoTsaCertificate
            | TspError::Cms(_)
            | TspError::Malformed(_) => NetKind::InvalidResponse,
        }
    }
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
/// unsigned big-endian number (an empty slice is zero) sent as a non-negative INTEGER.
///
/// # Panics
///
/// If `imprint` or `nonce` is longer than DER allows (256 MiB).
pub fn request_der(profile: &TsaProfile, imprint: &[u8], nonce: &[u8]) -> Vec<u8> {
    request_spec_der(&TsaSpec::from(profile.clone()), imprint, Some(nonce))
}

/// DER `TimeStampReq` of `spec` for `imprint` (already hashed with `spec.hash`) and
/// `nonce`, as [`request_der`]; `None` sends no nonce.
fn request_spec_der(spec: &TsaSpec, imprint: &[u8], nonce: Option<&[u8]>) -> Vec<u8> {
    let nonce = nonce.map(|n| if n.is_empty() { &[0][..] } else { n });
    asn1::TimeStampReq {
        version: 1,
        message_imprint: asn1::MessageImprint {
            hash_algorithm: AlgorithmIdentifierRef {
                oid: spec.hash.oid(),
                parameters: Some(AnyRef::NULL),
            },
            hashed_message: OctetStringRef::new(imprint).expect("imprint fits DER"),
        },
        req_policy: spec.policy,
        nonce: nonce.map(|n| UintRef::new(n).expect("nonce fits DER")),
        cert_req: spec.cert_req.then_some(true),
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
    parse_response_signed(resp, true).map(|(token, tst, _)| (token, tst))
}

/// [`parse_response`], the TSA's key usage required or not, also returning the TSA
/// certificate.
fn parse_response_signed(
    resp: &[u8],
    require_eku: bool,
) -> Result<(Vec<u8>, TstInfo, Certificate), TspError> {
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
    let (tst, tsa) = verify_token_signed(&token, require_eku)?;
    Ok((token, tst, tsa))
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
    verify_token_signed(token, true).map(|(tst, _)| tst)
}

/// [`verify_token`], the TSA's key usage required or not, also returning the TSA
/// certificate that signed the token.
fn verify_token_signed(
    token: &[u8],
    require_eku: bool,
) -> Result<(TstInfo, Certificate), TspError> {
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
    // One signer: the count is checked above.
    let tsa = signers
        .into_iter()
        .next()
        .ok_or(TspError::NoTsaCertificate)?
        .cert;
    if require_eku
        && !cert_info(&tsa)
            .ext_key_usages
            .contains(&oid::TIME_STAMPING.to_string())
    {
        return Err(TspError::NoTsaCertificate);
    }
    Ok((tst_info(content.as_bytes())?, tsa))
}

/// [`verify_token`] for the token of a CMS signer whose `SignerInfo.signature` value is
/// `signature`: the token's message imprint must also be the hash of `signature` (with the
/// token's own imprint algorithm), as [`timestamp_signer`] requests it. Returns the
/// `TSTInfo` and the TSA certificate that signed the token (its chain is up to the caller).
///
/// Besides the [`TspHash`] algorithms, any imprint hash of [`HashAlg`] is accepted here
/// (SHA-1 included): the NCA TSA stamps them for clients that ask, and CAdES-T made by such
/// clients must verify.
///
/// # Errors
///
/// Errors of [`verify_token`]; [`TspError::UnsupportedImprintAlgorithm`] if the imprint
/// algorithm is none of those; [`TspError::ImprintMismatch`] if the imprint is not the hash
/// of `signature`.
pub fn verify_token_for(
    token: &[u8],
    signature: &[u8],
) -> Result<(TstInfo, Certificate), TspError> {
    let (tst, tsa) = verify_token_signed(token, true)?;
    let expected = match HashAlg::from_oid(&tst.imprint_alg) {
        Some(hash) => hash.digest(signature),
        None => return Err(TspError::UnsupportedImprintAlgorithm(tst.imprint_alg)),
    };
    if tst.imprint != expected {
        return Err(TspError::ImprintMismatch);
    }
    Ok((tst, tsa))
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
    stamp(
        cms,
        SignerSel::Index(signer_index),
        &TsaSpec::from(profile.clone()),
        StampMode::Replace,
        TokenForm::Token,
        http,
    )
}

/// Asks the TSA of `spec` for a time-stamp of `imprint` (already hashed with `spec.hash`),
/// repeating the request up to `spec.retries` times while the TSA does not answer, and
/// checks the answer: granted, a valid token (signed by a certificate with the
/// timeStamping key usage if `spec` requires it) answering this request, its genTime
/// within `spec.check_skew` of the core's clock.
///
/// # Errors
///
/// The transport's (after the retries); [`TspError::Status`] or [`TspError::ContentType`]
/// for an unexpected HTTP reply; the errors of [`parse_response`]; the mismatches of the
/// answer; [`TspError::ClockSkew`].
pub fn request(
    spec: &TsaSpec,
    imprint: &[u8],
    http: &dyn HttpTransport,
) -> Result<TspReply, TspError> {
    let nonce = spec.nonce.draw();
    let request = request_spec_der(spec, imprint, nonce.as_deref());
    let opts = GetOptions {
        timeout: spec.timeout,
        ..GetOptions::default()
    };
    let mut attempt = 0;
    let body = loop {
        let answer = pki_send(
            http,
            &spec.method,
            &spec.url,
            TIMESTAMP_QUERY,
            &request,
            opts,
        )
        .map_err(TspError::from)
        .and_then(|reply| {
            if reply.status != 200 {
                return Err(TspError::Status(reply.status));
            }
            if !is_timestamp_reply(reply.content_type.as_deref()) {
                return Err(TspError::ContentType(reply.content_type));
            }
            Ok(reply.body)
        });
        match answer {
            Err(_) if attempt < spec.retries => attempt += 1,
            answer => break answer?,
        }
    };
    let (token, tst, tsa_cert) = parse_response_signed(&body, spec.require_tsa_eku)?;
    check_answers(&tst, spec, imprint, nonce.as_deref())?;
    if let Some(skew) = spec.check_skew
        && (tst.gen_time - OffsetDateTime::now_utc()).unsigned_abs() > skew
    {
        return Err(TspError::ClockSkew);
    }
    Ok(TspReply {
        response: body,
        token,
        tst,
        tsa_cert,
    })
}

/// Time-stamps the signers `signers` of a DER or BER `ContentInfo{SignedData}`: for each,
/// requests a token for its `SignerInfo.signature` value ([`request`]) and puts it (or the
/// whole response, per `form`) into its unsigned attributes as id-aa-timeStampToken,
/// replacing or keeping an earlier one per `mode`. Other signers are kept byte for byte.
/// Returns the CMS as DER.
///
/// # Errors
///
/// [`TspError::Cms`] for an invalid CMS; [`TspError::Malformed`] if there is no such
/// signer; the errors of [`request`].
pub fn stamp(
    cms: &[u8],
    signers: SignerSel,
    spec: &TsaSpec,
    mode: StampMode,
    form: TokenForm,
    http: &dyn HttpTransport,
) -> Result<Vec<u8>, TspError> {
    attach_tokens(cms, signers, mode, |signature| {
        let reply = request(spec, &spec.hash.digest(signature), http)?;
        Ok(match form {
            TokenForm::Token => reply.token,
            TokenForm::WholeResponse => reply.response,
        })
    })
}

/// `cms` (a DER or BER `ContentInfo{SignedData}`) as DER, with the value `stamp` returns
/// for the `SignerInfo.signature` value of signer `signer_index` as that signer's
/// id-aa-timeStampToken unsigned attribute, replacing an earlier one. Other signers are
/// kept byte for byte.
///
/// # Errors
///
/// [`TspError::Cms`] for an invalid CMS; [`TspError::Malformed`] if there is no such
/// signer; errors of `stamp`.
#[cfg(feature = "testing")]
fn replace_token(
    cms: &[u8],
    signer_index: usize,
    stamp: impl FnMut(&[u8]) -> Result<Vec<u8>, TspError>,
) -> Result<Vec<u8>, TspError> {
    attach_tokens(
        cms,
        SignerSel::Index(signer_index),
        StampMode::Replace,
        stamp,
    )
}

/// `cms` as DER, with the value `stamp` returns for each selected signer's signature as
/// its id-aa-timeStampToken attribute, per `mode`.
fn attach_tokens(
    cms: &[u8],
    signers: SignerSel,
    mode: StampMode,
    mut stamp: impl FnMut(&[u8]) -> Result<Vec<u8>, TspError>,
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
    let tlvs = signed_data.signer_infos.tlvs().map_err(CmsError::from)?;
    let infos = tlvs
        .iter()
        .map(|tlv| SignerInfo::from_der(tlv))
        .collect::<der::Result<Vec<_>>>()
        .map_err(CmsError::from)?;
    let targets: Vec<usize> = match signers {
        SignerSel::Index(index) if index < infos.len() => vec![index],
        SignerSel::Index(index) => {
            return Err(TspError::Malformed(format!(
                "no signer {index} among {} signers",
                infos.len()
            )));
        }
        SignerSel::Last => match infos.len() {
            0 => return Err(TspError::Malformed("the CMS has no signers".to_owned())),
            len => vec![len - 1],
        },
        SignerSel::AllUnstamped => {
            let mut unstamped = Vec::new();
            for (index, info) in infos.iter().enumerate() {
                if !has_token(info).map_err(TspError::from)? {
                    unstamped.push(index);
                }
            }
            unstamped
        }
    };
    let mut stamped: Vec<Vec<u8>> = tlvs.iter().map(|tlv| tlv.to_vec()).collect();
    for index in targets {
        let info = infos[index];
        let token = stamp(info.signature.as_bytes())?;
        stamped[index] = with_token(info, &token, mode)?;
    }
    let signer_infos = stamped.concat();
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

/// Whether a signer has an id-aa-timeStampToken unsigned attribute.
fn has_token(info: &SignerInfo<'_>) -> Result<bool, CmsError> {
    let Some(attrs) = info.unsigned_attrs else {
        return Ok(false);
    };
    for tlv in attrs.tlvs()? {
        if Attribute::from_der(tlv)?.attr_type == oid::TIME_STAMP_TOKEN {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a `Content-Type` is `application/timestamp-reply`, ignoring case and parameters.
fn is_timestamp_reply(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case(TIMESTAMP_REPLY))
}

/// Whether `tst` answers a request of `spec` with `imprint` and `nonce` (`None`: the
/// request had none, and any echo is accepted). The token's nonce must be the same INTEGER
/// as the request's unsigned `nonce`: a sign octet before a set top bit is part of its
/// encoding, a negative echo is a mismatch. Without a requested policy any policy is taken.
fn check_answers(
    tst: &TstInfo,
    spec: &TsaSpec,
    imprint: &[u8],
    nonce: Option<&[u8]>,
) -> Result<(), TspError> {
    if let Some(nonce) = nonce
        && !tst.nonce.as_deref().is_some_and(|n| is_uint(n, nonce))
    {
        return Err(TspError::NonceMismatch);
    }
    if tst.imprint_alg != spec.hash.oid() || tst.imprint != imprint {
        return Err(TspError::ImprintMismatch);
    }
    if spec.policy.is_some_and(|policy| tst.policy != policy) {
        return Err(TspError::PolicyMismatch);
    }
    Ok(())
}

/// Whether `contents`, the contents octets of a DER INTEGER (minimal two's complement), are
/// the encoding of the unsigned big-endian number `n` (leading zeros allowed, an empty
/// slice is zero): `n` itself, with a `00` sign octet before a set top bit, and `00` for
/// zero.
fn is_uint(contents: &[u8], n: &[u8]) -> bool {
    let magnitude = match contents {
        [0, rest @ ..] => rest,
        [first, ..] if first & 0x80 != 0 => return false,
        positive => positive,
    };
    magnitude == unsigned(n)
}

/// DER `SignerInfo` with `token` as an id-aa-timeStampToken unsigned attribute: its only
/// one ([`StampMode::Replace`]) or another one ([`StampMode::Append`]).
fn with_token(info: SignerInfo<'_>, token: &[u8], mode: StampMode) -> Result<Vec<u8>, CmsError> {
    let mut attrs = vec![
        Attribute {
            attr_type: oid::TIME_STAMP_TOKEN,
            attr_values: RawSet(token),
        }
        .to_der()?,
    ];
    if let Some(existing) = info.unsigned_attrs {
        for tlv in existing.tlvs()? {
            if mode == StampMode::Append
                || Attribute::from_der(tlv)?.attr_type != oid::TIME_STAMP_TOKEN
            {
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
        nonce: tst.nonce.map(|n| n.as_bytes().to_vec()),
        gen_time: generalized_time(tst.gen_time.0)
            .map_err(|e| TspError::Malformed(format!("genTime: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::IntRef;
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
            check_answers(
                &tst(&[1, 2]),
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&[0, 0, 1, 2])
            ),
            Ok(())
        );
        assert_eq!(
            check_answers(
                &tst(&[1, 3]),
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&[1, 2])
            ),
            Err(TspError::NonceMismatch)
        );
        let no_nonce = TstInfo {
            nonce: None,
            ..tst(&[1])
        };
        assert_eq!(
            check_answers(&no_nonce, &TsaSpec::from(p.clone()), &imprint, Some(&[1])),
            Err(TspError::NonceMismatch)
        );
        assert_eq!(
            check_answers(&tst(&[1]), &TsaSpec::from(p.clone()), &[8; 64], Some(&[1])),
            Err(TspError::ImprintMismatch)
        );
        let other_alg = TstInfo {
            imprint_alg: oid::SHA256,
            ..tst(&[1])
        };
        assert_eq!(
            check_answers(&other_alg, &TsaSpec::from(p.clone()), &imprint, Some(&[1])),
            Err(TspError::ImprintMismatch)
        );
        let other_policy = TstInfo {
            policy: ObjectIdentifier::new_unwrap("1.2.398.3.3.2.6.1"),
            ..tst(&[1])
        };
        assert_eq!(
            check_answers(
                &other_policy,
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&[1])
            ),
            Err(TspError::PolicyMismatch)
        );
    }

    /// DER `TSTInfo` with the basics policy and hash, the imprint of [`tst`] and a nonce
    /// INTEGER with the contents octets `nonce` (`IntRef::new` drops only redundant leading
    /// `ff` octets).
    fn tst_info_der(nonce: &[u8]) -> Vec<u8> {
        let p = TsaProfile::basics_default();
        let imprint = [7; 64];
        asn1::TstInfo {
            version: 1,
            policy: p.policy,
            message_imprint: asn1::MessageImprint {
                hash_algorithm: AlgorithmIdentifierRef {
                    oid: p.hash.oid(),
                    parameters: Some(AnyRef::NULL),
                },
                hashed_message: OctetStringRef::new(&imprint).unwrap(),
            },
            serial_number: IntRef::new(&[1]).unwrap(),
            gen_time: crate::asn1util::RawGeneralizedTime(b"20260301100000Z"),
            accuracy: None,
            ordering: None,
            nonce: Some(IntRef::new(nonce).unwrap()),
            tsa: None,
            extensions: None,
        }
        .to_der()
        .unwrap()
    }

    /// [`tst_info`] of [`tst_info_der`].
    fn parsed(nonce: &[u8]) -> TstInfo {
        tst_info(&tst_info_der(nonce)).unwrap()
    }

    #[test]
    fn nonce_echo_must_be_the_same_integer() {
        let p = TsaProfile::basics_default();
        let imprint = [7; 64];
        // A request nonce with the top bit set goes out as 00 80 … 01; its echo matches.
        let request = [0x80, 0, 0, 0, 0, 0, 0, 1];
        let echo = parsed(&[0, 0x80, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            echo.nonce.as_deref(),
            Some(&[0, 0x80, 0, 0, 0, 0, 0, 0, 1][..])
        );
        assert_eq!(
            check_answers(&echo, &TsaSpec::from(p.clone()), &imprint, Some(&request)),
            Ok(())
        );
        // Leading zero bytes of the request do not matter.
        assert_eq!(
            check_answers(
                &parsed(&[0x7f, 1]),
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&[0, 0, 0x7f, 1])
            ),
            Ok(())
        );

        // The same octets without the sign octet: a negative INTEGER, another number.
        let flipped = parsed(&request);
        assert_eq!(flipped.nonce.as_deref(), Some(&request[..]));
        assert_eq!(
            check_answers(
                &flipped,
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&request)
            ),
            Err(TspError::NonceMismatch)
        );
        // The negated request: −0x8000000000000001.
        let negated = parsed(&[0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            check_answers(
                &negated,
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&request)
            ),
            Err(TspError::NonceMismatch)
        );
        // Another positive number.
        let altered = parsed(&[0, 0x80, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(
            check_answers(
                &altered,
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&request)
            ),
            Err(TspError::NonceMismatch)
        );
        // Zero is a single 00 octet, whatever leading zeros the request had.
        assert_eq!(
            check_answers(
                &parsed(&[0]),
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&[0, 0])
            ),
            Ok(())
        );
        assert_eq!(
            check_answers(
                &parsed(&[0]),
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&[])
            ),
            Ok(())
        );
        assert_eq!(
            check_answers(
                &parsed(&[0x80]),
                &TsaSpec::from(p.clone()),
                &imprint,
                Some(&[0])
            ),
            Err(TspError::NonceMismatch)
        );
    }

    #[test]
    fn negative_nonce_is_read() {
        assert_eq!(parsed(&[0x80]).nonce, Some(vec![0x80]));
        assert_eq!(parsed(&[0xff]).nonce, Some(vec![0xff]));
        assert_eq!(parsed(&[0]).nonce, Some(vec![0]));
    }

    #[test]
    fn non_minimal_nonce_is_malformed() {
        // A redundant 00 before a clear top bit: `IntRef::new` keeps it.
        let der = tst_info_der(&[0, 1]);
        assert!(der.windows(4).any(|w| w == [0x02, 0x02, 0x00, 0x01]));
        assert!(matches!(tst_info(&der), Err(TspError::Malformed(_))));

        // A redundant ff before a set top bit: `IntRef::new` would drop it, so the
        // encoding of a placeholder nonce is patched.
        let mut der = tst_info_der(&[0x12, 0x34]);
        let placeholder: [u8; 4] = [0x02, 0x02, 0x12, 0x34];
        let at = der.windows(4).position(|w| w == placeholder).unwrap();
        assert!(!der[at + 1..].windows(4).any(|w| w == placeholder));
        der[at + 2..at + 4].copy_from_slice(&[0xff, 0x80]);
        assert!(matches!(tst_info(&der), Err(TspError::Malformed(_))));
    }
}
