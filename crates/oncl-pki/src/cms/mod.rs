//! CMS `SignedData` (RFC 5652) as NCALayer's `CMSUtil.createCAdES` makes it: signing,
//! co-signing (including BER with indefinite lengths from the original NCALayer),
//! verification and PEM output.
//!
//! Profile of a signature:
//!
//! - `ContentInfo{id-signedData}` → `SignedData` v1 (v3 when the content type is not
//!   id-data, as for a time-stamp token), `sid` = `IssuerAndSerialNumber`;
//! - the algorithm is the signer certificate's own signature algorithm; digest and signature
//!   `AlgorithmIdentifier`s carry `NULL` parameters;
//! - signed attributes, a DER `SET OF`: contentType, signingTime (UTCTime before 2050, else
//!   GeneralizedTime), messageDigest and signingCertificateV2 with only the SHA-256 hash of
//!   the signer certificate;
//! - `certificates` holds the signer certificate only (a co-signature adds it to the existing
//!   ones unless already there).

pub(crate) mod asn1;
mod report;
mod sign;
mod verify;

use crate::ber::{self, BerError};
use crate::key::KeyError;
use crate::oid;
use asn1::{ContentInfo, IssuerAndSerialNumber, SignedData, SignerInfo};
use der::{Decode, Tag, Tagged};
use x509_cert::Certificate;

pub use report::{
    ChainPolicy, Check, NetFailure, NetStage, Problem, Report, ReportSpec, Revocation,
    SignerReport, TspReport, VerifyAt, report,
};
#[cfg(feature = "testing")]
pub(crate) use sign::sign_content;
pub use sign::{
    AttrSpec, CertSpec, CoSign, Content, SignOptions, SignSpec, TimeForm, sign, sign_spec,
};
pub use verify::{VerifiedSigner, verify};

/// A DER CMS as `-----BEGIN CMS-----` PEM ([`crate::pem::encode`]).
pub fn to_pem(der: &[u8]) -> String {
    crate::pem::encode("CMS", der)
}

/// Number of signers (`signerInfos` elements) of a DER or BER `ContentInfo{SignedData}`.
///
/// # Errors
///
/// [`CmsError::Malformed`] if `cms` is not a readable `ContentInfo{SignedData}`.
pub fn signer_count(cms: &[u8]) -> Result<usize, CmsError> {
    let der = ber::to_der(cms)?;
    let content_info = ContentInfo::from_der(&der)?;
    Ok(signed_data(&content_info)?.signer_infos.tlvs()?.len())
}

/// Index of the first signer of a DER or BER `ContentInfo{SignedData}` whose
/// `IssuerAndSerialNumber` names `cert` (as Kalkan's `SignerId` selector finds it), or
/// `None`. Signers identified by a SubjectKeyIdentifier never match.
///
/// # Errors
///
/// [`CmsError::Malformed`] if `cms` is not a readable `ContentInfo{SignedData}`.
pub fn signer_index_of(cms: &[u8], cert: &Certificate) -> Result<Option<usize>, CmsError> {
    let der = ber::to_der(cms)?;
    let content_info = ContentInfo::from_der(&der)?;
    let tbs = cert.tbs_certificate();
    for (index, tlv) in signed_data(&content_info)?
        .signer_infos
        .tlvs()?
        .into_iter()
        .enumerate()
    {
        let sid = SignerInfo::from_der(tlv)?.sid;
        if sid.tag() != Tag::Sequence {
            continue;
        }
        let sid: IssuerAndSerialNumber = sid.decode_as()?;
        if sid.issuer == *tbs.issuer()
            && sid.serial_number.as_bytes() == tbs.serial_number().as_bytes()
        {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// The encapsulated content (`eContent`) of a DER or BER `ContentInfo{SignedData}`, or
/// `None` for a detached CMS. No signature is checked: [`verify`] does that.
///
/// # Errors
///
/// [`CmsError::Malformed`] if `cms` is not a readable `ContentInfo{SignedData}`.
pub fn content(cms: &[u8]) -> Result<Option<Vec<u8>>, CmsError> {
    let der = ber::to_der(cms)?;
    let content_info = ContentInfo::from_der(&der)?;
    Ok(signed_data(&content_info)?
        .encap_content_info
        .e_content
        .map(|c| c.as_bytes().to_vec()))
}

/// The certificates (`certificates` field) of a DER or BER `ContentInfo{SignedData}`, in
/// their order; other `CertificateChoices` are skipped. No signature is checked.
///
/// # Errors
///
/// [`CmsError::Malformed`] if `cms` is not a readable `ContentInfo{SignedData}` or a
/// certificate does not parse.
pub fn certificates(cms: &[u8]) -> Result<Vec<Certificate>, CmsError> {
    let der = ber::to_der(cms)?;
    let content_info = ContentInfo::from_der(&der)?;
    Ok(verify::certificates(&signed_data(&content_info)?)?
        .into_iter()
        .map(|(cert, _)| cert)
        .collect())
}

/// The `SignedData` of a `ContentInfo`, which must be of type id-signedData.
fn signed_data<'a>(content_info: &ContentInfo<'a>) -> Result<SignedData<'a>, CmsError> {
    if content_info.content_type != oid::SIGNED_DATA {
        return Err(CmsError::Malformed(format!(
            "content type {} is not signedData",
            content_info.content_type
        )));
    }
    Ok(content_info.content.decode_as()?)
}

/// Error of a CMS operation. `usize` values are signer indexes in `signerInfos`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CmsError {
    /// The CMS has no encapsulated content and none was given (verification), or a
    /// detached CMS was given for co-signing.
    #[error("CMS has no encapsulated content")]
    NoEncapsulatedData,
    /// The signature or digest algorithm is not supported.
    #[error("unsupported algorithm {0}")]
    UnknownAlgorithm(String),
    /// The CMS (or a value written into it) is not valid.
    #[error("malformed CMS: {0}")]
    Malformed(String),
    /// No certificate in the CMS matches the signer identifier.
    #[error("certificate of signer {0} not found")]
    CertNotFound(usize),
    /// The messageDigest attribute does not match the content.
    #[error("message digest of signer {0} does not match the content")]
    DigestMismatch(usize),
    /// The signature does not verify.
    #[error("signature of signer {0} does not verify")]
    BadSignature(usize),
    /// The signingCertificateV2 hash does not match the signer certificate.
    #[error("signing certificate attribute of signer {0} does not match its certificate")]
    SigningCertificateMismatch(usize),
    /// The key cannot be used with the algorithm.
    #[error("key: {0}")]
    Key(KeyError),
    /// The signature asked for cannot be made: why.
    #[error("{0}")]
    Constraint(String),
}

impl From<der::Error> for CmsError {
    fn from(e: der::Error) -> Self {
        CmsError::Malformed(e.to_string())
    }
}

impl From<BerError> for CmsError {
    fn from(e: BerError) -> Self {
        CmsError::Malformed(e.to_string())
    }
}
