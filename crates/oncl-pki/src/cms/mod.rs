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
mod sign;
mod verify;

use crate::ber::{self, BerError};
use crate::key::KeyError;
use crate::oid;
use asn1::{ContentInfo, SignedData};
use der::Decode;

#[cfg(feature = "testing")]
pub(crate) use sign::sign_content;
pub use sign::{SignOptions, sign};
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
    if content_info.content_type != oid::SIGNED_DATA {
        return Err(CmsError::Malformed(format!(
            "content type {} is not signedData",
            content_info.content_type
        )));
    }
    let signed_data: SignedData<'_> = content_info.content.decode_as()?;
    Ok(signed_data.signer_infos.tlvs()?.len())
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
