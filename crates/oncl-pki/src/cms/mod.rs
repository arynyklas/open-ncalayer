//! CMS `SignedData` (RFC 5652) as NCALayer's `CMSUtil.createCAdES` makes it: signing,
//! co-signing (including BER with indefinite lengths from the original NCALayer),
//! verification and PEM output.
//!
//! Profile of a signature:
//!
//! - `ContentInfo{id-signedData}` → `SignedData` v1, `sid` = `IssuerAndSerialNumber`;
//! - the algorithm is the signer certificate's own signature algorithm; digest and signature
//!   `AlgorithmIdentifier`s carry `NULL` parameters;
//! - signed attributes, a DER `SET OF`: contentType, signingTime (UTCTime before 2050, else
//!   GeneralizedTime), messageDigest and signingCertificateV2 with only the SHA-256 hash of
//!   the signer certificate;
//! - `certificates` holds the signer certificate only (a co-signature adds it to the existing
//!   ones unless already there).

mod asn1;
mod pem;
mod sign;
mod verify;

use crate::ber::BerError;
use crate::key::KeyError;

pub use pem::to_pem;
#[allow(unused_imports, reason = "used by the TSP mock")]
pub(crate) use sign::sign_content;
pub use sign::{SignOptions, sign};
pub use verify::{VerifiedSigner, verify};

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
