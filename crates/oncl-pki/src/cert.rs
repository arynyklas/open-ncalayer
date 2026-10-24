//! X.509 certificates: parsing (BER accepted) and signature checks.

use crate::ber::{self, BerError};
use crate::key::{KeyError, PublicKey, SigAlg};
use der::{Decode, Encode};

pub use x509_cert::Certificate;

/// Error of a certificate operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// The certificate encoding is invalid.
    #[error("malformed certificate: {0}")]
    Malformed(String),
    /// The certificate signature algorithm is not supported.
    #[error("unsupported certificate signature algorithm {0}")]
    UnsupportedAlgorithm(String),
    /// The issuer key cannot be used.
    #[error("issuer key: {0}")]
    Key(KeyError),
    /// The signature does not verify with the issuer key.
    #[error("certificate signature does not verify")]
    BadSignature,
}

impl From<BerError> for CertError {
    fn from(e: BerError) -> Self {
        CertError::Malformed(e.to_string())
    }
}

impl From<der::Error> for CertError {
    fn from(e: der::Error) -> Self {
        CertError::Malformed(e.to_string())
    }
}

/// Parses a DER or BER certificate; BER is normalized with [`ber::to_der`] first.
///
/// # Errors
///
/// [`CertError::Malformed`] unless the input is exactly one certificate.
pub fn parse(der: &[u8]) -> Result<Certificate, CertError> {
    Ok(Certificate::from_der(&ber::to_der(der)?)?)
}

/// Checks that `issuer`'s public key signed `cert`. Only the signature is checked: names,
/// validity and extensions are not.
///
/// # Errors
///
/// [`CertError::UnsupportedAlgorithm`] for an unknown signature algorithm,
/// [`CertError::Key`] if the issuer key is unusable or does not fit the algorithm,
/// [`CertError::BadSignature`] if the signature does not verify.
pub fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<(), CertError> {
    let oid = cert.signature_algorithm().oid;
    let alg = SigAlg::from_signature_oid(&oid)
        .ok_or_else(|| CertError::UnsupportedAlgorithm(oid.to_string()))?;
    if cert.tbs_certificate().signature().oid != oid {
        return Err(CertError::Malformed(
            "signatureAlgorithm differs from tbsCertificate.signature".to_owned(),
        ));
    }
    let key = PublicKey::from_spki(issuer.tbs_certificate().subject_public_key_info())
        .map_err(CertError::Key)?;
    let sig = cert
        .signature()
        .as_bytes()
        .ok_or_else(|| CertError::Malformed("signature BIT STRING has unused bits".to_owned()))?;
    let tbs = cert.tbs_certificate().to_der()?;
    key.verify(alg, &tbs, sig).map_err(|e| match e {
        KeyError::BadSignature => CertError::BadSignature,
        e => CertError::Key(e),
    })
}
