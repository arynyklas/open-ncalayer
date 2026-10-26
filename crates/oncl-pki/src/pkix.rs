//! Certification paths: from a certificate up through a set of CA certificates to an
//! anchor, checked by the rules of RFC 5280 §6.1 without policies and name constraints.
//!
//! - The anchor is a self-signed CA of the set or, as in the original's `PKIXUtil`, the
//!   topmost CA of the set found on the way up: a CA of the set whose issuer name no CA of
//!   the set has. So a set of an intermediate CA alone anchors the certificates it issued.
//!   The certificate itself always needs an issuer in the set.
//! - The issuer of a certificate is a CA of the set whose subject equals the certificate's
//!   issuer name and whose key verifies its signature. Among several such CAs the one whose
//!   subjectKeyIdentifier equals the certificate's authorityKeyIdentifier is tried first,
//!   then the others in set order; the first that verifies wins. (The original keeps the CAs
//!   in a map by name, so the last CA of a name hides the others.)
//! - Every certificate of the path must be valid at the validation time, bounds included,
//!   and carry no critical extension outside [`KNOWN_EXTENSIONS`].
//! - Every issuer must have basicConstraints with cA, a pathLenConstraint the path below it
//!   respects (self-issued certificates are not counted) and, if it has keyUsage,
//!   keyCertSign.

use crate::cert::{self, Certificate};
use crate::oid;
use der::asn1::ObjectIdentifier;
use der::oid::AssociatedOid;
use time::OffsetDateTime;
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies,
    CrlDistributionPoints, ExtendedKeyUsage, KeyUsage, NameConstraints, PrivateKeyUsagePeriod,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::time::Time;

/// Longest path, the certificate and its anchor included.
pub const MAX_PATH_LEN: usize = 8;

/// Extensions a certificate may mark critical. nameConstraints is recognized but not
/// enforced: no NCA certificate has it.
pub const KNOWN_EXTENSIONS: [ObjectIdentifier; 12] = [
    BasicConstraints::OID,
    KeyUsage::OID,
    ExtendedKeyUsage::OID,
    CertificatePolicies::OID,
    SubjectKeyIdentifier::OID,
    AuthorityKeyIdentifier::OID,
    SubjectAltName::OID,
    CrlDistributionPoints::OID,
    AuthorityInfoAccessSyntax::OID,
    oid::OCSP_NOCHECK,
    PrivateKeyUsagePeriod::OID,
    NameConstraints::OID,
];

/// Why no certification path was built. `index` is the position in the path: 0 is the
/// certificate itself, its issuer is 1, and so on.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// No CA of the set has the certificate's issuer name (above it, the topmost CA of the
    /// set is the anchor).
    #[error("issuer certificate not found")]
    IssuerNotFound,
    /// CAs with the issuer name exist, but none of their keys verifies the signature.
    #[error("certificate signature does not verify with any issuer candidate")]
    BadSignature,
    /// A certificate is not valid at the validation time.
    #[error("certificate {index} of the path is not valid at the validation time")]
    NotValidAt {
        /// Position in the path.
        index: usize,
    },
    /// An issuer is not a CA: basicConstraints is missing, malformed or without cA.
    #[error("issuer certificate {index} of the path is not a CA")]
    NotCa {
        /// Position in the path.
        index: usize,
    },
    /// An issuer's pathLenConstraint is smaller than the number of CAs below it.
    #[error("path length constraint of certificate {index} of the path is exceeded")]
    PathLenExceeded {
        /// Position in the path.
        index: usize,
    },
    /// An issuer has keyUsage without keyCertSign (or a malformed keyUsage).
    #[error("issuer certificate {index} of the path lacks the keyCertSign key usage")]
    KeyCertSignMissing {
        /// Position in the path.
        index: usize,
    },
    /// A certificate has a critical extension this implementation does not process.
    #[error("certificate {index} of the path has an unknown critical extension {oid}")]
    UnknownCriticalExtension {
        /// Position in the path.
        index: usize,
        /// Extension OID, dotted.
        oid: String,
    },
    /// No anchor within [`MAX_PATH_LEN`] certificates.
    #[error("certification path is longer than {MAX_PATH_LEN} certificates")]
    TooLong,
}

/// A set of CA certificates paths are built through: issuing CAs and anchors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaSet {
    certs: Vec<Certificate>,
}

impl CaSet {
    /// The set of `certs`, in this order.
    pub fn new(certs: Vec<Certificate>) -> CaSet {
        CaSet { certs }
    }

    /// The embedded NCA production CAs ([`crate::roots::nca_production`]).
    pub fn nca_production() -> CaSet {
        CaSet::new(crate::roots::nca_production().to_vec())
    }

    /// Whether the set has no certificate.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// CAs whose subject is `cert`'s issuer name, in set order, except that those whose
    /// subjectKeyIdentifier equals `cert`'s authorityKeyIdentifier come first.
    pub fn issuers_of<'a>(
        &'a self,
        cert: &Certificate,
    ) -> impl Iterator<Item = &'a Certificate> + use<'a> {
        let issuer = cert.tbs_certificate().issuer();
        let mut named: Vec<&Certificate> = self
            .certs
            .iter()
            .filter(|c| c.tbs_certificate().subject() == issuer)
            .collect();
        if let Some(aki) = authority_key_id(cert) {
            // Stable: the set order holds within both groups.
            named.sort_by_key(|c| subject_key_id(c).as_ref() != Some(&aki));
        }
        named.into_iter()
    }
}

/// Builds and checks the path from `leaf` through `cas` to an anchor of `cas` at time `at`,
/// returning `[leaf, issuer, …, anchor]`. The anchor is a self-signed CA of `cas`, or the
/// first CA of the path whose issuer name no CA of `cas` has. A `leaf` that is itself a
/// self-signed CA of `cas` (byte for byte) gives the path `[leaf]`. The anchor is checked
/// like any issuer.
///
/// # Errors
///
/// The first rule the path breaks, see [`PathError`]; certificates are checked from `leaf`
/// up.
pub fn build_path(
    leaf: &Certificate,
    cas: &CaSet,
    at: OffsetDateTime,
) -> Result<Vec<Certificate>, PathError> {
    let mut path = vec![leaf.clone()];
    loop {
        let index = path.len() - 1;
        let current = &path[index];
        check_certificate(current, index, at)?;
        if index > 0 {
            check_issuer(&path, index)?;
        }
        if is_anchor(current, cas) {
            return Ok(path);
        }
        let issuer = match find_issuer(current, cas) {
            Ok(issuer) => issuer.clone(),
            // The topmost CA of the set: the original's trust anchor.
            Err(PathError::IssuerNotFound) if index > 0 => return Ok(path),
            Err(e) => return Err(e),
        };
        if path.len() == MAX_PATH_LEN {
            return Err(PathError::TooLong);
        }
        path.push(issuer);
    }
}

/// Time to validate `leaf`'s path at: `now`, or `leaf`'s notAfter once it has expired (the
/// original's `allowExpired()`: an expired key's own validity is checked elsewhere).
pub fn validation_time(leaf: &Certificate, now: OffsetDateTime) -> OffsetDateTime {
    now.min(time_of(&leaf.tbs_certificate().validity().not_after))
}

/// Whether `cert` is a self-signed certificate of `cas`.
fn is_anchor(cert: &Certificate, cas: &CaSet) -> bool {
    let tbs = cert.tbs_certificate();
    tbs.subject() == tbs.issuer()
        && cas.certs.contains(cert)
        && cert::verify_signature(cert, cert).is_ok()
}

fn find_issuer<'a>(cert: &Certificate, cas: &'a CaSet) -> Result<&'a Certificate, PathError> {
    let mut candidates = cas.issuers_of(cert).peekable();
    if candidates.peek().is_none() {
        return Err(PathError::IssuerNotFound);
    }
    candidates
        .find(|issuer| cert::verify_signature(cert, issuer).is_ok())
        .ok_or(PathError::BadSignature)
}

/// Rules for every certificate of the path: validity and critical extensions.
fn check_certificate(
    cert: &Certificate,
    index: usize,
    at: OffsetDateTime,
) -> Result<(), PathError> {
    let validity = cert.tbs_certificate().validity();
    if at < time_of(&validity.not_before) || time_of(&validity.not_after) < at {
        return Err(PathError::NotValidAt { index });
    }
    let unknown = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.critical && !KNOWN_EXTENSIONS.contains(&e.extn_id));
    match unknown {
        Some(e) => Err(PathError::UnknownCriticalExtension {
            index,
            oid: e.extn_id.to_string(),
        }),
        None => Ok(()),
    }
}

/// Rules for the issuer `path[index]` (`index > 0`): cA, pathLenConstraint, keyCertSign.
fn check_issuer(path: &[Certificate], index: usize) -> Result<(), PathError> {
    let tbs = path[index].tbs_certificate();
    let constraints = match tbs.get_extension::<BasicConstraints>() {
        Ok(Some((_, bc))) if bc.ca => bc,
        _ => return Err(PathError::NotCa { index }),
    };
    if let Some(max) = constraints.path_len_constraint {
        let below = path[1..index].iter().filter(|c| !is_self_issued(c)).count();
        if below > usize::from(max) {
            return Err(PathError::PathLenExceeded { index });
        }
    }
    match tbs.get_extension::<KeyUsage>() {
        Ok(None) => Ok(()),
        Ok(Some((_, ku))) if ku.key_cert_sign() => Ok(()),
        _ => Err(PathError::KeyCertSignMissing { index }),
    }
}

fn is_self_issued(cert: &Certificate) -> bool {
    cert.tbs_certificate().subject() == cert.tbs_certificate().issuer()
}

fn subject_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    match cert
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
    {
        Ok(Some((_, ski))) => Some(ski.0.as_bytes().to_vec()),
        _ => None,
    }
}

fn authority_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    match cert
        .tbs_certificate()
        .get_extension::<AuthorityKeyIdentifier>()
    {
        Ok(Some((_, aki))) => aki.key_identifier.map(|id| id.as_bytes().to_vec()),
        _ => None,
    }
}

/// An X.509 `Time` as an `OffsetDateTime` in UTC.
pub(crate) fn time_of(time: &Time) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time.to_unix_duration()
}
