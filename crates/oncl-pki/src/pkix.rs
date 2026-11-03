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

    /// The certificates, in set order.
    pub fn certs(&self) -> &[Certificate] {
        &self.certs
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
    Ok(build_borrowed_path(
        leaf,
        CaView {
            first: cas.certs(),
            second: &[],
            selected: &[],
        },
        at,
        None,
        None,
    )?
    .to_owned())
}

/// Build with explicit host anchors; candidate certificates never grant trust.
/// Unlike compatibility build_path, a topmost untrusted CA is not an anchor.
pub fn build_anchored_path(
    leaf: &Certificate,
    anchors: &CaSet,
    candidates: &[Certificate],
    at: OffsetDateTime,
) -> Result<Vec<Certificate>, PathError> {
    Ok(build_borrowed_path(
        leaf,
        CaView {
            first: anchors.certs(),
            second: candidates,
            selected: &[],
        },
        at,
        Some(anchors),
        None,
    )?
    .to_owned())
}

/// Borrowed format-derived candidate view, using the same PKIX search and
/// signature/path checks as the complete-bundle entry point.
pub(crate) fn build_anchored_path_selected(
    leaf: &Certificate,
    anchors: &CaSet,
    candidates: &[&Certificate],
    at: OffsetDateTime,
    max_len: usize,
) -> Result<Vec<Certificate>, PathError> {
    if max_len == 0 {
        return Err(PathError::TooLong);
    }
    Ok(build_borrowed_path(
        leaf,
        CaView {
            first: anchors.certs(),
            second: &[],
            selected: candidates,
        },
        at,
        Some(anchors),
        Some(max_len.min(MAX_PATH_LEN)),
    )?
    .to_owned())
}
#[derive(Clone, Copy)]
struct CaView<'a> {
    first: &'a [Certificate],
    second: &'a [Certificate],
    selected: &'a [&'a Certificate],
}
impl<'a> CaView<'a> {
    fn certificates(self) -> impl Iterator<Item = &'a Certificate> + Clone {
        self.first
            .iter()
            .chain(self.second.iter())
            .chain(self.selected.iter().copied())
    }
    fn contains(self, certificate: &Certificate) -> bool {
        self.certificates()
            .any(|candidate| candidate == certificate)
    }
    fn issuer(self, certificate: &Certificate) -> Result<&'a Certificate, PathError> {
        let name = certificate.tbs_certificate().issuer();
        let aki = authority_key_id(certificate);
        let mut named = false;
        // Same stable AKI preference as CaSet::issuers_of, without a Vec of
        // names or any deep copy of host trust. SKI reads borrow extension DER.
        for preferred in [true, false] {
            if aki.is_none() && !preferred {
                break;
            }
            for issuer in self
                .certificates()
                .filter(|issuer| issuer.tbs_certificate().subject() == name)
            {
                named = true;
                let matches = aki
                    .as_deref()
                    .is_none_or(|id| subject_key_id_ref(issuer) == Some(id));
                if matches == preferred && cert::verify_signature(certificate, issuer).is_ok() {
                    return Ok(issuer);
                }
            }
        }
        Err(if named {
            PathError::BadSignature
        } else {
            PathError::IssuerNotFound
        })
    }
}
struct BorrowedPath<'a> {
    certificates: [&'a Certificate; MAX_PATH_LEN],
    len: usize,
}
impl BorrowedPath<'_> {
    fn as_slice(&self) -> &[&Certificate] {
        &self.certificates[..self.len]
    }
    fn to_owned(&self) -> Vec<Certificate> {
        self.as_slice()
            .iter()
            .map(|certificate| (*certificate).clone())
            .collect()
    }
}
fn build_borrowed_path<'a>(
    leaf: &'a Certificate,
    cas: CaView<'a>,
    at: OffsetDateTime,
    anchors: Option<&CaSet>,
    limit: Option<usize>,
) -> Result<BorrowedPath<'a>, PathError> {
    let mut path = BorrowedPath {
        certificates: [leaf; MAX_PATH_LEN],
        len: 1,
    };
    loop {
        let index = path.len - 1;
        let current = path.certificates[index];
        check_certificate(current, index, at)?;
        if index > 0 {
            check_issuer(path.as_slice(), index)?;
        }
        let anchor = anchors.map_or_else(
            || {
                is_self_issued(current)
                    && cas.contains(current)
                    && cert::verify_signature(current, current).is_ok()
            },
            |roots| roots.certs.contains(current),
        );
        if anchor {
            return Ok(path);
        }
        if limit.is_some_and(|limit| path.len >= limit) {
            return Err(PathError::TooLong);
        }
        let issuer = match cas.issuer(current) {
            Ok(issuer) => issuer,
            Err(PathError::IssuerNotFound) if index > 0 && anchors.is_none() => return Ok(path),
            Err(error) => return Err(error),
        };
        if path.len == MAX_PATH_LEN {
            return Err(PathError::TooLong);
        }
        path.certificates[path.len] = issuer;
        path.len += 1;
    }
}

/// Owns only the selected path, with pre-copy admission held through status
/// processing. The complete host trust store remains borrowed.
pub(crate) struct AdmittedPath {
    certificates: Vec<Certificate>,
    _memory: crate::resource::ResourceReservation,
    _metadata: crate::resource::ResourceReservation,
}
impl std::ops::Deref for AdmittedPath {
    type Target = [Certificate];
    fn deref(&self) -> &Self::Target {
        &self.certificates
    }
}
pub(crate) enum AdmittedPathError {
    Path,
    Processing(crate::resource::ProcessingError),
}
pub(crate) fn build_anchored_path_admitted(
    leaf: &Certificate,
    anchors: &CaSet,
    candidates: &[Certificate],
    at: OffsetDateTime,
    scope: &crate::resource::ResourceScope,
) -> Result<AdmittedPath, AdmittedPathError> {
    use crate::resource::ProcessingError;
    use der::Encode;
    scope.checkpoint().map_err(AdmittedPathError::Processing)?;
    // Issuer selection verifies one borrowed candidate at a time. Admit that
    // candidate's key-decoding scratch before crypto, without copying or
    // charging every unrelated host certificate/extension as owned storage.
    let mut key_bytes = 0u64;
    for certificate in anchors.certs().iter().chain(candidates.iter()) {
        let length = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .encoded_len()
            .map_err(|_| AdmittedPathError::Path)?;
        key_bytes = key_bytes.max(u64::from(u32::from(length)));
        scope.checkpoint().map_err(AdmittedPathError::Processing)?;
    }
    let _key_memory = scope
        .reserve_memory(
            key_bytes
                .checked_mul(128)
                .and_then(|bytes| bytes.checked_add(4096))
                .ok_or(AdmittedPathError::Processing(ProcessingError::MemoryLimit))?,
        )
        .map_err(AdmittedPathError::Processing)?;
    let _key_metadata = scope
        .reserve_metadata(
            key_bytes
                .checked_mul(16)
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or(AdmittedPathError::Processing(
                    ProcessingError::MetadataLimit,
                ))?,
        )
        .map_err(AdmittedPathError::Processing)?;
    let path = build_borrowed_path(
        leaf,
        CaView {
            first: anchors.certs(),
            second: candidates,
            selected: &[],
        },
        at,
        Some(anchors),
        None,
    )
    .map_err(|_| AdmittedPathError::Path)?;
    let mut bytes = (path.len * std::mem::size_of::<Certificate>()) as u64;
    for certificate in path.as_slice() {
        let length = certificate
            .encoded_len()
            .map_err(|_| AdmittedPathError::Path)?;
        bytes = bytes
            .checked_add(u64::from(u32::from(length)))
            .ok_or(AdmittedPathError::Processing(ProcessingError::MemoryLimit))?;
    }
    let memory = scope
        .reserve_memory(
            bytes
                .checked_mul(128)
                .ok_or(AdmittedPathError::Processing(ProcessingError::MemoryLimit))?,
        )
        .map_err(AdmittedPathError::Processing)?;
    let metadata = scope
        .reserve_metadata(bytes.checked_mul(16).ok_or(AdmittedPathError::Processing(
            ProcessingError::MetadataLimit,
        ))?)
        .map_err(AdmittedPathError::Processing)?;
    scope.checkpoint().map_err(AdmittedPathError::Processing)?;
    Ok(AdmittedPath {
        certificates: path.to_owned(),
        _memory: memory,
        _metadata: metadata,
    })
}

fn subject_key_id_ref(certificate: &Certificate) -> Option<&[u8]> {
    use der::Decode;
    let extension = certificate
        .tbs_certificate()
        .extensions()?
        .iter()
        .find(|extension| {
            extension.extn_id == der::asn1::ObjectIdentifier::new_unwrap("2.5.29.14")
        })?;
    Some(
        <&der::asn1::OctetStringRef>::from_der(extension.extn_value.as_bytes())
            .ok()?
            .as_bytes(),
    )
}

/// Time to validate `leaf`'s path at: `now`, or `leaf`'s notAfter once it has expired (the
/// original's `allowExpired()`: an expired key's own validity is checked elsewhere).
pub fn validation_time(leaf: &Certificate, now: OffsetDateTime) -> OffsetDateTime {
    now.min(time_of(&leaf.tbs_certificate().validity().not_after))
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
fn check_issuer<T: std::borrow::Borrow<Certificate>>(
    path: &[T],
    index: usize,
) -> Result<(), PathError> {
    let certificate: &Certificate = path[index].borrow();
    let tbs = certificate.tbs_certificate();
    let constraints = match tbs.get_extension::<BasicConstraints>() {
        Ok(Some((_, bc))) if bc.ca => bc,
        _ => return Err(PathError::NotCa { index }),
    };
    if let Some(max) = constraints.path_len_constraint {
        let below = path[1..index]
            .iter()
            .filter(|certificate| !is_self_issued((*certificate).borrow()))
            .count();
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

/// The subjectKeyIdentifier of `cert`, if it has a well-formed one.
pub fn subject_key_id(cert: &Certificate) -> Option<Vec<u8>> {
    match cert
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
    {
        Ok(Some((_, ski))) => Some(ski.0.as_bytes().to_vec()),
        _ => None,
    }
}

/// The keyIdentifier of `cert`'s authorityKeyIdentifier, if it has a well-formed one.
pub fn authority_key_id(cert: &Certificate) -> Option<Vec<u8>> {
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
