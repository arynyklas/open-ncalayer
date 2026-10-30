//! Verification reports of a CMS `SignedData`: for each signer, its signature,
//! signingCertificateV2, certificate validity, certification path, revocation and
//! time-stamp, each checked on its own, so that a caller can answer as its clients expect
//! (a signature valid but expired, revoked only after signing, …).
//!
//! - The time a signer is judged at is now, its signingTime, or the genTime of its verified
//!   time-stamp ([`VerifyAt`]); without a signingTime or a verified time-stamp it is now.
//! - The path is built through a CA set at that time (moved into the certificate's validity,
//!   which is a check of its own), or not at all ([`ChainPolicy::Skip`]).
//! - Revocation comes from an OCSP answer the CMS carries (an id-pkix-ocsp-basic attribute —
//!   an `OCSPResponse` or a `BasicOCSPResponse`, in an OCTET STRING or bare — or an
//!   id-ri-ocsp-response in `crls`), from the certificate's OCSP responder, or from its CRL
//!   when the responder fails ([`Revocation`]). A certificate revoked after that time is
//!   good: the signature was made before.
//! - A time-stamp token is verified against the signer's signature (imprint) and its TSA
//!   certificate's path at its genTime.

use super::CmsError;
use super::asn1::{ContentInfo, SignedData, SignerInfo};
use super::verify::{ContentDigests, Signer, certificates};
use crate::ber;
use crate::cert::{self, Certificate};
use crate::crl::{self, CrlError, CrlStatus};
use crate::http::{HttpTransport, NetKind};
use crate::info::{CertInfo, KeyUsageBits, cert_info};
use crate::key::PublicKey;
use crate::ocsp::{self, CertStatus, OcspError};
use crate::oid;
use crate::pkix::{CaSet, PathError, build_path};
use crate::tsp::{self, TspError};
use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader, Tag, Tagged};
use std::time::Duration;
use time::OffsetDateTime;

/// id-ri-ocsp-response (RFC 5940): an `OCSPResponse` among the `crls` of a `SignedData`.
const RI_OCSP_RESPONSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.16.2");

/// Timeout of each CRL download.
const CRL_TIMEOUT: Duration = Duration::from_secs(10);

/// The time a signer is judged at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyAt {
    /// Now.
    Now,
    /// Its signingTime attribute (now without one).
    SigningTime,
    /// The genTime of its verified time-stamp (now without one).
    TspTime,
}

/// The CAs a signer's certification path is built through.
#[derive(Clone, Copy, Debug)]
pub enum ChainPolicy<'a> {
    /// These.
    Through(&'a CaSet),
    /// None: no path is built.
    Skip,
}

/// Where a signer certificate's revocation status comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// Nowhere: not checked.
    None,
    /// Only the OCSP answer the CMS carries.
    EmbeddedOcsp,
    /// The OCSP answer the CMS carries, else the certificate's OCSP responder.
    LiveOcsp,
    /// As [`Revocation::LiveOcsp`], then the certificate's CRL if the responder fails.
    LiveOcspThenCrl,
}

/// How [`report`] judges the signers.
#[derive(Clone, Debug)]
pub struct ReportSpec<'a> {
    /// The time each signer is judged at.
    pub at: VerifyAt,
    /// The CAs of the certification paths (also of the TSA certificates).
    pub chain: ChainPolicy<'a>,
    /// The CAs OCSP responders must chain through, and where a certificate's issuer is
    /// looked for when no path is built.
    pub trust: &'a CaSet,
    /// Where revocation status comes from.
    pub revocation: Revocation,
    /// Only the first signer.
    pub first_signer_only: bool,
    /// Key usage bits the signer certificate must all have: among the certificates its
    /// signer identifier names, the first that has them is the signer's.
    pub require_key_usage: KeyUsageBits,
}

/// The outcome of one check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    /// It holds.
    Ok,
    /// Not checked: not asked for, or nothing to check it on.
    Skipped,
    /// It fails.
    Fail(Problem),
}

/// What is wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// Not readable: a malformed signer, attribute or OCSP answer.
    Malformed,
    /// No content to verify against (a detached signature without its data).
    NoContent,
    /// The signer's certificate is not in the CMS.
    NoSignerCert,
    /// The signature does not verify.
    BadSignature,
    /// The messageDigest does not match the content.
    DigestMismatch,
    /// The signingCertificateV2 does not match the signer's certificate.
    EssCertIdMismatch,
    /// The certificate expired before the time it is judged at.
    Expired,
    /// The certificate is not yet valid at that time.
    NotYetValid,
    /// Issued by none of the CAs.
    UnknownCa,
    /// The path does not hold.
    PathInvalid,
    /// Revoked at or before the time it is judged at.
    Revoked {
        /// When.
        at: OffsetDateTime,
        /// The CRLReason.
        reason: Option<u8>,
    },
    /// The responder does not know the certificate, or answers about another one.
    StatusUnknown,
    /// The OCSP responder is not trusted, or its signature does not verify.
    ResponderUnverified,
    /// The OCSP answer is not current at the time the certificate is judged at.
    OcspStale,
    /// The CRL is not valid.
    CrlInvalid,
    /// The time-stamp does not verify, or its TSA certificate has no path.
    TspInvalid,
    /// The time-stamp is of another signature.
    TspImprintMismatch,
    /// The responder or distribution point could not be asked.
    Net(NetFailure),
}

/// A revocation source that could not be asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFailure {
    /// Which.
    pub stage: NetStage,
    /// How it failed.
    pub kind: NetKind,
    /// The URL asked (empty if the certificate names none).
    pub url: String,
    /// What happened, for the log.
    pub detail: String,
}

/// A revocation source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetStage {
    /// The OCSP responder.
    Ocsp,
    /// The CRL distribution point.
    Crl,
}

/// The time-stamp of a signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TspReport {
    /// Its genTime, if it verifies.
    pub gen_time: Option<OffsetDateTime>,
    /// Whether it verifies.
    pub check: Check,
    /// The TSA certificate, if it verifies.
    pub tsa_cert: Option<Certificate>,
}

/// One signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerReport {
    /// Its certificate, if the CMS has it.
    pub certificate: Option<Certificate>,
    /// Its signingTime attribute.
    pub signing_time: Option<OffsetDateTime>,
    /// The signature over the signed attributes, and messageDigest over the content.
    pub signature: Check,
    /// signingCertificateV2 against the certificate; skipped without the attribute.
    pub ess_cert_id: Check,
    /// The certificate's validity at the time the signer is judged at.
    pub validity: Check,
    /// The certification path.
    pub path: Check,
    /// The certificate's revocation status.
    pub revocation: Check,
    /// The time-stamp token, if the signer has one.
    pub tsp: Option<TspReport>,
}

/// The report of a CMS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The encapsulated content, if the CMS has it.
    pub content: Option<Vec<u8>>,
    /// The signers, in `signerInfos` order.
    pub signers: Vec<SignerReport>,
}

/// Reports on the signers of a DER or BER `ContentInfo{SignedData}` over its encapsulated
/// content, or over `data` when it has none, as `spec` says; `http` asks the revocation
/// sources, `now` is the time of [`VerifyAt::Now`] and the time OCSP and CRL answers must
/// be current at.
///
/// # Errors
///
/// [`CmsError::Malformed`] if the input is not a `ContentInfo{SignedData}` with signers
/// that read as `SignerInfo`s. Whatever is wrong with a signer is in its report.
pub fn report(
    cms: &[u8],
    data: Option<&[u8]>,
    spec: &ReportSpec<'_>,
    http: &dyn HttpTransport,
    now: OffsetDateTime,
) -> Result<Report, CmsError> {
    let der = ber::to_der(cms)?;
    let content_info = ContentInfo::from_der(&der)?;
    if content_info.content_type != oid::SIGNED_DATA {
        return Err(CmsError::Malformed(format!(
            "content type {} is not signedData",
            content_info.content_type
        )));
    }
    let signed_data: SignedData<'_> = content_info.content.decode_as()?;
    let encap = signed_data.encap_content_info;
    let encapsulated = encap.e_content.map(|c| c.as_bytes());
    let digests = ContentDigests::new(encapsulated.or(data));
    let certs = certificates(&signed_data)?;
    let carried = ocsp_in_crls(&signed_data);
    let mut tlvs = signed_data.signer_infos.tlvs()?;
    if tlvs.is_empty() {
        return Err(CmsError::Malformed("no signers".to_owned()));
    }
    if spec.first_signer_only {
        tlvs.truncate(1);
    }
    let signers = tlvs
        .into_iter()
        .enumerate()
        .map(|(index, tlv)| {
            let signer = Signer {
                index,
                info: SignerInfo::from_der(tlv)?,
                content_type: encap.e_content_type,
                digests: &digests,
            };
            Ok(Judge {
                signer: &signer,
                certs: &certs,
                carried: &carried,
                spec,
                http,
                now,
            }
            .report())
        })
        .collect::<Result<Vec<_>, CmsError>>()?;
    Ok(Report {
        content: encapsulated.map(<[u8]>::to_vec),
        signers,
    })
}

/// The id-ri-ocsp-response `OCSPResponse`s among the `crls` of `signed_data`; whatever does
/// not read is left out.
fn ocsp_in_crls(signed_data: &SignedData<'_>) -> Vec<Vec<u8>> {
    let Some(Ok(tlvs)) = signed_data.crls.map(|set| set.tlvs()) else {
        return Vec::new();
    };
    tlvs.into_iter()
        // `[1] IMPLICIT OtherRevocationInfoFormat`.
        .filter(|tlv| tlv.first() == Some(&0xa1))
        .filter_map(|tlv| {
            let other = AnyRef::from_der(tlv).ok()?;
            let mut reader = SliceReader::new(other.value()).ok()?;
            let format: ObjectIdentifier = reader.decode().ok()?;
            let info: AnyRef<'_> = reader.decode().ok()?;
            (format == RI_OCSP_RESPONSE)
                .then(|| info.to_der().ok())
                .flatten()
        })
        .collect()
}

/// Whether `cert` has every key usage bit of `required`.
fn has_usage(cert: &Certificate, required: &KeyUsageBits) -> bool {
    let bits = cert_info(cert).key_usage;
    (bits.digital_signature || !required.digital_signature)
        && (bits.non_repudiation || !required.non_repudiation)
        && (bits.key_encipherment || !required.key_encipherment)
        && (bits.key_agreement || !required.key_agreement)
}

/// One signer being judged.
struct Judge<'s, 'a> {
    signer: &'s Signer<'a>,
    certs: &'s [(Certificate, &'a [u8])],
    carried: &'s [Vec<u8>],
    spec: &'s ReportSpec<'s>,
    http: &'s dyn HttpTransport,
    now: OffsetDateTime,
}

impl Judge<'_, '_> {
    fn report(&self) -> SignerReport {
        let signer = self.signer;
        let found = signer
            .find_cert(self.certs, |c| has_usage(c, &self.spec.require_key_usage))
            .ok()
            .flatten();
        let (cert, cert_der) = (found.map(|(c, _)| c), found.map(|(_, d)| d));
        let attrs = signer.signed_attrs().and_then(|attrs| {
            let alg = signer.algorithm()?;
            let seen = signer.check_signed_attrs(attrs, alg, cert_der, false)?;
            Ok((attrs, alg, seen))
        });

        let signature = match (&attrs, cert) {
            (Err(_), _) => Check::Fail(Problem::Malformed),
            (Ok(_), None) => Check::Fail(Problem::NoSignerCert),
            (Ok((_, _, seen)), Some(_)) if seen.digest_matches.is_none() => {
                Check::Fail(Problem::NoContent)
            }
            (Ok((_, _, seen)), Some(_)) if seen.digest_matches == Some(false) => {
                Check::Fail(Problem::DigestMismatch)
            }
            (Ok((attrs, alg, _)), Some(cert)) => {
                let verified =
                    PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())
                        .map_err(CmsError::Key)
                        .and_then(|key| signer.signature_verifies(*attrs, *alg, &key));
                match verified {
                    Ok(true) => Check::Ok,
                    Ok(false) | Err(_) => Check::Fail(Problem::BadSignature),
                }
            }
        };
        let (signing_time, ess_cert_id) = match &attrs {
            Ok((_, _, seen)) => (
                seen.signing_time,
                match seen.ess_matches {
                    None => Check::Skipped,
                    Some(true) => Check::Ok,
                    Some(false) => Check::Fail(Problem::EssCertIdMismatch),
                },
            ),
            Err(_) => (None, Check::Skipped),
        };

        let tsp = self.tsp();
        let proven = tsp.as_ref().and_then(|t| t.gen_time);
        let at = match self.spec.at {
            VerifyAt::Now => self.now,
            VerifyAt::SigningTime => signing_time.unwrap_or(self.now),
            VerifyAt::TspTime => proven.unwrap_or(self.now),
        };

        let mut report = SignerReport {
            certificate: cert.cloned(),
            signing_time,
            signature,
            ess_cert_id,
            validity: Check::Skipped,
            path: Check::Skipped,
            revocation: Check::Skipped,
            tsp,
        };
        let Some(cert) = cert else {
            return report;
        };
        let info = cert_info(cert);
        report.validity = if at < info.not_before {
            Check::Fail(Problem::NotYetValid)
        } else if at > info.not_after {
            Check::Fail(Problem::Expired)
        } else {
            Check::Ok
        };
        let path = match self.spec.chain {
            ChainPolicy::Through(cas) => Some(build_path(cert, cas, path_time(&info, at))),
            ChainPolicy::Skip => None,
        };
        report.path = match &path {
            None => Check::Skipped,
            Some(Ok(_)) => Check::Ok,
            Some(Err(PathError::IssuerNotFound)) => Check::Fail(Problem::UnknownCa),
            Some(Err(_)) => Check::Fail(Problem::PathInvalid),
        };
        if self.spec.revocation != Revocation::None {
            let issuer = match &path {
                Some(Ok(path)) => path.get(1).cloned(),
                _ => self.issuer_of(cert),
            };
            report.revocation = match issuer {
                Some(issuer) => self.revocation(cert, &issuer, at),
                None => Check::Fail(Problem::UnknownCa),
            };
        }
        report
    }

    /// The issuer of `cert` among the trusted CAs, else among the CMS certificates: one
    /// whose key verifies it.
    fn issuer_of(&self, cert: &Certificate) -> Option<Certificate> {
        self.spec
            .trust
            .issuers_of(cert)
            .chain(self.certs.iter().map(|(c, _)| c))
            .find(|issuer| cert::verify_signature(cert, issuer).is_ok())
            .cloned()
    }

    /// The time-stamp token of the signer, verified, if it has one.
    fn tsp(&self) -> Option<TspReport> {
        let token = match self.signer.timestamp_token() {
            Ok(token) => token?,
            Err(_) => {
                return Some(TspReport {
                    gen_time: None,
                    check: Check::Fail(Problem::TspInvalid),
                    tsa_cert: None,
                });
            }
        };
        let failed = |problem| TspReport {
            gen_time: None,
            check: Check::Fail(problem),
            tsa_cert: None,
        };
        Some(
            match tsp::verify_token_for(&token, self.signer.info.signature.as_bytes()) {
                Ok((tst, tsa)) => {
                    let trusted = match self.spec.chain {
                        ChainPolicy::Through(cas) => build_path(&tsa, cas, tst.gen_time).is_ok(),
                        ChainPolicy::Skip => true,
                    };
                    if trusted {
                        TspReport {
                            gen_time: Some(tst.gen_time),
                            check: Check::Ok,
                            tsa_cert: Some(tsa),
                        }
                    } else {
                        failed(Problem::TspInvalid)
                    }
                }
                Err(TspError::ImprintMismatch) => failed(Problem::TspImprintMismatch),
                Err(_) => failed(Problem::TspInvalid),
            },
        )
    }

    /// The OCSP answers the CMS carries for this signer: its id-pkix-ocsp-basic signed,
    /// then unsigned, attribute, then the `crls` ones.
    fn carried_ocsp(&self) -> Vec<Vec<u8>> {
        let info = &self.signer.info;
        let mut out = Vec::new();
        for attrs in [info.signed_attrs, info.unsigned_attrs] {
            if let Ok(Some(value)) = self.signer.attribute(attrs, oid::OCSP_BASIC) {
                let bytes = if value.tag() == Tag::OctetString {
                    Some(value.value().to_vec())
                } else {
                    value.to_der().ok()
                };
                out.extend(bytes);
            }
        }
        out.extend(self.carried.iter().cloned());
        out
    }

    fn revocation(&self, cert: &Certificate, issuer: &Certificate, at: OffsetDateTime) -> Check {
        let carried = self.carried_ocsp();
        if !carried.is_empty() {
            let mut first_problem = None;
            for response in &carried {
                match ocsp::check_embedded(response, cert, issuer, self.spec.trust, at) {
                    Ok(answer) => return decide(answer.status, at),
                    Err(e) => {
                        first_problem.get_or_insert_with(|| ocsp_problem(&e));
                    }
                }
            }
            return Check::Fail(first_problem.unwrap_or(Problem::StatusUnknown));
        }
        if self.spec.revocation == Revocation::EmbeddedOcsp {
            return Check::Fail(Problem::StatusUnknown);
        }
        let url = ocsp::ocsp_url(cert).unwrap_or_default();
        let ocsp = match ocsp::check_answer(
            cert,
            issuer,
            self.spec.trust,
            self.http,
            self.now,
            ocsp::TIMEOUT,
        ) {
            Ok(answer) => return decide(answer.status, at),
            Err(e) if is_network(&e) => Problem::Net(NetFailure {
                stage: NetStage::Ocsp,
                kind: e.kind(),
                url,
                detail: e.to_string(),
            }),
            Err(e) => ocsp_problem(&e),
        };
        if self.spec.revocation != Revocation::LiveOcspThenCrl {
            return Check::Fail(ocsp);
        }
        match crl::fetch_for(cert, issuer, self.http, CRL_TIMEOUT, self.now) {
            Ok((_, CrlStatus::Good)) => Check::Ok,
            Ok((_, CrlStatus::Revoked { time, reason })) => {
                decide(CertStatus::Revoked { time, reason }, at)
            }
            Err(e @ (CrlError::NoUrl | CrlError::Http(_) | CrlError::HttpStatus(_))) => {
                Check::Fail(Problem::Net(NetFailure {
                    stage: NetStage::Crl,
                    kind: e.kind(),
                    url: crl::crl_urls(cert).into_iter().next().unwrap_or_default(),
                    detail: e.to_string(),
                }))
            }
            Err(_) => Check::Fail(Problem::CrlInvalid),
        }
    }
}

/// A status as of `at`: a revocation after it does not count.
fn decide(status: CertStatus, at: OffsetDateTime) -> Check {
    match status {
        CertStatus::Good => Check::Ok,
        CertStatus::Revoked { time, reason } if time <= at => {
            Check::Fail(Problem::Revoked { at: time, reason })
        }
        CertStatus::Revoked { .. } => Check::Ok,
        CertStatus::Unknown => Check::Fail(Problem::StatusUnknown),
    }
}

/// Whether the responder could not be asked (or would not answer), rather than answered
/// wrong.
fn is_network(e: &OcspError) -> bool {
    matches!(
        e,
        OcspError::NoUrl
            | OcspError::Http(_)
            | OcspError::HttpStatus(_)
            | OcspError::ContentType(_)
            | OcspError::NotSuccessful(_)
    )
}

/// What an OCSP answer that fails the check has wrong.
fn ocsp_problem(e: &OcspError) -> Problem {
    match e {
        OcspError::NoCerts
        | OcspError::ResponderNotFound
        | OcspError::ResponderNotTrusted(_)
        | OcspError::OcspSigningMissing
        | OcspError::NoCheckMissing
        | OcspError::BadSignature(_) => Problem::ResponderUnverified,
        OcspError::ThisUpdate | OcspError::NextUpdate => Problem::OcspStale,
        OcspError::CertIdMismatch | OcspError::NotSuccessful(_) => Problem::StatusUnknown,
        _ => Problem::Malformed,
    }
}

/// Time to build the certificate's path at: `at` moved into its validity, so the path is
/// judged on the CAs and the certificate's own period by the validity check.
fn path_time(info: &CertInfo, at: OffsetDateTime) -> OffsetDateTime {
    // Not `clamp`: a hostile certificate may end before it starts.
    at.max(info.not_before).min(info.not_after)
}
