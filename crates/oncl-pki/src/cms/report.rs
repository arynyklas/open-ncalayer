//! Signer facts of a CMS `SignedData`: for each signer, its certificate, signingTime,
//! signature, signingCertificateV2 and time-stamp token, each checked on its own.
//!
//! This is the single signer-intake of the project: [`crate::validation::validate_cms`] and
//! the plugin `cms_verify` capability both start from it. It decides nothing about trust,
//! validity, certification paths or revocation: those belong to the shared validator, and
//! a caller that needs them calls it (see [`crate::validation`]).
//!
//! - A time-stamp token is verified against the signer's signature (imprint) and its own
//!   signature; its TSA certificate's path and status are the validator's business, so a
//!   `genTime` here is a claim of the token, not a [`crate::evidence::ProofTime`].

use super::CmsError;
use super::asn1::{ContentInfo, SignedData, SignerInfo};
use super::verify::{ContentDigests, Signer, certificates};
use crate::ber;
use crate::cert::Certificate;
use crate::info::KeyUsageBits;
use crate::info::cert_info;
use crate::key::PublicKey;
use crate::oid;
use crate::tsp::{self, TspError};
use der::{Decode, Reader, SliceReader};
use time::OffsetDateTime;

/// Which signers are read, and which certificate counts as a signer's.
#[derive(Clone, Debug, Default)]
pub struct ReportSpec {
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
    /// Not checked: nothing to check it on.
    Skipped,
    /// It fails.
    Fail(Problem),
}

/// What is wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// Not readable: a malformed signer or attribute.
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
    /// The time-stamp does not verify.
    TspInvalid,
    /// The time-stamp is of another signature.
    TspImprintMismatch,
}

/// The time-stamp of a signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TspReport {
    /// Its genTime, if the token verifies.
    pub gen_time: Option<OffsetDateTime>,
    /// Whether the token verifies.
    pub check: Check,
    /// The TSA certificate, if the token verifies.
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
    /// The time-stamp token, if the signer has one.
    pub tsp: Option<TspReport>,
}

/// The facts of a CMS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The encapsulated content, if the CMS has it.
    pub content: Option<Vec<u8>>,
    /// The signers, in `signerInfos` order.
    pub signers: Vec<SignerReport>,
}

/// The facts of the signers of a DER or BER `ContentInfo{SignedData}` over its
/// encapsulated content, or over `data` when it has none.
///
/// # Errors
///
/// [`CmsError::Malformed`] if the input is not a `ContentInfo{SignedData}` with signers
/// that read as `SignerInfo`s. Whatever is wrong with a signer is in its report.
pub fn report(cms: &[u8], data: Option<&[u8]>, spec: &ReportSpec) -> Result<Report, CmsError> {
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
    let mut signers = Vec::new();
    let _flow = visit_parsed_signers(&signed_data, &digests, spec, &mut |signer| {
        signers.push(signer);
        std::ops::ControlFlow::<()>::Continue(())
    })?;
    Ok(Report {
        content: encapsulated.map(<[u8]>::to_vec),
        signers,
    })
}

/// A borrowed view cannot outlive the reserved metadata owner (or the bounded
/// legacy caller's already charged normalization buffer).
pub(crate) struct PreparedCms<'a> {
    encoded: &'a [u8],
    digests: ContentDigests<'a>,
}
impl<'a> PreparedCms<'a> {
    pub(crate) fn from_content(
        encoded: &'a [u8],
        detached: Option<&'a [u8]>,
    ) -> Result<Self, CmsError> {
        let info = ContentInfo::from_der(encoded)?;
        let data: SignedData<'_> = info.content.decode_as()?;
        Ok(Self {
            encoded,
            digests: ContentDigests::new(
                data.encap_content_info
                    .e_content
                    .map(|content| content.as_bytes())
                    .or(detached),
            ),
        })
    }
    pub(crate) fn from_digests(
        encoded: &'a [u8],
        values: [Option<crate::digest::DigestValue>; 4],
    ) -> Self {
        Self {
            encoded,
            digests: ContentDigests::from_values(values),
        }
    }
    pub(crate) fn encoded(&self) -> &'a [u8] {
        self.encoded
    }
    pub(crate) fn signed_data(&self) -> Result<SignedData<'a>, CmsError> {
        let info = ContentInfo::from_der(self.encoded)?;
        if info.content_type != oid::SIGNED_DATA {
            return Err(CmsError::Malformed("content is not SignedData".to_owned()));
        }
        Ok(info.content.decode_as()?)
    }
    pub(crate) fn signer_count(&self) -> Result<usize, CmsError> {
        let data = self.signed_data()?;
        let mut reader = SliceReader::new(data.signer_infos.0)?;
        let mut count = 0usize;
        while !reader.is_finished() {
            let _ = reader.tlv_bytes()?;
            count = count
                .checked_add(1)
                .ok_or_else(|| CmsError::Malformed("too many signers".to_owned()))?;
        }
        if count == 0 {
            return Err(CmsError::Malformed("no signers".to_owned()));
        }
        Ok(count)
    }
    pub(crate) fn certificates(&self) -> Result<Vec<Certificate>, CmsError> {
        Ok(certificates(&self.signed_data()?)?
            .into_iter()
            .map(|(certificate, _)| certificate)
            .collect())
    }
}

pub(crate) fn visit_prepared_signers<B>(
    prepared: &PreparedCms<'_>,
    spec: &ReportSpec,
    mut visit: impl FnMut(SignerReport) -> std::ops::ControlFlow<B>,
) -> Result<std::ops::ControlFlow<B>, CmsError> {
    visit_parsed_signers(
        &prepared.signed_data()?,
        &prepared.digests,
        spec,
        &mut visit,
    )
}

fn visit_parsed_signers<B>(
    signed_data: &SignedData<'_>,
    digests: &ContentDigests<'_>,
    spec: &ReportSpec,
    visit: &mut impl FnMut(SignerReport) -> std::ops::ControlFlow<B>,
) -> Result<std::ops::ControlFlow<B>, CmsError> {
    let certs = certificates(signed_data)?;
    let mut reader = SliceReader::new(signed_data.signer_infos.0)?;
    let mut index = 0usize;
    if reader.is_finished() {
        return Err(CmsError::Malformed("no signers".to_owned()));
    }
    while !reader.is_finished() {
        let signer = Signer {
            index,
            info: SignerInfo::from_der(reader.tlv_bytes()?)?,
            content_type: signed_data.encap_content_info.e_content_type,
            digests,
        };
        let report = Judge {
            signer: &signer,
            certs: &certs,
            spec,
        }
        .report();
        if let std::ops::ControlFlow::Break(cause) = visit(report) {
            return Ok(std::ops::ControlFlow::Break(cause));
        }
        if spec.first_signer_only {
            break;
        }
        index += 1;
    }
    Ok(std::ops::ControlFlow::Continue(()))
}

/// Whether `cert` has every key usage bit of `required`.
fn has_usage(cert: &Certificate, required: &KeyUsageBits) -> bool {
    let bits = cert_info(cert).key_usage;
    (bits.digital_signature || !required.digital_signature)
        && (bits.non_repudiation || !required.non_repudiation)
        && (bits.key_encipherment || !required.key_encipherment)
        && (bits.key_agreement || !required.key_agreement)
}

/// One signer being read.
struct Judge<'s, 'a> {
    signer: &'s Signer<'a>,
    certs: &'s [(Certificate, &'a [u8])],
    spec: &'s ReportSpec,
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
        SignerReport {
            certificate: cert.cloned(),
            signing_time,
            signature,
            ess_cert_id,
            tsp: self.tsp(),
        }
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
                Ok((tst, tsa)) => TspReport {
                    gen_time: Some(tst.gen_time),
                    check: Check::Ok,
                    tsa_cert: Some(tsa),
                },
                Err(TspError::ImprintMismatch) => failed(Problem::TspImprintMismatch),
                Err(_) => failed(Problem::TspInvalid),
            },
        )
    }
}
