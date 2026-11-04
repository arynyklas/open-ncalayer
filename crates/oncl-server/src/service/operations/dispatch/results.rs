//! Wire projections of SDK reports. One implementation shared by the sequential
//! `/v1/operations` dispatch and the closed `/v1/batch` route. Each projection also
//! returns the bounded metadata bytes the caller reserves under the original scope.
use super::*;
use oncl_api::dto::JwsFormat;
use oncl_core::{
    ExtractionReport, HashReport, InspectionReport, OperationReport, TimestampReport,
    VerificationReport,
    jose::{DecodedJwt, JoseWriteReport, JwsVerificationReport, JwtVerificationReport},
};

pub(in crate::service::operations) type Projection = (OperationResult, u64);

pub(in crate::service::operations) fn hash(
    algorithm: HashAlgorithm,
    report: &HashReport,
    bytes_in: u64,
) -> Projection {
    (
        OperationResult::Hash {
            algorithm,
            digest: crate::auth::encode(report.digest.as_bytes()),
            bytes_in,
        },
        512,
    )
}
pub(in crate::service::operations) fn verification(
    profile: VerifyProfile,
    report: &VerificationReport,
) -> Result<Projection, ProcessingError> {
    // The host owns this actual scoped report until its bounded wire projection has
    // been serialized under the same context reservation.
    let bytes = (report.signers.len() as u64)
        .checked_mul(8192)
        .and_then(|n| n.checked_add(512))
        .ok_or(ProcessingError::MetadataLimit)?;
    Ok((
        OperationResult::Verification {
            profile,
            verdict: verdict(report.verdict),
            policy: policy_name(report.policy),
            checked_at_unix: report.checked_at.unix_timestamp(),
            signers: report.signers.iter().map(signer).collect(),
        },
        bytes,
    ))
}
pub(in crate::service::operations) fn extraction(
    artifact: Option<String>,
    report: &ExtractionReport,
) -> Projection {
    (
        OperationResult::Extraction {
            artifact,
            bytes_written: report.bytes_written,
        },
        512,
    )
}
pub(in crate::service::operations) fn signing(
    profile: SignKind,
    artifact: Option<String>,
    report: &OperationReport,
) -> Result<Projection, ProcessingError> {
    let signers: Vec<_> = report.signer_states().map(applied).collect();
    let bytes = (signers.len() as u64 * 16)
        .checked_add(512)
        .ok_or(ProcessingError::MetadataLimit)?;
    Ok((
        OperationResult::Signing {
            profile,
            artifact,
            bytes_in: report.bytes_in,
            bytes_out: report.bytes_out,
            signers,
        },
        bytes,
    ))
}
pub(in crate::service::operations) fn extension(
    profile: ExtendKind,
    artifact: Option<String>,
    report: &OperationReport,
) -> Result<Projection, ProcessingError> {
    let verdicts: Vec<&'static str> = report
        .validation_reports()
        .map(|reports| reports.iter().map(|r| verdict(r.verdict)).collect())
        .unwrap_or_default();
    let bytes = (verdicts.len() as u64 * 16)
        .checked_add(512)
        .ok_or(ProcessingError::MetadataLimit)?;
    Ok((
        OperationResult::Extension {
            profile,
            artifact,
            bytes_in: report.bytes_in,
            bytes_out: report.bytes_out,
            verdicts,
        },
        bytes,
    ))
}
pub(in crate::service::operations) fn inspection(
    label: &'static str,
    report: &InspectionReport,
) -> Result<Projection, ProcessingError> {
    let entries: Vec<InspectedEntry> = report
        .entries()
        .iter()
        .map(|entry| InspectedEntry {
            alias: entry.alias().map(str::to_owned),
            subject_cn: entry.subject_cn().map(str::to_owned),
            serial_hex: entry.serial_hex().map(str::to_owned),
            sha256: entry
                .fingerprint()
                .map(|value| crate::auth::encode(value.as_bytes())),
            signature_algorithm_oid: entry.signature_algorithm_oid().map(str::to_owned),
            public_key_algorithm_oid: entry.public_key_algorithm_oid().map(str::to_owned),
            not_before_unix: entry.not_before().map(|t| t.unix_timestamp()),
            not_after_unix: entry.not_after().map(|t| t.unix_timestamp()),
        })
        .collect();
    let cms = report.cms().map(|facts| InspectedCms {
        detached: facts.detached(),
        content_len: facts.content_len(),
        signer_count: facts.signer_count(),
    });
    let bytes = (entries.len() as u64)
        .checked_mul(1024)
        .and_then(|n| n.checked_add(512))
        .ok_or(ProcessingError::MetadataLimit)?;
    Ok((
        OperationResult::Inspection {
            target: label,
            bytes_in: report.bytes_in(),
            integrity: report.container_integrity().map(|i| format!("{i:?}")),
            entries,
            cms,
        },
        bytes,
    ))
}
/// The token length is the artifact length; `bytes_in`/`bytes_out` of the
/// resource scope are deltas, not token sizes.
pub(in crate::service::operations) fn stamping(
    artifact: Option<String>,
    report: &TimestampReport,
) -> Projection {
    let token_len = report.facts().token().len() as u64;
    (
        OperationResult::Stamping {
            artifact,
            bytes_in: report.bytes_in(),
            bytes_out: token_len,
            timestamp: timestamp_facts(report),
        },
        1024,
    )
}
pub(in crate::service::operations) fn stamp_verification(report: &TimestampReport) -> Projection {
    (
        OperationResult::StampVerification {
            bytes_in: report.bytes_in(),
            timestamp: timestamp_facts(report),
        },
        1024,
    )
}
pub(in crate::service::operations) fn jose_written(
    serialization: JwsFormat,
    artifact: Option<String>,
    report: &JoseWriteReport,
) -> Projection {
    let signers = vec![applied(report.applied); report.signer_count];
    let bytes = 512 + signers.len() as u64 * 16;
    (
        OperationResult::Jws {
            serialization,
            artifact,
            bytes_in: report.bytes_in,
            bytes_out: report.bytes_out,
            signers,
        },
        bytes,
    )
}
pub(in crate::service::operations) fn jws_verification(
    report: &JwsVerificationReport,
) -> Projection {
    let signers = jws_signers(report);
    let bytes = 512 + signers.len() as u64 * 8192;
    (
        OperationResult::JwsVerification {
            verdict: verdict(report.verdict()),
            policy: policy_name(report.policy()),
            checked_at_unix: report.checked_at().unix_timestamp(),
            signers,
        },
        bytes,
    )
}
pub(in crate::service::operations) fn jwt_decoded(decoded: &DecodedJwt) -> Projection {
    let claims = String::from_utf8_lossy(decoded.payload()).into_owned();
    let bytes = 512 + claims.len() as u64;
    (
        OperationResult::JwtDecoded {
            verified: decoded.is_verified(),
            issuer: decoded.issuer().map(str::to_owned),
            audience: decoded.audience().map(str::to_owned).collect(),
            expiration_unix: decoded.expiration(),
            claims,
        },
        bytes,
    )
}
pub(in crate::service::operations) fn jwt_verification(
    report: &JwtVerificationReport,
) -> Projection {
    let signers = jws_signers(report.jws());
    let claims = String::from_utf8_lossy(report.jws().payload()).into_owned();
    let bytes = 512 + claims.len() as u64 + signers.len() as u64 * 8192;
    (
        OperationResult::JwtVerification {
            verdict: verdict(report.verdict()),
            signature_verdict: verdict(report.jws().verdict()),
            claims_verdict: verdict(report.claims().verdict()),
            claim_failures: report
                .claims()
                .failures()
                .iter()
                .map(|f| format!("{f:?}"))
                .collect(),
            checked_at_unix: report.claims().checked_at(),
            signers,
            claims,
        },
        bytes,
    )
}
