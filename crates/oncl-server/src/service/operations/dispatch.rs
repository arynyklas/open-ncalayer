use super::*;
use oncl_api::dto::{SignerChecks, VerifyProfile};
use oncl_pki::{
    evidence::{AdesLevel, EvidenceLimits},
    validation::{CheckStatus, TimeBasis, ValidationPolicy, Verdict},
};

pub(super) fn action(operation: &Operation) -> Action {
    match operation {
        Operation::Hash { .. } => Action::Hash,
        Operation::Verify { .. } => Action::Verify,
        Operation::Extract { .. } => Action::Extract,
    }
}
pub(super) fn inputs(operation: &Operation) -> impl Iterator<Item = &str> {
    let names = match operation {
        Operation::Hash { input, .. } => [Some(input.as_str()), None],
        Operation::Extract { input } => [Some(input.as_str()), None],
        Operation::Verify {
            input, detached, ..
        } => [Some(input.as_str()), detached.as_deref()],
    };
    names.into_iter().flatten()
}
pub(super) fn evidence_limits(limits: &oncl_pki::resource::ResourceLimits) -> EvidenceLimits {
    EvidenceLimits {
        max_items: 128,
        max_bytes: limits.metadata_bytes.min(16 << 20),
        max_item_bytes: limits.metadata_bytes.min(2 << 20),
        max_chain_len: 8,
        max_proofs: 16,
        max_coverage_parts: 4096,
        max_coverage_bytes: limits.input_bytes,
    }
}
fn verify_request(profile: VerifyProfile, limits: EvidenceLimits) -> oncl_core::VerifyRequest {
    use VerifyProfile::*;
    match profile {
        Cms => oncl_core::VerifyRequest::cms(),
        Pdf => oncl_core::VerifyRequest::pdf(),
        Xml => oncl_core::VerifyRequest::xml(),
        XmlKalkan => oncl_core::VerifyRequest::xml_kalkan(),
        CadesB => oncl_core::VerifyRequest::cades(AdesLevel::B, limits),
        CadesT => oncl_core::VerifyRequest::cades(AdesLevel::T, limits),
        CadesLt => oncl_core::VerifyRequest::cades(AdesLevel::Lt, limits),
        CadesLta => oncl_core::VerifyRequest::cades(AdesLevel::Lta, limits),
        PadesB => oncl_core::VerifyRequest::pades(AdesLevel::B, limits),
        PadesT => oncl_core::VerifyRequest::pades(AdesLevel::T, limits),
        PadesLt => oncl_core::VerifyRequest::pades(AdesLevel::Lt, limits),
        PadesLta => oncl_core::VerifyRequest::pades(AdesLevel::Lta, limits),
    }
}
pub(super) fn verdict(value: Verdict) -> &'static str {
    match value {
        Verdict::Valid => "Valid",
        Verdict::Invalid => "Invalid",
        Verdict::Indeterminate => "Indeterminate",
    }
}
fn check(value: CheckStatus) -> &'static str {
    match value {
        CheckStatus::Passed => "Passed",
        CheckStatus::Failed => "Failed",
        CheckStatus::Unavailable => "Unavailable",
        CheckStatus::NotApplicable => "NotApplicable",
    }
}
pub(super) fn level(value: AdesLevel) -> &'static str {
    match value {
        AdesLevel::B => "B",
        AdesLevel::T => "T",
        AdesLevel::Lt => "LT",
        AdesLevel::Lta => "LTA",
    }
}
pub(super) fn signer(value: &oncl_pki::validation::SignerValidation) -> SignerChecks {
    let (time_basis, time) = match value.time_basis {
        TimeBasis::Current(t) => ("Current", t),
        TimeBasis::VerifiedTimestamp(t) => ("VerifiedTimestamp", t),
        TimeBasis::ClaimedSigningTime(t) => ("ClaimedSigningTime", t),
    };
    SignerChecks {
        signature: check(value.signature),
        chain: check(value.chain),
        validity: check(value.validity),
        revocation: check(value.revocation),
        timestamp: check(value.timestamp),
        key_usage: check(value.key_usage),
        time_basis,
        time_basis_unix: time.unix_timestamp(),
        claimed_signing_time_unix: value.claimed_signing_time.map(|t| t.unix_timestamp()),
        ades_level: value.ades_level.map(level),
        reasons: value.reasons.iter().map(|r| format!("{r:?}")).collect(),
    }
}
pub(super) struct ArtifactSink<'a> {
    pub store: &'a Arc<super::artifact::ArtifactStore>,
    pub owner: &'a Arc<super::ownership::OperationOutput>,
    pub id: String,
}
pub(super) fn run(
    operation: Operation,
    documents: &mut intake::Documents,
    engine: &Engine,
    ctx: &mut OperationContext,
    output: Option<ArtifactSink<'_>>,
) -> Result<
    (
        OperationResult,
        ResourceReservation,
        Option<super::artifact::FinishedArtifact>,
    ),
    OperationError,
> {
    match operation {
        Operation::Hash {
            algorithm: hash,
            input,
        } => {
            let mut document = documents.take(&input)?;
            let bytes_in = document.len();
            let mut reader = document.reader(ctx.resources())?;
            let report = engine.hash(algorithm(hash), reader.source(), ctx)?;
            reader.finish()?;
            let projection = ctx.resources().reserve_metadata(512)?;
            Ok((
                OperationResult::Hash {
                    algorithm: hash,
                    digest: crate::auth::encode(report.digest.as_bytes()),
                    bytes_in,
                },
                projection,
                None,
            ))
        }
        Operation::Verify {
            profile,
            input,
            detached,
        } => {
            let mut document = documents.take(&input)?;
            let mut detached = detached.map(|name| documents.take(&name)).transpose()?;
            let mut reader = document.reader(ctx.resources())?;
            let mut detached_reader = detached
                .as_mut()
                .map(|input| input.reader(ctx.resources()))
                .transpose()?;
            let request = verify_request(profile, evidence_limits(ctx.resources().limits()));
            let report = engine.verify(
                &request,
                reader.source(),
                detached_reader.as_mut().map(intake::DocumentReader::source),
                ctx,
            )?;
            reader.finish()?;
            if let Some(reader) = &mut detached_reader {
                reader.finish()?;
            }
            // The host owns this actual scoped report until its bounded wire
            // projection has been serialized under the same context reservation.
            let projection = ctx.resources().reserve_metadata(
                (report.signers.len() as u64)
                    .checked_mul(8192)
                    .and_then(|n| n.checked_add(512))
                    .ok_or(ProcessingError::MetadataLimit)?,
            )?;
            Ok((
                OperationResult::Verification {
                    profile,
                    verdict: verdict(report.verdict),
                    policy: match report.policy {
                        ValidationPolicy::StrictOnline => "StrictOnline",
                        ValidationPolicy::OfflineReport => "OfflineReport",
                        ValidationPolicy::NcalayerCompatibility => "NcalayerCompatibility",
                    },
                    checked_at_unix: report.checked_at.unix_timestamp(),
                    signers: report.signers.iter().map(signer).collect(),
                },
                projection,
                None,
            ))
        }
        Operation::Extract { input } => {
            let output = output.ok_or(OperationError::MissingTemporaryStore)?;
            let mut document = documents.take(&input)?;
            let mut reader = document.reader(ctx.resources())?;
            let mut writer = super::artifact::ArtifactWriter::new(
                output.store.clone(),
                output.owner.clone(),
                ctx,
            )?;
            let report = engine.extract(reader.source(), &mut writer, ctx)?;
            reader.finish()?;
            let artifact = writer.finish(report.bytes_written)?;
            let projection = ctx.resources().reserve_metadata(512)?;
            Ok((
                OperationResult::Extraction {
                    artifact: output.id,
                    bytes_written: report.bytes_written,
                },
                projection,
                Some(artifact),
            ))
        }
    }
}
