//! Source-bound private operations share the original immutable operation view.
use crate::{
    Action, Engine, OperationContext, OperationError, OperationId, SignProfile, SignRequest,
    request::SignMode,
};
use oncl_pki::{
    cms::stream::{self, CmsSignRequest, CmsSignServices, SignSummary},
    http::deadline::DeadlineTransport,
    io::{Source, StagedArtifact},
    key::{AppliedState, DigestSigner},
    resource::ProcessingError,
    validation::{ValidationContext, ValidationPolicy},
};
use std::{io::Write, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignProvenance {
    Document,
    ProvidedDigest,
    EvidenceExtension,
}
/// Completion facts own the PKI result's original reservations/root lifetime.
/// No signature/key buffer or independent quota token can be detached.
#[derive(Debug)]
pub struct OperationReport {
    pub id: OperationId,
    pub profile: SignProfile,
    pub provenance: SignProvenance,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub applied: AppliedState,
    result: OperationResult,
}
#[derive(Debug)]
enum OperationResult {
    Signed(SignSummary),
    Extended(oncl_pki::cms::ades::AdesReport),
    #[cfg(feature = "pdf")]
    PdfExtended {
        reports: [oncl_pki::validation::ValidationReport; 1],
        facts: oncl_pdf::PdfRevisionFacts,
    },
}
impl OperationReport {
    pub fn signer_count(&self) -> usize {
        match &self.result {
            OperationResult::Signed(report) => report.signer_count,
            OperationResult::Extended(report) => report
                .reports()
                .iter()
                .map(|report| report.signers.len())
                .sum(),
            #[cfg(feature = "pdf")]
            OperationResult::PdfExtended { reports, .. } => reports[0].signers.len(),
        }
    }
    /// All requested signers completed. Partial application is always an error,
    /// carrying its conservative application state, never a successful artifact.
    pub fn signer_states(&self) -> impl ExactSizeIterator<Item = AppliedState> + '_ {
        (0..self.signer_count()).map(|_| self.applied)
    }
    pub(crate) fn extended(
        id: OperationId,
        profile: SignProfile,
        provenance: SignProvenance,
        applied: AppliedState,
        report: oncl_pki::cms::ades::AdesReport,
    ) -> Self {
        Self {
            id,
            profile,
            provenance,
            bytes_in: report.bytes_in(),
            bytes_out: report.bytes_out(),
            applied,
            result: OperationResult::Extended(report),
        }
    }
    #[cfg(feature = "pdf")]
    pub(crate) fn extended_pdf(
        id: OperationId,
        bytes_in: u64,
        bytes_out: u64,
        report: oncl_pdf::ades::PadesReport,
        scope: &oncl_pki::resource::ResourceScope,
    ) -> Result<Self, OperationError> {
        let level = report.level().ok_or(OperationError::ValidationRequired)?;
        let (validation, facts) = report
            .into_verification()
            .into_aggregate(scope)
            .map_err(crate::pades::error)?;
        Ok(Self {
            id,
            profile: SignProfile::Pades(level),
            provenance: SignProvenance::EvidenceExtension,
            bytes_in,
            bytes_out,
            applied: AppliedState::NotApplied,
            result: OperationResult::PdfExtended {
                reports: [validation],
                facts,
            },
        })
    }
    #[cfg(feature = "pdf")]
    pub fn pdf_revision_facts(&self) -> Option<&oncl_pdf::PdfRevisionFacts> {
        match &self.result {
            OperationResult::PdfExtended { facts, .. } => Some(facts),
            _ => None,
        }
    }
    pub fn validation_reports(&self) -> Option<&[oncl_pki::validation::ValidationReport]> {
        match &self.result {
            OperationResult::Extended(report) => Some(report.reports()),
            #[cfg(feature = "pdf")]
            OperationResult::PdfExtended { reports, .. } => Some(reports),
            OperationResult::Signed(_) => None,
        }
    }
}
struct StatusCheckedSigner<'s, 'http> {
    signer: &'s mut dyn DigestSigner,
    transport: &'s DeadlineTransport<'http>,
}
impl DigestSigner for StatusCheckedSigner<'_, '_> {
    fn certificate(&self) -> &oncl_pki::cert::Certificate {
        self.signer.certificate()
    }
    fn algorithm(&self) -> oncl_pki::key::SigAlg {
        self.signer.algorithm()
    }
    fn sign_digest(
        &mut self,
        digest: &oncl_pki::digest::DigestValue,
    ) -> Result<Vec<u8>, oncl_pki::key::KeyError> {
        // Flush fatal scoped status admission before any new private application.
        self.transport.finish().map_err(OperationError::from)?;
        self.signer.sign_digest(digest)
    }
}
enum Output<'a> {
    Writer(&'a mut dyn Write),
    Staged(&'a mut StagedArtifact),
}
impl Engine {
    /// Hash and sign the actual source, or explicitly sign a supplied digest.
    /// This consumes any one-shot detached reader in the request. An arbitrary
    /// writer can retain a partial prefix on failure; it is charged by the stream.
    pub fn sign(
        &self,
        request: SignRequest<'_>,
        input: Source<'_>,
        output: &mut dyn Write,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        self.sign_operation(request, input, Output::Writer(output), ctx)
    }
    /// Sign directly to an empty, live output artifact owned by this exact
    /// operation. The artifact owns output accounting; no adapter double charge.
    /// Failed operations poison the artifact, which cannot then be published.
    pub fn sign_staged(
        &self,
        request: SignRequest<'_>,
        input: Source<'_>,
        output: &mut StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        self.sign_operation(request, input, Output::Staged(output), ctx)
    }
    fn sign_operation(
        &self,
        request: SignRequest<'_>,
        input: Source<'_>,
        output: Output<'_>,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        #[cfg(feature = "pdf")]
        if matches!(request.mode, SignMode::Pdf(..) | SignMode::Pades(..))
            && let Output::Staged(stage) = &output
        {
            oncl_pki::io::PdfSignatureOutput::check_output(stage, &ctx.scope)?;
        }
        let profile = request.profile();
        let (requests, action, provenance) = match &request.mode {
            SignMode::RawMessage(key) => (
                std::slice::from_ref(key),
                Action::Sign,
                SignProvenance::Document,
            ),
            SignMode::RawDigest(key, _) => (
                std::slice::from_ref(key),
                Action::SignDigest,
                SignProvenance::ProvidedDigest,
            ),
            SignMode::CmsCreate(keys, _)
            | SignMode::CmsAdd(keys, _)
            | SignMode::CadesCreate(keys, _, _, _, _)
            | SignMode::CadesAdd(keys, _, _, _, _) => {
                (keys.as_slice(), Action::Sign, SignProvenance::Document)
            }
            #[cfg(feature = "pdf")]
            SignMode::Pdf(key, _) | SignMode::Pades(key, ..) => (
                std::slice::from_ref(key),
                Action::Sign,
                SignProvenance::Document,
            ),
        };
        if !ctx.grant.allows(action) {
            return Err(OperationError::PermissionDenied);
        }
        if let SignProfile::Cades(level) = profile
            && level > oncl_pki::evidence::AdesLevel::B
            && self.cades.is_none()
        {
            return Err(OperationError::MissingCadesConfiguration);
        }
        #[cfg(feature = "pdf")]
        if matches!(profile, SignProfile::Pades(level) if level > oncl_pki::evidence::AdesLevel::B)
            && self.cades.is_none()
        {
            return Err(OperationError::MissingCadesConfiguration);
        }
        if requests.is_empty() || requests.len() > 64 {
            return Err(ProcessingError::InvalidInput("signer count must be 1..=64").into());
        }
        // Covers temporary index/signer/reference arrays, including old/new Vec
        // capacity during growth. The opaque key leases retain their own slots.
        let bytes = (requests.len()
            * (std::mem::size_of::<crate::keys::AuthorizedSigner<'_>>()
                + std::mem::size_of::<usize>()
                + std::mem::size_of::<&mut dyn DigestSigner>())
            * 2) as u64;
        let _memory = ctx.scope.reserve_memory(bytes)?;
        let _metadata = ctx.scope.reserve_metadata(bytes)?;
        let indices = self.prepare_sign_keys(requests, ctx, action)?;
        let services = self
            .validation
            .as_ref()
            .ok_or(OperationError::MissingValidationServices)?;
        // Opening resolves only opaque leases under mutable context. From here
        // every signer and format adapter borrow the SAME immutable operation;
        // ResourceScope provides its original checked interior accounting.
        let mut signers = Vec::with_capacity(indices.len());
        for index in indices {
            signers.push(self.operation_signer(index, ctx, action)?);
        }
        let transport =
            DeadlineTransport::new(services.http.as_ref(), &services.network, &ctx.scope);
        let mut checked: Vec<_> = signers
            .iter_mut()
            .map(|signer| StatusCheckedSigner {
                signer,
                transport: &transport,
            })
            .collect();
        let mut refs: Vec<&mut dyn DigestSigner> = checked
            .iter_mut()
            .map(|signer| signer as &mut dyn DigestSigner)
            .collect();
        let validation = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: (services.clock)(),
            anchors: &services.anchors,
            intermediates: &services.intermediates,
            http: &transport,
        };
        let cms_services = CmsSignServices::new(Some(&validation), self.temporary.as_ref());
        let result = match request.mode {
            #[cfg(feature = "pdf")]
            SignMode::Pdf(_, profile) => sign_pdf(
                input,
                &profile.with_allowed_algorithms(ctx.policy.allowed_signature_algorithms),
                refs[0],
                &cms_services,
                output,
                &ctx.scope,
            )
            .map_err(crate::report::stream_error),
            #[cfg(feature = "pdf")]
            SignMode::Pades(_, profile, level, material, limits) => pades_sign(
                self,
                level,
                input,
                &profile.with_allowed_algorithms(ctx.policy.allowed_signature_algorithms),
                refs[0],
                &validation,
                services,
                material,
                limits,
                output,
                &ctx.scope,
            ),
            SignMode::RawMessage(_) => match output {
                Output::Writer(writer) => stream::sign_raw(input, refs[0], writer, &ctx.scope),
                Output::Staged(stage) => stream::sign_raw_staged(input, refs[0], stage, &ctx.scope),
            }
            .map_err(crate::report::stream_error),
            SignMode::RawDigest(_, digest) => match output {
                Output::Writer(writer) => {
                    stream::sign_raw_digest(input, &digest, refs[0], writer, &ctx.scope)
                }
                Output::Staged(stage) => {
                    stream::sign_raw_digest_staged(input, &digest, refs[0], stage, &ctx.scope)
                }
            }
            .map_err(crate::report::stream_error),
            SignMode::CmsCreate(_, attached) => match output {
                Output::Writer(writer) => stream::sign(
                    &CmsSignRequest::create(attached),
                    input,
                    None,
                    &mut refs,
                    &cms_services,
                    writer,
                    &ctx.scope,
                ),
                Output::Staged(stage) => stream::sign_staged(
                    &CmsSignRequest::create(attached),
                    input,
                    None,
                    &mut refs,
                    &cms_services,
                    stage,
                    &ctx.scope,
                ),
            }
            .map_err(crate::report::stream_error),
            SignMode::CmsAdd(_, detached) => match output {
                Output::Writer(writer) => stream::sign(
                    &CmsSignRequest::add()
                        .with_allowed_algorithms(ctx.policy.allowed_signature_algorithms),
                    input,
                    detached,
                    &mut refs,
                    &cms_services,
                    writer,
                    &ctx.scope,
                ),
                Output::Staged(stage) => stream::sign_staged(
                    &CmsSignRequest::add()
                        .with_allowed_algorithms(ctx.policy.allowed_signature_algorithms),
                    input,
                    detached,
                    &mut refs,
                    &cms_services,
                    stage,
                    &ctx.scope,
                ),
            }
            .map_err(crate::report::stream_error),
            SignMode::CadesCreate(_, attached, level, material, limits) => cades_sign(
                self,
                &CmsSignRequest::create(attached)
                    .with_signing_time(validation.now)
                    .with_allowed_algorithms(ctx.policy.allowed_signature_algorithms),
                level,
                input,
                None,
                &mut refs,
                &cms_services,
                &validation,
                services,
                material,
                limits,
                output,
                &ctx.scope,
            ),
            SignMode::CadesAdd(_, detached, level, material, limits) => cades_sign(
                self,
                &CmsSignRequest::add()
                    .with_signing_time(validation.now)
                    .with_allowed_algorithms(ctx.policy.allowed_signature_algorithms),
                level,
                input,
                detached,
                &mut refs,
                &cms_services,
                &validation,
                services,
                material,
                limits,
                output,
                &ctx.scope,
            ),
        };
        let transport_result = transport.finish();
        if let Err(error) = transport_result {
            let applied = match &result {
                Ok(report) => report.applied,
                Err(error) => error.applied_state(),
            };
            if applied == AppliedState::NotApplied {
                return Err(error.into());
            }
            return Err(OperationError::AfterKeyUse {
                source: Box::new(error.into()),
                applied,
            });
        }
        let result = result?;
        Ok(OperationReport {
            id: ctx.id,
            profile,
            provenance,
            bytes_in: result.bytes_in,
            bytes_out: result.bytes_out,
            applied: result.applied,
            result: OperationResult::Signed(result),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn cades_sign(
    engine: &Engine,
    request: &CmsSignRequest,
    level: oncl_pki::evidence::AdesLevel,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    cms: &CmsSignServices<'_>,
    validation: &ValidationContext<'_>,
    host: &crate::ValidationServices,
    material: oncl_pki::cms::ades::ValidationMaterial<'_>,
    limits: oncl_pki::evidence::EvidenceLimits,
    output: Output<'_>,
    scope: &oncl_pki::resource::ResourceScope,
) -> Result<SignSummary, OperationError> {
    let temporary = engine
        .temporary
        .as_ref()
        .ok_or(OperationError::MissingTemporaryStore)?;
    limits
        .validate()
        .map_err(|error| crate::cades::error(error.into()))?;
    let services = oncl_pki::cms::ades::AdesServices {
        validation,
        network: &host.network,
        temporary,
        limits,
        tsa: engine
            .cades
            .as_ref()
            .map(|configuration| &configuration.tsa),
        material,
    };
    match output {
        Output::Writer(writer) => oncl_pki::cms::ades::sign(
            request,
            level,
            input,
            detached,
            signers,
            cms,
            Some(&services),
            writer,
            scope,
        ),
        Output::Staged(stage) => oncl_pki::cms::ades::sign_staged(
            request,
            level,
            input,
            detached,
            signers,
            cms,
            Some(&services),
            stage,
            scope,
        ),
    }
    .map_err(crate::cades::error)
}

#[cfg(feature = "pdf")]
fn sign_pdf(
    input: Source<'_>,
    profile: &oncl_pdf::PdfSignProfile,
    signer: &mut dyn DigestSigner,
    services: &CmsSignServices<'_>,
    output: Output<'_>,
    scope: &oncl_pki::resource::ResourceScope,
) -> Result<SignSummary, stream::StreamError> {
    fn error(error: oncl_pdf::PdfError) -> stream::StreamError {
        match error {
            oncl_pdf::PdfError::Cms(e) => e,
            oncl_pdf::PdfError::Processing(e) => e.into(),
            oncl_pdf::PdfError::Io(e) => ProcessingError::Io(e).into(),
            oncl_pdf::PdfError::Limit(_) => ProcessingError::MetadataLimit.into(),
            _ => ProcessingError::InvalidInput("unsupported or malformed PDF").into(),
        }
    }
    match output {
        Output::Staged(stage) => {
            oncl_pdf::sign_source(input, profile, signer, services, stage, scope).map_err(error)
        }
        Output::Writer(writer) => {
            let store = services
                .temporary()
                .ok_or(stream::StreamError::MissingTemporaryStore)?;
            let mut stage = store.stage(&mut scope.shared_view())?;
            let report = oncl_pdf::sign_source(input, profile, signer, services, &mut stage, scope)
                .map_err(error)?;
            stage
                .copy_to(writer)
                .map_err(|e| stream::StreamError::AfterKeyUse {
                    source: Box::new(e.into()),
                    applied: report.applied,
                })?;
            Ok(report)
        }
    }
}

#[cfg(feature = "pdf")]
#[allow(
    clippy::too_many_arguments,
    reason = "Existing private operation context with explicit PAdES acquisition"
)]
fn pades_sign(
    engine: &Engine,
    level: oncl_pki::evidence::AdesLevel,
    input: Source<'_>,
    profile: &oncl_pdf::PdfSignProfile,
    signer: &mut dyn DigestSigner,
    validation: &ValidationContext<'_>,
    host: &crate::ValidationServices,
    material: oncl_pki::cms::ades::ValidationMaterial<'_>,
    limits: oncl_pki::evidence::EvidenceLimits,
    output: Output<'_>,
    scope: &oncl_pki::resource::ResourceScope,
) -> Result<SignSummary, OperationError> {
    let temporary = engine
        .temporary
        .as_ref()
        .ok_or(OperationError::MissingTemporaryStore)?;
    let services = oncl_pki::cms::ades::AdesServices {
        validation,
        network: &host.network,
        temporary,
        limits,
        tsa: engine.cades.as_ref().map(|c| &c.tsa),
        material,
    };
    match output {
        Output::Staged(stage) => {
            oncl_pdf::ades::sign(level, input, profile, signer, &services, stage, scope)
                .map_err(crate::pades::error)
        }
        Output::Writer(writer) => {
            let mut stage = temporary.stage(&mut scope.shared_view())?;
            let report =
                oncl_pdf::ades::sign(level, input, profile, signer, &services, &mut stage, scope)
                    .map_err(crate::pades::error)?;
            stage
                .copy_to(writer)
                .map_err(|error| OperationError::AfterKeyUse {
                    source: Box::new(error.into()),
                    applied: report.applied,
                })?;
            Ok(report)
        }
    }
}
