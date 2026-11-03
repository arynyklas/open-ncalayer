//! Host-configured CAdES acquisition and non-private augmentation.
use crate::{
    Action, Engine, OperationContext, OperationError, OperationReport, SignProfile, SignProvenance,
};
use oncl_pki::{
    cms::ades::{self, AdesError, AdesServices, ValidationMaterial},
    evidence::{AdesLevel, EvidenceError, EvidenceLimits},
    http::deadline::DeadlineTransport,
    io::{Source, StagedArtifact},
    key::AppliedState,
    resource::ProcessingError,
    tsp::TsaSpec,
    validation::{ValidationContext, ValidationPolicy},
};
use std::{cell::RefCell, io::Write};

/// Acquisition configuration is trusted host state, never deserialized from a
/// document/request. Verification has its own explicit reader limits and does
/// not require this value or a TSA capable of issuing new timestamps.
#[derive(Clone, Debug)]
pub struct CadesConfiguration {
    pub evidence_limits: EvidenceLimits,
    pub tsa: TsaSpec,
}
impl CadesConfiguration {
    pub fn new(evidence_limits: EvidenceLimits, tsa: TsaSpec) -> Self {
        Self {
            evidence_limits,
            tsa,
        }
    }
}
/// One-shot detached input is consumed only after action/dependency admission.
/// Public evidence is not a trust anchor, an execution grant or a cached verdict.
pub struct ExtendRequest<'a> {
    pub(crate) level: AdesLevel,
    pub(crate) material: ValidationMaterial<'a>,
    pub(crate) detached: RefCell<Option<Source<'a>>>,
    pub(crate) detached_requested: bool,
    pub(crate) limits: Option<EvidenceLimits>,
}
impl<'a> ExtendRequest<'a> {
    pub fn cms(level: AdesLevel) -> Self {
        Self {
            level,
            material: ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
            detached: RefCell::new(None),
            detached_requested: false,
            limits: None,
        }
    }
    pub fn with_material(mut self, material: ValidationMaterial<'a>) -> Self {
        self.material = material;
        self
    }
    pub fn with_detached(mut self, detached: Source<'a>) -> Self {
        self.detached = RefCell::new(Some(detached));
        self.detached_requested = true;
        self
    }
    pub fn with_evidence_limits(mut self, limits: EvidenceLimits) -> Self {
        self.limits = Some(limits);
        self
    }
    pub fn level(&self) -> AdesLevel {
        self.level
    }
}
pub(crate) fn material<'a>(value: &ValidationMaterial<'a>) -> ValidationMaterial<'a> {
    ValidationMaterial {
        certificates: value.certificates,
        ocsp: value.ocsp,
        crls: value.crls,
    }
}
pub(crate) fn error(error: AdesError) -> OperationError {
    match error {
        AdesError::MissingConfiguration => OperationError::MissingCadesConfiguration,
        AdesError::Stream(error) => crate::report::stream_error(error),
        AdesError::Processing(error) | AdesError::Evidence(EvidenceError::Processing(error)) => {
            error.into()
        }
        AdesError::Evidence(EvidenceError::Limit) => ProcessingError::MetadataLimit.into(),
        AdesError::AfterKeyUse { source, applied } => OperationError::AfterKeyUse {
            source: Box::new(self::error(*source)),
            applied,
        },
        AdesError::Cms(oncl_pki::cms::CmsError::Key(error)) => OperationError::Key(error),
        AdesError::Timestamp(_) | AdesError::Evidence(EvidenceError::Timestamp(_)) => {
            OperationError::ValidationRequired
        }
        AdesError::Cms(_) | AdesError::Evidence(EvidenceError::InvalidBinding) => {
            ProcessingError::InvalidInput("malformed CAdES input or proof binding").into()
        }
    }
}
impl Engine {
    /// Augment actual CMS signers with public evidence under a distinct grant.
    /// No key provider, lease, SignDigest privilege, consent or audit is invoked.
    pub fn extend(
        &self,
        request: &ExtendRequest<'_>,
        input: Source<'_>,
        output: &mut dyn Write,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        self.extend_operation(request, input, Some(output), None, ctx)
    }
    pub fn extend_staged(
        &self,
        request: &ExtendRequest<'_>,
        input: Source<'_>,
        output: &mut StagedArtifact,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        self.extend_operation(request, input, None, Some(output), ctx)
    }
    fn extend_operation(
        &self,
        request: &ExtendRequest<'_>,
        input: Source<'_>,
        output: Option<&mut dyn Write>,
        staged: Option<&mut StagedArtifact>,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        let validation = self.validation_context(ctx, Action::Extend)?;
        let temporary = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let acquisition = self.cades.as_ref();
        let limits = request
            .limits
            .or_else(|| acquisition.map(|configuration| configuration.evidence_limits))
            .ok_or(OperationError::MissingCadesConfiguration)?;
        let mut source = request
            .detached
            .try_borrow_mut()
            .map_err(|_| ProcessingError::InvalidInput("detached CAdES input is already in use"))?;
        let detached = source.take();
        if request.detached_requested && detached.is_none() {
            return Err(
                ProcessingError::InvalidInput("detached CAdES input was already consumed").into(),
            );
        }
        let transport =
            DeadlineTransport::new(validation.http.as_ref(), &validation.network, &ctx.scope);
        let context = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: (validation.clock)(),
            anchors: &validation.anchors,
            intermediates: &validation.intermediates,
            http: &transport,
        };
        let services = AdesServices {
            validation: &context,
            network: &validation.network,
            temporary,
            limits,
            tsa: acquisition.map(|configuration| &configuration.tsa),
            material: material(&request.material),
        };
        let result = match (output, staged) {
            (Some(output), None) => ades::extend(
                request.level,
                input,
                detached,
                &services,
                ctx.policy.allowed_signature_algorithms,
                output,
                &ctx.scope,
            ),
            (None, Some(output)) => ades::extend_staged(
                request.level,
                input,
                detached,
                &services,
                ctx.policy.allowed_signature_algorithms,
                output,
                &ctx.scope,
            ),
            _ => {
                return Err(
                    ProcessingError::InvalidInput("exactly one CAdES output is required").into(),
                );
            }
        };
        transport.finish()?;
        ctx.scope.checkpoint()?;
        let report = result.map_err(error)?;
        Ok(OperationReport::extended(
            ctx.id,
            SignProfile::Cades(report.level().ok_or(OperationError::ValidationRequired)?),
            SignProvenance::EvidenceExtension,
            AppliedState::NotApplied,
            report,
        ))
    }
    pub(crate) fn verify_cades(
        &self,
        request: &crate::VerifyRequest,
        required: AdesLevel,
        input: Source<'_>,
        detached: Option<Source<'_>>,
        ctx: &mut OperationContext,
    ) -> Result<crate::VerificationReport, OperationError> {
        let validation = self.validation_context(ctx, Action::Verify)?;
        let temporary = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let limits = request
            .evidence_limits()
            .ok_or(ProcessingError::InvalidInput(
                "CAdES reader limits are required",
            ))?;
        let transport =
            DeadlineTransport::new(validation.http.as_ref(), &validation.network, &ctx.scope);
        let context = ValidationContext {
            policy: ctx.policy.validation,
            now: (validation.clock)(),
            anchors: &validation.anchors,
            intermediates: &validation.intermediates,
            http: &transport,
        };
        let services = AdesServices {
            validation: &context,
            network: &validation.network,
            temporary,
            limits,
            tsa: None,
            material: ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
        };
        let result = ades::verify(
            required,
            input,
            detached,
            &services,
            ctx.policy.allowed_signature_algorithms,
            &ctx.scope,
        );
        transport.finish()?;
        ctx.scope.checkpoint()?;
        let report = result.map_err(error)?;
        let ades_level = report.level();
        let report = report.into_validation(&ctx.scope)?;
        Ok(crate::VerificationReport {
            id: ctx.id,
            verdict: report.verdict,
            policy: report.policy,
            checked_at: report.checked_at,
            signers: report.signers,
            #[cfg(feature = "pdf")]
            pdf: None,
            ades_level,
            #[cfg(feature = "xml")]
            xml: None,
        })
    }
}
