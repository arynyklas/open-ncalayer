//! Explicit PDF evidence operations using the existing host PKI/TSA services.
use crate::{
    Action, Engine, ExtendRequest, OperationContext, OperationError, OperationReport,
    VerificationReport, VerifyRequest,
};
use oncl_pki::{
    cms::ades::{AdesServices, ValidationMaterial},
    evidence::AdesLevel,
    http::deadline::DeadlineTransport,
    io::{PdfSignatureOutput, Source, StagedArtifact},
    resource::ProcessingError,
    validation::{ValidationContext, ValidationPolicy},
};
use std::io::Write;
pub(crate) fn error(error: oncl_pdf::PdfError) -> OperationError {
    match error {
        oncl_pdf::PdfError::Ades(error) => crate::cades::error(error),
        oncl_pdf::PdfError::Cms(error) => crate::report::stream_error(error),
        oncl_pdf::PdfError::Processing(error) => error.into(),
        oncl_pdf::PdfError::Io(error) => ProcessingError::Io(error).into(),
        oncl_pdf::PdfError::Limit(_) => ProcessingError::MetadataLimit.into(),
        oncl_pdf::PdfError::Malformed(_) | oncl_pdf::PdfError::Unsupported(_) => {
            ProcessingError::InvalidInput("unsupported or malformed PAdES").into()
        }
    }
}
impl Engine {
    pub(crate) fn verify_pades(
        &self,
        request: &VerifyRequest,
        required: AdesLevel,
        input: Source<'_>,
        detached: Option<Source<'_>>,
        ctx: &mut OperationContext,
    ) -> Result<VerificationReport, OperationError> {
        let host = self.validation_context(ctx, Action::Verify)?;
        if detached.is_some() {
            return Err(
                ProcessingError::InvalidInput("PAdES does not accept detached input").into(),
            );
        }
        let temporary = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let limits = request
            .evidence_limits()
            .ok_or(ProcessingError::InvalidInput(
                "PAdES reader limits required",
            ))?;
        let transport = DeadlineTransport::new(host.http.as_ref(), &host.network, &ctx.scope);
        let validation = ValidationContext {
            policy: ctx.policy.validation,
            now: (host.clock)(),
            anchors: &host.anchors,
            intermediates: &host.intermediates,
            http: &transport,
        };
        let services = AdesServices {
            validation: &validation,
            network: &host.network,
            temporary,
            limits,
            tsa: None,
            material: ValidationMaterial {
                certificates: &[],
                ocsp: &[],
                crls: &[],
            },
        };
        let result = oncl_pdf::ades::verify(
            required,
            input,
            &oncl_pdf::PdfLimits::default(),
            &services,
            ctx.policy.allowed_signature_algorithms,
            &mut ctx.scope,
        );
        transport.finish()?;
        ctx.scope.checkpoint()?;
        let report = result.map_err(error)?;
        let ades_level = report.level();
        let (report, facts) = report
            .into_verification()
            .into_aggregate(&ctx.scope)
            .map_err(error)?;
        Ok(VerificationReport {
            id: ctx.id,
            verdict: report.verdict,
            policy: report.policy,
            checked_at: report.checked_at,
            signers: report.signers,
            pdf: Some(facts),
            ades_level,
        })
    }
    pub(crate) fn extend_pades(
        &self,
        request: &ExtendRequest<'_>,
        pdf_limits: &oncl_pdf::PdfLimits,
        input: Source<'_>,
        writer: Option<&mut dyn Write>,
        staged: Option<&mut StagedArtifact>,
        ctx: &mut OperationContext,
    ) -> Result<OperationReport, OperationError> {
        let host = self.validation_context(ctx, Action::Extend)?;
        let temporary = self
            .temporary
            .as_ref()
            .ok_or(OperationError::MissingTemporaryStore)?;
        let limits = request
            .limits
            .or_else(|| self.cades.as_ref().map(|c| c.evidence_limits))
            .ok_or(ProcessingError::InvalidInput(
                "PAdES reader limits required",
            ))?;
        let transport = DeadlineTransport::new(host.http.as_ref(), &host.network, &ctx.scope);
        let validation = ValidationContext {
            policy: ValidationPolicy::StrictOnline,
            now: (host.clock)(),
            anchors: &host.anchors,
            intermediates: &host.intermediates,
            http: &transport,
        };
        let services = AdesServices {
            validation: &validation,
            network: &host.network,
            temporary,
            limits,
            tsa: self.cades.as_ref().map(|c| &c.tsa),
            material: crate::cades::material(&request.material),
        };
        let before = ctx.scope.progress();
        let mut local = None;
        let (output, writer) = match (staged, writer) {
            (Some(stage), None) => (stage, None),
            (None, Some(writer)) => {
                local = Some(temporary.stage(&mut ctx.scope.shared_view())?);
                (
                    local.as_mut().expect("local stage just created"),
                    Some(writer),
                )
            }
            _ => {
                return Err(
                    ProcessingError::InvalidInput("exactly one PAdES output required").into(),
                );
            }
        };
        PdfSignatureOutput::check_output(output, &ctx.scope)?;
        let result = (|| {
            let report = oncl_pdf::ades::extend(
                request.level,
                input,
                pdf_limits,
                &services,
                ctx.policy.allowed_signature_algorithms,
                output,
                &ctx.scope,
            )
            .map_err(error)?;
            transport.finish()?;
            ctx.scope.checkpoint()?;
            OperationReport::extended_pdf(
                ctx.id,
                ctx.scope.progress().bytes_in - before.bytes_in,
                output.len(),
                report,
                &ctx.scope,
            )
        })();
        if result.is_err() {
            let _ = PdfSignatureOutput::abort_output(output, &ctx.scope);
        }
        let report = result?;
        if let Some(writer) = writer {
            local.expect("writer owns local stage").copy_to(writer)?;
        }
        Ok(report)
    }
}
