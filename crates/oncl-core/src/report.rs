//! CMS validation shares one PKI normalizer for bounded and streaming inputs.
use crate::{Action, Engine, OperationContext, OperationError, OperationId};
use oncl_pki::{
    cert::Certificate,
    http::{HttpReply, HttpRequest, HttpTransport, deadline::DeadlineTransport},
    pkix::CaSet,
    validation::{
        self, NetworkPolicy, ScopedSigners, ValidationContext, ValidationPolicy, Verdict,
    },
};
use std::sync::Arc;
use time::OffsetDateTime;

/// Immutable trusted-host configuration. Custom transports are trusted host code.
/// Actual Ureq hostname endpoints require operator-supplied address pins; the SDK
/// never launches an unbounded DNS lookup from a validation operation.
#[derive(Clone)]
pub struct ValidationServices {
    pub(crate) anchors: CaSet,
    pub(crate) intermediates: Vec<Certificate>,
    pub(crate) http: Arc<dyn HttpTransport>,
    pub(crate) network: NetworkPolicy,
    pub(crate) clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
}
impl std::fmt::Debug for ValidationServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ValidationServices { host-configured }")
    }
}
impl ValidationServices {
    pub fn new(
        anchors: CaSet,
        intermediates: Vec<Certificate>,
        http: Arc<dyn HttpTransport>,
        network: NetworkPolicy,
        clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
    ) -> Self {
        Self {
            anchors,
            intermediates,
            http,
            network,
            clock,
        }
    }
    pub(crate) fn check_private(
        &self,
        cert: &Certificate,
        ctx: &OperationContext,
    ) -> Result<(), OperationError> {
        let _memory = ctx
            .scope
            .reserve_memory(4 * oncl_pki::http::MAX_RESPONSE_LEN)?;
        let _metadata = ctx
            .scope
            .reserve_metadata(oncl_pki::http::MAX_RESPONSE_LEN)?;
        ctx.scope.checkpoint()?;
        let transport = DeadlineTransport::new(self.http.as_ref(), &self.network, &ctx.scope);
        let now = (self.clock)();
        let report = validation::validate_certificate(
            cert,
            now,
            &ValidationContext {
                policy: ValidationPolicy::StrictOnline,
                now,
                anchors: &self.anchors,
                intermediates: &self.intermediates,
                http: &transport,
            },
            &self.intermediates,
        );
        transport.finish()?;
        ctx.scope.checkpoint()?;
        if report.verdict() != Verdict::Valid {
            return Err(OperationError::ValidationRequired);
        }
        Ok(())
    }
}
/// Owned validation output keeps its allocation reservations inseparable.
///
/// A consumer cannot detach the SDK's charged buffers as a raw unscoped vector:
/// ```compile_fail
/// fn detach(mut report: oncl_core::VerificationReport) {
///     let _unscoped: Vec<oncl_pki::validation::SignerValidation> =
///         std::mem::take(&mut report.signers);
/// }
/// ```
#[derive(Debug)]
pub struct VerificationReport {
    pub id: OperationId,
    pub verdict: Verdict,
    pub policy: ValidationPolicy,
    pub checked_at: OffsetDateTime,
    pub signers: ScopedSigners,
    /// Minimum actually verified CAdES level; legacy CMS reports have none.
    pub ades_level: Option<oncl_pki::evidence::AdesLevel>,
}

/// Raw structural extraction, not a signature/validation verdict. Arbitrary
/// sinks may retain a partial prefix if the operation fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtractionReport {
    pub id: OperationId,
    pub bytes_written: u64,
}

pub(crate) fn stream_error(error: oncl_pki::cms::stream::StreamError) -> OperationError {
    use oncl_pki::cms::{CmsError, stream::StreamError};
    match error {
        StreamError::MissingTemporaryStore => OperationError::MissingTemporaryStore,
        StreamError::AfterKeyUse { source, applied } => OperationError::AfterKeyUse {
            source: Box::new(stream_error(*source)),
            applied,
        },
        StreamError::Processing(error) => OperationError::Processing(error),
        StreamError::Cms(CmsError::UnknownAlgorithm(_)) => {
            OperationError::Key(oncl_pki::key::KeyError::UnsupportedAlgorithm)
        }
        StreamError::Cms(CmsError::Key(error)) => OperationError::Key(error),
        StreamError::Cms(_) => OperationError::Processing(
            oncl_pki::resource::ProcessingError::InvalidInput("malformed CMS input"),
        ),
    }
}
impl Engine {
    pub(crate) fn validation_context<'a>(
        &'a self,
        ctx: &OperationContext,
        action: Action,
    ) -> Result<&'a ValidationServices, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if !ctx.grant.allows(action) {
            return Err(OperationError::PermissionDenied);
        }
        ctx.scope.checkpoint()?;
        self.validation
            .as_deref()
            .ok_or(OperationError::MissingValidationServices)
    }
    /// Validate an already bounded CMS container using the existing CMS crypto
    /// implementation and shared signer validation. This is not streaming verify.
    /// Container/detached input and parser working memory are bounded by metadata
    /// and memory quotas before allocation; callers own their original buffers.
    pub fn validate_cms(
        &self,
        input: &[u8],
        detached: Option<&[u8]>,
        ctx: &mut OperationContext,
    ) -> Result<VerificationReport, OperationError> {
        let services = self.validation_context(ctx, Action::Validate)?;
        let bytes = (input.len() as u64)
            .checked_add(detached.map_or(0, |b| b.len() as u64))
            .ok_or(oncl_pki::resource::ProcessingError::MetadataLimit)?;
        ctx.scope.account_input(bytes)?;
        ctx.scope.account_container(input.len() as u64)?;
        let _metadata = ctx.scope.reserve_metadata(bytes)?;
        let now = (services.clock)();
        ctx.scope.checkpoint()?;
        let transport =
            DeadlineTransport::new(services.http.as_ref(), &services.network, &ctx.scope);
        let result = validation::validate_cms(
            input,
            detached,
            &ValidationContext {
                policy: ctx.policy.validation,
                now,
                anchors: &services.anchors,
                intermediates: &services.intermediates,
                http: &transport,
            },
            &ctx.scope,
        );
        transport.finish()?;
        ctx.scope.checkpoint()?;
        let report = result.map_err(|error| match error {
            validation::ValidationError::Processing(error) => OperationError::Processing(error),
            validation::ValidationError::Cms(_) => OperationError::Processing(
                oncl_pki::resource::ProcessingError::InvalidInput("malformed CMS validation input"),
            ),
        })?;
        Ok(VerificationReport {
            id: ctx.id,
            verdict: report.verdict,
            policy: report.policy,
            checked_at: report.checked_at,
            signers: report.signers,
            ades_level: None,
        })
    }
    /// Host PKI-only bounded fetch using this operation's authorization and
    /// transport. No wire request may choose its URL policy/anchors/address pins.
    pub fn validation_http(
        &self,
        request: &HttpRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<HttpReply, OperationError> {
        let services = self.validation_context(ctx, Action::Validate)?;
        let _memory = ctx
            .scope
            .reserve_memory(request.opts.max_len.min(oncl_pki::http::MAX_RESPONSE_LEN))?;
        let transport =
            DeadlineTransport::new(services.http.as_ref(), &services.network, &ctx.scope);
        let result = transport.send(request);
        transport.finish()?;
        result.map_err(|_| OperationError::ValidationRequired)
    }

    /// Verify actual CMS bytes and every signer under immutable host trust,
    /// clock, network and operation policy. No key or temporary store is needed.
    pub fn verify(
        &self,
        request: &crate::VerifyRequest,
        input: oncl_pki::io::Source<'_>,
        detached: Option<oncl_pki::io::Source<'_>>,
        ctx: &mut OperationContext,
    ) -> Result<VerificationReport, OperationError> {
        if let crate::VerifyProfile::Cades(required) = request.profile() {
            return self.verify_cades(request, required, input, detached, ctx);
        }
        let services = self.validation_context(ctx, Action::Verify)?;
        let now = (services.clock)();
        let transport =
            DeadlineTransport::new(services.http.as_ref(), &services.network, &ctx.scope);
        let result = oncl_pki::cms::stream::verify(
            input,
            detached,
            &ValidationContext {
                policy: ctx.policy.validation,
                now,
                anchors: &services.anchors,
                intermediates: &services.intermediates,
                http: &transport,
            },
            ctx.policy.allowed_signature_algorithms,
            &mut ctx.scope,
        );
        transport.finish()?;
        ctx.scope.checkpoint()?;
        let report = result.map_err(stream_error)?;
        Ok(VerificationReport {
            id: ctx.id,
            verdict: report.verdict,
            policy: report.policy,
            checked_at: report.checked_at,
            signers: report.signers,
            ades_level: None,
        })
    }

    /// Copy attached content without claiming cryptographic validity.
    pub fn extract(
        &self,
        input: oncl_pki::io::Source<'_>,
        output: &mut dyn std::io::Write,
        ctx: &mut OperationContext,
    ) -> Result<ExtractionReport, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if !ctx.grant.allows(Action::Extract) {
            return Err(OperationError::PermissionDenied);
        }
        ctx.scope.checkpoint()?;
        let report =
            oncl_pki::cms::stream::extract(input, output, &mut ctx.scope).map_err(stream_error)?;
        ctx.scope.checkpoint()?;
        Ok(ExtractionReport {
            id: ctx.id,
            bytes_written: report.bytes_written,
        })
    }
}
