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
        let scoped_http = ctx.http(self.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &self.network, &ctx.scope);
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
        ctx.network_status()?;
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
    #[cfg(feature = "pdf")]
    pub pdf: Option<oncl_pdf::PdfRevisionFacts>,
    /// Minimum actually verified CAdES level; legacy CMS reports have none.
    pub ades_level: Option<oncl_pki::evidence::AdesLevel>,
    #[cfg(feature = "xml")]
    pub xml: Option<oncl_xml::XmlVerificationFacts>,
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
        ctx.account_borrowed(input, detached)?;
        ctx.scope.account_container(input.len() as u64)?;
        let _metadata = ctx.scope.reserve_metadata(bytes)?;
        let now = (services.clock)();
        ctx.scope.checkpoint()?;
        let scoped_http = ctx.http(services.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &services.network, &ctx.scope);
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
            #[cfg(feature = "pdf")]
            pdf: None,
            ades_level: None,
            #[cfg(feature = "xml")]
            xml: None,
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
        let scoped_http = ctx.http(services.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &services.network, &ctx.scope);
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
        #[cfg(feature = "pdf")]
        if let crate::VerifyProfile::Pades(required) = request.profile() {
            return self.verify_pades(request, required, input, detached, ctx);
        }
        let services = self.validation_context(ctx, Action::Verify)?;
        let now = (services.clock)();
        let scoped_http = ctx.http(services.http.as_ref());
        let transport = DeadlineTransport::new(&scoped_http, &services.network, &ctx.scope);
        #[cfg(feature = "pdf")]
        let mut pdf = None;
        #[cfg(feature = "xml")]
        let mut xml = None;
        #[cfg(feature = "xml")]
        let mut ades_level = None;
        let result = match request.profile() {
            // CAdES is dispatched before constructing the generic transport above.
            // Keep the real handler here as well so the profile match stays exhaustive.
            crate::VerifyProfile::Cades(required) => {
                return self.verify_cades(request, required, input, detached, ctx);
            }
            #[cfg(feature = "pdf")]
            crate::VerifyProfile::Pades(required) => {
                return self.verify_pades(request, required, input, detached, ctx);
            }
            crate::VerifyProfile::Cms => oncl_pki::cms::stream::verify(
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
            ),
            #[cfg(feature = "pdf")]
            crate::VerifyProfile::Pdf => {
                if detached.is_some() {
                    return Err(OperationError::Processing(
                        oncl_pki::resource::ProcessingError::InvalidInput(
                            "PDF does not accept detached input",
                        ),
                    ));
                }
                let result = oncl_pdf::verify_source(
                    input,
                    &oncl_pdf::PdfLimits::default(),
                    self.temporary
                        .as_ref()
                        .ok_or(OperationError::MissingTemporaryStore)?,
                    &ValidationContext {
                        policy: ctx.policy.validation,
                        now,
                        anchors: &services.anchors,
                        intermediates: &services.intermediates,
                        http: &transport,
                    },
                    ctx.policy.allowed_signature_algorithms,
                    &mut ctx.scope,
                )
                .and_then(|report| report.into_aggregate(&ctx.scope));
                match result {
                    Ok((report, facts)) => {
                        pdf = Some(facts);
                        Ok(report)
                    }
                    Err(oncl_pdf::PdfError::Cms(error)) => Err(error),
                    Err(oncl_pdf::PdfError::Processing(error)) => Err(error.into()),
                    Err(oncl_pdf::PdfError::Io(error)) => {
                        Err(oncl_pki::resource::ProcessingError::Io(error).into())
                    }
                    Err(oncl_pdf::PdfError::Limit(_)) => {
                        Err(oncl_pki::resource::ProcessingError::MetadataLimit.into())
                    }
                    Err(_) => Err(oncl_pki::resource::ProcessingError::InvalidInput(
                        "unsupported or malformed PDF",
                    )
                    .into()),
                }
            }
            #[cfg(feature = "xml")]
            crate::VerifyProfile::Xml
            | crate::VerifyProfile::XmlKalkan
            | crate::VerifyProfile::Xades(_) => {
                if detached.is_some() {
                    return Err(OperationError::Processing(
                        oncl_pki::resource::ProcessingError::InvalidInput(
                            "XML does not accept detached input",
                        ),
                    ));
                }
                let profile = oncl_xml::XmlVerifyProfile {
                    canonicalization: if request.profile() == crate::VerifyProfile::XmlKalkan {
                        oncl_xml::C14nProfile::KalkanLegacy
                    } else {
                        oncl_xml::C14nProfile::Standard
                    },
                    allowed_signature_algorithms: ctx.policy.allowed_signature_algorithms,
                    evidence_limits: crate::xml::intersect_evidence_limits(
                        self.cades
                            .as_ref()
                            .map(|configuration| configuration.evidence_limits),
                        request.evidence_limits(),
                    ),
                    required_level: match request.profile() {
                        crate::VerifyProfile::Xades(level) => Some(level),
                        _ => None,
                    },
                    ..oncl_xml::XmlVerifyProfile::default()
                };
                match oncl_xml::verify_source(
                    input,
                    &profile,
                    self.temporary
                        .as_ref()
                        .ok_or(OperationError::MissingTemporaryStore)?,
                    &ValidationContext {
                        policy: ctx.policy.validation,
                        now,
                        anchors: &services.anchors,
                        intermediates: &services.intermediates,
                        http: &transport,
                    },
                    &services.network,
                    &mut ctx.scope,
                ) {
                    Ok(report) => {
                        ades_level = report.minimum_level();
                        xml = Some(report.facts);
                        Ok(report.validation)
                    }
                    Err(oncl_xml::XmlSourceError::Processing(error))
                    | Err(oncl_xml::XmlSourceError::Evidence(
                        oncl_pki::evidence::EvidenceError::Processing(error),
                    )) => Err(error.into()),
                    Err(oncl_xml::XmlSourceError::Evidence(
                        oncl_pki::evidence::EvidenceError::Limit,
                    )) => Err(oncl_pki::resource::ProcessingError::MetadataLimit.into()),
                    Err(_) => Err(oncl_pki::resource::ProcessingError::InvalidInput(
                        "unsupported, denied or malformed XML signature",
                    )
                    .into()),
                }
            }
        };
        transport.finish()?;
        ctx.scope.checkpoint()?;
        let report = result.map_err(stream_error)?;
        Ok(VerificationReport {
            id: ctx.id,
            verdict: report.verdict,
            policy: report.policy,
            checked_at: report.checked_at,
            signers: report.signers,
            #[cfg(feature = "pdf")]
            pdf,
            #[cfg(feature = "xml")]
            ades_level,
            #[cfg(not(feature = "xml"))]
            ades_level: None,
            #[cfg(feature = "xml")]
            xml,
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
