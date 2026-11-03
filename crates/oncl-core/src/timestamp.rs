//! Standalone streaming timestamps with explicit host-approved TSA requests.
use crate::{Action, Engine, OperationContext, OperationError, OperationId};
use oncl_pki::{
    digest::hash_source,
    evidence::EvidenceError,
    http::deadline::DeadlineTransport,
    io::{MetadataInput, Source},
    key::HashAlg,
    resource::ProcessingError,
    tsp::{DocumentTimestamp, TsaSpec},
    validation::{ValidationContext, Verdict},
};
use std::{io::Write, sync::Arc, time::Duration};
/// An explicit TSA specification is required; there is no hidden default TSA.
/// The configured host NetworkPolicy must authorize/pin its endpoint. The wire
/// request cannot change anchors, clock, transport or the network policy.
pub struct StampRequest {
    spec: TsaSpec,
}
impl StampRequest {
    pub fn new(spec: TsaSpec) -> Self {
        Self { spec }
    }
}
pub struct StampVerifyRequest {
    algorithm: Option<HashAlg>,
    policy: Option<der::asn1::ObjectIdentifier>,
    nonce: Option<Vec<u8>>,
    maximum_age: Option<Duration>,
}
impl StampVerifyRequest {
    pub fn new() -> Self {
        Self {
            algorithm: None,
            policy: None,
            nonce: None,
            maximum_age: None,
        }
    }
    pub fn with_algorithm(mut self, algorithm: HashAlg) -> Self {
        self.algorithm = Some(algorithm);
        self
    }
    pub fn with_policy(mut self, policy: der::asn1::ObjectIdentifier) -> Self {
        self.policy = Some(policy);
        self
    }
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }
    pub fn with_maximum_age(mut self, maximum_age: Duration) -> Self {
        self.maximum_age = Some(maximum_age);
        self
    }
}
impl Default for StampVerifyRequest {
    fn default() -> Self {
        Self::new()
    }
}
/// The immutable public token/facts owner retains its exact original operation.
/// ```compile_fail
/// fn detach(report: oncl_core::TimestampReport) -> oncl_pki::tsp::DocumentTimestamp {
///     report.facts().clone()
/// }
/// ```
#[derive(Debug)]
pub struct TimestampReport {
    id: OperationId,
    facts: DocumentTimestamp,
    bytes_in: u64,
    bytes_out: u64,
}
impl TimestampReport {
    pub fn id(&self) -> OperationId {
        self.id
    }
    pub fn facts(&self) -> &DocumentTimestamp {
        &self.facts
    }
    pub fn verdict(&self) -> Verdict {
        self.facts.verdict()
    }
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in
    }
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out
    }
}
fn error(error: EvidenceError) -> OperationError {
    match error {
        EvidenceError::Processing(error) => error.into(),
        EvidenceError::Limit => ProcessingError::MetadataLimit.into(),
        EvidenceError::InvalidBinding => {
            ProcessingError::InvalidInput("invalid standalone timestamp request").into()
        }
        EvidenceError::Timestamp(error) => OperationError::Timestamp(error),
    }
}
impl Engine {
    pub fn stamp(
        &self,
        request: &StampRequest,
        input: Source<'_>,
        output: &mut dyn Write,
        ctx: &mut OperationContext,
    ) -> Result<TimestampReport, OperationError> {
        let services = self.validation_context(ctx, Action::Stamp)?;
        // Verify request choices before consuming a possibly huge document.
        if request.spec.hash == HashAlg::Sha1
            || !request.spec.require_tsa_eku
            || request.spec.timeout.is_zero()
        {
            return Err(ProcessingError::InvalidInput("invalid timestamp profile").into());
        }
        let before = ctx.scope.progress();
        let digest = hash_source(input, request.spec.hash, &mut ctx.scope)?;
        let now = (services.clock)();
        let transport =
            DeadlineTransport::new(services.http.as_ref(), &services.network, &ctx.scope);
        let result = oncl_pki::tsp::acquire_document_timestamp(
            &request.spec,
            &digest,
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
        let facts = result.map_err(error)?;
        ctx.scope.checkpoint()?;
        if facts.verdict() != Verdict::Valid {
            return Err(OperationError::ValidationRequired);
        }
        for chunk in facts.token().chunks(oncl_pki::resource::IO_CHUNK_BYTES) {
            ctx.scope.checkpoint()?;
            ctx.scope.account_output(chunk.len() as u64)?;
            output.write_all(chunk).map_err(ProcessingError::from)?;
            ctx.scope.checkpoint()?;
        }
        Ok(TimestampReport {
            id: ctx.id,
            facts,
            bytes_in: ctx.scope.progress().bytes_in - before.bytes_in,
            bytes_out: ctx.scope.progress().bytes_out - before.bytes_out,
        })
    }
    pub fn verify_stamp(
        &self,
        request: &StampVerifyRequest,
        token: Source<'_>,
        data: Option<Source<'_>>,
        ctx: &mut OperationContext,
    ) -> Result<TimestampReport, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        let services = self.validation_context(ctx, Action::VerifyStamp)?;
        let before = ctx.scope.progress().bytes_in;
        let token = MetadataInput::read(token, &mut ctx.scope, oncl_pki::http::MAX_RESPONSE_LEN)?;
        let transport =
            DeadlineTransport::new(services.http.as_ref(), &services.network, &ctx.scope);
        let result = oncl_pki::tsp::validate_document_token(
            token.as_bytes(),
            &ValidationContext {
                policy: ctx.policy.validation,
                now: (services.clock)(),
                anchors: &services.anchors,
                intermediates: &services.intermediates,
                http: &transport,
            },
            &ctx.scope,
        );
        transport.finish()?;
        let mut facts = result.map_err(error)?;
        // End the immutable transport borrow before streaming data into scope.
        drop(transport);
        if let Some(data) = data {
            let algorithm = facts.algorithm().ok_or(OperationError::Key(
                oncl_pki::key::KeyError::UnsupportedAlgorithm,
            ))?;
            let digest = hash_source(data, algorithm, &mut ctx.scope)?;
            facts.check_document(&digest);
        }
        facts.check_expectations(
            request.algorithm,
            request.policy,
            request.nonce.as_deref(),
            request.maximum_age,
        );
        ctx.scope.checkpoint()?;
        Ok(TimestampReport {
            id: ctx.id,
            facts,
            bytes_in: ctx.scope.progress().bytes_in - before,
            bytes_out: 0,
        })
    }
}
