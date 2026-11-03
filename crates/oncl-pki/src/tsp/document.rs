//! Standalone RFC3161 adapter. Cryptography and path/status semantics are the
//! existing TSP + F03/F04 mechanisms, not trust inferred from carried roots.
use super::*;
use crate::{
    digest::DigestValue,
    evidence::EvidenceError,
    resource::{ProcessingError, ResourceReservation, ResourceScope},
    validation::{self, CheckStatus, ValidationContext, ValidationPolicy, Verdict},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentImprint {
    NotProvided,
    Matched,
    Mismatched,
}
pub struct DocumentTimestamp {
    token: Vec<u8>,
    info: TstInfo,
    algorithm: Option<HashAlg>,
    signature: CheckStatus,
    eku: CheckStatus,
    chain: CheckStatus,
    validity: CheckStatus,
    revocation: CheckStatus,
    imprint: DocumentImprint,
    expectations: CheckStatus,
    now: OffsetDateTime,
    policy: ValidationPolicy,
    revoked_at: Option<OffsetDateTime>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl std::fmt::Debug for DocumentTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentTimestamp")
            .field("verdict", &self.verdict())
            .finish_non_exhaustive()
    }
}
impl DocumentTimestamp {
    pub fn token(&self) -> &[u8] {
        &self.token
    }
    pub fn algorithm(&self) -> Option<HashAlg> {
        self.algorithm
    }
    pub fn imprint(&self) -> DocumentImprint {
        self.imprint
    }
    pub fn imprint_bytes(&self) -> &[u8] {
        &self.info.imprint
    }
    pub fn nonce(&self) -> Option<&[u8]> {
        self.info.nonce.as_deref()
    }
    pub fn tsa_policy(&self) -> ObjectIdentifier {
        self.info.policy
    }
    pub fn gen_time(&self) -> OffsetDateTime {
        self.info.gen_time
    }
    pub fn checked_at(&self) -> OffsetDateTime {
        self.now
    }
    pub fn validation_policy(&self) -> ValidationPolicy {
        self.policy
    }
    pub fn signature(&self) -> CheckStatus {
        self.signature
    }
    pub fn eku(&self) -> CheckStatus {
        self.eku
    }
    pub fn chain(&self) -> CheckStatus {
        self.chain
    }
    pub fn validity(&self) -> CheckStatus {
        self.validity
    }
    pub fn revocation(&self) -> CheckStatus {
        self.revocation
    }
    pub fn expectations(&self) -> CheckStatus {
        self.expectations
    }
    pub fn revoked_at(&self) -> Option<OffsetDateTime> {
        self.revoked_at
    }
    pub fn verdict(&self) -> Verdict {
        let checks = [
            self.signature,
            self.eku,
            self.chain,
            self.validity,
            self.revocation,
            self.expectations,
        ];
        if self.imprint == DocumentImprint::Mismatched || checks.contains(&CheckStatus::Failed) {
            Verdict::Invalid
        } else if self.imprint == DocumentImprint::NotProvided
            || checks.contains(&CheckStatus::Unavailable)
        {
            Verdict::Indeterminate
        } else {
            Verdict::Valid
        }
    }
    /// The caller must compute this digest from the document. Algorithm tags,
    /// not just equal digest lengths, are part of the actual binding.
    pub fn check_document(&mut self, digest: &DigestValue) {
        self.imprint = if check_imprint(&self.info, digest).is_ok() {
            DocumentImprint::Matched
        } else {
            DocumentImprint::Mismatched
        };
    }
    pub fn check_expectations(
        &mut self,
        algorithm: Option<HashAlg>,
        policy: Option<ObjectIdentifier>,
        nonce: Option<&[u8]>,
        maximum_age: Option<Duration>,
    ) {
        if algorithm.is_some_and(|algorithm| self.algorithm != Some(algorithm))
            || policy.is_some_and(|policy| self.info.policy != policy)
            || nonce.is_some_and(|nonce| self.info.nonce.as_deref() != Some(nonce))
            || maximum_age.is_some_and(|age| (self.now - self.info.gen_time).unsigned_abs() > age)
        {
            self.expectations = CheckStatus::Failed;
        }
    }
}
/// Decode bounded token metadata, verify its actual signature/EKU, then reuse
/// F03/F04 current status at ctx.now and certificate validity at genTime. No data
/// means no document proof.
pub fn validate_document_token(
    token: &[u8],
    ctx: &ValidationContext<'_>,
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    validate_document_token_scoped(token, None, ctx, None, scope)
}
/// Hash optional actual document data before sampling the trusted host clock and
/// evaluating current status. Initial bounded decoding establishes no trust.
pub fn validate_document_token_with_clock(
    token: &[u8],
    data: Option<crate::io::Source<'_>>,
    ctx: &ValidationContext<'_>,
    clock: &(dyn Fn() -> OffsetDateTime + Send + Sync),
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    validate_document_token_scoped(token, data, ctx, Some(clock), scope)
}
fn validate_document_token_scoped(
    token: &[u8],
    data: Option<crate::io::Source<'_>>,
    ctx: &ValidationContext<'_>,
    clock: Option<&(dyn Fn() -> OffsetDateTime + Send + Sync)>,
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    if ctx
        .http
        .resource_scope()
        .is_some_and(|original| !original.same_operation(scope))
    {
        return Err(ProcessingError::InvalidInput(
            "timestamp transport belongs to another operation",
        )
        .into());
    }
    let http = crate::http::ResourceTransport::new(ctx.http, scope);
    let scoped = ValidationContext {
        policy: ctx.policy,
        now: ctx.now,
        anchors: ctx.anchors,
        intermediates: ctx.intermediates,
        http: &http,
    };
    let result = validate_document_token_inner(token, data, &scoped, clock, scope);
    http.finish()?;
    result
}
fn validate_document_token_inner(
    token: &[u8],
    data: Option<crate::io::Source<'_>>,
    ctx: &ValidationContext<'_>,
    clock: Option<&(dyn Fn() -> OffsetDateTime + Send + Sync)>,
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    scope.checkpoint()?;
    let bytes = (token.len() as u64)
        .checked_mul(64)
        .and_then(|n| n.checked_add(8192))
        .ok_or(ProcessingError::MetadataLimit)?;
    let memory = scope.reserve_memory(bytes)?;
    let metadata = scope.reserve_metadata(bytes)?;
    let token = ber::to_der(token).map_err(TspError::from)?;
    let ci = ContentInfo::from_der(&token).map_err(TspError::from)?;
    if ci.content_type != oid::SIGNED_DATA {
        return Err(TspError::Malformed("not a timestamp SignedData".into()).into());
    }
    let sd: SignedData<'_> = ci.content.decode_as().map_err(TspError::from)?;
    if sd.encap_content_info.e_content_type != oid::TST_INFO
        || sd.signer_infos.tlvs().map_err(TspError::from)?.len() != 1
    {
        return Err(TspError::Malformed("not one timestamp signer".into()).into());
    }
    let content = sd
        .encap_content_info
        .e_content
        .ok_or(TspError::Cms(CmsError::NoEncapsulatedData))?;
    let info = tst_info(content.as_bytes())?;
    let algorithm =
        HashAlg::from_oid(&info.imprint_alg).filter(|algorithm| *algorithm != HashAlg::Sha1);
    let digest = if let Some(data) = data {
        let algorithm = algorithm.ok_or(TspError::UnsupportedImprintAlgorithm(info.imprint_alg))?;
        Some(crate::digest::hash_source(
            data,
            algorithm,
            &mut scope.shared_view(),
        )?)
    } else {
        None
    };
    scope.checkpoint()?;
    let current = ValidationContext {
        now: clock.map_or(ctx.now, |clock| clock()),
        ..*ctx
    };
    if clock.is_some() && current.now < ctx.now {
        return Err(TspError::ClockSkew.into());
    }
    let ctx = &current;
    let mut result = DocumentTimestamp {
        token: Vec::new(),
        info,
        algorithm,
        signature: CheckStatus::Failed,
        eku: CheckStatus::Unavailable,
        chain: CheckStatus::Unavailable,
        validity: CheckStatus::Unavailable,
        revocation: CheckStatus::Unavailable,
        imprint: DocumentImprint::NotProvided,
        expectations: CheckStatus::Passed,
        now: ctx.now,
        policy: ctx.policy,
        revoked_at: None,
        _memory: memory,
        _metadata: metadata,
    };
    if algorithm
        .is_none_or(|algorithm| DigestValue::from_bytes(algorithm, &result.info.imprint).is_err())
        || result.info.gen_time > ctx.now
    {
        result.expectations = CheckStatus::Failed;
    }
    let verified = verify_token_signed(&token, false);
    scope.checkpoint()?;
    if let Ok((_, tsa)) = verified {
        result.signature = CheckStatus::Passed;
        result.eku = if cert_info(&tsa)
            .ext_key_usages
            .contains(&oid::TIME_STAMPING.to_string())
        {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        };
        let mut candidates = cms::certificates(&token).map_err(TspError::from)?;
        let mut host_bytes = 0u64;
        for cert in ctx.intermediates {
            scope.checkpoint()?;
            host_bytes = host_bytes
                .checked_add(
                    u64::from(u32::from(cert.encoded_len().map_err(TspError::from)?))
                        .checked_mul(64)
                        .and_then(|bytes| bytes.checked_add(1024))
                        .ok_or(ProcessingError::MetadataLimit)?,
                )
                .ok_or(ProcessingError::MetadataLimit)?;
        }
        let _host_candidates = scope.reserve_metadata(host_bytes)?;
        candidates
            .try_reserve_exact(ctx.intermediates.len())
            .map_err(|_| ProcessingError::MemoryLimit)?;
        candidates.extend_from_slice(ctx.intermediates);
        // Carried certificates are candidates only. The host anchor set is never
        // amended, and current revocation freshness still uses ctx.now.
        let checked =
            validation::validate_certificate(&tsa, result.info.gen_time, ctx, &candidates);
        result.chain = checked.chain;
        result.validity = checked.validity;
        if checked.key_usage == CheckStatus::Failed {
            result.eku = CheckStatus::Failed;
        }
        result.revocation = checked.revocation;
        result.revoked_at = checked.reasons.iter().find_map(|reason| match reason {
            validation::ValidationReason::Revoked { at }
            | validation::ValidationReason::RevokedAfterProvenTime { at } => Some(*at),
            _ => None,
        });
    }
    scope.checkpoint()?;
    result.token = token;
    if let Some(digest) = digest {
        result.check_document(&digest);
    }
    Ok(result)
}
/// Request only a digest; scoped HTTP owns both network body and decoder work.
/// A failed/undelivered reply never implies exactly-once issuance or rollback.
pub fn acquire_document_timestamp(
    spec: &TsaSpec,
    digest: &DigestValue,
    ctx: &ValidationContext<'_>,
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    acquire_document_timestamp_scoped(spec, digest, ctx, None, scope)
}
/// Acquire through the shared RFC3161 request implementation, then validate at
/// its post-reply trusted host sample. Static acquisition remains explicit-as-of.
pub fn acquire_document_timestamp_with_clock(
    spec: &TsaSpec,
    digest: &DigestValue,
    ctx: &ValidationContext<'_>,
    clock: &(dyn Fn() -> OffsetDateTime + Send + Sync),
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    acquire_document_timestamp_scoped(spec, digest, ctx, Some(clock), scope)
}
fn acquire_document_timestamp_scoped(
    spec: &TsaSpec,
    digest: &DigestValue,
    ctx: &ValidationContext<'_>,
    clock: Option<&(dyn Fn() -> OffsetDateTime + Send + Sync)>,
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    if ctx
        .http
        .resource_scope()
        .is_some_and(|original| !original.same_operation(scope))
    {
        return Err(ProcessingError::InvalidInput(
            "timestamp transport belongs to another operation",
        )
        .into());
    }
    let http = crate::http::ResourceTransport::new(ctx.http, scope);
    let scoped = ValidationContext {
        policy: ctx.policy,
        now: ctx.now,
        anchors: ctx.anchors,
        intermediates: ctx.intermediates,
        http: &http,
    };
    let result = acquire_document_timestamp_inner(spec, digest, &scoped, clock, scope);
    http.finish()?;
    result
}
fn acquire_document_timestamp_inner(
    spec: &TsaSpec,
    digest: &DigestValue,
    ctx: &ValidationContext<'_>,
    clock: Option<&(dyn Fn() -> OffsetDateTime + Send + Sync)>,
    scope: &ResourceScope,
) -> Result<DocumentTimestamp, EvidenceError> {
    if spec.hash != digest.algorithm()
        || spec.hash == HashAlg::Sha1
        || !spec.require_tsa_eku
        || spec.timeout.is_zero()
    {
        return Err(EvidenceError::InvalidBinding);
    }
    let nonce_len = match &spec.nonce {
        NonceSpec::None => 0,
        NonceSpec::Random(len) => usize::from(*len),
        NonceSpec::Value(bytes) => bytes.len(),
    };
    if nonce_len > 1024 || spec.url.len() > 8192 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let _request = scope.reserve_metadata((spec.url.len() as u64 + nonce_len as u64 + 4096) * 8)?;
    scope.checkpoint()?;
    let (reply, checked_at) = if let Some(clock) = clock {
        request_with_clock_scoped(spec, digest.as_bytes(), ctx.http, clock)?
    } else {
        (
            request_at_scoped(spec, digest.as_bytes(), ctx.http, ctx.now)?,
            ctx.now,
        )
    };
    if clock.is_some() && (reply.reply.tst.gen_time > checked_at || checked_at < ctx.now) {
        return Err(TspError::ClockSkew.into());
    }
    let current = ValidationContext {
        now: checked_at,
        ..*ctx
    };
    let mut result =
        validate_document_token_inner(&reply.reply.token, None, &current, None, scope)?;
    result.check_document(digest);
    Ok(result)
}
