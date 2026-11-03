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
/// F03/F04 current status evaluated at genTime. No data means no document proof.
pub fn validate_document_token(
    token: &[u8],
    ctx: &ValidationContext<'_>,
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
    let result = validate_document_token_inner(token, &scoped, scope);
    http.finish()?;
    result
}
fn validate_document_token_inner(
    token: &[u8],
    ctx: &ValidationContext<'_>,
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
    let result = acquire_document_timestamp_inner(spec, digest, &scoped, scope);
    http.finish()?;
    result
}
fn acquire_document_timestamp_inner(
    spec: &TsaSpec,
    digest: &DigestValue,
    ctx: &ValidationContext<'_>,
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
    let nonce = spec.nonce.draw();
    let request = request_spec_der(spec, digest.as_bytes(), nonce.as_deref());
    let opts = GetOptions {
        timeout: spec.timeout,
        ..GetOptions::default()
    };
    let mut attempt = 0;
    loop {
        scope.checkpoint()?;
        let reply = crate::http::pki_send_scoped(
            ctx.http,
            &spec.method,
            &spec.url,
            TIMESTAMP_QUERY,
            &request,
            opts,
        );
        let reply = match reply {
            Err(_) if attempt < spec.retries => {
                attempt += 1;
                continue;
            }
            Err(error) => return Err(TspError::Http(error).into()),
            Ok(reply) => reply,
        };
        if reply.status() != 200 || !is_timestamp_reply(reply.content_type()) {
            if attempt < spec.retries {
                attempt += 1;
                continue;
            }
            return Err(if reply.status() != 200 {
                TspError::Status(reply.status())
            } else {
                TspError::ContentType(reply.content_type().map(str::to_owned))
            }
            .into());
        }
        let _decode = reply.reserve_decode().map_err(TspError::from)?;
        let token = response_token(reply.body())?;
        let mut result = validate_document_token(&token, ctx, scope)?;
        check_answers(&result.info, spec, digest.as_bytes(), nonce.as_deref())?;
        if spec
            .check_skew
            .is_some_and(|skew| (result.info.gen_time - ctx.now).unsigned_abs() > skew)
        {
            return Err(TspError::ClockSkew.into());
        }
        result.check_document(digest);
        return Ok(result);
    }
}
