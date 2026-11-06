//! Host-selected validation and evidence provenance shared by SDK and adapters.
//! Compatibility behavior is explicit; untrusted input cannot grant trust or network.
pub use crate::http::deadline::NetworkPolicy;
use crate::resource::{ProcessingError, ResourceReservation, ResourceScope};
use crate::{
    cert::Certificate,
    cms,
    crl::{self, CrlStatus},
    http::HttpTransport,
    info::{CertInfo, cert_info},
    ocsp::{self, CertStatus},
    pkix::{self, CaSet},
};
use time::OffsetDateTime;
const SIGNER_REASON_CAPACITY: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error(transparent)]
    Cms(#[from] cms::CmsError),
    #[error(transparent)]
    Processing(#[from] ProcessingError),
}
struct ReportMemory {
    memory: ResourceReservation,
    metadata: ResourceReservation,
    scope: ResourceScope,
}
impl std::fmt::Debug for ReportMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportMemory")
            .field("bytes", &self.memory.bytes())
            .field("metadata", &self.metadata.bytes())
            .finish()
    }
}

/// Owns checked signers and their charged storage as one transferable value.
/// Moving this collection retains the original operation admission; only
/// immutable borrowed signer/reason views are exposed.
///
/// ```compile_fail
/// fn detach_reasons(mut signers: oncl_pki::validation::ScopedSigners) {
///     let _unscoped = std::mem::take(&mut signers[0].reasons);
/// }
/// ```
#[derive(Debug)]
pub struct ScopedSigners {
    values: Vec<SignerValidation>,
    _memory: ReportMemory,
    _sources: Vec<ReportMemory>,
}
impl ScopedSigners {
    /// Append checked signers without detaching any original reservation/root.
    /// Admission includes old and new Vec storage during reallocations.
    pub fn append(&mut self, other: Self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        if !self._memory.scope.same_operation(scope) || !other._memory.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "reports belong to another operation",
            ));
        }
        let count = self
            .values
            .len()
            .checked_add(other.values.len())
            .ok_or(ProcessingError::MetadataLimit)?;
        let guards = self
            ._sources
            .len()
            .checked_add(other._sources.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(ProcessingError::MetadataLimit)?;
        let values_bytes = if count > self.values.capacity() {
            (count as u64)
                .checked_mul(std::mem::size_of::<SignerValidation>() as u64)
                .ok_or(ProcessingError::MemoryLimit)?
        } else {
            0
        };
        let guards_bytes = if guards > self._sources.capacity() {
            (guards as u64)
                .checked_mul(std::mem::size_of::<ReportMemory>() as u64)
                .ok_or(ProcessingError::MemoryLimit)?
        } else {
            0
        };
        let extra = values_bytes
            .checked_add(guards_bytes)
            .ok_or(ProcessingError::MemoryLimit)?;
        let old_values = if values_bytes != 0 {
            (self.values.capacity() as u64)
                .checked_mul(std::mem::size_of::<SignerValidation>() as u64)
                .ok_or(ProcessingError::MemoryLimit)?
        } else {
            0
        };
        let old_guards = if guards_bytes != 0 {
            (self._sources.capacity() as u64)
                .checked_mul(std::mem::size_of::<ReportMemory>() as u64)
                .ok_or(ProcessingError::MemoryLimit)?
        } else {
            0
        };
        let reclaimed = old_values
            .checked_add(old_guards)
            .ok_or(ProcessingError::MemoryLimit)?;
        self._memory.memory.grow(extra)?;
        self._memory.metadata.grow(extra)?;
        // A failed allocation retains the conservative extra charge. No live
        // buffer or source guard is ever made free by the failure path.
        self._sources
            .try_reserve_exact(guards - self._sources.len())
            .map_err(|_| ProcessingError::MemoryLimit)?;
        self.values
            .try_reserve_exact(count - self.values.len())
            .map_err(|_| ProcessingError::MemoryLimit)?;
        self._memory.memory.shrink(reclaimed)?;
        self._memory.metadata.shrink(reclaimed)?;
        self._sources.push(other._memory);
        self._sources.extend(other._sources);
        self.values.extend(other.values);
        Ok(())
    }
}
impl std::ops::Deref for ScopedSigners {
    type Target = [SignerValidation];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl ScopedSigners {
    pub(crate) fn cades_level(&mut self, index: usize, level: crate::evidence::AdesLevel) {
        if let Some(signer) = self.values.get_mut(index) {
            signer.ades_level = (signer.verdict() == Verdict::Valid).then_some(level);
        }
    }
    pub(crate) fn cades_failure(
        &mut self,
        index: usize,
        reason: ValidationReason,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        if !self._memory.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "CAdES facts belong to another operation",
            ));
        }
        let signer = self
            .values
            .get_mut(index)
            .ok_or(ProcessingError::InvalidInput("missing CAdES signer"))?;
        if signer.reasons.len() == signer.reasons.capacity() {
            let slots = self
                ._sources
                .len()
                .checked_add(1)
                .ok_or(ProcessingError::MemoryLimit)?;
            let bytes = signer
                .reasons
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(std::mem::size_of::<ValidationReason>()))
                .and_then(|bytes| {
                    slots
                        .checked_mul(std::mem::size_of::<ReportMemory>())
                        .and_then(|slots| bytes.checked_add(slots))
                })
                .ok_or(ProcessingError::MemoryLimit)? as u64;
            let growth = ReportMemory {
                memory: scope.reserve_memory(bytes)?,
                metadata: scope.reserve_metadata(bytes)?,
                scope: scope.retain(),
            };
            let mut sources = Vec::new();
            sources
                .try_reserve_exact(slots)
                .map_err(|_| ProcessingError::MemoryLimit)?;
            signer
                .reasons
                .try_reserve_exact(1)
                .map_err(|_| ProcessingError::MemoryLimit)?;
            sources.append(&mut self._sources);
            sources.push(growth);
            self._sources = sources;
        }
        if matches!(&reason, ValidationReason::Signature(_)) {
            signer.signature = CheckStatus::Failed;
        } else {
            signer.timestamp = CheckStatus::Failed;
        }
        signer.ades_level = None;
        signer.reasons.push(reason);
        scope.checkpoint()
    }
}
impl<'a> IntoIterator for &'a ScopedSigners {
    type Item = &'a SignerValidation;
    type IntoIter = std::slice::Iter<'a, SignerValidation>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationPolicy {
    StrictOnline,
    OfflineReport,
    NcalayerCompatibility,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    Invalid,
    Indeterminate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Passed,
    Failed,
    Unavailable,
    NotApplicable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeBasis {
    Current(OffsetDateTime),
    VerifiedTimestamp(OffsetDateTime),
    ClaimedSigningTime(OffsetDateTime),
}
/// Format checks can only invalidate already checked cryptographic evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatFailure {
    ReferenceDigestMismatch,
    ReferenceTargetMissing,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationReason {
    Signature(cms::Problem),
    Format(FormatFailure),
    CertificateValidity,
    UntrustedChain,
    KeyUsage,
    Timestamp,
    RevocationUnavailable,
    Revoked { at: OffsetDateTime },
    RevokedAfterProvenTime { at: OffsetDateTime },
    TimestampRevocationUnavailable,
    TimestampRevoked { at: OffsetDateTime },
    TimestampRevokedAfterProof { at: OffsetDateTime },
}
/// Checked signer facts are borrowed through the scoped owning report, not
/// a free deep-copy surface for SDK-allocated reason buffers.
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// fn copy_signer() {
///     requires_clone::<oncl_pki::validation::SignerValidation>();
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct SignerValidation {
    pub signature: CheckStatus,
    pub chain: CheckStatus,
    pub validity: CheckStatus,
    pub revocation: CheckStatus,
    pub timestamp: CheckStatus,
    pub key_usage: CheckStatus,
    pub claimed_signing_time: Option<OffsetDateTime>,
    pub time_basis: TimeBasis,
    /// Common evidence validation's fully checked proof, borrowed with this
    /// scoped report. Legacy CMS time provenance remains in `time_basis`.
    pub proof_time: Option<crate::evidence::ProofTime>,
    /// Actual format level, assigned only by a fully checked standard adapter.
    pub ades_level: Option<crate::evidence::AdesLevel>,
    pub reasons: Vec<ValidationReason>,
}
/// Owned validation output does not expose a separately droppable reservation:
/// ```compile_fail
/// fn detach(report: oncl_pki::validation::ValidationReport) {
///     drop(report.memory);
///     drop(report.signers);
/// }
/// ```
#[derive(Debug)]
pub struct ValidationReport {
    pub verdict: Verdict,
    pub policy: ValidationPolicy,
    pub checked_at: OffsetDateTime,
    pub signers: ScopedSigners,
}
impl ValidationReport {
    /// Attach an actual format failure under the report's original operation.
    /// This surface cannot mark checks passed, remove reasons or detach owners.
    pub fn invalidate_signer(
        &mut self,
        index: usize,
        failure: FormatFailure,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        if !self.signers._memory.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "report belongs to another operation",
            ));
        }
        let signer = self
            .signers
            .values
            .get_mut(index)
            .ok_or(ProcessingError::InvalidInput("signer index"))?;
        if signer.reasons.len() == signer.reasons.capacity() {
            // Reserve the old and new allocations while reallocation is live.
            let capacity = signer
                .reasons
                .capacity()
                .max(1)
                .checked_mul(2)
                .ok_or(ProcessingError::MetadataLimit)?;
            let old =
                signer.reasons.capacity() as u64 * std::mem::size_of::<ValidationReason>() as u64;
            let next = (capacity as u64)
                .checked_mul(std::mem::size_of::<ValidationReason>() as u64)
                .ok_or(ProcessingError::MetadataLimit)?;
            self.signers._memory.memory.grow(next)?;
            if let Err(error) = self.signers._memory.metadata.grow(next) {
                self.signers._memory.memory.shrink(next)?;
                return Err(error);
            }
            if signer
                .reasons
                .try_reserve_exact(capacity - signer.reasons.len())
                .is_err()
            {
                self.signers._memory.memory.shrink(next)?;
                self.signers._memory.metadata.shrink(next)?;
                return Err(ProcessingError::MemoryLimit);
            }
            self.signers._memory.memory.shrink(old)?;
            self.signers._memory.metadata.shrink(old)?;
        }
        signer.reasons.push(ValidationReason::Format(failure));
        signer.signature = CheckStatus::Failed;
        self.verdict = Verdict::Invalid;
        scope.checkpoint()
    }
}
pub struct ValidationContext<'a> {
    pub policy: ValidationPolicy,
    pub now: OffsetDateTime,
    pub anchors: &'a CaSet,
    pub intermediates: &'a [Certificate],
    pub http: &'a dyn HttpTransport,
}
impl SignerValidation {
    pub fn verdict(&self) -> Verdict {
        let checks = [
            self.signature,
            self.chain,
            self.validity,
            self.revocation,
            self.timestamp,
            self.key_usage,
        ];
        if checks.contains(&CheckStatus::Failed) {
            Verdict::Invalid
        } else if checks.contains(&CheckStatus::Unavailable) {
            Verdict::Indeterminate
        } else {
            Verdict::Valid
        }
    }
}
/// The existing CMS checker performs signed-attribute/content/signature and TSA
/// cryptography. This layer applies host trust, freshness and time provenance.
pub fn validate_cms(
    input: &[u8],
    detached: Option<&[u8]>,
    ctx: &ValidationContext<'_>,
    resources: &ResourceScope,
) -> Result<ValidationReport, ValidationError> {
    resources.checkpoint()?;
    // Preserve the existing bounded decoder scratch allowance at the PKI seam
    // itself; it no longer stands in for evidence or retained result capacity.
    let input_bytes = (input.len() as u64)
        .checked_add(detached.map_or(0, |bytes| bytes.len() as u64))
        .ok_or(ProcessingError::MemoryLimit)?;
    let parser_bytes = input_bytes
        .checked_mul(16)
        .and_then(|bytes| bytes.checked_add(1 << 20))
        .ok_or(ProcessingError::MemoryLimit)?;
    let _parser = resources.reserve_memory(parser_bytes)?;
    let normalized = crate::ber::to_der(input).map_err(cms::CmsError::from)?;
    let prepared = cms::report::PreparedCms::from_content(&normalized, detached)?;
    validate_prepared_cms(&prepared, ctx, resources)
}

/// Both bounded legacy input and the streaming metadata owner use this exact
/// signer/evidence/trust/time/status normalizer and scoped result constructor.
pub(crate) fn validate_prepared_cms(
    prepared: &cms::report::PreparedCms<'_>,
    ctx: &ValidationContext<'_>,
    resources: &ResourceScope,
) -> Result<ValidationReport, ValidationError> {
    let transport = crate::http::ResourceTransport::new(ctx.http, resources);
    let effective = ValidationContext {
        policy: ctx.policy,
        now: ctx.now,
        anchors: ctx.anchors,
        intermediates: ctx.intermediates,
        http: &transport,
    };
    let result = validate_prepared_cms_impl(prepared, &effective, resources);
    transport.finish()?;
    result
}

fn validate_prepared_cms_impl(
    prepared: &cms::report::PreparedCms<'_>,
    ctx: &ValidationContext<'_>,
    resources: &ResourceScope,
) -> Result<ValidationReport, ValidationError> {
    resources.checkpoint()?;
    let count = prepared.signer_count()?;
    // One exact-capacity output slot and eight reason slots per signer:
    // two integrity checks, validity, chain, usage, timestamp and two status facts.
    let result_bytes = count
        .checked_mul(
            std::mem::size_of::<SignerValidation>()
                + SIGNER_REASON_CAPACITY * std::mem::size_of::<ValidationReason>(),
        )
        .ok_or(ProcessingError::MemoryLimit)? as u64;
    let memory = ReportMemory {
        memory: resources.reserve_memory(result_bytes)?,
        metadata: resources.reserve_metadata(result_bytes)?,
        scope: resources.retain(),
    };
    let mut candidates = ctx.intermediates.to_vec();
    candidates.extend(prepared.certificates()?);
    let embedded = if ctx.policy == ValidationPolicy::OfflineReport {
        Some(EmbeddedEvidence::parse(prepared.encoded(), resources)?)
    } else {
        None
    };
    let mut signers = Vec::with_capacity(count);
    let flow =
        cms::report::visit_prepared_signers(prepared, &cms::ReportSpec::default(), |signer| {
            if let Err(error) = resources.checkpoint() {
                return std::ops::ControlFlow::Break(error);
            }
            let index = signers.len();
            let mut proven = None;
            let mut timestamp = CheckStatus::NotApplicable;
            let mut timestamp_reason = None;
            if let Some(tsp) = &signer.tsp {
                timestamp = CheckStatus::Failed;
                if tsp.check == cms::Check::Ok
                    && let (Some(time), Some(tsa)) = (tsp.gen_time, tsp.tsa_cert.as_ref())
                    && time <= ctx.now
                    && let Some(path) = anchored_path(tsa, &candidates, time, ctx)
                {
                    let (status, revoked) = match &embedded {
                        Some(evidence) => offline_revocation(
                            &path,
                            evidence.responses(index),
                            &evidence.crls,
                            time,
                            ctx.now,
                        ),
                        None => online_path_status(&path, time, ctx),
                    };
                    timestamp = status;
                    timestamp_reason = timestamp_reason_for(status, revoked, time);
                    // Explicit NCALayer compatibility: a token whose TSA is anchored fixes
                    // the time even when the TSA's own status cannot be obtained (the
                    // original never asked); the timestamp stays `Unavailable` in the
                    // report, so the verdict is never `Valid` on this basis alone.
                    if timestamp == CheckStatus::Passed
                        || (timestamp == CheckStatus::Unavailable
                            && ctx.policy == ValidationPolicy::NcalayerCompatibility)
                    {
                        proven = Some(time);
                    }
                }
            }
            if let Err(error) = resources.checkpoint() {
                return std::ops::ControlFlow::Break(error);
            }
            let at = proven.unwrap_or(ctx.now);
            let mut checked = match signer.certificate.as_ref() {
                Some(cert) => validate_certificate(cert, at, ctx, &candidates),
                None => SignerValidation {
                    signature: CheckStatus::Failed,
                    chain: CheckStatus::Unavailable,
                    validity: CheckStatus::Unavailable,
                    revocation: CheckStatus::Unavailable,
                    timestamp: CheckStatus::NotApplicable,
                    key_usage: CheckStatus::Unavailable,
                    claimed_signing_time: None,
                    time_basis: TimeBasis::Current(ctx.now),
                    proof_time: None,
                    ades_level: None,
                    reasons: Vec::with_capacity(SIGNER_REASON_CAPACITY),
                },
            };
            checked.claimed_signing_time = signer.signing_time;
            checked.time_basis =
                proven.map_or(TimeBasis::Current(ctx.now), TimeBasis::VerifiedTimestamp);
            checked.timestamp = timestamp;
            if matches!(timestamp, CheckStatus::Failed | CheckStatus::Unavailable) {
                checked.reasons.push(ValidationReason::Timestamp);
            }
            if let Some(reason) = timestamp_reason {
                checked.reasons.push(reason);
            }
            if let (Some(evidence), Some(cert)) = (&embedded, signer.certificate.as_ref())
                && let Some(path) =
                    anchored_path(cert, &candidates, path_time(&cert_info(cert), at), ctx)
            {
                let (status, revoked) = offline_revocation(
                    &path,
                    evidence.responses(index),
                    &evidence.crls,
                    at,
                    ctx.now,
                );
                checked.revocation = status;
                if let Some(time) = revoked {
                    checked.reasons.push(if time <= at {
                        ValidationReason::Revoked { at: time }
                    } else {
                        ValidationReason::RevokedAfterProvenTime { at: time }
                    });
                }
                if checked.revocation != CheckStatus::Unavailable {
                    checked
                        .reasons
                        .retain(|reason| *reason != ValidationReason::RevocationUnavailable);
                }
            }
            for check in [signer.signature, signer.ess_cert_id] {
                if let cms::Check::Fail(problem) = check {
                    checked.signature = CheckStatus::Failed;
                    checked.reasons.push(ValidationReason::Signature(problem));
                }
            }
            if let Err(error) = resources.checkpoint() {
                return std::ops::ControlFlow::Break(error);
            }
            signers.push(checked);
            std::ops::ControlFlow::Continue(())
        })?;
    if let std::ops::ControlFlow::Break(error) = flow {
        return Err(error.into());
    }
    let verdict = if signers.iter().any(|s| s.verdict() == Verdict::Invalid) {
        Verdict::Invalid
    } else if signers.is_empty()
        || signers
            .iter()
            .any(|s| s.verdict() == Verdict::Indeterminate)
    {
        Verdict::Indeterminate
    } else {
        Verdict::Valid
    };
    Ok(ValidationReport {
        verdict,
        policy: ctx.policy,
        checked_at: ctx.now,
        signers: ScopedSigners {
            values: signers,
            _memory: memory,
            _sources: Vec::new(),
        },
    })
}

enum CheckedPath {
    Legacy(Vec<Certificate>),
    Admitted(pkix::AdmittedPath),
}
impl std::ops::Deref for CheckedPath {
    type Target = [Certificate];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(path) => path,
            Self::Admitted(path) => path,
        }
    }
}
fn anchored_path(
    cert: &Certificate,
    candidates: &[Certificate],
    at: OffsetDateTime,
    ctx: &ValidationContext<'_>,
) -> Option<CheckedPath> {
    if let Some(scope) = ctx.http.resource_scope() {
        match pkix::build_anchored_path_admitted(cert, ctx.anchors, candidates, at, scope) {
            Ok(path) => Some(CheckedPath::Admitted(path)),
            Err(pkix::AdmittedPathError::Path) => None,
            Err(pkix::AdmittedPathError::Processing(error)) => {
                let _ = ctx.http.resource_failure(error);
                None
            }
        }
    } else {
        pkix::build_anchored_path(cert, ctx.anchors, candidates, at)
            .ok()
            .map(CheckedPath::Legacy)
    }
}
/// Mandatory current validation for private use calls this with StrictOnline,
/// irrespective of a caller's offline verification-report policy.
pub fn validate_certificate(
    cert: &Certificate,
    at: OffsetDateTime,
    ctx: &ValidationContext<'_>,
    candidates: &[Certificate],
) -> SignerValidation {
    let info = cert_info(cert);
    let mut report = certificate_facts(cert, at, &info);
    let path = anchored_path(cert, candidates, path_time(&info, at), ctx);
    match path {
        None => {
            report.chain = CheckStatus::Failed;
            report.reasons.push(ValidationReason::UntrustedChain);
        }
        Some(path) if ctx.policy != ValidationPolicy::OfflineReport => {
            let status = check_path_revocation(&path, at, ctx.http, ctx.now);
            match status {
                PathRevocation::Good => report.revocation = CheckStatus::Passed,
                PathRevocation::After(revoked) => {
                    report.revocation = CheckStatus::Passed;
                    report
                        .reasons
                        .push(ValidationReason::RevokedAfterProvenTime { at: revoked.time });
                }
                PathRevocation::Revoked(revoked) => {
                    report.revocation = CheckStatus::Failed;
                    report
                        .reasons
                        .push(ValidationReason::Revoked { at: revoked.time });
                }
                PathRevocation::Unavailable => {}
            }
        }
        Some(_) => {}
    }
    if report.revocation == CheckStatus::Unavailable {
        report.reasons.push(ValidationReason::RevocationUnavailable);
    }
    report
}

pub(crate) fn certificate_facts(
    cert: &Certificate,
    at: OffsetDateTime,
    info: &CertInfo,
) -> SignerValidation {
    let mut report = SignerValidation {
        signature: CheckStatus::Passed,
        chain: CheckStatus::Passed,
        validity: CheckStatus::Passed,
        revocation: CheckStatus::Unavailable,
        timestamp: CheckStatus::NotApplicable,
        key_usage: CheckStatus::Passed,
        claimed_signing_time: None,
        time_basis: TimeBasis::Current(at),
        proof_time: None,
        ades_level: None,
        reasons: Vec::with_capacity(SIGNER_REASON_CAPACITY),
    };
    if !is_valid_at(info, at) {
        report.validity = CheckStatus::Failed;
        report.reasons.push(ValidationReason::CertificateValidity);
    }
    // RFC5280: absent KU imposes no use restriction.
    let usage_ok = match cert
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::KeyUsage>()
    {
        Ok(None) => true,
        Ok(Some((_, usage))) => usage.digital_signature() || usage.non_repudiation(),
        Err(_) => false,
    };
    if !usage_ok {
        report.key_usage = CheckStatus::Failed;
        report.reasons.push(ValidationReason::KeyUsage);
    }
    report
}
pub fn is_valid_at(info: &CertInfo, at: OffsetDateTime) -> bool {
    info.not_before <= at && at <= info.not_after
}
pub fn path_time(info: &CertInfo, at: OffsetDateTime) -> OffsetDateTime {
    at.max(info.not_before).min(info.not_after)
}

/// Shared path revocation mechanism: the signer's status by OCSP bound to its issuer's path
/// (a CRL when OCSP gives none), then every CA certificate between the signer and the anchor
/// by the CRL of its issuer. Strict: an unknown or unreachable status is `Unavailable`,
/// never "not revoked"; a revocation after the proven time `at` does not invalidate.
pub enum PathRevocation {
    Good,
    Revoked(PathRevoked),
    After(PathRevoked),
    Unavailable,
}
pub struct PathRevoked {
    pub time: OffsetDateTime,
}
fn keep_earliest(earliest: &mut Option<PathRevoked>, revoked: PathRevoked) {
    if earliest.as_ref().is_none_or(|e| revoked.time < e.time) {
        *earliest = Some(revoked);
    }
}
pub fn check_path_revocation(
    path: &[Certificate],
    at: OffsetDateTime,
    http: &dyn HttpTransport,
    now: OffsetDateTime,
) -> PathRevocation {
    let Some(issuer) = path.get(1) else {
        return PathRevocation::Unavailable;
    };
    let mut unavailable = false;
    let mut after = None;
    // These candidates are a successfully anchored signer's path, never arbitrary client
    // CAs. Include them for the delegated responder chain.
    let status = ocsp::check_issuer_bound(
        &path[0],
        issuer,
        &CaSet::new(path[1..].to_vec()),
        http,
        now,
        ocsp::TIMEOUT,
    );
    let status = if !matches!(status, Ok(CertStatus::Good | CertStatus::Revoked { .. })) {
        match crl::fetch_status_for(&path[0], issuer, http, ocsp::TIMEOUT, now) {
            Ok(CrlStatus::Good) => Ok(CertStatus::Good),
            Ok(CrlStatus::Revoked { time, reason }) => Ok(CertStatus::Revoked { time, reason }),
            Err(_) => status,
        }
    } else {
        status
    };
    match status {
        Ok(CertStatus::Good) => {}
        Ok(CertStatus::Revoked { time, .. }) => {
            let revoked = PathRevoked { time };
            if time <= at {
                return PathRevocation::Revoked(revoked);
            }
            keep_earliest(&mut after, revoked);
        }
        Ok(CertStatus::Unknown) | Err(_) => unavailable = true,
    }
    for pair in path[1..].windows(2) {
        match crl::fetch_status_for(&pair[0], &pair[1], http, ocsp::TIMEOUT, now) {
            Ok(CrlStatus::Good) => {}
            Ok(CrlStatus::Revoked { time, .. }) => {
                let revoked = PathRevoked { time };
                if time <= at {
                    return PathRevocation::Revoked(revoked);
                }
                keep_earliest(&mut after, revoked);
            }
            Err(_) => unavailable = true,
        }
    }
    match after {
        _ if unavailable => PathRevocation::Unavailable,
        Some(revoked) => PathRevocation::After(revoked),
        None => PathRevocation::Good,
    }
}

/// Explicit NCALayer key-list compatibility: unavailable/unknown is not a
/// revocation indication. Never use this presentation decision for strict use.
pub fn compatibility_revoked(status: Option<CertStatus>) -> Option<OffsetDateTime> {
    match status {
        Some(CertStatus::Revoked { time, .. }) => Some(time),
        _ => None,
    }
}

/// One normalized CMS owns the bytes; common and local evidence own only views.
struct EmbeddedEvidence<'a> {
    common: Vec<&'a [u8]>,
    crls: Vec<&'a [u8]>,
    local: Vec<LocalEvidence<'a>>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
struct LocalEvidence<'a> {
    signer: usize,
    bytes: &'a [u8],
}
enum EvidenceKind {
    Common,
    Crl,
    Local(usize),
}
impl<'a> EmbeddedEvidence<'a> {
    fn parse(input: &'a [u8], resources: &ResourceScope) -> Result<Self, ValidationError> {
        let (mut common, mut crls, mut local) = (0usize, 0usize, 0usize);
        scan_evidence(input, |kind, _| match kind {
            EvidenceKind::Common => common += 1,
            EvidenceKind::Crl => crls += 1,
            EvidenceKind::Local(_) => local += 1,
        })?;
        let bytes = (common + crls)
            .checked_mul(std::mem::size_of::<&[u8]>())
            .and_then(|n| {
                local
                    .checked_mul(std::mem::size_of::<LocalEvidence<'_>>())
                    .and_then(|l| n.checked_add(l))
            })
            .ok_or(ProcessingError::MemoryLimit)?;
        let memory = resources.reserve_memory(bytes as u64)?;
        let metadata = resources.reserve_metadata(bytes as u64)?;
        let mut evidence = Self {
            common: Vec::with_capacity(common),
            crls: Vec::with_capacity(crls),
            local: Vec::with_capacity(local),
            _memory: memory,
            _metadata: metadata,
        };
        scan_evidence(input, |kind, bytes| match kind {
            EvidenceKind::Common => evidence.common.push(bytes),
            EvidenceKind::Crl => evidence.crls.push(bytes),
            EvidenceKind::Local(signer) => evidence.local.push(LocalEvidence { signer, bytes }),
        })?;
        Ok(evidence)
    }
    fn responses(&self, signer: usize) -> impl Iterator<Item = &'a [u8]> + Clone + '_ {
        self.local
            .iter()
            .filter(move |entry| entry.signer == signer)
            .map(|entry| entry.bytes)
            .chain(self.common.iter().copied())
    }
}
fn scan_evidence<'a>(
    input: &'a [u8],
    mut found: impl FnMut(EvidenceKind, &'a [u8]),
) -> Result<(), cms::CmsError> {
    use crate::cms::asn1::{Attribute, ContentInfo, SignedData, SignerInfo};
    use der::asn1::{AnyRef, ObjectIdentifier};
    use der::{Decode, Reader, SliceReader, Tagged};
    let ci = ContentInfo::from_der(input)?;
    let sd: SignedData<'_> = ci.content.decode_as()?;
    if let Some(set) = sd.crls {
        let mut reader = SliceReader::new(set.0)?;
        while !reader.is_finished() {
            let tlv = reader.tlv_bytes()?;
            if tlv.first() == Some(&0x30) {
                found(EvidenceKind::Crl, tlv);
            } else if tlv.first() == Some(&0xa1) {
                let any = AnyRef::from_der(tlv)?;
                let mut other = SliceReader::new(any.value())?;
                let oid: ObjectIdentifier = other.decode()?;
                let response = other.tlv_bytes()?;
                if oid == ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.16.2") {
                    found(EvidenceKind::Common, response);
                }
            }
        }
    }
    let mut reader = SliceReader::new(sd.signer_infos.0)?;
    let mut index = 0;
    while !reader.is_finished() {
        let signer = SignerInfo::from_der(reader.tlv_bytes()?)?;
        for attrs in [signer.signed_attrs, signer.unsigned_attrs]
            .into_iter()
            .flatten()
        {
            let mut attributes = SliceReader::new(attrs.0)?;
            while !attributes.is_finished() {
                let attribute = Attribute::from_der(attributes.tlv_bytes()?)?;
                if attribute.attr_type == crate::oid::OCSP_BASIC {
                    let mut values = SliceReader::new(attribute.attr_values.0)?;
                    while !values.is_finished() {
                        let tlv = values.tlv_bytes()?;
                        let any = AnyRef::from_der(tlv)?;
                        found(
                            EvidenceKind::Local(index),
                            if any.tag() == der::Tag::OctetString {
                                any.value()
                            } else {
                                tlv
                            },
                        );
                    }
                }
            }
        }
        index += 1;
    }
    Ok(())
}
pub(crate) fn offline_revocation<'a>(
    path: &[Certificate],
    responses: impl Iterator<Item = &'a [u8]> + Clone,
    crls: &[&[u8]],
    at: OffsetDateTime,
    now: OffsetDateTime,
) -> (CheckStatus, Option<OffsetDateTime>) {
    if path.len() < 2 {
        return (CheckStatus::Unavailable, None);
    }
    let trusted = CaSet::new(path[1..].to_vec());
    let mut unavailable = false;
    let mut revoked_after: Option<OffsetDateTime> = None;
    for (index, pair) in path.windows(2).enumerate() {
        let cert = &pair[0];
        let issuer = &pair[1];
        let mut status = None;
        if index == 0 {
            for response in responses.clone() {
                if let Ok(answer) =
                    ocsp::check_embedded_issuer_bound(response, cert, issuer, &trusted, now)
                    && answer.status != CertStatus::Unknown
                {
                    status = Some(answer.status);
                    break;
                }
            }
        }
        if status.is_none() {
            for bytes in crls {
                if let Ok(found) = crl::serial_status(
                    bytes,
                    issuer,
                    cert.tbs_certificate().serial_number().as_bytes(),
                    now,
                ) {
                    status = Some(match found {
                        CrlStatus::Good => CertStatus::Good,
                        CrlStatus::Revoked { time, reason } => CertStatus::Revoked { time, reason },
                    });
                    break;
                }
            }
        }
        match status {
            Some(CertStatus::Revoked { time, .. }) if time <= at => {
                return (CheckStatus::Failed, Some(time));
            }
            Some(CertStatus::Revoked { time, .. }) => {
                revoked_after = Some(revoked_after.map_or(time, |earliest| earliest.min(time)));
            }
            Some(CertStatus::Good) => {}
            _ => unavailable = true,
        }
    }
    (
        if unavailable {
            CheckStatus::Unavailable
        } else {
            CheckStatus::Passed
        },
        revoked_after,
    )
}

/// Shared F03/F04 mapping: current status evidence compared at the proven time.
pub(crate) fn online_path_status(
    path: &[Certificate],
    at: OffsetDateTime,
    ctx: &ValidationContext<'_>,
) -> (CheckStatus, Option<OffsetDateTime>) {
    match check_path_revocation(path, at, ctx.http, ctx.now) {
        PathRevocation::Good => (CheckStatus::Passed, None),
        PathRevocation::After(revoked) => (CheckStatus::Passed, Some(revoked.time)),
        PathRevocation::Revoked(revoked) => (CheckStatus::Failed, Some(revoked.time)),
        PathRevocation::Unavailable => (CheckStatus::Unavailable, None),
    }
}

pub(crate) fn timestamp_reason_for(
    status: CheckStatus,
    revoked: Option<OffsetDateTime>,
    at: OffsetDateTime,
) -> Option<ValidationReason> {
    if let Some(time) = revoked {
        Some(if time <= at {
            ValidationReason::TimestampRevoked { at: time }
        } else {
            ValidationReason::TimestampRevokedAfterProof { at: time }
        })
    } else if status == CheckStatus::Unavailable {
        Some(ValidationReason::TimestampRevocationUnavailable)
    } else {
        None
    }
}

/// Reserve before constructing F04 signer facts; never detach their buffers
/// from this immutable scoped owner.
pub(crate) struct SingleSignerReport {
    memory: ReportMemory,
    values: Vec<SignerValidation>,
}
impl SingleSignerReport {
    pub(crate) fn new(scope: &ResourceScope, reasons: usize) -> Result<Self, ProcessingError> {
        let bytes = reasons
            .checked_mul(std::mem::size_of::<ValidationReason>())
            .and_then(|n| n.checked_add(std::mem::size_of::<SignerValidation>()))
            .ok_or(ProcessingError::MemoryLimit)? as u64;
        let memory = ReportMemory {
            memory: scope.reserve_memory(bytes)?,
            metadata: scope.reserve_metadata(bytes)?,
            scope: scope.retain(),
        };
        Ok(Self {
            memory,
            values: Vec::with_capacity(1),
        })
    }
    pub(crate) fn finish(
        mut self,
        signer: SignerValidation,
        ctx: &ValidationContext<'_>,
    ) -> ValidationReport {
        let verdict = signer.verdict();
        self.values.push(signer);
        ValidationReport {
            verdict,
            policy: ctx.policy,
            checked_at: ctx.now,
            signers: ScopedSigners {
                values: self.values,
                _memory: self.memory,
                _sources: Vec::new(),
            },
        }
    }
}
