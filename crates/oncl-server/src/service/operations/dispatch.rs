pub(super) mod requests;
pub(super) mod results;
use super::*;
use crate::auth::{AccessPolicy, Principal};
use oncl_api::dto::{
    ExtendKind, InspectTarget, InspectedCms, InspectedEntry, JwsSignerFacts, KeyRef, SignKind,
    SignWriteMode, SignerChecks, SoapKind, TimestampFacts, VerifyProfile,
};
use oncl_core::keys::{KeyId, KeyRequest, KeySelector};
use oncl_pki::{cms::ades::ValidationMaterial, resource::ResourceScope};
use oncl_pki::{
    evidence::{AdesLevel, EvidenceLimits},
    validation::{CheckStatus, TimeBasis, ValidationPolicy, Verdict},
};
use std::collections::HashMap;

pub(super) fn action(operation: &Operation) -> Action {
    match operation {
        Operation::Hash { .. } => Action::Hash,
        Operation::Verify { .. } => Action::Verify,
        Operation::Extract { .. } => Action::Extract,
        Operation::Sign { .. } => Action::Sign,
        Operation::Extend { .. } => Action::Extend,
        // Plugins are authorized only by their exact operator grant (no action right).
        Operation::Plugin { .. } => Action::Hash,
        Operation::JwsSign { .. } | Operation::JwsAdd { .. } | Operation::JwtEncode { .. } => {
            Action::Sign
        }
        Operation::JwsVerify { .. } | Operation::JwtVerify { .. } => Action::Verify,
        Operation::JwtDecode { .. } => Action::Extract,
        Operation::Inspect { .. } => Action::Inspect,
        Operation::Stamp { .. } => Action::Stamp,
        Operation::VerifyStamp { .. } => Action::VerifyStamp,
    }
}
/// Operations whose result is a binary artifact stream, not only JSON.
pub(super) fn has_output(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Extract { .. }
            | Operation::Sign { .. }
            | Operation::Extend { .. }
            | Operation::Stamp { .. }
            | Operation::JwsSign { .. }
            | Operation::JwsAdd { .. }
            | Operation::JwtEncode { .. }
    )
}
fn jose_inputs<'a>(
    input: &'a str,
    detached: Option<&'a str>,
    certificate: Option<&'a str>,
) -> std::vec::IntoIter<&'a str> {
    let mut names = vec![input];
    names.extend(detached);
    names.extend(certificate);
    names.into_iter()
}
/// The documents that may already be signed results: the `input` of a verify, extend,
/// extract or sign item. Their engine classifies the signature, revision or envelope bytes
/// of its wire itself, so such a document may exceed `input_bytes` by container bytes (never
/// past `container_bytes`); every other document part stays within `input_bytes`.
pub(super) fn wire_inputs(metadata: &OperationMetadata) -> impl Iterator<Item = &str> {
    metadata
        .items
        .iter()
        .filter_map(|item| match &item.operation {
            Operation::Verify { input, .. }
            | Operation::Extend { input, .. }
            | Operation::Extract { input }
            | Operation::Sign { input, .. } => Some(input.as_str()),
            _ => None,
        })
}
/// The most bytes of one evidence document (certificate, OCSP response or CRL).
pub(super) const EVIDENCE_ITEM_BYTES: u64 = 1 << 20;
/// The most evidence references of one item (the cap `load_evidence` applies).
pub(super) const MAX_EVIDENCE_REFS: usize = 64;
/// The evidence documents of sign and extend items. They are validation material with their
/// own bounds ([`EVIDENCE_ITEM_BYTES`] each, and the evidence limits of the engine), not
/// documents: like the SDK and the CLI, which read them from memory and files, the service
/// does not charge them to the document allowance.
pub(super) fn evidence_inputs(metadata: &OperationMetadata) -> impl Iterator<Item = &str> {
    metadata
        .items
        .iter()
        .flat_map(|item| match &item.operation {
            Operation::Sign { evidence, .. } | Operation::Extend { evidence, .. } => {
                evidence.iter().map(|e| e.input.as_str()).collect()
            }
            _ => Vec::new(),
        })
}
pub(super) fn inputs(operation: &Operation) -> std::vec::IntoIter<&str> {
    let names = match operation {
        Operation::Hash { input, .. } => [Some(input.as_str()), None],
        Operation::Extract { input } => [Some(input.as_str()), None],
        Operation::Verify {
            input, detached, ..
        } => [Some(input.as_str()), detached.as_deref()],
        Operation::Sign {
            input,
            detached,
            evidence,
            ..
        }
        | Operation::Extend {
            input,
            detached,
            evidence,
            ..
        } => {
            let mut names = vec![input.as_str()];
            names.extend(detached.as_deref());
            names.extend(evidence.iter().map(|e| e.input.as_str()));
            return names.into_iter();
        }
        Operation::Plugin { .. } => [None, None],
        Operation::Stamp { input }
        | Operation::JwsSign { input, .. }
        | Operation::JwtEncode { input, .. }
        | Operation::JwtDecode { input } => [Some(input.as_str()), None],
        Operation::JwsAdd {
            input,
            detached,
            certificate,
            ..
        }
        | Operation::JwsVerify {
            input,
            detached,
            certificate,
            ..
        } => return jose_inputs(input, detached.as_deref(), certificate.as_deref()),
        Operation::JwtVerify { input, certificate } => {
            return jose_inputs(input, None, certificate.as_deref());
        }
        Operation::VerifyStamp { token, data, .. } => [Some(token.as_str()), data.as_deref()],
        Operation::Inspect { target } => match target {
            InspectTarget::Certificate { input } | InspectTarget::Cms { input } => {
                [Some(input.as_str()), None]
            }
            InspectTarget::Container { .. } | InspectTarget::Named { .. } => [None, None],
        },
    };
    names.into_iter().flatten().collect::<Vec<_>>().into_iter()
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SecretKind {
    Container,
    Password,
}
fn key_refs(operation: &Operation) -> &[KeyRef] {
    match operation {
        Operation::Sign { keys, .. }
        | Operation::JwsSign { keys, .. }
        | Operation::JwsAdd { keys, .. } => keys,
        Operation::JwtEncode { key, .. } => std::slice::from_ref(key),
        _ => &[],
    }
}
/// Secret parts referenced by an item (container, optional password).
pub(super) fn secret_refs(operation: &Operation) -> Vec<(&str, SecretKind)> {
    let mut refs = Vec::new();
    if let Operation::Inspect {
        target: InspectTarget::Container {
            container,
            password,
        },
    } = operation
    {
        refs.push((container.as_str(), SecretKind::Container));
        if let Some(password) = password {
            refs.push((password.as_str(), SecretKind::Password));
        }
    }
    for key in key_refs(operation) {
        if let KeyRef::Inline {
            container,
            password,
            ..
        } = key
        {
            refs.push((container.as_str(), SecretKind::Container));
            if let Some(password) = password {
                refs.push((password.as_str(), SecretKind::Password));
            }
        }
    }
    refs
}
pub(super) fn secret_kinds(metadata: &OperationMetadata) -> HashMap<&str, SecretKind> {
    metadata
        .items
        .iter()
        .flat_map(|item| secret_refs(&item.operation))
        .collect()
}
/// The one rights function of both public routes. A batch additionally needs the
/// token's separate batch right and carries no plugin item (the SDK closed batch has
/// no plugin operation); every item still passes the per-item rights of `precheck`
/// for ALL items before any document or secret byte is read.
pub(super) fn route_precheck(
    route: super::Route,
    metadata: &OperationMetadata,
    policy: &AccessPolicy,
    principal: &Principal,
    inline_enabled: bool,
    host: &super::HostPolicy,
) -> Result<(), ApiError> {
    if route == super::Route::Batch {
        policy
            .authorize_batch(principal)
            .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))?;
        if metadata
            .items
            .iter()
            .any(|item| matches!(item.operation, Operation::Plugin { .. }))
        {
            return Err(invalid_request());
        }
    }
    precheck(metadata, policy, principal, inline_enabled, host)
}
/// Rights that do not depend on received secret bytes. Runs right after the
/// bounded metadata parse and before any secret byte is reserved or read.
pub(super) fn precheck(
    metadata: &OperationMetadata,
    policy: &AccessPolicy,
    principal: &Principal,
    inline_enabled: bool,
    host: &super::HostPolicy,
) -> Result<(), ApiError> {
    let denied = || ApiError::not_applied(ErrorCode::PermissionDenied);
    for item in &metadata.items {
        let act = action(&item.operation);
        if let Operation::Plugin {
            plugin,
            operation,
            keys,
            ..
        } = &item.operation
        {
            // Liveness first: a plugin item has no action right, so without this a
            // revoked token would pass the exact-grant lookup (a host table).
            policy.ensure_live(principal).map_err(|_| denied())?;
            let grant = plugin_grant(host, principal, plugin, operation).ok_or_else(denied)?;
            if keys.len() > MAX_KEYS_PER_ITEM {
                return Err(invalid_request());
            }
            for key in keys {
                if !grant.keys.contains(&key.name) {
                    return Err(denied());
                }
                policy
                    .authorize(principal, Action::Sign, Some(&key.name), None)
                    .map_err(|_| denied())?;
            }
            continue;
        }
        if act != Action::Sign {
            policy
                .authorize(principal, act, None, None)
                .map_err(|_| denied())?;
        }
        let keys = key_refs(&item.operation);
        if act == Action::Sign && (keys.is_empty() || keys.len() > MAX_KEYS_PER_ITEM) {
            return Err(invalid_request());
        }
        for key in keys {
            match key {
                KeyRef::Named { name } => {
                    policy
                        .authorize(principal, Action::Sign, Some(name), None)
                        .map_err(|_| denied())?;
                }
                KeyRef::Inline { password, .. } => {
                    policy
                        .precheck_inline(principal, Action::Sign, inline_enabled)
                        .map_err(|_| denied())?;
                    if password.is_none() {
                        return Err(invalid_request());
                    }
                }
            }
        }
        if let Operation::Inspect {
            target: InspectTarget::Named { name },
        } = &item.operation
        {
            policy
                .authorize(principal, Action::Inspect, Some(name), None)
                .map_err(|_| denied())?;
        }
        if let Operation::Inspect {
            target: InspectTarget::Container { password, .. },
        } = &item.operation
        {
            if password.is_none() {
                return Err(invalid_request());
            }
            if policy
                .metadata_aliases(principal)
                .map_or(true, |aliases| aliases.is_empty())
            {
                return Err(denied());
            }
        }
        // XAdES timestamp levels bind the TSA policy OID (SDK contract): a host TSA
        // without one is a configuration refusal BEFORE any secret or body is read,
        // but only after this item's own rights passed (a token without the right
        // gets 403 and learns nothing about host configuration).
        if matches!(
            &item.operation,
            Operation::Sign {
                profile: SignKind::XadesT | SignKind::XadesLegacyT,
                ..
            }
        ) && host.tsa.as_ref().is_none_or(|t| t.policy.is_none())
        {
            return Err(ApiError::not_applied(ErrorCode::MissingConfiguration));
        }
    }
    Ok(())
}
fn plugin_grant<'h>(
    host: &'h super::HostPolicy,
    principal: &Principal,
    plugin: &str,
    operation: &str,
) -> Option<&'h super::PluginGrantRuntime> {
    host.plugin_grants
        .iter()
        .find(|g| g.token == principal.id() && g.plugin == plugin && g.operation == operation)
}
pub(super) const MAX_KEYS_PER_ITEM: usize = 8;
/// Host authorization of every key named by an item, performed after bounded
/// metadata/secret intake and BEFORE any document/provider/private work.
pub(super) struct Resolved {
    pub selectors: HashMap<String, Vec<KeySelector>>,
    pub keys: Vec<KeyId>,
    pub inline: HashMap<KeyId, ()>,
    pub reservations: Vec<oncl_pki::resource::ResourceReservation>,
    pub plugins: Vec<oncl_core::plugins::PluginPermission>,
}
pub(super) fn resolve_keys(
    metadata: &OperationMetadata,
    secrets: &intake::Secrets,
    policy: &AccessPolicy,
    principal: &Principal,
    inline_enabled: bool,
    host: &super::HostPolicy,
    scope: &ResourceScope,
) -> Result<Resolved, ApiError> {
    let denied = || ApiError::not_applied(ErrorCode::PermissionDenied);
    // One authorization function for rights: resolve_keys only adds what needs the
    // received bytes (the exact immutable InlineID) on top of `precheck`.
    precheck(metadata, policy, principal, inline_enabled, host)?;
    let mut resolved = Resolved {
        selectors: HashMap::new(),
        keys: Vec::new(),
        inline: HashMap::new(),
        reservations: Vec::new(),
        plugins: Vec::new(),
    };
    for item in &metadata.items {
        if let Operation::Plugin {
            plugin,
            operation,
            keys,
            ..
        } = &item.operation
        {
            let grant = plugin_grant(host, principal, plugin, operation).ok_or_else(denied)?;
            let mut selectors = Vec::new();
            for key in keys {
                let id = KeyId::new(&key.name).map_err(|_| invalid_request())?;
                if !resolved.keys.contains(&id) {
                    resolved.keys.push(id.clone());
                }
                selectors.push(KeySelector::named(id));
            }
            resolved.plugins.push(grant.permission.clone());
            resolved.selectors.insert(item.id.clone(), selectors);
            continue;
        }
        let keys = key_refs(&item.operation);
        if action(&item.operation) == Action::Sign
            && (keys.is_empty() || keys.len() > MAX_KEYS_PER_ITEM)
        {
            return Err(invalid_request());
        }
        if let Operation::Inspect {
            target: InspectTarget::Named { name },
        } = &item.operation
        {
            let id = KeyId::new(name).map_err(|_| invalid_request())?;
            if !resolved.keys.contains(&id) {
                resolved.keys.push(id);
            }
        }
        let mut selectors = Vec::with_capacity(keys.len());
        for key in keys {
            let selector = match key {
                KeyRef::Named { name } => {
                    KeySelector::named(KeyId::new(name).map_err(|_| invalid_request())?)
                }
                KeyRef::Inline {
                    container, alias, ..
                } => {
                    let bytes = secrets.bytes(container).map_err(processing_error)?;
                    resolved.reservations.push(
                        scope
                            .reserve_memory(bytes.len() as u64)
                            .map_err(processing_error)?,
                    );
                    let selector = KeySelector::inline(bytes.to_vec(), alias.clone());
                    policy
                        .authorize_inline(principal, Action::Sign, &selector, inline_enabled)
                        .map_err(|_| denied())?;
                    resolved.inline.insert(selector.key_id(), ());
                    selector
                }
            };
            if !resolved.keys.contains(&selector.key_id()) {
                resolved.keys.push(selector.key_id());
            }
            selectors.push(selector);
        }
        resolved.selectors.insert(item.id.clone(), selectors);
    }
    Ok(resolved)
}
pub(super) fn evidence_limits(limits: &oncl_pki::resource::ResourceLimits) -> EvidenceLimits {
    EvidenceLimits {
        max_items: 128,
        max_bytes: limits.metadata_bytes.min(16 << 20),
        max_item_bytes: limits.metadata_bytes.min(2 << 20),
        max_crl_bytes: limits.metadata_bytes.min(16 << 20),
        max_crl_item_bytes: limits.metadata_bytes.min(2 << 20),
        max_total_bytes: limits.metadata_bytes.min(16 << 20),
        max_chain_len: 8,
        max_proofs: 16,
        max_coverage_parts: 4096,
        // Proofs hash the signed document plus the container it carries (as the CLI does):
        // bounded by the output ceiling, not by the unsigned `input_bytes`.
        max_coverage_bytes: limits.output_bytes,
    }
}
pub(super) fn verify_request(
    profile: VerifyProfile,
    soap: Option<SoapKind>,
    limits: EvidenceLimits,
) -> oncl_core::VerifyRequest {
    use VerifyProfile::*;
    match profile {
        Cms => oncl_core::VerifyRequest::cms(),
        Pdf => oncl_core::VerifyRequest::pdf(),
        Xml => oncl_core::VerifyRequest::xml(),
        XmlKalkan => oncl_core::VerifyRequest::xml_kalkan(),
        XadesB => oncl_core::VerifyRequest::xades(AdesLevel::B),
        XadesT => oncl_core::VerifyRequest::xades(AdesLevel::T),
        XadesLt => oncl_core::VerifyRequest::xades(AdesLevel::Lt),
        XadesLta => oncl_core::VerifyRequest::xades(AdesLevel::Lta),
        Wsse => oncl_core::VerifyRequest::wsse(oncl_xml::wsse::WsseVerifyProfile {
            soap: soap_version(soap),
            ..Default::default()
        }),
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
fn policy_name(value: ValidationPolicy) -> &'static str {
    match value {
        ValidationPolicy::StrictOnline => "StrictOnline",
        ValidationPolicy::OfflineReport => "OfflineReport",
        ValidationPolicy::NcalayerCompatibility => "NcalayerCompatibility",
    }
}
fn check_name(value: CheckStatus) -> &'static str {
    check(value)
}
fn timestamp_facts(report: &oncl_core::TimestampReport) -> TimestampFacts {
    let facts = report.facts();
    TimestampFacts {
        verdict: verdict(report.verdict()),
        gen_time_unix: facts.gen_time().unix_timestamp(),
        checked_at_unix: facts.checked_at().unix_timestamp(),
        policy: match facts.validation_policy() {
            ValidationPolicy::StrictOnline => "StrictOnline",
            ValidationPolicy::OfflineReport => "OfflineReport",
            ValidationPolicy::NcalayerCompatibility => "NcalayerCompatibility",
        },
        algorithm: facts.algorithm().map(|a| format!("{a:?}")),
        imprint: format!("{:?}", facts.imprint()),
        signature: check_name(facts.signature()),
        eku: check_name(facts.eku()),
        chain: check_name(facts.chain()),
        validity: check_name(facts.validity()),
        revocation: check_name(facts.revocation()),
        expectations: check_name(facts.expectations()),
    }
}
/// Single shared failure policy for streaming and non-streaming execution.
/// Resource/deadline/cancel failures that never applied a key, with no earlier
/// applied item, stay a first-fatal abort; everything else is a typed failure
/// carrying the honest Applied state. A document or container limit is the exception:
/// the engine classifies the signed wire of a verify, extend, extract or sign input itself
/// (see [`wire_inputs`]), so the oversize refusal of such a document is only found here, and
/// it stays the typed, not applied `InputLimit` that any other oversize document gets at intake.
pub(super) enum Failure {
    Abort(ProcessingError),
    Typed(ApiError),
}
pub(super) fn classify(
    error: OperationError,
    applied_any: bool,
    subcode: Option<&'static str>,
) -> Failure {
    let mut failure = crate::service::operation_failure(&error);
    if let Some(subcode) = subcode {
        failure = failure.with_subcode(subcode);
    }
    let applied = failure.applied != oncl_api::error::AppliedState::NotApplied;
    match error {
        OperationError::Processing(e)
            if !matches!(
                intake::first_cause(&e),
                ProcessingError::InvalidInput(_)
                    | ProcessingError::InputLimit
                    | ProcessingError::ContainerLimit
            ) && !applied
                && !applied_any =>
        {
            Failure::Abort(e)
        }
        _ => Failure::Typed(failure),
    }
}
/// Item-level key application derived from the real per-signer/report state.
pub(super) fn applied_of(result: &OperationResult) -> oncl_api::error::AppliedState {
    use oncl_api::error::AppliedState as A;
    let fold = |signers: &[A]| {
        signers.iter().fold(A::NotApplied, |a, s| match (a, *s) {
            (A::Unknown, _) | (_, A::Unknown) => A::Unknown,
            (A::Applied, _) | (_, A::Applied) => A::Applied,
            _ => A::NotApplied,
        })
    };
    // Exhaustive: a new result family must decide its key-application state.
    match result {
        OperationResult::Plugin { applied, .. } => *applied,
        OperationResult::Signing { signers, .. } | OperationResult::Jws { signers, .. } => {
            fold(signers)
        }
        OperationResult::Hash { .. }
        | OperationResult::Verification { .. }
        | OperationResult::Extraction { .. }
        | OperationResult::Extension { .. }
        | OperationResult::Inspection { .. }
        | OperationResult::Stamping { .. }
        | OperationResult::StampVerification { .. }
        | OperationResult::JwsVerification { .. }
        | OperationResult::JwtDecoded { .. }
        | OperationResult::JwtVerification { .. } => A::NotApplied,
    }
}
pub(super) struct ArtifactSink<'a> {
    pub store: &'a Arc<super::artifact::ArtifactStore>,
    pub owner: &'a Arc<super::ownership::OperationOutput>,
    pub id: String,
}
pub(super) struct Env<'a> {
    pub engine: &'a Engine,
    pub documents: &'a mut intake::Documents,
    pub secrets: &'a intake::Secrets,
    pub selectors: &'a HashMap<String, Vec<KeySelector>>,
    pub staging: Option<&'a oncl_pki::io::TemporaryStore>,
    pub host: &'a super::HostPolicy,
    pub caller: &'a oncl_core::plugins::CallerContext,
    /// The subcode of the plugin refusal of the item that just failed, for [`classify`].
    pub subcode: Option<&'static str>,
}
/// The stable subcode of why a plugin call was refused, if Core or the server's ticket policy
/// named a reason (docs/design/manual-plugins.md 4.8): the policy's refusal of this very
/// invocation first, otherwise Core's own (an undeclared operation).
fn plugin_subcode(host: &super::HostPolicy, ctx: &OperationContext) -> Option<&'static str> {
    use oncl_core::plugins::PluginRefusalCode;
    host.plugin_policy
        .take_refusal(ctx.id())
        .map(|refusal| PluginRefusalCode::from(refusal).id())
        .or_else(|| ctx.plugin_refusal_code().map(PluginRefusalCode::id))
}
fn applied(value: oncl_pki::key::AppliedState) -> oncl_api::error::AppliedState {
    match value {
        oncl_pki::key::AppliedState::NotApplied => oncl_api::error::AppliedState::NotApplied,
        oncl_pki::key::AppliedState::Applied => oncl_api::error::AppliedState::Applied,
        oncl_pki::key::AppliedState::Unknown => oncl_api::error::AppliedState::Unknown,
    }
}
fn ades_level(kind: SignKind) -> Option<AdesLevel> {
    use SignKind::*;
    match kind {
        Cms | Pdf | Xml | Wsse | XmlLegacy | XadesLegacyB | XadesLegacyT => None,
        CadesB | PadesB | XadesB => Some(AdesLevel::B),
        CadesT | PadesT | XadesT => Some(AdesLevel::T),
        CadesLt | PadesLt => Some(AdesLevel::Lt),
        CadesLta | PadesLta => Some(AdesLevel::Lta),
    }
}
/// Caller-acquired public status/chain evidence. It is never a trust anchor.
pub(super) struct Evidence {
    pub(super) certificates: Vec<oncl_pki::cert::Certificate>,
    ocsp: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    _reservations: Vec<ResourceReservation>,
}
impl Evidence {
    pub(super) fn slices(&self) -> (Vec<&[u8]>, Vec<&[u8]>) {
        (
            self.ocsp.iter().map(Vec::as_slice).collect(),
            self.crls.iter().map(Vec::as_slice).collect(),
        )
    }
}
pub(super) fn load_evidence(
    env: &mut Env<'_>,
    refs: &[oncl_api::dto::EvidenceRef],
    ctx: &mut OperationContext,
) -> Result<Evidence, OperationError> {
    use oncl_api::dto::EvidenceKind;
    if refs.len() > MAX_EVIDENCE_REFS {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let mut evidence = Evidence {
        certificates: Vec::new(),
        ocsp: Vec::new(),
        crls: Vec::new(),
        _reservations: Vec::new(),
    };
    for reference in refs {
        let mut document = env.documents.take(&reference.input)?;
        let (bytes, reservation) = read_bytes(&mut document, ctx, EVIDENCE_ITEM_BYTES as usize)?;
        evidence._reservations.push(reservation);
        match reference.kind {
            EvidenceKind::Certificate => evidence.certificates.push(
                oncl_pki::cert::parse(&bytes)
                    .map_err(|_| ProcessingError::InvalidInput("invalid evidence certificate"))?,
            ),
            EvidenceKind::Ocsp => evidence.ocsp.push(bytes),
            EvidenceKind::Crl => evidence.crls.push(bytes),
        }
    }
    Ok(evidence)
}
fn soap_version(kind: Option<SoapKind>) -> oncl_xml::wsse::SoapVersion {
    match kind {
        Some(SoapKind::Soap12) => oncl_xml::wsse::SoapVersion::Soap12,
        _ => oncl_xml::wsse::SoapVersion::Soap11,
    }
}
/// Reject unsupported field/profile combinations from metadata alone, before any
/// key, secret or document is touched.
pub(super) fn validate_shape(operation: &Operation) -> Result<(), ApiError> {
    // `load_evidence` takes at most MAX_EVIDENCE_REFS references; refusing more here bounds the
    // evidence spool before any part is read.
    if let Operation::Sign { evidence, .. } | Operation::Extend { evidence, .. } = operation
        && evidence.len() > MAX_EVIDENCE_REFS
    {
        return Err(invalid_request());
    }
    match operation {
        Operation::Sign {
            profile,
            detached,
            mode,
            attached,
            target,
            parent,
            signature_id,
            soap,
            body_id,
            element,
            xpath_parent,
            signature_method,
            digest_method,
            evidence,
            ..
        } => {
            use SignKind::*;
            let cms_like = matches!(profile, Cms | CadesB | CadesT | CadesLt | CadesLta);
            let xml_ids = matches!(profile, Xml | XadesB | XadesT);
            let legacy = matches!(profile, XmlLegacy | XadesLegacyB | XadesLegacyT);
            let high = matches!(profile, CadesLt | CadesLta | PadesLt | PadesLta);
            // LT/LTA need caller-acquired OCSP/CRL material: predictable, so refused
            // before any secret/key/document is touched (not after key use).
            if high && !has_status_material(evidence) {
                return Err(invalid_request());
            }
            let bad = (!cms_like
                && (*mode == SignWriteMode::Add || *attached || detached.is_some()))
                || (*mode == SignWriteMode::Create && detached.is_some())
                || (!xml_ids && (target.is_some() || parent.is_some() || signature_id.is_some()))
                || (!matches!(profile, Wsse) && (soap.is_some() || body_id.is_some()))
                || (!legacy
                    && (element.is_some()
                        || xpath_parent.is_some()
                        || signature_method.is_some()
                        || digest_method.is_some()))
                || (!high
                    && !evidence.is_empty()
                    && !matches!(
                        profile,
                        CadesT | PadesT | XadesT | XadesLegacyB | XadesLegacyT
                    ));
            if bad {
                return Err(invalid_request());
            }
            Ok(())
        }
        Operation::Extend {
            profile, evidence, ..
        } if matches!(
            profile,
            ExtendKind::CadesLt
                | ExtendKind::CadesLta
                | ExtendKind::PadesLt
                | ExtendKind::PadesLta
                | ExtendKind::XadesLt
                | ExtendKind::XadesLta
        ) && !has_status_material(evidence) =>
        {
            Err(invalid_request())
        }
        Operation::Verify { profile, soap, .. }
            if soap.is_some() && !matches!(profile, VerifyProfile::Wsse) =>
        {
            Err(invalid_request())
        }
        _ => Ok(()),
    }
}
fn has_status_material(evidence: &[oncl_api::dto::EvidenceRef]) -> bool {
    use oncl_api::dto::EvidenceKind;
    evidence
        .iter()
        .any(|e| matches!(e.kind, EvidenceKind::Ocsp | EvidenceKind::Crl))
}
/// Host-side reservations made AFTER the preflight, from named quantities (not fitted):
/// the document/evidence/frame/output chunk buffers (`IO_CHUNK_BYTES` each) and a
/// bounded metadata projection; the request's evidence is additionally copied once by
/// `read_bytes`.
const HOST_CHUNK_BUFFERS: u64 = 4;
const HOST_METADATA_BYTES: u64 = 64 << 10;
fn refuse_processing(error: ProcessingError) -> ApiError {
    crate::service::processing_error(error)
}
/// A PDF the layer cannot read is a predictable refusal (never a zero default):
/// limits keep their typed code, resource/deadline/cancel keep theirs, the rest is
/// an invalid request, all before any key use.
fn refuse_pdf(error: oncl_pdf::PdfError) -> ApiError {
    match error {
        oncl_pdf::PdfError::Processing(error) => crate::service::processing_error(error),
        oncl_pdf::PdfError::Limit(_) => ApiError::not_applied(ErrorCode::InputLimit),
        _ => invalid_request(),
    }
}
/// Refuse a predictable PAdES LT/LTA memory need BEFORE any private key use, from
/// inputs known before the key opens: the PDF's existing signature contents (read from
/// the document), the request's evidence sizes and the operator trust set. The need
/// comes from `oncl_pdf::budget::plan_memory` (the reservation formulas the PDF layer
/// itself uses) and is probed against the ORIGINAL scope and released.
pub(super) fn memory_preflight(
    metadata: &OperationMetadata,
    documents: &mut intake::Documents,
    host: &super::HostPolicy,
    scope: &mut ResourceScope,
) -> Result<(), ApiError> {
    let refuse = || ApiError::not_applied(ErrorCode::MemoryLimit);
    let limits = oncl_pdf::PdfLimits::default();
    for item in &metadata.items {
        let (input, evidence) = match &item.operation {
            Operation::Sign {
                profile: SignKind::PadesLt | SignKind::PadesLta,
                input,
                evidence,
                ..
            }
            | Operation::Extend {
                profile: ExtendKind::PadesLt | ExtendKind::PadesLta,
                input,
                evidence,
                ..
            } => (input, evidence),
            _ => continue,
        };
        let mut evidence_bytes = 0u64;
        for reference in evidence {
            evidence_bytes += documents
                .get_mut(&reference.input)
                .map(|d| d.len())
                .ok_or_else(invalid_request)?;
        }
        let prior = {
            let mut document = documents.get_mut(input).ok_or_else(invalid_request)?;
            let mut reader = document.reader(scope).map_err(refuse_processing)?;
            oncl_pdf::budget::prior_signature_contents(reader.source(), &limits, scope)
                .map_err(refuse_pdf)?
        };
        signature_count_fits(prior.count, limits.max_signatures)?;
        let inputs = oncl_pdf::budget::PlanInputs {
            xref_entries: prior.xref_entries,
            prior_contents_sum: prior.contents_sum,
            prior_contents_max: prior.contents_max,
            evidence_bytes,
            trust_bytes: host.trust_bytes,
        };
        let need = oncl_pdf::budget::plan_memory(&limits, &inputs)
            .ok()
            .and_then(|n| {
                n.checked_add(HOST_CHUNK_BUFFERS * oncl_pki::resource::IO_CHUNK_BYTES as u64)
            })
            .and_then(|n| n.checked_add(HOST_METADATA_BYTES))
            .and_then(|n| n.checked_add(evidence_bytes))
            .ok_or_else(refuse)?;
        let need_metadata = oncl_pdf::budget::plan_metadata(&limits, &inputs)
            .ok()
            .and_then(|n| n.checked_add(HOST_METADATA_BYTES))
            .ok_or_else(|| ApiError::not_applied(ErrorCode::MetadataLimit))?;
        // Deadline, cancellation and capacity keep their own typed codes; only a real
        // memory/metadata shortfall is MemoryLimit/MetadataLimit.
        scope
            .reserve_metadata(need_metadata)
            .map(drop)
            .map_err(refuse_processing)?;
        scope
            .reserve_memory(need)
            .map(drop)
            .map_err(refuse_processing)?;
    }
    Ok(())
}
/// The new signature must itself fit the PDF signature-count limit (a document that
/// already carries `max_signatures` signatures fails after key use otherwise).
fn signature_count_fits(prior: u64, maximum: usize) -> Result<(), ApiError> {
    if prior.saturating_add(1) > maximum as u64 {
        return Err(ApiError::not_applied(ErrorCode::InputLimit));
    }
    Ok(())
}
fn is_xml(kind: SignKind) -> bool {
    matches!(kind, SignKind::Xml | SignKind::XadesB | SignKind::XadesT)
}
fn is_pdf(kind: SignKind) -> bool {
    matches!(
        kind,
        SignKind::Pdf
            | SignKind::PadesB
            | SignKind::PadesT
            | SignKind::PadesLt
            | SignKind::PadesLta
    )
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Cms,
    Pdf,
    Xml,
}
fn extend_level(kind: ExtendKind) -> (AdesLevel, Format) {
    use ExtendKind::*;
    match kind {
        CadesT => (AdesLevel::T, Format::Cms),
        CadesLt => (AdesLevel::Lt, Format::Cms),
        CadesLta => (AdesLevel::Lta, Format::Cms),
        PadesT => (AdesLevel::T, Format::Pdf),
        PadesLt => (AdesLevel::Lt, Format::Pdf),
        PadesLta => (AdesLevel::Lta, Format::Pdf),
        XadesLt => (AdesLevel::Lt, Format::Xml),
        XadesLta => (AdesLevel::Lta, Format::Xml),
    }
}
/// The sign/extend result is always a new SDK-staged artifact; the engine
/// charges its output once and a failed operation poisons it.
pub(super) fn staged_output(
    env: &Env<'_>,
    ctx: &mut OperationContext,
) -> Result<oncl_pki::io::StagedArtifact, OperationError> {
    env.staging
        .ok_or(OperationError::MissingTemporaryStore)?
        .stage(ctx.resources())
        .map_err(Into::into)
}
pub(super) fn key_requests<'a>(
    keys: &[KeyRef],
    selectors: &'a [KeySelector],
    secrets: &'a intake::Secrets,
) -> Result<Vec<KeyRequest<'a>>, OperationError> {
    let mut requests = Vec::with_capacity(keys.len());
    for (key, selector) in keys.iter().zip(selectors) {
        let password = match key {
            KeyRef::Named { .. } => None,
            KeyRef::Inline { password, .. } => password
                .as_deref()
                .map(|name| secrets.text(name))
                .transpose()?,
        };
        requests.push(KeyRequest::new(selector, password));
    }
    if requests.len() != keys.len() {
        return Err(ProcessingError::InvalidInput("unresolved signing keys").into());
    }
    Ok(requests)
}
/// Bounded in-memory copy of a public document (JOSE APIs borrow slices).
pub(super) fn read_bytes(
    document: &mut intake::Document,
    ctx: &mut OperationContext,
    maximum: usize,
) -> Result<(Vec<u8>, ResourceReservation), OperationError> {
    use std::io::Read;
    let length = usize::try_from(document.len()).map_err(|_| ProcessingError::InputLimit)?;
    if length > maximum {
        return Err(ProcessingError::InputLimit.into());
    }
    let reservation = ctx.resources().reserve_memory(length as u64)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    let mut reader = document.reader(ctx.resources())?;
    reader
        .source()
        .take(length as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(ProcessingError::from)?;
    reader.finish()?;
    if bytes.len() != length {
        return Err(ProcessingError::InvalidInput("document length changed").into());
    }
    Ok((bytes, reservation))
}
pub(super) fn jose_profile(
    format: oncl_api::dto::JwsFormat,
    detached: bool,
) -> oncl_core::jose::JoseProfile {
    use oncl_core::jose::JwsSerialization as S;
    oncl_core::jose::JoseProfile::new(
        match format {
            oncl_api::dto::JwsFormat::Compact => S::Compact,
            oncl_api::dto::JwsFormat::Flattened => S::Flattened,
            oncl_api::dto::JwsFormat::General => S::General,
        },
        detached,
    )
}
fn jws_signers(report: &oncl_core::jose::JwsVerificationReport) -> Vec<JwsSignerFacts> {
    report
        .signers()
        .iter()
        .map(|s| JwsSignerFacts {
            algorithm: s.algorithm().name(),
            crypto: check(s.crypto()),
            verdict: verdict(s.verdict()),
            trust: signer(s.trust()),
        })
        .collect()
}
pub(super) fn certificate(
    env: &mut Env<'_>,
    name: Option<String>,
    ctx: &mut OperationContext,
) -> Result<Option<oncl_pki::cert::Certificate>, OperationError> {
    let Some(name) = name else { return Ok(None) };
    let mut document = env.documents.take(&name)?;
    let (bytes, _reservation) = read_bytes(&mut document, ctx, 1 << 20)?;
    oncl_pki::cert::parse(&bytes)
        .map(Some)
        .map_err(|_| ProcessingError::InvalidInput("invalid public certificate").into())
}
/// A host failure after the SDK reported key application keeps its truthful
/// Applied/Unknown state instead of becoming NotApplied.
fn after_use<T, E: Into<OperationError>>(
    applied: oncl_pki::key::AppliedState,
    result: Result<T, E>,
) -> Result<T, OperationError> {
    result.map_err(|error| {
        let error = error.into();
        if applied == oncl_pki::key::AppliedState::NotApplied
            || matches!(error, OperationError::AfterKeyUse { .. })
        {
            error
        } else {
            OperationError::AfterKeyUse {
                source: Box::new(error),
                applied,
            }
        }
    })
}
fn strongest(
    states: impl IntoIterator<Item = oncl_pki::key::AppliedState>,
) -> oncl_pki::key::AppliedState {
    use oncl_pki::key::AppliedState::*;
    states.into_iter().fold(NotApplied, |a, s| match (a, s) {
        (Unknown, _) | (_, Unknown) => Unknown,
        (Applied, _) | (_, Applied) => Applied,
        _ => NotApplied,
    })
}
/// Runs one item and reports only its closed kind/outcome/applied-state to the
/// optional telemetry of the current request (no ids, names, sizes or messages).
pub(super) fn run(
    operation: Operation,
    item_id: &str,
    env: &mut Env<'_>,
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
    use crate::telemetry::{ItemResult, Observer, operation_kind};
    let observer = Observer::worker();
    if !observer.enabled() {
        return run_item(operation, item_id, env, ctx, output);
    }
    let (kind, family) = operation_kind(&operation);
    let timer = observer.item_start();
    let outcome = run_item(operation, item_id, env, ctx, output);
    let result = match &outcome {
        Ok((result, ..)) => ItemResult::Ok(applied_of(result)),
        Err(error) => {
            let failure = crate::service::operation_failure(error);
            ItemResult::Failed(failure.code, failure.applied)
        }
    };
    observer.item_end(timer, kind, family, result);
    outcome
}
fn run_item(
    operation: Operation,
    item_id: &str,
    env: &mut Env<'_>,
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
            let mut document = env.documents.take(&input)?;
            let bytes_in = document.len();
            let mut reader = document.reader(ctx.resources())?;
            let report = env.engine.hash(algorithm(hash), reader.source(), ctx)?;
            reader.finish()?;
            let (result, bytes) = results::hash(hash, &report, bytes_in);
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, None))
        }
        Operation::Verify {
            profile,
            input,
            detached,
            soap,
        } => {
            let mut document = env.documents.take(&input)?;
            let mut detached = detached.map(|name| env.documents.take(&name)).transpose()?;
            let mut reader = document.reader(ctx.resources())?;
            let mut detached_reader = detached
                .as_mut()
                .map(|input| input.reader(ctx.resources()))
                .transpose()?;
            let request = verify_request(profile, soap, evidence_limits(ctx.resources().limits()));
            let report = env.engine.verify(
                &request,
                reader.source(),
                detached_reader.as_mut().map(intake::DocumentReader::source),
                ctx,
            )?;
            reader.finish()?;
            if let Some(reader) = &mut detached_reader {
                reader.finish()?;
            }
            let (result, bytes) = results::verification(profile, &report)?;
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, None))
        }
        Operation::Extract { input } => {
            let output = output.ok_or(OperationError::MissingTemporaryStore)?;
            let mut document = env.documents.take(&input)?;
            let mut reader = document.reader(ctx.resources())?;
            let mut writer = super::artifact::ArtifactWriter::new(
                output.store.clone(),
                output.owner.clone(),
                ctx,
            )?;
            let report = env.engine.extract(reader.source(), &mut writer, ctx)?;
            reader.finish()?;
            let artifact = writer.finish(report.bytes_written)?;
            let (result, bytes) = results::extraction(Some(output.id), &report);
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, Some(artifact)))
        }
        Operation::Sign {
            profile,
            input,
            detached,
            mode,
            attached,
            target,
            parent,
            signature_id,
            soap,
            body_id,
            element,
            xpath_parent,
            signature_method,
            digest_method,
            evidence,
            keys,
        } => {
            let sink = output.ok_or(OperationError::MissingTemporaryStore)?;
            let selectors = env
                .selectors
                .get(item_id)
                .ok_or(ProcessingError::InvalidInput("unresolved signing keys"))?;
            let mut passwords = Vec::with_capacity(keys.len());
            for key in &keys {
                passwords.push(match key {
                    KeyRef::Named { .. } => None,
                    KeyRef::Inline { password, .. } => password
                        .as_deref()
                        .map(|name| env.secrets.text(name))
                        .transpose()?,
                });
            }
            let requests: Vec<KeyRequest<'_>> = selectors
                .iter()
                .zip(passwords)
                .map(|(selector, password)| KeyRequest::new(selector, password))
                .collect();
            let limits = evidence_limits(ctx.resources().limits());
            let evidence = load_evidence(env, &evidence, ctx)?;
            let (ocsp, crls) = evidence.slices();
            let material = ValidationMaterial {
                certificates: &evidence.certificates,
                ocsp: &ocsp,
                crls: &crls,
            };
            let mut document = env.documents.take(&input)?;
            let mut detached = detached.map(|name| env.documents.take(&name)).transpose()?;
            let mut staged = staged_output(env, ctx)?;
            let mut reader = document.reader(ctx.resources())?;
            let mut detached_reader = detached
                .as_mut()
                .map(|input| input.reader(ctx.resources()))
                .transpose()?;
            let spec = requests::SignSpec {
                profile,
                mode,
                attached,
                target: target.as_deref(),
                parent: parent.as_deref(),
                signature_id: signature_id.as_deref(),
                soap,
                body_id: body_id.as_deref(),
                element: element.as_deref(),
                xpath_parent: xpath_parent.as_deref(),
                signature_method: signature_method.as_deref(),
                digest_method: digest_method.as_deref(),
            };
            let request = requests::sign_request(
                &spec,
                requests,
                detached_reader.as_mut().map(intake::DocumentReader::source),
                material,
                limits,
                env.host.tsa.as_ref(),
            )?;
            let report = env
                .engine
                .sign_staged(request, reader.source(), &mut staged, ctx)?;
            // Everything below runs after the key may have been used.
            let state = strongest(report.signer_states());
            after_use(state, reader.finish())?;
            if let Some(reader) = &mut detached_reader {
                after_use(state, reader.finish())?;
            }
            let (result, bytes) =
                after_use(state, results::signing(profile, Some(sink.id), &report))?;
            let projection = after_use(state, ctx.resources().reserve_metadata(bytes))?;
            let artifact = after_use(
                state,
                super::artifact::FinishedArtifact::from_staged(sink.owner, staged),
            )?;
            Ok((result, projection, Some(artifact)))
        }
        Operation::Extend {
            profile,
            input,
            detached,
            evidence,
        } => {
            let sink = output.ok_or(OperationError::MissingTemporaryStore)?;
            let limits = evidence_limits(ctx.resources().limits());
            let evidence = load_evidence(env, &evidence, ctx)?;
            let (ocsp, crls) = evidence.slices();
            let mut document = env.documents.take(&input)?;
            let mut detached = detached.map(|name| env.documents.take(&name)).transpose()?;
            let mut staged = staged_output(env, ctx)?;
            let mut reader = document.reader(ctx.resources())?;
            let mut detached_reader = detached
                .as_mut()
                .map(|input| input.reader(ctx.resources()))
                .transpose()?;
            let request = requests::extend_request(
                profile,
                detached_reader.as_mut().map(intake::DocumentReader::source),
                ValidationMaterial {
                    certificates: &evidence.certificates,
                    ocsp: &ocsp,
                    crls: &crls,
                },
                limits,
            )?;
            let report = env
                .engine
                .extend_staged(&request, reader.source(), &mut staged, ctx)?;
            reader.finish()?;
            drop(request);
            if let Some(reader) = &mut detached_reader {
                reader.finish()?;
            }
            let (result, bytes) = results::extension(profile, Some(sink.id), &report)?;
            let projection = ctx.resources().reserve_metadata(bytes)?;
            let artifact = super::artifact::FinishedArtifact::from_staged(sink.owner, staged)?;
            Ok((result, projection, Some(artifact)))
        }
        Operation::Inspect { target } => {
            let request_label;
            let mut cursor;
            let mut document;
            let mut reader;
            let report = match &target {
                InspectTarget::Certificate { input } | InspectTarget::Cms { input } => {
                    document = env.documents.take(input)?;
                    reader = document.reader(ctx.resources())?;
                    let certificate = matches!(target, InspectTarget::Certificate { .. });
                    request_label = if certificate { "certificate" } else { "cms" };
                    let request = if certificate {
                        oncl_core::InspectRequest::certificate()
                    } else {
                        oncl_core::InspectRequest::cms_metadata()
                    };
                    let report = env.engine.inspect(&request, Some(reader.source()), ctx)?;
                    reader.finish()?;
                    report
                }
                InspectTarget::Named { name } => {
                    request_label = "named_key";
                    let selector = KeySelector::named(
                        KeyId::new(name).map_err(|_| ProcessingError::InvalidInput("key name"))?,
                    );
                    let key = KeyRequest::new(&selector, None);
                    env.engine
                        .inspect(&oncl_core::InspectRequest::named_key(&key), None, ctx)?
                }
                InspectTarget::Container {
                    container,
                    password,
                } => {
                    request_label = "container";
                    let bytes = env.secrets.bytes(container)?;
                    cursor = std::io::Cursor::new(bytes);
                    let password = password
                        .as_deref()
                        .map(|name| env.secrets.text(name))
                        .transpose()?;
                    let request = oncl_core::InspectRequest::container(password);
                    env.engine.inspect(
                        &request,
                        Some(Source::sequential(&mut cursor, Some(bytes.len() as u64))),
                        ctx,
                    )?
                }
            };
            let (result, bytes) = results::inspection(request_label, &report)?;
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, None))
        }
        Operation::Stamp { input } => {
            let sink = output.ok_or(OperationError::MissingTemporaryStore)?;
            let spec = env
                .host
                .tsa
                .clone()
                .ok_or(OperationError::MissingCadesConfiguration)?;
            let mut document = env.documents.take(&input)?;
            let mut reader = document.reader(ctx.resources())?;
            let mut writer =
                super::artifact::ArtifactWriter::new(sink.store.clone(), sink.owner.clone(), ctx)?;
            let report = env.engine.stamp(
                &oncl_core::StampRequest::new(spec),
                reader.source(),
                &mut writer,
                ctx,
            )?;
            reader.finish()?;
            let artifact = writer.finish(report.facts().token().len() as u64)?;
            let (result, bytes) = results::stamping(Some(sink.id), &report);
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, Some(artifact)))
        }
        Operation::VerifyStamp {
            token,
            data,
            algorithm: expected,
            max_age_seconds,
        } => {
            let mut token = env.documents.take(&token)?;
            let mut data = data.map(|name| env.documents.take(&name)).transpose()?;
            let mut token_reader = token.reader(ctx.resources())?;
            let mut data_reader = data
                .as_mut()
                .map(|input| input.reader(ctx.resources()))
                .transpose()?;
            let mut request = oncl_core::StampVerifyRequest::new();
            if let Some(algorithm) = expected {
                request = request.with_algorithm(super::algorithm(algorithm));
            }
            if let Some(seconds) = max_age_seconds {
                request = request.with_maximum_age(std::time::Duration::from_secs(seconds));
            }
            let report = env.engine.verify_stamp(
                &request,
                token_reader.source(),
                data_reader.as_mut().map(intake::DocumentReader::source),
                ctx,
            )?;
            token_reader.finish()?;
            if let Some(reader) = &mut data_reader {
                reader.finish()?;
            }
            let (result, bytes) = results::stamp_verification(&report);
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, None))
        }
        Operation::JwsSign {
            serialization,
            detached,
            input,
            keys,
        } => {
            let sink = output.ok_or(OperationError::MissingTemporaryStore)?;
            let selectors = env
                .selectors
                .get(item_id)
                .ok_or(ProcessingError::InvalidInput("unresolved signing keys"))?;
            let requests = key_requests(&keys, selectors, env.secrets)?;
            let mut document = env.documents.take(&input)?;
            let (payload, _payload) =
                read_bytes(&mut document, ctx, oncl_core::jose::MAX_PAYLOAD_BYTES)?;
            let mut writer =
                super::artifact::ArtifactWriter::new(sink.store.clone(), sink.owner.clone(), ctx)?;
            let report = env.engine.jws_create(
                jose_profile(serialization, detached),
                requests,
                &payload,
                &mut writer,
                ctx,
            )?;
            let artifact = after_use(report.applied, writer.finish(report.bytes_out))?;
            let (result, bytes) = results::jose_written(serialization, Some(sink.id), &report);
            let projection = after_use(report.applied, ctx.resources().reserve_metadata(bytes))?;
            Ok((result, projection, Some(artifact)))
        }
        Operation::JwsAdd {
            serialization,
            input,
            detached,
            certificate: certificate_name,
            keys,
        } => {
            let sink = output.ok_or(OperationError::MissingTemporaryStore)?;
            let selectors = env
                .selectors
                .get(item_id)
                .ok_or(ProcessingError::InvalidInput("unresolved signing keys"))?;
            let requests = key_requests(&keys, selectors, env.secrets)?;
            let certificate = certificate(env, certificate_name, ctx)?;
            let mut document = env.documents.take(&input)?;
            let (existing, _existing) =
                read_bytes(&mut document, ctx, oncl_core::jose::MAX_PAYLOAD_BYTES * 2)?;
            let mut payload_document = detached
                .as_ref()
                .map(|name| env.documents.take(name))
                .transpose()?;
            let payload = payload_document
                .as_mut()
                .map(|d| read_bytes(d, ctx, oncl_core::jose::MAX_PAYLOAD_BYTES))
                .transpose()?;
            let mut writer =
                super::artifact::ArtifactWriter::new(sink.store.clone(), sink.owner.clone(), ctx)?;
            let mut request = oncl_core::jose::JwsVerifyRequest::new(jose_profile(
                serialization,
                payload.is_some(),
            ));
            request.certificate = certificate.as_ref();
            let report = env.engine.jws_add(
                request,
                requests,
                &existing,
                payload.as_ref().map(|(b, _)| b.as_slice()),
                &mut writer,
                ctx,
            )?;
            let artifact = after_use(report.applied, writer.finish(report.bytes_out))?;
            let (result, bytes) = results::jose_written(serialization, Some(sink.id), &report);
            let projection = after_use(report.applied, ctx.resources().reserve_metadata(bytes))?;
            Ok((result, projection, Some(artifact)))
        }
        Operation::JwtEncode { input, key } => {
            let sink = output.ok_or(OperationError::MissingTemporaryStore)?;
            let selectors = env
                .selectors
                .get(item_id)
                .ok_or(ProcessingError::InvalidInput("unresolved signing keys"))?;
            let mut requests = key_requests(std::slice::from_ref(&key), selectors, env.secrets)?;
            let mut document = env.documents.take(&input)?;
            let (claims, _claims) =
                read_bytes(&mut document, ctx, oncl_core::jose::MAX_CLAIMS_BYTES)?;
            let mut writer =
                super::artifact::ArtifactWriter::new(sink.store.clone(), sink.owner.clone(), ctx)?;
            let report = env
                .engine
                .jwt_encode(requests.remove(0), &claims, &mut writer, ctx)?;
            let artifact = after_use(report.applied, writer.finish(report.bytes_out))?;
            let (result, bytes) =
                results::jose_written(oncl_api::dto::JwsFormat::Compact, Some(sink.id), &report);
            let projection = after_use(report.applied, ctx.resources().reserve_metadata(bytes))?;
            Ok((result, projection, Some(artifact)))
        }
        Operation::JwsVerify {
            serialization,
            input,
            detached,
            certificate: certificate_name,
        } => {
            let certificate = certificate(env, certificate_name, ctx)?;
            let mut document = env.documents.take(&input)?;
            let (token, _token) =
                read_bytes(&mut document, ctx, oncl_core::jose::MAX_PAYLOAD_BYTES * 2)?;
            let mut payload_document = detached
                .as_ref()
                .map(|name| env.documents.take(name))
                .transpose()?;
            let payload = payload_document
                .as_mut()
                .map(|d| read_bytes(d, ctx, oncl_core::jose::MAX_PAYLOAD_BYTES))
                .transpose()?;
            let mut request = oncl_core::jose::JwsVerifyRequest::new(jose_profile(
                serialization,
                payload.is_some(),
            ));
            request.certificate = certificate.as_ref();
            let report = env.engine.jws_verify(
                request,
                &token,
                payload.as_ref().map(|(b, _)| b.as_slice()),
                ctx,
            )?;
            let (result, bytes) = results::jws_verification(&report);
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, None))
        }
        Operation::JwtDecode { input } => {
            let mut document = env.documents.take(&input)?;
            let (token, _token) =
                read_bytes(&mut document, ctx, oncl_core::jose::MAX_CLAIMS_BYTES)?;
            let decoded = env.engine.jwt_decode_unverified(&token, ctx)?;
            let (result, bytes) = results::jwt_decoded(&decoded);
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, None))
        }
        Operation::JwtVerify {
            input,
            certificate: certificate_name,
        } => {
            let certificate = certificate(env, certificate_name, ctx)?;
            let mut document = env.documents.take(&input)?;
            let (token, _token) =
                read_bytes(&mut document, ctx, oncl_core::jose::MAX_CLAIMS_BYTES)?;
            let mut policy = oncl_core::jose::JwtValidationPolicy::new(
                time::OffsetDateTime::now_utc().unix_timestamp(),
            );
            policy.expected_issuer = env.host.jwt_issuer.clone();
            policy.expected_audience = env.host.jwt_audience.clone();
            let report = env
                .engine
                .jwt_verify(certificate.as_ref(), &token, &policy, ctx)?;
            let (result, bytes) = results::jwt_verification(&report);
            let projection = ctx.resources().reserve_metadata(bytes)?;
            Ok((result, projection, None))
        }
        Operation::Plugin {
            plugin,
            operation,
            args,
            keys,
        } => {
            let selectors = env
                .selectors
                .get(item_id)
                .ok_or(ProcessingError::InvalidInput("unresolved plugin keys"))?;
            let bindings: Vec<_> = keys
                .iter()
                .zip(selectors)
                .map(|(key, selector)| {
                    oncl_core::plugins::PluginKeyBinding::new(
                        key.handle,
                        KeyRequest::new(selector, None),
                    )
                })
                .collect();
            let call = oncl_core::plugins::PluginCall {
                plugin_id: &plugin,
                operation: &operation,
                args: &args,
            };
            let bound = oncl_core::plugins::PluginBindings::new(env.caller, &bindings);
            // The ORIGINAL admitted context: no new budget, grant or deadline.
            let result = match env.engine.plugin_call(&call, &bound, ctx) {
                Ok(result) => result,
                Err(error) => {
                    env.subcode = plugin_subcode(env.host, ctx);
                    return Err(error);
                }
            };
            let state = result.applied_state();
            let response = result.response().to_owned();
            let projection = after_use(
                state,
                ctx.resources()
                    .reserve_metadata(512 + response.len() as u64),
            )?;
            Ok((
                OperationResult::Plugin {
                    response,
                    applied: applied(state),
                },
                projection,
                None,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::key::AppliedState::*;
    /// A timestamp or archive proof covers the whole signed document and the container it
    /// carries, so the coverage ceiling must reach the document plus its container: a
    /// ceiling of `input_bytes` alone refused the keyless PAdES LT -> LTA extension of a
    /// document of the full input allowance (its LT result is already past `input_bytes`)
    /// with `MetadataLimit`, which the stream then reported as a lost response.
    #[test]
    fn evidence_coverage_reaches_a_full_size_document_with_its_container() {
        let limits = crate::config::ServerConfig::default().limits();
        let largest_signed_wire = limits.input_bytes + limits.container_bytes;
        let coverage = evidence_limits(&limits).max_coverage_bytes;
        assert!(
            coverage >= largest_signed_wire,
            "coverage {coverage} < signed wire {largest_signed_wire}"
        );
        assert!(
            coverage <= limits.output_bytes,
            "coverage is finite and bounded by the output ceiling"
        );
    }
    fn plugin_metadata(keys: &str) -> OperationMetadata {
        serde_json::from_str(&format!(
            r#"{{"items":[{{"id":"p","operation":{{"kind":"plugin","plugin":"vendor.x","operation":"run","args":"{{}}","keys":[{keys}]}}}}],"parts":[]}}"#
        ))
        .unwrap()
    }
    fn live_policy(token: &str) -> (AccessPolicy, Principal, crate::auth::TokenSecret) {
        let secret = crate::auth::TokenSecret::generate().unwrap();
        let record = crate::auth::TokenRecord::new(
            token,
            secret.verifier(),
            vec![Action::Hash, Action::Sign],
            vec!["k".into()],
        )
        .unwrap();
        let policy = AccessPolicy::new(vec![record]).unwrap();
        let principal = policy.authenticate(secret.bearer().as_bytes()).unwrap();
        (policy, principal, secret)
    }
    fn host_with_grant(token: &str) -> crate::service::operations::HostPolicy {
        crate::service::operations::HostPolicy {
            tsa: None,
            jwt_issuer: None,
            jwt_audience: None,
            plugin_policy: Default::default(),
            plugin_grants: vec![crate::service::operations::PluginGrantRuntime {
                token: token.into(),
                plugin: "vendor.x".into(),
                operation: "run".into(),
                keys: vec!["k".into()],
                permission: oncl_core::plugins::PluginPermission::new(
                    "vendor.x",
                    "run",
                    oncl_core::plugins::CallerContext::ServiceClient(token.into()),
                    vec![],
                ),
            }],
            trust_bytes: 0,
        }
    }
    #[test]
    fn plugin_items_need_a_live_principal_with_and_without_keys() {
        for keys in ["", r#"{"handle":1,"name":"k"}"#] {
            let (policy, principal, _secret) = live_policy("tok");
            let host = host_with_grant("tok");
            let metadata = plugin_metadata(keys);
            assert!(
                precheck(&metadata, &policy, &principal, false, &host).is_ok(),
                "{keys}"
            );
            policy.revoke("tok").unwrap();
            let error = precheck(&metadata, &policy, &principal, false, &host).unwrap_err();
            assert_eq!(error.code, ErrorCode::PermissionDenied, "{keys}");
        }
    }
    #[test]
    fn xades_timestamp_profiles_need_a_tsa_policy_from_metadata_alone() {
        let (policy, principal, _secret) = live_policy("tok");
        let metadata: OperationMetadata = serde_json::from_str(r#"{"items":[{"id":"s","operation":{"kind":"sign","profile":"xades_t","input":"d","keys":[{"source":"named","name":"k"}]}}],"parts":[{"name":"d","item_id":"s","role":"document"}]}"#).unwrap();
        let mut host = host_with_grant("tok");
        let error = precheck(&metadata, &policy, &principal, false, &host).unwrap_err();
        assert_eq!(error.code, ErrorCode::MissingConfiguration);
        assert_eq!(error.applied, oncl_api::error::AppliedState::NotApplied);
        host.tsa = Some(oncl_pki::tsp::TsaSpec {
            url: "http://tsa.example/".into(),
            method: oncl_pki::http::PkiMethod::Post { content_type: None },
            hash: oncl_pki::key::HashAlg::Sha256,
            policy: None,
            nonce: oncl_pki::http::NonceSpec::Random(8),
            cert_req: true,
            retries: 0,
            timeout: std::time::Duration::from_secs(1),
            check_skew: None,
            require_tsa_eku: true,
        });
        assert_eq!(
            precheck(&metadata, &policy, &principal, false, &host)
                .unwrap_err()
                .code,
            ErrorCode::MissingConfiguration,
            "a TSA without a policy OID is still refused"
        );
    }
    #[test]
    fn the_new_signature_must_fit_the_signature_count_limit() {
        let maximum = oncl_pdf::PdfLimits::default().max_signatures;
        assert!(signature_count_fits(maximum as u64 - 1, maximum).is_ok());
        let error = signature_count_fits(maximum as u64, maximum).unwrap_err();
        assert_eq!(error.code, ErrorCode::InputLimit);
        assert_eq!(error.applied, oncl_api::error::AppliedState::NotApplied);
        assert_eq!(
            signature_count_fits(u64::MAX, maximum).unwrap_err().code,
            ErrorCode::InputLimit
        );
    }
    #[test]
    fn more_evidence_references_than_the_engine_loads_are_refused_before_any_part_is_read() {
        let refs = |n: usize| {
            (0..n)
                .map(|i| format!(r#"{{"kind":"crl","input":"e{i}"}}"#))
                .collect::<Vec<_>>()
                .join(",")
        };
        for (kind, extra) in [
            ("extend", r#""profile":"cades_lt""#),
            (
                "sign",
                r#""profile":"cades_t","keys":[{"source":"named","name":"k"}]"#,
            ),
        ] {
            for (count, ok) in [(MAX_EVIDENCE_REFS, true), (MAX_EVIDENCE_REFS + 1, false)] {
                let operation: Operation = serde_json::from_str(&format!(
                    r#"{{"kind":"{kind}","input":"d",{extra},"evidence":[{}]}}"#,
                    refs(count)
                ))
                .unwrap();
                assert_eq!(validate_shape(&operation).is_ok(), ok, "{kind} {count}");
            }
        }
    }
    #[test]
    fn only_the_input_of_verify_extend_extract_and_sign_may_be_signed_wire() {
        let metadata: OperationMetadata = serde_json::from_str(
            r#"{"items":[
                {"id":"v","operation":{"kind":"verify","profile":"cms","input":"v-in","detached":"v-data"}},
                {"id":"e","operation":{"kind":"extend","profile":"cades_lt","input":"e-in","evidence":[{"kind":"ocsp","input":"e-ocsp"},{"kind":"crl","input":"e-crl"}]}},
                {"id":"x","operation":{"kind":"extract","input":"x-in"}},
                {"id":"s","operation":{"kind":"sign","profile":"cades_t","input":"s-in","evidence":[{"kind":"certificate","input":"s-cert"}],"keys":[{"source":"named","name":"k"}]}},
                {"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"h-in"}},
                {"id":"i","operation":{"kind":"inspect","target":{"type":"cms","input":"i-in"}}}
            ],"parts":[]}"#,
        )
        .unwrap();
        // Signed wire: exactly the four inputs. A detached payload, a hashed document and an
        // inspected container are documents within `input_bytes`.
        assert_eq!(
            wire_inputs(&metadata).collect::<Vec<_>>(),
            ["v-in", "e-in", "x-in", "s-in"]
        );
        // Evidence is validation material with its own bounds, never a document.
        assert_eq!(
            evidence_inputs(&metadata).collect::<Vec<_>>(),
            ["e-ocsp", "e-crl", "s-cert"]
        );
    }
    #[test]
    fn a_document_or_container_limit_found_by_the_engine_is_a_typed_refusal_not_an_abort() {
        for limit in [ProcessingError::InputLimit, ProcessingError::ContainerLimit] {
            match classify(OperationError::Processing(limit), false, None) {
                Failure::Typed(api) => {
                    assert_eq!(api.code, ErrorCode::InputLimit);
                    assert_eq!(api.applied, oncl_api::error::AppliedState::NotApplied);
                }
                Failure::Abort(_) => panic!("a document limit must be typed"),
            }
        }
        // Other resource failures keep the first-fatal abort.
        for other in [
            ProcessingError::MemoryLimit,
            ProcessingError::DeadlineExceeded,
            ProcessingError::Cancelled,
        ] {
            assert!(matches!(
                classify(OperationError::Processing(other), false, None),
                Failure::Abort(_)
            ));
        }
    }
    /// Control that can be flipped to a latched cancel/deadline stop after `begin`.
    struct Latch(std::sync::atomic::AtomicU8);
    impl oncl_pki::resource::OperationControl for Latch {
        fn checkpoint(
            &self,
            _: oncl_pki::resource::Progress,
        ) -> Result<(), oncl_pki::resource::ProcessingError> {
            match self.0.load(std::sync::atomic::Ordering::SeqCst) {
                1 => Err(ProcessingError::Cancelled),
                2 => Err(ProcessingError::DeadlineExceeded),
                _ => Ok(()),
            }
        }
    }
    #[test]
    fn preflight_keeps_cancel_and_deadline_typing_and_never_reports_a_memory_limit() {
        for (state, expected) in [
            (1u8, ErrorCode::Cancelled),
            (2u8, ErrorCode::DeadlineExceeded),
        ] {
            let engine = Engine::new(oncl_core::EngineServices::hash_only(
                oncl_pki::resource::ResourceLimits::default(),
            ))
            .unwrap();
            let latch = Arc::new(Latch(std::sync::atomic::AtomicU8::new(0)));
            let mut ctx = engine
                .begin(
                    oncl_core::ExecutionGrant::new([Action::Sign]),
                    oncl_core::OperationPolicy::strict_online(),
                    latch.clone(),
                )
                .unwrap();
            let metadata: OperationMetadata = serde_json::from_str(r#"{"items":[{"id":"s","operation":{"kind":"sign","profile":"pades_lt","input":"d","evidence":[{"kind":"ocsp","input":"e"}],"keys":[{"source":"named","name":"k"}]}}],"parts":[{"name":"d","item_id":"s","role":"document"},{"name":"e","item_id":"s","role":"document"}]}"#).unwrap();
            let mut documents = intake::Documents::Text(
                [
                    ("d".to_owned(), "%PDF".to_owned()),
                    ("e".to_owned(), "ocsp".to_owned()),
                ]
                .into_iter()
                .collect(),
            );
            let host = host_with_grant("tok");
            latch.0.store(state, std::sync::atomic::Ordering::SeqCst);
            let error =
                memory_preflight(&metadata, &mut documents, &host, ctx.resources()).unwrap_err();
            assert_eq!(error.code, expected);
            assert_eq!(error.applied, oncl_api::error::AppliedState::NotApplied);
        }
    }
    #[test]
    fn rights_are_decided_before_the_host_tsa_configuration_is_revealed() {
        let (policy, principal, _secret) = live_policy("tok");
        let host = host_with_grant("tok");
        for profile in ["xades_t", "xades_legacy_t"] {
            // The token holds the sign right only for key "k": "other" is not granted.
            let metadata: OperationMetadata = serde_json::from_str(&format!(r#"{{"items":[{{"id":"s","operation":{{"kind":"sign","profile":"{profile}","input":"d","keys":[{{"source":"named","name":"other"}}]}}}}],"parts":[{{"name":"d","item_id":"s","role":"document"}}]}}"#)).unwrap();
            let error = precheck(&metadata, &policy, &principal, false, &host).unwrap_err();
            assert_eq!(error.code, ErrorCode::PermissionDenied, "{profile}");
            // With the right the configuration refusal appears.
            let granted: OperationMetadata = serde_json::from_str(&format!(r#"{{"items":[{{"id":"s","operation":{{"kind":"sign","profile":"{profile}","input":"d","keys":[{{"source":"named","name":"k"}}]}}}}],"parts":[{{"name":"d","item_id":"s","role":"document"}}]}}"#)).unwrap();
            let error = precheck(&granted, &policy, &principal, false, &host).unwrap_err();
            assert_eq!(error.code, ErrorCode::MissingConfiguration, "{profile}");
        }
    }
    #[test]
    fn host_failure_after_key_use_keeps_the_real_applied_state() {
        for state in [Applied, Unknown] {
            let error = after_use::<(), _>(state, Err(ProcessingError::MetadataLimit)).unwrap_err();
            assert_eq!(error.applied_state(), state);
            // Never wrapped twice and never downgraded.
            let again = after_use::<(), _>(Unknown, Err(error)).unwrap_err();
            assert_eq!(again.applied_state(), state);
        }
        let plain =
            after_use::<(), _>(NotApplied, Err(ProcessingError::MetadataLimit)).unwrap_err();
        assert_eq!(plain.applied_state(), NotApplied);
        assert_eq!(strongest([NotApplied, Applied, Unknown]), Unknown);
        assert_eq!(strongest([NotApplied, Applied]), Applied);
        assert_eq!(strongest([]), NotApplied);
    }
    #[test]
    fn every_private_result_family_maps_its_signers_to_the_item_state() {
        use oncl_api::error::AppliedState as A;
        let jws = OperationResult::Jws {
            serialization: oncl_api::dto::JwsFormat::Compact,
            artifact: None,
            bytes_in: 0,
            bytes_out: 0,
            signers: vec![A::Applied],
        };
        assert_eq!(applied_of(&jws), A::Applied);
        let signing = OperationResult::Signing {
            profile: SignKind::Cms,
            artifact: None,
            bytes_in: 0,
            bytes_out: 0,
            signers: vec![A::NotApplied, A::Unknown],
        };
        assert_eq!(applied_of(&signing), A::Unknown);
    }
}
