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
            policy
                .authorize(principal, Action::Inspect, Some(name), None)
                .map_err(|_| denied())?;
            let id = KeyId::new(name).map_err(|_| invalid_request())?;
            if !resolved.keys.contains(&id) {
                resolved.keys.push(id);
            }
        }
        let mut selectors = Vec::with_capacity(keys.len());
        for key in keys {
            let selector = match key {
                KeyRef::Named { name } => {
                    policy
                        .authorize(principal, Action::Sign, Some(name), None)
                        .map_err(|_| denied())?;
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
        max_chain_len: 8,
        max_proofs: 16,
        max_coverage_parts: 4096,
        max_coverage_bytes: limits.input_bytes,
    }
}
fn verify_request(
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
/// Item-level key application derived from the real per-signer/report state.
pub(super) fn applied_of(result: &OperationResult) -> oncl_api::error::AppliedState {
    use oncl_api::error::AppliedState as A;
    match result {
        OperationResult::Plugin { applied, .. } => *applied,
        OperationResult::Signing { signers, .. } | OperationResult::Jws { signers, .. } => {
            signers.iter().fold(A::NotApplied, |a, s| match (a, *s) {
                (A::Unknown, _) | (_, A::Unknown) => A::Unknown,
                (A::Applied, _) | (_, A::Applied) => A::Applied,
                _ => A::NotApplied,
            })
        }
        _ => A::NotApplied,
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
        Cms | Pdf | Xml | Wsse | XmlLegacy | XadesLegacyB => None,
        CadesB | PadesB | XadesB => Some(AdesLevel::B),
        CadesT | PadesT | XadesT => Some(AdesLevel::T),
        CadesLt | PadesLt | XadesLt => Some(AdesLevel::Lt),
        CadesLta | PadesLta | XadesLta => Some(AdesLevel::Lta),
    }
}
/// Caller-acquired public status/chain evidence. It is never a trust anchor.
struct Evidence {
    certificates: Vec<oncl_pki::cert::Certificate>,
    ocsp: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    _reservations: Vec<ResourceReservation>,
}
impl Evidence {
    fn slices(&self) -> (Vec<&[u8]>, Vec<&[u8]>) {
        (
            self.ocsp.iter().map(Vec::as_slice).collect(),
            self.crls.iter().map(Vec::as_slice).collect(),
        )
    }
}
fn load_evidence(
    env: &mut Env<'_>,
    refs: &[oncl_api::dto::EvidenceRef],
    ctx: &mut OperationContext,
) -> Result<Evidence, OperationError> {
    use oncl_api::dto::EvidenceKind;
    if refs.len() > 64 {
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
        let (bytes, reservation) = read_bytes(&mut document, ctx, 1 << 20)?;
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
            let xml_ids = matches!(profile, Xml | XadesB | XadesT | XadesLt | XadesLta);
            let legacy = matches!(profile, XmlLegacy | XadesLegacyB);
            let high = matches!(
                profile,
                CadesLt | CadesLta | PadesLt | PadesLta | XadesLt | XadesLta
            );
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
                    && !matches!(profile, CadesT | PadesT | XadesT | XadesLegacyB));
            if bad {
                return Err(invalid_request());
            }
            Ok(())
        }
        Operation::Verify { profile, soap, .. }
            if soap.is_some() && !matches!(profile, VerifyProfile::Wsse) =>
        {
            Err(invalid_request())
        }
        _ => Ok(()),
    }
}
fn is_xml(kind: SignKind) -> bool {
    matches!(
        kind,
        SignKind::Xml
            | SignKind::XadesB
            | SignKind::XadesT
            | SignKind::XadesLt
            | SignKind::XadesLta
    )
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
fn extend_level(kind: ExtendKind) -> (AdesLevel, bool) {
    use ExtendKind::*;
    match kind {
        CadesT => (AdesLevel::T, false),
        CadesLt => (AdesLevel::Lt, false),
        CadesLta => (AdesLevel::Lta, false),
        PadesT => (AdesLevel::T, true),
        PadesLt => (AdesLevel::Lt, true),
        PadesLta => (AdesLevel::Lta, true),
    }
}
/// The sign/extend result is always a new SDK-staged artifact; the engine
/// charges its output once and a failed operation poisons it.
fn staged_output(
    env: &Env<'_>,
    ctx: &mut OperationContext,
) -> Result<oncl_pki::io::StagedArtifact, OperationError> {
    env.staging
        .ok_or(OperationError::MissingTemporaryStore)?
        .stage(ctx.resources())
        .map_err(Into::into)
}
fn key_requests<'a>(
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
fn read_bytes(
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
fn jose_profile(format: oncl_api::dto::JwsFormat, detached: bool) -> oncl_core::jose::JoseProfile {
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
fn certificate(
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
            let projection = ctx.resources().reserve_metadata(512)?;
            Ok((
                OperationResult::Hash {
                    algorithm: hash,
                    digest: crate::auth::encode(report.digest.as_bytes()),
                    bytes_in,
                },
                projection,
                None,
            ))
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
            // The host owns this actual scoped report until its bounded wire
            // projection has been serialized under the same context reservation.
            let projection = ctx.resources().reserve_metadata(
                (report.signers.len() as u64)
                    .checked_mul(8192)
                    .and_then(|n| n.checked_add(512))
                    .ok_or(ProcessingError::MetadataLimit)?,
            )?;
            Ok((
                OperationResult::Verification {
                    profile,
                    verdict: verdict(report.verdict),
                    policy: match report.policy {
                        ValidationPolicy::StrictOnline => "StrictOnline",
                        ValidationPolicy::OfflineReport => "OfflineReport",
                        ValidationPolicy::NcalayerCompatibility => "NcalayerCompatibility",
                    },
                    checked_at_unix: report.checked_at.unix_timestamp(),
                    signers: report.signers.iter().map(signer).collect(),
                },
                projection,
                None,
            ))
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
            let projection = ctx.resources().reserve_metadata(512)?;
            Ok((
                OperationResult::Extraction {
                    artifact: Some(output.id),
                    bytes_written: report.bytes_written,
                },
                projection,
                Some(artifact),
            ))
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
            let mut requests: Vec<KeyRequest<'_>> = selectors
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
            let level = ades_level(profile);
            let request = if matches!(profile, SignKind::Wsse) {
                if requests.len() != 1 {
                    return Err(ProcessingError::InvalidInput("WSSE signing takes one key").into());
                }
                let key = requests.remove(0);
                let mut wsse = oncl_xml::wsse::SourceWsseSignProfile::default();
                wsse.verification.soap = soap_version(soap);
                if let Some(id) = body_id {
                    wsse.body_id = id;
                }
                oncl_core::SignRequest::wsse(key, wsse)
            } else if matches!(profile, SignKind::XmlLegacy) {
                if requests.len() != 1 {
                    return Err(ProcessingError::InvalidInput("XML signing takes one key").into());
                }
                let key = requests.remove(0);
                let mut spec =
                    oncl_xml::XmlSignSpec::kalkan(element.as_deref(), xpath_parent.as_deref());
                spec.signature_method = signature_method.as_deref();
                spec.digest_method = digest_method.as_deref();
                oncl_core::SignRequest::xml_legacy(key, spec)
            } else if matches!(profile, SignKind::XadesLegacyB) {
                if requests.len() != 1 {
                    return Err(ProcessingError::InvalidInput("XML signing takes one key").into());
                }
                let key = requests.remove(0);
                let spec = oncl_xml::xades::XadesSpec {
                    level: oncl_xml::xades::XadesLevel::B,
                    tsa: None,
                    chain: evidence.certificates.clone(),
                    signature_method: signature_method.as_deref(),
                    digest_method: digest_method.as_deref(),
                };
                oncl_core::SignRequest::xades_legacy(key, spec)
            } else if is_xml(profile) {
                if mode != SignWriteMode::Create || detached_reader.is_some() || attached {
                    return Err(
                        ProcessingError::InvalidInput("XML signing is enveloped create").into(),
                    );
                }
                if requests.len() != 1 {
                    return Err(ProcessingError::InvalidInput("XML signing takes one key").into());
                }
                let key = requests.remove(0);
                let xml = oncl_xml::XmlSignProfile {
                    target: target.as_deref(),
                    parent: parent.as_deref(),
                    signature_id: signature_id.as_deref(),
                    ..oncl_xml::XmlSignProfile::default()
                };
                match level {
                    None => oncl_core::SignRequest::xml(key, xml),
                    Some(level) => oncl_core::SignRequest::xades(key, xml, level),
                }
            } else if is_pdf(profile) {
                if mode != SignWriteMode::Create || detached_reader.is_some() || attached {
                    return Err(ProcessingError::InvalidInput("PDF signing is incremental").into());
                }
                if requests.len() != 1 {
                    return Err(ProcessingError::InvalidInput("PDF signing takes one key").into());
                }
                let key = requests.remove(0);
                let pdf = oncl_pdf::PdfSignProfile::default();
                match level {
                    None => oncl_core::SignRequest::pdf(key, pdf),
                    Some(level) => oncl_core::SignRequest::pades(key, pdf, level, material, limits),
                }
            } else {
                let detached_source = detached_reader.as_mut().map(intake::DocumentReader::source);
                match (level, mode) {
                    (None, SignWriteMode::Create) => {
                        if detached_source.is_some() {
                            return Err(ProcessingError::InvalidInput(
                                "create takes no detached input",
                            )
                            .into());
                        }
                        oncl_core::SignRequest::cms_create(requests, attached)
                    }
                    (None, SignWriteMode::Add) => {
                        oncl_core::SignRequest::cms_add(requests, detached_source)
                    }
                    (Some(level), SignWriteMode::Create) => {
                        if detached_source.is_some() {
                            return Err(ProcessingError::InvalidInput(
                                "create takes no detached input",
                            )
                            .into());
                        }
                        oncl_core::SignRequest::cades_create(
                            requests, attached, level, material, limits,
                        )
                    }
                    (Some(level), SignWriteMode::Add) => oncl_core::SignRequest::cades_add(
                        requests,
                        detached_source,
                        level,
                        material,
                        limits,
                    ),
                }
            };
            let report = env
                .engine
                .sign_staged(request, reader.source(), &mut staged, ctx)?;
            // Everything below runs after the key may have been used.
            let state = strongest(report.signer_states());
            after_use(state, reader.finish())?;
            if let Some(reader) = &mut detached_reader {
                after_use(state, reader.finish())?;
            }
            let signers: Vec<_> = report.signer_states().map(applied).collect();
            let projection = after_use(
                state,
                ctx.resources().reserve_metadata(
                    (signers.len() as u64 * 16)
                        .checked_add(512)
                        .ok_or(ProcessingError::MetadataLimit)?,
                ),
            )?;
            let artifact = after_use(
                state,
                super::artifact::FinishedArtifact::from_staged(sink.owner, staged),
            )?;
            Ok((
                OperationResult::Signing {
                    profile,
                    artifact: Some(sink.id),
                    bytes_in: report.bytes_in,
                    bytes_out: report.bytes_out,
                    signers,
                },
                projection,
                Some(artifact),
            ))
        }
        Operation::Extend {
            profile,
            input,
            detached,
            evidence,
        } => {
            let sink = output.ok_or(OperationError::MissingTemporaryStore)?;
            let (level, pdf) = extend_level(profile);
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
            let mut request = if pdf {
                if detached_reader.is_some() {
                    return Err(ProcessingError::InvalidInput("PDF has no detached input").into());
                }
                oncl_core::ExtendRequest::pdf(level, oncl_pdf::PdfLimits::default())
            } else {
                oncl_core::ExtendRequest::cms(level)
            }
            .with_evidence_limits(limits)
            .with_material(ValidationMaterial {
                certificates: &evidence.certificates,
                ocsp: &ocsp,
                crls: &crls,
            });
            if let Some(reader) = &mut detached_reader {
                request = request.with_detached(reader.source());
            }
            let report = env
                .engine
                .extend_staged(&request, reader.source(), &mut staged, ctx)?;
            reader.finish()?;
            drop(request);
            if let Some(reader) = &mut detached_reader {
                reader.finish()?;
            }
            let verdicts: Vec<&'static str> = report
                .validation_reports()
                .map(|reports| reports.iter().map(|r| verdict(r.verdict)).collect())
                .unwrap_or_default();
            let projection = ctx.resources().reserve_metadata(
                (verdicts.len() as u64 * 16)
                    .checked_add(512)
                    .ok_or(ProcessingError::MetadataLimit)?,
            )?;
            let artifact = super::artifact::FinishedArtifact::from_staged(sink.owner, staged)?;
            Ok((
                OperationResult::Extension {
                    profile,
                    artifact: Some(sink.id),
                    bytes_in: report.bytes_in,
                    bytes_out: report.bytes_out,
                    verdicts,
                },
                projection,
                Some(artifact),
            ))
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
            let entries: Vec<InspectedEntry> = report
                .entries()
                .iter()
                .map(|entry| InspectedEntry {
                    alias: entry.alias().map(str::to_owned),
                    subject_cn: entry.subject_cn().map(str::to_owned),
                    serial_hex: entry.serial_hex().map(str::to_owned),
                    sha256: entry
                        .fingerprint()
                        .map(|value| crate::auth::encode(value.as_bytes())),
                    signature_algorithm_oid: entry.signature_algorithm_oid().map(str::to_owned),
                    public_key_algorithm_oid: entry.public_key_algorithm_oid().map(str::to_owned),
                    not_before_unix: entry.not_before().map(|t| t.unix_timestamp()),
                    not_after_unix: entry.not_after().map(|t| t.unix_timestamp()),
                })
                .collect();
            let cms = report.cms().map(|facts| InspectedCms {
                detached: facts.detached(),
                content_len: facts.content_len(),
                signer_count: facts.signer_count(),
            });
            let projection = ctx.resources().reserve_metadata(
                (entries.len() as u64)
                    .checked_mul(1024)
                    .and_then(|n| n.checked_add(512))
                    .ok_or(ProcessingError::MetadataLimit)?,
            )?;
            Ok((
                OperationResult::Inspection {
                    target: request_label,
                    bytes_in: report.bytes_in(),
                    integrity: report.container_integrity().map(|i| format!("{i:?}")),
                    entries,
                    cms,
                },
                projection,
                None,
            ))
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
            let token_len = report.facts().token().len() as u64;
            let artifact = writer.finish(token_len)?;
            let projection = ctx.resources().reserve_metadata(1024)?;
            Ok((
                OperationResult::Stamping {
                    artifact: Some(sink.id),
                    bytes_in: report.bytes_in(),
                    bytes_out: token_len,
                    timestamp: timestamp_facts(&report),
                },
                projection,
                Some(artifact),
            ))
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
            let projection = ctx.resources().reserve_metadata(1024)?;
            Ok((
                OperationResult::StampVerification {
                    bytes_in: report.bytes_in(),
                    timestamp: timestamp_facts(&report),
                },
                projection,
                None,
            ))
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
            let signers = vec![applied(report.applied); report.signer_count];
            let projection = after_use(
                report.applied,
                ctx.resources()
                    .reserve_metadata(512 + signers.len() as u64 * 16),
            )?;
            Ok((
                OperationResult::Jws {
                    serialization,
                    artifact: Some(sink.id),
                    bytes_in: report.bytes_in,
                    bytes_out: report.bytes_out,
                    signers,
                },
                projection,
                Some(artifact),
            ))
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
            let signers = vec![applied(report.applied); report.signer_count];
            let projection = after_use(
                report.applied,
                ctx.resources()
                    .reserve_metadata(512 + signers.len() as u64 * 16),
            )?;
            Ok((
                OperationResult::Jws {
                    serialization,
                    artifact: Some(sink.id),
                    bytes_in: report.bytes_in,
                    bytes_out: report.bytes_out,
                    signers,
                },
                projection,
                Some(artifact),
            ))
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
            let signers = vec![applied(report.applied); report.signer_count];
            let projection = after_use(
                report.applied,
                ctx.resources()
                    .reserve_metadata(512 + signers.len() as u64 * 16),
            )?;
            Ok((
                OperationResult::Jws {
                    serialization: oncl_api::dto::JwsFormat::Compact,
                    artifact: Some(sink.id),
                    bytes_in: report.bytes_in,
                    bytes_out: report.bytes_out,
                    signers,
                },
                projection,
                Some(artifact),
            ))
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
            let signers = jws_signers(&report);
            let projection = ctx
                .resources()
                .reserve_metadata(512 + signers.len() as u64 * 8192)?;
            Ok((
                OperationResult::JwsVerification {
                    verdict: verdict(report.verdict()),
                    policy: policy_name(report.policy()),
                    checked_at_unix: report.checked_at().unix_timestamp(),
                    signers,
                },
                projection,
                None,
            ))
        }
        Operation::JwtDecode { input } => {
            let mut document = env.documents.take(&input)?;
            let (token, _token) =
                read_bytes(&mut document, ctx, oncl_core::jose::MAX_CLAIMS_BYTES)?;
            let decoded = env.engine.jwt_decode_unverified(&token, ctx)?;
            let claims = String::from_utf8_lossy(decoded.payload()).into_owned();
            let projection = ctx
                .resources()
                .reserve_metadata(512 + claims.len() as u64)?;
            Ok((
                OperationResult::JwtDecoded {
                    verified: decoded.is_verified(),
                    issuer: decoded.issuer().map(str::to_owned),
                    audience: decoded.audience().map(str::to_owned).collect(),
                    expiration_unix: decoded.expiration(),
                    claims,
                },
                projection,
                None,
            ))
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
            let signers = jws_signers(report.jws());
            let claims = String::from_utf8_lossy(report.jws().payload()).into_owned();
            let projection = ctx
                .resources()
                .reserve_metadata(512 + claims.len() as u64 + signers.len() as u64 * 8192)?;
            Ok((
                OperationResult::JwtVerification {
                    verdict: verdict(report.verdict()),
                    signature_verdict: verdict(report.jws().verdict()),
                    claims_verdict: verdict(report.claims().verdict()),
                    claim_failures: report
                        .claims()
                        .failures()
                        .iter()
                        .map(|f| format!("{f:?}"))
                        .collect(),
                    checked_at_unix: report.claims().checked_at(),
                    signers,
                    claims,
                },
                projection,
                None,
            ))
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
            let result = env.engine.plugin_call(&call, &bound, ctx)?;
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
