//! Issuing the approval of a manual-window key use, and the call that runs under it.
//!
//! `docs/design/manual-plugins.md` 4.2, 4.3, 4.8 and `docs/design/plugins.md` (MP3a-2). The
//! order is fixed and each step is Core's:
//!
//! 1. [`Engine::plugin_prepare`] computes, from the declared operation, the frozen bytes of the
//!    bound parameter and the key the user bound, everything the user is asked to approve:
//!    a [`ConsentSummary`] (trusted data only: no text of the plugin) and, inside the returned
//!    [`PluginPrepared`], the [`ApprovedUse`] the approval will name.
//! 2. The host UI renders the summary. Only when the user explicitly confirms does it build a
//!    [`UserConfirmation`] from the summary it showed ([`UserConfirmation::after_user_confirmed`])
//!    and call [`PluginPrepared::approve`], which refuses a confirmation of any other summary.
//!    Nothing here confirms on the user's behalf and nothing is stored: a confirmation and an
//!    approval are each used once.
//! 3. [`Engine::plugin_call_approved`] re-derives the use from the parameters it is handed now,
//!    refuses before the module runs if they are not the approved ones, grants the approval to
//!    the engine's [`PluginConsentGuard`], runs the module in the manual window and revokes the
//!    approval when the call ends, whatever way it ends.
use super::*;
use crate::{OperationId, keys::signature_algorithm};
use der::Encode;
use oncl_pki::{cert::Certificate, digest::HashState, key::HashAlg};
use oncl_plugin::manual::{BoundInteraction, BoundKey, OcspCache};
use oncl_plugin::operations::{
    CmsExProfile, Content, ContentForm, KeyKind, Network, Profile, Source, XmlExProfile, XmlProfile,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::TryLockError;
use std::time::{Duration, Instant};

/// How long an approval lives: from the user's confirmation to the key use. A host may ask
/// for less ([`PluginPrepared::approve`]), never more.
pub const APPROVAL_TTL: Duration = Duration::from_secs(120);

/// Why a manual-window key use could not be prepared. Raised before any key is applied (preparing opens the key once, see [`Engine::plugin_prepare`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginPrepareError {
    /// The operation or its parameters (see [`PluginRequestError`]).
    Request(PluginRequestError),
    /// The context belongs to another engine.
    InvalidContext,
    /// The caller is not a local operator: the manual window has no browser origin.
    CallerNotManual,
    /// The operation declares no key use, so there is nothing to approve.
    NoKeyUse,
    /// The key binding carries no public metadata (alias, certificate).
    KeyMetadataMissing,
    /// The key's certificate or its signature algorithm cannot be used.
    UnsupportedKey,
    /// A `param:` source of the profile has no valid text.
    Options,
    /// The key could not be opened to compare its certificate with the binding's. The cause
    /// (wrong secret, cancellation, deadline, permission) is not kept: collect the secret before
    /// preparing and treat this as "could not open".
    KeyUnavailable,
    /// The certificate in the binding's metadata is not the one the key store holds for the
    /// key: what the user would be shown is not what would sign.
    CertificateMismatch,
}
impl PluginPrepareError {
    /// Always `NotApplied`: nothing here applies a key.
    pub fn applied_state(&self) -> AppliedState {
        AppliedState::NotApplied
    }
}
impl std::fmt::Display for PluginPrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(e) => e.fmt(f),
            Self::InvalidContext => f.write_str("the context belongs to another engine"),
            Self::CallerNotManual => f.write_str("the caller is not a local operator"),
            Self::NoKeyUse => f.write_str("the operation declares no key use"),
            Self::KeyMetadataMissing => f.write_str("the key binding has no public metadata"),
            Self::UnsupportedKey => f.write_str("the key's certificate cannot be used"),
            Self::Options => f.write_str("a profile parameter has no valid text"),
            Self::KeyUnavailable => f.write_str("the key could not be opened"),
            Self::CertificateMismatch => {
                f.write_str("the binding's certificate is not the key's certificate")
            }
        }
    }
}
impl std::error::Error for PluginPrepareError {}
impl From<PluginRequestError> for PluginPrepareError {
    fn from(error: PluginRequestError) -> Self {
        Self::Request(error)
    }
}
impl From<PluginPrepareError> for OperationError {
    fn from(error: PluginPrepareError) -> Self {
        match error {
            PluginPrepareError::Request(e) => e.into(),
            PluginPrepareError::InvalidContext => OperationError::InvalidContext,
            PluginPrepareError::UnsupportedKey => {
                OperationError::Key(oncl_pki::key::KeyError::UnsupportedAlgorithm)
            }
            PluginPrepareError::Options => {
                ProcessingError::InvalidInput("invalid plugin operation parameters").into()
            }
            PluginPrepareError::KeyUnavailable => OperationError::MissingKeyProvider,
            PluginPrepareError::CallerNotManual
            | PluginPrepareError::CertificateMismatch
            | PluginPrepareError::NoKeyUse
            | PluginPrepareError::KeyMetadataMissing => OperationError::PermissionDenied,
        }
    }
}

/// Why [`PluginPrepared::approve`] issued no approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalIssueError {
    /// The confirmation is of another summary than the one prepared.
    ConfirmationMismatch,
    /// The requested lifetime is zero or does not fit a deadline.
    Ttl,
    /// The system random generator failed; no nonce, no approval.
    Random,
}
impl std::fmt::Display for ApprovalIssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ConfirmationMismatch => "the confirmation is of another consent summary",
            Self::Ttl => "invalid approval lifetime",
            Self::Random => "no random nonce available",
        })
    }
}
impl std::error::Error for ApprovalIssueError {}

/// The digest Core computed of a document for a `cms_ex` use whose content form is `digest`:
/// with the hash algorithm of the bound key's signature algorithm, never one a plugin names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrehashedDigest {
    pub alg: HashAlg,
    pub digest: Vec<u8>,
}

/// The signed content as the user is shown it. All of it is computed by Core from the
/// frozen bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentContent {
    /// The declared parameter the bytes come from (the author's name for it).
    pub param: String,
    /// Length of the document, in bytes.
    pub len: u64,
    /// SHA-256 of the document.
    pub sha256: [u8; 32],
    /// For a `digest` content form: what the key actually signs over.
    pub prehashed: Option<PrehashedDigest>,
}

/// The key as the certificate the host bound describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentKey {
    /// The key's alias in its store (host data, not the plugin's). May hold any characters:
    /// the renderer escapes it.
    pub alias: String,
    pub serial_hex: String,
    pub subject_cn: Option<String>,
    /// SHA-256 of the certificate's DER.
    pub fingerprint_sha256: [u8; 32],
    pub not_after: time::OffsetDateTime,
}

/// Where the plugin may send data during the call.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsentNetwork {
    None,
    /// Only these PKI endpoints (as registered by the host), sorted. The document may be
    /// sent to them.
    Pki {
        endpoints: Vec<String>,
    },
}

/// What the user approves: the TRUSTED description of one key use. Every field is computed
/// by Core from the registry, the declared operation, the frozen parameters and the key
/// binding. No text of the plugin (`name`, `description`, `label`) is in it; a renderer that
/// shows those puts them in a separate frame "from the plugin". Strings that are not Core's
/// own (`key.alias`, `key.subject_cn`) may contain any character: escape them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentSummary {
    /// `{id, package hash, version}` of the plugin.
    pub plugin: PluginIdentity,
    /// The declared operation's name.
    pub operation: String,
    pub kind: KeyKind,
    /// How many times the key is applied: always [`oncl_plugin::operations::MAX_USES`].
    pub uses: u8,
    /// The declared profile with the user's text filled in where it names a parameter: what
    /// the signature will be made with. Everything else about the options is Core's default.
    pub profile: Profile,
    /// SHA-256 of the canonical options of `profile` (the one the ticket must carry).
    pub options_sha256: [u8; 32],
    pub content: ConsentContent,
    pub key: ConsentKey,
    pub network: ConsentNetwork,
}
impl ConsentSummary {
    /// SHA-256 over every field, domain-separated and length-prefixed: what a
    /// [`UserConfirmation`] names, so that confirming one summary can never approve another.
    pub fn digest(&self) -> [u8; 32] {
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        fn alg_tag(alg: HashAlg) -> u8 {
            match alg {
                HashAlg::Sha1 => 1,
                HashAlg::Sha256 => 2,
                HashAlg::Sha512 => 3,
                HashAlg::Gost34311 => 4,
                HashAlg::Streebog256 => 5,
                HashAlg::Streebog512 => 6,
            }
        }
        // Exhaustive on purpose: a new field breaks the build until it is hashed here.
        let Self {
            plugin,
            operation,
            kind,
            uses,
            profile,
            options_sha256,
            content,
            key,
            network,
        } = self;
        let ConsentContent {
            param,
            len,
            sha256,
            prehashed,
        } = content;
        let ConsentKey {
            alias,
            serial_hex,
            subject_cn,
            fingerprint_sha256,
            not_after,
        } = key;
        let mut h = Sha256::new();
        h.update(b"ONCLCONSENT2\0");
        field(&mut h, plugin.id.as_bytes());
        field(&mut h, &plugin.package.canonical());
        field(&mut h, plugin.version.as_bytes());
        field(&mut h, operation.as_bytes());
        field(&mut h, kind.as_str().as_bytes());
        h.update([*uses]);
        // The resolved profile, in the canonical encoding that `options_sha256` also names.
        field(&mut h, &profile.encode(*kind, None).unwrap_or_default());
        field(&mut h, options_sha256);
        field(&mut h, param.as_bytes());
        h.update(len.to_be_bytes());
        field(&mut h, sha256);
        match prehashed {
            None => h.update([0]),
            Some(PrehashedDigest { alg, digest }) => {
                h.update([1, alg_tag(*alg)]);
                field(&mut h, digest);
            }
        }
        field(&mut h, alias.as_bytes());
        field(&mut h, serial_hex.as_bytes());
        match subject_cn {
            None => h.update([0]),
            Some(cn) => {
                h.update([1]);
                field(&mut h, cn.as_bytes());
            }
        }
        field(&mut h, fingerprint_sha256);
        h.update(not_after.unix_timestamp().to_be_bytes());
        match network {
            ConsentNetwork::None => h.update([0]),
            ConsentNetwork::Pki { endpoints } => {
                h.update([1]);
                h.update((endpoints.len() as u64).to_be_bytes());
                for endpoint in endpoints {
                    field(&mut h, endpoint.as_bytes());
                }
            }
        }
        h.finalize().into()
    }
}

/// The user's explicit confirmation of one [`ConsentSummary`].
///
/// **The host UI's duty:** build it only inside the handler of the user's own action on the
/// confirm control, after the summary it names was rendered to the user. Never
/// auto-confirm, never build one ahead of time, never from a stored answer. It is neither
/// `Clone` nor `Copy`, has no `Default`, and the only way to make one is
/// [`UserConfirmation::after_user_confirmed`].
#[derive(Debug)]
#[must_use = "a confirmation is spent by PluginPrepared::approve"]
pub struct UserConfirmation {
    summary: [u8; 32],
}
impl UserConfirmation {
    /// The user confirmed `shown`: the summary the host rendered. See the type's duty.
    pub fn after_user_confirmed(shown: &ConsentSummary) -> Self {
        Self {
            summary: shown.digest(),
        }
    }
}

/// Everything about one key use that Core derives from its inputs, and the unit
/// [`PluginApproval::refusal`] compares an approval to.
pub(super) struct Plan {
    pub(super) identity: PluginIdentity,
    pub(super) operation: String,
    pub(super) caller: CallerContext,
    pub(super) key: KeyId,
    pub(super) handle: u32,
    pub(super) used: ApprovedUse,
    summary: ConsentSummary,
}

/// A manual-window key use prepared for the user's consent. See the module documentation.
pub struct PluginPrepared {
    plan: Plan,
    operation_id: OperationId,
}
impl std::fmt::Debug for PluginPrepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginPrepared")
            .field("operation", &self.plan.operation)
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}
impl PluginPrepared {
    /// What to render for the user to confirm.
    pub fn summary(&self) -> &ConsentSummary {
        &self.plan.summary
    }
    /// The invocation the approval will be for (the context it was prepared with).
    pub fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    /// Issues the approval for the confirmed summary: kind, content binding and options hash
    /// are the ones computed at preparation, the nonce is 16 bytes of the system CSPRNG, the
    /// deadline is `ttl` (at most [`APPROVAL_TTL`]; `None` is [`APPROVAL_TTL`]) from now on a
    /// monotonic clock, and the single use is [`oncl_plugin::operations::MAX_USES`].
    ///
    /// # Errors
    ///
    /// [`ApprovalIssueError`]; the confirmation is spent either way.
    pub fn approve(
        self,
        confirmation: UserConfirmation,
        ttl: Option<Duration>,
    ) -> Result<PluginApproval, ApprovalIssueError> {
        if confirmation.summary != self.plan.summary.digest() {
            return Err(ApprovalIssueError::ConfirmationMismatch);
        }
        let ttl = match ttl {
            None => APPROVAL_TTL,
            Some(ttl) if ttl.is_zero() => return Err(ApprovalIssueError::Ttl),
            Some(ttl) => ttl.min(APPROVAL_TTL),
        };
        let deadline = Instant::now()
            .checked_add(ttl)
            .ok_or(ApprovalIssueError::Ttl)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| ApprovalIssueError::Random)?;
        let Plan {
            identity,
            operation,
            caller,
            key,
            handle,
            used,
            summary: _,
        } = self.plan;
        Ok(PluginApproval::new(
            identity,
            operation,
            caller,
            self.operation_id,
            key,
            handle,
            vec![used],
            deadline,
            nonce,
        ))
    }
}

/// One manual-window call as the host hands it to [`Engine::plugin_prepare`] and, with the
/// same values, to [`Engine::plugin_call_approved`]: the declared operation, the typed
/// parameters (the frozen documents), the key the user bound and the local operator the
/// operation is registered for.
#[derive(Clone, Copy)]
pub struct ManualCall<'a> {
    pub plugin_id: &'a str,
    pub operation: &'a str,
    pub params: &'a [(&'a str, PluginParam<'a>)],
    /// The binding the backend signs with; it must carry its public metadata
    /// ([`PluginKeyBinding::with_public_metadata`]).
    pub key: &'a PluginKeyBinding<'a>,
    /// Must be a [`CallerContext::LocalOperator`]: the manual window has no origin.
    pub caller: &'a CallerContext,
}

/// Where a manual call's host services come from: the host's own PKI transport (with its
/// network policy) and its shared OCSP cache. They are the host's, never the plugin's, and
/// the same transport serves the plugin's PKI requests and the key choice's OCSP check.
#[derive(Clone, Copy)]
pub struct ManualHost<'a> {
    pub transport: &'a Arc<dyn HttpTransport>,
    pub network: &'a NetworkPolicy,
    pub ocsp_cache: &'a Arc<OcspCache>,
}

/// What a manual call did, honestly.
///
/// `applied` is whether the key was applied: [`AppliedState::Applied`] also when the plugin
/// failed (trapped, ran out of fuel, a later PKI request failed) after the key use;
/// [`AppliedState::Unknown`] when the application itself did not report; `NotApplied` for
/// every refusal before the key. `refusals` are the typed reasons the guard (or the call
/// before the module ran) refused for this invocation.
#[derive(Debug)]
pub struct ApprovedCall {
    outcome: Result<PluginResult, OperationError>,
    applied: AppliedState,
    refusals: Vec<TicketRefusal>,
}
impl ApprovedCall {
    fn refused(reason: TicketRefusal) -> Self {
        Self {
            outcome: Err(OperationError::PermissionDenied),
            applied: AppliedState::NotApplied,
            refusals: vec![reason],
        }
    }
    fn failed(error: PluginPrepareError) -> Self {
        let refusals = match &error {
            PluginPrepareError::Request(PluginRequestError::UndeclaredOperation) => {
                vec![TicketRefusal::UndeclaredOperation]
            }
            PluginPrepareError::CallerNotManual => vec![TicketRefusal::Caller],
            _ => Vec::new(),
        };
        Self {
            outcome: Err(error.into()),
            applied: AppliedState::NotApplied,
            refusals,
        }
    }
    fn of(outcome: Result<PluginResult, OperationError>, refusals: Vec<TicketRefusal>) -> Self {
        let applied = match &outcome {
            Ok(result) => result.applied_state(),
            Err(error) => error.applied_state(),
        };
        Self {
            outcome,
            applied,
            refusals,
        }
    }
    /// Whether the key was applied.
    pub fn applied(&self) -> AppliedState {
        self.applied
    }
    /// The refusals recorded for this invocation, oldest first.
    pub fn refusals(&self) -> &[TicketRefusal] {
        &self.refusals
    }
    /// The plugin's reply, or why there is none.
    pub fn result(&self) -> Result<&PluginResult, &OperationError> {
        self.outcome.as_ref()
    }
    /// The plugin's reply string, if it replied.
    pub fn response(&self) -> Option<&str> {
        self.outcome.as_ref().ok().map(PluginResult::response)
    }
    pub fn error(&self) -> Option<&OperationError> {
        self.outcome.as_ref().err()
    }
    pub fn into_result(self) -> Result<PluginResult, OperationError> {
        self.outcome
    }
}

/// Revokes the approval when dropped: the call ends, normally, by error or by unwinding.
struct ArmedApproval<'g>(&'g PluginConsentGuard);
impl<'g> ArmedApproval<'g> {
    fn grant(
        guard: &'g PluginConsentGuard,
        approval: PluginApproval,
    ) -> Result<Self, TicketRefusal> {
        let armed = Self(guard);
        guard.grant(approval).map_err(|rejected| match rejected {
            ApprovalRejected::Replayed => TicketRefusal::Replayed,
            _ => TicketRefusal::Uses,
        })?;
        Ok(armed)
    }
}
impl Drop for ArmedApproval<'_> {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

fn bound_bytes<'p>(
    name: &str,
    params: &[(&str, PluginParam<'p>)],
) -> Result<&'p [u8], PluginPrepareError> {
    match params.iter().find(|(n, _)| *n == name) {
        Some((_, PluginParam::Document(bytes))) => Ok(bytes),
        Some((_, PluginParam::Text(text))) => Ok(text.as_bytes()),
        Some(_) => Err(PluginRequestError::WrongKind(name.to_owned()).into()),
        None => Err(PluginRequestError::MissingParam(name.to_owned()).into()),
    }
}

/// `profile` with every `param:` source replaced by the text `values` gives for it.
fn resolved(profile: &Profile, values: &dyn Fn(&str) -> Option<String>) -> Option<Profile> {
    let source = |s: &Option<Source>| -> Option<Option<Source>> {
        match s {
            None => Some(None),
            Some(Source::Fixed(text)) => Some(Some(Source::Fixed(text.clone()))),
            Some(Source::Param(name)) => Some(Some(Source::Fixed(values(name)?))),
        }
    };
    Some(match profile {
        Profile::Xml(p) => Profile::Xml(XmlProfile {
            element: source(&p.element)?,
            parent: source(&p.parent)?,
        }),
        Profile::XmlEx(p) => Profile::XmlEx(XmlExProfile {
            element: source(&p.element)?,
            parent: source(&p.parent)?,
            ..p.clone()
        }),
        other => other.clone(),
    })
}

fn is_digest_form(profile: &Profile) -> bool {
    matches!(
        profile,
        Profile::CmsEx(CmsExProfile {
            content_form: ContentForm::Digest,
            ..
        })
    )
}

impl Engine {
    /// Derives everything that one manual-window key use is, from Core's data only: the
    /// registered identity, the declared operation, the frozen parameter bytes and the bound
    /// key. Nothing from a plugin is read.
    fn plugin_plan(
        &self,
        call: &ManualCall<'_>,
        ctx: &OperationContext,
    ) -> Result<Plan, PluginPrepareError> {
        let ManualCall {
            plugin_id,
            operation,
            params,
            key,
            caller,
        } = *call;
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(PluginPrepareError::InvalidContext);
        }
        if !matches!(caller, CallerContext::LocalOperator(_)) {
            return Err(PluginPrepareError::CallerNotManual);
        }
        let installed = self
            .plugins
            .as_ref()
            .and_then(|r| r.installed.get(plugin_id))
            .ok_or(PluginRequestError::UnknownPlugin)?;
        let op = installed.manual_operation(operation)?;
        let [declared] = op.uses().keys() else {
            return Err(PluginPrepareError::NoKeyUse);
        };
        let Content::Bound(param) = declared.content() else {
            return Err(PluginRequestError::DerivedUnsupported.into());
        };
        let bytes = bound_bytes(param, params)?;
        let metadata = key
            .metadata
            .as_ref()
            .ok_or(PluginPrepareError::KeyMetadataMissing)?;
        let cert: &Certificate = metadata.certificate;
        cert.to_der()
            .map_err(|_| PluginPrepareError::UnsupportedKey)?;
        let info = oncl_pki::info::cert_info(cert);

        let sha256: [u8; 32] = Sha256::digest(bytes).into();
        let (content, prehashed) = if is_digest_form(declared.profile()) {
            // The digest of the document with the algorithm the signer will use for this
            // key (the strict one `Engine::operation_signer` derives for a plugin's signing import): Core's, never the plugin's.
            let public = oncl_pki::key::PublicKey::from_spki(
                cert.tbs_certificate().subject_public_key_info(),
            )
            .map_err(|_| PluginPrepareError::UnsupportedKey)?;
            let alg = signature_algorithm(cert, public.alg(), ctx.policy(), true)
                .map_err(|_| PluginPrepareError::UnsupportedKey)?
                .hash_alg();
            let mut state = HashState::new(alg);
            state.update(bytes);
            let digest = state.finish();
            (
                ContentBinding::prehashed(digest.as_bytes()),
                Some(PrehashedDigest {
                    alg,
                    digest: digest.as_bytes().to_vec(),
                }),
            )
        } else {
            (ContentBinding::bytes(bytes), None)
        };

        let values = |name: &str| -> Option<String> {
            match params.iter().find(|(n, _)| *n == name) {
                Some((_, PluginParam::Text(text))) => Some((*text).to_owned()),
                _ => None,
            }
        };
        let options_sha256 = declared
            .options_sha256(&values)
            .ok_or(PluginPrepareError::Options)?;
        let profile = resolved(declared.profile(), &values).ok_or(PluginPrepareError::Options)?;

        let network = match op.uses().network() {
            Network::Pki => ConsentNetwork::Pki {
                endpoints: installed
                    .policy
                    .iter()
                    .filter(|p| {
                        p.plugin_id == plugin_id && p.operation == operation && p.caller == *caller
                    })
                    .flat_map(|p| p.pki_endpoints.iter().map(|e| e.url.clone()))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
            _ => ConsentNetwork::None,
        };
        let fingerprint = certificate_sha256(cert);
        let used = ApprovedUse::new(declared.kind(), content, options_sha256, fingerprint);
        Ok(Plan {
            identity: installed.identity.clone(),
            operation: operation.to_owned(),
            caller: caller.clone(),
            key: key.key.selector().key_id(),
            handle: key.handle,
            summary: ConsentSummary {
                plugin: installed.identity.clone(),
                operation: operation.to_owned(),
                kind: declared.kind(),
                uses: declared.max_uses(),
                profile,
                options_sha256,
                content: ConsentContent {
                    param: param.clone(),
                    len: bytes.len() as u64,
                    sha256,
                    prehashed,
                },
                key: ConsentKey {
                    alias: metadata.alias.to_owned(),
                    serial_hex: info.serial_hex,
                    subject_cn: info.subject_cn,
                    fingerprint_sha256: fingerprint,
                    not_after: info.not_after,
                },
                network,
            },
            used,
        })
    }

    /// Prepares the manual-window key use of the declared `call.operation` for the user's consent:
    /// validates the parameters as [`Engine::plugin_request`] does, freezes what is signed
    /// (the bound parameter's bytes) and the options (the declared profile with the user's
    /// text), and returns the trusted [`ConsentSummary`] to render. `caller` must be the
    /// local operator the operation is registered for; `key` must carry its public
    /// metadata (alias, certificate).
    ///
    /// The key is opened (and released) once, at preparation, with the secret in `call.key.key`
    /// (a token login or a key-store decryption happens now, and again in the call): the host
    /// collects the secret BEFORE showing the consent. The key is opened to compare its certificate with the binding's
    /// metadata ([`PluginPrepareError::CertificateMismatch`]); nothing is granted or applied.
    /// The approval binds that certificate's SHA-256: the guard refuses the key use
    /// ([`TicketRefusal::CertificateChanged`], not applied) if the key about to sign holds
    /// another. The alias is display only and is not compared. `ctx` names the approval that
    /// [`PluginPrepared::approve`] will issue.
    ///
    /// # Errors
    ///
    /// [`PluginPrepareError`], always with the key not applied.
    pub fn plugin_prepare(
        &self,
        call: &ManualCall<'_>,
        ctx: &mut OperationContext,
    ) -> Result<PluginPrepared, PluginPrepareError> {
        let plan = self.plugin_plan(call, ctx)?;
        // A request that cannot be built is no operation to ask the user about.
        self.plugin_request(call.plugin_id, call.operation, call.params)?;
        // What the user is shown is what will sign: the key store's own certificate for this
        // key must be the one the binding's metadata carries. Opening a key applies none.
        let services = self
            .keys
            .as_ref()
            .ok_or(PluginPrepareError::KeyUnavailable)?;
        let lease = services
            .provider
            .open(&call.key.key, ctx)
            .map_err(|_| PluginPrepareError::KeyUnavailable)?;
        if certificate_sha256(lease.certificate()) != plan.used.certificate_sha256 {
            return Err(PluginPrepareError::CertificateMismatch);
        }
        drop(lease);
        Ok(PluginPrepared {
            plan,
            operation_id: ctx.id(),
        })
    }

    /// Runs a declared operation in the manual window under `approval`.
    ///
    /// The use is re-derived from `params` and `key` as handed here and compared to the
    /// approval; any difference (another document, text, key, caller, operation, an expired
    /// or other invocation's approval) is refused **before the module runs**, so a document
    /// the user did not approve is never handed to the plugin. Then the request is built
    /// from the declared template and `params`, the approval is granted to the engine's
    /// [`PluginConsentGuard`] (the only key-use guard of this call: the engine must be
    /// configured with [`crate::EngineServices::with_plugin_keys`]) and the module runs with
    /// [`oncl_plugin::Compiled::call_manual`]: no browser origin, key choices answered for
    /// the one bound key, no dialogs, files or key stores. The guard remains the
    /// authoritative check at the key use (kind, content, options, one use, expiry). Whatever
    /// way the call ends, including a panic, the approval is revoked.
    ///
    /// `ctx` carries the deadline and cancellation of the host and the per-call grant (the
    /// chosen key and the operation's [`PluginPermission`]); `host` the PKI transport and
    /// the shared OCSP cache. The key's `BoundKey` is built from `key`: the binding the
    /// backend signs with, so the plugin sees exactly that key's alias and certificate.
    pub fn plugin_call_approved(
        &self,
        call: &ManualCall<'_>,
        approval: PluginApproval,
        host: &ManualHost<'_>,
        ctx: &mut OperationContext,
    ) -> ApprovedCall {
        let ManualCall {
            plugin_id,
            operation,
            params,
            key,
            caller,
        } = *call;
        let Some(guard) = self.plugin_guard.as_deref() else {
            return ApprovedCall::refused(TicketRefusal::NoGuard);
        };
        let _in_flight = match self.approved_call.try_lock() {
            Ok(held) => held,
            Err(TryLockError::Poisoned(held)) => held.into_inner(),
            Err(TryLockError::WouldBlock) => return ApprovedCall::refused(TicketRefusal::Busy),
        };
        let plan = match self.plugin_plan(call, ctx) {
            Ok(plan) => plan,
            Err(error) => return ApprovedCall::failed(error),
        };
        if let Some(reason) = approval.refusal(&plan, ctx.id()) {
            return ApprovedCall::refused(reason);
        }
        let request = match self.plugin_request(plugin_id, operation, params) {
            Ok(request) => request,
            Err(error) => return ApprovedCall::failed(error.into()),
        };
        let Some(validation) = self.validation.as_ref() else {
            return ApprovedCall {
                outcome: Err(OperationError::MissingValidationServices),
                applied: AppliedState::NotApplied,
                refusals: Vec::new(),
            };
        };
        let Some(metadata) = key.metadata.as_ref() else {
            return ApprovedCall::failed(PluginPrepareError::KeyMetadataMissing);
        };
        let Ok(certificate) = metadata.certificate.to_der() else {
            return ApprovedCall::failed(PluginPrepareError::UnsupportedKey);
        };
        // Fresh for this call: the clock is read now, the key is the binding itself.
        let interaction = BoundInteraction {
            key: BoundKey {
                handle: key.handle,
                alias: metadata.alias.to_owned(),
                certificate,
            },
            now: (validation.clock)(),
            http: host.transport.clone(),
            ocsp_cache: host.ocsp_cache.clone(),
        };
        let armed = match ArmedApproval::grant(guard, approval) {
            Ok(armed) => armed,
            Err(reason) => return ApprovedCall::refused(reason),
        };
        let bindings = PluginBindings::new(caller, std::slice::from_ref(key))
            .with_network(&**host.transport, host.network);
        let outcome = self.call_plugin(
            &PluginCall {
                plugin_id,
                operation,
                args: &request,
            },
            &bindings,
            ctx,
            Some(&interaction),
        );
        drop(armed);
        ApprovedCall::of(outcome, guard.take_refusals(ctx.id()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The honest AppliedState of an outcome is the engine's own, for all three states.
    #[test]
    fn applied_follows_the_engines_state_in_all_three_cases() {
        let after = |applied| {
            Err(OperationError::AfterKeyUse {
                source: Box::new(OperationError::PermissionDenied),
                applied,
            })
        };
        assert_eq!(
            ApprovedCall::of(after(AppliedState::Unknown), Vec::new()).applied(),
            AppliedState::Unknown
        );
        assert_eq!(
            ApprovedCall::of(after(AppliedState::Applied), Vec::new()).applied(),
            AppliedState::Applied
        );
        assert_eq!(
            ApprovedCall::of(Err(OperationError::PermissionDenied), Vec::new()).applied(),
            AppliedState::NotApplied
        );
    }

    /// Changing any one field of a summary changes its digest.
    #[test]
    fn every_field_of_the_summary_changes_the_digest() {
        let base = ConsentSummary {
            plugin: PluginIdentity {
                id: "p".into(),
                package: PackageHash::File([1; 32]),
                version: "1".into(),
            },
            operation: "op".into(),
            kind: KeyKind::Raw,
            uses: 1,
            profile: Profile::Raw,
            options_sha256: [2; 32],
            content: ConsentContent {
                param: "file".into(),
                len: 3,
                sha256: [3; 32],
                prehashed: None,
            },
            key: ConsentKey {
                alias: "a".into(),
                serial_hex: "01".into(),
                subject_cn: Some("cn".into()),
                fingerprint_sha256: [4; 32],
                not_after: time::OffsetDateTime::UNIX_EPOCH,
            },
            network: ConsentNetwork::None,
        };
        let d = base.digest();
        let variants: Vec<(&str, Box<dyn Fn(&mut ConsentSummary)>)> = vec![
            ("id", Box::new(|s| s.plugin.id = "q".into())),
            (
                "package",
                Box::new(|s| s.plugin.package = PackageHash::File([9; 32])),
            ),
            ("version", Box::new(|s| s.plugin.version = "2".into())),
            ("operation", Box::new(|s| s.operation = "o2".into())),
            ("kind", Box::new(|s| s.kind = KeyKind::Cms)),
            ("uses", Box::new(|s| s.uses = 2)),
            (
                "profile",
                Box::new(|s| s.profile = Profile::Cms(Default::default())),
            ),
            ("options", Box::new(|s| s.options_sha256 = [9; 32])),
            ("param", Box::new(|s| s.content.param = "x".into())),
            ("len", Box::new(|s| s.content.len = 4)),
            ("sha256", Box::new(|s| s.content.sha256 = [9; 32])),
            (
                "prehashed",
                Box::new(|s| {
                    s.content.prehashed = Some(PrehashedDigest {
                        alg: HashAlg::Sha256,
                        digest: vec![1],
                    })
                }),
            ),
            ("alias", Box::new(|s| s.key.alias = "b".into())),
            ("serial", Box::new(|s| s.key.serial_hex = "02".into())),
            ("cn", Box::new(|s| s.key.subject_cn = None)),
            (
                "cn text",
                Box::new(|s| s.key.subject_cn = Some("other".into())),
            ),
            (
                "fingerprint",
                Box::new(|s| s.key.fingerprint_sha256 = [9; 32]),
            ),
            (
                "not_after",
                Box::new(|s| s.key.not_after += time::Duration::DAY),
            ),
            (
                "network",
                Box::new(|s| {
                    s.network = ConsentNetwork::Pki {
                        endpoints: vec!["http://a/".into()],
                    }
                }),
            ),
        ];
        for (name, change) in variants {
            let mut s = base.clone();
            change(&mut s);
            assert_ne!(s.digest(), d, "{name} is not in the digest");
        }
    }
}
