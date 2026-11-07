//! The key-use ticket of a declared plugin operation and the guard that checks it.
//!
//! `docs/design/manual-plugins.md` §4.2: the one authoritative check of a plugin's key use
//! is [`KeyUseGuard::before_use`] on a [`PluginUse`]. Core builds the ticket from the very
//! arguments it then hands to the engine (never from anything the plugin claims about them),
//! parks it in the operation context, and `AuthorizedSigner::sign_digest` moves it into the
//! [`KeyUseEvent`]. [`PluginConsentGuard`] lets the key be used only for a ticket that an
//! unexpired, unconsumed [`PluginApproval`] names exactly. With no approval it refuses
//! everything, so a plugin cannot use a key unless the host armed the guard for this call.
//!
//! Core issues an approval (from the user's confirmed consent, the declared profile and the
//! frozen input) by `Engine::plugin_prepare` and `PluginPrepared::approve`; here it is the data type the guard checks.
use super::*;
use crate::{
    Action, OperationId,
    keys::{KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt},
};
use oncl_plugin::operations::{
    CmsExProfile, CmsProfile, Content, KeyKind, MAX_USES, Namespace, Operation, Profile, Source,
    XadesProfile, XmlExProfile, XmlOutputProfile, XmlProfile,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

/// What the signed content of a ticket is: the SHA-256 of the bytes the key signs and their
/// length. `prehashed` marks a CMS `Digest` input, where the "bytes" are the digest the
/// plugin supplies (the key use is `Action::SignDigest`); it never equals the same bytes
/// as a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentBinding {
    pub sha256: [u8; 32],
    pub len: u64,
    pub prehashed: bool,
}
impl ContentBinding {
    /// The content is these document bytes.
    pub fn bytes(bytes: &[u8]) -> Self {
        Self {
            sha256: Sha256::digest(bytes).into(),
            len: bytes.len() as u64,
            prehashed: false,
        }
    }
    /// The content is this caller-supplied digest (the CMS `Digest` input).
    pub fn prehashed(digest: &[u8]) -> Self {
        Self {
            sha256: Sha256::digest(digest).into(),
            len: digest.len() as u64,
            prehashed: true,
        }
    }
    fn action(&self) -> Action {
        if self.prehashed {
            Action::SignDigest
        } else {
            Action::Sign
        }
    }
}

/// The ticket of one key use of a plugin. Only Core builds it, from the decoded arguments of
/// the signing import it is about to run; there is no constructor outside this crate and no
/// `Deserialize`. A ticket allows exactly one use ([`PluginUse::max_uses`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginUse {
    identity: PluginIdentity,
    operation: String,
    caller: CallerContext,
    kind: KeyKind,
    handle: u32,
    key: KeyId,
    content: ContentBinding,
    options_sha256: [u8; 32],
    /// SHA-256 of the DER of the certificate of the key that is about to sign: set at the
    /// signing point from the key lease itself (never from host metadata or the plugin).
    certificate_sha256: [u8; 32],
    max_uses: u8,
}
impl PluginUse {
    pub(crate) fn with_signer_certificate(mut self, certificate_sha256: [u8; 32]) -> Self {
        self.certificate_sha256 = certificate_sha256;
        self
    }
    /// SHA-256 of the certificate of the key that signs, from its lease.
    pub fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }
    /// A ticket for tests of guards (for example a document guard that must refuse every
    /// plugin event). Core builds the real ones from the arguments it runs. Not part of a
    /// release: only with the `testing` feature.
    #[cfg(feature = "testing")]
    #[allow(clippy::too_many_arguments)]
    pub fn for_tests(
        identity: PluginIdentity,
        operation: impl Into<String>,
        caller: CallerContext,
        kind: KeyKind,
        handle: u32,
        key: KeyId,
        content: ContentBinding,
        options_sha256: [u8; 32],
        certificate_sha256: [u8; 32],
    ) -> Self {
        Self {
            identity,
            operation: operation.into(),
            caller,
            kind,
            handle,
            key,
            content,
            options_sha256,
            certificate_sha256,
            max_uses: MAX_USES,
        }
    }
    /// `{id, package hash, version}` of the registered plugin.
    pub fn identity(&self) -> &PluginIdentity {
        &self.identity
    }
    /// The declared operation (the host's label of the call, not anything the plugin sent).
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn caller(&self) -> &CallerContext {
        &self.caller
    }
    pub fn kind(&self) -> KeyKind {
        self.kind
    }
    /// The plugin's handle of the one bound key.
    pub fn handle(&self) -> u32 {
        self.handle
    }
    pub fn key(&self) -> &KeyId {
        &self.key
    }
    pub fn content(&self) -> &ContentBinding {
        &self.content
    }
    /// SHA-256 of the canonical options of the actual call
    /// ([`oncl_plugin::operations::Profile::encode`], the encoder of the declared profile).
    pub fn options_sha256(&self) -> &[u8; 32] {
        &self.options_sha256
    }
    /// Always [`oncl_plugin::operations::MAX_USES`].
    pub fn max_uses(&self) -> u8 {
        self.max_uses
    }
    /// SHA-256 over every field, domain-separated and length-prefixed: what an audit record
    /// of the use names without carrying bytes.
    pub fn digest(&self) -> [u8; 32] {
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        let mut h = Sha256::new();
        h.update(b"ONCLTKT1\0");
        field(&mut h, self.identity.id.as_bytes());
        field(&mut h, &self.identity.package.canonical());
        field(&mut h, self.identity.version.as_bytes());
        field(&mut h, self.operation.as_bytes());
        let (tag, text) = match &self.caller {
            CallerContext::Browser { origin } => (1u8, origin),
            CallerContext::LocalOperator(name) => (2, name),
            CallerContext::ServiceClient(name) => (3, name),
        };
        h.update([tag]);
        field(&mut h, text.as_bytes());
        field(&mut h, self.kind.as_str().as_bytes());
        h.update(self.handle.to_be_bytes());
        field(&mut h, self.key.as_str().as_bytes());
        field(&mut h, &self.content.sha256);
        h.update(self.content.len.to_be_bytes());
        h.update([u8::from(self.content.prehashed)]);
        field(&mut h, &self.options_sha256);
        field(&mut h, &self.certificate_sha256);
        h.update([self.max_uses]);
        h.finalize().into()
    }
}

/// One key use the user approved: what is signed and how. Only Core builds it: from the
/// frozen bytes of the bound parameter and the declared profile ([`super::PluginPrepared`]),
/// never from a host-supplied or plugin-supplied digest. There is no public constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedUse {
    pub(super) kind: KeyKind,
    pub(super) content: ContentBinding,
    pub(super) options_sha256: [u8; 32],
    /// SHA-256 of the DER of the signer certificate the user was shown.
    pub(super) certificate_sha256: [u8; 32],
}
impl ApprovedUse {
    pub(super) fn new(
        kind: KeyKind,
        content: ContentBinding,
        options_sha256: [u8; 32],
        certificate_sha256: [u8; 32],
    ) -> Self {
        Self {
            kind,
            content,
            options_sha256,
            certificate_sha256,
        }
    }
    /// For tests of the guard, which must forge what Core never would. Not part of a
    /// release: only with the `testing` feature.
    #[cfg(feature = "testing")]
    pub fn for_tests(
        kind: KeyKind,
        content: ContentBinding,
        options_sha256: [u8; 32],
        certificate_sha256: [u8; 32],
    ) -> Self {
        Self::new(kind, content, options_sha256, certificate_sha256)
    }
    pub fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }
    pub fn kind(&self) -> KeyKind {
        self.kind
    }
    pub fn content(&self) -> &ContentBinding {
        &self.content
    }
    pub fn options_sha256(&self) -> &[u8; 32] {
        &self.options_sha256
    }
}

/// The approval a [`PluginConsentGuard`] checks tickets against: one plugin, operation,
/// caller, invocation and key, for the uses listed, until `ttl_deadline`. It is neither
/// `Clone` nor `Deserialize`, and the guard accepts a nonce only once. Core issues it
/// ([`super::PluginPrepared::approve`]) from a confirmed [`super::ConsentSummary`]; a host has
/// no constructor.
pub struct PluginApproval {
    identity: PluginIdentity,
    operation: String,
    caller: CallerContext,
    operation_id: OperationId,
    key: KeyId,
    handle: u32,
    uses: Vec<ApprovedUse>,
    ttl_deadline: Instant,
    nonce: [u8; 16],
}
impl PluginApproval {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        identity: PluginIdentity,
        operation: impl Into<String>,
        caller: CallerContext,
        operation_id: OperationId,
        key: KeyId,
        handle: u32,
        uses: Vec<ApprovedUse>,
        ttl_deadline: Instant,
        nonce: [u8; 16],
    ) -> Self {
        Self {
            identity,
            operation: operation.into(),
            caller,
            operation_id,
            key,
            handle,
            uses,
            ttl_deadline,
            nonce,
        }
    }
    /// For tests of the guard, which must forge what Core never would. Not part of a
    /// release: only with the `testing` feature.
    #[cfg(feature = "testing")]
    #[allow(clippy::too_many_arguments)]
    pub fn for_tests(
        identity: PluginIdentity,
        operation: impl Into<String>,
        caller: CallerContext,
        operation_id: OperationId,
        key: KeyId,
        handle: u32,
        uses: Vec<ApprovedUse>,
        ttl_deadline: Instant,
        nonce: [u8; 16],
    ) -> Self {
        Self::new(
            identity,
            operation,
            caller,
            operation_id,
            key,
            handle,
            uses,
            ttl_deadline,
            nonce,
        )
    }
    /// The facts of the use `ticket` makes under this approval, for audit.
    pub fn audit_record(&self, ticket: &PluginUse) -> PluginAuditRecord {
        PluginAuditRecord::from_ticket(ticket, Some(&self.nonce), None)
    }
    /// The monotonic deadline after which the guard refuses every use of this approval
    /// ([`TicketRefusal::Expired`]).
    pub fn expires_at(&self) -> Instant {
        self.ttl_deadline
    }
    /// The first reason this approval cannot cover `plan` for invocation `operation_id` now,
    /// in the guard's order: a fast refusal before the plugin runs, so a document that is not
    /// the approved one is never handed to it. The guard still decides at the key use.
    pub(super) fn refusal(
        &self,
        plan: &super::approval::Plan,
        operation_id: OperationId,
    ) -> Option<TicketRefusal> {
        if self.uses.len() != usize::from(MAX_USES) {
            return Some(TicketRefusal::Uses);
        }
        if Instant::now() >= self.ttl_deadline {
            return Some(TicketRefusal::Expired);
        }
        if self.operation_id != operation_id {
            return Some(TicketRefusal::OperationId);
        }
        if self.identity != plan.identity {
            return Some(TicketRefusal::Identity);
        }
        if self.operation != plan.operation {
            return Some(TicketRefusal::Operation);
        }
        if self.caller != plan.caller {
            return Some(TicketRefusal::Caller);
        }
        if self.key != plan.key || self.handle != plan.handle {
            return Some(TicketRefusal::Key);
        }
        let used = &self.uses[0];
        if used.certificate_sha256 != plan.used.certificate_sha256 {
            return Some(TicketRefusal::CertificateChanged);
        }
        if used.kind != plan.used.kind {
            return Some(TicketRefusal::Kind);
        }
        if used.content != plan.used.content {
            return Some(TicketRefusal::Content);
        }
        if used.options_sha256 != plan.used.options_sha256 {
            return Some(TicketRefusal::Options);
        }
        None
    }
}
impl std::fmt::Debug for PluginApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginApproval")
            .field("identity", &self.identity)
            .field("operation", &self.operation)
            .field("operation_id", &self.operation_id)
            .field("uses", &self.uses.len())
            .finish_non_exhaustive()
    }
}

/// Why a guard refused a key use. The caller always sees `PermissionDenied` with the key
/// not applied; this is for audit and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TicketRefusal {
    /// The event carries no ticket (not a plugin key use of a declared operation).
    NoTicket,
    /// No approval was granted to the guard (or it was revoked).
    NoApproval,
    /// The ticket allows other than one use.
    Uses,
    /// The approval's deadline passed.
    Expired,
    /// Another invocation than the approved one.
    OperationId,
    /// Another plugin, package or version.
    Identity,
    /// Another declared operation.
    Operation,
    /// Another caller.
    Caller,
    /// Another key or handle than the approved one.
    Key,
    /// The key action does not fit the content (document vs prehashed).
    Action,
    /// Another signature kind.
    Kind,
    /// Other content bytes.
    Content,
    /// Other signature options.
    Options,
    /// The approved use is spent.
    AlreadyUsed,
    /// The plugin declares operations and the call's operation is none of them (refused
    /// in `plugin_call`, before the module runs; see `OperationContext::plugin_refusal`).
    UndeclaredOperation,
    /// The certificate of the key that is about to sign is not the one the user approved.
    CertificateChanged,
    /// The engine has no [`PluginConsentGuard`] configured for plugin key uses
    /// ([`crate::EngineServices::with_plugin_keys`]), so no approved call can run.
    NoGuard,
    /// Another approved call of this engine is running.
    Busy,
    /// The approval's nonce was granted to the guard before.
    Replayed,
    /// No operator grant covers the ticket (the server or CLI has no `plugin_bytes` grant for
    /// the plugin, operation and key).
    NotGranted,
}

/// Why [`PluginConsentGuard::grant`] did not take an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalRejected {
    /// The nonce was granted before.
    Replayed,
    /// More uses than [`oncl_plugin::operations::MAX_USES`] allows for a key use, or none.
    Uses,
}

struct Armed {
    approval: PluginApproval,
    spent: Vec<bool>,
}
#[derive(Default)]
struct GuardState {
    armed: Option<Armed>,
    nonces: HashSet<[u8; 16]>,
    /// Newest last; at most [`REFUSAL_LOG`] entries, the oldest dropped first.
    refusals: VecDeque<(OperationId, TicketRefusal)>,
}

/// How many refusals a guard remembers for the host to drain.
pub const REFUSAL_LOG: usize = 64;

/// The key-use guard of a plugin engine: it refuses every key use unless the event's ticket
/// matches an unspent use of the granted [`PluginApproval`]. It also refuses an event
/// without a ticket, so a document key use through it is refused (give documents their own
/// engine and guard).
#[derive(Default)]
pub struct PluginConsentGuard {
    state: Mutex<GuardState>,
    applications: AtomicUsize,
}
impl std::fmt::Debug for PluginConsentGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginConsentGuard")
            .field("applications", &self.applications())
            .finish_non_exhaustive()
    }
}
impl PluginConsentGuard {
    pub fn new() -> Self {
        Self::default()
    }
    /// Arms the guard with `approval`, replacing an earlier one. An approval is for one
    /// invocation: its nonce is accepted once for the life of the guard.
    ///
    /// # Errors
    ///
    /// [`ApprovalRejected`] if the nonce was seen or the uses are not exactly one.
    pub fn grant(&self, approval: PluginApproval) -> Result<(), ApprovalRejected> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if approval.uses.len() != usize::from(MAX_USES) {
            return Err(ApprovalRejected::Uses);
        }
        if !state.nonces.insert(approval.nonce) {
            return Err(ApprovalRejected::Replayed);
        }
        let spent = vec![false; approval.uses.len()];
        state.armed = Some(Armed { approval, spent });
        Ok(())
    }
    /// Drops the approval: every later key use is refused.
    pub fn revoke(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .armed = None;
    }
    /// How many times the guard let a key be used.
    pub fn applications(&self) -> usize {
        self.applications.load(Ordering::SeqCst)
    }
    /// The refusals recorded for `operation`, oldest first, without removing them. A later
    /// success or refusal of another operation never hides one.
    pub fn refusals(&self, operation: OperationId) -> Vec<TicketRefusal> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .refusals
            .iter()
            .filter(|(id, _)| *id == operation)
            .map(|(_, reason)| *reason)
            .collect()
    }
    /// Removes and returns the refusals recorded for `operation`, oldest first: what an
    /// audit record of the finished call names.
    pub fn take_refusals(&self, operation: OperationId) -> Vec<TicketRefusal> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut taken = Vec::new();
        state.refusals.retain(|(id, reason)| {
            let mine = *id == operation;
            if mine {
                taken.push(*reason);
            }
            !mine
        });
        taken
    }
    /// Every remembered refusal, oldest first (at most [`REFUSAL_LOG`]).
    pub fn refusal_log(&self) -> Vec<(OperationId, TicketRefusal)> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.refusals.iter().copied().collect()
    }
    fn check(
        state: &mut GuardState,
        event: &KeyUseEvent,
    ) -> Result<PluginAuditRecord, TicketRefusal> {
        let ticket = event.plugin().ok_or(TicketRefusal::NoTicket)?;
        let armed = state.armed.as_mut().ok_or(TicketRefusal::NoApproval)?;
        let approval = &armed.approval;
        if ticket.max_uses != MAX_USES {
            return Err(TicketRefusal::Uses);
        }
        if Instant::now() >= approval.ttl_deadline {
            return Err(TicketRefusal::Expired);
        }
        if event.operation_id != approval.operation_id {
            return Err(TicketRefusal::OperationId);
        }
        if ticket.identity != approval.identity {
            return Err(TicketRefusal::Identity);
        }
        if ticket.operation != approval.operation {
            return Err(TicketRefusal::Operation);
        }
        if ticket.caller != approval.caller {
            return Err(TicketRefusal::Caller);
        }
        if event.key_id != ticket.key
            || ticket.key != approval.key
            || ticket.handle != approval.handle
        {
            return Err(TicketRefusal::Key);
        }
        if event.action != ticket.content.action() {
            return Err(TicketRefusal::Action);
        }
        if approval
            .uses
            .iter()
            .any(|u| u.certificate_sha256 != ticket.certificate_sha256)
        {
            return Err(TicketRefusal::CertificateChanged);
        }
        let matches = |u: &ApprovedUse| {
            u.kind == ticket.kind
                && u.content == ticket.content
                && u.options_sha256 == ticket.options_sha256
        };
        let first_open = armed
            .approval
            .uses
            .iter()
            .zip(&armed.spent)
            .find(|(_, spent)| !**spent)
            .map(|(u, _)| *u);
        let position = armed
            .approval
            .uses
            .iter()
            .zip(&armed.spent)
            .position(|(u, spent)| !*spent && matches(u));
        match position {
            Some(i) => {
                armed.spent[i] = true;
                Ok(armed.approval.audit_record(ticket))
            }
            None => {
                if armed
                    .approval
                    .uses
                    .iter()
                    .zip(&armed.spent)
                    .any(|(u, spent)| *spent && matches(u))
                {
                    return Err(TicketRefusal::AlreadyUsed);
                }
                match first_open {
                    None => Err(TicketRefusal::AlreadyUsed),
                    Some(u) if u.kind != ticket.kind => Err(TicketRefusal::Kind),
                    Some(u) if u.content != ticket.content => Err(TicketRefusal::Content),
                    Some(_) => Err(TicketRefusal::Options),
                }
            }
        }
    }
}
impl KeyUseGuard for PluginConsentGuard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match Self::check(&mut state, event) {
            Ok(record) => {
                self.applications.fetch_add(1, Ordering::SeqCst);
                trace_authorised(event, &record);
                Ok(KeyUseReceipt::new(event.clone()))
            }
            Err(reason) => {
                tracing::warn!(
                    target: "oncl::plugin_audit",
                    operation = event.operation_id.get(),
                    reason = ?reason,
                    subcode = PluginRefusalCode::from(reason).id(),
                    ticket_digest = event.plugin().map(|t| hex(&t.digest())).as_deref(),
                    "a plugin key use was refused before the key"
                );
                if state.refusals.len() == REFUSAL_LOG {
                    state.refusals.pop_front();
                }
                state.refusals.push_back((event.operation_id, reason));
                Err(OperationError::PermissionDenied)
            }
        }
    }
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        tracing::info!(
            operation = receipt.event().operation_id.get(),
            applied = ?outcome.applied,
            succeeded = outcome.succeeded,
            "a private key was applied for a plugin"
        );
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The trace record of an authorised plugin key use: the same facts the durable journal
/// keeps, none of them secret (the nonce only as a hash).
pub(crate) fn trace_authorised(event: &KeyUseEvent, record: &PluginAuditRecord) {
    tracing::info!(
        target: "oncl::plugin_audit",
        operation = event.operation_id.get(),
        plugin = %record.plugin_id,
        package_kind = record.package_kind,
        package_sha256 = %hex(&record.package_sha256),
        version = %record.version,
        plugin_operation = %record.operation,
        ticket_digest = %hex(&record.ticket_digest),
        approval_nonce_sha256 = record.approval_nonce_sha256.map(|h| hex(&h)).as_deref(),
        content_sha256 = %hex(&record.content_sha256),
        content_len = record.content_len,
        options_sha256 = %hex(&record.options_sha256),
        caller = record.caller.as_str(),
        declared = record.declared,
        "a plugin key use was authorised"
    );
}

/// The declared operation a call runs, when its manifest declares one of that name.
#[derive(Clone, Copy)]
pub(super) struct Declared<'a> {
    pub identity: &'a PluginIdentity,
    pub operation: &'a Operation,
}

impl<'a, 'b> Backend<'a, 'b> {
    /// The one bound key of the call. A declared operation binds at most one key (checked
    /// before the module runs); any other handle, a released one included, is refused with
    /// the same error as a handle that was never bound.
    pub(super) fn bound_key(
        &self,
        handle: u32,
    ) -> Result<&'b PluginKeyBinding<'b>, OperationError> {
        let keys: &'b [PluginKeyBinding<'b>] = self.bindings.keys;
        match (self.declared, keys) {
            (Some(_), [only]) if only.handle == handle => Ok(only),
            (Some(_), _) => Err(OperationError::PermissionDenied),
            (None, keys) => keys
                .iter()
                .find(|key| key.handle == handle)
                .ok_or(OperationError::PermissionDenied),
        }
    }

    /// For a declared operation: checks the key use fits a declared one and parks the ticket
    /// for the use that follows. Nothing is opened or applied here. For an operation
    /// without declarations, does nothing.
    ///
    /// `content` and `profile` MUST come from the same decoded arguments that are passed to
    /// the engine.
    pub(super) fn arm_ticket(
        &self,
        key: &PluginKeyBinding<'_>,
        kind: KeyKind,
        content: ContentBinding,
        profile: Option<Profile>,
    ) -> Result<(), OperationError> {
        let Some(declared) = self.declared else {
            return Ok(());
        };
        let fits = declared
            .operation
            .uses()
            .keys()
            .iter()
            .any(|u| u.kind() == kind && matches!(u.content(), Content::Bound(_)));
        let options = profile
            .and_then(|p| p.encode(kind, None))
            .map(|bytes| -> [u8; 32] { Sha256::digest(bytes).into() });
        let (true, Some(options_sha256)) = (fits, options) else {
            return Err(OperationError::PermissionDenied);
        };
        let ticket = PluginUse {
            identity: declared.identity.clone(),
            operation: self.call.operation.to_owned(),
            caller: self.bindings.caller.clone(),
            kind,
            handle: key.handle,
            key: key.key.selector().key_id(),
            content,
            options_sha256,
            // Filled in at the signing point from the key lease.
            certificate_sha256: [0; 32],
            max_uses: MAX_USES,
        };
        *self
            .ctx
            .plugin_ticket
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(ticket);
        Ok(())
    }

    /// Drops a ticket nobody took (the import failed before the key was used).
    pub(super) fn clear_ticket(&self) {
        *self
            .ctx
            .plugin_ticket
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// `keys_sign_cms`: the profile of the call. Core fixes everything else in this import.
pub(super) fn cms_profile(args: &abi::SignCmsExArgs) -> Profile {
    Profile::Cms(CmsProfile {
        attached: args.encapsulate,
        timestamp: if args.timestamp.is_some() {
            oncl_plugin::operations::Timestamp::Basics
        } else {
            oncl_plugin::operations::Timestamp::None
        },
    })
}

/// `keys_sign_cms_ex`: the profile of the actual call, with `cosign` already forced to
/// `Never`. `None` for anything a profile cannot say (a co-signed CMS, extra attributes or
/// certificates, a custom TSA, an eContentType, a digest choice, another signingTime).
pub(super) fn cms_ex_profile(args: &abi::SignCmsExArgs) -> Option<Profile> {
    use oncl_plugin::operations as ops;
    let abi::SignCmsExArgs {
        handle: _,
        content,
        encapsulate,
        cosign,
        econtent_type,
        digest,
        attrs,
        certificates,
        timestamp,
        output,
    } = args;
    let abi::SignedAttrs {
        content_type,
        message_digest,
        signing_certificate_v2,
        signing_time,
        extra,
    } = attrs;
    if !matches!(cosign, abi::CoSign::Never)
        || econtent_type.is_some()
        || digest.is_some()
        || !extra.is_empty()
    {
        return None;
    }
    Some(Profile::CmsEx(CmsExProfile {
        encapsulate: *encapsulate,
        cosign: ops::CoSign::Never,
        content_form: match content {
            abi::CmsContent::Data(_) => ops::ContentForm::Data,
            abi::CmsContent::Digest(_) => ops::ContentForm::Digest,
        },
        timestamp: match timestamp {
            None => ops::Timestamp::None,
            Some(abi::TsaChoice::Basics) => ops::Timestamp::Basics,
            Some(abi::TsaChoice::Kalkan) => ops::Timestamp::Kalkan,
            Some(abi::TsaChoice::Custom(_)) => return None,
        },
        certificates: match certificates {
            abi::CmsCerts::Signer => ops::Certificates::Signer,
            abi::CmsCerts::Chain => ops::Certificates::Chain,
            abi::CmsCerts::Extra(_) => return None,
        },
        output: *output,
        content_type: *content_type,
        message_digest: *message_digest,
        signing_certificate_v2: *signing_certificate_v2,
        signing_time: match signing_time {
            None => ops::SigningTime::None,
            Some(abi::SigningTime {
                at: abi::TimeSource::Now,
                form: abi::TimeForm::Auto,
            }) => ops::SigningTime::Now,
            Some(_) => return None,
        },
    }))
}

fn xpath(text: &Option<String>) -> Option<Source> {
    text.clone().map(Source::Fixed)
}

pub(super) fn xml_profile(args: &abi::SignXmlArgs) -> Profile {
    let abi::SignXmlArgs {
        handle: _,
        xml: _,
        element,
        parent,
    } = args;
    Profile::Xml(XmlProfile {
        element: xpath(element),
        parent: xpath(parent),
    })
}

/// `keys_sign_xml_ex`; `None` for `transforms`, `signature_id` or a signing-time object,
/// which no profile can say.
pub(super) fn xml_ex_profile(args: &abi::SignXmlExArgs) -> Option<Profile> {
    let abi::SignXmlExArgs {
        handle: _,
        xml: _,
        element,
        parent,
        namespaces,
        other_prefix_uri,
        placement,
        signature_method,
        digest_method,
        signed_info_c14n,
        transforms,
        signature_id,
        signing_time_object,
        strip_whitespace,
        base64_line_breaks,
        output,
    } = args;
    if transforms.is_some() || signature_id.is_some() || signing_time_object.is_some() {
        return None;
    }
    Some(Profile::XmlEx(XmlExProfile {
        element: xpath(element),
        parent: xpath(parent),
        placement: *placement,
        namespaces: namespaces
            .iter()
            .map(|n| Namespace {
                prefix: n.prefix.clone(),
                uri: n.uri.clone(),
            })
            .collect(),
        other_prefix_uri: other_prefix_uri.clone(),
        signature_method: signature_method.clone(),
        digest_method: digest_method.clone(),
        c14n: *signed_info_c14n,
        strip_whitespace: *strip_whitespace,
        base64_line_breaks: *base64_line_breaks,
        output: match output {
            abi::XmlOutput::AsIs => XmlOutputProfile::AsIs,
            abi::XmlOutput::Serialize {
                declaration,
                standalone_no,
                trim,
            } => XmlOutputProfile::Serialize {
                declaration: *declaration,
                standalone_no: *standalone_no,
                trim: *trim,
            },
        },
    }))
}

/// `keys_sign_xades`; `None` for a custom TSA or a chain, which no profile can say.
pub(super) fn xades_profile(args: &abi::XadesArgs) -> Option<Profile> {
    let abi::XadesArgs {
        handle: _,
        xml: _,
        level,
        tsa,
        chain,
        signature_method,
        digest_method,
    } = args;
    if !chain.is_empty() {
        return None;
    }
    Some(Profile::Xades(XadesProfile {
        level: *level,
        tsa: match tsa {
            abi::TsaChoice::Basics => oncl_plugin::operations::XadesTsa::Basics,
            abi::TsaChoice::Kalkan => oncl_plugin::operations::XadesTsa::Kalkan,
            abi::TsaChoice::Custom(_) => return None,
        },
        signature_method: signature_method.clone(),
        digest_method: digest_method.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pdk::abi;
    use oncl_plugin::operations::Timestamp;

    fn enc(profile: Option<Profile>, kind: KeyKind) -> Option<Vec<u8>> {
        profile.and_then(|p| p.encode(kind, None))
    }
    /// The encodings of one field's values (the base value included) must be pairwise
    /// different; a value no profile can say must be refused (`None`).
    fn field(kind: KeyKind, name: &str, values: Vec<(&str, Option<Profile>)>) {
        let mut seen: Vec<(&str, Vec<u8>)> = Vec::new();
        for (label, profile) in values {
            if let Some(bytes) = enc(profile, kind) {
                for (other, prior) in &seen {
                    assert_ne!(*prior, bytes, "{name}: {label} encodes like {other}");
                }
                seen.push((label, bytes));
            }
        }
    }
    fn refused(kind: KeyKind, name: &str, profile: Option<Profile>) {
        assert!(enc(profile, kind).is_none(), "{name} must be refused");
    }

    fn cms_ex() -> abi::SignCmsExArgs {
        abi::SignCmsExArgs {
            handle: 1,
            content: abi::CmsContent::Data(vec![1].into()),
            encapsulate: false,
            cosign: abi::CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: abi::SignedAttrs {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: true,
                signing_time: Some(abi::SigningTime {
                    at: abi::TimeSource::Now,
                    form: abi::TimeForm::Auto,
                }),
                extra: Vec::new(),
            },
            certificates: abi::CmsCerts::Signer,
            timestamp: None,
            output: abi::CmsOutput::Der,
        }
    }
    fn custom_tsa() -> abi::TsaSpec {
        abi::TsaSpec {
            url: abi::PkiUrl::Default,
            method: abi::PkiMethod::Get,
            hash: abi::HashAlg::Sha256,
            policy: None,
            nonce: abi::Nonce::None,
            cert_req: true,
            retries: 0,
            timeout_ms: 1000,
            check_skew_ms: None,
            require_tsa_eku: false,
        }
    }

    #[test]
    fn every_cms_ex_field_changes_the_options_or_is_refused() {
        let k = KeyKind::CmsEx;
        let p = |f: &dyn Fn(&mut abi::SignCmsExArgs)| {
            let mut a = cms_ex();
            f(&mut a);
            cms_ex_profile(&a)
        };
        field(
            k,
            "encapsulate",
            vec![("off", p(&|_| {})), ("on", p(&|a| a.encapsulate = true))],
        );
        field(
            k,
            "content form",
            vec![
                ("data", p(&|_| {})),
                (
                    "digest",
                    p(&|a| a.content = abi::CmsContent::Digest(vec![1].into())),
                ),
            ],
        );
        refused(
            k,
            "cosign into",
            p(&|a| a.cosign = abi::CoSign::Into(vec![1].into())),
        );
        refused(k, "cosign auto", p(&|a| a.cosign = abi::CoSign::Auto));
        refused(
            k,
            "econtent_type",
            p(&|a| a.econtent_type = Some("1.2.3".into())),
        );
        refused(k, "digest", p(&|a| a.digest = Some(abi::HashAlg::Sha256)));
        refused(
            k,
            "extra attribute",
            p(&|a| {
                a.attrs.extra.push(abi::RawAttribute {
                    oid: "1.2.3".into(),
                    values: Vec::new(),
                })
            }),
        );
        field(
            k,
            "content_type",
            vec![
                ("on", p(&|_| {})),
                ("off", p(&|a| a.attrs.content_type = false)),
            ],
        );
        field(
            k,
            "message_digest",
            vec![
                ("on", p(&|_| {})),
                ("off", p(&|a| a.attrs.message_digest = false)),
            ],
        );
        field(
            k,
            "signing_certificate_v2",
            vec![
                ("on", p(&|_| {})),
                ("off", p(&|a| a.attrs.signing_certificate_v2 = false)),
            ],
        );
        field(
            k,
            "signing_time",
            vec![
                ("now", p(&|_| {})),
                ("none", p(&|a| a.attrs.signing_time = None)),
            ],
        );
        refused(
            k,
            "signing_time unix",
            p(&|a| {
                a.attrs.signing_time = Some(abi::SigningTime {
                    at: abi::TimeSource::UnixMs(0),
                    form: abi::TimeForm::Auto,
                })
            }),
        );
        refused(
            k,
            "signing_time form",
            p(&|a| {
                a.attrs.signing_time = Some(abi::SigningTime {
                    at: abi::TimeSource::Now,
                    form: abi::TimeForm::Generalized,
                })
            }),
        );
        field(
            k,
            "certificates",
            vec![
                ("signer", p(&|_| {})),
                ("chain", p(&|a| a.certificates = abi::CmsCerts::Chain)),
                (
                    "extra",
                    p(&|a| a.certificates = abi::CmsCerts::Extra(Vec::new())),
                ),
            ],
        );
        refused(
            k,
            "extra certs",
            p(&|a| a.certificates = abi::CmsCerts::Extra(Vec::new())),
        );
        field(
            k,
            "timestamp",
            vec![
                ("none", p(&|_| {})),
                ("basics", p(&|a| a.timestamp = Some(abi::TsaChoice::Basics))),
                ("kalkan", p(&|a| a.timestamp = Some(abi::TsaChoice::Kalkan))),
                (
                    "custom",
                    p(&|a| a.timestamp = Some(abi::TsaChoice::Custom(custom_tsa()))),
                ),
            ],
        );
        refused(
            k,
            "custom tsa",
            p(&|a| a.timestamp = Some(abi::TsaChoice::Custom(custom_tsa()))),
        );
        field(
            k,
            "output",
            vec![
                ("der", p(&|_| {})),
                ("base64", p(&|a| a.output = abi::CmsOutput::Base64)),
                ("pem", p(&|a| a.output = abi::CmsOutput::Pem)),
            ],
        );
    }

    #[test]
    fn every_plain_cms_field_changes_the_options() {
        let k = KeyKind::Cms;
        let p = |attached: bool, timestamp: bool| {
            let mut a = cms_ex();
            a.encapsulate = attached;
            a.timestamp = timestamp.then_some(abi::TsaChoice::Basics);
            Some(cms_profile(&a))
        };
        field(
            k,
            "attached/timestamp",
            vec![
                ("detached", p(false, false)),
                ("attached", p(true, false)),
                ("stamped", p(false, true)),
                ("both", p(true, true)),
            ],
        );
        // The timestamp of the plain import is the basics TSA.
        assert!(matches!(
            cms_profile(&{
                let mut a = cms_ex();
                a.timestamp = Some(abi::TsaChoice::Basics);
                a
            }),
            Profile::Cms(CmsProfile {
                timestamp: Timestamp::Basics,
                ..
            })
        ));
    }

    fn xml() -> abi::SignXmlArgs {
        abi::SignXmlArgs {
            handle: 1,
            xml: vec![b'<', b'a', b'/', b'>'].into(),
            element: None,
            parent: None,
        }
    }
    #[test]
    fn every_xml_field_changes_the_options() {
        let k = KeyKind::Xml;
        let p = |f: &dyn Fn(&mut abi::SignXmlArgs)| {
            let mut a = xml();
            f(&mut a);
            Some(xml_profile(&a))
        };
        field(
            k,
            "element",
            vec![
                ("none", p(&|_| {})),
                ("a", p(&|a| a.element = Some("/a".into()))),
                ("b", p(&|a| a.element = Some("/b".into()))),
            ],
        );
        field(
            k,
            "parent",
            vec![
                ("none", p(&|_| {})),
                ("a", p(&|a| a.parent = Some("/a".into()))),
                ("b", p(&|a| a.parent = Some("/b".into()))),
            ],
        );
        // element and parent are different fields.
        field(
            k,
            "element vs parent",
            vec![
                ("element", p(&|a| a.element = Some("/a".into()))),
                ("parent", p(&|a| a.parent = Some("/a".into()))),
            ],
        );
    }

    fn xml_ex() -> abi::SignXmlExArgs {
        abi::SignXmlExArgs {
            handle: 1,
            xml: vec![b'<', b'a', b'/', b'>'].into(),
            element: None,
            parent: None,
            namespaces: Vec::new(),
            other_prefix_uri: None,
            placement: abi::Placement::DocumentElement,
            signature_method: None,
            digest_method: None,
            signed_info_c14n: None,
            transforms: None,
            signature_id: None,
            signing_time_object: None,
            strip_whitespace: false,
            base64_line_breaks: None,
            output: abi::XmlOutput::AsIs,
        }
    }
    #[test]
    fn every_xml_ex_field_changes_the_options_or_is_refused() {
        let k = KeyKind::XmlEx;
        let p = |f: &dyn Fn(&mut abi::SignXmlExArgs)| {
            let mut a = xml_ex();
            f(&mut a);
            xml_ex_profile(&a)
        };
        let ns = |prefix: &str, uri: &str| abi::NsBinding {
            prefix: prefix.into(),
            uri: uri.into(),
        };
        field(
            k,
            "element/parent",
            vec![
                ("none", p(&|_| {})),
                ("element", p(&|a| a.element = Some("/a".into()))),
                ("parent", p(&|a| a.parent = Some("/a".into()))),
            ],
        );
        field(
            k,
            "namespaces",
            vec![
                ("none", p(&|_| {})),
                ("p=u", p(&|a| a.namespaces = vec![ns("p", "u")])),
                ("p=v", p(&|a| a.namespaces = vec![ns("p", "v")])),
                ("q=u", p(&|a| a.namespaces = vec![ns("q", "u")])),
                (
                    "two",
                    p(&|a| a.namespaces = vec![ns("p", "u"), ns("q", "u")]),
                ),
            ],
        );
        field(
            k,
            "other_prefix_uri",
            vec![
                ("none", p(&|_| {})),
                ("u", p(&|a| a.other_prefix_uri = Some("u".into()))),
                ("v", p(&|a| a.other_prefix_uri = Some("v".into()))),
            ],
        );
        field(
            k,
            "placement",
            vec![
                ("document", p(&|_| {})),
                (
                    "first",
                    p(&|a| a.placement = abi::Placement::FirstChildOfDocument),
                ),
                ("parent", p(&|a| a.placement = abi::Placement::Parent)),
            ],
        );
        field(
            k,
            "signature_method",
            vec![
                ("none", p(&|_| {})),
                ("m", p(&|a| a.signature_method = Some("m".into()))),
            ],
        );
        field(
            k,
            "digest_method",
            vec![
                ("none", p(&|_| {})),
                ("m", p(&|a| a.digest_method = Some("m".into()))),
            ],
        );
        // Method and digest are different fields.
        field(
            k,
            "signature vs digest",
            vec![
                ("signature", p(&|a| a.signature_method = Some("m".into()))),
                ("digest", p(&|a| a.digest_method = Some("m".into()))),
            ],
        );
        field(
            k,
            "c14n",
            vec![
                ("none", p(&|_| {})),
                (
                    "inc",
                    p(&|a| a.signed_info_c14n = Some(abi::C14n::Inclusive)),
                ),
                (
                    "incc",
                    p(&|a| a.signed_info_c14n = Some(abi::C14n::InclusiveWithComments)),
                ),
                (
                    "exc",
                    p(&|a| a.signed_info_c14n = Some(abi::C14n::Exclusive)),
                ),
                (
                    "excc",
                    p(&|a| a.signed_info_c14n = Some(abi::C14n::ExclusiveWithComments)),
                ),
            ],
        );
        refused(k, "transforms", p(&|a| a.transforms = Some(Vec::new())));
        refused(k, "signature_id", p(&|a| a.signature_id = Some("s".into())));
        refused(
            k,
            "signing_time_object",
            p(&|a| {
                a.signing_time_object = Some(abi::SigningTimeObject {
                    property_id: "p".into(),
                    target_ref: false,
                    text: "t".into(),
                })
            }),
        );
        field(
            k,
            "strip_whitespace",
            vec![
                ("off", p(&|_| {})),
                ("on", p(&|a| a.strip_whitespace = true)),
            ],
        );
        field(
            k,
            "base64_line_breaks",
            vec![
                ("none", p(&|_| {})),
                ("on", p(&|a| a.base64_line_breaks = Some(true))),
                ("off", p(&|a| a.base64_line_breaks = Some(false))),
            ],
        );
        let ser = |declaration, standalone_no, trim| abi::XmlOutput::Serialize {
            declaration,
            standalone_no,
            trim,
        };
        field(
            k,
            "output",
            vec![
                ("as_is", p(&|_| {})),
                ("none", p(&|a| a.output = ser(false, false, false))),
                ("declaration", p(&|a| a.output = ser(true, false, false))),
                ("standalone", p(&|a| a.output = ser(false, true, false))),
                ("trim", p(&|a| a.output = ser(false, false, true))),
            ],
        );
    }

    #[test]
    fn every_xades_field_changes_the_options_or_is_refused() {
        let k = KeyKind::Xades;
        let base = || abi::XadesArgs {
            handle: 1,
            xml: vec![b'<', b'a', b'/', b'>'].into(),
            level: abi::XadesLevel::B,
            tsa: abi::TsaChoice::Basics,
            chain: Vec::new(),
            signature_method: None,
            digest_method: None,
        };
        let p = |f: &dyn Fn(&mut abi::XadesArgs)| {
            let mut a = base();
            f(&mut a);
            xades_profile(&a)
        };
        field(
            k,
            "level",
            vec![
                ("b", p(&|_| {})),
                ("t", p(&|a| a.level = abi::XadesLevel::T)),
                ("lt", p(&|a| a.level = abi::XadesLevel::Lt)),
            ],
        );
        field(
            k,
            "tsa",
            vec![
                ("basics", p(&|_| {})),
                ("kalkan", p(&|a| a.tsa = abi::TsaChoice::Kalkan)),
            ],
        );
        refused(
            k,
            "custom tsa",
            p(&|a| a.tsa = abi::TsaChoice::Custom(custom_tsa())),
        );
        refused(k, "chain", p(&|a| a.chain = vec![vec![1].into()]));
        field(
            k,
            "signature_method",
            vec![
                ("none", p(&|_| {})),
                ("m", p(&|a| a.signature_method = Some("m".into()))),
            ],
        );
        field(
            k,
            "digest_method",
            vec![
                ("none", p(&|_| {})),
                ("m", p(&|a| a.digest_method = Some("m".into()))),
            ],
        );
        field(
            k,
            "signature vs digest",
            vec![
                ("signature", p(&|a| a.signature_method = Some("m".into()))),
                ("digest", p(&|a| a.digest_method = Some("m".into()))),
            ],
        );
    }

    // The ticket of one use is moved into the event by `sign_digest`: a second use in the same
    // operation finds none, whatever the plugin backend does between imports.
    #[test]
    fn one_ticket_is_taken_by_the_first_key_use() {
        use crate::keys::{KeyRequest, KeySelector, KeySources};
        use crate::{Engine, EngineServices, ExecutionGrant, OperationPolicy};
        use oncl_pki::{
            digest::DigestValue,
            resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
        };
        struct Control;
        impl OperationControl for Control {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                Ok(())
            }
        }
        struct Record(Mutex<Vec<bool>>);
        impl KeyUseGuard for Record {
            fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
                self.0.lock().unwrap().push(event.plugin().is_some());
                Ok(KeyUseReceipt::new(event.clone()))
            }
            fn finish(&self, _: KeyUseReceipt, _: KeyUseOutcome) -> Result<(), OperationError> {
                Ok(())
            }
        }
        let fixture = oncl_testkit::synthetic("user-rsa-sign");
        let selector = KeySelector::inline(oncl_testkit::read(fixture.path), None);
        let guard = Arc::new(Record(Mutex::new(Vec::new())));
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_keys(Arc::new(KeySources::new()), guard.clone()),
        )
        .unwrap();
        let mut policy = OperationPolicy::ncalayer_compatibility();
        policy.allow_prehashed = true;
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Sign, Action::SignDigest])
                    .with_keys([selector.key_id()]),
                policy,
                Arc::new(Control),
            )
            .unwrap();
        let ticket = PluginUse {
            identity: PluginIdentity {
                id: "t".into(),
                package: PackageHash::File([0; 32]),
                version: "1".into(),
            },
            operation: "op".into(),
            caller: CallerContext::LocalOperator("o".into()),
            kind: KeyKind::Raw,
            handle: 1,
            key: selector.key_id(),
            content: ContentBinding::bytes(b"x"),
            options_sha256: [0; 32],
            certificate_sha256: [0; 32],
            max_uses: MAX_USES,
        };
        *ctx.plugin_ticket.lock().unwrap() = Some(ticket);
        let request = KeyRequest::new(&selector, Some(&fixture.password));
        let mut signer = engine.signer(&request, &mut ctx).unwrap();
        let alg = signer.algorithm().hash_alg();
        let mut hash = oncl_pki::digest::HashState::new(alg);
        hash.update(b"x");
        let digest: DigestValue = hash.finish();
        signer.sign_digest(&digest).unwrap();
        signer.sign_digest(&digest).unwrap();
        assert_eq!(*guard.0.lock().unwrap(), [true, false]);
    }

    #[test]
    fn guard_refuses_an_action_that_does_not_fit_the_content() {
        use crate::keys::{KeyRequest, KeySelector, KeySources};
        use crate::{Engine, EngineServices, ExecutionGrant, OperationPolicy};
        use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
        struct Control;
        impl OperationControl for Control {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                Ok(())
            }
        }
        let fixture = oncl_testkit::synthetic("user-rsa-sign");
        let selector = KeySelector::inline(oncl_testkit::read(fixture.path), None);
        let guard = Arc::new(PluginConsentGuard::new());
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_keys(Arc::new(KeySources::new()), guard.clone()),
        )
        .unwrap();
        let mut policy = OperationPolicy::ncalayer_compatibility();
        policy.allow_prehashed = true;
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Sign, Action::SignDigest])
                    .with_keys([selector.key_id()]),
                policy,
                Arc::new(Control),
            )
            .unwrap();
        let identity = PluginIdentity {
            id: "t".into(),
            package: PackageHash::File([0; 32]),
            version: "1".into(),
        };
        // A document-bytes ticket (a `Sign` use) reaches the key as `SignDigest`.
        let content = ContentBinding::bytes(b"x");
        let ticket = PluginUse {
            identity: identity.clone(),
            operation: "op".into(),
            caller: CallerContext::LocalOperator("o".into()),
            kind: KeyKind::Raw,
            handle: 1,
            key: selector.key_id(),
            content,
            options_sha256: [0; 32],
            certificate_sha256: [0; 32],
            max_uses: MAX_USES,
        };
        guard
            .grant(PluginApproval::new(
                identity,
                "op",
                CallerContext::LocalOperator("o".into()),
                ctx.id(),
                selector.key_id(),
                1,
                vec![ApprovedUse {
                    kind: KeyKind::Raw,
                    content,
                    options_sha256: [0; 32],
                    certificate_sha256: [0; 32],
                }],
                Instant::now() + std::time::Duration::from_secs(60),
                [1; 16],
            ))
            .unwrap();
        *ctx.plugin_ticket.lock().unwrap() = Some(ticket);
        let id = ctx.id();
        let request = KeyRequest::new(&selector, Some(&fixture.password));
        let mut signer = engine.signer(&request, &mut ctx).unwrap();
        let alg = signer.algorithm().hash_alg();
        let mut hash = oncl_pki::digest::HashState::new(alg);
        hash.update(b"x");
        assert!(signer.sign_digest(&hash.finish()).is_err());
        assert_eq!(guard.refusals(id), [TicketRefusal::Action]);
    }

    #[test]
    fn refusal_log_is_bounded_and_per_operation() {
        let guard = PluginConsentGuard::new();
        let mut state = guard.state.lock().unwrap();
        for n in 0..REFUSAL_LOG as u64 + 5 {
            if state.refusals.len() == REFUSAL_LOG {
                state.refusals.pop_front();
            }
            state
                .refusals
                .push_back((OperationId(n % 2), TicketRefusal::NoApproval));
        }
        drop(state);
        assert_eq!(guard.refusal_log().len(), REFUSAL_LOG);
        let mine = guard.refusals(OperationId(1));
        assert!(!mine.is_empty() && mine.len() < REFUSAL_LOG);
        assert_eq!(guard.take_refusals(OperationId(1)), mine);
        assert!(guard.refusals(OperationId(1)).is_empty());
        assert!(!guard.refusals(OperationId(0)).is_empty());
    }
}
