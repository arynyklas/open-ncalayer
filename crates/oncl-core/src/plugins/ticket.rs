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
//! Issuing an approval (from the user's consent, the declared profile and the frozen input)
//! is the next stage; here an approval is the data type the guard checks.
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
    collections::HashSet,
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
    max_uses: u8,
}
impl PluginUse {
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
        h.update([self.max_uses]);
        h.finalize().into()
    }
}

/// One key use the user approved: what is signed and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedUse {
    pub kind: KeyKind,
    pub content: ContentBinding,
    pub options_sha256: [u8; 32],
}

/// The approval a [`PluginConsentGuard`] checks tickets against: one plugin, operation,
/// caller, invocation and key, for the uses listed, until `ttl_deadline`. It is neither
/// `Clone` nor `Deserialize`, and the guard accepts a nonce only once.
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
    /// The host builds this from the consent it collected; nothing here can be derived by a
    /// plugin.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
}

/// Why [`PluginConsentGuard::grant`] did not take an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    last_refusal: Option<TicketRefusal>,
}

/// The key-use guard of a plugin engine: it refuses every key use unless the event's ticket
/// matches an unspent use of the granted [`PluginApproval`]. It also refuses an event
/// without a ticket, so a document key use through it is refused (give documents their own
/// engine and guard).
#[derive(Default)]
pub struct PluginConsentGuard {
    state: Mutex<GuardState>,
    applications: AtomicUsize,
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
    /// The reason of the most recent refusal.
    pub fn last_refusal(&self) -> Option<TicketRefusal> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_refusal
    }
    fn check(state: &mut GuardState, event: &KeyUseEvent) -> Result<(), TicketRefusal> {
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
                Ok(())
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
            Ok(()) => {
                state.last_refusal = None;
                self.applications.fetch_add(1, Ordering::SeqCst);
                Ok(KeyUseReceipt::new(event.clone()))
            }
            Err(reason) => {
                state.last_refusal = Some(reason);
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
