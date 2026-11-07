//! Operation-scoped key sources and per-use host authority. Strict/offline key
//! application also requires current shared validation before the host use guard.
use crate::{Action, Engine, ExecutionGrant, OperationContext, OperationError, OperationId};
pub use oncl_pki::key::AppliedState;
use oncl_pki::{
    cert::Certificate,
    digest::{DigestValue, HashState},
    key::{DigestSigner, HashAlg, KeyError, SigAlg, leaf_signature_algorithm},
    pkcs12::KeyEntry,
    resource::ResourceReservation,
    validation::ValidationPolicy,
};
#[cfg(feature = "tokens")]
use oncl_token::{
    TokenKind, Tokens,
    execution::{TokenDeviceId, TokenExecution, TokenGateRegistry},
};
use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(Arc<str>);
impl KeyId {
    pub fn new(host_name: impl Into<String>) -> Result<Self, OperationError> {
        let name = host_name.into();
        if name.is_empty() || name.contains('\0') {
            return Err(OperationError::InvalidKeySource);
        }
        Ok(Self(Arc::from(format!("named:{name}"))))
    }
    /// The canonical text, for hashing into a ticket digest.
    #[cfg(feature = "plugins")]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone)]
enum Source {
    File(PathBuf, Option<String>),
    Inline(Arc<Zeroizing<Vec<u8>>>, Option<String>),
    Named,
    #[cfg(feature = "tokens")]
    Token(TokenDeviceId, TokenKind, String),
}
/// Clone shares encrypted inline bytes, never deep-copies private container data.
#[derive(Clone)]
pub struct KeySelector {
    id: KeyId,
    source: Source,
}
impl fmt::Debug for KeySelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySelector")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
fn source_id(domain: &[u8], fields: &[&[u8]]) -> KeyId {
    let mut hash = HashState::new(HashAlg::Sha256);
    hash.update(domain);
    for field in fields {
        hash.update(&(field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    let value = hash.finish();
    let mut text = String::with_capacity(71);
    use fmt::Write;
    text.push_str("source:");
    for byte in value.as_bytes() {
        let _ = write!(text, "{byte:02x}");
    }
    KeyId(Arc::from(text))
}
impl KeySelector {
    pub fn file(path: impl Into<PathBuf>, alias: Option<String>) -> Result<Self, OperationError> {
        let path =
            std::fs::canonicalize(path.into()).map_err(|e| OperationError::Processing(e.into()))?;
        let id = source_id(
            b"file",
            &[
                path.as_os_str().as_encoded_bytes(),
                &[u8::from(alias.is_some())],
                alias.as_deref().unwrap_or("").as_bytes(),
            ],
        );
        Ok(Self {
            id,
            source: Source::File(path, alias),
        })
    }
    pub fn inline(container: Vec<u8>, alias: Option<String>) -> Self {
        let id = source_id(
            b"inline",
            &[
                &container,
                &[u8::from(alias.is_some())],
                alias.as_deref().unwrap_or("").as_bytes(),
            ],
        );
        Self {
            id,
            source: Source::Inline(Arc::new(Zeroizing::new(container)), alias),
        }
    }
    /// Source classification only: no paths, PINs or container bytes escape.
    /// Hosts must still authorize the exact selector identity before opening.
    pub fn is_inline(&self) -> bool {
        matches!(self.source, Source::Inline(..))
    }
    pub fn named(id: KeyId) -> Self {
        Self {
            id,
            source: Source::Named,
        }
    }
    #[cfg(feature = "tokens")]
    pub fn token(device: TokenDeviceId, kind: TokenKind, alias: String) -> Self {
        let id = source_id(
            b"token",
            &[
                device.reader().as_bytes(),
                kind.storage_name().as_bytes(),
                alias.as_bytes(),
            ],
        );
        Self {
            id,
            source: Source::Token(device, kind, alias),
        }
    }
    pub fn key_id(&self) -> KeyId {
        self.id.clone()
    }
}
/// Secrets are borrowed at intake. No Debug, serialization or secret clone.
pub struct KeyRequest<'a> {
    selector: &'a KeySelector,
    secret: Option<&'a str>,
}
impl<'a> KeyRequest<'a> {
    pub fn new(selector: &'a KeySelector, secret: Option<&'a str>) -> Self {
        Self { selector, secret }
    }
    pub fn selector(&self) -> &KeySelector {
        self.selector
    }
    pub fn secret(&self) -> Option<&str> {
        self.secret
    }
}
pub trait KeyProvider: Send + Sync {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError>;
}
/// Holds host source configuration, not unlocked desktop entries or PINs.
#[derive(Default)]
pub struct KeySources {
    named: HashMap<KeyId, KeySelector>,
    #[cfg(feature = "tokens")]
    tokens: Option<(Arc<Tokens>, Arc<TokenGateRegistry>)>,
}
impl KeySources {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_named(mut self, id: KeyId, selector: KeySelector) -> Result<Self, OperationError> {
        if !id.0.starts_with("named:")
            || matches!(selector.source, Source::Named)
            || self.named.contains_key(&id)
        {
            return Err(OperationError::InvalidKeySource);
        }
        self.named.insert(id, selector);
        Ok(self)
    }
    #[cfg(feature = "tokens")]
    pub fn with_tokens(mut self, tokens: Arc<Tokens>, gates: Arc<TokenGateRegistry>) -> Self {
        self.tokens = Some((tokens, gates));
        self
    }
}
fn authority(grant: &ExecutionGrant, id: &KeyId) -> Result<(), OperationError> {
    if !(grant.allows(Action::SignDigest) || grant.allows(Action::Sign)) || !grant.allows_key(id) {
        return Err(OperationError::PermissionDenied);
    }
    Ok(())
}
fn choose(mut entries: Vec<KeyEntry>, alias: Option<&str>) -> Result<KeyEntry, OperationError> {
    let index = match alias {
        Some(alias) => entries.iter().position(|entry| entry.alias == alias),
        None if entries.len() == 1 => Some(0),
        None => return Err(OperationError::InvalidKeySource),
    }
    .ok_or(OperationError::KeyNotFound)?;
    Ok(entries.swap_remove(index))
}
fn decode(
    bytes: &[u8],
    password: &str,
    alias: &Option<String>,
) -> Result<KeyEntry, OperationError> {
    let entries = if oncl_pki::jks::is_jks(bytes) {
        oncl_pki::jks::load(bytes, password).map_err(|_| OperationError::InvalidKeySource)?
    } else {
        oncl_pki::pkcs12::load(bytes, password).map_err(|_| OperationError::InvalidKeySource)?
    };
    choose(entries, alias.as_deref())
}
fn read_container(
    path: &Path,
    ctx: &mut OperationContext,
) -> Result<(Zeroizing<Vec<u8>>, ResourceReservation), OperationError> {
    ctx.resources().checkpoint()?;
    let mut file = File::open(path).map_err(|e| OperationError::Processing(e.into()))?;
    let len = file
        .metadata()
        .map_err(|e| OperationError::Processing(e.into()))?
        .len();
    let limit = ctx.resources().limits().container_bytes;
    if len > limit {
        return Err(oncl_pki::resource::ProcessingError::ContainerLimit.into());
    }
    let size = usize::try_from(len).map_err(|_| OperationError::InvalidKeySource)?;
    let reservation = ctx.resources().reserve_memory(len)?;
    ctx.resources().account_container(len)?;
    let mut bytes = Zeroizing::new(vec![0; size]);
    for chunk in bytes.chunks_mut(oncl_pki::resource::IO_CHUNK_BYTES) {
        ctx.resources().checkpoint()?;
        file.read_exact(chunk)
            .map_err(|e| OperationError::Processing(e.into()))?;
    }
    let mut extra = [0];
    if file
        .read(&mut extra)
        .map_err(|e| OperationError::Processing(e.into()))?
        != 0
    {
        return Err(OperationError::InvalidKeySource);
    }
    ctx.resources().checkpoint()?;
    Ok((bytes, reservation))
}
impl KeyProvider for KeySources {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError> {
        let id = request.selector.key_id();
        authority(ctx.grant(), &id)?;
        ctx.resources().checkpoint()?;
        let selector = if matches!(request.selector.source, Source::Named) {
            self.named.get(&id).ok_or(OperationError::KeyNotFound)?
        } else {
            request.selector
        };
        let secret = request.secret.ok_or(OperationError::SecretRequired)?;
        let (entry, reservation) = match &selector.source {
            Source::File(path, alias) => {
                let (bytes, reservation) = read_container(path, ctx)?;
                (decode(&bytes, secret, alias)?, Some(reservation))
            }
            Source::Inline(bytes, alias) => {
                let len =
                    u64::try_from(bytes.len()).map_err(|_| OperationError::InvalidKeySource)?;
                let reservation = ctx.resources().reserve_memory(len)?;
                ctx.resources().account_container(len)?;
                (decode(bytes, secret, alias)?, Some(reservation))
            }
            Source::Named => return Err(OperationError::InvalidKeySource),
            #[cfg(feature = "tokens")]
            Source::Token(device, kind, alias) => {
                let (tokens, gates) = self
                    .tokens
                    .as_ref()
                    .ok_or(OperationError::MissingKeyProvider)?;
                let execution = TokenExecution::new(
                    device.clone(),
                    ctx.lease(),
                    ctx.resources().operation_control(),
                    gates.clone(),
                );
                let entries = tokens
                    .open_scoped(device.reader(), *kind, secret, execution)
                    .map_err(|error| match error {
                        oncl_token::TokenError::Execution(error) => {
                            OperationError::Key(KeyError::Execution(error))
                        }
                        _ => OperationError::InvalidKeySource,
                    })?;
                (choose(entries, Some(alias.as_str()))?, None)
            }
        };
        ctx.resources().checkpoint()?;
        let mut lease = KeyLease::new(id, entry, ctx)?;
        lease._reservation = reservation;
        Ok(lease)
    }
}

impl crate::ReadMetadataProvider for KeySources {
    fn inspect(
        &self,
        request: &KeyRequest<'_>,
        limits: &oncl_pki::info::InspectionLimits,
        ctx: &mut OperationContext,
    ) -> Result<oncl_pki::info::PublicMetadata, OperationError> {
        // Named IDs authorize the immutable host slot, not a wire-supplied
        // certificate fingerprint. Check the slot before resolving its source.
        let id = request.selector.key_id();
        if !ctx.grant.allows(Action::Inspect) || !ctx.grant.allows_key(&id) {
            return Err(OperationError::PermissionDenied);
        }
        ctx.scope.checkpoint()?;
        let selector = if matches!(request.selector.source, Source::Named) {
            self.named.get(&id).ok_or(OperationError::KeyNotFound)?
        } else {
            request.selector
        };
        let alias = match &selector.source {
            Source::File(_, alias) | Source::Inline(_, alias) => alias.as_ref(),
            Source::Named => return Err(OperationError::InvalidKeySource),
            #[cfg(feature = "tokens")]
            Source::Token(_, _, alias) => Some(alias),
        };
        let aliases = alias.map_or(ctx.grant.metadata_aliases(), std::slice::from_ref);
        if aliases.is_empty() {
            return Err(OperationError::PermissionDenied);
        }
        if aliases.len() > limits.max_entries {
            return Err(oncl_pki::resource::ProcessingError::MetadataLimit.into());
        }
        let secret = request.secret.ok_or(OperationError::SecretRequired)?;
        match &selector.source {
            Source::File(path, _) => {
                let mut file =
                    File::open(path).map_err(|error| OperationError::Processing(error.into()))?;
                let length = file
                    .metadata()
                    .map_err(|error| OperationError::Processing(error.into()))?
                    .len();
                crate::inspect::container(
                    oncl_pki::io::Source::sequential(&mut file, Some(length)),
                    secret,
                    aliases,
                    limits,
                    &mut ctx.scope,
                )
            }
            Source::Inline(bytes, _) => {
                let mut input = bytes.as_slice();
                crate::inspect::container(
                    oncl_pki::io::Source::sequential(&mut input, Some(bytes.len() as u64)),
                    secret,
                    aliases,
                    limits,
                    &mut ctx.scope,
                )
            }
            Source::Named => Err(OperationError::InvalidKeySource),
            #[cfg(feature = "tokens")]
            Source::Token(device, kind, alias) => {
                let (tokens, gates) = self
                    .tokens
                    .as_ref()
                    .ok_or(OperationError::MissingMetadataProvider)?;
                tokens
                    .inspect_scoped(device, *kind, secret, alias, gates.clone(), &ctx.scope)
                    .map_err(|error| match error {
                        oncl_token::TokenError::Execution(error) => {
                            OperationError::Key(KeyError::Execution(error))
                        }
                        _ => OperationError::InvalidKeySource,
                    })
            }
        }
    }
}
/// Opaque operation-bound private material. No raw signer/accessor/export/Clone.
pub struct KeyLease {
    id: KeyId,
    operation: OperationId,
    entry: KeyEntry,
    _reservation: Option<ResourceReservation>,
    _slot_memory: ResourceReservation,
}
impl fmt::Debug for KeyLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyLease")
            .field("id", &self.id)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}
impl KeyLease {
    /// The certificate this lease holds for its key.
    #[cfg(feature = "plugins")]
    pub(crate) fn certificate(&self) -> &Certificate {
        &self.entry.cert
    }
    pub fn new(id: KeyId, entry: KeyEntry, ctx: &OperationContext) -> Result<Self, OperationError> {
        authority(ctx.grant(), &id)?;
        let public = oncl_pki::key::PublicKey::from_spki(
            entry.cert.tbs_certificate().subject_public_key_info(),
        )?;
        if public != entry.key.public_key() {
            return Err(OperationError::Key(KeyError::KeyMismatch));
        }
        Ok(Self {
            id,
            operation: ctx.id(),
            entry,
            _reservation: None,
            _slot_memory: ctx
                .scope
                .reserve_memory((std::mem::size_of::<Self>() * 2) as u64)?,
        })
    }
}
/// Zero-based ordinal in one closed, bounded approved batch, not a free-form
/// client label or a process-global private-use counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BatchItemOrdinal(u16);
impl BatchItemOrdinal {
    pub fn get(self) -> u16 {
        self.0
    }
    pub(crate) fn from_batch_index(index: usize) -> Self {
        assert!(index < crate::batch::MAX_ITEMS);
        Self(index as u16)
    }
}
#[derive(Clone, Debug)]
pub struct KeyUseEvent {
    pub operation_id: OperationId,
    pub key_id: KeyId,
    pub action: Action,
    batch_item: Option<BatchItemOrdinal>,
    #[cfg(feature = "plugins")]
    plugin: Option<crate::plugins::PluginUse>,
}
impl KeyUseEvent {
    /// Describe the original invocation/item. This grants no private-key authority.
    pub fn new(ctx: &OperationContext, key_id: KeyId, action: Action) -> Self {
        Self {
            operation_id: ctx.id(),
            key_id,
            action,
            batch_item: ctx.batch_item,
            #[cfg(feature = "plugins")]
            plugin: None,
        }
    }
    pub fn batch_item(&self) -> Option<BatchItemOrdinal> {
        self.batch_item
    }
    /// The ticket of a plugin's key use: set (by Core, from the arguments the engine is
    /// about to run) only for the signing imports of a plugin operation that declares its
    /// key uses. `None` for every document use and for a plugin operation without
    /// declarations. A guard of a plugin engine MUST refuse an event without one; a
    /// document guard MUST refuse one with one (consent to a document is not consent to a
    /// plugin).
    #[cfg(feature = "plugins")]
    pub fn plugin(&self) -> Option<&crate::plugins::PluginUse> {
        self.plugin.as_ref()
    }
    /// Whether the event carries a plugin ticket ([`KeyUseEvent::plugin`]). Available without
    /// the `plugins` feature (then always `false`: no ticket can exist), so a document guard
    /// of a host that does not link plugins can still refuse it: **a document guard MUST
    /// refuse every event for which this is `true`**.
    pub fn is_plugin(&self) -> bool {
        #[cfg(feature = "plugins")]
        {
            self.plugin.is_some()
        }
        #[cfg(not(feature = "plugins"))]
        {
            false
        }
    }
    /// An event carrying `ticket`, for tests of guards. Not part of any release: only with
    /// the `testing` feature.
    #[cfg(all(feature = "plugins", feature = "testing"))]
    pub fn with_plugin_ticket_for_tests(mut self, ticket: crate::plugins::PluginUse) -> Self {
        self.plugin = Some(ticket);
        self
    }
}
/// Non-cloneable successful host receipt, returned to the same guard after use.
pub struct KeyUseReceipt {
    event: KeyUseEvent,
    correlation: Option<(u64, u64)>,
}
impl KeyUseReceipt {
    pub fn new(event: KeyUseEvent) -> Self {
        Self {
            event,
            correlation: None,
        }
    }
    pub fn event(&self) -> &KeyUseEvent {
        &self.event
    }
    /// Host guard correlation, carried unchanged through the actual private use.
    /// This is not authority against a privileged host implementing this trait.
    pub fn with_correlation(event: KeyUseEvent, guard_instance: u64, use_id: u64) -> Self {
        Self {
            event,
            correlation: Some((guard_instance, use_id)),
        }
    }
    pub fn correlation(&self) -> Option<(u64, u64)> {
        self.correlation
    }
}
#[derive(Clone, Copy, Debug)]
pub struct KeyUseOutcome {
    pub applied: AppliedState,
    pub succeeded: bool,
}
pub trait KeyUseGuard: Send + Sync {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError>;
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError>;
}
pub(crate) struct KeyServices {
    pub provider: Arc<dyn KeyProvider>,
    pub guard: Arc<dyn KeyUseGuard>,
}
impl fmt::Debug for KeyServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyServices { configured }")
    }
}

pub struct AuthorizedSigner<'ctx> {
    ctx: &'ctx OperationContext,
    index: usize,
    algorithm: SigAlg,
    guard: Arc<dyn KeyUseGuard>,
    validation: Option<Arc<crate::ValidationServices>>,
    action: Action,
    strict: bool,
}
fn algorithm(entry: &KeyEntry, ctx: &OperationContext) -> Result<SigAlg, OperationError> {
    algorithm_mode(entry, ctx, false)
}
fn algorithm_mode(
    entry: &KeyEntry,
    ctx: &OperationContext,
    strict: bool,
) -> Result<SigAlg, OperationError> {
    signature_algorithm(&entry.cert, entry.key.alg(), ctx.policy(), strict)
}
/// The signature algorithm a key of type `key_alg` with certificate `cert` signs with under
/// `policy`: the one place that decides it, so what a host computes before the key is open
/// (the digest algorithm of a prehashed approval) is what the signer later uses.
pub(crate) fn signature_algorithm(
    cert: &Certificate,
    key_alg: oncl_pki::key::KeyAlg,
    policy: &crate::OperationPolicy,
    strict: bool,
) -> Result<SigAlg, OperationError> {
    let alg = if !strict && policy.validation == ValidationPolicy::NcalayerCompatibility {
        oncl_pki::info::cert_info(cert)
            .signing_alg()
            .map_err(|_| OperationError::Key(KeyError::UnsupportedAlgorithm))?
    } else {
        leaf_signature_algorithm(key_alg)
    };
    if alg == SigAlg::RsaSha1 || alg.key_alg() != key_alg {
        return Err(OperationError::Key(KeyError::UnsupportedAlgorithm));
    }
    if !policy.allowed_signature_algorithms.contains(&alg) {
        return Err(OperationError::PermissionDenied);
    }
    Ok(alg)
}
impl Engine {
    /// Explicit caller-prehashed private action; not an authorization shortcut for
    /// future SDK document-format operations that bind/hash their own source.
    pub fn signer<'ctx>(
        &self,
        request: &KeyRequest<'_>,
        ctx: &'ctx mut OperationContext,
    ) -> Result<AuthorizedSigner<'ctx>, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if ctx
            .private_use_stopped
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(OperationError::PermissionDenied);
        }
        authority(ctx.grant(), &request.selector.id)?;
        if !ctx.grant().allows(Action::SignDigest) {
            return Err(OperationError::PermissionDenied);
        }
        if !ctx.policy().allow_prehashed {
            return Err(OperationError::PermissionDenied);
        }
        ctx.resources().checkpoint()?;
        let services = self
            .keys
            .as_ref()
            .ok_or(OperationError::MissingKeyProvider)?;
        let index = if let Some(index) = ctx
            .leases
            .iter()
            .position(|lease| lease.id == request.selector.id)
        {
            index
        } else {
            let lease = services.provider.open(request, ctx)?;
            if lease.id != request.selector.id || lease.operation != ctx.id() {
                return Err(OperationError::InvalidContext);
            }
            ctx.leases
                .try_reserve_exact(1)
                .map_err(|_| oncl_pki::resource::ProcessingError::MemoryLimit)?;
            ctx.leases.push(lease);
            ctx.leases.len() - 1
        };
        let algorithm = algorithm(&ctx.leases[index].entry, ctx)?;
        Ok(AuthorizedSigner {
            ctx,
            index,
            algorithm,
            guard: services.guard.clone(),
            validation: self.validation.clone(),
            action: Action::SignDigest,
            strict: false,
        })
    }
}
impl AuthorizedSigner<'_> {
    pub fn certificate(&self) -> &Certificate {
        &self.ctx.leases[self.index].entry.cert
    }
    pub fn algorithm(&self) -> SigAlg {
        self.algorithm
    }
    pub fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, OperationError> {
        if self
            .ctx
            .private_use_stopped
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(OperationError::PermissionDenied);
        }
        let lease = &self.ctx.leases[self.index];
        authority(self.ctx.grant(), &lease.id)?;
        if !self.ctx.grant().allows(self.action) {
            return Err(OperationError::PermissionDenied);
        }
        if lease.operation != self.ctx.id() {
            return Err(OperationError::InvalidContext);
        }
        if self.action == Action::SignDigest && !self.ctx.policy().allow_prehashed {
            return Err(OperationError::PermissionDenied);
        }
        let alg = algorithm_mode(&lease.entry, self.ctx, self.strict)?;
        if digest.algorithm() != alg.hash_alg() {
            return Err(OperationError::Key(KeyError::UnsupportedAlgorithm));
        }
        self.ctx.scope.checkpoint()?;
        if self.strict || self.ctx.policy().validation != ValidationPolicy::NcalayerCompatibility {
            let validation = self
                .validation
                .as_ref()
                .ok_or(OperationError::MissingValidationServices)?;
            validation.check_private(&self.ctx.leases[self.index].entry.cert, self.ctx)?;
        }
        self.ctx.network_status()?;
        #[cfg_attr(not(feature = "plugins"), allow(unused_mut))]
        let mut event = KeyUseEvent::new(
            self.ctx,
            self.ctx.leases[self.index].id.clone(),
            self.action,
        );
        // One ticket, one use: a second `sign_digest` of the same plugin call finds none.
        #[cfg(feature = "plugins")]
        {
            // The certificate of the key that is actually about to sign, from its lease.
            let signer =
                crate::plugins::certificate_sha256(&self.ctx.leases[self.index].entry.cert);
            event.plugin = self
                .ctx
                .plugin_ticket
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .map(|ticket| ticket.with_signer_certificate(signer));
        }
        let receipt = self.guard.before_use(&event).inspect_err(|_| {
            self.ctx
                .private_use_stopped
                .store(true, std::sync::atomic::Ordering::Release);
        })?;
        // User guard code may take time or revoke/cancel while recording consent.
        let result = match self.ctx.scope.checkpoint() {
            Err(error) => Err(OperationError::from(error)),
            Ok(()) => self.ctx.leases[self.index]
                .entry
                .key
                .sign_digest(alg, digest)
                .map_err(OperationError::from),
        };
        let applied = match &result {
            Ok(_) => AppliedState::Applied,
            Err(error) => error.applied_state(),
        };
        let result = match result {
            Ok(signature) => match self.ctx.scope.checkpoint() {
                Ok(()) => Ok(signature),
                Err(error) => Err(OperationError::AfterKeyUse {
                    source: Box::new(error.into()),
                    applied,
                }),
            },
            Err(error) => Err(error),
        };
        if let Err(error) = self.guard.finish(
            receipt,
            KeyUseOutcome {
                applied,
                succeeded: result.is_ok(),
            },
        ) {
            self.ctx
                .private_use_stopped
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(OperationError::AfterKeyUse {
                source: Box::new(error),
                applied,
            });
        }
        result
    }
}
impl DigestSigner for AuthorizedSigner<'_> {
    fn certificate(&self) -> &Certificate {
        self.certificate()
    }
    fn algorithm(&self) -> SigAlg {
        self.algorithm()
    }
    fn sign_digest(&mut self, digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
        AuthorizedSigner::sign_digest(self, digest).map_err(KeyError::from)
    }
}

impl Engine {
    /// Pure request authority only: no provider, crypto, allocation, or callback.
    /// Staged producers use this before admitting an OUTPUT capability.
    pub(crate) fn check_sign_requests(
        &self,
        requests: &[KeyRequest<'_>],
        ctx: &OperationContext,
        action: Action,
    ) -> Result<(), OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        if ctx
            .private_use_stopped
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(OperationError::PermissionDenied);
        }
        if !ctx.grant.allows(action)
            || (action == Action::SignDigest && !ctx.policy.allow_prehashed)
        {
            return Err(OperationError::PermissionDenied);
        }
        for request in requests {
            authority(ctx.grant(), &request.selector.id)?;
        }
        Ok(())
    }
    pub(crate) fn prepare_sign_keys(
        &self,
        requests: &[KeyRequest<'_>],
        ctx: &mut OperationContext,
        action: Action,
    ) -> Result<Vec<usize>, OperationError> {
        self.check_sign_requests(requests, ctx, action)?;
        let services = self
            .keys
            .as_ref()
            .ok_or(OperationError::MissingKeyProvider)?;
        let mut indices = Vec::with_capacity(requests.len());
        for request in requests {
            ctx.scope.checkpoint()?;
            let index = if let Some(index) = ctx
                .leases
                .iter()
                .position(|lease| lease.id == request.selector.id)
            {
                index
            } else {
                let lease = services.provider.open(request, ctx)?;
                if lease.id != request.selector.id || lease.operation != ctx.id {
                    return Err(OperationError::InvalidContext);
                }
                ctx.leases
                    .try_reserve_exact(1)
                    .map_err(|_| oncl_pki::resource::ProcessingError::MemoryLimit)?;
                ctx.leases.push(lease);
                ctx.leases.len() - 1
            };
            algorithm_mode(&ctx.leases[index].entry, ctx, true)?;
            indices.push(index);
        }
        Ok(indices)
    }
    pub(crate) fn operation_signer<'ctx>(
        &self,
        index: usize,
        ctx: &'ctx OperationContext,
        action: Action,
    ) -> Result<AuthorizedSigner<'ctx>, OperationError> {
        let services = self
            .keys
            .as_ref()
            .ok_or(OperationError::MissingKeyProvider)?;
        Ok(AuthorizedSigner {
            ctx,
            index,
            algorithm: algorithm_mode(&ctx.leases[index].entry, ctx, true)?,
            guard: services.guard.clone(),
            validation: self.validation.clone(),
            action,
            strict: true,
        })
    }
}
