pub(crate) mod operations;

use crate::{
    audit::{AuditBinding, AuditConfig, AuditHealth, DurableAuditGuard},
    auth::{AccessPolicy, Principal},
    config::{Exposure, ServerConfig, invalid, normalized_peer},
    executor::{BoundedExecutor, CancelOnDrop, Cancellation},
    keys::{KeyBinding, OperatorKeys},
    pace::{PaceConfig, UploadPace},
    telemetry::{Route as ObservedRoute, Telemetry},
};
use axum::{
    body::{Body, Bytes},
    extract::ConnectInfo,
    http::{HeaderValue, Request},
    response::IntoResponse,
};
use oncl_api::{
    dto::HashResponse,
    error::{ApiError, ErrorCode},
    server::{HashHost, RequestMetadata, ResponseFuture},
};
use oncl_core::{
    Action, Engine, EngineServices, OperationContext, OperationError, OperationPolicy,
};
use oncl_pki::{
    digest::{DigestValue, HashStream},
    io::Source,
    key::HashAlg,
    resource::{
        Deadline, OperationControl, ProcessingError, Progress, ResourceReservation, ResourceScope,
        SharedBudget,
    },
};
use oncl_token::{PcscBackend, Tokens, execution::TokenGateRegistry};
use std::{
    future::Future,
    io::{self, Read},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
};

pub struct ServiceHost {
    pub engine: Arc<Engine>,
    pub policy: Arc<AccessPolicy>,
    pub executor: BoundedExecutor,
    pub keys: Arc<OperatorKeys>,
    pub audit: DurableAuditGuard,
    config: ServerConfig,
    /// Opt-in OTLP export handle; `Telemetry::disabled()` unless configured.
    pub telemetry: Telemetry,
    store: Option<oncl_pki::io::TemporaryStore>,
    output_store: Option<Arc<operations::artifact::ArtifactStore>>,
    host_policy: Arc<operations::HostPolicy>,
    /// The `max_uploads` slots of the upload phase (see `hash_unobserved` and `operations`):
    /// taken before a body is read, held until the operation takes its `max_in_flight` slot
    /// or ends.
    uploads: Arc<tokio::sync::Semaphore>,
}
struct InvocationControl {
    cancel: Arc<Cancellation>,
    deadline: Deadline,
    progress: Option<Arc<operations::progress::ProgressHub>>,
}
impl OperationControl for InvocationControl {
    fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError> {
        self.deadline.checkpoint()?;
        self.cancel.checkpoint(progress)?;
        if let Some(hub) = &self.progress {
            hub.publish(progress);
        }
        Ok(())
    }
}
impl ServiceHost {
    /// Synchronous startup only, before the network runtime/listener. Configuration
    /// owns all mounts and the journal; an existing journal requires explicit recovery.
    pub fn new(config: ServerConfig) -> io::Result<Arc<Self>> {
        Self::build(config, Arc::new(PcscBackend::new()))
    }
    /// Startup with an explicit card backend (emulator in tests). Test-support only:
    /// production always uses the system PC/SC service through [`Self::new`].
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_token_backend(
        config: ServerConfig,
        backend: Arc<dyn oncl_token::backend::Backend>,
    ) -> io::Result<Arc<Self>> {
        Self::build(config, backend)
    }
    /// Token keys fail closed when no reader/card answers.
    fn build(
        mut config: ServerConfig,
        backend: Arc<dyn oncl_token::backend::Backend>,
    ) -> io::Result<Arc<Self>> {
        config.validate()?;
        if let Exposure::TrustedProxy { peers } = &mut config.exposure {
            for peer in peers {
                *peer = normalized_peer(*peer);
            }
        }
        let policy = Arc::new(AccessPolicy::new(
            config
                .tokens
                .iter()
                .map(|t| t.record())
                .collect::<io::Result<_>>()?,
        )?);
        let bindings = config
            .keys
            .iter()
            .map(KeyBinding::from_config)
            .collect::<io::Result<Vec<_>>>()?;
        let token_services = if config
            .keys
            .iter()
            .any(|k| matches!(k, crate::config::KeyConfig::Token { .. }))
        {
            let tokens = Tokens::new(backend, true);
            tokens.set_trace(false);
            Some((
                tokens,
                Arc::new(TokenGateRegistry::new(64, config.queue_capacity).map_err(|_| invalid())?),
            ))
        } else {
            None
        };
        let keys = Arc::new(
            OperatorKeys::new(bindings, token_services, config.inline_pkcs12)
                .map_err(|_| invalid())?,
        );
        let audit_config = AuditConfig::new(
            config.audit_directory.clone(),
            config.audit_segment_bytes,
            config.audit_quota_bytes,
            32,
            config.max_in_flight as usize,
        )?;
        let (registry, plugin_grants, plugin_policy) = install_plugins(&config)?;
        let audit = if config.audit_directory.exists() {
            DurableAuditGuard::open(audit_config)?
        } else {
            DurableAuditGuard::create(audit_config)?
        }
        .with_plugin_policy(plugin_policy.clone())?;
        if audit.health() != AuditHealth::Healthy {
            if !config.recover_audit {
                return Err(io::Error::other("audit recovery required"));
            }
            audit.recover()?;
        }
        if audit.health() != AuditHealth::Healthy {
            return Err(io::Error::other("audit unavailable"));
        }
        let budget = Arc::new(SharedBudget::new(config.aggregate_limits()).map_err(|_| invalid())?);
        let store = if config.scratch_directory.as_os_str().is_empty() {
            None
        } else {
            if config.scratch_directory.exists() {
                oncl_pki::private_fs::PrivateDirectory::open(&config.scratch_directory)?;
            } else {
                oncl_pki::private_fs::PrivateDirectory::create(&config.scratch_directory)?;
            }
            Some(
                oncl_pki::io::TemporaryStore::new(&config.scratch_directory)
                    .map_err(|_| invalid())?,
            )
        };
        let mut services = EngineServices::hash_only(config.limits())
            .with_shared_budget(budget)
            .with_keys(keys.clone(), Arc::new(audit.clone()))
            .with_metadata_provider(keys.clone())
            .with_validation(config.pki.services()?);
        if !config.plugins.is_empty() {
            services = services.with_plugins(registry);
        }
        if let Some(tsa) = &config.pki.tsa {
            services = services.with_cades(oncl_core::CadesConfiguration::new(
                operations::evidence_limits(&config.limits()),
                tsa.spec()?,
            ));
        }
        if let Some(store) = &store {
            services = services.with_temporary_store(store.clone());
        }
        let engine = Arc::new(Engine::new(services).map_err(|_| invalid())?);
        let output_store = if store.is_some() {
            Some(
                operations::artifact::ArtifactStore::new(&config.scratch_directory)
                    .map_err(|_| invalid())?,
            )
        } else {
            None
        };
        let executor = BoundedExecutor::new(config.executor()).map_err(|_| invalid())?;
        let telemetry = Telemetry::start(&config.telemetry)?;
        telemetry.register_load(executor.load_probe());
        let host_policy = Arc::new(operations::HostPolicy {
            tsa: config.pki.tsa.as_ref().map(|t| t.spec()).transpose()?,
            jwt_issuer: config.pki.jwt.expected_issuer.clone(),
            jwt_audience: config.pki.jwt.expected_audience.clone(),
            plugin_grants,
            plugin_policy,
            trust_bytes: config.pki.trust_bytes()?,
        });
        let uploads = Arc::new(tokio::sync::Semaphore::new(config.effective_max_uploads()));
        Ok(Arc::new(Self {
            engine,
            policy,
            executor,
            keys,
            audit,
            config,
            telemetry,
            store,
            output_store,
            host_policy,
            uploads,
        }))
    }
    fn principal(&self, metadata: &RequestMetadata) -> Result<Principal, ApiError> {
        let denied = || ApiError::not_applied(ErrorCode::PermissionDenied);
        let peer = normalized_peer(metadata.peer.ip());
        if peer.is_unspecified() {
            return Err(denied());
        }
        if let Exposure::TrustedProxy { peers } = &self.config.exposure
            && !peers.contains(&peer)
        {
            return Err(denied());
        }
        let host = metadata
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(denied)?;
        let authority = host
            .parse::<axum::http::uri::Authority>()
            .map_err(|_| denied())?;
        if authority.as_str() != host
            || authority.as_str().contains('@')
            || !self.config.hosts.iter().any(|h| h == host)
        {
            return Err(denied());
        }
        let auth = metadata
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(denied)?;
        self.policy
            .authenticate(auth.as_bytes())
            .map_err(|_| denied())
    }
    /// Trusted SDK composition path used by private-operation callers as well as
    /// hash. Actor binding belongs to this exact original context, not wire DTOs.
    pub fn begin(
        &self,
        principal: &Principal,
        action: Action,
        key: Option<&str>,
        control: Arc<dyn OperationControl>,
    ) -> Result<(OperationContext, Option<AuditBinding>), ApiError> {
        begin_operation(
            &self.engine,
            &self.policy,
            &self.audit,
            &self.keys,
            principal,
            action,
            key,
            control,
        )
    }
    /// How many of the `max_uploads` upload slots are free now (diagnostics and tests).
    pub fn upload_slots_free(&self) -> usize {
        self.uploads.available_permits()
    }
    pub fn router(self: &Arc<Self>) -> axum::Router {
        oncl_api::server::router(self.clone())
    }
    pub fn for_listener(self: Arc<Self>, address: SocketAddr) -> io::Result<Arc<Self>> {
        let mut this = Arc::try_unwrap(self).map_err(|_| invalid())?;
        if this.config.hosts.is_empty() {
            this.config.hosts.push(address.to_string());
        }
        Ok(Arc::new(this))
    }
}
/// Operator-only plugin installation: code availability, never authority. The
/// per-(token, operation) permission lists exact host imports and key names and
/// binds the caller identity to the token, not to any request field. A grant of a plugin
/// that declares operations is judged against the declaration
/// ([`crate::plugin_grants::judge`]); the ticket policy of its key uses is built here too.
fn install_plugins(
    config: &ServerConfig,
) -> io::Result<(
    oncl_core::plugins::PluginRegistry,
    Vec<operations::PluginGrantRuntime>,
    Arc<crate::plugin_grants::ServerPluginPolicy>,
)> {
    use crate::plugin_grants::{ServerPluginPolicy, Verdict, judge};
    use oncl_core::plugins::{CallerContext, PluginPermission, PluginRegistry};
    let mut registry = PluginRegistry::new();
    let mut grants = Vec::new();
    let mut policy = ServerPluginPolicy::default();
    let mut ids = std::collections::HashSet::new();
    let mut skipped = 0usize;
    for plugin in &config.plugins {
        if !ids.insert(plugin.id.as_str()) {
            return Err(invalid());
        }
        let read = |path: &std::path::Path, limit: u64| -> io::Result<Vec<u8>> {
            use std::io::Read;
            let mut file = std::fs::File::open(path)?;
            if file.metadata()?.len() > limit {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            file.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > limit {
                return Err(invalid());
            }
            Ok(bytes)
        };
        let manifest_text =
            String::from_utf8(read(&plugin.manifest, 64 << 10)?).map_err(|_| invalid())?;
        let manifest = oncl_plugin::Manifest::from_toml(&manifest_text).map_err(|_| invalid())?;
        if manifest.id != plugin.id {
            return Err(invalid());
        }
        let wasm = read(&plugin.wasm, 16 << 20)?;
        let package = oncl_core::plugins::loose_package_hash(manifest_text.as_bytes(), &wasm);
        let mut permissions = Vec::new();
        for grant in &plugin.permissions {
            if !config.tokens.iter().any(|t| t.id == grant.token) {
                return Err(invalid());
            }
            // Design 4.7: a grant wider than the declaration is skipped (and said so), not
            // the server; an import that does not exist is a configuration error.
            let (imports, declared) = match judge(&plugin.id, &manifest, grant)? {
                Verdict::Skip(error) => {
                    eprintln!("oncl-server: error: {error}");
                    tracing::error!(target: "oncl::plugin_grants", "{error}");
                    skipped += 1;
                    continue;
                }
                Verdict::Keep {
                    imports,
                    declared,
                    warnings,
                } => {
                    for warning in warnings {
                        eprintln!("oncl-server: warning: {warning}");
                        tracing::warn!(target: "oncl::plugin_grants", "{warning}");
                    }
                    (imports, declared)
                }
            };
            if declared
                && let Some(operation) = manifest
                    .operations()
                    .iter()
                    .find(|o| o.name() == grant.operation)
                && !operation.uses().keys().is_empty()
            {
                policy.add(&plugin.id, grant, package, operation)?;
            }
            let keys = grant
                .keys
                .iter()
                .map(|k| oncl_core::keys::KeyId::new(k).map_err(|_| invalid()))
                .collect::<io::Result<Vec<_>>>()?;
            let permission = PluginPermission::new(
                &plugin.id,
                &grant.operation,
                CallerContext::ServiceClient(grant.token.clone()),
                imports,
            )
            .with_keys(keys)
            .with_pki_endpoints(
                grant
                    .pki_endpoints
                    .iter()
                    .map(|url| (oncl_pki::http::HttpMethod::Get, url.as_str())),
            )
            .map_err(|_| invalid())?;
            grants.push(operations::PluginGrantRuntime {
                token: grant.token.clone(),
                plugin: plugin.id.clone(),
                operation: grant.operation.clone(),
                keys: grant.keys.clone(),
                permission: permission.clone(),
            });
            permissions.push(permission);
        }
        registry
            .install(
                manifest,
                package,
                &wasm,
                oncl_plugin::InstanceLimits {
                    max_memory: plugin.max_memory,
                    max_transfer: plugin.max_transfer,
                    ..oncl_plugin::InstanceLimits::default()
                },
                permissions,
            )
            .map_err(|_| invalid())?;
    }
    if skipped > 0 {
        eprintln!("oncl-server: error: {skipped} plugin grants skipped (see the lines above)");
        tracing::error!(target: "oncl::plugin_grants", skipped, "plugin grants skipped");
    }
    Ok((registry, grants, Arc::new(policy)))
}
/// Stable wire code of a processing failure (never its message).
pub(crate) fn processing_code(error: &ProcessingError) -> ErrorCode {
    match operations::intake::first_cause(error) {
        ProcessingError::CapacityExceeded => ErrorCode::CapacityExceeded,
        ProcessingError::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        ProcessingError::Cancelled => ErrorCode::Cancelled,
        ProcessingError::InputLimit | ProcessingError::ContainerLimit => ErrorCode::InputLimit,
        ProcessingError::FramingLimit => ErrorCode::FramingLimit,
        ProcessingError::MemoryLimit => ErrorCode::MemoryLimit,
        ProcessingError::TempLimit => ErrorCode::TempLimit,
        ProcessingError::MetadataLimit => ErrorCode::MetadataLimit,
        ProcessingError::OutputLimit => ErrorCode::OutputLimit,
        ProcessingError::Io(_) | ProcessingError::InvalidInput(_) => ErrorCode::InvalidRequest,
        ProcessingError::InvalidLimits => ErrorCode::Internal,
    }
}
pub(crate) fn processing_error(error: ProcessingError) -> ApiError {
    ApiError::not_applied(processing_code(&error))
}
pub(crate) fn api_applied(value: oncl_pki::key::AppliedState) -> oncl_api::error::AppliedState {
    use oncl_api::error::AppliedState as Api;
    match value {
        oncl_pki::key::AppliedState::NotApplied => Api::NotApplied,
        oncl_pki::key::AppliedState::Applied => Api::Applied,
        oncl_pki::key::AppliedState::Unknown => Api::Unknown,
    }
}
/// Stable terminal error + honest key-application state from the typed SDK
/// error, never reconstructed from a message.
pub(crate) fn operation_failure(error: &OperationError) -> ApiError {
    ApiError::new(api_code(error.code()), api_applied(error.applied_state()))
}
/// Stable wire code of a typed SDK error code.
pub(crate) fn api_code(code: oncl_core::ErrorCode) -> ErrorCode {
    use oncl_core::ErrorCode as Core;
    match code {
        Core::PermissionDenied => ErrorCode::PermissionDenied,
        Core::InteractionRequired => ErrorCode::InteractionRequired,
        Core::InvalidInput | Core::SecretRequired => ErrorCode::InvalidRequest,
        Core::Cancelled => ErrorCode::Cancelled,
        Core::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        Core::CapacityExceeded => ErrorCode::CapacityExceeded,
        Core::InputLimit | Core::ContainerLimit => ErrorCode::InputLimit,
        Core::FramingLimit => ErrorCode::FramingLimit,
        Core::OutputLimit => ErrorCode::OutputLimit,
        Core::MemoryLimit => ErrorCode::MemoryLimit,
        Core::TempLimit => ErrorCode::TempLimit,
        Core::MetadataLimit => ErrorCode::MetadataLimit,
        Core::Io | Core::UnsupportedAlgorithm | Core::KeyFailure => ErrorCode::OperationFailed,
        Core::MissingKeyProvider
        | Core::MissingMetadataProvider
        | Core::MissingValidationServices
        | Core::MissingCadesConfiguration => ErrorCode::MissingConfiguration,
        Core::MissingTemporaryStore => ErrorCode::MissingTemporaryStore,
        Core::KeyNotFound => ErrorCode::KeyNotFound,
        Core::AuditFailed => ErrorCode::AuditUnavailable,
        Core::ValidationRequired => ErrorCode::ValidationFailed,
    }
}
/// Opens the operation for a hash/sign-family request: audit health, token right, SDK
/// context and, for private use, the durable audit binding.
#[allow(clippy::too_many_arguments)]
fn begin_operation(
    engine: &Engine,
    policy: &AccessPolicy,
    audit: &DurableAuditGuard,
    keys: &OperatorKeys,
    principal: &Principal,
    action: Action,
    key: Option<&str>,
    control: Arc<dyn OperationControl>,
) -> Result<(OperationContext, Option<AuditBinding>), ApiError> {
    if audit.health() != AuditHealth::Healthy {
        return Err(ApiError::not_applied(ErrorCode::AuditUnavailable));
    }
    let grant = policy
        .authorize(principal, action, key, None)
        .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))?;
    let ctx = engine
        .begin(grant, OperationPolicy::strict_online(), control)
        .map_err(core_error)?;
    let binding = if matches!(action, Action::Sign | Action::SignDigest) {
        Some(
            audit
                .bind(
                    &ctx,
                    principal.audit_label(),
                    keys.labels().filter(|(id, _)| ctx.grant().allows_key(id)),
                )
                .map_err(|_| ApiError::not_applied(ErrorCode::AuditUnavailable))?,
        )
    } else {
        None
    };
    Ok((ctx, binding))
}
/// How often a request that finds every slot taken looks again.
const ADMISSION_POLL: Duration = Duration::from_millis(10);
/// Runs `attempt` until it is admitted. A refusal with `CapacityExceeded` (every
/// `max_in_flight` slot taken) is retried for at most `wait` (`admission_wait_ms`) before it
/// is returned; any other result is final. A request that reaches this point has taken its
/// whole body: it keeps its upload slot, spool and temp reservation while it waits, and
/// they are released with the refusal.
async fn admit_within<T>(
    wait: Duration,
    mut attempt: impl FnMut() -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let end = tokio::time::Instant::now() + wait;
    loop {
        match attempt() {
            Err(refused) if refused.code == ErrorCode::CapacityExceeded => {
                let now = tokio::time::Instant::now();
                if now >= end {
                    return Err(refused);
                }
                tokio::time::sleep(ADMISSION_POLL.min(end - now)).await;
            }
            result => return result,
        }
    }
}
/// One of the `max_uploads` slots of the upload phase. A request waits for it for at most
/// `wait` (`admission_wait_ms`) before the typed `CapacityExceeded` refusal, which comes
/// before any byte of its body is read. Dropping the permit (every exit of the phase, a
/// dropped connection included) frees the slot.
async fn acquire_upload(
    uploads: &Arc<tokio::sync::Semaphore>,
    wait: Duration,
) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    match tokio::time::timeout(wait, uploads.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        _ => Err(ApiError::not_applied(ErrorCode::CapacityExceeded)),
    }
}
/// The request is refused before its body is read when no `max_in_flight` slot is free and
/// none frees up within `wait` (`admission_wait_ms`), and otherwise takes an upload slot
/// within the rest of `wait`: a refusal costs no body bytes, as it did before the upload
/// phase, and an `Expect: 100-continue` client is never told to send. Best effort: a slot
/// can be taken meanwhile, the check after the body stays authoritative.
async fn admit_to_upload(
    engine: &Engine,
    uploads: &Arc<tokio::sync::Semaphore>,
    wait: Duration,
) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    let began = tokio::time::Instant::now();
    admit_within(wait, || {
        if engine.slot_available() {
            Ok(())
        } else {
            Err(ApiError::not_applied(ErrorCode::CapacityExceeded))
        }
    })
    .await?;
    acquire_upload(uploads, wait.saturating_sub(began.elapsed())).await
}
fn core_error(error: OperationError) -> ApiError {
    match error {
        OperationError::Processing(error) => processing_error(error),
        OperationError::PermissionDenied => ApiError::not_applied(ErrorCode::PermissionDenied),
        _ => ApiError::not_applied(ErrorCode::Internal),
    }
}
/// The most one received HTTP frame is charged for. The connection's parser buffer is
/// `max_buf_size(32768)`, but a frame is whatever one socket read returned into the spare
/// capacity of that buffer plus what was already buffered: 49,152 and 57,344 bytes were
/// observed from a client that writes 64 KiB at once, so a frame is *not* at most 32 KiB.
/// Two buffers' worth (the retained one plus one read) covers it.
pub(crate) const FRAME_RESERVE_BYTES: u64 = 65_536;
/// A digest state that runs on an async runtime thread, between two network waits. That is
/// acceptable only for SHA-2 (measured per 32 KiB frame: SHA-256 12 us, SHA-512 37 us); the
/// slower digests (Streebog-512 166 us, GOST R 34.11-94 802 us) starve every other request
/// of the runtime's two threads, so the constructor refuses them and a future algorithm on
/// an inline route has to take the worker path instead.
pub(crate) struct InlineHash(HashStream);
impl InlineHash {
    pub(crate) const fn allows(algorithm: HashAlg) -> bool {
        matches!(algorithm, HashAlg::Sha256 | HashAlg::Sha512)
    }
    pub(crate) fn new(algorithm: HashAlg, scope: &ResourceScope) -> Result<Self, ProcessingError> {
        if !Self::allows(algorithm) {
            return Err(ProcessingError::InvalidInput(
                "inline hashing is limited to SHA-2",
            ));
        }
        HashStream::new(algorithm, scope).map(Self)
    }
    fn update(&mut self, bytes: &[u8], scope: &ResourceScope) -> Result<(), ProcessingError> {
        self.0.update(bytes, scope)
    }
    fn finish(self, scope: &ResourceScope) -> Result<DigestValue, ProcessingError> {
        self.0.finish(scope)
    }
}
/// Hashes a raw request body while it arrives. Every wait for the client is asynchronous
/// and governed by the pace rules, the operation deadline and `cancel`; a piece is one
/// Hyper frame (see [`FRAME_RESERVE_BYTES`]; `update` consumes it in as many input requests
/// as the budget needs) and is hashed where it arrives, so no thread is held while the
/// client is silent. Returns the SHA-256 and the number of bytes.
async fn hash_body(
    mut body: Body,
    scope: &ResourceScope,
    deadline: Deadline,
    pace: PaceConfig,
    cancel: &Arc<Cancellation>,
) -> Result<(DigestValue, u64), ApiError> {
    let invalid = || ApiError::not_applied(ErrorCode::InvalidRequest);
    let mut pace = UploadPace::new(pace);
    let mut hasher = InlineHash::new(HashAlg::Sha256, scope).map_err(processing_error)?;
    let mut total = 0u64;
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => return Err(processing_error(ProcessingError::Cancelled)),
            frame = pace.frame(&mut body, deadline) => frame.map_err(processing_error)?,
        };
        let Some(frame) = frame else { break };
        let data = frame
            .map_err(|_| invalid())?
            .into_data()
            .map_err(|_| invalid())?;
        hasher.update(&data, scope).map_err(processing_error)?;
        total += data.len() as u64;
    }
    let digest = hasher.finish(scope).map_err(processing_error)?;
    Ok((digest, total))
}
impl ServiceHost {
    /// `POST /v1/hash`. The body is hashed while it arrives, in the upload phase: waiting
    /// for the client takes no `max_in_flight` slot and no native worker (every piece is
    /// hashed where it arrives and the next wait is asynchronous), only one of the
    /// `max_uploads`. The slot and a worker are taken when the whole body has been hashed.
    fn hash_unobserved(&self, metadata: RequestMetadata, body: Body) -> ResponseFuture {
        let engine = self.engine.clone();
        let policy = self.policy.clone();
        let audit = self.audit.clone();
        let executor = self.executor.clone();
        let uploads = self.uploads.clone();
        let operation_timeout = Duration::from_millis(self.config.operation_timeout_ms);
        let admission_wait = Duration::from_millis(self.config.admission_wait_ms);
        let pace = self.config.upload_pace();
        let cancel = Arc::new(Cancellation::new());
        let principal = self.principal(&metadata);
        Box::pin(async move {
            let disconnect = Arc::new(CancelOnDrop(cancel.clone()));
            let principal = principal?;
            // Audit health and the token right are decided before a body byte is read.
            if audit.health() != AuditHealth::Healthy {
                return Err(ApiError::not_applied(ErrorCode::AuditUnavailable));
            }
            let grant = policy
                .authorize(&principal, Action::Hash, None, None)
                .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))?;
            // The upload limit: a client that finds every upload slot taken queues for at
            // most `admission_wait`; the deadline starts at its own admission, never at arrival.
            let upload = admit_to_upload(&engine, &uploads, admission_wait).await?;
            let deadline = Deadline::after(operation_timeout).map_err(processing_error)?;
            let mut admission = engine
                .admit_intake(Arc::new(InvocationControl {
                    cancel: cancel.clone(),
                    deadline,
                    progress: None,
                }))
                .map_err(core_error)?;
            if metadata
                .content_length
                .is_some_and(|n| n > admission.resources().limits().input_bytes)
            {
                return Err(ApiError::not_applied(ErrorCode::InputLimit));
            }
            let header_bytes = metadata
                .headers
                .iter()
                .try_fold(0u64, |n, (k, v)| {
                    n.checked_add((k.as_str().len() + v.as_bytes().len() + 4) as u64)
                })
                .ok_or_else(|| ApiError::not_applied(ErrorCode::MetadataLimit))?;
            let metadata_reservation = admission
                .resources()
                .reserve_metadata(header_bytes)
                .map_err(processing_error)?;
            let ingress = admission
                .resources()
                .reserve_memory(FRAME_RESERVE_BYTES)
                .map_err(processing_error)?;
            let (digest, bytes_in) =
                hash_body(body, admission.resources(), deadline, pace, &cancel).await?;
            if metadata.content_length.is_some_and(|n| n != bytes_in) {
                return Err(ApiError::not_applied(ErrorCode::InvalidRequest));
            }
            // The whole body is in: only now the operation takes an in-flight slot.
            admit_within(admission_wait, || {
                admission.occupy_slot().map_err(core_error)
            })
            .await?;
            drop(upload);
            // `hash_unobserved` does not call `Engine::hash`: the digest is computed inline
            // in `hash_body` and the operation is only begun here. Any per-hash logic added to
            // `Engine::hash` later (new checks, accounting, telemetry) MUST be mirrored here.
            let ctx = engine
                .begin_admitted(admission, grant, OperationPolicy::strict_online())
                .map_err(core_error)?;
            let work = executor
                .submit(ctx, move |ctx| {
                    let _metadata = metadata_reservation;
                    let _ingress = ingress;
                    let reservation = ctx.resources().reserve_memory(512)?;
                    let dto = HashResponse {
                        operation_id: ctx.id().get(),
                        algorithm: "sha256".into(),
                        digest: crate::auth::encode(digest.as_bytes()),
                        bytes_in,
                    };
                    let bytes = serde_json::to_vec(&dto)
                        .map_err(|_| ProcessingError::InvalidInput("response serialization"))?;
                    if bytes.len() > 512 {
                        return Err(ProcessingError::OutputLimit);
                    }
                    ctx.resources().account_output(bytes.len() as u64)?;
                    Ok((bytes, reservation))
                })
                .await
                .map_err(processing_error)?;
            let output = tokio::time::timeout(deadline.remaining(), work.wait())
                .await
                .map_err(|_| ApiError::not_applied(ErrorCode::DeadlineExceeded))?
                .map_err(processing_error)?;
            let ((bytes, reservation), mut ctx) = (output.value, output.context);
            let delivery = ResponseDelivery {
                deadline,
                cancel,
                control: ctx.resources().operation_control(),
                _disconnect: disconnect.clone(),
            };
            delivery.checkpoint().map_err(processing_error)?;
            let owner = ResponseOwner {
                _disconnect: disconnect,
                bytes,
                _context: ctx,
                _reservation: reservation,
            };
            let mut response = Body::new(DeliveryBody {
                data: Some(Bytes::from_owner(owner)),
                delivery: delivery.clone(),
            })
            .into_response();
            response.extensions_mut().insert(delivery);
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            Ok(response)
        })
    }
}
impl HashHost for ServiceHost {
    fn hash(&self, metadata: RequestMetadata, body: Body) -> ResponseFuture {
        self.telemetry
            .begin(ObservedRoute::Hash)
            .observe(self.hash_unobserved(metadata, body))
    }
    fn operations(&self, metadata: RequestMetadata, body: Body) -> ResponseFuture {
        self.telemetry
            .begin(ObservedRoute::Operations)
            .observe(self.dispatch_operations(metadata, body, operations::Route::Operations))
    }
    fn batch(&self, metadata: RequestMetadata, body: Body) -> ResponseFuture {
        self.telemetry
            .begin(ObservedRoute::Batch)
            .observe(self.dispatch_operations(metadata, body, operations::Route::Batch))
    }
    fn openapi(&self, metadata: RequestMetadata) -> ResponseFuture {
        let result = self.principal(&metadata).map(|_| {
            let bytes = serde_json::to_vec(&oncl_api::openapi::document()).expect("document");
            let mut response = axum::body::Body::from(bytes).into_response();
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            response
        });
        Box::pin(async move { result })
    }
    fn health(&self, metadata: RequestMetadata) -> ResponseFuture {
        let result = self
            .principal(&metadata)
            .and_then(|principal| {
                self.policy
                    .authorize(&principal, Action::Hash, None, None)
                    .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))
            })
            .and_then(|_| {
                if self.audit.health() == AuditHealth::Healthy {
                    Ok((axum::http::StatusCode::OK, "healthy").into_response())
                } else {
                    Err(ApiError::not_applied(ErrorCode::AuditUnavailable))
                }
            });
        Box::pin(async move { result })
    }
}
struct ResponseOwner {
    _disconnect: Arc<CancelOnDrop>,
    bytes: Vec<u8>,
    _context: OperationContext,
    _reservation: ResourceReservation,
}
impl AsRef<[u8]> for ResponseOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
/// Read-only original invocation delivery state carried in response extensions.
/// Transport integrations must not replace this deadline with a fresh timeout.
#[derive(Clone)]
pub struct ResponseDelivery {
    deadline: Deadline,
    cancel: Arc<Cancellation>,
    control: Arc<dyn OperationControl>,
    _disconnect: Arc<CancelOnDrop>,
}
impl ResponseDelivery {
    pub fn deadline(&self) -> Deadline {
        self.deadline
    }
    fn checkpoint(&self) -> Result<(), ProcessingError> {
        self.deadline.checkpoint()?;
        self.control.checkpoint(Progress::default())?;
        self.deadline.checkpoint()
    }
}
struct DeliveryBody {
    data: Option<Bytes>,
    delivery: ResponseDelivery,
}
impl axum::body::HttpBody for DeliveryBody {
    type Data = Bytes;
    type Error = ProcessingError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, ProcessingError>>> {
        if self.data.is_none() {
            return Poll::Ready(None);
        }
        if let Err(error) = self.delivery.checkpoint() {
            self.data.take();
            return Poll::Ready(Some(Err(error)));
        }
        Poll::Ready(
            self.data
                .take()
                .map(|bytes| Ok(hyper::body::Frame::data(bytes))),
        )
    }
    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.data.as_ref().map_or(0, |bytes| bytes.len() as u64))
    }
}

pub fn tls_configuration(config: &ServerConfig) -> io::Result<Option<tokio_rustls::TlsAcceptor>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let Exposure::Tls {
        certificate,
        private_key,
    } = &config.exposure
    else {
        return Ok(None);
    };
    let mut file = std::fs::File::open(certificate)?;
    if file.metadata()?.len() > 1_048_576 {
        return Err(invalid());
    }
    let mut pem = Vec::new();
    file.by_ref().take(1_048_577).read_to_end(&mut pem)?;
    if pem.len() > 1_048_576 {
        return Err(invalid());
    }
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    let secret = private_key.read(65_536)?;
    let key = PrivateKeyDer::from_pem_slice(&secret).map_err(|_| invalid())?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|_| invalid())?;
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls))))
}
#[derive(Default)]
struct ConnectionDelivery {
    delivery: Mutex<Option<ResponseDelivery>>,
    changed: tokio::sync::Notify,
}
impl ConnectionDelivery {
    fn install(&self, delivery: ResponseDelivery) {
        let mut slot = self
            .delivery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Keep-alive is disabled: this connection has one original invocation.
        // Re-registration must never replace/refresh its delivery bound.
        if slot.is_none() {
            *slot = Some(delivery);
        }
        drop(slot);
        self.changed.notify_waiters();
    }
    fn checkpoint(&self) -> io::Result<()> {
        let delivery = self
            .delivery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        delivery.as_ref().map_or(Ok(()), |delivery| {
            delivery.checkpoint().map_err(delivery_io_error)
        })
    }
    async fn stopped(&self) -> ProcessingError {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let delivery = self
                .delivery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(delivery) = delivery {
                if let Err(error) = delivery.checkpoint() {
                    return error;
                }
                return tokio::select! {
                    biased;
                    _=delivery.cancel.cancelled()=>ProcessingError::Cancelled,
                    _=tokio::time::sleep(delivery.deadline().remaining())=>ProcessingError::DeadlineExceeded,
                };
            }
            changed.await;
        }
    }
}
fn delivery_io_error(error: ProcessingError) -> io::Error {
    match error {
        ProcessingError::DeadlineExceeded => io::Error::new(
            io::ErrorKind::TimedOut,
            "operation delivery deadline exceeded",
        ),
        ProcessingError::Cancelled => io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "operation delivery cancelled",
        ),
        _ => io::Error::other("operation delivery refused"),
    }
}
struct ConnectionDisconnect(Arc<ConnectionDelivery>);
impl Drop for ConnectionDisconnect {
    fn drop(&mut self) {
        let cancel = self
            .0
            .delivery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|delivery| delivery.cancel.clone());
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
    }
}
// The timer aborts an unpolled/pending write; the I/O checkpoint also refuses a
// newly-ready write at the boundary, including Bytes already buffered by Hyper.
struct DeliveryIo<S> {
    stream: S,
    delivery: Arc<ConnectionDelivery>,
}
impl<S: AsyncRead + Unpin> AsyncRead for DeliveryIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.delivery.checkpoint() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.stream).poll_read(cx, buffer)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for DeliveryIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.delivery.checkpoint() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.stream).poll_write(cx, buffer)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.delivery.checkpoint() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.stream).poll_write_vectored(cx, buffers)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.delivery.checkpoint() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.delivery.checkpoint() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
/// Serve one accepted transport (plain/TLS/wrapped I/O). The trusted acceptor
/// supplies the ACTUAL peer and finite accept/header bounds, never request data.
/// A response's original invocation bound can only shorten these outer bounds.
pub async fn serve_connection<S>(
    stream: S,
    peer: SocketAddr,
    router: axum::Router,
    header_timeout: Duration,
    connection_deadline: tokio::time::Instant,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if header_timeout.is_zero() {
        return Err(invalid());
    }
    let delivery = Arc::new(ConnectionDelivery::default());
    let _disconnect = ConnectionDisconnect(delivery.clone());
    let service_delivery = delivery.clone();
    let service = hyper::service::service_fn(move |mut request: Request<hyper::body::Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        let router = router.clone();
        let delivery = service_delivery.clone();
        async move {
            use hyper::service::Service;
            let service = hyper_util::service::TowerToHyperService::new(router);
            let response = service.call(request).await?;
            if let Some(state) = response.extensions().get::<ResponseDelivery>() {
                delivery.install(state.clone());
            }
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(64)
        .max_buf_size(32_768)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(header_timeout);
    let connection = builder.serve_connection(
        hyper_util::rt::TokioIo::new(DeliveryIo {
            stream,
            delivery: delivery.clone(),
        }),
        service,
    );
    tokio::pin!(connection);
    tokio::select! {
        biased;
        error=delivery.stopped()=>Err(delivery_io_error(error)),
        _=tokio::time::sleep_until(connection_deadline)=>Err(io::Error::new(io::ErrorKind::TimedOut,"connection time bound exceeded")),
        result=&mut connection=>result.map_err(|_|io::Error::new(io::ErrorKind::ConnectionAborted,"HTTP connection closed")),
    }
}
trait NetworkStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> NetworkStream for T {}
/// Listener is supplied only by the explicitly enabled standalone composition.
/// Connections, HTTP header buffers and TLS handshake time are bounded separately
/// from admitted Core document memory. No synchronous I/O runs on this event loop.
pub async fn serve<F: Future<Output = ()>>(
    listener: TcpListener,
    host: Arc<ServiceHost>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: F,
) -> io::Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(host.config.max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! { _ = &mut shutdown => break, permit = slots.clone().acquire_owned() => permit.map_err(|_| invalid())? };
        let accepted =
            tokio::select! { _ = &mut shutdown => break, result = listener.accept() => result? };
        let (socket, peer) = accepted;
        let router = host.router();
        let tls = tls.clone();
        let header_timeout = Duration::from_millis(host.config.header_timeout_ms);
        let connection_timeout =
            Duration::from_millis(host.config.header_timeout_ms + host.config.operation_timeout_ms);
        tasks.spawn(async move {
            let _permit = permit;
            let connection_deadline = tokio::time::Instant::now() + connection_timeout;
            let stream: Box<dyn NetworkStream> = if let Some(tls) = tls {
                match tokio::time::timeout(header_timeout, tls.accept(socket)).await {
                    Ok(Ok(stream)) => Box::new(stream),
                    _ => return,
                }
            } else {
                Box::new(socket)
            };
            let _ =
                serve_connection(stream, peer, router, header_timeout, connection_deadline).await;
        });
        while tasks.try_join_next().is_some() {}
    }
    drop(listener);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    host.executor.idle().await;
    // Final bounded flush on a blocking thread: never longer than the configured
    // deadline, and a dead collector cannot hold the process open past it.
    let telemetry = host.telemetry.clone();
    let _ = tokio::task::spawn_blocking(move || telemetry.shutdown()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::resource::ResourceLimits;

    fn scope() -> ResourceScope {
        let limits = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        budget
            .begin_unslotted(
                limits,
                Arc::new(InvocationControl {
                    cancel: Arc::new(Cancellation::new()),
                    deadline: Deadline::after(Duration::from_secs(30)).unwrap(),
                    progress: None,
                }),
            )
            .unwrap()
    }

    #[test]
    fn inline_hashing_is_refused_for_every_algorithm_but_sha2() {
        let scope = scope();
        for algorithm in HashAlg::ALL {
            let sha2 = matches!(algorithm, HashAlg::Sha256 | HashAlg::Sha512);
            assert_eq!(InlineHash::allows(algorithm), sha2, "{algorithm:?}");
            assert_eq!(
                InlineHash::new(algorithm, &scope).is_ok(),
                sha2,
                "{algorithm:?}"
            );
        }
    }

    #[test]
    fn the_frame_reservation_covers_the_frames_hyper_delivers() {
        // 49,152 and 57,344 byte frames were observed against `max_buf_size(32768)`.
        const { assert!(FRAME_RESERVE_BYTES >= 57_344) };
    }
}
