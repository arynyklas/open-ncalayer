use crate::{
    audit::{AuditBinding, AuditConfig, AuditHealth, DurableAuditGuard},
    auth::{AccessPolicy, Principal},
    config::{Exposure, ServerConfig, invalid},
    executor::{BoundedExecutor, CancelOnDrop, Cancellation},
    keys::{KeyBinding, OperatorKeys},
};
use axum::{
    body::{Body, Bytes},
    extract::ConnectInfo,
    http::{HeaderValue, Request},
    response::IntoResponse,
};
use http_body_util::BodyExt;
use oncl_api::{
    dto::HashResponse,
    error::{ApiError, ErrorCode},
    server::{HashHost, RequestMetadata, ResponseFuture},
};
use oncl_core::{
    Action, Engine, EngineServices, OperationContext, OperationError, OperationPolicy,
};
use oncl_pki::{
    io::Source,
    key::HashAlg,
    resource::{
        Deadline, OperationControl, ProcessingError, Progress, ResourceReservation, SharedBudget,
    },
};
use oncl_token::{PcscBackend, Tokens, execution::TokenGateRegistry};
use std::{
    future::Future,
    io::{self, Read},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};

pub struct ServiceHost {
    pub engine: Arc<Engine>,
    pub policy: Arc<AccessPolicy>,
    pub executor: BoundedExecutor,
    pub keys: Arc<OperatorKeys>,
    pub audit: DurableAuditGuard,
    config: ServerConfig,
}
struct InvocationControl {
    cancel: Arc<Cancellation>,
    deadline: Deadline,
}
impl OperationControl for InvocationControl {
    fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError> {
        self.deadline.checkpoint()?;
        self.cancel.checkpoint(progress)
    }
}
impl ServiceHost {
    /// Synchronous startup only, before the network runtime/listener. Configuration
    /// owns all mounts and the journal; an existing journal requires explicit recovery.
    pub fn new(config: ServerConfig) -> io::Result<Arc<Self>> {
        config.validate()?;
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
            let tokens = Tokens::new(Arc::new(PcscBackend::new()), true);
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
        let audit = if config.audit_directory.exists() {
            DurableAuditGuard::open(audit_config)?
        } else {
            DurableAuditGuard::create(audit_config)?
        };
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
        let engine = Arc::new(
            Engine::new(
                EngineServices::hash_only(config.limits())
                    .with_shared_budget(budget)
                    .with_keys(keys.clone(), Arc::new(audit.clone())),
            )
            .map_err(|_| invalid())?,
        );
        let executor = BoundedExecutor::new(config.executor()).map_err(|_| invalid())?;
        Ok(Arc::new(Self {
            engine,
            policy,
            executor,
            keys,
            audit,
            config,
        }))
    }
    fn principal(&self, metadata: &RequestMetadata) -> Result<Principal, ApiError> {
        let denied = || ApiError::not_applied(ErrorCode::PermissionDenied);
        if let Exposure::TrustedProxy { peers } = &self.config.exposure
            && !peers.contains(&metadata.peer.ip())
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
        if self.audit.health() != AuditHealth::Healthy {
            return Err(ApiError::not_applied(ErrorCode::AuditUnavailable));
        }
        let grant = self
            .policy
            .authorize(principal, action, key, None)
            .map_err(|_| ApiError::not_applied(ErrorCode::PermissionDenied))?;
        let ctx = self
            .engine
            .begin(grant, OperationPolicy::strict_online(), control)
            .map_err(core_error)?;
        let binding = if matches!(action, Action::Sign | Action::SignDigest) {
            Some(
                self.audit
                    .bind(
                        &ctx,
                        principal.audit_label(),
                        self.keys
                            .labels()
                            .filter(|(id, _)| ctx.grant().allows_key(id)),
                    )
                    .map_err(|_| ApiError::not_applied(ErrorCode::AuditUnavailable))?,
            )
        } else {
            None
        };
        Ok((ctx, binding))
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
fn processing_error(error: ProcessingError) -> ApiError {
    let code = match error {
        ProcessingError::CapacityExceeded => ErrorCode::CapacityExceeded,
        ProcessingError::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        ProcessingError::Cancelled => ErrorCode::Cancelled,
        ProcessingError::InputLimit
        | ProcessingError::ContainerLimit
        | ProcessingError::FramingLimit => ErrorCode::InputLimit,
        ProcessingError::MemoryLimit => ErrorCode::MemoryLimit,
        ProcessingError::TempLimit => ErrorCode::TempLimit,
        ProcessingError::MetadataLimit => ErrorCode::MetadataLimit,
        ProcessingError::OutputLimit => ErrorCode::OutputLimit,
        ProcessingError::Io(_) | ProcessingError::InvalidInput(_) => ErrorCode::InvalidRequest,
        ProcessingError::InvalidLimits => ErrorCode::Internal,
    };
    ApiError::not_applied(code)
}
fn core_error(error: OperationError) -> ApiError {
    match error {
        OperationError::Processing(error) => processing_error(error),
        OperationError::PermissionDenied => ApiError::not_applied(ErrorCode::PermissionDenied),
        _ => ApiError::not_applied(ErrorCode::Internal),
    }
}
impl HashHost for ServiceHost {
    fn hash(&self, metadata: RequestMetadata, body: Body) -> ResponseFuture {
        let engine = self.engine.clone();
        let executor = self.executor.clone();
        let deadline = Deadline::after(Duration::from_millis(self.config.operation_timeout_ms));
        let cancel = Arc::new(Cancellation::new());
        let admitted = deadline.map_err(processing_error).and_then(|deadline| {
            let principal = self.principal(&metadata)?;
            let (mut ctx, binding) = self.begin(
                &principal,
                Action::Hash,
                None,
                Arc::new(InvocationControl {
                    cancel: cancel.clone(),
                    deadline,
                }),
            )?;
            if metadata
                .content_length
                .is_some_and(|n| n > ctx.resources().limits().input_bytes)
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
            let metadata_reservation = ctx
                .resources()
                .reserve_metadata(header_bytes)
                .map_err(processing_error)?;
            Ok((ctx, binding, metadata_reservation, deadline))
        });
        Box::pin(async move {
            let _disconnect = CancelOnDrop(cancel.clone());
            let (ctx, binding, metadata_reservation, deadline) = admitted?;
            let runtime = tokio::runtime::Handle::current();
            let work = executor
                .submit(ctx, move |ctx| {
                    let _binding = binding;
                    let _metadata = metadata_reservation;
                    let _ingress = ctx.resources().reserve_memory(32_768)?;
                    let mut reader = BodyReader {
                        body,
                        pending: Bytes::new(),
                        runtime,
                        deadline,
                        cancel,
                    };
                    let report = engine
                        .hash(
                            HashAlg::Sha256,
                            Source::sequential(&mut reader, metadata.content_length),
                            ctx,
                        )
                        .map_err(|error| match error {
                            OperationError::Processing(error) => error,
                            _ => ProcessingError::InvalidInput("hash failed"),
                        })?;
                    if metadata
                        .content_length
                        .is_some_and(|n| n != report.bytes_in)
                    {
                        return Err(ProcessingError::InvalidInput("content length mismatch"));
                    }
                    let reservation = ctx.resources().reserve_memory(512)?;
                    let dto = HashResponse {
                        operation_id: report.id.get(),
                        algorithm: "sha256".into(),
                        digest: crate::auth::encode(report.digest.as_bytes()),
                        bytes_in: report.bytes_in,
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
            let ((bytes, reservation), ctx) = (output.value, output.context);
            let owner = ResponseOwner {
                bytes,
                _context: ctx,
                _reservation: reservation,
            };
            let mut response = Body::from(Bytes::from_owner(owner)).into_response();
            response
                .headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            Ok(response)
        })
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
    bytes: Vec<u8>,
    _context: OperationContext,
    _reservation: ResourceReservation,
}
impl AsRef<[u8]> for ResponseOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
struct BodyReader {
    body: Body,
    pending: Bytes,
    runtime: tokio::runtime::Handle,
    deadline: Deadline,
    cancel: Arc<Cancellation>,
}
impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.pending.is_empty() {
                let n = out.len().min(self.pending.len());
                out[..n].copy_from_slice(&self.pending[..n]);
                self.pending = self.pending.slice(n..);
                return Ok(n);
            }
            let frame = self.runtime.block_on(async {
                tokio::select! {
                    _ = self.cancel.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted,"cancelled")),
                    result = tokio::time::timeout(self.deadline.remaining(),self.body.frame()) => match result {
                        Ok(Some(Ok(frame))) => Ok(Some(frame)), Ok(None) => Ok(None), Ok(Some(Err(_))) => Err(io::Error::new(io::ErrorKind::InvalidData,"invalid request body")), Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut,"deadline exceeded"))
                    }
                }
            })?;
            match frame {
                None => return Ok(0),
                Some(frame) => {
                    if let Ok(data) = frame.into_data() {
                        if data.len() > 32_768 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "body frame exceeds ingress bound",
                            ));
                        }
                        self.pending = data;
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trailers unsupported",
                        ));
                    }
                }
            }
        }
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
            let service =
                hyper::service::service_fn(move |mut request: Request<hyper::body::Incoming>| {
                    request.extensions_mut().insert(ConnectInfo(peer));
                    let router = router.clone();
                    async move {
                        use hyper::service::Service;
                        use std::convert::Infallible;
                        let service = hyper_util::service::TowerToHyperService::new(router);
                        let response = service.call(request).await;
                        response.map_err(|never: Infallible| match never {})
                    }
                });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(false)
                .max_headers(64)
                .max_buf_size(32_768)
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(header_timeout);
            let _ = tokio::time::timeout_at(
                connection_deadline,
                builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service),
            )
            .await;
        });
        while tasks.try_join_next().is_some() {}
    }
    drop(listener);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    host.executor.idle().await;
    Ok(())
}
