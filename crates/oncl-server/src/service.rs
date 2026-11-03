pub(crate) mod operations;

use crate::{
    audit::{AuditBinding, AuditConfig, AuditHealth, DurableAuditGuard},
    auth::{AccessPolicy, Principal},
    config::{Exposure, ServerConfig, invalid, normalized_peer},
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
    store: Option<oncl_pki::io::TemporaryStore>,
    output_store: Option<Arc<operations::artifact::ArtifactStore>>,
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
    pub fn new(mut config: ServerConfig) -> io::Result<Arc<Self>> {
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
            .with_validation(config.pki.services()?);
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
        Ok(Arc::new(Self {
            engine,
            policy,
            executor,
            keys,
            audit,
            config,
            store,
            output_store,
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
    let code = match operations::intake::first_cause(&error) {
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
                    progress: None,
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
            let disconnect = Arc::new(CancelOnDrop(cancel.clone()));
            let (ctx, binding, metadata_reservation, deadline) = admitted?;
            let runtime = tokio::runtime::Handle::current();
            let worker_cancel = cancel.clone();
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
                        cancel: worker_cancel,
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
    fn operations(&self, metadata: RequestMetadata, body: Body) -> ResponseFuture {
        self.dispatch_operations(metadata, body)
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
    Ok(())
}
