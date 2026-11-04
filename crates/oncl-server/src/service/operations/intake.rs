use super::*;
use futures_util::stream;
use oncl_api::multipart::BoundedMultipart;
use oncl_core::OperationAdmission;
use oncl_pki::{
    io::{FrozenInput, TemporaryStore},
    resource::ResourceScope,
};

pub(super) struct Prepared {
    pub metadata: OperationMetadata,
    pub payload: Payload,
    pub secrets: Secrets,
    pub reservations: Vec<ResourceReservation>,
    pub failure: Arc<Failure>,
}
/// Bounded, fixed-capacity memory-only secret role. It is never given to a
/// TemporaryStore or a spool and its owned bytes are wiped on drop. (Transient
/// network/parser read buffers outside this owner are not under its control.)
pub(super) struct Secret {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    _reservation: ResourceReservation,
}
#[derive(Default)]
pub(super) struct Secrets(BTreeMap<String, Secret>);
const CONTAINER_SECRET_BYTES: usize = 4 << 20;
const PASSWORD_SECRET_BYTES: usize = 4096;
impl Secrets {
    pub(super) fn bytes(&self, name: &str) -> Result<&[u8], ProcessingError> {
        self.0
            .get(name)
            .map(|s| s.bytes.as_slice())
            .ok_or(ProcessingError::InvalidInput("missing declared secret"))
    }
    pub(super) fn text(&self, name: &str) -> Result<&str, ProcessingError> {
        std::str::from_utf8(self.bytes(name)?)
            .map_err(|_| ProcessingError::InvalidInput("secret is not UTF-8"))
    }
}
pub(super) enum Documents {
    Text(BTreeMap<String, String>),
    Frozen(BTreeMap<String, FrozenInput>),
}
pub(super) enum Document {
    Text(String),
    Frozen(FrozenInput),
}
pub(super) enum DocumentReader<'a> {
    Text(std::io::Cursor<&'a [u8]>),
    Frozen(oncl_pki::io::FrozenReader<'a>),
}
impl Documents {
    pub(super) fn take(&mut self, name: &str) -> Result<Document, OperationError> {
        match self {
            Self::Text(values) => values.remove(name).map(Document::Text),
            Self::Frozen(values) => values.remove(name).map(Document::Frozen),
        }
        .ok_or_else(|| ProcessingError::InvalidInput("missing declared document").into())
    }
}
impl Document {
    pub(super) fn len(&self) -> u64 {
        match self {
            Self::Text(text) => text.len() as u64,
            Self::Frozen(input) => input.len(),
        }
    }
    pub(super) fn reader(
        &mut self,
        scope: &ResourceScope,
    ) -> Result<DocumentReader<'_>, ProcessingError> {
        match self {
            Self::Text(text) => Ok(DocumentReader::Text(std::io::Cursor::new(text.as_bytes()))),
            Self::Frozen(input) => {
                let len = input.len();
                Ok(DocumentReader::Frozen(input.reader(
                    &[oncl_pki::io::Region { offset: 0, len }],
                    scope,
                )?))
            }
        }
    }
}
impl DocumentReader<'_> {
    pub(super) fn source(&mut self) -> Source<'_> {
        match self {
            Self::Text(reader) => {
                let len = reader.get_ref().len() as u64;
                Source::seekable(reader, Some(len))
            }
            Self::Frozen(reader) => reader.source(),
        }
    }
    pub(super) fn finish(&mut self) -> Result<(), ProcessingError> {
        match self {
            Self::Text(_) => Ok(()),
            Self::Frozen(reader) => reader.finish(),
        }
    }
}
#[derive(Default)]
pub(super) struct Failure {
    state: Mutex<Option<Arc<ProcessingError>>>,
}
impl Failure {
    pub(super) fn record(&self, error: ProcessingError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.is_none() {
            *state = Some(Arc::new(error));
        }
    }
    fn stopped(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
    pub(super) fn recover(&self, fallback: ProcessingError) -> ProcessingError {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let original = state.get_or_insert_with(|| Arc::new(fallback)).clone();
        ProcessingError::Io(io::Error::other(SharedFatal(original)))
    }
}

// An intermediate Read/worker bridge owns a shared reference, never the only
// copy of the first cause. Display/Debug do not disclose an underlying I/O path.
struct SharedFatal(Arc<ProcessingError>);
impl std::fmt::Debug for SharedFatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedIntakeFailure")
    }
}
impl std::fmt::Display for SharedFatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original intake failure")
    }
}
impl std::error::Error for SharedFatal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
pub(in crate::service) fn first_cause(mut error: &ProcessingError) -> &ProcessingError {
    while let ProcessingError::Io(carrier) = error {
        match carrier
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<SharedFatal>())
        {
            Some(shared) => error = shared.0.as_ref(),
            None => break,
        }
    }
    error
}
pub(super) struct Ledger {
    scope: ResourceScope,
    failure: Arc<Failure>,
    framing: std::sync::atomic::AtomicU64,
}
impl multer::FramingObserver for Ledger {
    fn observe(&self, bytes: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::sync::atomic::Ordering;
        let result = if self.failure.stopped() {
            Err(ProcessingError::InvalidInput("intake stopped"))
        } else if self
            .framing
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(bytes))
            .is_err()
        {
            Err(ProcessingError::FramingLimit)
        } else {
            self.scope.account_framing(bytes)
        };
        result.map_err(|error| {
            self.failure.record(error);
            Box::new(io::Error::other("multipart framing admission failed"))
                as Box<dyn std::error::Error + Send + Sync>
        })
    }
}
impl oncl_api::multipart::IntakeObserver for Ledger {
    fn admission_limit(&self, limit: oncl_api::multipart::AdmissionLimit) {
        self.failure.record(match limit {
            oncl_api::multipart::AdmissionLimit::Header => ProcessingError::MetadataLimit,
            oncl_api::multipart::AdmissionLimit::WholeStream => ProcessingError::FramingLimit,
        });
    }
}
pub(super) enum Payload {
    Text(BTreeMap<String, String>),
    Multipart {
        parser: BoundedMultipart<'static>,
        wire: Arc<tokio::sync::Mutex<Wire>>,
        metadata_bytes: u64,
        content_length: Option<u64>,
        deadline: Deadline,
        cancel: Arc<Cancellation>,
        ledger: Arc<Ledger>,
    },
}
pub(super) struct Wire {
    body: Body,
    total: u64,
    limit: u64,
    scope: ResourceScope,
    failure: Arc<Failure>,
    tail_ledger: Option<Arc<Ledger>>,
}
async fn frame(
    wire: &Arc<tokio::sync::Mutex<Wire>>,
    deadline: Deadline,
    cancel: &Arc<Cancellation>,
) -> Result<Option<Bytes>, ProcessingError> {
    let mut wire = wire.lock().await;
    if wire.failure.stopped() {
        return Err(ProcessingError::InvalidInput("intake stopped"));
    }
    let result = async {
        wire.scope.checkpoint()?;
        let result = tokio::select! {
            _=cancel.cancelled()=>return Err(ProcessingError::Cancelled),
            result=tokio::time::timeout(deadline.remaining(),wire.body.frame())=>result.map_err(|_|ProcessingError::DeadlineExceeded)?,
        };
        let Some(result) = result else { return Ok(None); };
        let data = result.map_err(|_| ProcessingError::InvalidInput("invalid body frame"))?
            .into_data().map_err(|_| ProcessingError::InvalidInput("trailers unsupported"))?;
        // Record every successful actual read, including the offending over-limit
        // read, before quota refusal or a post-read cancellation/deadline.
        wire.total = wire.total.checked_add(data.len() as u64).ok_or(ProcessingError::FramingLimit)?;
        if wire.total > wire.limit { return Err(ProcessingError::FramingLimit); }
        if let Some(ledger) = &wire.tail_ledger {
            multer::FramingObserver::observe(ledger.as_ref(), data.len() as u64)
                .map_err(|_| ProcessingError::InvalidInput("epilogue admission failed"))?;
        }
        wire.scope.checkpoint()?;
        Ok(Some(data))
    }.await;
    result.map_err(|error| {
        wire.failure.record(error);
        ProcessingError::InvalidInput("intake failed")
    })
}
fn parse_error(failure: &Failure) -> ApiError {
    processing_error(failure.recover(ProcessingError::InvalidInput("invalid multipart framing")))
}
pub(super) async fn prepare(
    metadata: &RequestMetadata,
    body: Body,
    admission: &mut OperationAdmission,
    deadline: Deadline,
    cancel: Arc<Cancellation>,
    precheck: &(dyn Fn(&OperationMetadata) -> Result<(), ApiError> + Sync),
) -> Result<Prepared, ApiError> {
    let content_type = metadata
        .headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(invalid_request)?;
    // One retained Hyper read buffer, bounded by the actual standalone builder's
    // max_buf_size(32768), plus parser header/data and decoded metadata working
    // allocations. Wire chunks are not assumed to be Hyper frame boundaries.
    let transport = admission
        .resources()
        .reserve_memory(32768)
        .map_err(processing_error)?;
    let parsed = admission
        .resources()
        .reserve_memory(JSON_BYTES * 8)
        .map_err(processing_error)?;
    let metadata_reservation = admission
        .resources()
        .reserve_metadata(JSON_BYTES)
        .map_err(processing_error)?;
    let scope = admission.resources().shared_view();
    let failure = Arc::new(Failure::default());
    if content_type == "application/json" {
        if metadata.content_length.is_some_and(|n| n > JSON_BYTES) {
            return Err(ApiError::not_applied(ErrorCode::MetadataLimit));
        }
        let wire = Arc::new(tokio::sync::Mutex::new(Wire {
            body,
            total: 0,
            limit: JSON_BYTES,
            scope,
            failure: failure.clone(),
            tail_ledger: None,
        }));
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(JSON_BYTES as usize)
            .map_err(|_| ApiError::not_applied(ErrorCode::MemoryLimit))?;
        while let Some(data) = frame(&wire, deadline, &cancel)
            .await
            .map_err(|error| processing_error(failure.recover(error)))?
        {
            if bytes.len() as u64 + data.len() as u64 > JSON_BYTES {
                return Err(ApiError::not_applied(ErrorCode::MetadataLimit));
            }
            admission
                .resources()
                .account_framing(data.len() as u64)
                .map_err(processing_error)?;
            bytes.extend_from_slice(&data);
        }
        if metadata
            .content_length
            .is_some_and(|n| n != bytes.len() as u64)
        {
            return Err(invalid_request());
        }
        let request: SmallRequest =
            serde_json::from_slice(&bytes).map_err(|_| invalid_request())?;
        validate_metadata(&request.metadata)?;
        precheck(&request.metadata)?;
        if request
            .metadata
            .parts
            .iter()
            .any(|p| p.role == PartRole::Secret)
        {
            // Secrets never travel in the JSON body: it is a decoded String map.
            return Err(invalid_request());
        }
        for part in &request.metadata.parts {
            if !request.documents.contains_key(&part.name) {
                return Err(invalid_request());
            }
        }
        if request.documents.len() != request.metadata.parts.len() {
            return Err(invalid_request());
        }
        return Ok(Prepared {
            metadata: request.metadata,
            payload: Payload::Text(request.documents),
            secrets: Secrets::default(),
            reservations: vec![transport, parsed, metadata_reservation],
            failure: failure.clone(),
        });
    }
    if !content_type.starts_with("multipart/form-data;") {
        return Err(invalid_request());
    }
    let boundary = multer_boundary(content_type)?;
    let limits = scope.limits();
    let maximum_wire = limits
        .input_bytes
        .checked_add(limits.framing_bytes)
        .and_then(|n| n.checked_add(JSON_BYTES))
        .ok_or_else(invalid_request)?;
    if metadata.content_length.is_some_and(|n| n > maximum_wire) {
        return Err(ApiError::not_applied(ErrorCode::InputLimit));
    }
    let wire = Arc::new(tokio::sync::Mutex::new(Wire {
        body,
        total: 0,
        limit: maximum_wire,
        scope: scope.shared_view(),
        failure: failure.clone(),
        tail_ledger: None,
    }));
    let source = stream::unfold(
        (wire.clone(), cancel.clone()),
        move |(wire, cancel)| async move {
            match frame(&wire, deadline, &cancel).await {
                Ok(Some(bytes)) => Some((Ok::<_, io::Error>(bytes), (wire, cancel))),
                Ok(None) => None,
                Err(_) => Some((
                    Err(io::Error::other("multipart transport failure")),
                    (wire, cancel),
                )),
            }
        },
    );
    let ledger = Arc::new(Ledger {
        scope: scope.shared_view(),
        failure: failure.clone(),
        framing: std::sync::atomic::AtomicU64::new(0),
    });
    let mut parser = BoundedMultipart::new_observed(
        source,
        &boundary,
        maximum_wire,
        &["metadata"],
        ledger.clone(),
    )
    .map_err(|_| invalid_request())?;
    let mut field = parser
        .next_field()
        .await
        .map_err(|_| parse_error(&failure))?
        .ok_or_else(invalid_request)?;
    if field.name() != Some("metadata") || field.file_name().is_some() {
        return Err(invalid_request());
    }
    parser.admit_data();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(JSON_BYTES as usize)
        .map_err(|_| ApiError::not_applied(ErrorCode::MemoryLimit))?;
    while let Some(chunk) = field.chunk().await.map_err(|_| parse_error(&failure))? {
        scope
            .checkpoint()
            .map_err(|error| processing_error(failure.recover(error)))?;
        if bytes.len() as u64 + chunk.len() as u64 > JSON_BYTES {
            return Err(ApiError::not_applied(ErrorCode::MetadataLimit));
        }
        bytes.extend_from_slice(&chunk);
    }
    drop(field);
    let request: OperationMetadata =
        serde_json::from_slice(&bytes).map_err(|_| invalid_request())?;
    validate_metadata(&request)?;
    // Rights are checked before any secret byte is reserved or read.
    precheck(&request)?;
    parser
        .install_fields(
            &request
                .parts
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            request.parts.len(),
        )
        .map_err(|_| invalid_request())?;
    let mut secrets = Secrets::default();
    let mut secret_total = 0u64;
    let secret_kinds = super::dispatch::secret_kinds(&request);
    for part in request.parts.iter().filter(|p| p.role == PartRole::Secret) {
        // Role comes from host-validated metadata; filename/Content-Type are ignored.
        let mut field = parser
            .next_field()
            .await
            .map_err(|_| parse_error(&failure))?
            .ok_or_else(invalid_request)?;
        if field.name() != Some(part.name.as_str()) {
            return Err(invalid_request());
        }
        parser.admit_data();
        let capacity = match secret_kinds.get(part.name.as_str()) {
            Some(super::dispatch::SecretKind::Password) => PASSWORD_SECRET_BYTES,
            Some(super::dispatch::SecretKind::Container) => CONTAINER_SECRET_BYTES,
            None => return Err(invalid_request()),
        };
        let reservation = scope
            .reserve_memory(capacity as u64)
            .map_err(processing_error)?;
        let mut secret = zeroize::Zeroizing::new(Vec::new());
        secret
            .try_reserve_exact(capacity)
            .map_err(|_| ApiError::not_applied(ErrorCode::MemoryLimit))?;
        while let Some(chunk) = field.chunk().await.map_err(|_| parse_error(&failure))? {
            scope
                .checkpoint()
                .map_err(|error| processing_error(failure.recover(error)))?;
            if secret.len() + chunk.len() > capacity {
                return Err(ApiError::not_applied(ErrorCode::MetadataLimit));
            }
            secret.extend_from_slice(&chunk);
        }
        drop(field);
        secret_total += secret.len() as u64;
        secrets.0.insert(
            part.name.clone(),
            Secret {
                bytes: secret,
                _reservation: reservation,
            },
        );
    }
    Ok(Prepared {
        metadata: request,
        secrets,
        failure: failure.clone(),
        payload: Payload::Multipart {
            parser,
            wire,
            metadata_bytes: bytes.len() as u64 + secret_total,
            content_length: metadata.content_length,
            deadline,
            cancel,
            ledger,
        },
        reservations: vec![transport, parsed, metadata_reservation],
    })
}
fn multer_boundary(content_type: &str) -> Result<String, ApiError> {
    // Boundary parameter parsing is delegated to the proven multipart parser.
    multer::parse_boundary(content_type).map_err(|_| invalid_request())
}
struct FieldReader<'a> {
    field: multer::Field<'a>,
    pending: Bytes,
    runtime: tokio::runtime::Handle,
    deadline: Deadline,
    cancel: Arc<Cancellation>,
    failure: Arc<Failure>,
    scope: ResourceScope,
}
impl Read for FieldReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.failure.stopped() {
            return Err(io::Error::other("intake stopped"));
        }
        self.scope.checkpoint().map_err(|error| {
            self.failure.record(error);
            io::Error::other("intake control failed")
        })?;
        loop {
            if !self.pending.is_empty() {
                let n = out.len().min(self.pending.len());
                out[..n].copy_from_slice(&self.pending[..n]);
                self.pending = self.pending.slice(n..);
                return Ok(n);
            }
            let chunk=self.runtime.block_on(async{
                tokio::select!{
                    _=self.cancel.cancelled()=>Err(ProcessingError::Cancelled),
                    result=tokio::time::timeout(self.deadline.remaining(),self.field.chunk())=>match result{
                        Ok(Ok(value))=>Ok(value),
                        Ok(Err(_))=>Err(ProcessingError::InvalidInput("invalid multipart field")),
                        Err(_)=>Err(ProcessingError::DeadlineExceeded),
                    }
                }
            }).map_err(|error| {
                self.failure.record(error);
                io::Error::other("multipart field intake failed")
            })?;
            match chunk {
                Some(bytes) => self.pending = bytes,
                None => return Ok(0),
            }
        }
    }
}
impl Payload {
    pub(super) fn capture(
        self,
        metadata: &OperationMetadata,
        store: Option<&TemporaryStore>,
        ctx: &mut OperationContext,
        runtime: tokio::runtime::Handle,
    ) -> Result<Documents, ProcessingError> {
        match self {
            Self::Text(documents) => Ok(Documents::Text(documents)),
            Self::Multipart {
                mut parser,
                wire,
                metadata_bytes,
                content_length,
                deadline,
                cancel,
                ledger,
            } => {
                let failure = ledger.failure.clone();
                let store = store.ok_or(ProcessingError::InvalidInput(
                    "explicit scratch directory required",
                ))?;
                let mut seen = BTreeSet::new();
                let mut documents = BTreeMap::new();
                let mut payload = metadata_bytes;
                let mut declared = metadata
                    .parts
                    .iter()
                    .filter(|p| p.role == PartRole::Document);
                let documents_expected = declared.clone().count();
                while let Some(field) = runtime.block_on(parser.next_field()).map_err(|_| {
                    failure.recover(ProcessingError::InvalidInput("invalid multipart framing"))
                })? {
                    ctx.resources()
                        .checkpoint()
                        .map_err(|error| failure.recover(error))?;
                    let name = field
                        .name()
                        .ok_or(ProcessingError::InvalidInput(
                            "missing multipart field name",
                        ))?
                        .to_owned();
                    let part = metadata
                        .parts
                        .iter()
                        .find(|p| p.name == name)
                        .ok_or(ProcessingError::InvalidInput("unknown multipart role"))?;
                    // Wire order is the declared order: secrets first, then documents.
                    if declared.next().map(|p| p.name.as_str()) != Some(name.as_str()) {
                        return Err(ProcessingError::InvalidInput("multipart order mismatch"));
                    }
                    if part.role != PartRole::Document || !seen.insert(name.clone()) {
                        return Err(ProcessingError::InvalidInput(
                            "duplicate or invalid multipart role",
                        ));
                    }
                    parser.admit_data();
                    let mut reader = FieldReader {
                        field,
                        pending: Bytes::new(),
                        runtime: runtime.clone(),
                        deadline,
                        cancel: cancel.clone(),
                        failure: failure.clone(),
                        scope: ctx.resources().shared_view(),
                    };
                    let frozen = FrozenInput::capture(
                        Source::sequential(&mut reader, None),
                        store,
                        ctx.resources(),
                    )
                    .map_err(|error| failure.recover(error))?;
                    payload = payload
                        .checked_add(frozen.len())
                        .ok_or(ProcessingError::FramingLimit)?;
                    documents.insert(name, frozen);
                }
                drop(parser);
                // multer stops at the closing delimiter. Read the remaining HTTP
                // entity as well so epilogues/lying lengths cannot evade quotas.
                let admitted_total = runtime.block_on(async { wire.lock().await.total });
                let known = ledger.framing.load(std::sync::atomic::Ordering::SeqCst);
                let remaining = admitted_total
                    .checked_sub(payload)
                    .and_then(|n| n.checked_sub(known))
                    .ok_or(ProcessingError::FramingLimit)?;
                multer::FramingObserver::observe(ledger.as_ref(), remaining).map_err(|_| {
                    failure.recover(ProcessingError::InvalidInput("epilogue admission failed"))
                })?;
                runtime.block_on(async {
                    wire.lock().await.tail_ledger = Some(ledger.clone());
                });
                while runtime
                    .block_on(frame(&wire, deadline, &cancel))
                    .map_err(|error| failure.recover(error))?
                    .is_some()
                {}
                let total = runtime.block_on(async { wire.lock().await.total });
                if content_length.is_some_and(|n| n != total) || seen.len() != documents_expected {
                    return Err(ProcessingError::InvalidInput(
                        "multipart length or field mismatch",
                    ));
                }
                Ok(Documents::Frozen(documents))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{BoundedExecutor, ExecutorConfig};
    use oncl_core::ExecutionGrant;
    use oncl_pki::resource::ResourceLimits;
    use std::sync::Condvar;

    struct Release(Arc<(Mutex<bool>, Condvar)>);
    impl Release {
        fn open(&self) {
            let (lock, changed) = &*self.0;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
        }
    }
    impl Drop for Release {
        fn drop(&mut self) {
            self.open();
        }
    }
    #[derive(Clone, Copy)]
    enum First {
        Framing,
        Metadata,
        Cancelled,
        Deadline,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn original_first_fatal_survives_recovery_while_worker_delivery_is_held() {
        for (first, expected, status) in [
            (First::Framing, ErrorCode::FramingLimit, 413),
            (First::Metadata, ErrorCode::MetadataLimit, 413),
            (First::Cancelled, ErrorCode::Cancelled, 408),
            (First::Deadline, ErrorCode::DeadlineExceeded, 504),
        ] {
            let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
                max_in_flight: 1,
                framing_bytes: 32,
                metadata_bytes: 32,
                operation_timeout: Duration::from_millis(500),
                ..ResourceLimits::default()
            }))
            .unwrap();
            let cancel = Arc::new(Cancellation::new());
            let ctx = engine
                .begin(
                    ExecutionGrant::new([Action::Hash]),
                    OperationPolicy::strict_online(),
                    cancel.clone(),
                )
                .unwrap();
            let deadline = ctx.deadline();
            let executor = BoundedExecutor::new(ExecutorConfig {
                blocking_workers: 1,
                queue_capacity: 0,
                admission_wait: Duration::from_millis(100),
            })
            .unwrap();
            let failure = Arc::new(Failure::default());
            let worker_failure = failure.clone();
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let release = Release(gate.clone());
            let (entered, observed) = tokio::sync::oneshot::channel();
            let work = executor
                .submit(ctx, move |ctx| {
                    let cause = match first {
                        First::Framing => ctx.resources().account_framing(33).err(),
                        First::Metadata => ctx.resources().reserve_metadata(33).err(),
                        First::Cancelled => {
                            cancel.cancel();
                            ctx.resources().checkpoint().err()
                        }
                        First::Deadline => None,
                    };
                    let recovered = cause.map(|cause| {
                        worker_failure.record(cause);
                        worker_failure.recover(ProcessingError::InvalidInput("worker bridge"))
                    });
                    let _ = entered.send(());
                    let (lock, changed) = &*gate;
                    let mut open = lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    while !*open {
                        open = changed
                            .wait(open)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                    drop(open);
                    match recovered {
                        Some(error) => Err(error),
                        None => Ok(()),
                    }
                })
                .await
                .unwrap();
            observed.await.unwrap(); // Actual quota/control cause was recovered.
            let error = match super::super::await_worker(work, deadline, &failure).await {
                Err(error) => error,
                Ok(_) => panic!("held native work cannot publish before release"),
            };
            assert_eq!(error.code, expected);
            assert_eq!(error.into_response().status().as_u16(), status);
            assert_eq!(
                executor.running(),
                1,
                "deadline must not release native permit"
            );
            assert!(matches!(engine.admit(Arc::new(Cancellation::new())),
                Err(error) if error.code() == oncl_core::ErrorCode::CapacityExceeded));
            release.open();
            executor.idle().await;
            assert_eq!(executor.running(), 0);
        }
    }

    #[test]
    fn repeated_bridges_retain_the_same_owned_io_cause() {
        let failure = Failure::default();
        failure.record(ProcessingError::Io(io::Error::from_raw_os_error(5)));
        let first = failure.recover(ProcessingError::FramingLimit);
        let second = failure.recover(ProcessingError::DeadlineExceeded);
        assert!(std::ptr::eq(first_cause(&first), first_cause(&second)));
        drop(first);
        drop(second);
        let final_bridge = failure.recover(ProcessingError::Cancelled);
        match first_cause(&final_bridge) {
            ProcessingError::Io(original) => assert_eq!(original.raw_os_error(), Some(5)),
            _ => panic!("original I/O cause was replaced"),
        }
        assert!(failure.stopped());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successful_worker_wait_preserves_result_context_without_recording_failure() {
        let engine =
            Arc::new(Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap());
        let ctx = engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Cancellation::new()),
            )
            .unwrap();
        let original_id = ctx.id();
        let deadline = ctx.deadline();
        let executor = BoundedExecutor::new(ExecutorConfig {
            blocking_workers: 1,
            queue_capacity: 0,
            admission_wait: Duration::from_millis(100),
        })
        .unwrap();
        let failure = Failure::default();
        let worker_engine = engine.clone();
        let work = executor
            .submit(ctx, move |ctx| {
                worker_engine
                    .hash(
                        HashAlg::Sha256,
                        Source::sequential(&mut &b"abc"[..], None),
                        ctx,
                    )
                    .map_err(|error| match error {
                        OperationError::Processing(error) => error,
                        _ => ProcessingError::InvalidInput("unexpected SDK error"),
                    })
            })
            .await
            .unwrap();
        let output = super::super::await_worker(work, deadline, &failure)
            .await
            .unwrap();
        assert_eq!(output.context.id(), original_id);
        assert_eq!(
            crate::auth::encode(output.value.digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!failure.stopped());
        drop(output);
        executor.idle().await;
        assert!(engine.admit(Arc::new(Cancellation::new())).is_ok());
    }
}
