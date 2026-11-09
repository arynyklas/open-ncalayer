use super::*;
use crate::pace::{PaceConfig, UploadPace};
use futures_util::stream;
use oncl_api::multipart::BoundedMultipart;
use oncl_core::OperationAdmission;
use oncl_pki::{
    io::{FrozenInput, InputSpool, TemporaryStore},
    resource::{IO_CHUNK_BYTES, ResourceScope},
};

/// What the metadata part of a request settled (and its secrets): everything but the
/// documents, which [`Payload::capture`] takes from the rest of the body.
pub(super) struct Prepared {
    pub metadata: OperationMetadata,
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
pub(super) enum DocumentMut<'a> {
    Text(&'a String),
    Frozen(&'a mut FrozenInput),
}
impl DocumentMut<'_> {
    pub(super) fn len(&self) -> u64 {
        match self {
            Self::Text(t) => t.len() as u64,
            Self::Frozen(f) => f.len(),
        }
    }
    pub(super) fn reader(
        &mut self,
        scope: &ResourceScope,
    ) -> Result<DocumentReader<'_>, ProcessingError> {
        match self {
            Self::Text(t) => Ok(DocumentReader::Text(std::io::Cursor::new(t.as_bytes()))),
            Self::Frozen(input) => {
                let reader = if input.is_wire() {
                    // Host-side checks only: the engine never reads this replay.
                    input.wire_inspection_reader(scope)?
                } else {
                    let len = input.len();
                    input.reader(&[oncl_pki::io::Region { offset: 0, len }], scope)?
                };
                Ok(DocumentReader::Frozen(reader))
            }
        }
    }
}
pub(super) enum DocumentReader<'a> {
    Text(std::io::Cursor<&'a [u8]>),
    Frozen(oncl_pki::io::FrozenReader<'a>),
}
impl Documents {
    /// Borrow a declared document without consuming it (for pre-key sizing).
    pub(super) fn get_mut(&mut self, name: &str) -> Option<DocumentMut<'_>> {
        match self {
            Self::Text(values) => values.get(name).map(DocumentMut::Text),
            Self::Frozen(values) => values.get_mut(name).map(DocumentMut::Frozen),
        }
    }
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
                // Unclassified wire is read by the engine as an external source, which
                // charges and classifies it; any other document is an admitted snapshot.
                let reader = if input.is_wire() {
                    input.wire_reader(scope)?
                } else {
                    let len = input.len();
                    input.reader(&[oncl_pki::io::Region { offset: 0, len }], scope)?
                };
                Ok(DocumentReader::Frozen(reader))
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
        staging: Arc<Staging>,
        metadata_bytes: u64,
        content_length: Option<u64>,
        deadline: Deadline,
        cancel: Arc<Cancellation>,
        ledger: Arc<Ledger>,
    },
}
pub(super) struct Wire {
    body: Body,
    pace: UploadPace,
    total: u64,
    /// Shared so that the request can widen it once its metadata is known, without waiting
    /// for the mutex a pending frame read holds.
    limit: Arc<std::sync::atomic::AtomicU64>,
    scope: ResourceScope,
    failure: Arc<Failure>,
    tail_ledger: Option<Arc<Ledger>>,
    /// The document being taken, when there is one: its buffered bytes are written before
    /// the server waits for the client (see [`Staging`]).
    staging: Option<Arc<Staging>>,
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
        let result = {
            let Wire {
                body,
                pace,
                staging,
                ..
            } = &mut *wire;
            let unused = tokio::sync::Notify::new();
            let staging = staging.as_deref();
            let dirty = staging.map_or(&unused, |staging| &staging.dirty);
            let flush = || async {
                match staging {
                    Some(staging) => staging.flush().await,
                    None => Ok(()),
                }
            };
            tokio::select! {
                _=cancel.cancelled()=>return Err(ProcessingError::Cancelled),
                result=pace.frame_after(body,deadline,dirty,flush)=>result?,
            }
        };
        let Some(result) = result else {
            return Ok(None);
        };
        let data = result
            .map_err(|_| ProcessingError::InvalidInput("invalid body frame"))?
            .into_data()
            .map_err(|_| ProcessingError::InvalidInput("trailers unsupported"))?;
        // Record every successful actual read, including the offending over-limit
        // read, before quota refusal or a post-read cancellation/deadline.
        wire.total = wire
            .total
            .checked_add(data.len() as u64)
            .ok_or(ProcessingError::FramingLimit)?;
        if wire.total > wire.limit.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ProcessingError::FramingLimit);
        }
        if let Some(ledger) = &wire.tail_ledger {
            multer::FramingObserver::observe(ledger.as_ref(), data.len() as u64)
                .map_err(|_| ProcessingError::InvalidInput("epilogue admission failed"))?;
        }
        wire.scope.checkpoint()?;
        Ok(Some(data))
    }
    .await;
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
    pace: PaceConfig,
    cancel: Arc<Cancellation>,
    precheck: &(dyn Fn(&OperationMetadata) -> Result<(), ApiError> + Sync),
) -> Result<(Prepared, Payload), ApiError> {
    let content_type = metadata
        .headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(invalid_request)?;
    // One retained Hyper read buffer plus the frame one read adds to it (a frame is not
    // bounded by the builder's max_buf_size(32768), see `FRAME_RESERVE_BYTES`), plus parser
    // header/data and decoded metadata working allocations. Wire chunks are not assumed to
    // be Hyper frame boundaries.
    let transport = admission
        .resources()
        .reserve_memory(crate::service::FRAME_RESERVE_BYTES)
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
            pace: UploadPace::new(pace),
            total: 0,
            limit: Arc::new(std::sync::atomic::AtomicU64::new(JSON_BYTES)),
            scope,
            failure: failure.clone(),
            tail_ledger: None,
            staging: None,
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
        return Ok((
            Prepared {
                metadata: request.metadata,
                secrets: Secrets::default(),
                reservations: vec![transport, parsed, metadata_reservation],
                failure: failure.clone(),
            },
            Payload::Text(request.documents),
        ));
    }
    if !content_type.starts_with("multipart/form-data;") {
        return Err(invalid_request());
    }
    let boundary = multer_boundary(content_type)?;
    let limits = scope.limits();
    // Everything but the document bytes: multipart framing and the metadata part.
    let ordinary_wire = limits
        .input_bytes
        .saturating_add(limits.framing_bytes)
        .saturating_add(JSON_BYTES);
    // The input of a verify, extend, extract or sign item may be a signed result: its
    // document may be followed by up to `container_bytes` of signature bytes that the engine
    // classifies. A declared length is checked against this ceiling at once; the counted wire
    // starts at the plain ceiling and is widened when the metadata names such an input.
    let maximum_wire = ordinary_wire.saturating_add(limits.container_bytes);
    if metadata.content_length.is_some_and(|n| n > maximum_wire) {
        return Err(ApiError::not_applied(ErrorCode::InputLimit));
    }
    let wire_limit = Arc::new(std::sync::atomic::AtomicU64::new(ordinary_wire));
    let staging = Staging::new();
    let wire = Arc::new(tokio::sync::Mutex::new(Wire {
        body,
        pace: UploadPace::new(pace),
        total: 0,
        limit: wire_limit.clone(),
        scope: scope.shared_view(),
        failure: failure.clone(),
        tail_ledger: None,
        staging: Some(staging.clone()),
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
    // The ceiling of a request is the one of a plain upload unless it has an input that may
    // already be signed: only then the metadata widens it by the container allowance.
    if super::dispatch::wire_inputs(&request).next().is_some() {
        wire_limit.store(maximum_wire, std::sync::atomic::Ordering::SeqCst);
    } else if metadata.content_length.is_some_and(|n| n > ordinary_wire) {
        return Err(ApiError::not_applied(ErrorCode::InputLimit));
    }
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
    Ok((
        Prepared {
            metadata: request,
            secrets,
            failure: failure.clone(),
            reservations: vec![transport, parsed, metadata_reservation],
        },
        Payload::Multipart {
            parser,
            wire,
            staging,
            metadata_bytes: bytes.len() as u64 + secret_total,
            content_length: metadata.content_length,
            deadline,
            cancel,
            ledger,
        },
    ))
}
fn multer_boundary(content_type: &str) -> Result<String, ApiError> {
    // Boundary parameter parsing is delegated to the proven multipart parser.
    multer::parse_boundary(content_type).map_err(|_| invalid_request())
}
/// The bytes of one document between the network and its spool. Pieces (a Hyper frame is
/// 16-57 KiB) are gathered up to `IO_CHUNK_BYTES` and written to the spool in one blocking
/// section, so the disk is not visited once per frame. What is gathered is written
/// (flushed) before the server waits for the client with no frame ready (`Wire` does this,
/// before the pace timer starts, so the write is never charged to the client and the bytes
/// are in the spool while the server waits), and at the end of the document. Only the disk
/// is waited for in a blocking section, never the client; a section ends by itself also
/// when the request that started it is gone (the spool and the buffer are then dropped
/// there: the file is deleted and its reservations are released; the buffer's own memory
/// charge is released with the request, up to one write earlier than the buffer itself).
pub(super) struct Staging {
    inner: std::sync::Mutex<StagingState>,
    /// Told when bytes were gathered, so that a wait that is already running writes them.
    dirty: tokio::sync::Notify,
    #[cfg(test)]
    writes: std::sync::atomic::AtomicUsize,
}
struct StagingState {
    spool: Option<InputSpool>,
    buffer: Vec<u8>,
}
impl Staging {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(StagingState {
                spool: None,
                buffer: Vec::new(),
            }),
            dirty: tokio::sync::Notify::new(),
            #[cfg(test)]
            writes: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    /// Starts a document. The buffer (`IO_CHUNK_BYTES`, charged by the caller) is allocated
    /// once and serves every document of the request.
    fn begin(&self, spool: InputSpool) -> Result<(), ProcessingError> {
        let mut state = self.state();
        let wanted = IO_CHUNK_BYTES - state.buffer.len();
        state
            .buffer
            .try_reserve_exact(wanted)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        state.spool = Some(spool);
        Ok(())
    }
    fn state(&self) -> std::sync::MutexGuard<'_, StagingState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Takes `data`, writing every full chunk.
    async fn push(&self, mut data: &[u8]) -> Result<(), ProcessingError> {
        while !data.is_empty() {
            let full = {
                let mut state = self.state();
                let room = IO_CHUNK_BYTES - state.buffer.len();
                let (head, rest) = data.split_at(room.min(data.len()));
                state.buffer.extend_from_slice(head);
                data = rest;
                state.buffer.len() == IO_CHUNK_BYTES
            };
            if full {
                self.flush().await?;
            } else {
                self.dirty.notify_one();
            }
        }
        Ok(())
    }
    /// Writes what is buffered (nothing: no hop).
    async fn flush(&self) -> Result<(), ProcessingError> {
        let (mut spool, mut buffer) = {
            let mut state = self.state();
            if state.buffer.is_empty() {
                return Ok(());
            }
            // Bytes with no spool cannot be: `begin` comes first and `finish` flushes.
            let spool = state.spool.take().ok_or(ProcessingError::InvalidInput(
                "spool write did not complete",
            ))?;
            (spool, std::mem::take(&mut state.buffer))
        };
        #[cfg(test)]
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (spool, buffer) = tokio::task::spawn_blocking(move || {
            let result = spool.push(&buffer);
            buffer.clear();
            result.map(|()| (spool, buffer))
        })
        .await
        .map_err(|_| ProcessingError::InvalidInput("spool write did not complete"))??;
        let mut state = self.state();
        state.spool = Some(spool);
        state.buffer = buffer;
        Ok(())
    }
    /// The end of the document: everything written, the spool given back.
    async fn finish(&self) -> Result<InputSpool, ProcessingError> {
        self.flush().await?;
        self.state()
            .spool
            .take()
            .ok_or(ProcessingError::InvalidInput(
                "spool write did not complete",
            ))
    }
}
impl Payload {
    /// Takes every declared document of the body into the temporary store: the upload phase.
    /// Waiting for the client is asynchronous (pace rules, operation deadline and
    /// cancellation as ever); a spool takes the bytes as they arrive and only its chunk
    /// writes to disk run, one at a time, in short blocking sections. No native worker and no
    /// `max_in_flight` slot is involved: `scope` is the admission's (unslotted) one, and the
    /// spools, their temp reservations and the chunk memory are charged to it.
    pub(super) async fn capture(
        self,
        metadata: &OperationMetadata,
        store: Option<&TemporaryStore>,
        scope: &mut ResourceScope,
    ) -> Result<Documents, ProcessingError> {
        match self {
            Self::Text(documents) => Ok(Documents::Text(documents)),
            Self::Multipart {
                mut parser,
                wire,
                staging,
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
                let mut buffer_charge: Option<ResourceReservation> = None;
                let mut seen = BTreeSet::new();
                let mut documents = BTreeMap::new();
                let mut payload = metadata_bytes;
                let mut declared = metadata
                    .parts
                    .iter()
                    .filter(|p| p.role == PartRole::Document);
                let documents_expected = declared.clone().count();
                while let Some(mut field) = parser.next_field().await.map_err(|_| {
                    failure.recover(ProcessingError::InvalidInput("invalid multipart framing"))
                })? {
                    scope.checkpoint().map_err(|error| failure.recover(error))?;
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
                    // The input of a verify, extend, extract or sign item may be a signed result:
                    // it is spooled as unclassified wire and the engine, which reads it like
                    // the SDK and the CLI read a file, charges `input_bytes` for the document
                    // and the format's container allowance for the signature. Every other part
                    // is a document and stays within `input_bytes` at once. Evidence is validation
                    // material, bounded per item and not charged to the document allowance.
                    let spool = if super::dispatch::wire_inputs(metadata).any(|n| n == name) {
                        InputSpool::wire(store, scope, None)
                    } else if super::dispatch::evidence_inputs(metadata).any(|n| n == name) {
                        InputSpool::wire(store, scope, Some(super::dispatch::EVIDENCE_ITEM_BYTES))
                    } else {
                        InputSpool::document(store, scope)
                    }
                    .map_err(|error| failure.recover(error))?;
                    // The gathering buffer is charged like any chunk buffer, for as long as
                    // the request is.
                    if buffer_charge.is_none() {
                        buffer_charge = Some(
                            scope
                                .reserve_memory(IO_CHUNK_BYTES as u64)
                                .map_err(|error| failure.recover(error))?,
                        );
                    }
                    staging
                        .begin(spool)
                        .map_err(|error| failure.recover(error))?;
                    loop {
                        if failure.stopped() {
                            return Err(
                                failure.recover(ProcessingError::InvalidInput("intake stopped"))
                            );
                        }
                        scope.checkpoint().map_err(|error| failure.recover(error))?;
                        let chunk = tokio::select! {
                            _ = cancel.cancelled() => Err(ProcessingError::Cancelled),
                            result = tokio::time::timeout(deadline.remaining(), field.chunk()) => match result {
                                Ok(Ok(value)) => Ok(value),
                                Ok(Err(_)) => Err(ProcessingError::InvalidInput("invalid multipart field")),
                                Err(_) => Err(ProcessingError::DeadlineExceeded),
                            }
                        }
                        .map_err(|error| failure.recover(error))?;
                        let Some(bytes) = chunk else { break };
                        staging
                            .push(&bytes)
                            .await
                            .map_err(|error| failure.recover(error))?;
                    }
                    drop(field);
                    let spool = staging
                        .finish()
                        .await
                        .map_err(|error| failure.recover(error))?;
                    let frozen = spool.finish().map_err(|error| failure.recover(error))?;
                    payload = payload
                        .checked_add(frozen.len())
                        .ok_or(ProcessingError::FramingLimit)?;
                    documents.insert(name, frozen);
                }
                drop(parser);
                // multer stops at the closing delimiter. Read the remaining HTTP
                // entity as well so epilogues/lying lengths cannot evade quotas.
                let admitted_total = wire.lock().await.total;
                let known = ledger.framing.load(std::sync::atomic::Ordering::SeqCst);
                let remaining = admitted_total
                    .checked_sub(payload)
                    .and_then(|n| n.checked_sub(known))
                    .ok_or(ProcessingError::FramingLimit)?;
                multer::FramingObserver::observe(ledger.as_ref(), remaining).map_err(|_| {
                    failure.recover(ProcessingError::InvalidInput("epilogue admission failed"))
                })?;
                wire.lock().await.tail_ledger = Some(ledger.clone());
                while frame(&wire, deadline, &cancel)
                    .await
                    .map_err(|error| failure.recover(error))?
                    .is_some()
                {}
                let total = wire.lock().await.total;
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
    use futures_util::StreamExt;
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

    fn staging_scope(memory: u64, directory: &std::path::Path) -> (TemporaryStore, ResourceScope) {
        let limits = ResourceLimits {
            input_bytes: 64 << 20,
            memory_bytes: memory,
            ..ResourceLimits::default()
        };
        let scope = Arc::new(oncl_pki::resource::SharedBudget::new(limits.clone()).unwrap())
            .begin(limits, Arc::new(Cancellation::new()))
            .unwrap();
        (TemporaryStore::new(directory).unwrap(), scope)
    }

    /// The disk is visited once per `IO_CHUNK_BYTES`, not once per piece of the network.
    #[tokio::test]
    async fn staging_writes_whole_chunks_and_the_rest_once() {
        let directory = tempfile::tempdir().unwrap();
        let (store, mut scope) = staging_scope(1 << 30, directory.path());
        let staging = Staging::new();
        staging
            .begin(InputSpool::document(&store, &mut scope).unwrap())
            .unwrap();
        assert!(staging.flush().await.is_ok());
        assert_eq!(
            staging.writes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "nothing buffered is not a hop"
        );
        let piece = [9u8; 16 * 1024];
        let pieces = 1000;
        for _ in 0..pieces {
            staging.push(&piece).await.unwrap();
        }
        let total = (pieces * piece.len()) as u64;
        let spool = staging.finish().await.unwrap();
        assert_eq!(spool.len(), total);
        let hops = staging.writes.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            hops as u64,
            total.div_ceil(IO_CHUNK_BYTES as u64),
            "one blocking write per full chunk plus the last"
        );
        // Pieces larger than the chunk (the rest of one carries over) keep the rule.
        let big = vec![1u8; 3 * IO_CHUNK_BYTES + 5];
        let (store, mut scope) = staging_scope(1 << 30, directory.path());
        let staging = Staging::new();
        staging
            .begin(InputSpool::document(&store, &mut scope).unwrap())
            .unwrap();
        staging.push(&big).await.unwrap();
        let spool = staging.finish().await.unwrap();
        assert_eq!(spool.len(), big.len() as u64);
        assert_eq!(staging.writes.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    /// What is gathered when the server must wait for the client is in the spool before it
    /// waits (and stays there when the idle timeout ends the wait); a ready frame is not a
    /// wait and does not flush.
    #[tokio::test]
    async fn gathered_bytes_are_in_the_spool_when_the_server_waits_for_the_client() {
        let directory = tempfile::tempdir().unwrap();
        let (store, mut scope) = staging_scope(1 << 30, directory.path());
        let staging = Staging::new();
        staging
            .begin(InputSpool::document(&store, &mut scope).unwrap())
            .unwrap();
        let first = Bytes::from(vec![1u8; 50 * 1024]);
        let body = Body::from_stream(
            futures_util::stream::iter([first.clone(), first.clone()].map(Ok::<_, io::Error>))
                .chain(futures_util::stream::pending()),
        );
        let failure = Arc::new(Failure::default());
        let wire = Arc::new(tokio::sync::Mutex::new(Wire {
            body,
            pace: UploadPace::new(PaceConfig {
                idle: Duration::from_millis(200),
                min_rate: 0,
            }),
            total: 0,
            limit: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            scope: scope.shared_view(),
            failure,
            tail_ledger: None,
            staging: Some(staging.clone()),
        }));
        let deadline = Deadline::after(Duration::from_secs(30)).unwrap();
        let cancel = Arc::new(Cancellation::new());
        for _ in 0..2 {
            let data = frame(&wire, deadline, &cancel).await.unwrap().unwrap();
            staging.push(&data).await.unwrap();
        }
        assert_eq!(
            staging.writes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "ready frames are gathered, not written"
        );
        assert!(frame(&wire, deadline, &cancel).await.is_err());
        assert_eq!(staging.writes.load(std::sync::atomic::Ordering::SeqCst), 1);
        let spool = staging.finish().await.unwrap();
        assert_eq!(spool.len(), 100 * 1024, "everything received was written");
    }

    /// Bytes gathered while the server is already waiting for the client are written during
    /// that wait, not at its end.
    #[tokio::test]
    async fn bytes_gathered_during_a_wait_are_written_during_it() {
        let directory = tempfile::tempdir().unwrap();
        let (store, mut scope) = staging_scope(1 << 30, directory.path());
        let staging = Staging::new();
        staging
            .begin(InputSpool::document(&store, &mut scope).unwrap())
            .unwrap();
        let wire = Arc::new(tokio::sync::Mutex::new(Wire {
            body: Body::from_stream(futures_util::stream::pending::<Result<Bytes, io::Error>>()),
            pace: UploadPace::new(PaceConfig {
                idle: Duration::from_millis(600),
                min_rate: 0,
            }),
            total: 0,
            limit: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            scope: scope.shared_view(),
            failure: Arc::new(Failure::default()),
            tail_ledger: None,
            staging: Some(staging.clone()),
        }));
        let deadline = Deadline::after(Duration::from_secs(30)).unwrap();
        let waiting = tokio::spawn({
            let wire = wire.clone();
            async move { frame(&wire, deadline, &Arc::new(Cancellation::new())).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        staging.push(&[4u8; 1000]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !waiting.is_finished(),
            "the client is still being waited for"
        );
        assert_eq!(
            staging.state().spool.as_ref().map(InputSpool::len),
            Some(1000),
            "written while the wait goes on"
        );
        assert!(waiting.await.unwrap().is_err());
    }

    /// The buffer and the spool of a request that is gone (here: dropped between two
    /// writes) release their memory charge and their file.
    #[tokio::test]
    async fn a_dropped_staging_releases_its_charge_and_its_file() {
        const MEMORY: u64 = 8 << 20;
        let directory = tempfile::tempdir().unwrap();
        let (store, mut scope) = staging_scope(MEMORY, directory.path());
        let charge = scope.reserve_memory(IO_CHUNK_BYTES as u64).unwrap();
        assert!(scope.reserve_memory(MEMORY).is_err(), "the charge is held");
        let staging = Staging::new();
        staging
            .begin(InputSpool::document(&store, &mut scope).unwrap())
            .unwrap();
        staging.push(&[1u8; 100 * 1024]).await.unwrap();
        drop(staging);
        drop(charge);
        scope
            .reserve_memory(MEMORY)
            .expect("the whole budget is free again");
        fn files(root: &std::path::Path) -> usize {
            std::fs::read_dir(root)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    if path.is_dir() { files(&path) } else { 1 }
                })
                .sum()
        }
        assert_eq!(files(directory.path()), 0);
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
