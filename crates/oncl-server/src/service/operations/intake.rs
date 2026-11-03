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
    pub reservations: Vec<ResourceReservation>,
    pub failure: Arc<Failure>,
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
    state: Mutex<(bool, Option<ProcessingError>)>,
}
impl Failure {
    fn record(&self, error: ProcessingError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.0 {
            state.0 = true;
            state.1 = Some(error);
        }
    }
    fn stopped(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
    }
    pub(super) fn recover(&self, fallback: ProcessingError) -> ProcessingError {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.0 = true;
        state.1.take().unwrap_or(fallback)
    }
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
    Ok(Prepared {
        metadata: request,
        failure: failure.clone(),
        payload: Payload::Multipart {
            parser,
            wire,
            metadata_bytes: bytes.len() as u64,
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
                if content_length.is_some_and(|n| n != total) || seen.len() != metadata.parts.len()
                {
                    return Err(ProcessingError::InvalidInput(
                        "multipart length or field mismatch",
                    ));
                }
                Ok(Documents::Frozen(documents))
            }
        }
    }
}
