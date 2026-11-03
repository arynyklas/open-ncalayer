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
}
pub(super) enum Documents {
    Text(BTreeMap<String, String>),
    Frozen(BTreeMap<String, FrozenInput>),
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
    },
}
pub(super) struct Wire {
    body: Body,
    total: u64,
    limit: u64,
    scope: ResourceScope,
}
async fn frame(
    wire: &Arc<tokio::sync::Mutex<Wire>>,
    deadline: Deadline,
    cancel: &Arc<Cancellation>,
) -> Result<Option<Bytes>, ProcessingError> {
    let mut wire = wire.lock().await;
    wire.scope.checkpoint()?;
    let result = tokio::select! {
        _=cancel.cancelled()=>return Err(ProcessingError::Cancelled),
        result=tokio::time::timeout(deadline.remaining(),wire.body.frame())=>result.map_err(|_|ProcessingError::DeadlineExceeded)?,
    };
    let Some(result) = result else {
        return Ok(None);
    };
    let data = result
        .map_err(|_| ProcessingError::InvalidInput("invalid body frame"))?
        .into_data()
        .map_err(|_| ProcessingError::InvalidInput("trailers unsupported"))?;
    wire.total = wire
        .total
        .checked_add(data.len() as u64)
        .filter(|n| *n <= wire.limit)
        .ok_or(ProcessingError::FramingLimit)?;
    wire.scope.checkpoint()?;
    Ok(Some(data))
}
fn parse_error(scope: &ResourceScope) -> ApiError {
    match scope.checkpoint() {
        Err(e) => processing_error(e),
        Ok(()) => invalid_request(),
    }
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
    if content_type == "application/json" {
        if metadata.content_length.is_some_and(|n| n > JSON_BYTES) {
            return Err(ApiError::not_applied(ErrorCode::MetadataLimit));
        }
        let wire = Arc::new(tokio::sync::Mutex::new(Wire {
            body,
            total: 0,
            limit: JSON_BYTES,
            scope,
        }));
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(JSON_BYTES as usize)
            .map_err(|_| ApiError::not_applied(ErrorCode::MemoryLimit))?;
        while let Some(data) = frame(&wire, deadline, &cancel)
            .await
            .map_err(processing_error)?
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
    let mut parser = BoundedMultipart::new(source, &boundary, maximum_wire, &["metadata"])
        .map_err(|_| invalid_request())?;
    let mut field = parser
        .next_field()
        .await
        .map_err(|_| parse_error(&scope))?
        .ok_or_else(invalid_request)?;
    if field.name() != Some("metadata") || field.file_name().is_some() {
        return Err(invalid_request());
    }
    parser.admit_data();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(JSON_BYTES as usize)
        .map_err(|_| ApiError::not_applied(ErrorCode::MemoryLimit))?;
    while let Some(chunk) = field.chunk().await.map_err(|_| parse_error(&scope))? {
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
        payload: Payload::Multipart {
            parser,
            wire,
            metadata_bytes: bytes.len() as u64,
            content_length: metadata.content_length,
            deadline,
            cancel,
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
}
impl Read for FieldReader<'_> {
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
            let chunk=self.runtime.block_on(async{
                tokio::select!{
                    _=self.cancel.cancelled()=>Err(io::Error::new(io::ErrorKind::Interrupted,"cancelled")),
                    result=tokio::time::timeout(self.deadline.remaining(),self.field.chunk())=>match result{Ok(Ok(value))=>Ok(value),Ok(Err(_))=>Err(io::Error::new(io::ErrorKind::InvalidData,"invalid multipart field")),Err(_)=>Err(io::Error::new(io::ErrorKind::TimedOut,"deadline exceeded"))}
                }
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
            } => {
                let store = store.ok_or(ProcessingError::InvalidInput(
                    "explicit scratch directory required",
                ))?;
                let mut seen = BTreeSet::new();
                let mut documents = BTreeMap::new();
                let mut payload = metadata_bytes;
                while let Some(field) = runtime
                    .block_on(parser.next_field())
                    .map_err(|_| ProcessingError::InvalidInput("invalid multipart framing"))?
                {
                    ctx.resources().checkpoint()?;
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
                    };
                    let frozen = FrozenInput::capture(
                        Source::sequential(&mut reader, None),
                        store,
                        ctx.resources(),
                    )?;
                    payload = payload
                        .checked_add(frozen.len())
                        .ok_or(ProcessingError::FramingLimit)?;
                    documents.insert(name, frozen);
                }
                drop(parser);
                // multer stops at the closing delimiter. Read the remaining HTTP
                // entity as well so epilogues/lying lengths cannot evade quotas.
                let admitted_total = runtime.block_on(async { wire.lock().await.total });
                ctx.resources().account_framing(
                    admitted_total
                        .checked_sub(payload)
                        .ok_or(ProcessingError::FramingLimit)?,
                )?;
                while let Some(tail) = runtime.block_on(frame(&wire, deadline, &cancel))? {
                    ctx.resources().account_framing(tail.len() as u64)?;
                }
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
