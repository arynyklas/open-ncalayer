//! Sequential batches: immutable source capture is separate from explicit host authority.
use crate::*;
use oncl_pki::{
    digest::{DigestValue, hash_source},
    io::{FrozenInput, Region, Source},
    key::{AppliedState, HashAlg},
    resource::{Progress, ResourceReservation},
};
use std::{io::Write, sync::Arc};

pub(crate) const MAX_ITEMS: usize = 1024;
const MAX_ID_BYTES: usize = 128;

/// Requests and destinations move into the plan; none can be replaced after approval.
pub enum BatchOperation<'a> {
    Hash {
        algorithm: HashAlg,
        input: Source<'a>,
    },
    ValidateCms {
        input: &'a [u8],
        detached: Option<&'a [u8]>,
    },
    Sign {
        request: SignRequest<'a>,
        input: Source<'a>,
        output: &'a mut dyn Write,
    },
    Verify {
        request: VerifyRequest,
        input: Source<'a>,
        detached: Option<Source<'a>>,
    },
    Extend {
        request: ExtendRequest<'a>,
        input: Source<'a>,
        output: &'a mut dyn Write,
    },
    Extract {
        input: Source<'a>,
        output: &'a mut dyn Write,
    },
    Inspect {
        request: InspectRequest<'a>,
        input: Option<Source<'a>>,
    },
    Stamp {
        request: StampRequest,
        input: Source<'a>,
        output: &'a mut dyn Write,
    },
    VerifyStamp {
        request: StampVerifyRequest,
        token: Source<'a>,
        data: Option<Source<'a>>,
    },
    #[cfg(feature = "jose")]
    Jose(BatchJoseOperation<'a>),
}

/// JOSE's bounded byte APIs borrow immutable slices, pinning the exact bytes.
#[cfg(feature = "jose")]
pub enum BatchJoseOperation<'a> {
    Create {
        profile: jose::JoseProfile,
        keys: Vec<keys::KeyRequest<'a>>,
        payload: &'a [u8],
        output: &'a mut dyn Write,
    },
    Add {
        request: jose::JwsVerifyRequest<'a>,
        keys: Vec<keys::KeyRequest<'a>>,
        input: &'a [u8],
        detached: Option<&'a [u8]>,
        output: &'a mut dyn Write,
    },
    Verify {
        request: jose::JwsVerifyRequest<'a>,
        input: &'a [u8],
        detached: Option<&'a [u8]>,
    },
    JwtEncode {
        key: keys::KeyRequest<'a>,
        claims: &'a [u8],
        output: &'a mut dyn Write,
    },
    JwtDecode {
        input: &'a [u8],
    },
    JwtVerify {
        certificate: Option<&'a oncl_pki::cert::Certificate>,
        input: &'a [u8],
        policy: &'a jose::JwtValidationPolicy,
    },
}
pub struct BatchItem<'a> {
    id: &'a str,
    operation: BatchOperation<'a>,
}
impl<'a> BatchItem<'a> {
    pub fn new(id: &'a str, operation: BatchOperation<'a>) -> Self {
        Self { id, operation }
    }
}
pub enum BatchError {
    ConsentMismatch,
    Operation(OperationError),
}
impl std::fmt::Debug for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsentMismatch => f.write_str("ConsentMismatch"),
            Self::Operation(e) => f
                .debug_struct("Operation")
                .field("code", &e.code())
                .field("applied", &e.applied_state())
                .finish(),
        }
    }
}
impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConsentMismatch => {
                f.write_str("batch approval does not match this captured plan and operation")
            }
            Self::Operation(e) => std::fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for BatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConsentMismatch => None,
            Self::Operation(e) => Some(e),
        }
    }
}
impl From<OperationError> for BatchError {
    fn from(e: OperationError) -> Self {
        Self::Operation(e)
    }
}
impl From<oncl_pki::resource::ProcessingError> for BatchError {
    fn from(e: oncl_pki::resource::ProcessingError) -> Self {
        Self::Operation(e.into())
    }
}

/// Opaque, single-use host approval, deliberately not Clone/Deserialize.
pub struct BatchApproval {
    plan: Arc<()>,
    owner: Arc<()>,
    operation: OperationId,
    _lease: oncl_pki::resource::OperationLease,
}
pub struct CapturedBatch<'a> {
    identity: Arc<()>,
    owner: Arc<()>,
    operation: OperationId,
    scope: oncl_pki::resource::ResourceScope,
    number: u64,
    items: Vec<CapturedItem<'a>>,
    results: Vec<BatchItemResult>,
    result_memory: ResourceReservation,
    result_metadata: ResourceReservation,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
pub struct BatchItemView<'a> {
    pub id: &'a str,
    pub action: Action,
    pub sources: &'a [BatchSourceIdentity],
    pub signing_profile: Option<SignProfile>,
    pub keys: &'a [BatchKeyBinding],
    pub capture_error: Option<ErrorCode>,
}
pub struct BatchSourceIdentity {
    digest: DigestValue,
    bytes: u64,
}
impl BatchSourceIdentity {
    pub fn sha256(&self) -> &DigestValue {
        &self.digest
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}
pub struct BatchKeyBinding {
    key: keys::KeyId,
    certificate: DigestValue,
}
impl BatchKeyBinding {
    pub fn key(&self) -> &keys::KeyId {
        &self.key
    }
    pub fn certificate_sha256(&self) -> &DigestValue {
        &self.certificate
    }
}
impl CapturedBatch<'_> {
    pub fn plan_id(&self) -> u64 {
        self.number
    }
    pub fn items(&self) -> impl ExactSizeIterator<Item = BatchItemView<'_>> {
        self.items.iter().map(|i| BatchItemView {
            id: i.id,
            action: i.action,
            sources: &i.digests,
            signing_profile: match &i.operation {
                Dispatch::Sign(r, _) => Some(r.profile()),
                _ => None,
            },
            keys: &i.keys,
            capture_error: i.error.as_ref().map(OperationError::code).or_else(|| {
                match &i.operation {
                    Dispatch::Inspect(Err(error)) => Some(error.code()),
                    _ => None,
                }
            }),
        })
    }
    /// Call only from the trusted host after confirming these exact immutable
    /// items/sources/destinations. Capture and run never call this implicitly.
    pub fn authorize(&self, ctx: &OperationContext) -> Result<BatchApproval, BatchError> {
        if self.operation != ctx.id
            || !Arc::ptr_eq(&self.owner, &ctx.owner)
            || !self.scope.same_operation(&ctx.scope)
        {
            return Err(BatchError::ConsentMismatch);
        }
        ctx.scope.checkpoint()?;
        Ok(BatchApproval {
            plan: self.identity.clone(),
            owner: self.owner.clone(),
            operation: self.operation,
            _lease: ctx.lease(),
        })
    }
}
/// Only a completed batch capture constructs this proof. The closed Dispatch
/// retains immutable slice borrows for the entire installation lifetime.
pub(crate) struct BorrowedReplay {
    scope: oncl_pki::resource::ResourceScope,
    first: (usize, usize),
    second: Option<(usize, usize)>,
}
impl std::fmt::Debug for BorrowedReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BorrowedReplay { scoped: true }")
    }
}
impl BorrowedReplay {
    pub(crate) fn matches(
        &self,
        input: &[u8],
        detached: Option<&[u8]>,
        scope: &oncl_pki::resource::ResourceScope,
    ) -> bool {
        self.scope.same_operation(scope)
            && self.first == (input.as_ptr() as usize, input.len())
            && self.second == detached.map(|d| (d.as_ptr() as usize, d.len()))
    }
}
struct CapturedItem<'a> {
    id: &'a str,
    action: Action,
    operation: Dispatch<'a>,
    source: Option<FrozenInput>,
    detached: Option<FrozenInput>,
    digests: Vec<BatchSourceIdentity>,
    keys: Vec<BatchKeyBinding>,
    error: Option<OperationError>,
    replay: Option<BorrowedReplay>,
    _key_memory: Option<ResourceReservation>,
    _key_metadata: Option<ResourceReservation>,
}
enum Dispatch<'a> {
    Hash(HashAlg),
    Sign(SignRequest<'a>, &'a mut dyn Write),
    Verify(VerifyRequest),
    ValidateCms(&'a [u8], Option<&'a [u8]>),
    Extend(ExtendRequest<'a>, &'a mut dyn Write),
    Extract(&'a mut dyn Write),
    Inspect(Result<InspectionReport, OperationError>),
    Stamp(StampRequest, &'a mut dyn Write),
    VerifyStamp(StampVerifyRequest),
    #[cfg(feature = "jose")]
    Jose(BatchJoseOperation<'a>),
}
pub enum BatchReport {
    Hash(HashReport),
    Sign(OperationReport),
    Verify(VerificationReport),
    Extend(OperationReport),
    Validate(VerificationReport),
    Extract(ExtractionReport),
    Inspect(InspectionReport),
    Stamp(TimestampReport),
    #[cfg(feature = "jose")]
    JoseWrite(jose::JoseWriteReport),
    #[cfg(feature = "jose")]
    JwsVerify(jose::JwsVerificationReport),
    #[cfg(feature = "jose")]
    JwtDecode(jose::DecodedJwt),
    #[cfg(feature = "jose")]
    JwtVerify(jose::JwtVerificationReport),
}
impl std::fmt::Debug for BatchReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Hash(_) => "Hash",
            Self::Sign(_) => "Sign",
            Self::Verify(_) => "Verify",
            Self::Validate(_) => "Validate",
            Self::Extend(_) => "Extend",
            Self::Extract(_) => "Extract",
            Self::Inspect(_) => "Inspect",
            Self::Stamp(_) => "Stamp",
            #[cfg(feature = "jose")]
            Self::JoseWrite(_) => "JoseWrite",
            #[cfg(feature = "jose")]
            Self::JwsVerify(_) => "JwsVerify",
            #[cfg(feature = "jose")]
            Self::JwtDecode(_) => "JwtDecode",
            #[cfg(feature = "jose")]
            Self::JwtVerify(_) => "JwtVerify",
        })
    }
}
// Slots reserve their full bounded size before private use; boxing each success
// would add an unnecessary allocation and a separately retained capacity owner.
#[allow(clippy::large_enum_variant)]
pub enum BatchOutcome {
    Completed(BatchReport),
    Failed(OperationError),
    NotRun,
}
impl std::fmt::Debug for BatchOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed(report) => f.debug_tuple("Completed").field(report).finish(),
            Self::Failed(error) => f
                .debug_struct("Failed")
                .field("code", &error.code())
                .field("applied", &error.applied_state())
                .finish(),
            Self::NotRun => f.write_str("NotRun"),
        }
    }
}
/// The indivisible item owns its collection capacity/root even when moved out of
/// the summary; format reports additionally retain all their original owners.
pub struct BatchItemResult {
    id: String,
    outcome: BatchOutcome,
    applied: AppliedState,
    sources: Vec<BatchSourceIdentity>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl BatchItemResult {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn outcome(&self) -> &BatchOutcome {
        &self.outcome
    }
    pub fn applied_state(&self) -> AppliedState {
        self.applied
    }
    pub fn sources(&self) -> &[BatchSourceIdentity] {
        &self.sources
    }
}
pub enum BatchStop {
    Control(OperationError),
    Item {
        index: usize,
        code: ErrorCode,
        applied: AppliedState,
    },
}
impl BatchStop {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Control(error) => error.code(),
            Self::Item { code, .. } => *code,
        }
    }
}
pub struct BatchSummary {
    results: Vec<BatchItemResult>,
    pub attempted: usize,
    pub completed: usize,
    pub total: usize,
    pub progress: Progress,
    pub stop: Option<BatchStop>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl BatchSummary {
    pub fn results(&self) -> &[BatchItemResult] {
        &self.results
    }
}
#[derive(Clone, Copy)]
pub enum BatchEvent<'a> {
    Started {
        total: usize,
    },
    ItemStarted {
        id: &'a str,
        index: usize,
    },
    ItemFinished {
        result: &'a BatchItemResult,
        attempted: usize,
        completed: usize,
        total: usize,
        progress: Progress,
    },
    Finished {
        attempted: usize,
        completed: usize,
        total: usize,
        progress: Progress,
    },
}
fn terminal(error: &OperationError) -> bool {
    !matches!(
        error.code(),
        ErrorCode::InvalidInput
            | ErrorCode::Io
            | ErrorCode::KeyNotFound
            | ErrorCode::UnsupportedAlgorithm
            | ErrorCode::ValidationRequired
            | ErrorCode::MissingValidationServices
            | ErrorCode::MissingCadesConfiguration
            | ErrorCode::MissingTemporaryStore
            | ErrorCode::MissingMetadataProvider
            | ErrorCode::MissingKeyProvider
            | ErrorCode::SecretRequired
    ) || error.applied_state() != AppliedState::NotApplied
}
impl Engine {
    pub fn capture_batch<'a>(
        &self,
        items: impl IntoIterator<Item = BatchItem<'a>>,
        ctx: &mut OperationContext,
    ) -> Result<CapturedBatch<'a>, BatchError> {
        let result = self.capture_batch_inner(items, ctx);
        if matches!(&result, Err(BatchError::Operation(error)) if terminal(error)) {
            ctx.private_use_stopped
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
    fn capture_batch_inner<'a>(
        &self,
        items: impl IntoIterator<Item = BatchItem<'a>>,
        ctx: &mut OperationContext,
    ) -> Result<CapturedBatch<'a>, BatchError> {
        if !Arc::ptr_eq(&self.identity, &ctx.owner) {
            return Err(BatchError::ConsentMismatch);
        }
        ctx.scope.checkpoint()?;
        let capacity = (MAX_ITEMS
            * (std::mem::size_of::<CapturedItem<'_>>()
                + 2 * std::mem::size_of::<BatchSourceIdentity>())) as u64;
        let memory = ctx.scope.reserve_memory(capacity)?;
        let metadata = ctx.scope.reserve_metadata(capacity)?;
        let mut captured = Vec::with_capacity(MAX_ITEMS);
        static NEXT_PLAN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let number = NEXT_PLAN
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_add(1),
            )
            .map_err(|_| OperationError::IdExhausted)?;
        for item in items {
            if captured.len() == MAX_ITEMS
                || item.id.is_empty()
                || item.id.len() > MAX_ID_BYTES
                || item.id.contains('\0')
                || captured.iter().any(|i: &CapturedItem<'_>| i.id == item.id)
            {
                return Err(oncl_pki::resource::ProcessingError::InvalidInput(
                    "batch item count/id",
                )
                .into());
            }
            let mut bindings = Vec::new();
            let mut key_reservations = None;
            let mut preflight_error = None;
            let (operation, source, detached, action) = match item.operation {
                BatchOperation::Hash { algorithm, input } => {
                    (Dispatch::Hash(algorithm), Some(input), None, Action::Hash)
                }
                BatchOperation::ValidateCms { input, detached } => (
                    Dispatch::ValidateCms(input, detached),
                    None,
                    None,
                    Action::Validate,
                ),
                BatchOperation::Sign {
                    mut request,
                    input,
                    output,
                } => {
                    input
                        .is_snapshot_for(&ctx.scope)
                        .map_err(|_| BatchError::ConsentMismatch)?;
                    match &request.mode {
                        crate::request::SignMode::CmsAdd(_, Some(d))
                        | crate::request::SignMode::CadesAdd(_, Some(d), ..) => {
                            d.is_snapshot_for(&ctx.scope)
                                .map_err(|_| BatchError::ConsentMismatch)?;
                        }
                        _ => {}
                    }
                    let (keys, action) = match &request.mode {
                        crate::request::SignMode::RawMessage(k) => {
                            (std::slice::from_ref(k), Action::Sign)
                        }
                        crate::request::SignMode::RawDigest(k, _) => {
                            (std::slice::from_ref(k), Action::SignDigest)
                        }
                        crate::request::SignMode::CmsCreate(k, _)
                        | crate::request::SignMode::CmsAdd(k, _)
                        | crate::request::SignMode::CadesCreate(k, ..)
                        | crate::request::SignMode::CadesAdd(k, ..) => (k.as_slice(), Action::Sign),
                        #[cfg(feature = "pdf")]
                        crate::request::SignMode::Pdf(k, _)
                        | crate::request::SignMode::Pades(k, ..) => {
                            (std::slice::from_ref(k), Action::Sign)
                        }
                    };
                    // Resolve and pin opaque lease/certificate before host confirmation,
                    // never spool key containers or apply a private key at capture.
                    match self.capture_batch_keys(keys, ctx, action) {
                        Ok((values, memory, metadata)) => {
                            bindings = values;
                            key_reservations = Some((memory, metadata));
                        }
                        Err(error)
                            if !terminal(&error)
                                && !ctx
                                    .private_use_stopped
                                    .load(std::sync::atomic::Ordering::Acquire) =>
                        {
                            preflight_error = Some(error)
                        }
                        Err(error) => return Err(error.into()),
                    }
                    let detached = match &mut request.mode {
                        crate::request::SignMode::CmsAdd(_, d)
                        | crate::request::SignMode::CadesAdd(_, d, ..) => d.take(),
                        _ => None,
                    };
                    (
                        Dispatch::Sign(request, output),
                        Some(input),
                        detached,
                        action,
                    )
                }
                BatchOperation::Verify {
                    request,
                    input,
                    detached,
                } => (
                    Dispatch::Verify(request),
                    Some(input),
                    detached,
                    Action::Verify,
                ),
                BatchOperation::Extend {
                    request,
                    input,
                    output,
                } => {
                    let detached = request.detached.borrow_mut().take();
                    if request.detached_requested && detached.is_none() {
                        return Err(oncl_pki::resource::ProcessingError::InvalidInput(
                            "detached source already consumed",
                        )
                        .into());
                    }
                    (
                        Dispatch::Extend(request, output),
                        Some(input),
                        detached,
                        Action::Extend,
                    )
                }
                BatchOperation::Extract { input, output } => (
                    Dispatch::Extract(output),
                    Some(input),
                    None,
                    Action::Extract,
                ),
                BatchOperation::Inspect { request, input } => {
                    // Metadata/container intake may contain secret key material:
                    // use the existing bounded in-memory inspector, NEVER a spool.
                    if !ctx.grant.allows(Action::Inspect) {
                        return Err(OperationError::PermissionDenied.into());
                    }
                    if let Some(source) = &input {
                        source
                            .is_snapshot_for(&ctx.scope)
                            .map_err(|_| BatchError::ConsentMismatch)?;
                    }
                    let inspected = self.inspect(&request, input, ctx);
                    if inspected.as_ref().err().is_some_and(terminal) {
                        return Err(inspected.err().unwrap().into());
                    }
                    (Dispatch::Inspect(inspected), None, None, Action::Inspect)
                }
                BatchOperation::Stamp {
                    request,
                    input,
                    output,
                } => (
                    Dispatch::Stamp(request, output),
                    Some(input),
                    None,
                    Action::Stamp,
                ),
                BatchOperation::VerifyStamp {
                    request,
                    token,
                    data,
                } => (
                    Dispatch::VerifyStamp(request),
                    Some(token),
                    data,
                    Action::VerifyStamp,
                ),
                #[cfg(feature = "jose")]
                BatchOperation::Jose(operation) => {
                    use BatchJoseOperation::*;
                    let (action, keys): (_, &[keys::KeyRequest<'_>]) = match &operation {
                        Create { keys, .. } | Add { keys, .. } => (Action::Sign, keys),
                        JwtEncode { key, .. } => (Action::Sign, std::slice::from_ref(key)),
                        JwtDecode { .. } => (Action::Extract, &[]),
                        Verify { .. } | JwtVerify { .. } => (Action::Verify, &[]),
                    };
                    if !ctx.grant.allows(action) {
                        return Err(OperationError::PermissionDenied.into());
                    }
                    if action == Action::Sign {
                        match self.capture_batch_keys(keys, ctx, action) {
                            Ok((values, memory, metadata)) => {
                                bindings = values;
                                key_reservations = Some((memory, metadata));
                            }
                            Err(error)
                                if !terminal(&error)
                                    && !ctx
                                        .private_use_stopped
                                        .load(std::sync::atomic::Ordering::Acquire) =>
                            {
                                preflight_error = Some(error)
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    (Dispatch::Jose(operation), None, None, action)
                }
            };
            if !ctx.grant.allows(action) {
                return Err(OperationError::PermissionDenied.into());
            }
            let (key_memory, key_metadata) = match key_reservations {
                Some((m, d)) => (Some(m), Some(d)),
                None => (None, None),
            };
            let mut entry = CapturedItem {
                id: item.id,
                action,
                operation,
                source: None,
                detached: None,
                digests: Vec::with_capacity(2),
                keys: bindings,
                error: preflight_error,
                replay: None,
                _key_memory: key_memory,
                _key_metadata: key_metadata,
            };
            let borrowed = match &entry.operation {
                Dispatch::ValidateCms(input, detached) => Some((*input, *detached)),
                #[cfg(feature = "jose")]
                Dispatch::Jose(operation) => {
                    use BatchJoseOperation::*;
                    Some(match operation {
                        Create { payload, .. } => (*payload, None),
                        Add {
                            input, detached, ..
                        }
                        | Verify {
                            input, detached, ..
                        } => (*input, *detached),
                        JwtEncode { claims, .. } => (*claims, None),
                        JwtDecode { input } | JwtVerify { input, .. } => (*input, None),
                    })
                }
                _ => None,
            };
            if let Some((first, second)) = borrowed
                && entry.error.is_none()
            {
                let total = (first.len() as u64)
                    .checked_add(second.map_or(0, |d| d.len() as u64))
                    .ok_or(oncl_pki::resource::ProcessingError::InputLimit)?;
                if total > ctx.scope.input_remaining() {
                    return Err(oncl_pki::resource::ProcessingError::InputLimit.into());
                }
                match &entry.operation {
                    Dispatch::ValidateCms(..) => {
                        if total > ctx.scope.limits().metadata_bytes
                            || total > ctx.scope.limits().memory_bytes
                        {
                            return Err(oncl_pki::resource::ProcessingError::MetadataLimit.into());
                        }
                    }
                    #[cfg(feature = "jose")]
                    Dispatch::Jose(operation) => {
                        use BatchJoseOperation::*;
                        let valid = match operation {
                            Create { .. } => first.len() <= jose::MAX_PAYLOAD_BYTES,
                            JwtEncode { .. } => first.len() <= jose::MAX_CLAIMS_BYTES,
                            Add { .. } | Verify { .. } => {
                                first.len() <= jose::MAX_CONTAINER_BYTES
                                    && second.is_none_or(|d| d.len() <= jose::MAX_PAYLOAD_BYTES)
                            }
                            JwtDecode { .. } | JwtVerify { .. } => {
                                first.len() <= jose::MAX_CONTAINER_BYTES
                            }
                        };
                        if !valid {
                            return Err(oncl_pki::resource::ProcessingError::InvalidInput(
                                "borrowed input exceeds format profile",
                            )
                            .into());
                        }
                    }
                    _ => {}
                }
                for bytes in [Some(first), second].into_iter().flatten() {
                    if bytes.len() as u64 > ctx.scope.limits().input_bytes {
                        return Err(oncl_pki::resource::ProcessingError::InputLimit.into());
                    }
                    let mut hash = oncl_pki::digest::HashState::new(HashAlg::Sha256);
                    for chunk in bytes.chunks(oncl_pki::resource::IO_CHUNK_BYTES) {
                        ctx.scope.checkpoint()?;
                        ctx.scope.account_input(chunk.len() as u64)?;
                        hash.update(chunk);
                        ctx.scope.checkpoint()?;
                    }
                    entry.digests.push(BatchSourceIdentity {
                        digest: hash.finish(),
                        bytes: bytes.len() as u64,
                    });
                }
                entry.replay = Some(BorrowedReplay {
                    scope: ctx.scope.shared_view(),
                    first: (first.as_ptr() as usize, first.len()),
                    second: second.map(|d| (d.as_ptr() as usize, d.len())),
                });
            }
            for (source, destination) in
                [(source, &mut entry.source), (detached, &mut entry.detached)]
            {
                if entry.error.is_some() {
                    break;
                }
                if let Some(source) = source {
                    source
                        .is_snapshot_for(&ctx.scope)
                        .map_err(|_| BatchError::ConsentMismatch)?;
                    let store = self
                        .temporary
                        .as_ref()
                        .ok_or(OperationError::MissingTemporaryStore)?;
                    match FrozenInput::capture(source, store, &mut ctx.scope) {
                        Ok(mut frozen) => {
                            let region = Region {
                                offset: 0,
                                len: frozen.len(),
                            };
                            let mut reader = frozen.reader(&[region], &ctx.scope)?;
                            let digest =
                                hash_source(reader.source(), HashAlg::Sha256, &mut ctx.scope)?;
                            reader.finish()?;
                            drop(reader);
                            entry.digests.push(BatchSourceIdentity {
                                digest,
                                bytes: frozen.len(),
                            });
                            *destination = Some(frozen);
                        }
                        Err(error) => {
                            entry.error = Some(error.into());
                            break;
                        }
                    }
                }
            }
            let stop = entry.error.as_ref().is_some_and(terminal);
            captured.push(entry);
            if stop {
                return Err(captured.pop().unwrap().error.unwrap().into());
            }
        }
        let bytes = (captured.len() * std::mem::size_of::<BatchItemResult>()) as u64;
        let result_memory = ctx.scope.reserve_memory(bytes)?;
        let result_metadata = ctx.scope.reserve_metadata(bytes)?;
        let mut results = Vec::with_capacity(captured.len());
        for item in &captured {
            let bytes = (std::mem::size_of::<BatchItemResult>()
                + item.id.len()
                + 2 * std::mem::size_of::<BatchSourceIdentity>()) as u64;
            let memory = ctx.scope.reserve_memory(bytes)?;
            let metadata = ctx.scope.reserve_metadata(bytes)?;
            results.push(BatchItemResult {
                id: item.id.to_owned(),
                outcome: BatchOutcome::NotRun,
                applied: AppliedState::NotApplied,
                sources: Vec::new(),
                _memory: memory,
                _metadata: metadata,
            });
        }
        Ok(CapturedBatch {
            identity: Arc::new(()),
            owner: self.identity.clone(),
            operation: ctx.id,
            scope: ctx.scope.shared_view(),
            number,
            items: captured,
            results,
            result_memory,
            result_metadata,
            _memory: memory,
            _metadata: metadata,
        })
    }
    fn capture_batch_keys(
        &self,
        requests: &[keys::KeyRequest<'_>],
        ctx: &mut OperationContext,
        action: Action,
    ) -> Result<
        (
            Vec<BatchKeyBinding>,
            ResourceReservation,
            ResourceReservation,
        ),
        OperationError,
    > {
        use der::Encode;
        if requests.is_empty() || requests.len() > 64 {
            return Err(
                oncl_pki::resource::ProcessingError::InvalidInput("batch signer count").into(),
            );
        }
        let bytes = (requests.len()
            * (std::mem::size_of::<BatchKeyBinding>() + std::mem::size_of::<usize>()))
            as u64;
        let memory = ctx.scope.reserve_memory(bytes)?;
        let metadata = ctx.scope.reserve_metadata(bytes)?;
        let indices = self.prepare_sign_keys(requests, ctx, action)?;
        let mut result = Vec::with_capacity(requests.len());
        for (request, index) in requests.iter().zip(indices) {
            let signer = self.operation_signer(index, ctx, action)?;
            let cert = signer.certificate();
            let length = u32::from(
                cert.encoded_len()
                    .map_err(|_| OperationError::InvalidKeySource)?,
            ) as u64;
            let _memory = ctx.scope.reserve_memory(length)?;
            let der = cert
                .to_der()
                .map_err(|_| OperationError::InvalidKeySource)?;
            let mut hash = oncl_pki::digest::HashState::new(HashAlg::Sha256);
            hash.update(&der);
            result.push(BatchKeyBinding {
                key: request.selector().key_id(),
                certificate: hash.finish(),
            });
        }
        Ok((result, memory, metadata))
    }
    pub fn run_batch(
        &self,
        plan: CapturedBatch<'_>,
        approval: BatchApproval,
        ctx: &mut OperationContext,
        emit: impl FnMut(BatchEvent<'_>),
    ) -> Result<BatchSummary, BatchError> {
        let result = self.run_batch_inner(plan, approval, ctx, emit);
        if matches!(&result, Ok(summary) if summary.stop.is_some())
            || matches!(&result, Err(BatchError::Operation(error)) if terminal(error))
        {
            ctx.private_use_stopped
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }
    fn run_batch_inner(
        &self,
        plan: CapturedBatch<'_>,
        approval: BatchApproval,
        ctx: &mut OperationContext,
        mut emit: impl FnMut(BatchEvent<'_>),
    ) -> Result<BatchSummary, BatchError> {
        if !Arc::ptr_eq(&plan.identity, &approval.plan)
            || !Arc::ptr_eq(&plan.owner, &approval.owner)
            || !Arc::ptr_eq(&plan.owner, &self.identity)
            || !Arc::ptr_eq(&plan.owner, &ctx.owner)
            || plan.operation != approval.operation
            || plan.operation != ctx.id
            || !plan.scope.same_operation(&ctx.scope)
        {
            return Err(BatchError::ConsentMismatch);
        }
        let total = plan.items.len();
        let mut summary = BatchSummary {
            results: plan.results,
            attempted: 0,
            completed: 0,
            total,
            progress: ctx.scope.progress(),
            stop: None,
            _memory: plan.result_memory,
            _metadata: plan.result_metadata,
        };
        emit(BatchEvent::Started { total });
        for (index, mut item) in plan.items.into_iter().enumerate() {
            if summary.stop.is_none()
                && let Err(error) = ctx.scope.checkpoint()
            {
                summary.stop = Some(BatchStop::Control(error.into()));
            }
            let outcome = if summary.stop.is_some() {
                BatchOutcome::NotRun
            } else {
                summary.attempted += 1;
                emit(BatchEvent::ItemStarted { id: item.id, index });
                let previous = ctx
                    .batch_item
                    .replace(keys::BatchItemOrdinal::from_batch_index(index));
                let previous_replay =
                    std::mem::replace(&mut ctx.borrowed_replay, item.replay.take());
                // Restore correlation even when trusted host guard/provider code
                // panics and the host catches the unwind to reuse this context.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if let Some(error) = item.error.take() {
                        Err(error)
                    } else {
                        self.dispatch_batch_item(
                            item.operation,
                            item.source.as_mut(),
                            item.detached.as_mut(),
                            ctx,
                        )
                    }
                }));
                ctx.batch_item = previous;
                ctx.borrowed_replay = previous_replay;
                let result = match result {
                    Ok(result) => result,
                    Err(payload) => std::panic::resume_unwind(payload),
                };
                match result {
                    Ok(report) => {
                        summary.completed += 1;
                        BatchOutcome::Completed(report)
                    }
                    Err(error) => BatchOutcome::Failed(error),
                }
            };
            let applied = match &outcome {
                BatchOutcome::Completed(BatchReport::Sign(r) | BatchReport::Extend(r)) => r.applied,
                #[cfg(feature = "jose")]
                BatchOutcome::Completed(BatchReport::JoseWrite(r)) => r.applied,
                BatchOutcome::Failed(e) => e.applied_state(),
                _ => AppliedState::NotApplied,
            };
            if let BatchOutcome::Failed(error) = &outcome
                && (terminal(error)
                    || ctx
                        .private_use_stopped
                        .load(std::sync::atomic::Ordering::Acquire))
            {
                summary.stop = Some(BatchStop::Item {
                    index,
                    code: error.code(),
                    applied,
                });
            }
            let result = &mut summary.results[index];
            result.outcome = outcome;
            result.applied = applied;
            result.sources = item.digests;
            summary.progress = ctx.scope.progress();
            emit(BatchEvent::ItemFinished {
                result,
                attempted: summary.attempted,
                completed: summary.completed,
                total,
                progress: summary.progress,
            });
        }
        emit(BatchEvent::Finished {
            attempted: summary.attempted,
            completed: summary.completed,
            total,
            progress: summary.progress,
        });
        Ok(summary)
    }
    fn dispatch_batch_item(
        &self,
        operation: Dispatch<'_>,
        source: Option<&mut FrozenInput>,
        detached: Option<&mut FrozenInput>,
        ctx: &mut OperationContext,
    ) -> Result<BatchReport, OperationError> {
        let mut source = source
            .map(|s| {
                let region = Region {
                    offset: 0,
                    len: s.len(),
                };
                s.reader(&[region], &ctx.scope)
            })
            .transpose()?;
        let mut detached = detached
            .map(|s| {
                let region = Region {
                    offset: 0,
                    len: s.len(),
                };
                s.reader(&[region], &ctx.scope)
            })
            .transpose()?;
        let input = source.as_mut().map(|s| s.source());
        let data = detached.as_mut().map(|s| s.source());
        let result = match operation {
            Dispatch::Hash(algorithm) => self
                .hash(algorithm, input.unwrap(), ctx)
                .map(BatchReport::Hash),
            Dispatch::Sign(request, output) => {
                use crate::request::SignMode;
                let mode = match request.mode {
                    SignMode::RawMessage(k) => SignMode::RawMessage(k),
                    SignMode::RawDigest(k, d) => SignMode::RawDigest(k, d),
                    SignMode::CmsCreate(k, a) => SignMode::CmsCreate(k, a),
                    SignMode::CmsAdd(k, _) => SignMode::CmsAdd(k, data),
                    SignMode::CadesCreate(k, a, l, m, e) => SignMode::CadesCreate(k, a, l, m, e),
                    SignMode::CadesAdd(k, _, l, m, e) => SignMode::CadesAdd(k, data, l, m, e),
                    #[cfg(feature = "pdf")]
                    SignMode::Pdf(k, p) => SignMode::Pdf(k, p),
                    #[cfg(feature = "pdf")]
                    SignMode::Pades(k, p, l, m, e) => SignMode::Pades(k, p, l, m, e),
                };
                self.sign(SignRequest { mode }, input.unwrap(), output, ctx)
                    .map(BatchReport::Sign)
            }
            Dispatch::Verify(request) => self
                .verify(&request, input.unwrap(), data, ctx)
                .map(BatchReport::Verify),
            Dispatch::ValidateCms(input, detached) => self
                .validate_cms(input, detached, ctx)
                .map(BatchReport::Validate),
            Dispatch::Extend(request, output) => {
                let bound = ExtendRequest::cms(request.level);
                #[cfg(feature = "pdf")]
                let bound = match request.pdf_limits {
                    Some(limits) => ExtendRequest::pdf(request.level, limits),
                    None => bound,
                };
                let mut bound = bound.with_material(request.material);
                if let Some(limits) = request.limits {
                    bound = bound.with_evidence_limits(limits);
                }
                if let Some(data) = data {
                    bound = bound.with_detached(data);
                }
                self.extend(&bound, input.unwrap(), output, ctx)
                    .map(BatchReport::Extend)
            }
            Dispatch::Extract(output) => self
                .extract(input.unwrap(), output, ctx)
                .map(BatchReport::Extract),
            Dispatch::Inspect(result) => result.map(BatchReport::Inspect),
            Dispatch::Stamp(request, output) => self
                .stamp(&request, input.unwrap(), output, ctx)
                .map(BatchReport::Stamp),
            Dispatch::VerifyStamp(request) => self
                .verify_stamp(&request, input.unwrap(), data, ctx)
                .map(BatchReport::Stamp),
            #[cfg(feature = "jose")]
            Dispatch::Jose(operation) => {
                use BatchJoseOperation::*;
                match operation {
                    Create {
                        profile,
                        keys,
                        payload,
                        output,
                    } => self
                        .jws_create(profile, keys, payload, output, ctx)
                        .map(BatchReport::JoseWrite),
                    Add {
                        request,
                        keys,
                        input,
                        detached,
                        output,
                    } => self
                        .jws_add(request, keys, input, detached, output, ctx)
                        .map(BatchReport::JoseWrite),
                    Verify {
                        request,
                        input,
                        detached,
                    } => self
                        .jws_verify(request, input, detached, ctx)
                        .map(BatchReport::JwsVerify),
                    JwtEncode {
                        key,
                        claims,
                        output,
                    } => self
                        .jwt_encode(key, claims, output, ctx)
                        .map(BatchReport::JoseWrite),
                    JwtDecode { input } => self
                        .jwt_decode_unverified(input, ctx)
                        .map(BatchReport::JwtDecode),
                    JwtVerify {
                        certificate,
                        input,
                        policy,
                    } => self
                        .jwt_verify(certificate, input, policy, ctx)
                        .map(BatchReport::JwtVerify),
                }
            }
        };
        // Preserve format/key errors, including Applied, ahead of replay failures.
        if let Ok(report) = &result {
            let applied = match report {
                BatchReport::Sign(report) | BatchReport::Extend(report) => report.applied,
                #[cfg(feature = "jose")]
                BatchReport::JoseWrite(report) => report.applied,
                _ => AppliedState::NotApplied,
            };
            let finalized = (|| {
                if let Some(reader) = source.as_mut() {
                    reader.finish()?;
                }
                if let Some(reader) = detached.as_mut() {
                    reader.finish()?;
                }
                Ok::<(), oncl_pki::resource::ProcessingError>(())
            })();
            if let Err(error) = finalized {
                return Err(if applied == AppliedState::NotApplied {
                    error.into()
                } else {
                    OperationError::AfterKeyUse {
                        source: Box::new(error.into()),
                        applied,
                    }
                });
            }
        }
        result
    }
}
