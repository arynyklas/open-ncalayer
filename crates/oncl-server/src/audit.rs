//! Fixed-size, checksummed local journal. Checksums detect damaged frames, not
//! malicious owner edits; this is neither a hash chain nor nonrepudiation.
use oncl_core::keys::{
    AppliedState, KeyId, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
};
use oncl_core::{Action, OperationContext, OperationError, OperationId};
use oncl_pki::digest::HashState;
use oncl_pki::key::HashAlg;
use oncl_pki::private_fs::PrivateDirectory;
use oncl_pki::resource::{Deadline, OperationLease};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FRAME_BYTES: u64 = 160;
const MAGIC: &[u8; 8] = b"ONCLAU01";
const IDENTITY: &str = "oncl-audit.identity";
const MAX_BINDINGS: usize = 1024;
const MAX_KEYS_PER_OPERATION: usize = 32;

/// Opaque host-assigned identity. Never constructed from paths, subject names,
/// passwords, request bodies or Debug-formatted KeyId. No textual metadata API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditLabel([u8; 16]);
impl AuditLabel {
    pub const fn new(id: [u8; 16]) -> Self {
        Self(id)
    }
    pub fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct AuditConfig {
    root: PathBuf,
    segment_bytes: u64,
    quota_bytes: u64,
    retained_segments: usize,
    max_operations: usize,
}
impl AuditConfig {
    /// Quota covers journal frames and identity, not filesystem allocation units.
    pub fn new(
        root: PathBuf,
        segment_bytes: u64,
        quota_bytes: u64,
        retained_segments: usize,
        max_operations: usize,
    ) -> io::Result<Self> {
        if segment_bytes < FRAME_BYTES * 4
            || quota_bytes
                < segment_bytes
                    .checked_add(FRAME_BYTES * 2)
                    .ok_or_else(invalid)?
            || quota_bytes > 67_108_864
            || retained_segments == 0
            || retained_segments > 1024
            || max_operations == 0
            || max_operations > MAX_BINDINGS
        {
            return Err(invalid());
        }
        Ok(Self {
            root,
            segment_bytes,
            quota_bytes,
            retained_segments,
            max_operations,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditHealth {
    Healthy,
    Failed,
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Header,
    Begin,
    Final,
    Recovery,
}
impl RecordKind {
    pub fn is_final(self) -> bool {
        self == Self::Final
    }
}
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub kind: RecordKind,
    pub sequence: u64,
    pub use_id: u64,
    pub operation_id: u64,
    pub session: [u8; 16],
    pub principal: AuditLabel,
    pub key: AuditLabel,
    pub unix_millis: u64,
    pub applied: AppliedState,
    pub succeeded: bool,
    pub action: Option<Action>,
    /// Observed byte boundary in a Recovery record's `use_id` segment, or in
    /// this FINAL's segment when completing a previously durable recovery probe.
    pub repair_from: u64,
    pub repair_to: u64,
}
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub truncated_bytes: u64,
    pub resolved_unknown: usize,
}

/// Faults interrupt the actual production append/sync path once. Host-only
/// diagnostic control; no writer replacement and no simulated successful write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    BeforeWrite,
    PartialWrite,
    BeforeSync,
    AfterSync,
}
struct Binding {
    principal: AuditLabel,
    keys: HashMap<KeyId, AuditLabel>,
    deadline: Deadline,
    lease: Option<OperationLease>,
    closed: bool,
}
struct Pending {
    event: AuditEvent,
    key: Option<KeyId>,
    action: Action,
    live: bool,
    outcome: Option<KeyUseOutcome>,
    _lease: Option<OperationLease>,
}
struct Segment {
    number: u64,
    bytes: u64,
}
struct State {
    health: AuditHealth,
    directory: PrivateDirectory,
    _identity_lock: File,
    identity: [u8; 16],
    session: [u8; 16],
    segments: Vec<Segment>,
    active: File,
    total: u64,
    sequence: u64,
    bindings: HashMap<OperationId, Binding>,
    pending: BTreeMap<u64, Pending>,
    fault: Option<FaultPoint>,
    fatal_corruption: bool,
}
struct Shared {
    config: AuditConfig,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct DurableAuditGuard {
    shared: Arc<Shared>,
}
/// Lifetime token for the host's immutable original-invocation identity binding.
/// Dropping it never invents a FINAL for a private operation still in progress.
pub struct AuditBinding {
    shared: Arc<Shared>,
    operation: OperationId,
}
impl Drop for AuditBinding {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock()
            && let Some(binding) = state.bindings.get_mut(&self.operation)
        {
            binding.closed = true;
            binding.keys = HashMap::new();
            binding.principal = AuditLabel([0; 16]);
            binding.lease = None;
        }
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid audit configuration or record",
    )
}
fn damaged() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "audit journal requires operator inspection",
    )
}
fn blocked() -> io::Error {
    io::Error::other("audit journal unavailable")
}
fn random() -> io::Result<[u8; 16]> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| blocked())?;
    Ok(id)
}
fn name(number: u64) -> String {
    format!("oncl-audit-{number:016x}.log")
}
fn number(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("oncl-audit-")?.strip_suffix(".log")?;
    if digits.len() != 16 {
        return None;
    }
    let n = u64::from_str_radix(digits, 16).ok()?;
    (self::name(n) == name).then_some(n)
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = HashState::new(HashAlg::Sha256);
    hash.update(bytes);
    hash.finish().as_bytes().try_into().expect("SHA256 length")
}
fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| blocked())?
        .as_millis()
        .try_into()
        .map_err(|_| blocked())
}
fn blank(kind: RecordKind) -> AuditEvent {
    AuditEvent {
        kind,
        sequence: 0,
        use_id: 0,
        operation_id: 0,
        session: [0; 16],
        principal: AuditLabel([0; 16]),
        key: AuditLabel([0; 16]),
        unix_millis: 0,
        applied: AppliedState::NotApplied,
        succeeded: false,
        action: None,
        repair_from: 0,
        repair_to: 0,
    }
}
fn encode(record: &AuditEvent, identity: [u8; 16]) -> [u8; 160] {
    let mut bytes = [0; 160];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&identity);
    bytes[24..32].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[32..40].copy_from_slice(&record.use_id.to_le_bytes());
    bytes[40..48].copy_from_slice(&record.operation_id.to_le_bytes());
    bytes[48..64].copy_from_slice(&record.session);
    bytes[64..80].copy_from_slice(&record.principal.0);
    bytes[80..96].copy_from_slice(&record.key.0);
    bytes[96..104].copy_from_slice(&record.unix_millis.to_le_bytes());
    bytes[104] = match record.kind {
        RecordKind::Header => 0,
        RecordKind::Begin => 1,
        RecordKind::Final => 2,
        RecordKind::Recovery => 3,
    };
    bytes[105] = match record.action {
        None => 0,
        Some(Action::Sign) => 1,
        Some(Action::SignDigest) => 2,
        _ => 255,
    };
    bytes[106] = match record.applied {
        AppliedState::NotApplied => 0,
        AppliedState::Applied => 1,
        AppliedState::Unknown => 2,
    };
    bytes[107] = u8::from(record.succeeded);
    bytes[108..116].copy_from_slice(&record.repair_from.to_le_bytes());
    bytes[116..124].copy_from_slice(&record.repair_to.to_le_bytes());
    let sum = checksum(&bytes[..128]);
    bytes[128..].copy_from_slice(&sum);
    bytes
}
fn decode(bytes: &[u8; 160], identity: [u8; 16]) -> io::Result<AuditEvent> {
    if &bytes[..8] != MAGIC
        || bytes[8..24] != identity
        || bytes[128..] != checksum(&bytes[..128])
        || bytes[124..128] != [0; 4]
    {
        return Err(damaged());
    }
    let word =
        |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed frame"));
    Ok(AuditEvent {
        kind: match bytes[104] {
            0 => RecordKind::Header,
            1 => RecordKind::Begin,
            2 => RecordKind::Final,
            3 => RecordKind::Recovery,
            _ => return Err(damaged()),
        },
        sequence: word(24),
        use_id: word(32),
        operation_id: word(40),
        session: bytes[48..64].try_into().unwrap(),
        principal: AuditLabel(bytes[64..80].try_into().unwrap()),
        key: AuditLabel(bytes[80..96].try_into().unwrap()),
        unix_millis: word(96),
        action: match bytes[105] {
            0 => None,
            1 => Some(Action::Sign),
            2 => Some(Action::SignDigest),
            _ => return Err(damaged()),
        },
        applied: match bytes[106] {
            0 => AppliedState::NotApplied,
            1 => AppliedState::Applied,
            2 => AppliedState::Unknown,
            _ => return Err(damaged()),
        },
        succeeded: match bytes[107] {
            0 => false,
            1 => true,
            _ => return Err(damaged()),
        },
        repair_from: word(108),
        repair_to: word(116),
    })
}
fn check_partial_tail(file: &mut File, identity: [u8; 16], sequence: u64) -> io::Result<()> {
    let len = file.metadata()?.len();
    let tail = (len % FRAME_BYTES) as usize;
    if tail == 0 {
        return Ok(());
    }
    let mut expected = [0; 32];
    expected[..8].copy_from_slice(MAGIC);
    expected[8..24].copy_from_slice(&identity);
    expected[24..32].copy_from_slice(&sequence.checked_add(1).ok_or_else(damaged)?.to_le_bytes());
    let mut bytes = [0; 160];
    file.seek(SeekFrom::Start(len - tail as u64))?;
    file.read_exact(&mut bytes[..tail])?;
    let prefix = tail.min(expected.len());
    if bytes[..prefix] != expected[..prefix] {
        return Err(damaged());
    }
    Ok(())
}
fn check_segment_len(len: u64, last: bool, config: &AuditConfig) -> io::Result<()> {
    if len < FRAME_BYTES
        || len > config.segment_bytes
        || (!last && !len.is_multiple_of(FRAME_BYTES))
    {
        return Err(damaged());
    }
    Ok(())
}
fn read_header(file: &mut File, identity: [u8; 16], number: u64) -> io::Result<AuditEvent> {
    let mut bytes = [0; 160];
    file.read_exact(&mut bytes)?;
    let header = decode(&bytes, identity)?;
    if header.kind != RecordKind::Header || header.use_id != number {
        return Err(damaged());
    }
    Ok(header)
}
fn partial_final_matches(file: &mut File, pending: &BTreeMap<u64, Pending>) -> io::Result<bool> {
    let len = file.metadata()?.len();
    let tail = (len % FRAME_BYTES) as usize;
    if tail == 0 {
        return Ok(true);
    }
    let mut bytes = [0; 160];
    file.seek(SeekFrom::Start(len - tail as u64))?;
    file.read_exact(&mut bytes[..tail])?;
    if (tail > 104 && bytes[104] != 2)
        || (tail > 106 && bytes[106] > 2)
        || (tail > 107 && bytes[107] > 1)
    {
        return Ok(false);
    }
    if tail > 128 && bytes[128..tail] != checksum(&bytes[..128])[..tail - 128] {
        return Ok(false);
    }
    for original in pending.values() {
        let mut expected = [0; 64];
        expected[..8].copy_from_slice(&original.event.use_id.to_le_bytes());
        expected[8..16].copy_from_slice(&original.event.operation_id.to_le_bytes());
        expected[16..32].copy_from_slice(&original.event.session);
        expected[32..48].copy_from_slice(&original.event.principal.0);
        expected[48..64].copy_from_slice(&original.event.key.0);
        let end = tail.min(96);
        let action = match original.action {
            Action::Sign => 1,
            Action::SignDigest => 2,
            _ => return Err(damaged()),
        };
        if (tail <= 32 || bytes[32..end] == expected[..end - 32])
            && (tail <= 105 || bytes[105] == action)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
impl DurableAuditGuard {
    pub fn create(config: AuditConfig) -> io::Result<Self> {
        Self::load(config, true)
    }
    pub fn open(config: AuditConfig) -> io::Result<Self> {
        Self::load(config, false)
    }
    fn load(config: AuditConfig, create: bool) -> io::Result<Self> {
        let directory = if create {
            PrivateDirectory::create(&config.root)?
        } else {
            PrivateDirectory::open(&config.root)?
        };
        let mut identity_lock = if create {
            directory.create_file(IDENTITY)?
        } else {
            directory.open_file(IDENTITY)?
        };
        identity_lock.try_lock().map_err(|_| blocked())?;
        let identity = if create {
            let id = random()?;
            let frame = encode(&blank(RecordKind::Header), id);
            identity_lock.write_all(&frame)?;
            identity_lock.sync_all()?;
            directory.sync()?;
            id
        } else {
            if identity_lock.metadata()?.len() != FRAME_BYTES {
                return Err(damaged());
            }
            let mut bytes = [0; 160];
            identity_lock.read_exact(&mut bytes)?;
            let id = bytes[8..24].try_into().unwrap();
            if decode(&bytes, id)?.kind != RecordKind::Header {
                return Err(damaged());
            }
            id
        };
        let mut numbers = Vec::new();
        for entry in directory.names()? {
            if let Some(n) = number(&entry) {
                if numbers.len() > config.retained_segments {
                    return Err(damaged());
                }
                numbers.push(n);
            }
        }
        numbers.sort_unstable();
        if numbers
            .windows(2)
            .any(|pair| pair[0].checked_add(1) != Some(pair[1]))
        {
            return Err(damaged());
        }
        if create && !numbers.is_empty() {
            return Err(damaged());
        }
        if numbers.is_empty() {
            if !create {
                return Err(damaged());
            }
            let mut file = directory.create_file(&name(0))?;
            let mut header = blank(RecordKind::Header);
            header.use_id = 0;
            file.write_all(&encode(&header, identity))?;
            file.sync_all()?;
            directory.sync()?;
            numbers.push(0);
        }
        let active = directory.open_file(&name(*numbers.last().unwrap()))?;
        let mut state = State {
            health: if create {
                AuditHealth::Healthy
            } else {
                AuditHealth::RecoveryRequired
            },
            directory,
            _identity_lock: identity_lock,
            identity,
            session: random()?,
            segments: Vec::new(),
            active,
            total: FRAME_BYTES,
            sequence: 0,
            bindings: HashMap::new(),
            pending: BTreeMap::new(),
            fault: None,
            fatal_corruption: false,
        };
        for (index, n) in numbers.iter().enumerate() {
            let mut file = state.directory.open_file(&name(*n))?;
            let len = file.metadata()?.len();
            check_segment_len(len, index + 1 == numbers.len(), &config)?;
            if state
                .total
                .checked_add(len)
                .is_none_or(|sum| sum > config.quota_bytes)
            {
                return Err(damaged());
            }
            state.total += len;
            state.segments.push(Segment {
                number: *n,
                bytes: len,
            });
            let header = read_header(&mut file, identity, *n)?;
            let mut bytes = [0; 160];
            if index > 0 && header.sequence != state.sequence {
                return Err(damaged());
            }
            if index == 0 {
                state.sequence = header.sequence;
            }
            for _ in 1..len / FRAME_BYTES {
                file.read_exact(&mut bytes)?;
                match decode(&bytes, identity)
                    .and_then(|record| Self::replay(&mut state, record, &config))
                {
                    Ok(()) => (),
                    Err(_) => {
                        state.fatal_corruption = true;
                        state.health = AuditHealth::RecoveryRequired;
                        break;
                    }
                }
            }
            if state.fatal_corruption {
                break;
            }
            if len % FRAME_BYTES != 0 {
                if check_partial_tail(&mut file, identity, state.sequence).is_err() {
                    state.fatal_corruption = true;
                }
                state.health = AuditHealth::RecoveryRequired;
            }
        }
        if !state.pending.is_empty() {
            state.health = AuditHealth::RecoveryRequired;
        }
        state.active.seek(SeekFrom::End(0))?;
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                state: Mutex::new(state),
            }),
        })
    }
    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.shared.state.lock().map_err(|_| blocked())
    }
    pub fn health(&self) -> AuditHealth {
        self.lock().map_or(AuditHealth::Failed, |s| s.health)
    }
    /// The trusted host binds its authenticated principal to the ORIGINAL ctx.
    /// No current-principal variable, new Engine or new resource budget is used.
    pub fn bind(
        &self,
        ctx: &OperationContext,
        principal: AuditLabel,
        keys: impl IntoIterator<Item = (KeyId, AuditLabel)>,
    ) -> io::Result<AuditBinding> {
        let mut state = self.lock()?;
        state
            .bindings
            .retain(|_, binding| !binding.deadline.is_expired());
        if ctx.deadline().is_expired() {
            return Err(invalid());
        }
        if state.bindings.len() >= self.shared.config.max_operations
            || state.bindings.contains_key(&ctx.id())
        {
            return Err(invalid());
        }
        let mut mapped = HashMap::new();
        for (key, label) in keys {
            if mapped.len() >= MAX_KEYS_PER_OPERATION || mapped.insert(key, label).is_some() {
                return Err(invalid());
            }
        }
        if mapped.is_empty() {
            return Err(invalid());
        }
        state.bindings.insert(
            ctx.id(),
            Binding {
                principal,
                keys: mapped,
                deadline: ctx.deadline(),
                lease: Some(ctx.lease()),
                closed: false,
            },
        );
        Ok(AuditBinding {
            shared: self.shared.clone(),
            operation: ctx.id(),
        })
    }
    pub fn inject_fault(&self, point: FaultPoint) {
        if let Ok(mut state) = self.lock() {
            state.fault = Some(point);
        }
    }
    fn replay(state: &mut State, record: AuditEvent, config: &AuditConfig) -> io::Result<()> {
        if record.sequence != state.sequence.checked_add(1).ok_or_else(damaged)? {
            return Err(damaged());
        }
        match record.kind {
            RecordKind::Begin => {
                let action = record.action.ok_or_else(damaged)?;
                if state.pending.len() >= config.max_operations
                    || record.use_id != record.sequence
                    || state.pending.contains_key(&record.use_id)
                {
                    return Err(damaged());
                }
                state.pending.insert(
                    record.use_id,
                    Pending {
                        event: record.clone(),
                        key: None,
                        action,
                        live: false,
                        outcome: None,
                        _lease: None,
                    },
                );
            }
            RecordKind::Final => {
                let prior = state.pending.remove(&record.use_id).ok_or_else(damaged)?;
                if prior.event.operation_id != record.operation_id
                    || prior.event.session != record.session
                    || prior.event.principal != record.principal
                    || prior.event.key != record.key
                    || prior.event.action != record.action
                {
                    return Err(damaged());
                }
            }
            RecordKind::Recovery => (),
            RecordKind::Header => return Err(damaged()),
        }
        state.sequence = record.sequence;
        Ok(())
    }
    fn append(state: &mut State, record: &AuditEvent) -> io::Result<()> {
        let previous_health = state.health;
        state.health = AuditHealth::Failed;
        if state.active.metadata()?.len() % FRAME_BYTES != 0 {
            return Err(blocked());
        }
        let bytes = encode(record, state.identity);
        let fault = state.fault.take();
        let result = (|| {
            if fault == Some(FaultPoint::BeforeWrite) {
                return Err(blocked());
            }
            if fault == Some(FaultPoint::PartialWrite) {
                state.active.write_all(&bytes[..79])?;
                return Err(blocked());
            }
            state.active.write_all(&bytes)?;
            state.active.flush()?;
            if fault == Some(FaultPoint::BeforeSync) {
                return Err(blocked());
            }
            state.active.sync_all()?;
            if fault == Some(FaultPoint::AfterSync) {
                return Err(blocked());
            }
            Ok(())
        })();
        let len = state.active.metadata()?.len();
        let segment = state.segments.last_mut().ok_or_else(damaged)?;
        state.total = state
            .total
            .checked_sub(segment.bytes)
            .and_then(|n| n.checked_add(len))
            .ok_or_else(damaged)?;
        segment.bytes = len;
        if result.is_ok() {
            state.sequence = record.sequence;
            state.health = previous_health;
        }
        result
    }
    fn retire_closed(state: &mut State, config: &AuditConfig, headroom: u64) -> io::Result<()> {
        if !state.pending.is_empty() {
            return Err(blocked());
        }
        while state.segments.len() > config.retained_segments
            || state
                .total
                .checked_add(headroom)
                .is_none_or(|n| n > config.quota_bytes)
        {
            if state.segments.len() <= 1 {
                return Err(blocked());
            }
            let old = &state.segments[0];
            let mut file = state.directory.open_file(&name(old.number))?;
            read_header(&mut file, state.identity, old.number)?;
            if file.metadata()?.len() != old.bytes {
                return Err(damaged());
            }
            drop(file);
            state.directory.remove_file(&name(old.number))?;
            state.directory.sync()?;
            state.total -= old.bytes;
            state.segments.remove(0);
        }
        Ok(())
    }
    fn rotate(state: &mut State, config: &AuditConfig, headroom: u64) -> io::Result<()> {
        if !state.pending.is_empty() {
            return Err(blocked());
        }
        let next = state
            .segments
            .last()
            .unwrap()
            .number
            .checked_add(1)
            .ok_or_else(blocked)?;
        if state
            .total
            .checked_add(FRAME_BYTES)
            .is_none_or(|n| n > config.quota_bytes)
        {
            // A previously identified active replacement is kept and synced
            // before retiring older CLOSED segments to make new-header room.
            state.active.sync_all()?;
            state.directory.sync()?;
            Self::retire_closed(state, config, FRAME_BYTES)?;
        }
        let mut active = state.directory.create_file(&name(next))?;
        let mut header = blank(RecordKind::Header);
        header.use_id = next;
        header.sequence = state.sequence;
        active.write_all(&encode(&header, state.identity))?;
        active.sync_all()?;
        state.directory.sync()?;
        state.active = active;
        state.total += FRAME_BYTES;
        state.segments.push(Segment {
            number: next,
            bytes: FRAME_BYTES,
        });
        Self::retire_closed(state, config, headroom)
    }
    fn reconcile_complete_tail(state: &mut State) -> io::Result<()> {
        let len = state.active.metadata()?.len();
        if len % FRAME_BYTES != 0 || len < FRAME_BYTES {
            return Err(blocked());
        }
        state.active.seek(SeekFrom::Start(len - FRAME_BYTES))?;
        let mut bytes = [0; 160];
        state.active.read_exact(&mut bytes)?;
        let record = decode(&bytes, state.identity)?;
        state.active.sync_all()?;
        if record.kind != RecordKind::Header
            && record.sequence == state.sequence.checked_add(1).ok_or_else(blocked)?
        {
            match record.kind {
                RecordKind::Final => {
                    state.pending.remove(&record.use_id);
                }
                RecordKind::Begin => {
                    let action = record.action.ok_or_else(damaged)?;
                    state.pending.entry(record.use_id).or_insert(Pending {
                        event: record.clone(),
                        key: None,
                        action,
                        live: false,
                        outcome: None,
                        _lease: None,
                    });
                }
                _ => return Err(damaged()),
            }
            state.sequence = record.sequence;
        } else if record.sequence != state.sequence {
            return Err(damaged());
        }
        state.active.seek(SeekFrom::End(0))?;
        Ok(())
    }
    /// Read bounded complete frames from the pinned journal. Partial trailing
    /// bytes are omitted, never represented as a successful FINAL.
    pub fn records(&self) -> io::Result<Vec<AuditEvent>> {
        let mut state = self.lock()?;
        let result = Self::read_frames(&state, &self.shared.config).map(|(records, _)| records);
        if result.is_err() {
            state.health = AuditHealth::Failed;
        }
        result
    }
    fn read_frames(state: &State, config: &AuditConfig) -> io::Result<(Vec<AuditEvent>, u64)> {
        let mut records = Vec::new();
        let mut total = FRAME_BYTES;
        let mut sequence = None;
        for (index, segment) in state.segments.iter().enumerate() {
            let mut file = state.directory.open_file(&name(segment.number))?;
            let len = file.metadata()?.len();
            check_segment_len(len, index + 1 == state.segments.len(), config)?;
            total = total
                .checked_add(len)
                .filter(|sum| *sum <= config.quota_bytes)
                .ok_or_else(damaged)?;
            let header = read_header(&mut file, state.identity, segment.number)?;
            if sequence.is_some_and(|previous| previous != header.sequence) {
                return Err(damaged());
            }
            sequence = Some(header.sequence);
            records.push(header);
            let mut bytes = [0; 160];
            for _ in 1..len / FRAME_BYTES {
                file.read_exact(&mut bytes)?;
                let record = decode(&bytes, state.identity)?;
                if record.kind == RecordKind::Header
                    || Some(record.sequence)
                        != sequence.and_then(|previous| previous.checked_add(1))
                {
                    return Err(damaged());
                }
                sequence = Some(record.sequence);
                records.push(record);
            }
            if index + 1 == state.segments.len() {
                check_partial_tail(&mut file, state.identity, sequence.ok_or_else(damaged)?)?;
            }
        }
        Ok((records, total))
    }
    /// Explicit operator action. Refuses live private uses and complete corrupt
    /// frames. Only a partial final tail may be truncated; its exact byte range
    /// is recorded durably. Unfinished BEGINs are finalized Unknown, never success.
    pub fn recover(&self) -> io::Result<RecoveryReport> {
        let mut state = self.lock()?;
        state
            .bindings
            .retain(|_, binding| !binding.deadline.is_expired());
        if state.pending.values().any(|p| p.live) || state.fatal_corruption {
            return Err(blocked());
        }
        state.health = AuditHealth::Failed;
        // Re-read complete disk frames: a failed sync may nevertheless have
        // persisted a whole BEGIN/FINAL; never append duplicate sequence numbers.
        let (disk, total) = Self::read_frames(&state, &self.shared.config)?;
        state.total = total;
        let complete_probe = disk
            .iter()
            .rfind(|record| record.kind == RecordKind::Recovery)
            .map(|record| record.sequence);
        let known_outcomes: HashMap<_, _> = state
            .pending
            .iter()
            .filter_map(|(id, p)| p.outcome.map(|outcome| (*id, outcome)))
            .collect();
        let mut previous_pending = std::mem::take(&mut state.pending);
        let mut first = true;
        let replay = (|| {
            for record in disk {
                if record.kind == RecordKind::Header {
                    if first {
                        state.sequence = record.sequence;
                        first = false;
                    } else if record.sequence != state.sequence {
                        return Err(damaged());
                    }
                } else {
                    Self::replay(&mut state, record, &self.shared.config)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = replay {
            state.pending = previous_pending;
            state.fatal_corruption = true;
            return Err(error);
        }
        for (id, pending) in &mut state.pending {
            if let Some(previous) = previous_pending.remove(id) {
                pending._lease = previous._lease;
                pending.outcome = previous.outcome;
            }
        }
        let original = state.active.metadata()?.len();
        state.segments.last_mut().unwrap().bytes = original;
        let repair_segment = state.segments.last().unwrap().number;
        let tail = original % FRAME_BYTES;
        let repaired = original - tail;
        let identity = state.identity;
        let sequence = state.sequence;
        if check_partial_tail(&mut state.active, identity, sequence).is_err() {
            state.fatal_corruption = true;
            return Err(damaged());
        }
        let mut reuse_probe = !state.pending.is_empty()
            && complete_probe.is_some_and(|probe| state.pending.keys().all(|begin| *begin < probe));
        if reuse_probe && tail > 0 {
            let State {
                active, pending, ..
            } = &mut *state;
            reuse_probe = partial_final_matches(active, pending)?;
        }
        let needed = (state.pending.len() as u64 + u64::from(!reuse_probe))
            .checked_mul(FRAME_BYTES)
            .ok_or_else(blocked)?;
        let needs_rotation = repaired
            .checked_add(needed)
            .is_none_or(|n| n > self.shared.config.segment_bytes)
            || state
                .total
                .checked_sub(tail)
                .and_then(|n| n.checked_add(needed))
                .is_none_or(|n| n > self.shared.config.quota_bytes);
        if needs_rotation && !state.pending.is_empty() {
            return Err(blocked());
        }
        if tail > 0 {
            state.active.set_len(repaired)?;
            state.active.sync_all()?;
            state.total -= tail;
            state.segments.last_mut().unwrap().bytes = repaired;
        }
        if needs_rotation {
            Self::rotate(&mut state, &self.shared.config, FRAME_BYTES)?;
        }
        state.active.seek(SeekFrom::End(0))?;
        let pending: Vec<_> = state.pending.values().map(|p| p.event.clone()).collect();
        let report = RecoveryReport {
            truncated_bytes: tail,
            resolved_unknown: pending
                .iter()
                .filter(|event| {
                    known_outcomes
                        .get(&event.use_id)
                        .is_none_or(|outcome| outcome.applied == AppliedState::Unknown)
                })
                .count(),
        };
        // These are this recovery's observed boundaries, not a forensic claim
        // about uncommitted repairs interrupted before a Recovery frame synced.
        if !reuse_probe {
            let mut recovery = blank(RecordKind::Recovery);
            recovery.sequence = state.sequence.checked_add(1).ok_or_else(blocked)?;
            recovery.session = state.session;
            recovery.unix_millis = now()?;
            recovery.use_id = repair_segment;
            recovery.repair_from = original;
            recovery.repair_to = repaired;
            Self::append(&mut state, &recovery)?;
        }
        for (index, mut event) in pending.into_iter().enumerate() {
            event.kind = RecordKind::Final;
            event.sequence = state.sequence.checked_add(1).ok_or_else(blocked)?;
            let outcome = known_outcomes.get(&event.use_id);
            event.applied = outcome.map_or(AppliedState::Unknown, |o| o.applied);
            event.succeeded = outcome.is_some_and(|o| o.succeeded);
            event.unix_millis = now()?;
            if reuse_probe && tail > 0 && index == 0 {
                event.repair_from = original;
                event.repair_to = repaired;
            }
            Self::append(&mut state, &event)?;
            state.pending.remove(&event.use_id);
        }
        state.active.sync_all()?;
        state.directory.sync()?;
        state.health = AuditHealth::Healthy;
        Ok(report)
    }
}
impl KeyUseGuard for DurableAuditGuard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        let mut state = self.lock().map_err(|_| OperationError::AuditFailed)?;
        let result = (|| {
            if state.health != AuditHealth::Healthy
                || state.pending.len() >= self.shared.config.max_operations
                || state.pending.values().any(|p| {
                    p.event.session == state.session
                        && p.event.operation_id == event.operation_id.get()
                })
            {
                return Err(blocked());
            }
            let binding = state
                .bindings
                .get(&event.operation_id)
                .ok_or_else(blocked)?;
            if binding.closed || binding.deadline.is_expired() {
                return Err(blocked());
            }
            let lease = binding.lease.clone();
            let principal = binding.principal;
            let key = *binding.keys.get(&event.key_id).ok_or_else(blocked)?;
            if !matches!(event.action, Action::Sign | Action::SignDigest) {
                return Err(blocked());
            }
            // One reserved FINAL per pending BEGIN plus a recovery/probe frame.
            let reserved = (state.pending.len() as u64 + 3) * FRAME_BYTES;
            if state
                .segments
                .last()
                .unwrap()
                .bytes
                .checked_add(reserved)
                .is_none_or(|n| n > self.shared.config.segment_bytes)
                || state
                    .total
                    .checked_add(reserved)
                    .is_none_or(|n| n > self.shared.config.quota_bytes)
            {
                Self::rotate(&mut state, &self.shared.config, reserved)?;
            }
            if state
                .total
                .checked_add(reserved)
                .is_none_or(|n| n > self.shared.config.quota_bytes)
            {
                return Err(blocked());
            }
            let seq = state.sequence.checked_add(1).ok_or_else(blocked)?;
            let mut record = blank(RecordKind::Begin);
            record.sequence = seq;
            record.use_id = seq;
            record.operation_id = event.operation_id.get();
            record.session = state.session;
            record.principal = principal;
            record.key = key;
            record.unix_millis = now()?;
            record.action = Some(event.action);
            if let Err(error) = Self::append(&mut state, &record) {
                // No receipt escaped, so this process knows private use was not
                // admitted. Replay will ignore this fact if no whole BEGIN exists.
                state.pending.insert(
                    seq,
                    Pending {
                        event: record,
                        key: None,
                        action: event.action,
                        live: false,
                        outcome: Some(KeyUseOutcome {
                            applied: AppliedState::NotApplied,
                            succeeded: false,
                        }),
                        _lease: None,
                    },
                );
                return Err(error);
            }
            state.pending.insert(
                seq,
                Pending {
                    event: record,
                    key: Some(event.key_id.clone()),
                    action: event.action,
                    live: true,
                    outcome: None,
                    _lease: lease,
                },
            );
            Ok(KeyUseReceipt::with_correlation(
                event.clone(),
                u64::from_le_bytes(state.session[..8].try_into().unwrap()),
                seq,
            ))
        })();
        if result.is_err() {
            state.health = AuditHealth::Failed;
        }
        result.map_err(|_| OperationError::AuditFailed)
    }
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        let mut state = self.lock().map_err(|_| OperationError::AuditFailed)?;
        let event = receipt.event();
        let id = receipt.correlation().and_then(|(guard, id)| {
            let p = state.pending.get(&id)?;
            (guard == u64::from_le_bytes(state.session[..8].try_into().unwrap())
                && p.live
                && p.event.session == state.session
                && p.event.operation_id == event.operation_id.get()
                && p.key.as_ref() == Some(&event.key_id)
                && p.action == event.action)
                .then_some(id)
        });
        let Some(id) = id else {
            state.health = AuditHealth::Failed;
            return Err(OperationError::AuditFailed);
        };
        let mut record = state.pending.get(&id).unwrap().event.clone();
        let pending = state.pending.get_mut(&id).unwrap();
        pending.live = false;
        pending.outcome = Some(outcome);
        let poisoned = state.health != AuditHealth::Healthy;
        if poisoned && Self::reconcile_complete_tail(&mut state).is_err() {
            return Err(OperationError::AuditFailed);
        }
        record.kind = RecordKind::Final;
        record.sequence = state
            .sequence
            .checked_add(1)
            .ok_or(OperationError::AuditFailed)?;
        record.applied = outcome.applied;
        record.succeeded = outcome.succeeded;
        record.unix_millis = now().map_err(|_| OperationError::AuditFailed)?;
        Self::append(&mut state, &record).map_err(|_| OperationError::AuditFailed)?;
        state.pending.remove(&id);
        if poisoned {
            Err(OperationError::AuditFailed)
        } else {
            Ok(())
        }
    }
}
