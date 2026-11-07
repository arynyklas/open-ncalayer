//! Fixed-size, checksummed local journal. Checksums detect damaged frames, not
//! malicious owner edits; this is neither a hash chain nor nonrepudiation.
use oncl_core::keys::{
    AppliedState, KeyId, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
};
use oncl_core::plugins::{
    PluginAuditRecord, PluginCallerKind, PluginRefusalCode, PluginUse, TicketRefusal,
};
use oncl_core::{Action, OperationContext, OperationError, OperationId};
use oncl_pki::digest::HashState;
use oncl_pki::key::HashAlg;
use oncl_pki::private_fs::PrivateDirectory;
use oncl_pki::resource::{Deadline, OperationLease};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FRAME_BYTES: u64 = 160;
// v01's zero reserved item bits are unknowable, not authoritative non-batch.
const MAGIC: &[u8; 8] = b"ONCLAU02";
const IDENTITY: &str = "oncl-audit.identity";
const MAX_BINDINGS: usize = 1024;
const MAX_KEYS_PER_OPERATION: usize = 32;
const MAX_BATCH_ITEMS: u16 = 1024;
/// Payload bytes one `PluginDetail` frame carries: the bytes at 48..104 and 108..124.
const CHUNK_BYTES: usize = 72;
/// Most frames one plugin record may take (a bound on the record, not on the journal).
const MAX_CHUNKS: usize = 24;
/// Plugin refusals one bound operation may write to the journal; later ones are traced only,
/// so a plugin that keeps asking cannot push earlier records out of the journal.
const MAX_JOURNALED_REFUSALS: u8 = 4;
/// Refusals the guard remembers for the host to drain ([`DurableAuditGuard::take_plugin_refusals`]):
/// at most this many in all, and [`REFUSALS_PER_OPERATION`] per operation, so one noisy
/// operation cannot evict another's.
const REFUSAL_LOG: usize = 64;
const REFUSALS_PER_OPERATION: usize = 8;
/// Version of the plugin record layout inside the chunks.
const PLUGIN_RECORD_VERSION: u8 = 1;

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
    /// One chunk of the facts of a plugin key use or refusal: written before the `Begin`
    /// (or `PluginRefusal`) it describes, which names it by `use_id`. A chunk without its
    /// terminal frame is a use that never began: the key was not applied.
    PluginDetail,
    /// A plugin key use refused before the key; the reason is in the preceding chunks.
    PluginRefusal,
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
    /// Original Core batch item, not a private-use counter; None outside batch.
    pub batch_item: Option<u16>,
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
    /// The payload of a `PluginDetail` frame.
    pub chunk: Option<PluginChunk>,
}
/// One chunk of a plugin record: `index` of `count`, `bytes` zero-padded to the frame's capacity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginChunk {
    pub index: u8,
    pub count: u8,
    pub bytes: [u8; CHUNK_BYTES],
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
    /// Non-owning; a closed tombstone is pruned once every owner of the
    /// operation is gone, since its id can then never be presented again.
    weak: Option<oncl_pki::resource::WeakOperationLease>,
    closed: bool,
    /// Plugin refusals written to the journal for this operation.
    refusals: u8,
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
    identity_lock: File,
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
    /// Chunks seen with no terminal frame yet: `(use_id of the terminal, next index, count)`.
    plugin_chunks: Option<(u64, u8, u8)>,
    /// Newest last, at most [`REFUSAL_LOG`].
    plugin_refusals: VecDeque<(OperationId, TicketRefusal)>,
}
struct Shared {
    config: AuditConfig,
    state: Mutex<State>,
    policy: Option<Arc<dyn PluginTicketPolicy>>,
}
#[derive(Clone)]
pub struct DurableAuditGuard {
    shared: Arc<Shared>,
}
/// What a ticket check of the operator's grants established (docs/design/manual-plugins.md
/// §4.7): facts for the journal, never a decision the plugin can influence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginGrantFacts {
    /// Names the grant that covered the use (token, plugin, operation); recorded as text.
    pub grant_id: String,
    /// The operation is declared in the manifest (always true for a ticketed use).
    pub declared: bool,
}
/// The host's check of a ticketed plugin key use against the operator's grants. It runs inside
/// [`KeyUseGuard::before_use`], before the journal is touched and before the key is applied.
/// `Err` refuses the use (the plugin sees `PermissionDenied`; the reason is journaled).
///
/// `check` runs while the journal's one lock is held, before the operation's binding and
/// deadline are looked at: it must not call back into the guard, must be quick, and a grant
/// it consumes is consumed even if the journal then refuses the use (a failed write, a full
/// journal). It should keep `grant_id` short; a text over 255 bytes refuses the use as
/// [`TicketRefusal::AuditFactTooLong`].
pub trait PluginTicketPolicy: Send + Sync {
    fn check(
        &self,
        operation_id: OperationId,
        ticket: &PluginUse,
    ) -> Result<PluginGrantFacts, TicketRefusal>;
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
        batch_item: None,
        session: [0; 16],
        principal: AuditLabel([0; 16]),
        key: AuditLabel([0; 16]),
        unix_millis: 0,
        applied: AppliedState::NotApplied,
        succeeded: false,
        action: None,
        repair_from: 0,
        repair_to: 0,
        chunk: None,
    }
}
fn encode(record: &AuditEvent, identity: [u8; 16]) -> [u8; 160] {
    let mut bytes = [0; 160];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..24].copy_from_slice(&identity);
    bytes[24..32].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[32..40].copy_from_slice(&record.use_id.to_le_bytes());
    bytes[40..48].copy_from_slice(&record.operation_id.to_le_bytes());
    if let Some(chunk) = &record.chunk {
        // A chunk frame is all payload between the operation id and the kind.
        bytes[48..104].copy_from_slice(&chunk.bytes[..56]);
        bytes[104] = 4;
        bytes[106] = chunk.index;
        bytes[107] = chunk.count;
        bytes[108..124].copy_from_slice(&chunk.bytes[56..]);
        let sum = checksum(&bytes[..128]);
        bytes[128..].copy_from_slice(&sum);
        return bytes;
    }
    bytes[48..64].copy_from_slice(&record.session);
    bytes[64..80].copy_from_slice(&record.principal.0);
    bytes[80..96].copy_from_slice(&record.key.0);
    bytes[96..104].copy_from_slice(&record.unix_millis.to_le_bytes());
    bytes[104] = match record.kind {
        RecordKind::Header => 0,
        RecordKind::Begin => 1,
        RecordKind::Final => 2,
        RecordKind::Recovery => 3,
        RecordKind::PluginDetail => 4,
        RecordKind::PluginRefusal => 5,
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
    if let Some(item) = record.batch_item {
        bytes[124..126].copy_from_slice(&item.to_le_bytes());
        bytes[126] = 1;
    }
    let sum = checksum(&bytes[..128]);
    bytes[128..].copy_from_slice(&sum);
    bytes
}
fn check_version(bytes: &[u8; 160]) -> io::Result<()> {
    if &bytes[..8] != MAGIC {
        return Err(damaged());
    }
    Ok(())
}
fn decode(bytes: &[u8; 160], identity: [u8; 16]) -> io::Result<AuditEvent> {
    check_version(bytes)?;
    if bytes[8..24] != identity || bytes[128..] != checksum(&bytes[..128]) || bytes[127] != 0 {
        return Err(damaged());
    }
    let word =
        |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed frame"));
    if bytes[104] == 4 {
        let (index, count) = (bytes[106], bytes[107]);
        if bytes[105] != 0
            || bytes[124..127] != [0; 3]
            || count == 0
            || usize::from(count) > MAX_CHUNKS
            || index >= count
        {
            return Err(damaged());
        }
        let mut payload = [0; CHUNK_BYTES];
        payload[..56].copy_from_slice(&bytes[48..104]);
        payload[56..].copy_from_slice(&bytes[108..124]);
        let mut event = blank(RecordKind::PluginDetail);
        event.sequence = word(24);
        event.use_id = word(32);
        event.operation_id = word(40);
        event.chunk = Some(PluginChunk {
            index,
            count,
            bytes: payload,
        });
        return Ok(event);
    }
    let item = u16::from_le_bytes(bytes[124..126].try_into().unwrap());
    let batch_item = match (bytes[126], item) {
        (0, 0) => None,
        (1, item) if item < MAX_BATCH_ITEMS => Some(item),
        _ => return Err(damaged()),
    };
    if batch_item.is_some() && !matches!(bytes[104], 1 | 2) {
        return Err(damaged());
    }
    Ok(AuditEvent {
        kind: match bytes[104] {
            0 => RecordKind::Header,
            1 => RecordKind::Begin,
            2 => RecordKind::Final,
            3 => RecordKind::Recovery,
            5 => RecordKind::PluginRefusal,
            _ => return Err(damaged()),
        },
        sequence: word(24),
        use_id: word(32),
        operation_id: word(40),
        batch_item,
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
        chunk: None,
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
fn read_identity(file: &File, expected: Option<[u8; 16]>) -> io::Result<[u8; 16]> {
    if file.metadata()?.len() != FRAME_BYTES {
        return Err(damaged());
    }
    // Borrow the held lock handle: a separate handle cannot read its mandatory
    // locked region on Windows, and no duplicate descriptor is needed.
    let mut reader = file;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = [0; 160];
    reader.read_exact(&mut bytes)?;
    let identity = bytes[8..24].try_into().unwrap();
    if expected.is_some_and(|expected| expected != identity) {
        return Err(damaged());
    }
    let header = decode(&bytes, identity)?;
    if header.kind != RecordKind::Header || header.use_id != 0 {
        return Err(damaged());
    }
    Ok(identity)
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
        let mut expected_item = [0; 4];
        if let Some(item) = original.event.batch_item {
            expected_item[..2].copy_from_slice(&item.to_le_bytes());
            expected_item[2] = 1;
        }
        let item_prefix = tail.saturating_sub(124).min(4);
        if (tail <= 32 || bytes[32..end] == expected[..end - 32])
            && (tail <= 105 || bytes[105] == action)
            && (item_prefix == 0 || bytes[124..124 + item_prefix] == expected_item[..item_prefix])
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
fn put_text(out: &mut Vec<u8>, text: &str) -> io::Result<()> {
    out.push(u8::try_from(text.len()).map_err(|_| invalid())?);
    out.extend_from_slice(text.as_bytes());
    Ok(())
}
/// The chunks of one plugin record: `[len u16 le][version][flags][caller][package kind]
/// [package sha256][ticket digest][nonce sha256 if flagged][content sha256][content len u64 le]
/// [options sha256][id][version][operation][grant id if flagged][subcode if flagged]`, texts
/// as `[len u8][bytes]`, padded with zeros to whole chunks. A later layout bumps the
/// version byte; readers that do not know it report the record as unreadable, not as another one.
fn plugin_frames(
    record: &PluginAuditRecord,
    subcode: Option<PluginRefusalCode>,
) -> io::Result<Vec<PluginChunk>> {
    let flags = u8::from(record.declared)
        | u8::from(record.prehashed) << 1
        | u8::from(record.approval_nonce_sha256.is_some()) << 2
        | u8::from(record.grant_id.is_some()) << 3
        | u8::from(subcode.is_some()) << 4;
    let mut body = vec![
        PLUGIN_RECORD_VERSION,
        flags,
        match record.caller {
            PluginCallerKind::Browser => 1,
            PluginCallerKind::LocalOperator => 2,
            PluginCallerKind::ServiceClient => 3,
        },
        record.package_kind,
    ];
    body.extend_from_slice(&record.package_sha256);
    body.extend_from_slice(&record.ticket_digest);
    if let Some(nonce) = &record.approval_nonce_sha256 {
        body.extend_from_slice(nonce);
    }
    body.extend_from_slice(&record.content_sha256);
    body.extend_from_slice(&record.content_len.to_le_bytes());
    body.extend_from_slice(&record.options_sha256);
    put_text(&mut body, &record.plugin_id)?;
    put_text(&mut body, &record.version)?;
    put_text(&mut body, &record.operation)?;
    if let Some(grant) = &record.grant_id {
        put_text(&mut body, grant)?;
    }
    if let Some(code) = subcode {
        put_text(&mut body, code.id())?;
    }
    let mut all = u16::try_from(body.len())
        .map_err(|_| invalid())?
        .to_le_bytes()
        .to_vec();
    all.extend_from_slice(&body);
    let count = all.len().div_ceil(CHUNK_BYTES);
    if count > MAX_CHUNKS {
        return Err(invalid());
    }
    all.resize(count * CHUNK_BYTES, 0);
    Ok(all
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, bytes)| PluginChunk {
            index: index as u8,
            count: count as u8,
            bytes: bytes.try_into().expect("chunk size"),
        })
        .collect())
}
/// A plugin use or refusal as the journal records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginJournalRecord {
    /// Sequence of the terminal frame (`Begin` or `PluginRefusal`).
    pub use_id: u64,
    pub operation_id: u64,
    pub facts: PluginAuditRecord,
    /// The stable subcode id of a refusal; `None` for an authorised use.
    pub refusal: Option<String>,
    /// How the authorised use ended: `None` while it has no FINAL, which is `Unknown`.
    pub finished: Option<(AppliedState, bool)>,
}
fn read_text(bytes: &mut &[u8]) -> Option<String> {
    let (&len, rest) = bytes.split_first()?;
    let (text, rest) = rest.split_at_checked(usize::from(len))?;
    *bytes = rest;
    String::from_utf8(text.to_vec()).ok()
}
fn take<const N: usize>(bytes: &mut &[u8]) -> Option<[u8; N]> {
    let (head, rest) = bytes.split_at_checked(N)?;
    *bytes = rest;
    head.try_into().ok()
}
fn plugin_record(blob: &[u8]) -> Option<(PluginAuditRecord, Option<String>)> {
    let len = usize::from(u16::from_le_bytes(blob.get(..2)?.try_into().ok()?));
    let mut rest = blob.get(2..2 + len)?;
    let [version, flags, caller, package_kind] = take::<4>(&mut rest)?;
    if version != PLUGIN_RECORD_VERSION {
        return None;
    }
    let package_sha256 = take::<32>(&mut rest)?;
    let ticket_digest = take::<32>(&mut rest)?;
    let approval_nonce_sha256 = if flags & 4 != 0 {
        Some(take::<32>(&mut rest)?)
    } else {
        None
    };
    let content_sha256 = take::<32>(&mut rest)?;
    let content_len = u64::from_le_bytes(take::<8>(&mut rest)?);
    let options_sha256 = take::<32>(&mut rest)?;
    let plugin_id = read_text(&mut rest)?;
    let version = read_text(&mut rest)?;
    let operation = read_text(&mut rest)?;
    let grant_id = if flags & 8 != 0 {
        Some(read_text(&mut rest)?)
    } else {
        None
    };
    let subcode = if flags & 16 != 0 {
        Some(read_text(&mut rest)?)
    } else {
        None
    };
    Some((
        PluginAuditRecord {
            plugin_id,
            package_kind,
            package_sha256,
            version,
            operation,
            ticket_digest,
            approval_nonce_sha256,
            content_sha256,
            content_len,
            prehashed: flags & 2 != 0,
            options_sha256,
            caller: match caller {
                1 => PluginCallerKind::Browser,
                2 => PluginCallerKind::LocalOperator,
                3 => PluginCallerKind::ServiceClient,
                _ => return None,
            },
            declared: flags & 1 != 0,
            grant_id,
        },
        subcode,
    ))
}
impl DurableAuditGuard {
    /// Remembers and journals a refused ticketed use: tracing always, the journal while it is
    /// healthy and the operation's bound (a refusing plugin cannot fill it). Best effort: a
    /// refusal is already an outcome, and a journal that fails here is failed for the next use.
    fn refuse_plugin(
        state: &mut State,
        config: &AuditConfig,
        event: &KeyUseEvent,
        ticket: &PluginUse,
        reason: TicketRefusal,
    ) {
        let subcode = PluginRefusalCode::from(reason);
        tracing::warn!(
            target: "oncl::plugin_audit",
            operation = event.operation_id.get(),
            subcode = subcode.id(),
            ticket_digest = %hex(&ticket.digest()),
            "a plugin key use was refused before the key"
        );
        // Bounded per operation first (a noisy operation evicts its own oldest, never
        // another's), then overall.
        let mine = state
            .plugin_refusals
            .iter()
            .filter(|(id, _)| *id == event.operation_id)
            .count();
        if mine >= REFUSALS_PER_OPERATION
            && let Some(at) = state
                .plugin_refusals
                .iter()
                .position(|(id, _)| *id == event.operation_id)
        {
            state.plugin_refusals.remove(at);
        }
        if state.plugin_refusals.len() == REFUSAL_LOG {
            state.plugin_refusals.pop_front();
        }
        state
            .plugin_refusals
            .push_back((event.operation_id, reason));
        let _ = Self::journal_refusal(state, config, event, ticket, subcode);
    }
    fn journal_refusal(
        state: &mut State,
        config: &AuditConfig,
        event: &KeyUseEvent,
        ticket: &PluginUse,
        subcode: PluginRefusalCode,
    ) -> io::Result<()> {
        if state.health != AuditHealth::Healthy
            || !matches!(event.action, Action::Sign | Action::SignDigest)
        {
            // An action the frame cannot encode is traced, never journaled: an
            // undecodable frame would brick the journal.
            return Err(blocked());
        }
        let binding = state
            .bindings
            .get_mut(&event.operation_id)
            .ok_or_else(blocked)?;
        if binding.closed
            || binding.deadline.is_expired()
            || binding.refusals >= MAX_JOURNALED_REFUSALS
        {
            return Err(blocked());
        }
        binding.refusals += 1;
        let principal = binding.principal;
        let key = binding
            .keys
            .get(&event.key_id)
            .copied()
            .unwrap_or(AuditLabel([0; 16]));
        let detail = plugin_frames(
            &PluginAuditRecord::from_ticket(ticket, None, None),
            Some(subcode),
        )?;
        let reserved = (state.pending.len() as u64 + 3 + detail.len() as u64 + 1) * FRAME_BYTES;
        if state
            .segments
            .last()
            .unwrap()
            .bytes
            .checked_add(reserved)
            .is_none_or(|n| n > config.segment_bytes)
            || state
                .total
                .checked_add(reserved)
                .is_none_or(|n| n > config.quota_bytes)
        {
            // Only an idle journal rotates (and may retire old segments); a busy one keeps
            // its evidence and this refusal is traced only.
            Self::rotate(state, config, reserved)?;
            if state
                .segments
                .last()
                .unwrap()
                .bytes
                .checked_add(reserved)
                .is_none_or(|n| n > config.segment_bytes)
                || state
                    .total
                    .checked_add(reserved)
                    .is_none_or(|n| n > config.quota_bytes)
            {
                return Err(blocked());
            }
        }
        let first = state.sequence.checked_add(1).ok_or_else(blocked)?;
        let terminal_seq = first.checked_add(detail.len() as u64).ok_or_else(blocked)?;
        let operation_id = event.operation_id.get();
        let mut frames = Vec::with_capacity(detail.len() + 1);
        for (index, chunk) in detail.into_iter().enumerate() {
            let mut frame = blank(RecordKind::PluginDetail);
            frame.sequence = first + index as u64;
            frame.use_id = terminal_seq;
            frame.operation_id = operation_id;
            frame.chunk = Some(chunk);
            frames.push(frame);
        }
        let mut terminal = blank(RecordKind::PluginRefusal);
        terminal.sequence = terminal_seq;
        terminal.use_id = terminal_seq;
        terminal.operation_id = operation_id;
        terminal.session = state.session;
        terminal.principal = principal;
        terminal.key = key;
        terminal.unix_millis = now()?;
        terminal.action = Some(event.action);
        frames.push(terminal);
        Self::append_many(state, &frames)
    }
    /// The plugin key uses and refusals of the journal with their facts, oldest first, joined
    /// from their chunks, terminal frame and FINAL. A use with no FINAL has `finished: None`
    /// (`Unknown`). Chunks without a terminal frame (a use that never began) are omitted.
    pub fn plugin_records(&self) -> io::Result<Vec<PluginJournalRecord>> {
        let frames = self.records()?;
        let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut out: Vec<PluginJournalRecord> = Vec::new();
        let mut by_use: HashMap<u64, usize> = HashMap::new();
        for frame in frames {
            match frame.kind {
                RecordKind::PluginDetail => {
                    let chunk = frame.chunk.ok_or_else(damaged)?;
                    if chunk.index == 0 {
                        chunks.push((frame.use_id, Vec::new()));
                    }
                    chunks
                        .last_mut()
                        .ok_or_else(damaged)?
                        .1
                        .extend_from_slice(&chunk.bytes);
                }
                RecordKind::Begin | RecordKind::PluginRefusal => {
                    let Some(position) = chunks.iter().position(|(id, _)| *id == frame.use_id)
                    else {
                        continue;
                    };
                    let (_, blob) = chunks.swap_remove(position);
                    let (facts, refusal) = plugin_record(&blob).ok_or_else(damaged)?;
                    if refusal.is_none() {
                        by_use.insert(frame.use_id, out.len());
                    }
                    out.push(PluginJournalRecord {
                        use_id: frame.use_id,
                        operation_id: frame.operation_id,
                        facts,
                        refusal,
                        finished: None,
                    });
                }
                RecordKind::Final => {
                    if let Some(&at) = by_use.get(&frame.use_id) {
                        out[at].finished = Some((frame.applied, frame.succeeded));
                    }
                }
                _ => (),
            }
        }
        Ok(out)
    }
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
            read_identity(&identity_lock, None)?
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
            identity_lock,
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
            plugin_chunks: None,
            plugin_refusals: VecDeque::new(),
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
                check_version(&bytes)?;
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
                policy: None,
            }),
        })
    }
    /// Lets ticketed plugin key uses through, when `policy` accepts them (the operator's
    /// grants); without a policy every such use is refused with [`TicketRefusal::NoGuard`].
    /// Call it right after `create`/`open`, before the guard is cloned.
    ///
    /// # Errors
    ///
    /// `InvalidInput` if the guard was already cloned or bound: the policy would not be
    /// seen by the other holders.
    pub fn with_plugin_policy(mut self, policy: Arc<dyn PluginTicketPolicy>) -> io::Result<Self> {
        Arc::get_mut(&mut self.shared).ok_or_else(invalid)?.policy = Some(policy);
        Ok(self)
    }
    /// The plugin refusals recorded for `operation`, oldest first, without removing them.
    pub fn plugin_refusals(&self, operation: OperationId) -> Vec<TicketRefusal> {
        self.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .plugin_refusals
                    .iter()
                    .filter(|(id, _)| *id == operation)
                    .map(|(_, reason)| *reason)
                    .collect()
            },
        )
    }
    /// Removes and returns the plugin refusals recorded for `operation`: how the host reads
    /// the stable subcode of a refused call (`PluginRefusalCode::from`) after the engine
    /// returned `PermissionDenied`.
    pub fn take_plugin_refusals(&self, operation: OperationId) -> Vec<TicketRefusal> {
        let Ok(mut state) = self.lock() else {
            return Vec::new();
        };
        let mut taken = Vec::new();
        state.plugin_refusals.retain(|(id, reason)| {
            let mine = *id == operation;
            if mine {
                taken.push(*reason);
            }
            !mine
        });
        taken
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
        state.bindings.retain(|_, binding| {
            !binding.deadline.is_expired()
                && !(binding.closed && binding.weak.as_ref().is_some_and(|w| !w.is_live()))
        });
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
        let lease = ctx.lease();
        state.bindings.insert(
            ctx.id(),
            Binding {
                principal,
                keys: mapped,
                deadline: ctx.deadline(),
                weak: Some(lease.downgrade()),
                lease: Some(lease),
                closed: false,
                refusals: 0,
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
            RecordKind::PluginDetail => {
                let chunk = record.chunk.as_ref().ok_or_else(damaged)?;
                let ahead = u64::from(chunk.count - chunk.index);
                if record.use_id != record.sequence.checked_add(ahead).ok_or_else(damaged)? {
                    return Err(damaged());
                }
                state.plugin_chunks = match state.plugin_chunks {
                    Some((use_id, next, count))
                        if use_id == record.use_id
                            && next == chunk.index
                            && count == chunk.count =>
                    {
                        Some((use_id, next + 1, count))
                    }
                    // A new record; the earlier chunks never got their terminal frame.
                    _ if chunk.index == 0 => Some((record.use_id, 1, chunk.count)),
                    _ => return Err(damaged()),
                };
            }
            RecordKind::PluginRefusal => {
                if record.use_id != record.sequence {
                    return Err(damaged());
                }
                Self::close_chunks(state, record.use_id, true)?;
            }
            RecordKind::Begin => {
                Self::close_chunks(state, record.use_id, false)?;
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
                state.plugin_chunks = None;
                let prior = state.pending.remove(&record.use_id).ok_or_else(damaged)?;
                if prior.event.operation_id != record.operation_id
                    || prior.event.session != record.session
                    || prior.event.principal != record.principal
                    || prior.event.key != record.key
                    || prior.event.action != record.action
                    || prior.event.batch_item != record.batch_item
                {
                    return Err(damaged());
                }
            }
            RecordKind::Recovery => state.plugin_chunks = None,
            RecordKind::Header => return Err(damaged()),
        }
        state.sequence = record.sequence;
        Ok(())
    }
    /// A terminal frame of use `use_id` closes the chunks written for it, which must be
    /// complete. Chunks of another use never got their terminal frame and are dropped.
    fn close_chunks(state: &mut State, use_id: u64, required: bool) -> io::Result<()> {
        match state.plugin_chunks.take() {
            Some((id, next, count)) if id == use_id => {
                if next != count {
                    return Err(damaged());
                }
            }
            _ if required => return Err(damaged()),
            _ => (),
        }
        Ok(())
    }
    fn append(state: &mut State, record: &AuditEvent) -> io::Result<()> {
        Self::append_many(state, std::slice::from_ref(record))
    }
    /// Appends `records` (consecutive sequence numbers) in one write and one sync.
    fn append_many(state: &mut State, records: &[AuditEvent]) -> io::Result<()> {
        let previous_health = state.health;
        state.health = AuditHealth::Failed;
        if state.active.metadata()?.len() % FRAME_BYTES != 0 {
            return Err(blocked());
        }
        let mut bytes = Vec::with_capacity(records.len() * FRAME_BYTES as usize);
        for record in records {
            bytes.extend_from_slice(&encode(record, state.identity));
        }
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
            state.sequence = records.last().ok_or_else(blocked)?.sequence;
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
        if record.kind != RecordKind::Header && record.sequence > state.sequence {
            // A plugin use is several frames written at once: the failed write may have
            // persisted all of them, so take every frame after the known sequence.
            let gap = record.sequence - state.sequence;
            if gap > MAX_CHUNKS as u64 + 1 || len < (gap + 1) * FRAME_BYTES {
                return Err(damaged());
            }
            state
                .active
                .seek(SeekFrom::Start(len - gap * FRAME_BYTES))?;
            for _ in 0..gap {
                state.active.read_exact(&mut bytes)?;
                let record = decode(&bytes, state.identity)?;
                if record.sequence != state.sequence.checked_add(1).ok_or_else(blocked)? {
                    return Err(damaged());
                }
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
                    RecordKind::PluginDetail | RecordKind::PluginRefusal => (),
                    _ => return Err(damaged()),
                }
                state.sequence = record.sequence;
            }
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
        read_identity(&state.identity_lock, Some(state.identity))?;
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
        state.plugin_chunks = None;
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
        // A key use that carries a plugin ticket belongs to a declared plugin operation
        // (docs/design/manual-plugins.md 4.2/4.7): the operator's policy decides on it before
        // the journal is asked for a BEGIN, and without a policy it is refused. Whatever is
        // refused is journaled with its subcode (never a BEGIN: the key is not applied).
        // Plugin operations without declarations carry no ticket and run as before, with no
        // plugin record (`declared=false` is the absence of one).
        let mut plugin: Option<Vec<PluginChunk>> = None;
        if let Some(ticket) = event.plugin() {
            let decided = match self.shared.policy.as_deref() {
                Some(policy) => policy.check(event.operation_id, ticket),
                None => Err(TicketRefusal::NoGuard),
            };
            match decided {
                Ok(facts) => {
                    let mut record =
                        PluginAuditRecord::from_ticket(ticket, None, Some(facts.grant_id));
                    record.declared = facts.declared;
                    // A fact that cannot be journaled refuses the use here, before the
                    // journal is touched: it must not poison the service's audit health,
                    // and an unauditable use does not run.
                    match plugin_frames(&record, None) {
                        Ok(chunks) => plugin = Some(chunks),
                        Err(_) => {
                            Self::refuse_plugin(
                                &mut state,
                                &self.shared.config,
                                event,
                                ticket,
                                TicketRefusal::AuditFactTooLong,
                            );
                            return Err(OperationError::PermissionDenied);
                        }
                    }
                }
                Err(reason) => {
                    Self::refuse_plugin(&mut state, &self.shared.config, event, ticket, reason);
                    return Err(OperationError::PermissionDenied);
                }
            }
        }
        // Refusals decided before any journal I/O (expired deadline, closed or
        // unknown binding, table capacity) are per-request outcomes. Only a
        // failure of the journal itself may poison service-wide health.
        let journal_touched = std::cell::Cell::new(false);
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
            journal_touched.set(true);
            let detail = plugin.take().unwrap_or_default();
            // One reserved FINAL per pending BEGIN plus a recovery/probe frame; the plugin
            // chunks of this use come before its BEGIN in the same write.
            let reserved = (state.pending.len() as u64 + 3 + detail.len() as u64) * FRAME_BYTES;
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
                || state
                    .segments
                    .last()
                    .unwrap()
                    .bytes
                    .checked_add(reserved)
                    .is_none_or(|n| n > self.shared.config.segment_bytes)
            {
                return Err(blocked());
            }
            let first = state.sequence.checked_add(1).ok_or_else(blocked)?;
            let seq = first.checked_add(detail.len() as u64).ok_or_else(blocked)?;
            let mut record = blank(RecordKind::Begin);
            record.sequence = seq;
            record.use_id = seq;
            record.operation_id = event.operation_id.get();
            record.session = state.session;
            record.principal = principal;
            record.key = key;
            record.unix_millis = now()?;
            record.action = Some(event.action);
            record.batch_item = event.batch_item().map(|item| item.get());
            let mut frames = Vec::with_capacity(detail.len() + 1);
            for (index, chunk) in detail.into_iter().enumerate() {
                let mut frame = blank(RecordKind::PluginDetail);
                frame.sequence = first + index as u64;
                frame.use_id = seq;
                frame.operation_id = record.operation_id;
                frame.chunk = Some(chunk);
                frames.push(frame);
            }
            frames.push(record.clone());
            if let Err(error) = Self::append_many(&mut state, &frames) {
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
        if result.is_err() && journal_touched.get() {
            state.health = AuditHealth::Failed;
        }
        result.map_err(|_| OperationError::AuditFailed)
    }
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        let mut state = self.lock().map_err(|_| OperationError::AuditFailed)?;
        let event = receipt.event();
        if let Some(ticket) = event.plugin() {
            tracing::info!(
                target: "oncl::plugin_audit",
                operation = event.operation_id.get(),
                ticket_digest = %hex(&ticket.digest()),
                applied = ?outcome.applied,
                succeeded = outcome.succeeded,
                "a private key was applied for a plugin"
            );
        }
        let id = receipt.correlation().and_then(|(guard, id)| {
            let p = state.pending.get(&id)?;
            (guard == u64::from_le_bytes(state.session[..8].try_into().unwrap())
                && p.live
                && p.event.session == state.session
                && p.event.operation_id == event.operation_id.get()
                && p.key.as_ref() == Some(&event.key_id)
                && p.action == event.action
                && p.event.batch_item == event.batch_item().map(|item| item.get()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> PluginAuditRecord {
        PluginAuditRecord {
            plugin_id: "org.example.p".to_owned(),
            package_kind: 2,
            package_sha256: [3; 32],
            version: "0.1.0".to_owned(),
            operation: "sign".to_owned(),
            ticket_digest: [4; 32],
            approval_nonce_sha256: Some([5; 32]),
            content_sha256: [6; 32],
            content_len: u64::MAX,
            prehashed: false,
            options_sha256: [7; 32],
            caller: PluginCallerKind::LocalOperator,
            declared: true,
            grant_id: None,
        }
    }
    fn joined(chunks: &[PluginChunk]) -> Vec<u8> {
        chunks.iter().flat_map(|c| c.bytes).collect()
    }

    #[test]
    fn a_record_with_nonce_hash_and_subcode_round_trips_through_chunks() {
        for (subcode, grant) in [
            (None, None),
            (Some(PluginRefusalCode::KeyMismatch), Some("g".to_owned())),
        ] {
            let mut r = record();
            r.grant_id = grant;
            let chunks = plugin_frames(&r, subcode).unwrap();
            assert!(chunks.iter().all(|c| usize::from(c.count) == chunks.len()));
            let (back, code) = plugin_record(&joined(&chunks)).unwrap();
            assert_eq!(back, r);
            assert_eq!(code.as_deref(), subcode.map(PluginRefusalCode::id));
        }
    }

    #[test]
    fn the_nonce_is_never_in_the_chunks_only_what_the_record_names() {
        let chunks = plugin_frames(&record(), None).unwrap();
        // A record has no field for a nonce; the 16 raw nonce bytes of a test approval are
        // absent and the hash is what is present.
        let bytes = joined(&chunks);
        assert!(bytes.windows(32).any(|w| w == [5u8; 32]));
        assert!(!bytes.windows(16).any(|w| w == [0xA5u8; 16]));
    }

    #[test]
    fn oversized_texts_and_unknown_versions_are_refused_not_truncated() {
        let mut r = record();
        r.operation = "o".repeat(256);
        assert!(plugin_frames(&r, None).is_err());
        let mut r = record();
        r.plugin_id = "i".repeat(255);
        r.version = "v".repeat(255);
        r.operation = "o".repeat(255);
        r.grant_id = Some("g".repeat(255));
        let chunks = plugin_frames(&r, Some(PluginRefusalCode::Busy)).unwrap();
        assert!(chunks.len() <= MAX_CHUNKS);
        let mut bytes = joined(&chunks);
        bytes[2] = 2;
        assert!(plugin_record(&bytes).is_none());
        // Truncated bodies are no record either.
        let good = joined(&plugin_frames(&record(), None).unwrap());
        let len = usize::from(u16::from_le_bytes([good[0], good[1]]));
        assert!(plugin_record(&good[..len]).is_none());
    }

    #[test]
    fn chunk_frames_round_trip_through_encode_and_decode() {
        let identity = [9; 16];
        let mut frame = blank(RecordKind::PluginDetail);
        frame.sequence = 5;
        frame.use_id = 9;
        frame.operation_id = 3;
        let mut payload = [0; CHUNK_BYTES];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        frame.chunk = Some(PluginChunk {
            index: 2,
            count: 4,
            bytes: payload,
        });
        let bytes = encode(&frame, identity);
        let back = decode(&bytes, identity).unwrap();
        assert_eq!(back.kind, RecordKind::PluginDetail);
        assert_eq!((back.sequence, back.use_id, back.operation_id), (5, 9, 3));
        assert_eq!(back.chunk, frame.chunk);
        // Reserved bytes and out-of-range indexes fail closed even with a valid checksum.
        for (at, value) in [
            (105usize, 1u8),
            (124, 1),
            (126, 1),
            (106, 4),
            (107, 0),
            (107, 25),
        ] {
            let mut bad = bytes;
            bad[at] = value;
            let sum = checksum(&bad[..128]);
            bad[128..].copy_from_slice(&sum);
            assert!(decode(&bad, identity).is_err(), "byte {at}");
        }
    }
}
