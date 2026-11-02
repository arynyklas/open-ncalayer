//! Owned, bounded public PKI evidence and verified time provenance.
//!
//! Coverage is an explicit stream of signature/evidence/literal octets, with no
//! hidden framing. These primitives are not a standardized AdES wire format.
//! Format adapters must independently reconstruct their document binding and
//! standard-specific DER, canonical XML, or PDF ByteRange/archive rules.
use crate::cert::{self, Certificate};
use crate::digest::{DigestValue, HashState};
use crate::http::deadline::DeadlineTransport;
use crate::http::{MAX_RESPONSE_LEN, NonceSpec};
use crate::io::{Region, Source, StagedArtifact, TemporaryStore};
use crate::key::{HashAlg, PublicKey, SigAlg};
use crate::pkix::{self, PathError};
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope};
use crate::tsp::{self, TsaSpec, TspError};
use crate::validation::{
    self, CheckStatus, NetworkPolicy, SingleSignerReport, TimeBasis, ValidationContext,
    ValidationPolicy, ValidationReason, ValidationReport,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::Encode;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdesLevel {
    B,
    T,
    Lt,
    Lta,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Certificate,
    Ocsp,
    Crl,
    Timestamp,
}

/// Public evidence provenance only; never pass key containers or secrets here.
pub enum EvidenceOrigin<'a> {
    Embedded {
        label: &'a str,
    },
    Fetched {
        url: &'a str,
        obtained_at: OffsetDateTime,
    },
}
#[derive(Clone, Debug)]
pub struct EvidenceLimits {
    pub max_items: usize,
    pub max_bytes: u64,
    pub max_item_bytes: u64,
    pub max_chain_len: usize,
    pub max_proofs: usize,
    pub max_coverage_parts: usize,
    pub max_coverage_bytes: u64,
}
impl EvidenceLimits {
    fn validate(&self) -> Result<(), EvidenceError> {
        if self.max_items == 0
            || self.max_bytes == 0
            || self.max_item_bytes == 0
            || self.max_chain_len == 0
            || self.max_proofs == 0
            || self.max_coverage_parts == 0
            || self.max_coverage_bytes == 0
        {
            return Err(EvidenceError::Limit);
        }
        Ok(())
    }
}
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error(transparent)]
    Processing(#[from] ProcessingError),
    #[error("evidence size, count or work limit exceeded")]
    Limit,
    #[error("invalid evidence owner, coverage graph or timestamp configuration")]
    InvalidBinding,
    #[error(transparent)]
    Timestamp(#[from] TspError),
}

// Process-local, non-reusing identities. Exhaustion fails closed before storage.
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceId {
    owner: u64,
    index: usize,
}

pub struct EvidenceEntry {
    kind: EvidenceKind,
    region: Region,
    source: String,
    obtained_at: Option<OffsetDateTime>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl EvidenceEntry {
    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }
    pub fn region(&self) -> Region {
        self.region
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn obtained_at(&self) -> Option<OffsetDateTime> {
        self.obtained_at
    }
}

/// Inseparable staging, metadata, original operation control and reservations.
/// No Clone/Default/DerefMut or raw owning SDK-buffer escape is provided.
pub struct EvidenceBundle {
    owner: u64,
    entries: Vec<EvidenceEntry>,
    staged: StagedArtifact,
    scope: ResourceScope,
    limits: EvidenceLimits,
    intake_bytes: u64,
    poisoned: bool,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
pub struct EvidenceStore {
    bundle: EvidenceBundle,
}
impl EvidenceStore {
    pub fn new(
        store: TemporaryStore,
        limits: EvidenceLimits,
        scope: &mut ResourceScope,
    ) -> Result<Self, EvidenceError> {
        scope.checkpoint()?;
        limits.validate()?;
        let bytes = limits
            .max_items
            .checked_mul(std::mem::size_of::<EvidenceEntry>())
            .and_then(|n| n.checked_add(std::mem::size_of::<EvidenceBundle>()))
            .ok_or(EvidenceError::Limit)? as u64;
        let memory = scope.reserve_memory(bytes)?;
        let metadata = scope.reserve_metadata(bytes)?;
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| EvidenceError::Limit)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.max_items)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        let staged = store.stage(scope)?;
        Ok(Self {
            bundle: EvidenceBundle {
                owner,
                entries,
                staged,
                scope: scope.retain(),
                limits,
                intake_bytes: 0,
                poisoned: false,
                _memory: memory,
                _metadata: metadata,
            },
        })
    }
    pub fn collect(
        &mut self,
        kind: EvidenceKind,
        mut source: Source<'_>,
        origin: EvidenceOrigin<'_>,
    ) -> Result<EvidenceId, EvidenceError> {
        let bundle = &mut self.bundle;
        bundle.checkpoint()?;
        let remaining = bundle.limits.max_bytes.saturating_sub(bundle.intake_bytes);
        if bundle.entries.len() >= bundle.limits.max_items
            || source
                .known_len()
                .is_some_and(|n| n > remaining || n > bundle.limits.max_item_bytes)
        {
            return Err(EvidenceError::Limit);
        }
        let (label, obtained_at) = match origin {
            EvidenceOrigin::Embedded { label } => (label, None),
            EvidenceOrigin::Fetched { url, obtained_at } => (url, Some(obtained_at)),
        };
        // Provenance strings are untrusted metadata too, not an unbounded side channel.
        if label.len() > 4096 {
            return Err(EvidenceError::Limit);
        }
        let source_memory = bundle.scope.reserve_memory(label.len() as u64)?;
        let source_metadata = bundle.scope.reserve_metadata(label.len() as u64)?;
        let mut buffer = working_buffer(
            &bundle.scope,
            remaining.saturating_add(1).min(IO_CHUNK_BYTES as u64) as usize,
        )?;
        let offset = bundle.staged.len();
        let result = (|| {
            let mut length = 0u64;
            loop {
                bundle.checkpoint()?;
                let allowance = bundle
                    .limits
                    .max_item_bytes
                    .saturating_sub(length)
                    .min(bundle.limits.max_bytes.saturating_sub(bundle.intake_bytes));
                let request = allowance.saturating_add(1).min(buffer.bytes.len() as u64) as usize;
                let n = match source.read(&mut buffer.bytes[..request]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result.map_err(ProcessingError::from)?,
                };
                if n > request {
                    return Err(
                        ProcessingError::InvalidInput("reader exceeded evidence buffer").into(),
                    );
                }
                // Irrevocable consumption is retained even if quota/checkpoint/write fails.
                bundle.intake_bytes = bundle
                    .intake_bytes
                    .checked_add(n as u64)
                    .ok_or(EvidenceError::Limit)?;
                length = length.checked_add(n as u64).ok_or(EvidenceError::Limit)?;
                bundle.scope.account_container(n as u64)?;
                bundle.checkpoint()?;
                if length > bundle.limits.max_item_bytes
                    || bundle.intake_bytes > bundle.limits.max_bytes
                {
                    return Err(EvidenceError::Limit);
                }
                if n == 0 {
                    break;
                }
                bundle.staged.write_chunk(&buffer.bytes[..n])?;
            }
            bundle.checkpoint()?;
            Ok(length)
        })();
        let length = match result {
            Ok(length) => length,
            Err(error) => {
                bundle.poisoned = true;
                return Err(error);
            }
        };
        let id = EvidenceId {
            owner: bundle.owner,
            index: bundle.entries.len(),
        };
        bundle.entries.push(EvidenceEntry {
            kind,
            region: Region {
                offset,
                len: length,
            },
            source: label.to_owned(),
            obtained_at,
            _memory: source_memory,
            _metadata: source_metadata,
        });
        Ok(id)
    }
    /// Request only a bounded imprint. A collected token is NOT a trusted proof.
    pub fn request_timestamp(
        &mut self,
        signer: &SignerEvidence<'_>,
        coverage: &[CoveragePart<'_>],
        spec: &TsaSpec,
        ctx: &ValidationContext<'_>,
        network: &NetworkPolicy,
    ) -> Result<EvidenceId, EvidenceError> {
        self.bundle.checkpoint()?;
        if !spec.require_tsa_eku
            || !spec.cert_req
            || spec.policy.is_none()
            || spec.hash == HashAlg::Sha1
            || spec.retries > 2
            || spec.timeout.is_zero()
            || spec.url.len() > 4096
            || ctx.policy == ValidationPolicy::OfflineReport
            || match &spec.nonce {
                NonceSpec::None => true,
                NonceSpec::Random(n) => *n == 0 || *n > 64,
                NonceSpec::Value(value) => value.is_empty() || value.len() > 64,
            }
        {
            return Err(EvidenceError::InvalidBinding);
        }
        // Reject impossible token intake before hashing or contacting a responder.
        if self.bundle.entries.len() == self.bundle.limits.max_items
            || self.bundle.intake_bytes >= self.bundle.limits.max_bytes
        {
            return Err(EvidenceError::Limit);
        }
        let imprint = hash_coverage(&mut self.bundle, signer, coverage, spec.hash, None)?;
        // Covers bounded response/token/parser/nonce allocations before HTTP.
        let _scratch = self.bundle.scope.reserve_memory(MAX_RESPONSE_LEN * 20)?;
        let _metadata = self.bundle.scope.reserve_metadata(MAX_RESPONSE_LEN * 2)?;
        let http = DeadlineTransport::new(ctx.http, network, &self.bundle.scope);
        let result = tsp::request_at(spec, imprint.as_bytes(), &http, ctx.now);
        http.finish()?;
        let reply = result?;
        if reply.tst.gen_time > ctx.now {
            return Err(TspError::ClockSkew.into());
        }
        self.collect(
            EvidenceKind::Timestamp,
            Source::sequential(&mut reply.token.as_slice(), Some(reply.token.len() as u64)),
            EvidenceOrigin::Fetched {
                url: &spec.url,
                obtained_at: ctx.now,
            },
        )
    }
    /// Move the owner, including any poisoned state. No validation/publication is
    /// performed; a partially failed store remains unreadable after this move.
    pub fn finish(self) -> EvidenceBundle {
        self.bundle
    }
}
impl EvidenceBundle {
    fn checkpoint(&self) -> Result<(), EvidenceError> {
        self.scope.checkpoint()?;
        if self.poisoned {
            return Err(ProcessingError::InvalidInput("evidence intake is incomplete").into());
        }
        Ok(())
    }
    pub fn entry(&self, id: EvidenceId) -> Option<&EvidenceEntry> {
        if self.poisoned || id.owner != self.owner {
            return None;
        }
        self.entries.get(id.index)
    }
    fn checked_entry(&self, id: EvidenceId) -> Result<&EvidenceEntry, EvidenceError> {
        self.entry(id).ok_or(EvidenceError::InvalidBinding)
    }
    /// External, repeatable delivery is charged every time. Only internal
    /// Region replay is free of document output double-counting.
    pub fn copy_entry(
        &mut self,
        id: EvidenceId,
        output: &mut dyn Write,
    ) -> Result<u64, EvidenceError> {
        self.checkpoint()?;
        let mut region = self.checked_entry(id)?.region;
        let length = region.len;
        let mut buffer = working_buffer(&self.scope, IO_CHUNK_BYTES)?;
        while region.len != 0 {
            self.checkpoint()?;
            let n = self.staged.read_region(region, &mut buffer.bytes)?;
            // Reserve the whole offered chunk before user-controlled output;
            // short/failing writers may consume less, never more than charged.
            self.scope.account_output(n as u64)?;
            let mut bytes = &buffer.bytes[..n];
            while !bytes.is_empty() {
                self.checkpoint()?;
                let written = match output.write(bytes) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result.map_err(ProcessingError::from)?,
                };
                if written == 0 || written > bytes.len() {
                    return Err(ProcessingError::InvalidInput(
                        "evidence writer made invalid progress",
                    )
                    .into());
                }
                bytes = &bytes[written..];
                self.checkpoint()?;
            }
            region.offset = region
                .offset
                .checked_add(n as u64)
                .ok_or(EvidenceError::Limit)?;
            region.len -= n as u64;
        }
        self.checkpoint()?;
        output.flush().map_err(ProcessingError::from)?;
        self.checkpoint()?;
        Ok(length)
    }
}
struct WorkingBuffer {
    bytes: Vec<u8>,
    _memory: ResourceReservation,
}
fn working_buffer(scope: &ResourceScope, maximum: usize) -> Result<WorkingBuffer, ProcessingError> {
    let capacity = scope
        .available_memory()
        .min(maximum as u64)
        .min(IO_CHUNK_BYTES as u64) as usize;
    if capacity == 0 {
        return Err(ProcessingError::MemoryLimit);
    }
    let memory = scope.reserve_memory(capacity as u64)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    bytes.resize(capacity, 0);
    Ok(WorkingBuffer {
        bytes,
        _memory: memory,
    })
}

pub struct SignerEvidence<'a> {
    pub certificate: &'a Certificate,
    pub algorithm: SigAlg,
    pub signed_digest: DigestValue,
    pub signature: &'a [u8],
    pub claimed_time: Option<OffsetDateTime>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageEncoding {
    Raw,
    Base64,
}
pub enum CoveragePart<'a> {
    Signature,
    Evidence {
        id: EvidenceId,
        encoding: CoverageEncoding,
    },
    Bytes(&'a [u8]),
    /// Borrow already-staged profile bytes (e.g. a PDF ByteRange). No new spool,
    /// trusted digest or owning-buffer escape. Adapters must freeze their source
    /// across the complete format operation; each verification replays it.
    Staged {
        artifact: &'a std::sync::Mutex<StagedArtifact>,
        region: Region,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Signature,
    Archive,
}
pub struct TimestampBinding<'a> {
    pub token: EvidenceId,
    pub kind: ProofKind,
    pub coverage: &'a [CoveragePart<'a>],
}
/// Constructed only after imprint, signature, EKU, host trust and current
/// TSA-path status checks. Borrowed through immutable ScopedSigners.
#[derive(Debug, PartialEq, Eq)]
pub struct ProofTime {
    at: OffsetDateTime,
    token: EvidenceId,
    imprint: DigestValue,
}
impl ProofTime {
    pub fn at(&self) -> OffsetDateTime {
        self.at
    }
    pub fn token(&self) -> EvidenceId {
        self.token
    }
    pub fn imprint(&self) -> &DigestValue {
        &self.imprint
    }
}

fn coverage_size(
    bundle: &EvidenceBundle,
    signer: &SignerEvidence<'_>,
    parts: &[CoveragePart<'_>],
) -> Result<u64, EvidenceError> {
    if parts.is_empty() || parts.len() > bundle.limits.max_coverage_parts {
        return Err(EvidenceError::Limit);
    }
    let mut total = 0u64;
    for part in parts {
        let length = match part {
            CoveragePart::Signature => signer.signature.len() as u64,
            CoveragePart::Bytes(bytes) => bytes.len() as u64,
            CoveragePart::Staged { artifact, region } => {
                let mut artifact = lock_staged(artifact)?;
                artifact.read_region(*region, &mut [])?;
                region.len
            }
            CoveragePart::Evidence { id, encoding } => {
                let n = bundle.checked_entry(*id)?.region.len;
                match encoding {
                    CoverageEncoding::Raw => n,
                    CoverageEncoding::Base64 => n
                        .checked_add(2)
                        .and_then(|n| (n / 3).checked_mul(4))
                        .ok_or(EvidenceError::Limit)?,
                }
            }
        };
        total = total.checked_add(length).ok_or(EvidenceError::Limit)?;
        if total > bundle.limits.max_coverage_bytes {
            return Err(EvidenceError::Limit);
        }
    }
    Ok(total)
}
fn hash_coverage(
    bundle: &mut EvidenceBundle,
    signer: &SignerEvidence<'_>,
    parts: &[CoveragePart<'_>],
    algorithm: HashAlg,
    resources: Option<&ResourceScope>,
) -> Result<DigestValue, EvidenceError> {
    let work = resources.map_or_else(|| bundle.scope.retain(), ResourceScope::retain);
    let checkpoint = |bundle: &EvidenceBundle| -> Result<(), EvidenceError> {
        bundle.checkpoint()?;
        work.checkpoint()?;
        Ok(())
    };
    checkpoint(bundle)?;
    coverage_size(bundle, signer, parts)?;
    let _state = work.reserve_metadata(std::mem::size_of::<HashState>() as u64)?;
    let base64 = parts.iter().any(|p| {
        matches!(
            p,
            CoveragePart::Evidence {
                encoding: CoverageEncoding::Base64,
                ..
            }
        )
    });
    // Raw base64 chunks are multiples of three: only the final chunk is padded.
    let raw_max = if base64 {
        ((work.available_memory() / 7).min((IO_CHUNK_BYTES / 4) as u64) * 3) as usize
    } else {
        IO_CHUNK_BYTES
    };
    let mut raw = working_buffer(&work, raw_max)?;
    let mut encoded = if base64 {
        let capacity = raw.bytes.len() / 3 * 4;
        if capacity < 4 {
            return Err(ProcessingError::MemoryLimit.into());
        }
        // Round down raw capacity if a small live-memory budget shortened it.
        raw.bytes.truncate(capacity / 4 * 3);
        Some(working_buffer(&work, capacity)?)
    } else {
        None
    };
    if let Some(out) = &encoded {
        let raw_len = (out.bytes.len() / 4 * 3).min(raw.bytes.len());
        if raw_len == 0 {
            return Err(ProcessingError::MemoryLimit.into());
        }
        raw.bytes.truncate(raw_len);
    }
    let mut hash = HashState::new(algorithm);
    for part in parts {
        checkpoint(bundle)?;
        match part {
            CoveragePart::Signature => {
                for bytes in signer.signature.chunks(IO_CHUNK_BYTES) {
                    checkpoint(bundle)?;
                    hash.update(bytes);
                }
            }
            CoveragePart::Bytes(bytes) => {
                for bytes in bytes.chunks(IO_CHUNK_BYTES) {
                    checkpoint(bundle)?;
                    hash.update(bytes);
                }
            }
            CoveragePart::Staged { artifact, region } => {
                let mut source = lock_staged(artifact)?;
                let mut region = *region;
                while region.len != 0 {
                    checkpoint(bundle)?;
                    let n = source.read_region(region, &mut raw.bytes)?;
                    checkpoint(bundle)?;
                    hash.update(&raw.bytes[..n]);
                    region.offset = region
                        .offset
                        .checked_add(n as u64)
                        .ok_or(EvidenceError::Limit)?;
                    region.len -= n as u64;
                }
            }
            CoveragePart::Evidence { id, encoding } => {
                let mut region = bundle.checked_entry(*id)?.region;
                while region.len != 0 {
                    checkpoint(bundle)?;
                    let n = bundle.staged.read_region(region, &mut raw.bytes)?;
                    checkpoint(bundle)?;
                    match encoding {
                        CoverageEncoding::Raw => hash.update(&raw.bytes[..n]),
                        CoverageEncoding::Base64 => {
                            let out = encoded.as_mut().ok_or(EvidenceError::InvalidBinding)?;
                            let count = STANDARD
                                .encode_slice(&raw.bytes[..n], &mut out.bytes)
                                .map_err(|_| ProcessingError::MemoryLimit)?;
                            hash.update(&out.bytes[..count]);
                        }
                    }
                    region.offset = region
                        .offset
                        .checked_add(n as u64)
                        .ok_or(EvidenceError::Limit)?;
                    region.len -= n as u64;
                    checkpoint(bundle)?;
                }
            }
        }
    }
    checkpoint(bundle)?;
    Ok(hash.finish())
}

struct RawEvidence {
    kind: EvidenceKind,
    bytes: Vec<u8>,
}
struct ParsedEvidence {
    raw: Vec<RawEvidence>,
    candidates: Vec<Certificate>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
fn encoded_size(cert: &Certificate) -> Result<u64, EvidenceError> {
    cert.encoded_len()
        .map(|n| u32::from(n) as u64)
        .map_err(|_| ProcessingError::InvalidInput("invalid certificate encoding").into())
}
impl ParsedEvidence {
    fn read(
        bundle: &mut EvidenceBundle,
        signer: &SignerEvidence<'_>,
        ctx: &ValidationContext<'_>,
        resources: &ResourceScope,
    ) -> Result<Self, EvidenceError> {
        resources.checkpoint()?;
        bundle.checkpoint()?;
        let mut bytes = bundle
            .staged
            .len()
            .checked_add(encoded_size(signer.certificate)?)
            .ok_or(EvidenceError::Limit)?;
        for cert in ctx.intermediates.iter().chain(ctx.anchors.certs()) {
            resources.checkpoint()?;
            bundle.scope.checkpoint()?;
            bytes = bytes
                .checked_add(encoded_size(cert)?)
                .ok_or(EvidenceError::Limit)?;
        }
        // Charge retained raw evidence ONCE and concurrent parser/certificate/path
        // scratch before any decoder allocations. Never load an archive stream.
        let headers = bundle
            .entries
            .len()
            .checked_add(ctx.intermediates.len())
            .and_then(|n| {
                n.checked_mul(
                    std::mem::size_of::<RawEvidence>() + std::mem::size_of::<Certificate>() + 32,
                )
            })
            .ok_or(EvidenceError::Limit)? as u64;
        resources.checkpoint()?;
        bundle.scope.checkpoint()?;
        let memory = bundle.scope.reserve_memory(
            bytes
                .checked_mul(32)
                .and_then(|n| n.checked_add(headers))
                .ok_or(EvidenceError::Limit)?,
        )?;
        let metadata = bundle.scope.reserve_metadata(
            bytes
                .checked_mul(4)
                .and_then(|n| n.checked_add(headers))
                .ok_or(EvidenceError::Limit)?,
        )?;
        let mut raw = Vec::with_capacity(bundle.entries.len());
        let mut candidates = Vec::with_capacity(bundle.entries.len() + ctx.intermediates.len());
        candidates.extend_from_slice(ctx.intermediates);
        for entry in &bundle.entries {
            resources.checkpoint()?;
            bundle.scope.checkpoint()?;
            let len = usize::try_from(entry.region.len).map_err(|_| EvidenceError::Limit)?;
            let mut value = Vec::new();
            value
                .try_reserve_exact(len)
                .map_err(|_| ProcessingError::MemoryLimit)?;
            value.resize(len, 0);
            resources.checkpoint()?;
            bundle.scope.checkpoint()?;
            let mut region = entry.region;
            let mut offset = 0;
            while region.len != 0 {
                resources.checkpoint()?;
                let n = bundle.staged.read_region(region, &mut value[offset..])?;
                resources.checkpoint()?;
                region.offset += n as u64;
                region.len -= n as u64;
                offset += n;
            }
            if entry.kind == EvidenceKind::Certificate
                && let Ok(cert) = cert::parse(&value)
            {
                candidates.push(cert);
            }
            resources.checkpoint()?;
            bundle.scope.checkpoint()?;
            raw.push(RawEvidence {
                kind: entry.kind,
                bytes: value,
            });
        }
        resources.checkpoint()?;
        bundle.scope.checkpoint()?;
        Ok(Self {
            raw,
            candidates,
            _memory: memory,
            _metadata: metadata,
        })
    }
}
fn binding_graph(
    bundle: &EvidenceBundle,
    signer: &SignerEvidence<'_>,
    proofs: &[TimestampBinding<'_>],
) -> Result<(), EvidenceError> {
    if proofs.len() > bundle.limits.max_proofs {
        return Err(EvidenceError::Limit);
    }
    let mut previous = None;
    let mut signature_seen = false;
    for (position, proof) in proofs.iter().enumerate() {
        coverage_size(bundle, signer, proof.coverage)?;
        let entry = bundle.checked_entry(proof.token)?;
        if entry.kind != EvidenceKind::Timestamp
            || previous.is_some_and(|index| index >= proof.token.index)
        {
            return Err(EvidenceError::InvalidBinding);
        }
        previous = Some(proof.token.index);
        match proof.kind {
            ProofKind::Signature => {
                if signature_seen
                    || position != 0
                    || !matches!(proof.coverage, [CoveragePart::Signature])
                {
                    return Err(EvidenceError::InvalidBinding);
                }
                signature_seen = true;
            }
            ProofKind::Archive => {
                if !signature_seen {
                    return Err(EvidenceError::InvalidBinding);
                }
                let mut signature = false;
                let mut index = 0;
                for part in proof.coverage {
                    match part {
                        CoveragePart::Bytes(_) | CoveragePart::Staged { .. } => {}
                        CoveragePart::Signature if !signature && index == 0 => signature = true,
                        CoveragePart::Evidence { id, .. }
                            if signature
                                && id.owner == bundle.owner
                                && id.index == index
                                && index < proof.token.index =>
                        {
                            index += 1
                        }
                        _ => return Err(EvidenceError::InvalidBinding),
                    }
                }
                if !signature || index != proof.token.index {
                    return Err(EvidenceError::InvalidBinding);
                }
                for (index, item) in bundle.entries[..proof.token.index].iter().enumerate() {
                    if item.kind == EvidenceKind::Timestamp
                        && !proofs[..position]
                            .iter()
                            .any(|earlier| earlier.token.index == index)
                    {
                        return Err(EvidenceError::InvalidBinding);
                    }
                }
            }
        }
    }
    Ok(())
}
fn path_status<'a>(
    path: &[Certificate],
    at: OffsetDateTime,
    ctx: &ValidationContext<'_>,
    responses: &'a [&'a [u8]],
    crls: &'a [&'a [u8]],
    embedded_only: bool,
) -> (CheckStatus, Option<OffsetDateTime>) {
    let status = validation::offline_revocation(path, responses.iter().copied(), crls, at, ctx.now);
    if status.0 == CheckStatus::Unavailable
        && !embedded_only
        && ctx.policy != ValidationPolicy::OfflineReport
    {
        validation::online_path_status(path, at, ctx)
    } else {
        status
    }
}
fn combine(a: CheckStatus, b: CheckStatus) -> CheckStatus {
    if a == CheckStatus::Failed || b == CheckStatus::Failed {
        CheckStatus::Failed
    } else if a == CheckStatus::Unavailable || b == CheckStatus::Unavailable {
        CheckStatus::Unavailable
    } else {
        CheckStatus::Passed
    }
}

/// Check one real signature and its explicit proof graph. A required level is
/// not an achieved-format claim. Source digest/document reconstruction remains
/// the responsibility of the concrete format adapter.
pub fn validate_evidence(
    signer: &SignerEvidence<'_>,
    bundle: &mut EvidenceBundle,
    proofs: &[TimestampBinding<'_>],
    required: AdesLevel,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    resources: &ResourceScope,
) -> Result<ValidationReport, EvidenceError> {
    resources.checkpoint()?;
    bundle.checkpoint()?;
    binding_graph(bundle, signer, proofs)?;
    if signer.signature.len() as u64 > bundle.limits.max_item_bytes {
        return Err(EvidenceError::Limit);
    }
    let reason_capacity = proofs
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(16))
        .ok_or(EvidenceError::Limit)?;
    let report = SingleSignerReport::new(&bundle.scope, reason_capacity)?;
    let reason_bytes = reason_capacity
        .checked_mul(std::mem::size_of::<ValidationReason>())
        .ok_or(EvidenceError::Limit)? as u64;
    let _reason_memory = bundle.scope.reserve_memory(reason_bytes)?;
    let _reason_metadata = bundle.scope.reserve_metadata(reason_bytes)?;
    let parsed = ParsedEvidence::read(bundle, signer, ctx, resources)?;
    let responses: Vec<&[u8]> = parsed
        .raw
        .iter()
        .filter(|item| item.kind == EvidenceKind::Ocsp)
        .map(|item| item.bytes.as_slice())
        .collect();
    let crls: Vec<&[u8]> = parsed
        .raw
        .iter()
        .filter(|item| item.kind == EvidenceKind::Crl)
        .map(|item| item.bytes.as_slice())
        .collect();
    let original = bundle.scope.retain();
    // The outer owner-A transport and inner current-B transport independently
    // clamp the same request: the actual pinned delegate sees min(A, B, request).
    // The inner wrapper reauthorizes the same pins when send_pinned falls back
    // to send; neither destination/redirect policy nor proxy handling changes.
    let current = DeadlineTransport::new(ctx.http, network, resources);
    let http = DeadlineTransport::new(&current, network, &original);
    let scoped = ValidationContext {
        http: &http,
        ..*ctx
    };
    let finish = || -> Result<(), ProcessingError> {
        // Evaluate BOTH even if A fails; B may hold the fatal cause swallowed
        // by a PKI status parser. Do not downgrade it to unavailable evidence.
        let owner = http.finish();
        let validation = current.finish();
        owner.and(validation)
    };
    let result = (|| {
        let mut proof_time = None;
        let mut timestamp = CheckStatus::NotApplicable;
        let mut previous_time = None;
        let mut archive_valid = false;
        let mut reasons = Vec::with_capacity(reason_capacity);
        for proof in proofs {
            resources.checkpoint()?;
            bundle.checkpoint()?;
            let token = &parsed.raw[proof.token.index].bytes;
            let verified = tsp::verify_token_signed(token, true);
            resources.checkpoint()?;
            bundle.checkpoint()?;
            let (info, tsa) = match verified {
                Ok(value) => value,
                Err(_) => {
                    timestamp = combine(timestamp, CheckStatus::Failed);
                    continue;
                }
            };
            let Some(algorithm) =
                HashAlg::from_oid(&info.imprint_alg).filter(|alg| *alg != HashAlg::Sha1)
            else {
                timestamp = combine(timestamp, CheckStatus::Failed);
                continue;
            };
            let imprint =
                hash_coverage(bundle, signer, proof.coverage, algorithm, Some(resources))?;
            if tsp::check_imprint(&info, &imprint).is_err()
                || info.gen_time > ctx.now
                || previous_time.is_some_and(|at| info.gen_time < at)
            {
                timestamp = combine(timestamp, CheckStatus::Failed);
                continue;
            }
            resources.checkpoint()?;
            bundle.checkpoint()?;
            let built = pkix::build_anchored_path_limited(
                &tsa,
                ctx.anchors,
                &parsed.candidates,
                info.gen_time,
                bundle.limits.max_chain_len,
            );
            resources.checkpoint()?;
            bundle.checkpoint()?;
            let path = match built {
                Ok(path) => path,
                Err(PathError::TooLong) if bundle.limits.max_chain_len < pkix::MAX_PATH_LEN => {
                    return Err(EvidenceError::Limit);
                }
                Err(_) => {
                    timestamp = combine(timestamp, CheckStatus::Failed);
                    continue;
                }
            };
            let (status, revoked) = path_status(
                &path,
                info.gen_time,
                &scoped,
                &responses,
                &crls,
                required >= AdesLevel::Lt,
            );
            finish()?;
            timestamp = combine(timestamp, status);
            if let Some(reason) = validation::timestamp_reason_for(status, revoked, info.gen_time) {
                reasons.push(reason);
            }
            if status == CheckStatus::Passed {
                previous_time = Some(info.gen_time);
                match proof.kind {
                    ProofKind::Signature => {
                        proof_time = Some(ProofTime {
                            at: info.gen_time,
                            token: proof.token,
                            imprint,
                        })
                    }
                    ProofKind::Archive => {
                        archive_valid = proof_time.is_some() && timestamp == CheckStatus::Passed
                    }
                }
            }
        }
        if proofs.is_empty() && required >= AdesLevel::T {
            timestamp = CheckStatus::Unavailable;
        }
        if required == AdesLevel::Lta
            && (!archive_valid
                || !proofs.last().is_some_and(|proof| {
                    proof.kind == ProofKind::Archive
                        && proof.token.index + 1 == bundle.entries.len()
                }))
        {
            timestamp = combine(timestamp, CheckStatus::Unavailable);
        }
        resources.checkpoint()?;
        bundle.checkpoint()?;
        let at = proof_time.as_ref().map_or(ctx.now, ProofTime::at);
        let certificate_info = crate::info::cert_info(signer.certificate);
        let mut checked = validation::certificate_facts(signer.certificate, at, &certificate_info);
        resources.checkpoint()?;
        bundle.checkpoint()?;
        // Capacity was charged before any fact/reason allocation, including the
        // simultaneously live timestamp reasons and final signer reasons.
        checked
            .reasons
            .reserve_exact(reason_capacity.saturating_sub(checked.reasons.len()));
        checked.claimed_signing_time = signer.claimed_time;
        checked.time_basis = proof_time
            .as_ref()
            .map_or(TimeBasis::Current(ctx.now), |proof| {
                TimeBasis::VerifiedTimestamp(proof.at)
            });
        checked.proof_time = proof_time;
        checked.timestamp = timestamp;
        resources.checkpoint()?;
        bundle.checkpoint()?;
        let signature_valid = PublicKey::from_spki(
            signer
                .certificate
                .tbs_certificate()
                .subject_public_key_info(),
        )
        .and_then(|key| {
            key.verify_digest(signer.algorithm, &signer.signed_digest, signer.signature)
        })
        .is_ok();
        resources.checkpoint()?;
        bundle.checkpoint()?;
        if !signature_valid {
            checked.signature = CheckStatus::Failed;
            checked.reasons.push(ValidationReason::Signature(
                crate::cms::Problem::BadSignature,
            ));
        }
        let built = pkix::build_anchored_path_limited(
            signer.certificate,
            ctx.anchors,
            &parsed.candidates,
            validation::path_time(&certificate_info, at),
            bundle.limits.max_chain_len,
        );
        resources.checkpoint()?;
        bundle.checkpoint()?;
        match built {
            Ok(path) => {
                let (status, revoked) = path_status(
                    &path,
                    at,
                    &scoped,
                    &responses,
                    &crls,
                    required >= AdesLevel::Lt,
                );
                finish()?;
                checked.revocation = status;
                if let Some(time) = revoked {
                    checked.reasons.push(if time <= at {
                        ValidationReason::Revoked { at: time }
                    } else {
                        ValidationReason::RevokedAfterProvenTime { at: time }
                    });
                }
            }
            Err(PathError::TooLong) if bundle.limits.max_chain_len < pkix::MAX_PATH_LEN => {
                return Err(EvidenceError::Limit);
            }
            Err(_) => {
                checked.chain = CheckStatus::Failed;
                checked.reasons.push(ValidationReason::UntrustedChain);
            }
        }
        if checked.revocation == CheckStatus::Unavailable {
            checked
                .reasons
                .push(ValidationReason::RevocationUnavailable);
        }
        if matches!(timestamp, CheckStatus::Failed | CheckStatus::Unavailable) {
            checked.reasons.push(ValidationReason::Timestamp);
        }
        checked.reasons.extend(reasons);
        resources.checkpoint()?;
        bundle.checkpoint()?;
        Ok(report.finish(checked, ctx))
    })();
    finish()?;
    result
}

fn lock_staged(
    source: &std::sync::Mutex<StagedArtifact>,
) -> Result<std::sync::MutexGuard<'_, StagedArtifact>, ProcessingError> {
    match source.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::WouldBlock) => Err(ProcessingError::CapacityExceeded),
        Err(std::sync::TryLockError::Poisoned(_)) => Err(ProcessingError::InvalidInput(
            "staged coverage lock is poisoned",
        )),
    }
}
