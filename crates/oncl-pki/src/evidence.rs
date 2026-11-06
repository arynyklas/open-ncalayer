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
mod signature_representation;
pub use signature_representation::BoundSignatureRepresentation;
mod archive_representation;
pub use archive_representation::BoundArchiveRepresentation;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceLimits {
    pub max_items: usize,
    pub max_bytes: u64,
    pub max_item_bytes: u64,
    /// Aggregate CRL spool admission, separate from decoded certificate/OCSP/token
    /// limits. Every retained readback is still charged before allocation.
    pub max_crl_bytes: u64,
    /// Per-CRL spool admission, never exceeding MAX_CRL_LEN.
    pub max_crl_item_bytes: u64,
    /// Aggregate admission across CRLs and every other evidence category.
    pub max_total_bytes: u64,
    pub max_chain_len: usize,
    pub max_proofs: usize,
    pub max_coverage_parts: usize,
    pub max_coverage_bytes: u64,
}
impl EvidenceLimits {
    pub fn validate(&self) -> Result<(), EvidenceError> {
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
    crl_intake_bytes: u64,
    poisoned: bool,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
pub struct EvidenceStore {
    bundle: EvidenceBundle,
}
impl EvidenceStore {
    /// Continue the exact authentic owner, including counters and terminal
    /// poison. This move never creates a new store, scope, limit or allowance.
    pub fn resume(bundle: EvidenceBundle) -> Self {
        Self { bundle }
    }
    /// Internal public-evidence intake uses source-role scratch and container
    /// quotas, not final-output credit. Every external `copy_entry` delivery is
    /// separately admitted and charged, including repeat delivery.
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
        let staged = store.stage_source(scope)?;
        Ok(Self {
            bundle: EvidenceBundle {
                owner,
                entries,
                staged,
                scope: scope.retain(),
                limits,
                intake_bytes: 0,
                crl_intake_bytes: 0,
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
        let crl = kind == EvidenceKind::Crl;
        let maximum = if crl {
            bundle.limits.max_crl_bytes
        } else {
            bundle.limits.max_bytes
        };
        let item_maximum = if crl {
            bundle
                .limits
                .max_crl_item_bytes
                .min(crate::crl::MAX_CRL_LEN)
        } else {
            bundle.limits.max_item_bytes
        };
        let consumed = if crl {
            bundle.crl_intake_bytes
        } else {
            bundle.intake_bytes
        };
        let total_remaining = bundle
            .limits
            .max_total_bytes
            .saturating_sub(bundle.intake_bytes.saturating_add(bundle.crl_intake_bytes));
        let remaining = maximum.saturating_sub(consumed).min(total_remaining);
        if bundle.entries.len() >= bundle.limits.max_items
            || source
                .known_len()
                .is_some_and(|n| n > remaining || n > item_maximum)
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
                let consumed = if crl {
                    bundle.crl_intake_bytes
                } else {
                    bundle.intake_bytes
                };
                let allowance = item_maximum
                    .saturating_sub(length)
                    .min(maximum.saturating_sub(consumed))
                    .min(bundle.limits.max_total_bytes.saturating_sub(
                        bundle.intake_bytes.saturating_add(bundle.crl_intake_bytes),
                    ));
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
                let consumed = if crl {
                    &mut bundle.crl_intake_bytes
                } else {
                    &mut bundle.intake_bytes
                };
                *consumed = consumed.checked_add(n as u64).ok_or(EvidenceError::Limit)?;
                let total = *consumed;
                length = length.checked_add(n as u64).ok_or(EvidenceError::Limit)?;
                bundle.scope.account_container(n as u64)?;
                bundle.checkpoint()?;
                if length > item_maximum
                    || total > maximum
                    || bundle.intake_bytes.saturating_add(bundle.crl_intake_bytes)
                        > bundle.limits.max_total_bytes
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
    /// [`Self::collect`] of the DER that `encoded` carries as base64 text (ASCII whitespace
    /// ignored, padding only at the end): the text is decoded as it is read and only the
    /// decoded bytes are admitted, spooled and counted against the same item, aggregate
    /// and total quotas, so an encoded CRL is never materialised. The working buffers
    /// (16 KiB) are charged before they are allocated. Invalid text is
    /// `InvalidInput`, a quota breach is `Limit`, as for [`Self::collect`].
    pub fn collect_base64(
        &mut self,
        kind: EvidenceKind,
        encoded: Source<'_>,
        origin: EvidenceOrigin<'_>,
    ) -> Result<EvidenceId, EvidenceError> {
        let _memory = self
            .bundle
            .scope
            .reserve_memory(Base64Reader::<'_, Source<'_>>::WORKING)?;
        let failed = std::cell::Cell::new(false);
        let mut reader = Base64Reader::new(encoded, &failed);
        let result = self.collect(kind, Source::sequential(&mut reader, None), origin);
        match result {
            Err(EvidenceError::Processing(ProcessingError::Io(_))) if failed.get() => Err(
                EvidenceError::Processing(ProcessingError::InvalidInput("invalid base64 evidence")),
            ),
            other => other,
        }
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
        self.request_timestamp_impl(signer, coverage, spec, ctx, network, None)
    }
    /// Dynamic acquisition uses the original scope/deadline and a trusted host
    /// clock after the real reply. It does not mint a trusted timestamp fact.
    pub fn request_timestamp_with_clock(
        &mut self,
        signer: &SignerEvidence<'_>,
        coverage: &[CoveragePart<'_>],
        spec: &TsaSpec,
        ctx: &ValidationContext<'_>,
        network: &NetworkPolicy,
        clock: &(dyn Fn() -> OffsetDateTime + Send + Sync),
    ) -> Result<EvidenceId, EvidenceError> {
        self.request_timestamp_impl(signer, coverage, spec, ctx, network, Some(clock))
    }
    fn request_timestamp_impl(
        &mut self,
        signer: &SignerEvidence<'_>,
        coverage: &[CoveragePart<'_>],
        spec: &TsaSpec,
        ctx: &ValidationContext<'_>,
        network: &NetworkPolicy,
        clock: Option<&(dyn Fn() -> OffsetDateTime + Send + Sync)>,
    ) -> Result<EvidenceId, EvidenceError> {
        self.bundle.checkpoint()?;
        validate_timestamp_configuration(spec, ctx.policy)?;
        // Reject impossible token intake before hashing or contacting a responder.
        if self.bundle.entries.len() == self.bundle.limits.max_items
            || self.bundle.intake_bytes >= self.bundle.limits.max_bytes
        {
            return Err(EvidenceError::Limit);
        }
        if let [CoveragePart::BoundArchive(representation)] = coverage {
            representation.check_issuance(signer, &self.bundle)?;
        }
        let imprint = hash_coverage(&mut self.bundle, signer, coverage, spec.hash, None)?;
        // Covers bounded response/token/parser/nonce allocations before HTTP.
        let _scratch = self.bundle.scope.reserve_memory(MAX_RESPONSE_LEN * 20)?;
        let _metadata = self.bundle.scope.reserve_metadata(MAX_RESPONSE_LEN * 2)?;
        let http = DeadlineTransport::new(ctx.http, network, &self.bundle.scope);
        let result = if let Some(clock) = clock {
            tsp::request_with_clock_scoped(spec, imprint.as_bytes(), &http, clock)
        } else {
            tsp::request_at_scoped(spec, imprint.as_bytes(), &http, ctx.now)
                .map(|reply| (reply, ctx.now))
        };
        http.finish()?;
        let (scoped_reply, checked_at) = result?;
        let reply = &scoped_reply.reply;
        if reply.tst.gen_time > checked_at {
            return Err(TspError::ClockSkew.into());
        }
        self.collect(
            EvidenceKind::Timestamp,
            Source::sequential(&mut reply.token.as_slice(), Some(reply.token.len() as u64)),
            EvidenceOrigin::Fetched {
                url: &spec.url,
                obtained_at: checked_at,
            },
        )
    }
    /// Validate EVERY existing proof against proposed current LT material, then
    /// request the new archive that actually covers ALL of that material. No
    /// preflight ValidationReport/ProofTime/format-success token escapes.
    #[allow(
        clippy::too_many_arguments,
        reason = "Same F04 validator and TSA request require original proof, archive and host policy inputs"
    )]
    pub fn request_archive_timestamp_for_extension(
        &mut self,
        signer: &SignerEvidence<'_>,
        old_proofs: &[TimestampBinding<'_>],
        archive: &BoundArchiveRepresentation,
        spec: &TsaSpec,
        ctx: &ValidationContext<'_>,
        network: &NetworkPolicy,
        clock: Option<&(dyn Fn() -> OffsetDateTime + Send + Sync)>,
    ) -> Result<EvidenceId, EvidenceError> {
        self.bundle.checkpoint()?;
        validate_timestamp_configuration(spec, ctx.policy)?;
        archive.check_issuance(signer, &self.bundle)?;
        let timestamp_count = self
            .bundle
            .entries
            .iter()
            .filter(|entry| entry.kind == EvidenceKind::Timestamp)
            .count();
        if timestamp_count != old_proofs.len() {
            return Err(EvidenceError::InvalidBinding);
        }
        for (index, entry) in self.bundle.entries.iter().enumerate() {
            if entry.kind == EvidenceKind::Timestamp
                && old_proofs
                    .iter()
                    .filter(|proof| {
                        proof.token
                            == EvidenceId {
                                owner: self.bundle.owner,
                                index,
                            }
                    })
                    .count()
                    != 1
            {
                return Err(EvidenceError::InvalidBinding);
            }
        }
        let resources = self.bundle.scope.retain();
        let current = ValidationContext {
            now: clock.map_or(ctx.now, |clock| clock()),
            ..*ctx
        };
        let checked = validate_evidence_impl(
            signer,
            &mut self.bundle,
            old_proofs,
            AdesLevel::Lt,
            &current,
            network,
            &resources,
            None,
            None,
            None,
            ValidationPurpose::ArchiveIssuance,
        )?;
        if checked.verdict != crate::validation::Verdict::Valid {
            return Err(EvidenceError::InvalidBinding);
        }
        resources.checkpoint()?;
        self.request_timestamp_impl(
            signer,
            &[CoveragePart::BoundArchive(archive)],
            spec,
            ctx,
            network,
            clock,
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
    /// Internal bounded evidence replay for parsing/serialization. This is not
    /// an external delivery claim; final serialized sinks must be accounted by
    /// their format. `copy_entry` remains counted on EVERY external delivery.
    pub fn read_entry(
        &mut self,
        id: EvidenceId,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<usize, EvidenceError> {
        self.checkpoint()?;
        if bytes.len() > IO_CHUNK_BYTES {
            return Err(EvidenceError::Limit);
        }
        let region = self.checked_entry(id)?.region;
        if offset > region.len {
            return Err(EvidenceError::InvalidBinding);
        }
        let n = self.staged.read_region(
            Region {
                offset: region
                    .offset
                    .checked_add(offset)
                    .ok_or(EvidenceError::Limit)?,
                len: region.len - offset,
            },
            bytes,
        )?;
        self.checkpoint()?;
        Ok(n)
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
    BoundSignature(&'a BoundSignatureRepresentation),
    /// Actual ordered archive octets with current complete signature and prior
    /// evidence inclusion checked; format semantics remain the adapter's job.
    BoundArchive(&'a BoundArchiveRepresentation),
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
    /// Immutable captured bytes. Used by the closed inclusion-bound PDF adapter;
    /// this is not a caller-supplied digest or an owning source capability.
    Snapshot {
        input: &'a dyn crate::io::PdfSnapshotCoverage,
        region: Region,
    },
    /// Hash a reconstructed standard component, not a caller-supplied digest.
    /// Nested work and output bytes share the enclosing coverage quotas.
    Hashed {
        algorithm: HashAlg,
        parts: &'a [CoveragePart<'a>],
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Signature,
    Archive,
    /// RFC3161 over immutable document ranges; only the closed in-crate
    /// inclusion adapter can authorize this graph shape.
    Document,
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
    fn measure(
        bundle: &EvidenceBundle,
        signer: &SignerEvidence<'_>,
        parts: &[CoveragePart<'_>],
        depth: usize,
        count: &mut usize,
        work: &mut u64,
    ) -> Result<u64, EvidenceError> {
        if parts.is_empty() || depth > 8 {
            return Err(EvidenceError::Limit);
        }
        let mut size = 0u64;
        for part in parts {
            *count = count.checked_add(1).ok_or(EvidenceError::Limit)?;
            if *count > bundle.limits.max_coverage_parts {
                return Err(EvidenceError::Limit);
            }
            let length = match part {
                CoveragePart::Signature => signer.signature.len() as u64,
                CoveragePart::Bytes(bytes) => bytes.len() as u64,
                CoveragePart::BoundSignature(representation) => {
                    representation.check(signer, &bundle.scope)?;
                    representation.region.len
                }
                CoveragePart::BoundArchive(representation) => {
                    if depth != 0 || parts.len() != 1 {
                        return Err(EvidenceError::InvalidBinding);
                    }
                    representation.check(signer, bundle, &bundle.scope, None)?;
                    representation.region.len
                }
                CoveragePart::Staged { artifact, region } => {
                    lock_staged(artifact)?.read_region(*region, &mut [])?;
                    region.len
                }
                CoveragePart::Snapshot { input, region } => {
                    input.read_region(*region, &mut [])?;
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
                CoveragePart::Hashed { algorithm, parts } => {
                    measure(bundle, signer, parts, depth + 1, count, work)?;
                    match algorithm {
                        HashAlg::Sha1 => 20,
                        HashAlg::Sha256 | HashAlg::Gost34311 | HashAlg::Streebog256 => 32,
                        HashAlg::Sha512 | HashAlg::Streebog512 => 64,
                    }
                }
            };
            *work = work.checked_add(length).ok_or(EvidenceError::Limit)?;
            if *work > bundle.limits.max_coverage_bytes {
                return Err(EvidenceError::Limit);
            }
            size = size.checked_add(length).ok_or(EvidenceError::Limit)?;
        }
        Ok(size)
    }
    measure(bundle, signer, parts, 0, &mut 0, &mut 0)
}
struct CoverageHasher<'a, 'b, 'c> {
    bundle: &'a mut EvidenceBundle,
    signer: &'b SignerEvidence<'c>,
    work: ResourceScope,
    raw: WorkingBuffer,
    encoded: Option<WorkingBuffer>,
}
impl CoverageHasher<'_, '_, '_> {
    fn checkpoint(&self) -> Result<(), EvidenceError> {
        self.bundle.checkpoint()?;
        self.work.checkpoint()?;
        Ok(())
    }
    fn feed(
        &mut self,
        parts: &[CoveragePart<'_>],
        hash: &mut HashState,
    ) -> Result<(), EvidenceError> {
        for part in parts {
            self.checkpoint()?;
            match part {
                CoveragePart::Signature => {
                    for bytes in self.signer.signature.chunks(IO_CHUNK_BYTES) {
                        self.checkpoint()?;
                        hash.update(bytes);
                    }
                }
                CoveragePart::BoundSignature(representation) => {
                    representation.check(self.signer, &self.bundle.scope)?;
                    representation.check(self.signer, &self.work)?;
                    let mut source = lock_staged(&representation.artifact)?;
                    let mut region = representation.region;
                    while region.len != 0 {
                        self.checkpoint()?;
                        let n = source.read_region(region, &mut self.raw.bytes)?;
                        if n == 0 {
                            return Err(EvidenceError::InvalidBinding);
                        }
                        self.checkpoint()?;
                        hash.update(&self.raw.bytes[..n]);
                        region.offset = region
                            .offset
                            .checked_add(n as u64)
                            .ok_or(EvidenceError::Limit)?;
                        region.len -= n as u64;
                    }
                }
                CoveragePart::BoundArchive(representation) => {
                    representation.check(self.signer, self.bundle, &self.work, None)?;
                    let mut source = lock_staged(&representation.artifact)?;
                    let mut region = representation.region;
                    while region.len != 0 {
                        self.checkpoint()?;
                        let n = source.read_region(region, &mut self.raw.bytes)?;
                        if n == 0 {
                            return Err(EvidenceError::InvalidBinding);
                        }
                        hash.update(&self.raw.bytes[..n]);
                        region.offset = region
                            .offset
                            .checked_add(n as u64)
                            .ok_or(EvidenceError::Limit)?;
                        region.len -= n as u64;
                    }
                }
                CoveragePart::Bytes(bytes) => {
                    for bytes in bytes.chunks(IO_CHUNK_BYTES) {
                        self.checkpoint()?;
                        hash.update(bytes);
                    }
                }
                CoveragePart::Hashed { algorithm, parts } => {
                    let mut nested = HashState::new(*algorithm);
                    self.feed(parts, &mut nested)?;
                    hash.update(nested.finish().as_bytes());
                }
                CoveragePart::Staged { artifact, region } => {
                    let mut source = lock_staged(artifact)?;
                    let mut region = *region;
                    while region.len != 0 {
                        self.checkpoint()?;
                        let n = source.read_region(region, &mut self.raw.bytes)?;
                        self.checkpoint()?;
                        if n == 0 {
                            return Err(ProcessingError::InvalidInput(
                                "short staged coverage source",
                            )
                            .into());
                        }
                        hash.update(&self.raw.bytes[..n]);
                        region.offset = region
                            .offset
                            .checked_add(n as u64)
                            .ok_or(EvidenceError::Limit)?;
                        region.len -= n as u64;
                    }
                }
                CoveragePart::Snapshot { input, region } => {
                    let source = input;
                    let mut region = *region;
                    while region.len != 0 {
                        self.checkpoint()?;
                        let n = source.read_region(region, &mut self.raw.bytes)?;
                        self.checkpoint()?;
                        if n == 0 {
                            return Err(ProcessingError::InvalidInput(
                                "short snapshot coverage source",
                            )
                            .into());
                        }
                        hash.update(&self.raw.bytes[..n]);
                        region.offset = region
                            .offset
                            .checked_add(n as u64)
                            .ok_or(EvidenceError::Limit)?;
                        region.len -= n as u64;
                    }
                }
                CoveragePart::Evidence { id, encoding } => {
                    let mut region = self.bundle.checked_entry(*id)?.region;
                    while region.len != 0 {
                        self.checkpoint()?;
                        let n = self
                            .bundle
                            .staged
                            .read_region(region, &mut self.raw.bytes)?;
                        self.checkpoint()?;
                        if n == 0 {
                            return Err(ProcessingError::InvalidInput(
                                "short evidence coverage source",
                            )
                            .into());
                        }
                        match encoding {
                            CoverageEncoding::Raw => hash.update(&self.raw.bytes[..n]),
                            CoverageEncoding::Base64 => {
                                let out =
                                    self.encoded.as_mut().ok_or(EvidenceError::InvalidBinding)?;
                                let count = STANDARD
                                    .encode_slice(&self.raw.bytes[..n], &mut out.bytes)
                                    .map_err(|_| ProcessingError::MemoryLimit)?;
                                hash.update(&out.bytes[..count]);
                            }
                        }
                        region.offset = region
                            .offset
                            .checked_add(n as u64)
                            .ok_or(EvidenceError::Limit)?;
                        region.len -= n as u64;
                    }
                }
            }
        }
        self.checkpoint()
    }
}
fn hash_coverage(
    bundle: &mut EvidenceBundle,
    signer: &SignerEvidence<'_>,
    parts: &[CoveragePart<'_>],
    algorithm: HashAlg,
    resources: Option<&ResourceScope>,
) -> Result<DigestValue, EvidenceError> {
    let work = resources.map_or_else(|| bundle.scope.retain(), ResourceScope::retain);
    bundle.checkpoint()?;
    work.checkpoint()?;
    // This walk validates total (not per-recursion) work, part count and depth
    // before either recursive discovery or any hash state is constructed.
    coverage_size(bundle, signer, parts)?;
    fn features(parts: &[CoveragePart<'_>]) -> (bool, usize) {
        let mut base64 = false;
        let mut depth = 0;
        for part in parts {
            match part {
                CoveragePart::Evidence {
                    encoding: CoverageEncoding::Base64,
                    ..
                } => base64 = true,
                CoveragePart::Hashed { parts, .. } => {
                    let (nested_base64, nested_depth) = features(parts);
                    base64 |= nested_base64;
                    depth = depth.max(nested_depth + 1);
                }
                _ => {}
            }
        }
        (base64, depth)
    }
    let (base64, depth) = features(parts);
    let state_bytes = ((depth + 1) * std::mem::size_of::<HashState>()) as u64;
    let _state_metadata = work.reserve_metadata(state_bytes)?;
    let _state_memory = work.reserve_memory(state_bytes)?;
    // Every nested standard hash reuses these same admitted buffers. Base64
    // chunks stay multiples of three, so only the final chunk is padded.
    let raw_max = if base64 {
        ((work.available_memory() / 7).min((IO_CHUNK_BYTES / 4) as u64) * 3) as usize
    } else {
        IO_CHUNK_BYTES
    };
    let mut raw = working_buffer(&work, raw_max)?;
    let encoded = if base64 {
        let capacity = raw.bytes.len() / 3 * 4;
        if capacity < 4 {
            return Err(ProcessingError::MemoryLimit.into());
        }
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
    let mut hasher = CoverageHasher {
        bundle,
        signer,
        work,
        raw,
        encoded,
    };
    hasher.feed(parts, &mut hash)?;
    Ok(hash.finish())
}

struct RawEvidence {
    kind: EvidenceKind,
    bytes: Vec<u8>,
}
// Immutable syntax/signature math only, never a cached host verdict. Allocate
// these records only for actual tokens, not for each certificate/status entry.
type DecodedTimestamp = (usize, Result<(tsp::TstInfo, Certificate), tsp::TspError>);
struct ParsedEvidence {
    raw: Vec<RawEvidence>,
    candidates: Vec<(Option<EvidenceId>, Certificate)>,
    timestamps: Vec<DecodedTimestamp>,
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
        let timestamp_count = bundle
            .entries
            .iter()
            .filter(|entry| entry.kind == EvidenceKind::Timestamp)
            .count();
        let headers = bundle
            .entries
            .len()
            .checked_add(ctx.intermediates.len())
            .and_then(|n| {
                n.checked_mul(
                    std::mem::size_of::<RawEvidence>() + std::mem::size_of::<Certificate>() + 32,
                )
            })
            .and_then(|n| {
                timestamp_count
                    .checked_mul(std::mem::size_of::<DecodedTimestamp>())
                    .and_then(|timestamps| n.checked_add(timestamps))
            })
            .ok_or(EvidenceError::Limit)? as u64;
        resources.checkpoint()?;
        bundle.scope.checkpoint()?;
        // CRLs are loaded as raw bytes and only scanned (never decoded into a tree):
        // retained once. Certificates, tokens and OCSP answers decode and amplify.
        let crl_bytes = bundle
            .entries
            .iter()
            .filter(|entry| entry.kind == EvidenceKind::Crl)
            .try_fold(0u64, |sum, entry| sum.checked_add(entry.region.len))
            .ok_or(EvidenceError::Limit)?;
        let decoded = bytes.saturating_sub(crl_bytes);
        let memory = bundle.scope.reserve_memory(
            decoded
                .checked_mul(32)
                .and_then(|n| n.checked_add(crl_bytes))
                .and_then(|n| n.checked_add(headers))
                .ok_or(EvidenceError::Limit)?,
        )?;
        let metadata = bundle.scope.reserve_metadata(
            decoded
                .checked_mul(4)
                .and_then(|n| n.checked_add(crl_bytes))
                .and_then(|n| n.checked_add(headers))
                .ok_or(EvidenceError::Limit)?,
        )?;
        let mut raw = Vec::with_capacity(bundle.entries.len());
        let mut candidates = Vec::with_capacity(bundle.entries.len() + ctx.intermediates.len());
        let mut timestamps = Vec::with_capacity(timestamp_count);
        candidates.extend(ctx.intermediates.iter().cloned().map(|cert| (None, cert)));
        for (index, entry) in bundle.entries.iter().enumerate() {
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
                candidates.push((
                    Some(EvidenceId {
                        owner: bundle.owner,
                        index,
                    }),
                    cert,
                ));
            }
            resources.checkpoint()?;
            bundle.scope.checkpoint()?;
            if entry.kind == EvidenceKind::Timestamp {
                timestamps.push((index, tsp::verify_token_signed(&value, true)));
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
            timestamps,
            _memory: memory,
            _metadata: metadata,
        })
    }
}
/// Only concrete in-crate standard adapters may derive selections. Public
/// callers keep the original complete-bundle graph and cannot supply a skiplist.
pub(crate) struct ArchiveSelection<'a> {
    pub token: EvidenceId,
    pub protected: &'a [EvidenceId],
    /// Format-derived index algorithm, bound to the cryptographically checked
    /// TSTInfo message imprint, not the TSA's independent signature algorithm.
    pub algorithm: HashAlg,
}
fn binding_graph(
    bundle: &EvidenceBundle,
    signer: &SignerEvidence<'_>,
    proofs: &[TimestampBinding<'_>],
    selections: Option<&[ArchiveSelection<'_>]>,
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
            || (selections.is_none() && previous.is_some_and(|index| index >= proof.token.index))
            || proofs[..position]
                .iter()
                .any(|earlier| earlier.token == proof.token)
        {
            return Err(EvidenceError::InvalidBinding);
        }
        previous = Some(proof.token.index);
        match proof.kind {
            ProofKind::Signature => {
                if signature_seen
                    || position != 0
                    || !matches!(
                        proof.coverage,
                        [CoveragePart::Signature] | [CoveragePart::BoundSignature(_)]
                    )
                {
                    return Err(EvidenceError::InvalidBinding);
                }
                signature_seen = true;
            }
            ProofKind::Archive => {
                if !signature_seen {
                    return Err(EvidenceError::InvalidBinding);
                }
                if let [CoveragePart::BoundArchive(representation)] = proof.coverage {
                    if selections.is_some() {
                        return Err(EvidenceError::InvalidBinding);
                    }
                    representation.check(signer, bundle, &bundle.scope, Some(proof.token))?;
                    // All prior timestamp entries must be actual earlier proofs.
                    for (index, entry) in bundle.entries[..proof.token.index].iter().enumerate() {
                        if entry.kind == EvidenceKind::Timestamp
                            && !proofs[..position].iter().any(|p| p.token.index == index)
                        {
                            return Err(EvidenceError::InvalidBinding);
                        }
                    }
                    continue;
                }
                let selected = selections
                    .and_then(|values| values.iter().find(|value| value.token == proof.token))
                    .map(|value| value.protected);
                if selections.is_some() && selected.is_none() {
                    return Err(EvidenceError::InvalidBinding);
                }
                fn walk(
                    parts: &[CoveragePart<'_>],
                    bundle: &EvidenceBundle,
                    token: EvidenceId,
                    selected: Option<&[EvidenceId]>,
                    signature: &mut bool,
                    index: &mut usize,
                    depth: usize,
                ) -> Result<(), EvidenceError> {
                    for part in parts {
                        match part {
                            CoveragePart::Bytes(_) | CoveragePart::Staged { .. } => {}
                            CoveragePart::Hashed { parts, .. } => {
                                walk(parts, bundle, token, selected, signature, index, depth + 1)?;
                            }
                            CoveragePart::Signature if !*signature && *index == 0 && depth == 0 => {
                                *signature = true;
                            }
                            CoveragePart::Evidence { id, .. }
                                if *signature
                                    && id.owner == bundle.owner
                                    && *id != token
                                    && (selected.is_some() || id.index < token.index)
                                    && selected.map_or(id.index == *index, |ids| {
                                        ids.get(*index) == Some(id)
                                    }) =>
                            {
                                *index += 1;
                            }
                            _ => return Err(EvidenceError::InvalidBinding),
                        }
                    }
                    Ok(())
                }
                let mut signature = false;
                let mut index = 0;
                walk(
                    proof.coverage,
                    bundle,
                    proof.token,
                    selected,
                    &mut signature,
                    &mut index,
                    0,
                )?;
                if !signature || index != selected.map_or(proof.token.index, <[EvidenceId]>::len) {
                    return Err(EvidenceError::InvalidBinding);
                }
                for item_index in 0..selected.map_or(proof.token.index, |_| bundle.entries.len()) {
                    let id = EvidenceId {
                        owner: bundle.owner,
                        index: item_index,
                    };
                    let covered = selected.is_none_or(|ids| ids.contains(&id));
                    let prior = proofs[..position].iter().any(|earlier| earlier.token == id);
                    if bundle.entries[item_index].kind == EvidenceKind::Timestamp
                        && ((covered && !prior) || (prior && !covered))
                    {
                        return Err(EvidenceError::InvalidBinding);
                    }
                }
                if let Some(ids) = selected {
                    for (position, id) in ids.iter().enumerate() {
                        bundle.checked_entry(*id)?;
                        if ids[..position].contains(id) {
                            return Err(EvidenceError::InvalidBinding);
                        }
                    }
                }
            }
            ProofKind::Document => return Err(EvidenceError::InvalidBinding),
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
    validate_evidence_impl(
        signer,
        bundle,
        proofs,
        required,
        ctx,
        network,
        resources,
        None,
        None,
        None,
        ValidationPurpose::Final,
    )
}

/// One decoded common store for a multi-signer format operation. It cannot be
/// constructed or transferred outside the concrete in-crate adapters.
pub(crate) struct PreparedEvidence {
    owner: u64,
    parsed: ParsedEvidence,
}
impl PreparedEvidence {
    pub(crate) fn has_certificate(&self, id: EvidenceId) -> bool {
        id.owner == self.owner
            && self
                .parsed
                .candidates
                .iter()
                .any(|(candidate, _)| *candidate == Some(id))
    }
}
pub(crate) fn prepare_evidence(
    signer: &SignerEvidence<'_>,
    bundle: &mut EvidenceBundle,
    ctx: &ValidationContext<'_>,
    resources: &ResourceScope,
) -> Result<PreparedEvidence, EvidenceError> {
    Ok(PreparedEvidence {
        owner: bundle.owner,
        parsed: ParsedEvidence::read(bundle, signer, ctx, resources)?,
    })
}
#[allow(
    clippy::too_many_arguments,
    reason = "Existing F04 checks with one borrowed cache and format-derived selection, not a second validator"
)]
pub(crate) fn validate_prepared_evidence(
    signer: &SignerEvidence<'_>,
    bundle: &mut EvidenceBundle,
    proofs: &[TimestampBinding<'_>],
    required: AdesLevel,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    resources: &ResourceScope,
    selections: Option<&[ArchiveSelection<'_>]>,
    prepared: &PreparedEvidence,
) -> Result<ValidationReport, EvidenceError> {
    if prepared.owner != bundle.owner {
        return Err(EvidenceError::InvalidBinding);
    }
    validate_evidence_impl(
        signer,
        bundle,
        proofs,
        required,
        ctx,
        network,
        resources,
        selections,
        Some(&prepared.parsed),
        None,
        ValidationPurpose::Final,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "Closed format binding into the existing F04 validator"
)]
pub(crate) fn validate_snapshot_evidence(
    signer: &SignerEvidence<'_>,
    bundle: &mut EvidenceBundle,
    proofs: &[TimestampBinding<'_>],
    required: AdesLevel,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    resources: &ResourceScope,
    prepared: &PreparedEvidence,
    graph: &crate::cms::ades::pdf::SnapshotProofGraph<'_, '_>,
) -> Result<ValidationReport, EvidenceError> {
    if prepared.owner != bundle.owner {
        return Err(EvidenceError::InvalidBinding);
    }
    validate_evidence_impl(
        signer,
        bundle,
        proofs,
        required,
        ctx,
        network,
        resources,
        None,
        Some(&prepared.parsed),
        Some(graph),
        ValidationPurpose::Final,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValidationPurpose {
    Final,
    ArchiveIssuance,
}

#[allow(
    clippy::too_many_arguments,
    reason = "Same F04 validator serves complete public bundles and private selected views"
)]
fn validate_evidence_impl(
    signer: &SignerEvidence<'_>,
    bundle: &mut EvidenceBundle,
    proofs: &[TimestampBinding<'_>],
    required: AdesLevel,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    resources: &ResourceScope,
    selections: Option<&[ArchiveSelection<'_>]>,
    prepared: Option<&ParsedEvidence>,
    snapshot_graph: Option<&crate::cms::ades::pdf::SnapshotProofGraph<'_, '_>>,
    purpose: ValidationPurpose,
) -> Result<ValidationReport, EvidenceError> {
    resources.checkpoint()?;
    bundle.checkpoint()?;
    if let Some(graph) = snapshot_graph {
        graph.check(proofs, resources)?;
        for proof in proofs {
            coverage_size(bundle, signer, proof.coverage)?;
            if bundle.checked_entry(proof.token)?.kind != EvidenceKind::Timestamp {
                return Err(EvidenceError::InvalidBinding);
            }
        }
    } else {
        binding_graph(bundle, signer, proofs, selections)?;
    }
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
    let owned = if prepared.is_none() {
        Some(ParsedEvidence::read(bundle, signer, ctx, resources)?)
    } else {
        None
    };
    let parsed = prepared
        .or(owned.as_ref())
        .ok_or(EvidenceError::InvalidBinding)?;
    let selected = selections
        .and_then(|values| values.last())
        .map(|value| value.protected);
    // Only a closed ordered archive may have noncyclic CURRENT-TSA material
    // after its token. Signer/earlier-proof LT checks use its protected prefix.
    let closed_cutoff = if purpose == ValidationPurpose::Final {
        proofs.last().and_then(|proof| {
            (proof.kind == ProofKind::Archive
                && matches!(proof.coverage, [CoveragePart::BoundArchive(_)]))
            .then_some(proof.token.index)
        })
    } else {
        None
    };
    let included = |index: usize| {
        closed_cutoff.is_none_or(|cutoff| index < cutoff)
            && selected.is_none_or(|ids| {
                ids.contains(&EvidenceId {
                    owner: bundle.owner,
                    index,
                })
            })
    };
    let candidates: Vec<&Certificate> = parsed
        .candidates
        .iter()
        .filter(|(id, _)| {
            id.map_or(selected.is_none() && closed_cutoff.is_none(), |id| {
                included(id.index)
            })
        })
        .map(|(_, cert)| cert)
        .collect();
    // A carried source certificate is part of the mandatory archive validation
    // material, not an unrelated later root-set addition.
    if selected.is_some()
        && !parsed
            .candidates
            .iter()
            .any(|(id, cert)| id.is_some_and(|id| included(id.index)) && cert == signer.certificate)
    {
        return Err(EvidenceError::InvalidBinding);
    }
    let responses: Vec<&[u8]> = parsed
        .raw
        .iter()
        .enumerate()
        .filter(|(index, item)| included(*index) && item.kind == EvidenceKind::Ocsp)
        .map(|(_, item)| item.bytes.as_slice())
        .collect();
    let crls: Vec<&[u8]> = parsed
        .raw
        .iter()
        .enumerate()
        .filter(|(index, item)| included(*index) && item.kind == EvidenceKind::Crl)
        .map(|(_, item)| item.bytes.as_slice())
        .collect();
    // These borrowed views are used ONLY for the cryptographically checked
    // current TSA, never to repair a missing earlier signer/status prefix.
    let has_tail = closed_cutoff.is_some_and(|cutoff| cutoff + 1 < bundle.entries.len());
    let current_candidates: Option<Vec<_>> =
        has_tail.then(|| parsed.candidates.iter().map(|(_, cert)| cert).collect());
    let current_responses: Option<Vec<_>> = has_tail.then(|| {
        parsed
            .raw
            .iter()
            .filter(|i| i.kind == EvidenceKind::Ocsp)
            .map(|i| i.bytes.as_slice())
            .collect()
    });
    let current_crls: Option<Vec<_>> = has_tail.then(|| {
        parsed
            .raw
            .iter()
            .filter(|i| i.kind == EvidenceKind::Crl)
            .map(|i| i.bytes.as_slice())
            .collect()
    });
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
            let verified = parsed
                .timestamps
                .iter()
                .find(|(index, _)| *index == proof.token.index)
                .map(|(_, value)| value)
                .ok_or(EvidenceError::InvalidBinding)?;
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
            if selections.is_some_and(|values| {
                values.iter().any(|selection| {
                    selection.token == proof.token && selection.algorithm != algorithm
                })
            }) {
                timestamp = combine(timestamp, CheckStatus::Failed);
                continue;
            }
            let imprint =
                hash_coverage(bundle, signer, proof.coverage, algorithm, Some(resources))?;
            if tsp::check_imprint(info, &imprint).is_err()
                || info.gen_time > ctx.now
                || previous_time.is_some_and(|at| info.gen_time < at)
            {
                timestamp = combine(timestamp, CheckStatus::Failed);
                continue;
            }
            resources.checkpoint()?;
            bundle.checkpoint()?;
            let current_archive = closed_cutoff == Some(proof.token.index);
            let built = pkix::build_anchored_path_selected(
                tsa,
                ctx.anchors,
                current_candidates
                    .as_ref()
                    .filter(|_| current_archive)
                    .unwrap_or(&candidates),
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
            if current_archive {
                check_current_tsa_tail(
                    parsed,
                    proof.token.index,
                    &path,
                    info.gen_time,
                    ctx.now,
                    bundle,
                    resources,
                )?;
            }
            let (status, revoked) = path_status(
                &path,
                info.gen_time,
                &scoped,
                current_responses
                    .as_ref()
                    .filter(|_| current_archive)
                    .unwrap_or(&responses),
                current_crls
                    .as_ref()
                    .filter(|_| current_archive)
                    .unwrap_or(&crls),
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
                    ProofKind::Document => {
                        archive_valid = proof_time.is_some()
                            && timestamp == CheckStatus::Passed
                            && snapshot_graph.is_some_and(|graph| graph.is_archive(proof.token));
                        if proof_time.is_none() {
                            proof_time = Some(ProofTime {
                                at: info.gen_time,
                                token: proof.token,
                                imprint,
                            });
                        }
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
                    (proof.kind == ProofKind::Archive
                        && (selections.is_some()
                            || proof.token.index + 1 == bundle.entries.len()
                            || matches!(proof.coverage, [CoveragePart::BoundArchive(_)])))
                        || (proof.kind == ProofKind::Document
                            && snapshot_graph.is_some_and(|graph| graph.is_archive(proof.token)))
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
        let built = pkix::build_anchored_path_selected(
            signer.certificate,
            ctx.anchors,
            &candidates,
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

pub(crate) fn lock_snapshot<'a, 's>(
    input: &'a std::sync::Mutex<crate::io::PdfSnapshot<'s>>,
) -> Result<std::sync::MutexGuard<'a, crate::io::PdfSnapshot<'s>>, ProcessingError> {
    input
        .try_lock()
        .map_err(|_| ProcessingError::InvalidInput("snapshot already borrowed"))
}

/// This checks actual certificate/status roles against the already verified,
/// anchored CURRENT TSA path. XML separately checks TSVD grammar/URI/location;
/// no caller-supplied role boolean can promote these cryptographic facts.
fn check_current_tsa_tail(
    parsed: &ParsedEvidence,
    cutoff: usize,
    path: &[Certificate],
    _at: OffsetDateTime,
    now: OffsetDateTime,
    bundle: &EvidenceBundle,
    resources: &ResourceScope,
) -> Result<(), EvidenceError> {
    let has_ocsp = parsed
        .raw
        .iter()
        .skip(cutoff + 1)
        .any(|item| item.kind == EvidenceKind::Ocsp);
    let _role_metadata = if has_ocsp {
        let bytes = path.iter().try_fold(0u64, |total, cert| {
            cert.encoded_len()
                .map_err(|_| EvidenceError::InvalidBinding)
                .and_then(|n| {
                    total
                        .checked_add(u32::from(n) as u64)
                        .ok_or(EvidenceError::Limit)
                })
        })?;
        Some(resources.reserve_metadata(bytes.checked_mul(4).ok_or(EvidenceError::Limit)?)?)
    } else {
        None
    };
    let role_cas = has_ocsp.then(|| crate::pkix::CaSet::new(path.to_vec()));
    for item in parsed.raw.iter().skip(cutoff + 1) {
        resources.checkpoint()?;
        bundle.checkpoint()?;
        let relevant = match item.kind {
            EvidenceKind::Certificate => {
                cert::parse(&item.bytes).is_ok_and(|cert| path.contains(&cert))
            }
            // Role and freshness are separate facts: issuer/CertID/EKU/math
            // precede these time-only errors in the existing strict checker.
            // Current freshness is still checked by path_status below.
            EvidenceKind::Ocsp => path.windows(2).any(|pair| {
                matches!(
                    crate::ocsp::check_embedded_issuer_bound(
                        &item.bytes,
                        &pair[0],
                        &pair[1],
                        role_cas.as_ref().expect("OCSP role path"),
                        now
                    ),
                    Ok(_)
                        | Err(
                            crate::ocsp::OcspError::ThisUpdate | crate::ocsp::OcspError::NextUpdate
                        )
                )
            }),
            EvidenceKind::Crl => path.windows(2).any(|pair| {
                matches!(
                    crate::crl::serial_status(
                        &item.bytes,
                        &pair[1],
                        pair[0].tbs_certificate().serial_number().as_bytes(),
                        now
                    ),
                    Ok(_) | Err(crate::crl::CrlError::NotYetValid | crate::crl::CrlError::Outdated)
                )
            }),
            EvidenceKind::Timestamp => false,
        };
        resources.checkpoint()?;
        bundle.checkpoint()?;
        if !relevant {
            return Err(EvidenceError::InvalidBinding);
        }
    }
    Ok(())
}

/// Exact pure issuance-configuration gate, not a proof or trust decision.
pub fn validate_timestamp_configuration(
    spec: &TsaSpec,
    policy: ValidationPolicy,
) -> Result<(), EvidenceError> {
    if !spec.require_tsa_eku
        || !spec.cert_req
        || spec.policy.is_none()
        || spec.hash == HashAlg::Sha1
        || spec.retries > 2
        || spec.timeout.is_zero()
        || spec.url.len() > 4096
        || policy == ValidationPolicy::OfflineReport
        || match &spec.nonce {
            NonceSpec::None => true,
            NonceSpec::Random(n) => *n == 0 || *n > 64,
            NonceSpec::Value(value) => value.is_empty() || value.len() > 64,
        }
    {
        return Err(EvidenceError::InvalidBinding);
    }
    Ok(())
}

/// Streaming strict base64 decoder over a bounded text window: whitespace is skipped,
/// padding may only end the text, and nothing is retained beyond its two fixed buffers.
struct Base64Reader<'a, R: Read> {
    inner: R,
    failed: &'a std::cell::Cell<bool>,
    text: [u8; 4096],
    text_len: usize,
    text_pos: usize,
    group: [u8; 4],
    group_len: usize,
    out: [u8; 3 * 1024],
    out_len: usize,
    out_pos: usize,
    padded: bool,
    eof: bool,
}
impl<'a, R: Read> Base64Reader<'a, R> {
    const WORKING: u64 = std::mem::size_of::<Self>() as u64 + 4096;
    fn new(inner: R, failed: &'a std::cell::Cell<bool>) -> Self {
        Self {
            inner,
            failed,
            text: [0; 4096],
            text_len: 0,
            text_pos: 0,
            group: [0; 4],
            group_len: 0,
            out: [0; 3 * 1024],
            out_len: 0,
            out_pos: 0,
            padded: false,
            eof: false,
        }
    }
    fn invalid(&self) -> io::Error {
        self.failed.set(true);
        io::Error::new(io::ErrorKind::InvalidData, "invalid base64 evidence")
    }
    fn decode_group(&mut self) -> io::Result<()> {
        use base64::Engine as _;
        let mut decoded = [0u8; 3];
        let count = base64::engine::general_purpose::STANDARD
            .decode_slice(self.group, &mut decoded)
            .map_err(|_| self.invalid())?;
        self.out[self.out_len..self.out_len + count].copy_from_slice(&decoded[..count]);
        self.out_len += count;
        self.group_len = 0;
        Ok(())
    }
}
impl<R: Read> Read for Base64Reader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.out_pos == self.out_len {
            self.out_pos = 0;
            self.out_len = 0;
            if self.text_pos == self.text_len {
                if self.eof {
                    return if self.group_len == 0 {
                        Ok(0)
                    } else {
                        Err(self.invalid())
                    };
                }
                self.text_pos = 0;
                self.text_len = loop {
                    match self.inner.read(&mut self.text) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        other => break other?,
                    }
                };
                if self.text_len == 0 {
                    self.eof = true;
                    continue;
                }
            }
            while self.text_pos < self.text_len && self.out_len + 3 <= self.out.len() {
                let byte = self.text[self.text_pos];
                self.text_pos += 1;
                if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                    continue;
                }
                if self.padded && (byte != b'=' || self.group_len == 0) {
                    return Err(self.invalid());
                }
                self.padded |= byte == b'=';
                self.group[self.group_len] = byte;
                self.group_len += 1;
                if self.group_len == 4 {
                    self.decode_group()?;
                }
            }
        }
        let count = buffer.len().min(self.out_len - self.out_pos);
        buffer[..count].copy_from_slice(&self.out[self.out_pos..self.out_pos + count]);
        self.out_pos += count;
        Ok(count)
    }
}
