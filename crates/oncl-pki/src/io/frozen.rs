//! Immutable source-role snapshots. No constructor accepts a pre-populated stage.
use super::{Region, Source, StagedArtifact, TemporaryStore};
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope};
use std::{
    io::{self, Read, Seek, SeekFrom},
    sync::Arc,
};

pub struct FrozenInput {
    pub(super) stage: StagedArtifact,
    pub(super) identity: Arc<()>,
    pub(super) output_derived: bool,
    pub(super) pending_format: bool,
    pub(super) pending_accounting: bool,
    pub(super) classification: Option<Arc<super::provisional::FormatClassification>>,
    pub(super) wire_digest: Option<crate::digest::DigestValue>,
}
pub struct FrozenReader<'a> {
    input: &'a mut FrozenInput,
    regions: Vec<Region>,
    position: u64,
    length: u64,
    error: Option<ProcessingError>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
/// Closed transforms over actual immutable captured bytes. No caller decoder
/// can obtain a snapshot-derived capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotEncoding {
    Identity,
    PdfByteString,
}
pub struct DerivedInput {
    bytes: Vec<u8>,
    parent: Arc<()>,
    scope: ResourceScope,
    region: Region,
    encoding: SnapshotEncoding,
    output_derived: bool,
    format_specific: bool,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl FrozenInput {
    pub(super) fn output_failure(&self) -> Option<Arc<super::AtomicBool>> {
        self.stage.output_failure.clone()
    }
    /// Capture exactly the actual source bytes from its logical current start.
    /// The only persistent storage is the host's explicit source-role store.
    pub fn capture(
        source: Source<'_>,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
    ) -> Result<Self, ProcessingError> {
        Self::capture_limited(source, store, scope, None, None)
    }
    /// Narrow the existing input/output role limit; never grant fresh input
    /// credit or convert an authenticated output projection to original input.
    pub fn capture_bounded(
        source: Source<'_>,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
        maximum: u64,
    ) -> Result<Self, ProcessingError> {
        Self::capture_limited(source, store, scope, Some(maximum), None)
    }
    pub(super) fn capture_format(
        source: Source<'_>,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
        maximum_overhead: u64,
    ) -> Result<Self, ProcessingError> {
        Self::capture_limited(source, store, scope, None, Some(maximum_overhead))
    }
    fn capture_limited(
        mut source: Source<'_>,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
        maximum: Option<u64>,
        format_overhead: Option<u64>,
    ) -> Result<Self, ProcessingError> {
        // Authentic roles/foreign identities are checked BEFORE any debit,
        // pending ownership or originating-output invalidation.
        let format = matches!(source.reader, super::Reader::FormatSnapshot(_));
        let prior = if format {
            if format_overhead.is_none() {
                return Err(ProcessingError::InvalidInput(
                    "format-specific source requires classification",
                ));
            }
            if source
                .admitted
                .as_ref()
                .is_none_or(|original| !original.same_operation(scope))
            {
                return Err(ProcessingError::InvalidInput("foreign format snapshot"));
            }
            Some(
                source
                    .classification
                    .clone()
                    .ok_or(ProcessingError::InvalidInput(
                        "unclassified source cannot replay",
                    ))?,
            )
        } else {
            None
        };
        let replay = if format {
            true
        } else {
            source.is_snapshot_for(scope)?
        };
        let output_derived = source.is_output_projection_for(scope)?;
        let failure = source.output_failure.clone();
        let pending = format_overhead.is_some() && !replay && !output_derived;
        let identity = prior
            .as_ref()
            .map_or_else(|| Arc::new(()), |ledger| ledger.identity.clone());
        let mut ticket: Option<PendingCapture> = None;
        let result = (|| {
            let resource_limit = if output_derived {
                scope.limits().output_bytes
            } else if let Some(ledger) = &prior {
                ledger.extent
            } else if pending {
                (u128::from(scope.input_remaining())
                    + u128::from(
                        scope
                            .container_remaining()
                            .min(format_overhead.expect("pending overhead")),
                    ))
                .min(u128::from(u64::MAX)) as u64
            } else {
                scope.limits().input_bytes
            };
            let extent_limit = maximum.map_or(resource_limit, |m| m.min(resource_limit));
            let limit_error = || {
                if output_derived {
                    ProcessingError::OutputLimit
                } else {
                    ProcessingError::InputLimit
                }
            };
            scope.checkpoint()?;
            if !output_derived {
                scope.check_input()?;
            }
            if output_derived
                && failure
                    .as_ref()
                    .is_some_and(|f| f.load(super::Ordering::SeqCst))
            {
                return Err(ProcessingError::InvalidInput("failed output projection"));
            }
            if (maximum.is_some() || pending || format)
                && source.known_len().is_some_and(|n| n > extent_limit)
            {
                return Err(limit_error());
            }
            if let Some(reader) = source.as_seekable() {
                let start = reader.stream_position()?;
                let end = reader.seek(SeekFrom::End(0))?;
                reader.seek(SeekFrom::Start(start))?;
                let size = end
                    .checked_sub(start)
                    .ok_or(ProcessingError::InvalidInput("source extent"))?;
                if format && (start != 0 || size != prior.as_ref().expect("format ledger").extent) {
                    return Err(ProcessingError::InvalidInput(
                        "classified replay must be a complete fixed view",
                    ));
                }
                if size > extent_limit
                    || (!replay && !output_derived && !pending && size > scope.input_remaining())
                {
                    return Err(limit_error());
                }
            }
            if pending {
                scope.begin_signed_input(&identity)?;
                ticket = Some(PendingCapture {
                    scope: scope.retain(),
                    identity: identity.clone(),
                    active: true,
                });
            }
            let mut hash = (format_overhead.is_some() && prior.is_none())
                .then(|| crate::digest::HashState::new(crate::key::HashAlg::Sha256));
            let capacity = if maximum.is_some() {
                extent_limit
                    .saturating_add(1)
                    .min(IO_CHUNK_BYTES as u64)
                    .max(1) as usize
            } else {
                IO_CHUNK_BYTES
            };
            let _memory = scope.reserve_memory(capacity as u64)?;
            let mut buffer = vec![0; capacity];
            let mut stage = store.stage_source(scope)?;
            stage.output_failure = failure.clone();
            loop {
                scope.checkpoint()?;
                let offered = extent_limit
                    .saturating_sub(stage.len())
                    .saturating_add(1)
                    .min(buffer.len() as u64) as usize;
                let request = if pending {
                    scope.signed_input_request(
                        &identity,
                        format_overhead.expect("pending overhead"),
                        offered,
                    )?
                } else if replay || output_derived {
                    offered
                } else {
                    scope.input_request(offered)?
                };
                let count = match source.read(&mut buffer[..request]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        scope.checkpoint()?;
                        return Err(e.into());
                    }
                    Ok(count) => count,
                };
                if count > request {
                    return Err(ProcessingError::InvalidInput("reader exceeded buffer"));
                }
                if pending {
                    scope.consumed_signed_input(
                        &identity,
                        format_overhead.expect("pending overhead"),
                        count as u64,
                    )?;
                } else if !replay && !output_derived {
                    scope.consumed_input(count as u64)?;
                }
                if stage
                    .len()
                    .checked_add(count as u64)
                    .is_none_or(|n| n > extent_limit)
                {
                    if !output_derived {
                        scope.terminate_input_limit();
                    }
                    return Err(limit_error());
                }
                scope.checkpoint()?;
                if count == 0 {
                    break;
                }
                if let Some(hash) = &mut hash {
                    hash.update(&buffer[..count]);
                }
                stage.write_chunk(&buffer[..count])?;
            }
            source.finish_snapshot()?;
            Ok(Self {
                stage,
                identity: identity.clone(),
                output_derived,
                pending_format: format_overhead.is_some() && !output_derived && prior.is_none(),
                pending_accounting: pending,
                wire_digest: prior
                    .as_ref()
                    .map(|ledger| ledger.digest)
                    .or_else(|| hash.map(crate::digest::HashState::finish)),
                classification: prior.clone(),
            })
        })();
        if result.is_ok()
            && let Some(ticket) = &mut ticket
        {
            ticket.active = false;
        }
        if result.is_err() && output_derived {
            source.invalidate_output_projection();
            super::mark_output_failure(&failure);
        }
        result
    }
    /// Read only this snapshot's original-scope immutable region. Delegates the
    /// existing artifact's checked bounds, 256-KiB chunk, cursor restore and
    /// original control/deadline; no replay capability or owned buffer escapes.
    pub fn read_region(
        &mut self,
        region: Region,
        output: &mut [u8],
    ) -> Result<usize, ProcessingError> {
        self.stage.read_region(region, output)
    }
    pub fn len(&self) -> u64 {
        self.stage.len()
    }
    pub fn is_empty(&self) -> bool {
        self.stage.is_empty()
    }
    pub(super) fn is_output_derived(&self) -> bool {
        self.output_derived
    }
    pub(super) fn invalidate_output(&mut self) {
        if self.output_derived {
            self.stage.failed = true;
            super::mark_output_failure(&self.stage.output_failure);
        }
    }
    pub(super) fn check(&self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        self.stage.scope.checkpoint()?;
        if !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "snapshot belongs to another operation",
            ));
        }
        if self.stage.is_failed() {
            return Err(ProcessingError::InvalidInput("failed output snapshot"));
        }
        Ok(())
    }
    pub fn reader<'a>(
        &'a mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<FrozenReader<'a>, ProcessingError> {
        if !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "snapshot belongs to another operation",
            ));
        }
        let failure = self.stage.output_failure.clone();
        let result = self.reader_inner(regions, scope);
        if result.is_err() {
            super::mark_output_failure(&failure);
        }
        result
    }
    fn reader_inner<'a>(
        &'a mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<FrozenReader<'a>, ProcessingError> {
        self.check(scope)?;
        if regions.len() > 4096 {
            return Err(ProcessingError::MetadataLimit);
        }
        let mut previous_end = 0;
        let mut length = 0u64;
        for region in regions {
            if region.offset < previous_end {
                return Err(ProcessingError::InvalidInput(
                    "overlapping or reordered snapshot regions",
                ));
            }
            previous_end = region.end()?;
            if region.end()? > self.len() {
                return Err(ProcessingError::InvalidInput(
                    "snapshot region exceeds extent",
                ));
            }
            length = length
                .checked_add(region.len)
                .ok_or(ProcessingError::InputLimit)?;
        }
        let extent_limit = if self.output_derived {
            scope.limits().output_bytes
        } else if self.pending_format || self.classification.is_some() {
            self.len()
        } else {
            scope.limits().input_bytes
        };
        if length > self.len() || length > extent_limit {
            return Err(ProcessingError::InputLimit);
        }
        let bytes = (regions.len() as u64)
            .checked_mul(std::mem::size_of::<Region>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<FrozenReader<'_>>() as u64))
            .ok_or(ProcessingError::MetadataLimit)?;
        let metadata = scope.reserve_metadata(bytes)?;
        let memory = scope.reserve_memory(bytes)?;
        Ok(FrozenReader {
            input: self,
            regions: regions.to_vec(),
            position: 0,
            length,
            error: None,
            _memory: memory,
            _metadata: metadata,
        })
    }
    /// Decode bounded metadata using an SDK-controlled closed transform.
    /// Encoded/output storage is admitted before allocation; neither the bytes
    /// nor their original operation guards can escape as owned buffers.
    ///
    /// ```compile_fail
    /// fn inject(snapshot: &mut oncl_pki::io::FrozenInput,
    ///           scope: &oncl_pki::resource::ResourceScope) {
    ///     let _ = snapshot.derive_region(oncl_pki::io::Region { offset: 0, len: 4 },
    ///         scope, |_: &[u8], output: &mut dyn std::io::Write| {
    ///             output.write_all(b"EVIL")?;
    ///             Ok(())
    ///         });
    /// }
    /// ```
    pub fn derive_region(
        &mut self,
        region: Region,
        scope: &ResourceScope,
        encoding: SnapshotEncoding,
    ) -> Result<DerivedInput, ProcessingError> {
        if !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "snapshot belongs to another operation",
            ));
        }
        let failure = self.stage.output_failure.clone();
        let result = self.derive_region_inner(region, scope, encoding);
        if result.is_err() {
            super::mark_output_failure(&failure);
        }
        result
    }
    fn derive_region_inner(
        &mut self,
        region: Region,
        scope: &ResourceScope,
        encoding: SnapshotEncoding,
    ) -> Result<DerivedInput, ProcessingError> {
        self.check(scope)?;
        if region.end()? > self.len() {
            return Err(ProcessingError::InvalidInput(
                "derived region exceeds snapshot",
            ));
        }
        decode_region(
            region,
            scope,
            &self.identity,
            &self.stage.scope.retain(),
            encoding,
            self.output_derived,
            self.pending_format || self.classification.is_some(),
            |region, out| self.stage.read_region(region, out),
        )
    }
    pub(crate) fn binds(
        &self,
        derived: &DerivedInput,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        self.check(scope)?;
        if self.output_derived
            || derived.output_derived
            || self.pending_format
            || self.classification.is_some()
            || derived.format_specific
            || !Arc::ptr_eq(&self.identity, &derived.parent)
            || !derived.scope.same_operation(scope)
        {
            return Err(ProcessingError::InvalidInput(
                "derived metadata belongs to another snapshot",
            ));
        }
        Ok(())
    }
}

pub(super) fn decode_region(
    region: Region,
    scope: &ResourceScope,
    identity: &Arc<()>,
    owner: &ResourceScope,
    encoding: SnapshotEncoding,
    output_derived: bool,
    format_specific: bool,
    mut read: impl FnMut(Region, &mut [u8]) -> Result<usize, ProcessingError>,
) -> Result<DerivedInput, ProcessingError> {
    owner.checkpoint()?;
    scope.checkpoint()?;
    scope.account_container(region.len)?;
    let length = usize::try_from(region.len).map_err(|_| ProcessingError::MetadataLimit)?;
    let size = region
        .len
        .checked_mul(2)
        .ok_or(ProcessingError::MemoryLimit)?;
    let memory = scope.reserve_memory(size)?;
    let metadata = scope.reserve_metadata(size)?;
    let mut encoded = vec![0; length];
    let mut at = 0;
    while at < length {
        scope.checkpoint()?;
        let n = read(
            Region {
                offset: region.offset + at as u64,
                len: region.len - at as u64,
            },
            &mut encoded[at..],
        )?;
        if n == 0 {
            return Err(ProcessingError::InvalidInput("short snapshot region"));
        }
        at += n;
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    match encoding {
        SnapshotEncoding::Identity => output.extend_from_slice(&encoded),
        SnapshotEncoding::PdfByteString => {
            if super::decode_pdf_byte_string(&encoded, &mut output)? != encoded.len() {
                return Err(ProcessingError::InvalidInput(
                    "trailing bytes after PDF string",
                ));
            }
        }
    }
    owner.checkpoint()?;
    scope.checkpoint()?;
    Ok(DerivedInput {
        bytes: output,
        parent: identity.clone(),
        scope: owner.retain(),
        region,
        encoding,
        output_derived,
        format_specific,
        _memory: memory,
        _metadata: metadata,
    })
}
impl DerivedInput {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn region(&self) -> Region {
        self.region
    }
    pub fn encoding(&self) -> SnapshotEncoding {
        self.encoding
    }
    pub(super) fn binds_origin(
        &self,
        identity: &Arc<()>,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        self.scope.checkpoint()?;
        scope.checkpoint()?;
        if !Arc::ptr_eq(identity, &self.parent) || !self.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "derived metadata belongs to another snapshot",
            ));
        }
        Ok(())
    }
}
impl FrozenReader<'_> {
    pub fn source(&mut self) -> Source<'_> {
        let length = self.length.saturating_sub(self.position);
        let admitted = self.input.stage.scope.retain();
        let output_derived = self.input.output_derived;
        let output_failure = self.input.stage.output_failure.clone();
        let format = self.input.pending_format || self.input.classification.is_some();
        let classification = self.input.classification.clone();
        Source {
            reader: if output_derived {
                super::Reader::OutputProjection(self)
            } else if format {
                super::Reader::FormatSnapshot(self)
            } else {
                super::Reader::Snapshot(self)
            },
            len: Some(length),
            admitted: Some(admitted),
            output_failure,
            classification,
        }
    }
    pub fn finish(&mut self) -> Result<(), ProcessingError> {
        let result = if let Some(error) = self.error.take() {
            Err(error)
        } else {
            self.input.stage.scope.checkpoint().and_then(|_| {
                if self.input.stage.is_failed() {
                    Err(ProcessingError::InvalidInput("failed output snapshot"))
                } else {
                    Ok(())
                }
            })
        };
        if result.is_err() && self.input.output_derived {
            self.input.stage.fail_sign_output();
        }
        result
    }
}
impl Read for FrozenReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::Error::other("snapshot reader failed"));
        }
        if self.position >= self.length {
            return Ok(0);
        }
        let mut start = 0;
        let mut chosen = None;
        for region in &self.regions {
            if self.position < start + region.len {
                chosen = Some(Region {
                    offset: region.offset + self.position - start,
                    len: start + region.len - self.position,
                });
                break;
            }
            start += region.len;
        }
        let region = chosen.ok_or_else(|| io::Error::other("snapshot region position"))?;
        match self.input.stage.read_region(region, out) {
            Ok(n) => {
                self.position += n as u64;
                Ok(n)
            }
            Err(error) => {
                self.error = Some(error);
                Err(io::Error::other("snapshot replay failed"))
            }
        }
    }
}
impl Seek for FrozenReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.length.checked_add_signed(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
        }
        .ok_or_else(|| io::Error::other("snapshot seek overflow"))?;
        self.position = position;
        Ok(position)
    }
}

impl super::SnapshotReader for FrozenReader<'_> {
    fn finish_snapshot(&mut self) -> Result<(), ProcessingError> {
        self.finish()
    }
    fn invalidate_snapshot(&mut self) {
        if self.input.output_derived {
            self.input.stage.fail_sign_output();
        }
    }
}

struct PendingCapture {
    scope: ResourceScope,
    identity: Arc<()>,
    active: bool,
}
impl Drop for PendingCapture {
    fn drop(&mut self) {
        if self.active {
            self.scope.abandon_signed_input(&self.identity);
        }
    }
}
impl super::captured_private::Sealed for FrozenInput {}
impl super::CapturedInput for FrozenInput {
    fn len(&self) -> u64 {
        self.len()
    }
    fn read_region(&mut self, region: Region, output: &mut [u8]) -> Result<usize, ProcessingError> {
        self.read_region(region, output)
    }
    fn reader<'a>(
        &'a mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<FrozenReader<'a>, ProcessingError> {
        self.reader(regions, scope)
    }
}
