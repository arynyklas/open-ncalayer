//! Immutable external wire awaiting a format's exact byte classification.
//! Classification is accounting, not format validity, a signature or ProofTime.
use super::*;
use crate::digest::DigestValue;

pub(super) struct FormatClassification {
    pub(super) identity: Arc<()>,
    pub(super) extent: u64,
    pub(super) document: u64,
    pub(super) container: u64,
    pub(super) regions: Vec<Region>,
    pub(super) digest: DigestValue,
    _metadata: ResourceReservation,
}

/// Owned immutable captured wire. A parser may borrow bounded reads, but no
/// original-input Source, mutable spool, owning bytes or crypto fact is exposed.
/// Dropping unclassified external wire is terminal; observed bytes are never
/// refunded. Only one provisional intake may be active in one original scope.
pub struct ProvisionalInput {
    input: FrozenInput,
    scope: ResourceScope,
    owner: Arc<()>,
    pending: bool,
    accepted: bool,
    maximum_overhead: u64,
}
impl ProvisionalInput {
    pub fn capture(
        source: Source<'_>,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
        maximum_overhead: u64,
    ) -> Result<Self, ProcessingError> {
        let input = FrozenInput::capture_format(source, store, scope, maximum_overhead)?;
        let owner = input.identity.clone();
        let pending = input.pending_accounting;
        Ok(Self {
            input,
            scope: scope.retain(),
            owner,
            pending,
            accepted: false,
            maximum_overhead,
        })
    }
    pub fn len(&self) -> u64 {
        self.input.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Actual SHA-256 of the immutable complete source, not a caller's digest.
    pub fn wire_digest(&self) -> &DigestValue {
        self.input
            .wire_digest
            .as_ref()
            .expect("format capture hashes actual wire")
    }
    pub fn is_classified(&self) -> bool {
        !self.input.pending_format && self.input.classification.is_some()
    }
    pub fn document_bytes(&self) -> Option<u64> {
        self.input.classification.as_ref().map(|c| c.document)
    }
    pub fn container_bytes(&self) -> Option<u64> {
        self.input.classification.as_ref().map(|c| c.container)
    }
    pub fn reader<'a>(
        &'a mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<FrozenReader<'a>, ProcessingError> {
        self.input.reader(regions, scope)
    }
    pub fn read_region(
        &mut self,
        region: Region,
        output: &mut [u8],
    ) -> Result<usize, ProcessingError> {
        self.input.read_region(region, output)
    }
    /// Commit checked disjoint actual metadata extents. Returned format-specific
    /// reader provenance is NEVER an original snapshot. The format constructor
    /// MUST independently derive/check this geometry before using a replay.
    pub fn classify(
        &mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        if !self.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "foreign provisional classification",
            ));
        }
        let result = self.classify_inner(regions, scope);
        if result.is_err() {
            if self.pending {
                self.scope.abandon_signed_input(&self.owner);
            }
            if self.input.output_derived {
                self.input.stage.fail_sign_output();
            }
        } else {
            self.accepted = true;
        }
        result
    }
    fn classify_inner(
        &mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        self.scope.checkpoint()?;
        if !Arc::ptr_eq(&self.owner, &self.input.identity) {
            return Err(ProcessingError::InvalidInput("provisional source identity"));
        }
        if regions.len() > 4096 {
            return Err(ProcessingError::MetadataLimit);
        }
        let header = if self.input.classification.is_some() {
            0
        } else {
            std::mem::size_of::<FormatClassification>() as u64 + 64
        };
        let admission = (regions.len() as u64)
            .checked_mul(std::mem::size_of::<Region>() as u64)
            .and_then(|n| n.checked_add(header))
            .ok_or(ProcessingError::MetadataLimit)?;
        let metadata = scope.reserve_metadata(admission)?;
        let mut normalized: Vec<Region> = Vec::with_capacity(regions.len());
        let mut container = 0u64;
        for region in regions {
            scope.checkpoint()?;
            let end = region.end()?;
            if region.len == 0 || end > self.len() {
                return Err(ProcessingError::InvalidInput("classification extent"));
            }
            if let Some(previous) = normalized.last_mut() {
                let before = previous.end()?;
                if region.offset < before {
                    return Err(ProcessingError::InvalidInput(
                        "classification overlap/order",
                    ));
                }
                if region.offset == before {
                    previous.len = previous
                        .len
                        .checked_add(region.len)
                        .ok_or(ProcessingError::ContainerLimit)?;
                } else {
                    normalized.push(*region);
                }
            } else {
                normalized.push(*region);
            }
            container = container
                .checked_add(region.len)
                .ok_or(ProcessingError::ContainerLimit)?;
        }
        if container > self.maximum_overhead || container > scope.limits().container_bytes {
            return Err(ProcessingError::ContainerLimit);
        }
        let document = self
            .len()
            .checked_sub(container)
            .ok_or(ProcessingError::InputLimit)?;
        if document > scope.limits().input_bytes {
            return Err(ProcessingError::InputLimit);
        }
        if let Some(previous) = &self.input.classification {
            if !Arc::ptr_eq(&previous.identity, &self.owner)
                || previous.extent != self.len()
                || previous.document != document
                || previous.container != container
                || previous.regions != normalized
            {
                return Err(ProcessingError::InvalidInput(
                    "format replay geometry mismatch",
                ));
            }
            scope.checkpoint()?;
            return Ok(());
        }
        if self.pending {
            self.scope
                .classify_signed_input(&self.owner, self.len(), document, container)?;
            self.pending = false;
        }
        let ledger = FormatClassification {
            identity: self.owner.clone(),
            extent: self.len(),
            document,
            container,
            regions: normalized,
            digest: *self.wire_digest(),
            _metadata: metadata,
        };
        self.input.classification = Some(Arc::new(ledger));
        self.input.pending_format = false;
        self.input.pending_accounting = false;
        scope.checkpoint()?;
        Ok(())
    }
}
impl Drop for ProvisionalInput {
    fn drop(&mut self) {
        if self.pending {
            self.scope.abandon_signed_input(&self.owner)
        }
        // Parsing/classification may fail after an OUTPUT projection was fully
        // captured. That failure must reach the original transaction even if
        // no later read/checkpoint observes it.
        if self.input.output_derived && !self.accepted {
            self.input.stage.fail_sign_output();
        }
    }
}
impl captured_private::Sealed for ProvisionalInput {}
impl CapturedInput for ProvisionalInput {
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
