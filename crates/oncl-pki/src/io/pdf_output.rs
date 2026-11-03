//! Closed output-only PDF signature assembly. No mutable source capability.
use super::*;
use crate::{
    cms::stream::{self, CmsSignServices, SignSummary, StreamError},
    key::DigestSigner,
};

/// Owns the only append/patch borrow until the PDF signature is complete.
/// Drop before successful finish poisons the caller's unpublished output.
pub struct PdfSignatureOutput<'a> {
    stage: &'a mut StagedArtifact,
    range_offset: Option<u64>,
    contents: Option<Region>,
    complete: bool,
    append_start: u64,
}
impl<'a> PdfSignatureOutput<'a> {
    /// Admission only; no mutable capability or publication is created.
    pub fn check_output(
        stage: &StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        stage.check_sign_output(scope)
    }
    /// Terminal failure is sticky even if the host subsequently clears cancel.
    /// This cannot poison a foreign-operation or SOURCE artifact.
    pub fn abort_output(
        stage: &mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        if stage.source || !stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "cannot abort foreign or SOURCE artifact",
            ));
        }
        stage.fail_sign_output();
        Ok(())
    }
    pub fn new(
        stage: &'a mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        if stage.source || !stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "foreign or source PDF output",
            ));
        }
        stage.attach_output_failure();
        let transaction = Self {
            stage,
            range_offset: None,
            contents: None,
            complete: false,
            append_start: 0,
        };
        transaction.stage.check_sign_output(scope)?;
        Ok(transaction)
    }
    /// Append-only renewal transaction. No previous epoch's patch slots survive.
    pub fn resume_checked(
        stage: &'a mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        stage.check_pdf_live_output(scope)?;
        let append_start = stage.len();
        Ok(Self {
            stage,
            range_offset: None,
            contents: None,
            complete: false,
            append_start,
        })
    }
    /// Exclusively lend a sealed OUTPUT view. Any error poisons publication;
    /// no original-source or mutable output capability can escape the callback.
    pub fn with_snapshot<T, E: From<ProcessingError>>(
        stage: &mut StagedArtifact,
        scope: &ResourceScope,
        action: impl for<'s> FnOnce(PdfSnapshot<'s>) -> Result<T, E>,
    ) -> Result<T, E> {
        stage.check_pdf_live_output(scope)?;
        let result = (|| action(PdfSnapshot::output(stage, scope)?))();
        if result.is_err() {
            stage.fail_sign_output();
        }
        result
    }
    pub fn len(&self) -> u64 {
        self.stage.len()
    }
    pub fn is_empty(&self) -> bool {
        self.stage.is_empty()
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), ProcessingError> {
        let result = self.stage.write_chunk(bytes);
        if result.is_err() {
            self.stage.fail_sign_output();
        }
        result
    }
    /// Emits exactly one physical token and a fixed-width 64-bit ByteRange.
    pub fn reserve_contents(&mut self, bytes: usize) -> Result<Region, ProcessingError> {
        if self.contents.is_some() || bytes == 0 || bytes > 16 * 1024 * 1024 {
            self.stage.fail_sign_output();
            return Err(ProcessingError::InvalidInput(
                "invalid PDF signature reservation",
            ));
        }
        let hex = bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(2))
            .ok_or(ProcessingError::OutputLimit)?;
        self.append(b" /ByteRange [")?;
        self.range_offset = Some(self.len());
        self.append(&[b' '; 83])?;
        self.append(b"] /Contents ")?;
        let region = Region {
            offset: self.len(),
            len: hex as u64,
        };
        self.append(b"<")?;
        let zeros = [b'0'; 8192];
        let mut remaining = hex - 2;
        while remaining > 0 {
            let n = remaining.min(zeros.len());
            self.append(&zeros[..n])?;
            remaining -= n;
        }
        self.append(b">")?;
        self.contents = Some(region);
        Ok(region)
    }
    fn patch(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ProcessingError> {
        self.stage.scope.checkpoint()?;
        if self.stage.is_failed() {
            return Err(ProcessingError::InvalidInput("failed PDF output"));
        }
        if offset < self.append_start
            || offset
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > self.len())
        {
            self.stage.fail_sign_output();
            return Err(ProcessingError::InvalidInput(
                "PDF patch outside current append transaction",
            ));
        }
        let file = self
            .stage
            .file
            .as_mut()
            .ok_or(ProcessingError::InvalidInput("artifact closed"))?;
        let position = file.stream_position()?;
        let result = (|| {
            file.seek(SeekFrom::Start(offset))?;
            write_controlled(file, bytes, &self.stage.scope)
        })();
        let restored = file.seek(SeekFrom::Start(position));
        if let Err(e) = restored {
            self.stage.fail_sign_output();
            return Err(e.into());
        }
        result
    }
    fn patch_ranges(&mut self, scope: &ResourceScope) -> Result<(Region, u64), ProcessingError> {
        if !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput("foreign PDF output"));
        }
        let gap = self
            .contents
            .ok_or(ProcessingError::InvalidInput("missing PDF contents"))?;
        let end = gap.end()?;
        let extent = self.len();
        let ranges = [
            0,
            gap.offset,
            end,
            extent
                .checked_sub(end)
                .ok_or(ProcessingError::OutputLimit)?,
        ];
        let text = format!(
            "{:020} {:020} {:020} {:020}",
            ranges[0], ranges[1], ranges[2], ranges[3]
        );
        self.patch(
            self.range_offset
                .ok_or(ProcessingError::InvalidInput("missing PDF range"))?,
            text.as_bytes(),
        )?;
        Ok((gap, extent))
    }
    fn sign_contents(
        &mut self,
        signer: &mut dyn DigestSigner,
        services: &CmsSignServices<'_>,
        scope: &ResourceScope,
    ) -> Result<(SignSummary, BoundedCms), StreamError> {
        let (gap, extent) = self.patch_ranges(scope)?;
        let capacity =
            usize::try_from((gap.len - 2) / 2).map_err(|_| ProcessingError::MemoryLimit)?;
        let memory = scope.reserve_memory(
            (capacity as u64)
                .checked_mul(3)
                .ok_or(ProcessingError::MemoryLimit)?,
        )?;
        let metadata = scope.reserve_metadata(capacity as u64)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        let mut sink = BoundedCms {
            bytes,
            capacity,
            _memory: memory,
            _metadata: metadata,
        };
        let mut reader = OutputReplay {
            stage: self.stage,
            gap,
            position: 0,
            error: None,
        };
        let output_failure = reader.stage.output_failure.clone();
        let source = Source {
            reader: Reader::OutputProjection(&mut reader),
            len: Some(extent - gap.len),
            admitted: Some(scope.retain()),
            output_failure,
            classification: None,
        };
        let outcome =
            stream::sign_pdf_contents(source, signer, services, &mut sink, capacity, scope);
        // Replay completes before CMS performs any private operation.
        if let Some(error) = reader.error.take() {
            return Err(error.into());
        }
        let summary = outcome?;
        reader
            .finish_snapshot()
            .map_err(|error| StreamError::AfterKeyUse {
                source: Box::new(error.into()),
                applied: summary.applied,
            })?;
        Ok((summary, sink))
    }
    fn patch_contents(
        &mut self,
        bytes: &[u8],
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        let gap = self
            .contents
            .ok_or(ProcessingError::InvalidInput("missing PDF contents"))?;
        if bytes.len() as u64 > (gap.len - 2) / 2 {
            return Err(ProcessingError::InvalidInput(
                "CMS exceeds reserved PDF signature space",
            ));
        }
        let mut hex = [0u8; 8192];
        let mut offset = gap.offset + 1;
        for chunk in bytes.chunks(hex.len() / 2) {
            for (i, b) in chunk.iter().enumerate() {
                hex[2 * i] = b"0123456789ABCDEF"[(b >> 4) as usize];
                hex[2 * i + 1] = b"0123456789ABCDEF"[(b & 15) as usize];
            }
            self.patch(offset, &hex[..chunk.len() * 2])?;
            offset += chunk.len() as u64 * 2;
        }
        scope.checkpoint()
    }
    pub fn finish(
        mut self,
        signer: &mut dyn DigestSigner,
        services: &CmsSignServices<'_>,
        scope: &ResourceScope,
    ) -> Result<SignSummary, StreamError> {
        let (mut summary, sink) = self.sign_contents(signer, services, scope)?;
        self.patch_contents(&sink.bytes, scope)
            .map_err(|source| StreamError::AfterKeyUse {
                source: Box::new(source.into()),
                applied: summary.applied,
            })?;
        summary.bytes_out = self.len();
        self.complete = true;
        Ok(summary)
    }
    /// PAdES T adds a CMS SignatureTimeStamp over the actual signature value.
    /// Acquisition is preflighted before the one local key operation.
    pub fn finish_pades(
        mut self,
        signer: &mut dyn DigestSigner,
        services: &CmsSignServices<'_>,
        ades: &crate::cms::ades::AdesServices<'_>,
        scope: &ResourceScope,
    ) -> Result<SignSummary, crate::cms::ades::AdesError> {
        use crate::cms::ades::AdesError;
        let tsa = ades.tsa.ok_or(AdesError::MissingConfiguration)?;
        ades.limits.validate()?;
        if tsa.hash != crate::key::HashAlg::Sha256 || !tsa.require_tsa_eku {
            return Err(ProcessingError::InvalidInput(
                "PAdES acquisition requires SHA-256 and TSA EKU",
            )
            .into());
        }
        let (mut summary, sink) = self.sign_contents(signer, services, scope)?;
        let result = (|| {
            let stamped = crate::cms::ades::pdf::stamp_contents(&sink.bytes, ades, scope)?;
            self.patch_contents(&stamped.bytes, scope)?;
            Ok::<_, AdesError>(())
        })();
        result.map_err(|source| AdesError::AfterKeyUse {
            source: Box::new(source),
            applied: summary.applied,
        })?;
        summary.bytes_out = self.len();
        self.complete = true;
        Ok(summary)
    }
    /// RFC3161 imprint over these actual output ByteRanges, not CMS signatureValue.
    /// No local DigestSigner or private-key capability is accepted.
    pub fn finish_document_timestamp(
        mut self,
        services: &crate::cms::ades::AdesServices<'_>,
        scope: &ResourceScope,
    ) -> Result<u64, crate::cms::ades::AdesError> {
        let (gap, _) = self.patch_ranges(scope)?;
        let mut reader = OutputReplay {
            stage: self.stage,
            gap,
            position: 0,
            error: None,
        };
        let _memory = scope.reserve_memory(crate::resource::IO_CHUNK_BYTES as u64)?;
        let mut bytes = vec![0; crate::resource::IO_CHUNK_BYTES];
        let mut hash = crate::digest::HashState::new(crate::key::HashAlg::Sha256);
        loop {
            scope.checkpoint()?;
            let count = match reader.read(&mut bytes) {
                Ok(count) => count,
                Err(error) => {
                    reader.finish_snapshot()?;
                    return Err(ProcessingError::from(error).into());
                }
            };
            if count == 0 {
                break;
            }
            hash.update(&bytes[..count]);
        }
        reader.finish_snapshot()?;
        let token = crate::cms::ades::request_imprint(&hash.finish(), services, scope)?;
        self.patch_contents(&token.bytes, scope)?;
        self.complete = true;
        Ok(self.len())
    }
    /// Close an unsigned validation-material transaction. This does not assert
    /// validity; callers must verify the final artifact before publication.
    pub fn finish_validation_update(
        mut self,
        scope: &ResourceScope,
    ) -> Result<u64, ProcessingError> {
        if self.contents.is_some() || !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput("invalid validation update"));
        }
        scope.checkpoint()?;
        self.complete = true;
        Ok(self.len())
    }
}
impl Drop for PdfSignatureOutput<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.stage.fail_sign_output();
        }
    }
}
struct BoundedCms {
    bytes: Vec<u8>,
    capacity: usize,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl Write for BoundedCms {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.capacity - self.bytes.len() {
            return Err(io::Error::other("CMS exceeds reserved PDF signature space"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct OutputReplay<'a> {
    stage: &'a mut StagedArtifact,
    gap: Region,
    position: u64,
    error: Option<ProcessingError>,
}
impl Read for OutputReplay<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let length = self.stage.len() - self.gap.len;
        if self.position >= length {
            return Ok(0);
        }
        let physical = if self.position < self.gap.offset {
            self.position
        } else {
            self.position + self.gap.len
        };
        let count = (if self.position < self.gap.offset {
            self.gap.offset - self.position
        } else {
            length - self.position
        })
        .min(out.len() as u64);
        match self.stage.read_region(
            Region {
                offset: physical,
                len: count,
            },
            out,
        ) {
            Ok(n) => {
                self.position += n as u64;
                Ok(n)
            }
            Err(e) => {
                self.error = Some(e);
                Err(io::Error::other("PDF output replay failed"))
            }
        }
    }
}
impl Seek for OutputReplay<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let length = self.stage.len() - self.gap.len;
        let p = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
            SeekFrom::End(n) => length.checked_add_signed(n),
        }
        .filter(|n| *n <= length)
        .ok_or_else(|| io::Error::other("PDF output replay seek"))?;
        self.position = p;
        Ok(p)
    }
}
impl SnapshotReader for OutputReplay<'_> {
    fn finish_snapshot(&mut self) -> Result<(), ProcessingError> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        self.stage.scope.checkpoint()
    }
    fn invalidate_snapshot(&mut self) {
        self.stage.fail_sign_output();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Control;
    impl crate::resource::OperationControl for Control {
        fn checkpoint(&self, _: crate::resource::Progress) -> Result<(), ProcessingError> {
            Ok(())
        }
    }
    #[test]
    fn source_role_never_acquires_output_patch_transaction() {
        let limits = crate::resource::ResourceLimits::default();
        let budget = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut source = store.stage_source(&mut scope).unwrap();
        source.write_chunk(b"immutable source").unwrap();
        assert!(PdfSignatureOutput::new(&mut source, &scope).is_err());
        let mut original = [0; 16];
        assert_eq!(
            source
                .read_region(Region { offset: 0, len: 16 }, &mut original)
                .unwrap(),
            16
        );
        assert_eq!(&original, b"immutable source");
    }
    #[test]
    fn output_projection_is_not_an_original_frozen_input_capability() {
        let limits = crate::resource::ResourceLimits::default();
        let budget = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut stage = store.stage(&mut scope).unwrap();
        stage.write_chunk(b"abc<0000>xyz").unwrap();
        let output_failure = Some(stage.attach_output_failure());
        let mut reader = OutputReplay {
            stage: &mut stage,
            gap: Region { offset: 3, len: 6 },
            position: 0,
            error: None,
        };
        let mut source = Source {
            reader: Reader::OutputProjection(&mut reader),
            len: Some(6),
            admitted: Some(scope.retain()),
            output_failure,
            classification: None,
        };
        assert!(!source.is_snapshot_for(&scope).unwrap());
        assert!(source.is_output_projection_for(&scope).unwrap());
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcxyz");
        assert_eq!(scope.progress().bytes_in, 0);
        assert_eq!(scope.progress().bytes_out, 12);
    }
    #[test]
    fn renewal_patch_slots_cannot_reach_old_prefix() {
        let limits = crate::resource::ResourceLimits::default();
        let budget = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut stage = store.stage(&mut scope).unwrap();
        stage.write_chunk(b"old protected prefix").unwrap();
        let mut renewed = PdfSignatureOutput::resume_checked(&mut stage, &scope).unwrap();
        renewed.append(b"new tail").unwrap();
        assert!(renewed.patch(0, b"ATTACK").is_err());
        drop(renewed);
        assert!(stage.copy_to(&mut Vec::new()).is_err());
    }
    #[test]
    fn sealed_output_epoch_cannot_be_reused_after_resume() {
        let limits = crate::resource::ResourceLimits::default();
        let budget = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut stage = store.stage(&mut scope).unwrap();
        stage.write_chunk(b"<4142>").unwrap();
        let old = PdfSignatureOutput::with_snapshot(&mut stage, &scope, |mut view| {
            view.derive_region(
                Region { offset: 0, len: 6 },
                &scope,
                SnapshotEncoding::PdfByteString,
            )
        })
        .unwrap();
        let mut next = PdfSignatureOutput::resume_checked(&mut stage, &scope).unwrap();
        next.append(b" tail").unwrap();
        next.finish_validation_update(&scope).unwrap();
        let result: Result<(), ProcessingError> =
            PdfSignatureOutput::with_snapshot(&mut stage, &scope, |view| view.binds(&old, &scope));
        assert!(result.is_err());
        assert!(stage.copy_to(&mut Vec::new()).is_err());
    }
    #[test]
    fn cancelled_terminal_abort_stays_unpublishable_after_control_clear() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Cancel(Arc<AtomicBool>);
        impl crate::resource::OperationControl for Cancel {
            fn checkpoint(&self, _: crate::resource::Progress) -> Result<(), ProcessingError> {
                if self.0.load(Ordering::SeqCst) {
                    Err(ProcessingError::Cancelled)
                } else {
                    Ok(())
                }
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let limits = crate::resource::ResourceLimits::default();
        let budget = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget
            .begin(limits, Arc::new(Cancel(cancelled.clone())))
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut stage = store.stage(&mut scope).unwrap();
        stage.write_chunk(b"not a completed PDF").unwrap();
        cancelled.store(true, Ordering::SeqCst);
        PdfSignatureOutput::abort_output(&mut stage, &scope).unwrap();
        cancelled.store(false, Ordering::SeqCst);
        assert!(stage.copy_to(&mut Vec::new()).is_err());
    }
    fn initially_cancelled_output_entry(snapshot: bool) {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Cancel(Arc<AtomicBool>);
        impl crate::resource::OperationControl for Cancel {
            fn checkpoint(&self, _: crate::resource::Progress) -> Result<(), ProcessingError> {
                if self.0.load(Ordering::SeqCst) {
                    Err(ProcessingError::Cancelled)
                } else {
                    Ok(())
                }
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let limits = crate::resource::ResourceLimits::default();
        let budget = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget
            .begin(limits, Arc::new(Cancel(cancelled.clone())))
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut stage = store.stage(&mut scope).unwrap();
        stage.write_chunk(b"protected bytes").unwrap();
        cancelled.store(true, Ordering::SeqCst);
        let error = if snapshot {
            PdfSignatureOutput::with_snapshot(&mut stage, &scope, |_| Ok::<_, ProcessingError>(()))
                .unwrap_err()
        } else {
            match PdfSignatureOutput::resume_checked(&mut stage, &scope) {
                Ok(_) => panic!("cancelled renewal unexpectedly admitted"),
                Err(error) => error,
            }
        };
        assert!(matches!(error, ProcessingError::Cancelled));
        cancelled.store(false, Ordering::SeqCst);
        assert!(
            stage.copy_to(&mut Vec::new()).is_err(),
            "failed entry must poison without a caller abort"
        );
        let mut normal = store.stage(&mut scope).unwrap();
        normal.write_chunk(b"positive").unwrap();
        if snapshot {
            PdfSignatureOutput::with_snapshot(&mut normal, &scope, |mut view| {
                let mut actual = [0; 8];
                assert_eq!(
                    view.read_region(Region { offset: 0, len: 8 }, &mut actual)?,
                    8
                );
                assert_eq!(&actual, b"positive");
                Ok::<_, ProcessingError>(())
            })
            .unwrap();
        } else {
            let mut transaction = PdfSignatureOutput::resume_checked(&mut normal, &scope).unwrap();
            transaction.append(b" tail").unwrap();
            transaction.finish_validation_update(&scope).unwrap();
        }
        let mut delivered = Vec::new();
        normal.copy_to(&mut delivered).unwrap();
        assert_eq!(
            delivered,
            if snapshot {
                b"positive".as_slice()
            } else {
                b"positive tail".as_slice()
            }
        );
    }
    #[test]
    fn initially_cancelled_resume_is_sticky_after_control_clear() {
        initially_cancelled_output_entry(false);
    }
    #[test]
    fn initially_cancelled_snapshot_is_sticky_after_control_clear() {
        initially_cancelled_output_entry(true);
    }
    #[test]
    fn failed_output_entry_does_not_poison_foreign_or_source_artifacts() {
        let limits = crate::resource::ResourceLimits::default();
        let budget = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut owner = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
        let foreign = Arc::new(crate::resource::SharedBudget::new(limits.clone()).unwrap())
            .begin(limits, Arc::new(Control))
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        for snapshot in [false, true] {
            let mut output = store.stage(&mut owner).unwrap();
            output.write_chunk(b"owner bytes").unwrap();
            let mut source = store.stage_source(&mut owner).unwrap();
            source.write_chunk(b"source").unwrap();
            if snapshot {
                assert!(
                    PdfSignatureOutput::with_snapshot(&mut output, &foreign, |_| Ok::<
                        _,
                        ProcessingError,
                    >(
                        ()
                    ))
                    .is_err()
                );
                assert!(
                    PdfSignatureOutput::with_snapshot(&mut source, &owner, |_| Ok::<
                        _,
                        ProcessingError,
                    >(
                        ()
                    ))
                    .is_err()
                );
            } else {
                assert!(PdfSignatureOutput::resume_checked(&mut output, &foreign).is_err());
                assert!(PdfSignatureOutput::resume_checked(&mut source, &owner).is_err());
            }
            let mut bytes = Vec::new();
            output.copy_to(&mut bytes).unwrap();
            assert_eq!(bytes, b"owner bytes");
            let mut original = [0; 6];
            source
                .read_region(Region { offset: 0, len: 6 }, &mut original)
                .unwrap();
            assert_eq!(&original, b"source");
        }
    }
}
