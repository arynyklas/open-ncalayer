//! Closed output-only PDF signature assembly. No mutable source capability.
use super::*;
use crate::{
    cms::stream::{self, CmsSignServices, SignSummary, StreamError},
    key::{AppliedState, DigestSigner},
};

/// Owns the only append/patch borrow until the PDF signature is complete.
/// Drop before successful finish poisons the caller's unpublished output.
pub struct PdfSignatureOutput<'a> {
    stage: &'a mut StagedArtifact,
    range_offset: Option<u64>,
    contents: Option<Region>,
    complete: bool,
}
impl<'a> PdfSignatureOutput<'a> {
    /// Admission only; no mutable capability or publication is created.
    pub fn check_output(
        stage: &StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        stage.check_sign_output(scope)
    }
    pub fn new(
        stage: &'a mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        stage.check_sign_output(scope)?;
        Ok(Self {
            stage,
            range_offset: None,
            contents: None,
            complete: false,
        })
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
            self.stage.failed = true;
        }
        result
    }
    /// Emits exactly one physical token and a fixed-width 64-bit ByteRange.
    pub fn reserve_contents(&mut self, bytes: usize) -> Result<Region, ProcessingError> {
        if self.contents.is_some() || bytes == 0 || bytes > 16 * 1024 * 1024 {
            self.stage.failed = true;
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
        if self.stage.failed {
            return Err(ProcessingError::InvalidInput("failed PDF output"));
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
            self.stage.failed = true;
            return Err(e.into());
        }
        result
    }
    pub fn finish(
        mut self,
        signer: &mut dyn DigestSigner,
        services: &CmsSignServices<'_>,
        scope: &ResourceScope,
    ) -> Result<SignSummary, StreamError> {
        if !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput("foreign PDF output").into());
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
        let capacity =
            usize::try_from((gap.len - 2) / 2).map_err(|_| ProcessingError::MemoryLimit)?;
        let _memory = scope.reserve_memory(
            (capacity as u64)
                .checked_mul(3)
                .ok_or(ProcessingError::MemoryLimit)?,
        )?;
        let _metadata = scope.reserve_metadata(capacity as u64)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        let mut sink = BoundedCms { bytes, capacity };
        let mut reader = OutputReplay {
            stage: self.stage,
            gap,
            position: 0,
            error: None,
        };
        let source = Source {
            reader: Reader::OutputProjection(&mut reader),
            len: Some(extent - gap.len),
            admitted: Some(scope.retain()),
        };
        let outcome = stream::sign_pdf_contents(source, signer, services, &mut sink, scope);
        // Replay completes before CMS performs any private operation.
        if let Some(error) = reader.error.take() {
            return Err(error.into());
        }
        let mut summary = outcome?;
        reader
            .finish_snapshot()
            .map_err(|error| StreamError::AfterKeyUse {
                source: Box::new(error.into()),
                applied: summary.applied,
            })?;
        let result = (|| {
            let mut hex = [0u8; 8192];
            let mut offset = gap.offset + 1;
            for chunk in sink.bytes.chunks(hex.len() / 2) {
                for (i, b) in chunk.iter().enumerate() {
                    hex[2 * i] = b"0123456789ABCDEF"[(b >> 4) as usize];
                    hex[2 * i + 1] = b"0123456789ABCDEF"[(b & 15) as usize];
                }
                self.patch(offset, &hex[..chunk.len() * 2])?;
                offset += chunk.len() as u64 * 2;
            }
            scope.checkpoint()?;
            Ok::<_, ProcessingError>(())
        })();
        if let Err(error) = result {
            return Err(StreamError::AfterKeyUse {
                source: Box::new(error.into()),
                applied: AppliedState::Applied,
            });
        }
        summary.bytes_out = extent;
        self.complete = true;
        Ok(summary)
    }
}
impl Drop for PdfSignatureOutput<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.stage.failed = true;
        }
    }
}
struct BoundedCms {
    bytes: Vec<u8>,
    capacity: usize,
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
        };
        assert!(!source.is_snapshot_for(&scope).unwrap());
        assert!(source.is_output_projection_for(&scope).unwrap());
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcxyz");
        assert_eq!(scope.progress().bytes_in, 0);
        assert_eq!(scope.progress().bytes_out, 12);
    }
}
