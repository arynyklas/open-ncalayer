//! A lending, read-only PDF view. OUTPUT stays OUTPUT: it never mints an
//! original-source snapshot capability, and an exclusive borrow prevents resume.
use super::*;

pub struct PdfSnapshot<'a> {
    backing: Backing<'a>,
    identity: Arc<()>,
    scope: ResourceScope,
    extent: u64,
}
enum Backing<'a> {
    Input(&'a mut FrozenInput),
    Output(&'a mut StagedArtifact),
}
impl<'a> PdfSnapshot<'a> {
    pub fn input(
        input: &'a mut FrozenInput,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        if input.output_derived || input.pending_format || input.classification.is_some() {
            return Err(ProcessingError::InvalidInput(
                "PDF input snapshot requires original input provenance",
            ));
        }
        // Check through the original immutable owner; never replace its control.
        let extent = input.len();
        let mut reader = input.reader(
            &[Region {
                offset: 0,
                len: extent,
            }],
            scope,
        )?;
        reader.finish()?;
        drop(reader);
        Ok(Self {
            backing: Backing::Input(input),
            identity: Arc::new(()),
            scope: scope.retain(),
            extent,
        })
    }
    pub(super) fn output(
        output: &'a mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        output.check_pdf_live_output(scope)?;
        let extent = output.len();
        Ok(Self {
            backing: Backing::Output(output),
            identity: Arc::new(()),
            scope: scope.retain(),
            extent,
        })
    }
    pub fn len(&self) -> u64 {
        self.extent
    }
    pub fn is_empty(&self) -> bool {
        self.extent == 0
    }
    fn is_output_derived(&self) -> bool {
        match &self.backing {
            Backing::Input(input) => input.is_output_derived(),
            Backing::Output(_) => true,
        }
    }
    fn output_failure(&self) -> Option<Arc<AtomicBool>> {
        match &self.backing {
            Backing::Input(input) => input.output_failure(),
            Backing::Output(output) => output.output_failure.clone(),
        }
    }
    fn invalidate_output(&mut self) {
        match &mut self.backing {
            Backing::Input(input) => input.invalidate_output(),
            Backing::Output(output) => {
                output.failed = true;
                mark_output_failure(&output.output_failure);
            }
        }
    }
    fn check(&self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        self.scope.checkpoint()?;
        scope.checkpoint()?;
        if !self.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput("foreign PDF snapshot"));
        }
        match &self.backing {
            Backing::Input(input) => input.check(scope)?,
            Backing::Output(output) => output.scope.checkpoint()?,
        }
        Ok(())
    }
    pub fn read_region(
        &mut self,
        region: Region,
        output: &mut [u8],
    ) -> Result<usize, ProcessingError> {
        self.scope.checkpoint()?;
        if region.end()? > self.extent {
            return Err(ProcessingError::InvalidInput(
                "PDF snapshot region exceeds sealed extent",
            ));
        }
        match &mut self.backing {
            Backing::Input(input) => input.read_region(region, output),
            Backing::Output(output_stage) => output_stage.read_region(region, output),
        }
    }
    pub fn derive_region(
        &mut self,
        region: Region,
        scope: &ResourceScope,
        encoding: SnapshotEncoding,
    ) -> Result<DerivedInput, ProcessingError> {
        self.check(scope)?;
        if region.end()? > self.extent {
            return Err(ProcessingError::InvalidInput(
                "derived PDF region exceeds sealed extent",
            ));
        }
        let identity = self.identity.clone();
        let owner = self.scope.retain();
        let output_derived = self.is_output_derived();
        super::frozen::decode_region(
            region,
            scope,
            &identity,
            &owner,
            encoding,
            output_derived,
            false,
            |region, out| self.read_region(region, out),
        )
    }
    pub(crate) fn binds(
        &self,
        value: &DerivedInput,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        self.check(scope)?;
        value.binds_origin(&self.identity, scope)
    }
    pub fn reader<'s>(
        &'s mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<PdfSnapshotReader<'s, 'a>, ProcessingError> {
        self.check(scope)?;
        if regions.is_empty() || regions.len() > 4096 {
            return Err(ProcessingError::MetadataLimit);
        }
        let mut end = 0;
        let mut length = 0u64;
        for region in regions {
            if region.offset < end || region.end()? > self.extent {
                return Err(ProcessingError::InvalidInput(
                    "PDF snapshot regions overlap or exceed extent",
                ));
            }
            end = region.end()?;
            length = length
                .checked_add(region.len)
                .ok_or(ProcessingError::InputLimit)?;
        }
        let bytes = regions.len() as u64 * std::mem::size_of::<Region>() as u64;
        let memory = scope.reserve_memory(bytes)?;
        let metadata = scope.reserve_metadata(bytes)?;
        Ok(PdfSnapshotReader {
            input: self,
            regions: regions.to_vec(),
            length,
            position: 0,
            error: None,
            _memory: memory,
            _metadata: metadata,
        })
    }
}
pub struct PdfSnapshotReader<'a, 's> {
    input: &'a mut PdfSnapshot<'s>,
    regions: Vec<Region>,
    length: u64,
    position: u64,
    error: Option<ProcessingError>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl PdfSnapshotReader<'_, '_> {
    pub fn source(&mut self) -> Source<'_> {
        let len = Some(self.length);
        let admitted = Some(self.input.scope.retain());
        let output = self.input.is_output_derived();
        let output_failure = self.input.output_failure();
        Source {
            reader: if output {
                Reader::OutputProjection(self)
            } else {
                Reader::Snapshot(self)
            },
            len,
            admitted,
            output_failure,
            classification: None,
        }
    }
    pub fn finish(&mut self) -> Result<(), ProcessingError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        self.input.scope.checkpoint()
    }
}
impl Read for PdfSnapshotReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::Error::other("PDF snapshot read failed"));
        }
        if self.position == self.length {
            return Ok(0);
        }
        let mut start = 0;
        let region = self
            .regions
            .iter()
            .find_map(|r| {
                if self.position < start + r.len {
                    Some(Region {
                        offset: r.offset + self.position - start,
                        len: start + r.len - self.position,
                    })
                } else {
                    start += r.len;
                    None
                }
            })
            .ok_or_else(|| io::Error::other("PDF snapshot read position"))?;
        match self.input.read_region(region, out) {
            Ok(n) => {
                self.position += n as u64;
                Ok(n)
            }
            Err(error) => {
                self.error = Some(error);
                Err(io::Error::other("PDF snapshot read failed"))
            }
        }
    }
}
impl Seek for PdfSnapshotReader<'_, '_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let at = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
            SeekFrom::End(n) => self.length.checked_add_signed(n),
        }
        .filter(|at| *at <= self.length)
        .ok_or_else(|| io::Error::other("PDF snapshot seek"))?;
        self.position = at;
        Ok(at)
    }
}
impl SnapshotReader for PdfSnapshotReader<'_, '_> {
    fn finish_snapshot(&mut self) -> Result<(), ProcessingError> {
        self.finish()
    }
    fn invalidate_snapshot(&mut self) {
        self.input.invalidate_output();
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for std::sync::Mutex<super::PdfSnapshot<'_>> {}
}
/// Sealed read-only coverage handle. Only SDK immutable input or exclusively
/// borrowed sealed OUTPUT views implement it; callers cannot forge a reader.
pub trait PdfSnapshotCoverage: sealed::Sealed + Send + Sync {
    fn read_region(&self, region: Region, output: &mut [u8]) -> Result<usize, ProcessingError>;
}
impl PdfSnapshotCoverage for std::sync::Mutex<PdfSnapshot<'_>> {
    fn read_region(&self, region: Region, output: &mut [u8]) -> Result<usize, ProcessingError> {
        self.try_lock()
            .map_err(|_| ProcessingError::InvalidInput("snapshot already borrowed"))?
            .read_region(region, output)
    }
}
