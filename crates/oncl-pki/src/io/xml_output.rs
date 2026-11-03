//! Role-preserving output assembly/replay. XML placement stays in oncl-xml.
use super::*;
/// Exclusive append transaction. Drop or any terminal failure before finish
/// permanently poisons only its own unpublished OUTPUT artifact.
pub struct XmlSignatureOutput<'a> {
    stage: &'a mut StagedArtifact,
    position: u64,
    extent: u64,
    error: Option<ProcessingError>,
    complete: bool,
}
impl<'a> XmlSignatureOutput<'a> {
    pub fn check_output(
        stage: &StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        if stage.source || !stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "foreign or source XML output",
            ));
        }
        stage.check_sign_output(scope)
    }
    pub fn new(
        stage: &'a mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        // Foreign/source rejection is not authority to poison someone else's artifact.
        if stage.source || !stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "foreign or source XML output",
            ));
        }
        stage.attach_output_failure();
        let transaction = Self {
            stage,
            position: 0,
            extent: 0,
            error: None,
            complete: false,
        };
        // The Drop guard already exists before the first fallible checkpoint.
        transaction.stage.check_sign_output(scope)?;
        Ok(transaction)
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), ProcessingError> {
        let result = self.stage.write_chunk(bytes);
        if result.is_err() {
            self.stage.fail_sign_output()
        }
        result
    }
    pub fn len(&self) -> u64 {
        self.stage.len()
    }
    pub fn is_empty(&self) -> bool {
        self.stage.is_empty()
    }
    pub fn source(&mut self) -> Result<Source<'_>, ProcessingError> {
        if let Err(error) = self.check() {
            self.stage.fail_sign_output();
            return Err(error);
        }
        self.position = 0;
        self.extent = self.stage.len();
        let length = self.extent;
        let scope = self.stage.scope.retain();
        let output_failure = self.stage.output_failure.clone();
        Ok(Source {
            reader: Reader::OutputProjection(self),
            len: Some(length),
            admitted: Some(scope),
            output_failure,
        })
    }
    fn check(&self) -> Result<(), ProcessingError> {
        self.stage.scope.checkpoint()?;
        if self.stage.is_failed() || self.error.is_some() {
            return Err(ProcessingError::InvalidInput(
                "failed XML output transaction",
            ));
        }
        Ok(())
    }
    pub fn finish(mut self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        if !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "foreign XML output completion",
            ));
        }
        self.check()?;
        scope.checkpoint()?;
        self.complete = true;
        Ok(())
    }
}
impl Drop for XmlSignatureOutput<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.stage.fail_sign_output()
        }
    }
}
impl Read for XmlSignatureOutput<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let result = (|| {
            self.check()?;
            if self.stage.len() != self.extent {
                return Err(ProcessingError::InvalidInput("stale XML output extent"));
            }
            if self.position >= self.extent {
                return Ok(0);
            }
            let n = self.stage.read_region(
                Region {
                    offset: self.position,
                    len: self.extent - self.position,
                },
                bytes,
            )?;
            if n == 0 {
                return Err(ProcessingError::InvalidInput("short XML output replay"));
            }
            self.position += n as u64;
            Ok(n)
        })();
        match result {
            Ok(n) => Ok(n),
            Err(error) => {
                self.stage.fail_sign_output();
                self.error = Some(error);
                Err(io::Error::other("XML output replay failed"))
            }
        }
    }
}
impl Seek for XmlSignatureOutput<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let value = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
            SeekFrom::End(n) => self.extent.checked_add_signed(n),
        }
        .ok_or_else(|| io::Error::other("XML output seek overflow"))?;
        self.position = value;
        Ok(value)
    }
}
impl SnapshotReader for XmlSignatureOutput<'_> {
    fn finish_snapshot(&mut self) -> Result<(), ProcessingError> {
        self.check()
    }
    fn invalidate_snapshot(&mut self) {
        self.stage.fail_sign_output()
    }
}
