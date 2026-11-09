//! Borrowed streaming sources and explicitly published document artifacts.
//!
//! Temporary storage is for documents, never passwords or private keys. Each
//! store creates an unpredictable, owner-only child of the supplied parent.
//! Cleanup unlinks only its own files and removes an empty owned directory; it
//! never recursively traverses a parent, directory link, or reparse target.
//!
//! On Unix the supplied parent must be owned by this user or root, with no
//! group/other write access unless the sticky bit protects child names. Child
//! operations use pinned directory descriptors; final empty-root removal also
//! checks device/inode identity under that parent-security invariant. Same-user
//! or privileged mutations are outside the security boundary: a renamed own
//! root may remain, but an observed foreign replacement is never removed or
//! searched recursively. Windows retains its protective DELETE-capable root
//! handle through handle-bound disposition and close, never path-deleting after
//! releasing that protection. Failed setup/OS cleanup can leave own empty
//! directories rather than risk deleting an unidentified object.
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[path = "io/byte_string.rs"]
mod byte_string;
pub use byte_string::{decode_pdf_byte_string, padded_der_sequence};
#[path = "io/frozen.rs"]
mod frozen;
pub use frozen::{DerivedInput, FrozenInput, FrozenReader, InputSpool, SnapshotEncoding};
#[path = "io/pdf_output.rs"]
mod pdf_output;
pub use pdf_output::PdfSignatureOutput;
mod metadata;
pub use metadata::MetadataInput;
#[path = "io/pdf_snapshot.rs"]
mod pdf_snapshot;
pub use pdf_snapshot::{PdfSnapshot, PdfSnapshotCoverage, PdfSnapshotReader};
#[path = "io/xml_output.rs"]
mod xml_output;
pub use xml_output::XmlSignatureOutput;
#[path = "io/provisional.rs"]
mod provisional;
pub use provisional::ProvisionalInput;

mod captured_private {
    pub trait Sealed {}
}
/// Sealed immutable captured-byte lending for format parsers. A view does not
/// grant original-input provenance, publication or a validated format fact.
pub trait CapturedInput: captured_private::Sealed + Send {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_region(&mut self, region: Region, output: &mut [u8]) -> Result<usize, ProcessingError>;
    fn reader<'a>(
        &'a mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<FrozenReader<'a>, ProcessingError>;
}

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}
trait SnapshotReader: ReadSeek {
    fn finish_snapshot(&mut self) -> Result<(), ProcessingError>;
    fn invalidate_snapshot(&mut self);
}

enum Reader<'a> {
    Sequential(&'a mut dyn Read),
    Seekable(&'a mut dyn ReadSeek),
    Snapshot(&'a mut dyn SnapshotReader),
    // Minted only while a closed output signing transaction owns the stage.
    // It is OUTPUT-admitted, never original frozen-input provenance.
    OutputProjection(&'a mut dyn SnapshotReader),
    FormatSnapshot(&'a mut dyn SnapshotReader),
}
/// A source starts at the reader's current position; length is an optional
/// admission hint, never a substitute for counting bytes actually consumed.
pub struct Source<'a> {
    reader: Reader<'a>,
    len: Option<u64>,
    admitted: Option<ResourceScope>,
    output_failure: Option<Arc<AtomicBool>>,
    classification: Option<Arc<provisional::FormatClassification>>,
}
impl<'a> Source<'a> {
    pub fn sequential(reader: &'a mut dyn Read, len: Option<u64>) -> Self {
        Self {
            reader: Reader::Sequential(reader),
            len,
            admitted: None,
            output_failure: None,
            classification: None,
        }
    }
    pub fn seekable(reader: &'a mut dyn ReadSeek, len: Option<u64>) -> Self {
        Self {
            reader: Reader::Seekable(reader),
            len,
            admitted: None,
            output_failure: None,
            classification: None,
        }
    }
    pub fn known_len(&self) -> Option<u64> {
        self.len
    }
    /// True only for an immutable captured source view from this exact operation.
    pub fn is_snapshot_for(&self, scope: &ResourceScope) -> Result<bool, ProcessingError> {
        match &self.admitted {
            Some(original) if !original.same_operation(scope) => Err(
                ProcessingError::InvalidInput("snapshot belongs to another operation"),
            ),
            Some(_) if matches!(self.reader, Reader::FormatSnapshot(_)) => Err(
                ProcessingError::InvalidInput("format-specific snapshot requires its classifier"),
            ),
            Some(_) => Ok(matches!(self.reader, Reader::Snapshot(_))),
            None => Ok(false),
        }
    }
    pub fn is_output_projection_for(&self, scope: &ResourceScope) -> Result<bool, ProcessingError> {
        match &self.admitted {
            Some(original) if !original.same_operation(scope) => Err(
                ProcessingError::InvalidInput("output projection belongs to another operation"),
            ),
            Some(_) => Ok(matches!(self.reader, Reader::OutputProjection(_))),
            None => Ok(false),
        }
    }
    pub(crate) fn finish_snapshot(&mut self) -> Result<(), ProcessingError> {
        match &mut self.reader {
            Reader::Snapshot(reader)
            | Reader::OutputProjection(reader)
            | Reader::FormatSnapshot(reader) => reader.finish_snapshot(),
            _ => Ok(()),
        }
    }
    fn invalidate_output_projection(&mut self) {
        if let Reader::OutputProjection(reader) = &mut self.reader {
            reader.invalidate_snapshot();
            mark_output_failure(&self.output_failure);
        }
    }
    pub fn as_seekable(&mut self) -> Option<&mut dyn ReadSeek> {
        match &mut self.reader {
            Reader::Sequential(_) => None,
            Reader::Seekable(reader) => Some(&mut **reader),
            Reader::Snapshot(reader)
            | Reader::OutputProjection(reader)
            | Reader::FormatSnapshot(reader) => Some(&mut **reader),
        }
    }
}
impl Read for Source<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.reader {
            Reader::Sequential(reader) => reader.read(buffer),
            Reader::Seekable(reader) => reader.read(buffer),
            Reader::Snapshot(reader)
            | Reader::OutputProjection(reader)
            | Reader::FormatSnapshot(reader) => reader.read(buffer),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub offset: u64,
    pub len: u64,
}
impl Region {
    pub fn end(self) -> Result<u64, ProcessingError> {
        self.offset
            .checked_add(self.len)
            .ok_or(ProcessingError::InvalidInput("region overflows u64"))
    }
}

/// An owner-only private namespace. Artifacts retain the store even if its
/// caller drops this handle, and retain their original operation's budget.
#[derive(Clone)]
pub struct TemporaryStore {
    root: Arc<platform::Root>,
}
impl std::fmt::Debug for TemporaryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TemporaryStore { host-configured }")
    }
}
impl TemporaryStore {
    pub fn new(parent: &Path) -> Result<Self, ProcessingError> {
        Ok(Self {
            root: Arc::new(platform::Root::new(parent)?),
        })
    }
    pub fn stage(&self, scope: &mut ResourceScope) -> Result<StagedArtifact, ProcessingError> {
        self.stage_role(scope, false)
    }
    /// Internal document snapshot. Replay is uncharged internal I/O; this artifact
    /// cannot be published or copied to an external writer, even when empty.
    pub fn stage_source(
        &self,
        scope: &mut ResourceScope,
    ) -> Result<StagedArtifact, ProcessingError> {
        self.stage_role(scope, true)
    }
    fn stage_role(
        &self,
        scope: &mut ResourceScope,
        source: bool,
    ) -> Result<StagedArtifact, ProcessingError> {
        scope.checkpoint()?;
        let metadata =
            scope.reserve_metadata(std::mem::size_of::<StagedArtifact>() as u64 + 512)?;
        let temp = scope.reserve_temp(0)?;
        let name = random_name()?;
        scope.checkpoint()?;
        let file = self.root.create_file(&name)?;
        Ok(StagedArtifact {
            root: self.root.clone(),
            name,
            file: Some(file),
            scope: scope.retain(),
            temp,
            _metadata: metadata,
            failed: false,
            source,
            output_failure: None,
        })
    }
}

/// Unpublished output. Drop deletes scratch; it never commits. Writes reserve
/// temporary disk and cumulative output capacity before touching the file.
/// `commit` is a no-clobber hard-link publication on the same filesystem;
/// unsupported/cross-filesystem links fail without creating a partial destination.
/// The published file retains private permissions. Destination ownership transfers
/// to the caller on success and its persistent disk is no longer SDK scratch.
pub struct StagedArtifact {
    root: Arc<platform::Root>,
    name: String,
    file: Option<File>,
    scope: ResourceScope,
    temp: ResourceReservation,
    _metadata: ResourceReservation,
    failed: bool,
    source: bool,
    output_failure: Option<Arc<AtomicBool>>,
}

/// A synchronized, closed output and fixed host destination. Preparation never
/// grants permission to ignore a later cancellation, deadline, or failure latch.
/// There is no producer, file, Scope, permit, or mutable byte access.
pub struct PreparedPublication {
    stage: StagedArtifact,
    destination: PathBuf,
    _path: ResourceReservation,
}
impl PreparedPublication {
    pub fn commit(self) -> Result<(), ProcessingError> {
        self.stage.scope.checkpoint()?;
        // Control is host code: it may drop another unfinished guard while
        // returning Ok. No callback may intervene between this gate and publish.
        check_output_failure(self.stage.output_failure.as_deref())?;
        if self.stage.failed || self.stage.file.is_none() {
            return Err(ProcessingError::InvalidInput(
                "artifact is failed or closed",
            ));
        }
        self.stage
            .root
            .publish(&self.stage.name, &self.destination)?;
        Ok(())
    }
}

/// Monotonic publication lifecycle, not a validation or authorization receipt.
/// Retains the original resource root through a producer's later replay/report
/// checks. Dropping it unfinished only marks its admitted OUTPUT unpublishable.
pub struct OutputPublicationGuard {
    original: ResourceScope,
    failure: Arc<AtomicBool>,
    finished: bool,
    _metadata: Option<ResourceReservation>,
}
impl OutputPublicationGuard {
    fn check(&self) -> Result<(), ProcessingError> {
        if self.failure.load(Ordering::SeqCst) {
            return Err(ProcessingError::InvalidInput(
                "output publication was aborted",
            ));
        }
        self.original.checkpoint()?;
        if self.failure.load(Ordering::SeqCst) {
            return Err(ProcessingError::InvalidInput(
                "output publication was aborted",
            ));
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<(), ProcessingError> {
        self.check()?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for OutputPublicationGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.failure.store(true, Ordering::SeqCst);
        }
    }
}

/// Closed producer-owned output transaction. Every write reserves and charges
/// output and temporary storage; unfinished or failed execution is unpublishable.
/// It never exposes a file, an unchecked writer, or a separately owned permit.
pub struct OutputTransaction<'a> {
    stage: &'a mut StagedArtifact,
    original: ResourceScope,
    finished: bool,
}
impl<'a> OutputTransaction<'a> {
    pub fn new(
        stage: &'a mut StagedArtifact,
        scope: &ResourceScope,
    ) -> Result<Self, ProcessingError> {
        // A foreign or SOURCE artifact is not admitted and must remain untouched.
        if stage.source || !stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "output transaction requires same-operation OUTPUT",
            ));
        }
        stage.attach_output_failure();
        let transaction = Self {
            stage,
            original: scope.retain(),
            finished: false,
        };
        transaction.check_live()?;
        if !transaction.stage.is_empty() {
            return Err(ProcessingError::InvalidInput(
                "output transaction requires empty OUTPUT",
            ));
        }
        Ok(transaction)
    }
    fn check_live(&self) -> Result<(), ProcessingError> {
        if self.stage.is_failed() || self.stage.file.is_none() {
            return Err(ProcessingError::InvalidInput(
                "output transaction is failed or closed",
            ));
        }
        self.original.checkpoint()?;
        self.stage.scope.checkpoint()?;
        if self.stage.is_failed() || self.stage.file.is_none() {
            return Err(ProcessingError::InvalidInput(
                "output transaction is failed or closed",
            ));
        }
        Ok(())
    }
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), ProcessingError> {
        let result = self
            .check_live()
            .and_then(|()| self.stage.write_chunk(bytes));
        if result.is_err() {
            self.stage.fail_sign_output();
        }
        result
    }
    pub fn len(&self) -> u64 {
        self.stage.len()
    }
    pub fn is_empty(&self) -> bool {
        self.stage.is_empty()
    }
    pub fn finish(mut self) -> Result<(), ProcessingError> {
        self.check_live()?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for OutputTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.stage.fail_sign_output();
        }
    }
}

impl StagedArtifact {
    /// Admit an empty live same-operation OUTPUT before producer execution.
    /// Foreign/SOURCE refusals leave the artifact untouched. Every later own
    /// execution failure, including initial cancellation, is sticky.
    pub fn publication_guard(
        &mut self,
        scope: &ResourceScope,
    ) -> Result<OutputPublicationGuard, ProcessingError> {
        if self.source || !self.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "publication requires same-operation OUTPUT",
            ));
        }
        let failure = self.attach_output_failure();
        let mut guard = OutputPublicationGuard {
            original: scope.retain(),
            failure,
            finished: false,
            _metadata: None,
        };
        if self.file.is_none() || !self.is_empty() || self.is_failed() {
            return Err(ProcessingError::InvalidInput(
                "publication requires empty live OUTPUT",
            ));
        }
        guard.check()?;
        self.scope.checkpoint()?;
        guard._metadata = Some(scope.reserve_metadata(
            (std::mem::size_of::<OutputPublicationGuard>() + std::mem::size_of::<AtomicBool>())
                as u64,
        )?);
        Ok(guard)
    }
    fn attach_output_failure(&mut self) -> Arc<AtomicBool> {
        let failed = self.failed;
        self.output_failure
            .get_or_insert_with(|| Arc::new(AtomicBool::new(failed)))
            .clone()
    }
    fn is_failed(&self) -> bool {
        self.failed
            || self
                .output_failure
                .as_ref()
                .is_some_and(|state| state.load(Ordering::SeqCst))
    }
    pub(crate) fn check_source_binding(
        &self,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        self.scope.checkpoint()?;
        if !self.source || self.is_failed() || !self.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "immutable source binding owner/role",
            ));
        }
        Ok(())
    }
    pub(crate) fn check_sign_output(&self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        if !self.scope.same_operation(scope) || self.source || self.is_failed() || !self.is_empty()
        {
            return Err(ProcessingError::InvalidInput(
                "sign output requires an empty live output artifact from this operation",
            ));
        }
        Ok(())
    }
    pub(crate) fn check_internal_output(
        &self,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        if !self.scope.same_operation(scope) || !self.source || self.is_failed() || !self.is_empty()
        {
            return Err(ProcessingError::InvalidInput(
                "internal output requires an empty live source artifact from this operation",
            ));
        }
        Ok(())
    }
    pub(crate) fn fail_sign_output(&mut self) {
        self.failed = true;
        mark_output_failure(&self.output_failure);
    }
    fn check_pdf_live_output(&mut self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        // Foreign/SOURCE artifacts are not ours to poison. Once the immutable
        // role/operation check admits this OUTPUT, every failure is terminal,
        // including a checkpoint returned before a transaction can be created.
        if self.source || !self.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "PDF requires live same-operation OUTPUT",
            ));
        }
        self.attach_output_failure();
        let result = if self.is_failed() || self.file.is_none() {
            Err(ProcessingError::InvalidInput(
                "PDF output is failed or closed",
            ))
        } else {
            let current = scope.checkpoint();
            let original = self.scope.checkpoint();
            current.and(original)
        };
        if result.is_err() {
            self.fail_sign_output();
        }
        result
    }
    pub fn len(&self) -> u64 {
        self.temp.bytes()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn lease(&self) -> crate::resource::OperationLease {
        self.scope.lease()
    }
    /// Replay at most one bounded chunk without exposing the spool file or
    /// changing its append position. Internal replay is not new document I/O.
    pub fn read_region(
        &mut self,
        region: Region,
        output: &mut [u8],
    ) -> Result<usize, ProcessingError> {
        let result = self.read_region_inner(region, output);
        if result.is_err() && self.output_failure.is_some() {
            self.fail_sign_output();
        }
        result
    }
    fn read_region_inner(
        &mut self,
        region: Region,
        output: &mut [u8],
    ) -> Result<usize, ProcessingError> {
        self.scope.checkpoint()?;
        if self.is_failed() {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        if region.end()? > self.len() {
            return Err(ProcessingError::InvalidInput("region exceeds artifact"));
        }
        let count = region
            .len
            .min(output.len() as u64)
            .min(IO_CHUNK_BYTES as u64) as usize;
        if count == 0 {
            self.scope.checkpoint()?;
            return Ok(0);
        }
        let file = self
            .file
            .as_mut()
            .ok_or(ProcessingError::InvalidInput("artifact closed"))?;
        let position = file.stream_position()?;
        let result = (|| {
            self.scope.checkpoint()?;
            file.seek(SeekFrom::Start(region.offset))?;
            let mut read = 0;
            while read < count {
                self.scope.checkpoint()?;
                let n = match file.read(&mut output[read..count]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                self.scope.checkpoint()?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short staged region",
                    )
                    .into());
                }
                read += n;
            }
            self.scope.checkpoint()?;
            Ok(read)
        })();
        // Restore even when the operation was interrupted. If restoration is
        // ambiguous, neither future append nor publication is safe.
        if let Err(error) = file.seek(SeekFrom::Start(position)) {
            self.failed = true;
            return Err(error.into());
        }
        if result.is_ok() {
            self.scope.checkpoint()?;
        }
        result
    }
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), ProcessingError> {
        let result = self.write_chunk_inner(bytes);
        if result.is_err() && self.output_failure.is_some() {
            self.fail_sign_output();
        }
        result
    }
    fn write_chunk_inner(&mut self, bytes: &[u8]) -> Result<(), ProcessingError> {
        self.scope.checkpoint()?;
        if self.is_failed() {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        let count = u64::try_from(bytes.len()).map_err(|_| ProcessingError::TempLimit)?;
        self.temp.grow(count)?;
        if !self.source
            && let Err(error) = self.scope.account_output(count)
        {
            self.temp.shrink(count)?;
            return Err(error);
        }
        // Keep the full reservation on I/O failure: a partial file still occupies
        // scratch. Never let that incomplete file be committed subsequently.
        let result = write_controlled(
            self.file
                .as_mut()
                .ok_or(ProcessingError::InvalidInput("artifact closed"))?,
            bytes,
            &self.scope,
            self.output_failure.as_deref(),
        );
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn commit(self, destination: &Path) -> Result<(), ProcessingError> {
        self.prepare_commit(destination)?.commit()
    }
    /// Perform deterministic admission and file synchronization without publishing.
    /// Final namespace publication still checks the original live control/latch.
    pub fn prepare_commit(
        self,
        destination: &Path,
    ) -> Result<PreparedPublication, ProcessingError> {
        self.scope.checkpoint()?;
        if self.source {
            return Err(ProcessingError::InvalidInput(
                "source snapshot cannot be published",
            ));
        }
        if self.is_failed() {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        let path_bytes = destination
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .checked_add(std::mem::size_of::<PathBuf>())
            .ok_or(ProcessingError::MetadataLimit)?;
        let path = self.scope.reserve_metadata(path_bytes as u64)?;
        let destination = destination.to_path_buf();
        self.file
            .as_ref()
            .ok_or(ProcessingError::InvalidInput("artifact closed"))?
            .sync_all()?;
        checkpoint_output(&self.scope, self.output_failure.as_deref())?;
        if self.failed || self.file.is_none() {
            return Err(ProcessingError::InvalidInput(
                "artifact is failed or closed",
            ));
        }
        Ok(PreparedPublication {
            stage: self,
            destination,
            _path: path,
        })
    }
    /// Explicit streaming delivery. The caller's writer can receive a partial
    /// result on I/O/cancel/deadline failure; use `commit` for atomic publication.
    /// Output was already charged when staged, and is not double-counted here.
    pub fn copy_to(mut self, output: &mut dyn Write) -> Result<u64, ProcessingError> {
        self.scope.checkpoint()?;
        if self.source {
            return Err(ProcessingError::InvalidInput(
                "source snapshot cannot be delivered",
            ));
        }
        if self.is_failed() {
            return Err(ProcessingError::InvalidInput(
                "artifact has an incomplete write",
            ));
        }
        let failure = self.output_failure.clone();
        let capacity = self.scope.available_memory().min(IO_CHUNK_BYTES as u64) as usize;
        if capacity == 0 {
            return Err(ProcessingError::MemoryLimit);
        }
        let _memory = self.scope.reserve_memory(capacity as u64)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        buffer.resize(capacity, 0);
        let file = self
            .file
            .as_mut()
            .ok_or(ProcessingError::InvalidInput("artifact closed"))?;
        checkpoint_output(&self.scope, failure.as_deref())?;
        file.seek(SeekFrom::Start(0))?;
        let mut copied = 0u64;
        loop {
            checkpoint_output(&self.scope, failure.as_deref())?;
            let n = match file.read(&mut buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            checkpoint_output(&self.scope, failure.as_deref())?;
            if n == 0 {
                break;
            }
            write_controlled(output, &buffer[..n], &self.scope, failure.as_deref())?;
            copied = copied
                .checked_add(n as u64)
                .ok_or(ProcessingError::OutputLimit)?;
        }
        checkpoint_output(&self.scope, failure.as_deref())?;
        output.flush()?;
        checkpoint_output(&self.scope, failure.as_deref())?;
        Ok(copied)
    }
}

fn mark_output_failure(failure: &Option<Arc<AtomicBool>>) {
    if let Some(state) = failure {
        state.store(true, Ordering::SeqCst);
    }
}
impl Drop for StagedArtifact {
    fn drop(&mut self) {
        // Close before unlink on Windows. Reservations are released only after
        // cleanup has run, not when the original context/connection disappears.
        drop(self.file.take());
        self.root.remove_file(&self.name);
    }
}

fn check_output_failure(failure: Option<&AtomicBool>) -> Result<(), ProcessingError> {
    if failure.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
        return Err(ProcessingError::InvalidInput(
            "artifact has an incomplete write",
        ));
    }
    Ok(())
}
fn checkpoint_output(
    scope: &ResourceScope,
    failure: Option<&AtomicBool>,
) -> Result<(), ProcessingError> {
    scope.checkpoint()?;
    check_output_failure(failure)
}
fn write_controlled(
    output: &mut dyn Write,
    mut bytes: &[u8],
    scope: &ResourceScope,
    failure: Option<&AtomicBool>,
) -> Result<(), ProcessingError> {
    while !bytes.is_empty() {
        checkpoint_output(scope, failure)?;
        let request = bytes.len().min(IO_CHUNK_BYTES);
        let n = match output.write(&bytes[..request]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        checkpoint_output(scope, failure)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "artifact write made no progress",
            )
            .into());
        }
        if n > request {
            return Err(ProcessingError::InvalidInput(
                "writer exceeded its supplied buffer",
            ));
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

fn random_name() -> io::Result<String> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    use std::fmt::Write as _;
    let mut name = String::with_capacity(37);
    name.push_str("oncl-");
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    Ok(name)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    pub(super) struct Root {
        parent: File,
        directory: File,
        name: CString,
    }
    fn cpath(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    }
    impl Root {
        pub(super) fn new(parent: &Path) -> io::Result<Self> {
            let parent = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent)?;
            let parent_metadata = parent.metadata()?;
            // Sticky directories (e.g. root-owned /tmp) protect our entries from
            // other writers. A writable non-sticky parent does not, even when we
            // own it. Only this user or root may control the parent itself.
            // SAFETY: geteuid is a parameterless identity query.
            let uid = unsafe { libc::geteuid() };
            if (parent_metadata.uid() != uid && parent_metadata.uid() != 0)
                || (parent_metadata.mode() & 0o022 != 0 && parent_metadata.mode() & 0o1000 == 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "temporary parent permits foreign name replacement",
                ));
            }
            let name = CString::new(random_name()?).map_err(io::Error::other)?;
            // SAFETY: parent is an open directory and name is a single NUL-terminated
            // component. mkdirat creates a new directory, never follows an existing link.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: same pinned parent; O_NOFOLLOW refuses a replaced final link.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                // No pinned child identity exists to authorize cleanup. Leave a
                // possible own empty child rather than unlink an unknown entry.
                return Err(error);
            }
            // SAFETY: successful openat returns one newly owned descriptor.
            let directory = unsafe { File::from_raw_fd(fd) };
            let metadata = directory.metadata()?;
            // An untrusted writable parent can rename a new child before it is
            // opened. Refuse a substituted directory owned by another identity
            // or exposing group/other access. Descriptor-relative I/O then stays
            // in this pinned namespace even if the parent is renamed later.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "temporary root is not owner-only",
                ));
            }
            Ok(Self {
                parent,
                directory,
                name,
            })
        }
        pub(super) fn create_file(&self, name: &str) -> io::Result<File> {
            let name = CString::new(name).map_err(io::Error::other)?;
            // SAFETY: directory is pinned, name is generated internally, and the
            // exclusive create does not open any existing file or final symlink.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful openat returns one newly owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        pub(super) fn remove_file(&self, name: &str) {
            if let Ok(name) = CString::new(name) {
                // SAFETY: unlinkat removes only this exact component relative to
                // the pinned directory; even a substituted symlink is not followed.
                unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
            }
        }
        pub(super) fn publish(&self, name: &str, destination: &Path) -> io::Result<()> {
            let name = CString::new(name).map_err(io::Error::other)?;
            let destination = cpath(destination)?;
            // SAFETY: source is relative to our pinned private directory. linkat
            // without AT_SYMLINK_FOLLOW does not dereference a final source link;
            // the kernel creates the destination exclusively, including dangling links.
            if unsafe {
                libc::linkat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_FDCWD,
                    destination.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: live pinned directory descriptor and writable stat output.
            if unsafe { libc::fstat(self.directory.as_raw_fd(), identity.as_mut_ptr()) } != 0 {
                return;
            }
            // SAFETY: successful fstat initialized the complete identity.
            let identity = unsafe { identity.assume_init() };
            let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: pinned parent, single name, writable stat output; no final
            // link is followed. The parent invariant excludes another identity
            // racing a rename between this check and removal.
            if unsafe {
                libc::fstatat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    entry.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return;
            }
            // SAFETY: successful fstatat initialized the complete stat value.
            let entry = unsafe { entry.assume_init() };
            if identity.st_dev != entry.st_dev || identity.st_ino != entry.st_ino {
                return;
            }
            // Same-user mutations are outside the trust boundary, but an already
            // replaced name is still never removed. Do not search for a moved root.
            // SAFETY: same pinned parent and identity-checked directory name;
            // AT_REMOVEDIR only removes an empty directory, never recursively.
            unsafe {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::private_fs::windows_security::{owner_descriptor, verify_private_directory};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{
        FALSE, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL,
        FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileDispositionInfo, SetFileInformationByHandle,
    };

    pub(super) struct Root {
        path: PathBuf,
        directory: File,
    }
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut result: Vec<u16> = path.as_os_str().encode_wide().collect();
        if result.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
        }
        result.push(0);
        Ok(result)
    }
    impl Root {
        pub(super) fn new(parent: &Path) -> io::Result<Self> {
            let parent = fs::canonicalize(parent)?;
            let path = parent.join(random_name()?);
            let descriptor = owner_descriptor()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: FALSE,
            };
            // SAFETY: path and explicit protected owner-only descriptor live
            // through this exclusive directory creation call.
            if unsafe { CreateDirectoryW(wide(&path)?.as_ptr(), &attributes) } == FALSE {
                return Err(io::Error::last_os_error());
            }
            let directory = fs::OpenOptions::new()
                .read(true)
                .access_mode(FILE_GENERIC_READ | DELETE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)?;
            use std::os::windows::fs::MetadataExt;
            if directory.metadata()?.file_attributes() & 0x400 != 0 {
                // Refuse every reparse kind, not merely recognized symlinks.
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "temporary root is a reparse point",
                ));
            }
            verify_private_directory(&directory, &descriptor)?;
            Ok(Self { path, directory })
        }
        pub(super) fn create_file(&self, name: &str) -> io::Result<File> {
            // The root handle denies delete sharing: the private directory cannot
            // be renamed/replaced by a link while artifacts use its child paths.
            // Give the file its own protected owner-only DACL. Merely inheriting
            // the root's ACE does not set SE_DACL_PROTECTED on the new file.
            let descriptor = owner_descriptor()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: FALSE,
            };
            let path = wide(&self.path.join(name))?;
            // SAFETY: internally generated component and pinned nonreplaceable
            // root; path/descriptor live through exclusive non-reparse creation.
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    &attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful CreateFileW returns exactly one owned handle.
            Ok(unsafe { File::from_raw_handle(handle) })
        }
        pub(super) fn remove_file(&self, name: &str) {
            let _ = fs::remove_file(self.path.join(name));
        }
        pub(super) fn publish(&self, name: &str, destination: &Path) -> io::Result<()> {
            fs::hard_link(self.path.join(name), destination)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: retain the original DELETE-capable, non-delete-shared
            // directory handle throughout disposition and close. This Vista+
            // FileDispositionInfo API preserves the Windows 7 floor. A nonempty
            // directory fails disposition without deleting unrelated contents.
            unsafe {
                SetFileInformationByHandle(
                    self.directory.as_raw_handle(),
                    FileDispositionInfo,
                    (&raw const disposition).cast(),
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            };
            // File's field destructor closes this exact handle; no path deletion
            // occurs after protection is released, even if the old name changes.
        }
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("owner-only temporary stores require a supported Unix or Windows target");
