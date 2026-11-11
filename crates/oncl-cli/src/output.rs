use crate::args::Cli;
use oncl_core::{OperationContext, OperationError};
use oncl_pki::{
    io::{PreparedPublication, StagedArtifact, TemporaryStore},
    resource::{ProcessingError, ResourceReservation},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::Path,
};

/// The process's standard output, whose write errors are all reported.
///
/// `std::io::Stdout` treats `EBADF` as success on Unix (it discards what is written to a
/// closed or read-only descriptor), which would report a result that went nowhere as
/// delivered. Here, as everywhere in this program, a result that was not written is a failure.
#[cfg(unix)]
fn stdout() -> impl Write {
    use std::{
        fs::File,
        mem::ManuallyDrop,
        os::fd::{FromRawFd, RawFd},
    };
    struct Descriptor(ManuallyDrop<File>);
    impl Write for Descriptor {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            (&*self.0).write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    const STDOUT: RawFd = 1;
    // SAFETY: descriptor 1 is only borrowed: `ManuallyDrop` never closes it.
    Descriptor(ManuallyDrop::new(unsafe { File::from_raw_fd(STDOUT) }))
}
#[cfg(not(unix))]
fn stdout() -> impl Write {
    io::stdout().lock()
}

struct BoundedReport {
    bytes: Vec<u8>,
    memory: ResourceReservation,
}
impl Write for BoundedReport {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        const LIMIT: usize = 1024 * 1024;
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= LIMIT)
            .ok_or_else(|| io::Error::other("report capacity"))?;
        if length > self.bytes.capacity() {
            let capacity = length
                .max(self.bytes.capacity().saturating_mul(2))
                .min(LIMIT);
            self.memory
                .grow((capacity - self.bytes.capacity()) as u64)
                .map_err(io::Error::other)?;
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
/// Memory reserved up front for [`terminal`].
pub const TERMINAL_REPORT_BYTES: u64 = 512 * 1024;
struct Capped(Vec<u8>);
impl Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > TERMINAL_REPORT_BYTES as usize {
            return Err(io::Error::other("terminal report capacity"));
        }
        self.0.try_reserve(bytes.len()).map_err(io::Error::other)?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
/// The report of work that already happened, after the operation's control
/// or deadline has stopped it. Every scope operation is gated by that sticky
/// stop, so this path touches none: serialization is capped inside the memory
/// reserved before the work started, a `--report` file is created no-clobber
/// directly (not staged, so a crash mid-write can leave a partial report) and
/// synchronized. It reports failure to its caller, which must keep the stop exit code.
pub fn terminal<T: Serialize>(cli: &Cli, value: &T, human: &str) -> Result<(), OperationError> {
    let mut buffer = Capped(Vec::new());
    if cli.json || cli.report.is_some() {
        serde_json::to_writer(&mut buffer, value).map_err(|_| ProcessingError::MetadataLimit)?;
    } else {
        buffer
            .write_all(human.as_bytes())
            .map_err(ProcessingError::from)?;
    }
    buffer.write_all(b"\n").map_err(ProcessingError::from)?;
    if let Some(path) = &cli.report {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(ProcessingError::from)?;
        file.write_all(&buffer.0).map_err(ProcessingError::from)?;
        file.sync_all().map_err(ProcessingError::from)?;
    } else {
        let mut stdout = stdout();
        stdout.write_all(&buffer.0).map_err(ProcessingError::from)?;
        stdout.flush().map_err(ProcessingError::from)?;
    }
    Ok(())
}
pub struct PreparedReport {
    destination: ReportDestination,
}
enum ReportDestination {
    File(PreparedPublication),
    Stdout(BoundedReport),
    Stderr(BoundedReport),
}
pub fn prepare<T: Serialize>(
    cli: &Cli,
    value: &T,
    human: &str,
    artifact: bool,
    ctx: &mut OperationContext,
) -> Result<PreparedReport, OperationError> {
    ctx.resources().checkpoint()?;
    let mut buffer = BoundedReport {
        bytes: Vec::new(),
        memory: ctx.resources().reserve_memory(0)?,
    };
    if cli.json || cli.report.is_some() {
        serde_json::to_writer(&mut buffer, value).map_err(|_| ProcessingError::MetadataLimit)?;
    } else {
        buffer
            .write_all(human.as_bytes())
            .map_err(ProcessingError::from)?;
    }
    buffer.write_all(b"\n").map_err(ProcessingError::from)?;
    let destination = if let Some(path) = &cli.report {
        let store = TemporaryStore::new(parent(path))?;
        let mut staged = store.stage(ctx.resources())?;
        staged.write_chunk(&buffer.bytes)?;
        ReportDestination::File(staged.prepare_commit(path)?)
    } else if artifact && !cli.json {
        ctx.resources().account_output(buffer.bytes.len() as u64)?;
        ReportDestination::Stderr(buffer)
    } else {
        ctx.resources().account_output(buffer.bytes.len() as u64)?;
        ReportDestination::Stdout(buffer)
    };
    ctx.resources().checkpoint()?;
    Ok(PreparedReport { destination })
}
impl PreparedReport {
    pub fn send(self) -> Result<(), OperationError> {
        match self.destination {
            ReportDestination::File(publication) => publication.commit()?,
            ReportDestination::Stdout(buffer) => send_buffer(buffer, &mut stdout())?,
            ReportDestination::Stderr(buffer) => send_buffer(buffer, &mut io::stderr().lock())?,
        }
        Ok(())
    }
}
fn send_buffer(buffer: BoundedReport, writer: &mut dyn Write) -> Result<(), OperationError> {
    writer
        .write_all(&buffer.bytes)
        .map_err(ProcessingError::from)?;
    writer.flush().map_err(ProcessingError::from)?;
    Ok(())
}
pub fn report<T: Serialize>(
    cli: &Cli,
    value: &T,
    human: &str,
    ctx: &mut OperationContext,
) -> Result<(), OperationError> {
    prepare(cli, value, human, false, ctx)?.send()
}
pub fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
pub fn store(cli: &Cli, destination: &str) -> Result<TemporaryStore, OperationError> {
    let parent = if destination == "-" {
        cli.temporary_directory.as_deref().unwrap_or(Path::new("."))
    } else {
        parent(Path::new(destination))
    };
    Ok(TemporaryStore::new(parent)?)
}
pub fn deliver(stage: StagedArtifact, destination: &str) -> Result<(), OperationError> {
    if destination == "-" {
        stage.copy_to(&mut stdout())?;
    } else {
        stage.commit(Path::new(destination))?;
    }
    Ok(())
}

fn after_use(error: OperationError, applied: oncl_core::keys::AppliedState) -> OperationError {
    let applied = applied.combine(error.applied_state());
    if applied == oncl_core::keys::AppliedState::NotApplied || applied == error.applied_state() {
        error
    } else {
        OperationError::AfterKeyUse {
            source: Box::new(error),
            applied,
        }
    }
}
/// All report serialization/quota admission precedes document publication.
/// A later physical report I/O/control failure cannot roll back a complete file.
pub fn finish_artifact(
    stage: StagedArtifact,
    destination: &str,
    prepared: Result<PreparedReport, OperationError>,
    applied: oncl_core::keys::AppliedState,
) -> Result<(), OperationError> {
    let prepared = prepared.map_err(|error| after_use(error, applied))?;
    deliver(stage, destination).map_err(|error| after_use(error, applied))?;
    if let Err(error) = prepared.send() {
        crate::diagnostic(format_args!(
            "oncl: report_delivery_failed; document={}; code={:?}; applied={:?}",
            if destination == "-" {
                "Delivered"
            } else {
                "Published"
            },
            error.code(),
            applied.combine(error.applied_state()),
        ));
        return Err(after_use(error, applied));
    }
    Ok(())
}
