use crate::args::Cli;
use oncl_core::{OperationContext, OperationError};
use oncl_pki::{
    io::{StagedArtifact, TemporaryStore},
    resource::{ProcessingError, ResourceReservation},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

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
pub struct PreparedReport {
    destination: ReportDestination,
}
enum ReportDestination {
    File(StagedArtifact, PathBuf),
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
        ReportDestination::File(staged, path.clone())
    } else if artifact && !cli.json {
        ReportDestination::Stderr(buffer)
    } else {
        ReportDestination::Stdout(buffer)
    };
    Ok(PreparedReport { destination })
}
impl PreparedReport {
    pub fn send(self, ctx: &mut OperationContext) -> Result<(), OperationError> {
        match self.destination {
            ReportDestination::File(stage, destination) => stage.commit(&destination)?,
            ReportDestination::Stdout(buffer) => {
                send_buffer(buffer, &mut io::stdout().lock(), ctx)?
            }
            ReportDestination::Stderr(buffer) => {
                send_buffer(buffer, &mut io::stderr().lock(), ctx)?
            }
        }
        Ok(())
    }
}
fn send_buffer(
    buffer: BoundedReport,
    writer: &mut dyn Write,
    ctx: &mut OperationContext,
) -> Result<(), OperationError> {
    ctx.resources().checkpoint()?;
    ctx.resources().account_output(buffer.bytes.len() as u64)?;
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
    prepare(cli, value, human, false, ctx)?.send(ctx)
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
        stage.copy_to(&mut io::stdout().lock())?;
    } else {
        stage.commit(Path::new(destination))?;
    }
    Ok(())
}
