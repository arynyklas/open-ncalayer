use super::ownership::{FrameBuffer, OperationOutput};
use super::*;
use oncl_core::OperationId;
use oncl_pki::{
    private_fs::PrivateDirectory,
    resource::{IO_CHUNK_BYTES, ResourceScope},
};
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const HEADER_BYTES: usize = 40;
const HEADER_MAGIC: &[u8; 8] = b"ONCLOUT1";

pub(in crate::service) struct ArtifactStore {
    directory: Option<PrivateDirectory>,
    path: PathBuf,
    _parent: PrivateDirectory,
}
pub(super) fn random_component(prefix: &str) -> Result<(String, [u8; 16]), ProcessingError> {
    use std::fmt::Write as _;
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|error| ProcessingError::Io(io::Error::other(error)))?;
    let mut name = String::with_capacity(prefix.len() + 32);
    name.push_str(prefix);
    for byte in random {
        write!(&mut name, "{byte:02x}")
            .map_err(|_| ProcessingError::InvalidInput("random name encoding"))?;
    }
    Ok((name, random))
}
impl ArtifactStore {
    pub(in crate::service) fn new(parent: &Path) -> Result<Arc<Self>, ProcessingError> {
        let pinned = PrivateDirectory::open(parent)?;
        let (name, _) = random_component("oncl-http-")?;
        let path = parent.join(name);
        let directory = PrivateDirectory::create(&path)?;
        Ok(Arc::new(Self {
            directory: Some(directory),
            path,
            _parent: pinned,
        }))
    }
    fn directory(&self) -> &PrivateDirectory {
        self.directory.as_ref().expect("live output store")
    }
}
impl Drop for ArtifactStore {
    fn drop(&mut self) {
        drop(self.directory.take());
        // Never recursively delete a directory or an unexpected foreign entry.
        let _ = std::fs::remove_dir(&self.path);
    }
}
struct FileBody {
    file: Option<File>,
    store: Arc<ArtifactStore>,
    name: String,
    header: [u8; HEADER_BYTES],
    initialized: bool,
    failed: bool,
    length: u64,
    temp: ResourceReservation,
    _metadata: ResourceReservation,
}
impl Drop for FileBody {
    fn drop(&mut self) {
        // Before initialization returns there is no external handle/name handoff:
        // exclusive create_new itself proves ownership of an incomplete header.
        let owned = if !self.initialized {
            true
        } else {
            self.store
                .directory()
                .open_file(&self.name)
                .ok()
                .is_some_and(|mut file| {
                    let mut header = [0; HEADER_BYTES];
                    file.read_exact(&mut header).is_ok() && header == self.header
                })
        };
        drop(self.file.take());
        if owned {
            let _ = self.store.directory().remove_file(&self.name);
        }
    }
}
enum ArtifactPhase {
    Writing(FileBody),
    Finished(FileBody),
    Aborted,
}
pub(super) struct ArtifactState {
    operation: OperationId,
    identity: Arc<()>,
    scope: ResourceScope,
    failure: Arc<intake::Failure>,
    phase: Mutex<ArtifactPhase>,
}
impl ArtifactState {
    pub(super) fn check_owner(&self, owner: &OperationOutput) -> Result<(), ProcessingError> {
        if self.operation != owner.id()
            || !Arc::ptr_eq(&self.identity, owner.identity())
            || !self.scope.same_operation(owner.scope())
        {
            return Err(ProcessingError::InvalidInput("foreign output artifact"));
        }
        Ok(())
    }
    fn io_error(&self, error: ProcessingError) -> io::Error {
        self.failure.record(error);
        match self
            .failure
            .recover(ProcessingError::InvalidInput("artifact I/O failed"))
        {
            ProcessingError::Io(carrier) => carrier,
            error => io::Error::other(error),
        }
    }
}
/// Server-private SDK dynWrite destination. SDK accounts actual produced output
/// once; this adapter accounts only its own real disk and metadata allocations.
pub(super) struct ArtifactWriter {
    state: Arc<ArtifactState>,
    finalized: bool,
}
#[derive(Clone)]
pub(super) struct FinishedArtifact {
    state: Arc<ArtifactState>,
    length: u64,
}
impl ArtifactWriter {
    pub(super) fn new(
        store: Arc<ArtifactStore>,
        owner: Arc<OperationOutput>,
        context: &mut OperationContext,
    ) -> Result<Self, ProcessingError> {
        owner.check_context(context)?;
        owner.delivery().checkpoint()?;
        let scope = owner.scope().shared_view();
        let metadata = scope.reserve_metadata(std::mem::size_of::<ArtifactState>() as u64 + 256)?;
        let temp = scope.reserve_temp(HEADER_BYTES as u64)?;
        let (name, random) = random_component("http-")?;
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(HEADER_MAGIC);
        header[8..24].copy_from_slice(&random);
        header[24..32].copy_from_slice(&owner.id().get().to_le_bytes());
        let file = store.directory().create_file(&name)?;
        let mut body = FileBody {
            file: Some(file),
            store,
            name,
            header,
            initialized: false,
            failed: false,
            length: 0,
            temp,
            _metadata: metadata,
        };
        body.file
            .as_mut()
            .expect("new artifact")
            .write_all(&header)?;
        body.initialized = true;
        let state = Arc::new(ArtifactState {
            operation: owner.id(),
            identity: owner.identity().clone(),
            scope,
            failure: owner.failure().clone(),
            phase: Mutex::new(ArtifactPhase::Writing(body)),
        });
        owner.register_artifact(state.clone())?;
        Ok(Self {
            state,
            finalized: false,
        })
    }
    pub(super) fn finish(
        mut self,
        expected_length: u64,
    ) -> Result<FinishedArtifact, ProcessingError> {
        self.state.scope.checkpoint()?;
        let mut phase = self
            .state
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut body = match std::mem::replace(&mut *phase, ArtifactPhase::Aborted) {
            ArtifactPhase::Writing(body) => body,
            _ => {
                return Err(self
                    .state
                    .failure
                    .recover(ProcessingError::InvalidInput("artifact already closed")));
            }
        };
        if body.failed {
            return Err(self
                .state
                .failure
                .recover(ProcessingError::InvalidInput("failed output cannot finish")));
        }
        let result = (|| -> Result<(), ProcessingError> {
            if body.length != expected_length {
                return Err(ProcessingError::InvalidInput("SDK output length mismatch"));
            }
            let file = body.file.as_mut().expect("live artifact");
            file.flush()?;
            file.sync_all()?;
            let expected = (HEADER_BYTES as u64)
                .checked_add(body.length)
                .ok_or(ProcessingError::OutputLimit)?;
            if file.metadata()?.len() != expected {
                return Err(ProcessingError::InvalidInput("artifact extent changed"));
            }
            file.seek(SeekFrom::Start(0))?;
            let mut header = [0; HEADER_BYTES];
            file.read_exact(&mut header)?;
            if header != body.header {
                return Err(ProcessingError::InvalidInput("artifact ownership changed"));
            }
            self.state.scope.checkpoint()?;
            Ok(())
        })();
        if let Err(error) = result {
            self.state.failure.record(error);
            return Err(self.state.failure.recover(ProcessingError::InvalidInput(
                "artifact finalization failed",
            )));
        }
        let length = body.length;
        *phase = ArtifactPhase::Finished(body);
        self.finalized = true;
        Ok(FinishedArtifact {
            state: self.state.clone(),
            length,
        })
    }
}
impl Write for ArtifactWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut phase = self
            .state
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = match &mut *phase {
            ArtifactPhase::Writing(body) if !body.failed => body,
            _ => {
                return Err(self
                    .state
                    .io_error(ProcessingError::InvalidInput("closed output writer")));
            }
        };
        if let Err(error) = self.state.scope.checkpoint() {
            body.failed = true;
            return Err(self.state.io_error(error));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let wanted = bytes.len().min(IO_CHUNK_BYTES);
        if let Err(error) = body.temp.grow(wanted as u64) {
            body.failed = true;
            return Err(self.state.io_error(error));
        }
        match body
            .file
            .as_mut()
            .expect("live artifact")
            .write(&bytes[..wanted])
        {
            Ok(written) => {
                body.temp
                    .shrink((wanted - written) as u64)
                    .map_err(|error| self.state.io_error(error))?;
                body.length = body
                    .length
                    .checked_add(written as u64)
                    .ok_or_else(|| self.state.io_error(ProcessingError::OutputLimit))?;
                Ok(written)
            }
            Err(error) => {
                body.failed = true;
                // Keep a conservative reservation if the OS cannot report its
                // extent. Never assume write_all succeeded or refund output.
                if let Ok(metadata) = body.file.as_ref().expect("live artifact").metadata()
                    && let Some(actual) = metadata
                        .len()
                        .checked_sub(HEADER_BYTES as u64)
                        .and_then(|extent| extent.checked_sub(body.length))
                        .filter(|count| *count <= wanted as u64)
                {
                    body.length += actual;
                    let _ = body.temp.shrink(wanted as u64 - actual);
                }
                Err(self.state.io_error(ProcessingError::Io(error)))
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut phase = self
            .state
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &mut *phase {
            ArtifactPhase::Writing(body) if !body.failed => {
                let result = self.state.scope.checkpoint().and_then(|()| {
                    body.file
                        .as_mut()
                        .expect("live artifact")
                        .flush()
                        .map_err(ProcessingError::Io)
                });
                result.map_err(|error| {
                    body.failed = true;
                    self.state.io_error(error)
                })
            }
            _ => Err(self
                .state
                .io_error(ProcessingError::InvalidInput("closed output flush"))),
        }
    }
}
impl Drop for ArtifactWriter {
    fn drop(&mut self) {
        if !self.finalized {
            let mut phase = self
                .state
                .phase
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *phase = ArtifactPhase::Aborted;
        }
    }
}
pub(crate) struct OutputReadTask {
    artifact: FinishedArtifact,
    owner: Arc<OperationOutput>,
    offset: u64,
}
pub(crate) struct OutputReadResult {
    pub(crate) bytes: Bytes,
    pub(crate) next: u64,
}
impl FinishedArtifact {
    pub(super) fn len(&self) -> u64 {
        self.length
    }
    pub(super) fn read_task(
        &self,
        owner: Arc<OperationOutput>,
        offset: u64,
    ) -> Result<OutputReadTask, ProcessingError> {
        self.state.check_owner(&owner)?;
        owner.delivery().checkpoint()?;
        if !owner.context_returned() || offset > self.length {
            return Err(ProcessingError::InvalidInput(
                "output is not ready for delivery",
            ));
        }
        Ok(OutputReadTask {
            artifact: self.clone(),
            owner,
            offset,
        })
    }
}
impl OutputReadTask {
    pub(crate) fn scope(&self) -> ResourceScope {
        self.owner.scope().shared_view()
    }
    pub(crate) fn execute(self) -> Result<OutputReadResult, ProcessingError> {
        self.artifact.state.check_owner(&self.owner)?;
        self.owner.delivery().checkpoint()?;
        if !self.owner.context_returned() {
            return Err(ProcessingError::InvalidInput("output context still active"));
        }
        let length =
            usize::try_from((self.artifact.length - self.offset).min(IO_CHUNK_BYTES as u64))
                .map_err(|_| ProcessingError::MemoryLimit)?;
        let mut bytes: FrameBuffer = self.owner.data_buffer(length)?;
        let mut phase = self
            .artifact
            .state
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = match &mut *phase {
            ArtifactPhase::Finished(body) => body,
            _ => return Err(ProcessingError::InvalidInput("unpublished artifact")),
        };
        let position = (HEADER_BYTES as u64)
            .checked_add(self.offset)
            .ok_or(ProcessingError::OutputLimit)?;
        let file = body.file.as_mut().expect("finished artifact");
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(bytes.as_mut())?;
        self.owner.delivery().checkpoint()?;
        Ok(OutputReadResult {
            bytes: bytes.freeze(),
            next: self.offset + length as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{intake::Failure, ownership::OperationOutput};
    use super::*;
    use crate::{
        executor::{CancelOnDrop, Cancellation},
        service::ResponseDelivery,
    };
    use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
    use oncl_pki::{
        io::{Source, TemporaryStore},
        resource::ResourceLimits,
    };
    use std::{
        io::{Cursor, Write},
        sync::Arc,
    };

    fn fixture(
        output: u64,
        temp: u64,
    ) -> (
        tempfile::TempDir,
        Arc<Engine>,
        Arc<OperationOutput>,
        super::super::ownership::ContextGuard,
        Arc<ArtifactStore>,
    ) {
        fixture_control(output, temp, None)
    }
    fn fixture_control(
        output: u64,
        temp: u64,
        control: Option<Arc<dyn oncl_pki::resource::OperationControl>>,
    ) -> (
        tempfile::TempDir,
        Arc<Engine>,
        Arc<OperationOutput>,
        super::super::ownership::ContextGuard,
        Arc<ArtifactStore>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let scratch = directory.path().join("scratch");
        drop(oncl_pki::private_fs::PrivateDirectory::create(&scratch).unwrap());
        let store = ArtifactStore::new(&scratch).unwrap();
        let temporary = TemporaryStore::new(&scratch).unwrap();
        let engine = Arc::new(
            Engine::new(
                EngineServices::hash_only(ResourceLimits {
                    max_in_flight: 2,
                    output_bytes: output,
                    temp_bytes: temp,
                    metadata_bytes: 67_108_864,
                    ..ResourceLimits::default()
                })
                .with_temporary_store(temporary),
            )
            .unwrap(),
        );
        let cancel = Arc::new(Cancellation::new());
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Extract]),
                OperationPolicy::strict_online(),
                control.unwrap_or_else(|| cancel.clone()),
            )
            .unwrap();
        let delivery = ResponseDelivery {
            deadline: ctx.deadline(),
            cancel: cancel.clone(),
            control: ctx.resources().operation_control(),
            _disconnect: Arc::new(CancelOnDrop(cancel)),
        };
        let (root, guard) = OperationOutput::new(
            engine.clone(),
            ctx,
            delivery,
            Arc::new(Failure::default()),
            1,
        )
        .unwrap();
        (directory, engine, root, guard, store)
    }
    fn cms(data: &[u8]) -> Vec<u8> {
        use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
        let fixture = oncl_testkit::synthetic("user-rsa-sign");
        let key = oncl_pki::pkcs12::load(&oncl_testkit::read(&fixture.path), &fixture.password)
            .unwrap()
            .remove(0);
        cms::sign_spec(
            &key,
            &[],
            &SignSpec {
                content: Content::Data(data),
                encapsulate: true,
                cosign: CoSign::Never,
                econtent_type: None,
                digest: None,
                attrs: AttrSpec {
                    content_type: true,
                    message_digest: true,
                    signing_certificate_v2: true,
                    signing_time: None,
                    extra: vec![],
                },
                certificates: CertSpec::Signer,
            },
        )
        .unwrap()
    }
    fn file_bytes(writer: &ArtifactWriter) -> u64 {
        match &*writer
            .state
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            ArtifactPhase::Writing(body) | ArtifactPhase::Finished(body) => body.length,
            ArtifactPhase::Aborted => 0,
        }
    }
    #[test]
    fn actual_sdk_extraction_counts_output_once_with_exact_n_and_n_minus_one() {
        let payload = vec![b'x'; 300_000];
        let cms = cms(&payload);
        for limit in [payload.len() as u64, payload.len() as u64 - 1] {
            let (_directory, engine, root, mut guard, store) = fixture(limit, 10_000_000);
            let mut writer = ArtifactWriter::new(store, root.clone(), guard.context()).unwrap();
            let result = engine.extract(
                Source::seekable(&mut Cursor::new(&cms), Some(cms.len() as u64)),
                &mut writer,
                guard.context(),
            );
            if limit == payload.len() as u64 {
                assert_eq!(result.unwrap().bytes_written, payload.len() as u64);
                let artifact = writer.finish(payload.len() as u64).unwrap();
                guard.complete().unwrap();
                assert_eq!(artifact.len(), payload.len() as u64);
                assert_eq!(root.scope().progress().bytes_out, payload.len() as u64);
                let mut position = 0;
                let mut actual = Vec::with_capacity(payload.len());
                while position < artifact.len() {
                    let result = artifact
                        .read_task(root.clone(), position)
                        .unwrap()
                        .execute()
                        .unwrap();
                    actual.extend_from_slice(&result.bytes);
                    position = result.next;
                }
                assert_eq!(actual, payload);
            } else {
                assert!(matches!(
                    result,
                    Err(oncl_core::OperationError::Processing(
                        ProcessingError::OutputLimit
                    ))
                ));
            }
        }
    }
    #[test]
    fn real_partial_disk_writes_reserve_before_growth_and_failed_output_is_not_finished() {
        let (_directory, _engine, root, mut guard, store) = fixture(
            1_000_000,
            HEADER_BYTES as u64 + oncl_pki::resource::IO_CHUNK_BYTES as u64,
        );
        let mut writer = ArtifactWriter::new(store.clone(), root.clone(), guard.context()).unwrap();
        let data = vec![b'p'; oncl_pki::resource::IO_CHUNK_BYTES * 2];
        guard
            .context()
            .resources()
            .account_output(data.len() as u64)
            .unwrap();
        let written = writer.write(&data).unwrap();
        assert_eq!(written, oncl_pki::resource::IO_CHUNK_BYTES);
        assert_eq!(file_bytes(&writer), written as u64);
        assert!(writer.write(&data[written..]).is_err());
        assert_eq!(file_bytes(&writer), written as u64);
        assert!(writer.finish(data.len() as u64).is_err());
        assert!(store.directory().names().unwrap().is_empty());
    }
    #[test]
    fn unfinished_or_foreign_artifact_cannot_create_a_read_task() {
        let (_directory, _engine, root, mut guard, store) = fixture(16, 10_000);
        let mut writer = ArtifactWriter::new(store, root.clone(), guard.context()).unwrap();
        guard.context().resources().account_output(3).unwrap();
        writer.write_all(b"abc").unwrap();
        let artifact = writer.finish(3).unwrap();
        assert!(artifact.read_task(root.clone(), 0).is_err());
        guard.complete().unwrap();
        assert!(artifact.read_task(root.clone(), 0).is_ok());
        let (_other_dir, _other_engine, foreign, other_guard, _other_store) = fixture(16, 10_000);
        other_guard.complete().unwrap();
        assert!(matches!(
            artifact.read_task(foreign, 0),
            Err(ProcessingError::InvalidInput(_))
        ));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn paced_native_read_releases_worker_but_last_slice_keeps_real_output_temp() {
        use crate::executor::{BoundedExecutor, ExecutorConfig};
        let (_directory, engine, root, mut guard, store) = fixture(3, HEADER_BYTES as u64 + 3);
        let cms = cms(b"abc");
        let mut writer = ArtifactWriter::new(store, root.clone(), guard.context()).unwrap();
        engine
            .extract(
                Source::seekable(&mut Cursor::new(&cms), Some(cms.len() as u64)),
                &mut writer,
                guard.context(),
            )
            .unwrap();
        let artifact = writer.finish(3).unwrap();
        guard.complete().unwrap();
        let executor = BoundedExecutor::new(ExecutorConfig {
            blocking_workers: 1,
            queue_capacity: 1,
            admission_wait: std::time::Duration::from_millis(100),
        })
        .unwrap();
        let result = executor
            .read_output(artifact.read_task(root.clone(), 0).unwrap())
            .await
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(result.bytes.as_ref(), b"abc");
        executor.idle().await;
        assert_eq!(executor.running(), 0);
        let slice = result.bytes.slice(1..2);
        drop(result);
        drop(artifact);
        drop(root);
        let mut other = engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Cancellation::new()),
            )
            .unwrap();
        assert!(matches!(
            other.resources().reserve_temp(1),
            Err(ProcessingError::TempLimit)
        ));
        let worker_engine = engine.clone();
        let value = executor
            .submit_owned(other, move |mut ctx: oncl_core::OperationContext| {
                let result = worker_engine
                    .hash(
                        oncl_pki::key::HashAlg::Sha256,
                        Source::sequential(&mut &b"abc"[..], None),
                        &mut ctx,
                    )
                    .map_err(|error| match error {
                        oncl_core::OperationError::Processing(error) => error,
                        _ => ProcessingError::InvalidInput("SDK error"),
                    })?;
                Ok((ctx, result))
            })
            .await
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(value.1.bytes_in, 3);
        let (mut other, _) = value;
        assert!(matches!(
            other.resources().reserve_temp(1),
            Err(ProcessingError::TempLimit)
        ));
        drop(slice);
        assert!(other.resources().reserve_temp(1).is_ok());
        executor.idle().await;
    }
    #[test]
    fn failed_flush_permanently_seals_actual_writing_body_after_control_recovers() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct FlushControl(AtomicBool);
        impl oncl_pki::resource::OperationControl for FlushControl {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                if self.0.load(Ordering::SeqCst) {
                    Err(ProcessingError::Io(io::Error::from_raw_os_error(5)))
                } else {
                    Ok(())
                }
            }
        }
        let control = Arc::new(FlushControl(AtomicBool::new(false)));
        let (_directory, _engine, root, mut guard, store) =
            fixture_control(16, 10_000, Some(control.clone()));
        let mut writer = ArtifactWriter::new(store.clone(), root.clone(), guard.context()).unwrap();
        guard.context().resources().account_output(3).unwrap();
        writer.write_all(b"abc").unwrap();
        control.0.store(true, Ordering::SeqCst);
        assert!(writer.flush().is_err());
        control.0.store(false, Ordering::SeqCst);
        assert!(
            writer.write(b"later").is_err(),
            "a later successful control checkpoint must not unpoison output"
        );
        assert!(writer.flush().is_err());
        assert!(writer.finish(3).is_err());
        assert!(store.directory().names().unwrap().is_empty());
        let recovered = root.failure().recover(ProcessingError::DeadlineExceeded);
        match intake::first_cause(&recovered) {
            ProcessingError::Io(original) => assert_eq!(original.raw_os_error(), Some(5)),
            _ => panic!("first owned flush cause was lost"),
        }
    }
}
