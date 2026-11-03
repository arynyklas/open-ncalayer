use axum::body::Bytes;
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy,
};
use oncl_pki::{
    io::{Source, StagedArtifact, TemporaryStore},
    key::HashAlg,
    resource::{ProcessingError, ResourceLimits, ResourceReservation},
};
use oncl_server::executor::{BoundedExecutor, Cancellation, ExecutorConfig, WorkOutput};
use std::{sync::Arc, time::Duration};
fn error(error: OperationError) -> ProcessingError {
    match error {
        OperationError::Processing(error) => error,
        _ => ProcessingError::InvalidInput("SDK rejected original context"),
    }
}
fn executor() -> BoundedExecutor {
    BoundedExecutor::new(ExecutorConfig {
        blocking_workers: 1,
        queue_capacity: 1,
        admission_wait: Duration::from_millis(100),
    })
    .unwrap()
}
fn engine() -> Arc<Engine> {
    Arc::new(
        Engine::new(EngineServices::hash_only(ResourceLimits {
            max_in_flight: 2,
            input_bytes: 4,
            memory_bytes: 2_097_152,
            metadata_bytes: 65_536,
            temp_bytes: 32,
            operation_timeout: Duration::from_secs(10),
            ..ResourceLimits::default()
        }))
        .unwrap(),
    )
}
fn context(engine: &Engine) -> OperationContext {
    engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Cancellation::new()),
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_native_intake_transitions_the_exact_original_root_once() {
    let engine = engine();
    let executor = executor();
    let mut admission = engine.admit(Arc::new(Cancellation::new())).unwrap();
    let id = admission.id();
    let original = admission.resources().shared_view();
    admission.resources().account_input(1).unwrap();
    let reservation = admission.resources().reserve_metadata(1024).unwrap();
    let worker_engine = engine.clone();
    let work = executor
        .submit_admitted(
            admission,
            move |admission: oncl_core::OperationAdmission| {
                let mut ctx = worker_engine
                    .begin_admitted(
                        admission,
                        ExecutionGrant::new([Action::Hash]),
                        OperationPolicy::strict_online(),
                    )
                    .map_err(error)?;
                assert_eq!(ctx.id(), id);
                assert!(ctx.resources().same_operation(&original));
                assert_eq!(ctx.resources().progress().bytes_in, 1);
                let report = worker_engine
                    .hash(
                        HashAlg::Sha256,
                        Source::sequential(&mut &b"abc"[..], None),
                        &mut ctx,
                    )
                    .map_err(error)?;
                Ok(WorkOutput {
                    value: (report, reservation),
                    context: ctx,
                })
            },
        )
        .await
        .unwrap();
    let mut output = work.wait().await.unwrap();
    assert_eq!(output.context.id(), id);
    assert_eq!(output.context.resources().progress().bytes_in, 4);
    assert_eq!(output.value.0.bytes_in, 3);
    assert_eq!(output.value.1.bytes(), 1024);
    assert!(matches!(
        output.context.resources().reserve_metadata(65_536),
        Err(ProcessingError::MetadataLimit)
    ));
    drop(output);
    executor.idle().await;
    assert!(engine.admit(Arc::new(Cancellation::new())).is_ok());
}

struct NetworkBytes {
    bytes: Vec<u8>,
    _context: OperationContext,
    _artifact: StagedArtifact,
    _memory: ResourceReservation,
}
impl AsRef<[u8]> for NetworkBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn materialize_output(
    mut ctx: OperationContext,
    engine: &Engine,
    store: &TemporaryStore,
) -> Result<NetworkBytes, ProcessingError> {
    let report = engine
        .hash(
            HashAlg::Sha256,
            Source::sequential(&mut &b"abc"[..], None),
            &mut ctx,
        )
        .map_err(error)?;
    let mut artifact = store.stage(ctx.resources())?;
    artifact.write_chunk(report.digest.as_bytes())?;
    let memory = ctx
        .resources()
        .reserve_memory(report.digest.as_bytes().len() as u64)?;
    let bytes = report.digest.as_bytes().to_vec();
    Ok(NetworkBytes {
        bytes,
        _context: ctx,
        _artifact: artifact,
        _memory: memory,
    })
}
fn artifact_files(parent: &std::path::Path) -> usize {
    std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                std::fs::read_dir(entry.path())
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_file())
                    .count()
            } else {
                0
            }
        })
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owned_work_releases_native_slot_but_output_last_bytes_keep_original_root_and_temp() {
    let engine = engine();
    let executor = executor();
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let ctx = context(&engine);
    let original_id = ctx.id();
    let worker_engine = engine.clone();
    let work = executor
        .submit_owned(ctx, move |ctx: OperationContext| {
            assert_eq!(ctx.id(), original_id);
            materialize_output(ctx, &worker_engine, &store).map(Bytes::from_owner)
        })
        .await
        .unwrap();
    let bytes = work.wait().await.unwrap();
    executor.idle().await;
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(64);
    for byte in bytes.iter() {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    assert_eq!(
        encoded,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(bytes.len(), 32);
    assert_eq!(executor.running(), 0);
    let clone = bytes.clone();
    let slice = clone.slice(1..4);
    drop(bytes);
    drop(clone);
    let mut second = context(&engine);
    assert!(matches!(
        second.resources().reserve_temp(1),
        Err(ProcessingError::TempLimit)
    ));
    let second_engine = engine.clone();
    let work = executor
        .submit(second, move |ctx| {
            second_engine
                .hash(
                    HashAlg::Sha256,
                    Source::sequential(&mut &b"abc"[..], None),
                    ctx,
                )
                .map_err(error)
        })
        .await
        .unwrap();
    let mut second = work.wait().await.unwrap();
    assert_eq!(
        second.value.bytes_in, 3,
        "slow output must not hold a native worker permit"
    );
    assert!(matches!(
        second.context.resources().reserve_temp(1),
        Err(ProcessingError::TempLimit)
    ));
    assert!(
        matches!(engine.admit(Arc::new(Cancellation::new())),Err(error)if error.code()==oncl_core::ErrorCode::CapacityExceeded)
    );
    drop(slice);
    let reservation = second.context.resources().reserve_temp(1).unwrap();
    drop(reservation);
    assert!(engine.admit(Arc::new(Cancellation::new())).is_ok());
    drop(second);
    executor.idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_owned_receiver_keeps_running_worker_and_real_output_until_return() {
    let engine = engine();
    let executor = executor();
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let worker_engine = engine.clone();
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let work = executor
        .submit_owned(context(&engine), move |ctx: OperationContext| {
            let output = materialize_output(ctx, &worker_engine, &store)?;
            let _ = entered.send(());
            let _ = blocked.recv_timeout(Duration::from_secs(20));
            Ok(Bytes::from_owner(output))
        })
        .await
        .unwrap();
    observed.await.unwrap();
    drop(work);
    assert_eq!(executor.running(), 1);
    assert_eq!(artifact_files(directory.path()), 1);
    let mut other = context(&engine);
    assert!(matches!(
        other.resources().reserve_temp(1),
        Err(ProcessingError::TempLimit)
    ));
    assert!(
        matches!(engine.admit(Arc::new(Cancellation::new())),Err(error)if error.code()==oncl_core::ErrorCode::CapacityExceeded)
    );
    release.send(()).unwrap();
    executor.idle().await;
    assert_eq!(artifact_files(directory.path()), 0);
    let temporary = other.resources().reserve_temp(1).unwrap();
    drop(temporary);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owned_worker_panic_unwinds_actual_scratch_and_does_not_publish_output() {
    let engine = engine();
    let executor = executor();
    let directory = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(directory.path()).unwrap();
    let worker_engine = engine.clone();
    let work = executor
        .submit_owned(
            context(&engine),
            move |ctx: OperationContext| -> Result<Bytes, ProcessingError> {
                let _output = materialize_output(ctx, &worker_engine, &store)?;
                panic!("intentional owned worker unwind");
            },
        )
        .await
        .unwrap();
    assert!(matches!(work.wait().await, Err(ProcessingError::Cancelled)));
    executor.idle().await;
    assert_eq!(executor.running(), 0);
    assert_eq!(artifact_files(directory.path()), 0);
    assert!(engine.admit(Arc::new(Cancellation::new())).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_admission_expires_without_native_or_authorized_work_and_queue_is_bounded() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let engine = Arc::new(
        Engine::new(EngineServices::hash_only(ResourceLimits {
            max_in_flight: 4,
            operation_timeout: Duration::from_millis(500),
            ..ResourceLimits::default()
        }))
        .unwrap(),
    );
    let executor = BoundedExecutor::new(ExecutorConfig {
        blocking_workers: 1,
        queue_capacity: 1,
        admission_wait: Duration::from_secs(1),
    })
    .unwrap();
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let worker_engine = engine.clone();
    let held = executor
        .submit_owned(context(&engine), move |mut ctx: OperationContext| {
            let report = worker_engine
                .hash(
                    HashAlg::Sha256,
                    Source::sequential(&mut &b"abc"[..], None),
                    &mut ctx,
                )
                .map_err(error)?;
            let _ = entered.send(());
            let _ = blocked.recv_timeout(Duration::from_secs(20));
            Ok(report)
        })
        .await
        .unwrap();
    observed.await.unwrap();
    let invoked = Arc::new(AtomicBool::new(false));
    let worker_invoked = invoked.clone();
    let admission = engine.admit(Arc::new(Cancellation::new())).unwrap();
    let queued = executor
        .submit_admitted(admission, move |_: oncl_core::OperationAdmission| {
            worker_invoked.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(executor.queued(), 1);
    let rejected = executor
        .submit_admitted(
            engine.admit(Arc::new(Cancellation::new())).unwrap(),
            |_: oncl_core::OperationAdmission| Ok(()),
        )
        .await;
    assert!(matches!(rejected, Err(ProcessingError::CapacityExceeded)));
    assert!(matches!(
        queued.wait().await,
        Err(ProcessingError::DeadlineExceeded)
    ));
    assert!(!invoked.load(Ordering::SeqCst));
    assert_eq!(executor.running(), 1);
    drop(held);
    release.send(()).unwrap();
    executor.idle().await;
    assert!(!invoked.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_native_transition_refuses_foreign_engine_before_sdk_work() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let original = engine();
    let foreign = engine();
    let executor = executor();
    let admission = original.admit(Arc::new(Cancellation::new())).unwrap();
    let invoked = Arc::new(AtomicBool::new(false));
    let worker_invoked = invoked.clone();
    let work = executor
        .submit_admitted(
            admission,
            move |admission: oncl_core::OperationAdmission| {
                let mut ctx = foreign
                    .begin_admitted(
                        admission,
                        ExecutionGrant::new([Action::Hash]),
                        OperationPolicy::strict_online(),
                    )
                    .map_err(error)?;
                worker_invoked.store(true, Ordering::SeqCst);
                foreign
                    .hash(
                        HashAlg::Sha256,
                        Source::sequential(&mut &b"abc"[..], None),
                        &mut ctx,
                    )
                    .map_err(error)?;
                Ok(())
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        work.wait().await,
        Err(ProcessingError::InvalidInput(_))
    ));
    assert!(!invoked.load(Ordering::SeqCst));
    executor.idle().await;
    assert!(original.admit(Arc::new(Cancellation::new())).is_ok());
}
