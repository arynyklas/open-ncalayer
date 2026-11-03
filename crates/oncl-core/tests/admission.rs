use oncl_core::{Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationPolicy};
use oncl_pki::{
    io::Source,
    key::HashAlg,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
#[derive(Default)]
struct Control(AtomicBool);
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
fn engine(timeout: Duration) -> Engine {
    Engine::new(EngineServices::hash_only(ResourceLimits {
        memory_bytes: 1_048_576,
        metadata_bytes: 65_536,
        input_bytes: 4,
        operation_timeout: timeout,
        ..ResourceLimits::default()
    }))
    .unwrap()
}
fn grant() -> ExecutionGrant {
    ExecutionGrant::new([Action::Hash])
}

#[test]
fn admitted_resources_and_original_root_survive_context_transition() {
    let engine = engine(Duration::from_secs(3));
    let mut admitted = engine.admit(Arc::new(Control::default())).unwrap();
    let id = admitted.id();
    let original = admitted.resources().shared_view();
    let metadata = admitted.resources().reserve_metadata(20).unwrap();
    let memory = admitted.resources().reserve_memory(1_048_552).unwrap();
    admitted.resources().account_input(1).unwrap();
    admitted.resources().account_framing(7).unwrap();
    let remaining = admitted.resources().deadline().remaining();
    let mut ctx = engine
        .begin_admitted(admitted, grant(), OperationPolicy::strict_online())
        .unwrap();
    assert_eq!(ctx.id(), id);
    assert!(ctx.resources().same_operation(&original));
    assert_eq!(ctx.resources().progress().bytes_in, 1);
    assert!(ctx.resources().deadline().remaining() <= remaining);
    assert!(ctx.resources().reserve_memory(5).is_err());
    assert!(
        matches!(engine.admit(Arc::new(Control::default())),Err(e) if e.code()==ErrorCode::CapacityExceeded)
    );
    drop(metadata);
    drop(memory);
    let report = engine
        .hash(
            HashAlg::Sha256,
            Source::sequential(&mut &b"abc"[..], None),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.bytes_in, 3);
    assert_eq!(ctx.resources().progress().bytes_in, 4);
    drop(ctx);
    assert!(engine.admit(Arc::new(Control::default())).is_err());
    drop(original);
    assert!(engine.admit(Arc::new(Control::default())).is_ok());
}

#[test]
fn admission_has_no_foreign_engine_or_rebound_scope_authority() {
    let first = engine(Duration::from_secs(3));
    let second = engine(Duration::from_secs(3));
    let admitted = first.admit(Arc::new(Control::default())).unwrap();
    assert!(
        matches!(second.begin_admitted(admitted,grant(),OperationPolicy::strict_online()),Err(e) if e.code()==ErrorCode::InvalidInput)
    );
    let mut original = first.admit(Arc::new(Control::default())).unwrap();
    let mut foreign = second.admit(Arc::new(Control::default())).unwrap();
    std::mem::swap(original.resources(), foreign.resources());
    assert!(
        matches!(first.begin_admitted(original,grant(),OperationPolicy::strict_online()),Err(e) if e.code()==ErrorCode::InvalidInput)
    );
    assert!(
        matches!(second.begin_admitted(foreign,grant(),OperationPolicy::strict_online()),Err(e) if e.code()==ErrorCode::InvalidInput)
    );
    let mut original = first.admit(Arc::new(Control::default())).unwrap();
    let same = original.resources().shared_view();
    *original.resources() = same;
    assert!(
        first
            .begin_admitted(original, grant(), OperationPolicy::strict_online())
            .is_ok()
    );
}

#[test]
fn admission_rejects_empty_authority_expiry_and_original_cancellation() {
    let engine = engine(Duration::from_millis(25));
    let admitted = engine.admit(Arc::new(Control::default())).unwrap();
    assert!(
        matches!(engine.begin_admitted(admitted,ExecutionGrant::new([]),OperationPolicy::strict_online()),Err(e) if e.code()==ErrorCode::PermissionDenied)
    );
    let admitted = engine.admit(Arc::new(Control::default())).unwrap();
    std::thread::sleep(Duration::from_millis(40));
    assert!(
        matches!(engine.begin_admitted(admitted,grant(),OperationPolicy::strict_online()),Err(e) if e.code()==ErrorCode::DeadlineExceeded)
    );
    let cancel = Arc::new(Control::default());
    let admitted = engine.admit(cancel.clone()).unwrap();
    cancel.0.store(true, Ordering::SeqCst);
    assert!(
        matches!(engine.begin_admitted(admitted,grant(),OperationPolicy::strict_online()),Err(e) if e.code()==ErrorCode::Cancelled)
    );
    assert!(engine.admit(Arc::new(Control::default())).is_ok());
}
