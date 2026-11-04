//! Operations of an engine count in the host's activity gate from their start to the end of
//! their context, so a maintainer that holds the gate sees them and holds them back.

use oncl_core::activity::ActivityGate;
use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
use oncl_pki::io::Source;
use oncl_pki::key::HashAlg;
use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}

const QUIET: Duration = Duration::from_secs(30);

fn engine(gate: &Arc<ActivityGate>) -> Arc<Engine> {
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    Arc::new(engine.with_activity(Arc::clone(gate)))
}

fn grant() -> ExecutionGrant {
    ExecutionGrant::new([Action::Hash])
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

#[test]
fn a_running_operation_is_activity_until_its_context_ends() {
    let gate = Arc::new(ActivityGate::new());
    let engine = engine(&gate);
    assert!(gate.idle(QUIET, later()));
    let mut ctx = engine
        .begin(grant(), OperationPolicy::strict_online(), Arc::new(Control))
        .unwrap();
    assert!(!gate.idle(QUIET, later()), "the operation is running");
    assert!(
        gate.maintenance(Duration::ZERO, Instant::now, || false)
            .is_none(),
        "a maintainer cannot take the gate under a running operation"
    );
    assert!(!gate.is_held(), "and gives it back at once");
    let mut input = &b"abc"[..];
    engine
        .hash(
            HashAlg::Sha256,
            Source::sequential(&mut input, Some(3)),
            &mut ctx,
        )
        .unwrap();
    drop(ctx);
    assert!(
        !gate.idle(QUIET, Instant::now()),
        "its quiet time has not passed"
    );
    assert!(gate.idle(QUIET, later()));
}

#[test]
fn an_admitted_intake_is_activity_before_any_authority() {
    let gate = Arc::new(ActivityGate::new());
    let engine = engine(&gate);
    let admission = engine.admit(Arc::new(Control)).unwrap();
    assert!(!gate.idle(QUIET, later()), "intake is an operation too");
    drop(admission);
    assert!(gate.idle(QUIET, later()));
}

#[test]
fn an_operation_waits_while_a_maintainer_holds_the_gate() {
    let gate = Arc::new(ActivityGate::new());
    let engine = engine(&gate);
    let lease = gate
        .maintenance(Duration::ZERO, Instant::now, || false)
        .expect("idle");
    let started = Arc::new(AtomicBool::new(false));
    let worker = {
        let (engine, started) = (Arc::clone(&engine), Arc::clone(&started));
        std::thread::spawn(move || {
            let ctx = engine
                .begin(grant(), OperationPolicy::strict_online(), Arc::new(Control))
                .unwrap();
            started.store(true, Ordering::SeqCst);
            drop(ctx);
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !started.load(Ordering::SeqCst),
        "a new operation starts only after the maintainer lets go"
    );
    drop(lease);
    worker.join().unwrap();
    assert!(started.load(Ordering::SeqCst));
}

#[test]
fn an_engine_without_a_gate_is_not_held_back() {
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let ctx = engine
        .begin(grant(), OperationPolicy::strict_online(), Arc::new(Control))
        .unwrap();
    drop(ctx);
}

#[test]
fn a_worker_that_outlives_its_context_keeps_the_operation_running() {
    // A native call still running when the context is dropped (cancelled, abandoned) holds
    // the operation's lease; an installer must not replace the program under it.
    let gate = Arc::new(ActivityGate::new());
    let engine = engine(&gate);
    let ctx = engine
        .begin(grant(), OperationPolicy::strict_online(), Arc::new(Control))
        .unwrap();
    let worker_lease = ctx.lease();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        let _native = worker_lease;
        released.recv().unwrap();
    });
    drop(ctx);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !gate.idle(Duration::ZERO, later()),
        "the worker is still running"
    );
    assert!(
        gate.maintenance(Duration::ZERO, Instant::now, || false)
            .is_none(),
        "a maintainer cannot hold the program under a native worker"
    );
    release.send(()).unwrap();
    worker.join().unwrap();
    assert!(gate.idle(QUIET, later()), "the worker returned");
    // And a maintainer that is abandoned still lets go.
    let hold = gate
        .maintenance(Duration::ZERO, Instant::now, || false)
        .unwrap();
    drop(hold);
    assert!(!gate.is_held());
}
