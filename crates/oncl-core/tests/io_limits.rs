//! F01: observable budget, streaming, cancellation and staging invariants.
use oncl_core::{Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationPolicy};
use oncl_pki::digest::HashState;
use oncl_pki::io::{Source, TemporaryStore};
use oncl_pki::key::HashAlg;
use oncl_pki::resource::{
    OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget,
};
use std::io::{self, Read};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

#[derive(Default)]
struct Control {
    cancelled: AtomicBool,
}
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
fn grant() -> ExecutionGrant {
    ExecutionGrant::new([Action::Hash])
}
fn engine(limits: ResourceLimits) -> Engine {
    Engine::new(EngineServices::hash_only(limits)).unwrap()
}
fn begin(engine: &Engine) -> oncl_core::OperationContext {
    engine
        .begin(
            grant(),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct CountingReader<'a> {
    remaining: &'a [u8],
    read: Arc<AtomicUsize>,
    chunk: usize,
}
impl Read for CountingReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.remaining.len().min(out.len()).min(self.chunk);
        out[..n].copy_from_slice(&self.remaining[..n]);
        self.remaining = &self.remaining[n..];
        self.read.fetch_add(n, Ordering::SeqCst);
        Ok(n)
    }
}

#[test]
fn scopes_share_one_budget() {
    let limits = ResourceLimits {
        max_in_flight: 1,
        ..ResourceLimits::default()
    };
    let engine = engine(limits);
    let first = begin(&engine);
    assert_eq!(
        engine
            .begin(
                grant(),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    drop(first);
    let mut next = begin(&engine);
    let mut abc = &b"abc"[..];
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut abc, None),
                &mut next
            )
            .unwrap()
            .bytes_in,
        3
    );
}

#[test]
fn aggregate_reservations_are_checked_and_released() {
    let limits = ResourceLimits {
        max_in_flight: 2,
        memory_bytes: 9,
        temp_bytes: 7,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let a =
        Engine::new(EngineServices::hash_only(limits.clone()).with_shared_budget(budget.clone()))
            .unwrap();
    let b = Engine::new(EngineServices::hash_only(limits).with_shared_budget(budget)).unwrap();
    let mut ca = begin(&a);
    let mut cb = begin(&b);
    let ma = ca.resources().reserve_memory(6).unwrap();
    assert!(matches!(
        cb.resources().reserve_memory(4),
        Err(ProcessingError::MemoryLimit)
    ));
    let mb = cb.resources().reserve_memory(3).unwrap();
    assert!(matches!(
        ca.resources().reserve_memory(u64::MAX),
        Err(ProcessingError::MemoryLimit)
    ));
    let ta = ca.resources().reserve_temp(5).unwrap();
    assert!(matches!(
        cb.resources().reserve_temp(3),
        Err(ProcessingError::TempLimit)
    ));
    let tb = cb.resources().reserve_temp(2).unwrap();
    drop((ma, mb, ta, tb));
    let _all_memory = cb.resources().reserve_memory(9).unwrap();
    let _all_temp = ca.resources().reserve_temp(7).unwrap();
}

#[test]
fn deadline_before_read_and_release_after_worker() {
    let engine = engine(ResourceLimits {
        max_in_flight: 1,
        ..ResourceLimits::default()
    });
    let ctx = begin(&engine);
    let worker = ctx.lease();
    drop(ctx);
    assert_eq!(
        engine
            .begin(
                grant(),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    drop(worker);
    let ctx = begin(&engine);
    drop(ctx);

    let short = engine_with_short_deadline();
    let mut ctx = begin(&short);
    while !ctx.deadline().is_expired() {
        std::thread::yield_now();
    }
    let consumed = Arc::new(AtomicUsize::new(0));
    let mut reader = CountingReader {
        remaining: b"abc",
        read: consumed.clone(),
        chunk: 1,
    };
    let err = short
        .hash(
            HashAlg::Sha256,
            Source::sequential(&mut reader, None),
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
    assert_eq!(consumed.load(Ordering::SeqCst), 0);
}
fn engine_with_short_deadline() -> Engine {
    engine(ResourceLimits {
        operation_timeout: Duration::from_millis(20),
        ..ResourceLimits::default()
    })
}

#[test]
fn reservations_retain_operation_after_context_drop() {
    let engine = engine(ResourceLimits {
        max_in_flight: 1,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let reservation = ctx.resources().reserve_temp(1).unwrap();
    drop(ctx);
    assert_eq!(
        engine
            .begin(
                grant(),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    drop(reservation);
    let _next = begin(&engine);
}

#[test]
fn unknown_length_limit_and_cancel() {
    let engine = engine(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let mut input = &b"abcd"[..];
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut input, None),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InputLimit
    );
    drop(ctx);
    let control = Arc::new(Control::default());
    control.cancelled.store(true, Ordering::SeqCst);
    let mut ctx = engine
        .begin(grant(), OperationPolicy::strict_online(), control)
        .unwrap();
    let consumed = Arc::new(AtomicUsize::new(0));
    let mut input = CountingReader {
        remaining: b"abc",
        read: consumed.clone(),
        chunk: 1,
    };
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut input, None),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::Cancelled
    );
    assert_eq!(consumed.load(Ordering::SeqCst), 0);
}

struct CancelOnRead {
    control: Arc<Control>,
    consumed: Arc<AtomicUsize>,
}
impl Read for CancelOnRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        out[0] = b'a';
        self.consumed.fetch_add(1, Ordering::SeqCst);
        self.control.cancelled.store(true, Ordering::SeqCst);
        Ok(1)
    }
}
#[test]
fn cancellation_between_chunks_stops_reading() {
    let engine = engine(ResourceLimits::default());
    let control = Arc::new(Control::default());
    let mut ctx = engine
        .begin(grant(), OperationPolicy::strict_online(), control.clone())
        .unwrap();
    let consumed = Arc::new(AtomicUsize::new(0));
    let mut input = CancelOnRead {
        control,
        consumed: consumed.clone(),
    };
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut input, None),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::Cancelled
    );
    assert_eq!(consumed.load(Ordering::SeqCst), 1);
}

#[test]
fn sha256_is_independent_of_read_boundaries() {
    let engine = engine(ResourceLimits::default());
    for chunk in [1, 2, 3] {
        let mut ctx = begin(&engine);
        let mut input = CountingReader {
            remaining: b"abc",
            read: Arc::new(AtomicUsize::new(0)),
            chunk,
        };
        let report = engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut input, Some(3)),
                &mut ctx,
            )
            .unwrap();
        assert_eq!(report.bytes_in, 3);
        assert_eq!(
            hex(report.digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

#[test]
fn gost_known_vectors_incrementally() {
    for (data, expected) in [
        (
            &b"This is message, length=32 bytes"[..],
            "b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa",
        ),
        (
            &b""[..],
            "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",
        ),
    ] {
        for chunk in [1, 2, 3] {
            let mut state = HashState::new(HashAlg::Gost34311);
            for part in data.chunks(chunk) {
                state.update(part);
            }
            assert_eq!(hex(state.finish().as_bytes()), expected);
        }
    }
}

#[test]
fn missing_hash_authority_reads_no_input() {
    let engine = engine(ResourceLimits::default());
    let result = engine.begin(
        ExecutionGrant::new([]),
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    if let Ok(mut ctx) = result {
        let consumed = Arc::new(AtomicUsize::new(0));
        let mut reader = CountingReader {
            remaining: b"abc",
            read: consumed.clone(),
            chunk: 1,
        };
        assert_eq!(
            engine
                .hash(
                    HashAlg::Sha256,
                    Source::sequential(&mut reader, None),
                    &mut ctx
                )
                .unwrap_err()
                .code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(consumed.load(Ordering::SeqCst), 0);
    } else {
        assert_eq!(result.unwrap_err().code(), ErrorCode::PermissionDenied);
    }
}

#[test]
fn staging_never_publishes_on_drop_or_clobbers_destination() {
    let dir = tempfile::tempdir().unwrap();
    let foreign = dir.path().join("foreign");
    std::fs::write(&foreign, b"keep").unwrap();
    let destination = dir.path().join("result");
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    {
        let store = TemporaryStore::new(dir.path()).unwrap();
        let mut artifact = store.stage(ctx.resources()).unwrap();
        artifact.write_chunk(b"unfinished").unwrap();
        drop(artifact);
        assert!(!destination.exists());
        std::fs::write(&destination, b"original").unwrap();
        let mut artifact = store.stage(ctx.resources()).unwrap();
        artifact.write_chunk(b"replacement").unwrap();
        assert!(artifact.commit(&destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
    }
    assert!(foreign.exists());
    assert_eq!(std::fs::read(&foreign).unwrap(), b"keep");
}

#[test]
fn staging_quota_is_reserved_before_write_and_released_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits {
        temp_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"abc").unwrap();
    assert!(matches!(
        artifact.write_chunk(b"d"),
        Err(ProcessingError::TempLimit)
    ));
    let destination = dir.path().join("result");
    drop(artifact);
    assert!(!destination.exists());
    let mut clean = store.stage(ctx.resources()).unwrap();
    clean.write_chunk(b"xyz").unwrap();
    clean.commit(&destination).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"xyz");
}

#[test]
fn zero_timeout_is_rejected() {
    let result = Engine::new(EngineServices::hash_only(ResourceLimits {
        operation_timeout: Duration::ZERO,
        ..ResourceLimits::default()
    }));
    assert_eq!(result.unwrap_err().code(), ErrorCode::InvalidInput);
}

/// Catches a growing read buffer on a document larger than the memory budget.
#[test]
fn large_source_uses_bounded_read_chunks() {
    struct Repeated {
        remaining: usize,
        max_request: usize,
    }
    impl Read for Repeated {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.max_request = self.max_request.max(out.len());
            assert!(out.len() <= 256 * 1024, "unbounded streaming read buffer");
            let n = self.remaining.min(out.len());
            out[..n].fill(b'a');
            self.remaining -= n;
            Ok(n)
        }
    }
    let engine = engine(ResourceLimits {
        memory_bytes: 256 * 1024,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let mut input = Repeated {
        remaining: 3 * 1024 * 1024 + 17,
        max_request: 0,
    };
    let report = engine
        .hash(
            HashAlg::Sha256,
            Source::sequential(&mut input, None),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.bytes_in, 3 * 1024 * 1024 + 17);
    // Independently calculated with Python hashlib, not the production digest helper.
    assert_eq!(
        hex(report.digest.as_bytes()),
        "8cb91458835f2fefeb12cf01e67a7ea18523a0567d4835a974dc04c2ddbb955b"
    );
    assert_eq!(input.remaining, 0);
    assert!(input.max_request <= 256 * 1024);
}

#[test]
fn cleanup_does_not_follow_external_directory_link() {
    let parent = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let marker = outside.path().join("must-survive");
    std::fs::write(&marker, b"external data").unwrap();
    let link = parent.path().join("external-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    #[cfg(windows)]
    match std::os::windows::fs::symlink_dir(outside.path(), &link) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(1314) => {
            eprintln!("SKIP cleanup link case: Windows symlink privilege unavailable (1314)");
            return;
        }
        Err(error) => panic!("creating test directory symlink: {error}"),
    }
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    {
        let store = TemporaryStore::new(parent.path()).unwrap();
        let mut artifact = store.stage(ctx.resources()).unwrap();
        artifact.write_chunk(b"owned scratch").unwrap();
    }
    assert_eq!(std::fs::read(&marker).unwrap(), b"external data");
    assert!(link.exists());
}

#[test]
fn shared_views_aggregate_quotas_and_retain_last_admission() {
    let limits = ResourceLimits {
        memory_bytes: 9,
        temp_bytes: 7,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let scope = budget
        .begin(limits.clone(), Arc::new(Control::default()))
        .unwrap();
    let a = scope.shared_view();
    let b = a.shared_view();
    let memory = scope.reserve_memory(6).unwrap();
    assert!(matches!(
        a.reserve_memory(4),
        Err(ProcessingError::MemoryLimit)
    ));
    let temp = a.reserve_temp(5).unwrap();
    assert!(matches!(b.reserve_temp(3), Err(ProcessingError::TempLimit)));
    drop(scope);
    drop(a);
    drop(memory);
    drop(temp);
    assert!(
        budget
            .begin(limits.clone(), Arc::new(Control::default()))
            .is_err()
    );
    drop(b);
    assert!(budget.begin(limits, Arc::new(Control::default())).is_ok());
}

#[test]
fn shared_views_keep_input_terminal_cancel_and_original_deadline() {
    let limits = ResourceLimits {
        input_bytes: 2,
        ..ResourceLimits::default()
    };
    let control = Arc::new(Control::default());
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let scope = budget.begin(limits, control.clone()).unwrap();
    let mut view = scope.shared_view();
    assert!(
        oncl_pki::digest::hash_source(
            Source::sequential(&mut &b"abc"[..], None),
            HashAlg::Sha256,
            &mut view
        )
        .is_err()
    );
    assert_eq!(scope.progress().bytes_in, 3);
    let mut other = scope.shared_view();
    assert!(
        oncl_pki::digest::hash_source(
            Source::sequential(&mut &b""[..], None),
            HashAlg::Sha256,
            &mut other
        )
        .is_err()
    );
    control.cancelled.store(true, Ordering::SeqCst);
    assert!(matches!(view.checkpoint(), Err(ProcessingError::Cancelled)));
    let limits = ResourceLimits {
        operation_timeout: Duration::from_millis(20),
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let scope = budget.begin(limits, Arc::new(Control::default())).unwrap();
    std::thread::sleep(Duration::from_millis(25));
    let view = scope.shared_view();
    assert!(matches!(
        view.checkpoint(),
        Err(ProcessingError::DeadlineExceeded)
    ));
}
