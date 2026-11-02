//! Additional F01 boundary/security cases; controller owns execution.
use oncl_core::{Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationPolicy};
use oncl_pki::resource::{
    OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget,
};
use oncl_pki::{
    digest::HashState,
    io::{Region, Source, TemporaryStore},
    key::HashAlg,
};
use std::{
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
fn begin(engine: &Engine) -> oncl_core::OperationContext {
    engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap()
}
fn engine(limits: ResourceLimits) -> Engine {
    Engine::new(EngineServices::hash_only(limits)).unwrap()
}

#[test]
fn larger_shared_budget_does_not_enlarge_scope_limits() {
    let shared = Arc::new(SharedBudget::new(ResourceLimits::default()).unwrap());
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits {
            memory_bytes: 4,
            temp_bytes: 2,
            metadata_bytes: 1,
            ..ResourceLimits::default()
        })
        .with_shared_budget(shared),
    )
    .unwrap();
    let mut ctx = begin(&engine);
    assert!(matches!(
        ctx.resources().reserve_memory(5),
        Err(ProcessingError::MemoryLimit)
    ));
    assert!(matches!(
        ctx.resources().reserve_temp(3),
        Err(ProcessingError::TempLimit)
    ));
    assert!(matches!(
        ctx.resources().reserve_metadata(2),
        Err(ProcessingError::MetadataLimit)
    ));
    let _memory = ctx.resources().reserve_memory(3).unwrap();
    let _temp = ctx.resources().reserve_temp(2).unwrap();
    let _metadata = ctx.resources().reserve_metadata(1).unwrap();
    assert!(matches!(
        ctx.resources().reserve_memory(1),
        Err(ProcessingError::MemoryLimit)
    ));
}

#[test]
fn failed_growth_and_overrelease_do_not_corrupt_reservations() {
    let engine = engine(ResourceLimits {
        memory_bytes: u64::MAX,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let mut reservation = ctx.resources().reserve_memory(u64::MAX).unwrap();
    assert!(matches!(
        reservation.grow(1),
        Err(ProcessingError::MemoryLimit)
    ));
    assert_eq!(reservation.bytes(), u64::MAX);
    reservation.shrink(u64::MAX).unwrap();
    assert!(matches!(
        reservation.shrink(1),
        Err(ProcessingError::MemoryLimit)
    ));
    let _all = ctx.resources().reserve_memory(u64::MAX).unwrap();
}

#[test]
fn metadata_is_live_globally_and_released_after_context_drop() {
    let limits = ResourceLimits {
        max_in_flight: 2,
        metadata_bytes: 3,
        ..ResourceLimits::default()
    };
    let engine = engine(limits);
    let mut a = begin(&engine);
    let mut b = begin(&engine);
    let reservation = a.resources().reserve_metadata(3).unwrap();
    drop(a);
    assert!(matches!(
        b.resources().reserve_metadata(1),
        Err(ProcessingError::MetadataLimit)
    ));
    drop(reservation);
    let _all = b.resources().reserve_metadata(3).unwrap();
}

#[test]
fn cumulative_byte_categories_have_independent_checked_limits() {
    let engine = engine(ResourceLimits {
        input_bytes: 3,
        container_bytes: 2,
        framing_bytes: 1,
        output_bytes: 4,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let scope = ctx.resources();
    scope.account_input(3).unwrap();
    scope.account_container(2).unwrap();
    scope.account_framing(1).unwrap();
    scope.account_output(4).unwrap();
    assert!(matches!(
        scope.account_input(1),
        Err(ProcessingError::InputLimit)
    ));
    assert!(matches!(
        scope.account_container(u64::MAX),
        Err(ProcessingError::ContainerLimit)
    ));
    assert!(matches!(
        scope.account_framing(u64::MAX),
        Err(ProcessingError::FramingLimit)
    ));
    assert!(matches!(
        scope.account_output(u64::MAX),
        Err(ProcessingError::OutputLimit)
    ));
    assert_eq!(
        scope.progress(),
        Progress {
            bytes_in: 3,
            bytes_out: 4
        }
    );
}

#[test]
fn exact_limit_succeeds_and_known_oversize_reads_nothing() {
    struct RefuseRead;
    impl Read for RefuseRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("oversize hint must be rejected before reading")
        }
    }
    let engine = engine(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let mut reader = RefuseRead;
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut reader, Some(4)),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InputLimit
    );
    let mut abc = &b"abc"[..];
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut abc, None),
                &mut ctx
            )
            .unwrap()
            .bytes_in,
        3
    );
}

#[test]
fn output_rejection_leaves_temporary_capacity_available() {
    let parent = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits {
        temp_bytes: 3,
        output_bytes: 2,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    assert!(matches!(
        artifact.write_chunk(b"abc"),
        Err(ProcessingError::OutputLimit)
    ));
    assert_eq!(artifact.len(), 0);
    let _all_temp = ctx.resources().reserve_temp(3).unwrap();
}

#[test]
fn artifact_retains_admission_after_store_and_context_drop() {
    let parent = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"complete").unwrap();
    drop((store, ctx));
    assert_eq!(
        engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    let destination = parent.path().join("published");
    artifact.commit(&destination).unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), b"complete");
    let _next = begin(&engine);
}

#[test]
fn cancelled_artifact_cannot_publish() {
    let parent = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits::default());
    let control = Arc::new(Control::default());
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            control.clone(),
        )
        .unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"complete").unwrap();
    control.0.store(true, Ordering::SeqCst);
    let destination = parent.path().join("must-not-publish");
    assert!(matches!(
        artifact.commit(&destination),
        Err(ProcessingError::Cancelled)
    ));
    assert!(!destination.exists());
}

#[test]
fn copy_to_streams_explicitly_without_double_charging_output() {
    let parent = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits {
        output_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"abc").unwrap();
    let mut destination = Vec::new();
    assert_eq!(artifact.copy_to(&mut destination).unwrap(), 3);
    assert_eq!(destination, b"abc");
    assert_eq!(ctx.resources().progress().bytes_out, 3);
}

#[test]
fn other_engine_cannot_use_context_even_with_shared_budget() {
    let limits = ResourceLimits {
        max_in_flight: 2,
        ..ResourceLimits::default()
    };
    let shared = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let a =
        Engine::new(EngineServices::hash_only(limits.clone()).with_shared_budget(shared.clone()))
            .unwrap();
    let b = Engine::new(EngineServices::hash_only(limits).with_shared_budget(shared)).unwrap();
    let mut ctx = begin(&a);
    let mut input = &b"abc"[..];
    assert_eq!(
        b.hash(
            HashAlg::Sha256,
            Source::sequential(&mut input, None),
            &mut ctx
        )
        .unwrap_err()
        .code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(input, b"abc");
}

#[test]
fn regions_reject_overflow() {
    assert_eq!(Region { offset: 4, len: 3 }.end().unwrap(), 7);
    assert!(matches!(
        Region {
            offset: u64::MAX,
            len: 1
        }
        .end(),
        Err(ProcessingError::InvalidInput(_))
    ));
}

#[test]
fn independent_vectors_cover_dispatch_and_chunk_boundaries() {
    // Independent complete byte-oriented vectors:
    // https://github.com/torvalds/linux/blob/master/crypto/testmgr.h
    // sha1_tv_template / sha512_tv_template ("abc", NIST vectors), and
    // streebog256_tv_template / streebog512_tv_template (M1/M2 from RFC 6986
    // sections 10.1/10.2, https://www.rfc-editor.org/rfc/rfc6986).
    // The kernel's literals specify input/output byte order directly. Expected
    // values below are literals, never computed by the implementation under test.
    // Exact SHA256 and D-TEST vectors already live in unchanged io_limits tests.
    const M1: &[u8] = b"012345678901234567890123456789012345678901234567890123456789012";
    const M2: &[u8] = b"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb";
    let vectors: &[(HashAlg, &[u8], &[u8])] = &[
        (HashAlg::Sha1, b"abc", b"\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d"),
        (HashAlg::Sha512, b"abc", b"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f"),
        (HashAlg::Streebog256, M1, b"\x9d\x15\x1e\xef\xd8\x59\x0b\x89\xda\xa6\xba\x6c\xb7\x4a\xf9\x27\x5d\xd0\x51\x02\x6b\xb1\x49\xa4\x52\xfd\x84\xe5\xe5\x7b\x55\x00"),
        (HashAlg::Streebog512, M1, b"\x1b\x54\xd0\x1a\x4a\xf5\xb9\xd5\xcc\x3d\x86\xd6\x8d\x28\x54\x62\xb1\x9a\xbc\x24\x75\x22\x2f\x35\xc0\x85\x12\x2b\xe4\xba\x1f\xfa\x00\xad\x30\xf8\x76\x7b\x3a\x82\x38\x4c\x65\x74\xf0\x24\xc3\x11\xe2\xa4\x81\x33\x2b\x08\xef\x7f\x41\x79\x78\x91\xc1\x64\x6f\x48"),
        (HashAlg::Streebog256, M2, b"\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d\xa8\x7f\x53\x97\x6d\x74\x05\xb0\xc0\xca\xc6\x28\xfc\x66\x9a\x74\x1d\x50\x06\x3c\x55\x7e\x8f\x50"),
        (HashAlg::Streebog512, M2, b"\x1e\x88\xe6\x22\x26\xbf\xca\x6f\x99\x94\xf1\xf2\xd5\x15\x69\xe0\xda\xf8\x47\x5a\x3b\x0f\xe6\x1a\x53\x00\xee\xe4\x6d\x96\x13\x76\x03\x5f\xe8\x35\x49\xad\xa2\xb8\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3\x3f\x0c\xb9\xdd\xdc\x2b\x64\x60\x14\x3b\x03\xda\xba\xc9\xfb\x28"),
    ];
    struct Chunked<'a> {
        remaining: &'a [u8],
        chunk: usize,
    }
    impl Read for Chunked<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.remaining.len().min(self.chunk).min(out.len());
            out[..n].copy_from_slice(&self.remaining[..n]);
            self.remaining = &self.remaining[n..];
            Ok(n)
        }
    }
    let engine = engine(ResourceLimits::default());
    for &(algorithm, data, expected) in vectors {
        assert_eq!(algorithm.digest(data).as_slice(), expected);
        for chunk in [1, 2, 3, 31, 63, 64, 65] {
            let mut state = HashState::new(algorithm);
            for part in data.chunks(chunk) {
                state.update(part);
            }
            let value = state.finish();
            assert_eq!(value.algorithm(), algorithm);
            assert_eq!(value.as_bytes(), expected);
            let mut ctx = begin(&engine);
            let mut input = Chunked {
                remaining: data,
                chunk,
            };
            let report = engine
                .hash(
                    algorithm,
                    Source::sequential(&mut input, Some(data.len() as u64)),
                    &mut ctx,
                )
                .unwrap();
            assert_eq!(report.digest.as_bytes(), expected);
            assert_eq!(report.bytes_in, data.len() as u64);
        }
    }
}

#[cfg(unix)]
#[test]
fn staged_and_published_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"private document").unwrap();
    let root = std::fs::read_dir(parent.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let destination = parent.path().join("private-result");
    artifact.commit(&destination).unwrap();
    assert_eq!(
        std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(store);
    assert!(!root.exists());
}

#[test]
fn parallel_reservations_share_one_atomic_capacity() {
    let engine = Arc::new(engine(ResourceLimits {
        max_in_flight: 8,
        memory_bytes: 7,
        ..ResourceLimits::default()
    }));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let engine = engine.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let mut ctx = begin(&engine);
            barrier.wait();
            let reservation = ctx.resources().reserve_memory(1);
            let success = reservation.is_ok();
            // No successful reservation is freed until all eight attempts finish.
            barrier.wait();
            drop(reservation);
            success
        }));
    }
    let successes = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 7);
    let mut ctx = begin(&engine);
    let _all_memory = ctx.resources().reserve_memory(7).unwrap();
}

#[test]
fn cleanup_preserves_unowned_file_even_inside_private_root() {
    let parent = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"owned").unwrap();
    let root = std::fs::read_dir(parent.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let foreign = root.join("not-an-owned-lease");
    std::fs::write(&foreign, b"preserve").unwrap();
    drop((artifact, store));
    assert_eq!(std::fs::read(foreign).unwrap(), b"preserve");
}

#[test]
fn oversized_consumed_input_cannot_reuse_context_allowance() {
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("over-limit intake must not read again");
        }
    }
    let engine = engine(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut ctx = begin(&engine);
    let mut oversized = &b"abcd"[..];
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut oversized, None),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InputLimit
    );
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut MustNotRead, None),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InputLimit
    );
}

#[test]
fn cancelled_read_still_consumes_input_allowance() {
    struct CancellingRead(Arc<Control>);
    impl Read for CancellingRead {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            out[..2].copy_from_slice(b"ab");
            self.0.0.store(true, Ordering::SeqCst);
            Ok(2)
        }
    }
    let engine = engine(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let control = Arc::new(Control::default());
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            control.clone(),
        )
        .unwrap();
    let mut reader = CancellingRead(control.clone());
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut reader, None),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::Cancelled
    );
    control.0.store(false, Ordering::SeqCst);
    assert_eq!(ctx.resources().progress().bytes_in, 2);
    let mut more = &b"cd"[..];
    assert_eq!(
        engine
            .hash(
                HashAlg::Sha256,
                Source::sequential(&mut more, None),
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::InputLimit
    );
}

#[test]
fn root_cleanup_preserves_foreign_name_replacement() {
    let parent = tempfile::tempdir().unwrap();
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"owned").unwrap();
    let root = std::fs::read_dir(parent.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let moved = parent.path().join("moved-owned-root");
    match std::fs::rename(&root, &moved) {
        Ok(()) => {
            std::fs::create_dir(&root).unwrap();
            drop((artifact, store));
            assert!(
                root.is_dir(),
                "cleanup deleted an unowned replacement directory"
            );
        }
        Err(error) => {
            #[cfg(windows)]
            {
                // Windows may report ACCESS_DENIED (5) or SHARING_VIOLATION (32).
                assert!(
                    matches!(error.raw_os_error(), Some(5 | 32)),
                    "unexpected rename failure: {error}"
                );
                drop((artifact, store));
                assert!(!root.exists(), "normal owned-root cleanup failed");
            }
            #[cfg(not(windows))]
            panic!("unexpected inability to rename test root: {error}");
        }
    }
}

#[cfg(unix)]
#[test]
fn nonsticky_foreign_writable_parent_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        TemporaryStore::new(parent.path()).is_err(),
        "untrusted parent permits another identity to replace root names"
    );
}

#[cfg(windows)]
#[test]
fn ancestor_replacement_cannot_redirect_staged_paths() {
    let sandbox = tempfile::tempdir().unwrap();
    let parent = sandbox.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(&parent).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"owned document").unwrap();
    let root = std::fs::read_dir(&parent)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let owned_file = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    let moved = sandbox.path().join("moved-parent");
    match std::fs::rename(&parent, &moved) {
        Err(error) => {
            assert!(
                matches!(error.raw_os_error(), Some(5 | 32)),
                "unexpected ancestor rename failure: {error}"
            );
            drop((artifact, store));
            assert!(!root.exists());
        }
        Ok(()) => {
            std::fs::create_dir(&parent).unwrap();
            let replacement_root = parent.join(root.file_name().unwrap());
            std::fs::create_dir(&replacement_root).unwrap();
            let foreign = replacement_root.join(owned_file);
            std::fs::write(&foreign, b"foreign document").unwrap();
            let published = sandbox.path().join("published");
            let result = artifact.commit(&published);
            drop(store);
            if result.is_ok() {
                assert_eq!(
                    std::fs::read(&published).unwrap(),
                    b"owned document",
                    "publication followed a substituted ancestor"
                );
            }
            assert_eq!(
                std::fs::read(&foreign).unwrap(),
                b"foreign document",
                "cleanup deleted substituted foreign file"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn sticky_foreign_writable_parent_protects_owned_store_entries() {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
    let foreign = parent.path().join("foreign");
    std::fs::write(&foreign, b"preserve").unwrap();
    let engine = engine(ResourceLimits::default());
    let mut ctx = begin(&engine);
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    artifact.write_chunk(b"owned").unwrap();
    drop((artifact, store));
    assert_eq!(std::fs::read(&foreign).unwrap(), b"preserve");
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
}
