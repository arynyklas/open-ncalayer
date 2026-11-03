use oncl_pki::{
    io::{FrozenInput, Region, SnapshotEncoding, Source, TemporaryStore},
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{
    io::{Cursor, Read},
    sync::Arc,
};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope(limits: ResourceLimits) -> ResourceScope {
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
#[test]
fn captured_bytes_are_immutable_and_intake_charged_once() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 6,
        ..ResourceLimits::default()
    });
    let mut source = Cursor::new(b"prefixabcdef".to_vec());
    source.set_position(6);
    let mut frozen =
        FrozenInput::capture(Source::seekable(&mut source, Some(1)), &store, &mut scope).unwrap();
    source.get_mut()[6..].fill(b'X');
    assert_eq!(scope.progress().bytes_in, 6);
    let mut view = frozen
        .reader(
            &[Region { offset: 1, len: 2 }, Region { offset: 5, len: 1 }],
            &scope,
        )
        .unwrap();
    let mut got = Vec::new();
    view.read_to_end(&mut got).unwrap();
    view.finish().unwrap();
    assert_eq!(got, b"bcf");
    assert_eq!(scope.progress().bytes_in, 6);
    drop(view);
    let mut other = super_scope();
    assert!(matches!(
        frozen.reader(&[Region { offset: 0, len: 1 }], &other),
        Err(ProcessingError::InvalidInput(_))
    ));
    assert!(
        frozen
            .reader(
                &[Region {
                    offset: u64::MAX,
                    len: 1
                }],
                &scope
            )
            .is_err()
    );
    let derived = frozen
        .derive_region(
            Region { offset: 0, len: 3 },
            &scope,
            SnapshotEncoding::Identity,
        )
        .unwrap();
    assert_eq!(derived.as_bytes(), b"abc");
    assert!(
        frozen
            .derive_region(
                Region { offset: 0, len: 1 },
                &scope,
                SnapshotEncoding::PdfByteString
            )
            .is_err()
    );
    let _ = &mut other;
}
fn super_scope() -> ResourceScope {
    scope(ResourceLimits::default())
}
#[test]
fn sequential_capture_counts_actual_limit_plus_one() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut source = Cursor::new(b"abcdef");
    assert!(matches!(
        FrozenInput::capture(Source::sequential(&mut source, Some(1)), &store, &mut scope),
        Err(ProcessingError::InputLimit)
    ));
    assert_eq!(scope.progress().bytes_in, 4);
}

#[test]
fn derived_metadata_cannot_bind_another_snapshot_in_the_same_operation() {
    use oncl_pki::{
        http::{HttpError, HttpReply, HttpRequest, HttpTransport},
        pkix::CaSet,
        validation::{ValidationContext, ValidationPolicy},
    };
    struct Offline;
    impl HttpTransport for Offline {
        fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
            panic!("unexpected network")
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits::default());
    let mut first = Cursor::new(b"abc");
    let mut second = Cursor::new(b"abc");
    let mut one =
        FrozenInput::capture(Source::sequential(&mut first, None), &store, &mut scope).unwrap();
    let mut two =
        FrozenInput::capture(Source::sequential(&mut second, None), &store, &mut scope).unwrap();
    let metadata = one
        .derive_region(
            Region { offset: 0, len: 3 },
            &scope,
            SnapshotEncoding::Identity,
        )
        .unwrap();
    let anchors = CaSet::new(vec![]);
    let validation = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::UNIX_EPOCH,
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    assert!(matches!(
        oncl_pki::cms::stream::verify_snapshot_detached(
            &metadata,
            &mut two,
            &[Region { offset: 0, len: 3 }],
            &validation,
            &[],
            &mut scope
        ),
        Err(oncl_pki::cms::stream::StreamError::Processing(
            ProcessingError::InvalidInput("derived metadata belongs to another snapshot")
        ))
    ));
    for regions in [
        vec![Region { offset: 0, len: 0 }],
        vec![Region { offset: 0, len: 2 }, Region { offset: 1, len: 1 }],
        vec![Region {
            offset: u64::MAX,
            len: 2,
        }],
    ] {
        assert!(
            oncl_pki::cms::stream::verify_snapshot_detached(
                &metadata,
                &mut one,
                &regions,
                &validation,
                &[],
                &mut scope
            )
            .is_err()
        );
    }
}

#[test]
fn metadata_derivation_cannot_inject_unrelated_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits::default());
    let mut source = Cursor::new(b"<4142>");
    let mut frozen =
        FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope).unwrap();
    let derived = frozen
        .derive_region(
            Region { offset: 0, len: 6 },
            &scope,
            SnapshotEncoding::PdfByteString,
        )
        .unwrap();
    assert_eq!(derived.as_bytes(), b"AB");
}

#[test]
fn authentic_source_recapture_preserves_exact_original_input_quota() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut source = Cursor::new(b"abc");
    let mut original =
        FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope).unwrap();
    let mut reader = original
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    let mut recaptured = FrozenInput::capture(reader.source(), &store, &mut scope).unwrap();
    reader.finish().unwrap();
    assert_eq!(scope.progress().bytes_in, 3);
    let mut replay = recaptured
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    let mut bytes = Vec::new();
    replay.read_to_end(&mut bytes).unwrap();
    replay.finish().unwrap();
    assert_eq!(bytes, b"abc");
}

#[test]
fn foreign_snapshot_capture_fails_before_original_read() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Armed(Arc<AtomicBool>);
    impl OperationControl for Armed {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            assert!(
                !self.0.load(Ordering::SeqCst),
                "foreign capture touched original reader"
            );
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let limits = ResourceLimits::default();
    let armed = Arc::new(AtomicBool::new(false));
    let mut original_scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Armed(armed.clone())))
        .unwrap();
    let mut bytes = Cursor::new(b"abc");
    let mut original = FrozenInput::capture(
        Source::sequential(&mut bytes, None),
        &store,
        &mut original_scope,
    )
    .unwrap();
    let mut reader = original
        .reader(&[Region { offset: 0, len: 3 }], &original_scope)
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    let mut foreign = scope(ResourceLimits::default());
    assert!(matches!(
        FrozenInput::capture(reader.source(), &store, &mut foreign),
        Err(ProcessingError::InvalidInput(
            "snapshot belongs to another operation"
        ))
    ));
}

#[test]
fn closed_byte_string_codecs_preserve_real_pdf_semantics_and_provenance() {
    for (encoded, expected) in [
        (b"<41 4>".as_slice(), b"A@".as_slice()),
        (b"(A\\102)".as_slice(), b"AB".as_slice()),
        (b"(a(b)c)".as_slice(), b"a(b)c".as_slice()),
        (b"(a\\\r\nb\r\nc)".as_slice(), b"ab\nc".as_slice()),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut scope = scope(ResourceLimits::default());
        let mut source = Cursor::new(encoded);
        let mut snapshot =
            FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope)
                .unwrap();
        let region = Region {
            offset: 0,
            len: encoded.len() as u64,
        };
        let decoded = snapshot
            .derive_region(region, &scope, SnapshotEncoding::PdfByteString)
            .unwrap();
        assert_eq!(decoded.as_bytes(), expected);
        assert_eq!(decoded.region(), region);
        assert_eq!(decoded.encoding(), SnapshotEncoding::PdfByteString);
    }
    for encoded in [
        b"<GG>".as_slice(),
        b"(unterminated".as_slice(),
        b"<41>garbage".as_slice(),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut scope = scope(ResourceLimits::default());
        let mut source = Cursor::new(encoded);
        let mut snapshot =
            FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope)
                .unwrap();
        assert!(matches!(
            snapshot.derive_region(
                Region {
                    offset: 0,
                    len: encoded.len() as u64
                },
                &scope,
                SnapshotEncoding::PdfByteString
            ),
            Err(ProcessingError::InvalidInput(_))
        ));
    }
}

#[test]
fn derived_storage_and_container_limits_are_admitted_before_closed_decode() {
    for (limits, metadata) in [
        (
            ResourceLimits {
                metadata_bytes: 2000,
                ..ResourceLimits::default()
            },
            true,
        ),
        (
            ResourceLimits {
                container_bytes: 3,
                ..ResourceLimits::default()
            },
            false,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(temp.path()).unwrap();
        let mut scope = scope(limits);
        let mut source = Cursor::new(vec![b'0'; 4096]);
        let mut snapshot =
            FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope)
                .unwrap();
        let result = snapshot.derive_region(
            Region {
                offset: 0,
                len: 4096,
            },
            &scope,
            SnapshotEncoding::PdfByteString,
        );
        if metadata {
            assert!(matches!(result, Err(ProcessingError::MetadataLimit)));
        } else {
            assert!(matches!(result, Err(ProcessingError::ContainerLimit)));
        }
    }
}

#[test]
fn snapshot_copies_reuse_live_disk_quota_and_keep_original_deadline() {
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 3,
        temp_bytes: 6,
        operation_timeout: Duration::from_secs(1),
        ..ResourceLimits::default()
    });
    let mut bytes = Cursor::new(b"abc");
    let mut snapshot =
        FrozenInput::capture(Source::sequential(&mut bytes, None), &store, &mut scope).unwrap();
    assert!(matches!(
        snapshot.reader(
            &[Region { offset: 0, len: 3 }, Region { offset: 0, len: 3 }],
            &scope
        ),
        Err(ProcessingError::InvalidInput(_))
    ));
    let started = Instant::now();
    let mut completed = 0;
    loop {
        let mut source = match snapshot.reader(&[Region { offset: 0, len: 3 }], &scope) {
            Ok(source) => source,
            Err(ProcessingError::DeadlineExceeded) => break,
            Err(error) => panic!("unexpected source failure: {error}"),
        };
        let copied = match FrozenInput::capture(source.source(), &store, &mut scope) {
            Ok(copied) => copied,
            Err(ProcessingError::DeadlineExceeded) => break,
            Err(error) => panic!("live disk should be reusable: {error}"),
        };
        drop(source);
        // Original N + copied N exhaust the real live 2N disk allowance.
        match scope.reserve_temp(1) {
            Err(ProcessingError::TempLimit) => {}
            Err(ProcessingError::DeadlineExceeded) => break,
            _ => panic!("copy did not retain the real live N-byte reservation"),
        }
        assert_eq!(copied.len(), 3);
        drop(copied);
        // Copy drop releases exactly N, while the original N remains live.
        let available = match scope.reserve_temp(3) {
            Ok(available) => available,
            Err(ProcessingError::DeadlineExceeded) => break,
            Err(error) => panic!("copy drop did not free disk: {error}"),
        };
        drop(available);
        completed += 1;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "recapture reset original deadline"
        );
    }
    assert!(
        completed >= 3,
        "expected repeated real copy/drop reuse before deadline"
    );
    assert_eq!(scope.progress().bytes_in, 3);
}

#[test]
fn recapture_keeps_original_cancellation_after_successful_copy_drop() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Cancel(Arc<AtomicBool>);
    impl OperationControl for Cancel {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let limits = ResourceLimits {
        input_bytes: 3,
        temp_bytes: 6,
        ..ResourceLimits::default()
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Cancel(cancelled.clone())))
        .unwrap();
    let mut bytes = Cursor::new(b"abc");
    let mut original =
        FrozenInput::capture(Source::sequential(&mut bytes, None), &store, &mut scope).unwrap();
    let mut source = original
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    let copied = FrozenInput::capture(source.source(), &store, &mut scope).unwrap();
    drop(copied);
    drop(source);
    let mut source = original
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    cancelled.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        assert!(matches!(
            FrozenInput::capture(source.source(), &store, &mut scope),
            Err(ProcessingError::Cancelled)
        ));
    }
    assert_eq!(scope.progress().bytes_in, 3);
}

#[test]
fn authentic_hash_replay_preserves_exact_intake_and_literal_sha256() {
    use oncl_pki::{digest::hash_source, key::HashAlg};
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    });
    let mut input = Cursor::new(b"abc");
    let mut captured =
        FrozenInput::capture(Source::sequential(&mut input, None), &store, &mut scope).unwrap();
    let mut reader = captured
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    let digest = hash_source(reader.source(), HashAlg::Sha256, &mut scope).unwrap();
    reader.finish().unwrap();
    assert_eq!(
        digest.as_bytes(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert_eq!(scope.progress().bytes_in, 3);
}

#[test]
fn hash_replay_rejects_foreign_scope_before_original_read() {
    use oncl_pki::{digest::hash_source, key::HashAlg};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Armed(Arc<AtomicBool>);
    impl OperationControl for Armed {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            assert!(
                !self.0.load(Ordering::SeqCst),
                "foreign hash touched original reader"
            );
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let limits = ResourceLimits::default();
    let armed = Arc::new(AtomicBool::new(false));
    let mut original = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Armed(armed.clone())))
        .unwrap();
    let mut input = Cursor::new(b"abc");
    let mut captured =
        FrozenInput::capture(Source::sequential(&mut input, None), &store, &mut original).unwrap();
    let mut reader = captured
        .reader(&[Region { offset: 0, len: 3 }], &original)
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    let mut foreign = scope(ResourceLimits::default());
    assert!(matches!(
        hash_source(reader.source(), HashAlg::Sha256, &mut foreign),
        Err(ProcessingError::InvalidInput(
            "snapshot belongs to another operation"
        ))
    ));
}

#[test]
fn hash_replay_preserves_one_shot_typed_read_cancellation() {
    use oncl_pki::{digest::hash_source, key::HashAlg};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Once(Arc<AtomicUsize>);
    impl OperationControl for Once {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            let at = self.0.fetch_add(1, Ordering::SeqCst);
            if at == 4 {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let limits = ResourceLimits::default();
    let calls = Arc::new(AtomicUsize::new(100));
    let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Once(calls.clone())))
        .unwrap();
    let mut input = Cursor::new(b"abc");
    let mut captured =
        FrozenInput::capture(Source::sequential(&mut input, None), &store, &mut scope).unwrap();
    let mut reader = captured
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    calls.store(0, Ordering::SeqCst);
    assert!(matches!(
        hash_source(reader.source(), HashAlg::Sha256, &mut scope),
        Err(ProcessingError::Cancelled)
    ));
    reader.finish().unwrap();
}

#[test]
fn original_bound_region_reads_are_chunked_checked_and_hash_compatible() {
    use oncl_pki::{digest::hash_source, key::HashAlg, resource::IO_CHUNK_BYTES};
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits::default());
    let data = vec![0x5a; IO_CHUNK_BYTES + 17];
    let mut source = Cursor::new(data.as_slice());
    let mut frozen =
        FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope).unwrap();
    let mut output = vec![0; data.len()];
    assert_eq!(
        frozen
            .read_region(
                Region {
                    offset: 0,
                    len: data.len() as u64
                },
                &mut output
            )
            .unwrap(),
        IO_CHUNK_BYTES
    );
    assert_eq!(&output[..IO_CHUNK_BYTES], &data[..IO_CHUNK_BYTES]);
    assert!(matches!(
        frozen.read_region(
            Region {
                offset: u64::MAX,
                len: 1
            },
            &mut []
        ),
        Err(ProcessingError::InvalidInput(_))
    ));
    assert!(matches!(
        frozen.read_region(
            Region {
                offset: 0,
                len: data.len() as u64 + 1
            },
            &mut []
        ),
        Err(ProcessingError::InvalidInput(_))
    ));
    let mut source = Cursor::new(b"abc");
    let mut frozen =
        FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope).unwrap();
    let mut part = [0; 2];
    assert_eq!(
        frozen
            .read_region(Region { offset: 1, len: 2 }, &mut part)
            .unwrap(),
        2
    );
    assert_eq!(&part, b"bc");
    let before = scope.progress().bytes_in;
    let mut reader = frozen
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    let digest = hash_source(reader.source(), HashAlg::Sha256, &mut scope).unwrap();
    reader.finish().unwrap();
    assert_eq!(
        digest.as_bytes(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert_eq!(scope.progress().bytes_in, before);
}

#[test]
fn original_bound_region_read_checks_control_even_for_empty_output() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Cancel(Arc<AtomicBool>);
    impl OperationControl for Cancel {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let limits = ResourceLimits::default();
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Cancel(cancelled.clone())))
        .unwrap();
    let mut source = Cursor::new(b"abc");
    let mut frozen =
        FrozenInput::capture(Source::sequential(&mut source, None), &store, &mut scope).unwrap();
    cancelled.store(true, Ordering::SeqCst);
    assert!(matches!(
        frozen.read_region(Region { offset: 0, len: 0 }, &mut []),
        Err(ProcessingError::Cancelled)
    ));
    assert_eq!(scope.progress().bytes_in, 3);
}

#[test]
fn shared_view_keeps_frozen_identity_but_foreign_same_budget_does_not() {
    let limits = ResourceLimits {
        max_in_flight: 2,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut original = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
    let view = original.shared_view();
    let foreign = budget.begin(limits, Arc::new(Control)).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut Cursor::new(b"abc"), None),
        &store,
        &mut original,
    )
    .unwrap();
    let mut reader = frozen
        .reader(&[Region { offset: 0, len: 3 }], &view)
        .unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    reader.finish().unwrap();
    drop(reader);
    assert_eq!(bytes, b"abc");
    assert!(
        frozen
            .reader(&[Region { offset: 0, len: 3 }], &foreign)
            .is_err()
    );
    let mut stage = store.stage(&mut original).unwrap();
    assert!(oncl_pki::io::PdfSignatureOutput::check_output(&stage, &foreign).is_err());
    assert!(oncl_pki::io::PdfSignatureOutput::check_output(&stage, &view).is_ok());
    {
        let mut output = oncl_pki::io::PdfSignatureOutput::new(&mut stage, &view).unwrap();
        output.append(b"registered output").unwrap();
        output.reserve_contents(1024).unwrap();
        // A caller ignoring a framing failure cannot later publish success.
        assert!(output.reserve_contents(1024).is_err());
        assert!(output.append(b"ignored failure").is_err());
    }
    assert!(stage.copy_to(&mut Vec::new()).is_err());
    assert_eq!(original.progress().bytes_in, 3);
}
