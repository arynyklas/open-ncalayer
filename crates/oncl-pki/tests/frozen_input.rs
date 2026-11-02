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
fn repeated_snapshot_copy_work_is_bounded_after_previous_copy_drops() {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut scope = scope(ResourceLimits {
        input_bytes: 3,
        temp_bytes: 6,
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
    let mut source = snapshot
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    let copied = FrozenInput::capture(source.source(), &store, &mut scope).unwrap();
    source.finish().unwrap();
    drop(source);
    drop(copied);
    let mut source = snapshot
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    assert!(matches!(
        FrozenInput::capture(source.source(), &store, &mut scope),
        Err(ProcessingError::TempLimit)
    ));
    assert_eq!(scope.progress().bytes_in, 3);
}
