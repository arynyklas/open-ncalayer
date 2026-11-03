use oncl_pki::{
    io::{FrozenInput, Region, SnapshotEncoding, Source, TemporaryStore, XmlSignatureOutput},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
};
use std::{
    io::Cursor,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
struct Control(Arc<AtomicBool>);
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
#[test]
fn output_capture_never_becomes_original_input_or_double_debits_output() {
    let cap = ResourceLimits {
        input_bytes: 5,
        output_bytes: 8,
        ..Default::default()
    };
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut scope = budget
        .begin(cap, Arc::new(Control(Arc::new(AtomicBool::new(false)))))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let original = FrozenInput::capture(
        Source::sequential(&mut Cursor::new(b"<r/>\n"), None),
        &store,
        &mut scope,
    )
    .unwrap();
    assert_eq!(original.len(), 5);
    let mut stage = store.stage(&mut scope).unwrap();
    let mut transaction = XmlSignatureOutput::new(&mut stage, &scope).unwrap();
    transaction.append(b"<r>x</r>").unwrap();
    let mut capture =
        FrozenInput::capture(transaction.source().unwrap(), &store, &mut scope).unwrap();
    let all = [Region { offset: 0, len: 8 }];
    let mut replay = capture.reader(&all, &scope).unwrap();
    assert!(!replay.source().is_snapshot_for(&scope).unwrap());
    let mut again = FrozenInput::capture(replay.source(), &store, &mut scope).unwrap();
    replay.finish().unwrap();
    let metadata = again
        .derive_region(
            Region { offset: 0, len: 8 },
            &scope,
            SnapshotEncoding::Identity,
        )
        .unwrap();
    assert_eq!(metadata.as_bytes(), b"<r>x</r>");
    let mut reader = again.reader(&all, &scope).unwrap();
    assert!(!reader.source().is_snapshot_for(&scope).unwrap());
    drop(reader);
    assert_eq!(scope.progress().bytes_in, 5);
    assert_eq!(scope.progress().bytes_out, 8);
    transaction.finish(&scope).unwrap();
}
#[test]
fn initial_cancel_and_failed_final_validation_are_sticky_without_poisoning_foreign() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let cap = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut scope = budget
        .begin(cap.clone(), Arc::new(Control(cancelled.clone())))
        .unwrap();
    let mut stage = store.stage(&mut scope).unwrap();
    cancelled.store(true, Ordering::SeqCst);
    assert!(XmlSignatureOutput::new(&mut stage, &scope).is_err());
    cancelled.store(false, Ordering::SeqCst);
    assert!(stage.commit(&dir.path().join("cancelled.xml")).is_err());
    let other_budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut foreign = other_budget
        .begin(cap, Arc::new(Control(Arc::new(AtomicBool::new(false)))))
        .unwrap();
    let mut stage = store.stage(&mut foreign).unwrap();
    assert!(XmlSignatureOutput::new(&mut stage, &scope).is_err());
    stage.write_chunk(b"safe").unwrap();
    stage
        .commit(&dir.path().join("foreign-unpoisoned.xml"))
        .unwrap();
    let mut stage = store.stage(&mut scope).unwrap();
    {
        let mut transaction = XmlSignatureOutput::new(&mut stage, &scope).unwrap();
        transaction.append(b"<r/>").unwrap();
    }
    assert!(stage.commit(&dir.path().join("unvalidated.xml")).is_err());
}

#[test]
fn bounded_capture_counts_n_plus_one_before_cancel_and_keeps_input_terminal() {
    use std::io::Read;
    struct Input {
        bytes: Cursor<&'static [u8]>,
        cancel: Arc<AtomicBool>,
    }
    impl Read for Input {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let n = self.bytes.read(b)?;
            if n != 0 {
                self.cancel.store(true, Ordering::SeqCst);
            }
            Ok(n)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let cap = ResourceLimits {
        input_bytes: 10,
        ..Default::default()
    };
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut scope = budget
        .begin(cap, Arc::new(Control(cancelled.clone())))
        .unwrap();
    let mut exact = FrozenInput::capture_bounded(
        Source::sequential(&mut Cursor::new(b"abc"), None),
        &store,
        &mut scope,
        3,
    )
    .unwrap();
    assert_eq!(scope.progress().bytes_in, 3);
    let mut replay = exact
        .reader(&[Region { offset: 0, len: 3 }], &scope)
        .unwrap();
    let captured = FrozenInput::capture_bounded(replay.source(), &store, &mut scope, 3).unwrap();
    assert_eq!(captured.len(), 3);
    assert_eq!(scope.progress().bytes_in, 3);
    drop(captured);
    drop(replay);
    let error = FrozenInput::capture_bounded(
        Source::sequential(
            &mut Input {
                bytes: Cursor::new(b"abcd"),
                cancel: cancelled.clone(),
            },
            Some(3),
        ),
        &store,
        &mut scope,
        3,
    )
    .err()
    .unwrap();
    assert!(matches!(error, ProcessingError::InputLimit));
    assert_eq!(
        scope.progress().bytes_in,
        7,
        "actual N+1 debit, not a forged resource-cap debit"
    );
    cancelled.store(false, Ordering::SeqCst);
    assert!(matches!(
        FrozenInput::capture(
            Source::sequential(&mut Cursor::new(b""), None),
            &store,
            &mut scope
        ),
        Err(ProcessingError::InputLimit)
    ));
}

#[test]
fn output_derived_recapture_failure_poison_reaches_the_original_output() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let cap = ResourceLimits {
        input_bytes: 0,
        output_bytes: 5,
        ..Default::default()
    };
    let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut scope = budget
        .begin(cap, Arc::new(Control(Arc::new(AtomicBool::new(false)))))
        .unwrap();
    let mut stage = store.stage(&mut scope).unwrap();
    let mut transaction = XmlSignatureOutput::new(&mut stage, &scope).unwrap();
    transaction.append(b"<r/> ").unwrap();
    let mut first =
        FrozenInput::capture_bounded(transaction.source().unwrap(), &store, &mut scope, 5).unwrap();
    let mut reader = first
        .reader(&[Region { offset: 0, len: 5 }], &scope)
        .unwrap();
    let mut second = FrozenInput::capture_bounded(reader.source(), &store, &mut scope, 5).unwrap();
    reader.finish().unwrap();
    drop(reader);
    let metadata = second
        .derive_region(
            Region { offset: 0, len: 5 },
            &scope,
            SnapshotEncoding::Identity,
        )
        .unwrap();
    assert_eq!(metadata.as_bytes(), b"<r/> ");
    let mut reader = second
        .reader(&[Region { offset: 0, len: 5 }], &scope)
        .unwrap();
    assert!(!reader.source().is_snapshot_for(&scope).unwrap());
    assert!(matches!(
        FrozenInput::capture_bounded(reader.source(), &store, &mut scope, 4),
        Err(ProcessingError::OutputLimit)
    ));
    drop(reader);
    assert!(transaction.finish(&scope).is_err());
    assert!(
        stage
            .commit(&dir.path().join("must-not-publish.xml"))
            .is_err()
    );
    assert_eq!(scope.progress().bytes_in, 0);
    assert_eq!(scope.progress().bytes_out, 5);
}

#[test]
fn foreign_output_capture_rejects_before_poisoning_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let cap = ResourceLimits::default();
    let a = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let b = Arc::new(SharedBudget::new(cap.clone()).unwrap());
    let mut owner = a
        .begin(
            cap.clone(),
            Arc::new(Control(Arc::new(AtomicBool::new(false)))),
        )
        .unwrap();
    let mut foreign = b
        .begin(cap, Arc::new(Control(Arc::new(AtomicBool::new(false)))))
        .unwrap();
    let mut stage = store.stage(&mut owner).unwrap();
    let mut transaction = XmlSignatureOutput::new(&mut stage, &owner).unwrap();
    transaction.append(b"<r/>").unwrap();
    assert!(matches!(
        FrozenInput::capture_bounded(transaction.source().unwrap(), &store, &mut foreign, 3),
        Err(ProcessingError::InvalidInput(_))
    ));
    transaction.finish(&owner).unwrap();
    stage.commit(&dir.path().join("owner-valid.xml")).unwrap();
}

#[test]
fn output_factory_reader_and_decode_cancel_remain_terminal_after_control_clears() {
    for phase in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(dir.path()).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cap = ResourceLimits::default();
        let budget = Arc::new(SharedBudget::new(cap.clone()).unwrap());
        let mut scope = budget
            .begin(cap, Arc::new(Control(cancelled.clone())))
            .unwrap();
        let mut stage = store.stage(&mut scope).unwrap();
        let mut transaction = XmlSignatureOutput::new(&mut stage, &scope).unwrap();
        transaction.append(b"<r/>").unwrap();
        if phase == 0 {
            cancelled.store(true, Ordering::SeqCst);
            assert!(matches!(
                transaction.source(),
                Err(ProcessingError::Cancelled)
            ));
        } else {
            let mut captured =
                FrozenInput::capture(transaction.source().unwrap(), &store, &mut scope).unwrap();
            cancelled.store(true, Ordering::SeqCst);
            if phase == 1 {
                assert!(matches!(
                    captured.reader(&[Region { offset: 0, len: 4 }], &scope),
                    Err(ProcessingError::Cancelled)
                ));
            } else {
                assert!(matches!(
                    captured.derive_region(
                        Region { offset: 0, len: 4 },
                        &scope,
                        SnapshotEncoding::Identity
                    ),
                    Err(ProcessingError::Cancelled)
                ));
            }
        }
        cancelled.store(false, Ordering::SeqCst);
        assert!(transaction.finish(&scope).is_err());
        assert!(
            stage
                .commit(&dir.path().join("cancel-must-not-publish.xml"))
                .is_err()
        );
    }
}
