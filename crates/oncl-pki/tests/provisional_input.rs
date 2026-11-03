use oncl_pki::{
    io::{FrozenInput, ProvisionalInput, Region, Source, TemporaryStore},
    key::HashAlg,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{
    io::{self, Cursor, Read},
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
fn scope(document: u64, container: u64, cancel: Arc<AtomicBool>) -> ResourceScope {
    let limits = ResourceLimits {
        input_bytes: document,
        container_bytes: container,
        ..Default::default()
    };
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control(cancel)))
        .unwrap()
}
#[test]
fn actual_wire_is_transferred_once_and_generic_consumers_reject_classified_role() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(3, 3, Arc::new(AtomicBool::new(false)));
    let mut captured = ProvisionalInput::capture(
        Source::sequential(&mut Cursor::new(b"docSIG"), None),
        &store,
        &mut s,
        3,
    )
    .unwrap();
    assert_eq!(s.progress().bytes_in, 6);
    assert_eq!(s.input_remaining(), 0);
    assert_eq!(s.container_remaining(), 0);
    assert!(matches!(
        s.account_input(1),
        Err(ProcessingError::InputLimit)
    ));
    assert!(matches!(
        s.account_container(1),
        Err(ProcessingError::ContainerLimit)
    ));
    assert_eq!(s.progress().bytes_in, 6);
    captured
        .classify(&[Region { offset: 3, len: 3 }], &s)
        .unwrap();
    assert_eq!(captured.document_bytes(), Some(3));
    assert_eq!(captured.container_bytes(), Some(3));
    assert_eq!(
        captured.wire_digest().as_bytes(),
        HashAlg::Sha256.digest(b"docSIG")
    );
    assert_eq!(s.progress().bytes_in, 6);
    {
        let mut reader = captured
            .reader(&[Region { offset: 0, len: 6 }], &s)
            .unwrap();
        assert!(matches!(
            FrozenInput::capture(reader.source(), &store, &mut s),
            Err(ProcessingError::InvalidInput(_))
        ));
    }
    {
        let mut reader = captured
            .reader(&[Region { offset: 0, len: 6 }], &s)
            .unwrap();
        assert!(matches!(
            oncl_pki::digest::hash_source(reader.source(), HashAlg::Sha256, &mut s),
            Err(ProcessingError::InvalidInput(_))
        ));
    }
    let mut reader = captured
        .reader(&[Region { offset: 0, len: 6 }], &s)
        .unwrap();
    let mut replay = ProvisionalInput::capture(reader.source(), &store, &mut s, 3).unwrap();
    reader.finish().unwrap();
    replay
        .classify(&[Region { offset: 3, len: 3 }], &s)
        .unwrap();
    assert_eq!(s.progress().bytes_in, 6);
    assert_eq!(s.input_remaining(), 0);
    assert!(
        replay
            .classify(&[Region { offset: 0, len: 3 }], &s)
            .is_err()
    );
    assert_eq!(s.progress().bytes_in, 6);
}
#[test]
fn pending_drop_never_refunds_consumption_and_second_intake_cannot_spend_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(3, 3, Arc::new(AtomicBool::new(false)));
    let first = ProvisionalInput::capture(
        Source::sequential(&mut Cursor::new(b"docSIG"), None),
        &store,
        &mut s,
        3,
    )
    .unwrap();
    assert!(matches!(
        ProvisionalInput::capture(
            Source::sequential(&mut Cursor::new(b""), Some(0)),
            &store,
            &mut s,
            3
        ),
        Err(ProcessingError::CapacityExceeded)
    ));
    drop(first);
    assert_eq!(s.progress().bytes_in, 6);
    assert!(matches!(
        FrozenInput::capture(
            Source::sequential(&mut Cursor::new(b""), None),
            &store,
            &mut s
        ),
        Err(ProcessingError::InputLimit)
    ));
}
#[test]
fn real_n_plus_one_is_irrevocable_before_post_read_cancellation() {
    struct Input {
        cancel: Arc<AtomicBool>,
        data: Cursor<&'static [u8]>,
    }
    impl Read for Input {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = self.data.read(b)?;
            if n > 0 {
                self.cancel.store(true, Ordering::SeqCst)
            }
            Ok(n)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut s = scope(3, 3, cancel.clone());
    let error = ProvisionalInput::capture(
        Source::sequential(
            &mut Input {
                cancel: cancel.clone(),
                data: Cursor::new(b"docSIG!"),
            },
            Some(6),
        ),
        &store,
        &mut s,
        3,
    )
    .err()
    .unwrap();
    assert!(matches!(error, ProcessingError::InputLimit));
    assert_eq!(s.progress().bytes_in, 7);
    cancel.store(false, Ordering::SeqCst);
    assert!(matches!(
        FrozenInput::capture(
            Source::sequential(&mut Cursor::new(b""), None),
            &store,
            &mut s
        ),
        Err(ProcessingError::InputLimit)
    ));
}
#[test]
fn foreign_classification_does_not_poison_the_original_pending_owner() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut owner = scope(3, 3, Arc::new(AtomicBool::new(false)));
    let foreign = scope(3, 3, Arc::new(AtomicBool::new(false)));
    let mut p = ProvisionalInput::capture(
        Source::sequential(&mut Cursor::new(b"docSIG"), None),
        &store,
        &mut owner,
        3,
    )
    .unwrap();
    assert!(matches!(
        p.classify(&[Region { offset: 3, len: 3 }], &foreign),
        Err(ProcessingError::InvalidInput(_))
    ));
    p.classify(&[Region { offset: 3, len: 3 }], &owner).unwrap();
    assert_eq!(owner.progress().bytes_in, 6);
}
#[test]
fn already_paid_original_snapshot_is_not_credited_or_rebucketed() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(6, 3, Arc::new(AtomicBool::new(false)));
    let mut original = FrozenInput::capture(
        Source::sequential(&mut Cursor::new(b"docSIG"), None),
        &store,
        &mut s,
    )
    .unwrap();
    let mut reader = original
        .reader(&[Region { offset: 0, len: 6 }], &s)
        .unwrap();
    let mut p = ProvisionalInput::capture(reader.source(), &store, &mut s, 3).unwrap();
    reader.finish().unwrap();
    p.classify(&[Region { offset: 3, len: 3 }], &s).unwrap();
    assert_eq!(s.progress().bytes_in, 6);
    assert_eq!(s.input_remaining(), 0);
    assert_eq!(s.container_remaining(), 3);
}

#[test]
fn incomplete_classified_output_recapture_reaches_its_original_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(3, 3, Arc::new(AtomicBool::new(false)));
    let mut stage = store.stage(&mut s).unwrap();
    let mut output = oncl_pki::io::XmlSignatureOutput::new(&mut stage, &s).unwrap();
    output.append(b"docSIG").unwrap();
    let mut captured =
        ProvisionalInput::capture(output.source().unwrap(), &store, &mut s, 3).unwrap();
    captured
        .classify(&[Region { offset: 3, len: 3 }], &s)
        .unwrap();
    let mut reader = captured
        .reader(&[Region { offset: 0, len: 6 }], &s)
        .unwrap();
    let replay = ProvisionalInput::capture(reader.source(), &store, &mut s, 3).unwrap();
    reader.finish().unwrap();
    drop(reader);
    // A previous classification cannot stand in for this consumer's required
    // geometry recheck. Dropping before acceptance poisons the actual output.
    drop(replay);
    drop(captured);
    assert!(output.finish(&s).is_err());
    assert!(stage.copy_to(&mut Vec::new()).is_err());
    assert_eq!(s.progress().bytes_in, 0);
}
