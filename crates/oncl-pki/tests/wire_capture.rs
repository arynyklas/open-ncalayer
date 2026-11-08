//! `FrozenInput::capture_wire`: the spool of a document role that may be a signed result. It
//! holds at most the remaining document allowance plus the remaining container allowance,
//! charges neither of them (the engine charges and classifies the bytes it reads), and is
//! given to the engine only as an external seekable source.
use oncl_pki::{
    io::{FrozenInput, Region, Source, TemporaryStore},
    key::HashAlg,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{
    io::{self, Cursor, Read},
    path::Path,
    sync::Arc,
};

struct Allow;
impl OperationControl for Allow {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope(document: u64, container: u64) -> ResourceScope {
    let limits = ResourceLimits {
        input_bytes: document,
        container_bytes: container,
        ..Default::default()
    };
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Allow))
        .unwrap()
}
fn files(root: &Path) -> usize {
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                files(&entry.path())
            } else {
                1
            }
        })
        .sum()
}
fn wire(
    bytes: &[u8],
    store: &TemporaryStore,
    s: &mut ResourceScope,
    maximum: Option<u64>,
) -> Result<FrozenInput, ProcessingError> {
    FrozenInput::capture_wire(
        Source::sequential(&mut Cursor::new(bytes.to_vec()), None),
        store,
        s,
        maximum,
    )
}

#[test]
fn the_spool_holds_the_document_and_container_allowance_and_charges_no_input() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(4, 3);
    let mut captured = wire(b"docSIG!", &store, &mut s, None).unwrap();
    assert!(captured.is_wire());
    assert_eq!(captured.len(), 7);
    // Nothing is charged to the document, container or input accounting yet.
    assert_eq!(s.input_remaining(), 4);
    assert_eq!(s.container_remaining(), 3);
    assert_eq!(s.progress().bytes_in, 0);
    // The engine's view is an external seekable source of known length, not a snapshot.
    let mut reader = captured.wire_reader(&s).unwrap();
    let mut source = reader.source();
    assert_eq!(source.known_len(), Some(7));
    assert!(!source.is_snapshot_for(&s).unwrap());
    assert!(!source.is_output_projection_for(&s).unwrap());
    let mut bytes = Vec::new();
    source.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"docSIG!");
    reader.finish().unwrap();
    drop(reader);
    // The admitted-snapshot reader refuses wire; the host's inspection replay does not.
    assert!(matches!(
        captured.reader(&[Region { offset: 0, len: 7 }], &s),
        Err(ProcessingError::InvalidInput(_))
    ));
    let mut inspection = captured.wire_inspection_reader(&s).unwrap();
    assert!(inspection.source().is_snapshot_for(&s).unwrap());
    inspection.finish().unwrap();
    drop(inspection);
    assert_eq!(s.progress().bytes_in, 0);
    assert_eq!(s.input_remaining(), 4);
}

#[test]
fn the_engine_charges_the_document_when_it_reads_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    // A document inside the allowance is charged as the engine reads it, once.
    let mut s = scope(4, 3);
    let mut captured = wire(b"doc!", &store, &mut s, None).unwrap();
    let mut reader = captured.wire_reader(&s).unwrap();
    let report = oncl_pki::digest::hash_source(reader.source(), HashAlg::Sha256, &mut s).unwrap();
    reader.finish().unwrap();
    assert_eq!(report.as_bytes(), HashAlg::Sha256.digest(b"doc!"));
    assert_eq!(s.progress().bytes_in, 4);
    assert_eq!(s.input_remaining(), 0);
    // The container allowance is spooled, but a reader that treats it all as document
    // (an unsigned document) is refused by the engine's own accounting.
    let mut s = scope(4, 3);
    let mut captured = wire(b"docSIG!", &store, &mut s, None).unwrap();
    let mut reader = captured.wire_reader(&s).unwrap();
    assert!(matches!(
        oncl_pki::digest::hash_source(reader.source(), HashAlg::Sha256, &mut s),
        Err(ProcessingError::InputLimit)
    ));
}

#[test]
fn one_byte_past_the_document_and_container_allowance_is_input_limit_and_not_stored() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(4, 3);
    assert!(matches!(
        wire(b"docSIG!!", &store, &mut s, None),
        Err(ProcessingError::InputLimit)
    ));
    assert_eq!(files(dir.path()), 0, "no spool survives the refusal");
    // A declared length past the allowance is refused before a byte is read.
    struct Unread;
    impl Read for Unread {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("a declared oversize wire must not be read");
        }
    }
    let mut s = scope(4, 3);
    assert!(matches!(
        FrozenInput::capture_wire(
            Source::sequential(&mut Unread, Some(8)),
            &store,
            &mut s,
            None
        ),
        Err(ProcessingError::InputLimit)
    ));
    // The allowance is what remains: input already charged narrows the document part.
    let mut s = scope(4, 3);
    s.account_input(2).unwrap();
    assert!(wire(b"docSI", &store, &mut s, None).is_ok());
    assert!(matches!(
        wire(b"docSIG", &store, &mut s, None),
        Err(ProcessingError::InputLimit)
    ));
}

#[test]
fn a_maximum_narrows_the_spool_and_never_widens_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(4, 3);
    assert!(wire(b"ab", &store, &mut s, Some(2)).is_ok());
    assert!(matches!(
        wire(b"abc", &store, &mut s, Some(2)),
        Err(ProcessingError::InputLimit)
    ));
    assert!(matches!(
        wire(b"docSIG!!", &store, &mut s, Some(100)),
        Err(ProcessingError::InputLimit)
    ));
    // The bytes of a bounded role are not document bytes either.
    assert_eq!(s.input_remaining(), 4);
}

#[test]
fn only_an_external_source_is_wire_and_only_wire_has_a_wire_reader() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(4, 3);
    let mut document = FrozenInput::capture(
        Source::sequential(&mut Cursor::new(b"doc".to_vec()), None),
        &store,
        &mut s,
    )
    .unwrap();
    assert!(!document.is_wire());
    assert!(matches!(
        document.wire_reader(&s),
        Err(ProcessingError::InvalidInput(_))
    ));
    assert!(matches!(
        document.wire_inspection_reader(&s),
        Err(ProcessingError::InvalidInput(_))
    ));
    // An admitted snapshot is not external wire: it was charged already.
    let mut reader = document
        .reader(&[Region { offset: 0, len: 3 }], &s)
        .unwrap();
    assert!(matches!(
        FrozenInput::capture_wire(reader.source(), &store, &mut s, None),
        Err(ProcessingError::InvalidInput(_))
    ));
}
