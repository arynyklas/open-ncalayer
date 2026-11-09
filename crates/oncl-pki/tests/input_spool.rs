//! The incremental forms for a host that is handed the bytes of a request body while it waits
//! for the client: `InputSpool` (the spool of `FrozenInput::capture` / `capture_wire`),
//! `HashStream` (`hash_source`) and the `max_in_flight` slot that an operation takes only after
//! its input arrived (`SharedBudget::begin_unslotted`, `ResourceScope::occupy_slot`).
use oncl_pki::{
    digest::{HashStream, hash_source},
    io::{FrozenInput, InputSpool, Source, TemporaryStore},
    key::HashAlg,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{
    io::{Cursor, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Default)]
struct Switch(AtomicBool);
impl OperationControl for Switch {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
fn limits(document: u64, container: u64) -> ResourceLimits {
    ResourceLimits {
        input_bytes: document,
        container_bytes: container,
        ..Default::default()
    }
}
fn scope(document: u64, container: u64) -> ResourceScope {
    let limits = limits(document, container);
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Switch::default()))
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
/// Splits `bytes` into pieces of the given sizes (the last piece takes the rest).
fn pieces(bytes: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut rest = bytes;
    let mut out = Vec::new();
    for size in sizes.iter().cycle() {
        if rest.is_empty() {
            break;
        }
        let (head, tail) = rest.split_at((*size).min(rest.len()));
        out.push(head.to_vec());
        rest = tail;
    }
    out
}
fn read_back(captured: &mut FrozenInput, scope: &ResourceScope) -> Vec<u8> {
    let mut bytes = Vec::new();
    if captured.is_wire() {
        let mut reader = captured.wire_reader(scope).unwrap();
        reader.source().read_to_end(&mut bytes).unwrap();
        reader.finish().unwrap();
    } else {
        let len = captured.len();
        let mut reader = captured
            .reader(&[oncl_pki::io::Region { offset: 0, len }], scope)
            .unwrap();
        reader.source().read_to_end(&mut bytes).unwrap();
        reader.finish().unwrap();
    }
    bytes
}

#[test]
fn a_document_spool_holds_exactly_what_the_one_call_capture_holds_whatever_the_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    // Larger than one IO chunk, and ragged.
    let data: Vec<u8> = (0..700_001u32).map(|i| (i % 251) as u8).collect();
    for sizes in [&[1usize][..], &[7, 4096], &[32_768], &[300_000, 1], &[700_001]] {
        let mut one = scope(1 << 20, 0);
        let mut reference = FrozenInput::capture(
            Source::sequential(&mut Cursor::new(data.clone()), None),
            &store,
            &mut one,
        )
        .unwrap();
        let mut s = scope(1 << 20, 0);
        let mut spool = InputSpool::document(&store, &mut s).unwrap();
        for piece in pieces(&data, sizes) {
            spool.push(&piece).unwrap();
        }
        assert_eq!(spool.len(), data.len() as u64);
        let mut captured = spool.finish().unwrap();
        assert!(!captured.is_wire(), "a plain document is an admitted snapshot");
        assert_eq!(captured.len(), reference.len());
        // The same accounting as the one-call capture.
        assert_eq!(s.progress().bytes_in, one.progress().bytes_in, "{sizes:?}");
        assert_eq!(s.input_remaining(), one.input_remaining(), "{sizes:?}");
        assert_eq!(read_back(&mut captured, &s), data, "{sizes:?}");
        assert_eq!(read_back(&mut reference, &one), data);
    }
}

#[test]
fn a_document_spool_refuses_the_byte_past_the_allowance_like_the_capture_and_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    // Exactly at the allowance is accepted, in any pieces.
    let mut s = scope(10, 0);
    let mut spool = InputSpool::document(&store, &mut s).unwrap();
    spool.push(b"0123").unwrap();
    spool.push(b"456789").unwrap();
    spool.finish().unwrap();
    // One byte more is `InputLimit`, which is what the one-call capture says as well.
    let mut reference = scope(10, 0);
    assert!(matches!(
        FrozenInput::capture(
            Source::sequential(&mut Cursor::new(vec![1u8; 11]), None),
            &store,
            &mut reference,
        ),
        Err(ProcessingError::InputLimit)
    ));
    let mut s = scope(10, 0);
    let mut spool = InputSpool::document(&store, &mut s).unwrap();
    spool.push(&[1u8; 10]).unwrap();
    assert!(matches!(spool.push(&[1]), Err(ProcessingError::InputLimit)));
    // The operation's input is terminal, exactly as after the failed capture.
    assert!(matches!(
        InputSpool::document(&store, &mut s),
        Err(ProcessingError::InputLimit)
    ));
    drop(spool);
    // A single piece that crosses the allowance is refused as a whole.
    let mut s = scope(10, 0);
    let mut spool = InputSpool::document(&store, &mut s).unwrap();
    assert!(matches!(spool.push(&[1u8; 64]), Err(ProcessingError::InputLimit)));
    drop(spool);
    // A refused or dropped spool deletes its file and frees its temp reservation.
    assert_eq!(files(dir.path()), 0);
}

#[test]
fn a_wire_spool_has_the_allowance_of_the_one_call_wire_capture_and_charges_no_input() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let mut s = scope(4, 3);
    let mut spool = InputSpool::wire(&store, &mut s, None).unwrap();
    spool.push(b"doc").unwrap();
    spool.push(b"SIG!").unwrap();
    let mut captured = spool.finish().unwrap();
    assert!(captured.is_wire());
    assert_eq!(captured.len(), 7);
    assert_eq!(s.input_remaining(), 4, "nothing is charged before the engine reads it");
    assert_eq!(s.progress().bytes_in, 0);
    assert_eq!(read_back(&mut captured, &s), b"docSIG!");
    drop(captured);
    // One byte past document + container is `InputLimit`, nothing is stored.
    let mut s = scope(4, 3);
    let mut spool = InputSpool::wire(&store, &mut s, None).unwrap();
    spool.push(&[1u8; 7]).unwrap();
    assert!(matches!(spool.push(&[1]), Err(ProcessingError::InputLimit)));
    drop(spool);
    assert_eq!(files(dir.path()), 0);
    // A maximum narrows the spool and never widens it.
    let mut s = scope(4, 3);
    let mut spool = InputSpool::wire(&store, &mut s, Some(5)).unwrap();
    spool.push(&[1u8; 5]).unwrap();
    assert!(matches!(spool.push(&[1]), Err(ProcessingError::InputLimit)));
    let mut s = scope(4, 3);
    let mut spool = InputSpool::wire(&store, &mut s, Some(100)).unwrap();
    spool.push(&[1u8; 7]).unwrap();
    assert!(matches!(spool.push(&[1]), Err(ProcessingError::InputLimit)));
}

#[test]
fn a_cancelled_or_expired_operation_stops_the_spool_and_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let control = Arc::new(Switch::default());
    let limits = limits(1 << 20, 0);
    let mut s = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, control.clone())
        .unwrap();
    let mut spool = InputSpool::document(&store, &mut s).unwrap();
    spool.push(b"first").unwrap();
    assert_eq!(files(dir.path()), 1);
    control.0.store(true, Ordering::SeqCst);
    assert!(matches!(spool.push(b"more"), Err(ProcessingError::Cancelled)));
    assert!(matches!(spool.finish(), Err(ProcessingError::Cancelled)));
    assert_eq!(files(dir.path()), 0, "a stopped spool leaves no file");
    // The temp reservation is back: a new operation can reserve the whole budget again.
    let mut again = scope(1 << 20, 0);
    let spool = InputSpool::document(&store, &mut again).unwrap();
    drop(spool);
}

#[test]
fn a_hash_stream_gives_the_digest_and_the_accounting_of_hash_source_whatever_the_pieces() {
    let data: Vec<u8> = (0..300_007u32).map(|i| (i % 253) as u8).collect();
    let mut one = scope(1 << 20, 0);
    let reference = hash_source(
        Source::sequential(&mut Cursor::new(data.clone()), None),
        HashAlg::Sha256,
        &mut one,
    )
    .unwrap();
    for sizes in [&[1usize][..], &[7, 4096], &[32_768], &[300_007]] {
        let s = scope(1 << 20, 0);
        let mut stream = HashStream::new(HashAlg::Sha256, &s).unwrap();
        for piece in pieces(&data, sizes) {
            stream.update(&piece, &s).unwrap();
        }
        assert_eq!(stream.finish(&s).unwrap(), reference, "{sizes:?}");
        assert_eq!(s.progress().bytes_in, one.progress().bytes_in);
        assert_eq!(s.input_remaining(), one.input_remaining());
    }
}

#[test]
fn a_hash_stream_refuses_the_byte_past_the_allowance_and_a_cancelled_operation() {
    let s = scope(10, 0);
    let mut stream = HashStream::new(HashAlg::Sha256, &s).unwrap();
    stream.update(&[1u8; 10], &s).unwrap();
    assert!(matches!(stream.update(&[1], &s), Err(ProcessingError::InputLimit)));
    // A single piece across the allowance is refused, and the input stays terminal.
    let s = scope(10, 0);
    let mut stream = HashStream::new(HashAlg::Sha256, &s).unwrap();
    assert!(matches!(stream.update(&[1u8; 64], &s), Err(ProcessingError::InputLimit)));
    assert!(matches!(
        HashStream::new(HashAlg::Sha256, &s),
        Err(ProcessingError::InputLimit)
    ));
    let control = Arc::new(Switch::default());
    let limits = limits(10, 0);
    let s = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, control.clone())
        .unwrap();
    let mut stream = HashStream::new(HashAlg::Sha256, &s).unwrap();
    control.0.store(true, Ordering::SeqCst);
    assert!(matches!(stream.update(b"x", &s), Err(ProcessingError::Cancelled)));
}

#[test]
fn an_unslotted_operation_takes_no_in_flight_slot_until_it_occupies_one() {
    let limits = ResourceLimits {
        max_in_flight: 1,
        ..Default::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    // Any number of operations may still be receiving their input; they hold no slot.
    let receiving: Vec<_> = (0..4)
        .map(|_| {
            budget
                .begin_unslotted(limits.clone(), Arc::new(Switch::default()))
                .unwrap()
        })
        .collect();
    assert!(receiving.iter().all(|scope| !scope.holds_slot()));
    // ... and do not stop a running one (the single slot is free).
    let running = budget
        .begin(limits.clone(), Arc::new(Switch::default()))
        .unwrap();
    assert!(running.holds_slot());
    // With the slot taken, an operation that has its input is refused (retryably) ...
    assert!(matches!(
        receiving[0].occupy_slot(),
        Err(ProcessingError::CapacityExceeded)
    ));
    assert!(matches!(
        receiving[0].occupy_slot(),
        Err(ProcessingError::CapacityExceeded)
    ));
    assert!(!receiving[0].holds_slot());
    // ... and takes it as soon as it is free; occupying twice takes one slot only.
    drop(running);
    receiving[0].occupy_slot().unwrap();
    receiving[0].occupy_slot().unwrap();
    assert!(receiving[0].holds_slot());
    assert!(matches!(
        receiving[1].occupy_slot(),
        Err(ProcessingError::CapacityExceeded)
    ));
    assert!(matches!(
        budget.begin(limits.clone(), Arc::new(Switch::default())),
        Err(ProcessingError::CapacityExceeded)
    ));
    // Dropping operations that never took a slot frees nothing they did not hold.
    let mut receiving = receiving;
    let holder = receiving.remove(0);
    drop(receiving);
    assert!(matches!(
        budget.begin(limits.clone(), Arc::new(Switch::default())),
        Err(ProcessingError::CapacityExceeded)
    ));
    // The slot is released when the operation that took it ends, once.
    drop(holder);
    let again = budget
        .begin(limits.clone(), Arc::new(Switch::default()))
        .unwrap();
    assert!(matches!(
        budget.begin(limits, Arc::new(Switch::default())),
        Err(ProcessingError::CapacityExceeded)
    ));
    drop(again);
}

#[test]
fn an_unslotted_operation_charges_every_other_budget_like_an_admitted_one() {
    let limits = ResourceLimits {
        max_in_flight: 1,
        memory_bytes: 100,
        ..Default::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let receiving = budget
        .begin_unslotted(limits.clone(), Arc::new(Switch::default()))
        .unwrap();
    let memory = receiving.reserve_memory(100).unwrap();
    assert!(matches!(
        receiving.reserve_memory(1),
        Err(ProcessingError::MemoryLimit)
    ));
    // The shared memory is taken: another operation sees it, slot or not.
    let other = budget
        .begin_unslotted(limits.clone(), Arc::new(Switch::default()))
        .unwrap();
    assert!(matches!(
        other.reserve_memory(1),
        Err(ProcessingError::MemoryLimit)
    ));
    drop(memory);
    other.reserve_memory(1).unwrap();
    // A stopped operation cannot take a slot.
    let control = Arc::new(Switch::default());
    let stopped = budget.begin_unslotted(limits, control.clone()).unwrap();
    control.0.store(true, Ordering::SeqCst);
    assert!(matches!(
        stopped.occupy_slot(),
        Err(ProcessingError::Cancelled)
    ));
}
