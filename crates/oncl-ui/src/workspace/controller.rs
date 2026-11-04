//! What the tools window does with its operations, without Slint: one operation at a time, run
//! on a worker thread, cancelled from the event loop, its progress read from atomics, its
//! outcome delivered once and only to the operation that is still the current one.
//!
//! The [`JobControl`] of an operation is the only thing the event loop and the worker share
//! (`Arc` and atomics; the SDK checks it at every checkpoint). Everything with `Rc`, `RefCell`
//! or a Slint handle stays on the event loop.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use oncl_core::{ErrorCode, OperationError};
use oncl_pki::resource::{OperationControl, ProcessingError, Progress};

/// What an operation does; which page of the window owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Job {
    Hash,
    Inspect,
    /// A step of the signing page: freezing a document, opening a key store, signing.
    Sign,
}

/// Why an operation did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JobError {
    /// The user cancelled it.
    Cancelled,
    /// The input could not be opened or read.
    Io(io::ErrorKind),
    /// The path is not a regular file (a pipe, a device): nothing is opened.
    NotRegular,
    /// The SDK refused or failed it.
    Operation(ErrorCode),
    /// A field the action needs is empty.
    Input(MissingField),
    /// The worker thread could not be started or broke off.
    Worker,
}

/// The field of a page that is empty, found before anything runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MissingField {
    Path,
    Password,
    Aliases,
}

impl From<OperationError> for JobError {
    fn from(e: OperationError) -> Self {
        match e.code() {
            ErrorCode::Cancelled => JobError::Cancelled,
            code => JobError::Operation(code),
        }
    }
}

impl From<io::Error> for JobError {
    fn from(e: io::Error) -> Self {
        JobError::Io(e.kind())
    }
}

/// The cancel flag and the progress of one operation.
#[derive(Debug, Default)]
pub(crate) struct JobControl {
    cancelled: AtomicBool,
    bytes_in: AtomicU64,
    total: AtomicU64,
}

impl JobControl {
    /// Asks the operation to stop at its next checkpoint.
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// The size of the input, once the worker knows it.
    pub(crate) fn set_total(&self, total: u64) {
        self.total.store(total.max(1), Ordering::SeqCst);
    }

    /// Bytes read so far and the size of the input, if known.
    pub(crate) fn progress(&self) -> (u64, Option<u64>) {
        let total = self.total.load(Ordering::SeqCst);
        (
            self.bytes_in.load(Ordering::SeqCst),
            (total != 0).then_some(total),
        )
    }
}

impl OperationControl for JobControl {
    fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError> {
        self.bytes_in.fetch_max(progress.bytes_in, Ordering::SeqCst);
        if self.is_cancelled() {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// An operation that was started.
pub(crate) struct Started {
    pub(crate) id: u64,
    pub(crate) control: Arc<JobControl>,
}

struct Active {
    id: u64,
    job: Job,
    control: Arc<JobControl>,
}

/// An operation is running already.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Busy;

/// How an operation ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Settled<T> {
    Done(Job, T),
    Cancelled(Job),
    Failed(Job, JobError),
}

/// Ids are unique across windows: the late result of an operation of a window that was closed
/// never matches the operation of the window opened since.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// One operation at a time.
#[derive(Default)]
pub(crate) struct Controller {
    active: Option<Active>,
}

impl Controller {
    /// Starts `job`, unless another is running.
    pub(crate) fn begin(&mut self, job: Job) -> Result<Started, Busy> {
        if self.active.is_some() {
            return Err(Busy);
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let control = Arc::new(JobControl::default());
        self.active = Some(Active {
            id,
            job,
            control: Arc::clone(&control),
        });
        Ok(Started { id, control })
    }

    /// Asks the running operation to stop; whether one runs. It ends when the worker
    /// reports back ([`Controller::finish`]), not now.
    pub(crate) fn cancel(&mut self) -> bool {
        match &self.active {
            Some(active) => {
                active.control.cancel();
                true
            }
            None => false,
        }
    }

    /// The running operation and its control.
    pub(crate) fn running(&self) -> Option<(Job, &Arc<JobControl>)> {
        self.active.as_ref().map(|a| (a.job, &a.control))
    }

    /// Takes the outcome of operation `id`. `None` if `id` is not the running operation (a
    /// result that arrives twice, or after the window was left): nothing changes then.
    pub(crate) fn finish<T>(&mut self, id: u64, result: Result<T, JobError>) -> Option<Settled<T>> {
        let active = self.active.take_if(|a| a.id == id)?;
        Some(match result {
            Ok(value) => Settled::Done(active.job, value),
            Err(JobError::Cancelled) => Settled::Cancelled(active.job),
            Err(e) => Settled::Failed(active.job, e),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read};

    use oncl_core::{Engine, EngineServices};
    use oncl_pki::key::HashAlg;
    use oncl_pki::resource::ResourceLimits;

    use super::*;
    use crate::workspace::jobs;

    fn engine() -> Engine {
        Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap()
    }

    /// Serves `len` zero bytes in `chunk`-sized reads, running `on_read` before each.
    struct Zeros<F> {
        left: u64,
        chunk: usize,
        reads: u64,
        on_read: F,
    }

    impl<F: FnMut(u64)> Read for Zeros<F> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            (self.on_read)(self.reads);
            self.reads += 1;
            let n = buf
                .len()
                .min(self.chunk)
                .min(usize::try_from(self.left).unwrap());
            buf[..n].fill(0);
            self.left -= n as u64;
            Ok(n)
        }
    }

    #[test]
    fn a_second_operation_waits_for_the_first() {
        let mut c = Controller::default();
        let first = c.begin(Job::Hash).unwrap();
        assert_eq!(c.begin(Job::Inspect).err(), Some(Busy));
        c.finish::<()>(first.id, Ok(())).unwrap();
        assert!(c.begin(Job::Inspect).is_ok());
    }

    #[test]
    fn a_result_of_another_operation_changes_nothing() {
        let mut c = Controller::default();
        let first = c.begin(Job::Hash).unwrap();
        assert_eq!(
            c.finish(first.id, Ok(1)),
            Some(Settled::Done(Job::Hash, 1)),
            "the first result is taken"
        );
        let second = c.begin(Job::Inspect).unwrap();
        assert_eq!(c.finish(first.id, Ok(2)), None, "a repeat is dropped");
        assert_eq!(c.finish(second.id + 1000, Ok(3)), None, "a stranger too");
        assert!(c.running().is_some(), "the second still runs");
        assert_eq!(
            c.finish(second.id, Err::<u8, _>(JobError::Worker)),
            Some(Settled::Failed(Job::Inspect, JobError::Worker))
        );
        assert!(c.running().is_none());
    }

    /// The result of a window that was closed must not land in the operation of the window
    /// opened next, whichever controller each has.
    #[test]
    fn a_late_result_of_a_closed_window_is_dropped_by_the_next_one() {
        let mut old = Controller::default();
        let late = old.begin(Job::Hash).unwrap();
        old.cancel();
        drop(old);
        let mut new = Controller::default();
        let current = new.begin(Job::Hash).unwrap();
        assert_ne!(late.id, current.id);
        assert_eq!(new.finish(late.id, Ok(1)), None);
        assert!(new.running().is_some(), "the new window's action goes on");
        assert_eq!(
            new.finish(current.id, Ok(2)),
            Some(Settled::Done(Job::Hash, 2))
        );
    }

    #[test]
    fn cancelling_without_an_operation_is_not_an_operation() {
        let mut c = Controller::default();
        assert!(!c.cancel());
        let started = c.begin(Job::Hash).unwrap();
        assert!(c.cancel());
        assert!(started.control.is_cancelled());
    }

    /// The cancel reaches the worker through the control while the hash runs: no digest, the
    /// window hears «cancelled», and the input was not read to its end.
    #[test]
    fn cancelling_stops_a_hash_that_is_reading() {
        let engine = engine();
        let mut c = Controller::default();
        let started = c.begin(Job::Hash).unwrap();
        let control = Arc::clone(&started.control);
        let canceller = Arc::clone(&control);
        let total = 64 << 20;
        let mut input = Zeros {
            left: total,
            chunk: 64 << 10,
            reads: 0,
            on_read: move |n| {
                if n == 20 {
                    canceller.cancel();
                }
            },
        };
        let result = jobs::hash(
            &engine,
            HashAlg::Sha256,
            oncl_pki::io::Source::sequential(&mut input, Some(total)),
            &control,
        );
        assert!(input.left > 0, "the input was read to its end");
        assert!(matches!(result, Err(JobError::Cancelled)), "{result:?}");
        assert_eq!(
            c.finish(started.id, result),
            Some(Settled::Cancelled(Job::Hash))
        );
        assert!(c.running().is_none(), "the window is free again");
    }

    /// A cancel after the work is done does not turn its digest into a cancellation.
    #[test]
    fn a_hash_that_finished_is_not_cancelled_by_a_late_cancel() {
        let engine = engine();
        let mut c = Controller::default();
        let started = c.begin(Job::Hash).unwrap();
        let mut input: &[u8] = b"abc";
        let result = jobs::hash(
            &engine,
            HashAlg::Sha256,
            oncl_pki::io::Source::sequential(&mut input, Some(3)),
            &started.control,
        );
        c.cancel();
        let Some(Settled::Done(Job::Hash, out)) = c.finish(started.id, result) else {
            panic!("the digest is lost");
        };
        assert_eq!(
            out.digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(out.bytes, 3);
    }

    #[test]
    fn progress_counts_what_was_read() {
        let engine = engine();
        let control = Arc::new(JobControl::default());
        let total = 3 << 20;
        let mut input = Zeros {
            left: total,
            chunk: 100 << 10,
            reads: 0,
            on_read: |_| {},
        };
        control.set_total(total);
        let out = jobs::hash(
            &engine,
            HashAlg::Sha256,
            oncl_pki::io::Source::sequential(&mut input, Some(total)),
            &control,
        )
        .unwrap();
        assert_eq!(out.bytes, total);
        assert_eq!(control.progress(), (total, Some(total)));
    }

    #[test]
    fn an_unreadable_file_is_an_input_error_not_a_panic() {
        let engine = engine();
        let dir = tempfile::tempdir().unwrap();
        let control = JobControl::default();
        let missing = dir.path().join("missing");
        let result = jobs::hash_file(&engine, HashAlg::Sha256, &missing, &Arc::new(control));
        assert_eq!(result, Err(JobError::Io(io::ErrorKind::NotFound)));
    }
}
