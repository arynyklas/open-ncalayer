//! What the tools window does with its operations, without Slint: one operation at a time, run
//! on a worker thread, cancelled from the event loop, its progress queued for the event loop
//! ([`progress`](super::progress)), its outcome delivered once and only to the operation that
//! is still the current one of the window that is still open.
//!
//! The [`JobControl`] of an operation is the only thing the event loop and the worker share
//! (`Arc`, atomics and the bounded queue of the [`Reporter`]; the SDK checks it at every
//! checkpoint). Everything with `Rc`, `RefCell` or a Slint handle stays on the event loop.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oncl_core::{ErrorCode, OperationError};
use oncl_pki::resource::{OperationControl, ProcessingError, Progress};

use super::progress::{Lifecycle, Reporter, Stamp, Update};

/// What an operation does; which page of the window owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Job {
    Hash,
    Inspect,
    /// A step of the signing page: freezing a document, opening a key store, signing.
    Sign,
    /// A run of one of the tools that use no private key: verify, extend, extract, timestamp.
    Tool,
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
    /// A signature file would replace an existing one: nothing is signed.
    DestinationExists,
    /// The folder of a document cannot publish a signature file (no hard links).
    NoLinks,
    /// Two documents would be written to the same file: nothing is done.
    DuplicateOutput,
    /// The key store changed after the certificate was shown: no key is used.
    StoreChanged,
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
    /// The folder the results are to be written to.
    Folder,
    /// The certificates and the OCSP responses or CRLs the LT and LTA levels are built from.
    Evidence,
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

/// How often a running operation tells the event loop how far it is: more often is not seen.
const REPORT_EVERY: Duration = Duration::from_millis(50);

/// The cancel flag and the progress of one operation. `Send + Sync`: the SDK calls it from the
/// worker, the event loop cancels it.
#[derive(Debug)]
pub struct JobControl {
    cancelled: AtomicBool,
    bytes_in: AtomicU64,
    total: AtomicU64,
    items: AtomicUsize,
    begun: AtomicUsize,
    reporter: Option<Reporter>,
    clock: Instant,
    /// Milliseconds after `clock` of the last word queued, plus one (0: none yet).
    last_report: AtomicU64,
}

impl Default for JobControl {
    fn default() -> Self {
        JobControl {
            cancelled: AtomicBool::new(false),
            bytes_in: AtomicU64::new(0),
            total: AtomicU64::new(0),
            items: AtomicUsize::new(0),
            begun: AtomicUsize::new(0),
            reporter: None,
            clock: Instant::now(),
            last_report: AtomicU64::new(0),
        }
    }
}

impl JobControl {
    /// A control whose progress goes to `reporter`'s window.
    pub fn reporting(reporter: Reporter) -> JobControl {
        JobControl {
            reporter: Some(reporter),
            ..JobControl::default()
        }
    }

    /// The queue this control's progress goes to; the outcome of the operation goes through it
    /// too ([`Reporter::finish`]).
    pub fn reporter(&self) -> Option<&Reporter> {
        self.reporter.as_ref()
    }

    /// Asks the operation to stop at its next checkpoint.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// The size of the input, once the worker knows it. Never 0: «unknown» is a different thing.
    pub fn set_total(&self, total: u64) {
        self.total.store(total.max(1), Ordering::SeqCst);
    }

    /// The operation is a batch of `items` documents, being prepared. Told at once, not by the
    /// clock.
    pub fn set_items(&self, items: usize) {
        self.items.store(items, Ordering::SeqCst);
        self.begun.store(0, Ordering::SeqCst);
        self.publish();
    }

    /// The document `index` (zero-based) of the batch begins. Told at once.
    pub fn begin_item(&self, index: usize) {
        self.begun.store(index + 1, Ordering::SeqCst);
        self.publish();
    }

    /// Bytes read so far and the size of the input, if known.
    pub fn progress(&self) -> (u64, Option<u64>) {
        let total = self.total.load(Ordering::SeqCst);
        (
            self.bytes_in.load(Ordering::SeqCst),
            (total != 0).then_some(total),
        )
    }

    fn snapshot(&self) -> Update {
        let (bytes_in, total) = self.progress();
        Update {
            bytes_in,
            total,
            items: self.items.load(Ordering::SeqCst),
            started: self.begun.load(Ordering::SeqCst),
        }
    }

    /// Queues the current state for the window. Never waits and never calls the UI.
    fn publish(&self) {
        if let Some(reporter) = &self.reporter {
            reporter.report(self.snapshot());
        }
    }
}

impl OperationControl for JobControl {
    fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError> {
        self.bytes_in.fetch_max(progress.bytes_in, Ordering::SeqCst);
        if self.is_cancelled() {
            return Err(ProcessingError::Cancelled);
        }
        if self.reporter.is_some() {
            // Checkpoints come for every chunk of a large file: the window is told at most
            // every [`REPORT_EVERY`].
            let now = u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX) + 1;
            let last = self.last_report.load(Ordering::Relaxed);
            let due = last == 0 || now.saturating_sub(last) >= REPORT_EVERY.as_millis() as u64;
            if due
                && self
                    .last_report
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                self.publish();
            }
        }
        Ok(())
    }
}

/// An operation that was started.
pub(crate) struct Started {
    pub(crate) stamp: Stamp,
    pub(crate) control: Arc<JobControl>,
}

struct Active {
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

/// One operation at a time, for one window. Its [`Lifecycle`] numbers the window and the
/// operations uniquely across the process: the late word of a window that was closed never
/// matches the operation of the window opened since.
#[derive(Default)]
pub(crate) struct Controller {
    life: Lifecycle,
    active: Option<Active>,
}

impl Controller {
    /// Starts `job`, unless another is running or the window is closed. `control` makes the
    /// operation's control from its stamp (the one that tells the window how far it is).
    pub(crate) fn begin(
        &mut self,
        job: Job,
        control: impl FnOnce(Stamp) -> JobControl,
    ) -> Result<Started, Busy> {
        let stamp = self.life.begin().ok_or(Busy)?;
        let control = Arc::new(control(stamp));
        self.active = Some(Active {
            job,
            control: Arc::clone(&control),
        });
        Ok(Started { stamp, control })
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

    /// The window is closed: the running operation is asked to stop and nothing it says is
    /// accepted any more.
    pub(crate) fn close(&mut self) {
        self.cancel();
        self.active = None;
        self.life.close();
    }

    /// The running operation and its control.
    pub(crate) fn running(&self) -> Option<(Job, &Arc<JobControl>)> {
        self.active.as_ref().map(|a| (a.job, &a.control))
    }

    /// Whether a word of `stamp` is for the running operation of this window.
    pub(crate) fn accepts(&self, stamp: Stamp) -> bool {
        self.life.accepts(stamp)
    }

    /// Takes the outcome of the operation `stamp`. `None` if it is not the running operation
    /// of this window (a result that arrives twice, or after the window was left): nothing
    /// changes then.
    pub(crate) fn finish<T>(
        &mut self,
        stamp: Stamp,
        result: Result<T, JobError>,
    ) -> Option<Settled<T>> {
        if !self.life.end(stamp) {
            return None;
        }
        let active = self.active.take()?;
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

    /// Starts `job` with a control that reports to nobody.
    fn begin(c: &mut Controller, job: Job) -> Result<Started, Busy> {
        c.begin(job, |_| JobControl::default())
    }

    #[test]
    fn a_second_operation_waits_for_the_first() {
        let mut c = Controller::default();
        let first = begin(&mut c, Job::Hash).unwrap();
        assert_eq!(begin(&mut c, Job::Inspect).err(), Some(Busy));
        c.finish::<()>(first.stamp, Ok(())).unwrap();
        assert!(begin(&mut c, Job::Inspect).is_ok());
    }

    #[test]
    fn a_result_of_another_operation_changes_nothing() {
        let mut c = Controller::default();
        let first = begin(&mut c, Job::Hash).unwrap();
        assert_eq!(
            c.finish(first.stamp, Ok(1)),
            Some(Settled::Done(Job::Hash, 1)),
            "the first result is taken"
        );
        let second = begin(&mut c, Job::Inspect).unwrap();
        assert_eq!(c.finish(first.stamp, Ok(2)), None, "a repeat is dropped");
        let stranger = Stamp {
            generation: second.stamp.generation + 1000,
            ..second.stamp
        };
        assert_eq!(c.finish(stranger, Ok(3)), None, "a stranger too");
        assert!(c.running().is_some(), "the second still runs");
        assert_eq!(
            c.finish(second.stamp, Err::<u8, _>(JobError::Worker)),
            Some(Settled::Failed(Job::Inspect, JobError::Worker))
        );
        assert!(c.running().is_none());
    }

    /// The result of a window that was closed must not land in the operation of the window
    /// opened next, whichever controller each has.
    #[test]
    fn a_late_result_of_a_closed_window_is_dropped_by_the_next_one() {
        let mut old = Controller::default();
        let late = begin(&mut old, Job::Hash).unwrap();
        old.close();
        assert!(
            late.control.is_cancelled(),
            "closing asks the operation to stop"
        );
        drop(old);
        let mut new = Controller::default();
        let current = begin(&mut new, Job::Hash).unwrap();
        assert_ne!(late.stamp, current.stamp);
        assert_eq!(new.finish(late.stamp, Ok(1)), None);
        assert!(new.running().is_some(), "the new window's action goes on");
        assert_eq!(
            new.finish(current.stamp, Ok(2)),
            Some(Settled::Done(Job::Hash, 2))
        );
    }

    /// A closed window accepts no word of its own operation any more, and starts none.
    #[test]
    fn a_closed_window_hears_nothing_of_its_own_operation() {
        let mut c = Controller::default();
        let started = begin(&mut c, Job::Hash).unwrap();
        assert!(c.accepts(started.stamp));
        c.close();
        assert!(!c.accepts(started.stamp));
        assert_eq!(c.finish(started.stamp, Ok(1)), None);
        assert_eq!(begin(&mut c, Job::Hash).err(), Some(Busy));
    }

    #[test]
    fn cancelling_without_an_operation_is_not_an_operation() {
        let mut c = Controller::default();
        assert!(!c.cancel());
        let started = begin(&mut c, Job::Hash).unwrap();
        assert!(c.cancel());
        assert!(started.control.is_cancelled());
    }

    /// The cancel reaches the worker through the control while the hash runs: no digest, the
    /// window hears «cancelled», and the input was not read to its end.
    #[test]
    fn cancelling_stops_a_hash_that_is_reading() {
        let engine = engine();
        let mut c = Controller::default();
        let started = begin(&mut c, Job::Hash).unwrap();
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
            c.finish(started.stamp, result),
            Some(Settled::Cancelled(Job::Hash))
        );
        assert!(c.running().is_none(), "the window is free again");
    }

    /// A cancel after the work is done does not turn its digest into a cancellation.
    #[test]
    fn a_hash_that_finished_is_not_cancelled_by_a_late_cancel() {
        let engine = engine();
        let mut c = Controller::default();
        let started = begin(&mut c, Job::Hash).unwrap();
        let mut input: &[u8] = b"abc";
        let result = jobs::hash(
            &engine,
            HashAlg::Sha256,
            oncl_pki::io::Source::sequential(&mut input, Some(3)),
            &started.control,
        );
        c.cancel();
        let Some(Settled::Done(Job::Hash, out)) = c.finish(started.stamp, result) else {
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
