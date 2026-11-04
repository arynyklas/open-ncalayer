//! What a running operation tells its window, and how the word gets to the event loop.
//!
//! A worker holds only `Arc`s and atomics ([`JobControl`](super::controller::JobControl)), a
//! bounded queue of [`Update`]s ([`Reporter`]) and the [`Stamp`] of the window and the
//! operation it works for. Nothing with `Rc`, `RefCell` or a Slint handle ever crosses: the
//! worker never calls the UI, not from a checkpoint and not from anywhere else. It queues a
//! word and, when none is waiting yet, asks the event loop to read the queue with
//! [`slint::invoke_from_event_loop`]; the event loop then finds the window by the stamp
//! ([`Lifecycle`]) and shows what it holds.
//!
//! * The queue is bounded ([`QUEUE_CAPACITY`]). Progress is cumulative, so when it is full the
//!   newest word replaces the one behind it: a slow window costs the worker nothing and never
//!   makes it wait, and the latest value is never the one that is dropped.
//! * One wake-up is outstanding at a time however many words are queued.
//! * The outcome of an operation does not travel through that queue: [`Reporter::finish`]
//!   hands it to the event loop on its own, so a full queue cannot lose it.
//! * A word carries the window id and the generation of the operation. A window that was
//!   closed, or an operation that was left, no longer accepts it, and a window opened since
//!   never takes it for its own ([`Lifecycle::accepts`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// How many words may wait for the event loop. Beyond it the newest replaces the one behind
/// it ([`Reporter::report`]).
pub const QUEUE_CAPACITY: usize = 8;

/// The window and the operation a word belongs to. Both numbers are unique in the process, so
/// the late word of a window that was closed never matches the window opened next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stamp {
    pub window: u64,
    pub generation: u64,
}

static NEXT_WINDOW: AtomicU64 = AtomicU64::new(1);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// How far an operation is. Cumulative: only the latest word matters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Update {
    /// Bytes read so far, over the whole operation.
    pub bytes_in: u64,
    /// The size of what is read, when it is known: unknown lengths are shown as such.
    pub total: Option<u64>,
    /// How many documents the operation works on (0: it is not a batch), and how many of them
    /// have begun: 0 while the batch is being prepared (frozen), then the number of the
    /// document being processed (1-based).
    pub items: usize,
    pub started: usize,
}

/// The event loop's authority over one window: which operation it still listens to. It lives
/// with the window, on the event loop only; the stamp that comes from a worker is checked here
/// before anything is shown or settled.
#[derive(Debug)]
pub struct Lifecycle {
    window: u64,
    running: Option<u64>,
    closed: bool,
}

impl Lifecycle {
    /// A new window, with an id no window has had.
    pub fn new() -> Lifecycle {
        Lifecycle {
            window: NEXT_WINDOW.fetch_add(1, Ordering::Relaxed),
            running: None,
            closed: false,
        }
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    /// Starts an operation, unless the window is closed or one runs already.
    pub fn begin(&mut self) -> Option<Stamp> {
        if self.closed || self.running.is_some() {
            return None;
        }
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        self.running = Some(generation);
        Some(Stamp {
            window: self.window,
            generation,
        })
    }

    /// The operation that runs, if any.
    pub fn running(&self) -> Option<Stamp> {
        self.running.map(|generation| Stamp {
            window: self.window,
            generation,
        })
    }

    /// Whether a word of `stamp` is still for this window's running operation.
    pub fn accepts(&self, stamp: Stamp) -> bool {
        !self.closed && stamp.window == self.window && self.running == Some(stamp.generation)
    }

    /// Takes the outcome of `stamp`: `true` once, for the running operation; any other (a
    /// repeat, a left operation, another window's) is refused and changes nothing.
    pub fn end(&mut self, stamp: Stamp) -> bool {
        if !self.accepts(stamp) {
            return false;
        }
        self.running = None;
        true
    }

    /// The window is closed: nothing a worker says is accepted from now on. The caller asks
    /// the running operation to stop.
    pub fn close(&mut self) {
        self.closed = true;
        self.running = None;
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle::new()
    }
}

/// How a closure gets to the event loop.
pub type Deliver = fn(Box<dyn FnOnce() + Send>);

fn invoke_from_event_loop(f: Box<dyn FnOnce() + Send>) {
    if let Err(e) = slint::invoke_from_event_loop(f) {
        tracing::warn!(error = %e, "a worker's word is lost: the event loop is gone");
    }
}

struct Shared {
    stamp: Stamp,
    queue: Mutex<VecDeque<Update>>,
    wake_pending: AtomicBool,
    coalesced: AtomicU64,
    wakes: AtomicU64,
    /// Shows one word; runs on the event loop.
    apply: fn(Stamp, Update),
    deliver: Deliver,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Update>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs on the event loop: reads what waits, in order.
    fn drain(&self) {
        // Cleared before the queue is taken: a word queued from here on asks for its own
        // wake-up, and one queued before it is in what is taken.
        self.wake_pending.store(false, Ordering::SeqCst);
        let words: Vec<Update> = self.lock().drain(..).collect();
        for word in words {
            (self.apply)(self.stamp, word);
        }
    }
}

/// The worker's side of the handoff of one operation: `Send + Sync`, cheap to clone.
#[derive(Clone)]
pub struct Reporter {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Reporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reporter")
            .field("stamp", &self.shared.stamp)
            .field("queued", &self.queued())
            .finish_non_exhaustive()
    }
}

impl Reporter {
    /// A reporter for the operation `stamp`; `apply` runs on the event loop for every word.
    pub fn new(stamp: Stamp, apply: fn(Stamp, Update)) -> Reporter {
        Reporter::with_delivery(stamp, apply, invoke_from_event_loop)
    }

    /// As [`Reporter::new`], with another way to reach the event loop (the tests of the
    /// windows have none and pump their queue).
    pub(crate) fn with_delivery(
        stamp: Stamp,
        apply: fn(Stamp, Update),
        deliver: Deliver,
    ) -> Reporter {
        Reporter {
            shared: Arc::new(Shared {
                stamp,
                queue: Mutex::new(VecDeque::with_capacity(QUEUE_CAPACITY)),
                wake_pending: AtomicBool::new(false),
                coalesced: AtomicU64::new(0),
                wakes: AtomicU64::new(0),
                apply,
                deliver,
            }),
        }
    }

    pub fn stamp(&self) -> Stamp {
        self.shared.stamp
    }

    /// Queues a word and, if the event loop has not been asked yet, asks it to read the
    /// queue. Never waits for the event loop and never touches the UI. When the queue is
    /// full the newest word replaces the one behind it, so the latest is always kept.
    pub fn report(&self, update: Update) {
        let shared = &self.shared;
        {
            let mut queue = shared.lock();
            if queue.len() >= QUEUE_CAPACITY {
                queue.pop_back();
                shared.coalesced.fetch_add(1, Ordering::Relaxed);
            }
            queue.push_back(update);
        }
        if !shared.wake_pending.swap(true, Ordering::SeqCst) {
            shared.wakes.fetch_add(1, Ordering::Relaxed);
            let shared = Arc::clone(shared);
            (self.shared.deliver)(Box::new(move || shared.drain()));
        }
    }

    /// Hands the outcome to the event loop: on its own path, never through the bounded queue,
    /// so that however many words were dropped, this one is not. Words still waiting are
    /// dropped: the outcome says more than they do.
    pub fn finish<T: Send + 'static>(&self, outcome: T, settle: fn(Stamp, T)) {
        let shared = Arc::clone(&self.shared);
        (self.shared.deliver)(Box::new(move || {
            shared.lock().clear();
            settle(shared.stamp, outcome);
        }));
    }

    /// How many words were replaced by a newer one because the queue was full.
    pub fn coalesced(&self) -> u64 {
        self.shared.coalesced.load(Ordering::Relaxed)
    }

    /// How many times the event loop was asked to read the queue.
    pub fn wakes(&self) -> u64 {
        self.shared.wakes.load(Ordering::Relaxed)
    }

    /// How many words wait now.
    pub fn queued(&self) -> usize {
        self.shared.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static SEEN: std::cell::RefCell<Vec<(Stamp, Update)>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn seen(stamp: Stamp, update: Update) {
        SEEN.with_borrow_mut(|s| s.push((stamp, update)));
    }

    type Held = Mutex<Vec<Box<dyn FnOnce() + Send>>>;
    static HELD: Held = Mutex::new(Vec::new());

    fn hold(f: Box<dyn FnOnce() + Send>) {
        HELD.lock().unwrap().push(f);
    }

    fn at(n: u64) -> Update {
        Update {
            bytes_in: n,
            ..Update::default()
        }
    }

    /// The window decides what it listens to: the running operation only, once.
    #[test]
    fn a_lifecycle_listens_to_its_running_operation_only() {
        let mut life = Lifecycle::new();
        let a = life.begin().unwrap();
        assert!(life.begin().is_none(), "one operation at a time");
        let stranger = Stamp {
            window: a.window + 1000,
            generation: a.generation,
        };
        assert!(life.accepts(a) && !life.accepts(stranger));
        assert!(!life.end(Stamp {
            generation: a.generation + 1,
            ..a
        }));
        assert!(life.end(a));
        assert!(!life.end(a), "an outcome is taken once");
        assert!(!life.accepts(a), "a left operation is not listened to");
        let b = life.begin().unwrap();
        assert_ne!(a.generation, b.generation);
        life.close();
        assert!(!life.accepts(b) && life.begin().is_none());
    }

    #[test]
    fn two_windows_never_share_a_stamp() {
        let (mut a, mut b) = (Lifecycle::new(), Lifecycle::new());
        assert_ne!(a.window(), b.window());
        let (sa, sb) = (a.begin().unwrap(), b.begin().unwrap());
        assert!(!a.accepts(sb) && !b.accepts(sa));
    }

    /// Many words while the event loop is busy: one wake-up, a bounded queue, the latest kept.
    #[test]
    fn a_full_queue_replaces_the_newest_and_keeps_the_latest() {
        HELD.lock().unwrap().clear();
        let stamp = Stamp {
            window: 1,
            generation: 1,
        };
        let reporter = Reporter::with_delivery(stamp, seen, hold);
        for n in 1..=1000 {
            reporter.report(at(n));
        }
        assert_eq!(reporter.queued(), QUEUE_CAPACITY);
        assert_eq!(reporter.wakes(), 1, "one wake-up however many words");
        assert_eq!(reporter.coalesced(), 1000 - QUEUE_CAPACITY as u64);
        let wakes: Vec<_> = std::mem::take(&mut *HELD.lock().unwrap());
        assert_eq!(wakes.len(), 1);
        SEEN.with_borrow_mut(Vec::clear);
        for wake in wakes {
            wake();
        }
        let got = SEEN.with_borrow(Clone::clone);
        assert_eq!(got.len(), QUEUE_CAPACITY);
        assert_eq!(got.last().unwrap().1.bytes_in, 1000, "the latest survives");
        assert!(got.windows(2).all(|w| w[0].1.bytes_in < w[1].1.bytes_in));
        assert!(got.iter().all(|(s, _)| *s == stamp));
        // After a read the next word asks again.
        reporter.report(at(1001));
        assert_eq!(reporter.wakes(), 2);
    }
}
