//! The handoff between the workers and the event loop, run for real: a Slint event loop on a
//! thread of its own, worker threads that read through the SDK's engine under the desktop's
//! [`JobControl`], and the words reaching the event loop by `slint::invoke_from_event_loop`.
//! Nothing is copied into a mock: the checks are on which thread the words arrive, in what
//! order, and whether a window that was closed, or an operation that was left, still hears them.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, mpsc};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use oncl_core::{Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationPolicy};
use oncl_pki::io::Source;
use oncl_pki::key::HashAlg;
use oncl_pki::resource::ResourceLimits;
use oncl_ui::JobControl;
use oncl_ui::progress::{Lifecycle, QUEUE_CAPACITY, Reporter, Stamp, Update};
use slint::platform::{EventLoopProxy, Platform, WindowAdapter};
use slint::{EventLoopError, PlatformError};

// ---- a real event loop on its own thread -------------------------------------------------

enum Message {
    Run(Box<dyn FnOnce() + Send>),
    Quit,
}

struct Proxy(Mutex<mpsc::Sender<Message>>);

impl EventLoopProxy for Proxy {
    fn quit_event_loop(&self) -> Result<(), EventLoopError> {
        self.0
            .lock()
            .unwrap()
            .send(Message::Quit)
            .map_err(|_| EventLoopError::EventLoopTerminated)
    }

    fn invoke_from_event_loop(
        &self,
        event: Box<dyn FnOnce() + Send>,
    ) -> Result<(), EventLoopError> {
        self.0
            .lock()
            .unwrap()
            .send(Message::Run(event))
            .map_err(|_| EventLoopError::EventLoopTerminated)
    }
}

struct Loop {
    tx: mpsc::Sender<Message>,
    rx: RefCell<Option<mpsc::Receiver<Message>>>,
}

impl Platform for Loop {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Err(PlatformError::Other("these tests open no windows".into()))
    }

    fn new_event_loop_proxy(&self) -> Option<Box<dyn EventLoopProxy>> {
        Some(Box::new(Proxy(Mutex::new(self.tx.clone()))))
    }

    fn run_event_loop(&self) -> Result<(), PlatformError> {
        let rx = self.rx.borrow_mut().take().expect("the loop runs once");
        while let Ok(Message::Run(event)) = rx.recv() {
            event();
            slint::platform::update_timers_and_animations();
        }
        Ok(())
    }
}

struct Ui {
    tx: mpsc::Sender<Message>,
    thread: ThreadId,
}

/// The one event loop of this test process, started on first use.
static UI: LazyLock<Ui> = LazyLock::new(|| {
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::Builder::new()
        .name("event-loop".into())
        .spawn(move || {
            let (tx, rx) = mpsc::channel();
            let platform = Loop {
                tx: tx.clone(),
                rx: RefCell::new(Some(rx)),
            };
            slint::platform::set_platform(Box::new(platform)).expect("no platform yet");
            ready_tx.send((tx, thread::current().id())).unwrap();
            slint::run_event_loop().expect("the event loop runs");
        })
        .unwrap();
    let (tx, thread) = ready_rx.recv().unwrap();
    Ui { tx, thread }
});

fn ui() -> &'static Ui {
    &UI
}

/// Runs `f` on the event loop's thread and returns what it returns.
fn on_ui<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    ui().tx
        .send(Message::Run(Box::new(move || {
            tx.send(f()).unwrap();
        })))
        .unwrap();
    rx.recv_timeout(Duration::from_secs(60))
        .expect("the event loop answers")
}

/// Holds the event loop busy until the returned guard is dropped: whatever the workers say
/// meanwhile waits in the event queue, behind this.
struct Busy(mpsc::Sender<()>);

fn hold_the_event_loop() -> Busy {
    let (hold_tx, hold_rx) = mpsc::channel::<()>();
    let (started_tx, started_rx) = mpsc::channel();
    ui().tx
        .send(Message::Run(Box::new(move || {
            started_tx.send(()).unwrap();
            let _ = hold_rx.recv();
        })))
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(60)).unwrap();
    Busy(hold_tx)
}

impl Drop for Busy {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

// ---- windows, as the event loop keeps them -------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Heard {
    Progress {
        update: Update,
        thread: ThreadId,
    },
    Settled {
        result: Result<String, ErrorCode>,
        thread: ThreadId,
    },
}

/// What a window does with what the workers say: the same [`Lifecycle`] the tools window uses
/// decides whether a word is for it.
struct Window {
    life: RefCell<Lifecycle>,
    heard: RefCell<Vec<Heard>>,
}

/// How many words reached the event loop and were not for the window that is open.
struct Refused {
    progress: AtomicU64,
    settled: AtomicU64,
}

static REFUSED: Refused = Refused {
    progress: AtomicU64::new(0),
    settled: AtomicU64::new(0),
};

/// The tests share one event loop and one «open window», as the application does: they take
/// turns.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

thread_local! {
    /// The window that is open: the tools window keeps its one the same way, and a word of a
    /// worker is looked for only there.
    static CURRENT: RefCell<Option<Rc<Window>>> = const { RefCell::new(None) };
    /// Every window the test opened, to read what each heard after it was closed.
    static ALL: RefCell<HashMap<u64, Rc<Window>>> = RefCell::new(HashMap::new());
}

fn current() -> Option<Rc<Window>> {
    CURRENT.with_borrow(Clone::clone)
}

/// Runs on the event loop for every progress word, like the tools window's own.
fn apply(stamp: Stamp, update: Update) {
    match current() {
        Some(w) if w.life.borrow().accepts(stamp) => {
            w.heard.borrow_mut().push(Heard::Progress {
                update,
                thread: thread::current().id(),
            });
        }
        _ => {
            REFUSED.progress.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Runs on the event loop for the outcome of an operation.
fn settle(stamp: Stamp, result: Result<String, ErrorCode>) {
    match current() {
        Some(w) if w.life.borrow_mut().end(stamp) => {
            w.heard.borrow_mut().push(Heard::Settled {
                result,
                thread: thread::current().id(),
            });
        }
        _ => {
            REFUSED.settled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// An operation of the open window, made on the event loop.
struct Started {
    stamp: Stamp,
    control: Arc<JobControl>,
}

/// Opens a window; the one open before it, if any, is closed first.
fn open_window() -> u64 {
    on_ui(|| {
        close_current();
        let w = Rc::new(Window {
            life: RefCell::new(Lifecycle::new()),
            heard: RefCell::default(),
        });
        let id = w.life.borrow().window();
        ALL.with_borrow_mut(|all| all.insert(id, Rc::clone(&w)));
        CURRENT.set(Some(w));
        id
    })
}

/// The open window is closed: it hears nothing from now on.
fn close_current() {
    if let Some(w) = CURRENT.take() {
        w.life.borrow_mut().close();
    }
}

fn begin() -> Started {
    on_ui(move || {
        let w = current().expect("a window is open");
        let stamp = w.life.borrow_mut().begin().expect("the window is free");
        Started {
            stamp,
            control: Arc::new(JobControl::reporting(Reporter::new(stamp, apply))),
        }
    })
}

fn heard(window: u64) -> Vec<Heard> {
    on_ui(move || {
        ALL.with_borrow(|all| all.get(&window).cloned())
            .map(|w| w.heard.borrow().clone())
            .unwrap_or_default()
    })
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "timed out: {what}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

// ---- workers: the real engine under the real control ---------------------------------------

/// Deterministic bytes: the digest of the same bytes made another way is the oracle.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn expected_digest(bytes: &[u8]) -> String {
    hex(&HashAlg::Sha256.digest(bytes))
}

/// A reader that serves `bytes` in `chunk`-sized reads and stops at `gate` bytes until it is
/// opened, so that a test decides what the worker has done when it looks.
struct Gated {
    bytes: Arc<Vec<u8>>,
    at: usize,
    chunk: usize,
    gate: Option<(usize, Arc<Gate>)>,
}

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
    reached: AtomicBool,
}

impl Gate {
    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }

    fn wait_open(&self) {
        self.reached.store(true, Ordering::SeqCst);
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.changed.wait(open).unwrap();
        }
    }
}

impl Read for Gated {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some((at, gate)) = &self.gate
            && self.at >= *at
        {
            gate.wait_open();
        }
        let n = buf.len().min(self.chunk).min(self.bytes.len() - self.at);
        buf[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

fn engine() -> Engine {
    Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap()
}

/// Hashes `reader` under `control`, as the tools window's hash does, and tells the event
/// loop how it ended.
fn work(
    stamp: Stamp,
    control: Arc<JobControl>,
    bytes: Arc<Vec<u8>>,
    chunk: usize,
    gate: Option<(usize, Arc<Gate>)>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let engine = engine();
        let mut reader = Gated {
            bytes: Arc::clone(&bytes),
            at: 0,
            chunk,
            gate,
        };
        control.set_total(bytes.len() as u64);
        let result = engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                control.clone(),
            )
            .and_then(|mut ctx| {
                engine.hash(
                    HashAlg::Sha256,
                    Source::sequential(&mut reader, Some(bytes.len() as u64)),
                    &mut ctx,
                )
            })
            .map(|report| hex(report.digest.as_bytes()))
            .map_err(|e| e.code());
        assert_eq!(stamp, control.reporter().unwrap().stamp());
        control.reporter().unwrap().finish(result, settle);
    })
}

// ---- the cases -----------------------------------------------------------------------------

/// Progress and the outcome arrive on the event loop's thread, in order, and the outcome is
/// the digest of what was read (compared with the digest of the same bytes made in one piece).
#[test]
fn progress_and_outcome_arrive_on_the_event_loop_thread() {
    let _turn = serial();
    let bytes = Arc::new(pattern(6 << 20));
    let window = open_window();
    let started = begin();
    work(
        started.stamp,
        started.control,
        Arc::clone(&bytes),
        64 << 10,
        None,
    )
    .join()
    .unwrap();
    wait_until("the outcome", || {
        heard(window)
            .iter()
            .any(|h| matches!(h, Heard::Settled { .. }))
    });
    let log = heard(window);
    let ui_thread = ui().thread;
    assert_ne!(ui_thread, thread::current().id());
    let mut last = 0;
    let mut progress = 0;
    for entry in &log {
        match entry {
            Heard::Progress { update, thread } => {
                assert_eq!(*thread, ui_thread, "progress is shown on the event loop");
                assert!(update.bytes_in >= last, "progress only grows: {log:?}");
                last = update.bytes_in;
                progress += 1;
            }
            Heard::Settled { result, thread } => {
                assert_eq!(
                    *thread, ui_thread,
                    "the outcome is settled on the event loop"
                );
                assert_eq!(result, &Ok(expected_digest(&bytes)));
            }
        }
    }
    assert!(
        progress >= 1,
        "a 6 MiB read told the window how far it was: {log:?}"
    );
    assert_eq!(
        log.iter()
            .filter(|h| matches!(h, Heard::Settled { .. }))
            .count(),
        1,
        "the outcome is told once"
    );
    assert!(
        matches!(log.last(), Some(Heard::Settled { .. })),
        "nothing is shown after the outcome: {log:?}"
    );
}

/// THE lifecycle case: the window is closed while its worker is still working and another is
/// opened. What the closed window's worker says afterwards, progress and outcome, reaches the
/// event loop (it is not swallowed on the way) and is refused there by the window that is
/// open: the new window's own operation is unharmed, and shows none of it.
#[test]
fn closed_window_not_replaced_by_late_progress() {
    let _turn = serial();
    let bytes = Arc::new(pattern(4 << 20));
    let (refused_progress, refused_settled) = (
        REFUSED.progress.load(Ordering::SeqCst),
        REFUSED.settled.load(Ordering::SeqCst),
    );
    let old = open_window();
    let old_started = begin();
    let old_stamp = old_started.stamp;
    let (new, new_started);
    {
        // The event loop is busy: what the old window's worker says queues up behind what
        // the user does meanwhile, in the order the application would have met it.
        let busy = hold_the_event_loop();
        // The user closes the window and opens another one, and starts an operation in it.
        let (opened_tx, opened_rx) = mpsc::channel();
        let control = Arc::clone(&old_started.control);
        ui().tx
            .send(Message::Run(Box::new(move || {
                close_current();
                // The closed window's operation is asked to stop, as the window does.
                control.cancel();
                let w = Rc::new(Window {
                    life: RefCell::new(Lifecycle::new()),
                    heard: RefCell::default(),
                });
                let id = w.life.borrow().window();
                let stamp = w.life.borrow_mut().begin().unwrap();
                ALL.with_borrow_mut(|all| all.insert(id, Rc::clone(&w)));
                CURRENT.set(Some(w));
                opened_tx
                    .send((
                        id,
                        Started {
                            stamp,
                            control: Arc::new(JobControl::reporting(Reporter::new(stamp, apply))),
                        },
                    ))
                    .unwrap();
            })))
            .unwrap();
        // The worker of the closed window has not noticed the cancel yet, as a worker blocked in
        // a read does not: it passes its checkpoints (a fresh control stands for the moment
        // before the cancel), reporting as it goes, then ends and reports its outcome.
        let gate = Arc::new(Gate::default());
        let worker = work(
            old_stamp,
            Arc::new(JobControl::reporting(Reporter::new(old_stamp, apply))),
            Arc::clone(&bytes),
            64 << 10,
            Some((1 << 20, Arc::clone(&gate))),
        );
        wait_until("the old worker reads on", || {
            gate.reached.load(Ordering::SeqCst)
        });
        gate.open();
        worker.join().unwrap();
        drop(busy);
        (new, new_started) = opened_rx.recv_timeout(Duration::from_secs(60)).unwrap();
    }
    // The new window runs its own operation to its end.
    work(
        new_started.stamp,
        new_started.control,
        Arc::new(pattern(2 << 20)),
        64 << 10,
        None,
    )
    .join()
    .unwrap();
    wait_until("the new window's outcome", || {
        heard(new)
            .iter()
            .any(|h| matches!(h, Heard::Settled { .. }))
    });
    // Everything the closed window's worker said reached the event loop and was refused there.
    wait_until("the late words are refused", || {
        REFUSED.settled.load(Ordering::SeqCst) > refused_settled
            && REFUSED.progress.load(Ordering::SeqCst) > refused_progress
    });
    assert_ne!(old_stamp.window, new_started.stamp.window);
    assert!(
        heard(old).is_empty(),
        "the closed window hears nothing: {:?}",
        heard(old)
    );
    let log = heard(new);
    assert_eq!(
        log.iter()
            .filter(|h| matches!(h, Heard::Settled { .. }))
            .count(),
        1,
        "{log:?}"
    );
    assert!(
        log.iter().all(|h| match h {
            Heard::Settled { result, .. } => result == &Ok(expected_digest(&pattern(2 << 20))),
            Heard::Progress { update, .. } => update.bytes_in <= 2 << 20,
        }),
        "only the new window's own words are in its log: {log:?}"
    );
}

/// A cancel from the event loop reaches the worker through the control; the worker stops at
/// its next checkpoint and the window hears «cancelled» once, as the outcome, not as success
/// and not as silence.
#[test]
fn cancel_reaches_the_worker_and_the_outcome_is_delivered() {
    let _turn = serial();
    let bytes = Arc::new(pattern(8 << 20));
    let window = open_window();
    let started = begin();
    let gate = Arc::new(Gate::default());
    let worker = work(
        started.stamp,
        Arc::clone(&started.control),
        Arc::clone(&bytes),
        64 << 10,
        Some((2 << 20, Arc::clone(&gate))),
    );
    wait_until("the worker is mid-way", || {
        gate.reached.load(Ordering::SeqCst)
    });
    let control = Arc::clone(&started.control);
    on_ui(move || control.cancel());
    gate.open();
    worker.join().unwrap();
    wait_until("the outcome", || {
        heard(window)
            .iter()
            .any(|h| matches!(h, Heard::Settled { .. }))
    });
    let log = heard(window);
    let settled: Vec<_> = log
        .iter()
        .filter_map(|h| match h {
            Heard::Settled { result, thread } => Some((result.clone(), *thread)),
            Heard::Progress { .. } => None,
        })
        .collect();
    assert_eq!(settled, vec![(Err(ErrorCode::Cancelled), ui().thread)]);
    let (read, _) = started.control.progress();
    assert!(
        read < bytes.len() as u64,
        "the input was not read to its end: {read}"
    );
}

/// A window that cannot keep up costs the worker nothing and loses nothing that matters: the
/// queue stays bounded, one wake-up asks for a read, the latest word survives, and the outcome,
/// which does not travel through that queue, is delivered whatever was dropped.
#[test]
fn a_busy_window_coalesces_progress_and_never_loses_the_outcome() {
    let _turn = serial();
    let window = open_window();
    let started = begin();
    let reporter = started.control.reporter().unwrap().clone();
    {
        let _busy = hold_the_event_loop();
        for n in 1..=10_000u64 {
            reporter.report(Update {
                bytes_in: n,
                ..Update::default()
            });
        }
        assert_eq!(reporter.queued(), QUEUE_CAPACITY, "the queue is bounded");
        assert_eq!(reporter.wakes(), 1, "one wake-up however many words");
        assert_eq!(reporter.coalesced(), 10_000 - QUEUE_CAPACITY as u64);
        reporter.finish(Ok("done".to_owned()), settle);
    }
    wait_until("the outcome", || {
        heard(window)
            .iter()
            .any(|h| matches!(h, Heard::Settled { .. }))
    });
    let log = heard(window);
    // The words that were kept are the newest, in order, and the outcome follows them.
    assert!(
        matches!(log.last(), Some(Heard::Settled { result: Ok(text), .. }) if text == "done"),
        "{log:?}"
    );
    let words: Vec<u64> = log
        .iter()
        .filter_map(|h| match h {
            Heard::Progress { update, .. } => Some(update.bytes_in),
            Heard::Settled { .. } => None,
        })
        .collect();
    assert_eq!(words.len(), QUEUE_CAPACITY, "{log:?}");
    assert_eq!(
        words.last(),
        Some(&10_000),
        "the latest word survives: {words:?}"
    );
    assert!(words.windows(2).all(|w| w[0] < w[1]), "{words:?}");
}
