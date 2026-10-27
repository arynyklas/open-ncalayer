//! The jobs of the daemon's windows (settings, the TLS wizard): one at a time per window, on a
//! worker thread, while the window waits (`busy`) and cannot be closed, so that it shows the
//! outcome. The outcome comes back on the event loop to the window that started the job, found
//! again by its id; if that window is gone, the job's `done` still runs without it (a saved
//! setting takes effect anyway). A job that panics frees its window, which says the action
//! failed.

use std::panic::{self, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::Arc;

use slint::CloseRequestResponse;

use crate::prompter::panic_text;
use crate::windows::{self, Desktop};

/// A window whose actions run as jobs.
pub(crate) trait JobWindow: 'static {
    /// What its jobs work with.
    type Services: Send + Sync + 'static;
    /// The jobs' thread name; also how the log names the window.
    const NAME: &'static str;

    /// The window `id`, if it is still open.
    fn find(id: u64) -> Option<Rc<Self>>;
    fn id(&self) -> u64;
    fn desktop(&self) -> &Rc<Desktop>;
    fn services(&self) -> Arc<Self::Services>;
    fn busy(&self) -> bool;
    fn set_busy(&self, busy: bool);
    fn show_message(&self, text: &str, error: bool);
    /// «The action failed», in the window's language: for a job that cannot start or that
    /// broke off.
    fn failure_text(&self) -> &'static str;
}

/// Runs `f` with the window `id`, if it is open.
pub(crate) fn with<W: JobWindow>(id: u64, f: impl FnOnce(&W)) {
    if let Some(window) = W::find(id) {
        f(&window);
    }
}

/// A close request of the window `id`: refused while a job runs (its outcome must be seen),
/// otherwise `close` closes it.
pub(crate) fn close_requested<W: JobWindow>(
    id: u64,
    close: impl FnOnce(u64),
) -> CloseRequestResponse {
    if W::find(id).is_some_and(|window| window.busy()) {
        return CloseRequestResponse::KeepWindowShown;
    }
    close(id);
    CloseRequestResponse::HideWindow
}

/// Runs `job` on a worker thread while `window` waits; then [`finish`] hands the result to
/// `done` on the event loop.
pub(crate) fn run<W: JobWindow, T: Send + 'static>(
    window: &W,
    job: impl FnOnce(&W::Services) -> T + Send + 'static,
    done: impl FnOnce(&Desktop, Option<&W>, T) + Send + 'static,
) {
    window.set_busy(true);
    let services = window.services();
    let id = window.id();
    let work = move || panic::catch_unwind(AssertUnwindSafe(|| job(&services)));
    #[cfg(test)]
    if manual::enabled() {
        manual::push(Box::new(move || finish::<W, T>(id, work(), done)));
        return;
    }
    let spawned = std::thread::Builder::new()
        .name(W::NAME.into())
        .spawn(move || {
            let outcome = work();
            let delivered =
                slint::invoke_from_event_loop(move || finish::<W, T>(id, outcome, done));
            if let Err(e) = delivered {
                tracing::warn!(window = W::NAME, error = %e, "a job's result is lost");
            }
        });
    if let Err(e) = spawned {
        tracing::error!(window = W::NAME, error = %e, "cannot start a worker thread");
        window.set_busy(false);
        window.show_message(window.failure_text(), true);
    }
}

/// Hands a job's `outcome` to `done`, with the daemon's windows and the window `id` if it is
/// still open (it waits no longer). A panic is logged and shown instead; `done` does not run.
pub(crate) fn finish<W: JobWindow, T>(
    id: u64,
    outcome: std::thread::Result<T>,
    done: impl FnOnce(&Desktop, Option<&W>, T),
) {
    let window = W::find(id);
    if let Some(window) = &window {
        window.set_busy(false);
    }
    let result = match outcome {
        Ok(result) => result,
        Err(panic) => {
            tracing::error!(
                window = W::NAME,
                panic = panic_text(&*panic),
                "a job broke off"
            );
            if let Some(window) = &window {
                window.show_message(window.failure_text(), true);
            }
            return;
        }
    };
    let desktop = window
        .as_ref()
        .map(|window| Rc::clone(window.desktop()))
        .or_else(windows::desktop);
    match desktop {
        Some(desktop) => done(&desktop, window.as_deref(), result),
        None => tracing::warn!(window = W::NAME, "a job's result without the windows"),
    }
}

/// Jobs run when the test says, on the test's thread: no worker threads, no event loop.
#[cfg(test)]
pub(crate) mod manual {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    type Task = Box<dyn FnOnce()>;

    thread_local! {
        static QUEUE: RefCell<Option<VecDeque<Task>>> = const { RefCell::new(None) };
    }

    /// From now on this thread's jobs wait in a queue for [`run_all`].
    pub(crate) fn enable() {
        QUEUE.set(Some(VecDeque::new()));
    }

    pub(super) fn enabled() -> bool {
        QUEUE.with_borrow(Option::is_some)
    }

    pub(super) fn push(task: Task) {
        QUEUE.with_borrow_mut(|queue| {
            queue
                .as_mut()
                .expect("manual jobs are enabled")
                .push_back(task);
        });
    }

    /// Runs the queued jobs, and those they queue, in order; how many ran.
    pub(crate) fn run_all() -> usize {
        let mut ran = 0;
        while let Some(task) = QUEUE.with_borrow_mut(|queue| queue.as_mut()?.pop_front()) {
            task();
            ran += 1;
        }
        ran
    }
}
