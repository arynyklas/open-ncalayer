//! Request handling shared by the WebSocket server and the browser extension bridge,
//! whether a request is being answered ([`requests_idle`]: an update waits for it), and
//! holding new requests back while an update is applied ([`hold_requests`]).

use std::thread;

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oncl_protocol::{AddInfo, Registry, Route, module_not_found};
use tracing::debug;

/// The module requests being answered, by the wss servers and the bridge together, and when
/// the last one ended.
struct Activity {
    in_flight: AtomicUsize,
    last_end: Mutex<Option<Instant>>,
    /// New requests wait while this is set.
    held: AtomicBool,
}

static ACTIVITY: Activity = Activity::new();

/// How often a held request looks whether it may go on.
const HELD_POLL: Duration = Duration::from_millis(50);

/// A module request being answered, from [`Activity::begin`] to its drop.
struct Answering<'a>(&'a Activity);

impl Activity {
    const fn new() -> Activity {
        Activity {
            in_flight: AtomicUsize::new(0),
            last_end: Mutex::new(None),
            held: AtomicBool::new(false),
        }
    }

    /// Counts a request in; while requests are held, waits first. The count goes up before
    /// `held` is read, and [`Activity::hold`] sets `held` before it reads the count, so a
    /// request either waits or is seen.
    fn begin(&self) -> Answering<'_> {
        loop {
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            if !self.held.load(Ordering::SeqCst) {
                return Answering(self);
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            while self.held.load(Ordering::SeqCst) {
                thread::sleep(HELD_POLL);
            }
        }
    }

    /// Holds new requests back; whether the activity is still [`Activity::idle`] for
    /// `quiet`, looked at only after the hold is in place (with the time from `now` read
    /// then): a request that ended while the caller was busy elsewhere, after its own
    /// look, still counts. If it is not idle, they are let through again.
    fn hold(&self, quiet: Duration, now: impl FnOnce() -> Instant) -> bool {
        self.held.store(true, Ordering::SeqCst);
        if self.idle(quiet, now()) {
            return true;
        }
        self.release();
        false
    }

    fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
    }

    /// Whether no request is being answered and none ended within `quiet` before `now`.
    fn idle(&self, quiet: Duration, now: Instant) -> bool {
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            return false;
        }
        let last_end = *self.last_end.lock().unwrap_or_else(PoisonError::into_inner);
        last_end.is_none_or(|end| now.saturating_duration_since(end) >= quiet)
    }
}

impl Drop for Answering<'_> {
    fn drop(&mut self) {
        *self
            .0
            .last_end
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Whether no page's request (a module call over wss or the bridge; heartbeats do not count)
/// is being answered, and none ended within `quiet`: a signing flow of several requests is
/// not cut between them.
pub fn requests_idle(quiet: Duration) -> bool {
    ACTIVITY.idle(quiet, Instant::now())
}

/// Holds back page requests that arrive from now on (they wait, and end with the process
/// that applies an update); whether no request is being answered and none ended within
/// `quiet`, looked at once the hold is in place. If that is not so, nothing is held.
pub fn hold_requests(quiet: Duration) -> bool {
    ACTIVITY.hold(quiet, Instant::now)
}

/// Lets held requests through again.
pub fn release_requests() {
    ACTIVITY.release();
}

/// The reply to a request, or `None` to drop the connection (the request is not a JSON
/// object). The heartbeat is echoed.
pub(crate) fn dispatch(registry: &Registry, text: &str, add_info: &AddInfo) -> Option<String> {
    match registry.route(text) {
        Route::Heartbeat => Some(text.to_owned()),
        Route::Module(module) => {
            let _answering = ACTIVITY.begin();
            Some(module.process(text, add_info))
        }
        Route::NotFound => Some(module_not_found()),
        Route::InvalidJson => None,
    }
}

/// [`dispatch`] on the blocking pool: routing parses the whole request (possibly tens of
/// megabytes) and a module call may wait for a dialog, so neither may hold up the runtime.
///
/// # Errors
///
/// The module call panicked.
pub(crate) async fn process<T>(
    registry: &Arc<Registry>,
    text: T,
    add_info: &AddInfo,
) -> io::Result<Option<String>>
where
    T: AsRef<str> + Send + 'static,
{
    let registry = Arc::clone(registry);
    let add_info = add_info.clone();
    let len = text.as_ref().len();
    let answer = tokio::task::spawn_blocking(move || dispatch(&registry, text.as_ref(), &add_info))
        .await
        .map_err(io::Error::other)?;
    if let Some(reply) = &answer {
        debug!(
            request_len = len,
            reply_len = reply.len(),
            "request answered"
        );
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_counts_requests_and_their_quiet() {
        let activity = Activity::new();
        let quiet = Duration::from_secs(30);
        let now = Instant::now();
        assert!(activity.idle(quiet, now), "nothing ever ran");
        let a = activity.begin();
        let b = activity.begin();
        assert!(!activity.idle(quiet, now));
        drop(a);
        assert!(!activity.idle(quiet, Instant::now()), "one still runs");
        drop(b);
        let ended = Instant::now();
        assert!(!activity.idle(quiet, ended + Duration::from_secs(29)));
        assert!(activity.idle(quiet, ended + quiet));
    }

    #[test]
    fn held_requests_wait_and_a_running_one_prevents_the_hold() {
        let quiet = Duration::from_secs(30);
        let activity = std::sync::Arc::new(Activity::new());
        let running = activity.begin();
        let later = || Instant::now() + Duration::from_secs(3600);
        assert!(!activity.hold(quiet, later), "a request is being answered");
        assert!(!activity.held.load(Ordering::SeqCst));
        drop(running);
        assert!(activity.hold(quiet, later));
        let waiting = std::sync::Arc::clone(&activity);
        let request = thread::spawn(move || drop(waiting.begin()));
        thread::sleep(HELD_POLL * 3);
        assert!(!request.is_finished(), "a held request waits");
        assert_eq!(activity.in_flight.load(Ordering::SeqCst), 0);
        activity.release();
        request.join().unwrap();
    }

    #[test]
    fn the_hold_looks_at_the_quiet_time_again() {
        let quiet = Duration::from_secs(30);
        let activity = Activity::new();
        // The updater saw an idle daemon, then re-checked the index; meanwhile a request
        // came and went.
        assert!(activity.idle(quiet, Instant::now()));
        drop(activity.begin());
        let ended = activity
            .last_end
            .lock()
            .unwrap()
            .expect("the request ended");
        // Within the quiet time of its end, up to its last moment: nothing is held.
        for after in [
            Duration::ZERO,
            Duration::from_secs(1),
            quiet - Duration::from_millis(1),
        ] {
            assert!(!activity.hold(quiet, || ended + after), "{after:?}");
            assert!(!activity.held.load(Ordering::SeqCst), "{after:?}");
        }
        // From the end of the quiet time on, the hold takes.
        assert!(activity.hold(quiet, || ended + quiet));
        assert!(activity.held.load(Ordering::SeqCst));
    }
}
