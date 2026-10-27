//! Request handling shared by the WebSocket server and the browser extension bridge, and
//! whether a request is being answered ([`requests_idle`]: an update waits for it).

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oncl_protocol::{AddInfo, Registry, Route, module_not_found};
use tracing::debug;

/// The module requests being answered, by the wss servers and the bridge together, and when
/// the last one ended.
struct Activity {
    in_flight: AtomicUsize,
    last_end: Mutex<Option<Instant>>,
}

static ACTIVITY: Activity = Activity {
    in_flight: AtomicUsize::new(0),
    last_end: Mutex::new(None),
};

/// A module request being answered, from [`Activity::begin`] to its drop.
struct Answering<'a>(&'a Activity);

impl Activity {
    fn begin(&self) -> Answering<'_> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Answering(self)
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
        let activity = Activity {
            in_flight: AtomicUsize::new(0),
            last_end: Mutex::new(None),
        };
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
}
