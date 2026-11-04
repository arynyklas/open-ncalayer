//! Request handling shared by the WebSocket server and the browser extension bridge,
//! whether a request is being answered ([`requests_idle`]: an update waits for it), and
//! holding new requests back while an update is applied ([`hold_requests`]).
//!
//! What counts as activity is one [`ActivityGate`] of the process ([`activity`]): the module
//! requests answered here, and, through [`oncl_core::Engine::with_activity`], the operations
//! of the tools window. The updater and the installer's management endpoint hold that same
//! gate, so there is one answer to whether the program may be replaced.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use oncl_core::activity::ActivityGate;
use oncl_protocol::{AddInfo, Registry, Route, SessionId, module_not_found};
use tracing::debug;

static ACTIVITY: LazyLock<Arc<ActivityGate>> = LazyLock::new(|| Arc::new(ActivityGate::new()));

/// The activity of this process: every module request, tools-window operation and plugin
/// call counts in it, and a maintainer holds it to replace the program.
pub fn activity() -> Arc<ActivityGate> {
    Arc::clone(&ACTIVITY)
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
    hold_requests_unless(quiet, || false)
}

/// [`hold_requests`], which also lets go if `blocked` says so: `blocked` is asked only once
/// the hold is in place, so what it looks at (a window that is open) is seen with new
/// requests already held back.
pub fn hold_requests_unless(quiet: Duration, blocked: impl FnOnce() -> bool) -> bool {
    ACTIVITY.hold_unless(quiet, Instant::now, blocked)
}

/// Whether the requests are held back now.
pub fn requests_held() -> bool {
    ACTIVITY.is_held()
}

/// Lets held requests through again.
pub fn release_requests() {
    ACTIVITY.release();
}

/// The next session id; ids start at 1, `0` is no session.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// A new session id, unique within the process.
pub fn new_session() -> SessionId {
    NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
}

/// A session of a WebSocket connection or a bridge socket: the registry, the context of its
/// calls (with a new session id), and [`Registry::session_closed`] when the last reference
/// goes. [`process`] holds a reference for the whole module call, so the close comes after
/// the session's last call however the session ends (a closed or failed connection, an idle
/// timeout, an aborted task).
pub(crate) struct Session {
    registry: Arc<Registry>,
    add_info: AddInfo,
}

impl Session {
    pub(crate) fn new(registry: &Arc<Registry>, origin: Option<String>) -> Arc<Self> {
        Arc::new(Session {
            registry: Arc::clone(registry),
            add_info: AddInfo {
                origin,
                session: new_session(),
            },
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.registry.session_closed(self.add_info.session);
    }
}

/// What the page sees when a request ends without a reply: the TCP connection (or the
/// bridge's virtual socket) closes without a close frame, close code 1006 in the browser.
pub(crate) const DROP_CLOSE: u16 = 1006;

/// The reply to a request, or `None` to drop the connection ([`DROP_CLOSE`]): the request is
/// not a JSON object org.json reads (a repeated key, a byte order mark before it), or its
/// module answered [`oncl_protocol::Reply::Drop`]. The heartbeat is echoed. The module gets
/// the request through the end of its JSON object, what follows is ignored. A string
/// `module` that nothing serves is reported to [`Registry::missing`]; the reply is
/// [`module_not_found`] all the same.
pub(crate) fn dispatch(registry: &Registry, text: &str, add_info: &AddInfo) -> Option<String> {
    match registry.route(text) {
        Route::Heartbeat => Some(text.to_owned()),
        Route::Module { module, request } => {
            let _answering = ACTIVITY.begin();
            module.process(request, add_info).into_text()
        }
        Route::NotFound { module } => {
            if let Some(name) = module {
                registry.missing(&name, add_info);
            }
            Some(module_not_found())
        }
        Route::InvalidJson => None,
    }
}

/// [`dispatch`] on the blocking pool: routing parses the whole request (possibly tens of
/// megabytes) and a module call may wait for a dialog, so neither may hold up the runtime.
/// The call keeps `session` open until it returns, even if the caller is dropped.
///
/// # Errors
///
/// The module call panicked.
pub(crate) async fn process<T>(session: &Arc<Session>, text: T) -> io::Result<Option<String>>
where
    T: AsRef<str> + Send + 'static,
{
    let session = Arc::clone(session);
    let len = text.as_ref().len();
    let answer = tokio::task::spawn_blocking(move || {
        dispatch(&session.registry, text.as_ref(), &session.add_info)
    })
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
    use std::sync::mpsc;
    use std::thread;

    use oncl_protocol::{Module, Reply};

    use super::*;

    /// Says it started, then answers when told to.
    struct Slow {
        started: mpsc::Sender<()>,
        finish: std::sync::Mutex<mpsc::Receiver<()>>,
    }

    impl Module for Slow {
        fn process(&self, _request: &str, _add_info: &AddInfo) -> Reply {
            self.started.send(()).unwrap();
            self.finish.lock().unwrap().recv().unwrap();
            "done".to_owned().into()
        }
    }

    /// A module request that is being answered is the activity an update or an installer
    /// waits for: nothing is held and the process does not count as idle while it runs.
    #[test]
    fn a_module_request_counts_in_the_shared_gate_while_it_is_answered() {
        let (started, started_rx) = mpsc::channel();
        let (finish, finish_rx) = mpsc::channel();
        let mut registry = Registry::default();
        registry.register(
            "slow",
            Arc::new(Slow {
                started,
                finish: std::sync::Mutex::new(finish_rx),
            }),
        );
        let registry = Arc::new(registry);
        let call = {
            let registry = Arc::clone(&registry);
            thread::spawn(move || dispatch(&registry, r#"{"module":"slow"}"#, &AddInfo::default()))
        };
        started_rx.recv().unwrap();
        assert!(
            !requests_idle(Duration::ZERO),
            "a request is being answered"
        );
        assert!(
            !hold_requests(Duration::ZERO),
            "an update cannot hold the process under it"
        );
        finish.send(()).unwrap();
        assert_eq!(call.join().unwrap().as_deref(), Some("done"));
        // A heartbeat is not a request.
        let heartbeat = oncl_protocol::HEARTBEAT;
        assert_eq!(
            dispatch(&registry, heartbeat, &AddInfo::default()).as_deref(),
            Some(heartbeat)
        );
    }
}
