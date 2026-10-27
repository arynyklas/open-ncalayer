//! The wss server of the running daemon ([`Wss`]): serving from the start, or off for a
//! reason a later [`Wss::start`] may find gone — TLS set up in the wizard, the port freed by
//! stopping the original NCALayer — and then started in the same process, without a restart.
//! Each listener it opens goes to the server task ([`Listening`]) over a channel.

use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oncl_tls::TlsFiles;
use oncl_ui::tls_wizard::Applied;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::cli::{WssFailure, WssOff, open_wss};
use crate::renewal;
use crate::server::LiveTls;

/// How often [`Wss::start_within`] tries to bind again while the port is still busy.
const RETRY_EVERY: Duration = Duration::from_millis(100);

/// A bound wss listener (non-blocking) and the TLS configuration to serve on it.
pub struct Listening {
    pub tls: Arc<LiveTls>,
    pub listener: TcpListener,
}

/// The wss server of this daemon on `127.0.0.1:<port>` with the TLS files `files`.
pub struct Wss {
    files: TlsFiles,
    port: u16,
    state: Mutex<State>,
    listeners: mpsc::UnboundedSender<Listening>,
}

/// Serving (`live`) or off (`off`).
struct State {
    live: Option<Arc<LiveTls>>,
    off: Option<WssOff>,
}

impl Wss {
    /// The wss server as `run` found it: `opened` serving at once, or why it is off. The
    /// listeners to serve arrive on the receiver, the first one at once.
    pub fn new(
        files: TlsFiles,
        port: u16,
        opened: Result<(Arc<rustls::ServerConfig>, TcpListener), WssOff>,
    ) -> (Arc<Wss>, mpsc::UnboundedReceiver<Listening>) {
        let (listeners, receiver) = mpsc::unbounded_channel();
        let wss = Wss {
            files,
            port,
            state: Mutex::new(State {
                live: None,
                off: None,
            }),
            listeners,
        };
        {
            let mut state = wss.lock();
            match opened {
                Ok(opened) => wss.serve(&mut state, opened),
                Err(off) => state.off = Some(off),
            }
        }
        (Arc::new(wss), receiver)
    }

    /// The port wss listens on, or is to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Why wss is off; `None` while it serves.
    pub fn off(&self) -> Option<WssOff> {
        self.lock().off
    }

    /// The TLS configuration being served, while wss serves.
    pub fn live(&self) -> Option<Arc<LiveTls>> {
        self.lock().live.clone()
    }

    /// Starts wss unless it serves already: loads TLS from the files and binds the port.
    ///
    /// # Errors
    ///
    /// Why it is still off (also kept for [`Wss::off`]).
    pub fn start(&self) -> Result<(), WssOff> {
        self.start_with(&mut self.lock()).map_err(still_off)
    }

    /// [`Wss::start`], tried again for up to `wait` while the port is busy: a process that
    /// has just ended may hold it a moment longer.
    ///
    /// # Errors
    ///
    /// As [`Wss::start`]: the last reason.
    pub fn start_within(&self, wait: Duration) -> Result<(), WssOff> {
        let deadline = Instant::now() + wait;
        loop {
            match self.start_with(&mut self.lock()) {
                Err(failure)
                    if matches!(failure.off, WssOff::PortBusy(_)) && Instant::now() < deadline =>
                {
                    std::thread::sleep(RETRY_EVERY);
                }
                result => return result.map_err(still_off),
            }
        }
    }

    /// Has the server take the certificate just saved in the files: served from the next
    /// connection if wss runs ([`renewal::reload`]), otherwise wss is started with it.
    /// [`Applied::AfterRestart`] when wss still cannot start for its port (it starts once
    /// the port is free, e.g. by stopping the original NCALayer); [`Applied::Failed`] when
    /// the certificate cannot be served.
    pub fn reload(&self) -> Applied {
        let mut state = self.lock();
        if let Some(live) = &state.live {
            return renewal::reload(&self.files, Some(live.as_ref()));
        }
        match self.start_with(&mut state) {
            Ok(()) => Applied::Serving,
            Err(failure) => {
                warn!(reason = %failure.message, "wss is still off");
                match failure.off {
                    WssOff::PortBusy(_) | WssOff::PortUnavailable(_) => Applied::AfterRestart,
                    WssOff::TlsNotConfigured | WssOff::TlsUnusable => {
                        Applied::Failed(failure.message)
                    }
                }
            }
        }
    }

    fn start_with(&self, state: &mut State) -> Result<(), WssFailure> {
        if state.live.is_some() {
            return Ok(());
        }
        match open_wss(&self.files, self.port) {
            Ok(opened) => {
                self.serve(state, opened);
                info!(port = self.port, "wss started in the running daemon");
                Ok(())
            }
            Err(failure) => {
                debug!(reason = %failure.message, "wss cannot start");
                state.off = Some(failure.off);
                Err(failure)
            }
        }
    }

    /// Hands `opened` to the server task and records it as served.
    fn serve(&self, state: &mut State, (tls, listener): (Arc<rustls::ServerConfig>, TcpListener)) {
        let live = Arc::new(LiveTls::new(tls));
        let listening = Listening {
            tls: Arc::clone(&live),
            listener,
        };
        if self.listeners.send(listening).is_err() {
            // The servers have stopped: the daemon is on its way out.
            warn!("the servers have stopped; wss is not served");
        }
        state.live = Some(live);
        state.off = None;
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Logs why wss is still off; gives the reason.
fn still_off(failure: WssFailure) -> WssOff {
    warn!(reason = %failure.message, "wss is still off");
    failure.off
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use time::OffsetDateTime;

    fn configure(files: &TlsFiles) {
        let material = oncl_tls::generate(OffsetDateTime::now_utc(), "wss").unwrap();
        oncl_tls::save(files, &material).unwrap();
    }

    /// A port held by a listener of this process.
    fn held_port() -> (u16, TcpListener) {
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        (held.local_addr().unwrap().port(), held)
    }

    #[test]
    fn tls_set_up_later_starts_wss_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles {
            dir: dir.path().join("tls"),
        };
        let (port, held) = held_port();
        drop(held);
        let (wss, mut listeners) = Wss::new(files.clone(), port, Err(WssOff::TlsNotConfigured));
        assert_eq!(wss.off(), Some(WssOff::TlsNotConfigured));
        assert!(wss.live().is_none());
        assert_eq!(wss.start(), Err(WssOff::TlsNotConfigured));
        assert!(matches!(wss.reload(), Applied::Failed(_)));
        assert!(listeners.try_recv().is_err());

        // The wizard saved a certificate.
        configure(&files);
        assert_eq!(wss.reload(), Applied::Serving);
        assert_eq!(wss.off(), None);
        let listening = listeners.try_recv().expect("a listener to serve");
        assert_eq!(listening.listener.local_addr().unwrap().port(), port);
        assert!(Arc::ptr_eq(&listening.tls, &wss.live().unwrap()));
        // Serving already: nothing is bound again; a new certificate is taken in place.
        assert_eq!(wss.start(), Ok(()));
        let before = wss.live().unwrap().current();
        configure(&files);
        assert_eq!(wss.reload(), Applied::Serving);
        assert!(!Arc::ptr_eq(&before, &wss.live().unwrap().current()));
        assert!(listeners.try_recv().is_err());
    }

    #[test]
    fn a_freed_port_is_taken_within_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles {
            dir: dir.path().join("tls"),
        };
        configure(&files);
        let (port, held) = held_port();
        let (wss, mut listeners) = Wss::new(files, port, Err(WssOff::PortBusy(port)));
        assert_eq!(wss.start(), Err(WssOff::PortBusy(port)));
        assert_eq!(wss.reload(), Applied::AfterRestart);
        assert_eq!(
            wss.start_within(Duration::from_millis(300)),
            Err(WssOff::PortBusy(port))
        );
        assert_eq!(wss.off(), Some(WssOff::PortBusy(port)));

        // Like the original's socket closing a moment after its process ended.
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            drop(held);
        });
        assert_eq!(wss.start_within(Duration::from_secs(10)), Ok(()));
        release.join().unwrap();
        assert_eq!(wss.off(), None);
        let listening = listeners.try_recv().expect("a listener to serve");
        assert_eq!(listening.listener.local_addr().unwrap().port(), port);
    }

    #[test]
    fn serving_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles {
            dir: dir.path().join("tls"),
        };
        configure(&files);
        let (port, held) = held_port();
        drop(held);
        let opened = open_wss(&files, port).map_err(|f| f.off);
        let (wss, mut listeners) = Wss::new(files, port, opened);
        assert_eq!(wss.off(), None);
        assert!(wss.live().is_some());
        assert!(listeners.try_recv().is_ok());
        assert_eq!(wss.start(), Ok(()));
        assert!(listeners.try_recv().is_err());
    }
}
