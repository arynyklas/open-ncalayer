//! The wss server of the running daemon ([`Wss`]): serving from the start, or off for a
//! reason that may go away — TLS set up in the wizard, the port freed by the original
//! NCALayer (stopped from the tray, or quit by the user) — and then started in the same
//! process, without a restart. Each listener it opens goes to the server task
//! ([`Listening`]) over a channel.
//!
//! A busy port is looked at again ([`Wss::recheck`]) after a stop, after a certificate is
//! saved, when the user picks «Остановить оригинал…», and every [`WATCH_EVERY`] while wss is
//! off ([`Wss::watch`]): when nobody listens there any more, wss takes it.

use std::io;
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oncl_basics::Locale;
use oncl_desktop::PortOwner;
use oncl_tls::TlsFiles;
use oncl_ui::Stopped;
use oncl_ui::tls_wizard::Applied;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::cli::{WssFailure, WssOff, open_wss};
use crate::renewal;
use crate::server::LiveTls;

/// How often [`Wss::start_within`] tries to bind again while the port is still busy.
const RETRY_EVERY: Duration = Duration::from_millis(100);
/// How often the daemon looks at a busy port again ([`Wss::watch`]).
pub const WATCH_EVERY: Duration = Duration::from_secs(30);

/// Who listens on a TCP port: [`oncl_desktop::port_owner::port_owner`], or a test's.
pub type OwnerOf<'a> = &'a dyn Fn(u16) -> io::Result<Option<PortOwner>>;

/// How wss's port stands for the tray: why wss is off, and the original NCALayer holding
/// the port when a busy port is why.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortState {
    pub off: Option<WssOff>,
    pub original: Option<PortOwner>,
}

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
    #[cfg(test)]
    fn live(&self) -> Option<Arc<LiveTls>> {
        self.lock().live.clone()
    }

    /// Starts wss unless it serves already, tried again for up to `wait` while the port is
    /// busy: a process that has just ended may hold it a moment longer. The state is not
    /// held while it waits.
    ///
    /// # Errors
    ///
    /// Why it is still off (also kept for [`Wss::off`]).
    pub fn start_within(&self, wait: Duration) -> Result<(), WssOff> {
        let deadline = Instant::now() + wait;
        loop {
            let started = self.start_with(&mut self.lock());
            match started {
                Err(failure)
                    if matches!(failure.off, WssOff::PortBusy(_)) && Instant::now() < deadline =>
                {
                    std::thread::sleep(RETRY_EVERY);
                }
                result => return result.map_err(still_off),
            }
        }
    }

    /// Looks at a port that keeps wss off: when nobody listens there any more wss takes it;
    /// otherwise who holds it, kept if it is the original NCALayer (not this process).
    pub fn recheck(&self, owner_of: OwnerOf<'_>) -> PortState {
        let off = self.off();
        let Some(WssOff::PortBusy(port)) = off else {
            return PortState {
                off,
                original: None,
            };
        };
        let original = match owner_of(port) {
            Ok(None) => {
                let started = self.start_with(&mut self.lock());
                if let Err(failure) = started {
                    debug!(reason = %failure.message, "nobody listens, yet wss cannot start");
                }
                None
            }
            Ok(Some(owner)) if owner.looks_original && owner.pid != std::process::id() => {
                debug!(pid = owner.pid, exe = %owner.exe.display(), port, "the original NCALayer holds the port");
                Some(owner)
            }
            Ok(Some(owner)) => {
                debug!(pid = owner.pid, exe = %owner.exe.display(), port, "another program holds the port");
                None
            }
            Err(e) => {
                debug!(error = %e, port, "cannot tell who holds the port");
                None
            }
        };
        PortState {
            off: self.off(),
            original,
        }
    }

    /// Looks at the port every `every` ([`Wss::recheck`]) while wss is off for it, and tells
    /// `on_change` each state that differs from the last one told. Returns once wss serves.
    pub fn watch(
        &self,
        every: Duration,
        owner_of: OwnerOf<'_>,
        mut on_change: impl FnMut(&PortState),
    ) {
        let mut last = None;
        while self.off().is_some() {
            std::thread::sleep(every);
            if !matches!(self.off(), Some(WssOff::PortBusy(_))) {
                continue;
            }
            let state = self.recheck(owner_of);
            if last.as_ref() != Some(&state) {
                on_change(&state);
                last = Some(state);
            }
        }
    }

    /// «Остановить»: ends the original `owner` with `stop` (which checks it is still that
    /// process), then starts wss on the freed port, waiting up to `wait`; why wss is still
    /// off is told in `locale`. If the process is gone already ([`io::ErrorKind::NotFound`])
    /// wss still takes the port if it is free ([`Stopped::WasGone`]).
    ///
    /// # Errors
    ///
    /// `stop`'s error: nothing was ended (and, for `NotFound`, the port is not free).
    pub fn stop_original(
        &self,
        owner: &PortOwner,
        stop: impl FnOnce(&PortOwner) -> io::Result<()>,
        wait: Duration,
        locale: Locale,
    ) -> io::Result<Stopped> {
        match stop(owner) {
            Ok(()) => {
                info!(pid = owner.pid, exe = %owner.exe.display(), "the original NCALayer is stopped");
                Ok(match self.start_within(wait) {
                    Ok(()) => Stopped::Serving,
                    Err(off) => Stopped::WssOff(off.text(locale)),
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                info!(pid = owner.pid, error = %e, "the original NCALayer is gone already");
                match self.start_within(wait) {
                    Ok(()) => Ok(Stopped::WasGone),
                    Err(_) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Has the server take the certificate just saved in the files: served from the next
    /// connection if wss runs ([`renewal::reload`]), otherwise wss is started with it.
    /// [`Applied::WhenPortFree`] while another program holds the port (wss takes it once it
    /// is free, [`Wss::watch`]), [`Applied::AfterRestart`] when the port cannot be opened;
    /// [`Applied::Failed`] when the certificate cannot be served.
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
                    WssOff::PortBusy(_) => Applied::WhenPortFree,
                    WssOff::PortUnavailable(_) => Applied::AfterRestart,
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
        assert_eq!(
            wss.start_within(Duration::ZERO),
            Err(WssOff::TlsNotConfigured)
        );
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
        assert_eq!(wss.start_within(Duration::ZERO), Ok(()));
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
        assert_eq!(
            wss.start_within(Duration::ZERO),
            Err(WssOff::PortBusy(port))
        );
        assert_eq!(wss.reload(), Applied::WhenPortFree);
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
        assert_eq!(wss.start_within(Duration::ZERO), Ok(()));
        assert!(listeners.try_recv().is_err());
    }

    fn original(pid: u32) -> PortOwner {
        PortOwner {
            pid,
            exe: std::path::PathBuf::from(r"C:\Program Files\NCALayer\NCALayer.exe"),
            started: std::time::SystemTime::UNIX_EPOCH,
            looks_original: true,
        }
    }

    /// TLS set up, the port held by `held` and wss off for it.
    fn busy() -> (
        tempfile::TempDir,
        Arc<Wss>,
        mpsc::UnboundedReceiver<Listening>,
        TcpListener,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let files = TlsFiles {
            dir: dir.path().join("tls"),
        };
        configure(&files);
        let (port, held) = held_port();
        let (wss, listeners) = Wss::new(files, port, Err(WssOff::PortBusy(port)));
        (dir, wss, listeners, held)
    }

    /// Who holds the port as a fake lookup sees it: the original while `held` is set.
    fn lookup(
        held: &Arc<Mutex<Option<TcpListener>>>,
    ) -> impl Fn(u16) -> io::Result<Option<PortOwner>> + use<> {
        let held = Arc::clone(held);
        move |_| Ok(held.lock().unwrap().as_ref().map(|_| original(4242)))
    }

    #[test]
    fn stopping_the_original_starts_wss() {
        let (_dir, wss, mut listeners, held) = busy();
        let held = Mutex::new(Some(held));
        let stopped = wss.stop_original(
            &original(4242),
            |_| {
                // The original ends: its socket closes.
                held.lock().unwrap().take();
                Ok(())
            },
            Duration::from_secs(2),
            Locale::Ru,
        );
        assert_eq!(stopped.unwrap(), Stopped::Serving);
        assert_eq!(wss.off(), None);
        assert!(listeners.try_recv().is_ok());
    }

    /// The original ended before «Остановить»: nothing is stopped, wss takes the free port.
    #[test]
    fn an_original_gone_already_still_lets_wss_start() {
        let (_dir, wss, mut listeners, held) = busy();
        drop(held);
        let stopped = wss.stop_original(
            &original(4242),
            |_| Err(io::Error::new(io::ErrorKind::NotFound, "gone")),
            Duration::from_secs(2),
            Locale::Ru,
        );
        assert_eq!(stopped.unwrap(), Stopped::WasGone);
        assert_eq!(wss.off(), None);
        assert!(listeners.try_recv().is_ok());
    }

    /// Gone, but another program holds the port now; or refused: wss stays off.
    #[test]
    fn a_refused_stop_leaves_wss_off() {
        let (_dir, wss, mut listeners, _held) = busy();
        let port = wss.port();
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::InvalidInput] {
            let stopped = wss.stop_original(
                &original(4242),
                |_| Err(io::Error::from(kind)),
                Duration::from_millis(200),
                Locale::Ru,
            );
            assert_eq!(stopped.unwrap_err().kind(), kind);
            assert_eq!(wss.off(), Some(WssOff::PortBusy(port)));
        }
        // Still busy after the stop: why, in the window's language.
        let stopped = wss.stop_original(&original(4242), |_| Ok(()), Duration::ZERO, Locale::En);
        assert_eq!(
            stopped.unwrap(),
            Stopped::WssOff(WssOff::PortBusy(port).text(Locale::En))
        );
        assert!(listeners.try_recv().is_err());
    }

    #[test]
    fn a_look_at_the_port_finds_the_original_or_takes_the_free_port() {
        let (_dir, wss, mut listeners, held) = busy();
        let port = wss.port();
        let held = Arc::new(Mutex::new(Some(held)));
        let owner_of = lookup(&held);
        assert_eq!(
            wss.recheck(&owner_of),
            PortState {
                off: Some(WssOff::PortBusy(port)),
                original: Some(original(4242)),
            }
        );
        // Another program, this process, or no answer: nothing to stop.
        let other = PortOwner {
            looks_original: false,
            ..original(4242)
        };
        let us = original(std::process::id());
        for answer in [
            Ok(Some(other)),
            Ok(Some(us)),
            Err(io::Error::other("denied")),
        ] {
            let answer = Mutex::new(Some(answer));
            let state = wss.recheck(&|_| answer.lock().unwrap().take().unwrap());
            assert_eq!(state.original, None);
            assert_eq!(state.off, Some(WssOff::PortBusy(port)));
        }
        assert!(listeners.try_recv().is_err());

        held.lock().unwrap().take();
        assert_eq!(
            wss.recheck(&owner_of),
            PortState {
                off: None,
                original: None,
            }
        );
        assert!(listeners.try_recv().is_ok());
    }

    /// The port is freed later (the original quit by the user): the watch takes it at its
    /// next check, tells what changed, and ends once wss serves.
    #[test]
    fn a_port_freed_later_is_taken_within_one_check() {
        let (_dir, wss, mut listeners, held) = busy();
        let port = wss.port();
        let held = Arc::new(Mutex::new(Some(held)));
        let owner_of = lookup(&held);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let watching = {
            let (wss, seen) = (Arc::clone(&wss), Arc::clone(&seen));
            std::thread::spawn(move || {
                wss.watch(Duration::from_millis(50), &owner_of, |state| {
                    seen.lock().unwrap().push(state.clone());
                });
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        let freed = Instant::now();
        held.lock().unwrap().take();
        while !watching.is_finished() {
            assert!(
                freed.elapsed() < Duration::from_secs(10),
                "the watch did not end"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        watching.join().unwrap();
        assert_eq!(wss.off(), None);
        assert!(listeners.try_recv().is_ok());
        let seen = seen.lock().unwrap();
        // Only changes are told: the original found, then wss serving.
        assert_eq!(
            *seen,
            [
                PortState {
                    off: Some(WssOff::PortBusy(port)),
                    original: Some(original(4242)),
                },
                PortState {
                    off: None,
                    original: None,
                },
            ]
        );
    }

    /// The retry does not hold the state while it waits: others read it meanwhile.
    #[test]
    fn the_retry_lets_others_read_the_state() {
        let (_dir, wss, _listeners, _held) = busy();
        let retrying = {
            let wss = Arc::clone(&wss);
            std::thread::spawn(move || wss.start_within(Duration::from_millis(1500)))
        };
        std::thread::sleep(Duration::from_millis(200));
        let asked = Instant::now();
        assert!(wss.off().is_some());
        assert!(
            asked.elapsed() < Duration::from_millis(500),
            "{:?}",
            asked.elapsed()
        );
        assert!(retrying.join().unwrap().is_err());
    }
}
