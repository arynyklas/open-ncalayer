//! `openncalayer`: see [`openncalayer::cli`].

use std::cell::{Cell, RefCell};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;
use oncl_accessory::UiRequest;
use oncl_basics::{Locale, Prompter};
use oncl_desktop::Settings;
use oncl_desktop::port_owner;
use oncl_ipc::IpcListener;
use oncl_pki::http::HttpTransport;
use oncl_protocol::Registry;
use oncl_tls::{SelftestReports, TlsFiles};
use oncl_ui::settings_view::Updates;
use oncl_ui::{
    AboutInfo, DesktopWindow, DesktopWindows, Notification, SlintPrompter, StopOriginal,
    TrayCommand, TrayHandle, TrayState,
};
use oncl_update::{Flavor, embedded_keys};
use openncalayer::cli::{self, Cli, Command};
use openncalayer::notices::TrayStatus;
use openncalayer::renewal::{self, RenewalCheck};
use openncalayer::update::installer::VelopackInstaller;
use openncalayer::update::{
    self, Host, Notice, RollBack, Startup, Updater, UpdaterConfig, UpdaterHandle,
};
use openncalayer::wss::{Listening, PortState, WATCH_EVERY, Watcher, Wss};
use openncalayer::{
    JsonSettings, LiveProxyTransport, Paths, ServerConfig, build_registry, desktop, hold_requests,
    listen_port, load_settings, release_requests, requests_idle, serve, serve_ipc,
};
use time::OffsetDateTime;
use tokio::runtime::Runtime;
use tokio::sync::{Notify, mpsc};

/// How long `run` waits for the server thread once the dialogs' event loop has ended.
const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
/// How long wss keeps trying to take the port after the original NCALayer is stopped.
const REBIND_WAIT: Duration = Duration::from_secs(2);

/// The tray and what it shows, on the event loop's thread.
struct Tray {
    handle: Weak<TrayHandle>,
    status: TrayStatus,
}

thread_local! {
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
}

/// Changes the tray's status with `f` on the event loop, from any thread; then the tray
/// shows the status's warning and menu and the notification `f` returns. Without an event
/// loop or a tray nothing is shown.
fn post_to_tray(f: impl FnOnce(&mut TrayStatus) -> Option<Notification> + Send + 'static) {
    let posted = oncl_ui::run_on_event_loop(move || {
        TRAY.with_borrow_mut(|tray| {
            let Some(tray) = tray else {
                return;
            };
            let notification = f(&mut tray.status);
            if let Some(handle) = tray.handle.upgrade() {
                handle.set_state(tray.status.tray_state());
                if let Some(notification) = notification {
                    handle.notify(notification);
                }
            }
        });
    });
    if let Err(e) = posted {
        tracing::debug!(error = %e, "no event loop: the tray is not told");
    }
}

/// A user action looks at wss's port again ([`Wss::recheck`]: wss takes it if nobody
/// listens there any more) and tells the tray. Blocks for the lookup: call it off the event
/// loop.
fn recheck_for_user(wss: &Wss) -> PortState {
    let state = wss.recheck(&port_owner::port_owner);
    show_port(state.clone(), false);
    state
}

/// Looks at wss's port without a user action ([`Wss::look`]: a free port is taken only if
/// wss may do so on its own) and tells the tray. Blocks: call it off the event loop.
fn look_for_tray(wss: &Wss) {
    show_port(wss.look(&port_owner::port_owner), false);
}

/// Has the tray show `state`; with `notify` a problem the tray can fix is also notified.
fn show_port(state: PortState, notify: bool) {
    post_to_tray(move |status| {
        status.wss_off = state.off;
        status.original = state.original;
        if notify {
            status.wss_off_notification()
        } else {
            None
        }
    });
}

/// While wss is off, from when the event loop runs: looks at the port once and tells the
/// tray (notifying a problem it can fix if `notify`); then, if wss may take a freed port on
/// its own, watches it every [`WATCH_EVERY`] ([`Wss::watch_if_allowed`]). A relay-started
/// daemon starts that watch only after the user stopped the original or saved a
/// certificate. On a thread.
fn watch_wss(wss: Arc<Wss>, notify: bool) {
    wss.set_watcher(Watcher {
        every: WATCH_EVERY,
        owner_of: Box::new(port_owner::port_owner),
        on_change: Box::new(|state| show_port(state.clone(), false)),
    });
    spawn_named("wss-port", move || {
        show_port(wss.look(&port_owner::port_owner), notify);
        wss.watch_if_allowed();
    });
}

/// «Остановить оригинал…» (the menu, or the notification's button): looks at the port again,
/// then asks before the original NCALayer holding it is stopped. If it is gone, wss takes a
/// free port and a notification says what became of it. The lookup runs on a thread.
fn offer_to_stop_original(wss: &Arc<Wss>) {
    let wss = Arc::clone(wss);
    spawn_named("stop-original", move || {
        let state = recheck_for_user(&wss);
        let Some(owner) = state.original else {
            tracing::info!(
                serving = state.off.is_none(),
                "the original NCALayer does not hold the port any more"
            );
            let port = wss.port();
            post_to_tray(move |status| Some(status.original_gone_notification(port)));
            return;
        };
        let stopping = Arc::clone(&wss);
        oncl_ui::ask_stop_original(StopOriginal {
            port: wss.port(),
            exe: owner.exe.clone(),
            pid: owner.pid,
            // After any outcome the tray shows the port as it is then.
            stop: Box::new(move |locale: Locale| {
                let stopped = stopping.stop_original(&owner, port_owner::stop, REBIND_WAIT, locale);
                recheck_for_user(&stopping);
                stopped
            }),
        });
    });
}

fn main() -> ExitCode {
    // Velopack's install, update and uninstall hooks run here and exit; a copy that was not
    // installed through Velopack carries on. A downloaded update is applied only by the
    // updater, when no signing is in progress (not on the next start).
    velopack::VelopackApp::build()
        .set_auto_apply_on_startup(false)
        .run();
    let command = Cli::parse().command.unwrap_or(Command::Run {
        allow_no_wss: false,
        no_tray: false,
    });
    match command {
        Command::Run {
            allow_no_wss,
            no_tray,
        } => run(allow_no_wss, !no_tray),
        Command::Tls { command } => cli::tls(command),
        Command::CmsVerify {
            file,
            content,
            chain,
            offline,
        } => cli::cms_verify(&file, content.as_deref(), &chain, offline),
        Command::Nm { command } => cli::nm(command),
    }
}

/// The servers run on a tokio runtime in a background thread; the main thread runs the
/// event loop of the dialogs, the windows and the tray, as windowing systems require.
/// «Выход» in the tray stops the servers, and a stopped server ends the loop; closing
/// windows does not. With feature `e2e-prompter` and its script set there are no dialogs:
/// without a tray the main thread only waits for the servers. A tray that cannot be shown
/// is logged, and `run` carries on without it unless a deferred failure waits for it.
///
/// With a tray, TLS not set up and a busy port do not end `run`: it serves the browser
/// extension, the tray says what is wrong, and wss starts in this process once the TLS
/// wizard saves a certificate or the port is free (the original NCALayer stopped from the
/// tray, or quit). Without one (`--no-tray`, a tray that cannot be shown, one lost on the
/// event loop's first turn on macOS or not taken by a StatusNotifierWatcher within a minute
/// on Linux, or no event loop) they end it with P1's code, unless `allow_no_wss` — or unless
/// the failure was lifted by then (wss serves): such a daemon carries on without an icon
/// ([`tray_loss_ends_run`]). Only a daemon started without `allow_no_wss` (by the user or
/// our autostart, not the extension's relay) notifies them at the start, and takes a freed
/// port by itself; a relay-started one does so only after the user stopped the original or
/// saved a certificate (D13).
fn run(allow_no_wss: bool, with_tray: bool) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Не удалось запустить сервер: {e}");
            return ExitCode::FAILURE;
        }
    };
    let daemon = match runtime.block_on(cli::prepare_run(allow_no_wss, with_tray)) {
        Ok(daemon) => daemon,
        Err(code) => return code,
    };
    // Panics (e.g. of the windowing libraries) go to the log, not as raw text to stderr only.
    std::panic::set_hook(Box::new(|info| tracing::error!(%info, "panic")));
    let scripted = match scripted_prompter() {
        Ok(scripted) => scripted,
        Err(code) => return code,
    };
    let windows = scripted.is_none();
    let settings = load_settings(&daemon.paths.settings());
    let locale = settings.ui_locale();
    let http = Arc::new(LiveProxyTransport::new(settings.proxy.clone()));
    let registry = build_registry(
        scripted.unwrap_or_else(|| Arc::new(SlintPrompter::new())),
        Arc::new(JsonSettings::new(daemon.paths.settings())),
        Arc::clone(&http) as _,
        Arc::new(open_requested_window),
    );
    let stop = Arc::new(Notify::new());
    // Whether the windows' event loop runs (an update waits for its windows to close).
    let loop_runs = Arc::new(AtomicBool::new(false));
    let (updates, startup) = updater(
        &daemon.paths,
        Arc::clone(&http),
        Arc::clone(&stop),
        Arc::clone(&loop_runs),
    );
    // A version that did not prove healthy goes back before anything else starts.
    let mut rollback = None;
    if let (UpdaterHandle::Running(updater), Startup::RollBack { failed, to }) =
        (&updates, &startup)
    {
        match updater.roll_back_now(failed, to) {
            RollBack::Applied => {
                tracing::info!(%failed, %to, "rolling back; exiting");
                return ExitCode::SUCCESS;
            }
            RollBack::Retry => rollback = Some((failed.clone(), to.clone())),
            RollBack::GaveUp => {}
        }
    }
    // A failure only a tray lets the daemon live with.
    let (opened, waits_for_tray) = match daemon.wss {
        Ok(opened) => (Ok(opened), None),
        Err(failure) => (Err(failure.off), (!allow_no_wss).then_some(failure)),
    };
    let (wss, listeners) = Wss::new(daemon.paths.tls(), listen_port(), opened, !allow_no_wss);
    let status = TrayStatus::new(locale, wss.off());
    let tray = if with_tray {
        start_tray(
            locale,
            daemon.paths.logs(),
            status.tray_state(),
            Arc::clone(&stop),
            Arc::clone(&wss),
            updates.clone(),
            waits_for_tray.is_some(),
        )
        .map(Rc::new)
    } else {
        None
    };
    if tray.is_none()
        && let Some(failure) = waits_for_tray
    {
        // Nothing would tell the user, nor let them fix it: P1's exit.
        ended_cleanly(&updates);
        return failure.report();
    }
    // A tray lost after the start (macOS: on the event loop's first turn; Linux: no
    // StatusNotifierWatcher within the grace) ends the loop, and then `run`, while wss is
    // still off.
    let tray_lost = Rc::new(Cell::new(false));
    if let Some(tray) = &tray {
        TRAY.set(Some(Tray {
            handle: Rc::downgrade(tray),
            status,
        }));
        if waits_for_tray.is_some() {
            let lost = Rc::clone(&tray_lost);
            let wss = Arc::clone(&wss);
            tray.when_unavailable(move |_| {
                if tray_loss_ends_run(true, wss.off()) {
                    lost.set(true);
                    oncl_ui::quit();
                } else {
                    tracing::warn!("wss serves already: running without the system tray");
                }
            });
        }
    }
    let wss_at_exit = Arc::clone(&wss);
    let reports = Arc::new(SelftestReports::new());
    let ipc = daemon.ipc;
    let event_loop = windows || tray.is_some();
    if event_loop {
        oncl_ui::set_desktop_windows(desktop_windows(
            &daemon.paths,
            locale,
            registry.names(),
            on_settings_saved(http, tray.as_ref().map_or_else(Weak::new, Rc::downgrade)),
            Arc::clone(&reports),
            Arc::clone(&wss),
            updates.clone(),
        ));
        if wss.off().is_some() {
            let watched = Arc::clone(&wss);
            let notify = tray.is_some() && !allow_no_wss;
            oncl_ui::when_event_loop_runs(move || watch_wss(watched, notify));
        }
    }
    let files = daemon.paths.tls();
    if event_loop {
        // Its outcome goes to the tray once the event loop runs.
        oncl_ui::when_event_loop_runs(move || start_renewal(files, wss));
    } else {
        start_renewal(files, wss);
    }
    // Whether the servers run, for a new version's health; cleared however the server
    // thread ends.
    let serving = Arc::new(AtomicBool::new(false));
    if let (UpdaterHandle::Running(updater), Startup::Confirm) = (&updates, &startup) {
        let (serving, loop_runs) = (Arc::clone(&serving), Arc::clone(&loop_runs));
        updater.watch_health(move || {
            serving.load(Ordering::SeqCst) && (!event_loop || loop_runs.load(Ordering::SeqCst))
        });
    }
    let served = Flag::set(Arc::clone(&serving));
    let server = thread::Builder::new().name("server".into()).spawn(move || {
        let _served = served;
        let result = runtime.block_on(serve_all(ipc, listeners, Arc::new(registry), reports, stop));
        if let Err(e) = &result {
            tracing::error!(error = %e, "server stopped");
        }
        stop_runtime(runtime);
        if event_loop {
            oncl_ui::quit();
        }
        result
    });
    let server = match server {
        Ok(server) => server,
        Err(e) => {
            eprintln!("Не удалось запустить сервер: {e}");
            return ExitCode::FAILURE;
        }
    };
    if event_loop {
        let runs = Arc::clone(&loop_runs);
        oncl_ui::when_event_loop_runs(move || runs.store(true, Ordering::SeqCst));
    }
    if let UpdaterHandle::Running(updater) = &updates {
        Arc::clone(updater).spawn(rollback);
    }
    if !event_loop {
        return server_ended(&updates, server.join());
    }
    let mut looped = oncl_ui::run_event_loop();
    loop_runs.store(false, Ordering::SeqCst);
    if tray_lost.get()
        && looped.is_ok()
        && !server.is_finished()
        && !tray_loss_ends_run(true, wss_at_exit.off())
    {
        // wss started between the tray's loss and the loop's end: serve without the icon
        // (winit keeps its event loop for another run).
        tracing::warn!("wss serves already: running without the system tray");
        tray_lost.set(false);
        loop_runs.store(true, Ordering::SeqCst);
        looped = oncl_ui::run_event_loop();
        loop_runs.store(false, Ordering::SeqCst);
    }
    // The icon goes before the process does (on Windows a dead process's icon lingers).
    drop(tray);
    if let Some(failure) = waits_for_tray
        && (looped.is_err() || tray_lost.get())
        && tray_loss_ends_run(true, wss_at_exit.off())
    {
        // The tray that was to fix it is gone: P1's exit, as if there had been none.
        let reason = looped.as_ref().err().map(ToString::to_string);
        tracing::error!(
            ?reason,
            "the system tray is unavailable, and wss cannot start without it: exiting"
        );
        ended_cleanly(&updates);
        return failure.report();
    }
    if let Err(e) = looped {
        if !windows {
            // Only the tray needed the loop: the servers carry on without it.
            tracing::warn!(error = %e, "the system tray is unavailable; running without it");
            return server_ended(&updates, server.join());
        }
        tracing::error!(error = %e, "signing dialogs are unavailable");
        eprintln!("Не удалось показать окна подписи: {e}");
        if cfg!(target_os = "linux") {
            eprintln!(
                "Нужны графический сеанс (DISPLAY или WAYLAND_DISPLAY) и библиотеки окон, \
                 в Debian и Ubuntu — пакет libxkbcommon-x11-0."
            );
        }
        return ExitCode::FAILURE;
    }
    match join_within(server, SERVER_JOIN_TIMEOUT) {
        Some(result) => server_ended(&updates, result),
        None => {
            tracing::error!("the dialog event loop ended while the server is running");
            ExitCode::FAILURE
        }
    }
}

/// The exit code of the joined server thread; servers that stopped as asked (the tray's
/// «Выход», an update applied) end the run cleanly ([`ended_cleanly`]).
fn server_ended(updates: &UpdaterHandle, server: thread::Result<io::Result<()>>) -> ExitCode {
    if matches!(server, Ok(Ok(()))) {
        ended_cleanly(updates);
    }
    exit_code(server)
}

/// The run ends cleanly (asked to, or with P1's exit code for TLS not set up or a busy
/// port): a new version not yet confirmed healthy has not failed.
fn ended_cleanly(updates: &UpdaterHandle) {
    if let UpdaterHandle::Running(updater) = updates {
        updater.ended_cleanly();
    }
}

/// Whether losing the tray after the start ends `run`: only for a daemon whose wss failure
/// `waits_for_tray`, and only while wss is still off (`wss_off`). Once the user lifted the
/// failure from the start notification (stopped the original, saved a certificate) or the
/// port came free, the daemon serves on without an icon.
fn tray_loss_ends_run(waits_for_tray: bool, wss_off: Option<cli::WssOff>) -> bool {
    waits_for_tray && wss_off.is_some()
}

/// The exit code of the joined server thread.
fn exit_code(server: thread::Result<io::Result<()>>) -> ExitCode {
    match server {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(_)) | Err(_) => ExitCode::FAILURE,
    }
}

/// Opens the window a page asks for: `showSettings` the settings, `showBundleManager` the
/// About window's «Модули» tab; `installBundle` points the user to the plugin registry in a
/// tray notification. There is no key store explorer and no AdES window.
fn open_requested_window(window: UiRequest) {
    match window {
        UiRequest::Settings => oncl_ui::open_window(DesktopWindow::Settings),
        UiRequest::BundleManager => oncl_ui::open_window(DesktopWindow::Modules),
        UiRequest::InstallBundle => {
            post_to_tray(|status| status.bundle_notification(Instant::now()));
        }
        UiRequest::KeystoreExplorer | UiRequest::AdesSigning | UiRequest::AdesValidation => {
            tracing::info!(?window, "window requested; not available");
        }
    }
}

/// Checks the certificate in `files` now and then once a day by the wall clock
/// ([`renewal::check`], [`renewal::check_due`]): a re-issued one goes to `wss` at once
/// ([`Wss::reload`]); the outcome goes to the tray.
fn start_renewal(files: TlsFiles, wss: Arc<Wss>) {
    let spawned = thread::Builder::new().name("renewal".into()).spawn(move || {
        loop {
            let checked = SystemTime::now();
            let check = renewal::check(&files, OffsetDateTime::now_utc(), || wss.reload());
            if matches!(check, RenewalCheck::Renewed { .. }) {
                // It may have started wss, too, or met a busy port the watch should wait out.
                look_for_tray(&wss);
                wss.watch_if_allowed();
            }
            match &check {
                RenewalCheck::Nothing => {}
                RenewalCheck::Due { days, expired } => {
                    tracing::info!(days, expired, "the server certificate is due for renewal");
                }
                RenewalCheck::Renewed { not_after } => {
                    tracing::info!(%not_after, "the server certificate is re-issued with mkcert");
                }
                RenewalCheck::RenewFailed { days, failure } => {
                    tracing::warn!(days, ?failure, "cannot re-issue the server certificate with mkcert");
                }
            }
            post_to_tray(move |status| {
                status.renewal = check;
                status.renewal_notification()
            });
            // Monotonic sleep stops while the computer sleeps: wake hourly, compare clocks.
            while !renewal::check_due(checked, SystemTime::now()) {
                thread::sleep(renewal::WAKE_EVERY);
            }
        }
    });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "cannot start the certificate renewal");
    }
}

/// What the settings, TLS wizard and About windows show and change. A save runs
/// `on_saved`. A certificate the wizard saves goes to `wss` at once: served, or wss started
/// with it, or kept for when the port is free or for the next start ([`Wss::apply_saved`]).
/// The settings window shows the `updates` and checks for them.
fn desktop_windows(
    paths: &Paths,
    locale: Locale,
    modules: Vec<String>,
    on_saved: Box<dyn Fn(&Settings)>,
    reports: Arc<SelftestReports>,
    wss: Arc<Wss>,
    updates: UpdaterHandle,
) -> DesktopWindows {
    let exe = std::env::current_exe().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "the program's path is unknown; autostart cannot be set");
        PathBuf::new()
    });
    let bundles = oncl_accessory::bundles()
        .into_iter()
        .map(|(symname, version)| (symname.to_owned(), version.to_owned()))
        .collect();
    let saved_to = Arc::clone(&wss);
    DesktopWindows {
        locale,
        settings: desktop::settings_services(paths, exe, wss.port(), Box::new(updates)),
        about: AboutInfo {
            commit: env!("ONCL_GIT_COMMIT").to_owned(),
            bundles,
            modules,
        },
        tls: desktop::tls_wizard_services(paths, reports, wss, move |files: &TlsFiles| {
            // A new certificate is not due: the tray forgets the reminder. It may have
            // started wss; if not, the tray shows the port as it is (on the wizard's worker
            // thread).
            let state = renewal::state(files, OffsetDateTime::now_utc());
            post_to_tray(move |status| {
                status.renewal = state;
                None
            });
            look_for_tray(&saved_to);
        }),
        on_saved,
    }
}

/// What a save of the settings window changes in the daemon: the proxy of `http`, and the
/// language of the tray, if it is still there.
fn on_settings_saved(
    http: Arc<LiveProxyTransport>,
    tray: Weak<TrayHandle>,
) -> Box<dyn Fn(&Settings)> {
    Box::new(move |settings: &Settings| {
        http.set_proxy(settings.proxy.clone());
        let locale = settings.ui_locale();
        if let Some(tray) = tray.upgrade() {
            tray.set_locale(locale);
        }
        post_to_tray(move |status| {
            status.locale = locale;
            None
        });
    })
}

/// The tray in `locale` showing `state`, or `None` (logged) if it cannot be shown. Its
/// commands run on the event loop: «Выход» notifies `stop`, «Журнал» opens `logs`,
/// «Настройки…», «Сертификат для браузера…» and «О программе» open their windows,
/// «Остановить оригинал…» asks before stopping the original that keeps `wss` off,
/// «Проверить обновления» has the `updates` check and notifies what they found. With
/// `needed`, `run` cannot go on without it (wss waits for the tray).
fn start_tray(
    locale: Locale,
    logs: PathBuf,
    state: TrayState,
    stop: Arc<Notify>,
    wss: Arc<Wss>,
    updates: UpdaterHandle,
    needed: bool,
) -> Option<TrayHandle> {
    let tray = oncl_ui::start_tray(locale, move |command| match command {
        TrayCommand::Quit => {
            tracing::info!("quit from the tray");
            stop.notify_one();
        }
        TrayCommand::OpenLogs => open_folder(&logs),
        TrayCommand::Settings => oncl_ui::open_window(DesktopWindow::Settings),
        TrayCommand::About => oncl_ui::open_window(DesktopWindow::About),
        TrayCommand::TlsWizard => oncl_ui::open_window(DesktopWindow::TlsWizard),
        TrayCommand::StopOriginal => offer_to_stop_original(&wss),
        TrayCommand::CheckUpdates => {
            let updates = updates.clone();
            spawn_named("check-updates", move || {
                let found = updates.check_now(None);
                post_to_tray(move |status| status.update_notification(&Notice::Checked(found)));
            });
        }
    });
    match tray {
        Ok(tray) => {
            tray.set_state(state);
            Some(tray)
        }
        Err(e) if needed => {
            tracing::error!(error = %e, "the system tray is unavailable, and wss cannot start without it: exiting");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "the system tray is unavailable; running without it");
            None
        }
    }
}

/// The daemon as the updater sees it.
struct DaemonHost {
    stop: Arc<Notify>,
    /// Whether the windows' event loop runs (its windows can be open).
    loop_runs: Arc<AtomicBool>,
}

/// How long the event loop has to say whether a window is open; one that does not answer
/// counts as one open.
const WINDOW_ASK: Duration = Duration::from_secs(10);

impl DaemonHost {
    fn window_open(&self) -> bool {
        self.loop_runs.load(Ordering::SeqCst) && window_open()
    }
}

impl Host for DaemonHost {
    fn busy(&self) -> bool {
        !requests_idle(update::QUIET) || self.window_open()
    }

    fn hold(&self) -> bool {
        if !hold_requests() {
            return false;
        }
        if self.window_open() {
            release_requests();
            return false;
        }
        true
    }

    fn release(&self) {
        release_requests();
    }

    fn notify(&self, notice: Notice) {
        post_to_tray(move |status| status.update_notification(&notice));
    }

    fn exit(&self) {
        self.stop.notify_one();
    }
}

/// Whether a window of the daemon is open, asked on the event loop.
fn window_open() -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    let asked = oncl_ui::run_on_event_loop(move || {
        let _ = tx.send(oncl_ui::any_window_open());
    });
    if asked.is_err() {
        return false;
    }
    rx.recv_timeout(WINDOW_ASK).unwrap_or(true)
}

/// The updater of this copy and what it found at the start, or why it is off: only a copy
/// installed through Velopack, built with the keys of the update index, updates itself.
/// It downloads through `http` (the proxy of the settings) and exits through `stop`.
fn updater(
    paths: &Paths,
    http: Arc<LiveProxyTransport>,
    stop: Arc<Notify>,
    loop_runs: Arc<AtomicBool>,
) -> (UpdaterHandle, Startup) {
    let transport: Arc<dyn HttpTransport> = http;
    let available = update::availability(embedded_keys(), Flavor::current(), || {
        VelopackInstaller::detect(Arc::clone(&transport))
    });
    let (keys, flavor, installer) = match available {
        Ok(available) => available,
        Err(status) => return (UpdaterHandle::Off(status), Startup::Normal),
    };
    let updater = Updater::new(
        UpdaterConfig {
            data_dir: paths.data.clone(),
            settings: paths.settings(),
            base: update::index_base(),
            keys,
            flavor,
            idle_poll: update::IDLE_POLL,
            health_grace: update::HEALTH_GRACE,
            health_settle: update::HEALTH_SETTLE,
        },
        transport,
        Box::new(installer),
        Box::new(DaemonHost { stop, loop_runs }),
    );
    let startup = updater.startup();
    (UpdaterHandle::Running(Arc::new(updater)), startup)
}

/// A flag set from its creation to its drop, however its owner ends (a panic included).
struct Flag(Arc<AtomicBool>);

impl Flag {
    fn set(flag: Arc<AtomicBool>) -> Flag {
        flag.store(true, Ordering::SeqCst);
        Flag(flag)
    }
}

impl Drop for Flag {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Runs `f` on a thread named `name`; a thread that cannot start is logged.
fn spawn_named(name: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = thread::Builder::new().name(name.into()).spawn(f) {
        tracing::warn!(thread = name, error = %e, "cannot start a thread");
    }
}

/// Shows `dir`, created if missing, in the file manager without waiting for it.
fn open_folder(dir: &Path) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!(dir = %dir.display(), error = %e, "cannot create the directory");
        return;
    }
    let mut command = file_manager(dir);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match command.spawn() {
        // Reaped in the background: a file manager may take its time to return.
        Ok(mut child) => {
            if let Err(e) = thread::Builder::new()
                .name("file-manager".into())
                .spawn(move || child.wait())
            {
                tracing::warn!(error = %e, "cannot wait for the file manager");
            }
        }
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "cannot open the file manager");
        }
    }
}

/// The command that shows `dir` in the platform's file manager.
fn file_manager(dir: &Path) -> std::process::Command {
    let program = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let mut command = std::process::Command::new(program);
    command.arg(dir);
    command
}

/// The prompter of the `e2e-prompter` script, if the feature is on and the script set.
fn scripted_prompter() -> Result<Option<Arc<dyn Prompter>>, ExitCode> {
    #[cfg(feature = "e2e-prompter")]
    let scripted = cli::e2e_prompter()?.map(|p| Arc::new(p) as Arc<dyn Prompter>);
    #[cfg(not(feature = "e2e-prompter"))]
    let scripted = None;
    Ok(scripted)
}

/// The bridge and the wss server on each listener `listeners` brings (at the start, or once
/// [`Wss`] starts it later; its self-test reports going to `reports`), until the bridge or a
/// wss server stops or `stop` is notified.
async fn serve_all(
    ipc: IpcListener,
    mut listeners: mpsc::UnboundedReceiver<Listening>,
    registry: Arc<Registry>,
    reports: Arc<SelftestReports>,
    stop: Arc<Notify>,
) -> io::Result<()> {
    let bridge = serve_ipc(ipc, Arc::clone(&registry));
    let stopped = stop.notified();
    tokio::pin!(bridge, stopped);
    let mut servers = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            result = &mut bridge => return result,
            () = &mut stopped => {
                tracing::info!("stopping the servers");
                return Ok(());
            }
            Some(Listening { tls, listener }) = listeners.recv() => {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                let cfg = ServerConfig {
                    selftest: Arc::clone(&reports),
                    ..ServerConfig::new(tls, Arc::clone(&registry))
                };
                servers.spawn(serve(listener, cfg));
            }
            // `serve` returns only if it cannot run.
            Some(ended) = servers.join_next() => return ended.map_err(io::Error::other)?,
        }
    }
}

/// Drops `runtime` without waiting for its blocking tasks: a signing flow may be blocked in
/// a dialog that will never answer once the server has stopped.
fn stop_runtime(runtime: Runtime) {
    runtime.shutdown_background();
}

/// Joins `thread` if it finishes within `timeout`; `None` leaves it running.
fn join_within<T>(thread: JoinHandle<T>, timeout: Duration) -> Option<thread::Result<T>> {
    let deadline = Instant::now() + timeout;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
    Some(thread.join())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn join_gives_up_on_a_running_thread() {
        let done = thread::spawn(|| 7);
        assert_eq!(
            join_within(done, Duration::from_secs(5)).unwrap().unwrap(),
            7
        );

        let (tx, rx) = mpsc::channel::<()>();
        let stuck = thread::spawn(move || rx.recv());
        let started = Instant::now();
        assert!(join_within(stuck, Duration::from_millis(100)).is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(tx);
    }

    #[test]
    fn runtime_stops_despite_a_blocked_task() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (tx, rx) = mpsc::channel::<()>();
        // Like a signing flow waiting for a dialog that never answers.
        drop(runtime.spawn_blocking(move || rx.recv()));
        let started = Instant::now();
        stop_runtime(runtime);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(tx);
    }

    /// A wss listener on a free port of `127.0.0.1`, with a certificate saved under `dir`.
    fn listening(dir: &Path) -> Listening {
        let files = oncl_tls::TlsFiles {
            dir: dir.join("tls"),
        };
        let material = oncl_tls::generate(time::OffsetDateTime::now_utc(), "stop").unwrap();
        oncl_tls::save(&files, &material).unwrap();
        let tls = Arc::new(oncl_tls::server_config(&files).unwrap());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Listening {
            tls: Arc::new(openncalayer::LiveTls::new(tls)),
            listener,
        }
    }

    async fn bridge(dir: &Path) -> IpcListener {
        oncl_ipc::bind(&oncl_ipc::endpoint(dir).unwrap())
            .await
            .unwrap()
    }

    /// `serve_all` with the bridge in `dir` and, if `wss`, a wss server on a free port;
    /// `stop` notified before it starts.
    async fn serve_all_stopped(dir: &Path, wss: bool) -> io::Result<()> {
        let ipc = bridge(dir).await;
        let (listeners, received) = tokio::sync::mpsc::unbounded_channel();
        if wss {
            assert!(listeners.send(listening(dir)).is_ok());
        }
        let stop = Arc::new(Notify::new());
        // Like «Выход» picked before the servers got to wait for it.
        stop.notify_one();
        tokio::time::timeout(
            Duration::from_secs(10),
            serve_all(
                ipc,
                received,
                Arc::new(Registry::default()),
                Arc::new(SelftestReports::new()),
                stop,
            ),
        )
        .await
        .expect("the servers did not stop")
    }

    /// A listener handed over while the servers run (wss started later, [`Wss`]) is served:
    /// a connection that is no TLS gets closed.
    #[test]
    fn a_later_listener_is_served() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        runtime.block_on(async {
            let ipc = bridge(dir.path()).await;
            let (listeners, received) = tokio::sync::mpsc::unbounded_channel();
            let stop = Arc::new(Notify::new());
            let servers = tokio::spawn(serve_all(
                ipc,
                received,
                Arc::new(Registry::default()),
                Arc::new(SelftestReports::new()),
                Arc::clone(&stop),
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;
            let later = listening(dir.path());
            let address = later.listener.local_addr().unwrap();
            assert!(listeners.send(later).is_ok());

            let mut tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            let mut rest = Vec::new();
            // Only a served listener's connection is answered and closed; one left in the
            // backlog would wait for the timeout.
            let closed = tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut rest))
                .await
                .expect("the connection was not served");
            drop(closed);

            stop.notify_one();
            tokio::time::timeout(Duration::from_secs(10), servers)
                .await
                .expect("the servers did not stop")
                .unwrap()
                .unwrap();
        });
    }

    #[test]
    fn stop_ends_the_servers() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        for wss in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            runtime
                .block_on(serve_all_stopped(dir.path(), wss))
                .unwrap_or_else(|e| panic!("wss {wss}: {e}"));
        }
    }

    #[test]
    fn a_lost_tray_ends_run_only_while_wss_is_off() {
        use cli::WssOff;
        assert!(tray_loss_ends_run(true, Some(WssOff::TlsNotConfigured)));
        // The user stopped the original or saved a certificate within the grace.
        assert!(!tray_loss_ends_run(true, None));
        // A daemon that does not wait for the tray (configured, or `--allow-no-wss`).
        assert!(!tray_loss_ends_run(false, Some(WssOff::TlsNotConfigured)));
        assert!(!tray_loss_ends_run(false, None));
    }

    #[test]
    fn file_manager_opens_the_directory() {
        let dir = Path::new("data").join("logs");
        let command = file_manager(&dir);
        let expected = if cfg!(windows) {
            "explorer"
        } else if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        assert_eq!(command.get_program(), expected);
        assert_eq!(command.get_args().collect::<Vec<_>>(), [dir.as_os_str()]);
    }
}
