//! The daemon's own windows, settings, the TLS wizard and About: [`set_desktop_windows`]
//! gives them what they show and change, [`open_window`] opens one from any thread (the tray
//! menu, a notification, a page's `showSettings` or `showBundleManager`). They live on the
//! event loop of
//! [`run_event_loop`](crate::run_event_loop); closing them does not end it.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use oncl_basics::Locale;
use oncl_desktop::Settings;

use crate::about_view::{self, AboutInfo, AboutTab};
use crate::prompter::select_desktop_language;
use crate::settings_view::{self, SettingsServices};
use crate::tls_wizard::{self, TlsWizardServices};

/// A window of the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopWindow {
    /// «Настройки».
    Settings,
    /// «Сертификат для браузера» (the TLS wizard).
    TlsWizard,
    /// «О программе».
    About,
    /// «О программе» on its «Модули» tab (`showBundleManager`).
    Modules,
}

/// What the windows show and change.
pub struct DesktopWindows {
    /// The language of the windows until the settings window saves another.
    pub locale: Locale,
    pub settings: SettingsServices,
    pub about: AboutInfo,
    pub tls: TlsWizardServices,
    /// Runs on the event loop once the settings window has saved new settings.
    pub on_saved: Box<dyn Fn(&Settings)>,
}

/// [`DesktopWindows`] on the event loop.
pub(crate) struct Desktop {
    pub(crate) locale: Cell<Locale>,
    pub(crate) settings: Arc<SettingsServices>,
    pub(crate) about: AboutInfo,
    pub(crate) tls: Arc<TlsWizardServices>,
    pub(crate) on_saved: Box<dyn Fn(&Settings)>,
}

thread_local! {
    static DESKTOP: RefCell<Option<Rc<Desktop>>> = const { RefCell::new(None) };
}

/// Makes the windows available. Call it on the thread that runs
/// [`run_event_loop`](crate::run_event_loop), before it does.
pub fn set_desktop_windows(windows: DesktopWindows) {
    let desktop = Desktop {
        locale: Cell::new(windows.locale),
        settings: Arc::new(windows.settings),
        about: windows.about,
        tls: Arc::new(windows.tls),
        on_saved: windows.on_saved,
    };
    DESKTOP.set(Some(Rc::new(desktop)));
}

/// The windows of [`set_desktop_windows`], on this thread.
pub(crate) fn desktop() -> Option<Rc<Desktop>> {
    DESKTOP.with_borrow(Clone::clone)
}

/// Opens `window` on the event loop, or brings it to the front; callable from any thread,
/// returns at once. Without an event loop (no windows, e.g. a scripted e2e run) or without
/// [`set_desktop_windows`] the request is only logged.
pub fn open_window(window: DesktopWindow) {
    if let Err(e) = slint::invoke_from_event_loop(move || open_now(window)) {
        tracing::info!(?window, error = %e, "no windows: the window is not opened");
    }
}

fn open_now(window: DesktopWindow) {
    let Some(desktop) = desktop() else {
        tracing::info!(?window, "no windows: the window is not opened");
        return;
    };
    match window {
        DesktopWindow::Settings => settings_view::open(&desktop),
        DesktopWindow::TlsWizard => tls_wizard::open(&desktop),
        DesktopWindow::About => about_view::open(&desktop, AboutTab::Program),
        DesktopWindow::Modules => about_view::open(&desktop, AboutTab::Modules),
    }
}

/// Whether the settings, TLS wizard, About or stop-the-original window is open. On the
/// event loop (each window lives in its thread's slot); elsewhere it is `false`.
pub fn any_window_open() -> bool {
    settings_view::is_open()
        || tls_wizard::is_open()
        || about_view::is_open()
        || crate::stop_original::is_open()
}

/// After a signing dialog: the open settings, TLS wizard, About or stop-the-original window
/// gets its language back (the translation is the thread's, and the dialog had its page's).
pub(crate) fn restore_language() {
    if !any_window_open() {
        return;
    }
    if let Some(desktop) = desktop() {
        select_desktop_language(desktop.locale.get());
    }
}
