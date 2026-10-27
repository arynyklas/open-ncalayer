//! The settings window on the event loop: one at a time, its loading and actions are jobs
//! ([`worker`]). While one runs the window waits (`busy`) and cannot be closed, so its outcome
//! is shown; a successful save takes effect in the daemon even if the window is gone (e.g.
//! destroyed by the windowing system).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use oncl_basics::Locale;
use oncl_desktop::Settings;
use slint::{CloseRequestResponse, ComponentHandle, PlatformError, SharedString};

use super::texts::Texts;
use super::{
    ActionError, Language, ProxyMode, SaveError, SettingsForm, SettingsServices, Snapshot, States,
    action_error_text, extension_view, form_error_text, index_of, item, original_view,
    save_error_text,
};
use crate::foreground;
use crate::prompter::select_desktop_language;
use crate::ui::SettingsWindow;
use crate::windows::Desktop;
use crate::worker::{self, JobWindow, run, with};

/// The open settings window. Its callbacks find it by `id` in [`OPEN`], so that none holds
/// it (a reference cycle) and a late result never reaches a window opened since.
struct Open {
    id: u64,
    ui: SettingsWindow,
    desktop: Rc<Desktop>,
}

thread_local! {
    static OPEN: RefCell<Option<Rc<Open>>> = const { RefCell::new(None) };
    static NEXT_ID: Cell<u64> = const { Cell::new(0) };
}

/// The settings window `id`, if it is open.
fn current(id: u64) -> Option<Rc<Open>> {
    OPEN.with_borrow(|open| open.as_ref().filter(|o| o.id == id).cloned())
}

/// Whether the settings window is open.
pub(crate) fn is_open() -> bool {
    OPEN.with_borrow(Option::is_some)
}

/// Shows the settings window, or brings the open one to the front. On the event loop.
pub(crate) fn open(desktop: &Rc<Desktop>) {
    if let Some(open) = OPEN.with_borrow(Clone::clone) {
        select_desktop_language(desktop.locale.get());
        if let Err(e) = open.ui.show() {
            tracing::warn!(error = %e, "cannot show the settings window");
        }
        foreground::take(&open.ui);
        return;
    }
    if let Err(e) = create(desktop) {
        tracing::error!(error = %e, "cannot show the settings window");
    }
}

fn create(desktop: &Rc<Desktop>) -> Result<(), PlatformError> {
    let ui = SettingsWindow::new()?;
    let locale = desktop.locale.get();
    select_desktop_language(locale);
    let t = Texts::of(locale);
    ui.set_original_state(t.loading.into());
    ui.set_extension_state(t.loading.into());
    let id = NEXT_ID.replace(NEXT_ID.get() + 1);
    let open = Rc::new(Open {
        id,
        ui: ui.clone_strong(),
        desktop: Rc::clone(desktop),
    });

    ui.on_save(move || with(id, save));
    ui.on_disable_original(move || {
        with(id, |open| {
            act(open, SettingsServices::disable_original, false, |t| {
                (t.original_disabled, t.cannot_disable_original)
            });
        });
    });
    ui.on_restore_original(move || {
        with(id, |open| {
            act(open, SettingsServices::restore_original, true, |t| {
                (t.original_restored, t.cannot_restore_original)
            });
        });
    });
    ui.on_register_extension(move || {
        with(id, |open| {
            act(open, SettingsServices::register_extension, false, |t| {
                (t.extension_registered_now, t.cannot_register)
            });
        });
    });
    ui.on_unregister_extension(move || {
        with(id, |open| {
            act(open, SettingsServices::unregister_extension, false, |t| {
                (t.extension_unregistered, t.cannot_unregister)
            });
        });
    });
    ui.on_dismiss(move || {
        close_requested(id);
    });
    ui.window().on_close_requested(move || close_requested(id));

    OPEN.set(Some(Rc::clone(&open)));
    if let Err(e) = ui.show() {
        OPEN.set(None);
        return Err(e);
    }
    foreground::take(&ui);
    run(
        &*open,
        |s| s.load(),
        |desktop, open, snapshot| {
            if let Some(open) = open {
                show_snapshot(&open.ui, &snapshot, desktop.locale.get());
            }
        },
    );
    Ok(())
}

/// Fills `ui` with `snapshot` in `l`: the form, the states and what could not be read.
pub(crate) fn show_snapshot(ui: &SettingsWindow, snapshot: &Snapshot, l: Locale) {
    let t = Texts::of(l);
    show_form(ui, &snapshot.form);
    show_states(ui, &snapshot.states, l);
    let problems: Vec<String> = [
        (t.cannot_read_settings, &snapshot.settings_error),
        (t.cannot_read_autostart, &snapshot.autostart_error),
    ]
    .into_iter()
    .filter_map(|(what, e)| Some(format!("{what}: {}", e.as_ref()?)))
    .collect();
    show_message(ui, &problems.join("\n"), true);
}

/// «Закрыть» or the window's close button: closes the window `id`, unless it waits for an
/// action, whose outcome the user must see.
fn close_requested(id: u64) -> CloseRequestResponse {
    worker::close_requested::<Open>(id, close)
}

/// Closes the settings window `id`.
fn close(id: u64) {
    let Some(open) = OPEN.with_borrow_mut(|slot| slot.take_if(|open| open.id == id)) else {
        return;
    };
    if let Err(e) = open.ui.hide() {
        tracing::warn!(error = %e, "cannot hide the settings window");
    }
    // This runs inside one of the window's callbacks: release the window after it.
    slint::Timer::single_shot(Duration::ZERO, move || drop(open));
}

/// «Сохранить»: checks the form at once, saves it on a worker thread, then [`saved`].
fn save(open: &Open) {
    let form = form_of(&open.ui);
    if let Err(e) = form.settings() {
        show_message(
            &open.ui,
            form_error_text(e, open.desktop.locale.get()),
            true,
        );
        return;
    }
    run(open, move |s| (s.save(&form), s.states()), saved);
}

/// The outcome of «Сохранить». Saved settings take effect in the daemon (the windows'
/// language, the proxy, the tray) whether or not the window is still open; the window, if
/// it is, shows the outcome and the states in the (perhaps new) language.
fn saved(
    desktop: &Desktop,
    open: Option<&Open>,
    (saved, states): (Result<Settings, SaveError>, States),
) {
    match &saved {
        Ok(settings) => {
            let l = settings.ui_locale();
            desktop.locale.set(l);
            select_desktop_language(l);
            (desktop.on_saved)(settings);
        }
        Err(e) => tracing::warn!(error = ?e, "settings window: cannot save"),
    }
    let Some(open) = open else {
        return;
    };
    let l = desktop.locale.get();
    match &saved {
        Ok(_) => show_message(&open.ui, Texts::of(l).saved, false),
        Err(e) => show_message(&open.ui, &save_error_text(e, l), true),
    }
    show_states(&open.ui, &states, l);
}

/// The messages of an action: on success, on failure.
type ActionTexts = fn(&Texts) -> (&'static str, &'static str);

/// An action of the window.
type Action = fn(&SettingsServices) -> Result<(), ActionError>;

/// Runs `action` on a worker thread, then shows its outcome and the new states. With
/// `refresh_autostart` («Вернуть оригинал», which turns ours off) the form's box takes the
/// entry's new state; other actions leave an unsaved change of the box alone.
fn act(open: &Open, action: Action, refresh_autostart: bool, texts: ActionTexts) {
    run(
        open,
        move |s| {
            let done = action(s);
            let autostart = refresh_autostart
                .then(|| s.autostart.enabled().ok())
                .flatten();
            (done, autostart, s.states())
        },
        move |desktop, open, (done, autostart, states)| {
            let l = desktop.locale.get();
            let (ok, failed) = texts(Texts::of(l));
            if let Err(e) = &done {
                tracing::warn!(error = ?e, "settings window: {failed}");
            }
            let Some(open) = open else {
                return;
            };
            match done {
                Ok(()) => show_message(&open.ui, ok, false),
                Err(e) => show_message(&open.ui, &action_error_text(&e, failed, l), true),
            }
            if let Some(on) = autostart {
                open.ui.set_autostart(on);
            }
            show_states(&open.ui, &states, l);
        },
    );
}

impl JobWindow for Open {
    type Services = SettingsServices;
    const NAME: &'static str = "settings";

    fn find(id: u64) -> Option<Rc<Open>> {
        current(id)
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn desktop(&self) -> &Rc<Desktop> {
        &self.desktop
    }

    fn services(&self) -> Arc<SettingsServices> {
        Arc::clone(&self.desktop.settings)
    }

    fn busy(&self) -> bool {
        self.ui.get_busy()
    }

    fn set_busy(&self, busy: bool) {
        self.ui.set_busy(busy);
    }

    fn show_message(&self, text: &str, error: bool) {
        show_message(&self.ui, text, error);
    }

    fn failure_text(&self) -> &'static str {
        Texts::of(self.desktop.locale.get()).cannot_start
    }
}

fn show_form(ui: &SettingsWindow, form: &SettingsForm) {
    ui.set_language(index_of(&Language::ALL, &form.language));
    ui.set_autostart(form.autostart);
    ui.set_proxy_mode(index_of(&ProxyMode::ALL, &form.proxy_mode));
    ui.set_proxy_url(form.proxy_url.as_str().into());
}

fn form_of(ui: &SettingsWindow) -> SettingsForm {
    SettingsForm {
        language: item(&Language::ALL, ui.get_language()),
        autostart: ui.get_autostart(),
        proxy_mode: item(&ProxyMode::ALL, ui.get_proxy_mode()),
        proxy_url: ui.get_proxy_url().to_string(),
    }
}

fn show_states(ui: &SettingsWindow, states: &States, l: Locale) {
    let original = original_view(&states.original, l);
    ui.set_original_state(original.text.into());
    ui.set_can_disable_original(original.can_disable);
    ui.set_can_restore_original(original.can_restore);
    let extension = extension_view(&states.extension, l);
    ui.set_extension_state(extension.text.into());
    ui.set_can_unregister_extension(extension.can_unregister);
}

fn show_message(ui: &SettingsWindow, text: &str, error: bool) {
    ui.set_message(SharedString::from(text));
    ui.set_message_is_error(error);
}

/// The window on the offscreen platform of the tests, without an event loop: a worker's
/// result never arrives by itself, so the window keeps waiting until a test calls
/// [`finish`].
#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings_view::fakes::{FakeOriginal, services};
    use crate::windows::{DesktopWindows, set_desktop_windows};
    use crate::{AboutInfo, offscreen};
    use oncl_desktop::ProxySetting;

    /// The windows on a sandbox under `root`; the proxies `on_saved` got.
    fn desktop(root: &std::path::Path) -> (Rc<Desktop>, Rc<RefCell<Vec<ProxySetting>>>) {
        offscreen::install();
        worker::manual::enable();
        let applied = Rc::new(RefCell::new(Vec::new()));
        let record = Rc::clone(&applied);
        set_desktop_windows(DesktopWindows {
            locale: Locale::Ru,
            settings: services(root, FakeOriginal::default()),
            about: AboutInfo::default(),
            tls: crate::tls_wizard::fakes::services(root, Vec::new(), None),
            on_saved: Box::new(move |s: &Settings| record.borrow_mut().push(s.proxy.clone())),
        });
        (crate::windows::desktop().unwrap(), applied)
    }

    fn the_window() -> Rc<Open> {
        OPEN.with_borrow(Clone::clone)
            .expect("the settings window is open")
    }

    #[test]
    fn a_waiting_window_cannot_be_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (desktop, _) = desktop(dir.path());
        open(&desktop);
        let window = the_window();
        // Loading runs on a worker: the window waits for it.
        assert!(window.ui.get_busy());
        assert_eq!(
            close_requested(window.id),
            CloseRequestResponse::KeepWindowShown
        );
        window.ui.invoke_dismiss();
        assert!(is_open());

        let snapshot = desktop.settings.load();
        worker::finish::<Open, _>(window.id, Ok(snapshot), |desktop, open, snapshot| {
            show_snapshot(&open.unwrap().ui, &snapshot, desktop.locale.get());
        });
        assert!(!window.ui.get_busy());
        assert_eq!(close_requested(window.id), CloseRequestResponse::HideWindow);
        assert!(!is_open());
    }

    #[test]
    fn a_save_takes_effect_without_its_window() {
        let dir = tempfile::tempdir().unwrap();
        let (desktop, applied) = desktop(dir.path());
        open(&desktop);
        let window = the_window();
        worker::finish::<Open, _>(window.id, Ok(()), |_, _, ()| {});

        // «Сохранить» with English and the system's proxy: the window waits for the worker.
        window
            .ui
            .set_language(index_of(&Language::ALL, &Language::En));
        window
            .ui
            .set_proxy_mode(index_of(&ProxyMode::ALL, &ProxyMode::System));
        window.ui.invoke_save();
        assert!(window.ui.get_busy());
        assert_eq!(
            close_requested(window.id),
            CloseRequestResponse::KeepWindowShown
        );

        // The window is destroyed before the result arrives: the save still applies.
        let id = window.id;
        OPEN.set(None);
        drop(window);
        let form = SettingsForm {
            language: Language::En,
            autostart: false,
            proxy_mode: ProxyMode::System,
            proxy_url: String::new(),
        };
        let result = (desktop.settings.save(&form), desktop.settings.states());
        worker::finish::<Open, _>(id, Ok(result), saved);
        assert_eq!(*applied.borrow(), [ProxySetting::System]);
        assert_eq!(desktop.locale.get(), Locale::En);

        // A failed save changes nothing in the daemon.
        let bad = SettingsForm {
            proxy_mode: ProxyMode::Manual,
            proxy_url: "socks5://proxy.test:1080".to_owned(),
            ..form
        };
        let result = (desktop.settings.save(&bad), desktop.settings.states());
        worker::finish::<Open, _>(id, Ok(result), saved);
        assert_eq!(applied.borrow().len(), 1);
    }

    #[test]
    fn a_broken_job_frees_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let (desktop, _) = desktop(dir.path());
        open(&desktop);
        let window = the_window();
        assert_eq!(worker::manual::run_all(), 1);
        assert!(!window.ui.get_busy());

        run(
            &*window,
            |_| -> () { panic!("a broken job") },
            |_, _, ()| unreachable!("a panicked job has no result"),
        );
        assert!(window.ui.get_busy());
        assert_eq!(
            close_requested(window.id),
            CloseRequestResponse::KeepWindowShown
        );
        assert_eq!(worker::manual::run_all(), 1);
        assert!(!window.ui.get_busy());
        assert!(window.ui.get_message_is_error());
        assert_eq!(
            window.ui.get_message(),
            Texts::of(desktop.locale.get()).cannot_start
        );
        assert_eq!(close_requested(window.id), CloseRequestResponse::HideWindow);
        assert!(!is_open());
    }
}
