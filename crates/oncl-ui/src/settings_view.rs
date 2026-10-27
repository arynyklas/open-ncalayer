//! The settings window: the language, our autostart and the proxy, saved together into
//! `settings.json` and our autostart entry; the original NCALayer's autostart and the browser
//! extension's registration, acted on at once.
//!
//! The window's logic without a window is public: [`SettingsForm`] (what the form shows and
//! the settings it gives), [`SettingsServices`] (loading and the actions, on sandboxes in
//! tests) and the texts of the states ([`original_view`], [`extension_view`]). The actions
//! run on a worker thread; the window waits for them.

use std::cell::{Cell, RefCell};
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use oncl_basics::Locale;
use oncl_desktop::original::EntryKind;
use oncl_desktop::{
    Autostart, BrowserExtension, ExtensionStatus, OriginalControl, OriginalStatus, ProxySetting,
    Settings,
};
use slint::{CloseRequestResponse, ComponentHandle, PlatformError, SharedString};

use crate::foreground;
use crate::prompter::select_language;
use crate::ui::SettingsWindow;
use crate::windows::Desktop;

/// The language choice of the form, in the order of its list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    /// The system's language (no `locale` in `settings.json`).
    System,
    Ru,
    Kk,
    En,
}

impl Language {
    const ALL: [Language; 4] = [Language::System, Language::Ru, Language::Kk, Language::En];

    /// The choice of a `locale` setting; an unknown one counts as none.
    fn of(locale: Option<&str>) -> Language {
        match locale {
            Some("ru") => Language::Ru,
            Some("kk") => Language::Kk,
            Some("en") => Language::En,
            _ => Language::System,
        }
    }

    /// The `locale` setting of the choice.
    fn code(self) -> Option<&'static str> {
        match self {
            Language::System => None,
            Language::Ru => Some("ru"),
            Language::Kk => Some("kk"),
            Language::En => Some("en"),
        }
    }
}

/// The proxy choice of the form, in the order of its list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyMode {
    None,
    System,
    Manual,
}

impl ProxyMode {
    const ALL: [ProxyMode; 3] = [ProxyMode::None, ProxyMode::System, ProxyMode::Manual];
}

/// The list item at `i` of `all`; the first for an index out of range.
fn item<T: Copy>(all: &[T], i: i32) -> T {
    usize::try_from(i)
        .ok()
        .and_then(|i| all.get(i).copied())
        .unwrap_or(all[0])
}

/// The index of `value` in `all`.
fn index_of<T: PartialEq>(all: &[T], value: &T) -> i32 {
    all.iter()
        .position(|v| v == value)
        .and_then(|i| i32::try_from(i).ok())
        .unwrap_or(0)
}

/// What the form of the settings window holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsForm {
    pub language: Language,
    /// «Запускать при входе в систему».
    pub autostart: bool,
    pub proxy_mode: ProxyMode,
    /// The manual proxy's URL; kept while another mode is chosen.
    pub proxy_url: String,
}

/// Why the form cannot be saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormError {
    /// A manual proxy without a URL.
    ProxyUrlMissing,
    /// A manual proxy URL that is not an HTTP proxy ([`ProxySetting::validate`]).
    ProxyUrlInvalid,
}

impl SettingsForm {
    /// The form for `settings`, with our autostart entry's real state `autostart` (which
    /// wins over `settings.autostart`).
    pub fn new(settings: &Settings, autostart: bool) -> SettingsForm {
        let (proxy_mode, proxy_url) = match &settings.proxy {
            ProxySetting::None => (ProxyMode::None, String::new()),
            ProxySetting::System => (ProxyMode::System, String::new()),
            ProxySetting::Manual(url) => (ProxyMode::Manual, url.clone()),
        };
        SettingsForm {
            language: Language::of(settings.locale.as_deref()),
            autostart,
            proxy_mode,
            proxy_url,
        }
    }

    /// The settings the form gives. The URL is trimmed.
    ///
    /// # Errors
    ///
    /// A manual proxy without a usable URL.
    pub fn settings(&self) -> Result<Settings, FormError> {
        let proxy = match self.proxy_mode {
            ProxyMode::None => ProxySetting::None,
            ProxyMode::System => ProxySetting::System,
            ProxyMode::Manual => {
                let url = self.proxy_url.trim();
                if url.is_empty() {
                    return Err(FormError::ProxyUrlMissing);
                }
                let proxy = ProxySetting::Manual(url.to_owned());
                proxy.validate().map_err(|_| FormError::ProxyUrlInvalid)?;
                proxy
            }
        };
        Ok(Settings {
            locale: self.language.code().map(str::to_owned),
            autostart: self.autostart,
            proxy,
        })
    }
}

/// What the settings window works with: `settings.json`, our autostart entry for the
/// program `exe`, the original NCALayer and the browser extension's registration.
pub struct SettingsServices {
    pub settings_path: PathBuf,
    /// The program our autostart entry runs.
    pub exe: PathBuf,
    pub autostart: Box<dyn Autostart + Send + Sync>,
    pub original: Box<dyn OriginalControl>,
    pub extension: Box<dyn BrowserExtension>,
}

/// The original's and the extension's states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct States {
    pub original: OriginalStatus,
    pub extension: ExtensionStatus,
}

/// What the window shows when it opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub form: SettingsForm,
    /// `settings.json` could not be read: the form shows the defaults.
    pub settings_error: Option<String>,
    /// Our autostart entry could not be read: the form shows `settings.json`'s value.
    pub autostart_error: Option<String>,
    pub states: States,
}

/// Why saving failed.
#[derive(Debug)]
pub enum SaveError {
    Form(FormError),
    /// Our autostart entry could not be changed; nothing was saved.
    Autostart(io::Error),
    /// `settings.json` could not be written; the autostart entry is changed.
    Settings(io::Error),
}

impl SettingsServices {
    /// The settings, our autostart entry's real state and the states. Reads only.
    pub fn load(&self) -> Snapshot {
        let (settings, settings_error) = match Settings::load(&self.settings_path) {
            Ok(settings) => (settings, None),
            Err(e) => {
                tracing::warn!(error = %e, "settings window: cannot read the settings");
                (Settings::default(), Some(e.to_string()))
            }
        };
        let (autostart, autostart_error) = match self.autostart.enabled() {
            Ok(on) => (on, None),
            Err(e) => {
                tracing::warn!(error = %e, "settings window: cannot read the autostart entry");
                (settings.autostart, Some(e.to_string()))
            }
        };
        Snapshot {
            form: SettingsForm::new(&settings, autostart),
            settings_error,
            autostart_error,
            states: self.states(),
        }
    }

    /// The original's and the extension's states.
    pub fn states(&self) -> States {
        States {
            original: self.original.status(),
            extension: self.extension.status(),
        }
    }

    /// Saves `form`: first our autostart entry, if it differs from the form, then
    /// `settings.json` (its other keys kept). Returns the saved settings.
    ///
    /// # Errors
    ///
    /// The form is not valid or the autostart entry cannot be changed (nothing is saved),
    /// or `settings.json` cannot be written.
    pub fn save(&self, form: &SettingsForm) -> Result<Settings, SaveError> {
        let settings = form.settings().map_err(SaveError::Form)?;
        if self.autostart.enabled().ok() != Some(settings.autostart) {
            self.autostart
                .set(settings.autostart, &self.exe)
                .map_err(SaveError::Autostart)?;
        }
        settings
            .save(&self.settings_path)
            .map_err(SaveError::Settings)?;
        Ok(settings)
    }

    /// «Вернуть оригинал»: puts the original's autostart back, then turns ours off (the
    /// entry and `settings.json`).
    ///
    /// # Errors
    ///
    /// The original cannot be restored (ours is left as it is), or ours cannot be turned
    /// off.
    pub fn restore_original(&self) -> io::Result<()> {
        let report = self.original.restore()?;
        tracing::info!(changed = ?report.changed, "the original NCALayer's autostart is restored");
        self.autostart.set(false, &self.exe)?;
        let mut settings = Settings::load(&self.settings_path)?;
        settings.autostart = false;
        settings.save(&self.settings_path)
    }

    /// «Отключить автозапуск оригинала».
    ///
    /// # Errors
    ///
    /// See [`OriginalControl::disable`].
    pub fn disable_original(&self) -> io::Result<()> {
        let report = self.original.disable()?;
        tracing::info!(changed = ?report.changed, "the original NCALayer's autostart is disabled");
        Ok(())
    }
}

/// The original NCALayer's block: its text and which buttons work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalView {
    pub text: String,
    pub can_disable: bool,
    pub can_restore: bool,
}

/// The block of `status` in `l`. Only this user's entries can be disabled or restored; an
/// enabled `HKLM` entry gets the administrator's instructions.
pub fn original_view(status: &OriginalStatus, l: Locale) -> OriginalView {
    let t = Texts::of(l);
    let mut lines = vec![
        if status.found {
            t.original_found
        } else {
            t.original_not_found
        }
        .to_owned(),
    ];
    if status.found && status.autostart.is_empty() {
        lines.push(t.original_no_autostart.to_owned());
    }
    for entry in &status.autostart {
        let kind = match entry.kind {
            EntryKind::StartupShortcut => t.startup_shortcut,
            EntryKind::MachineRun => t.machine_run,
            EntryKind::DesktopEntry => t.desktop_entry,
        };
        let state = if entry.enabled { t.enabled } else { t.disabled };
        lines.push(format!("• {kind}: {} — {state}", entry.path.display()));
    }
    if status
        .autostart
        .iter()
        .any(|e| e.kind == EntryKind::MachineRun && e.enabled)
    {
        lines.push(t.machine_run_admin.to_owned());
    }
    if let Some(owner) = &status.port_owner {
        lines.push(format!("{}{owner}", t.port_owner));
    }
    let own = |enabled: bool| {
        status
            .autostart
            .iter()
            .any(|e| e.kind != EntryKind::MachineRun && e.enabled == enabled)
    };
    OriginalView {
        text: lines.join("\n"),
        can_disable: own(true),
        can_restore: own(false),
    }
}

/// The browser extension's block: its text and whether «Удалить» works.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionView {
    pub text: String,
    pub can_unregister: bool,
}

/// The block of `status` in `l`.
pub fn extension_view(status: &ExtensionStatus, l: Locale) -> ExtensionView {
    let t = Texts::of(l);
    let any = status.installed || status.broken || !status.browsers.is_empty();
    let text = if status.broken || (!status.installed && any) {
        t.extension_broken.to_owned()
    } else if !any {
        t.extension_not_registered.to_owned()
    } else if status.browsers.is_empty() {
        t.extension_no_browser.to_owned()
    } else {
        format!("{}{}", t.extension_registered, status.browsers.join(", "))
    };
    ExtensionView {
        text,
        can_unregister: any,
    }
}

/// The message of a form error in `l`.
pub fn form_error_text(e: FormError, l: Locale) -> &'static str {
    let t = Texts::of(l);
    match e {
        FormError::ProxyUrlMissing => t.proxy_url_missing,
        FormError::ProxyUrlInvalid => t.proxy_url_invalid,
    }
}

/// The message of a failed save in `l`.
fn save_error_text(e: &SaveError, l: Locale) -> String {
    let t = Texts::of(l);
    match e {
        SaveError::Form(e) => form_error_text(*e, l).to_owned(),
        SaveError::Autostart(e) => format!("{}: {e}", t.cannot_set_autostart),
        SaveError::Settings(e) => format!("{}: {e}", t.cannot_save),
    }
}

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

/// Shows the settings window, or brings the open one to the front. On the event loop.
pub(crate) fn open(desktop: &Rc<Desktop>) {
    if let Some(open) = OPEN.with_borrow(Clone::clone) {
        select_language(desktop.locale.get());
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
    select_language(locale);
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
            act(open, SettingsServices::disable_original, |t| {
                (t.original_disabled, t.cannot_disable_original)
            });
        });
    });
    ui.on_restore_original(move || {
        with(id, |open| {
            act(open, SettingsServices::restore_original, |t| {
                (t.original_restored, t.cannot_restore_original)
            });
        });
    });
    ui.on_register_extension(move || {
        with(id, |open| {
            act(
                open,
                |s| s.extension.register().map(drop),
                |t| (t.extension_registered_now, t.cannot_register),
            );
        });
    });
    ui.on_unregister_extension(move || {
        with(id, |open| {
            act(
                open,
                |s| s.extension.unregister().map(drop),
                |t| (t.extension_unregistered, t.cannot_unregister),
            );
        });
    });
    ui.on_dismiss(move || close(id));
    ui.window().on_close_requested(move || {
        close(id);
        CloseRequestResponse::HideWindow
    });

    OPEN.set(Some(Rc::clone(&open)));
    if let Err(e) = ui.show() {
        OPEN.set(None);
        return Err(e);
    }
    foreground::take(&ui);
    run(
        &open,
        |s| s.load(),
        |open, snapshot| show_snapshot(&open.ui, &snapshot, open.desktop.locale.get()),
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

/// Runs `f` with the settings window `id`, if it is open.
fn with(id: u64, f: impl FnOnce(&Open)) {
    if let Some(open) = current(id) {
        f(&open);
    }
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

/// «Сохранить»: checks the form at once, saves it on a worker thread, then applies the
/// saved settings and shows the states in the (perhaps new) language.
fn save(open: &Open) {
    let form = form_of(&open.ui);
    let l = open.desktop.locale.get();
    if let Err(e) = form.settings() {
        show_message(&open.ui, form_error_text(e, l), true);
        return;
    }
    run(
        open,
        move |s| (s.save(&form), s.states()),
        |open, (saved, states)| {
            match saved {
                Ok(settings) => {
                    let l = settings.ui_locale();
                    open.desktop.locale.set(l);
                    select_language(l);
                    (open.desktop.on_saved)(&settings);
                    show_message(&open.ui, Texts::of(l).saved, false);
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "settings window: cannot save");
                    let l = open.desktop.locale.get();
                    show_message(&open.ui, &save_error_text(&e, l), true);
                }
            }
            show_states(&open.ui, &states, open.desktop.locale.get());
        },
    );
}

/// The messages of an action: on success, on failure.
type ActionTexts = fn(&Texts) -> (&'static str, &'static str);

/// Runs the action `job` on a worker thread, then shows its outcome and the new states.
/// «Вернуть оригинал» also turns off our autostart, which the form then shows.
fn act(open: &Open, job: fn(&SettingsServices) -> io::Result<()>, texts: ActionTexts) {
    run(
        open,
        move |s| {
            let done = job(s);
            let autostart = s.autostart.enabled().ok();
            (done, autostart, s.states())
        },
        move |open, (done, autostart, states)| {
            let l = open.desktop.locale.get();
            let (ok, failed) = texts(Texts::of(l));
            match done {
                Ok(()) => show_message(&open.ui, ok, false),
                Err(e) => {
                    tracing::warn!(error = %e, "settings window: {failed}");
                    show_message(&open.ui, &format!("{failed}: {e}"), true);
                }
            }
            if let Some(on) = autostart {
                open.ui.set_autostart(on);
            }
            show_states(&open.ui, &states, l);
        },
    );
}

/// Runs `job` on a worker thread while the window waits; `done` gets its result on the
/// event loop if the window is still open.
fn run<T: Send + 'static>(
    open: &Open,
    job: impl FnOnce(&SettingsServices) -> T + Send + 'static,
    done: impl FnOnce(&Open, T) + Send + 'static,
) {
    open.ui.set_busy(true);
    let services = Arc::clone(&open.desktop.settings);
    let id = open.id;
    let spawned = std::thread::Builder::new()
        .name("settings".into())
        .spawn(move || {
            let result = job(&services);
            let delivered = slint::invoke_from_event_loop(move || {
                with(id, |open| {
                    open.ui.set_busy(false);
                    done(open, result);
                });
            });
            if let Err(e) = delivered {
                tracing::warn!(error = %e, "settings window: a result is lost");
            }
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "settings window: cannot start a worker thread");
        open.ui.set_busy(false);
        let t = Texts::of(open.desktop.locale.get());
        show_message(&open.ui, t.cannot_start, true);
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

/// The texts Rust composes for the settings window, in one language.
struct Texts {
    loading: &'static str,
    saved: &'static str,
    proxy_url_missing: &'static str,
    proxy_url_invalid: &'static str,
    cannot_save: &'static str,
    cannot_set_autostart: &'static str,
    cannot_read_settings: &'static str,
    cannot_read_autostart: &'static str,
    cannot_start: &'static str,
    original_not_found: &'static str,
    original_found: &'static str,
    original_no_autostart: &'static str,
    startup_shortcut: &'static str,
    machine_run: &'static str,
    desktop_entry: &'static str,
    enabled: &'static str,
    disabled: &'static str,
    machine_run_admin: &'static str,
    port_owner: &'static str,
    original_disabled: &'static str,
    original_restored: &'static str,
    cannot_disable_original: &'static str,
    cannot_restore_original: &'static str,
    extension_not_registered: &'static str,
    extension_registered: &'static str,
    extension_no_browser: &'static str,
    extension_broken: &'static str,
    extension_registered_now: &'static str,
    extension_unregistered: &'static str,
    cannot_register: &'static str,
    cannot_unregister: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                loading: "Жүктелуде…",
                saved: "Баптаулар сақталды",
                proxy_url_missing: "Прокси мекенжайын енгізіңіз",
                proxy_url_invalid: "Прокси мекенжайы жарамсыз: оны http://түйін:порт түрінде көрсетіңіз (SOCKS және https:// қолдау көрсетілмейді)",
                cannot_save: "Баптауларды сақтау мүмкін болмады",
                cannot_set_autostart: "Автоіске қосуды өзгерту мүмкін болмады",
                cannot_read_settings: "settings.json оқылмады, әдепкі мәндер көрсетілді",
                cannot_read_autostart: "Автоіске қосу күйін оқу мүмкін болмады",
                cannot_start: "Әрекетті орындау мүмкін болмады",
                original_not_found: "Түпнұсқа NCALayer табылмады.",
                original_found: "Түпнұсқа NCALayer табылды.",
                original_no_autostart: "Автоіске қосу жоқ.",
                startup_shortcut: "Автожүктеудегі белгіше",
                machine_run: "Барлық пайдаланушыларға арналған автоіске қосу (HKLM\\…\\Run)",
                desktop_entry: "Автоіске қосу файлы",
                enabled: "қосулы",
                disabled: "өшірулі",
                machine_run_admin: "Барлық пайдаланушыларға арналған автоіске қосуды тек әкімші өшіре алады: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run ішіндегі NCALayer мәнін жойыңыз немесе оны Тапсырмалар диспетчері → Автожүктеу бөлімінде өшіріңіз.",
                port_owner: "Портты алып тұрған бағдарлама: ",
                original_disabled: "Түпнұсқаның автоіске қосылуы өшірілді",
                original_restored: "Түпнұсқа қайтарылды, біздің автоіске қосу өшірілді",
                cannot_disable_original: "Түпнұсқаның автоіске қосылуын өшіру мүмкін болмады",
                cannot_restore_original: "Түпнұсқаны қайтару мүмкін болмады",
                extension_not_registered: "Кеңейту тіркелмеген.",
                extension_registered: "Тіркелген браузерлер: ",
                extension_no_browser: "Relay орнатылған, бірақ браузер табылмады: браузерді кемінде бір рет іске қосып, «Тіркеу» батырмасын басыңыз.",
                extension_broken: "Тіркеу толық емес немесе зақымдалған: «Тіркеу» батырмасын басыңыз.",
                extension_registered_now: "Кеңейту тіркелді",
                extension_unregistered: "Тіркеу жойылды",
                cannot_register: "Кеңейтуді тіркеу мүмкін болмады",
                cannot_unregister: "Тіркеуді жою мүмкін болмады",
            },
            Locale::Ru => &Texts {
                loading: "Загрузка…",
                saved: "Настройки сохранены",
                proxy_url_missing: "Укажите адрес прокси",
                proxy_url_invalid: "Адрес прокси не подходит: укажите его в виде http://узел:порт (SOCKS и https:// не поддерживаются)",
                cannot_save: "Не удалось сохранить настройки",
                cannot_set_autostart: "Не удалось изменить автозапуск",
                cannot_read_settings: "settings.json не прочитан, показаны значения по умолчанию",
                cannot_read_autostart: "Не удалось прочитать состояние автозапуска",
                cannot_start: "Не удалось выполнить действие",
                original_not_found: "Оригинальный NCALayer не найден.",
                original_found: "Оригинальный NCALayer найден.",
                original_no_autostart: "Автозапуска нет.",
                startup_shortcut: "Ярлык в автозагрузке",
                machine_run: "Автозапуск для всех пользователей (HKLM\\…\\Run)",
                desktop_entry: "Файл автозапуска",
                enabled: "включён",
                disabled: "выключен",
                machine_run_admin: "Автозапуск для всех пользователей отключает только администратор: удалите значение NCALayer в HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run или отключите его в Диспетчере задач → Автозагрузка.",
                port_owner: "Порт занят программой: ",
                original_disabled: "Автозапуск оригинала отключён",
                original_restored: "Оригинал возвращён, наш автозапуск выключен",
                cannot_disable_original: "Не удалось отключить автозапуск оригинала",
                cannot_restore_original: "Не удалось вернуть оригинал",
                extension_not_registered: "Расширение не зарегистрировано.",
                extension_registered: "Зарегистрировано в браузерах: ",
                extension_no_browser: "Relay установлен, но браузеры не найдены: запустите браузер хотя бы раз и нажмите «Зарегистрировать».",
                extension_broken: "Регистрация неполная или повреждена: нажмите «Зарегистрировать».",
                extension_registered_now: "Расширение зарегистрировано",
                extension_unregistered: "Регистрация удалена",
                cannot_register: "Не удалось зарегистрировать расширение",
                cannot_unregister: "Не удалось удалить регистрацию",
            },
            Locale::En => &Texts {
                loading: "Loading…",
                saved: "The settings are saved",
                proxy_url_missing: "Enter the proxy URL",
                proxy_url_invalid: "The proxy URL does not fit: enter it as http://host:port (SOCKS and https:// are not supported)",
                cannot_save: "Cannot save the settings",
                cannot_set_autostart: "Cannot change the autostart",
                cannot_read_settings: "settings.json could not be read; the defaults are shown",
                cannot_read_autostart: "Cannot read the autostart state",
                cannot_start: "Cannot run the action",
                original_not_found: "The original NCALayer is not found.",
                original_found: "The original NCALayer is found.",
                original_no_autostart: "It does not start at login.",
                startup_shortcut: "Startup shortcut",
                machine_run: "Autostart for all users (HKLM\\…\\Run)",
                desktop_entry: "Autostart file",
                enabled: "on",
                disabled: "off",
                machine_run_admin: "Only an administrator can turn off the autostart for all users: delete the NCALayer value of HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, or disable it in Task Manager → Startup.",
                port_owner: "The port is held by: ",
                original_disabled: "The original's autostart is disabled",
                original_restored: "The original is restored; our autostart is off",
                cannot_disable_original: "Cannot disable the original's autostart",
                cannot_restore_original: "Cannot restore the original",
                extension_not_registered: "The extension is not registered.",
                extension_registered: "Registered in: ",
                extension_no_browser: "The relay is installed but no browser is found: start a browser once, then press Register.",
                extension_broken: "The registration is incomplete or broken: press Register.",
                extension_registered_now: "The extension is registered",
                extension_unregistered: "The registration is removed",
                cannot_register: "Cannot register the extension",
                cannot_unregister: "Cannot remove the registration",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_desktop::original::{AutostartEntry, Report};
    use oncl_desktop::{AutostartPaths, FileAutostart};
    use std::path::Path;
    use std::sync::Mutex;

    fn manual(url: &str) -> SettingsForm {
        SettingsForm {
            language: Language::System,
            autostart: false,
            proxy_mode: ProxyMode::Manual,
            proxy_url: url.to_owned(),
        }
    }

    #[test]
    fn form_round_trips_the_settings() {
        for settings in [
            Settings::default(),
            Settings {
                locale: Some("kk".to_owned()),
                autostart: true,
                proxy: ProxySetting::System,
            },
            Settings {
                locale: Some("en".to_owned()),
                autostart: false,
                proxy: ProxySetting::Manual("http://user:pw@proxy.test:3128".to_owned()),
            },
        ] {
            let form = SettingsForm::new(&settings, settings.autostart);
            assert_eq!(form.settings().unwrap(), settings);
        }
        // The real autostart state wins over the stored one.
        let form = SettingsForm::new(&Settings::default(), true);
        assert!(form.autostart && form.settings().unwrap().autostart);
        // An unknown stored language shows as the system's.
        let odd = Settings {
            locale: Some("de".to_owned()),
            ..Settings::default()
        };
        assert_eq!(SettingsForm::new(&odd, false).language, Language::System);
    }

    #[test]
    fn manual_proxy_urls_are_checked() {
        assert_eq!(manual(" ").settings(), Err(FormError::ProxyUrlMissing));
        for bad in [
            "socks5://proxy.test:1080",
            "https://proxy.test:3128",
            "http://",
        ] {
            assert_eq!(
                manual(bad).settings(),
                Err(FormError::ProxyUrlInvalid),
                "{bad}"
            );
        }
        assert_eq!(
            manual(" http://proxy.test:3128 ").settings().unwrap().proxy,
            ProxySetting::Manual("http://proxy.test:3128".to_owned())
        );
        // A URL kept from manual mode does not matter in another mode.
        let form = SettingsForm {
            proxy_mode: ProxyMode::None,
            ..manual("socks5://proxy.test:1080")
        };
        assert_eq!(form.settings().unwrap().proxy, ProxySetting::None);
        assert_ne!(
            form_error_text(FormError::ProxyUrlInvalid, Locale::Ru),
            form_error_text(FormError::ProxyUrlInvalid, Locale::Kk)
        );
    }

    #[test]
    fn list_indexes_map_both_ways() {
        for (i, language) in Language::ALL.iter().enumerate() {
            assert_eq!(index_of(&Language::ALL, language), i as i32);
            assert_eq!(item(&Language::ALL, i as i32), *language);
        }
        assert_eq!(item(&ProxyMode::ALL, -1), ProxyMode::None);
        assert_eq!(item(&ProxyMode::ALL, 7), ProxyMode::None);
        assert_eq!(item(&ProxyMode::ALL, 2), ProxyMode::Manual);
    }

    /// An original NCALayer with one entry in each state, recording its calls.
    #[derive(Default)]
    struct FakeOriginal {
        status: Mutex<OriginalStatus>,
        fail: bool,
    }

    impl OriginalControl for FakeOriginal {
        fn status(&self) -> OriginalStatus {
            self.status.lock().unwrap().clone()
        }

        fn disable(&self) -> io::Result<Report> {
            self.set_all(false)
        }

        fn restore(&self) -> io::Result<Report> {
            self.set_all(true)
        }
    }

    impl FakeOriginal {
        fn set_all(&self, enabled: bool) -> io::Result<Report> {
            if self.fail {
                return Err(io::Error::other("moved halfway"));
            }
            let mut status = self.status.lock().unwrap();
            let mut changed = Vec::new();
            for entry in &mut status.autostart {
                if entry.kind != EntryKind::MachineRun && entry.enabled != enabled {
                    entry.enabled = enabled;
                    changed.push(entry.path.clone());
                }
            }
            Ok(Report { changed })
        }
    }

    struct FakeExtension;

    impl BrowserExtension for FakeExtension {
        fn status(&self) -> ExtensionStatus {
            ExtensionStatus::default()
        }

        fn register(&self) -> io::Result<ExtensionStatus> {
            Ok(ExtensionStatus::default())
        }

        fn unregister(&self) -> io::Result<ExtensionStatus> {
            Ok(ExtensionStatus::default())
        }
    }

    fn startup_shortcut(enabled: bool) -> AutostartEntry {
        AutostartEntry {
            kind: EntryKind::StartupShortcut,
            path: PathBuf::from("Startup").join("NCALayer.lnk"),
            enabled,
        }
    }

    /// Services on a sandbox under `root`: `settings.json`, the autostart file of the
    /// sandbox's XDG layout (on every system), the program `<root>/bin/openncalayer`.
    fn services(root: &Path, original: FakeOriginal) -> SettingsServices {
        SettingsServices {
            settings_path: root.join("settings.json"),
            exe: std::path::absolute(root.join("bin").join("openncalayer")).unwrap(),
            autostart: Box::new(FileAutostart::desktop_entry(&AutostartPaths::sandbox(root))),
            original: Box::new(original),
            extension: Box::new(FakeExtension),
        }
    }

    #[test]
    fn save_switches_the_real_autostart_and_keeps_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let s = services(dir.path(), FakeOriginal::default());
        std::fs::write(&s.settings_path, r#"{"recentPath": "C:\\keys\\a.p12"}"#).unwrap();
        let loaded = s.load();
        assert_eq!(loaded.form, SettingsForm::new(&Settings::default(), false));
        assert_eq!(
            (loaded.settings_error, loaded.autostart_error),
            (None, None)
        );

        let form = SettingsForm {
            language: Language::Kk,
            autostart: true,
            ..manual("http://proxy.test:3128")
        };
        let saved = s.save(&form).unwrap();
        assert_eq!(saved.ui_locale(), Locale::Kk);
        assert!(s.autostart.enabled().unwrap());
        assert_eq!(s.load().form, form);
        let json = std::fs::read_to_string(&s.settings_path).unwrap();
        assert!(json.contains("recentPath"), "{json}");

        // The entry removed behind our back: the form shows it off, and saving with the
        // box ticked creates it again even though settings.json says on.
        s.autostart.set(false, &s.exe).unwrap();
        assert!(!s.load().form.autostart);
        s.save(&form).unwrap();
        assert!(s.autostart.enabled().unwrap());

        // An invalid form saves nothing.
        let before = std::fs::read(&s.settings_path).unwrap();
        let bad = SettingsForm {
            autostart: false,
            ..manual("socks5://proxy.test:1080")
        };
        assert!(matches!(
            s.save(&bad),
            Err(SaveError::Form(FormError::ProxyUrlInvalid))
        ));
        assert!(s.autostart.enabled().unwrap());
        assert_eq!(std::fs::read(&s.settings_path).unwrap(), before);
    }

    #[test]
    fn failed_autostart_saves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = services(dir.path(), FakeOriginal::default());
        // A relative program cannot be written into the entry.
        s.exe = PathBuf::from("openncalayer");
        let form = SettingsForm {
            autostart: true,
            ..SettingsForm::new(&Settings::default(), false)
        };
        assert!(matches!(s.save(&form), Err(SaveError::Autostart(_))));
        assert!(!s.settings_path.exists());
        assert!(!s.autostart.enabled().unwrap());
    }

    #[test]
    fn restoring_the_original_turns_ours_off() {
        let dir = tempfile::tempdir().unwrap();
        let original = FakeOriginal::default();
        original.status.lock().unwrap().found = true;
        original
            .status
            .lock()
            .unwrap()
            .autostart
            .push(startup_shortcut(true));
        let s = services(dir.path(), original);
        let ours = SettingsForm {
            autostart: true,
            ..SettingsForm::new(&Settings::default(), false)
        };
        s.save(&ours).unwrap();

        s.disable_original().unwrap();
        assert!(!s.states().original.autostart[0].enabled);
        assert!(s.autostart.enabled().unwrap(), "disabling keeps ours");

        s.restore_original().unwrap();
        assert!(s.states().original.autostart[0].enabled);
        assert!(!s.autostart.enabled().unwrap());
        assert!(!Settings::load(&s.settings_path).unwrap().autostart);
    }

    #[test]
    fn failed_restore_keeps_our_autostart() {
        let dir = tempfile::tempdir().unwrap();
        let s = services(
            dir.path(),
            FakeOriginal {
                fail: true,
                ..FakeOriginal::default()
            },
        );
        s.autostart.set(true, &s.exe).unwrap();
        assert!(s.restore_original().is_err());
        assert!(s.autostart.enabled().unwrap());
        assert!(s.disable_original().is_err());
    }

    #[test]
    fn original_block_texts_and_buttons() {
        let none = original_view(&OriginalStatus::default(), Locale::Ru);
        assert_eq!(none.text, "Оригинальный NCALayer не найден.");
        assert!(!none.can_disable && !none.can_restore);

        let machine = AutostartEntry {
            kind: EntryKind::MachineRun,
            path: PathBuf::from(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\NCALayer"),
            enabled: true,
        };
        let status = OriginalStatus {
            found: true,
            autostart: vec![startup_shortcut(true), machine.clone()],
            port_owner: Some(r"C:\Program Files\NCALayer\NCALayer.exe".to_owned()),
        };
        let view = original_view(&status, Locale::En);
        assert!(view.can_disable && !view.can_restore);
        assert!(
            view.text
                .starts_with("The original NCALayer is found.\n• Startup shortcut: ")
        );
        assert!(view.text.contains("NCALayer.lnk — on\n"), "{}", view.text);
        assert!(view.text.contains("Only an administrator"), "{}", view.text);
        assert!(
            view.text
                .ends_with(r"The port is held by: C:\Program Files\NCALayer\NCALayer.exe")
        );

        // Only the machine-wide entry is left on: neither button can change it.
        let status = OriginalStatus {
            found: true,
            autostart: vec![startup_shortcut(false), machine],
            port_owner: None,
        };
        let view = original_view(&status, Locale::Kk);
        assert!(!view.can_disable && view.can_restore);
        let empty = original_view(
            &OriginalStatus {
                found: true,
                ..OriginalStatus::default()
            },
            Locale::Ru,
        );
        assert_eq!(
            empty.text,
            "Оригинальный NCALayer найден.\nАвтозапуска нет."
        );
    }

    #[test]
    fn extension_block_texts() {
        let view = |installed, browsers: &[&str], broken| {
            extension_view(
                &ExtensionStatus {
                    installed,
                    browsers: browsers.iter().map(ToString::to_string).collect(),
                    broken,
                },
                Locale::Ru,
            )
        };
        let none = view(false, &[], false);
        assert_eq!(none.text, "Расширение не зарегистрировано.");
        assert!(!none.can_unregister);
        let ok = view(true, &["Chrome", "Firefox"], false);
        assert_eq!(ok.text, "Зарегистрировано в браузерах: Chrome, Firefox");
        assert!(ok.can_unregister);
        assert!(view(true, &[], false).text.starts_with("Relay установлен"));
        for broken in [
            view(true, &["Chrome"], true),
            view(false, &["Chrome"], false),
        ] {
            assert!(
                broken.text.starts_with("Регистрация неполная"),
                "{}",
                broken.text
            );
            assert!(broken.can_unregister);
        }
    }
}
