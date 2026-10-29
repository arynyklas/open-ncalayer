//! The «Плагины» window: what the daemon's plugins are ([`PluginsView`], from
//! [`PluginsServices::view`]) and the actions on them, each a job ([`worker`]) after which
//! the list is read again; the daemon also has it read again when its plugins change
//! ([`refresh_plugins_window`]). Removing a plugin is asked about first. The rows' texts are
//! composed here.

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread::LocalKey;

use oncl_basics::Locale;
use slint::{ComponentHandle, ModelRc, PlatformError, SharedString, VecModel};
use time::OffsetDateTime;

use crate::foreground;
use crate::prompter::select_desktop_language;
use crate::ui::{AvailableRow, InstalledRow, PluginsWindow};
use crate::windows::Desktop;
use crate::worker::{self, JobWindow, Slot, run, with};

/// What the plugin window works with: the daemon's plugins.
pub trait PluginsServices: Send + Sync {
    /// The plugins now.
    fn view(&self) -> PluginsView;
    /// Installs `id` from the catalog: downloads it, then asks the user (in a window of its
    /// own). Blocks for the download.
    ///
    /// # Errors
    ///
    /// Why the user is not asked (for the window): the catalog or the package failed, or
    /// the plugin is installed or being installed already.
    fn install(&self, id: &str) -> Result<(), String>;
    /// Installs the package file at `path`, once the user agreed.
    ///
    /// # Errors
    ///
    /// Why the user is not asked: the file is not a valid package, or that plugin is being
    /// installed already.
    fn install_file(&self, path: PathBuf) -> Result<(), String>;
    /// Turns `id` on or off.
    ///
    /// # Errors
    ///
    /// What failed, for the user.
    fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), String>;
    /// Uninstalls `id`.
    ///
    /// # Errors
    ///
    /// What failed, for the user.
    fn remove(&self, id: &str) -> Result<(), String>;
    /// Downloads the catalog again. Blocks for the download.
    fn refresh(&self);
}

/// The plugins, as the window shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginsView {
    pub catalog: CatalogLine,
    pub installed: Vec<InstalledPlugin>,
    pub available: Vec<AvailablePlugin>,
}

/// The catalog's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogLine {
    /// This build has no catalog.
    Unavailable,
    /// The plugins are off: their data in the data directory cannot be read (why).
    Off(String),
    /// The catalog of `channel` made at `generated` is in use; `error`: its last download
    /// failed.
    Ready {
        channel: String,
        generated: OffsetDateTime,
        error: Option<String>,
    },
    /// No catalog of `channel`: not downloaded yet, or `error`.
    Missing {
        channel: String,
        error: Option<String>,
    },
}

/// An installed plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledPlugin {
    pub id: String,
    pub name: LocalizedText,
    pub version: String,
    pub replaces: Option<ReplacedBundle>,
    /// From a file the user chose, not from the catalog.
    pub local: bool,
    pub state: PluginStatus,
}

/// Whether an installed plugin serves its modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginStatus {
    Enabled,
    Disabled,
    /// Revoked in the catalog with nothing to move to.
    Withdrawn,
    /// On, but it could not be loaded: why.
    Error(String),
}

/// A plugin the catalog offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailablePlugin {
    pub id: String,
    pub name: LocalizedText,
    pub version: String,
    pub replaces: Option<ReplacedBundle>,
    /// A page called one of its modules.
    pub needed: bool,
    /// That page's origin, if it had one.
    pub needed_by: Option<String>,
}

/// A text in the three languages of the windows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalizedText {
    pub ru: String,
    pub kk: String,
    pub en: String,
}

impl LocalizedText {
    /// The text in `l`.
    pub fn get(&self, l: Locale) -> &str {
        match l {
            Locale::Ru => &self.ru,
            Locale::Kk => &self.kk,
            Locale::En => &self.en,
        }
    }
}

/// The original NCALayer bundle a plugin ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplacedBundle {
    pub symname: String,
    pub version: String,
}

/// What a plugin may do, a line each in the install confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityLine {
    /// Choose the user's key and sign with it.
    Keys,
    /// Show windows.
    Dialogs,
    /// Open and save files the user chooses.
    Files,
    /// Reach these URL prefixes.
    Http(Vec<String>),
}

/// The open window ([`worker::Slot`]).
struct Open {
    id: u64,
    ui: PluginsWindow,
    desktop: Rc<Desktop>,
    /// What the rows show, for the row an action names.
    shown: std::cell::RefCell<PluginsView>,
}

thread_local! {
    static OPEN: Slot<Open> = const { Slot::new() };
}

/// Whether the window is open.
pub(crate) fn is_open() -> bool {
    worker::is_open::<Open>()
}

/// Shows the window, or brings the open one to the front. On the event loop.
pub(crate) fn open(desktop: &Rc<Desktop>) {
    if let Some(open) = worker::opened::<Open>() {
        select_desktop_language(desktop.locale.get());
        if let Err(e) = open.ui.show() {
            tracing::warn!(error = %e, "cannot show the plugin window");
        }
        foreground::take(&open.ui);
        if !open.ui.get_busy() {
            load(&open);
        }
        return;
    }
    if let Err(e) = create(desktop) {
        tracing::error!(error = %e, "cannot show the plugin window");
    }
}

/// Has the open window read the plugins again (they changed); callable from any thread.
pub fn refresh_plugins_window() {
    if let Err(e) = slint::invoke_from_event_loop(|| {
        if let Some(open) = worker::opened::<Open>()
            && !open.ui.get_busy()
        {
            load(&open);
        }
    }) {
        tracing::debug!(error = %e, "no windows: the plugin window is not refreshed");
    }
}

fn create(desktop: &Rc<Desktop>) -> Result<(), PlatformError> {
    let ui = PluginsWindow::new()?;
    select_desktop_language(desktop.locale.get());
    let id = worker::next_id::<Open>();
    let open = Rc::new(Open {
        id,
        ui: ui.clone_strong(),
        desktop: Rc::clone(desktop),
        shown: std::cell::RefCell::new(PluginsView {
            catalog: CatalogLine::Unavailable,
            installed: Vec::new(),
            available: Vec::new(),
        }),
    });
    ui.on_toggle(move |row| with(id, |open: &Open| toggle(open, row)));
    ui.on_remove(move |row| with(id, |open: &Open| ask_remove(open, row)));
    ui.on_confirm_remove(move |row| with(id, |open: &Open| remove(open, row)));
    ui.on_install(move |row| with(id, |open: &Open| install(open, row)));
    ui.on_install_file(move || with(id, pick_file));
    ui.on_refresh(move || with(id, refresh));
    ui.on_dismiss(move || {
        worker::close_requested::<Open>(id);
    });
    ui.window()
        .on_close_requested(move || worker::close_requested::<Open>(id));
    worker::set_open(Some(Rc::clone(&open)));
    if let Err(e) = ui.show() {
        worker::set_open::<Open>(None);
        return Err(e);
    }
    foreground::take(&ui);
    load(&open);
    Ok(())
}

/// Reads the plugins on a worker thread, then shows them.
fn load(open: &Open) {
    run_action(open, |_| Ok(()), None);
}

/// Runs `action` on a worker thread, then reads the plugins and shows them with the
/// action's outcome: its error, or `done` if given.
fn run_action(
    open: &Open,
    action: impl FnOnce(&dyn PluginsServices) -> Result<(), String> + Send + 'static,
    done: Option<String>,
) {
    run(
        open,
        #[allow(clippy::borrowed_box)] // the worker hands its services as they are kept
        move |services: &Box<dyn PluginsServices>| {
            let outcome = action(services.as_ref());
            (outcome, services.view())
        },
        move |_, open, (outcome, view)| {
            let Some(open) = open else {
                return;
            };
            show(open, view);
            match outcome {
                Ok(()) => show_message(&open.ui, done.as_deref().unwrap_or(""), false),
                Err(e) => show_message(&open.ui, &e, true),
            }
        },
    );
}

/// Shows `view`.
fn show(open: &Open, view: PluginsView) {
    let l = open.desktop.locale.get();
    let (catalog, error) = catalog_text(&view.catalog, l);
    open.ui.set_catalog(catalog.into());
    open.ui.set_catalog_error(error);
    let installed: Vec<InstalledRow> = view.installed.iter().map(|p| installed_row(p, l)).collect();
    open.ui
        .set_installed(ModelRc::new(VecModel::from(installed)));
    let available: Vec<AvailableRow> = view.available.iter().map(|p| available_row(p, l)).collect();
    open.ui
        .set_available(ModelRc::new(VecModel::from(available)));
    open.ui.set_removing(-1);
    *open.shown.borrow_mut() = view;
}

/// The installed plugin of row `row`.
fn installed_at(open: &Open, row: i32) -> Option<InstalledPlugin> {
    let i = usize::try_from(row).ok()?;
    open.shown.borrow().installed.get(i).cloned()
}

/// «Выключить» / «Включить».
fn toggle(open: &Open, row: i32) {
    let Some(plugin) = installed_at(open, row) else {
        return;
    };
    let enable = plugin.state == PluginStatus::Disabled;
    run_action(
        open,
        move |services| services.set_enabled(&plugin.id, enable),
        None,
    );
}

/// «Удалить»: asks first.
fn ask_remove(open: &Open, row: i32) {
    let Some(plugin) = installed_at(open, row) else {
        return;
    };
    let l = open.desktop.locale.get();
    open.ui.set_remove_question(
        Texts::of(l)
            .remove_question
            .replace("{0}", plugin.name.get(l))
            .into(),
    );
    open.ui.set_removing(row);
}

/// «Удалить» of the question.
fn remove(open: &Open, row: i32) {
    let Some(plugin) = installed_at(open, row) else {
        return;
    };
    open.ui.set_removing(-1);
    let l = open.desktop.locale.get();
    let done = Texts::of(l).removed.replace("{0}", plugin.name.get(l));
    run_action(
        open,
        move |services| services.remove(&plugin.id),
        Some(done),
    );
}

/// «Установить…» of an available plugin: downloaded, then the user is asked.
fn install(open: &Open, row: i32) {
    let Some(plugin) = usize::try_from(row)
        .ok()
        .and_then(|i| open.shown.borrow().available.get(i).cloned())
    else {
        return;
    };
    let l = open.desktop.locale.get();
    show_message(
        &open.ui,
        &Texts::of(l).downloading.replace("{0}", plugin.name.get(l)),
        false,
    );
    run_action(open, move |services| services.install(&plugin.id), None);
}

/// «Установить из файла…»: the system file dialog, `*.onclp` only.
fn pick_file(open: &Open) {
    let l = open.desktop.locale.get();
    let dialog = rfd::AsyncFileDialog::new()
        .set_title(Texts::of(l).pick_title)
        .add_filter(Texts::of(l).filter, &["onclp"])
        .set_parent(&open.ui.window().window_handle());
    let id = open.id;
    let picked = slint::spawn_local(async move {
        let Some(file) = dialog.pick_file().await else {
            tracing::info!("the file dialog returned no file");
            return;
        };
        let path = file.path().to_owned();
        with(id, |open: &Open| install_file(open, path));
    });
    if let Err(e) = picked {
        tracing::warn!(error = %e, "cannot open the file dialog");
    }
}

/// Installs the package file at `path`, once the user agrees.
fn install_file(open: &Open, path: PathBuf) {
    run_action(open, move |services| services.install_file(path), None);
}

/// «Обновить каталог».
fn refresh(open: &Open) {
    let l = open.desktop.locale.get();
    show_message(&open.ui, Texts::of(l).refreshing, false);
    run_action(
        open,
        |services| {
            services.refresh();
            Ok(())
        },
        None,
    );
}

impl JobWindow for Open {
    type Services = Box<dyn PluginsServices>;
    const NAME: &'static str = "plugins";

    fn slot() -> &'static LocalKey<Slot<Open>> {
        &OPEN
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn desktop(&self) -> &Rc<Desktop> {
        &self.desktop
    }

    fn services(&self) -> Arc<Box<dyn PluginsServices>> {
        Arc::clone(&self.desktop.plugins)
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

    fn hide(&self) {
        if let Err(e) = self.ui.hide() {
            tracing::warn!(error = %e, "cannot hide the plugin window");
        }
    }
}

fn show_message(ui: &PluginsWindow, text: &str, error: bool) {
    ui.set_message(SharedString::from(text));
    ui.set_message_is_error(error);
}

/// The catalog's line in `l`, and whether it tells of a failure.
fn catalog_text(catalog: &CatalogLine, l: Locale) -> (String, bool) {
    let t = Texts::of(l);
    match catalog {
        CatalogLine::Unavailable => (t.unavailable.to_owned(), false),
        CatalogLine::Off(e) => (t.off.replace("{0}", e), true),
        CatalogLine::Ready {
            channel,
            generated,
            error,
        } => {
            let line = t
                .ready
                .replace("{channel}", channel)
                .replace("{date}", &date(*generated, l));
            match error {
                Some(e) => (
                    format!("{line}\n{}", t.update_failed.replace("{0}", e)),
                    true,
                ),
                None => (line, false),
            }
        }
        CatalogLine::Missing { channel, error } => match error {
            Some(e) => (
                t.missing_failed
                    .replace("{channel}", channel)
                    .replace("{0}", e),
                true,
            ),
            None => (t.not_loaded.replace("{channel}", channel), false),
        },
    }
}

/// `29.10.2026` (Russian, Kazakh) or `2026-10-29` (English).
fn date(at: OffsetDateTime, l: Locale) -> String {
    let (y, m, d) = (at.year(), u8::from(at.month()), at.day());
    match l {
        Locale::En => format!("{y:04}-{m:02}-{d:02}"),
        Locale::Ru | Locale::Kk => format!("{d:02}.{m:02}.{y:04}"),
    }
}

/// «Заменяет {symname} {version}» in `l`.
fn replaces_text(replaces: &ReplacedBundle, l: Locale) -> String {
    Texts::of(l)
        .replaces
        .replace("{symname}", &replaces.symname)
        .replace("{version}", &replaces.version)
}

fn installed_row(plugin: &InstalledPlugin, l: Locale) -> InstalledRow {
    let t = Texts::of(l);
    let mut details = vec![
        if plugin.local {
            t.local
        } else {
            t.from_catalog
        }
        .to_owned(),
    ];
    if let Some(replaces) = &plugin.replaces {
        details.push(replaces_text(replaces, l));
    }
    let (state, error) = match &plugin.state {
        PluginStatus::Enabled => (t.enabled.to_owned(), false),
        PluginStatus::Disabled => (t.disabled.to_owned(), false),
        PluginStatus::Withdrawn => (t.withdrawn.to_owned(), true),
        PluginStatus::Error(e) => (t.error.replace("{0}", e), true),
    };
    InstalledRow {
        title: title(&plugin.name, &plugin.version, l).into(),
        details: details.join(" · ").into(),
        state: state.into(),
        error,
        can_toggle: plugin.state != PluginStatus::Withdrawn,
        enabled: plugin.state != PluginStatus::Disabled,
    }
}

fn available_row(plugin: &AvailablePlugin, l: Locale) -> AvailableRow {
    let t = Texts::of(l);
    let needed = match (&plugin.needed, &plugin.needed_by) {
        (false, _) => String::new(),
        (true, Some(origin)) => t.needed_by.replace("{0}", origin),
        (true, None) => t.needed.to_owned(),
    };
    AvailableRow {
        title: title(&plugin.name, &plugin.version, l).into(),
        details: plugin
            .replaces
            .as_ref()
            .map(|r| replaces_text(r, l))
            .unwrap_or_default()
            .into(),
        needed: needed.into(),
    }
}

fn title(name: &LocalizedText, version: &str, l: Locale) -> String {
    Texts::of(l)
        .title
        .replace("{name}", name.get(l))
        .replace("{version}", version)
}

/// The texts of the window, in one language.
struct Texts {
    unavailable: &'static str,
    /// `{0}`: why.
    off: &'static str,
    /// `{channel}`, `{date}`.
    ready: &'static str,
    /// `{0}`: the error.
    update_failed: &'static str,
    /// `{channel}`.
    not_loaded: &'static str,
    /// `{channel}`, `{0}`: the error.
    missing_failed: &'static str,
    /// `{name}`, `{version}`.
    title: &'static str,
    /// `{symname}`, `{version}`.
    replaces: &'static str,
    from_catalog: &'static str,
    local: &'static str,
    enabled: &'static str,
    disabled: &'static str,
    withdrawn: &'static str,
    /// `{0}`.
    error: &'static str,
    /// `{0}`: the origin.
    needed_by: &'static str,
    needed: &'static str,
    /// `{0}`: the name.
    remove_question: &'static str,
    /// `{0}`: the name.
    removed: &'static str,
    /// `{0}`: the name.
    downloading: &'static str,
    refreshing: &'static str,
    pick_title: &'static str,
    filter: &'static str,
    cannot_start: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                unavailable: "Плагиндер каталогы бұл құрастыруда қолжетімсіз",
                off: "Плагиндер қолжетімсіз: {0}",
                ready: "Плагиндер каталогы: {channel} арнасы, {date}",
                update_failed: "Каталогты жаңарту мүмкін болмады: {0}",
                not_loaded: "Плагиндер каталогы: {channel} арнасы, әлі жүктелген жоқ",
                missing_failed: "Плагиндер каталогы: {channel} арнасы, жүктеу мүмкін болмады: {0}",
                title: "{name} {version}",
                replaces: "{symname} {version} алмастырады",
                from_catalog: "каталогтан",
                local: "жергілікті",
                enabled: "Қосулы",
                disabled: "Өшірулі",
                withdrawn: "Кері қайтарылған: нұсқасы каталогта кері қайтарылды",
                error: "Қате: {0}",
                needed_by: "{0} сайтына қажет",
                needed: "Сайтқа қажет",
                remove_question: "«{0}» плагинін жою керек пе?",
                removed: "«{0}» плагині жойылды.",
                downloading: "«{0}» плагині жүктелуде…",
                refreshing: "Каталог жүктелуде…",
                pick_title: "Плагин файлын таңдаңыз",
                filter: "OpenNCALayer плагині",
                cannot_start: "Әрекетті орындау мүмкін болмады",
            },
            Locale::Ru => &Texts {
                unavailable: "Каталог плагинов недоступен в этой сборке",
                off: "Плагины недоступны: {0}",
                ready: "Каталог плагинов: канал {channel}, от {date}",
                update_failed: "Не удалось обновить каталог: {0}",
                not_loaded: "Каталог плагинов: канал {channel}, ещё не загружен",
                missing_failed: "Каталог плагинов: канал {channel}, не удалось загрузить: {0}",
                title: "{name} {version}",
                replaces: "заменяет {symname} {version}",
                from_catalog: "из каталога",
                local: "локальный",
                enabled: "Включён",
                disabled: "Выключен",
                withdrawn: "Отозван: версия отозвана в каталоге",
                error: "Ошибка: {0}",
                needed_by: "Нужен сайту {0}",
                needed: "Нужен сайту",
                remove_question: "Удалить плагин «{0}»?",
                removed: "Плагин «{0}» удалён.",
                downloading: "Плагин «{0}» загружается…",
                refreshing: "Каталог загружается…",
                pick_title: "Выберите файл плагина",
                filter: "Плагин OpenNCALayer",
                cannot_start: "Не удалось выполнить действие",
            },
            Locale::En => &Texts {
                unavailable: "The plugin catalog is unavailable in this build",
                off: "Plugins are unavailable: {0}",
                ready: "Plugin catalog: the {channel} channel, of {date}",
                update_failed: "Cannot update the catalog: {0}",
                not_loaded: "Plugin catalog: the {channel} channel, not downloaded yet",
                missing_failed: "Plugin catalog: the {channel} channel, cannot download it: {0}",
                title: "{name} {version}",
                replaces: "replaces {symname} {version}",
                from_catalog: "from the catalog",
                local: "local",
                enabled: "On",
                disabled: "Off",
                withdrawn: "Withdrawn: its version is revoked in the catalog",
                error: "Error: {0}",
                needed_by: "Needed by {0}",
                needed: "Needed by a site",
                remove_question: "Remove the plugin «{0}»?",
                removed: "The plugin «{0}» is removed.",
                downloading: "Downloading the plugin «{0}»…",
                refreshing: "Downloading the catalog…",
                pick_title: "Choose a plugin file",
                filter: "OpenNCALayer plugin",
                cannot_start: "Cannot carry out the action",
            },
        }
    }
}

/// [`PluginsServices`] for the tests: a fixed view, the calls recorded.
#[cfg(test)]
pub(crate) mod fakes {
    use super::*;
    use std::sync::Mutex;

    /// What the window asked, in order.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum Call {
        View,
        Install(String),
        InstallFile(PathBuf),
        SetEnabled(String, bool),
        Remove(String),
        Refresh,
    }

    #[derive(Default)]
    pub(crate) struct FakePlugins {
        pub(crate) view: Mutex<Option<PluginsView>>,
        pub(crate) calls: Arc<Mutex<Vec<Call>>>,
        /// What `set_enabled` and `remove` answer.
        pub(crate) fail: Arc<Mutex<Option<String>>>,
    }

    impl FakePlugins {
        fn log(&self, call: Call) {
            self.calls.lock().unwrap().push(call);
        }

        fn outcome(&self) -> Result<(), String> {
            self.fail.lock().unwrap().clone().map_or(Ok(()), Err)
        }
    }

    impl PluginsServices for FakePlugins {
        fn view(&self) -> PluginsView {
            self.log(Call::View);
            self.view.lock().unwrap().clone().unwrap_or(PluginsView {
                catalog: CatalogLine::Unavailable,
                installed: Vec::new(),
                available: Vec::new(),
            })
        }

        fn install(&self, id: &str) -> Result<(), String> {
            self.log(Call::Install(id.to_owned()));
            self.outcome()
        }

        fn install_file(&self, path: PathBuf) -> Result<(), String> {
            self.log(Call::InstallFile(path));
            self.outcome()
        }

        fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), String> {
            self.log(Call::SetEnabled(id.to_owned(), enabled));
            self.outcome()
        }

        fn remove(&self, id: &str) -> Result<(), String> {
            self.log(Call::Remove(id.to_owned()));
            self.outcome()
        }

        fn refresh(&self) {
            self.log(Call::Refresh);
        }
    }
}

/// The window on the offscreen platform of the tests, without an event loop: a job runs
/// when a test says ([`worker::manual`]).
#[cfg(test)]
mod tests {
    use super::fakes::{Call, FakePlugins};
    use super::*;
    use crate::settings_view::fakes::{FakeOriginal, services};
    use crate::windows::{DesktopWindows, set_desktop_windows};
    use crate::{AboutInfo, offscreen};
    use slint::Model;
    use std::sync::Mutex;
    use time::macros::datetime;

    fn name(base: &str) -> LocalizedText {
        LocalizedText {
            ru: format!("{base} ru"),
            kk: format!("{base} kk"),
            en: format!("{base} en"),
        }
    }

    fn view() -> PluginsView {
        PluginsView {
            catalog: CatalogLine::Ready {
                channel: "beta".to_owned(),
                generated: datetime!(2026-10-29 09:00 UTC),
                error: None,
            },
            installed: vec![
                InstalledPlugin {
                    id: "kz.example.one".to_owned(),
                    name: name("Один"),
                    version: "1.0.0".to_owned(),
                    replaces: Some(ReplacedBundle {
                        symname: "kz.gov.one".to_owned(),
                        version: "0.3.1".to_owned(),
                    }),
                    local: false,
                    state: PluginStatus::Enabled,
                },
                InstalledPlugin {
                    id: "kz.example.two".to_owned(),
                    name: name("Два"),
                    version: "0.2.0".to_owned(),
                    replaces: None,
                    local: true,
                    state: PluginStatus::Disabled,
                },
                InstalledPlugin {
                    id: "kz.example.three".to_owned(),
                    name: name("Три"),
                    version: "3.0.0".to_owned(),
                    replaces: None,
                    local: false,
                    state: PluginStatus::Withdrawn,
                },
            ],
            available: vec![AvailablePlugin {
                id: "kz.example.four".to_owned(),
                name: name("Четыре"),
                version: "4.0.0".to_owned(),
                replaces: None,
                needed: true,
                needed_by: Some("https://shop.kz".to_owned()),
            }],
        }
    }

    /// The window open in `l` over a fake showing [`view`].
    struct Opened {
        _dir: tempfile::TempDir,
        open: Rc<Open>,
        calls: Arc<Mutex<Vec<Call>>>,
        fail: Arc<Mutex<Option<String>>>,
    }

    fn opened(l: Locale) -> Opened {
        let dir = tempfile::tempdir().unwrap();
        offscreen::install();
        worker::manual::enable();
        let fake = FakePlugins::default();
        *fake.view.lock().unwrap() = Some(view());
        let calls = Arc::clone(&fake.calls);
        let fail = Arc::clone(&fake.fail);
        set_desktop_windows(DesktopWindows {
            locale: l,
            settings: services(dir.path(), FakeOriginal::default()),
            about: AboutInfo::default(),
            tls: crate::tls_wizard::fakes::services(dir.path(), Vec::new(), None),
            plugins: Box::new(fake),
            on_saved: Box::new(|_: &oncl_desktop::Settings| {}),
        });
        open(&crate::windows::desktop().unwrap());
        worker::manual::run_all();
        let open = worker::opened::<Open>().expect("the window is open");
        Opened {
            _dir: dir,
            open,
            calls,
            fail,
        }
    }

    fn taken(calls: &Mutex<Vec<Call>>) -> Vec<Call> {
        std::mem::take(&mut *calls.lock().unwrap())
    }

    #[test]
    fn shows_the_plugins() {
        let o = opened(Locale::Ru);
        assert_eq!(taken(&o.calls), [Call::View]);
        let ui = &o.open.ui;
        assert_eq!(
            ui.get_catalog(),
            "Каталог плагинов: канал beta, от 29.10.2026"
        );
        assert!(!ui.get_catalog_error());
        let rows: Vec<InstalledRow> = ui.get_installed().iter().collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].title, "Один ru 1.0.0");
        assert_eq!(rows[0].details, "из каталога · заменяет kz.gov.one 0.3.1");
        assert_eq!(rows[0].state, "Включён");
        assert!(rows[0].enabled && rows[0].can_toggle && !rows[0].error);
        assert_eq!(rows[1].details, "локальный");
        assert_eq!(rows[1].state, "Выключен");
        assert!(!rows[1].enabled);
        assert!(!rows[2].can_toggle && rows[2].error);
        let available: Vec<AvailableRow> = ui.get_available().iter().collect();
        assert_eq!(available[0].title, "Четыре ru 4.0.0");
        assert_eq!(available[0].needed, "Нужен сайту https://shop.kz");
    }

    #[test]
    fn buttons_call_the_services() {
        let o = opened(Locale::Ru);
        let (open, calls) = (&o.open, &o.calls);
        taken(calls);
        let ui = &open.ui;
        ui.invoke_toggle(0);
        assert!(ui.get_busy());
        worker::manual::run_all();
        assert!(!ui.get_busy());
        ui.invoke_toggle(1);
        worker::manual::run_all();
        ui.invoke_install(0);
        assert_eq!(ui.get_message(), "Плагин «Четыре ru» загружается…");
        worker::manual::run_all();
        install_file(open, PathBuf::from("plugin.onclp"));
        worker::manual::run_all();
        ui.invoke_refresh();
        worker::manual::run_all();
        assert_eq!(
            taken(calls),
            [
                Call::SetEnabled("kz.example.one".to_owned(), false),
                Call::View,
                Call::SetEnabled("kz.example.two".to_owned(), true),
                Call::View,
                Call::Install("kz.example.four".to_owned()),
                Call::View,
                Call::InstallFile(PathBuf::from("plugin.onclp")),
                Call::View,
                Call::Refresh,
                Call::View,
            ]
        );
        assert_eq!(ui.get_message(), "");
    }

    #[test]
    fn remove_asks_first() {
        let o = opened(Locale::Ru);
        let calls = &o.calls;
        taken(calls);
        let ui = &o.open.ui;
        ui.invoke_remove(1);
        assert_eq!(ui.get_removing(), 1);
        assert_eq!(ui.get_remove_question(), "Удалить плагин «Два ru»?");
        worker::manual::run_all();
        assert!(taken(calls).is_empty(), "nothing removed yet");
        ui.invoke_confirm_remove(1);
        worker::manual::run_all();
        assert_eq!(
            taken(calls),
            [Call::Remove("kz.example.two".to_owned()), Call::View]
        );
        assert_eq!(ui.get_message(), "Плагин «Два ru» удалён.");
        assert_eq!(ui.get_removing(), -1);
    }

    #[test]
    fn a_failure_is_shown() {
        let o = opened(Locale::Ru);
        *o.fail.lock().unwrap() = Some("нет прав".to_owned());
        let ui = &o.open.ui;
        ui.invoke_toggle(0);
        worker::manual::run_all();
        assert_eq!(ui.get_message(), "нет прав");
        assert!(ui.get_message_is_error());
        // The list is read again all the same.
        assert_eq!(taken(&o.calls).last(), Some(&Call::View));
        // An install that cannot start (no catalog, being installed already) says why.
        *o.fail.lock().unwrap() =
            Some("the plugin kz.example.four is being installed already".to_owned());
        ui.invoke_install(0);
        worker::manual::run_all();
        assert_eq!(
            ui.get_message(),
            "the plugin kz.example.four is being installed already"
        );
        assert!(ui.get_message_is_error());
        install_file(&o.open, PathBuf::from("bad.onclp"));
        worker::manual::run_all();
        assert!(ui.get_message_is_error());
        assert_eq!(
            taken(&o.calls),
            [
                Call::Install("kz.example.four".to_owned()),
                Call::View,
                Call::InstallFile(PathBuf::from("bad.onclp")),
                Call::View,
            ]
        );
    }

    #[test]
    fn texts_in_every_language() {
        for l in [Locale::Kk, Locale::En] {
            // A thread of its own: the offscreen platform is set once per thread.
            std::thread::spawn(move || {
                let o = opened(l);
                let ui = &o.open.ui;
                let ru_rows: Vec<InstalledRow> = view()
                    .installed
                    .iter()
                    .map(|p| installed_row(p, Locale::Ru))
                    .collect();
                let rows: Vec<InstalledRow> = ui.get_installed().iter().collect();
                let suffix = if l == Locale::Kk { " kk " } else { " en " };
                for (row, ru) in rows.iter().zip(&ru_rows) {
                    assert!(row.title.contains(suffix), "{l:?}");
                    assert_ne!(row.state, ru.state, "{l:?}");
                    assert_ne!(row.details, ru.details, "{l:?}");
                }
                assert!(ui.get_catalog().contains("beta"), "{l:?}");
                assert_ne!(
                    catalog_text(&CatalogLine::Unavailable, l).0,
                    catalog_text(&CatalogLine::Unavailable, Locale::Ru).0
                );
            })
            .join()
            .unwrap();
        }
        assert_eq!(
            catalog_text(&CatalogLine::Unavailable, Locale::Ru).0,
            "Каталог плагинов недоступен в этой сборке"
        );
        assert_eq!(
            catalog_text(
                &CatalogLine::Missing {
                    channel: "stable".to_owned(),
                    error: Some("timed out".to_owned())
                },
                Locale::Ru
            ),
            (
                "Каталог плагинов: канал stable, не удалось загрузить: timed out".to_owned(),
                true
            )
        );
        assert_eq!(
            date(datetime!(2026-01-02 00:00 UTC), Locale::En),
            "2026-01-02"
        );
    }
}
