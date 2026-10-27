//! The settings window: the language, our autostart and the proxy, saved together into
//! `settings.json` and our autostart entry; the original NCALayer's autostart and the browser
//! extension's registration, acted on at once.
//!
//! The window's logic without a window is public: [`SettingsForm`] (what the form shows and
//! the settings it gives), [`SettingsServices`] (loading and the actions, on sandboxes in
//! tests) and the texts of the states ([`original_view`], [`extension_view`]). The window
//! itself is in `window`, its texts in `texts`; the actions run on a worker thread while the
//! window waits for them.

mod texts;
mod window;

#[cfg(test)]
pub(crate) use window::show_snapshot;
pub(crate) use window::{is_open, open};

use std::io;
use std::path::PathBuf;

use oncl_basics::Locale;
use oncl_desktop::original::EntryKind;
use oncl_desktop::{
    Autostart, BrowserExtension, ExtensionError, ExtensionStatus, OriginalControl, OriginalStatus,
    ProxySetting, Settings,
};

use texts::Texts;

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

/// Why an action of the window failed.
#[derive(Debug)]
pub enum ActionError {
    /// Disabling or restoring the original NCALayer.
    Original(io::Error),
    /// Registering or removing the browser extension.
    Extension(ExtensionError),
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

    /// Saves `form`: first our autostart entry, if the form changes it, then
    /// `settings.json` (its other keys kept). Returns the saved settings.
    ///
    /// The entry is changed when its state differs from the form. When it cannot be read,
    /// the form showed `settings.json`'s value, so it is changed only if the user changed
    /// that: the proxy and the language can still be saved.
    ///
    /// # Errors
    ///
    /// The form is not valid or the autostart entry cannot be changed (nothing is saved),
    /// or `settings.json` cannot be written.
    pub fn save(&self, form: &SettingsForm) -> Result<Settings, SaveError> {
        let settings = form.settings().map_err(SaveError::Form)?;
        let shown = match self.autostart.enabled() {
            Ok(on) => on,
            Err(_) => Settings::load(&self.settings_path).is_ok_and(|s| s.autostart),
        };
        if shown != settings.autostart {
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
    pub fn restore_original(&self) -> Result<(), ActionError> {
        let restore = || -> io::Result<()> {
            let report = self.original.restore()?;
            tracing::info!(changed = ?report.changed, "the original NCALayer's autostart is restored");
            self.autostart.set(false, &self.exe)?;
            let mut settings = Settings::load(&self.settings_path)?;
            settings.autostart = false;
            settings.save(&self.settings_path)
        };
        restore().map_err(ActionError::Original)
    }

    /// «Отключить автозапуск оригинала».
    ///
    /// # Errors
    ///
    /// See [`OriginalControl::disable`].
    pub fn disable_original(&self) -> Result<(), ActionError> {
        let report = self.original.disable().map_err(ActionError::Original)?;
        tracing::info!(changed = ?report.changed, "the original NCALayer's autostart is disabled");
        Ok(())
    }

    /// «Зарегистрировать».
    ///
    /// # Errors
    ///
    /// See [`BrowserExtension::register`].
    pub fn register_extension(&self) -> Result<(), ActionError> {
        self.extension
            .register()
            .map(drop)
            .map_err(ActionError::Extension)
    }

    /// «Удалить».
    ///
    /// # Errors
    ///
    /// See [`BrowserExtension::unregister`].
    pub fn unregister_extension(&self) -> Result<(), ActionError> {
        self.extension
            .unregister()
            .map(drop)
            .map_err(ActionError::Extension)
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

/// The message of a failed action in `l`, after `failed` (what failed).
pub fn action_error_text(e: &ActionError, failed: &str, l: Locale) -> String {
    let t = Texts::of(l);
    match e {
        ActionError::Extension(ExtensionError::RelayMissing(relay)) => {
            format!("{failed}: {}{}", t.relay_missing, relay.display())
        }
        ActionError::Extension(ExtensionError::RelayInUse) => {
            format!("{failed}: {}", t.relay_in_use)
        }
        ActionError::Extension(ExtensionError::Io(e)) | ActionError::Original(e) => {
            format!("{failed}: {e}")
        }
    }
}

/// Sandboxed services for the tests of the model and the window.
#[cfg(test)]
pub(crate) mod fakes {
    use super::*;
    use oncl_desktop::original::Report;
    use oncl_desktop::{AutostartPaths, FileAutostart};
    use std::path::Path;
    use std::sync::Mutex;

    /// An original NCALayer whose entries switch as asked, or that always fails.
    #[derive(Default)]
    pub(crate) struct FakeOriginal {
        pub(crate) status: Mutex<OriginalStatus>,
        pub(crate) fail: bool,
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

    /// An extension that registers nothing and never fails.
    pub(crate) struct FakeExtension;

    impl BrowserExtension for FakeExtension {
        fn status(&self) -> ExtensionStatus {
            ExtensionStatus::default()
        }

        fn register(&self) -> Result<ExtensionStatus, ExtensionError> {
            Ok(ExtensionStatus::default())
        }

        fn unregister(&self) -> Result<ExtensionStatus, ExtensionError> {
            Ok(ExtensionStatus::default())
        }
    }

    /// Services on a sandbox under `root`: `settings.json`, the autostart file of the
    /// sandbox's XDG layout (on every system), the program `<root>/bin/openncalayer`.
    pub(crate) fn services(root: &Path, original: FakeOriginal) -> SettingsServices {
        SettingsServices {
            settings_path: root.join("settings.json"),
            exe: std::path::absolute(root.join("bin").join("openncalayer")).unwrap(),
            autostart: Box::new(FileAutostart::desktop_entry(&AutostartPaths::sandbox(root))),
            original: Box::new(original),
            extension: Box::new(FakeExtension),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fakes::{FakeOriginal, services};
    use super::*;
    use oncl_desktop::original::AutostartEntry;
    use std::path::Path;

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

    fn startup_shortcut(enabled: bool) -> AutostartEntry {
        AutostartEntry {
            kind: EntryKind::StartupShortcut,
            path: PathBuf::from("Startup").join("NCALayer.lnk"),
            enabled,
        }
    }

    /// An autostart entry that cannot be read or written.
    struct Unreadable;

    impl Autostart for Unreadable {
        fn enabled(&self) -> io::Result<bool> {
            Err(io::Error::other("HOME is not set"))
        }

        fn set(&self, _: bool, _: &Path) -> io::Result<()> {
            Err(io::Error::other("HOME is not set"))
        }
    }

    #[test]
    fn unreadable_autostart_still_saves_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = services(dir.path(), FakeOriginal::default());
        s.autostart = Box::new(Unreadable);
        let loaded = s.load();
        assert!(loaded.autostart_error.is_some());
        // The box shows settings.json's value; the proxy and language are saved as long as
        // the user leaves it.
        let form = SettingsForm {
            language: Language::En,
            proxy_mode: ProxyMode::System,
            ..loaded.form
        };
        assert_eq!(s.save(&form).unwrap().proxy, ProxySetting::System);
        assert_eq!(
            Settings::load(&s.settings_path).unwrap().proxy,
            ProxySetting::System
        );
        let ticked = SettingsForm {
            autostart: true,
            ..form
        };
        assert!(matches!(s.save(&ticked), Err(SaveError::Autostart(_))));
        assert!(!Settings::load(&s.settings_path).unwrap().autostart);
    }

    #[test]
    fn action_errors_are_told_in_the_window_language() {
        let relay = PathBuf::from("bin").join("nmhost");
        let missing = ActionError::Extension(ExtensionError::RelayMissing(relay.clone()));
        assert_eq!(
            action_error_text(&missing, "Cannot register the extension", Locale::En),
            format!(
                "Cannot register the extension: The relay is not found: {}",
                relay.display()
            )
        );
        let busy = ActionError::Extension(ExtensionError::RelayInUse);
        assert!(action_error_text(&busy, "x", Locale::Kk).starts_with("x: Relay браузерде"));
        let io = ActionError::Original(io::Error::other("denied"));
        assert_eq!(action_error_text(&io, "x", Locale::Ru), "x: denied");
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
