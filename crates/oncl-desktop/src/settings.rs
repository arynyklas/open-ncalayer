//! `settings.json` in the data directory, one JSON object shared by the settings window
//! ([`Settings`]: `locale`, `autostart`, `proxy`, `updates`) and other owners of single keys
//! (the `recentPath` of the key store dialogs). Every change is a read-modify-write of the
//! whole object ([`update`]) that keeps the keys it does not change, unknown ones included.
//! The file may hold a proxy password: it is written readable by its owner only (mode
//! `0600` on Unix).

use std::io;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use oncl_basics::Locale;
use oncl_pki::fsutil::Access;
pub use oncl_pki::http::ProxySetting;
pub use oncl_update::Channel;
use oncl_update::Version;
use serde_json::{Map, Value};

use crate::write_file;

const LOCALE: &str = "locale";
const AUTOSTART: &str = "autostart";
const PROXY: &str = "proxy";
const MODE: &str = "mode";
const URL: &str = "url";
const UPDATES: &str = "updates";
const ENABLED: &str = "enabled";
const CHANNEL: &str = "channel";

/// The settings of the settings window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// The language of the windows and the tray: `ru`, `kk` or `en`; `None` follows the
    /// system's language ([`Settings::ui_locale`]).
    pub locale: Option<String>,
    /// Whether our entry starts OpenNCALayer at login (see [`crate::autostart`]).
    pub autostart: bool,
    /// The proxy of the time-stamping, OCSP and CRL requests (`{"mode": "none" | "system" |
    /// "manual", "url": …}`); none (direct connections) by default, as before the setting
    /// existed.
    pub proxy: ProxySetting,
    /// The self-update (`{"enabled": true, "channel": "stable" | "beta"}`).
    pub updates: UpdateSettings,
}

/// Whether OpenNCALayer updates itself, and from which channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateSettings {
    /// New versions are looked for, downloaded and installed by themselves; on by default.
    pub enabled: bool,
    /// The channel of the update index; by default the one of this build's version
    /// ([`UpdateSettings::default_for`]). A channel saved in the settings stays.
    pub channel: Channel,
}

impl UpdateSettings {
    /// The defaults of a build of `version`: updates on, from
    /// [`Channel::default_for`]`(version)` (beta for a pre-release, stable for a release).
    pub fn default_for(version: &Version) -> UpdateSettings {
        UpdateSettings {
            enabled: true,
            channel: Channel::default_for(version),
        }
    }
}

impl Default for UpdateSettings {
    /// [`UpdateSettings::default_for`] this build's version.
    fn default() -> Self {
        let version = Version::parse(env!("CARGO_PKG_VERSION")).expect("the package version");
        UpdateSettings::default_for(&version)
    }
}

impl Settings {
    /// The settings in the file `path`; the defaults if it does not exist. A key that is
    /// missing or not understood keeps its default (logged).
    ///
    /// # Errors
    ///
    /// The file cannot be read, or is not a JSON object ([`io::ErrorKind::InvalidData`]).
    pub fn load(path: &Path) -> io::Result<Settings> {
        Ok(read(path)?
            .map(|object| Settings::from_object(&object))
            .unwrap_or_default())
    }

    /// Stores the settings in the file `path`, keeping its other keys; see [`update`].
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] if a manual proxy URL is not usable
    /// ([`ProxySetting::validate`]), and nothing is written; otherwise as [`update`].
    pub fn save(&self, path: &Path) -> io::Result<()> {
        self.proxy
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.message))?;
        update(path, |object| self.store(object))
    }

    /// The language to show: [`Settings::locale`] if it is one of ours, otherwise the
    /// system's if it is one of ours, otherwise Russian.
    pub fn ui_locale(&self) -> Locale {
        self.locale
            .as_deref()
            .and_then(locale_of)
            .or_else(system_locale)
            .unwrap_or(Locale::Ru)
    }

    fn from_object(object: &Map<String, Value>) -> Settings {
        let defaults = Settings::default();
        let ignored = |key: &str| tracing::warn!(key, "settings: value not understood; ignored");
        let locale = match object.get(LOCALE) {
            None | Some(Value::Null) => None,
            Some(Value::String(l)) if locale_code(l) => Some(l.clone()),
            Some(_) => {
                ignored(LOCALE);
                None
            }
        };
        let autostart = match object.get(AUTOSTART) {
            None => defaults.autostart,
            Some(Value::Bool(on)) => *on,
            Some(_) => {
                ignored(AUTOSTART);
                defaults.autostart
            }
        };
        let proxy = match object.get(PROXY) {
            None => defaults.proxy,
            Some(v) => proxy_of(v).unwrap_or_else(|| {
                ignored(PROXY);
                defaults.proxy
            }),
        };
        let updates = match object.get(UPDATES) {
            None => defaults.updates,
            Some(v) => updates_of(v).unwrap_or_else(|| {
                ignored(UPDATES);
                defaults.updates
            }),
        };
        Settings {
            locale,
            autostart,
            proxy,
            updates,
        }
    }

    /// Writes the settings into `object`. Other members of a `proxy` object stay; its `url`
    /// goes when the mode is not manual, so no proxy password is kept that is not used.
    fn store(&self, object: &mut Map<String, Value>) {
        match &self.locale {
            Some(l) => object.insert(LOCALE.to_owned(), Value::String(l.clone())),
            None => object.remove(LOCALE),
        };
        object.insert(AUTOSTART.to_owned(), Value::Bool(self.autostart));
        let proxy = object
            .entry(PROXY)
            .or_insert_with(|| Value::Object(Map::new()));
        if !proxy.is_object() {
            *proxy = Value::Object(Map::new());
        }
        if let Value::Object(proxy) = proxy {
            let mode = match &self.proxy {
                ProxySetting::None => "none",
                ProxySetting::System => "system",
                ProxySetting::Manual(url) => {
                    proxy.insert(URL.to_owned(), Value::String(url.clone()));
                    "manual"
                }
            };
            if !matches!(self.proxy, ProxySetting::Manual(_)) {
                proxy.remove(URL);
            }
            proxy.insert(MODE.to_owned(), Value::String(mode.to_owned()));
        }
        let updates = object
            .entry(UPDATES)
            .or_insert_with(|| Value::Object(Map::new()));
        if !updates.is_object() {
            *updates = Value::Object(Map::new());
        }
        if let Value::Object(updates) = updates {
            updates.insert(ENABLED.to_owned(), Value::Bool(self.updates.enabled));
            updates.insert(
                CHANNEL.to_owned(),
                Value::String(self.updates.channel.as_str().to_owned()),
            );
        }
    }
}

/// Whether `l` is a language code of ours.
fn locale_code(l: &str) -> bool {
    ["ru", "kk", "en"].contains(&l)
}

/// The proxy of a `proxy` object; `None` if it is not one.
fn proxy_of(v: &Value) -> Option<ProxySetting> {
    match v.get(MODE)?.as_str()? {
        "none" => Some(ProxySetting::None),
        "system" => Some(ProxySetting::System),
        "manual" => Some(ProxySetting::Manual(v.get(URL)?.as_str()?.to_owned())),
        _ => None,
    }
}

/// The update settings of an `updates` object: each member missing keeps its default; `None`
/// if it is not an object or a member is not understood.
fn updates_of(v: &Value) -> Option<UpdateSettings> {
    let defaults = UpdateSettings::default();
    let enabled = match v.as_object()?.get(ENABLED) {
        None => defaults.enabled,
        Some(on) => on.as_bool()?,
    };
    let channel = match v.get(CHANNEL) {
        None => defaults.channel,
        Some(name) => {
            let name = name.as_str()?;
            Channel::ALL.into_iter().find(|c| c.as_str() == name)?
        }
    };
    Some(UpdateSettings { enabled, channel })
}

/// Our language of a locale name such as `ru`, `kk_KZ.UTF-8` or `en-US`; `None` for any
/// other language.
fn locale_of(name: &str) -> Option<Locale> {
    let language = name
        .split(['_', '-', '.', '@'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match language.as_str() {
        "ru" => Some(Locale::Ru),
        "kk" => Some(Locale::Kk),
        "en" => Some(Locale::En),
        _ => None,
    }
}

/// The system's display language, if it is one of ours.
#[cfg(windows)]
fn system_locale() -> Option<Locale> {
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;

    // SAFETY: no arguments; returns a LANGID.
    let langid = unsafe { GetUserDefaultUILanguage() };
    // The primary language: LANG_RUSSIAN, LANG_KAZAK, LANG_ENGLISH.
    match langid & 0x3ff {
        0x19 => Some(Locale::Ru),
        0x3f => Some(Locale::Kk),
        0x09 => Some(Locale::En),
        _ => None,
    }
}

/// The system's language, if it is one of ours: the first of `LC_ALL`, `LC_MESSAGES` and
/// `LANG` that is set; on macOS, where applications started from the Finder have none of
/// them, otherwise the `AppleLocale` preference.
#[cfg(unix)]
fn system_locale() -> Option<Locale> {
    let from_env = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()));
    match from_env {
        Some(name) => locale_of(&name),
        None => apple_locale().as_deref().and_then(locale_of),
    }
}

#[cfg(target_os = "macos")]
fn apple_locale() -> Option<String> {
    let out = std::process::Command::new("defaults")
        .args(["read", "-g", "AppleLocale"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn apple_locale() -> Option<String> {
    None
}

/// Serializes the read-modify-write cycles of [`update`] within the process.
static UPDATE: Mutex<()> = Mutex::new(());

/// The settings object in the file `path`; `Ok(None)` if the file does not exist.
///
/// # Errors
///
/// The file cannot be read, or is not a JSON object ([`io::ErrorKind::InvalidData`]).
pub fn read(path: &Path) -> io::Result<Option<Map<String, Value>>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(object)) => Ok(Some(object)),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a JSON object",
        )),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

/// Applies `change` to the settings object in the file `path` and writes it back through a
/// temporary file renamed into place, readable by its owner only; the file and its
/// directory are created if missing. A file that is not a JSON object is replaced (logged).
/// Changes within the process never interleave, so none is lost.
///
/// # Errors
///
/// The file cannot be read (other than missing or not a JSON object) or written.
pub fn update(path: &Path, change: impl FnOnce(&mut Map<String, Value>)) -> io::Result<()> {
    let _guard = UPDATE.lock().unwrap_or_else(PoisonError::into_inner);
    let mut object = match read(path) {
        Ok(object) => object.unwrap_or_default(),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            tracing::warn!(path = %path.display(), error = %e, "settings are broken; rewriting");
            Map::new()
        }
        Err(e) => return Err(e),
    };
    change(&mut object);
    let json = serde_json::to_vec_pretty(&object).map_err(io::Error::other)?;
    write_file(path, &json, Access::Private)
}

/// Records in the file `path` whether our autostart is on ([`Settings::autostart`]), as the
/// settings window saves it, without writing any other key ([`update`]).
///
/// # Errors
///
/// As [`update`].
pub fn set_autostart(path: &Path, on: bool) -> io::Result<()> {
    update(path, |object| {
        object.insert(AUTOSTART.to_owned(), Value::Bool(on));
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn file_with(json: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("settings.json");
        fs::write(&f, json).unwrap();
        (d, f)
    }

    /// The channel this build saves by default.
    fn default_channel() -> &'static str {
        UpdateSettings::default().channel.as_str()
    }

    fn on_disk(f: &Path) -> Value {
        serde_json::from_slice(&fs::read(f).unwrap()).unwrap()
    }

    #[test]
    fn round_trip_keeps_unknown_keys() {
        let (_d, f) = file_with(
            r#"{"recentPath": "k.p12", "future": {"a": [1, 2]}, "originalAutostart": true,
                "locale": "kk", "autostart": true,
                "proxy": {"mode": "manual", "url": "http://p:3128", "extra": 1},
                "updates": {"enabled": false, "channel": "beta", "later": "x"}}"#,
        );
        let mut s = Settings::load(&f).unwrap();
        assert_eq!(
            s,
            Settings {
                locale: Some("kk".to_owned()),
                autostart: true,
                proxy: ProxySetting::Manual("http://p:3128".to_owned()),
                updates: UpdateSettings {
                    enabled: false,
                    channel: Channel::Beta,
                },
            }
        );
        s.save(&f).unwrap();
        assert_eq!(Settings::load(&f).unwrap(), s);

        s.locale = None;
        s.autostart = false;
        s.proxy = ProxySetting::System;
        s.updates = UpdateSettings::default();
        s.save(&f).unwrap();
        assert_eq!(
            on_disk(&f),
            json!({
                "recentPath": "k.p12",
                "future": {"a": [1, 2]},
                "originalAutostart": true,
                "autostart": false,
                // The manual URL, and a password in it, goes with the manual mode.
                "proxy": {"mode": "system", "extra": 1},
                "updates": {"enabled": true, "channel": default_channel(), "later": "x"},
            })
        );
        assert_eq!(Settings::load(&f).unwrap(), s);
        s.proxy = ProxySetting::None;
        s.save(&f).unwrap();
        assert_eq!(Settings::load(&f).unwrap().proxy, ProxySetting::None);
    }

    #[test]
    fn the_default_channel_follows_the_version() {
        let v = |s: &str| Version::parse(s).unwrap();
        for (version, channel) in [
            ("0.1.0-alpha.1", Channel::Beta),
            ("0.2.0-beta.3", Channel::Beta),
            ("1.0.0-rc.1", Channel::Beta),
            // Releases below 1.0 are releases too.
            ("0.3.0", Channel::Stable),
            ("1.2.3", Channel::Stable),
            // Build metadata is not a pre-release.
            ("1.2.3+win7", Channel::Stable),
        ] {
            assert_eq!(
                UpdateSettings::default_for(&v(version)),
                UpdateSettings {
                    enabled: true,
                    channel,
                },
                "{version}"
            );
        }
    }

    #[test]
    fn a_saved_channel_is_kept_whatever_the_build() {
        // A pre-release build (the default is beta) keeps a saved stable, and a missing
        // channel takes the build's default.
        let (_d, f) = file_with(r#"{"updates": {"enabled": true, "channel": "stable"}}"#);
        assert_eq!(Settings::load(&f).unwrap().updates.channel, Channel::Stable);
        let (_d, f) = file_with(r#"{"updates": {"channel": "beta"}}"#);
        assert_eq!(Settings::load(&f).unwrap().updates.channel, Channel::Beta);
        let (_d, f) = file_with(r#"{"updates": {"enabled": false}}"#);
        assert_eq!(
            Settings::load(&f).unwrap().updates,
            UpdateSettings {
                enabled: false,
                ..UpdateSettings::default()
            }
        );
    }

    #[test]
    fn missing_file_and_keys_are_defaults() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("sub").join("settings.json");
        assert_eq!(Settings::load(&f).unwrap(), Settings::default());
        assert_eq!(Settings::default().proxy, ProxySetting::None);
        let build = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        assert_eq!(
            Settings::default().updates,
            UpdateSettings {
                enabled: true,
                channel: Channel::default_for(&build),
            }
        );

        let s = Settings {
            locale: Some("en".to_owned()),
            autostart: true,
            proxy: ProxySetting::Manual("http://u:p@h:1".to_owned()),
            ..Settings::default()
        };
        s.save(&f).unwrap();
        assert_eq!(Settings::load(&f).unwrap(), s);
        assert_eq!(
            on_disk(&f),
            json!({"locale": "en", "autostart": true,
                   "proxy": {"mode": "manual", "url": "http://u:p@h:1"},
                   "updates": {"enabled": true, "channel": default_channel()}})
        );
    }

    #[test]
    fn unusable_manual_proxy_is_not_saved() {
        let (_d, f) = file_with(r#"{"recentPath": "k.p12"}"#);
        for url in ["socks5://127.0.0.1:1080", "https://p:443", "http://[x", ""] {
            let s = Settings {
                proxy: ProxySetting::Manual(url.to_owned()),
                ..Settings::default()
            };
            let e = s.save(&f).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{url}");
            assert_eq!(on_disk(&f), json!({"recentPath": "k.p12"}), "{url}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let (_d, f) = file_with("{}");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        Settings::default().save(&f).unwrap();
        let mode = fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn values_not_understood_are_defaults() {
        let (_d, f) =
            file_with(r#"{"locale": "de", "autostart": "yes", "proxy": {"mode": "manual"}}"#);
        assert_eq!(Settings::load(&f).unwrap(), Settings::default());
        for proxy in [r#""system""#, r#"{"mode": "pac"}"#, r#"{"mode": 1}"#, "[]"] {
            let (_d, f) = file_with(&format!(r#"{{"proxy": {proxy}}}"#));
            assert_eq!(Settings::load(&f).unwrap().proxy, ProxySetting::None);
        }
        for updates in [
            r#""beta""#,
            r#"{"channel": "nightly"}"#,
            r#"{"enabled": "no"}"#,
            r#"{"channel": 1}"#,
        ] {
            let (_d, f) = file_with(&format!(r#"{{"updates": {updates}}}"#));
            assert_eq!(
                Settings::load(&f).unwrap().updates,
                UpdateSettings::default(),
                "{updates}"
            );
        }
        // Members missing keep their defaults.
        let (_d, f) = file_with(r#"{"updates": {"channel": "beta"}}"#);
        assert_eq!(
            Settings::load(&f).unwrap().updates,
            UpdateSettings {
                enabled: true,
                channel: Channel::Beta,
            }
        );
        // A `proxy` or `updates` that is not an object is replaced on save.
        let (_d, f) = file_with(r#"{"proxy": "system", "updates": false}"#);
        Settings::default().save(&f).unwrap();
        assert_eq!(on_disk(&f)["proxy"], json!({"mode": "none"}));
        assert_eq!(
            on_disk(&f)["updates"],
            json!({"enabled": true, "channel": default_channel()})
        );
    }

    #[test]
    fn broken_file_fails_to_load_and_is_replaced_on_save() {
        for broken in ["[", "[1]", ""] {
            let (_d, f) = file_with(broken);
            let e = Settings::load(&f).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{broken:?}");
            Settings::default().save(&f).unwrap();
            assert_eq!(Settings::load(&f).unwrap(), Settings::default());
        }
    }

    #[test]
    fn concurrent_updates_of_different_keys_are_all_kept() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("settings.json");
        std::thread::scope(|scope| {
            for i in 0..8 {
                let f = &f;
                scope.spawn(move || {
                    update(f, |o| {
                        o.insert(format!("k{i}"), json!(i));
                    })
                    .unwrap()
                });
            }
        });
        assert_eq!(read(&f).unwrap().unwrap().len(), 8);
    }

    #[test]
    fn explicit_locale_wins_and_names_are_parsed() {
        let with = |l: &str| Settings {
            locale: Some(l.to_owned()),
            ..Settings::default()
        };
        assert_eq!(with("kk").ui_locale(), Locale::Kk);
        assert_eq!(with("en").ui_locale(), Locale::En);
        assert_eq!(with("ru").ui_locale(), Locale::Ru);
        assert_eq!(locale_of("kk_KZ.UTF-8"), Some(Locale::Kk));
        assert_eq!(locale_of("ru-RU"), Some(Locale::Ru));
        assert_eq!(locale_of("EN_us"), Some(Locale::En));
        assert_eq!(locale_of("en@euro"), Some(Locale::En));
        assert_eq!(locale_of("de_DE.UTF-8"), None);
        assert_eq!(locale_of("C"), None);
        assert_eq!(locale_of(""), None);
        // A language that is not ours is ignored like no setting.
        assert_eq!(with("de").ui_locale(), Settings::default().ui_locale());
    }

    #[test]
    fn set_autostart_writes_only_that_key() {
        let (_d, f) = file_with(r#"{"recentPath": "k.p12", "proxy": {"mode": "system"}}"#);
        set_autostart(&f, true).unwrap();
        assert_eq!(
            on_disk(&f),
            json!({"recentPath": "k.p12", "proxy": {"mode": "system"}, "autostart": true})
        );
        // A missing file gets only the key: no default channel is pinned.
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("data").join("settings.json");
        set_autostart(&missing, false).unwrap();
        assert_eq!(on_disk(&missing), json!({"autostart": false}));
    }
}
