//! `settings.json` in the data directory, one JSON object shared by the settings window
//! ([`Settings`]: `locale`, `autostart`, `proxy`) and other owners of single keys (the
//! `recentPath` of the key store dialogs). Every change is a read-modify-write of the whole
//! object ([`update`]) that keeps the keys it does not change, unknown ones included.

use std::io;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use oncl_basics::Locale;
pub use oncl_pki::http::ProxySetting;
use serde_json::{Map, Value};

use crate::fsutil::write_atomic;

const LOCALE: &str = "locale";
const AUTOSTART: &str = "autostart";
const PROXY: &str = "proxy";
const MODE: &str = "mode";
const URL: &str = "url";

/// The settings of the settings window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// The language of the windows and the tray: `ru`, `kk` or `en`; `None` follows the
    /// system's language ([`Settings::ui_locale`]).
    pub locale: Option<String>,
    /// Whether our entry starts OpenNCALayer at login (see [`crate::autostart`]).
    pub autostart: bool,
    /// The proxy of the time-stamping, OCSP and CRL requests (`{"mode": "none" | "system" |
    /// "manual", "url": …}`); the system's by default.
    pub proxy: ProxySetting,
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
    /// As [`update`].
    pub fn save(&self, path: &Path) -> io::Result<()> {
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
        Settings {
            locale,
            autostart,
            proxy,
        }
    }

    /// Writes the settings into `object`. Other members of a `proxy` object stay, so a
    /// manual URL is remembered while another mode is chosen.
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
            proxy.insert(MODE.to_owned(), Value::String(mode.to_owned()));
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
/// temporary file renamed into place; the file and its directory are created if missing.
/// A file that is not a JSON object is replaced (logged). Changes within the process never
/// interleave, so none is lost.
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
    write_atomic(path, &json)
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

    fn on_disk(f: &Path) -> Value {
        serde_json::from_slice(&fs::read(f).unwrap()).unwrap()
    }

    #[test]
    fn round_trip_keeps_unknown_keys() {
        let (_d, f) = file_with(
            r#"{"recentPath": "k.p12", "future": {"a": [1, 2]}, "originalAutostart": true,
                "locale": "kk", "autostart": true,
                "proxy": {"mode": "manual", "url": "http://p:3128", "extra": 1}}"#,
        );
        let mut s = Settings::load(&f).unwrap();
        assert_eq!(
            s,
            Settings {
                locale: Some("kk".to_owned()),
                autostart: true,
                proxy: ProxySetting::Manual("http://p:3128".to_owned()),
            }
        );
        s.save(&f).unwrap();
        assert_eq!(Settings::load(&f).unwrap(), s);

        s.locale = None;
        s.autostart = false;
        s.proxy = ProxySetting::None;
        s.save(&f).unwrap();
        assert_eq!(
            on_disk(&f),
            json!({
                "recentPath": "k.p12",
                "future": {"a": [1, 2]},
                "originalAutostart": true,
                "autostart": false,
                // The manual URL is remembered for when it is chosen again.
                "proxy": {"mode": "none", "url": "http://p:3128", "extra": 1},
            })
        );
        assert_eq!(Settings::load(&f).unwrap(), s);
        s.proxy = ProxySetting::System;
        s.save(&f).unwrap();
        assert_eq!(Settings::load(&f).unwrap().proxy, ProxySetting::System);
    }

    #[test]
    fn missing_file_and_keys_are_defaults() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("sub").join("settings.json");
        assert_eq!(Settings::load(&f).unwrap(), Settings::default());
        assert_eq!(Settings::default().proxy, ProxySetting::System);

        let s = Settings {
            locale: Some("en".to_owned()),
            autostart: true,
            proxy: ProxySetting::Manual("http://u:p@h:1".to_owned()),
        };
        s.save(&f).unwrap();
        assert_eq!(Settings::load(&f).unwrap(), s);
        assert_eq!(
            on_disk(&f),
            json!({"locale": "en", "autostart": true,
                   "proxy": {"mode": "manual", "url": "http://u:p@h:1"}})
        );
    }

    #[test]
    fn values_not_understood_are_defaults() {
        let (_d, f) =
            file_with(r#"{"locale": "de", "autostart": "yes", "proxy": {"mode": "manual"}}"#);
        assert_eq!(Settings::load(&f).unwrap(), Settings::default());
        for proxy in [r#""none""#, r#"{"mode": "pac"}"#, r#"{"mode": 1}"#, "[]"] {
            let (_d, f) = file_with(&format!(r#"{{"proxy": {proxy}}}"#));
            assert_eq!(Settings::load(&f).unwrap().proxy, ProxySetting::System);
        }
        // A `proxy` that is not an object is replaced on save.
        let (_d, f) = file_with(r#"{"proxy": "none"}"#);
        Settings::default().save(&f).unwrap();
        assert_eq!(on_disk(&f)["proxy"], json!({"mode": "system"}));
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
        // Without a setting: the system's language or Russian, never anything else.
        let shown = Settings::default().ui_locale();
        assert_eq!(shown, system_locale().unwrap_or(Locale::Ru));
    }
}
