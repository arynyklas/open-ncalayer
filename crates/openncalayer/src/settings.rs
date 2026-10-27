//! `settings.json` of the data directory ([`oncl_desktop::settings`]): the `recentPath` of the
//! key store dialogs and the settings the daemon starts with.

use std::path::{Path, PathBuf};

use oncl_basics::RecentPathStore;
use oncl_desktop::settings::{self, Settings};
use serde_json::Value;

const RECENT_PATH: &str = "recentPath";

/// `recentPath` of `settings.json`, the last opened key store, as a [`RecentPathStore`]. The
/// file's other keys are kept as they are.
pub struct JsonSettings {
    path: PathBuf,
}

impl JsonSettings {
    /// Settings kept in the file `path`; the file and its directory are created on first save.
    pub fn new(path: PathBuf) -> Self {
        JsonSettings { path }
    }
}

impl RecentPathStore for JsonSettings {
    fn load(&self) -> Option<PathBuf> {
        match settings::read(&self.path) {
            Ok(settings) => settings?
                .get(RECENT_PATH)
                .and_then(Value::as_str)
                .map(PathBuf::from),
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e, "cannot read settings");
                None
            }
        }
    }

    fn save(&self, p: &Path) {
        let Some(p) = p.to_str() else {
            tracing::warn!("key store path is not valid Unicode; not remembered");
            return;
        };
        let saved = settings::update(&self.path, |settings| {
            settings.insert(RECENT_PATH.to_owned(), Value::String(p.to_owned()));
        });
        if let Err(e) = saved {
            tracing::warn!(path = %self.path.display(), error = %e, "cannot write settings");
        }
    }
}

/// The settings in the file `path`; the defaults (logged) if it cannot be read.
pub fn load_settings(path: &Path) -> Settings {
    Settings::load(path).unwrap_or_else(|e| {
        tracing::warn!(path = %path.display(), error = %e, "cannot read settings; using the defaults");
        Settings::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_desktop::ProxySetting;
    use std::fs;

    #[test]
    fn other_keys_are_kept_and_garbage_is_replaced() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("sub").join("settings.json");
        let s = JsonSettings::new(f.clone());
        s.save(Path::new("a.p12"));
        fs::write(&f, r#"{"other": 1, "recentPath": "a.p12"}"#).unwrap();
        s.save(Path::new("b.p12"));
        let v: Value = serde_json::from_slice(&fs::read(&f).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"other": 1, "recentPath": "b.p12"}));

        fs::write(&f, "[").unwrap();
        assert_eq!(s.load(), None);
        s.save(Path::new("c.p12"));
        assert_eq!(s.load(), Some(PathBuf::from("c.p12")));
    }

    #[test]
    fn recent_path_and_settings_share_the_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("settings.json");
        let recent = JsonSettings::new(f.clone());
        recent.save(Path::new("k.p12"));
        let settings = Settings {
            locale: Some("en".to_owned()),
            autostart: true,
            proxy: ProxySetting::None,
        };
        settings.save(&f).unwrap();
        recent.save(Path::new("l.p12"));
        assert_eq!(load_settings(&f), settings);
        assert_eq!(recent.load(), Some(PathBuf::from("l.p12")));

        fs::write(&f, "{").unwrap();
        assert_eq!(load_settings(&f), Settings::default());
    }
}
