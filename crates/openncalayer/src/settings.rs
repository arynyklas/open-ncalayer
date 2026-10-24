//! `settings.json`: `{"recentPath": "..."}`, the last opened key store.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use oncl_basics::RecentPathStore;
use serde_json::{Map, Value};

const RECENT_PATH: &str = "recentPath";

/// `settings.json` as a [`RecentPathStore`]. Other keys in the file are kept as they are.
pub struct JsonSettings {
    path: PathBuf,
    /// Serializes read-modify-write cycles of this instance.
    lock: Mutex<()>,
}

impl JsonSettings {
    /// Settings kept in the file `path`; the file and its directory are created on first save.
    pub fn new(path: PathBuf) -> Self {
        JsonSettings {
            path,
            lock: Mutex::new(()),
        }
    }

    /// The settings object; `Ok(None)` if the file does not exist.
    fn read(&self) -> io::Result<Option<Map<String, Value>>> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        match serde_json::from_slice(&bytes) {
            Ok(Value::Object(map)) => Ok(Some(map)),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a JSON object",
            )),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }

    /// Writes `settings` through a temporary sibling renamed into place.
    fn write(&self, settings: &Map<String, Value>) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let json = serde_json::to_vec_pretty(settings).map_err(io::Error::other)?;
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &self.path)
    }
}

impl RecentPathStore for JsonSettings {
    fn load(&self) -> Option<PathBuf> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        match self.read() {
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
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(p) = p.to_str() else {
            tracing::warn!("key store path is not valid Unicode; not remembered");
            return;
        };
        let mut settings = self
            .read()
            .unwrap_or_else(|e| {
                tracing::warn!(path = %self.path.display(), error = %e, "cannot read settings; rewriting");
                None
            })
            .unwrap_or_default();
        settings.insert(RECENT_PATH.to_owned(), Value::String(p.to_owned()));
        if let Err(e) = self.write(&settings) {
            tracing::warn!(path = %self.path.display(), error = %e, "cannot write settings");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
