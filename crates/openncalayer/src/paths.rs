//! The data directory: `tls/`, `logs/` and `settings.json`.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use oncl_tls::TlsFiles;

/// Overrides the data directory (tests and development runs).
pub use oncl_ipc::DATA_DIR_VAR;

/// Locations of OpenNCALayer's files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The data directory.
    pub data: PathBuf,
}

impl Paths {
    /// The data directory of this user: `ONCL_DATA_DIR` if set, otherwise
    /// `%APPDATA%\OpenNCALayer` (Windows), `~/Library/Application Support/OpenNCALayer`
    /// (macOS) or `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (other Unix). The path is
    /// made absolute against the current directory.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if the variables the platform default needs are not set.
    pub fn detect() -> io::Result<Paths> {
        let data = data_dir(|name| std::env::var_os(name))?;
        Ok(Paths {
            data: std::path::absolute(data)?,
        })
    }

    /// TLS material (`tls/`).
    pub fn tls(&self) -> TlsFiles {
        TlsFiles {
            dir: self.data.join("tls"),
        }
    }

    /// `settings.json`.
    pub fn settings(&self) -> PathBuf {
        self.data.join("settings.json")
    }

    /// Log directory (`logs/`).
    pub fn logs(&self) -> PathBuf {
        self.data.join("logs")
    }
}

/// The data directory from the environment `var`: the rule the relay and the installer
/// share ([`oncl_ipc::data_dir_from`]).
fn data_dir(var: impl Fn(&str) -> Option<OsString>) -> io::Result<PathBuf> {
    oncl_ipc::data_dir_from(var)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn override_wins_and_empty_is_unset() {
        let all = [
            (DATA_DIR_VAR, "target/oncl-data"),
            ("APPDATA", "/a"),
            ("HOME", "/h"),
            ("XDG_DATA_HOME", "/x"),
        ];
        assert_eq!(data_dir(env(&all)).unwrap(), Path::new("target/oncl-data"));
        let empty = [(DATA_DIR_VAR, ""), ("APPDATA", "/a"), ("HOME", "/h")];
        assert_ne!(data_dir(env(&empty)).unwrap(), Path::new(""));
        assert_eq!(
            data_dir(env(&[])).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn platform_default() {
        let vars = [("APPDATA", "/a"), ("HOME", "/h"), ("XDG_DATA_HOME", "rel")];
        let expected = if cfg!(windows) {
            Path::new("/a").join("OpenNCALayer")
        } else if cfg!(target_os = "macos") {
            Path::new("/h").join("Library/Application Support/OpenNCALayer")
        } else {
            Path::new("/h").join(".local/share/openncalayer")
        };
        assert_eq!(data_dir(env(&vars)).unwrap(), expected);
        if cfg!(all(unix, not(target_os = "macos"))) {
            let vars = [("HOME", "/h"), ("XDG_DATA_HOME", "/x")];
            assert_eq!(data_dir(env(&vars)).unwrap(), Path::new("/x/openncalayer"));
        }
    }

    #[test]
    fn layout() {
        let p = Paths {
            data: PathBuf::from("d"),
        };
        assert_eq!(p.tls().dir, Path::new("d").join("tls"));
        assert_eq!(p.settings(), Path::new("d").join("settings.json"));
        assert_eq!(p.logs(), Path::new("d").join("logs"));
    }
}
