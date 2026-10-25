//! Registration of the native messaging host (`openncalayer nm install|uninstall|status`,
//! roadmap D27): the relay `nmhost` with its `nmhost.json`, the host manifests of the
//! browsers and, on Windows, the HKCU keys that point the browsers at them.
//!
//! Messages in [`State::Invalid`] are for the user, in Russian.

#[cfg(windows)]
mod registry;

use std::env::consts::EXE_SUFFIX;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use oncl_ipc::ids::{CHROMIUM_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::paths::Paths;

/// The relay's config, next to it: `{"data_dir": "<abs>", "daemon": "<abs>"}`.
pub const RELAY_CONFIG: &str = "nmhost.json";

/// File name prefix of relays replaced while running, removed by a later install.
const OLD_RELAY_PREFIX: &str = "nmhost.old-";

/// The relay's file name: `nmhost` (`nmhost.exe` on Windows), as `cargo` builds it.
pub fn relay_file_name() -> String {
    format!("nmhost{EXE_SUFFIX}")
}

/// Registry keys of the Chromium family on Windows, under the registry base.
const CHROMIUM_KEYS: &[&str] = &[
    r"Google\Chrome\NativeMessagingHosts",
    r"Chromium\NativeMessagingHosts",
    r"Microsoft\Edge\NativeMessagingHosts",
];
/// Registry keys of Firefox on Windows, under the registry base.
const FIREFOX_KEYS: &[&str] = &[r"Mozilla\NativeMessagingHosts"];

/// The manifest format a browser reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Chrome, Chromium, Edge, Brave, Yandex Browser: `allowed_origins`.
    Chromium,
    /// Firefox: `allowed_extensions`.
    Firefox,
}

impl Family {
    fn manifest(self, relay: &Path) -> Value {
        match self {
            Family::Chromium => chromium_manifest(relay),
            Family::Firefox => firefox_manifest(relay),
        }
    }

    /// The family's keys, each holding a key `<HOST_NAME>` whose default value is the
    /// manifest path.
    fn registry_keys(self) -> &'static [&'static str] {
        match self {
            Family::Chromium => CHROMIUM_KEYS,
            Family::Firefox => FIREFOX_KEYS,
        }
    }

    /// The manifest's file name when the registry points at it.
    fn registry_manifest_name(self) -> &'static str {
        match self {
            Family::Chromium => "chromium.json",
            Family::Firefox => "firefox.json",
        }
    }
}

/// Where one host manifest goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestTarget {
    /// The browser(s) reading it, for the user.
    pub browser: &'static str,
    pub family: Family,
    /// The manifest's directory.
    pub dir: PathBuf,
    /// The browser's config directory: no manifest is written unless it exists.
    pub requires: PathBuf,
}

/// Where `nm install` puts the relay, its config and the host manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmLayout {
    /// The relay and [`RELAY_CONFIG`].
    pub relay_dir: PathBuf,
    pub manifests: Vec<ManifestTarget>,
    /// The HKCU key (normally `Software`) under which the browsers' `NativeMessagingHosts`
    /// keys point at the manifests; `None`: no registry, the browsers find the manifests
    /// by their directory.
    pub registry_base: Option<String>,
}

/// The operating system whose layout is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Windows,
    /// macOS.
    Mac,
    /// Linux and other Unix.
    Linux,
}

impl Os {
    fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Mac
        } else {
            Os::Linux
        }
    }
}

impl NmLayout {
    /// The layout of this user:
    /// - Windows: the relay in `%LOCALAPPDATA%\OpenNCALayer\`, the manifests in its `nm\`
    ///   (`chromium.json`, `firefox.json`), found through HKCU `Software\…`;
    /// - Linux: the relay in the data directory, `<HOST_NAME>.json` in the
    ///   `NativeMessagingHosts` directory of each Chromium-family browser in
    ///   `${XDG_CONFIG_HOME:-~/.config}` and in `~/.mozilla/native-messaging-hosts`;
    /// - macOS: the same under `~/Library/Application Support`.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if `LOCALAPPDATA` (Windows) or `HOME` is not set.
    pub fn detect(paths: &Paths) -> io::Result<NmLayout> {
        layout_for(Os::current(), &paths.data, |name| std::env::var_os(name))
    }

    /// A layout entirely under `root` that never touches the registry, for browsers started
    /// with `--user-data-dir=<root>/chromium` (Chromium family) or `HOME=<root>/home`
    /// (Firefox): the relay in `root/relay/`, the manifests in
    /// `root/chromium/NativeMessagingHosts/` and `root/home/.mozilla/native-messaging-hosts/`.
    /// Install creates the directories.
    pub fn sandbox(root: &Path) -> NmLayout {
        let target = |browser, family, dir: PathBuf| ManifestTarget {
            browser,
            family,
            dir,
            requires: root.to_path_buf(),
        };
        NmLayout {
            relay_dir: root.join("relay"),
            manifests: vec![
                target(
                    "Chromium",
                    Family::Chromium,
                    root.join("chromium").join("NativeMessagingHosts"),
                ),
                target(
                    "Firefox",
                    Family::Firefox,
                    root.join("home")
                        .join(".mozilla")
                        .join("native-messaging-hosts"),
                ),
            ],
            registry_base: None,
        }
    }

    /// The installed relay: `nmhost` (`nmhost.exe` on Windows) in the relay directory.
    pub fn relay(&self) -> PathBuf {
        self.relay_dir.join(relay_file_name())
    }

    /// The relay's config, [`RELAY_CONFIG`] in the relay directory.
    pub fn relay_config(&self) -> PathBuf {
        self.relay_dir.join(RELAY_CONFIG)
    }

    /// The manifest file of `target`: `<HOST_NAME>.json`, the name browsers look for in a
    /// directory, or with the registry `chromium.json`/`firefox.json`, as the families may
    /// share a directory.
    pub fn manifest_path(&self, target: &ManifestTarget) -> PathBuf {
        if self.registry_base.is_some() {
            target.dir.join(target.family.registry_manifest_name())
        } else {
            target.dir.join(format!("{HOST_NAME}.json"))
        }
    }

    /// The families of the manifests, each once, in order.
    fn families(&self) -> Vec<Family> {
        let mut families = Vec::new();
        for target in &self.manifests {
            if !families.contains(&target.family) {
                families.push(target.family);
            }
        }
        families
    }
}

/// The layout of `os` with the data directory `data` and the environment `var`.
fn layout_for(os: Os, data: &Path, var: impl Fn(&str) -> Option<OsString>) -> io::Result<NmLayout> {
    let set = |name: &str| var(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let required = |name: &str| {
        set(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} is not set")))
    };
    // Chromium-family browsers with a config directory `<base>/<dir>`.
    let chromium = |base: &Path, browsers: [(&'static str, &str); 5]| -> Vec<ManifestTarget> {
        browsers
            .into_iter()
            .map(|(browser, dir)| {
                let requires = base.join(dir);
                ManifestTarget {
                    browser,
                    family: Family::Chromium,
                    dir: requires.join("NativeMessagingHosts"),
                    requires,
                }
            })
            .collect()
    };
    match os {
        Os::Windows => {
            let relay_dir = required("LOCALAPPDATA")?.join("OpenNCALayer");
            let target = |browser, family| ManifestTarget {
                browser,
                family,
                dir: relay_dir.join("nm"),
                // The registry, not a directory, tells whether a browser is there: the keys
                // of every browser are written.
                requires: relay_dir.clone(),
            };
            Ok(NmLayout {
                manifests: vec![
                    target("Chrome, Chromium, Edge", Family::Chromium),
                    target("Firefox", Family::Firefox),
                ],
                registry_base: Some("Software".to_owned()),
                relay_dir,
            })
        }
        Os::Mac => {
            let support = required("HOME")?.join("Library/Application Support");
            let mut manifests = chromium(
                &support,
                [
                    ("Google Chrome", "Google/Chrome"),
                    ("Chromium", "Chromium"),
                    ("Microsoft Edge", "Microsoft Edge"),
                    ("Brave", "BraveSoftware/Brave-Browser"),
                    ("Yandex Browser", "Yandex/YandexBrowser"),
                ],
            );
            let mozilla = support.join("Mozilla");
            manifests.push(ManifestTarget {
                browser: "Firefox",
                family: Family::Firefox,
                dir: mozilla.join("NativeMessagingHosts"),
                requires: mozilla,
            });
            Ok(NmLayout {
                relay_dir: data.to_path_buf(),
                manifests,
                registry_base: None,
            })
        }
        Os::Linux => {
            let home = required("HOME")?;
            // Chromium honours an absolute XDG_CONFIG_HOME, like the XDG spec.
            let config = set("XDG_CONFIG_HOME")
                .filter(|dir| dir.is_absolute())
                .unwrap_or_else(|| home.join(".config"));
            let mut manifests = chromium(
                &config,
                [
                    ("Google Chrome", "google-chrome"),
                    ("Chromium", "chromium"),
                    ("Microsoft Edge", "microsoft-edge"),
                    ("Brave", "BraveSoftware/Brave-Browser"),
                    ("Yandex Browser", "yandex-browser"),
                ],
            );
            let mozilla = home.join(".mozilla");
            manifests.push(ManifestTarget {
                browser: "Firefox",
                family: Family::Firefox,
                dir: mozilla.join("native-messaging-hosts"),
                requires: mozilla,
            });
            Ok(NmLayout {
                relay_dir: data.to_path_buf(),
                manifests,
                registry_base: None,
            })
        }
    }
}

/// The host manifest for Chromium-family browsers, the relay at `relay` (absolute; a path
/// that is not UTF-8 is written lossily, [`install`] refuses it).
pub fn chromium_manifest(relay: &Path) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "OpenNCALayer",
        "path": relay.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")],
    })
}

/// The host manifest for Firefox, the relay at `relay` (as in [`chromium_manifest`]).
pub fn firefox_manifest(relay: &Path) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "OpenNCALayer",
        "path": relay.to_string_lossy(),
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    })
}

/// What a report entry is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// The relay executable.
    Relay,
    /// [`RELAY_CONFIG`].
    RelayConfig,
    /// A relay replaced while it was running (`nmhost.old-*`).
    OldRelay,
    /// The host manifest for `browser`.
    Manifest { browser: &'static str },
    /// An HKCU key pointing a browser at a manifest.
    RegistryKey,
}

/// The state of a report entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Written by install.
    Written,
    /// Removed.
    Removed,
    /// In place and as install writes it.
    Present,
    /// Not there.
    Missing,
    /// The browser's config directory does not exist; the location is that directory.
    Skipped,
    /// A replaced relay that is still running; a later install removes it.
    InUse,
    /// There but not usable: why, for the user.
    Invalid(String),
}

/// One file or registry key and its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub item: Item,
    /// A path, or `HKCU\…` for a registry key.
    pub location: String,
    pub state: State,
}

/// What install, uninstall or status found or did, entry by entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub entries: Vec<Entry>,
}

impl Report {
    /// For [`status`]: nothing is missing or invalid (skipped browsers are fine).
    pub fn is_healthy(&self) -> bool {
        !self
            .entries
            .iter()
            .any(|entry| matches!(entry.state, State::Missing | State::Invalid(_)))
    }

    fn push(&mut self, item: Item, location: impl Into<String>, state: State) {
        self.entries.push(Entry {
            item,
            location: location.into(),
            state,
        });
    }
}

/// The relay's config file, as the relay reads it.
#[derive(Serialize, Deserialize)]
struct RelayConfig {
    data_dir: PathBuf,
    daemon: PathBuf,
}

/// Installs the relay copied from `relay_src`, its config (the daemon `daemon` with the data
/// directory `data_dir`, both made absolute), the manifests of the browsers whose config
/// directory exists and the registry keys. Every file is written to a temporary name and
/// renamed into place, so a running relay keeps running: on Windows, which cannot replace a
/// running executable, the installed relay is first renamed to `nmhost.old-<unix-ms>.exe`.
/// Replaced relays that no longer run are removed.
///
/// # Errors
///
/// The first failure, with the path concerned; nothing is changed if `relay_src` cannot be
/// read.
pub fn install(
    layout: &NmLayout,
    relay_src: &Path,
    daemon: &Path,
    data_dir: &Path,
) -> io::Result<Report> {
    let relay_bytes = fs::read(relay_src).map_err(|e| at(relay_src, e))?;
    let config = RelayConfig {
        data_dir: std::path::absolute(data_dir)?,
        daemon: std::path::absolute(daemon)?,
    };
    let relay = std::path::absolute(layout.relay())?;
    if relay.to_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{}: a manifest cannot hold a path that is not UTF-8",
                relay.display()
            ),
        ));
    }
    let config = serde_json::to_vec_pretty(&config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mut report = Report::default();
    fs::create_dir_all(&layout.relay_dir).map_err(|e| at(&layout.relay_dir, e))?;
    replace_relay(&relay, &relay_bytes)?;
    report.push(Item::Relay, shown(&relay), State::Written);
    remove_old_relays(&layout.relay_dir, &mut report);
    let config_path = layout.relay_config();
    write_atomic(&config_path, &config)?;
    report.push(Item::RelayConfig, shown(&config_path), State::Written);

    let mut written = Vec::new();
    for target in &layout.manifests {
        let item = Item::Manifest {
            browser: target.browser,
        };
        if !target.requires.exists() {
            report.push(item, shown(&target.requires), State::Skipped);
            continue;
        }
        fs::create_dir_all(&target.dir).map_err(|e| at(&target.dir, e))?;
        let path = std::path::absolute(layout.manifest_path(target))?;
        write_atomic(&path, &manifest_bytes(target.family, &relay))?;
        report.push(item, shown(&path), State::Written);
        written.push((target.family, path));
    }

    if let Some(base) = &layout.registry_base {
        for (family, manifest) in &written {
            let value = manifest.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: the registry value must be UTF-8", manifest.display()),
                )
            })?;
            for sub in family.registry_keys() {
                let key = registry_key(base, sub);
                registry::set_default(&key, value)
                    .map_err(|e| io::Error::new(e.kind(), format!("HKCU\\{key}: {e}")))?;
                report.push(Item::RegistryKey, format!("HKCU\\{key}"), State::Written);
            }
        }
    }
    Ok(report)
}

/// Removes the registry keys, the manifests, the relay and its config and the replaced
/// relays that no longer run. Data in the relay directory (it is the data directory on
/// Linux and macOS) and the manifest directories stay.
///
/// # Errors
///
/// The first failure, with the path concerned (on Windows: the relay is running).
pub fn uninstall(layout: &NmLayout) -> io::Result<Report> {
    let mut report = Report::default();
    if let Some(base) = &layout.registry_base {
        for family in layout.families() {
            for sub in family.registry_keys() {
                let key = registry_key(base, sub);
                let existed = registry::delete_tree(&key)
                    .map_err(|e| io::Error::new(e.kind(), format!("HKCU\\{key}: {e}")))?;
                report.push(
                    Item::RegistryKey,
                    format!("HKCU\\{key}"),
                    removed_or_missing(existed),
                );
            }
        }
    }
    for target in &layout.manifests {
        let path = layout.manifest_path(target);
        let existed = remove_file(&path)?;
        let item = Item::Manifest {
            browser: target.browser,
        };
        report.push(item, shown(&path), removed_or_missing(existed));
    }
    let relay = layout.relay();
    let existed = remove_file(&relay)?;
    report.push(Item::Relay, shown(&relay), removed_or_missing(existed));
    remove_file(&with_suffix(&relay, ".new"))?;
    let config = layout.relay_config();
    let existed = remove_file(&config)?;
    report.push(
        Item::RelayConfig,
        shown(&config),
        removed_or_missing(existed),
    );
    remove_old_relays(&layout.relay_dir, &mut report);
    Ok(report)
}

/// What is installed and whether it is as [`install`] writes it.
pub fn status(layout: &NmLayout) -> Report {
    let mut report = Report::default();
    let relay = match std::path::absolute(layout.relay()) {
        Ok(relay) => relay,
        Err(e) => {
            let location = shown(&layout.relay());
            report.push(Item::Relay, location, State::Invalid(e.to_string()));
            return report;
        }
    };
    let state = if relay.is_file() {
        State::Present
    } else {
        State::Missing
    };
    report.push(Item::Relay, shown(&relay), state);
    let config = layout.relay_config();
    report.push(Item::RelayConfig, shown(&config), config_state(&config));
    for old in old_relays(&layout.relay_dir) {
        report.push(Item::OldRelay, shown(&old), State::Present);
    }

    for target in &layout.manifests {
        let item = Item::Manifest {
            browser: target.browser,
        };
        let path = layout.manifest_path(target);
        if path.exists() {
            let state = manifest_state(&path, &target.family.manifest(&relay));
            report.push(item, shown(&path), state);
        } else if target.requires.exists() {
            report.push(item, shown(&path), State::Missing);
        } else {
            report.push(item, shown(&target.requires), State::Skipped);
        }
    }

    if let Some(base) = &layout.registry_base {
        for family in layout.families() {
            let Some(target) = layout.manifests.iter().find(|t| t.family == family) else {
                continue;
            };
            let expected = std::path::absolute(layout.manifest_path(target))
                .map(|path| path.to_string_lossy().into_owned());
            for sub in family.registry_keys() {
                let key = registry_key(base, sub);
                let state = match (registry::get_default(&key), &expected) {
                    (Ok(Some(value)), Ok(expected)) if value == *expected => State::Present,
                    (Ok(Some(value)), Ok(expected)) => {
                        State::Invalid(format!("указывает на {value}, а не на {expected}"))
                    }
                    (Ok(None), _) => State::Missing,
                    (Err(e), _) => State::Invalid(e.to_string()),
                    (_, Err(e)) => State::Invalid(e.to_string()),
                };
                report.push(Item::RegistryKey, format!("HKCU\\{key}"), state);
            }
        }
    }
    report
}

/// `<base>\<sub>\<HOST_NAME>`.
fn registry_key(base: &str, sub: &str) -> String {
    format!("{base}\\{sub}\\{HOST_NAME}")
}

fn manifest_bytes(family: Family, relay: &Path) -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec_pretty(&family.manifest(relay)).expect("a JSON value always serializes");
    bytes.push(b'\n');
    bytes
}

/// Whether the manifest at `path` is `expected`.
fn manifest_state(path: &Path, expected: &Value) -> State {
    let found = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes),
        Err(e) => return State::Invalid(format!("не читается: {e}")),
    };
    match found {
        Ok(found) if found == *expected => State::Present,
        Ok(_) => State::Invalid(
            "отличается от ожидаемого, переустановите: openncalayer nm install".to_owned(),
        ),
        Err(e) => State::Invalid(format!("неверный JSON: {e}")),
    }
}

/// Whether the relay's config at `path` is usable: absolute paths, the daemon exists.
fn config_state(path: &Path) -> State {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return State::Missing,
        Err(e) => return State::Invalid(format!("не читается: {e}")),
    };
    let config: RelayConfig = match serde_json::from_slice(&bytes) {
        Ok(config) => config,
        Err(e) => return State::Invalid(format!("неверный JSON: {e}")),
    };
    if !config.data_dir.is_absolute() || !config.daemon.is_absolute() {
        return State::Invalid("пути data_dir и daemon должны быть абсолютными".to_owned());
    }
    if !config.daemon.is_file() {
        return State::Invalid(format!(
            "не найден исполняемый файл демона {}",
            config.daemon.display()
        ));
    }
    State::Present
}

/// Puts `bytes` at `relay`: written as `<relay>.new`, then renamed over it (Unix), or (Windows,
/// where a running executable can be renamed but not replaced) the old relay is renamed to
/// `nmhost.old-<unix-ms>.exe` first.
fn replace_relay(relay: &Path, bytes: &[u8]) -> io::Result<()> {
    let new = with_suffix(relay, ".new");
    write_synced(&new, bytes, true)?;
    let replaced = if cfg!(windows) && relay.exists() {
        let old = old_relay_name(relay)?;
        fs::rename(relay, &old).map_err(|e| at(relay, e))?;
        Some(old)
    } else {
        None
    };
    if let Err(e) = fs::rename(&new, relay) {
        if let Some(old) = replaced {
            // Best effort: keep a relay in place for the browsers.
            let _ = fs::rename(old, relay);
        }
        let _ = fs::remove_file(&new);
        return Err(at(relay, e));
    }
    Ok(())
}

/// A free `nmhost.old-<unix-ms><EXE_SUFFIX>` next to `relay`.
fn old_relay_name(relay: &Path) -> io::Result<PathBuf> {
    let dir = relay.parent().unwrap_or(Path::new("."));
    let mut ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    loop {
        let old = dir.join(format!("{OLD_RELAY_PREFIX}{ms}{EXE_SUFFIX}"));
        if !old.exists() {
            return Ok(old);
        }
        ms += 1;
    }
}

/// The replaced relays in `dir`, sorted.
fn old_relays(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut olds: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(OLD_RELAY_PREFIX))
        })
        .map(|entry| entry.path())
        .collect();
    olds.sort();
    olds
}

/// Removes the replaced relays in `dir`; those still running stay ([`State::InUse`]).
fn remove_old_relays(dir: &Path, report: &mut Report) {
    for old in old_relays(dir) {
        let state = match fs::remove_file(&old) {
            Ok(()) => State::Removed,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => State::InUse,
        };
        report.push(Item::OldRelay, shown(&old), state);
    }
}

/// Writes `bytes` to `path` through `<path>.tmp` and a rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = with_suffix(path, ".tmp");
    write_synced(&tmp, bytes, false)?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        at(path, e)
    })
}

/// Creates or truncates `path` with `bytes`, mode 0755 on Unix if `executable`, and flushes
/// it to disk.
fn write_synced(path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
    let write = || {
        let mut file = File::create(path)?;
        file.write_all(bytes)?;
        if executable {
            make_executable(&file)?;
        }
        file.sync_all()
    };
    write().map_err(|e| at(path, e))
}

#[cfg(unix)]
fn make_executable(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn make_executable(_: &File) -> io::Result<()> {
    Ok(())
}

/// Removes `path`; `false` if it did not exist.
fn remove_file(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(at(path, e)),
    }
}

fn removed_or_missing(existed: bool) -> State {
    if existed {
        State::Removed
    } else {
        State::Missing
    }
}

/// `path` with `suffix` appended to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// `path` for a report: absolute, so every entry reads the same way.
fn shown(path: &Path) -> String {
    match std::path::absolute(path) {
        Ok(absolute) => absolute.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// `e` with `path` in its message.
fn at(path: &Path, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

/// The registry exists on Windows only: elsewhere a layout with a registry base fails.
#[cfg(not(windows))]
mod registry {
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the registry exists on Windows only",
        )
    }

    pub fn set_default(_key: &str, _value: &str) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn get_default(_key: &str) -> io::Result<Option<String>> {
        Err(unsupported())
    }

    pub fn delete_tree(_key: &str) -> io::Result<bool> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn env<'a>(pairs: &'a [(&'a str, PathBuf)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone().into_os_string())
        }
    }

    #[test]
    fn manifests_have_exact_fields() {
        let relay = std::env::temp_dir().join("relay").join("nmhost");
        let path = relay.to_str().unwrap();
        assert_eq!(
            chromium_manifest(&relay),
            json!({
                "name": "io.github.arynyklas.openncalayer",
                "description": "OpenNCALayer",
                "path": path,
                "type": "stdio",
                "allowed_origins": [format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")],
            })
        );
        assert_eq!(
            firefox_manifest(&relay),
            json!({
                "name": "io.github.arynyklas.openncalayer",
                "description": "OpenNCALayer",
                "path": path,
                "type": "stdio",
                "allowed_extensions": ["openncalayer@arynyklas.github.io"],
            })
        );
        assert_eq!(chromium_manifest(&relay).as_object().unwrap().len(), 5);
        assert_eq!(firefox_manifest(&relay).as_object().unwrap().len(), 5);
    }

    #[test]
    fn layouts_per_os() {
        let tmp = TempDir::new().unwrap();
        let (home, local, data) = (
            tmp.path().join("home"),
            tmp.path().join("local"),
            tmp.path().join("data"),
        );
        let vars = [("HOME", home.clone()), ("LOCALAPPDATA", local.clone())];

        let windows = layout_for(Os::Windows, &data, env(&vars)).unwrap();
        let relay_dir = local.join("OpenNCALayer");
        assert_eq!(windows.relay_dir, relay_dir);
        assert_eq!(windows.registry_base.as_deref(), Some("Software"));
        let manifests: Vec<_> = windows
            .manifests
            .iter()
            .map(|t| (t.family, windows.manifest_path(t)))
            .collect();
        assert_eq!(
            manifests,
            [
                (Family::Chromium, relay_dir.join("nm").join("chromium.json")),
                (Family::Firefox, relay_dir.join("nm").join("firefox.json")),
            ]
        );
        assert_eq!(
            registry_key("Software", CHROMIUM_KEYS[0]),
            r"Software\Google\Chrome\NativeMessagingHosts\io.github.arynyklas.openncalayer"
        );
        assert_eq!(
            CHROMIUM_KEYS,
            [
                r"Google\Chrome\NativeMessagingHosts",
                r"Chromium\NativeMessagingHosts",
                r"Microsoft\Edge\NativeMessagingHosts",
            ]
        );
        assert_eq!(FIREFOX_KEYS, [r"Mozilla\NativeMessagingHosts"]);

        let host = format!("{HOST_NAME}.json");
        let linux = layout_for(Os::Linux, &data, env(&vars)).unwrap();
        assert_eq!(linux.relay_dir, data);
        assert_eq!(linux.registry_base, None);
        let config = home.join(".config");
        let expected: Vec<_> = [
            "google-chrome",
            "chromium",
            "microsoft-edge",
            "BraveSoftware/Brave-Browser",
            "yandex-browser",
        ]
        .iter()
        .map(|dir| {
            let requires = config.join(dir);
            (
                Family::Chromium,
                requires.join("NativeMessagingHosts").join(&host),
                requires,
            )
        })
        .chain([(
            Family::Firefox,
            home.join(".mozilla/native-messaging-hosts").join(&host),
            home.join(".mozilla"),
        )])
        .collect();
        let found: Vec<_> = linux
            .manifests
            .iter()
            .map(|t| (t.family, linux.manifest_path(t), t.requires.clone()))
            .collect();
        assert_eq!(found, expected);

        let xdg = tmp.path().join("xdg");
        let with_xdg = [("HOME", home.clone()), ("XDG_CONFIG_HOME", xdg.clone())];
        let linux = layout_for(Os::Linux, &data, env(&with_xdg)).unwrap();
        assert_eq!(linux.manifests[0].requires, xdg.join("google-chrome"));
        let relative = [("HOME", home.clone()), ("XDG_CONFIG_HOME", "rel".into())];
        let linux = layout_for(Os::Linux, &data, env(&relative)).unwrap();
        assert_eq!(linux.manifests[0].requires, config.join("google-chrome"));

        let macos = layout_for(Os::Mac, &data, env(&vars)).unwrap();
        let support = home.join("Library/Application Support");
        assert_eq!(macos.relay_dir, data);
        assert_eq!(macos.registry_base, None);
        let found: Vec<_> = macos
            .manifests
            .iter()
            .map(|t| (t.family, macos.manifest_path(t), t.requires.clone()))
            .collect();
        let expected: Vec<_> = [
            "Google/Chrome",
            "Chromium",
            "Microsoft Edge",
            "BraveSoftware/Brave-Browser",
            "Yandex/YandexBrowser",
        ]
        .iter()
        .map(|dir| {
            let requires = support.join(dir);
            (
                Family::Chromium,
                requires.join("NativeMessagingHosts").join(&host),
                requires,
            )
        })
        .chain([(
            Family::Firefox,
            support.join("Mozilla/NativeMessagingHosts").join(&host),
            support.join("Mozilla"),
        )])
        .collect();
        assert_eq!(found, expected);

        for os in [Os::Windows, Os::Mac, Os::Linux] {
            let err = layout_for(os, &data, env(&[])).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }
    }

    #[test]
    fn install_skips_browsers_without_config_dir() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".config").join("chromium")).unwrap();
        fs::create_dir_all(home.join(".mozilla")).unwrap();
        let data = tmp.path().join("data");
        let layout = layout_for(Os::Linux, &data, env(&[("HOME", home.clone())])).unwrap();
        assert_eq!(layout.registry_base, None);
        let src = tmp.path().join("relay-src");
        fs::write(&src, b"relay").unwrap();

        let report = install(&layout, &src, &tmp.path().join("openncalayer"), &data).unwrap();
        let host = format!("{HOST_NAME}.json");
        let chromium = home
            .join(".config/chromium/NativeMessagingHosts")
            .join(&host);
        let firefox = home.join(".mozilla/native-messaging-hosts").join(&host);
        assert!(chromium.is_file() && firefox.is_file());
        for dir in [
            "google-chrome",
            "microsoft-edge",
            "BraveSoftware",
            "yandex-browser",
        ] {
            assert!(!home.join(".config").join(dir).exists(), "{dir}");
        }
        let manifests: Vec<_> = report
            .entries
            .iter()
            .filter_map(|entry| match entry.item {
                Item::Manifest { browser } => Some((browser, entry.state.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            manifests,
            [
                ("Google Chrome", State::Skipped),
                ("Chromium", State::Written),
                ("Microsoft Edge", State::Skipped),
                ("Brave", State::Skipped),
                ("Yandex Browser", State::Skipped),
                ("Firefox", State::Written),
            ]
        );
        let skipped = &report.entries[2];
        let chrome = home.join(".config").join("google-chrome");
        assert_eq!(skipped.location, shown(&chrome));

        // Skipped browsers are no problem for status.
        fs::write(tmp.path().join("openncalayer"), b"daemon").unwrap();
        let status = status(&layout);
        assert!(status.is_healthy(), "{status:?}");
        assert_eq!(
            status
                .entries
                .iter()
                .filter(|e| e.state == State::Skipped)
                .count(),
            4
        );
    }

    #[cfg(windows)]
    #[test]
    fn registry_values_under_test_base() {
        /// Deletes the test base, also when the test fails.
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = registry::delete_tree(&self.0);
            }
        }

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = format!(
            r"Software\OpenNCALayer-test-{:x}-{nanos:x}",
            std::process::id()
        );
        let cleanup = Cleanup(base.clone());
        let tmp = TempDir::new().unwrap();
        let target = |browser, family| ManifestTarget {
            browser,
            family,
            dir: tmp.path().join("nm"),
            requires: tmp.path().to_path_buf(),
        };
        let layout = NmLayout {
            relay_dir: tmp.path().join("relay"),
            manifests: vec![
                target("Chromium", Family::Chromium),
                target("Firefox", Family::Firefox),
            ],
            registry_base: Some(base.clone()),
        };
        let src = tmp.path().join("relay-src");
        fs::write(&src, b"relay").unwrap();
        let daemon = tmp.path().join("openncalayer.exe");
        fs::write(&daemon, b"daemon").unwrap();

        let report = install(&layout, &src, &daemon, &tmp.path().join("data")).unwrap();
        let chromium = tmp.path().join("nm").join("chromium.json");
        let firefox = tmp.path().join("nm").join("firefox.json");
        assert!(chromium.is_file() && firefox.is_file());
        let keys: Vec<(String, PathBuf)> = CHROMIUM_KEYS
            .iter()
            .map(|sub| (registry_key(&base, sub), chromium.clone()))
            .chain([(registry_key(&base, FIREFOX_KEYS[0]), firefox.clone())])
            .collect();
        for (key, manifest) in &keys {
            assert!(key.starts_with(r"Software\OpenNCALayer-test-"), "{key}");
            assert_eq!(
                registry::get_default(key).unwrap().as_deref(),
                Some(manifest.to_str().unwrap()),
                "{key}"
            );
        }
        let written: Vec<_> = report
            .entries
            .iter()
            .filter(|e| e.item == Item::RegistryKey)
            .map(|e| (e.location.clone(), e.state.clone()))
            .collect();
        let expected: Vec<_> = keys
            .iter()
            .map(|(key, _)| (format!(r"HKCU\{key}"), State::Written))
            .collect();
        assert_eq!(written, expected);
        assert!(status(&layout).is_healthy());

        // A key pointing elsewhere is reported.
        registry::set_default(&keys[0].0, r"C:\elsewhere.json").unwrap();
        let report = status(&layout);
        assert!(!report.is_healthy());
        assert!(matches!(
            report
                .entries
                .iter()
                .find(|e| e.location == format!(r"HKCU\{}", keys[0].0))
                .map(|e| &e.state),
            Some(State::Invalid(_))
        ));

        let report = uninstall(&layout).unwrap();
        for (key, _) in &keys {
            assert_eq!(registry::get_default(key).unwrap(), None, "{key}");
            assert!(
                report.entries.contains(&Entry {
                    item: Item::RegistryKey,
                    location: format!(r"HKCU\{key}"),
                    state: State::Removed,
                }),
                "{key}"
            );
        }
        assert!(!chromium.exists() && !firefox.exists());
        let report = status(&layout);
        assert!(
            report
                .entries
                .iter()
                .filter(|e| e.item == Item::RegistryKey)
                .all(|e| e.state == State::Missing)
        );

        // The parents created for the test keys are still there; the base goes with them.
        assert!(registry::delete_tree(&base).unwrap());
        assert!(!registry::delete_tree(&base).unwrap());
        drop(cleanup);
    }
}
