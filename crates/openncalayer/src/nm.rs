//! Registration of the native messaging host (`openncalayer nm install|uninstall|status`,
//! roadmap D27): the relay `nmhost` with its `nmhost.json`, the host manifests of the
//! browsers and, on Windows, the HKCU keys that point the browsers at them.
//!
//! Messages in [`State::Invalid`] are for the user, in Russian.

use std::env::consts::EXE_SUFFIX;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oncl_desktop::registry;
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
    /// The browser's config directories: no manifest is written unless one of them exists.
    pub requires: Vec<PathBuf>,
}

impl ManifestTarget {
    /// Whether the browser is there: one of [`ManifestTarget::requires`] exists.
    pub fn browser_present(&self) -> bool {
        self.requires.iter().any(|dir| dir.exists())
    }

    /// [`ManifestTarget::requires`] for a report.
    fn shown_requires(&self) -> String {
        let dirs: Vec<String> = self.requires.iter().map(|dir| shown(dir)).collect();
        dirs.join(" | ")
    }
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
    ///   `${XDG_CONFIG_HOME:-~/.config}` and in `~/.mozilla/native-messaging-hosts` (Firefox
    ///   counts as present with `~/.mozilla` or, since Firefox 147, the XDG
    ///   `${XDG_CONFIG_HOME:-~/.config}/mozilla`; it reads host manifests from `~/.mozilla`
    ///   only);
    /// - macOS: the same under `~/Library/Application Support`, Firefox present with its
    ///   `Firefox` or `Mozilla` directory there.
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
            requires: vec![root.to_path_buf()],
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
                let config_dir = base.join(dir);
                ManifestTarget {
                    browser,
                    family: Family::Chromium,
                    dir: config_dir.join("NativeMessagingHosts"),
                    requires: vec![config_dir],
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
                requires: vec![relay_dir.clone()],
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
                requires: vec![support.join("Firefox"), mozilla],
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
            // Firefox 147+ keeps new profiles in `<config>/mozilla` and creates no
            // `~/.mozilla`, yet reads host manifests from `~/.mozilla` only (Mozilla bugs
            // 2001887, 2050007).
            let mozilla = home.join(".mozilla");
            manifests.push(ManifestTarget {
                browser: "Firefox",
                family: Family::Firefox,
                dir: mozilla.join("native-messaging-hosts"),
                requires: vec![mozilla, config.join("mozilla")],
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
    /// A temporary file of an interrupted install (`*.new`, `*.tmp`).
    TempFile,
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
    /// None of the browser's config directories exists; the location lists them.
    Skipped,
    /// Cannot be removed: a running process holds it (Windows: a relay the browser runs).
    InUse,
    /// Not usable, or the operation on it failed: why, for the user.
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
        !self.any(|state| matches!(state, State::Missing | State::Invalid(_)))
    }

    /// Some entry failed ([`State::Invalid`]).
    pub fn has_errors(&self) -> bool {
        self.any(|state| matches!(state, State::Invalid(_)))
    }

    /// Some file could not be removed because it is in use ([`State::InUse`]).
    pub fn has_in_use(&self) -> bool {
        self.any(|state| *state == State::InUse)
    }

    fn any(&self, f: impl Fn(&State) -> bool) -> bool {
        self.entries.iter().any(|entry| f(&entry.state))
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
/// directory `data_dir`, both made absolute), the manifests of the browsers that are present
/// and the registry keys. Every file is written to a temporary name and renamed into place,
/// so a running relay keeps running: on Windows, which cannot replace a running executable,
/// the installed relay is first renamed to `nmhost.old-<unix-ms>.exe`. Replaced relays that
/// no longer run are removed.
///
/// A manifest or registry key that cannot be written is recorded as [`State::Invalid`] and
/// the others are still written ([`Report::has_errors`]).
///
/// # Errors
///
/// The relay or its config cannot be installed, or a path is not UTF-8 (manifests hold the
/// relay path as a string); nothing is changed if `relay_src` cannot be read or a path is
/// refused.
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
    for path in [&relay, &config.data_dir, &config.daemon] {
        if path.to_str().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: the path is not UTF-8", path.display()),
            ));
        }
    }
    let config = serde_json::to_vec_pretty(&config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mut report = Report::default();
    fs::create_dir_all(&layout.relay_dir).map_err(|e| at(&layout.relay_dir, e))?;
    replace_relay(&relay, &relay_bytes, |from, to| {
        rename_retrying(|from, to| fs::rename(from, to), from, to)
    })?;
    report.push(Item::Relay, shown(&relay), State::Written);
    remove_old_relays(&layout.relay_dir, &mut report)?;
    let config_path = layout.relay_config();
    write_atomic(&config_path, &config)?;
    report.push(Item::RelayConfig, shown(&config_path), State::Written);

    let mut written = Vec::new();
    for target in &layout.manifests {
        let item = Item::Manifest {
            browser: target.browser,
        };
        if !target.browser_present() {
            report.push(item, target.shown_requires(), State::Skipped);
            continue;
        }
        let path = layout.manifest_path(target);
        let write = || {
            fs::create_dir_all(&target.dir).map_err(|e| at(&target.dir, e))?;
            let path = std::path::absolute(&path)?;
            write_atomic(&path, &manifest_bytes(target.family, &relay))?;
            Ok::<_, io::Error>(path)
        };
        match write() {
            Ok(path) => {
                report.push(item, shown(&path), State::Written);
                written.push((target.family, path));
            }
            Err(e) => report.push(item, shown(&path), State::Invalid(e.to_string())),
        }
    }

    if let Some(base) = &layout.registry_base {
        for (family, manifest) in &written {
            for sub in family.registry_keys() {
                let key = registry_key(base, sub);
                let state = match manifest.to_str() {
                    Some(value) => match registry::set_string(&key, None, value) {
                        Ok(()) => State::Written,
                        Err(e) => State::Invalid(e.to_string()),
                    },
                    None => {
                        State::Invalid(format!("путь манифеста {} не в UTF-8", manifest.display()))
                    }
                };
                report.push(Item::RegistryKey, format!("HKCU\\{key}"), state);
            }
        }
    }
    Ok(report)
}

/// Removes the registry keys, the manifests, the relay and its config, the replaced relays
/// and the temporary files of interrupted installs. Data in the relay directory (it is the
/// data directory on Linux and macOS) and the manifest directories stay.
///
/// Whatever cannot be removed is recorded and the rest is still removed: a running relay as
/// [`State::InUse`] (Windows), other failures as [`State::Invalid`].
///
/// # Errors
///
/// The relay directory cannot be listed.
pub fn uninstall(layout: &NmLayout) -> io::Result<Report> {
    let mut report = Report::default();
    if let Some(base) = &layout.registry_base {
        for family in layout.families() {
            for sub in family.registry_keys() {
                let key = registry_key(base, sub);
                let state = match registry::delete_tree(&key) {
                    Ok(existed) => removed_or_missing(existed),
                    Err(e) => State::Invalid(e.to_string()),
                };
                report.push(Item::RegistryKey, format!("HKCU\\{key}"), state);
            }
        }
    }
    for target in &layout.manifests {
        let path = layout.manifest_path(target);
        let item = Item::Manifest {
            browser: target.browser,
        };
        report.push(item, shown(&path), removal(&path));
        remove_temp(&with_suffix(&path, ".tmp"), &mut report);
    }
    let relay = layout.relay();
    report.push(Item::Relay, shown(&relay), removal(&relay));
    remove_temp(&with_suffix(&relay, ".new"), &mut report);
    let config = layout.relay_config();
    report.push(Item::RelayConfig, shown(&config), removal(&config));
    remove_temp(&with_suffix(&config, ".tmp"), &mut report);
    remove_old_relays(&layout.relay_dir, &mut report)?;
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
    match old_relays(&layout.relay_dir) {
        Ok(olds) => {
            for old in olds {
                report.push(Item::OldRelay, shown(&old), State::Present);
            }
        }
        Err(e) => report.push(
            Item::OldRelay,
            shown(&layout.relay_dir),
            State::Invalid(e.to_string()),
        ),
    }
    let mut temps = vec![with_suffix(&relay, ".new"), with_suffix(&config, ".tmp")];

    for target in &layout.manifests {
        let item = Item::Manifest {
            browser: target.browser,
        };
        let path = layout.manifest_path(target);
        temps.push(with_suffix(&path, ".tmp"));
        if path.exists() {
            let state = manifest_state(&path, &target.family.manifest(&relay));
            report.push(item, shown(&path), state);
        } else if target.browser_present() {
            report.push(item, shown(&path), State::Missing);
        } else {
            report.push(item, target.shown_requires(), State::Skipped);
        }
    }
    for temp in temps.iter().filter(|temp| temp.exists()) {
        report.push(Item::TempFile, shown(temp), State::Present);
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
                let state = match (registry::get_string(&key, None), &expected) {
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
/// `nmhost.old-<unix-ms>.exe` first. Renames go through `rename`. On failure the previous
/// relay stays in place (best effort on Windows) and `<relay>.new` is removed.
fn replace_relay(
    relay: &Path,
    bytes: &[u8],
    rename: impl Fn(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    let new = with_suffix(relay, ".new");
    write_synced(&new, bytes, true)?;
    let swap = || {
        let replaced = if cfg!(windows) && relay.exists() {
            let old = old_relay_name(relay)?;
            rename(relay, &old).map_err(|e| at(relay, e))?;
            Some(old)
        } else {
            None
        };
        rename(&new, relay).map_err(|e| {
            if let Some(old) = replaced {
                // Keep a relay in place for the browsers.
                let _ = rename(&old, relay);
            }
            at(&new, e)
        })
    };
    swap().inspect_err(|_| {
        let _ = fs::remove_file(&new);
    })
}

/// How long [`rename_retrying`] retries a rename refused with a sharing violation.
const RENAME_RETRY_FOR: Duration = Duration::from_secs(2);
/// The pause between two attempts of [`rename_retrying`].
const RENAME_RETRY_STEP: Duration = Duration::from_millis(50);

/// `rename(from, to)`, retried every [`RENAME_RETRY_STEP`] for up to [`RENAME_RETRY_FOR`]
/// while Windows refuses it with a sharing violation: another process, typically an
/// antivirus scanner, briefly holds a freshly written or started executable without delete
/// sharing. Any other error is returned at once.
fn rename_retrying(
    rename: impl Fn(&Path, &Path) -> io::Result<()>,
    from: &Path,
    to: &Path,
) -> io::Result<()> {
    let deadline = Instant::now() + RENAME_RETRY_FOR;
    loop {
        match rename(from, to) {
            Err(e) if sharing_violation(&e) && Instant::now() < deadline => {
                std::thread::sleep(RENAME_RETRY_STEP);
            }
            result => return result,
        }
    }
}

/// `ERROR_SHARING_VIOLATION`: a process holds the file without the needed sharing mode.
const SHARING_VIOLATION: i32 = 32;

/// Whether `e` is a Windows sharing violation (on Unix, 32 is an unrelated `errno`).
fn sharing_violation(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(SHARING_VIOLATION)
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

/// The replaced relays in `dir`, sorted; none if `dir` does not exist.
fn old_relays(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(at(dir, e)),
    };
    let mut olds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| at(dir, e))?;
        let old = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(OLD_RELAY_PREFIX));
        if old {
            olds.push(entry.path());
        }
    }
    olds.sort();
    Ok(olds)
}

/// Removes the replaced relays in `dir`; those still running stay ([`State::InUse`]).
fn remove_old_relays(dir: &Path, report: &mut Report) -> io::Result<()> {
    for old in old_relays(dir)? {
        match removal(&old) {
            // Gone meanwhile (another install).
            State::Missing => {}
            state => report.push(Item::OldRelay, shown(&old), state),
        }
    }
    Ok(())
}

/// Removes the temporary file `path` if it exists, recording it.
fn remove_temp(path: &Path, report: &mut Report) {
    match removal(path) {
        State::Missing => {}
        state => report.push(Item::TempFile, shown(path), state),
    }
}

/// Removes the file `path`: [`State::Removed`], [`State::Missing`] if it did not exist,
/// [`State::InUse`] or [`State::Invalid`].
fn removal(path: &Path) -> State {
    match fs::remove_file(path) {
        Ok(()) => State::Removed,
        Err(e) if e.kind() == io::ErrorKind::NotFound => State::Missing,
        Err(e) if in_use(&e) => State::InUse,
        Err(e) => State::Invalid(e.to_string()),
    }
}

/// Whether removing a file failed because a process holds it: Windows refuses to delete a
/// running executable (access denied) or a file opened without delete sharing (sharing
/// violation). Unix deletes such files.
fn in_use(e: &io::Error) -> bool {
    cfg!(windows) && (e.kind() == io::ErrorKind::PermissionDenied || sharing_violation(e))
}

/// Writes `bytes` to `path` through `<path>.tmp` and a rename; no `.tmp` stays on failure.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = with_suffix(path, ".tmp");
    write_synced(&tmp, bytes, false)?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        at(path, e)
    })
}

/// Creates or truncates `path` with `bytes`, mode 0755 on Unix if `executable`, and flushes
/// it to disk. On failure the file is removed.
fn write_synced(path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
    let write = || {
        let mut file = File::create(path)?;
        let result = file
            .write_all(bytes)
            .and_then(|()| {
                if executable {
                    make_executable(&file)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| file.sync_all());
        if result.is_err() {
            drop(file);
            let _ = fs::remove_file(path);
        }
        result
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
                vec![requires],
            )
        })
        .chain([(
            Family::Firefox,
            home.join(".mozilla/native-messaging-hosts").join(&host),
            vec![home.join(".mozilla"), config.join("mozilla")],
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
        assert_eq!(linux.manifests[0].requires, [xdg.join("google-chrome")]);
        // Firefox reads host manifests from `~/.mozilla` only, whatever XDG_CONFIG_HOME says.
        let firefox = &linux.manifests[5];
        assert_eq!(firefox.dir, home.join(".mozilla/native-messaging-hosts"));
        assert_eq!(
            firefox.requires,
            [home.join(".mozilla"), xdg.join("mozilla")]
        );
        let relative = [("HOME", home.clone()), ("XDG_CONFIG_HOME", "rel".into())];
        let linux = layout_for(Os::Linux, &data, env(&relative)).unwrap();
        assert_eq!(linux.manifests[0].requires, [config.join("google-chrome")]);

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
                vec![requires],
            )
        })
        .chain([(
            Family::Firefox,
            support.join("Mozilla/NativeMessagingHosts").join(&host),
            vec![support.join("Firefox"), support.join("Mozilla")],
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

    /// Firefox 147+ creates its profiles in `${XDG_CONFIG_HOME:-~/.config}/mozilla` and no
    /// `~/.mozilla`; it still reads host manifests from `~/.mozilla/native-messaging-hosts`.
    #[test]
    fn firefox_with_xdg_profiles_only_gets_its_manifest() {
        let host = format!("{HOST_NAME}.json");
        let firefox_written = |report: &Report| {
            report.entries.iter().any(|e| {
                e.item == Item::Manifest { browser: "Firefox" } && e.state == State::Written
            })
        };
        let daemon = Path::new("/opt/openncalayer");

        // Default XDG config directory.
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".config/mozilla/firefox")).unwrap();
        let src = tmp.path().join("relay-src");
        fs::write(&src, b"relay").unwrap();
        let data = tmp.path().join("data");
        let layout = layout_for(Os::Linux, &data, env(&[("HOME", home.clone())])).unwrap();
        let report = install(&layout, &src, daemon, &data).unwrap();
        assert!(firefox_written(&report), "{report:?}");
        assert!(
            home.join(".mozilla/native-messaging-hosts")
                .join(&host)
                .is_file()
        );
        assert!(!home.join(".config/mozilla/native-messaging-hosts").exists());

        // A custom XDG_CONFIG_HOME.
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let xdg = tmp.path().join("xdg");
        fs::create_dir_all(xdg.join("mozilla/firefox")).unwrap();
        let src = tmp.path().join("relay-src");
        fs::write(&src, b"relay").unwrap();
        let vars = [("HOME", home.clone()), ("XDG_CONFIG_HOME", xdg.clone())];
        let layout = layout_for(Os::Linux, &data, env(&vars)).unwrap();
        let report = install(&layout, &src, daemon, &tmp.path().join("data")).unwrap();
        assert!(firefox_written(&report), "{report:?}");
        assert!(
            home.join(".mozilla/native-messaging-hosts")
                .join(&host)
                .is_file()
        );

        // macOS: the profile root `Firefox` without `Mozilla`.
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let support = home.join("Library/Application Support");
        fs::create_dir_all(support.join("Firefox/Profiles")).unwrap();
        let src = tmp.path().join("relay-src");
        fs::write(&src, b"relay").unwrap();
        let layout = layout_for(Os::Mac, &data, env(&[("HOME", home.clone())])).unwrap();
        let report = install(&layout, &src, daemon, &tmp.path().join("data")).unwrap();
        assert!(firefox_written(&report), "{report:?}");
        assert!(
            support
                .join("Mozilla/NativeMessagingHosts")
                .join(&host)
                .is_file()
        );

        // Neither directory: skipped, the location names both.
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let src = tmp.path().join("relay-src");
        fs::write(&src, b"relay").unwrap();
        let layout = layout_for(Os::Linux, &data, env(&[("HOME", home.clone())])).unwrap();
        let report = install(&layout, &src, daemon, &tmp.path().join("data")).unwrap();
        let firefox = report
            .entries
            .iter()
            .find(|e| e.item == Item::Manifest { browser: "Firefox" })
            .unwrap();
        assert_eq!(firefox.state, State::Skipped);
        assert_eq!(
            firefox.location,
            format!(
                "{} | {}",
                shown(&home.join(".mozilla")),
                shown(&home.join(".config").join("mozilla"))
            )
        );
        assert!(!home.join(".mozilla").exists());
    }

    #[test]
    fn failed_relay_replacement_keeps_the_old_relay() {
        let tmp = TempDir::new().unwrap();
        let relay = tmp.path().join(relay_file_name());
        let new = with_suffix(&relay, ".new");
        let leftovers = || {
            let mut names: Vec<_> = fs::read_dir(tmp.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let only_relay = [OsString::from(relay_file_name())];
        fs::write(&relay, b"old").unwrap();

        // The last rename fails: on Windows the old relay, already renamed away, comes back.
        let failing_last = |from: &Path, to: &Path| {
            if from == new {
                Err(io::Error::other("injected"))
            } else {
                fs::rename(from, to)
            }
        };
        let err = replace_relay(&relay, b"new", failing_last).unwrap_err();
        assert!(err.to_string().contains("injected"), "{err}");
        assert_eq!(fs::read(&relay).unwrap(), b"old");
        assert_eq!(leftovers(), only_relay);

        // The first rename fails (Windows: moving the old relay away; Unix: the only one).
        let failing_all = |_: &Path, _: &Path| Err(io::Error::other("injected"));
        replace_relay(&relay, b"new", failing_all).unwrap_err();
        assert_eq!(fs::read(&relay).unwrap(), b"old");
        assert_eq!(leftovers(), only_relay);

        replace_relay(&relay, b"new", |from, to| fs::rename(from, to)).unwrap();
        assert_eq!(fs::read(&relay).unwrap(), b"new");
    }

    #[test]
    fn relay_rename_retries_only_sharing_violations() {
        use std::cell::Cell;

        let tmp = TempDir::new().unwrap();
        let relay = tmp.path().join(relay_file_name());
        fs::write(&relay, b"old").unwrap();

        // Every rename fails twice with a sharing violation, then goes through.
        let calls = Cell::new(0);
        let flaky = |from: &Path, to: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() % 3 != 0 {
                Err(io::Error::from_raw_os_error(SHARING_VIOLATION))
            } else {
                fs::rename(from, to)
            }
        };
        if cfg!(windows) {
            replace_relay(&relay, b"new", |from, to| rename_retrying(flaky, from, to)).unwrap();
            assert_eq!(fs::read(&relay).unwrap(), b"new");
            // Two renames on Windows (the old relay away, the new one in), three tries each.
            assert_eq!(calls.get(), 6);
        } else {
            // On Unix 32 is EPIPE: not retried.
            rename_retrying(flaky, &relay, &tmp.path().join("x")).unwrap_err();
            assert_eq!(calls.get(), 1);
        }

        // Any other error is returned at once.
        let calls = Cell::new(0);
        let denied = |_: &Path, _: &Path| {
            calls.set(calls.get() + 1);
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        };
        let err = rename_retrying(denied, &relay, &tmp.path().join("x")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn relay_rename_errors_name_their_source() {
        let tmp = TempDir::new().unwrap();
        let relay = tmp.path().join(relay_file_name());
        let new = with_suffix(&relay, ".new");
        fs::write(&relay, b"old").unwrap();
        let failing_last = |from: &Path, to: &Path| {
            if from == new {
                Err(io::Error::other("injected"))
            } else {
                fs::rename(from, to)
            }
        };
        let err = replace_relay(&relay, b"new", failing_last).unwrap_err();
        assert!(
            err.to_string().starts_with(&new.display().to_string()),
            "{err}"
        );
        if cfg!(windows) {
            let failing_first = |from: &Path, _: &Path| {
                if from == relay {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            };
            let err = replace_relay(&relay, b"new", failing_first).unwrap_err();
            let shown = format!("{}: injected", relay.display());
            assert_eq!(err.to_string(), shown);
        }
    }

    #[test]
    fn failed_write_leaves_no_temp_file() {
        let tmp = TempDir::new().unwrap();
        // A directory where the file should go: the rename fails on every platform.
        let path = tmp.path().join("manifest.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("inside"), b"x").unwrap();
        write_atomic(&path, b"{}").unwrap_err();
        assert!(!with_suffix(&path, ".tmp").exists());
        // The file cannot even be created.
        let path = tmp.path().join("missing").join("manifest.json");
        write_atomic(&path, b"{}").unwrap_err();
        assert!(!with_suffix(&path, ".tmp").exists());
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
            requires: vec![tmp.path().to_path_buf()],
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
                registry::get_string(key, None).unwrap().as_deref(),
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
        registry::set_string(&keys[0].0, None, r"C:\elsewhere.json").unwrap();
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
            assert_eq!(registry::get_string(key, None).unwrap(), None, "{key}");
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
