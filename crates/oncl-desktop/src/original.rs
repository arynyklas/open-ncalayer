//! The original NCALayer next to ours: whether it is installed, its autostart entries and
//! who holds the port, as the settings window shows them ([`OriginalControl`],
//! [`OriginalNcaLayer`]).
//!
//! Its autostart entries ([`original_autostart`]):
//! - Windows: the shortcut `NCALayer.lnk` in the user's Startup folder, and any other
//!   shortcut there to `NCALayer.exe` (a localized name); the value `NCALayer` of
//!   `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (the MSI), for every user and only
//!   read here;
//! - Linux: `ncalayer.desktop` in the XDG autostart directory;
//! - macOS: none, the original has no autostart.
//!
//! [`disable_original`] moves the shortcuts into `original-autostart/` next to the journal
//! and hides the desktop entry (`Hidden=true`) after a backup copy there; [`restore_original`]
//! puts them back. Both are driven by the journal `original-autostart.json`: an entry is
//! written there before it is changed and removed only after it is put back, so an
//! interrupted call loses nothing and a repeated one finishes the job.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use oncl_pki::fsutil::Access;
use serde_json::{Map, Value, json};

use crate::autostart::desktop_entry_disabled;
use crate::port_owner::port_owner;
use crate::write_file;

/// What starts the original at login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A shortcut in the user's Startup folder (Windows).
    StartupShortcut,
    /// The `NCALayer` value of `HKLM\…\Run` (Windows), for every user: only an administrator
    /// can change it.
    MachineRun,
    /// An XDG autostart desktop entry (Linux).
    DesktopEntry,
}

/// One autostart entry of the original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutostartEntry {
    pub kind: EntryKind,
    /// The file, or the registry value as `HKLM\…\Run\NCALayer`.
    pub path: PathBuf,
    /// Whether it starts the original at login (not moved aside or hidden).
    pub enabled: bool,
}

/// The original NCALayer as found on this system.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginalStatus {
    /// Whether the original is installed.
    pub found: bool,
    /// Its autostart entries, enabled or disabled by us.
    pub autostart: Vec<AutostartEntry>,
    /// The program holding our port, if it is not us (for the user).
    pub port_owner: Option<String>,
}

/// What [`OriginalControl::disable`] or [`OriginalControl::restore`] changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The entries moved aside, hidden or put back.
    pub changed: Vec<PathBuf>,
}

/// The settings window's view of the original NCALayer.
pub trait OriginalControl: Send + Sync {
    /// The original as it is now.
    fn status(&self) -> OriginalStatus;

    /// Stops the original's autostart entries of this user from starting it, keeping them.
    ///
    /// # Errors
    ///
    /// An entry cannot be changed; a repeated call finishes the job.
    fn disable(&self) -> io::Result<Report>;

    /// Puts back what [`OriginalControl::disable`] changed.
    ///
    /// # Errors
    ///
    /// An entry cannot be put back; a repeated call finishes the job.
    fn restore(&self) -> io::Result<Report>;
}

/// An original NCALayer that is not managed: nothing is found, and nothing can be disabled
/// or restored.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unavailable;

impl OriginalControl for Unavailable {
    fn status(&self) -> OriginalStatus {
        OriginalStatus::default()
    }

    fn disable(&self) -> io::Result<Report> {
        Err(not_available())
    }

    fn restore(&self) -> io::Result<Report> {
        Err(not_available())
    }
}

fn not_available() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the original NCALayer cannot be managed here",
    )
}

/// The original NCALayer of this user ([`OriginalLocations`]), its journal and the port it
/// would hold.
#[derive(Clone, Debug)]
pub struct OriginalNcaLayer {
    locations: OriginalLocations,
    journal: PathBuf,
    port: u16,
}

impl OriginalNcaLayer {
    /// The original at `locations`, with the journal `journal` (`<data>/original-autostart.json`)
    /// and the port `port`.
    pub fn new(locations: OriginalLocations, journal: PathBuf, port: u16) -> OriginalNcaLayer {
        OriginalNcaLayer {
            locations,
            journal,
            port,
        }
    }
}

impl OriginalControl for OriginalNcaLayer {
    /// Found if it has an autostart entry or one of its files exists; the port owner is
    /// any process holding the port but this one.
    fn status(&self) -> OriginalStatus {
        let autostart = original_autostart(&self.locations, &self.journal).entries;
        let found = !autostart.is_empty() || self.locations.installed();
        let port_owner = match port_owner(self.port) {
            Ok(Some(owner)) if owner.pid != std::process::id() => {
                Some(owner.exe.display().to_string())
            }
            Ok(_) => None,
            Err(e) => {
                tracing::debug!(error = %e, port = self.port, "the port's owner is unknown");
                None
            }
        };
        OriginalStatus {
            found,
            autostart,
            port_owner,
        }
    }

    fn disable(&self) -> io::Result<Report> {
        disable_original(&self.locations, &self.journal)
    }

    fn restore(&self) -> io::Result<Report> {
        restore_original(&self.locations, &self.journal)
    }
}

/// The name of the original's Startup shortcut.
const SHORTCUT_NAME: &str = "NCALayer.lnk";
/// The original's program on Windows, also what a localized shortcut points to.
const TARGET_NAME: &str = "NCALayer.exe";
/// The name of the original's XDG autostart entry.
const DESKTOP_NAME: &str = "ncalayer.desktop";
/// The directory next to the journal where the moved entries and the backups are.
const STORE_DIR: &str = "original-autostart";
/// Shortcuts larger than this are not read for their target.
const MAX_SHORTCUT: u64 = 1 << 20;

/// Where the original's autostart entries and files are: those of this user
/// ([`OriginalLocations::detect`]) or a sandbox for tests ([`OriginalLocations::sandbox`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalLocations {
    /// The Startup folder (Windows).
    startup: Option<PathBuf>,
    /// The XDG autostart directory (Linux).
    autostart: Option<PathBuf>,
    /// Files or directories of an installed original.
    installs: Vec<PathBuf>,
    /// The machine-wide `Run` value (Windows).
    #[cfg(windows)]
    machine_run: Option<MachineRun>,
}

impl OriginalLocations {
    /// The locations of the user running this process. A location that cannot be found
    /// (the Startup folder, the home directory) is left out with a warning.
    pub fn detect() -> OriginalLocations {
        #[cfg(windows)]
        {
            let startup = startup_folder()
                .inspect_err(|e| tracing::warn!(error = %e, "the Startup folder is unknown"))
                .ok();
            let program_dirs = [
                "ProgramW6432",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "APPDATA",
            ];
            let mut installs: Vec<PathBuf> = program_dirs
                .iter()
                .filter_map(std::env::var_os)
                .filter(|d| !d.is_empty())
                .map(|d| PathBuf::from(d).join("NCALayer").join(TARGET_NAME))
                .collect();
            installs.dedup();
            OriginalLocations {
                startup,
                autostart: None,
                installs,
                machine_run: Some(MachineRun::local_machine()),
            }
        }
        #[cfg(unix)]
        {
            let Ok(paths) = crate::AutostartPaths::detect()
                .inspect_err(|e| tracing::warn!(error = %e, "the home directory is unknown"))
            else {
                return OriginalLocations {
                    startup: None,
                    autostart: None,
                    installs: Vec::new(),
                };
            };
            let home = paths.home();
            if cfg!(target_os = "macos") {
                OriginalLocations {
                    startup: None,
                    autostart: None,
                    installs: vec![
                        PathBuf::from("/Applications/NCALayer.app"),
                        home.join("Applications/NCALayer.app"),
                        home.join("Library/Application Support/NCALayer"),
                    ],
                }
            } else {
                OriginalLocations {
                    startup: None,
                    autostart: Some(paths.autostart_dir()),
                    // Its home directory and its menu entry: `ncalayer.sh` itself is anywhere.
                    installs: vec![
                        home.join(".config/NCALayer"),
                        home.join(".local/share/applications").join(DESKTOP_NAME),
                    ],
                }
            }
        }
    }

    /// A sandbox under `root`, the same on every system: the Startup folder `root/Startup`,
    /// the XDG autostart directory `root/.config/autostart`, and `root/NCALayer` as the
    /// installed original. No machine-wide `Run` value, unless
    /// [`OriginalLocations::with_machine_run`] adds one.
    pub fn sandbox(root: &Path) -> OriginalLocations {
        OriginalLocations {
            startup: Some(root.join("Startup")),
            autostart: Some(root.join(".config").join("autostart")),
            installs: vec![root.join("NCALayer")],
            #[cfg(windows)]
            machine_run: None,
        }
    }

    /// These locations with the machine-wide `Run` value read from under `base`
    /// (`HKCU\<test key>\Software\Microsoft\Windows\CurrentVersion\Run\NCALayer`) in place
    /// of `HKLM`.
    #[cfg(windows)]
    pub fn with_machine_run(mut self, base: &crate::RegistryBase) -> OriginalLocations {
        self.machine_run = Some(MachineRun::under(base));
        self
    }

    /// Whether a file of an installed original exists.
    fn installed(&self) -> bool {
        self.installs.iter().any(|p| p.exists())
    }

    /// The directory where an entry of `kind` may be: the Startup folder or the XDG
    /// autostart directory.
    fn dir_of(&self, kind: EntryKind) -> Option<&Path> {
        match kind {
            EntryKind::StartupShortcut => self.startup.as_deref(),
            EntryKind::DesktopEntry => self.autostart.as_deref(),
            EntryKind::MachineRun => None,
        }
    }

    /// The entries of this user that we can disable and that are enabled now: the
    /// shortcuts of the Startup folder, and the desktop entry unless it is hidden.
    fn enabled_entries(&self) -> io::Result<Vec<(EntryKind, PathBuf)>> {
        let mut entries = Vec::new();
        if let Some(startup) = &self.startup {
            for shortcut in startup_shortcuts(startup)? {
                entries.push((EntryKind::StartupShortcut, shortcut));
            }
        }
        if let Some(autostart) = &self.autostart {
            let path = autostart.join(DESKTOP_NAME);
            if let Some(text) = read_text(&path)?
                && !desktop_entry_disabled(&text)
            {
                entries.push((EntryKind::DesktopEntry, path));
            }
        }
        Ok(entries)
    }
}

/// The original's autostart entries ([`original_autostart`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginalAutostart {
    pub entries: Vec<AutostartEntry>,
}

/// The original's autostart entries at `locations`, with those [`disable_original`] moved
/// aside according to `journal` as disabled. What cannot be read is left out with a
/// warning.
pub fn original_autostart(locations: &OriginalLocations, journal: &Path) -> OriginalAutostart {
    let mut entries = Vec::new();
    let records = Journal::load(journal)
        .inspect_err(
            |e| tracing::warn!(error = %e, "the original's autostart journal is unreadable"),
        )
        .map(|j| j.records)
        .unwrap_or_default();
    if let Some(startup) = &locations.startup {
        match startup_shortcuts(startup) {
            Ok(shortcuts) => entries.extend(shortcuts.into_iter().map(|path| AutostartEntry {
                kind: EntryKind::StartupShortcut,
                path,
                enabled: true,
            })),
            Err(e) => tracing::warn!(error = %e, "the Startup folder is unreadable"),
        }
    }
    if let Some(autostart) = &locations.autostart {
        let path = autostart.join(DESKTOP_NAME);
        match read_text(&path) {
            Ok(Some(text)) => entries.push(AutostartEntry {
                kind: EntryKind::DesktopEntry,
                path,
                enabled: !desktop_entry_disabled(&text),
            }),
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "the original's desktop entry is unreadable"),
        }
    }
    // Moved aside (a shortcut) or hidden and then deleted (a desktop entry): disabled.
    for record in records {
        if !entries.iter().any(|e| e.path == record.path) && record.stored.exists() {
            entries.push(AutostartEntry {
                kind: record.kind,
                path: record.path,
                enabled: false,
            });
        }
    }
    #[cfg(windows)]
    if let Some(run) = &locations.machine_run {
        match run.entry() {
            Ok(entry) => entries.extend(entry),
            Err(e) => tracing::warn!(error = %e, "the machine-wide Run value is unreadable"),
        }
    }
    OriginalAutostart { entries }
}

/// Stops the original's autostart entries of this user at `locations` from starting it:
/// moves the Startup shortcuts into `original-autostart/` next to `journal` and hides the
/// desktop entry after a backup copy there. The machine-wide `Run` value is left as it is.
/// Idempotent: entries already disabled are not changed again, and a call after an
/// interrupted one finishes it.
///
/// # Errors
///
/// The journal cannot be read or written, an entry cannot be moved or written, or the
/// journal names an entry outside `locations`. What was changed before stays in the
/// journal.
pub fn disable_original(locations: &OriginalLocations, journal: &Path) -> io::Result<Report> {
    disable_with(locations, journal, &mut Disk)
}

/// Puts back what [`disable_original`] changed at `locations` according to `journal`, then
/// removes the journal. Idempotent: a call after an interrupted one finishes it.
///
/// # Errors
///
/// As [`disable_original`]; the entries not put back yet stay in the journal.
pub fn restore_original(locations: &OriginalLocations, journal: &Path) -> io::Result<Report> {
    restore_with(locations, journal, &mut Disk)
}

fn disable_with(
    locations: &OriginalLocations,
    journal: &Path,
    changes: &mut dyn Changes,
) -> io::Result<Report> {
    let mut log = Journal::load(journal)?;
    log.check(locations)?;
    // Written down before anything is changed.
    let store = log.store();
    let mut added = false;
    for (kind, path) in locations.enabled_entries()? {
        if !log.records.iter().any(|r| r.path == path) {
            let stored = log.free_name(&store, &path)?;
            log.records.push(Record { kind, path, stored });
            added = true;
        }
    }
    if added {
        log.save()?;
    }
    let mut report = Report::default();
    let mut kept = Vec::with_capacity(log.records.len());
    for record in &log.records {
        match disable_record(record, changes)? {
            Outcome::Changed => report.changed.push(record.path.clone()),
            Outcome::Unchanged => {}
            Outcome::Gone => continue,
        }
        kept.push(record.clone());
    }
    if kept.len() != log.records.len() {
        log.records = kept;
        log.save()?;
    }
    Ok(report)
}

fn restore_with(
    locations: &OriginalLocations,
    journal: &Path,
    changes: &mut dyn Changes,
) -> io::Result<Report> {
    let mut log = Journal::load(journal)?;
    log.check(locations)?;
    let mut report = Report::default();
    while let Some(record) = log.records.first().cloned() {
        if restore_record(&record, changes)? {
            report.changed.push(record.path);
        }
        log.records.remove(0);
        log.save()?;
    }
    // Left only if something else is there.
    let _ = fs::remove_dir(log.store());
    Ok(report)
}

/// What a step did to one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Changed,
    Unchanged,
    /// Neither the entry nor its copy exist: nothing is left to track.
    Gone,
}

/// Moves the shortcut of `record` aside, or hides its desktop entry after a backup copy.
fn disable_record(record: &Record, changes: &mut dyn Changes) -> io::Result<Outcome> {
    let Record { kind, path, stored } = record;
    match kind {
        EntryKind::StartupShortcut => match (path.try_exists()?, stored.try_exists()?) {
            (true, false) => changes.rename(path, stored).map(|()| Outcome::Changed),
            (true, true) => {
                if fs::read(path)? == fs::read(stored)? {
                    // A move by copying that stopped before removing the original.
                    changes.remove(path)?;
                } else {
                    // Installed again since: the new shortcut is the one to keep.
                    changes.rename(path, stored)?;
                }
                Ok(Outcome::Changed)
            }
            (false, true) => Ok(Outcome::Unchanged),
            (false, false) => Ok(Outcome::Gone),
        },
        EntryKind::DesktopEntry => match fs_read(path)? {
            Some(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                if desktop_entry_disabled(&text) {
                    return Ok(Outcome::Unchanged);
                }
                changes.write(stored, &bytes)?;
                changes.write(path, hidden(&text).as_bytes())?;
                Ok(Outcome::Changed)
            }
            None if stored.try_exists()? => Ok(Outcome::Unchanged),
            None => Ok(Outcome::Gone),
        },
        EntryKind::MachineRun => Err(machine_run_in_journal()),
    }
}

/// Puts the shortcut of `record` back, or its desktop entry from the backup copy (without
/// one, shown again); whether the entry changed.
fn restore_record(record: &Record, changes: &mut dyn Changes) -> io::Result<bool> {
    let Record { kind, path, stored } = record;
    match kind {
        EntryKind::StartupShortcut => match (path.try_exists()?, stored.try_exists()?) {
            (false, true) => changes.rename(stored, path).map(|()| true),
            (true, true) => {
                // Put back by a copy that stopped before removing it, or installed again.
                if fs::read(path)? != fs::read(stored)? {
                    tracing::warn!(path = %path.display(), "the original's shortcut is back already: its moved copy is dropped");
                }
                changes.remove(stored).map(|()| false)
            }
            (true, false) => Ok(false),
            (false, false) => {
                tracing::warn!(path = %path.display(), "the original's moved shortcut is gone: nothing to put back");
                Ok(false)
            }
        },
        EntryKind::DesktopEntry => {
            let current = fs_read(path)?;
            let shown = |bytes: &[u8]| !desktop_entry_disabled(&String::from_utf8_lossy(bytes));
            match fs_read(stored)? {
                Some(backup) => {
                    let changed = !current.as_deref().is_some_and(shown);
                    if changed {
                        changes.write(path, &backup)?;
                    }
                    changes.remove(stored).map(|()| changed)
                }
                None => match current {
                    Some(bytes) if !shown(&bytes) => {
                        let text = unhidden(&String::from_utf8_lossy(&bytes));
                        changes.write(path, text.as_bytes()).map(|()| true)
                    }
                    _ => Ok(false),
                },
            }
        }
        EntryKind::MachineRun => Err(machine_run_in_journal()),
    }
}

fn machine_run_in_journal() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the journal names the machine-wide Run value, which is never changed",
    )
}

/// The file changes of [`disable_original`] and [`restore_original`], for a test to fail
/// one of them.
trait Changes {
    /// Moves `from` to `to`, replacing it, creating its directory.
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
    /// Writes `bytes` to `path` atomically, creating its directory.
    fn write(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    /// Removes the file `path`; a missing one is removed already.
    fn remove(&mut self, path: &Path) -> io::Result<()>;
}

/// The changes made on disk.
struct Disk;

impl Changes for Disk {
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        if let Some(dir) = to.parent() {
            fs::create_dir_all(dir)?;
        }
        match fs::rename(from, to) {
            // The data directory on another volume: copy, then remove.
            Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
                write_file(to, &fs::read(from)?, Access::Default)?;
                self.remove(from)
            }
            result => result,
        }
    }

    fn write(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        write_file(path, bytes, Access::Default)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

/// One entry disabled by us: where it belongs and where its moved file or backup is.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    kind: EntryKind,
    path: PathBuf,
    stored: PathBuf,
}

/// `original-autostart.json`: `{"entries": [{"kind", "path", "stored"}, …]}`, the entries
/// disabled by us; no file when there are none.
#[derive(Debug)]
struct Journal {
    path: PathBuf,
    records: Vec<Record>,
}

impl Journal {
    fn load(path: &Path) -> io::Result<Journal> {
        let records = match fs_read(path)? {
            None => Vec::new(),
            Some(bytes) => parse_records(&bytes).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "not a journal of the original's autostart: {}",
                        path.display()
                    ),
                )
            })?,
        };
        Ok(Journal {
            path: path.to_owned(),
            records,
        })
    }

    /// Writes the records, or removes the file when there are none.
    fn save(&self) -> io::Result<()> {
        if self.records.is_empty() {
            return Disk.remove(&self.path);
        }
        let mut entries = Vec::with_capacity(self.records.len());
        for r in &self.records {
            entries.push(json!({
                "kind": kind_name(r.kind),
                "path": path_text(&r.path)?,
                "stored": path_text(&r.stored)?,
            }));
        }
        let mut object = Map::new();
        object.insert("entries".to_owned(), Value::Array(entries));
        let json = serde_json::to_vec_pretty(&object).map_err(io::Error::other)?;
        write_file(&self.path, &json, Access::Default)
    }

    /// `original-autostart/` next to the journal.
    fn store(&self) -> PathBuf {
        self.path.with_file_name(STORE_DIR)
    }

    /// Refuses records outside `locations` and the store: a changed journal cannot make
    /// us move other files.
    fn check(&self, locations: &OriginalLocations) -> io::Result<()> {
        let store = self.store();
        for r in &self.records {
            let inside = |file: &Path, dir: Option<&Path>| {
                dir.is_some_and(|d| file.parent() == Some(d) && file.file_name().is_some())
            };
            if !inside(&r.path, locations.dir_of(r.kind)) || !inside(&r.stored, Some(&store)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the journal {} names an entry outside the original's places: {}",
                        self.path.display(),
                        r.path.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// A file in `store` for the entry `path` that neither exists nor is any record's.
    fn free_name(&self, store: &Path, path: &Path) -> io::Result<PathBuf> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "an entry without a name");
        let stem = path.file_stem().ok_or_else(invalid)?.to_string_lossy();
        let extension = path.extension().map(|e| e.to_string_lossy());
        for n in 1u32.. {
            let name = match (n, &extension) {
                (1, Some(e)) => format!("{stem}.{e}"),
                (1, None) => stem.clone().into_owned(),
                (n, Some(e)) => format!("{stem} ({n}).{e}"),
                (n, None) => format!("{stem} ({n})"),
            };
            let candidate = store.join(name);
            if !candidate.try_exists()? && !self.records.iter().any(|r| r.stored == candidate) {
                return Ok(candidate);
            }
        }
        unreachable!("a free name is found before u32 runs out")
    }
}

fn parse_records(bytes: &[u8]) -> Option<Vec<Record>> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let entries = value.as_object()?.get("entries")?.as_array()?;
    entries
        .iter()
        .map(|e| {
            let text = |key: &str| e.get(key).and_then(Value::as_str);
            Some(Record {
                kind: kind_of(text("kind")?)?,
                path: PathBuf::from(text("path")?),
                stored: PathBuf::from(text("stored")?),
            })
        })
        .collect()
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::StartupShortcut => "startupShortcut",
        EntryKind::MachineRun => "machineRun",
        EntryKind::DesktopEntry => "desktopEntry",
    }
}

fn kind_of(name: &str) -> Option<EntryKind> {
    [
        EntryKind::StartupShortcut,
        EntryKind::MachineRun,
        EntryKind::DesktopEntry,
    ]
    .into_iter()
    .find(|&k| kind_name(k) == name)
}

fn path_text(path: &Path) -> io::Result<&str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the path is not Unicode: {}", path.display()),
        )
    })
}

/// The bytes of `path`, or `None` if it does not exist.
fn fs_read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_text(path: &Path) -> io::Result<Option<String>> {
    Ok(fs_read(path)?.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

/// The desktop entry `text` with `Hidden=true` in its `[Desktop Entry]` group, in place of
/// a `Hidden` key there.
fn hidden(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 12);
    let mut in_entry = false;
    let mut done = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_entry = trimmed == "[Desktop Entry]";
        } else if in_entry && key_of(trimmed) == Some("Hidden") {
            continue;
        }
        out.push_str(line);
        if in_entry && !done {
            if !line.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("Hidden=true\n");
            done = true;
        }
    }
    if !done {
        out.insert_str(0, "[Desktop Entry]\nHidden=true\n");
    }
    out
}

/// The desktop entry `text` without `Hidden=true` in its `[Desktop Entry]` group.
fn unhidden(text: &str) -> String {
    let mut in_entry = false;
    text.split_inclusive('\n')
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_entry = trimmed == "[Desktop Entry]";
                return true;
            }
            !(in_entry
                && key_of(trimmed) == Some("Hidden")
                && trimmed
                    .split_once('=')
                    .is_some_and(|(_, v)| v.trim() == "true"))
        })
        .collect()
}

fn key_of(line: &str) -> Option<&str> {
    line.split_once('=').map(|(k, _)| k.trim())
}

/// The original's shortcuts in the Startup folder `dir`: `NCALayer.lnk`, and any shortcut
/// to `NCALayer.exe`; sorted.
fn startup_shortcuts(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut shortcuts = Vec::new();
    for entry in read {
        let entry = entry?;
        let path = entry.path();
        let is_lnk = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
        if !is_lnk || !entry.file_type()?.is_file() {
            continue;
        }
        let by_name = path
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case(SHORTCUT_NAME));
        if by_name || (entry.metadata()?.len() <= MAX_SHORTCUT && points_to_original(&path)?) {
            shortcuts.push(path);
        }
    }
    shortcuts.sort();
    Ok(shortcuts)
}

/// Whether the shortcut `path` points to a file named `NCALayer.exe`.
fn points_to_original(path: &Path) -> io::Result<bool> {
    let bytes = fs::read(path)?;
    Ok(shortcut_targets(&bytes).iter().any(|target| {
        target
            .rsplit(['\\', '/'])
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(TARGET_NAME))
    }))
}

/// The target paths a Shell Link (`.lnk`, \[MS-SHLLINK\]) holds: the local path of its
/// LinkInfo (ANSI and Unicode) and its relative path. Empty if it is not a shortcut.
fn shortcut_targets(bytes: &[u8]) -> Vec<String> {
    /// `{00021401-0000-0000-C000-000000000046}` as stored.
    const CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    const HEADER: usize = 0x4C;
    const HAS_ID_LIST: u32 = 0x1;
    const HAS_LINK_INFO: u32 = 0x2;
    const HAS_NAME: u32 = 0x4;
    const HAS_RELATIVE_PATH: u32 = 0x8;
    const IS_UNICODE: u32 = 0x80;
    const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x1;

    let mut targets = Vec::new();
    if u32_at(bytes, 0) != Some(HEADER as u32) || bytes.get(4..20) != Some(&CLSID[..]) {
        return targets;
    }
    let Some(flags) = u32_at(bytes, 0x14) else {
        return targets;
    };
    let mut at = HEADER;
    if flags & HAS_ID_LIST != 0 {
        let Some(size) = u16_at(bytes, at) else {
            return targets;
        };
        at = at.saturating_add(2 + usize::from(size));
    }
    if flags & HAS_LINK_INFO != 0 {
        let Some(info) = bytes.get(at..) else {
            return targets;
        };
        let field = |offset: usize| u32_at(info, offset).map(|v| v as usize);
        let (Some(size), Some(header), Some(info_flags)) = (field(0), field(4), field(8)) else {
            return targets;
        };
        if info_flags & (VOLUME_ID_AND_LOCAL_BASE_PATH as usize) != 0 {
            let suffix = field(24).and_then(|o| ansi_at(info, o)).unwrap_or_default();
            if let Some(base) = field(16).and_then(|o| ansi_at(info, o)) {
                targets.push(base + &suffix);
            }
            if header >= 0x24 {
                let suffix = field(32)
                    .and_then(|o| utf16_at(info, o))
                    .unwrap_or_default();
                if let Some(base) = field(28).and_then(|o| utf16_at(info, o)) {
                    targets.push(base + &suffix);
                }
            }
        }
        at = at.saturating_add(size);
    }
    // StringData: the name first, then the relative path.
    let unicode = flags & IS_UNICODE != 0;
    let string = |at: &mut usize| -> Option<String> {
        let count = usize::from(u16_at(bytes, *at)?);
        let start = at.saturating_add(2);
        let len = if unicode { count * 2 } else { count };
        let raw = bytes.get(start..start.saturating_add(len))?;
        *at = start + len;
        Some(if unicode {
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            raw.iter().map(|&b| char::from(b)).collect()
        })
    };
    if flags & HAS_NAME != 0 && string(&mut at).is_none() {
        return targets;
    }
    if flags & HAS_RELATIVE_PATH != 0
        && let Some(relative) = string(&mut at)
    {
        targets.push(relative);
    }
    targets
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The NUL-terminated single-byte string at `at`, its bytes taken as Latin-1 (the name
/// compared is ASCII).
fn ansi_at(bytes: &[u8], at: usize) -> Option<String> {
    let rest = bytes.get(at..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some(rest[..end].iter().map(|&b| char::from(b)).collect())
}

/// The NUL-terminated UTF-16LE string at `at`.
fn utf16_at(bytes: &[u8], at: usize) -> Option<String> {
    let mut units = Vec::new();
    for &c in bytes.get(at..)?.as_chunks::<2>().0 {
        match u16::from_le_bytes(c) {
            0 => return Some(String::from_utf16_lossy(&units)),
            u => units.push(u),
        }
    }
    None
}

/// The user's Startup folder (`FOLDERID_Startup`).
#[cfg(windows)]
fn startup_folder() -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_Startup, SHGetKnownFolderPath};

    let mut path: *mut u16 = std::ptr::null_mut();
    // SAFETY: the GUID is a static; a null token is the current user; `path` receives a
    // string the shell allocated, freed below also on failure as the API requires.
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_Startup, 0, std::ptr::null_mut(), &mut path) };
    let result = if hr >= 0 && !path.is_null() {
        // SAFETY: on success `path` is a NUL-terminated UTF-16 string.
        let wide = unsafe {
            let len = (0..).take_while(|&i| *path.add(i) != 0).count();
            std::slice::from_raw_parts(path, len)
        };
        Ok(PathBuf::from(std::ffi::OsString::from_wide(wide)))
    } else {
        Err(io::Error::from_raw_os_error(hr))
    };
    // SAFETY: `path` is null or allocated by SHGetKnownFolderPath, and freed once.
    unsafe { CoTaskMemFree(path.cast()) };
    result
}

/// The machine-wide `Run` value `NCALayer` (the MSI's), or for tests one under a key of
/// `HKCU` standing for `HKLM`: only read.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct MachineRun {
    hive: oncl_registry::Hive,
    run_key: String,
    approved_key: String,
}

#[cfg(windows)]
impl MachineRun {
    const VALUE: &'static str = "NCALayer";

    fn local_machine() -> MachineRun {
        MachineRun {
            hive: oncl_registry::Hive::LocalMachine,
            run_key: crate::RegistryAutostart::RUN_KEY.to_owned(),
            approved_key: crate::RegistryAutostart::APPROVED_KEY.to_owned(),
        }
    }

    fn under(base: &crate::RegistryBase) -> MachineRun {
        MachineRun {
            hive: oncl_registry::Hive::CurrentUser,
            run_key: base.key(crate::RegistryAutostart::RUN_KEY),
            approved_key: base.key(crate::RegistryAutostart::APPROVED_KEY),
        }
    }

    /// The value as an entry, enabled unless Windows' switch for it in `StartupApproved`
    /// disables it.
    fn entry(&self) -> io::Result<Option<AutostartEntry>> {
        if oncl_registry::get_string(self.hive, &self.run_key, Some(Self::VALUE))?.is_none() {
            return Ok(None);
        }
        let disabled =
            crate::autostart::disabled_by_windows(self.hive, &self.approved_key, Self::VALUE)?;
        let hive = match self.hive {
            oncl_registry::Hive::LocalMachine => "HKLM",
            oncl_registry::Hive::CurrentUser => "HKCU",
        };
        Ok(Some(AutostartEntry {
            kind: EntryKind::MachineRun,
            path: PathBuf::from(format!(r"{hive}\{}\{}", self.run_key, Self::VALUE)),
            enabled: !disabled,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_finds_nothing_and_changes_nothing() {
        assert_eq!(Unavailable.status(), OriginalStatus::default());
        for result in [Unavailable.disable(), Unavailable.restore()] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
    }

    /// A Shell Link to `target` the way the shell writes one for a local file: a LinkInfo
    /// with the local path (ANSI, and Unicode if `unicode`), and the relative path.
    fn shortcut(target: &str, unicode: bool) -> Vec<u8> {
        let mut info_header = Vec::new();
        let header_size: u32 = if unicode { 0x24 } else { 0x1C };
        let volume = {
            let mut v = Vec::new();
            v.extend(0x11u32.to_le_bytes()); // VolumeIDSize
            v.extend(3u32.to_le_bytes()); // DRIVE_FIXED
            v.extend(0u32.to_le_bytes()); // serial
            v.extend(0x10u32.to_le_bytes()); // label offset
            v.push(0); // empty label
            v
        };
        let ansi: Vec<u8> = target
            .bytes()
            .map(|b| if b.is_ascii() { b } else { b'?' })
            .chain([0])
            .collect();
        let wide: Vec<u8> = target
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let volume_at = header_size;
        let base_at = volume_at + volume.len() as u32;
        let suffix_at = base_at + ansi.len() as u32;
        let base_w_at = suffix_at + 1;
        let suffix_w_at = base_w_at + wide.len() as u32;
        let mut body = volume.clone();
        body.extend(&ansi);
        body.push(0); // empty common path suffix
        if unicode {
            body.extend(&wide);
            body.extend([0, 0]);
        }
        let size = header_size + body.len() as u32;
        for v in [size, header_size, 1, volume_at, base_at, 0, suffix_at] {
            info_header.extend(v.to_le_bytes());
        }
        if unicode {
            info_header.extend(base_w_at.to_le_bytes());
            info_header.extend(suffix_w_at.to_le_bytes());
        }
        let mut lnk = Vec::new();
        lnk.extend(0x4Cu32.to_le_bytes());
        lnk.extend([
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        // HasLinkTargetIDList | HasLinkInfo | HasRelativePath | IsUnicode
        lnk.extend((0x1u32 | 0x2 | 0x8 | 0x80).to_le_bytes());
        lnk.resize(0x4C, 0);
        // An ID list of one empty item list (only its terminator).
        lnk.extend(2u16.to_le_bytes());
        lnk.extend([0, 0]);
        lnk.extend(info_header);
        lnk.extend(body);
        let relative: Vec<u16> = format!("..\\{target}").encode_utf16().collect();
        lnk.extend((relative.len() as u16).to_le_bytes());
        lnk.extend(relative.into_iter().flat_map(u16::to_le_bytes));
        lnk.extend(0u32.to_le_bytes()); // TerminalBlock
        lnk
    }

    #[test]
    fn shortcut_targets_are_read() {
        let target = r"C:\Program Files\NCALayer\NCALayer.exe";
        assert_eq!(
            shortcut_targets(&shortcut(target, false)),
            [target.to_owned(), format!("..\\{target}")]
        );
        let target = r"C:\Users\Әлия\AppData\Roaming\NCALayer\NCALayer.exe";
        let targets = shortcut_targets(&shortcut(target, true));
        assert_eq!(targets[1], target);
        // Not a shortcut, or cut short: nothing, without a panic.
        assert!(shortcut_targets(b"[Desktop Entry]\n").is_empty());
        let whole = shortcut(target, true);
        for len in 0..whole.len() {
            let _ = shortcut_targets(&whole[..len]);
        }
    }

    /// The real shell's shortcut to a file of the sandbox.
    #[cfg(windows)]
    #[test]
    fn shell_shortcut_target_is_read() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("NCALayer").join(TARGET_NAME);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"MZ").unwrap();
        // WScript.Shell saves under ANSI names only: the localized name is in `sandbox`.
        let lnk = d.path().join("Startup item.lnk");
        let script = format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{}'; $s.Save()",
            lnk.display(),
            target.display()
        );
        let status = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .unwrap();
        assert!(status.success());
        assert!(
            points_to_original(&lnk).unwrap(),
            "{:?}",
            shortcut_targets(&fs::read(&lnk).unwrap())
        );
    }

    const DESKTOP: &str = "[Desktop Entry]\nType=Application\nName=NCALayer\nExec=\"/opt/NCALayer/ncalayer.sh\" --run\n";

    /// A sandbox with the original's shortcut, a localized one, a shortcut of another
    /// program and the desktop entry.
    fn sandbox() -> (tempfile::TempDir, OriginalLocations, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let startup = d.path().join("Startup");
        fs::create_dir_all(&startup).unwrap();
        let original = shortcut(r"C:\Program Files\NCALayer\NCALayer.exe", true);
        fs::write(startup.join(SHORTCUT_NAME), &original).unwrap();
        fs::write(
            startup.join("НЦАЛэйер.lnk"),
            shortcut(r"C:\Program Files\NCALayer\ncalayer.EXE", false),
        )
        .unwrap();
        fs::write(
            startup.join("Other.lnk"),
            shortcut(r"C:\Open\openncalayer.exe", true),
        )
        .unwrap();
        fs::write(startup.join("NCALayer.txt"), b"not a shortcut").unwrap();
        let autostart = d.path().join(".config/autostart");
        fs::create_dir_all(&autostart).unwrap();
        fs::write(autostart.join(DESKTOP_NAME), DESKTOP).unwrap();
        let journal = d.path().join("data").join("original-autostart.json");
        let locations = OriginalLocations::sandbox(d.path());
        (d, locations, journal)
    }

    fn states(l: &OriginalLocations, journal: &Path) -> Vec<(EntryKind, String, bool)> {
        original_autostart(l, journal)
            .entries
            .into_iter()
            .map(|e| {
                (
                    e.kind,
                    e.path.file_name().unwrap().to_string_lossy().into_owned(),
                    e.enabled,
                )
            })
            .collect()
    }

    #[test]
    fn disable_and_restore_in_a_sandbox() {
        let (d, l, journal) = sandbox();
        let startup = d.path().join("Startup");
        let desktop = d.path().join(".config/autostart").join(DESKTOP_NAME);
        let before: Vec<_> = ["NCALayer.lnk", "НЦАЛэйер.lnk"]
            .map(|n| fs::read(startup.join(n)).unwrap())
            .into();
        let all_on = vec![
            (EntryKind::StartupShortcut, "NCALayer.lnk".to_owned(), true),
            (EntryKind::StartupShortcut, "НЦАЛэйер.lnk".to_owned(), true),
            (EntryKind::DesktopEntry, DESKTOP_NAME.to_owned(), true),
        ];
        assert_eq!(states(&l, &journal), all_on);

        let report = disable_original(&l, &journal).unwrap();
        assert_eq!(
            report.changed,
            [
                startup.join("NCALayer.lnk"),
                startup.join("НЦАЛэйер.lnk"),
                desktop.clone()
            ]
        );
        assert!(!startup.join("NCALayer.lnk").exists());
        assert!(
            startup.join("Other.lnk").exists(),
            "another program's shortcut stays"
        );
        let store = journal.with_file_name(STORE_DIR);
        assert_eq!(fs::read(store.join("NCALayer.lnk")).unwrap(), before[0]);
        assert_eq!(
            fs::read_to_string(store.join(DESKTOP_NAME)).unwrap(),
            DESKTOP
        );
        let hidden_text = fs::read_to_string(&desktop).unwrap();
        assert!(
            hidden_text.starts_with("[Desktop Entry]\nHidden=true\nType=Application\n"),
            "{hidden_text}"
        );
        let all_off: Vec<_> = all_on
            .iter()
            .map(|(k, n, _)| (*k, n.clone(), false))
            .collect();
        let mut off = states(&l, &journal);
        off.sort_by_key(|e| e.0 == EntryKind::DesktopEntry);
        assert_eq!(off, all_off);
        let text = fs::read_to_string(&journal).unwrap();
        assert!(text.contains("\"kind\": \"startupShortcut\""), "{text}");

        // Again: nothing more to do.
        assert_eq!(disable_original(&l, &journal).unwrap(), Report::default());

        let report = restore_original(&l, &journal).unwrap();
        assert_eq!(report.changed.len(), 3);
        assert_eq!(states(&l, &journal), all_on);
        assert_eq!(fs::read(startup.join("НЦАЛэйер.lnk")).unwrap(), before[1]);
        assert_eq!(fs::read_to_string(&desktop).unwrap(), DESKTOP);
        assert!(!journal.exists() && !store.exists());
        assert_eq!(restore_original(&l, &journal).unwrap(), Report::default());
    }

    #[test]
    fn found_by_its_files_or_entries() {
        let d = tempfile::tempdir().unwrap();
        let journal = d.path().join("original-autostart.json");
        let original =
            OriginalNcaLayer::new(OriginalLocations::sandbox(d.path()), journal.clone(), 0);
        assert!(!original.status().found);
        fs::create_dir_all(d.path().join("NCALayer")).unwrap();
        assert!(original.status().found);
        assert!(original.status().autostart.is_empty());
    }

    /// Disk changes failing at the `fail_at`-th (from 1).
    struct FailingAt {
        n: usize,
        fail_at: usize,
    }

    impl FailingAt {
        fn step(&mut self) -> io::Result<()> {
            self.n += 1;
            if self.n == self.fail_at {
                Err(io::Error::other("simulated failure"))
            } else {
                Ok(())
            }
        }
    }

    impl Changes for FailingAt {
        fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
            self.step()?;
            Disk.rename(from, to)
        }
        fn write(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
            self.step()?;
            Disk.write(path, bytes)
        }
        fn remove(&mut self, path: &Path) -> io::Result<()> {
            self.step()?;
            Disk.remove(path)
        }
    }

    #[test]
    fn interrupted_disable_is_finished_by_disable_or_undone_by_restore() {
        for then_restore in [false, true] {
            let (d, l, journal) = sandbox();
            let startup = d.path().join("Startup");
            let shortcuts: Vec<_> = ["NCALayer.lnk", "НЦАЛэйер.lnk"]
                .map(|n| (startup.join(n), fs::read(startup.join(n)).unwrap()))
                .into();
            // The second move fails.
            let err = disable_with(&l, &journal, &mut FailingAt { n: 0, fail_at: 2 }).unwrap_err();
            assert_eq!(err.to_string(), "simulated failure");
            assert!(!shortcuts[0].0.exists());
            assert!(shortcuts[1].0.exists());
            assert_eq!(
                Journal::load(&journal).unwrap().records.len(),
                3,
                "all written down first"
            );

            if then_restore {
                let report = restore_original(&l, &journal).unwrap();
                assert_eq!(report.changed, [shortcuts[0].0.clone()]);
            } else {
                let report = disable_original(&l, &journal).unwrap();
                assert_eq!(report.changed.len(), 2, "{report:?}");
                assert!(!shortcuts[1].0.exists());
                restore_original(&l, &journal).unwrap();
            }
            for (path, bytes) in &shortcuts {
                assert_eq!(&fs::read(path).unwrap(), bytes, "nothing is lost");
            }
            let desktop = d.path().join(".config/autostart").join(DESKTOP_NAME);
            assert_eq!(fs::read_to_string(desktop).unwrap(), DESKTOP);
            assert!(!journal.exists());
        }
    }

    #[test]
    fn interrupted_restore_is_finished_by_restore() {
        let (d, l, journal) = sandbox();
        let startup = d.path().join("Startup");
        disable_original(&l, &journal).unwrap();
        let err = restore_with(&l, &journal, &mut FailingAt { n: 0, fail_at: 2 }).unwrap_err();
        assert_eq!(err.to_string(), "simulated failure");
        assert!(startup.join("NCALayer.lnk").exists());
        assert!(!startup.join("НЦАЛэйер.lnk").exists());
        assert_eq!(Journal::load(&journal).unwrap().records.len(), 2);
        // The UI's view meanwhile: the one put back is on, the other still off.
        let s = states(&l, &journal);
        assert!(s.contains(&(EntryKind::StartupShortcut, "NCALayer.lnk".to_owned(), true)));
        assert!(s.contains(&(EntryKind::StartupShortcut, "НЦАЛэйер.lnk".to_owned(), false)));

        let report = restore_original(&l, &journal).unwrap();
        assert_eq!(report.changed.len(), 2);
        assert!(startup.join("НЦАЛэйер.lnk").exists());
        assert!(!journal.exists());
    }

    #[test]
    fn a_move_by_copy_cut_short_is_finished() {
        let (d, l, journal) = sandbox();
        let startup = d.path().join("Startup");
        disable_original(&l, &journal).unwrap();
        // As if the copy back was made but the moved file not removed yet.
        let store = journal.with_file_name(STORE_DIR);
        fs::copy(store.join("NCALayer.lnk"), startup.join("NCALayer.lnk")).unwrap();
        let report = disable_original(&l, &journal).unwrap();
        assert_eq!(report.changed, [startup.join("NCALayer.lnk")]);
        assert!(!startup.join("NCALayer.lnk").exists());
        assert!(store.join("NCALayer.lnk").exists());
    }

    #[test]
    fn desktop_entry_restored_without_its_backup_is_shown() {
        let (d, l, journal) = sandbox();
        disable_original(&l, &journal).unwrap();
        fs::remove_file(journal.with_file_name(STORE_DIR).join(DESKTOP_NAME)).unwrap();
        restore_original(&l, &journal).unwrap();
        let desktop = d.path().join(".config/autostart").join(DESKTOP_NAME);
        assert_eq!(fs::read_to_string(desktop).unwrap(), DESKTOP);
    }

    #[test]
    fn hidden_by_the_user_is_left_alone() {
        let (d, l, journal) = sandbox();
        let desktop = d.path().join(".config/autostart").join(DESKTOP_NAME);
        let text = "[Desktop Entry]\nX-GNOME-Autostart-enabled=false\n";
        fs::write(&desktop, text).unwrap();
        let report = disable_original(&l, &journal).unwrap();
        assert!(!report.changed.contains(&desktop));
        restore_original(&l, &journal).unwrap();
        assert_eq!(fs::read_to_string(&desktop).unwrap(), text);
    }

    #[test]
    fn hiding_replaces_a_hidden_key_of_the_entry_group() {
        assert_eq!(
            hidden("[Desktop Entry]\r\nHidden=false\r\nName=x"),
            "[Desktop Entry]\r\nHidden=true\nName=x"
        );
        assert_eq!(
            hidden("[X]\nHidden=false\n[Desktop Entry]"),
            "[X]\nHidden=false\n[Desktop Entry]\nHidden=true\n"
        );
        assert_eq!(hidden("Name=x\n"), "[Desktop Entry]\nHidden=true\nName=x\n");
        assert_eq!(
            unhidden("[Desktop Entry]\nHidden = true\nName=x\n[X]\nHidden=true\n"),
            "[Desktop Entry]\nName=x\n[X]\nHidden=true\n"
        );
    }

    #[test]
    fn journal_outside_the_locations_is_refused() {
        let (d, l, journal) = sandbox();
        let elsewhere = d.path().join("elsewhere.lnk");
        fs::write(&elsewhere, b"x").unwrap();
        let text = json!({"entries": [{
            "kind": "startupShortcut",
            "path": d.path().join("Startup/NCALayer.lnk").to_str().unwrap(),
            "stored": elsewhere.to_str().unwrap(),
        }]});
        fs::create_dir_all(journal.parent().unwrap()).unwrap();
        fs::write(&journal, text.to_string()).unwrap();
        for result in [
            disable_original(&l, &journal),
            restore_original(&l, &journal),
        ] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        assert!(elsewhere.exists());
        fs::write(&journal, "[]").unwrap();
        assert_eq!(
            disable_original(&l, &journal).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn stored_names_do_not_collide() {
        let (d, l, journal) = sandbox();
        let store = journal.with_file_name(STORE_DIR);
        fs::create_dir_all(&store).unwrap();
        // Left behind by an earlier journal that was lost.
        fs::write(store.join("NCALayer.lnk"), b"older").unwrap();
        disable_original(&l, &journal).unwrap();
        assert_eq!(fs::read(store.join("NCALayer.lnk")).unwrap(), b"older");
        assert!(store.join("NCALayer (2).lnk").exists());
        restore_original(&l, &journal).unwrap();
        assert!(d.path().join("Startup/NCALayer.lnk").exists());
        assert_eq!(fs::read(store.join("NCALayer.lnk")).unwrap(), b"older");
    }

    /// `HKLM\…\Run\NCALayer` is shown and never changed: here a test key of `HKCU` stands
    /// for `HKLM`.
    #[cfg(windows)]
    #[test]
    fn machine_run_is_only_read() {
        use oncl_registry::{Hive, TestKey, get_string, set_binary, set_string};

        let root = TestKey::new();
        let base = crate::RegistryBase::sandbox(root.path());
        let d = tempfile::tempdir().unwrap();
        let journal = d.path().join("original-autostart.json");
        let l = OriginalLocations::sandbox(d.path()).with_machine_run(&base);
        assert!(original_autostart(&l, &journal).entries.is_empty());

        let run_key = base.key(crate::RegistryAutostart::RUN_KEY);
        let value = r#""C:\Program Files\NCALayer\NCALayer.exe""#;
        set_string(&run_key, Some("NCALayer"), value).unwrap();
        let entries = original_autostart(&l, &journal).entries;
        assert_eq!(
            entries,
            [AutostartEntry {
                kind: EntryKind::MachineRun,
                path: PathBuf::from(format!(r"HKCU\{run_key}\NCALayer")),
                enabled: true,
            }]
        );
        assert_eq!(disable_original(&l, &journal).unwrap(), Report::default());
        assert_eq!(restore_original(&l, &journal).unwrap(), Report::default());
        assert_eq!(
            get_string(Hive::CurrentUser, &run_key, Some("NCALayer"))
                .unwrap()
                .as_deref(),
            Some(value)
        );
        assert!(!journal.exists());

        // Disabled in Task Manager.
        let approved_key = base.key(crate::RegistryAutostart::APPROVED_KEY);
        set_binary(&approved_key, Some("NCALayer"), &[3, 0, 0, 0]).unwrap();
        assert!(!original_autostart(&l, &journal).entries[0].enabled);

        let real = MachineRun::local_machine();
        assert_eq!(real.hive, Hive::LocalMachine);
        assert_eq!(
            real.run_key,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
    }
}
