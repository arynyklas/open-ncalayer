//! The original NCALayer next to ours: whether it is installed, its autostart entries and
//! who holds the port, as the settings window shows them ([`OriginalControl`],
//! [`OriginalNcaLayer`]).
//!
//! Its autostart entries ([`original_autostart`]):
//! - Windows: the shortcut `NCALayer.lnk` in the user's Startup folder, and any other
//!   shortcut there to `NCALayer.exe` (a localized name); the value `NCALayer` of
//!   `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (the MSI) in the 64-bit and the
//!   32-bit registry view, for every user and only read here;
//! - Linux: `ncalayer.desktop` in the XDG autostart directory;
//! - macOS: none, the original has no autostart.
//!
//! [`disable_original`] moves the shortcuts into `original-autostart/` next to the journal
//! and hides the desktop entry (`Hidden=true`) after a backup copy there; [`restore_original`]
//! puts them back. Both are driven by the journal `original-autostart.json`: an entry is
//! written there before it is changed and removed only after it is put back, so an
//! interrupted call loses nothing and a repeated one finishes the job.

use std::ffi::OsStr;
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

/// Whether an autostart entry starts the original, and who turned it off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    /// It starts the original at login.
    Enabled,
    /// Turned off outside OpenNCALayer (the desktop's own settings, Task Manager): neither
    /// disabling nor restoring changes it.
    DisabledByUser,
    /// Moved aside or hidden by [`disable_original`], as its journal records:
    /// [`restore_original`] puts it back.
    DisabledByUs,
}

/// One autostart entry of the original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutostartEntry {
    pub kind: EntryKind,
    /// The file, or the registry value as `HKLM\…\Run\NCALayer`.
    pub path: PathBuf,
    pub state: EntryState,
}

impl AutostartEntry {
    /// Whether it starts the original at login.
    pub fn enabled(&self) -> bool {
        self.state == EntryState::Enabled
    }
}

/// The original NCALayer as found on this system.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginalStatus {
    /// Whether the original is installed.
    pub found: bool,
    /// Its autostart entries: enabled, or disabled by the user or by us.
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

/// The original's autostart entries at `locations`. An entry that does not start the
/// original is [`EntryState::DisabledByUs`] if `journal` records it (moved aside or
/// hidden by [`disable_original`]), [`EntryState::DisabledByUser`] otherwise. What cannot
/// be read is left out with a warning.
pub fn original_autostart(locations: &OriginalLocations, journal: &Path) -> OriginalAutostart {
    let mut entries = Vec::new();
    let records = Journal::load(journal)
        .inspect_err(
            |e| tracing::warn!(error = %e, "the original's autostart journal is unreadable"),
        )
        .map(|j| j.records)
        .unwrap_or_default();
    let off = |path: &Path| {
        if records.iter().any(|r| same_file(&r.path, path)) {
            EntryState::DisabledByUs
        } else {
            EntryState::DisabledByUser
        }
    };
    if let Some(startup) = &locations.startup {
        match startup_shortcuts(startup) {
            Ok(shortcuts) => entries.extend(shortcuts.into_iter().map(|path| AutostartEntry {
                kind: EntryKind::StartupShortcut,
                path,
                state: EntryState::Enabled,
            })),
            Err(e) => tracing::warn!(error = %e, "the Startup folder is unreadable"),
        }
    }
    if let Some(autostart) = &locations.autostart {
        let path = autostart.join(DESKTOP_NAME);
        match read_text(&path) {
            Ok(Some(text)) => entries.push(AutostartEntry {
                kind: EntryKind::DesktopEntry,
                state: if desktop_entry_disabled(&text) {
                    off(&path)
                } else {
                    EntryState::Enabled
                },
                path,
            }),
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "the original's desktop entry is unreadable"),
        }
    }
    // Moved aside (a shortcut) or hidden and then deleted (a desktop entry).
    for record in &records {
        if !entries.iter().any(|e| same_file(&e.path, &record.path)) && record.stored.exists() {
            entries.push(AutostartEntry {
                kind: record.kind,
                path: record.path.clone(),
                state: EntryState::DisabledByUs,
            });
        }
    }
    #[cfg(windows)]
    if let Some(run) = &locations.machine_run {
        match run.entries() {
            Ok(found) => entries.extend(found),
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
        if !log.records.iter().any(|r| same_file(&r.path, &path)) {
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

    /// Refuses a journal that names anything but the original's entries in `locations`
    /// and copies we could have made of them, one copy each, so that a changed journal
    /// cannot make us move or hide another file, nor two entries share one copy:
    /// - a shortcut record names a `.lnk` directly in the Startup folder, and each of its
    ///   two files that exists is the original's shortcut (named `NCALayer.lnk`, or
    ///   pointing to `NCALayer.exe`, as the Startup scan finds them); a desktop entry
    ///   record names `ncalayer.desktop` directly in the autostart directory; no record
    ///   names the machine-wide `Run` value;
    /// - its copy is directly in the store, under a name [`Journal::free_name`] gives the
    ///   entry: its own, or numbered (`NCALayer (2).lnk`);
    /// - no two records name one entry or one copy, compared without case on Windows,
    ///   whose file names ignore it.
    ///
    /// The error names every copy, so the user can put them back by hand (when a location
    /// changed since, e.g. a redirected Startup folder).
    fn check(&self, locations: &OriginalLocations) -> io::Result<()> {
        let store = self.store();
        let in_dir = |file: &Path, dir: Option<&Path>| {
            dir.is_some_and(|d| file.parent() == Some(d) && file.file_name().is_some())
        };
        for (i, r) in self.records.iter().enumerate() {
            let named = match r.kind {
                EntryKind::StartupShortcut => r
                    .path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("lnk")),
                EntryKind::DesktopEntry => r.path.file_name().is_some_and(|n| n == DESKTOP_NAME),
                EntryKind::MachineRun => false,
            };
            let earlier = &self.records[..i];
            let why = if !named || !in_dir(&r.path, locations.dir_of(r.kind)) {
                "an entry that is not one of the original's here"
            } else if !in_dir(&r.stored, Some(&store)) || !copy_name_of(&r.stored, &r.path) {
                "a copy that is not ours"
            } else if earlier
                .iter()
                .any(|e| same_file(&e.stored, &r.stored) || same_file(&e.path, &r.path))
            {
                "an entry or a copy twice"
            } else if r.kind == EntryKind::StartupShortcut && !original_shortcut(r) {
                "a shortcut that is not the original's"
            } else {
                continue;
            };
            let copies: Vec<String> = self
                .records
                .iter()
                .map(|r| format!("{} → {}", r.stored.display(), r.path.display()))
                .collect();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the journal {} names {why} ({}); nothing was changed. Its copies, to put \
                     back by hand: {}",
                    self.path.display(),
                    r.path.display(),
                    copies.join("; ")
                ),
            ));
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
            if !candidate.try_exists()?
                && !self
                    .records
                    .iter()
                    .any(|r| same_file(&r.stored, &candidate))
            {
                return Ok(candidate);
            }
        }
        unreachable!("a free name is found before u32 runs out")
    }
}

/// A file name as the file system compares it: without case on Windows.
fn folded(name: &OsStr) -> String {
    let name = name.to_string_lossy();
    if cfg!(windows) {
        name.to_lowercase()
    } else {
        name.into_owned()
    }
}

/// Whether `a` and `b` name one file (their texts; without case on Windows).
fn same_file(a: &Path, b: &Path) -> bool {
    folded(a.as_os_str()) == folded(b.as_os_str())
}

/// Whether `copy`'s name is one [`Journal::free_name`] gives the entry `path`: the entry's
/// own, or with ` (n)` (n ≥ 2) after its stem.
fn copy_name_of(copy: &Path, path: &Path) -> bool {
    let (Some(name), Some(stem)) = (copy.file_name(), path.file_stem()) else {
        return false;
    };
    let (name, stem) = (folded(name), folded(stem));
    let extension = path
        .extension()
        .map(|e| format!(".{}", folded(e)))
        .unwrap_or_default();
    let Some(number) = name
        .strip_prefix(&stem)
        .and_then(|rest| rest.strip_suffix(&extension))
    else {
        return false;
    };
    number.is_empty()
        || number
            .strip_prefix(" (")
            .and_then(|n| n.strip_suffix(')'))
            .filter(|n| !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| n >= 2)
}

/// Whether the files of the shortcut record `r` that exist, the entry and its copy, are the
/// original's shortcut: the entry is named `NCALayer.lnk`, or the file points to
/// `NCALayer.exe`. One that cannot be read is not.
fn original_shortcut(r: &Record) -> bool {
    let by_name = r
        .path
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case(SHORTCUT_NAME));
    [&r.path, &r.stored]
        .into_iter()
        .all(|file| match fs::metadata(file) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Ok(meta) if meta.is_file() => {
                by_name
                    || crate::lnk::points_to(file, TARGET_NAME, MAX_SHORTCUT)
                        .inspect_err(|e| tracing::warn!(error = %e, file = %file.display(), "a journalled shortcut is unreadable"))
                        .unwrap_or(false)
            }
            Ok(_) => false,
            Err(e) => {
                tracing::warn!(error = %e, file = %file.display(), "a journalled shortcut is unreadable");
                false
            }
        })
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
/// to `NCALayer.exe`; sorted. A shortcut that cannot be read is left out with a warning,
/// unless its name tells already.
fn startup_shortcuts(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut shortcuts = Vec::new();
    for entry in read {
        let path = entry?.path();
        let is_lnk = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
        if !is_lnk {
            continue;
        }
        let by_name = path
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case(SHORTCUT_NAME));
        let unreadable = |e: &io::Error| {
            tracing::warn!(error = %e, path = %path.display(), "a Startup shortcut is unreadable");
        };
        let matches = match fs::metadata(&path) {
            Ok(meta) if !meta.is_file() => false,
            Ok(_) if by_name => true,
            Ok(_) => crate::lnk::points_to(&path, TARGET_NAME, MAX_SHORTCUT)
                .inspect_err(unreadable)
                .unwrap_or(false),
            Err(e) => {
                unreadable(&e);
                by_name
            }
        };
        if matches {
            shortcuts.push(path);
        }
    }
    shortcuts.sort();
    Ok(shortcuts)
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

/// The machine-wide `Run` values `NCALayer` (the MSI's) of both registry views, or for
/// tests ones under a key of `HKCU` standing for `HKLM`: only read.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct MachineRun {
    hive: oncl_registry::Hive,
    sources: Vec<RunSource>,
}

/// Where one `Run` value and Windows' switch for it are.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RunSource {
    run_key: String,
    view: oncl_registry::View,
    /// In the native view: `StartupApproved\Run32` holds the switches of the 32-bit view.
    approved_key: String,
    /// The value as the user reads it, e.g. `HKLM\Software\WOW6432Node\…\Run\NCALayer`.
    shown: String,
}

#[cfg(windows)]
impl MachineRun {
    const VALUE: &'static str = "NCALayer";
    /// The 32-bit view's `Run` key as a 64-bit process names it.
    const RUN_KEY_32: &'static str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    /// Windows' switches of the 32-bit view's `Run` values.
    const APPROVED_KEY_32: &'static str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";

    /// `HKLM`, in the 64-bit view and, for a 32-bit MSI, in the 32-bit one. The switches
    /// are read in this process's view, the 64-bit one (OpenNCALayer is built for x64).
    fn local_machine() -> MachineRun {
        use crate::RegistryAutostart as R;
        let shown = |key: &str| format!(r"HKLM\{key}\{}", Self::VALUE);
        MachineRun {
            hive: oncl_registry::Hive::LocalMachine,
            sources: vec![
                RunSource {
                    run_key: R::RUN_KEY.to_owned(),
                    view: oncl_registry::View::Native,
                    approved_key: R::APPROVED_KEY.to_owned(),
                    shown: shown(R::RUN_KEY),
                },
                RunSource {
                    run_key: R::RUN_KEY.to_owned(),
                    view: oncl_registry::View::Wow32,
                    approved_key: Self::APPROVED_KEY_32.to_owned(),
                    shown: shown(Self::RUN_KEY_32),
                },
            ],
        }
    }

    /// The same keys under `base` of `HKCU`, where no view is redirected: the 32-bit
    /// view's `Run` key is named by its path.
    fn under(base: &crate::RegistryBase) -> MachineRun {
        use crate::RegistryAutostart as R;
        let source = |run: &str, approved: &str| RunSource {
            run_key: base.key(run),
            view: oncl_registry::View::Native,
            approved_key: base.key(approved),
            shown: format!(r"HKCU\{}\{}", base.key(run), Self::VALUE),
        };
        MachineRun {
            hive: oncl_registry::Hive::CurrentUser,
            sources: vec![
                source(R::RUN_KEY, R::APPROVED_KEY),
                source(Self::RUN_KEY_32, Self::APPROVED_KEY_32),
            ],
        }
    }

    /// The values that exist (of any string type), enabled unless Windows' switch for
    /// them in `StartupApproved` disables them.
    fn entries(&self) -> io::Result<Vec<AutostartEntry>> {
        let mut entries = Vec::new();
        for s in &self.sources {
            if !oncl_registry::value_exists(self.hive, &s.run_key, Some(Self::VALUE), s.view)? {
                continue;
            }
            let disabled =
                crate::autostart::disabled_by_windows(self.hive, &s.approved_key, Self::VALUE)?;
            entries.push(AutostartEntry {
                kind: EntryKind::MachineRun,
                path: PathBuf::from(&s.shown),
                state: if disabled {
                    EntryState::DisabledByUser
                } else {
                    EntryState::Enabled
                },
            });
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lnk::tests::shortcut;

    #[test]
    fn unavailable_finds_nothing_and_changes_nothing() {
        assert_eq!(Unavailable.status(), OriginalStatus::default());
        for result in [Unavailable.disable(), Unavailable.restore()] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        }
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

    fn states(l: &OriginalLocations, journal: &Path) -> Vec<(EntryKind, String, EntryState)> {
        original_autostart(l, journal)
            .entries
            .into_iter()
            .map(|e| {
                (
                    e.kind,
                    e.path.file_name().unwrap().to_string_lossy().into_owned(),
                    e.state,
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
        use EntryState::{DisabledByUs, Enabled};
        let all_on = vec![
            (
                EntryKind::StartupShortcut,
                "NCALayer.lnk".to_owned(),
                Enabled,
            ),
            (
                EntryKind::StartupShortcut,
                "НЦАЛэйер.lnk".to_owned(),
                Enabled,
            ),
            (EntryKind::DesktopEntry, DESKTOP_NAME.to_owned(), Enabled),
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
            .map(|(k, n, _)| (*k, n.clone(), DisabledByUs))
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
        let (on, ours) = (EntryState::Enabled, EntryState::DisabledByUs);
        assert!(s.contains(&(EntryKind::StartupShortcut, "NCALayer.lnk".to_owned(), on)));
        assert!(s.contains(&(EntryKind::StartupShortcut, "НЦАЛэйер.lnk".to_owned(), ours)));

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

    /// Turned off by the user: not changed, and not shown as something to put back.
    #[test]
    fn hidden_by_the_user_is_left_alone() {
        for text in [
            "[Desktop Entry]\nX-GNOME-Autostart-enabled=false\n",
            "[Desktop Entry]\nHidden=true\n",
        ] {
            let (d, l, journal) = sandbox();
            let desktop = d.path().join(".config/autostart").join(DESKTOP_NAME);
            fs::write(&desktop, text).unwrap();
            let user_off = (
                EntryKind::DesktopEntry,
                DESKTOP_NAME.to_owned(),
                EntryState::DisabledByUser,
            );
            assert!(states(&l, &journal).contains(&user_off));
            let report = disable_original(&l, &journal).unwrap();
            assert!(!report.changed.contains(&desktop));
            // Still the user's after our disabling (the shortcuts are ours now).
            assert!(states(&l, &journal).contains(&user_off));
            restore_original(&l, &journal).unwrap();
            assert_eq!(fs::read_to_string(&desktop).unwrap(), text);
            assert!(states(&l, &journal).contains(&user_off));
            assert!(
                !states(&l, &journal)
                    .iter()
                    .any(|s| s.2 == EntryState::DisabledByUs)
            );
        }
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

    /// Records the original's disabling never writes: another file of the Startup or
    /// autostart directory, our own entry, another program's shortcut (in Startup or as the
    /// copy), a copy not named after its entry, one entry twice (without case on Windows).
    #[test]
    fn journal_naming_other_files_is_refused() {
        let (d, l, journal) = sandbox();
        let startup = d.path().join("Startup");
        let autostart = d.path().join(".config/autostart");
        let store = journal.with_file_name(STORE_DIR);
        let ours = autostart.join("openncalayer.desktop");
        fs::write(&ours, "[Desktop Entry]\n").unwrap();
        fs::create_dir_all(&store).unwrap();
        fs::write(
            store.join("Moved.lnk"),
            shortcut(r"C:\Other\other.exe", true),
        )
        .unwrap();
        let record = |kind: &str, path: &Path, stored: &str| {
            json!({
                "kind": kind,
                "path": path.to_str().unwrap(),
                "stored": store.join(stored).to_str().unwrap(),
            })
        };
        let shortcut_record =
            |name: &str, stored: &str| record("startupShortcut", &startup.join(name), stored);
        let not_here = "an entry that is not one of the original's here";
        let not_ours = "a copy that is not ours";
        let twice = "an entry or a copy twice";
        let foreign = "a shortcut that is not the original's";
        let mut journals = vec![
            (
                vec![record("desktopEntry", &ours, "openncalayer.desktop")],
                not_here,
            ),
            (
                vec![shortcut_record("NCALayer.txt", "NCALayer.txt")],
                not_here,
            ),
            (
                vec![record("startupShortcut", &autostart.join("a.lnk"), "a.lnk")],
                not_here,
            ),
            (
                vec![record(
                    "machineRun",
                    &startup.join("NCALayer.lnk"),
                    "NCALayer.lnk",
                )],
                not_here,
            ),
            (vec![shortcut_record("NCALayer.lnk", "same.lnk")], not_ours),
            (
                vec![shortcut_record("NCALayer.lnk", "NCALayer (1).lnk")],
                not_ours,
            ),
            (
                vec![shortcut_record("NCALayer.lnk", "NCALayer (02).lnk")],
                not_ours,
            ),
            (
                vec![
                    shortcut_record("NCALayer.lnk", "NCALayer.lnk"),
                    shortcut_record("NCALayer.lnk", "NCALayer (2).lnk"),
                ],
                twice,
            ),
            (vec![shortcut_record("Other.lnk", "Other.lnk")], foreign),
            (vec![shortcut_record("Moved.lnk", "Moved.lnk")], foreign),
        ];
        if cfg!(windows) {
            // Names that differ only in case are one file there.
            journals.push((
                vec![
                    shortcut_record("NCALayer.lnk", "NCALayer.lnk"),
                    shortcut_record("ncalayer.LNK", "ncalayer (2).LNK"),
                ],
                twice,
            ));
        }
        for (entries, why) in journals {
            let text = json!({ "entries": entries }).to_string();
            fs::write(&journal, &text).unwrap();
            for result in [
                disable_original(&l, &journal),
                restore_original(&l, &journal),
            ] {
                let e = result.unwrap_err();
                assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{text}");
                assert!(e.to_string().contains(why), "{e}");
                // The copies are named for the user.
                assert!(e.to_string().contains(&*store.to_string_lossy()), "{e}");
            }
        }
        assert_eq!(fs::read_to_string(&ours).unwrap(), "[Desktop Entry]\n");
        for name in ["NCALayer.lnk", "НЦАЛэйер.lnk", "Other.lnk"] {
            assert!(startup.join(name).exists(), "{name}");
        }
        assert!(store.join("Moved.lnk").exists());
    }

    #[test]
    fn copies_are_named_after_their_entry() {
        let entry = Path::new("Startup").join("NCALayer.lnk");
        let store = Path::new("original-autostart");
        for ours in ["NCALayer.lnk", "NCALayer (2).lnk", "NCALayer (17).lnk"] {
            assert!(copy_name_of(&store.join(ours), &entry), "{ours}");
        }
        for other in [
            "Other.lnk",
            "NCALayer.txt",
            "NCALayer (1).lnk",
            "NCALayer (02).lnk",
            "NCALayer (x).lnk",
            "NCALayer (+2).lnk",
            "NCALayer(2).lnk",
            "NCALayer.lnk.lnk",
        ] {
            assert!(!copy_name_of(&store.join(other), &entry), "{other}");
        }
        assert_eq!(
            copy_name_of(&store.join("ncalayer (3).LNK"), &entry),
            cfg!(windows)
        );
        assert!(copy_name_of(
            &store.join("ncalayer.desktop"),
            Path::new("ncalayer.desktop")
        ));
    }

    /// A shortcut that cannot be read does not hide the others.
    #[test]
    fn unreadable_shortcut_is_skipped() {
        let (d, l, journal) = sandbox();
        let startup = d.path().join("Startup");
        let locked = startup.join("Locked.lnk");
        fs::write(&locked, shortcut(r"C:\NCALayer\NCALayer.exe", true)).unwrap();
        // Held open without sharing (Windows), or without read permission (Unix).
        #[cfg(windows)]
        let _hold = {
            use std::os::windows::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&locked)
                .unwrap()
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        }
        if fs::read(&locked).is_ok() {
            eprintln!("skipped: {} is readable here (root?)", locked.display());
            return;
        }
        let names: Vec<_> = states(&l, &journal).into_iter().map(|s| s.1).collect();
        assert!(names.contains(&"NCALayer.lnk".to_owned()), "{names:?}");
        assert!(!names.contains(&"Locked.lnk".to_owned()), "{names:?}");
        let report = disable_original(&l, &journal).unwrap();
        assert!(report.changed.contains(&startup.join("NCALayer.lnk")));
        assert!(locked.exists());
        restore_original(&l, &journal).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();
        }
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

    /// `HKLM\…\Run\NCALayer` of both views is shown and never changed: here a test key of
    /// `HKCU` stands for `HKLM`.
    #[cfg(windows)]
    #[test]
    fn machine_run_is_only_read() {
        use oncl_registry::{Hive, TestKey, View, get_string, set_binary, set_string};

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
                state: EntryState::Enabled,
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

        // Disabled in Task Manager: by the user.
        let approved_key = base.key(crate::RegistryAutostart::APPROVED_KEY);
        set_binary(&approved_key, Some("NCALayer"), &[3, 0, 0, 0]).unwrap();
        assert_eq!(
            original_autostart(&l, &journal).entries[0].state,
            EntryState::DisabledByUser
        );

        // A 32-bit MSI's value, in the 32-bit view (here named by its path).
        let run_32 = base.key(MachineRun::RUN_KEY_32);
        set_string(&run_32, Some("NCALayer"), value).unwrap();
        let entries = original_autostart(&l, &journal).entries;
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(
            entries[1].path,
            PathBuf::from(format!(r"HKCU\{run_32}\NCALayer"))
        );
        assert!(entries[1].enabled());
        set_binary(
            &base.key(MachineRun::APPROVED_KEY_32),
            Some("NCALayer"),
            &[3],
        )
        .unwrap();
        assert!(!original_autostart(&l, &journal).entries[1].enabled());

        let real = MachineRun::local_machine();
        assert_eq!(real.hive, Hive::LocalMachine);
        let views: Vec<_> = real
            .sources
            .iter()
            .map(|s| (s.run_key.as_str(), s.view, s.shown.as_str()))
            .collect();
        assert_eq!(
            views,
            [
                (
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    View::Native,
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\NCALayer"
                ),
                (
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    View::Wow32,
                    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\NCALayer"
                ),
            ]
        );
    }
}
