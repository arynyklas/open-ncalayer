//! The self-update of the core.
//!
//! An [`Updater`] looks at the signed index of the channel in the settings
//! ([`INDEX_BASE`]`/<channel>.json`) a few minutes after the start and then every 6 to 24
//! hours: [`oncl_update::fetch()`], [`oncl_update::verify()`] with the keys built in,
//! [`oncl_update::choose()`]. A version it chooses is downloaded and checked against the index
//! by an [`Installer`] (Velopack in an installed copy: [`installer::VelopackInstaller`]), and
//! applied once no page's request is being answered and no window is open ([`Host::busy`]),
//! new requests held back ([`Host::hold`]): the process then exits, and Velopack starts the
//! new version.
//!
//! Before the update is applied, `pending_health = {from, to}` goes into the updater's
//! state. The new version records the start of each run ([`Updater::startup`]) and clears
//! it once its servers and its windows' event loop have run for a while
//! ([`Updater::watch_health`]); a run that ends cleanly first is not held against it
//! ([`Updater::ended_cleanly`]). A version that has not proved healthy within
//! [`HEALTH_GRACE`] while it runs, or whose runs crashed or hung
//! [`CRASHES_TO_ROLL_BACK`] times in a row, is marked bad, never offered again, and the
//! previous version is installed back from its full package in the index: while it runs,
//! or at its next start before its servers and windows ([`Updater::roll_back_now`]). If the
//! index has no such package, the version stays marked bad and the checks go on.
//!
//! An index that cannot be downloaded is tried again quietly within hours; one that fails
//! its checks (another key, a broken signature, an older `seq`, too old) is logged, shown
//! in the settings window, and tried again at the next check: no notification is sent for
//! either. Every change of the state file is a read-modify-write under one lock.

pub mod installer;

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use oncl_desktop::UpdateSettings;
use oncl_pki::http::HttpTransport;
use oncl_ui::settings_view::{UpdateStatus, Updates};
use oncl_update::{
    Choice, Flavor, PendingHealth, PublicKey, State, Target, UpdateError, Version, choose, fetch,
    verify,
};
use time::OffsetDateTime;
use tracing::{error, info, warn};

use crate::load_settings;

/// Where the update indexes are published: the `updates/v1` directory of the project's
/// GitHub Pages.
pub const INDEX_BASE: &str = "https://arynyklas.github.io/open-ncalayer/updates/v1";

/// With feature `e2e-prompter` (test builds, never releases): another `https://` base of the
/// update indexes.
#[cfg(feature = "e2e-prompter")]
pub const INDEX_BASE_VAR: &str = "ONCL_UPDATE_INDEX_BASE";

/// The first check, this long after the start (a random time in the range).
pub const FIRST_CHECK: (Duration, Duration) = (minutes(2), minutes(10));
/// The checks after it, this far apart.
pub const CHECK_EVERY: (Duration, Duration) = (hours(6), hours(24));
/// A check that could not download the index is tried again this soon.
pub const RETRY_AFTER: (Duration, Duration) = (minutes(30), hours(2));
/// The longest the index and its signature may take to download, together.
pub const INDEX_TIMEOUT: Duration = Duration::from_secs(20);
/// The longest a package download may take.
pub const DOWNLOAD_TIMEOUT: Duration = minutes(30);
/// The longest a rollback at the start (the index and the package) may hold up the
/// daemon's start; then the daemon starts, and its updater's thread tries again with
/// [`DOWNLOAD_TIMEOUT`].
pub const STARTUP_BUDGET: Duration = Duration::from_secs(15);
/// A new version proves healthy within this long of its start.
pub const HEALTH_GRACE: Duration = Duration::from_secs(60);
/// A new version is healthy once its servers and its windows' event loop have run this
/// long.
pub const HEALTH_SETTLE: Duration = Duration::from_secs(5);
/// An update is applied only once no request ran for this long.
pub const QUIET: Duration = Duration::from_secs(30);
/// A new version is rolled back after this many runs in a row that crashed or hung before
/// it proved healthy.
pub const CRASHES_TO_ROLL_BACK: u32 = 2;
/// A rollback is handed to the installer at most this many times; then the failed version
/// stays.
pub const ROLLBACK_ATTEMPTS: u32 = 3;
/// A waiting update looks whether the daemon is idle this often.
pub const IDLE_POLL: Duration = Duration::from_secs(15);
/// The longest sleep of the schedule: the wall clock is compared at least this often, so
/// a computer's sleep does not delay a check by the length of the sleep.
const WAKE_EVERY: Duration = hours(1);

const fn minutes(n: u64) -> Duration {
    Duration::from_secs(n * 60)
}

const fn hours(n: u64) -> Duration {
    Duration::from_secs(n * 3600)
}

/// The base of the update indexes: [`INDEX_BASE`]; in test builds `ONCL_UPDATE_INDEX_BASE`
/// (`INDEX_BASE_VAR`) if set.
pub fn index_base() -> String {
    #[cfg(feature = "e2e-prompter")]
    if let Some(base) = std::env::var(INDEX_BASE_VAR).ok().filter(|b| !b.is_empty()) {
        return base;
    }
    INDEX_BASE.to_owned()
}

/// What installs versions: Velopack in an installed copy, a fake in the tests.
pub trait Installer: Send + Sync {
    /// The version running.
    fn current(&self) -> Version;

    /// Downloads `target` (its delta from the running version, or its full package) into
    /// the installer's store, each package download within `timeout`; every file is
    /// checked against the index (a full package rebuilt from a delta by its contents).
    /// `downgrade`: `target` is older than the running version.
    ///
    /// # Errors
    ///
    /// What failed, for the log and the settings window.
    fn download(&self, target: &Target, downgrade: bool, timeout: Duration) -> Result<(), String>;

    /// Hands the downloaded `target` to the installer, which installs it once this process
    /// has exited and then starts it with this process's arguments. The caller exits next.
    ///
    /// # Errors
    ///
    /// What failed; nothing is installed then.
    fn apply_on_exit(&self, target: &Target) -> Result<(), ApplyError>;
}

/// Why [`Installer::apply_on_exit`] did not hand an update over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// The downloaded package is gone (another start of the program cleans the installer's
    /// store of old packages): it can be downloaded again.
    PackageMissing(String),
    /// The installer refused it.
    Failed(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::PackageMissing(e) | ApplyError::Failed(e) => f.write_str(e),
        }
    }
}

/// The daemon, as the updater sees it.
pub trait Host: Send + Sync {
    /// Whether a page's request is being answered (or ended within [`QUIET`]) or a window
    /// is open: no update is applied then.
    fn busy(&self) -> bool;

    /// Holds back new requests of pages and returns whether the daemon is still idle: no
    /// request is being answered, none ended within [`QUIET`] and no window is open, all
    /// looked at once requests are held. If it is not idle, the requests are let through
    /// again. An update is applied only while they are held.
    fn hold(&self) -> bool;

    /// Lets held requests through again: the update was not applied.
    fn release(&self);

    /// Tells the user `notice` (a tray notification).
    fn notify(&self, notice: Notice);

    /// Ends the process, so that the installer can replace it.
    fn exit(&self);
}

/// What the updater tells the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The outcome of a check: a version found by a scheduled check (once per version), or
    /// whatever «Проверить обновления» in the tray found.
    Checked(UpdateStatus),
    /// This version started after an update to it and proved healthy.
    Updated(Version),
    /// `failed` did not prove healthy: `version` is back.
    RolledBack { failed: Version, version: Version },
    /// `failed` did not prove healthy, and the index has no package of `version`, the one
    /// before it: it stays, and is not offered again.
    NoRollback { failed: Version, version: Version },
    /// `failed` did not prove healthy, and `version`, the one before it, could not be
    /// installed back: it stays, and is not offered again.
    RollbackFailed { failed: Version, version: Version },
}

/// The outcome of [`Updater::install`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Installed {
    /// The installer applies it once the process exits.
    Applied,
    /// Not downloaded, not offered any more, or not recorded.
    NotApplied,
    /// The installer refused to apply it.
    ApplyFailed,
}

/// What [`Updater::startup`] found of the last update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Startup {
    /// No update waits for this version's health.
    Normal,
    /// This version was just installed: [`Updater::watch_health`] confirms its health, or
    /// finds it failed.
    Confirm,
    /// `failed`, this version, did not prove healthy (or a rollback from it did not install):
    /// `to` is to be installed back ([`Updater::roll_back_now`]).
    RollBack { failed: Version, to: Version },
}

/// The outcome of a rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollBack {
    /// The version before is being installed: the process is to exit.
    Applied,
    /// Not this time: the index could not be read, the package not downloaded or the
    /// rollback not recorded in the state file. It can be tried again.
    Retry,
    /// Nothing more is tried: the index has no package to go back to, or the installer
    /// refused it. The failed version stays (marked bad). A rollback handed over
    /// [`ROLLBACK_ATTEMPTS`] times without taking is not this: [`Updater::startup`] then
    /// keeps the failed version and returns [`Startup::Normal`].
    GaveUp,
}

/// Where the updater works.
#[derive(Clone, Debug)]
pub struct UpdaterConfig {
    /// The data directory: `update/state.json` is there.
    pub data_dir: PathBuf,
    /// `settings.json`: its `updates` are read at every check.
    pub settings: PathBuf,
    /// The base of the indexes ([`index_base`]).
    pub base: String,
    /// The keys the index must be signed with ([`oncl_update::embedded_keys`]).
    pub keys: Vec<PublicKey>,
    /// This build's flavor.
    pub flavor: Flavor,
    /// How often a waiting update looks whether the daemon is idle ([`IDLE_POLL`]).
    pub idle_poll: Duration,
    /// [`HEALTH_GRACE`].
    pub health_grace: Duration,
    /// [`HEALTH_SETTLE`].
    pub health_settle: Duration,
}

/// A version to install.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Plan {
    target: Target,
    /// `target` is older than the running version.
    downgrade: bool,
    /// Back to the version before a failed update: installed even with updates off.
    rollback: bool,
}

/// The outcome of [`Updater::check`].
struct Checked {
    status: UpdateStatus,
    /// The version to install, if updates are on.
    plan: Option<Plan>,
    /// The index could not be downloaded: try again within [`RETRY_AFTER`].
    retry_soon: bool,
}

/// Work handed to the updater's thread.
#[derive(Default)]
struct Queue {
    /// A version «Проверить сейчас» found.
    plan: Option<Plan>,
    /// A rollback the health check asks for: `(failed, to)`.
    rollback: Option<(Version, Version)>,
}

/// What the updater's thread does next.
enum Job {
    Plan(Plan),
    RollBack(Version, Version),
    Due,
}

/// The self-update; see the [module](self).
pub struct Updater {
    config: UpdaterConfig,
    transport: Arc<dyn HttpTransport>,
    installer: Box<dyn Installer>,
    host: Box<dyn Host>,
    status: Mutex<UpdateStatus>,
    /// One check at a time.
    checking: Mutex<()>,
    /// Every read-modify-write of the state file.
    state_lock: Mutex<()>,
    /// The version last told available, so a scheduled check tells it once.
    told: Mutex<Option<Version>>,
    queue: Mutex<Queue>,
    wake: Condvar,
    /// Notices from before the windows' event loop; [`Updater::tell_deferred`] tells them
    /// once it runs, or at once when the daemon has no event loop.
    deferred: Mutex<Vec<Notice>>,
}

impl Updater {
    pub fn new(
        config: UpdaterConfig,
        transport: Arc<dyn HttpTransport>,
        installer: Box<dyn Installer>,
        host: Box<dyn Host>,
    ) -> Updater {
        Updater {
            config,
            transport,
            installer,
            host,
            status: Mutex::new(UpdateStatus::NotChecked),
            checking: Mutex::new(()),
            state_lock: Mutex::new(()),
            told: Mutex::new(None),
            queue: Mutex::new(Queue::default()),
            wake: Condvar::new(),
            deferred: Mutex::new(Vec::new()),
        }
    }

    /// What the updater found last.
    pub fn status(&self) -> UpdateStatus {
        lock(&self.status).clone()
    }

    /// Looks at `pending_health` at the start of this version; see [`Startup`]. A version
    /// just installed records the start of its run. A run that ended neither cleanly
    /// ([`Updater::ended_cleanly`]) nor confirmed healthy crashed or hung; after
    /// [`CRASHES_TO_ROLL_BACK`] such runs in a row, or once the version is marked bad, it is
    /// rolled back. If the version before it failed here too, nothing is rolled back. If the
    /// state cannot be read or saved, nothing is done this run ([`Startup::Normal`]): the
    /// state stays as it is on disk for the next start.
    pub fn startup(&self) -> Startup {
        let current = self.installer.current();
        let now = OffsetDateTime::now_utc();
        let mut notice = None;
        let startup = self.update_state(|state| {
            let Some(pending) = state.pending_health.clone() else {
                return Startup::Normal;
            };
            if pending.rollback && current == pending.from {
                state.bad.insert(current.clone());
                if pending.attempts >= ROLLBACK_ATTEMPTS {
                    error!(failed = %current, to = %pending.to, attempts = pending.attempts, "the rollback did not install; keeping this version");
                    state.pending_health = None;
                    notice = Some(Notice::RollbackFailed {
                        failed: current.clone(),
                        version: pending.to,
                    });
                    return Startup::Normal;
                }
                warn!(failed = %current, to = %pending.to, attempts = pending.attempts, "the rollback did not install; trying again");
                return Startup::RollBack {
                    failed: current.clone(),
                    to: pending.to,
                };
            }
            if current != pending.to {
                warn!(from = %pending.from, to = %pending.to, %current, "an applied update did not install; forgetting it");
                state.pending_health = None;
                return Startup::Normal;
            }
            let crashes = pending.crashes + u32::from(pending.started.is_some());
            if state.bad.contains(&current) || crashes >= CRASHES_TO_ROLL_BACK {
                error!(version = %current, crashes, "this version did not prove healthy");
                return match mark_failed(state, &pending) {
                    Some(to) => Startup::RollBack {
                        failed: current.clone(),
                        to,
                    },
                    None => Startup::Normal,
                };
            }
            if crashes > pending.crashes {
                warn!(version = %current, crashes, "the last run of this version crashed or hung before it proved healthy");
            }
            if let Some(p) = &mut state.pending_health {
                p.started = Some(now);
                p.crashes = crashes;
            }
            Startup::Confirm
        });
        let Some(startup) = startup else {
            return Startup::Normal;
        };
        lock(&self.deferred).extend(notice);
        startup
    }

    /// The run ends cleanly (asked to stop, or P1's exit for TLS not set up or a busy
    /// port): a new version not yet confirmed healthy has neither crashed nor hung, and its
    /// count of crashed runs starts again.
    pub fn ended_cleanly(&self) {
        let current = self.installer.current();
        self.update_state(|state| {
            if let Some(p) = &mut state.pending_health
                && p.to == current
                && !state.bad.contains(&current)
            {
                p.started = None;
                p.crashes = 0;
            }
        });
    }

    /// The new version's health check, on a thread of its own: once `healthy` (its
    /// servers and its windows' event loop run) has held for [`HEALTH_SETTLE`], its
    /// `pending_health` goes and the user is told it was updated (or rolled back to); if
    /// that does not happen within [`HEALTH_GRACE`], the version is marked bad and the
    /// updater's thread installs the version before it.
    pub fn watch_health(self: &Arc<Self>, healthy: impl Fn() -> bool + Send + 'static) {
        let updater = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("update-health".into())
            .spawn(move || {
                let grace = updater.config.health_grace;
                let settle = updater.config.health_settle;
                let poll = (settle / 10).max(Duration::from_millis(1));
                let start = Instant::now();
                let mut since: Option<Instant> = None;
                loop {
                    let now = Instant::now();
                    if healthy() {
                        if now.duration_since(*since.get_or_insert(now)) >= settle {
                            updater.confirm_health();
                            return;
                        }
                    } else {
                        since = None;
                    }
                    if now.duration_since(start) >= grace {
                        updater.health_failed();
                        return;
                    }
                    thread::sleep(poll);
                }
            });
        if let Err(e) = spawned {
            error!(error = %e, "cannot start the health check");
        }
    }

    /// The running version proved healthy: its `pending_health` goes, and the user is told
    /// it was updated (or rolled back to).
    pub fn confirm_health(&self) {
        let current = self.installer.current();
        let confirmed = self
            .update_state(|state| match &state.pending_health {
                Some(p) if p.to == current => state.pending_health.take(),
                _ => None,
            })
            .flatten();
        let Some(pending) = confirmed else {
            return;
        };
        info!(from = %pending.from, to = %pending.to, "the update is healthy");
        self.host.notify(if pending.rollback {
            Notice::RolledBack {
                failed: pending.from,
                version: pending.to,
            }
        } else {
            Notice::Updated(pending.to)
        });
    }

    /// The running version did not prove healthy in time: it is marked bad, and the
    /// updater's thread is to install the version before it.
    fn health_failed(&self) {
        let current = self.installer.current();
        let to = self
            .update_state(|state| {
                let pending = state.pending_health.clone().filter(|p| p.to == current)?;
                error!(version = %current, "this version did not prove healthy in time");
                mark_failed(state, &pending)
            })
            .flatten();
        if let Some(to) = to {
            lock(&self.queue).rollback = Some((current, to));
            self.wake.notify_all();
        }
    }

    /// At the start, before the servers and windows: installs `to` back over the failed
    /// version, from its full package in the index, without waiting for anything and
    /// within [`STARTUP_BUDGET`]. With [`RollBack::Applied`] the caller exits; with
    /// [`RollBack::Retry`] it starts normally and hands the rollback to [`Updater::spawn`].
    pub fn roll_back_now(&self, failed: &Version, to: &Version) -> RollBack {
        self.roll_back(failed, to, false, STARTUP_BUDGET)
    }

    /// «Проверить сейчас»: checks with `settings` (the form's) or, without, the saved ones,
    /// even with updates off, and returns what it found; a version to install goes to the
    /// updater's thread, which installs it only if the saved settings still offer it.
    pub fn check_now(&self, settings: Option<UpdateSettings>) -> UpdateStatus {
        let checked = self.check(true, settings);
        if let Some(plan) = checked.plan {
            lock(&self.queue).plan = Some(plan);
            self.wake.notify_all();
        }
        checked.status
    }

    /// Starts the updater's thread: the `rollback` still to do, then the checks.
    pub fn spawn(self: Arc<Self>, rollback: Option<(Version, Version)>) {
        let spawned = thread::Builder::new()
            .name("updates".into())
            .spawn(move || self.run(rollback));
        if let Err(e) = spawned {
            error!(error = %e, "cannot start the updater");
        }
    }

    /// Tells the notices of the start (a rollback given up before the tray was there); call
    /// it once the windows' event loop runs.
    pub fn tell_deferred(&self) {
        for notice in std::mem::take(&mut *lock(&self.deferred)) {
            self.host.notify(notice);
        }
    }

    fn run(&self, mut rollback: Option<(Version, Version)>) {
        // Rollbacks that could not be done (index, download) in this process.
        let mut retries = 0;
        let mut due = if rollback.is_some() {
            SystemTime::now()
        } else {
            SystemTime::now() + jitter(FIRST_CHECK)
        };
        loop {
            let applied = match self.next(due) {
                Job::Plan(plan) => {
                    self.install(&plan, true, DOWNLOAD_TIMEOUT) == Installed::Applied
                }
                Job::RollBack(failed, to) => {
                    rollback = Some((failed, to));
                    due = SystemTime::now();
                    false
                }
                Job::Due => {
                    let (applied, wait) = match rollback.take() {
                        Some((failed, to)) => match self.roll_back(
                            &failed,
                            &to,
                            true,
                            INDEX_TIMEOUT + DOWNLOAD_TIMEOUT,
                        ) {
                            RollBack::Applied => (true, None),
                            RollBack::Retry if retries + 1 >= ROLLBACK_ATTEMPTS => {
                                self.give_up(&failed, &to, true, false);
                                (false, None)
                            }
                            RollBack::Retry => {
                                retries += 1;
                                rollback = Some((failed, to));
                                (false, Some(RETRY_AFTER))
                            }
                            // The checks go on at once: a newer version may fix it.
                            RollBack::GaveUp => (false, None),
                        },
                        None => {
                            let checked = self.check(false, None);
                            let applied = checked.plan.is_some_and(|plan| {
                                self.install(&plan, true, DOWNLOAD_TIMEOUT) == Installed::Applied
                            });
                            let wait = if checked.retry_soon {
                                RETRY_AFTER
                            } else {
                                CHECK_EVERY
                            };
                            (applied, Some(wait))
                        }
                    };
                    due = SystemTime::now() + wait.map_or(Duration::ZERO, jitter);
                    applied
                }
            };
            if applied {
                self.host.exit();
                return;
            }
        }
    }

    /// Waits until `due` by the wall clock, or work handed over.
    fn next(&self, due: SystemTime) -> Job {
        let mut queue = lock(&self.queue);
        loop {
            if let Some((failed, to)) = queue.rollback.take() {
                return Job::RollBack(failed, to);
            }
            if let Some(plan) = queue.plan.take() {
                return Job::Plan(plan);
            }
            let left = due
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO);
            if left.is_zero() {
                return Job::Due;
            }
            queue = self
                .wake
                .wait_timeout(queue, left.min(WAKE_EVERY))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// One check: the index of the channel in `settings` (the saved ones without), verified,
    /// and the version it offers this installation. A scheduled one (`manual` false) does
    /// nothing with updates off; it tells a version found once. A version is to be installed
    /// only if the saved settings enable updates and are the ones checked with.
    fn check(&self, manual: bool, settings: Option<UpdateSettings>) -> Checked {
        let _one = lock(&self.checking);
        let saved = self.settings();
        let settings = settings.unwrap_or(saved);
        let installs = settings.enabled && settings == saved;
        if !manual && !settings.enabled {
            return Checked {
                status: self.status(),
                plan: None,
                retry_soon: false,
            };
        }
        let channel = settings.channel;
        let index = match self.verified_index(channel, INDEX_TIMEOUT) {
            Ok(index) => index,
            Err((UpdateError::NotPublished(channel), _)) => {
                return self.checked(UpdateStatus::NotPublished(channel), None);
            }
            Err((e, retry_soon)) => return self.failed(&e, retry_soon),
        };
        let current = self.installer.current();
        let (install_id, bad) = match self.try_update_state(|s| (s.install_id, s.bad.clone())) {
            Ok(found) => found,
            Err(e) => {
                warn!(error = %e, "cannot read the updater's state");
                return self.failed(&UpdateError::Io(e), true);
            }
        };
        let (target, downgrade) =
            match choose(&index, &current, self.config.flavor, install_id, &bad) {
                Choice::UpToDate => {
                    info!(%current, %channel, seq = index.seq, "no update");
                    return self.checked(UpdateStatus::UpToDate, None);
                }
                Choice::Update(target) => (target, false),
                Choice::Downgrade(target) => (target, true),
            };
        info!(%current, version = %target.version, downgrade, installs, "an update is offered");
        let status = UpdateStatus::Available {
            version: target.version.to_string(),
            installing: installs,
        };
        let new = lock(&self.told).replace(target.version.clone()) != Some(target.version.clone());
        if new && !manual {
            self.host.notify(Notice::Checked(status.clone()));
        }
        let plan = installs.then_some(Plan {
            target,
            downgrade,
            rollback: false,
        });
        self.checked(status, plan)
    }

    /// The index of `channel`, downloaded within `timeout` and verified; its `seq` is
    /// saved, and an index whose `seq` cannot be saved is not used. The error says whether
    /// to try again soon (the index could not be downloaded, or the state not read or
    /// saved); [`UpdateError::NotPublished`] is not tried again soon.
    fn verified_index(
        &self,
        channel: oncl_update::Channel,
        timeout: Duration,
    ) -> Result<oncl_update::Index, (UpdateError, bool)> {
        let fetched = fetch(&*self.transport, &self.config.base, channel, timeout).map_err(|e| {
            if let UpdateError::NotPublished(_) = e {
                info!(%channel, "the channel has no update index yet");
                (e, false)
            } else {
                info!(error = %e, %channel, "cannot download the update index; trying again later");
                (e, true)
            }
        })?;
        let state_error = |e: std::io::Error| {
            warn!(error = %e, "cannot read or save the updater's state");
            (UpdateError::Io(e), true)
        };
        let last_seq = self
            .try_update_state(|s| s.last_seq.get(&channel).copied())
            .map_err(state_error)?;
        let index = verify(
            &fetched.index,
            &fetched.signature,
            &self.config.keys,
            channel,
            last_seq,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| {
            warn!(error = %e, %channel, "the update index is refused");
            (e, false)
        })?;
        // Only ever raised: the state is read again under the lock.
        self.try_update_state(|s| {
            let seq = s.last_seq.entry(channel).or_insert(index.seq);
            *seq = (*seq).max(index.seq);
        })
        .map_err(state_error)?;
        Ok(index)
    }

    fn checked(&self, status: UpdateStatus, plan: Option<Plan>) -> Checked {
        *lock(&self.status) = status.clone();
        Checked {
            status,
            plan,
            retry_soon: false,
        }
    }

    fn failed(&self, e: &UpdateError, retry_soon: bool) -> Checked {
        let status = UpdateStatus::Failed(e.to_string());
        *lock(&self.status) = status.clone();
        Checked {
            status,
            plan: None,
            retry_soon,
        }
    }

    /// Installs `to` back over `failed`, the index and the package within `budget`. Without
    /// `wait` (at the start) nothing is waited for, and a notice waits for the updater's
    /// thread.
    fn roll_back(&self, failed: &Version, to: &Version, wait: bool, budget: Duration) -> RollBack {
        let start = Instant::now();
        let package = {
            let _one = lock(&self.checking);
            let channel = self.settings().channel;
            match self.verified_index(channel, budget.min(INDEX_TIMEOUT)) {
                Ok(index) => index
                    .release(to)
                    .and_then(|release| release.package(self.config.flavor))
                    .map(|package| package.full.clone()),
                Err((e, _)) => {
                    warn!(error = %e, "cannot read the update index to roll back; trying again later");
                    return RollBack::Retry;
                }
            }
        };
        let Some(full) = package else {
            error!(%failed, version = %to, flavor = %self.config.flavor, "the update index has no package to roll back to; keeping this version");
            return self.give_up(failed, to, wait, true);
        };
        let left = budget.saturating_sub(start.elapsed());
        if left.is_zero() {
            warn!(%failed, version = %to, "no time left to download the rollback; trying again later");
            return RollBack::Retry;
        }
        let plan = Plan {
            target: Target {
                version: to.clone(),
                full,
                full_contents: None,
                delta: None,
                notes_url: None,
            },
            downgrade: true,
            rollback: true,
        };
        match self.install(&plan, wait, left) {
            Installed::Applied => RollBack::Applied,
            Installed::NotApplied => RollBack::Retry,
            Installed::ApplyFailed => {
                error!(%failed, version = %to, "the installer cannot roll back; keeping this version");
                self.give_up(failed, to, wait, false)
            }
        }
    }

    /// A rollback from `failed` to `to` cannot be done (`missing`: the index has no package
    /// of `to`): `failed` stays marked bad, its rollback is forgotten, and the user is told
    /// once (later, without `wait`: the tray is not there yet). If that cannot be saved,
    /// it is [`RollBack::Retry`]: the state on disk still asks for the rollback.
    fn give_up(&self, failed: &Version, to: &Version, wait: bool, missing: bool) -> RollBack {
        let saved = self.update_state(|s| {
            s.bad.insert(failed.clone());
            if s.pending_health
                .as_ref()
                .is_some_and(|p| p.to == *failed || (p.rollback && p.from == *failed))
            {
                s.pending_health = None;
            }
        });
        if saved.is_none() {
            return RollBack::Retry;
        }
        let (failed, version) = (failed.clone(), to.clone());
        let notice = if missing {
            Notice::NoRollback { failed, version }
        } else {
            Notice::RollbackFailed { failed, version }
        };
        if wait {
            self.host.notify(notice);
        } else {
            lock(&self.deferred).push(notice);
        }
        RollBack::GaveUp
    }

    /// Downloads `plan` (each package within `timeout`); with `wait`, waits until the
    /// daemon is idle, checks that the index still offers it (unless it is a rollback) and
    /// holds back new requests ([`Host::hold`] looks at the quiet time again). Then records
    /// `pending_health` (for a rollback, counting its attempts) and has the installer apply
    /// it; with [`Installed::Applied`] the caller exits. A package gone before it is handed
    /// over ([`ApplyError::PackageMissing`]) is [`Installed::NotApplied`]: it is downloaded
    /// again next time, and a rollback keeps its counted attempt.
    fn install(&self, plan: &Plan, wait: bool, timeout: Duration) -> Installed {
        let version = &plan.target.version;
        if let Err(e) = self
            .installer
            .download(&plan.target, plan.downgrade, timeout)
        {
            warn!(%version, error = %e, "cannot download the update");
            *lock(&self.status) = UpdateStatus::InstallFailed {
                version: version.to_string(),
                error: e,
            };
            return Installed::NotApplied;
        }
        if wait {
            info!(%version, "the update is downloaded; waiting until no signing is in progress");
            loop {
                while self.host.busy() {
                    thread::sleep(self.config.idle_poll);
                }
                if !plan.rollback && !self.still_offered(plan) {
                    info!(%version, "the update is no longer offered; it is not applied");
                    return Installed::NotApplied;
                }
                if self.host.hold() {
                    break;
                }
            }
        }
        let from = self.installer.current();
        let recorded = self.try_update_state(|s| {
            let attempts = match &s.pending_health {
                Some(p) if plan.rollback && p.rollback && p.from == from && p.to == *version => {
                    p.attempts + 1
                }
                _ => u32::from(plan.rollback),
            };
            let pending = PendingHealth {
                from: from.clone(),
                to: version.clone(),
                applied: OffsetDateTime::now_utc(),
                started: None,
                crashes: 0,
                rollback: plan.rollback,
                attempts,
            };
            s.pending_health = Some(pending.clone());
            pending
        });
        let pending = match recorded {
            Ok(pending) => pending,
            Err(e) => {
                error!(error = %e, "cannot record the update; it is not applied");
                if wait {
                    self.host.release();
                }
                return Installed::NotApplied;
            }
        };
        match self.installer.apply_on_exit(&plan.target) {
            Ok(()) => {
                info!(%from, to = %version, attempts = pending.attempts, "applying the update; exiting");
                Installed::Applied
            }
            Err(e) => {
                warn!(%version, error = %e, "cannot apply the update");
                let missing = matches!(e, ApplyError::PackageMissing(_));
                // A rollback whose package went keeps its record: its attempt counts, and
                // the next start still rolls back.
                if !(missing && plan.rollback) {
                    self.update_state(|s| {
                        if s.pending_health.as_ref() == Some(&pending) {
                            s.pending_health = None;
                        }
                    });
                }
                if wait {
                    self.host.release();
                }
                *lock(&self.status) = UpdateStatus::InstallFailed {
                    version: version.to_string(),
                    error: e.to_string(),
                };
                if missing {
                    Installed::NotApplied
                } else {
                    Installed::ApplyFailed
                }
            }
        }
    }

    /// Whether the saved settings still enable updates and the index still offers `plan`
    /// after the wait.
    fn still_offered(&self, plan: &Plan) -> bool {
        self.check(true, None)
            .plan
            .is_some_and(|now| now.target == plan.target)
    }

    /// The `updates` of `settings.json`.
    fn settings(&self) -> UpdateSettings {
        load_settings(&self.config.settings).updates
    }

    /// Applies `change` to the state as it is in the file now, under the state lock, and
    /// saves it if it changed. `None` (logged) if the state cannot be read or saved: the
    /// caller does not act on a change that is not on disk.
    fn update_state<R>(&self, change: impl FnOnce(&mut State) -> R) -> Option<R> {
        self.try_update_state(change)
            .inspect_err(|e| warn!(error = %e, "cannot read or save the updater's state"))
            .ok()
    }

    /// [`Updater::update_state`], with the error. A state file that is not a state
    /// ([`std::io::ErrorKind::InvalidData`]: damaged) is replaced by a fresh state
    /// (logged), so updates go on; any other read error (no permission, a file locked by
    /// another program) fails, and the file is left as it is.
    fn try_update_state<R>(&self, change: impl FnOnce(&mut State) -> R) -> std::io::Result<R> {
        let _guard = lock(&self.state_lock);
        let (mut state, broken) = match State::load(&self.config.data_dir) {
            Ok(state) => (state, false),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                warn!(error = %e, "the updater's state is broken; starting a new one");
                (State::fresh(), true)
            }
            Err(e) => return Err(e),
        };
        let before = state.clone();
        let result = change(&mut state);
        if broken || state != before {
            state.save(&self.config.data_dir)?;
        }
        Ok(result)
    }
}

/// Marks the version `pending` went to bad: the version to roll back to, or `None` (and
/// `pending_health` cleared) if that one failed here too.
fn mark_failed(state: &mut State, pending: &PendingHealth) -> Option<Version> {
    state.bad.insert(pending.to.clone());
    if state.bad.contains(&pending.from) {
        error!(version = %pending.from, "the version before it failed here too: nothing to roll back to");
        state.pending_health = None;
        return None;
    }
    Some(pending.from.clone())
}

/// The updater as the settings window and the tray see it: running, or off and why.
#[derive(Clone)]
pub enum UpdaterHandle {
    Running(Arc<Updater>),
    /// [`UpdateStatus::NotInstalled`], [`UpdateStatus::PackageManaged`] or
    /// [`UpdateStatus::NoKeys`].
    Off(UpdateStatus),
}

impl Updates for UpdaterHandle {
    fn status(&self) -> UpdateStatus {
        match self {
            UpdaterHandle::Running(updater) => updater.status(),
            UpdaterHandle::Off(status) => status.clone(),
        }
    }

    fn check_now(&self, settings: Option<UpdateSettings>) -> UpdateStatus {
        match self {
            UpdaterHandle::Running(updater) => updater.check_now(settings),
            UpdaterHandle::Off(status) => status.clone(),
        }
    }
}

/// What «Проверить сейчас» (the settings window) and «Проверить обновления» (the tray)
/// check: the core's updates, then the plugin catalog, downloaded even with updates off
/// ([`PluginService::check_now`](crate::plugins::PluginService::check_now)).
#[derive(Clone)]
pub struct Checks {
    pub core: UpdaterHandle,
    pub plugins: Option<Arc<crate::plugins::PluginService>>,
}

impl Updates for Checks {
    fn status(&self) -> UpdateStatus {
        self.core.status()
    }

    fn check_now(&self, settings: Option<UpdateSettings>) -> UpdateStatus {
        let status = self.core.check_now(settings);
        if let Some(plugins) = &self.plugins {
            plugins.check_now();
        }
        status
    }
}

/// Whether this build can update itself: not if `package_manager` installed it (it updates
/// the copy), otherwise with the keys built in and `installer` (`Err` if this copy is not
/// installed through Velopack, with the reason). `Err` is the status the settings window
/// shows; the reason is logged.
pub fn availability<I>(
    keys: Result<Vec<PublicKey>, UpdateError>,
    flavor: Option<Flavor>,
    package_manager: Option<&str>,
    installer: impl FnOnce() -> Result<I, String>,
) -> Result<(Vec<PublicKey>, Flavor, I), UpdateStatus> {
    if let Some(manager) = package_manager {
        info!(
            manager,
            "a package manager installed this copy and updates it: updates are off"
        );
        return Err(UpdateStatus::PackageManaged(manager.to_owned()));
    }
    let Some(flavor) = flavor else {
        info!("no update packages are built for this platform: updates are off");
        return Err(UpdateStatus::NotInstalled);
    };
    let installer = installer().map_err(|e| {
        info!(reason = %e, "updates are available only for the installed version");
        UpdateStatus::NotInstalled
    })?;
    match keys {
        Ok(keys) if keys.is_empty() => {
            info!("the update signing keys are not built into this build: updates are off");
            Err(UpdateStatus::NoKeys)
        }
        Ok(keys) => Ok((keys, flavor, installer)),
        Err(e) => {
            error!(error = %e, "updates are off");
            Err(UpdateStatus::NoKeys)
        }
    }
}

/// A random time in `range`.
pub(crate) fn jitter((low, high): (Duration, Duration)) -> Duration {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return low;
    }
    let span = high.saturating_sub(low).as_secs();
    low + Duration::from_secs(u64::from_le_bytes(bytes) % (span + 1))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
pub(crate) mod tests;
