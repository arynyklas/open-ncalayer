//! The self-update of the core.
//!
//! An [`Updater`] looks at the signed index of the channel in the settings
//! ([`INDEX_BASE`]`/<channel>.json`) a few minutes after the start and then every 6 to 24
//! hours: [`oncl_update::fetch`], [`oncl_update::verify`] with the keys built in,
//! [`oncl_update::choose`]. A version it chooses is downloaded and checked against the index
//! by an [`Installer`] (Velopack in an installed copy: [`installer::VelopackInstaller`]), and
//! applied once no page's request is being answered and no window is open ([`Host::busy`]),
//! new requests held back ([`Host::hold`]): the process then exits, and Velopack starts the
//! new version.
//!
//! Before the update is applied, `pending_health = {from, to}` goes into the updater's
//! state. The new version records its first start ([`Updater::startup`]) and clears it once
//! its servers and its windows' event loop have run for a while
//! ([`Updater::watch_health`]). A version that has not done so within [`HEALTH_GRACE`] of
//! its start, or that ended before it did, is marked bad, never offered again, and the
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
/// A new version proves healthy within this long of its start.
pub const HEALTH_GRACE: Duration = Duration::from_secs(60);
/// A new version is healthy once its servers and its windows' event loop have run this
/// long.
pub const HEALTH_SETTLE: Duration = Duration::from_secs(5);
/// An update is applied only once no request ran for this long.
pub const QUIET: Duration = Duration::from_secs(30);
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

/// The base of the update indexes: [`INDEX_BASE`]; in test builds [`INDEX_BASE_VAR`] if set.
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
    /// the installer's store; every file is checked against the size and sha256 of the
    /// index. `downgrade`: `target` is older than the running version.
    ///
    /// # Errors
    ///
    /// What failed, for the log and the settings window.
    fn download(&self, target: &Target, downgrade: bool) -> Result<(), String>;

    /// Hands the downloaded `target` to the installer, which installs it once this process
    /// has exited and then starts it with this process's arguments. The caller exits next.
    ///
    /// # Errors
    ///
    /// What failed; nothing is installed then.
    fn apply_on_exit(&self, target: &Target) -> Result<(), String>;
}

/// The daemon, as the updater sees it.
pub trait Host: Send + Sync {
    /// Whether a page's request is being answered (or ended within [`QUIET`]) or a window
    /// is open: no update is applied then.
    fn busy(&self) -> bool;

    /// Holds back new requests of pages and returns whether the daemon is still idle; if
    /// it is not, the requests are let through again. An update is applied only while they
    /// are held.
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
    /// The index could not be read, or the package not downloaded or applied: try again.
    Retry,
    /// The index has no package to go back to: the failed version stays (marked bad).
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
    /// Notices from before the windows' event loop, told when the updater's thread starts.
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
    /// just installed records its start. One that started before and never confirmed its
    /// health (it failed, or ended first) is marked bad; if the version before it failed
    /// here too, nothing is rolled back.
    pub fn startup(&self) -> Startup {
        let current = self.installer.current();
        let now = OffsetDateTime::now_utc();
        self.update_state(|state| {
            let Some(pending) = state.pending_health.clone() else {
                return Startup::Normal;
            };
            if pending.rollback && current == pending.from {
                warn!(failed = %current, to = %pending.to, "the rollback did not install; trying again");
                state.bad.insert(current.clone());
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
            match pending.started {
                None => {
                    if let Some(p) = &mut state.pending_health {
                        p.started = Some(now);
                    }
                    Startup::Confirm
                }
                Some(started) => {
                    error!(version = %current, %started, "this version ended before it proved healthy");
                    match mark_failed(state, &pending) {
                        Some(to) => Startup::RollBack { failed: current.clone(), to },
                        None => Startup::Normal,
                    }
                }
            }
        })
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
        let confirmed = self.update_state(|state| match &state.pending_health {
            Some(p) if p.to == current => state.pending_health.take(),
            _ => None,
        });
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
        let to = self.update_state(|state| {
            let pending = state.pending_health.clone().filter(|p| p.to == current)?;
            error!(version = %current, "this version did not prove healthy in time");
            mark_failed(state, &pending)
        });
        if let Some(to) = to {
            lock(&self.queue).rollback = Some((current, to));
            self.wake.notify_all();
        }
    }

    /// At the start, before the servers and windows: installs `to` back over the failed
    /// version, from its full package in the index, without waiting for anything. With
    /// [`RollBack::Applied`] the caller exits; with [`RollBack::Retry`] it starts normally
    /// and hands the rollback to [`Updater::spawn`].
    pub fn roll_back_now(&self, failed: &Version, to: &Version) -> RollBack {
        self.roll_back(failed, to, false)
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

    fn run(&self, mut rollback: Option<(Version, Version)>) {
        for notice in std::mem::take(&mut *lock(&self.deferred)) {
            self.host.notify(notice);
        }
        let mut due = if rollback.is_some() {
            SystemTime::now()
        } else {
            SystemTime::now() + jitter(FIRST_CHECK)
        };
        loop {
            let applied = match self.next(due) {
                Job::Plan(plan) => self.install(&plan, true),
                Job::RollBack(failed, to) => {
                    rollback = Some((failed, to));
                    due = SystemTime::now();
                    false
                }
                Job::Due => {
                    let (applied, wait) = match rollback.take() {
                        Some((failed, to)) => match self.roll_back(&failed, &to, true) {
                            RollBack::Applied => (true, None),
                            RollBack::Retry => {
                                rollback = Some((failed, to));
                                (false, Some(RETRY_AFTER))
                            }
                            // The checks go on at once: a newer version may fix it.
                            RollBack::GaveUp => (false, None),
                        },
                        None => {
                            let checked = self.check(false, None);
                            let applied =
                                checked.plan.is_some_and(|plan| self.install(&plan, true));
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
    /// nothing with updates off; it tells a version found once.
    fn check(&self, manual: bool, settings: Option<UpdateSettings>) -> Checked {
        let _one = lock(&self.checking);
        let settings = settings.unwrap_or_else(|| self.settings());
        if !manual && !settings.enabled {
            return Checked {
                status: self.status(),
                plan: None,
                retry_soon: false,
            };
        }
        let channel = settings.channel;
        let index = match self.verified_index(channel) {
            Ok(index) => index,
            Err((e, retry_soon)) => return self.failed(&e, retry_soon),
        };
        let current = self.installer.current();
        let (install_id, bad) = self.update_state(|s| (s.install_id, s.bad.clone()));
        let (target, downgrade) =
            match choose(&index, &current, self.config.flavor, install_id, &bad) {
                Choice::UpToDate => {
                    info!(%current, %channel, seq = index.seq, "no update");
                    return self.checked(UpdateStatus::UpToDate, None);
                }
                Choice::Update(target) => (target, false),
                Choice::Downgrade(target) => (target, true),
            };
        info!(%current, version = %target.version, downgrade, enabled = settings.enabled, "an update is offered");
        let status = UpdateStatus::Available {
            version: target.version.to_string(),
            installing: settings.enabled,
        };
        let new = lock(&self.told).replace(target.version.clone()) != Some(target.version.clone());
        if new && !manual {
            self.host.notify(Notice::Checked(status.clone()));
        }
        let plan = settings.enabled.then_some(Plan {
            target,
            downgrade,
            rollback: false,
        });
        self.checked(status, plan)
    }

    /// The index of `channel`, downloaded and verified; its `seq` is saved. The error says
    /// whether to try again soon (the index could not be downloaded).
    fn verified_index(
        &self,
        channel: oncl_update::Channel,
    ) -> Result<oncl_update::Index, (UpdateError, bool)> {
        let fetched = fetch(&*self.transport, &self.config.base, channel).map_err(|e| {
            info!(error = %e, %channel, "cannot download the update index; trying again later");
            (e, true)
        })?;
        let last_seq = self.update_state(|s| s.last_seq.get(&channel).copied());
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
        self.update_state(|s| {
            let seq = s.last_seq.entry(channel).or_insert(index.seq);
            *seq = (*seq).max(index.seq);
        });
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

    /// Installs `to` back over `failed`. Without `wait` (at the start) nothing is waited
    /// for, and a notice waits for the updater's thread.
    fn roll_back(&self, failed: &Version, to: &Version, wait: bool) -> RollBack {
        let package = {
            let _one = lock(&self.checking);
            let channel = self.settings().channel;
            match self.verified_index(channel) {
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
            return self.give_up_rollback(failed, to, wait);
        };
        let plan = Plan {
            target: Target {
                version: to.clone(),
                full,
                delta: None,
                notes_url: None,
            },
            downgrade: true,
            rollback: true,
        };
        if self.install(&plan, wait) {
            RollBack::Applied
        } else {
            RollBack::Retry
        }
    }

    /// The index has no package of `to`: `failed` stays marked bad, its rollback is
    /// forgotten, and the user is told once.
    fn give_up_rollback(&self, failed: &Version, to: &Version, wait: bool) -> RollBack {
        error!(%failed, version = %to, flavor = %self.config.flavor, "the update index has no package to roll back to; keeping this version");
        self.update_state(|s| {
            s.bad.insert(failed.clone());
            if s.pending_health
                .as_ref()
                .is_some_and(|p| p.to == *failed || (p.rollback && p.from == *failed))
            {
                s.pending_health = None;
            }
        });
        let notice = Notice::NoRollback {
            failed: failed.clone(),
            version: to.clone(),
        };
        if wait {
            self.host.notify(notice);
        } else {
            lock(&self.deferred).push(notice);
        }
        RollBack::GaveUp
    }

    /// Downloads `plan`; with `wait`, waits until the daemon is idle, checks that the index
    /// still offers it (unless it is a rollback) and holds back new requests. Then records
    /// `pending_health` and has the installer apply it: whether it was applied (the caller
    /// exits).
    fn install(&self, plan: &Plan, wait: bool) -> bool {
        let version = &plan.target.version;
        if let Err(e) = self.installer.download(&plan.target, plan.downgrade) {
            warn!(%version, error = %e, "cannot download the update");
            *lock(&self.status) = UpdateStatus::Failed(e);
            return false;
        }
        if wait {
            info!(%version, "the update is downloaded; waiting until no signing is in progress");
            loop {
                while self.host.busy() {
                    thread::sleep(self.config.idle_poll);
                }
                if !plan.rollback && !self.still_offered(plan) {
                    info!(%version, "the update is no longer offered; it is not applied");
                    return false;
                }
                if self.host.hold() {
                    break;
                }
            }
        }
        let from = self.installer.current();
        let pending = PendingHealth {
            from: from.clone(),
            to: version.clone(),
            applied: OffsetDateTime::now_utc(),
            started: None,
            rollback: plan.rollback,
        };
        if let Err(e) = self.try_update_state(|s| s.pending_health = Some(pending.clone())) {
            error!(error = %e, "cannot record the update; it is not applied");
            if wait {
                self.host.release();
            }
            return false;
        }
        match self.installer.apply_on_exit(&plan.target) {
            Ok(()) => {
                info!(%from, to = %version, "applying the update; exiting");
                true
            }
            Err(e) => {
                warn!(%version, error = %e, "cannot apply the update");
                // A rollback that did not apply is tried again, at the latest at the next
                // start.
                if !plan.rollback {
                    self.update_state(|s| {
                        if s.pending_health.as_ref() == Some(&pending) {
                            s.pending_health = None;
                        }
                    });
                }
                if wait {
                    self.host.release();
                }
                *lock(&self.status) = UpdateStatus::Failed(e);
                false
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
    /// saves it if it changed (logged if it cannot be).
    fn update_state<R>(&self, change: impl FnOnce(&mut State) -> R) -> R {
        let mut result = None;
        if let Err(e) = self.try_update_state(|s| result = Some(change(s))) {
            warn!(error = %e, "cannot save the updater's state");
        }
        result.expect("the change ran")
    }

    /// [`Updater::update_state`], failing if the state cannot be saved. A broken state file
    /// is replaced by a fresh state (logged), so updates go on.
    fn try_update_state<R>(&self, change: impl FnOnce(&mut State) -> R) -> std::io::Result<R> {
        let _guard = lock(&self.state_lock);
        let (mut state, broken) = match State::load(&self.config.data_dir) {
            Ok(state) => (state, false),
            Err(e) => {
                warn!(error = %e, "the updater's state is broken; starting a new one");
                (State::fresh(), true)
            }
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
    /// [`UpdateStatus::NotInstalled`] or [`UpdateStatus::NoKeys`].
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

/// Whether this build can update itself: the keys built in, and `installer` (`Err` if this
/// copy is not installed through Velopack, with the reason). `Err` is the status the
/// settings window shows; the reason is logged.
pub fn availability<I>(
    keys: Result<Vec<PublicKey>, UpdateError>,
    flavor: Option<Flavor>,
    installer: impl FnOnce() -> Result<I, String>,
) -> Result<(Vec<PublicKey>, Flavor, I), UpdateStatus> {
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
fn jitter((low, high): (Duration, Duration)) -> Duration {
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
mod tests;
