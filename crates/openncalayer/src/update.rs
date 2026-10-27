//! The self-update of the core.
//!
//! An [`Updater`] looks at the signed index of the channel in the settings
//! ([`INDEX_BASE`]`/<channel>.json`) a few minutes after the start and then every 6 to 24
//! hours: [`oncl_update::fetch`], [`oncl_update::verify`] with the keys built in,
//! [`oncl_update::choose`]. A version it chooses is downloaded and checked against the index
//! by an [`Installer`] (Velopack in an installed copy: [`installer::VelopackInstaller`]), and
//! applied once no page's request is being answered and no window is open ([`Host::busy`]):
//! the process then exits, and Velopack starts the new version.
//!
//! Before the update is applied, `pending_health = {from, to}` goes into the updater's
//! state. The new version clears it once its servers and its windows' event loop run
//! ([`Updater::confirm_health`]); a version that has not done so within [`HEALTH_GRACE`] of
//! its first start is found failed at the next start ([`Updater::startup`]): it is marked
//! bad, never offered again, and the previous version is installed back from its full
//! package in the index.
//!
//! An index that cannot be downloaded is tried again quietly within hours; one that fails
//! its checks (another key, a broken signature, an older `seq`, too old) is logged, shown
//! in the settings window, and tried again at the next check: no notification is sent for
//! either.

pub mod installer;

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime};

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
/// A new version proves healthy within this long of its first start.
pub const HEALTH_GRACE: Duration = Duration::from_secs(60);
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
}

/// What [`Updater::startup`] found of the last update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Startup {
    /// No update waits for this version's health.
    Normal,
    /// This version was just installed: it confirms its health once it runs
    /// ([`Updater::confirm_health`]).
    Confirm,
    /// This version did not prove healthy: the updater installs `from` back first.
    RollBack(PendingHealth),
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

/// The self-update; see the [module](self).
pub struct Updater {
    config: UpdaterConfig,
    transport: Arc<dyn HttpTransport>,
    installer: Box<dyn Installer>,
    host: Box<dyn Host>,
    status: Mutex<UpdateStatus>,
    /// One check at a time.
    checking: Mutex<()>,
    /// The version last told available, so a scheduled check tells it once.
    told: Mutex<Option<Version>>,
    /// A version «Проверить сейчас» found, for the updater's thread to install.
    queued: Mutex<Option<Plan>>,
    wake: Condvar,
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
            told: Mutex::new(None),
            queued: Mutex::new(None),
            wake: Condvar::new(),
        }
    }

    /// What the updater found last.
    pub fn status(&self) -> UpdateStatus {
        lock(&self.status).clone()
    }

    /// Looks at `pending_health` at the start of this version: see [`Startup`]. A version
    /// that was installed and has not confirmed its health within [`HEALTH_GRACE`] of its
    /// first start is marked bad (`pending_health` stays until the version before it is
    /// back); if that version failed here too, nothing is rolled back.
    pub fn startup(&self) -> Startup {
        let mut state = self.load_state();
        let Some(pending) = state.pending_health.clone() else {
            return Startup::Normal;
        };
        let current = self.installer.current();
        if current != pending.to {
            warn!(from = %pending.from, to = %pending.to, %current, "an applied update did not install; forgetting it");
            state.pending_health = None;
            self.save_state(&state);
            return Startup::Normal;
        }
        let now = OffsetDateTime::now_utc();
        match pending.started {
            None => {
                if let Some(p) = &mut state.pending_health {
                    p.started = Some(now);
                }
                self.save_state(&state);
                Startup::Confirm
            }
            Some(started) if now - started <= HEALTH_GRACE => Startup::Confirm,
            Some(started) => {
                error!(version = %pending.to, %started, "this version did not prove healthy after its update; marking it bad");
                state.bad.insert(pending.to.clone());
                if state.bad.contains(&pending.from) {
                    error!(version = %pending.from, "the version before it failed here too: nothing to roll back to");
                    state.pending_health = None;
                    self.save_state(&state);
                    return Startup::Normal;
                }
                self.save_state(&state);
                Startup::RollBack(pending)
            }
        }
    }

    /// The servers and the windows' event loop of a version just installed run: its
    /// `pending_health` goes, and the user is told it was updated (or rolled back to).
    pub fn confirm_health(&self) {
        let mut state = self.load_state();
        let Some(pending) = state.pending_health.take() else {
            return;
        };
        self.save_state(&state);
        info!(from = %pending.from, to = %pending.to, "the update is healthy");
        self.host.notify(if state.bad.contains(&pending.from) {
            Notice::RolledBack {
                failed: pending.from,
                version: pending.to,
            }
        } else {
            Notice::Updated(pending.to)
        });
    }

    /// «Проверить сейчас»: checks with the settings as saved, even with updates off, and
    /// returns what it found; a version to install goes to the updater's thread.
    pub fn check_now(&self) -> UpdateStatus {
        let checked = self.check(true);
        if let Some(plan) = checked.plan {
            *lock(&self.queued) = Some(plan);
            self.wake.notify_all();
        }
        checked.status
    }

    /// Starts the updater's thread: the rollback `startup` asks for, then the checks.
    pub fn spawn(self: Arc<Self>, startup: Startup) {
        let spawned = thread::Builder::new()
            .name("updates".into())
            .spawn(move || self.run(startup));
        if let Err(e) = spawned {
            error!(error = %e, "cannot start the updater");
        }
    }

    fn run(&self, startup: Startup) {
        let mut rollback = match startup {
            Startup::RollBack(pending) => Some(pending),
            Startup::Normal | Startup::Confirm => None,
        };
        let mut due = if rollback.is_some() {
            SystemTime::now()
        } else {
            SystemTime::now() + jitter(FIRST_CHECK)
        };
        loop {
            let plan = match self.next(due) {
                Some(plan) => Some(plan),
                None => {
                    let (plan, retry_soon) = match &rollback {
                        Some(pending) => match self.rollback_plan(pending) {
                            Some(plan) => (Some(plan), true),
                            None => (None, true),
                        },
                        None => {
                            let checked = self.check(false);
                            (checked.plan, checked.retry_soon)
                        }
                    };
                    let wait = if retry_soon { RETRY_AFTER } else { CHECK_EVERY };
                    due = SystemTime::now() + jitter(wait);
                    plan
                }
            };
            if let Some(plan) = plan
                && self.install(&plan)
            {
                return;
            }
            if rollback.is_some() && self.load_state().pending_health.is_none() {
                // Nothing left to roll back (the state was reset).
                rollback = None;
            }
        }
    }

    /// Waits until `due` by the wall clock, or a plan queued by «Проверить сейчас».
    fn next(&self, due: SystemTime) -> Option<Plan> {
        let mut queued = lock(&self.queued);
        loop {
            if let Some(plan) = queued.take() {
                return Some(plan);
            }
            let left = due
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO);
            if left.is_zero() {
                return None;
            }
            queued = self
                .wake
                .wait_timeout(queued, left.min(WAKE_EVERY))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// One check: the index of the channel in the settings, verified, and the version it
    /// offers this installation. A scheduled one (`manual` false) does nothing with updates
    /// off; it tells a version found once.
    fn check(&self, manual: bool) -> Checked {
        let _one = lock(&self.checking);
        let settings = self.settings();
        if !manual && !settings.enabled {
            return Checked {
                status: self.status(),
                plan: None,
                retry_soon: false,
            };
        }
        let channel = settings.channel;
        let mut state = self.load_state();
        let fetched = match fetch(&*self.transport, &self.config.base, channel) {
            Ok(fetched) => fetched,
            Err(e) => {
                info!(error = %e, %channel, "cannot download the update index; trying again later");
                return self.failed(&e, true);
            }
        };
        let last_seq = state.last_seq.get(&channel).copied();
        let index = match verify(
            &fetched.index,
            &fetched.signature,
            &self.config.keys,
            channel,
            last_seq,
            OffsetDateTime::now_utc(),
        ) {
            Ok(index) => index,
            Err(e) => {
                warn!(error = %e, %channel, "the update index is refused");
                return self.failed(&e, false);
            }
        };
        if last_seq != Some(index.seq) {
            state.last_seq.insert(channel, index.seq);
            self.save_state(&state);
        }
        let current = self.installer.current();
        let (target, downgrade) = match choose(
            &index,
            &current,
            self.config.flavor,
            state.install_id,
            &state.bad,
        ) {
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

    /// The version before the failed `pending.to`, from its full package in the index;
    /// `None` (logged) if the index cannot be read or no longer has it.
    fn rollback_plan(&self, pending: &PendingHealth) -> Option<Plan> {
        let _one = lock(&self.checking);
        let channel = self.settings().channel;
        let state = self.load_state();
        let fetched = fetch(&*self.transport, &self.config.base, channel)
            .map_err(|e| warn!(error = %e, "cannot download the update index to roll back"))
            .ok()?;
        let index = verify(
            &fetched.index,
            &fetched.signature,
            &self.config.keys,
            channel,
            state.last_seq.get(&channel).copied(),
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| warn!(error = %e, "the update index is refused; cannot roll back"))
        .ok()?;
        let Some(package) = index
            .release(&pending.from)
            .and_then(|release| release.package(self.config.flavor))
        else {
            error!(version = %pending.from, flavor = %self.config.flavor, "the update index has no package to roll back to");
            return None;
        };
        Some(Plan {
            target: Target {
                version: pending.from.clone(),
                full: package.full.clone(),
                delta: None,
                notes_url: None,
            },
            downgrade: true,
            rollback: true,
        })
    }

    /// Downloads `plan`, waits until the daemon is idle, records `pending_health` and has
    /// the installer apply it; then the process exits. Whether it was applied.
    fn install(&self, plan: &Plan) -> bool {
        let version = &plan.target.version;
        if let Err(e) = self.installer.download(&plan.target, plan.downgrade) {
            warn!(%version, error = %e, "cannot download the update");
            *lock(&self.status) = UpdateStatus::Failed(e);
            return false;
        }
        info!(%version, "the update is downloaded; waiting until no signing is in progress");
        while self.host.busy() {
            thread::sleep(self.config.idle_poll);
        }
        if !plan.rollback && !self.settings().enabled {
            info!(%version, "updates were turned off; the update is not applied");
            return false;
        }
        let mut state = self.load_state();
        let from = self.installer.current();
        state.pending_health = Some(PendingHealth {
            from: from.clone(),
            to: version.clone(),
            applied: OffsetDateTime::now_utc(),
            started: None,
        });
        if let Err(e) = state.save(&self.config.data_dir) {
            error!(error = %e, "cannot record the update; it is not applied");
            return false;
        }
        match self.installer.apply_on_exit(&plan.target) {
            Ok(()) => {
                info!(%from, to = %version, "applying the update; exiting");
                self.host.exit();
                true
            }
            Err(e) => {
                warn!(%version, error = %e, "cannot apply the update");
                state.pending_health = None;
                self.save_state(&state);
                *lock(&self.status) = UpdateStatus::Failed(e);
                false
            }
        }
    }

    /// The `updates` of `settings.json`.
    fn settings(&self) -> UpdateSettings {
        load_settings(&self.config.settings).updates
    }

    /// The state; a broken one is replaced by a fresh one (logged), so updates go on.
    fn load_state(&self) -> State {
        match State::load(&self.config.data_dir) {
            Ok(state) => state,
            Err(e) => {
                warn!(error = %e, "the updater's state is broken; starting a new one");
                let state = State::fresh();
                self.save_state(&state);
                state
            }
        }
    }

    fn save_state(&self, state: &State) {
        if let Err(e) = state.save(&self.config.data_dir) {
            warn!(error = %e, "cannot save the updater's state");
        }
    }
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

    fn check_now(&self) -> UpdateStatus {
        match self {
            UpdaterHandle::Running(updater) => updater.check_now(),
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
