//! The plugins of the daemon: installed in `<data>/plugins/` ([`Store`]), loaded as dynamic
//! modules ([`PluginModules`]), installed, updated and withdrawn from the catalog (the
//! plugin releases of the signed update index of the channel in the settings), or installed
//! from a file the user chose.
//!
//! - At the start the enabled plugins not withdrawn are loaded (one that fails is shown with
//!   its error and logged), and the catalog kept last is read again.
//! - The catalog is downloaded within 10 to 60 s of the start if none is kept, else after
//!   [`FIRST_CHECK`], then every [`CHECK_EVERY`] ([`RETRY_AFTER`] after a download failed);
//!   with updates off (`updates.enabled` of the settings) not at all, but still on demand
//!   (the plugin window, a page's `installBundle`, «Проверить сейчас»).
//! - After every catalog accepted on schedule (or on demand with updates on), each plugin
//!   installed from the catalog moves to the version [`choose_plugin`] picks: downloaded,
//!   checked against the index (HTTPS, size, sha256, then its manifest: id, version,
//!   modules, `replaces` and `min_core`), loaded, then recorded; a version that fails any of
//!   it is marked bad and the old one stays. A version revoked with nothing to move to is
//!   unloaded and marked withdrawn. Plugins installed from a file are never touched.
//! - An install asks the user ([`InstallUi`]) with the capabilities the package declares.
//! - A request for a module nothing serves that a plugin of the catalog would serve is told
//!   ([`PluginNotice::Needed`]) and listed in the plugin window.
//!
//! Without the keys of the update index built in there is no catalog: plugins are
//! installed from files only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use oncl_accessory::Bundles;
use oncl_desktop::UpdateSettings;
use oncl_pki::http::HttpTransport;
use oncl_plugin::{
    BUILT_IN, Capabilities, Installed, LoadError, Localized, MAX_PACKAGE, Package, PluginModules,
    Replaces, Source, Store,
};
use oncl_protocol::{AddInfo, DynamicModules};
use oncl_ui::PluginActionError;
use oncl_update::{
    Channel, Index, MAX_AGE, PluginChoice, PluginName, PluginRelease, PublicKey, Sha256,
    UpdateError, Version, choose_plugin, fetch, offer, verify,
};
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::load_settings;
use crate::update::installer::fetch_package;
use crate::update::{
    CHECK_EVERY, DOWNLOAD_TIMEOUT, FIRST_CHECK, INDEX_TIMEOUT, RETRY_AFTER, jitter,
};

/// The first download of the catalog when none is kept, this long after the start.
pub const FIRST_CHECK_WITHOUT_CATALOG: (Duration, Duration) =
    (Duration::from_secs(10), Duration::from_secs(60));

/// How often a bounded wait looks whether a catalog download running has ended.
const CATALOG_POLL: Duration = Duration::from_millis(20);

/// How long after a catalog download failed a page's request (`installBundle`, an install
/// a page started) does without a catalog instead of downloading it again.
pub const PAGE_RETRY_AFTER: Duration = Duration::from_secs(5 * 60);

/// How often an install a page started may tell that it failed, per plugin.
pub const PAGE_FAILURE_EVERY: Duration = Duration::from_secs(10 * 60);

/// The longest sleep of the schedule: the wall clock is compared at least this often.
const WAKE_EVERY: Duration = Duration::from_secs(3600);

/// What asks the user before a plugin is installed.
pub trait InstallUi: Send + Sync {
    /// Asks about `request` and returns at once; the answer goes to `decide` (`true`:
    /// install), once, from any thread. A request that cannot be shown is declined.
    fn confirm(&self, request: InstallRequest, decide: Box<dyn FnOnce(bool) + Send>);
}

/// A plugin about to be installed, as the user is asked about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    /// The page that asked for it (`installBundle`), if one did.
    pub origin: Option<String>,
    pub name: Localized,
    pub version: Version,
    pub replaces: Option<Replaces>,
    /// The installed plugin of the same id it would replace: its version and source.
    pub replacing: Option<(Version, Source)>,
    /// What its manifest declares it may do.
    pub capabilities: Capabilities,
    /// From a file the user chose, not from the catalog: nobody has reviewed it.
    pub local: bool,
}

/// What the plugins tell the user (tray notifications).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginNotice {
    /// A plugin is installed.
    Installed { name: Localized },
    /// A plugin is updated to `version` (or moved back to it from a revoked one).
    Updated { name: Localized, version: Version },
    /// A plugin's version is revoked with nothing to move to: it is off.
    Withdrawn { name: Localized },
    /// Installing or updating a plugin failed.
    Failed { name: Localized, error: String },
    /// A page (`origin`) called a module of the plugin `id` of the catalog, not installed.
    Needed {
        origin: Option<String>,
        name: Localized,
        id: String,
    },
}

/// Where and with what the plugins work.
pub struct PluginConfig {
    /// The data directory: `plugins/` is there.
    pub data_dir: PathBuf,
    /// `settings.json`: its `updates` (on or off, the channel) are read at every check.
    pub settings: PathBuf,
    /// The keys the update index must be signed with; none: no catalog.
    pub keys: Vec<PublicKey>,
    /// The base of the update indexes ([`crate::update::index_base`]).
    pub base: String,
    /// This version of OpenNCALayer: plugins needing a newer one are not offered or loaded.
    pub core: Version,
    /// The network: the catalog and the packages.
    pub http: Arc<dyn HttpTransport>,
    pub modules: Arc<PluginModules>,
    pub ui: Arc<dyn InstallUi>,
    /// Tells the user; called from any thread, must not block.
    pub notify: Arc<dyn Fn(PluginNotice) + Send + Sync>,
}

/// The plugins as the plugin window shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceView {
    pub catalog: CatalogView,
    /// By id.
    pub installed: Vec<InstalledView>,
    /// Offered by the catalog, not installed; by id.
    pub available: Vec<AvailableView>,
}

/// The catalog's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogView {
    /// This build has no keys of the update index: no catalog.
    Unavailable,
    /// The catalog of `channel` is in use, made at `generated`; `checked` is when it was
    /// last downloaded in this run, `error` why the last download failed, if it did.
    Ready {
        channel: Channel,
        generated: OffsetDateTime,
        checked: Option<OffsetDateTime>,
        error: Option<String>,
    },
    /// No catalog of `channel` in use: not downloaded yet (`error` none), not published, or
    /// the download failed (`error`).
    Missing {
        channel: Channel,
        error: Option<String>,
    },
}

/// An installed plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledView {
    pub id: String,
    pub name: Localized,
    pub version: Version,
    pub replaces: Option<Replaces>,
    pub source: Source,
    pub state: PluginState,
}

/// Whether an installed plugin serves its modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginState {
    Enabled,
    Disabled,
    /// Revoked in the catalog with nothing to move to.
    Withdrawn,
    /// Enabled, but it could not be loaded: why.
    Error(String),
}

/// A plugin of the catalog not installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableView {
    pub id: String,
    pub name: Localized,
    pub version: Version,
    pub replaces: Option<Replaces>,
    /// A page called one of its modules: its origin (`Some(None)`: without an origin).
    pub needed_by: Option<Option<String>>,
}

/// The plugins; see the [module](self).
pub struct PluginService {
    /// This service, for the installs started in the background.
    me: Weak<PluginService>,
    cfg: PluginConfig,
    store: Store,
    catalog: Mutex<Catalog>,
    /// Why an installed plugin is not loaded, by id.
    errors: Mutex<BTreeMap<String, String>>,
    /// The names of installed plugins and what they replace, by id, from their packages.
    known: Mutex<BTreeMap<String, Known>>,
    /// Plugins of the catalog a page needed, by id: the page's origin.
    needed: Mutex<BTreeMap<String, Option<String>>>,
    /// Plugins being installed (downloaded, or waiting for the user), by id.
    installing: Mutex<BTreeSet<String>>,
    /// When an install a page started last told that it failed, by plugin id.
    page_failures: Mutex<BTreeMap<String, Instant>>,
    /// Versions of the catalog that could not load because another plugin serves one of
    /// their modules, by id: not updated to until the plugins change. Not recorded: the
    /// package is not at fault.
    conflicts: Mutex<BTreeMap<String, BTreeSet<Version>>>,
    /// One catalog download at a time.
    checking: Mutex<()>,
    /// One application of the catalog at a time.
    applying: Mutex<()>,
    /// An application asked for while one ran: the running one goes over the catalog again.
    apply_pending: AtomicBool,
    /// Every change of an installed plugin (turned on or off, removed, installed, updated,
    /// withdrawn): each acts on the state as it is once it holds this.
    changing: Mutex<()>,
}

/// The catalog in use.
#[derive(Default)]
struct Catalog {
    index: Option<Index>,
    /// When it was last downloaded in this run.
    checked: Option<OffsetDateTime>,
    /// Why the last download failed.
    error: Option<String>,
    /// When the last download failed to bring a catalog; `None` after one that did.
    failed_at: Option<Instant>,
}

/// Who wants the catalog: how long they wait for a download running, and whether a recent
/// failure is tried again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asker {
    /// The user, in the plugin window: waits for a download running, and downloads again.
    User,
    /// A page: waits only within its time, and does without a catalog for
    /// [`PAGE_RETRY_AFTER`] after a download failed.
    Page,
}

#[derive(Clone)]
struct Known {
    name: Localized,
    replaces: Option<Replaces>,
}

/// Why a catalog download did not bring a catalog.
#[derive(Debug)]
enum Refresh {
    NoKeys,
    /// It could not be downloaded (or recorded): try again soon.
    Unreachable(String),
    /// The channel has no index yet.
    NotPublished,
    /// It was refused (signature, age, an older `seq`).
    Refused(String),
}

/// Why a downloaded package is not installed.
enum Download {
    /// It could not be downloaded: try again later.
    Unreachable(String),
    /// It is not what the index says: the version is marked bad.
    Bad(String),
}

impl PluginService {
    /// The plugins of `cfg`: the enabled ones loaded, the kept catalog read; without a
    /// schedule ([`PluginService::start`] has one).
    ///
    /// # Errors
    ///
    /// `<data>/plugins/` cannot be opened ([`Store::open`]).
    pub fn new(cfg: PluginConfig) -> std::io::Result<Arc<PluginService>> {
        let store = Store::open(&cfg.data_dir)?;
        let service = Arc::new_cyclic(|me| PluginService {
            me: Weak::clone(me),
            cfg,
            store,
            catalog: Mutex::new(Catalog::default()),
            errors: Mutex::default(),
            known: Mutex::default(),
            needed: Mutex::default(),
            installing: Mutex::default(),
            page_failures: Mutex::default(),
            conflicts: Mutex::default(),
            checking: Mutex::new(()),
            applying: Mutex::new(()),
            apply_pending: AtomicBool::new(false),
            changing: Mutex::new(()),
        });
        for (id, installed) in service.store.state().plugins {
            if installed.enabled && !installed.withdrawn {
                // Logged and shown in the plugin window.
                let _ = service.load_installed(&id);
            } else {
                service.read_known(&id);
            }
        }
        let weak = Arc::downgrade(&service);
        service
            .cfg
            .modules
            .set_on_missing(Arc::new(move |module: &str, add_info: &AddInfo| {
                if let Some(service) = weak.upgrade() {
                    service.missing(module, add_info);
                }
            }));
        Ok(service)
    }

    /// [`PluginService::new`], and the schedule of the catalog downloads on a thread (none
    /// without keys).
    ///
    /// # Errors
    ///
    /// As [`PluginService::new`].
    pub fn start(cfg: PluginConfig) -> std::io::Result<Arc<PluginService>> {
        let service = PluginService::new(cfg)?;
        if service.cfg.keys.is_empty() {
            info!("the update keys are not built in: no plugin catalog");
            return Ok(service);
        }
        let scheduled = Arc::clone(&service);
        let spawned = thread::Builder::new()
            .name("plugins".into())
            .spawn(move || scheduled.run_schedule());
        if let Err(e) = spawned {
            warn!(error = %e, "cannot start the plugin catalog's schedule");
        }
        Ok(service)
    }

    /// «Проверить сейчас»: downloads the catalog, even with updates off; with them on, the
    /// plugins of the catalog are updated by it. Blocks for the downloads.
    pub fn check_now(&self) {
        if self.refresh(INDEX_TIMEOUT).is_ok() && self.update_settings().enabled {
            self.apply_catalog();
        }
    }

    /// One turn of the schedule: with updates on, the catalog downloaded and applied. How
    /// long until the next.
    pub fn scheduled_check(&self) -> Duration {
        if !self.update_settings().enabled {
            return jitter(CHECK_EVERY);
        }
        match self.refresh(INDEX_TIMEOUT) {
            Ok(()) => {
                self.apply_catalog();
                jitter(CHECK_EVERY)
            }
            Err(Refresh::Unreachable(_)) => jitter(RETRY_AFTER),
            Err(_) => jitter(CHECK_EVERY),
        }
    }

    fn run_schedule(&self) {
        let first = if self.valid_index().is_some() {
            FIRST_CHECK
        } else {
            FIRST_CHECK_WITHOUT_CATALOG
        };
        let mut due = SystemTime::now() + jitter(first);
        loop {
            // A computer's sleep stops monotonic time: compare the wall clock hourly.
            while let Ok(left) = due.duration_since(SystemTime::now())
                && !left.is_zero()
            {
                thread::sleep(left.min(WAKE_EVERY));
            }
            due = SystemTime::now() + self.scheduled_check();
        }
    }

    /// The plugins, their states, the catalog's state and what it offers.
    pub fn view(&self) -> ServiceView {
        let state = self.store.state();
        let errors = lock(&self.errors).clone();
        let known = lock(&self.known).clone();
        let installed = state
            .plugins
            .iter()
            .map(|(id, installed)| {
                let known = known.get(id);
                InstalledView {
                    id: id.clone(),
                    name: known.map_or_else(|| same_name(id), |k| k.name.clone()),
                    version: installed.version.clone(),
                    replaces: known.and_then(|k| k.replaces.clone()),
                    source: installed.source,
                    state: if installed.withdrawn {
                        PluginState::Withdrawn
                    } else if !installed.enabled {
                        PluginState::Disabled
                    } else if let Some(error) = errors.get(id) {
                        PluginState::Error(error.clone())
                    } else {
                        PluginState::Enabled
                    },
                }
            })
            .collect();
        if self.cfg.keys.is_empty() {
            return ServiceView {
                catalog: CatalogView::Unavailable,
                installed,
                available: Vec::new(),
            };
        }
        let channel = self.update_settings().channel;
        let index = self.valid_index();
        let (checked, error) = {
            let catalog = lock(&self.catalog);
            (catalog.checked, catalog.error.clone())
        };
        let catalog = match &index {
            Some(index) => CatalogView::Ready {
                channel,
                generated: index.generated,
                checked,
                error,
            },
            None => CatalogView::Missing { channel, error },
        };
        let needed = lock(&self.needed).clone();
        let available = index
            .as_ref()
            .map(|index| {
                let ids: BTreeSet<&str> = index.plugins.iter().map(|r| r.id.as_str()).collect();
                ids.into_iter()
                    .filter(|id| !state.plugins.contains_key(*id))
                    .filter_map(|id| {
                        let release =
                            offer(index, &self.cfg.core, &state.install_id, &state.bad, |r| {
                                r.id == id
                            })?;
                        Some(AvailableView {
                            id: id.to_owned(),
                            name: localized(&release.name),
                            version: release.version.clone(),
                            replaces: replaces_of(release),
                            needed_by: needed.get(id).cloned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        ServiceView {
            catalog,
            installed,
            available,
        }
    }

    /// Installs the plugin `id` of the catalog (downloaded first if none is in use): its
    /// package is downloaded and checked, then the user is asked; `origin` is the page that
    /// asked for it. Blocks for the downloads, not for the user. An installed plugin, or one
    /// being installed, is left alone; a failure is told ([`PluginNotice::Failed`]), for an
    /// install a page started at most once per [`PAGE_FAILURE_EVERY`]. For a page the
    /// catalog is not downloaded again within [`PAGE_RETRY_AFTER`] of a failed download.
    ///
    /// # Errors
    ///
    /// Why nothing is asked, for the plugin window (also told in the tray, but for a plugin
    /// installed or being installed already).
    pub fn install_from_catalog(
        self: &Arc<Self>,
        id: &str,
        origin: Option<String>,
    ) -> Result<(), PluginActionError> {
        if self.store.state().plugins.contains_key(id) {
            info!(plugin = id, "installed already");
            return Err(PluginActionError::InstalledAlready);
        }
        let Some(guard) = self.begin_install(id) else {
            return Err(PluginActionError::BeingInstalled);
        };
        let asker = if origin.is_some() {
            Asker::Page
        } else {
            Asker::User
        };
        let failed = |name: Localized, error: String| self.install_failed(id, name, error, asker);
        let Some(index) = self.ensure_index(INDEX_TIMEOUT, asker) else {
            failed(
                same_name(id),
                "the plugin catalog is unavailable".to_owned(),
            );
            return Err(PluginActionError::NoCatalog);
        };
        let state = self.store.state();
        let Some(release) = offer(&index, &self.cfg.core, &state.install_id, &state.bad, |r| {
            r.id == id
        })
        .cloned() else {
            failed(
                same_name(id),
                "the plugin catalog does not offer it".to_owned(),
            );
            return Err(PluginActionError::NotOffered);
        };
        let (package, bytes) = match self.download(&release) {
            Ok(downloaded) => downloaded,
            Err(Download::Unreachable(e)) => {
                failed(localized(&release.name), e.clone());
                return Err(PluginActionError::Failed(e));
            }
            Err(Download::Bad(e)) => {
                self.mark_bad(&release, &e);
                failed(localized(&release.name), e.clone());
                return Err(PluginActionError::Failed(e));
            }
        };
        if let Err(e) = self.cfg.modules.check(&package) {
            self.refused(&release.id, &release.version, &e);
            failed(localized(&release.name), e.to_string());
            return Err(PluginActionError::Failed(e.to_string()));
        }
        self.ask(package, bytes, Source::Catalog, origin, guard);
        Ok(())
    }

    /// Installs the package file at `path` as a local plugin, once the user agreed (warned
    /// that nobody reviewed it). A failure is told ([`PluginNotice::Failed`]).
    ///
    /// # Errors
    ///
    /// Why nothing is asked, for the plugin window.
    pub fn install_from_file(self: &Arc<Self>, path: PathBuf) -> Result<(), PluginActionError> {
        let file_name = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let checked = read_package(&path)
            .map_err(PluginActionError::Failed)
            .and_then(|(package, bytes)| {
                if package.manifest.min_core > self.cfg.core {
                    return Err(PluginActionError::NeedsCore(
                        package.manifest.min_core.to_string(),
                    ));
                }
                self.cfg
                    .modules
                    .check(&package)
                    .map_err(|e| PluginActionError::Failed(e.to_string()))?;
                Ok((package, bytes))
            });
        let (package, bytes) = match checked {
            Ok(checked) => checked,
            Err(e) => {
                let detail = match &e {
                    PluginActionError::NeedsCore(v) => {
                        format!("the plugin needs OpenNCALayer {v} or newer")
                    }
                    PluginActionError::Failed(detail) => detail.clone(),
                    other => format!("{other:?}"),
                };
                warn!(path = %path.display(), error = %detail, "cannot install the plugin file");
                self.failed(same_name(&file_name), detail);
                return Err(e);
            }
        };
        let Some(guard) = self.begin_install(&package.manifest.id) else {
            return Err(PluginActionError::BeingInstalled);
        };
        self.ask(package, bytes, Source::Local, None, guard);
        Ok(())
    }

    /// Turns the installed `id` on (loaded, unless withdrawn) or off (unloaded).
    ///
    /// # Errors
    ///
    /// What failed, for the user: it is not installed, the state cannot be saved, or it
    /// cannot be loaded (it stays on, in error).
    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), PluginActionError> {
        let _change = lock(&self.changing);
        let Some(installed) = self.store.state().plugins.get(id).cloned() else {
            return Err(PluginActionError::NotInstalled);
        };
        self.store
            .set_enabled(id, enabled)
            .map_err(|e| PluginActionError::Failed(e.to_string()))?;
        if !enabled {
            self.cfg.modules.unload(id);
            lock(&self.errors).remove(id);
            lock(&self.conflicts).clear();
            return Ok(());
        }
        if installed.withdrawn {
            return Ok(());
        }
        self.load_installed(id).map_err(PluginActionError::Failed)
    }

    /// Uninstalls `id`: removed from `<data>/plugins/`, then unloaded. If its record is gone
    /// but its package file stays, it is unloaded all the same (and the error returned); if
    /// the record cannot be saved, it stays installed and loaded.
    ///
    /// # Errors
    ///
    /// What failed.
    pub fn remove(&self, id: &str) -> Result<(), PluginActionError> {
        let _change = lock(&self.changing);
        let removed = self.store.remove(id).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound
                && !self.store.state().plugins.contains_key(id)
                && !self.cfg.modules.loaded().iter().any(|p| p.id == id)
            {
                PluginActionError::NotInstalled
            } else {
                PluginActionError::Failed(e.to_string())
            }
        });
        if !self.store.state().plugins.contains_key(id) {
            self.cfg.modules.unload(id);
            lock(&self.errors).remove(id);
            lock(&self.known).remove(id);
            lock(&self.conflicts).clear();
        }
        removed
    }

    /// The newest release of the catalog porting the original's bundle `symname`, if the
    /// catalog has one for this installation. Without a catalog in use one is downloaded,
    /// all within `timeout`: a download already running is waited for within it, and then
    /// used; none within [`PAGE_RETRY_AFTER`] of a failed one.
    pub fn catalog_offer_for_symname(
        &self,
        symname: &str,
        timeout: Duration,
    ) -> Option<PluginRelease> {
        let index = self.ensure_index(timeout, Asker::Page)?;
        let state = self.store.state();
        offer(&index, &self.cfg.core, &state.install_id, &state.bad, |r| {
            r.replaces.as_ref().is_some_and(|p| p.symname == symname)
        })
        .cloned()
    }

    /// A request named `module`, which nothing serves: if a plugin of the catalog in use
    /// would, and is not installed, the page's need is listed, and told (the plugin window
    /// read again) when its entry changes: a plugin newly needed, or by another page. Never
    /// downloads.
    fn missing(&self, module: &str, add_info: &AddInfo) {
        let Some(index) = self.valid_index() else {
            return;
        };
        let state = self.store.state();
        let Some(release) = offer(&index, &self.cfg.core, &state.install_id, &state.bad, |r| {
            r.modules.iter().any(|m| m == module)
        }) else {
            return;
        };
        if state.plugins.contains_key(&release.id) {
            return;
        }
        let before = lock(&self.needed).insert(release.id.clone(), add_info.origin.clone());
        if before.as_ref() == Some(&add_info.origin) {
            return;
        }
        info!(plugin = %release.id, module, origin = ?add_info.origin, "a page needs a plugin of the catalog");
        (self.cfg.notify)(PluginNotice::Needed {
            origin: add_info.origin.clone(),
            name: localized(&release.name),
            id: release.id.clone(),
        });
    }

    /// Downloads the catalog of the channel in the settings within `timeout`, verifies it
    /// and keeps it.
    fn refresh(&self, timeout: Duration) -> Result<(), Refresh> {
        if self.cfg.keys.is_empty() {
            return Err(Refresh::NoKeys);
        }
        let one = lock(&self.checking);
        self.refresh_locked(&one, timeout)
    }

    /// [`PluginService::refresh`], `checking` held.
    fn refresh_locked(&self, _one: &MutexGuard<'_, ()>, timeout: Duration) -> Result<(), Refresh> {
        let channel = self.update_settings().channel;
        let result = self.download_catalog(channel, timeout);
        let mut catalog = lock(&self.catalog);
        match &result {
            Ok(index) => {
                info!(%channel, seq = index.seq, plugins = index.plugins.len(), "the plugin catalog is downloaded");
                catalog.index = Some(index.clone());
                catalog.checked = Some(OffsetDateTime::now_utc());
                catalog.error = None;
                catalog.failed_at = None;
            }
            Err(Refresh::NotPublished) => {
                catalog.error = None;
                catalog.failed_at = Some(Instant::now());
            }
            Err(Refresh::Unreachable(e) | Refresh::Refused(e)) => {
                catalog.error = Some(e.clone());
                catalog.failed_at = Some(Instant::now());
            }
            Err(Refresh::NoKeys) => {}
        }
        result.map(drop)
    }

    fn download_catalog(&self, channel: Channel, timeout: Duration) -> Result<Index, Refresh> {
        let fetched = fetch(&*self.cfg.http, &self.cfg.base, channel, timeout).map_err(|e| {
            if let UpdateError::NotPublished(_) = e {
                info!(%channel, "the channel has no update index yet: no plugin catalog");
                Refresh::NotPublished
            } else {
                info!(error = %e, %channel, "cannot download the plugin catalog");
                Refresh::Unreachable(e.to_string())
            }
        })?;
        let last_seq = self.store.state().last_seq.get(&channel).copied();
        let index = verify(
            &fetched.index,
            &fetched.signature,
            &self.cfg.keys,
            channel,
            last_seq,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| {
            warn!(error = %e, %channel, "the plugin catalog is refused");
            Refresh::Refused(e.to_string())
        })?;
        // A catalog whose `seq` is not recorded is not used.
        self.store
            .save_catalog(channel, &fetched.index, &fetched.signature)
            .map_err(|e| {
                warn!(error = %e, "cannot keep the plugin catalog");
                Refresh::Unreachable(e.to_string())
            })?;
        Ok(index)
    }

    /// The catalog of the channel in the settings, if one in use still holds: the one
    /// downloaded, or the one kept in `<data>/plugins/` (verified again).
    fn valid_index(&self) -> Option<Index> {
        if self.cfg.keys.is_empty() {
            return None;
        }
        let channel = self.update_settings().channel;
        let now = OffsetDateTime::now_utc();
        let mut catalog = lock(&self.catalog);
        if let Some(index) = &catalog.index
            && index.channel == channel
            && fresh(index, now)
        {
            return Some(index.clone());
        }
        let kept = self.store.load_catalog(channel, &self.cfg.keys, now);
        catalog.index.clone_from(&kept);
        kept
    }

    /// [`PluginService::valid_index`], or one downloaded within `timeout`. A download
    /// already running is waited for: fully for the user, or only within `timeout` for a
    /// page (then `None` once it runs out); a catalog it brought is used, else a download of
    /// our own gets the time left. A page does not download within [`PAGE_RETRY_AFTER`] of a
    /// failed download. With updates on, a catalog downloaded here is applied in the
    /// background.
    fn ensure_index(&self, timeout: Duration, asker: Asker) -> Option<Index> {
        if let Some(index) = self.valid_index() {
            return Some(index);
        }
        if self.cfg.keys.is_empty() || self.page_waits_out_failure(asker) {
            return None;
        }
        let wait = asker == Asker::User;
        let deadline = std::time::Instant::now() + timeout;
        let one = if wait {
            lock(&self.checking)
        } else {
            loop {
                match self.checking.try_lock() {
                    Ok(one) => break one,
                    Err(TryLockError::Poisoned(e)) => break e.into_inner(),
                    Err(TryLockError::WouldBlock) => {
                        if std::time::Instant::now() >= deadline {
                            info!("the plugin catalog download running took too long; not waiting");
                            return None;
                        }
                        thread::sleep(CATALOG_POLL);
                    }
                }
            }
        };
        if let Some(index) = self.valid_index() {
            return Some(index);
        }
        if self.page_waits_out_failure(asker) {
            return None;
        }
        let left = if wait {
            timeout
        } else {
            deadline.saturating_duration_since(std::time::Instant::now())
        };
        if left.is_zero() {
            return None;
        }
        self.refresh_locked(&one, left).ok()?;
        drop(one);
        if self.update_settings().enabled
            && let Some(service) = self.me.upgrade()
        {
            let spawned = thread::Builder::new()
                .name("plugins-apply".into())
                .spawn(move || service.apply_catalog());
            if let Err(e) = spawned {
                warn!(error = %e, "cannot start a thread: the plugin catalog is not applied");
            }
        }
        self.valid_index()
    }

    /// Whether `asker` is a page and the last catalog download failed within
    /// [`PAGE_RETRY_AFTER`]: the page does without a catalog then.
    fn page_waits_out_failure(&self, asker: Asker) -> bool {
        let recent = lock(&self.catalog)
            .failed_at
            .is_some_and(|at| at.elapsed() < PAGE_RETRY_AFTER);
        if asker == Asker::Page && recent {
            info!("the plugin catalog failed to download a moment ago; not again for a page");
            return true;
        }
        false
    }

    /// Moves each plugin installed from the catalog to the version the catalog in use
    /// chooses for it. One application at a time: one asked for while another runs marks
    /// itself pending, and the running one goes over the newest catalog once more. Each
    /// plugin is changed under `changing`, and only if it is still the one installed from
    /// the catalog at the version the choice was made for.
    fn apply_catalog(&self) {
        let _one = match self.applying.try_lock() {
            Ok(one) => one,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => {
                info!("the plugin catalog is being applied already; it goes over it again");
                self.apply_pending.store(true, Ordering::SeqCst);
                return;
            }
        };
        loop {
            self.apply_pending.store(false, Ordering::SeqCst);
            if let Some(index) = self.valid_index() {
                self.apply_index(&index);
            }
            if !self.apply_pending.swap(false, Ordering::SeqCst) {
                break;
            }
        }
    }

    /// One pass of [`PluginService::apply_catalog`] over `index`.
    fn apply_index(&self, index: &Index) {
        let state = self.store.state();
        for (id, snapshot) in &state.plugins {
            if snapshot.source != Source::Catalog {
                continue;
            }
            let mut bad = state.bad.get(id).cloned().unwrap_or_default();
            bad.extend(lock(&self.conflicts).get(id).into_iter().flatten().cloned());
            match choose_plugin(
                index,
                id,
                &snapshot.version,
                &self.cfg.core,
                &state.install_id,
                &bad,
            ) {
                PluginChoice::Keep => {
                    let listed = index
                        .plugins
                        .iter()
                        .any(|r| r.id == *id && r.version == snapshot.version && !r.revoked);
                    if !(snapshot.withdrawn && listed) {
                        continue;
                    }
                    let _change = lock(&self.changing);
                    let Some(fresh) = self.still(id, snapshot) else {
                        continue;
                    };
                    info!(plugin = %id, "the plugin's version is no longer revoked");
                    if let Err(e) = self.store.set_withdrawn(id, false) {
                        warn!(plugin = %id, error = %e, "cannot record the plugin's state");
                    } else if fresh.enabled {
                        let _ = self.load_installed(id);
                    }
                }
                PluginChoice::Update(release) | PluginChoice::Downgrade(release) => {
                    self.update_to(release, snapshot);
                }
                PluginChoice::Withdrawn if !snapshot.withdrawn => {
                    let _change = lock(&self.changing);
                    if self.still(id, snapshot).is_none() {
                        continue;
                    }
                    warn!(plugin = %id, version = %snapshot.version, "the plugin's version is revoked; it is turned off");
                    self.cfg.modules.unload(id);
                    lock(&self.conflicts).clear();
                    if let Err(e) = self.store.set_withdrawn(id, true) {
                        warn!(plugin = %id, error = %e, "cannot record the plugin's state");
                    }
                    (self.cfg.notify)(PluginNotice::Withdrawn {
                        name: self.name_of(id),
                    });
                }
                PluginChoice::Withdrawn => {}
            }
        }
    }

    /// The installed `id` as it is now, if it is still `snapshot`'s: from the catalog, at
    /// the same version. Call it holding `changing`.
    fn still(&self, id: &str, snapshot: &Installed) -> Option<Installed> {
        let fresh = self.store.state().plugins.get(id).cloned();
        let same = fresh
            .as_ref()
            .is_some_and(|f| f.source == Source::Catalog && f.version == snapshot.version);
        if !same {
            info!(
                plugin = id,
                "the plugin changed meanwhile; the catalog leaves it alone"
            );
        }
        fresh.filter(|_| same)
    }

    /// Installs `release` over `snapshot`, the version installed when it was chosen:
    /// downloaded and checked, then, under `changing` and only if the plugin is still
    /// `snapshot`, loaded (if it is on; else checked only) and recorded.
    fn update_to(&self, release: &PluginRelease, snapshot: &Installed) {
        info!(plugin = %release.id, version = %release.version, "updating the plugin");
        let (package, bytes) = match self.download(release) {
            Ok(downloaded) => downloaded,
            Err(Download::Unreachable(e)) => {
                // Quietly: the next check tries again.
                warn!(plugin = %release.id, error = %e, "cannot download the plugin's update");
                return;
            }
            Err(Download::Bad(e)) => return self.bad(release, e),
        };
        let _change = lock(&self.changing);
        let Some(fresh) = self.still(&release.id, snapshot) else {
            return;
        };
        let enabled = fresh.enabled;
        let loaded = if enabled {
            self.cfg.modules.load(package.clone())
        } else {
            self.cfg.modules.check(&package)
        };
        if let Err(e) = loaded {
            self.refused(&release.id, &release.version, &e);
            return self.failed(localized(&release.name), e.to_string());
        }
        if let Err(e) = self.store.install(&package, &bytes, Source::Catalog) {
            warn!(plugin = %release.id, error = %e, "cannot record the plugin's update");
            if enabled {
                // The version recorded runs again.
                let _ = self.load_installed(&release.id);
            }
            return self.failed(localized(&release.name), e.to_string());
        }
        self.remember(&package);
        lock(&self.errors).remove(&release.id);
        lock(&self.conflicts).clear();
        (self.cfg.notify)(PluginNotice::Updated {
            name: package.manifest.name.clone(),
            version: package.manifest.version.clone(),
        });
    }

    /// Downloads the package of `release` and checks it against the index and this core.
    fn download(&self, release: &PluginRelease) -> Result<(Package, Vec<u8>), Download> {
        let package = &release.package;
        if !package.url.starts_with("https://") {
            return Err(Download::Bad(format!(
                "{} is not an https URL",
                package.url
            )));
        }
        let bytes = fetch_package(&*self.cfg.http, package, DOWNLOAD_TIMEOUT)
            .map_err(Download::Unreachable)?;
        if bytes.len() as u64 != package.size {
            return Err(Download::Bad(format!(
                "{}: {} bytes, the index says {}",
                package.url,
                bytes.len(),
                package.size
            )));
        }
        if Sha256::of(&bytes) != package.sha256 {
            return Err(Download::Bad(format!(
                "{}: the sha256 does not match the index",
                package.url
            )));
        }
        let read = Package::read(&bytes).map_err(|e| Download::Bad(e.to_string()))?;
        check_manifest(&read, release, &self.cfg.core).map_err(Download::Bad)?;
        Ok((read, bytes))
    }

    /// Asks the user about `package`; installs it if they agree.
    fn ask(
        self: &Arc<Self>,
        package: Package,
        bytes: Vec<u8>,
        source: Source,
        origin: Option<String>,
        guard: Installing,
    ) {
        let m = &package.manifest;
        let request = InstallRequest {
            origin,
            name: m.name.clone(),
            version: m.version.clone(),
            replaces: m.replaces.clone(),
            replacing: self
                .store
                .state()
                .plugins
                .get(&m.id)
                .map(|installed| (installed.version.clone(), installed.source)),
            capabilities: m.capabilities.clone(),
            local: source == Source::Local,
        };
        let service = Arc::downgrade(self);
        self.cfg.ui.confirm(
            request,
            Box::new(move |yes| {
                let _guard = guard;
                let Some(service) = service.upgrade() else {
                    return;
                };
                if yes {
                    service.finish_install(package, &bytes, source);
                } else {
                    info!(plugin = %package.manifest.id, "the user declined the plugin");
                }
            }),
        );
    }

    /// Loads `package`, then records it.
    fn finish_install(&self, package: Package, bytes: &[u8], source: Source) {
        let _change = lock(&self.changing);
        let id = package.manifest.id.clone();
        let name = package.manifest.name.clone();
        if let Err(e) = self.cfg.modules.load(package.clone()) {
            warn!(plugin = %id, error = %e, "cannot load the plugin");
            if source == Source::Catalog {
                self.refused(&id, &package.manifest.version, &e);
            }
            return self.failed(name, e.to_string());
        }
        if let Err(e) = self.store.install(&package, bytes, source) {
            warn!(plugin = %id, error = %e, "cannot record the plugin");
            self.cfg.modules.unload(&id);
            // The version installed before, if any, runs again.
            if self.store.state().plugins.contains_key(&id) {
                let _ = self.load_installed(&id);
            }
            return self.failed(name, e.to_string());
        }
        if self
            .store
            .state()
            .plugins
            .get(&id)
            .is_some_and(|installed| !installed.enabled)
        {
            // Installed again over one turned off: it stays off.
            self.cfg.modules.unload(&id);
        }
        info!(plugin = %id, version = %package.manifest.version, ?source, "plugin installed");
        lock(&self.conflicts).clear();
        self.remember(&package);
        lock(&self.errors).remove(&id);
        lock(&self.needed).remove(&id);
        (self.cfg.notify)(PluginNotice::Installed { name });
    }

    /// Loads the installed `id` from its package; a failure is kept for the plugin window.
    fn load_installed(&self, id: &str) -> Result<(), String> {
        let loaded = self
            .store
            .load_package(id)
            .map_err(|e| e.to_string())
            .and_then(|package| {
                self.remember(&package);
                if package.manifest.min_core > self.cfg.core {
                    return Err(format!(
                        "the plugin needs OpenNCALayer {} or newer",
                        package.manifest.min_core
                    ));
                }
                self.cfg.modules.load(package).map_err(|e| e.to_string())
            });
        match &loaded {
            Ok(()) => {
                lock(&self.errors).remove(id);
            }
            Err(e) => {
                warn!(plugin = id, error = %e, "cannot load the installed plugin");
                lock(&self.errors).insert(id.to_owned(), e.clone());
            }
        }
        loaded
    }

    /// Reads the installed `id`'s name from its package, for the plugin window.
    fn read_known(&self, id: &str) {
        match self.store.load_package(id) {
            Ok(package) => self.remember(&package),
            Err(e) => {
                warn!(plugin = id, error = %e, "cannot read the installed plugin");
                lock(&self.errors).insert(id.to_owned(), e.to_string());
            }
        }
    }

    fn remember(&self, package: &Package) {
        lock(&self.known).insert(
            package.manifest.id.clone(),
            Known {
                name: package.manifest.name.clone(),
                replaces: package.manifest.replaces.clone(),
            },
        );
    }

    fn name_of(&self, id: &str) -> Localized {
        lock(&self.known)
            .get(id)
            .map_or_else(|| same_name(id), |k| k.name.clone())
    }

    /// `id` marked as being installed, until the returned guard goes; `None` if it is
    /// already.
    fn begin_install(self: &Arc<Self>, id: &str) -> Option<Installing> {
        if !lock(&self.installing).insert(id.to_owned()) {
            info!(plugin = id, "being installed already");
            return None;
        }
        Some(Installing {
            service: Arc::downgrade(self),
            id: id.to_owned(),
        })
    }

    /// `release` failed its checks here: marked bad, the user told.
    fn bad(&self, release: &PluginRelease, error: String) {
        self.mark_bad(release, &error);
        self.failed(localized(&release.name), error);
    }

    /// `release` failed its checks here: marked bad.
    fn mark_bad(&self, release: &PluginRelease, error: &str) {
        self.mark_version_bad(&release.id, &release.version, error);
    }

    fn mark_version_bad(&self, id: &str, version: &Version, error: &str) {
        warn!(plugin = id, %version, error = %error, "the plugin's package is refused; the version is marked bad");
        if let Err(e) = self.store.mark_bad(id, version) {
            warn!(plugin = id, error = %e, "cannot record the plugin's failure");
        }
    }

    /// The catalog's `version` of `id` could not be loaded (or checked): marked bad if the
    /// package is at fault; if another plugin serves one of its modules, which depends on
    /// this installation and not on the package, only kept from updates until the plugins
    /// change.
    fn refused(&self, id: &str, version: &Version, e: &LoadError) {
        if matches!(e, LoadError::ModuleTaken { owner, .. } if owner != BUILT_IN) {
            warn!(plugin = id, %version, error = %e, "another plugin serves a module of the plugin; the version is not marked bad");
            lock(&self.conflicts)
                .entry(id.to_owned())
                .or_default()
                .insert(version.clone());
        } else {
            self.mark_version_bad(id, version, &e.to_string());
        }
    }

    /// The install of `id` failed: told, but for one a page started only if no failure of
    /// `id`'s was told within [`PAGE_FAILURE_EVERY`] (a page may ask again and again).
    fn install_failed(&self, id: &str, name: Localized, error: String, asker: Asker) {
        if asker == Asker::Page {
            let mut told = lock(&self.page_failures);
            if told
                .get(id)
                .is_some_and(|at| at.elapsed() < PAGE_FAILURE_EVERY)
            {
                info!(plugin = id, error = %error, "a page's install of the plugin failed again; told already");
                return;
            }
            told.insert(id.to_owned(), Instant::now());
        }
        self.failed(name, error);
    }

    fn failed(&self, name: Localized, error: String) {
        (self.cfg.notify)(PluginNotice::Failed { name, error });
    }

    fn update_settings(&self) -> UpdateSettings {
        load_settings(&self.cfg.settings).updates
    }
}

/// A plugin being installed: [`PluginService::begin_install`].
struct Installing {
    service: Weak<PluginService>,
    id: String,
}

impl Drop for Installing {
    fn drop(&mut self) {
        if let Some(service) = self.service.upgrade() {
            lock(&service.installing).remove(&self.id);
        }
    }
}

/// Whether `package`'s manifest is the one `release` describes, for `core`.
fn check_manifest(
    package: &Package,
    release: &PluginRelease,
    core: &Version,
) -> Result<(), String> {
    let m = &package.manifest;
    let differs = |what: &str| Err(format!("the package's {what} differs from the index"));
    if m.id != release.id {
        return differs("id");
    }
    if m.version != release.version {
        return differs("version");
    }
    if m.modules != release.modules {
        return differs("modules");
    }
    let replaces = m.replaces.as_ref().map(|r| (&r.symname, &r.version));
    let listed = release.replaces.as_ref().map(|r| (&r.symname, &r.version));
    if replaces != listed {
        return differs("replaces");
    }
    if m.min_core > *core {
        return Err(format!(
            "the plugin needs OpenNCALayer {} or newer",
            m.min_core
        ));
    }
    Ok(())
}

/// The package file at `path` and its bytes.
fn read_package(path: &Path) -> Result<(Package, Vec<u8>), String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let package = Package::read(&bytes).map_err(|e| e.to_string())?;
    Ok((package, bytes))
}

/// Whether `index` is still within its validity at `now`.
fn fresh(index: &Index, now: OffsetDateTime) -> bool {
    let deadline = index
        .generated
        .checked_add(MAX_AGE)
        .map_or(index.expires, |aged| aged.min(index.expires));
    now < deadline
}

fn localized(name: &PluginName) -> Localized {
    Localized {
        ru: name.ru.clone(),
        kk: name.kk.clone(),
        en: name.en.clone(),
    }
}

fn replaces_of(release: &PluginRelease) -> Option<Replaces> {
    release.replaces.as_ref().map(|r| Replaces {
        symname: r.symname.clone(),
        version: r.version.clone(),
    })
}

/// `text` in every language: a name not known otherwise.
fn same_name(text: &str) -> Localized {
    Localized {
        ru: text.to_owned(),
        kk: text.to_owned(),
        en: text.to_owned(),
    }
}

/// How long `installBundle` waits for the catalog when none is in use.
pub const OFFER_TIMEOUT: Duration = Duration::from_secs(10);

impl Bundles for PluginService {
    fn services(&self) -> Vec<String> {
        self.cfg.modules.names()
    }

    fn bundles(&self) -> Vec<(String, String)> {
        self.cfg
            .modules
            .loaded()
            .into_iter()
            .filter_map(|plugin| plugin.replaces.map(|r| (r.symname, r.version)))
            .collect()
    }

    /// Looks in the catalog in use (downloaded within [`OFFER_TIMEOUT`] if there is none)
    /// for a plugin porting `symname`; one not installed is installed in the background
    /// (the user is asked) and `true` returned.
    fn request_install(&self, symname: &str, origin: &str) -> bool {
        let Some(release) = self.catalog_offer_for_symname(symname, OFFER_TIMEOUT) else {
            return false;
        };
        let installed = self.store.state().plugins.contains_key(&release.id)
            || self.cfg.modules.loaded().iter().any(|p| {
                p.id == release.id || p.replaces.as_ref().is_some_and(|r| r.symname == symname)
            });
        if installed {
            return false;
        }
        if lock(&self.installing).contains(&release.id) {
            // Going on already: the page's request is served by it.
            info!(plugin = %release.id, "being installed already");
            return true;
        }
        let Some(service) = self.me.upgrade() else {
            return false;
        };
        let origin = origin.to_owned();
        let spawned = thread::Builder::new()
            .name("plugin-install".into())
            .spawn(move || service.install_from_catalog(&release.id, Some(origin)));
        match spawned {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "cannot start a thread: the plugin is not installed");
                false
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub mod window;

#[cfg(test)]
mod tests;
