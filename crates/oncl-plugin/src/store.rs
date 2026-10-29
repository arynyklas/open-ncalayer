//! `<data>/plugins/`: the installed plugins and what is kept about them between runs.
//!
//! - `state.json` ([`StoreState`]): the installed plugins, the versions that failed here, the
//!   install id of the rollouts and the highest `seq` of each catalog accepted;
//! - `packages/<id>-<version>.onclp`: the package of each installed plugin, as downloaded or
//!   chosen;
//! - `catalog/<channel>.json` and `catalog/<channel>.json.minisig`: the last update index of
//!   the channel accepted, verified again whenever it is read.
//!
//! Every file is replaced atomically ([`write_atomically`]); every change of the state is
//! made under one lock and saved before it is seen.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use oncl_pki::fsutil::{Access, write_atomically};
use oncl_update::{Channel, Index, PublicKey, Sha256, Version, verify};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{MAX_PACKAGE, PACKAGE_EXT, Package, PackageError};

/// What is kept between runs: `<data>/plugins/state.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreState {
    /// This installation's random id, for the rollout buckets of plugin releases; never sent
    /// anywhere. Drawn anew if missing.
    #[serde(with = "hex16", default = "random_install_id")]
    pub install_id: [u8; 16],
    /// The highest `seq` of each channel's catalog accepted: an older one is refused.
    #[serde(default)]
    pub last_seq: BTreeMap<Channel, u64>,
    /// The installed plugins, by id.
    #[serde(default)]
    pub plugins: BTreeMap<String, Installed>,
    /// Versions of plugins that failed to load here, by id: never offered again.
    #[serde(default)]
    pub bad: BTreeMap<String, BTreeSet<Version>>,
}

/// An installed plugin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    pub version: Version,
    /// The sum of its package file: the file is not loaded if it no longer matches.
    pub sha256: Sha256,
    pub source: Source,
    /// Turned on: its modules are served.
    pub enabled: bool,
    /// Its version is revoked in the catalog with nothing to move to: it is not loaded.
    #[serde(default)]
    pub withdrawn: bool,
}

/// Where an installed plugin came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The catalog (the signed update index): updated and withdrawn by it.
    Catalog,
    /// A file the user chose: never touched by the catalog.
    Local,
}

/// Why an installed plugin's package cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No plugin of this id is installed.
    #[error("the plugin {0} is not installed")]
    NotInstalled(String),
    /// The package file cannot be read.
    #[error("the plugin package cannot be read: {0}")]
    Io(#[from] io::Error),
    /// The package file is not the one installed: its sha256 differs.
    #[error("the plugin package was changed after its installation")]
    Tampered,
    /// The package file is not a valid package.
    #[error(transparent)]
    Package(#[from] PackageError),
    /// The package is valid, but of another plugin or version.
    #[error("the plugin package is of {0}")]
    Mismatch(String),
}

/// The plugins' directory; see the [module](self).
pub struct Store {
    dir: PathBuf,
    state: Mutex<StoreState>,
}

impl StoreState {
    /// Nothing installed, nothing seen, a new random install id.
    pub fn fresh() -> StoreState {
        StoreState {
            install_id: random_install_id(),
            last_seq: BTreeMap::new(),
            plugins: BTreeMap::new(),
            bad: BTreeMap::new(),
        }
    }
}

impl Store {
    /// The store in `<data_dir>/plugins/`, created if missing. A missing `state.json` starts
    /// a fresh state, saved at once (its install id is kept); one that is not a state
    /// (damaged) is replaced by a fresh state (logged).
    ///
    /// # Errors
    ///
    /// Any other error reading the state, and any error creating the directory or saving a
    /// fresh state.
    pub fn open(data_dir: &Path) -> io::Result<Store> {
        let dir = data_dir.join("plugins");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("state.json");
        let (state, save) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<StoreState>(&bytes) {
                Ok(state) => (state, false),
                Err(e) => {
                    tracing::warn!(error = %e, "the plugins' state is broken; starting a new one");
                    (StoreState::fresh(), true)
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (StoreState::fresh(), true),
            Err(e) => return Err(e),
        };
        let store = Store {
            dir,
            state: Mutex::new(state),
        };
        if save {
            store.save(&lock(&store.state))?;
        }
        Ok(store)
    }

    /// The state now.
    pub fn state(&self) -> StoreState {
        lock(&self.state).clone()
    }

    /// Installs `package`, whose file is `bytes`, from `source`: the package file is written,
    /// then the state; the package of the version installed before, if another, is removed
    /// after that. A plugin installed before keeps whether it is enabled; a new one is
    /// enabled. It is no longer withdrawn.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] if `bytes` is not `package`'s file; any I/O error
    /// writing the package or the state (nothing is installed then).
    pub fn install(&self, package: &Package, bytes: &[u8], source: Source) -> io::Result<()> {
        let sha256 = Sha256::of(bytes);
        if sha256.0 != package.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the bytes are not the package's file",
            ));
        }
        let id = &package.manifest.id;
        let version = &package.manifest.version;
        let mut state = lock(&self.state);
        let file = self.package_path(id, version);
        std::fs::create_dir_all(self.dir.join("packages"))?;
        write_atomically(&file, bytes, Access::Default)?;
        let before = state.plugins.get(id).cloned();
        let mut next = state.clone();
        next.plugins.insert(
            id.clone(),
            Installed {
                version: version.clone(),
                sha256,
                source,
                enabled: before.as_ref().is_none_or(|b| b.enabled),
                withdrawn: false,
            },
        );
        if let Err(e) = self.save(&next) {
            if before.as_ref().is_none_or(|b| b.version != *version) {
                remove_file(&file);
            }
            return Err(e);
        }
        *state = next;
        if let Some(before) = before
            && before.version != *version
        {
            remove_file(&self.package_path(id, &before.version));
        }
        Ok(())
    }

    /// Uninstalls `id`: the state, then its package file.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if it is not installed; any I/O error saving the state
    /// (it stays installed then) or removing the package file (it is uninstalled, the file
    /// stays).
    pub fn remove(&self, id: &str) -> io::Result<()> {
        let mut state = lock(&self.state);
        let mut next = state.clone();
        let Some(removed) = next.plugins.remove(id) else {
            return Err(not_installed(id));
        };
        self.save(&next)?;
        *state = next;
        match std::fs::remove_file(self.package_path(id, &removed.version)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Turns `id` on or off.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if it is not installed; any I/O error saving the state.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> io::Result<()> {
        self.change_installed(id, |installed| installed.enabled = enabled)
    }

    /// Marks `id` withdrawn by the catalog, or not.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::NotFound`] if it is not installed; any I/O error saving the state.
    pub fn set_withdrawn(&self, id: &str, withdrawn: bool) -> io::Result<()> {
        self.change_installed(id, |installed| installed.withdrawn = withdrawn)
    }

    /// Marks `version` of `id` as failing here: it is not offered again.
    ///
    /// # Errors
    ///
    /// Any I/O error saving the state.
    pub fn mark_bad(&self, id: &str, version: &Version) -> io::Result<()> {
        self.change(|state| {
            state
                .bad
                .entry(id.to_owned())
                .or_default()
                .insert(version.clone());
        })
    }

    /// The package of the installed `id`, checked against the sum recorded at its
    /// installation and against its id and version.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn load_package(&self, id: &str) -> Result<Package, StoreError> {
        let installed = lock(&self.state)
            .plugins
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotInstalled(id.to_owned()))?;
        let file = std::fs::File::open(self.package_path(id, &installed.version))?;
        let mut bytes = Vec::new();
        file.take(MAX_PACKAGE + 1).read_to_end(&mut bytes)?;
        if Sha256::of(&bytes) != installed.sha256 {
            return Err(StoreError::Tampered);
        }
        let package = Package::read(&bytes)?;
        let manifest = &package.manifest;
        if manifest.id != id || manifest.version != installed.version {
            return Err(StoreError::Mismatch(format!(
                "{} {}",
                manifest.id, manifest.version
            )));
        }
        Ok(package)
    }

    /// Keeps the index of `channel` and its signature, which the caller has verified, and
    /// raises the channel's `last_seq` to its `seq`.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`] if `index` is not an index; any I/O error.
    pub fn save_catalog(&self, channel: Channel, index: &[u8], sig: &[u8]) -> io::Result<()> {
        let seq = Index::from_json(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .seq;
        let dir = self.dir.join("catalog");
        std::fs::create_dir_all(&dir)?;
        let (index_path, sig_path) = self.catalog_paths(channel);
        write_atomically(&index_path, index, Access::Default)?;
        write_atomically(&sig_path, sig, Access::Default)?;
        self.change(|state| {
            let last = state.last_seq.entry(channel).or_insert(seq);
            *last = (*last).max(seq);
        })
    }

    /// The kept index of `channel`, verified again with `keys`, the channel's `last_seq` and
    /// `now`; `None` if there is none, or it no longer holds (expired, among others: logged).
    pub fn load_catalog(
        &self,
        channel: Channel,
        keys: &[PublicKey],
        now: OffsetDateTime,
    ) -> Option<Index> {
        let (index_path, sig_path) = self.catalog_paths(channel);
        let read = |path: &Path| match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read the kept plugin catalog");
                None
            }
        };
        let index = read(&index_path)?;
        let sig = read(&sig_path)?;
        let last_seq = lock(&self.state).last_seq.get(&channel).copied();
        match verify(&index, &sig, keys, channel, last_seq, now) {
            Ok(index) => Some(index),
            Err(e) => {
                tracing::info!(%channel, error = %e, "the kept plugin catalog no longer holds");
                None
            }
        }
    }

    /// `packages/<id>-<version>.onclp`.
    fn package_path(&self, id: &str, version: &Version) -> PathBuf {
        self.dir
            .join("packages")
            .join(format!("{id}-{version}.{PACKAGE_EXT}"))
    }

    fn catalog_paths(&self, channel: Channel) -> (PathBuf, PathBuf) {
        let dir = self.dir.join("catalog");
        (
            dir.join(format!("{channel}.json")),
            dir.join(format!("{channel}.json.minisig")),
        )
    }

    /// Applies `f` to the installed `id` and saves the state.
    fn change_installed(&self, id: &str, f: impl FnOnce(&mut Installed)) -> io::Result<()> {
        let mut state = lock(&self.state);
        let mut next = state.clone();
        let Some(installed) = next.plugins.get_mut(id) else {
            return Err(not_installed(id));
        };
        f(installed);
        if next != *state {
            self.save(&next)?;
            *state = next;
        }
        Ok(())
    }

    /// Applies `f` to the state and saves it if it changed.
    fn change(&self, f: impl FnOnce(&mut StoreState)) -> io::Result<()> {
        let mut state = lock(&self.state);
        let mut next = state.clone();
        f(&mut next);
        if next != *state {
            self.save(&next)?;
            *state = next;
        }
        Ok(())
    }

    fn save(&self, state: &StoreState) -> io::Result<()> {
        let mut body = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
        body.push(b'\n');
        write_atomically(&self.dir.join("state.json"), &body, Access::Default)
    }
}

fn not_installed(id: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("the plugin {id} is not installed"),
    )
}

/// Removes a package file that is no longer installed; a failure is only logged.
fn remove_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), error = %e, "cannot remove an old plugin package");
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn random_install_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("operating system RNG failed");
    id
}

/// 16 bytes as 32 lowercase hexadecimal digits.
mod hex16 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        let text: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&text)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let text = String::deserialize(d)?;
        let bad = || D::Error::custom("expected 32 lowercase hexadecimal digits");
        let digits = text.as_bytes();
        if digits.len() != 32
            || !digits
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(bad());
        }
        let mut bytes = [0u8; 16];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| bad())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
        }
        Ok(bytes)
    }
}
