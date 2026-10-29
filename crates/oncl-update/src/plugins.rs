//! Plugin releases in the signed channel index, and the version an installation may use.

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{Index, Package, UpdateError};

/// A version of one plugin, independently released from the core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRelease {
    /// Its stable identifier, also used in the package's manifest.
    pub id: String,
    /// The version of our port, not the original bundle's version.
    pub version: Version,
    /// The immutable package URL, hash and byte size.
    #[serde(flatten)]
    pub package: Package,
    /// The oldest core version this plugin can run on.
    pub min_core: Version,
    /// Protocol module names provided by this plugin.
    pub modules: Vec<String>,
    /// The original NCALayer bundle this port replaces, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<PluginReplaces>,
    /// Its name in the three interface languages.
    pub name: PluginName,
    /// Percentage of installations offered this release, from zero to 100.
    pub rollout: u8,
    /// Stop offering this release and move installed copies away from it.
    #[serde(default)]
    pub revoked: bool,
}

/// The symbolic name and version exposed to sites as an installed original bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginReplaces {
    /// Its original OSGi symbolic name.
    pub symname: String,
    /// Its original version; OSGi versions need not be semver.
    pub version: String,
}

/// A plugin's display name in each supported language.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginName {
    /// Russian.
    pub ru: String,
    /// Kazakh.
    pub kk: String,
    /// English.
    pub en: String,
}

impl PluginRelease {
    pub(crate) fn check(&self) -> Result<(), UpdateError> {
        let invalid = |field| {
            UpdateError::Malformed(format!(
                "plugin {} {}: invalid {field}",
                self.id, self.version
            ))
        };
        if !valid_id(&self.id) {
            return Err(invalid("id"));
        }
        if self.rollout > 100 {
            return Err(invalid("rollout (must not exceed 100)"));
        }
        let mut names = BTreeSet::new();
        if self.modules.is_empty()
            || self.modules.len() > 32
            || self
                .modules
                .iter()
                .any(|name| !valid_module(name) || !names.insert(name))
        {
            return Err(invalid("modules"));
        }
        for name in [&self.name.ru, &self.name.kk, &self.name.en] {
            if name.trim().is_empty() || name.chars().count() > 128 {
                return Err(invalid("name"));
            }
        }
        if let Some(replaces) = &self.replaces
            && (!valid_module(&replaces.symname)
                || replaces.version.trim().is_empty()
                || replaces.version.chars().count() > 64)
        {
            return Err(invalid("replaces"));
        }
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    (3..=64).contains(&id.len())
        && id.contains('.')
        && id
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

fn valid_module(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The rollout bucket of `install_id` for one plugin release, from zero to 99.
///
/// It hashes `install_id ‖ id ‖ 0x00 ‖ version`, so separate plugins do not share a rollout.
pub fn plugin_bucket(install_id: &[u8; 16], id: &str, version: &Version) -> u8 {
    let digest = sha2::Sha256::new()
        .chain_update(install_id)
        .chain_update(id.as_bytes())
        .chain_update([0])
        .chain_update(version.to_string().as_bytes())
        .finalize();
    (u16::from(digest[0]) * 100 / 256) as u8
}

/// What to do with an installed plugin after accepting a new channel index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PluginChoice<'a> {
    /// Leave the installed version alone.
    Keep,
    /// Load a newer version without restarting the core.
    Update(&'a PluginRelease),
    /// Replace a revoked version with an older release.
    Downgrade(&'a PluginRelease),
    /// The installed version is revoked and no eligible replacement exists.
    Withdrawn,
}

/// Chooses a plugin update compatible with `core` and not known to fail here.
///
/// Ordinary updates respect rollout and never downgrade. Revocation bypasses rollout:
/// getting off the withdrawn version takes precedence, including by downgrade. If no
/// safe replacement exists the caller must unload it. An unlisted current version alone
/// never causes a downgrade or removal.
pub fn choose_plugin<'a>(
    index: &'a Index,
    id: &str,
    current: &Version,
    core: &Version,
    install_id: &[u8; 16],
    bad: &BTreeSet<Version>,
) -> PluginChoice<'a> {
    let revoked = index
        .plugins
        .iter()
        .any(|r| r.id == id && r.version == *current && r.revoked);
    let candidate = index
        .plugins
        .iter()
        .filter(|r| {
            r.id == id
                && !r.revoked
                && r.min_core <= *core
                && !bad.contains(&r.version)
                && (revoked || plugin_bucket(install_id, id, &r.version) < r.rollout)
        })
        .max_by(|a, b| a.version.cmp(&b.version));
    match candidate {
        Some(r) if r.version > *current => PluginChoice::Update(r),
        Some(r) if revoked && r.version < *current => PluginChoice::Downgrade(r),
        _ if revoked => PluginChoice::Withdrawn,
        _ => PluginChoice::Keep,
    }
}

/// Finds the newest compatible, non-revoked offered release matching a module or bundle.
///
/// `pick` supplies the lookup, for example a `replaces.symname` or a `modules` member.
pub fn offer<'a>(
    index: &'a Index,
    core: &Version,
    install_id: &[u8; 16],
    bad: &BTreeMap<String, BTreeSet<Version>>,
    pick: impl Fn(&PluginRelease) -> bool,
) -> Option<&'a PluginRelease> {
    index
        .plugins
        .iter()
        .filter(|r| {
            !r.revoked
                && r.min_core <= *core
                && !bad
                    .get(&r.id)
                    .is_some_and(|versions| versions.contains(&r.version))
                && plugin_bucket(install_id, &r.id, &r.version) < r.rollout
                && pick(r)
        })
        .max_by(|a, b| a.version.cmp(&b.version).then_with(|| b.id.cmp(&a.id)))
}
