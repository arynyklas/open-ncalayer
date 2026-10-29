//! [`VelopackInstaller`]: the [`Installer`] of a copy installed through Velopack. Velopack
//! gets a feed of the one version the updater chose ([`IndexSource`]), built from the update
//! index: its packages are downloaded through the daemon's transport, over HTTPS only, and
//! checked against the size and sha256 of the index before Velopack takes them. A full
//! package Velopack rebuilds from a delta, or finds already on disk, is checked too
//! ([`IndexSource`]'s `verify_full_package`, a hook of the patched Velopack under `vendor/`)
//! before it is used and before Velopack takes its Update.exe from it.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use oncl_pki::http::{GetOptions, HttpTransport};
use oncl_update::{Package, Sha256, Target, Version, contents_sha256};
use velopack::bundle::Manifest;
use velopack::sources::{NoneSource, UpdateSource};
use velopack::{UpdateCheck, UpdateManager, UpdateOptions, VelopackAsset, VelopackAssetFeed};

use super::{ApplyError, Installer};

/// Velopack's update manager of this copy.
pub struct VelopackInstaller {
    transport: Arc<dyn HttpTransport>,
    current: Version,
}

impl VelopackInstaller {
    /// The installer of this copy, downloading through `transport`.
    ///
    /// # Errors
    ///
    /// This copy is not installed through Velopack (a release archive, a build of its own).
    pub fn detect(transport: Arc<dyn HttpTransport>) -> Result<VelopackInstaller, String> {
        let manager = UpdateManager::new(NoneSource {}, None, None).map_err(|e| e.to_string())?;
        Ok(VelopackInstaller {
            transport,
            current: manager.get_current_version(),
        })
    }

    fn manager(
        &self,
        target: &Target,
        downgrade: bool,
        timeout: Duration,
    ) -> Result<UpdateManager, String> {
        let source = IndexSource::new(target, Arc::clone(&self.transport), timeout)?;
        let options = UpdateOptions {
            AllowVersionDowngrade: downgrade,
            ..UpdateOptions::default()
        };
        UpdateManager::new(source, Some(options), None).map_err(|e| e.to_string())
    }
}

impl Installer for VelopackInstaller {
    fn current(&self) -> Version {
        self.current.clone()
    }

    fn download(&self, target: &Target, downgrade: bool, timeout: Duration) -> Result<(), String> {
        download(
            &self.manager(target, downgrade, timeout)?,
            target,
            &self.current,
        )
    }

    fn apply_on_exit(&self, target: &Target) -> Result<(), ApplyError> {
        let manager = self
            .manager(target, true, super::DOWNLOAD_TIMEOUT)
            .map_err(ApplyError::Failed)?;
        let asset = VelopackAsset {
            PackageId: manager.get_app_id(),
            ..asset(&target.version, &target.full, FULL).map_err(ApplyError::Failed)?
        };
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        // Silent: the updater shows no window of its own; it starts the new version with
        // this process's arguments once this process has exited.
        manager
            .wait_exit_then_apply_updates(&asset, true, true, args)
            .map_err(|e| match e {
                velopack::Error::FileNotFound(_) => ApplyError::PackageMissing(e.to_string()),
                e => ApplyError::Failed(e.to_string()),
            })
    }
}

/// Has `manager` (fed by an [`IndexSource`] of `target`) download `target` for `current`.
fn download(manager: &UpdateManager, target: &Target, current: &Version) -> Result<(), String> {
    match manager.check_for_updates().map_err(|e| e.to_string())? {
        UpdateCheck::UpdateAvailable(update) => manager
            .download_updates(&update, None)
            .map_err(|e| e.to_string()),
        UpdateCheck::NoUpdateAvailable | UpdateCheck::RemoteIsEmpty => Err(format!(
            "Velopack does not take {} for an update of {current}",
            target.version
        )),
    }
}

const FULL: &str = "Full";
const DELTA: &str = "Delta";

/// A Velopack feed of one version of the update index: its full package, and its delta from
/// the running version if the index has one. Every package it downloads matches the index's
/// size and sha256; a full package it did not download (rebuilt from the delta, or already
/// on disk) is the index's full package or holds the same files
/// ([`Target::full_contents`]).
pub struct IndexSource {
    packages: Vec<(VelopackAsset, Package)>,
    full_contents: Option<Sha256>,
    transport: Arc<dyn HttpTransport>,
    timeout: Duration,
}

impl IndexSource {
    /// The feed of `target`, downloaded through `transport`, each package within `timeout`.
    ///
    /// # Errors
    ///
    /// A package URL does not end with a plain `.nupkg` file name.
    pub fn new(
        target: &Target,
        transport: Arc<dyn HttpTransport>,
        timeout: Duration,
    ) -> Result<IndexSource, String> {
        let mut packages = vec![(
            asset(&target.version, &target.full, FULL)?,
            target.full.clone(),
        )];
        if let Some(delta) = &target.delta {
            packages.push((asset(&target.version, delta, DELTA)?, delta.clone()));
        }
        Ok(IndexSource {
            packages,
            full_contents: target.full_contents,
            transport,
            timeout,
        })
    }

    fn package(&self, asset: &VelopackAsset) -> Result<&Package, velopack::Error> {
        self.packages
            .iter()
            .find(|(a, _)| a.FileName == asset.FileName)
            .map(|(_, package)| package)
            .ok_or_else(|| {
                velopack::Error::Other(format!("{} is not in the update index", asset.FileName))
            })
    }
}

impl UpdateSource for IndexSource {
    fn get_release_feed(
        &self,
        _channel: &str,
        app: &Manifest,
        _staged_user_id: &str,
    ) -> Result<VelopackAssetFeed, velopack::Error> {
        Ok(VelopackAssetFeed {
            Assets: self
                .packages
                .iter()
                .map(|(asset, _)| VelopackAsset {
                    PackageId: app.id.clone(),
                    ..asset.clone()
                })
                .collect(),
        })
    }

    fn download_release_entry(
        &self,
        asset: &VelopackAsset,
        local_file: &Path,
        _progress: Option<Sender<i16>>,
    ) -> Result<(), velopack::Error> {
        let package = self.package(asset)?;
        download_package(&*self.transport, package, local_file, self.timeout)
            .map_err(velopack::Error::Other)
    }

    /// The index's full package itself (its size and sha256), or an archive of the same
    /// files ([`contents_sha256`] against [`Target::full_contents`]): what Velopack rebuilds
    /// from a delta. Velopack's own checksum check is not needed: the index's is stronger.
    fn verify_full_package(
        &self,
        local_file: &Path,
        asset: &VelopackAsset,
        _verify_checksum: &dyn Fn(&Path, &VelopackAsset) -> Result<(), velopack::Error>,
    ) -> Result<(), velopack::Error> {
        let package = self.package(asset)?;
        let published = match package.check_file(local_file) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let Some(expected) = self.full_contents else {
            return Err(velopack::Error::Other(format!(
                "{}: {published}",
                local_file.display()
            )));
        };
        match contents_sha256(local_file) {
            Ok(actual) if actual == expected => Ok(()),
            Ok(_) => Err(velopack::Error::Other(format!(
                "{}: its files are not those of the update index's full package",
                local_file.display()
            ))),
            Err(e) => Err(velopack::Error::Other(format!(
                "{}: {e}",
                local_file.display()
            ))),
        }
    }
}

/// The Velopack asset of `package`, a `kind` (`Full` or `Delta`) package of `version`, with
/// the size and sha256 of the index. Its file name is the last segment of its URL.
///
/// # Errors
///
/// That segment is not a plain `.nupkg` file name.
fn asset(version: &Version, package: &Package, kind: &str) -> Result<VelopackAsset, String> {
    let name = package.url.rsplit('/').next().unwrap_or_default();
    let plain = name.len() > ".nupkg".len()
        && name.ends_with(".nupkg")
        && !name.starts_with('.')
        && !name.contains(['\\', ':', '?', '#', '%']);
    if !plain {
        return Err(format!(
            "{} does not name a package file of its own",
            package.url
        ));
    }
    Ok(VelopackAsset {
        PackageId: String::new(),
        Version: version.to_string(),
        Type: kind.to_owned(),
        FileName: name.to_owned(),
        SHA1: String::new(),
        SHA256: package.sha256.to_string(),
        Size: package.size,
        NotesMarkdown: String::new(),
        NotesHtml: String::new(),
    })
}

/// Downloads `package` over HTTPS only (redirects included) into `path` within `timeout`,
/// then checks it against the size and sha256 of the index; a file that does not match is
/// removed.
///
/// # Errors
///
/// What failed.
pub fn download_package(
    transport: &dyn HttpTransport,
    package: &Package,
    path: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let url = &package.url;
    let opts = GetOptions {
        timeout,
        connect_timeout: GetOptions::default().connect_timeout.min(timeout),
        max_len: package.size,
        https_only: true,
        redirects: true,
    };
    let reply = transport
        .get_with(url, opts)
        .map_err(|e| format!("{url}: {e}"))?;
    if reply.status != 200 {
        return Err(format!("{url}: HTTP {}", reply.status));
    }
    std::fs::write(path, &reply.body).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Err(e) = package.check_file(path) {
        if let Err(removed) = std::fs::remove_file(path) {
            tracing::warn!(path = %path.display(), error = %removed, "cannot remove a package that does not match the index");
        }
        return Err(format!("{url}: {e}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
