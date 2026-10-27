//! [`VelopackInstaller`]: the [`Installer`] of a copy installed through Velopack. Velopack
//! gets a feed of the one version the updater chose ([`IndexSource`]), built from the update
//! index: its packages are downloaded through the daemon's transport, over HTTPS only, and
//! checked against the size and sha256 of the index before Velopack takes them.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use oncl_pki::http::{GetOptions, HttpTransport};
use oncl_update::{Package, Target, Version};
use velopack::bundle::Manifest;
use velopack::sources::{NoneSource, UpdateSource};
use velopack::{UpdateCheck, UpdateManager, UpdateOptions, VelopackAsset, VelopackAssetFeed};

use super::Installer;

/// The longest a package download may take.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

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

    fn manager(&self, target: &Target, downgrade: bool) -> Result<UpdateManager, String> {
        let source = IndexSource::new(target, Arc::clone(&self.transport))?;
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

    fn download(&self, target: &Target, downgrade: bool) -> Result<(), String> {
        let manager = self.manager(target, downgrade)?;
        match manager.check_for_updates().map_err(|e| e.to_string())? {
            UpdateCheck::UpdateAvailable(update) => manager
                .download_updates(&update, None)
                .map_err(|e| e.to_string()),
            UpdateCheck::NoUpdateAvailable | UpdateCheck::RemoteIsEmpty => Err(format!(
                "Velopack does not take {} for an update of {}",
                target.version, self.current
            )),
        }
    }

    fn apply_on_exit(&self, target: &Target) -> Result<(), String> {
        let manager = self.manager(target, true)?;
        let asset = VelopackAsset {
            PackageId: manager.get_app_id(),
            ..asset(&target.version, &target.full, FULL)?
        };
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        // Silent: the updater shows no window of its own; it starts the new version with
        // this process's arguments once this process has exited.
        manager
            .wait_exit_then_apply_updates(&asset, true, true, args)
            .map_err(|e| e.to_string())
    }
}

const FULL: &str = "Full";
const DELTA: &str = "Delta";

/// A Velopack feed of one version of the update index: its full package, and its delta from
/// the running version if the index has one.
pub struct IndexSource {
    packages: Vec<(VelopackAsset, Package)>,
    transport: Arc<dyn HttpTransport>,
}

impl IndexSource {
    /// The feed of `target`, downloaded through `transport`.
    ///
    /// # Errors
    ///
    /// A package URL does not end with a plain `.nupkg` file name.
    pub fn new(target: &Target, transport: Arc<dyn HttpTransport>) -> Result<IndexSource, String> {
        let mut packages = vec![(
            asset(&target.version, &target.full, FULL)?,
            target.full.clone(),
        )];
        if let Some(delta) = &target.delta {
            packages.push((asset(&target.version, delta, DELTA)?, delta.clone()));
        }
        Ok(IndexSource {
            packages,
            transport,
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
        let (_, package) = self
            .packages
            .iter()
            .find(|(a, _)| a.FileName == asset.FileName)
            .ok_or_else(|| {
                velopack::Error::Other(format!("{} is not in the update index", asset.FileName))
            })?;
        download_package(&*self.transport, package, local_file).map_err(velopack::Error::Other)
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

/// Downloads `package` over HTTPS only (redirects included) into `path`, then checks it
/// against the size and sha256 of the index; a file that does not match is removed.
///
/// # Errors
///
/// What failed.
pub fn download_package(
    transport: &dyn HttpTransport,
    package: &Package,
    path: &Path,
) -> Result<(), String> {
    let url = &package.url;
    let opts = GetOptions {
        timeout: DOWNLOAD_TIMEOUT,
        max_len: package.size,
        https_only: true,
        ..GetOptions::default()
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
mod tests {
    use super::*;
    use crate::update::tests::FakeTransport;
    use oncl_update::Sha256;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn package(url: &str, body: &[u8]) -> Package {
        Package {
            url: url.to_owned(),
            sha256: Sha256::of(body),
            size: body.len() as u64,
        }
    }

    const FULL_URL: &str =
        "https://github.com/o/r/releases/download/v0.2.0/openncalayer-0.2.0-win-x64-full.nupkg";
    const DELTA_URL: &str =
        "https://github.com/o/r/releases/download/v0.2.0/openncalayer-0.2.0-win-x64-delta.nupkg";

    fn target(delta: bool) -> Target {
        Target {
            version: v("0.2.0"),
            full: package(FULL_URL, b"full package"),
            delta: delta.then(|| package(DELTA_URL, b"delta")),
            notes_url: None,
        }
    }

    #[test]
    fn the_feed_is_the_chosen_version_with_the_index_sums() {
        let transport = Arc::new(FakeTransport::default());
        let source = IndexSource::new(&target(true), transport).unwrap();
        let app = Manifest {
            id: "OpenNCALayer".to_owned(),
            ..Manifest::default()
        };
        let feed = source.get_release_feed("win-x64", &app, "staged").unwrap();
        let assets: Vec<_> = feed
            .Assets
            .iter()
            .map(|a| {
                (
                    a.PackageId.as_str(),
                    a.Version.as_str(),
                    a.Type.as_str(),
                    a.FileName.as_str(),
                    a.SHA256.clone(),
                    a.Size,
                )
            })
            .collect();
        assert_eq!(
            assets,
            [
                (
                    "OpenNCALayer",
                    "0.2.0",
                    "Full",
                    "openncalayer-0.2.0-win-x64-full.nupkg",
                    Sha256::of(b"full package").to_string(),
                    12,
                ),
                (
                    "OpenNCALayer",
                    "0.2.0",
                    "Delta",
                    "openncalayer-0.2.0-win-x64-delta.nupkg",
                    Sha256::of(b"delta").to_string(),
                    5,
                ),
            ]
        );
        let full_only = IndexSource::new(&target(false), Arc::new(FakeTransport::default()))
            .unwrap()
            .get_release_feed("win-x64", &app, "")
            .unwrap();
        assert_eq!(full_only.Assets.len(), 1);
    }

    #[test]
    fn package_urls_must_end_with_a_plain_file_name() {
        for url in [
            "https://example.org/",
            "https://example.org/.nupkg",
            "https://example.org/a.zip",
            "https://example.org/a.nupkg?x=1",
            "https://example.org/..%2Fa.nupkg",
            "https://example.org/a\\b.nupkg",
            "https://example.org/c:a.nupkg",
        ] {
            assert!(
                asset(&v("1.0.0"), &package(url, b""), FULL).is_err(),
                "{url}"
            );
        }
        assert!(asset(&v("1.0.0"), &package(FULL_URL, b""), FULL).is_ok());
    }

    #[test]
    fn a_package_is_kept_only_if_it_matches_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("p.partial");
        let transport = FakeTransport::default();
        transport.serve(FULL_URL, b"full package");
        let good = package(FULL_URL, b"full package");
        download_package(&transport, &good, &file).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"full package");
        // HTTPS only, and no more than the index's size.
        let asked = transport.asked();
        assert_eq!(asked.last().unwrap(), &(FULL_URL.to_owned(), 12, true));

        // Another body of the same size: its sha256 differs; it is not kept.
        transport.serve(FULL_URL, b"evil package");
        let e = download_package(&transport, &good, &file).unwrap_err();
        assert!(e.contains("sha256"), "{e}");
        assert!(!file.exists());

        // Through the Velopack source as well.
        let source = IndexSource::new(
            &Target {
                full: good.clone(),
                ..target(false)
            },
            Arc::new(transport),
        )
        .unwrap();
        let asset = asset(&v("0.2.0"), &good, FULL).unwrap();
        assert!(source.download_release_entry(&asset, &file, None).is_err());
        assert!(!file.exists());
        let other = VelopackAsset {
            FileName: "other.nupkg".to_owned(),
            ..asset
        };
        assert!(source.download_release_entry(&other, &file, None).is_err());
    }
}
