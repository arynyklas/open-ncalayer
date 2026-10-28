//! The feed and downloads of [`IndexSource`], and Velopack's public `UpdateManager` driven
//! by it over an app layout in a temporary directory: synthetic packages, and a stand-in
//! for Update.exe's `patch` that writes the rebuilt package it is given. `live_vpk_*` runs
//! the same against packages made by the real `vpk pack` and the real Update.exe.

use super::*;
use crate::update::tests::FakeTransport;
use std::io::Write;
use std::path::PathBuf;
use velopack::locator::VelopackLocatorConfig;
use zip::write::SimpleFileOptions;

const TIMEOUT: Duration = Duration::from_secs(60);

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
        full_contents: delta.then(|| Sha256::of(b"contents")),
        delta: delta.then(|| package(DELTA_URL, b"delta")),
        notes_url: None,
    }
}

#[test]
fn the_feed_is_the_chosen_version_with_the_index_sums() {
    let transport = Arc::new(FakeTransport::default());
    let source = IndexSource::new(&target(true), transport, TIMEOUT).unwrap();
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
    let full_only = IndexSource::new(&target(false), Arc::new(FakeTransport::default()), TIMEOUT)
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
    download_package(&transport, &good, &file, TIMEOUT).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"full package");
    // HTTPS only, and no more than the index's size.
    let asked = transport.asked();
    assert_eq!(asked.last().unwrap(), &(FULL_URL.to_owned(), 12, true));

    // Another body of the same size: its sha256 differs; it is not kept.
    transport.serve(FULL_URL, b"evil package");
    let e = download_package(&transport, &good, &file, TIMEOUT).unwrap_err();
    assert!(e.contains("sha256"), "{e}");
    assert!(!file.exists());

    // Through the Velopack source as well.
    let source = IndexSource::new(
        &Target {
            full: good.clone(),
            ..target(false)
        },
        Arc::new(transport),
        TIMEOUT,
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

/// The files of a package of `version` whose Update.exe is `updater`.
fn files(version: &str, updater: &[u8]) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "OpenNCALayer.nuspec".to_owned(),
            nuspec(version).into_bytes(),
        ),
        (
            "lib/app/openncalayer.exe".to_owned(),
            format!("program {version}").into_bytes(),
        ),
        ("lib/app/Squirrel.exe".to_owned(), updater.to_vec()),
    ]
}

fn nuspec(version: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
<metadata><id>OpenNCALayer</id><version>{version}</version><title>OpenNCALayer</title>
<authors>test</authors><description>test</description><mainExe>openncalayer.exe</mainExe>
</metadata></package>"#
    )
}

/// A zip archive of `files`, in this order, deflated or stored: archives of the same files
/// that differ byte for byte.
fn archive(files: &[(String, Vec<u8>)], deflate: bool) -> Vec<u8> {
    let method = if deflate {
        zip::CompressionMethod::Deflated
    } else {
        zip::CompressionMethod::Stored
    };
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in files {
        zip.start_file(
            name.as_str(),
            SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// An installed app of version `0.1.0` in a temporary directory, Velopack's layout: its
/// packages directory with the full package of `0.1.0` (the base of deltas), its manifest
/// and an Update.exe that rebuilds a package by copying `rebuilt`.
struct App {
    dir: tempfile::TempDir,
    rebuilt: PathBuf,
}

impl App {
    fn new() -> App {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("packages")).unwrap();
        std::fs::create_dir_all(root.join("current")).unwrap();
        std::fs::write(root.join("current").join("sq.version"), nuspec("0.1.0")).unwrap();
        std::fs::write(
            root.join("packages")
                .join("openncalayer-0.1.0-win-x64-full.nupkg"),
            archive(&files("0.1.0", b"updater 0.1.0"), true),
        )
        .unwrap();
        let app = App {
            rebuilt: dir.path().join("rebuilt.nupkg"),
            dir,
        };
        app.stand_in_updater();
        app
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }

    fn final_package(&self) -> PathBuf {
        self.root()
            .join("packages")
            .join("openncalayer-0.2.0-win-x64-full.nupkg")
    }

    fn update_exe(&self) -> PathBuf {
        if cfg!(windows) {
            self.root().join("Update.cmd")
        } else {
            self.root().join("Update.sh")
        }
    }

    /// `Update patch --old <base> --output <file> --delta <delta>`: copies `rebuilt` to
    /// `<file>`.
    fn stand_in_updater(&self) {
        let path = self.update_exe();
        let rebuilt = self.rebuilt.display();
        if cfg!(windows) {
            std::fs::write(&path, format!("@copy /b /y \"{rebuilt}\" %5 > nul\r\n")).unwrap();
        } else {
            std::fs::write(&path, format!("#!/bin/sh\ncp '{rebuilt}' \"$5\"\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    fn manager(&self, source: IndexSource) -> UpdateManager {
        let root = self.root();
        let locator = VelopackLocatorConfig {
            RootAppDir: root.clone(),
            UpdateExePath: self.update_exe(),
            PackagesDir: root.join("packages"),
            ManifestPath: root.join("current").join("sq.version"),
            CurrentBinaryDir: root.join("current"),
            IsPortable: true,
        };
        UpdateManager::new(source, None, Some(locator)).unwrap()
    }

    /// Has Velopack download `target` through `transport`.
    fn download(&self, target: &Target, transport: &Arc<FakeTransport>) -> Result<(), String> {
        let source = IndexSource::new(
            target,
            Arc::clone(transport) as Arc<dyn HttpTransport>,
            TIMEOUT,
        )
        .unwrap();
        download(&self.manager(source), target, &v("0.1.0"))
    }
}

/// The published packages of `0.2.0`: the full one (deflated) and a delta, served by the
/// transport, and the target of the index naming them.
fn published(transport: &FakeTransport) -> (Vec<u8>, Target) {
    let full = archive(&files("0.2.0", b"updater 0.2.0"), true);
    let contents = {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full.nupkg");
        std::fs::write(&path, &full).unwrap();
        contents_sha256(&path).unwrap()
    };
    transport.serve(FULL_URL, &full);
    transport.serve(DELTA_URL, b"delta from 0.1.0");
    let target = Target {
        version: v("0.2.0"),
        full: package(FULL_URL, &full),
        full_contents: Some(contents),
        delta: Some(package(DELTA_URL, b"delta from 0.1.0")),
        notes_url: None,
    };
    (full, target)
}

fn urls(transport: &FakeTransport) -> Vec<String> {
    transport
        .asked()
        .into_iter()
        .map(|(url, _, _)| url)
        .collect()
}

#[test]
fn a_package_rebuilt_from_the_delta_with_the_index_files_is_used() {
    let app = App::new();
    let transport = Arc::new(FakeTransport::default());
    let (full, target) = published(&transport);
    // The same files in another order, stored: another archive, as Update.exe makes.
    let mut reordered = files("0.2.0", b"updater 0.2.0");
    reordered.reverse();
    let rebuilt = archive(&reordered, false);
    assert_ne!(rebuilt, full);
    std::fs::write(&app.rebuilt, &rebuilt).unwrap();

    app.download(&target, &transport).unwrap();
    assert_eq!(urls(&transport), [DELTA_URL], "the delta only");
    assert_eq!(std::fs::read(app.final_package()).unwrap(), rebuilt);
    if cfg!(windows) {
        assert_eq!(std::fs::read(app.update_exe()).unwrap(), b"updater 0.2.0");
    }
}

#[test]
fn a_rebuilt_package_with_other_files_is_replaced_by_the_full_one() {
    let app = App::new();
    let transport = Arc::new(FakeTransport::default());
    let (full, target) = published(&transport);
    std::fs::write(
        &app.rebuilt,
        archive(&files("0.2.0", b"another updater"), true),
    )
    .unwrap();

    app.download(&target, &transport).unwrap();
    assert_eq!(
        urls(&transport),
        [DELTA_URL, FULL_URL],
        "then the full package"
    );
    assert_eq!(std::fs::read(app.final_package()).unwrap(), full);
    // Update.exe never comes from the package that did not match.
    if cfg!(windows) {
        assert_eq!(std::fs::read(app.update_exe()).unwrap(), b"updater 0.2.0");
    }

    // Not a package at all: the same.
    let app = App::new();
    let transport = Arc::new(FakeTransport::default());
    let (full, target) = published(&transport);
    std::fs::write(&app.rebuilt, b"not a zip archive").unwrap();
    app.download(&target, &transport).unwrap();
    assert_eq!(urls(&transport), [DELTA_URL, FULL_URL]);
    assert_eq!(std::fs::read(app.final_package()).unwrap(), full);
}

#[test]
fn a_package_already_on_disk_is_used_only_if_it_matches() {
    let transport = Arc::new(FakeTransport::default());
    let (full, target) = published(&transport);
    let full_only = Target {
        delta: None,
        ..target.clone()
    };

    // The published one, or one rebuilt earlier with the same files: nothing is downloaded.
    for kept in [full.clone(), {
        let mut reordered = files("0.2.0", b"updater 0.2.0");
        reordered.reverse();
        archive(&reordered, false)
    }] {
        let app = App::new();
        let transport = Arc::new(FakeTransport::default());
        published(&transport);
        std::fs::write(app.final_package(), &kept).unwrap();
        app.download(&target, &transport).unwrap();
        assert!(urls(&transport).is_empty());
        assert_eq!(std::fs::read(app.final_package()).unwrap(), kept);
    }

    // Anything else is deleted and the full package downloaded, with a delta in the index
    // or without: Velopack takes the newest package on disk, that one, for the base of
    // deltas, so it plans no delta.
    for target in [&target, &full_only] {
        let app = App::new();
        let transport = Arc::new(FakeTransport::default());
        published(&transport);
        std::fs::write(app.final_package(), archive(&files("0.2.0", b"evil"), true)).unwrap();
        app.download(target, &transport).unwrap();
        assert_eq!(urls(&transport), [FULL_URL]);
        assert_eq!(std::fs::read(app.final_package()).unwrap(), full);
        if cfg!(windows) {
            assert_eq!(std::fs::read(app.update_exe()).unwrap(), b"updater 0.2.0");
        }
    }
}

/// The real thing: two versions packed by `vpk pack` and the real Update.exe. Set
/// `ONCL_VPK_SMOKE` to a directory with `out/` (the output of `vpk pack` of
/// `0.1.0-alpha.1`, then `0.1.0-alpha.2`, channel `win-x64`) and `Update.exe` (the
/// `Squirrel.exe` of the first package). Windows only: the packs are Windows packages.
#[test]
#[ignore = "needs packages made by vpk: ONCL_VPK_SMOKE"]
#[cfg(windows)]
fn live_vpk_delta_rebuilds_the_full_package_and_tampering_is_refused() {
    let smoke = PathBuf::from(std::env::var_os("ONCL_VPK_SMOKE").expect("ONCL_VPK_SMOKE"));
    let out = smoke.join("out");
    let name = |version: &str, kind: &str| format!("OpenNCALayer-{version}-win-x64-{kind}.nupkg");
    let read = |name: &str| std::fs::read(out.join(name)).unwrap();
    let base = read(&name("0.1.0-alpha.1", "full"));
    let full = read(&name("0.1.0-alpha.2", "full"));
    let delta = read(&name("0.1.0-alpha.2", "delta"));
    let squirrel = |package: &[u8]| {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(package)).unwrap();
        let mut file = zip.by_name("lib/app/Squirrel.exe").unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
        bytes
    };
    let full_url = format!(
        "https://github.com/o/r/releases/download/v0.1.0-alpha.2/{}",
        name("0.1.0-alpha.2", "full")
    );
    let delta_url = format!(
        "https://github.com/o/r/releases/download/v0.1.0-alpha.2/{}",
        name("0.1.0-alpha.2", "delta")
    );
    let target = Target {
        version: v("0.1.0-alpha.2"),
        full: package(&full_url, &full),
        full_contents: Some(contents_sha256(&out.join(name("0.1.0-alpha.2", "full"))).unwrap()),
        delta: Some(package(&delta_url, &delta)),
        notes_url: None,
    };

    // An installed 0.1.0-alpha.1 with the real Update.exe, and `base` as its package.
    let install = |base: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("packages")).unwrap();
        std::fs::create_dir_all(root.join("current")).unwrap();
        std::fs::copy(smoke.join("Update.exe"), root.join("Update.exe")).unwrap();
        std::fs::write(
            root.join("packages").join(name("0.1.0-alpha.1", "full")),
            base,
        )
        .unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(base)).unwrap();
        let mut nuspec = String::new();
        std::io::Read::read_to_string(
            &mut zip.by_name("OpenNCALayer.nuspec").unwrap(),
            &mut nuspec,
        )
        .unwrap();
        std::fs::write(root.join("current").join("sq.version"), nuspec).unwrap();
        dir
    };
    let run = |dir: &tempfile::TempDir| {
        let root = dir.path().join("root");
        let transport = Arc::new(FakeTransport::default());
        transport.serve(&full_url, &full);
        transport.serve(&delta_url, &delta);
        let source = IndexSource::new(
            &target,
            Arc::clone(&transport) as Arc<dyn HttpTransport>,
            TIMEOUT,
        )
        .unwrap();
        let locator = VelopackLocatorConfig {
            RootAppDir: root.clone(),
            UpdateExePath: root.join("Update.exe"),
            PackagesDir: root.join("packages"),
            ManifestPath: root.join("current").join("sq.version"),
            CurrentBinaryDir: root.join("current"),
            IsPortable: true,
        };
        let manager = UpdateManager::new(source, None, Some(locator)).unwrap();
        download(&manager, &target, &v("0.1.0-alpha.1")).unwrap();
        let kept =
            std::fs::read(root.join("packages").join(name("0.1.0-alpha.2", "full"))).unwrap();
        (
            urls(&transport),
            kept,
            std::fs::read(root.join("Update.exe")).unwrap(),
        )
    };

    // The delta: the rebuilt package is another archive of the published files.
    let dir = install(&base);
    let (asked, kept, updater) = run(&dir);
    assert_eq!(asked, std::slice::from_ref(&delta_url), "the delta only");
    assert_ne!(
        Sha256::of(&kept),
        target.full.sha256,
        "rebuilt, not the published bytes"
    );
    let kept_path = dir.path().join("kept.nupkg");
    std::fs::write(&kept_path, &kept).unwrap();
    assert_eq!(
        Some(contents_sha256(&kept_path).unwrap()),
        target.full_contents
    );
    assert_eq!(updater, squirrel(&full));
    println!(
        "delta: {} bytes downloaded instead of {}; rebuilt sha256 {} (published {}), same files",
        delta.len(),
        full.len(),
        Sha256::of(&kept),
        target.full.sha256
    );

    // A damaged base package rebuilds other files: the full package is downloaded, and
    // Update.exe comes from it.
    let mut damaged = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let mut source = zip::ZipArchive::new(std::io::Cursor::new(&base[..])).unwrap();
    for i in 0..source.len() {
        let mut file = source.by_index(i).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
        let name = file.name().unwrap().into_owned();
        // A file the delta keeps as it is: the rebuilt package copies it from the base.
        if name == "lib/app/openncalayer.exe" {
            bytes.extend_from_slice(b"tampered");
        }
        damaged
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        damaged.write_all(&bytes).unwrap();
    }
    let damaged = damaged.finish().unwrap().into_inner();
    let dir = install(&damaged);
    let (asked, kept, updater) = run(&dir);
    assert_eq!(
        asked,
        [delta_url.clone(), full_url.clone()],
        "then the full package"
    );
    assert_eq!(kept, full);
    assert_eq!(updater, squirrel(&full));
    println!("damaged base: rebuilt package refused, full package downloaded");

    // A damaged package of the new version already on disk is deleted, not used.
    let dir = install(&base);
    let cached = dir
        .path()
        .join("root")
        .join("packages")
        .join(name("0.1.0-alpha.2", "full"));
    let mut bytes = full.clone();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    std::fs::write(&cached, &bytes).unwrap();
    let (asked, kept, updater) = run(&dir);
    // Downloaded again: through the delta if Velopack cannot read the damaged file as a
    // package, in full if it takes it for the newest base.
    assert!(
        asked == [delta_url.clone()] || asked == [full_url.clone()],
        "{asked:?}"
    );
    assert_eq!(
        Some(contents_sha256(&cached).unwrap()),
        target.full_contents
    );
    assert_ne!(kept, bytes);
    assert_eq!(updater, squirrel(&full));
    println!("damaged cached package: deleted, downloaded again ({asked:?}) and checked");
}
