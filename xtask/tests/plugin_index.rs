//! `cargo xtask plugin pack` and `cargo xtask index add-plugin`.

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use oncl_update::{Channel, Index, Sha256};
use time::OffsetDateTime;
use xtask::index;

const TAG: &str = "plugins-20261029";
const EXAMPLE_ID: &str = "io.github.arynyklas.openncalayer.example";
const EXAMPLE_URL: &str = "https://github.com/arynyklas/open-ncalayer/releases/download/\
                           plugins-20261029/io.github.arynyklas.openncalayer.example-0.1.0.onclp";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn read(path: &Path) -> Index {
    Index::from_json(&fs::read(path).unwrap()).unwrap()
}

fn error_text(result: anyhow::Result<impl std::fmt::Debug>) -> String {
    format!("{:#}", result.unwrap_err())
}

/// A package of the example's module under `manifest`.
fn package(dir: &Path, name: &str, manifest: &str) -> PathBuf {
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("plugin.toml", options).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();
    zip.start_file("plugin.wasm", options).unwrap();
    zip.write_all(&fs::read(oncl_testkit::plugin::example_wasm()).unwrap())
        .unwrap();
    let path = dir.join(name);
    fs::write(&path, zip.finish().unwrap().into_inner()).unwrap();
    path
}

fn example(dir: &Path) -> PathBuf {
    package(
        dir,
        "example.onclp",
        &oncl_testkit::plugin::example_manifest(),
    )
}

#[test]
fn pack_is_deterministic_and_passes_the_daemons_checks() {
    let root = oncl_testkit::workspace_root();
    let crate_dir = root.join("crates/oncl-pdk/example");
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let a = xtask::plugin::pack(&root, &crate_dir, first.path()).unwrap();
    let b = xtask::plugin::pack(&root, &crate_dir, second.path()).unwrap();
    assert_eq!(
        a.file_name().unwrap(),
        "io.github.arynyklas.openncalayer.example-0.1.0.onclp"
    );
    let bytes = fs::read(&a).unwrap();
    assert_eq!(bytes, fs::read(&b).unwrap(), "two packs differ");
    let package = oncl_plugin::Package::read(&bytes).unwrap();
    assert_eq!(package.manifest.id, EXAMPLE_ID);
    oncl_plugin::Engine::new()
        .compile(&package.manifest, &package.wasm)
        .unwrap();
}

#[test]
fn packed_modules_carry_no_paths_of_the_machine_that_built_them() {
    let root = oncl_testkit::workspace_root();
    let out = tempfile::tempdir().unwrap();
    let path =
        xtask::plugin::pack(&root, &root.join("crates/oncl-pdk/example"), out.path()).unwrap();
    let package = oncl_plugin::Package::read(&fs::read(path).unwrap()).unwrap();
    let text = String::from_utf8_lossy(&package.wasm);
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|h| h.join(".cargo")))
        .unwrap();
    for prefix in [root.as_path(), home.as_path()] {
        for form in [
            prefix.display().to_string(),
            prefix.display().to_string().replace('\\', "/"),
        ] {
            assert!(!text.contains(&form), "the module names {form}");
        }
    }
}

#[test]
fn pack_refuses_a_manifest_version_other_than_the_crates() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/lib.rs"), "").unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"p\"\nversion = \"1.0.0\"\nedition = \"2024\"\n\
         [workspace]\n[lib]\ncrate-type = [\"cdylib\"]\n",
    )
    .unwrap();
    let manifest = oncl_testkit::plugin::example_manifest()
        .replace("version = \"0.1.0\"", "version = \"2.0.0\"");
    fs::write(dir.path().join("plugin.toml"), manifest).unwrap();
    let out = tempfile::tempdir().unwrap();
    let result = xtask::plugin::pack(&oncl_testkit::workspace_root(), dir.path(), out.path());
    assert!(error_text(result).contains("differs from Cargo version 1.0.0"));
    assert_eq!(
        fs::read_dir(out.path()).unwrap().count(),
        0,
        "nothing written"
    );
}

#[test]
fn add_plugin_takes_everything_from_the_package() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let path = example(packages.path());
    let written = index::add_plugins(
        dir.path(),
        Channel::Beta,
        TAG,
        std::slice::from_ref(&path),
        30,
        now(),
    )
    .unwrap();
    assert_eq!(written.seq, 1);
    let index = read(&written.path);
    let [release] = index.plugins.as_slice() else {
        panic!("{:?}", index.plugins);
    };
    let bytes = fs::read(&path).unwrap();
    assert_eq!(release.id, EXAMPLE_ID);
    assert_eq!(release.version.to_string(), "0.1.0");
    assert_eq!(release.min_core.to_string(), "0.1.0-alpha.2");
    assert_eq!(
        release.modules,
        ["io.github.arynyklas.openncalayer.Example"]
    );
    assert_eq!(
        release.replaces.as_ref().unwrap().symname,
        "kz.example.echo"
    );
    assert_eq!(release.name.ru, "Пример плагина");
    assert_eq!(release.package.url, EXAMPLE_URL);
    assert_eq!(release.package.size, bytes.len() as u64);
    assert_eq!(release.package.sha256, Sha256::of(&bytes));
    assert_eq!(release.rollout, 30);
    assert!(!release.revoked);

    // The same version again is refused; the index is left as it was.
    let before = fs::read(&written.path).unwrap();
    let again = index::add_plugins(
        dir.path(),
        Channel::Beta,
        "plugins-20261030",
        &[path],
        100,
        now(),
    );
    assert!(error_text(again).contains("in the index already"));
    assert_eq!(fs::read(&written.path).unwrap(), before);
}

#[test]
fn add_plugin_refuses_bad_input() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let path = example(packages.path());
    for tag in [
        "v0.1.0",
        "plugins-2026102",
        "plugins-20261029.",
        "plugins-20261029.x",
    ] {
        let result = index::add_plugins(
            dir.path(),
            Channel::Beta,
            tag,
            std::slice::from_ref(&path),
            100,
            now(),
        );
        assert!(error_text(result).contains("plugins-YYYYMMDD"), "{tag}");
    }

    let manifest = oncl_testkit::plugin::example_manifest();
    let beta = package(
        packages.path(),
        "beta.onclp",
        &manifest.replace("version = \"0.1.0\"", "version = \"0.2.0-beta.1\""),
    );
    let result = index::add_plugins(
        dir.path(),
        Channel::Stable,
        TAG,
        std::slice::from_ref(&beta),
        100,
        now(),
    );
    assert!(error_text(result).contains("prerelease"));
    index::add_plugins(dir.path(), Channel::Beta, TAG, &[beta], 100, now()).unwrap();

    // Another plugin serving the same module.
    let other = package(
        packages.path(),
        "other.onclp",
        &manifest.replace(EXAMPLE_ID, "kz.example.other"),
    );
    let result = index::add_plugins(dir.path(), Channel::Beta, TAG, &[other], 100, now());
    assert!(error_text(result).contains("owned by both"));

    let broken = packages.path().join("broken.onclp");
    fs::write(&broken, b"not a zip").unwrap();
    let result = index::add_plugins(dir.path(), Channel::Beta, TAG, &[broken], 100, now());
    assert!(result.is_err());
}

#[test]
fn plugin_urls_off_the_project_releases_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let written = index::add_plugins(
        dir.path(),
        Channel::Beta,
        TAG,
        &[example(packages.path())],
        100,
        now(),
    )
    .unwrap();
    let text = fs::read_to_string(&written.path).unwrap();
    for to in [
        EXAMPLE_URL.replace("github.com", "example.com"),
        EXAMPLE_URL.replace("plugins-20261029", "v0.1.0"),
        EXAMPLE_URL.replace("-0.1.0.onclp", "-0.2.0.onclp"),
        format!("{EXAMPLE_URL}?x=1"),
    ] {
        let index = Index::from_json(text.replace(EXAMPLE_URL, &to).as_bytes()).unwrap();
        assert!(index::check_asset_urls(&index).is_err(), "{to}");
    }
    // `refresh` keeps the plugins and the rule.
    let before = read(&written.path).plugins;
    let refreshed = index::refresh(dir.path(), Channel::Beta, now()).unwrap();
    assert_eq!(read(&refreshed.path).plugins, before);
}
