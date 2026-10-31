//! `cargo xtask plugin pack`, `cargo xtask plugin pending` and `cargo xtask index add-plugin`.

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
/// A ports' directory that does not exist: `beta` never reads it.
const NO_PORTS: &str = "no-such-plugins-dir";

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
fn pack_rejects_min_core_below_imports() {
    let manifest = |min_core: &str| {
        oncl_plugin::Manifest::from_toml(&oncl_testkit::plugin::example_manifest().replace(
            "min_core = \"0.1.0-alpha.3\"",
            &format!("min_core = \"{min_core}\""),
        ))
        .unwrap()
    };
    let wasm = fs::read(oncl_testkit::plugin::example_wasm()).unwrap();
    let compiled = oncl_plugin::Engine::new()
        .compile(&manifest("0.1.0-alpha.3"), &wasm)
        .unwrap();
    assert!(!compiled.imports().is_empty());
    xtask::plugin::check_min_core(&manifest("0.1.0-alpha.3"), compiled.imports()).unwrap();
    xtask::plugin::check_min_core(&manifest("1.0.0"), compiled.imports()).unwrap();
    let error = error_text(xtask::plugin::check_min_core(
        &manifest("0.1.0-alpha.2"),
        compiled.imports(),
    ));
    assert!(
        error.contains("min_core 0.1.0-alpha.2 is below 0.1.0-alpha.3"),
        "{error}"
    );
    // A module importing nothing needs no particular core.
    xtask::plugin::check_min_core(&manifest("0.0.1"), &[]).unwrap();
}

#[test]
fn add_plugin_takes_everything_from_the_package() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let path = example(packages.path());
    let written = index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
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
    assert_eq!(release.min_core.to_string(), "0.1.0-alpha.3");
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
        Path::new(NO_PORTS),
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
            Path::new(NO_PORTS),
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
        Path::new(NO_PORTS),
        Channel::Stable,
        TAG,
        std::slice::from_ref(&beta),
        100,
        now(),
    );
    assert!(error_text(result).contains("prerelease"));
    index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
        Channel::Beta,
        TAG,
        &[beta],
        100,
        now(),
    )
    .unwrap();

    // Another plugin serving the same module.
    let other = package(
        packages.path(),
        "other.onclp",
        &manifest.replace(EXAMPLE_ID, "kz.example.other"),
    );
    let result = index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
        Channel::Beta,
        TAG,
        &[other],
        100,
        now(),
    );
    assert!(error_text(result).contains("owned by both"));

    let broken = packages.path().join("broken.onclp");
    fs::write(&broken, b"not a zip").unwrap();
    let result = index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
        Channel::Beta,
        TAG,
        &[broken],
        100,
        now(),
    );
    assert!(result.is_err());
}

#[test]
fn plugin_urls_off_the_project_releases_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let written = index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
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

#[test]
fn a_replaced_bundle_belongs_to_one_plugin() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let written = index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
        Channel::Beta,
        TAG,
        &[example(packages.path())],
        100,
        now(),
    )
    .unwrap();
    let before = fs::read(&written.path).unwrap();
    // Another plugin, with modules of its own, replacing the same bundle of the original.
    let manifest = oncl_testkit::plugin::example_manifest();
    let other = manifest.replace(EXAMPLE_ID, "kz.example.other").replace(
        "io.github.arynyklas.openncalayer.Example",
        "kz.example.Other",
    );
    assert!(other.contains("symname = \"kz.example.echo\""), "{other}");
    let other = package(packages.path(), "other.onclp", &other);
    let result = index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
        Channel::Beta,
        TAG,
        std::slice::from_ref(&other),
        100,
        now(),
    );
    let error = error_text(result);
    assert!(
        error.contains("kz.example.echo is replaced by both"),
        "{error}"
    );
    assert_eq!(fs::read(&written.path).unwrap(), before, "nothing written");

    // `index check` reads the rule from the index itself.
    let text = String::from_utf8(before).unwrap();
    let mut index = Index::from_json(text.as_bytes()).unwrap();
    let mut twin = index.plugins[0].clone();
    twin.id = "kz.example.other".to_owned();
    twin.modules = vec!["kz.example.Other".to_owned()];
    twin.package.url = twin.package.url.replace(EXAMPLE_ID, "kz.example.other");
    index.plugins.push(twin.clone());
    let error = error_text(index::check_asset_urls(&index));
    assert!(
        error.contains("kz.example.echo is replaced by both"),
        "{error}"
    );
    // A plugin without `replaces`, or a newer version of the same plugin, is fine.
    index.plugins[1].replaces = None;
    index::check_asset_urls(&index).unwrap();
    let mut newer = index.plugins[0].clone();
    newer.version = "0.2.0".parse().unwrap();
    newer.package.url = newer.package.url.replace("-0.1.0.onclp", "-0.2.0.onclp");
    index.plugins.push(newer);
    index::check_asset_urls(&index).unwrap();
}

/// The beta index with the example published, read back.
fn published_example() -> Index {
    let dir = index_with_example();
    read(&index::index_path(dir.path(), Channel::Beta))
}

#[test]
fn check_rejects_builtin_id() {
    let mut index = published_example();
    let id = format!("{}example", oncl_plugin::BUILTIN_ID_PREFIX);
    index.plugins[0].package.url = index.plugins[0].package.url.replace(EXAMPLE_ID, &id);
    index.plugins[0].id = id;
    let error = error_text(index::check_asset_urls(&index));
    assert!(
        error.contains("reserved for the built-in modules"),
        "{error}"
    );
}

#[test]
fn check_rejects_builtin_module() {
    let mut index = published_example();
    let builtin = index::builtin_modules().unwrap();
    assert!(builtin.contains(&"kz.gov.pki.ncalayerservices.accessory".to_owned()));
    index.plugins[0].modules.push(builtin[0].clone());
    let error = error_text(index::check_asset_urls(&index));
    assert!(error.contains("is a built-in module"), "{error}");
}

#[test]
fn check_rejects_core_bundle_symname() {
    let mut index = published_example();
    let replaces = index.plugins[0].replaces.as_mut().unwrap();
    replaces.symname = oncl_builtin_accessory::CORE_BUNDLES[3].0.to_owned();
    let error = error_text(index::check_asset_urls(&index));
    assert!(error.contains("is the core's"), "{error}");
    // The example's own bundle is not the core's.
    index::check_asset_urls(&published_example()).unwrap();
}

/// A `plugins/` directory with a port `dir` per entry, whose `plugin.toml` is the
/// example's with `id` and `version`.
fn ports(entries: &[(&str, &str, &str)]) -> tempfile::TempDir {
    let plugins = tempfile::tempdir().unwrap();
    for (dir, id, version) in entries {
        let port = plugins.path().join(dir);
        fs::create_dir_all(&port).unwrap();
        let manifest = oncl_testkit::plugin::example_manifest()
            .replace(EXAMPLE_ID, id)
            .replace("version = \"0.1.0\"", &format!("version = \"{version}\""));
        fs::write(port.join("plugin.toml"), manifest).unwrap();
    }
    plugins
}

/// The beta index in a new directory, with the example 0.1.0 published.
fn index_with_example() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    index::add_plugins(
        dir.path(),
        Path::new(NO_PORTS),
        Channel::Beta,
        TAG,
        &[example(packages.path())],
        100,
        now(),
    )
    .unwrap();
    dir
}

#[test]
fn pending_lists_versions_absent_from_index() {
    let indexes = index_with_example();
    let plugins = ports(&[
        ("zeta", "kz.example.zeta", "1.0.0"),
        ("example", EXAMPLE_ID, "0.1.0"),
        ("example-next", EXAMPLE_ID, "0.2.0"),
    ]);
    let pending = xtask::plugin::pending(plugins.path(), indexes.path(), Channel::Beta).unwrap();
    assert_eq!(pending, ["example-next", "zeta"]);
    // Without an index of the channel, every port is pending.
    let pending = xtask::plugin::pending(plugins.path(), indexes.path(), Channel::Stable).unwrap();
    assert_eq!(pending, ["example", "example-next", "zeta"]);
    // A port without a manifest is an error, not skipped.
    fs::create_dir(plugins.path().join("broken")).unwrap();
    let result = xtask::plugin::pending(plugins.path(), indexes.path(), Channel::Beta);
    assert!(error_text(result).contains("plugin.toml"));
}

#[test]
fn pending_ignores_common() {
    let indexes = index_with_example();
    let plugins = ports(&[("a", "kz.example.a", "1.0.0")]);
    for shared in [
        "common/kit/src",
        "common/pki",
        "target/wasm32-unknown-unknown",
    ] {
        fs::create_dir_all(plugins.path().join(shared)).unwrap();
    }
    fs::write(plugins.path().join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(plugins.path().join("THIRD-PARTY.txt"), "").unwrap();
    let pending = xtask::plugin::pending(plugins.path(), indexes.path(), Channel::Beta).unwrap();
    assert_eq!(pending, ["a"]);
}

#[test]
fn pending_empty_when_all_published() {
    let indexes = index_with_example();
    let plugins = ports(&[("example", EXAMPLE_ID, "0.1.0")]);
    let pending = xtask::plugin::pending(plugins.path(), indexes.path(), Channel::Beta).unwrap();
    assert!(pending.is_empty());
    // The command prints nothing and succeeds.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["plugin", "pending", "--channel", "beta", "--index"])
        .arg(indexes.path())
        .arg("--plugins")
        .arg(plugins.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    // Another port: printed as `plugins/<dir>`.
    let more = ports(&[
        ("example", EXAMPLE_ID, "0.1.0"),
        ("b", "kz.example.b", "1.0.0"),
    ]);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["plugin", "pending", "--channel", "beta", "--index"])
        .arg(indexes.path())
        .arg("--plugins")
        .arg(more.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "plugins/b\n");
}

const PORT_ID: &str = "io.github.arynyklas.openncalayer.port.echo";

/// A `plugins/` directory with the port `echo` (the example under [`PORT_ID`]) whose
/// `registry.toml` says `conformance`, and that port's package in `packages`.
fn port_with_package(conformance: &str, packages: &Path) -> (tempfile::TempDir, PathBuf) {
    let plugins = tempfile::tempdir().unwrap();
    let port = plugins.path().join("echo");
    fs::create_dir(&port).unwrap();
    let manifest = oncl_testkit::plugin::example_manifest().replace(EXAMPLE_ID, PORT_ID);
    fs::write(port.join("plugin.toml"), &manifest).unwrap();
    fs::write(
        port.join("registry.toml"),
        format!(
            "id = \"{PORT_ID}\"\n\
             modules = [\"io.github.arynyklas.openncalayer.Example\"]\n\
             \n\
             [original]\n\
             symname = \"kz.example.echo\"\n\
             version = \"1.0.0\"\n\
             vendor = \"Example\"\n\
             \n\
             [port]\n\
             status = \"full\"\n\
             conformance = \"{conformance}\"\n"
        ),
    )
    .unwrap();
    let package = package(packages, "echo.onclp", &manifest);
    (plugins, package)
}

#[test]
fn add_plugin_stable_refuses_computed() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let (plugins, package) = port_with_package("computed", packages.path());
    let result = index::add_plugins(
        dir.path(),
        plugins.path(),
        Channel::Stable,
        TAG,
        std::slice::from_ref(&package),
        100,
        now(),
    );
    let error = error_text(result);
    assert!(
        error.contains(&format!(
            "{PORT_ID}: conformance with the original is not confirmed (conformance = computed)"
        )),
        "{error}"
    );
    assert!(!index::index_path(dir.path(), Channel::Stable).exists());

    // The command reads the ports from `--plugins`.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["index", "add-plugin", "--channel", "stable", "--tag", TAG])
        .arg("--package")
        .arg(&package)
        .arg("--dir")
        .arg(dir.path())
        .arg("--plugins")
        .arg(plugins.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("(conformance = computed)"), "{stderr}");
    assert!(!index::index_path(dir.path(), Channel::Stable).exists());
}

#[test]
fn add_plugin_stable_accepts_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let packages = tempfile::tempdir().unwrap();
    let (plugins, package) = port_with_package("confirmed", packages.path());
    let written = index::add_plugins(
        dir.path(),
        plugins.path(),
        Channel::Stable,
        TAG,
        &[package],
        100,
        now(),
    )
    .unwrap();
    let index = read(&written.path);
    let [release] = index.plugins.as_slice() else {
        panic!("{:?}", index.plugins);
    };
    assert_eq!(release.id, PORT_ID);
    assert_eq!(release.version.to_string(), "0.1.0");
}

#[test]
fn add_plugin_beta_ignores_conformance() {
    let packages = tempfile::tempdir().unwrap();
    let (plugins, package) = port_with_package("computed", packages.path());
    for ports in [plugins.path(), Path::new(NO_PORTS)] {
        let dir = tempfile::tempdir().unwrap();
        let written = index::add_plugins(
            dir.path(),
            ports,
            Channel::Beta,
            TAG,
            std::slice::from_ref(&package),
            100,
            now(),
        )
        .unwrap();
        assert_eq!(read(&written.path).plugins[0].id, PORT_ID);
    }
}

#[test]
fn registry_conformance_unknown_id_is_error() {
    let packages = tempfile::tempdir().unwrap();
    let (plugins, _) = port_with_package("computed", packages.path());
    assert_eq!(
        xtask::plugin::registry_conformance(plugins.path(), PORT_ID).unwrap(),
        "computed"
    );
    let error = error_text(xtask::plugin::registry_conformance(
        plugins.path(),
        EXAMPLE_ID,
    ));
    assert!(error.contains(EXAMPLE_ID), "{error}");
    assert!(error.contains("no port"), "{error}");
}
