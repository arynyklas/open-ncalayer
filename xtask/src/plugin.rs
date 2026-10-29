//! Build a Rust plugin for core Wasm and package its checked manifest and module.

use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use oncl_pki::fsutil::{Access, write_atomically};
use oncl_plugin::{MAX_MANIFEST, MAX_PACKAGE, MAX_WASM, Manifest, Package};
use serde_json::Value;
use zip::write::SimpleFileOptions;

use crate::index::plugin_package_name;

/// Reads bounded package bytes and the checked plugin inside them.
///
/// # Errors
///
/// An oversized, unreadable or invalid package.
pub fn read_package(path: &Path) -> anyhow::Result<(Vec<u8>, Package)> {
    let bytes = read_limited(path, MAX_PACKAGE)?;
    let package = Package::read(&bytes).with_context(|| format!("reading {}", path.display()))?;
    Ok((bytes, package))
}

fn read_limited(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > limit {
        bail!("{} exceeds {limit} bytes", path.display());
    }
    Ok(bytes)
}

/// Builds one `cdylib` Rust crate and writes its deterministic `.onclp` package.
///
/// The manifest version must match Cargo's package version. The finished archive and
/// Wasm ABI are checked by the same code the daemon uses before an installation.
///
/// # Errors
///
/// An invalid crate or manifest, a failed build, an unsupported Wasm module or I/O error.
pub fn pack(root: &Path, directory: &Path, out: &Path) -> anyhow::Result<PathBuf> {
    let cargo_manifest = directory
        .join("Cargo.toml")
        .canonicalize()
        .with_context(|| format!("finding {}/Cargo.toml", directory.display()))?;
    let manifest_path = directory.join("plugin.toml");
    let manifest_bytes = read_limited(&manifest_path, MAX_MANIFEST)?;
    let manifest_text = std::str::from_utf8(&manifest_bytes).context("plugin.toml is not UTF-8")?;
    let manifest = Manifest::from_toml(manifest_text)?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let metadata = Command::new(&cargo)
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&cargo_manifest)
        .output()
        .context("running cargo metadata")?;
    if !metadata.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&metadata.stderr)
        );
    }
    let metadata: Value =
        serde_json::from_slice(&metadata.stdout).context("reading cargo metadata")?;
    let package = metadata["packages"]
        .as_array()
        .context("Cargo returned no packages")?
        .iter()
        .find(|p| {
            p["manifest_path"].as_str().is_some_and(|path| {
                Path::new(path)
                    .canonicalize()
                    .is_ok_and(|path| path == cargo_manifest)
            })
        })
        .context("the requested package is absent from cargo metadata")?;
    check_version(
        &manifest,
        package["version"]
            .as_str()
            .context("Cargo returned no package version")?,
    )?;
    let targets = package["targets"]
        .as_array()
        .context("Cargo returned no targets")?;
    let mut libraries = targets.iter().filter(|t| {
        t["crate_types"]
            .as_array()
            .is_some_and(|types| types.iter().any(|kind| kind == "cdylib"))
    });
    let target = libraries
        .next()
        .context("the plugin crate must have a cdylib target")?;
    if libraries.next().is_some() {
        bail!("the plugin crate must have exactly one cdylib target");
    }
    // Cargo names a library's artifact after the target with `-` made `_`.
    let target_name = target["name"]
        .as_str()
        .context("Cargo returned no target name")?
        .replace('-', "_");
    let target_dir = root.join("target/plugin-build");
    let status = Command::new(&cargo)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "wasm32-unknown-unknown",
            "--manifest-path",
        ])
        .arg(&cargo_manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        // Flags meant for the host build are not the plugin's; the package is published, so
        // the paths of the machine that built it (source files named in panic locations) are
        // replaced by fixed names.
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", remap_flags(root, directory)?)
        .status()
        .context("building the plugin for wasm32-unknown-unknown")?;
    if !status.success() {
        bail!("the plugin build failed ({status})");
    }
    let wasm = read_limited(
        &target_dir
            .join("wasm32-unknown-unknown/release")
            .join(format!("{target_name}.wasm")),
        MAX_WASM,
    )?;
    oncl_plugin::Engine::new()
        .compile(&manifest, &wasm)
        .context("checking the plugin ABI")?;
    let bytes = archive(&manifest_bytes, &wasm)?;
    Package::read(&bytes).context("checking the packaged plugin")?;
    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let path = out.join(plugin_package_name(&manifest.id, &manifest.version));
    write_atomically(&path, &bytes, Access::Default)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// `--remap-path-prefix` flags (separated by 0x1f, as `CARGO_ENCODED_RUSTFLAGS` takes them)
/// for the directories whose paths end up in a module: the cargo home (registry sources),
/// the toolchain, the workspace and the plugin crate. rustc applies the last matching one,
/// so the more specific directories come later.
fn remap_flags(root: &Path, crate_dir: &Path) -> anyhow::Result<String> {
    let home = match std::env::var_os("CARGO_HOME") {
        Some(home) => PathBuf::from(home),
        None => std::env::home_dir()
            .context("the home directory is unknown")?
            .join(".cargo"),
    };
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .current_dir(crate_dir)
        .output()
        .context("asking rustc for its sysroot")?;
    if !sysroot.status.success() {
        bail!("rustc --print sysroot failed");
    }
    let sysroot = PathBuf::from(
        String::from_utf8(sysroot.stdout)
            .context("the sysroot is not UTF-8")?
            .trim(),
    );
    let mut flags = Vec::new();
    for (from, to) in [
        (std::path::absolute(home)?, "/cargo"),
        (sysroot, "/rustc"),
        (std::path::absolute(root)?, "/workspace"),
        (std::path::absolute(crate_dir)?, "/plugin"),
    ] {
        let from = from.to_str().context("a build path is not UTF-8")?;
        flags.push(format!("--remap-path-prefix={from}={to}"));
    }
    Ok(flags.join("\u{1f}"))
}

fn check_version(manifest: &Manifest, cargo_version: &str) -> anyhow::Result<()> {
    if manifest.version.to_string() != cargo_version {
        bail!(
            "plugin.toml version {} differs from Cargo version {cargo_version}",
            manifest.version
        );
    }
    Ok(())
}

fn archive(manifest: &[u8], wasm: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);
    for (name, body) in [("plugin.toml", manifest), ("plugin.wasm", wasm)] {
        zip.start_file(name, options)?;
        zip.write_all(body)?;
    }
    Ok(zip.finish()?.into_inner())
}
