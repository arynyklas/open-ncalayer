//! Build a Rust plugin for core Wasm and package its checked manifest and module.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use oncl_pdk::abi::Import;
use oncl_pki::fsutil::{Access, write_atomically};
use oncl_plugin::{MAX_MANIFEST, MAX_PACKAGE, MAX_WASM, Manifest, Package};
use serde_json::Value;

use crate::index::{index_path, plugin_package_name, read_index};
use oncl_update::Channel;

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

pub(crate) fn read_limited(path: &Path, limit: u64) -> anyhow::Result<Vec<u8>> {
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
    // What Cargo is given: absolute, but not the verbatim (`\\?\`) form `canonicalize` gives on
    // Windows, with which Cargo fails to inherit a member's `workspace.dependencies` (as the
    // ports' shared crates do).
    let cargo_manifest_arg = std::path::absolute(directory.join("Cargo.toml"))
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
        .arg(&cargo_manifest_arg)
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
        .arg(&cargo_manifest_arg)
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
    let compiled = oncl_plugin::Engine::new()
        .compile(&manifest, &wasm)
        .context("checking the plugin ABI")?;
    check_min_core(&manifest, compiled.imports())?;
    let bytes = oncl_plugin::archive(&manifest_bytes, &wasm)?;
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

/// A core older than the newest of `imports` (their [`Import::since`]) cannot load the
/// plugin: its `min_core` must be at least that.
///
/// # Errors
///
/// `min_core` is below the `since` of an import, which the message names.
pub fn check_min_core(manifest: &Manifest, imports: &[Import]) -> anyhow::Result<()> {
    if let Some(newest) = imports.iter().max_by_key(|import| import.since())
        && manifest.min_core < newest.since()
    {
        bail!(
            "plugin.toml min_core {} is below {}, where the host function {} appeared",
            manifest.min_core,
            newest.since(),
            newest.name()
        );
    }
    Ok(())
}

/// The directories of `plugins` not shared by the ports: the guest libraries and the build
/// output.
const NOT_PORTS: [&str; 2] = ["common", "target"];

/// The port directories under `plugins`: every directory except [`NOT_PORTS`] and hidden
/// ones, sorted by name.
///
/// # Errors
///
/// An unreadable directory or a name that is not UTF-8.
pub fn port_names(plugins: &Path) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(plugins).with_context(|| format!("reading {}", plugins.display()))? {
        let entry = entry.with_context(|| format!("reading {}", plugins.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("{} is not a UTF-8 name", entry.path().display());
        };
        if !entry.file_type()?.is_dir() || NOT_PORTS.contains(&name) || name.starts_with('.') {
            continue;
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

/// The port directories (names under `plugins`) whose `plugin.toml` names an `(id,
/// version)` that `channel`'s index in `index_dir` does not list yet, sorted by name;
/// every port if the channel has no index.
///
/// # Errors
///
/// A port directory without a valid `plugin.toml`, an invalid index, or an I/O failure.
pub fn pending(plugins: &Path, index_dir: &Path, channel: Channel) -> anyhow::Result<Vec<String>> {
    let path = index_path(index_dir, channel);
    let published = if path.exists() {
        read_index(&path, channel)?.plugins
    } else {
        Vec::new()
    };
    let mut pending = Vec::new();
    for name in port_names(plugins)? {
        let manifest_path = plugins.join(&name).join("plugin.toml");
        let text = String::from_utf8(read_limited(&manifest_path, MAX_MANIFEST)?)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        let manifest = Manifest::from_toml(&text)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        if !published
            .iter()
            .any(|r| r.id == manifest.id && r.version == manifest.version)
        {
            pending.push(name);
        }
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_names_skip_common_target_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["zeta", "common", "target", ".git", "alpha"] {
            fs::create_dir(dir.path().join(name)).unwrap();
        }
        fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        assert_eq!(port_names(dir.path()).unwrap(), ["alpha", "zeta"]);
    }
}
