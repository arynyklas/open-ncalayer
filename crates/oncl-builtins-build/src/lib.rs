//! The WebAssembly of OpenNCALayer's built-in modules ([`GUESTS`]): built from this
//! workspace ([`build`]) or taken built ([`take`]), checked, and laid out as
//! `<out>/<package>/{plugin.toml,plugin.wasm}` with `<out>/SHA256SUMS`, for the daemon to
//! embed ([`sources_rs`]).
//!
//! Every flavour of a release embeds the same bytes: CI builds the modules once and hands
//! them to each build in `ONCL_BUILTINS_DIR` ([`BUILTINS_DIR_VAR`]).

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The variable naming a folder of modules built already ([`take`]).
pub const BUILTINS_DIR_VAR: &str = "ONCL_BUILTINS_DIR";

/// The id prefix of the built-in modules (`oncl_plugin::BUILTIN_ID_PREFIX`).
pub const BUILTIN_ID_PREFIX: &str = "io.github.arynyklas.openncalayer.builtin.";

/// The version every built-in module's manifest carries: the workspace's.
pub const WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The Cargo profile of the modules.
pub const PROFILE: &str = "builtin-wasm";

/// The target of the modules.
pub const TARGET: &str = "wasm32-unknown-unknown";

/// The checksums file of a folder of modules.
pub const SUMS: &str = "SHA256SUMS";

/// A built-in module's crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guest {
    /// Its package name.
    pub package: &'static str,
    /// Its folder, from the workspace root.
    pub dir: &'static str,
}

/// The built-in modules, in the order the core loads them.
pub const GUESTS: &[Guest] = &[Guest {
    package: "oncl-builtin-accessory",
    dir: "crates/oncl-builtin-accessory",
}];

/// A built-in module laid out for embedding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub package: String,
    /// Its `plugin.toml`.
    pub manifest: PathBuf,
    /// Its `plugin.wasm`.
    pub wasm: PathBuf,
    /// The SHA-256 of its `plugin.wasm`.
    pub sha256: [u8; 32],
}

/// The variables a build script or a toolchain override sets that the inner build must not
/// see: its toolchain is the workspace's (`rust-toolchain.toml`), its target directory and
/// flags its own.
const CLEARED_VARS: &[&str] = &[
    "RUSTUP_TOOLCHAIN",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "CARGO_MAKEFLAGS",
];

/// Builds the modules of the workspace at `workspace` in `target_dir` and lays them out in
/// `out`.
///
/// # Errors
///
/// The build fails, or a manifest is not a built-in module's of this version.
pub fn build(workspace: &Path, target_dir: &Path, out: &Path) -> io::Result<Vec<Built>> {
    let mut cargo = Command::new("cargo");
    cargo
        .current_dir(workspace)
        .args([
            "build",
            "--locked",
            "--profile",
            PROFILE,
            "--target",
            TARGET,
        ])
        .arg("--target-dir")
        .arg(target_dir);
    for guest in GUESTS {
        cargo.args(["-p", guest.package]);
    }
    for var in CLEARED_VARS {
        cargo.env_remove(var);
    }
    let output = cargo.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "the built-in modules do not build ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let wasm_dir = target_dir.join(TARGET).join(PROFILE);
    let mut built = Vec::new();
    for guest in GUESTS {
        let manifest = fs::read(workspace.join(guest.dir).join("plugin.toml"))?;
        let wasm = fs::read(wasm_dir.join(format!("{}.wasm", guest.package.replace('-', "_"))))?;
        built.push(lay_out(guest, &manifest, &wasm, out)?);
    }
    write_sums(out, &built)?;
    Ok(built)
}

/// Takes the modules laid out in `dir` (by [`build`]) and lays them out in `out`, checking
/// them against `dir`'s `SHA256SUMS`.
///
/// # Errors
///
/// A module or its checksum is missing, a checksum does not match, or a manifest is not a
/// built-in module's of this version.
pub fn take(dir: &Path, out: &Path) -> io::Result<Vec<Built>> {
    let sums = fs::read_to_string(dir.join(SUMS))?;
    let mut built = Vec::new();
    for guest in GUESTS {
        let manifest = fs::read(dir.join(guest.package).join("plugin.toml"))?;
        let wasm = fs::read(dir.join(guest.package).join("plugin.wasm"))?;
        for (name, bytes) in [("plugin.toml", &manifest), ("plugin.wasm", &wasm)] {
            let file = format!("{}/{name}", guest.package);
            let expected = sums
                .lines()
                .find_map(|line| {
                    let (sum, path) = line.split_once("  ")?;
                    (path == file).then_some(sum)
                })
                .ok_or_else(|| invalid(format!("{SUMS} has no checksum of {file}")))?;
            if expected != hex(&Sha256::digest(bytes)) {
                return Err(invalid(format!("{file} does not match its checksum")));
            }
        }
        built.push(lay_out(guest, &manifest, &wasm, out)?);
    }
    write_sums(out, &built)?;
    Ok(built)
}

/// Checks the `plugin.toml` text `manifest`: a built-in module's id, this version.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] saying what is wrong.
pub fn check_manifest(manifest: &str) -> io::Result<()> {
    #[derive(Deserialize)]
    struct Head {
        id: String,
        version: String,
    }
    let head: Head =
        toml::from_str(manifest).map_err(|e| invalid(format!("a malformed manifest: {e}")))?;
    if !head.id.starts_with(BUILTIN_ID_PREFIX) {
        return Err(invalid(format!(
            "{} is not a built-in module's id (under {BUILTIN_ID_PREFIX})",
            head.id
        )));
    }
    if head.version != WORKSPACE_VERSION {
        return Err(invalid(format!(
            "{} has version {}, not the workspace's {WORKSPACE_VERSION}",
            head.id, head.version
        )));
    }
    Ok(())
}

/// What a build script embedding the modules does: takes them from
/// [`BUILTINS_DIR_VAR`] if it is set, else builds them from the workspace at `workspace`
/// in `$OUT_DIR/builtins-target`; lays them out in `$OUT_DIR/builtins` and writes
/// `$OUT_DIR/builtins.rs` ([`sources_rs`]), to be `include!`d. Tells Cargo what to rerun
/// on.
///
/// # Errors
///
/// As [`take`] and [`build`]; `OUT_DIR` is not set.
pub fn embed(workspace: &Path) -> io::Result<()> {
    let out_dir = PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR is not set"))?,
    );
    println!("cargo:rerun-if-env-changed={BUILTINS_DIR_VAR}");
    let out = out_dir.join("builtins");
    let built = match std::env::var_os(BUILTINS_DIR_VAR) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            println!("cargo:rerun-if-changed={}", dir.display());
            take(&dir, &out)?
        }
        None => {
            for input in inputs(workspace)? {
                println!("cargo:rerun-if-changed={}", input.display());
            }
            build(workspace, &out_dir.join("builtins-target"), &out)?
        }
    };
    write_if_changed(&out_dir.join("builtins.rs"), sources_rs(&built).as_bytes())
}

/// The Rust source of `SOURCES: &[oncl_plugin::BuiltinSource<'static>]`, the modules of
/// `built` included from their files.
pub fn sources_rs(built: &[Built]) -> String {
    let mut rs = String::from(
        "/// The built-in modules, embedded.\n\
         pub const SOURCES: &[oncl_plugin::BuiltinSource<'static>] = &[\n",
    );
    for module in built {
        let _ = writeln!(
            rs,
            "    oncl_plugin::BuiltinSource {{\n        manifest: include_str!({:?}),\n        \
             wasm: include_bytes!({:?}),\n    }},",
            module.manifest.display().to_string(),
            module.wasm.display().to_string(),
        );
    }
    rs.push_str("];\n");
    rs
}

/// The files a build of the modules depends on, from the workspace root: what a build
/// script reruns on.
pub fn inputs(workspace: &Path) -> io::Result<Vec<PathBuf>> {
    let mut dirs = vec![
        workspace.join("crates/oncl-pdk"),
        workspace.join("crates/oncl-protocol"),
    ];
    for entry in fs::read_dir(workspace.join("crates"))? {
        let path = entry?.path();
        let is_guest = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("oncl-builtin-") && n != "oncl-builtin-tests");
        if is_guest {
            dirs.push(path);
        }
    }
    let mut inputs = vec![workspace.join("Cargo.toml"), workspace.join("Cargo.lock")];
    for dir in dirs {
        for name in ["src", "Cargo.toml", "plugin.toml"] {
            let path = dir.join(name);
            if path.exists() {
                inputs.push(path);
            }
        }
    }
    Ok(inputs)
}

/// Checks `manifest` and writes the module of `guest` into `out`.
fn lay_out(guest: &Guest, manifest: &[u8], wasm: &[u8], out: &Path) -> io::Result<Built> {
    let text = std::str::from_utf8(manifest)
        .map_err(|_| invalid(format!("the manifest of {} is not UTF-8", guest.package)))?;
    check_manifest(text)?;
    let dir = out.join(guest.package);
    fs::create_dir_all(&dir)?;
    let built = Built {
        package: guest.package.to_owned(),
        manifest: dir.join("plugin.toml"),
        wasm: dir.join("plugin.wasm"),
        sha256: Sha256::digest(wasm).into(),
    };
    write_if_changed(&built.manifest, manifest)?;
    write_if_changed(&built.wasm, wasm)?;
    Ok(built)
}

/// Writes `bytes` to `path` unless it holds them already (its time stays, nothing reruns).
fn write_if_changed(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if fs::read(path).is_ok_and(|old| old == bytes) {
        return Ok(());
    }
    fs::write(path, bytes)
}

/// Writes `out/SHA256SUMS` of `built`, as `sha256sum` does.
fn write_sums(out: &Path, built: &[Built]) -> io::Result<()> {
    let mut sums = String::new();
    for module in built {
        for path in [&module.manifest, &module.wasm] {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let _ = writeln!(
                sums,
                "{}  {}/{name}",
                hex(&Sha256::digest(fs::read(path)?)),
                module.package
            );
        }
    }
    write_if_changed(&out.join(SUMS), sums.as_bytes())
}

/// `bytes` in lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
