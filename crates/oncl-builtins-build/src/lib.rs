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

/// The file of a folder of modules naming what they were built from ([`source_digest`]).
pub const SOURCE: &str = "SOURCE-SHA256";

/// A built-in module's crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guest {
    /// Its package name.
    pub package: &'static str,
    /// Its folder, from the workspace root.
    pub dir: &'static str,
}

/// The built-in modules, in the order the core loads them.
pub const GUESTS: &[Guest] = &[
    Guest {
        package: "oncl-builtin-accessory",
        dir: "crates/oncl-builtin-accessory",
    },
    Guest {
        package: "oncl-builtin-basics",
        dir: "crates/oncl-builtin-basics",
    },
];

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
/// `out`. The modules hold no path of the machine: the Cargo home, the toolchain's sources
/// and the workspace are remapped (`--remap-path-prefix`), so a build anywhere else gives
/// the same bytes.
/// `out` also gets [`SOURCE`], the [`source_digest`] of what they were built from.
///
/// # Errors
///
/// The build fails, or a manifest is not a built-in module's of this version.
pub fn build(workspace: &Path, target_dir: &Path, out: &Path) -> io::Result<Vec<Built>> {
    let digest = source_digest(workspace)?;
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
    cargo.env("CARGO_ENCODED_RUSTFLAGS", remaps(workspace)?.join("\x1f"));
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
    write_if_changed(&out.join(SOURCE), format!("{digest}\n").as_bytes())?;
    Ok(built)
}

/// The output of `rustc args` in `workspace`, with its toolchain, trimmed.
fn rustc(workspace: &Path, args: &[&str]) -> io::Result<String> {
    let mut rustc = Command::new("rustc");
    rustc.current_dir(workspace).args(args);
    for var in CLEARED_VARS {
        rustc.env_remove(var);
    }
    let output = rustc.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "rustc {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| invalid("rustc's output is not UTF-8".to_owned()))
}

/// The `release` and `commit-hash` lines of the toolchain of `workspace`: what of the
/// compiler shapes the modules, the same on every host.
fn toolchain(workspace: &Path) -> io::Result<String> {
    let version = rustc(workspace, &["-vV"])?;
    let lines: Vec<&str> = version
        .lines()
        .filter(|line| line.starts_with("release: ") || line.starts_with("commit-hash: "))
        .collect();
    if lines.len() != 2 {
        return Err(invalid(format!(
            "rustc -vV has no release or commit hash:\n{version}"
        )));
    }
    Ok(lines.join("\n"))
}

/// The SHA-256 (hex) of what the modules of `workspace` are built from: every file of
/// [`inputs`] by its path from the workspace root (`/`-separated), its text with CRLF read
/// as LF, and the toolchain's release and commit. The same sources give the same digest on
/// every host, whatever their line endings.
///
/// # Errors
///
/// An input cannot be read, or `rustc` does not run.
pub fn source_digest(workspace: &Path) -> io::Result<String> {
    let mut files = Vec::new();
    for input in inputs(workspace)? {
        walk(&input, &mut files)?;
    }
    let mut named: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|path| {
            let name = path
                .strip_prefix(workspace)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            (name, path)
        })
        .collect();
    named.sort();
    let mut digest = Sha256::new();
    digest.update(toolchain(workspace)?.as_bytes());
    for (name, path) in named {
        let bytes = fs::read(&path)?;
        let mut text = Vec::with_capacity(bytes.len());
        let mut rest = &bytes[..];
        while let Some(at) = rest.windows(2).position(|w| w == b"\r\n") {
            text.extend_from_slice(&rest[..at]);
            text.push(b'\n');
            rest = &rest[at + 2..];
        }
        text.extend_from_slice(rest);
        digest.update(b"\0");
        digest.update(name.as_bytes());
        digest.update(b"\0");
        digest.update((text.len() as u64).to_le_bytes());
        digest.update(&text);
    }
    Ok(hex(&digest.finalize()))
}

/// Every file at or under `path`, into `files`.
fn walk(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            walk(&entry?.path(), files)?;
        }
    } else {
        files.push(path.to_owned());
    }
    Ok(())
}

/// The `--remap-path-prefix` flags of a build of `workspace`: the Cargo home to `/cargo`,
/// the toolchain's library sources to `/rustc/<commit>` (where they are when the rust-src
/// component is not installed), the workspace to `.`.
fn remaps(workspace: &Path) -> io::Result<Vec<String>> {
    let version = rustc(workspace, &["-vV"])?;
    let commit = version
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .ok_or_else(|| invalid(format!("rustc -vV has no commit hash:\n{version}")))?;
    let sysroot = PathBuf::from(rustc(workspace, &["--print", "sysroot"])?);
    let cargo_home = match std::env::var_os("CARGO_HOME") {
        Some(home) => PathBuf::from(home),
        None => std::env::home_dir()
            .ok_or_else(|| io::Error::other("no home folder for the Cargo home"))?
            .join(".cargo"),
    };
    let remap = |from: &Path, to: &str| format!("--remap-path-prefix={}={to}", from.display());
    Ok(vec![
        remap(&real(&cargo_home)?, "/cargo"),
        remap(
            &real(&sysroot)?.join("lib/rustlib/src/rust"),
            &format!("/rustc/{commit}"),
        ),
        remap(&real(workspace)?, "."),
    ])
}

/// `path` absolute, as the compiler names the files under it: without `..`, and on Windows
/// without the `\\?\` prefix canonical paths get there.
fn real(path: &Path) -> io::Result<PathBuf> {
    if cfg!(windows) {
        std::path::absolute(path)
    } else {
        fs::canonicalize(path)
    }
}

/// Takes the modules laid out in `dir` (by [`build`]) and lays them out in `out`, checking
/// them against `dir`'s `SHA256SUMS` and against the workspace at `workspace`: built from
/// its sources ([`source_digest`]), with its manifests.
///
/// # Errors
///
/// A module or its checksum is missing, a checksum does not match, the modules were built
/// from other sources, or a manifest is not the workspace's or not a built-in module's of
/// this version.
pub fn take(workspace: &Path, dir: &Path, out: &Path) -> io::Result<Vec<Built>> {
    let built_from = fs::read_to_string(dir.join(SOURCE))
        .map_err(|e| invalid(format!("{SOURCE} of {}: {e}", dir.display())))?;
    if built_from.trim() != source_digest(workspace)? {
        return Err(invalid(format!(
            "the modules of {} were built from other sources than {}",
            dir.display(),
            workspace.display()
        )));
    }
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
        let own = fs::read_to_string(workspace.join(guest.dir).join("plugin.toml"))?;
        if parse_manifest(&manifest)? != parse_manifest(own.as_bytes())? {
            return Err(invalid(format!(
                "{}/plugin.toml is not the workspace's {}/plugin.toml",
                guest.package, guest.dir
            )));
        }
        built.push(lay_out(guest, &manifest, &wasm, out)?);
    }
    write_sums(out, &built)?;
    write_if_changed(&out.join(SOURCE), built_from.as_bytes())?;
    Ok(built)
}

/// The `plugin.toml` bytes `manifest`, parsed.
fn parse_manifest(manifest: &[u8]) -> io::Result<toml::Table> {
    let text =
        std::str::from_utf8(manifest).map_err(|_| invalid("a manifest is not UTF-8".to_owned()))?;
    toml::from_str(text).map_err(|e| invalid(format!("a malformed manifest: {e}")))
}

/// Checks the `plugin.toml` text `manifest`: a built-in module's id, this version, and
/// `min_core` the same.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] saying what is wrong.
pub fn check_manifest(manifest: &str) -> io::Result<()> {
    #[derive(Deserialize)]
    struct Head {
        id: String,
        version: String,
        min_core: Option<String>,
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
    if head.min_core.as_deref() != Some(WORKSPACE_VERSION) {
        return Err(invalid(format!(
            "{} needs min_core = {WORKSPACE_VERSION:?}, its version",
            head.id
        )));
    }
    Ok(())
}

/// What a build script embedding the modules does: takes them from
/// [`BUILTINS_DIR_VAR`] if it is set (checked against the sources of `workspace`), else
/// builds them from the workspace at `workspace` in `$OUT_DIR/builtins-target`; lays them
/// out in `$OUT_DIR/builtins` and writes `$OUT_DIR/builtins.rs` ([`sources_rs`]), to be
/// `include!`d. Tells Cargo what to rerun on: the sources either way.
///
/// # Errors
///
/// As [`take`] and [`build`]; `OUT_DIR` is not set.
pub fn embed(workspace: &Path) -> io::Result<()> {
    let out_dir = PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR is not set"))?,
    );
    println!("cargo:rerun-if-env-changed={BUILTINS_DIR_VAR}");
    for input in inputs(workspace)? {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    let out = out_dir.join("builtins");
    let built = match std::env::var_os(BUILTINS_DIR_VAR) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            println!("cargo:rerun-if-changed={}", dir.display());
            take(workspace, &dir, &out)?
        }
        None => build(workspace, &out_dir.join("builtins-target"), &out)?,
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
    let mut inputs = vec![
        workspace.join("Cargo.toml"),
        workspace.join("Cargo.lock"),
        workspace.join("rust-toolchain.toml"),
    ];
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
