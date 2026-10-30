//! The example plugin of `crates/oncl-pdk/example` and the plugin ports of `plugins/`, built
//! for the tests.

use crate::workspace_root;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

/// The example's directory.
fn example_dir() -> PathBuf {
    workspace_root().join("crates/oncl-pdk/example")
}

/// The example's module, built once per process: `cargo build --release --locked` for
/// `wasm32-unknown-unknown`, into `plugin-example` of the target directory
/// (`CARGO_TARGET_DIR`, else `target`).
///
/// # Panics
///
/// If the build fails (the `wasm32-unknown-unknown` target of `rust-toolchain.toml` must be
/// installed).
pub fn example_wasm() -> &'static Path {
    static WASM: LazyLock<PathBuf> = LazyLock::new(build_example);
    &WASM
}

/// Builds the example: the path of its module.
fn build_example() -> PathBuf {
    let target_dir = target_dir("plugin-example");
    build_wasm(&example_dir().join("Cargo.toml"), &target_dir, &[]);
    target_dir.join("wasm32-unknown-unknown/release/oncl_plugin_example.wasm")
}

/// `name` in the target directory (`CARGO_TARGET_DIR`, else `target`).
fn target_dir(name: &str) -> PathBuf {
    let root = workspace_root();
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|dir| {
            if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            }
        })
        .unwrap_or_else(|| root.join("target"))
        .join(name)
}

/// `cargo build --release --locked --target wasm32-unknown-unknown` of `manifest` into
/// `target_dir`, with `extra` arguments.
///
/// # Panics
///
/// If the build fails.
fn build_wasm(manifest: &Path, target_dir: &Path, extra: &[&str]) {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(workspace_root())
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .args(extra)
        // The flags of the test build are not the plugins'.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("cargo runs");
    assert!(status.success(), "building {} failed", manifest.display());
}

/// The directory of the plugin ports' workspace.
pub fn ports_dir() -> PathBuf {
    workspace_root().join("plugins")
}

/// The directories of the plugin ports (`plugins/<short>`, those with a `plugin.toml`),
/// sorted by name.
pub fn port_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(ports_dir())
        .expect("plugins/ is readable")
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| path.join("plugin.toml").is_file())
        .collect();
    dirs.sort();
    dirs
}

/// The release directory of the plugin ports' modules
/// (`<target>/plugin-ports/wasm32-unknown-unknown/release`), the whole `plugins/` workspace
/// built once per process.
///
/// # Panics
///
/// If the build fails.
pub fn ports_built() -> &'static Path {
    static BUILT: LazyLock<PathBuf> = LazyLock::new(|| {
        let target_dir = target_dir("plugin-ports");
        build_wasm(
            &ports_dir().join("Cargo.toml"),
            &target_dir,
            &["--workspace"],
        );
        target_dir.join("wasm32-unknown-unknown/release")
    });
    &BUILT
}

/// The module of the port in `plugins/<short>`: `oncl_port_<short>.wasm` (`-` as `_`) of
/// [`ports_built`].
pub fn port_wasm(short: &str) -> PathBuf {
    ports_built().join(format!("oncl_port_{}.wasm", short.replace('-', "_")))
}

/// The example's `plugin.toml`.
pub fn example_manifest() -> String {
    let path = example_dir().join("plugin.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The example as a `.onclp` package: its `plugin.toml` and the module of [`example_wasm`].
pub fn example_package() -> Vec<u8> {
    example_package_with(|manifest| manifest)
}

/// The example as a `.onclp` package with its `plugin.toml` changed by `edit` (another id,
/// version or modules), the module of [`example_wasm`] as it is.
pub fn example_package_with(edit: impl FnOnce(String) -> String) -> Vec<u8> {
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("plugin.toml", options).unwrap();
    zip.write_all(edit(example_manifest()).as_bytes()).unwrap();
    zip.start_file("plugin.wasm", options).unwrap();
    zip.write_all(&crate::read(example_wasm())).unwrap();
    zip.finish().unwrap().into_inner()
}
