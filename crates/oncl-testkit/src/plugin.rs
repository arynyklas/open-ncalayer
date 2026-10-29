//! The example plugin of `crates/oncl-pdk/example`, built for the tests.

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
    let root = workspace_root();
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|dir| {
            if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            }
        })
        .unwrap_or_else(|| root.join("target"))
        .join("plugin-example");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(&root)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .arg("--manifest-path")
        .arg(example_dir().join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        // The flags of the test build are not the example's.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("cargo runs");
    assert!(status.success(), "building the example plugin failed");
    target_dir.join("wasm32-unknown-unknown/release/oncl_plugin_example.wasm")
}

/// The example's `plugin.toml`.
pub fn example_manifest() -> String {
    let path = example_dir().join("plugin.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The example as a `.onclp` package: its `plugin.toml` and the module of [`example_wasm`].
pub fn example_package() -> Vec<u8> {
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("plugin.toml", options).unwrap();
    zip.write_all(example_manifest().as_bytes()).unwrap();
    zip.start_file("plugin.wasm", options).unwrap();
    zip.write_all(&crate::read(example_wasm())).unwrap();
    zip.finish().unwrap().into_inner()
}
