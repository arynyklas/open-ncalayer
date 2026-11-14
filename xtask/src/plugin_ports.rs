//! `cargo xtask plugin-ports-manual`: the plugin ports' real wasm under the manual window's
//! call path (`crates/oncl-core/tests/plugin_ports_manual.rs`, docs/dev/plugins-manual-tests.md).
//!
//! One command: builds the port modules the way `plugin-ops-check` and `plugin pack` expect them
//! (`target/plugin-build`), lints the `[[operations]]` against the built modules
//! (`plugin-ops-check --require-wasm`), then runs the `#[ignore]`d tests with
//! `ONCL_PLUGIN_WASM_DIR` set. Offline: `--locked`, vendored sources.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

/// What to run.
pub struct Options<'a> {
    /// Where the modules are built and read from; the default is `plugin_ops::WASM_DIR`.
    pub wasm_dir: Option<&'a Path>,
    /// Use the modules that are there.
    pub no_build: bool,
    /// Only the tests whose names contain one of these.
    pub filters: &'a [String],
}

/// Builds, lints and runs; an error when any step fails.
///
/// # Errors
///
/// The step that failed.
pub fn run(root: &Path, options: &Options<'_>) -> anyhow::Result<()> {
    let default_dir = root.join(crate::plugin_ops::WASM_DIR);
    let wasm_dir: PathBuf = options.wasm_dir.map_or(default_dir, Path::to_path_buf);
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    if !options.no_build {
        // `release/` of the target directory is where the modules are looked for.
        let target_dir = wasm_dir
            .ancestors()
            .nth(2)
            .context("the wasm directory is not <target>/wasm32-unknown-unknown/release")?;
        let status = Command::new(&cargo)
            .args([
                "build",
                "--release",
                "--locked",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .args(["--workspace", "--manifest-path"])
            .arg(root.join("plugins/Cargo.toml"))
            .arg("--target-dir")
            .arg(target_dir)
            // The flags meant for the host build are not the plugins'.
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .status()
            .context("building the plugin ports")?;
        if !status.success() {
            bail!("the plugin ports did not build ({status})");
        }
    }
    let report = crate::plugin_ops::check(
        root,
        &crate::plugin_ops::Options {
            extra: &[],
            wasm_dir: &wasm_dir,
            require_wasm: true,
        },
    )?;
    print!("{}", report.to_text());
    if report.exit_code() != 0 {
        bail!("plugin-ops-check found {} errors", report.errors());
    }
    let mut test = Command::new(&cargo);
    test.current_dir(root)
        .args(["test", "-p", "oncl-core", "--features", "plugins"])
        .args(["--test", "plugin_ports_manual", "--", "--ignored"])
        .args(options.filters)
        .env("ONCL_PLUGIN_WASM_DIR", &wasm_dir);
    let status = test.status().context("running the port tests")?;
    if !status.success() {
        bail!("the port tests failed ({status})");
    }
    Ok(())
}
