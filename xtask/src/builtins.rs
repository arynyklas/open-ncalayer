//! `cargo xtask builtins build`: the built-in modules' WebAssembly, built once and laid out
//! for the builds that embed it (`ONCL_BUILTINS_DIR`).

use std::path::{Path, PathBuf};

use anyhow::Context;
use oncl_builtins_build::Built;

/// Where `builtins build` lays the modules out, from the workspace root.
pub const DEFAULT_OUT: &str = "target/builtins";

/// Builds the built-in modules of the workspace `root` (in `target/builtins-target`) and lays
/// them out in `out`, which it returns absolute; prints `<package> <sha256>` of each.
///
/// # Errors
///
/// The build fails or a manifest is not a built-in module's of this version.
pub fn build(root: &Path, out: &Path) -> anyhow::Result<(PathBuf, Vec<Built>)> {
    let out = std::path::absolute(out).with_context(|| format!("{}", out.display()))?;
    println!("Building the built-in modules into {}", out.display());
    let built =
        oncl_builtins_build::build(root, &root.join("target").join("builtins-target"), &out)
            .context("building the built-in modules")?;
    for module in &built {
        println!(
            "{} {}",
            module.package,
            oncl_builtins_build::hex(&module.sha256)
        );
    }
    Ok((out, built))
}

/// The built-in modules a build of the workspace `root` embeds: those of `ONCL_BUILTINS_DIR`
/// if it is set (built once for every flavor of a release), else built now into
/// [`DEFAULT_OUT`]. Returns their folder, absolute.
///
/// # Errors
///
/// As [`build`].
pub fn prepare(root: &Path) -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os(oncl_builtins_build::BUILTINS_DIR_VAR) {
        let dir = PathBuf::from(dir);
        println!("The built-in modules of {}", dir.display());
        return std::path::absolute(&dir).with_context(|| format!("{}", dir.display()));
    }
    Ok(build(root, &root.join(DEFAULT_OUT))?.0)
}

/// Checks that the program `exe` embeds the modules laid out in `dir`: the SHA-256 of each
/// module `exe builtins` lists is that of a `plugin.wasm` of `dir`'s `SHA256SUMS`, one each.
///
/// # Errors
///
/// The program does not run, or embeds other modules.
pub fn check(exe: &Path, dir: &Path) -> anyhow::Result<()> {
    let output = std::process::Command::new(exe)
        .arg("builtins")
        .output()
        .with_context(|| format!("running {}", exe.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "{} builtins: {}",
        exe.display(),
        output.status
    );
    let listed = String::from_utf8(output.stdout).context("the output is not UTF-8")?;
    let sums_path = dir.join(oncl_builtins_build::SUMS);
    let sums =
        std::fs::read_to_string(&sums_path).with_context(|| format!("{}", sums_path.display()))?;
    let built: Vec<&str> = sums
        .lines()
        .filter_map(|line| line.split_once("  "))
        .filter(|(_, path)| path.ends_with("/plugin.wasm"))
        .map(|(sum, _)| sum)
        .collect();
    let embedded: Vec<&str> = listed
        .lines()
        .map(|line| line.rsplit(' ').next().unwrap_or_default())
        .collect();
    anyhow::ensure!(
        embedded.len() == built.len() && embedded.iter().all(|sum| built.contains(sum)),
        "{} embeds other built-in modules than {}:\n{listed}",
        exe.display(),
        sums_path.display()
    );
    println!(
        "{}: {} built-in module(s) as built",
        exe.display(),
        embedded.len()
    );
    Ok(())
}
