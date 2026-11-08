//! `cargo xtask check-release-features`: the `testing` feature of the workspace crates
//! (`PluginUse::for_tests`, `PluginApproval::for_tests` and the like forge what Core never
//! would) must not be enabled in the **normal** dependency tree of any release program.
//!
//! A release is built with `-p <crate>`, whose normal tree has no dev-dependencies; but
//! `cargo build --workspace --all-targets` or `cargo test` unify the dev-dependencies' `testing`
//! into the same binaries. This check reads the exact resolution a release gets:
//! `cargo tree -p <crate> -e normal -f "{p} [{f}]"` prints every package with the features
//! enabled on it, and any `testing` there fails.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};

/// The release programs: the desktop, the CLI, the server and the UI.
pub const RELEASE_CRATES: [&str; 4] = ["openncalayer", "oncl-cli", "oncl-server", "oncl-ui"];

/// The packages of one `cargo tree -f "{p} [{f}]"` output with the `testing` feature enabled.
///
/// A line is `name vX.Y.Z (path) [feature,feature]`; the features are the last bracket group
/// (a package name never contains `[`).
pub fn packages_with_testing(tree: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in tree.lines() {
        let Some((head, rest)) = line.rsplit_once('[') else {
            continue;
        };
        let Some(features) = rest.trim_end().strip_suffix(']') else {
            continue;
        };
        if features.split(',').any(|f| f.trim() == "testing") {
            let name = head.split_whitespace().next().unwrap_or(head).to_owned();
            if !found.contains(&name) {
                found.push(name);
            }
        }
    }
    found
}

/// Runs the check for every [`RELEASE_CRATES`] at the workspace `root`.
///
/// # Errors
///
/// `cargo tree` fails, or some release program's normal tree enables `testing`.
pub fn run(root: &Path) -> anyhow::Result<()> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut offending = Vec::new();
    for krate in RELEASE_CRATES {
        let out = Command::new(&cargo)
            .args([
                "tree",
                "--locked",
                "--offline",
                "-p",
                krate,
                "-e",
                "normal",
                "--prefix",
                "none",
                "-f",
                "{p} [{f}]",
            ])
            .current_dir(root)
            .output()
            .with_context(|| format!("running cargo tree -p {krate}"))?;
        if !out.status.success() {
            bail!(
                "cargo tree -p {krate} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let tree = String::from_utf8(out.stdout).context("cargo tree output is not UTF-8")?;
        let found = packages_with_testing(&tree);
        if tree.lines().next().is_none() {
            bail!("cargo tree -p {krate} printed nothing");
        }
        if !found.is_empty() {
            offending.push(format!(
                "{krate}: `testing` enabled on {}",
                found.join(", ")
            ));
        }
    }
    if !offending.is_empty() {
        bail!(
            "the `testing` feature leaks into a release program's normal dependencies:\n{}",
            offending.join("\n")
        );
    }
    println!(
        "no `testing` feature in the normal tree of {}",
        RELEASE_CRATES.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_testing_only_as_a_whole_feature_name() {
        let tree = "\
openncalayer v0.1.0 (/w/crates/openncalayer) [default]
oncl-core v0.1.0 (/w/crates/oncl-core) [default,jose,plugins,testing,xml]
oncl-pki v0.1.0 (/w/crates/oncl-pki) [testing]
oncl-xml v0.1.0 (/w/crates/oncl-xml) [default,testing-extra]
oncl-flows v0.1.0 (/w/crates/oncl-flows) []
serde v1.0.0 [default,std]
";
        assert_eq!(packages_with_testing(tree), ["oncl-core", "oncl-pki"]);
        assert!(packages_with_testing("oncl-core v0.1.0 (/w) [default,xml]\n").is_empty());
    }
}
