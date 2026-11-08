//! `cargo xtask plugin-version-check`: a plugin port whose files changed since the last
//! `plugins-*` release tag must have a new version.
//!
//! `plugin pending` compares versions only; nothing else notices a port whose `plugin.toml`,
//! `Cargo.toml` or `src/` changed without a version bump (the release would then skip it, or
//! the package of the old version would differ from what the index promises). Compared: the
//! working tree against the last tag reachable from `HEAD` that matches `plugins-*`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};

/// Tags of plugin releases.
pub const TAG_PATTERN: &str = "plugins-*";

/// A port that changed without a version change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unbumped {
    pub port: String,
    pub version: String,
    /// The changed files below the repository root.
    pub files: Vec<String>,
}

/// The result.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// The tag compared against; `None`: there is none in this checkout.
    pub tag: Option<String>,
    pub unbumped: Vec<Unbumped>,
    /// Ports checked.
    pub checked: usize,
}

impl Report {
    pub fn to_text(&self) -> String {
        let Some(tag) = &self.tag else {
            return format!(
                "plugin-version-check: NOTICE: no tag matching `{TAG_PATTERN}` is reachable in this \
                 checkout (a shallow clone or one without tags?): nothing was checked\n"
            );
        };
        let mut out = String::new();
        for u in &self.unbumped {
            out += &format!(
                "plugin-version-check: error: {} changed since {tag} but stays at version {}: {}\n",
                u.port,
                u.version,
                u.files.join(", ")
            );
        }
        out += &format!(
            "plugin-version-check: {} ports against {tag}, {} unbumped\n",
            self.checked,
            self.unbumped.len()
        );
        out
    }
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.unbumped.is_empty())
    }
}

fn git(root: &Path, args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))
}

fn version_of(text: &str) -> Option<String> {
    let table: toml::Table = toml::from_str(text).ok()?;
    table.get("version")?.as_str().map(str::to_owned)
}

/// Checks every `plugins/<port>/plugin.toml` of the repository at `root`.
pub fn check(root: &Path) -> anyhow::Result<Report> {
    let described = git(
        root,
        &["describe", "--tags", "--abbrev=0", "--match", TAG_PATTERN],
    )?;
    if !described.status.success() {
        return Ok(Report {
            tag: None,
            unbumped: Vec::new(),
            checked: 0,
        });
    }
    let tag = String::from_utf8(described.stdout)?.trim().to_owned();
    let mut ports = Vec::new();
    for entry in std::fs::read_dir(root.join("plugins")).context("reading plugins/")? {
        let entry = entry?;
        if entry.path().join("plugin.toml").is_file() {
            ports.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    ports.sort();
    let mut report = Report {
        tag: Some(tag.clone()),
        unbumped: Vec::new(),
        checked: 0,
    };
    for port in ports {
        let manifest = format!("plugins/{port}/plugin.toml");
        let old = git(root, &["show", &format!("{tag}:{manifest}")])?;
        if !old.status.success() {
            continue; // a port the tag does not know: new, any version is new
        }
        report.checked += 1;
        let now = std::fs::read_to_string(root.join(&manifest))
            .with_context(|| format!("reading {manifest}"))?;
        let now_version = version_of(&now).with_context(|| format!("{manifest}: no version"))?;
        let old_version = version_of(&String::from_utf8_lossy(&old.stdout));
        if old_version.as_deref() != Some(now_version.as_str()) {
            continue;
        }
        let paths = [
            manifest.clone(),
            format!("plugins/{port}/Cargo.toml"),
            format!("plugins/{port}/src"),
        ];
        let mut args = vec!["diff", "--name-only", tag.as_str(), "--"];
        args.extend(paths.iter().map(String::as_str));
        let diff = git(root, &args)?;
        if !diff.status.success() {
            bail!(
                "git diff failed: {}",
                String::from_utf8_lossy(&diff.stderr).trim()
            );
        }
        let files: Vec<String> = String::from_utf8(diff.stdout)?
            .lines()
            .map(str::to_owned)
            .collect();
        if !files.is_empty() {
            report.unbumped.push(Unbumped {
                port,
                version: now_version,
                files,
            });
        }
    }
    Ok(report)
}
