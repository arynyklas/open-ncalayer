//! `cargo xtask winget`: the WinGet manifests of the desktop package, and the checks that
//! stand between a release and a manifest.
//!
//! ```text
//! published stable release (GitHub API JSON) ──┐
//! both installer assets, one stream each ──────┼─► candidate manifest ─► proof run on clean
//!                                              │                          machines (scripts/winget)
//! installer probe reports of that run ─────────┴─► final manifest ─► schema 1.12.0 + invariants
//! ```
//!
//! The generator never submits, forks, opens a pull request or reserves the package
//! identifier: it writes files to a directory and an evidence file next to it. What a real
//! `winget validate` and a real installation say is recorded by the maintainer's run
//! (`docs/dev/winget.md`); the first submission to `microsoft/winget-pkgs` needs its own
//! command from the project's owner.

pub mod cli;
pub mod download;
pub mod ledger;
pub mod manifest;
pub mod probe;
pub mod release;
pub mod schema;
pub mod yaml;

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use self::download::{AssetFetch, INSTALLER_MAX};
use self::ledger::Ledger;
use self::manifest::{Mode, Plan};
use self::probe::Published;

/// The architectures of the WinGet package.
#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// x64.
    X64,
    /// x86.
    X86,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Arch::X64 => "x64",
            Arch::X86 => "x86",
        })
    }
}

/// What one run takes.
pub struct Request<'a> {
    /// The release object of the GitHub API.
    pub release_json: &'a str,
    /// The merged probe reports; `None` makes a candidate manifest for the proof run.
    pub probe_json: Option<&'a str>,
    /// The hashes of versions already submitted.
    pub ledger: &'a Ledger,
    /// Accept probe reports of the synthetic fixtures (the tests of this repository).
    pub allow_synthetic: bool,
    /// The directory the manifest is written to: new or empty.
    pub out: &'a Path,
    /// Where the evidence file goes.
    pub evidence: &'a Path,
}

/// What a run produced.
#[derive(Clone, Debug)]
pub struct Generated {
    /// The manifest directory.
    pub dir: PathBuf,
    /// Candidate or final.
    pub mode: Mode,
    /// What was recorded in the evidence file.
    pub evidence: Evidence,
}

/// One downloaded installer.
#[derive(Clone, Debug, Serialize)]
pub struct InstallerEvidence {
    /// The architecture.
    pub arch: Arch,
    /// The asset.
    pub name: String,
    /// Where it was downloaded from.
    pub url: String,
    /// SHA-256 of the one stream, lowercase hex.
    pub sha256: String,
    /// Bytes.
    pub size: u64,
    /// The release API gave a digest and it equals the stream's.
    pub api_digest_checked: bool,
}

/// `<out>.evidence.json`.
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    /// `candidate` or `final`.
    pub manifest: &'static str,
    /// The package.
    pub package_identifier: &'static str,
    /// The version.
    pub version: String,
    /// The tag.
    pub tag: String,
    /// The inputs were synthetic fixtures: the output is not for submission.
    pub synthetic: bool,
    /// Always `false`: nothing is submitted by this tool.
    pub submitted: bool,
    /// What this is and is not.
    pub status: String,
    /// The installers as downloaded.
    pub installers: Vec<InstallerEvidence>,
    /// SHA-256 of the candidate `installer.yaml`: what the proof run must have used.
    pub candidate_installer_yaml_sha256: String,
    /// How many probe cells the manifest rests on (final only).
    pub probe_cells: Option<usize>,
    /// The ledger entry to commit with the submission.
    pub ledger_entry: Ledger,
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::upstream::hex(&Sha256::digest(bytes))
}

/// Makes the manifest: a candidate without `probe_json`, the final one with it.
///
/// # Errors
///
/// The release is not a stable published one ([`release::ReleaseError`]); an asset is not the
/// installer it should be ([`download::AssetError`]); a version already submitted is served with
/// other bytes ([`ledger::HashChanged`]); the probe does not prove its claims
/// ([`probe::ProbeError`]); the output directory is not empty; the written manifest fails its
/// own check (the files are removed again).
pub fn generate(request: &Request<'_>, fetch: &dyn AssetFetch) -> anyhow::Result<Generated> {
    let release = release::parse(request.release_json)?.stable()?;

    // One stream per installer: the only source of the hashes.
    let scratch = tempfile::tempdir().context("creating a scratch directory")?;
    let mut published = Vec::new();
    let mut evidence_installers = Vec::new();
    for asset in &release.installers {
        let dest = scratch.path().join(&asset.name);
        let done = fetch.fetch(&asset.url, INSTALLER_MAX, &dest)?;
        download::inspect(
            &asset.name,
            &dest,
            &done,
            asset.size,
            asset.api_sha256.as_deref(),
            asset.arch,
            &release.version,
        )?;
        evidence_installers.push(InstallerEvidence {
            arch: asset.arch,
            name: asset.name.clone(),
            url: asset.url.clone(),
            sha256: done.sha256.clone(),
            size: done.size,
            api_digest_checked: asset.api_sha256.is_some(),
        });
        published.push(Published {
            arch: asset.arch,
            sha256: done.sha256,
            size: done.size,
        });
    }
    let hashes: Vec<(Arch, String)> = published
        .iter()
        .map(|p| (p.arch, p.sha256.clone()))
        .collect();
    request
        .ledger
        .check(&release.version.to_string(), &hashes)?;

    // The candidate is what the proof run installs from; its installer.yaml is reproducible
    // from the release and the downloaded bytes alone.
    let candidate = manifest::render(&Plan {
        release: &release,
        sha256: &hashes,
        identity: None,
        synthetic: false,
    });
    let candidate_installer_sha = sha256_hex(candidate[2].1.as_bytes());

    let (files, mode, synthetic, cells) = match request.probe_json {
        None => (candidate, Mode::Candidate, false, None),
        Some(json) => {
            let set = probe::parse(json)?;
            let proof = set.prove(
                &release,
                &published,
                &candidate_installer_sha,
                request.allow_synthetic,
            )?;
            let files = manifest::render(&Plan {
                release: &release,
                sha256: &hashes,
                identity: Some(&proof.identity),
                synthetic: proof.synthetic,
            });
            (files, Mode::Final, proof.synthetic, Some(proof.cells))
        }
    };

    write_checked(request.out, &files, mode, &hashes)?;

    let version = release.version.to_string();
    let evidence = Evidence {
        manifest: match mode {
            Mode::Candidate => "candidate",
            Mode::Final => "final",
        },
        package_identifier: manifest::PACKAGE_IDENTIFIER,
        version: version.clone(),
        tag: release.tag.clone(),
        synthetic,
        submitted: false,
        status: match (mode, synthetic) {
            (Mode::Candidate, _) => "candidate for the installation proof run; not for submission",
            (Mode::Final, true) => "SYNTHETIC test fixture; not for submission",
            (Mode::Final, false) => {
                "ready locally; nothing is submitted and the package is not available in WinGet"
            }
        }
        .to_owned(),
        installers: evidence_installers,
        candidate_installer_yaml_sha256: candidate_installer_sha,
        probe_cells: cells,
        ledger_entry: Ledger::entry(&version, &hashes),
    };
    let json = serde_json::to_string_pretty(&evidence).context("writing the evidence")?;
    std::fs::write(request.evidence, format!("{json}\n"))
        .with_context(|| format!("writing {}", request.evidence.display()))?;
    Ok(Generated {
        dir: request.out.to_owned(),
        mode,
        evidence,
    })
}

/// Writes `files` into `out` (new or empty) and checks them as a reader would; a manifest that
/// fails is removed again.
fn write_checked(
    out: &Path,
    files: &manifest::Files,
    mode: Mode,
    hashes: &[(Arch, String)],
) -> anyhow::Result<()> {
    if out.exists() {
        let empty = std::fs::read_dir(out)
            .with_context(|| format!("reading {}", out.display()))?
            .next()
            .is_none();
        if !empty {
            bail!(
                "{} is not empty: remove it first, a manifest directory holds exactly its three files",
                out.display()
            );
        }
    }
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let written = (|| -> anyhow::Result<()> {
        for (name, text) in files {
            std::fs::write(out.join(name), text).with_context(|| format!("writing {name}"))?;
        }
        let checked = manifest::check_dir(out, mode)?;
        for (arch, _, sha) in &checked.installers {
            let downloaded = hashes
                .iter()
                .find(|(a, _)| a == arch)
                .map(|(_, sha)| sha.to_ascii_uppercase());
            if downloaded.as_deref() != Some(sha.as_str()) {
                bail!("the manifest's {arch} hash is not the hash of the downloaded installer");
            }
        }
        Ok(())
    })();
    if written.is_err() {
        for (name, _) in files {
            let _ = std::fs::remove_file(out.join(name));
        }
    }
    written
}
