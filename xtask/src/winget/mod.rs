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
    /// Skip the check of `final_cells`: makes the final directory that the final-manifest
    /// proof cells install from. The files are the same bytes the complete run will write, but
    /// the evidence says NOT READY.
    pub final_proof_pending: bool,
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
    /// The verdict file written next to the directory.
    pub status: StatusFile,
}

/// Whether a directory may be submitted. A not-ready directory is byte-identical to a ready one,
/// which is why this is written next to it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Every proof, the program's own update included.
    Ready,
    /// Everything but the self-update, and the owner's waiver of that is recorded in the probe.
    SubmittableWithWaiver,
    /// Anything else.
    NotReady,
}

/// `<out>.status.json`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusFile {
    /// The verdict.
    pub verdict: Verdict,
    /// Why not.
    pub reasons: Vec<String>,
    /// The recorded waiver, for `submittable-with-waiver`.
    pub waiver: Option<probe::Waiver>,
    /// The version.
    pub version: String,
    /// [`manifest::files_digest`] of the directory this status is about.
    pub manifest_files_sha256: String,
    /// SHA-256 of the release JSON this was made from.
    pub release_sha256: String,
    /// SHA-256 of the probe report, if there was one.
    pub probe_sha256: Option<String>,
    /// The version of the generator that wrote it.
    pub generator_version: String,
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
    /// `verdict == Ready`.
    pub ready: bool,
    /// ready, submittable-with-waiver or not-ready (also in `<out>.status.json`).
    pub verdict: Verdict,
    /// Why not (empty when ready).
    pub reasons: Vec<String>,
    /// The program's own update was seen installing a newer release in every cell.
    pub self_update_proven: bool,
    /// The installers as downloaded.
    pub installers: Vec<InstallerEvidence>,
    /// SHA-256 of the candidate `installer.yaml`: what the proof run must have used.
    pub candidate_installer_yaml_sha256: String,
    /// How many probe cells the manifest rests on (final only).
    pub probe_cells: Option<usize>,
    /// The ledger entry to commit with the submission.
    pub ledger_entry: Ledger,
}

/// The files as (name, bytes), for [`manifest::files_digest`].
fn owned(files: &manifest::Files) -> Vec<(String, Vec<u8>)> {
    files
        .iter()
        .map(|(name, text)| (name.clone(), text.clone().into_bytes()))
        .collect()
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

    let (files, mode, synthetic, proof) = match request.probe_json {
        None => (candidate, Mode::Candidate, false, None::<probe::Proof>),
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
            // The shipped manifest itself must have been installed, upgraded, uninstalled.
            if !request.final_proof_pending {
                set.prove_final(&release, &manifest::files_digest(&owned(&files)))?;
            }
            (
                files,
                if proof.synthetic {
                    Mode::Fixture
                } else {
                    Mode::Final
                },
                proof.synthetic,
                Some(proof),
            )
        }
    };

    write_checked(request.out, &files, mode, &hashes)?;

    let self_update_proven = proof.as_ref().is_some_and(|p| p.self_update_proven);
    let waiver = proof.as_ref().and_then(|p| p.waiver.clone());
    let version = release.version.to_string();
    // Everything that stops the directory from being submitted, in words; the self-update gap
    // is the one thing a recorded waiver of the owner can cover.
    let mut blocking: Vec<String> = Vec::new();
    match mode {
        Mode::Candidate => {
            blocking.push("this is the candidate for the proof run, not a manifest".to_owned())
        }
        Mode::Fixture => blocking.push("the inputs are synthetic test fixtures".to_owned()),
        Mode::Final => {}
    }
    if request.final_proof_pending {
        blocking.push(
            "the final manifest's installation proof is pending: install, upgrade and uninstall from this directory, then generate again without --final-proof-pending"
                .to_owned(),
        );
    }
    let self_update_gap = mode != Mode::Candidate && !self_update_proven;
    let verdict = if !blocking.is_empty() {
        Verdict::NotReady
    } else if !self_update_gap {
        Verdict::Ready
    } else if waiver.is_some() {
        Verdict::SubmittableWithWaiver
    } else {
        Verdict::NotReady
    };
    let mut reasons = blocking;
    if self_update_gap {
        reasons.push(
            "self-update is NOT PROVEN: no cell saw the program install a newer release; the first stable release can never prove it"
                .to_owned(),
        );
    }
    let digest = manifest::files_digest(&owned(&files));
    let status_file = StatusFile {
        verdict,
        reasons: reasons.clone(),
        waiver: if verdict == Verdict::SubmittableWithWaiver {
            waiver.clone()
        } else {
            None
        },
        version: version.clone(),
        manifest_files_sha256: digest,
        release_sha256: sha256_hex(request.release_json.as_bytes()),
        probe_sha256: request.probe_json.map(|p| sha256_hex(p.as_bytes())),
        generator_version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let evidence = Evidence {
        manifest: match mode {
            Mode::Candidate => "candidate",
            Mode::Final | Mode::Fixture => "final",
        },
        package_identifier: manifest::PACKAGE_IDENTIFIER,
        version: version.clone(),
        tag: release.tag.clone(),
        synthetic,
        submitted: false,
        ready: verdict == Verdict::Ready,
        verdict,
        reasons,
        self_update_proven,
        status: match verdict {
            Verdict::Ready => "ready locally; probe reports are operator attestations checked only for consistency with the published bytes; nothing is submitted and the package is not available in WinGet",
            Verdict::SubmittableWithWaiver => "submittable only with the owner's recorded waiver of the self-update proof; nothing is submitted and the package is not available in WinGet",
            Verdict::NotReady => "NOT READY: do not submit this directory",
        }
        .to_owned(),
        installers: evidence_installers,
        candidate_installer_yaml_sha256: candidate_installer_sha,
        probe_cells: proof.as_ref().map(|p| p.cells),
        ledger_entry: Ledger::entry(&version, &hashes),
    };
    // Next to the manifest directory, never in it: `winget validate` must see only manifest files.
    let status_path = PathBuf::from(format!("{}.status.json", request.out.display()));
    let status_json = serde_json::to_string_pretty(&status_file).context("writing the status")?;
    std::fs::write(&status_path, format!("{status_json}\n"))
        .with_context(|| format!("writing {}", status_path.display()))?;
    let json = serde_json::to_string_pretty(&evidence).context("writing the evidence")?;
    std::fs::write(request.evidence, format!("{json}\n"))
        .with_context(|| format!("writing {}", request.evidence.display()))?;
    Ok(Generated {
        dir: request.out.to_owned(),
        mode,
        evidence,
        status: status_file,
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

/// Whether `dir` may be submitted: the verdict is RECOMPUTED from the release and the probe
/// (everything `generate` does, downloads included, into a scratch directory) and must equal the
/// one in `<dir>.status.json`, describe exactly the files in `dir`, and not be `not-ready`.
/// `status.json` is an unsigned accident guard: it is never believed on its own, and none of
/// this protects against someone who can write the inputs. The probe is operator attestation.
///
/// # Errors
///
/// The first reason the directory is not submittable.
pub fn verify_for_submission(
    dir: &Path,
    release_json: &str,
    probe_json: &str,
    ledger: &Ledger,
    fetch: &dyn AssetFetch,
) -> anyhow::Result<StatusFile> {
    let path = format!("{}.status.json", dir.display());
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!("reading {path}: a directory without a status is not submittable")
    })?;
    let stored: StatusFile = serde_json::from_str(&text).context("the status file")?;
    let digest = manifest::dir_digest(dir)?;
    if stored.manifest_files_sha256 != digest {
        bail!("{path} is about other files than these");
    }
    if stored.release_sha256 != sha256_hex(release_json.as_bytes())
        || stored.probe_sha256.as_deref() != Some(sha256_hex(probe_json.as_bytes()).as_str())
    {
        bail!("{path} was made from another release JSON or probe report than the ones given");
    }
    let scratch = tempfile::tempdir().context("creating a scratch directory")?;
    let again = generate(
        &Request {
            release_json,
            probe_json: Some(probe_json),
            ledger,
            allow_synthetic: false,
            final_proof_pending: false,
            out: &scratch.path().join("manifest"),
            evidence: &scratch.path().join("evidence.json"),
        },
        fetch,
    )?;
    if again.status.manifest_files_sha256 != digest {
        bail!("these files are not what the release and the probe generate");
    }
    if again.status.verdict != stored.verdict {
        bail!(
            "{path} says {:?}, the inputs give {:?}",
            stored.verdict,
            again.status.verdict
        );
    }
    if again.status.verdict == Verdict::NotReady {
        bail!(
            "NOT READY, do not submit: {}",
            again.status.reasons.join("; ")
        );
    }
    Ok(again.status)
}
