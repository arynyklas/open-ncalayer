//! The command line of `cargo xtask winget`.

use std::path::PathBuf;

use anyhow::Context;
use clap::Subcommand;

use super::download::Https;
use super::ledger::Ledger;
use super::manifest::{self, Mode};
use super::{Request, generate};

/// The default hash ledger, relative to the workspace root.
const LEDGER: &str = "winget/hash-ledger.json";

/// `cargo xtask winget …`: WinGet manifests of the stable desktop release. Nothing here
/// submits anything (`docs/dev/winget.md`).
#[derive(Subcommand)]
pub enum WingetCommand {
    /// Make the CANDIDATE manifest for the installation proof run on clean machines: it is
    /// built from a published stable release and the bytes of its two installers, and has no
    /// Apps & Features mapping yet. Not for submission.
    Candidate {
        /// The release object of the GitHub API (`gh api repos/arynyklas/open-ncalayer/releases/tags/v<version>`).
        #[arg(long)]
        release_json: PathBuf,
        /// The directory to write (new or empty).
        #[arg(long, default_value = "target/winget-candidate")]
        out: PathBuf,
        /// The hashes of submitted versions [default: winget/hash-ledger.json].
        #[arg(long)]
        ledger: Option<PathBuf>,
        /// The evidence file [default: <out>.evidence.json].
        #[arg(long)]
        evidence: Option<PathBuf>,
    },
    /// Make the final manifest from a published stable release and the merged probe reports
    /// of the proof run; refuses unless every claim of the reports holds for the published bytes.
    Generate {
        /// The release object of the GitHub API.
        #[arg(long)]
        release_json: PathBuf,
        /// The merged installer probe reports (`scripts/winget/Merge-ProbeCells.ps1`).
        #[arg(long)]
        probe: PathBuf,
        /// The directory to write (new or empty).
        #[arg(long, default_value = "target/winget")]
        out: PathBuf,
        /// The hashes of submitted versions [default: winget/hash-ledger.json].
        #[arg(long)]
        ledger: Option<PathBuf>,
        /// The evidence file [default: <out>.evidence.json].
        #[arg(long)]
        evidence: Option<PathBuf>,
        /// Accept probe reports that say they are synthetic fixtures. The output is marked and
        /// is not for submission.
        #[arg(long)]
        allow_synthetic_fixture: bool,
    },
    /// Check a manifest directory with the pinned schemas 1.12.0 and the package's invariants
    /// (the same check `generate` runs on what it writes). Schema validation is not an
    /// installer proof; run `winget validate <dir>` as well.
    Check {
        /// The manifest directory.
        dir: PathBuf,
        /// Expect a candidate (no Apps & Features mapping) instead of a final manifest.
        #[arg(long)]
        candidate: bool,
    },
}

fn read_ledger(path: Option<PathBuf>) -> anyhow::Result<Ledger> {
    let path = path.unwrap_or_else(|| oncl_testkit::workspace_root().join(LEDGER));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading the hash ledger {}", path.display()))?;
    Ledger::parse(&text)
}

fn evidence_path(out: &std::path::Path, evidence: Option<PathBuf>) -> PathBuf {
    evidence.unwrap_or_else(|| PathBuf::from(format!("{}.evidence.json", out.display())))
}

/// Runs `command`.
///
/// # Errors
///
/// The command's refusal, with the reason.
pub fn run(command: WingetCommand) -> anyhow::Result<()> {
    match command {
        WingetCommand::Candidate {
            release_json,
            out,
            ledger,
            evidence,
        } => {
            let release = std::fs::read_to_string(&release_json)
                .with_context(|| format!("reading {}", release_json.display()))?;
            let ledger = read_ledger(ledger)?;
            let evidence = evidence_path(&out, evidence);
            let done = generate(
                &Request {
                    release_json: &release,
                    probe_json: None,
                    ledger: &ledger,
                    allow_synthetic: false,
                    out: &out,
                    evidence: &evidence,
                },
                &Https::new(),
            )?;
            println!(
                "candidate manifest of {} in {} (evidence: {}): for the proof run on clean machines, NOT for submission",
                done.evidence.version,
                done.dir.display(),
                evidence.display()
            );
            Ok(())
        }
        WingetCommand::Generate {
            release_json,
            probe,
            out,
            ledger,
            evidence,
            allow_synthetic_fixture,
        } => {
            let release = std::fs::read_to_string(&release_json)
                .with_context(|| format!("reading {}", release_json.display()))?;
            let probe = std::fs::read_to_string(&probe)
                .with_context(|| format!("reading {}", probe.display()))?;
            let ledger = read_ledger(ledger)?;
            let evidence = evidence_path(&out, evidence);
            let done = generate(
                &Request {
                    release_json: &release,
                    probe_json: Some(&probe),
                    ledger: &ledger,
                    allow_synthetic: allow_synthetic_fixture,
                    out: &out,
                    evidence: &evidence,
                },
                &Https::new(),
            )?;
            println!(
                "manifest of {} in {} (evidence: {}): {}\nrun `winget validate {}`; nothing was submitted",
                done.evidence.version,
                done.dir.display(),
                evidence.display(),
                done.evidence.status,
                done.dir.display()
            );
            Ok(())
        }
        WingetCommand::Check { dir, candidate } => {
            let mode = if candidate {
                Mode::Candidate
            } else {
                Mode::Final
            };
            let checked = manifest::check_dir(&dir, mode)?;
            println!(
                "{}: schema 1.12.0 and the package invariants hold for {} {} ({} installers); this is not an installer proof",
                dir.display(),
                manifest::PACKAGE_IDENTIFIER,
                checked.version,
                checked.installers.len()
            );
            Ok(())
        }
    }
}
