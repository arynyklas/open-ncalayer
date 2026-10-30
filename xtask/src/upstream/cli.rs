//! The `cargo xtask upstream` subcommands.

use std::path::PathBuf;

use anyhow::Context;
use clap::Subcommand;

use super::Endpoints;
use super::branch_layout::ToolVersions;
use super::http::Fetcher;
use super::poll::poll;
use super::run::{self as cycle, RunOptions};
use super::state::State;
use super::unpack::{Limits, Tools};

/// `cargo xtask upstream …`.
#[derive(Debug, Subcommand)]
pub enum UpstreamCommand {
    /// Sign `fixtures/upstream/manifest.json` into `fixtures/upstream/manifest.der` with the
    /// synthetic `CN=NCALayer` signer (run by `fixtures/upstream/make.sh`).
    MakeFixtures {
        /// Write the signed manifest here instead (the copy inside the launcher JAR).
        #[arg(long)]
        embedded: Option<PathBuf>,
    },
    /// Poll the sources once against `<state>/state.json` and print the changes (source ids
    /// and reasons only).
    Poll {
        /// The directory of `state.json` (a checkout of the `upstream` branch).
        #[arg(long, default_value = "target/upstream/state")]
        state: PathBuf,
        /// Also write the changes as JSON here.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// One cycle: poll, download what changed into `--work`, unpack, facts, diff; the changed
    /// files of the `upstream` branch and `run.json` go to `--emit` (JSON only). Without
    /// `--dry-run` the emit directory is then published (as `upstream publish`).
    Run {
        /// A checkout of the `upstream` branch (or an empty directory).
        #[arg(long, default_value = "target/upstream/state")]
        state: PathBuf,
        /// Where the originals are downloaded and unpacked.
        #[arg(long, default_value = "target/upstream/work")]
        work: PathBuf,
        /// The emit directory.
        #[arg(long, default_value = "target/upstream/emit")]
        emit: PathBuf,
        /// Only write the emit directory.
        #[arg(long)]
        dry_run: bool,
        /// Append `changed=` and `alert=` lines here (`$GITHUB_OUTPUT`).
        #[arg(long)]
        github_output: Option<PathBuf>,
    },
    /// Fetch and check the pinned external unpackers into `--out`; prints `ONCL_INNOUNP=…`
    /// (Windows) and `ONCL_7Z=…` lines for `$GITHUB_ENV`.
    Tools {
        /// Where innounp goes.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Runs `command`.
///
/// # Errors
///
/// What the subcommand fails with.
pub fn run(command: UpstreamCommand) -> anyhow::Result<()> {
    let root = oncl_testkit::workspace_root();
    match command {
        UpstreamCommand::MakeFixtures { embedded } => {
            super::testkit::make_fixtures(&root, embedded.as_deref())
        }
        UpstreamCommand::Poll { state, out } => {
            let prev = State::load(&state)?;
            let result = poll(
                &prev,
                &Fetcher::new(),
                &Endpoints::default(),
                None,
                oncl_pki::roots::nca_production(),
            );
            for alert in &result.alerts {
                println!("alert: {} {}", alert.kind.name(), alert.detail);
            }
            for change in &result.changes {
                println!("poll: {}", serde_json::to_string(change)?);
            }
            if let Some(out) = out {
                std::fs::write(&out, super::pretty_json(&result.changes))
                    .with_context(|| format!("write {}", out.display()))?;
            }
            Ok(())
        }
        UpstreamCommand::Tools { out } => super::tools::tools(&out),
        UpstreamCommand::Run {
            state,
            work,
            emit,
            dry_run,
            github_output,
        } => {
            let tools = Tools::from_env();
            let tool_versions = ToolVersions {
                innounp: tools.innounp.as_ref().map(|_| "2.71.2".to_owned()),
                sevenzip: std::env::var_os("ONCL_7Z")
                    .filter(|v| !v.is_empty())
                    .and_then(|p| super::tools::sevenzip_version(std::path::Path::new(&p))),
            };
            let outcome = cycle::run(&RunOptions {
                state_dir: state,
                work,
                emit,
                dry_run,
                endpoints: Endpoints::default(),
                trusted: oncl_pki::roots::nca_production().to_vec(),
                tools,
                tool_versions,
                limits: Limits::default(),
                fetcher: Fetcher::new(),
                now: time::OffsetDateTime::now_utc(),
                github_output,
            })?;
            println!(
                "run: changed={} entry={} alerts={}",
                outcome.changed,
                outcome.entry.as_deref().unwrap_or("-"),
                outcome.alerts.len()
            );
            anyhow::ensure!(
                dry_run,
                "run without --dry-run: publish with `upstream publish`"
            );
            Ok(())
        }
    }
}
