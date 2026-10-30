//! The `cargo xtask upstream` subcommands.

use std::path::PathBuf;

use anyhow::Context;
use clap::Subcommand;

use super::Endpoints;
use super::http::Fetcher;
use super::poll::poll;
use super::state::State;

/// `cargo xtask upstream …`.
#[derive(Debug, Subcommand)]
pub enum UpstreamCommand {
    /// Sign `fixtures/upstream/manifest.json` into `fixtures/upstream/manifest.der` with the
    /// synthetic `CN=NCALayer` signer (run by `fixtures/upstream/make.sh`).
    MakeFixtures,
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
}

/// Runs `command`.
///
/// # Errors
///
/// What the subcommand fails with.
pub fn run(command: UpstreamCommand) -> anyhow::Result<()> {
    let root = oncl_testkit::workspace_root();
    match command {
        UpstreamCommand::MakeFixtures => super::testkit::make_fixtures(&root),
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
    }
}
