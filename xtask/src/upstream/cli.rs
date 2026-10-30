//! The `cargo xtask upstream` subcommands.

use clap::Subcommand;

/// `cargo xtask upstream …`.
#[derive(Debug, Subcommand)]
pub enum UpstreamCommand {
    /// Sign `fixtures/upstream/manifest.json` into `fixtures/upstream/manifest.der` with the
    /// synthetic `CN=NCALayer` signer (run by `fixtures/upstream/make.sh`).
    MakeFixtures,
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
    }
}
