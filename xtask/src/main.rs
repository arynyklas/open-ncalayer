use clap::{Parser, Subcommand};

/// OpenNCALayer development tasks.
#[derive(Parser)]
#[command(name = "cargo xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Download pinned NCANode test fixtures into `target/fixtures/ncanode/`.
    FetchFixtures,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::FetchFixtures => xtask::fetch::fetch_fixtures(),
    }
}
