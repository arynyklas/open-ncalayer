use std::path::PathBuf;

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
    /// Fail if the executables import DLLs or functions that Windows 7 lacks.
    CheckImports {
        #[arg(required = true)]
        exes: Vec<PathBuf>,
    },
    /// Download pinned NCANode test fixtures into `target/fixtures/ncanode/`.
    FetchFixtures,
    /// Generate the deterministic synthetic PKI in `fixtures/synthetic/`.
    GenFixtures {
        /// Regenerate in memory and fail if the committed files differ.
        #[arg(long)]
        check: bool,
    },
    /// Sign with the synthetic RSA key and check the CMS with `openssl cms -verify`.
    InteropOpenssl,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::CheckImports { exes } => match xtask::imports::check_imports(&exes)? {
            0 => Ok(()),
            found => anyhow::bail!("{found} imports are missing on Windows 7"),
        },
        Command::FetchFixtures => xtask::fetch::fetch_fixtures(),
        Command::InteropOpenssl => xtask::interop::interop_openssl(&oncl_testkit::workspace_root()),
        Command::GenFixtures { check: false } => {
            xtask::fixtures::gen_fixtures(&oncl_testkit::workspace_root())
        }
        Command::GenFixtures { check: true } => {
            if !xtask::fixtures::check(&oncl_testkit::workspace_root())? {
                anyhow::bail!("fixtures/synthetic is stale: run `cargo xtask gen-fixtures`");
            }
            println!("fixtures/synthetic is up to date");
            Ok(())
        }
    }
}
