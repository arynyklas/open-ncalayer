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
    /// Fail if the executables import DLLs or functions that Windows 7 lacks; an import from
    /// an app-local DLL next to the executable passes if that DLL exports it.
    CheckImports {
        #[arg(required = true)]
        exes: Vec<PathBuf>,
    },
    /// Browser extension tasks.
    Ext {
        #[command(subcommand)]
        command: ExtCommand,
    },
    /// Browser e2e of the extension over native messaging (Linux only).
    ExtE2e {
        /// Browsers to run.
        #[arg(long, value_enum, default_value_t = xtask::e2e::Selection::All)]
        browser: xtask::e2e::Selection,
        /// Download Chrome for Testing, Firefox and their drivers into `target/browsers/`
        /// instead of taking them from ONCL_CHROME, ONCL_CHROMEDRIVER, ONCL_FIREFOX and
        /// ONCL_GECKODRIVER.
        #[arg(long)]
        download: bool,
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
    /// Generate the third-party licence texts of the programs for the About window
    /// (`crates/oncl-ui/assets/THIRD-PARTY.txt`) from the local cargo registry.
    Licenses {
        /// Regenerate in memory and fail if the committed file differs.
        #[arg(long)]
        check: bool,
    },
    /// Verify our XMLDSig and CMS signatures with NCANode (Kalkan) in Docker (Linux only).
    InteropNcanode,
    /// Build the Windows 7 programs with their app-local DLLs into `<out>/<arch>/`, run the
    /// import gate on them and, on Windows, start them there.
    Win7 {
        /// Architectures to build.
        #[arg(long, value_enum, default_value_t = xtask::win7::Selection::All)]
        arch: xtask::win7::Selection,
        /// Output directory [default: target/win7].
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ExtCommand {
    /// Build the unpacked extensions and their zip/xpi into `target/extension/`.
    Build,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::CheckImports { exes } => match xtask::imports::check_imports(&exes)? {
            0 => Ok(()),
            found => anyhow::bail!("{found} violations of the Windows 7 import gate"),
        },
        Command::Ext {
            command: ExtCommand::Build,
        } => {
            let root = oncl_testkit::workspace_root();
            let out = root.join("target").join("extension");
            for package in xtask::ext::build(&root, &out)? {
                println!(
                    "{}: {} and {}",
                    package.browser,
                    package.dir.display(),
                    package.archive.display()
                );
            }
            Ok(())
        }
        Command::ExtE2e { browser, download } => {
            xtask::e2e::run(&oncl_testkit::workspace_root(), browser, download)
        }
        Command::FetchFixtures => xtask::fetch::fetch_fixtures(),
        Command::InteropOpenssl => xtask::interop::interop_openssl(&oncl_testkit::workspace_root()),
        Command::InteropNcanode => xtask::ncanode::interop_ncanode(),
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
        Command::Licenses { check: false } => {
            let path = xtask::licenses::write(&oncl_testkit::workspace_root())?;
            println!("{}", path.display());
            Ok(())
        }
        Command::Licenses { check: true } => {
            if !xtask::licenses::check(&oncl_testkit::workspace_root())? {
                anyhow::bail!(
                    "{} is stale: run `cargo xtask licenses`",
                    xtask::licenses::OUTPUT
                );
            }
            println!("{} is up to date", xtask::licenses::OUTPUT);
            Ok(())
        }
        Command::Win7 { arch, out } => {
            let root = oncl_testkit::workspace_root();
            let out = out.unwrap_or_else(|| root.join("target").join("win7"));
            xtask::win7::run(&root, arch, &out)
        }
    }
}
