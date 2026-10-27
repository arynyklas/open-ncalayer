use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use oncl_update::Channel;
use time::OffsetDateTime;

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
    /// Sign an update index with minisign: writes `<index>.minisig` beside it, with the
    /// trusted comment `channel=<channel>;seq=<seq>`. The password is read without echo.
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Sign {
        #[command(subcommand)]
        command: Option<SignCommand>,
        /// The index, e.g. `updates/v1/beta.json`.
        #[arg(required = true)]
        index: Option<PathBuf>,
        /// The encrypted secret key made by `sign keygen`.
        #[arg(long, required = true)]
        key: Option<PathBuf>,
    },
    /// Update index tasks (`updates/v1/<channel>.json`).
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
}

#[derive(Subcommand)]
enum SignCommand {
    /// Make the minisign key pair of the update index: the secret key encrypted with a
    /// password (read without echo) and the public key. Refuses a directory where git could
    /// commit the secret key.
    Keygen {
        /// The directory of the key pair, outside the repository (or git-ignored).
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum IndexCommand {
    /// Append a released version to the channel's index, from the release's downloaded
    /// assets: sha256 and sizes of its packages, the next `seq`, 30 days of validity. The
    /// result is unsigned.
    Add {
        /// `stable` or `beta`.
        #[arg(long, value_parser = parse_channel)]
        channel: Channel,
        /// The release tag, `v<version>`.
        #[arg(long)]
        tag: String,
        /// The downloaded assets of the release.
        #[arg(long)]
        release_assets: PathBuf,
        /// Percentage of installations offered the version.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u8).range(0..=100))]
        rollout: u8,
        /// The directory of the indexes [default: `updates/v1/` of the workspace].
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Check the indexes in a directory before publishing: format, signature by a trusted
    /// key, validity, `seq` growth against the base branch, and that every asset answers
    /// `HEAD` with 200.
    Check {
        /// The directory of the indexes, e.g. `updates/v1`.
        dir: PathBuf,
        /// Skip the network checks (asset URLs, `vm-smoke`).
        #[arg(long)]
        offline: bool,
        /// The git revision of the base branch.
        #[arg(long, default_value = "origin/main")]
        base: String,
        /// The directory of the trusted public keys [default: `crates/oncl-update/keys/`].
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Require the `vm-smoke` commit status to be `success` on the tag of every new
        /// version (off until the lab runs it).
        #[arg(long, conflicts_with = "offline")]
        vm_smoke: bool,
    },
}

fn parse_channel(name: &str) -> Result<Channel, String> {
    Channel::ALL
        .into_iter()
        .find(|c| c.as_str() == name)
        .ok_or_else(|| format!("{name:?} is not a channel (stable, beta)"))
}

/// Reads a password from the terminal without echo.
fn password(prompt: &str) -> anyhow::Result<String> {
    rpassword::prompt_password(prompt).context("reading the password")
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
            found => anyhow::bail!("{found} imports are missing on Windows 7"),
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
        Command::Sign {
            command: Some(SignCommand::Keygen { out }),
            ..
        } => {
            xtask::sign::keygen_target(&out)?;
            let first = password("Password of the new secret key: ")?;
            if password("The password again: ")? != first {
                bail!("the passwords differ");
            }
            let files = xtask::sign::keygen(&out, &first)?;
            println!(
                "Secret key: {} (keep it offline, never in the repository)",
                files.secret.display()
            );
            println!("Public key: {}", files.public.display());
            println!(
                "Copy the public key to {}/current.pub (or next.pub, to prepare a key \
                 rotation) and commit it.",
                xtask::sign::TRUSTED_KEYS_DIR
            );
            Ok(())
        }
        Command::Sign {
            command: None,
            index,
            key,
        } => {
            let (Some(index), Some(key)) = (index, key) else {
                bail!("`sign` needs an index and --key");
            };
            let secret = xtask::sign::load_secret_key(
                &key,
                &password(&format!("Password of {}: ", key.display()))?,
            )?;
            let signature = xtask::sign::sign(&index, &secret, OffsetDateTime::now_utc())?;
            println!("{}", signature.display());
            Ok(())
        }
        Command::Index {
            command:
                IndexCommand::Add {
                    channel,
                    tag,
                    release_assets,
                    rollout,
                    dir,
                },
        } => {
            let dir =
                dir.unwrap_or_else(|| oncl_testkit::workspace_root().join(xtask::index::INDEX_DIR));
            let added = xtask::index::add(
                &dir,
                channel,
                &tag,
                &release_assets,
                rollout,
                OffsetDateTime::now_utc(),
            )?;
            let flavors: Vec<_> = added.flavors.iter().map(|f| f.as_str()).collect();
            println!(
                "{}: seq {}, {tag} for {}{}",
                added.path.display(),
                added.seq,
                flavors.join(", "),
                if added.extension {
                    " and the extension"
                } else {
                    ""
                }
            );
            if let Some(signature) = added.removed_signature {
                println!("removed the stale {}", signature.display());
            }
            println!(
                "unsigned: cargo xtask sign {} --key <secret key>",
                added.path.display()
            );
            Ok(())
        }
        Command::Index {
            command:
                IndexCommand::Check {
                    dir,
                    offline,
                    base,
                    keys,
                    vm_smoke,
                },
        } => {
            let keys = keys.unwrap_or_else(|| {
                oncl_testkit::workspace_root().join(xtask::sign::TRUSTED_KEYS_DIR)
            });
            let keys = xtask::index::trusted_keys(&keys)?;
            let github = xtask::index::GitHub::new();
            let remote: Option<&dyn xtask::index::Remote> =
                if offline { None } else { Some(&github) };
            let options = xtask::index::CheckOptions {
                keys: &keys,
                base: Some(&base),
                vm_smoke,
                now: OffsetDateTime::now_utc(),
            };
            for checked in xtask::index::check(&dir, &options, remote)? {
                let versions: Vec<_> = checked.new_versions.iter().map(|v| v.to_string()).collect();
                println!(
                    "{}: seq {} (base {}), new versions: {}",
                    checked.channel,
                    checked.seq,
                    checked
                        .base_seq
                        .map_or_else(|| "none".to_owned(), |s| s.to_string()),
                    if versions.is_empty() {
                        "none".to_owned()
                    } else {
                        versions.join(", ")
                    }
                );
            }
            if offline {
                println!("offline: asset URLs and vm-smoke not checked");
            }
            Ok(())
        }
    }
}
