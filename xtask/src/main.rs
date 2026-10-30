use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use oncl_update::{Channel, Version};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// OpenNCALayer development tasks.
#[derive(Parser)]
#[command(name = "cargo xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fail on imports from a list of DLLs and functions known to be missing on Windows 7 (a
    /// deny-list: passing does not show that a program runs there); an import from an
    /// app-local DLL next to the executable passes if that DLL exports it.
    CheckImports {
        #[arg(required = true)]
        exes: Vec<PathBuf>,
    },
    /// Fail on an ELF file that needs a glibc newer than 2.28 (the floor of the Linux
    /// packages) or a private glibc symbol; prints what each needs.
    CheckElf {
        #[arg(required = true)]
        files: Vec<PathBuf>,
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
        /// Download Chrome for Testing, Firefox, Firefox ESR 115 and their drivers into
        /// `target/browsers/` instead of taking them from ONCL_CHROME, ONCL_CHROMEDRIVER,
        /// ONCL_FIREFOX, ONCL_FIREFOX_ESR and ONCL_GECKODRIVER.
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
        /// The licences of the plugin ports (`plugins/THIRD-PARTY.txt`) instead.
        #[arg(long)]
        plugins: bool,
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
    /// Installers and update packages of a release (Velopack's `vpk` on the `PATH`, or
    /// `$VPK`); every command copies what is published into `--dist`.
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Update index tasks (`updates/v1/<channel>.json`).
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// Plugin tasks (`.onclp` packages).
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Serve the first card of an emulator configuration to vpcd (vsmartcard's virtual
    /// reader for pcscd) until the process is stopped: the PC/SC test of CI.
    TokenEmu {
        /// The emulator configuration (TOML); key paths are relative to the workspace root.
        #[arg(long)]
        config: PathBuf,
        /// vpcd's address [default: 127.0.0.1:35963].
        #[arg(long)]
        vpcd: Option<String>,
    },
    /// Build the Windows 7 programs with their app-local DLLs into `<out>/<arch>/`, run the
    /// import gate on them and, on Windows, start them there.
    Win7 {
        /// Architectures to build.
        #[arg(long, value_enum, default_value_t = xtask::win7::Selection::All)]
        arch: xtask::win7::Selection,
        /// Output directory [default: target/win7].
        #[arg(long)]
        out: Option<PathBuf>,
        /// Cargo's target directory for the build [default: the workspace's `target/`]. CI
        /// gives it one of its own to cache: the cache of `target/` drops the standard
        /// library `-Zbuild-std` builds, and every crate then rebuilds.
        #[arg(long)]
        target_dir: Option<PathBuf>,
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
    /// result is unsigned. The tag must hold a trusted update key (a build without one
    /// cannot update itself, so no installation may be moved onto it).
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
        /// The directory of the trusted public keys [default: `crates/oncl-update/keys/`].
        #[arg(long)]
        keys: Option<PathBuf>,
    },
    /// Give the channel's index the next `seq`, a new `generated` and 30 days of validity,
    /// and nothing else, to sign it again before it expires. The result is unsigned.
    Refresh {
        /// `stable` or `beta`.
        #[arg(long, value_parser = parse_channel)]
        channel: Channel,
        /// The directory of the indexes [default: `updates/v1/` of the workspace].
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Append plugin packages of a `plugins-YYYYMMDD[.N]` release to the channel's index:
    /// id, version, modules and hashes come from the packages. A prerelease plugin is not
    /// added to `stable`. The result is unsigned.
    AddPlugin {
        /// `stable` or `beta`.
        #[arg(long, value_parser = parse_channel)]
        channel: Channel,
        /// The release tag, `plugins-YYYYMMDD[.N]`.
        #[arg(long)]
        tag: String,
        /// The `.onclp` packages of the release (several after one flag, or the flag again).
        #[arg(long = "package", required = true, num_args = 1..)]
        packages: Vec<PathBuf>,
        /// Percentage of installations offered the new plugin versions.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u8).range(0..=100))]
        rollout: u8,
        /// The directory of the indexes [default: `updates/v1/` of the workspace].
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Check the indexes in a directory before publishing: format, signature by
    /// `current.pub` only (a `next.pub` is for clients, not for signing), validity, asset URLs
    /// on the project's releases, `seq` growth against the base branch, and that every asset
    /// answers `HEAD` with 200.
    Check {
        /// The directory of the indexes, e.g. `updates/v1`.
        dir: PathBuf,
        /// Skip the network checks (`HEAD` of the assets, `vm-smoke`).
        #[arg(long)]
        offline: bool,
        /// The git revision of the base branch.
        #[arg(long, default_value = "origin/main")]
        base: String,
        /// No base (a first push, a manual run): signatures, schema, expiry and URLs are
        /// checked; `seq` growth and the update key in the tags of new versions are not.
        #[arg(long)]
        no_base: bool,
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
fn password(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .context("reading the password")
}

/// The directory of the indexes: `dir`, or `updates/v1/` of the workspace.
fn index_dir(dir: Option<PathBuf>) -> PathBuf {
    dir.unwrap_or_else(|| oncl_testkit::workspace_root().join(xtask::index::INDEX_DIR))
}

/// Prints what [`xtask::index::add`] or [`xtask::index::refresh`] wrote.
fn print_written(written: &xtask::index::Written) {
    if let Some(signature) = &written.removed_signature {
        println!("removed the stale {}", signature.display());
    }
    println!(
        "unsigned: cargo xtask sign {} --key <secret key>",
        written.path.display()
    );
}

/// What every packaging command takes.
#[derive(clap::Args)]
struct PackageArgs {
    /// The version of the release.
    #[arg(long, value_parser = parse_version)]
    version: Version,
    /// Velopack's output: the previous full package for the delta goes here first.
    #[arg(long, default_value = "packages")]
    packages: PathBuf,
    /// Where the published files are copied.
    #[arg(long, default_value = "dist")]
    dist: PathBuf,
}

#[derive(Subcommand)]
enum PackageCommand {
    /// `Setup.exe` and the update packages of a Windows flavor (Windows 7 flavors through
    /// the import gate).
    Windows {
        /// `win-x64`, `win-x86`, `win7-x64` or `win7-x86`.
        #[arg(long)]
        flavor: String,
        /// The built programs (with the app-local DLLs for Windows 7).
        #[arg(long)]
        bin: PathBuf,
        #[command(flatten)]
        args: PackageArgs,
    },
    /// The universal macOS `.app` as `.zip` and `.pkg`, and the update packages (macOS).
    Macos {
        /// The universal programs.
        #[arg(long)]
        bin: PathBuf,
        /// A "Developer ID Installer" identity to sign the `.pkg`.
        #[arg(long)]
        install_identity: Option<String>,
        /// The keychain of the signing identities.
        #[arg(long)]
        keychain: Option<PathBuf>,
        /// A `notarytool` keychain profile: the `.pkg` is notarized and stapled.
        #[arg(long)]
        notary_profile: Option<String>,
        #[command(flatten)]
        args: PackageArgs,
    },
    /// Build the Linux programs and the AppDir in the glibc 2.28 container (Docker), into
    /// `target/linux-x64/`.
    LinuxBuild {
        /// The version of the release.
        #[arg(long, value_parser = parse_version)]
        version: Version,
        /// A Docker volume keeping the toolchain and cargo's files between runs.
        #[arg(long)]
        cache_volume: Option<String>,
    },
    /// Lay out and check the AppDir (inside the glibc 2.28 container).
    Appdir {
        /// The built programs.
        #[arg(long)]
        bin: PathBuf,
        /// The version of the release.
        #[arg(long, value_parser = parse_version)]
        version: Version,
        /// The AppDir to write.
        #[arg(long)]
        out: PathBuf,
    },
    /// The AppImage and the update packages from the AppDir, checked (Linux, Docker).
    Linux {
        /// The AppDir of `linux-build`.
        #[arg(long, default_value = "target/linux-x64/OpenNCALayer.AppDir")]
        appdir: PathBuf,
        #[command(flatten)]
        args: PackageArgs,
    },
    /// `PKGBUILD`, `.SRCINFO` and the install script of the AUR package `openncalayer-bin`.
    Aur {
        /// The version of the release.
        #[arg(long, value_parser = parse_version)]
        version: Version,
        /// The sha256 of the release's Linux archive.
        #[arg(long)]
        sha256: String,
        /// The package release of this version.
        #[arg(long, default_value_t = 1)]
        pkgrel: u32,
        /// Where to write the files.
        #[arg(long)]
        out: PathBuf,
    },
}

fn parse_version(text: &str) -> Result<Version, String> {
    Version::parse(text).map_err(|e| format!("{text:?} is not a version: {e}"))
}

/// Prints the published files.
fn print_published(files: &[PathBuf]) {
    for file in files {
        println!("published: {}", file.display());
    }
}

/// `cargo xtask package …`.
fn package(command: PackageCommand) -> anyhow::Result<()> {
    use xtask::package::{aur, linux, macos, windows};
    let root = oncl_testkit::workspace_root();
    match command {
        PackageCommand::Windows { flavor, bin, args } => {
            let flavor = windows::flavor(&flavor)?;
            print_published(&windows::package(
                &root,
                &flavor,
                &bin,
                &args.version,
                &args.packages,
                &args.dist,
            )?);
        }
        PackageCommand::Macos {
            bin,
            install_identity,
            keychain,
            notary_profile,
            args,
        } => {
            let signing = macos::PkgSigning {
                identity: install_identity,
                keychain,
                notary_profile,
            };
            print_published(&macos::package(
                &root,
                &bin,
                &args.version,
                &args.packages,
                &args.dist,
                &signing,
            )?);
        }
        PackageCommand::LinuxBuild {
            version,
            cache_volume,
        } => {
            let appdir = linux::build_in_container(&root, &version, cache_volume.as_deref())?;
            println!("{}", appdir.display());
        }
        PackageCommand::Appdir { bin, version, out } => linux::appdir(&root, &bin, &version, &out)?,
        PackageCommand::Linux { appdir, args } => {
            print_published(&linux::package(
                &root,
                &appdir,
                &args.version,
                &args.packages,
                &args.dist,
            )?);
        }
        PackageCommand::Aur {
            version,
            sha256,
            pkgrel,
            out,
        } => {
            for file in aur::Package::new(version, pkgrel, &sha256)?.write(&out)? {
                println!("{}", file.display());
            }
        }
    }
    Ok(())
}

#[derive(Subcommand)]
enum PluginCommand {
    /// Build a plugin crate for wasm32-unknown-unknown and write `<id>-<version>.onclp`:
    /// the manifest's version must be the crate's, and the module must pass the ABI check.
    Pack {
        /// The plugin crate's directory (with `Cargo.toml` and `plugin.toml`).
        dir: PathBuf,
        /// Output directory [default: target/plugins].
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
        Command::CheckElf { files } => {
            for file in &files {
                xtask::package::linux::check_elf(file, None)?;
            }
            Ok(())
        }
        Command::Package { command } => package(command),
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
        Command::TokenEmu { config, vpcd } => {
            xtask::token_emu::token_emu(&oncl_testkit::workspace_root(), &config, vpcd.as_deref())
        }
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
        Command::Licenses {
            check: false,
            plugins,
        } => {
            let root = oncl_testkit::workspace_root();
            let path = if plugins {
                xtask::licenses::write_plugins(&root)?
            } else {
                xtask::licenses::write(&root)?
            };
            println!("{}", path.display());
            Ok(())
        }
        Command::Licenses {
            check: true,
            plugins,
        } => {
            let root = oncl_testkit::workspace_root();
            let (fresh, output, command) = if plugins {
                (
                    xtask::licenses::check_plugins(&root)?,
                    xtask::licenses::PLUGINS_OUTPUT,
                    "cargo xtask licenses --plugins",
                )
            } else {
                (
                    xtask::licenses::check(&root)?,
                    xtask::licenses::OUTPUT,
                    "cargo xtask licenses",
                )
            };
            if !fresh {
                anyhow::bail!("{output} is stale: run `{command}`");
            }
            println!("{output} is up to date");
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
                    keys,
                },
        } => {
            let dir = index_dir(dir);
            if let Some(version) = tag.strip_prefix('v').and_then(|v| Version::parse(v).ok()) {
                let keys = xtask::index::trusted_keys(&keys.unwrap_or_else(|| {
                    oncl_testkit::workspace_root().join(xtask::sign::TRUSTED_KEYS_DIR)
                }))?;
                xtask::index::check_tag_key(&dir, &version, &keys)?;
            }
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
                added.written.path.display(),
                added.written.seq,
                flavors.join(", "),
                if added.extension {
                    " and the extension"
                } else {
                    ""
                }
            );
            print_written(&added.written);
            Ok(())
        }
        Command::Index {
            command: IndexCommand::Refresh { channel, dir },
        } => {
            let written =
                xtask::index::refresh(&index_dir(dir), channel, OffsetDateTime::now_utc())?;
            println!("{}: seq {}", written.path.display(), written.seq);
            print_written(&written);
            Ok(())
        }
        Command::Index {
            command:
                IndexCommand::AddPlugin {
                    channel,
                    tag,
                    packages,
                    rollout,
                    dir,
                },
        } => {
            let written = xtask::index::add_plugins(
                &index_dir(dir),
                channel,
                &tag,
                &packages,
                rollout,
                OffsetDateTime::now_utc(),
            )?;
            println!(
                "{}: seq {}, {} plugin package(s) of {tag}",
                written.path.display(),
                written.seq,
                packages.len()
            );
            print_written(&written);
            Ok(())
        }
        Command::Plugin {
            command: PluginCommand::Pack { dir, out },
        } => {
            let root = oncl_testkit::workspace_root();
            let out = out.unwrap_or_else(|| root.join("target").join("plugins"));
            let path = xtask::plugin::pack(&root, &dir, &out)?;
            println!("{}", path.display());
            Ok(())
        }
        Command::Index {
            command:
                IndexCommand::Check {
                    dir,
                    offline,
                    base,
                    no_base,
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
                base: (!no_base).then_some(base.as_str()),
                vm_smoke,
                now: OffsetDateTime::now_utc(),
            };
            let all = xtask::index::check(&dir, &options, remote)?;
            if all.is_empty() {
                println!(
                    "{}: no index is published yet; the trusted keys read fine",
                    dir.display()
                );
            }
            for checked in all {
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
                println!("offline: HEAD of the assets and vm-smoke not checked");
            }
            Ok(())
        }
        Command::Win7 {
            arch,
            out,
            target_dir,
        } => {
            let root = oncl_testkit::workspace_root();
            let out = out.unwrap_or_else(|| root.join("target").join("win7"));
            xtask::win7::run(&root, arch, &out, target_dir.as_deref())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("xtask").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn the_cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn sign_takes_an_index_or_keygen() {
        let Ok(Command::Sign {
            command: None,
            index: Some(index),
            key: Some(key),
        }) = parse(&["sign", "updates/v1/beta.json", "--key", "k.key"])
        else {
            panic!("sign <index> --key");
        };
        assert_eq!(
            (index.to_str(), key.to_str()),
            (Some("updates/v1/beta.json"), Some("k.key"))
        );
        assert!(matches!(
            parse(&["sign", "keygen", "--out", "keys"]),
            Ok(Command::Sign {
                command: Some(SignCommand::Keygen { .. }),
                index: None,
                key: None,
            })
        ));
        for args in [
            &["sign"][..],
            &["sign", "beta.json"],
            &["sign", "--key", "k.key"],
            &["sign", "keygen"],
            &["sign", "--key", "k.key", "keygen", "--out", "keys"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn index_commands_parse() {
        assert!(matches!(
            parse(&[
                "index",
                "add",
                "--channel",
                "beta",
                "--tag",
                "v1.0.0",
                "--release-assets",
                "a"
            ]),
            Ok(Command::Index {
                command: IndexCommand::Add {
                    channel: Channel::Beta,
                    rollout: 100,
                    ..
                }
            })
        ));
        assert!(matches!(
            parse(&["index", "refresh", "--channel", "stable"]),
            Ok(Command::Index {
                command: IndexCommand::Refresh {
                    channel: Channel::Stable,
                    dir: None
                }
            })
        ));
        assert!(matches!(
            parse(&["index", "check", "updates/v1", "--offline"]),
            Ok(Command::Index {
                command: IndexCommand::Check {
                    offline: true,
                    vm_smoke: false,
                    ..
                }
            })
        ));
        for args in [
            &["index", "check", "updates/v1", "--offline", "--vm-smoke"][..],
            &[
                "index",
                "add",
                "--channel",
                "nightly",
                "--tag",
                "v1.0.0",
                "--release-assets",
                "a",
            ],
            &[
                "index",
                "add",
                "--channel",
                "beta",
                "--tag",
                "v1.0.0",
                "--release-assets",
                "a",
                "--rollout",
                "101",
            ],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }
}
