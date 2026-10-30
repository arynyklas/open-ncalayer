//! The `cargo xtask upstream` subcommands.

use std::path::PathBuf;

use anyhow::Context;
use clap::Subcommand;

use super::Endpoints;
use super::branch_layout::ToolVersions;
use super::github::Client;
use super::http::Fetcher;
use super::poll::AlertKind;
use super::poll::poll;
use super::publish::{PublishOptions, alert, issues_for_entry, publish};
use super::report::PortRef;
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
    /// Publish an emit directory: checked strictly, copied into the `upstream` branch with the
    /// issue numbers, committed, pushed; issues created or updated by key; alerts of its
    /// `run.json` raised; `repository_dispatch` `upstream` sent after a push.
    Publish {
        /// The emit directory.
        #[arg(long)]
        from: PathBuf,
        #[command(flatten)]
        args: PublishArgs,
    },
    /// Publish the issues of an entry already in the `upstream` branch (default: the last)
    /// and commit their numbers: after facts arrive by a pull request.
    Issues {
        /// The entry id.
        #[arg(long)]
        entry: Option<String>,
        #[command(flatten)]
        args: PublishArgs,
    },
    /// Raise an `upstream-alert` issue (one per kind and day).
    Alert {
        /// The kind.
        #[arg(long, value_enum)]
        kind: AlertArg,
        /// The URL of the workflow run.
        #[arg(long)]
        run_url: Option<String>,
    },
    /// Fetch and check the pinned external unpackers into `--out`; prints `ONCL_INNOUNP=…`
    /// (Windows) and `ONCL_7Z=…` lines for `$GITHUB_ENV`.
    Tools {
        /// Where innounp goes.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Options shared by `publish` and `issues`.
#[derive(Debug, Default, clap::Args)]
pub struct PublishArgs {
    /// Where the branch's worktree goes [default: target/upstream/branch].
    #[arg(long)]
    pub branch_dir: Option<PathBuf>,
    /// The remote.
    #[arg(long, default_value = "origin")]
    pub remote: String,
    /// Commit without pushing.
    #[arg(long)]
    pub no_push: bool,
    /// No issues.
    #[arg(long)]
    pub no_issues: bool,
    /// Change nothing: no commit, no push, GET requests only.
    #[arg(long)]
    pub dry_run: bool,
}

/// Alerts the workflow raises.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum AlertArg {
    /// The collecting job failed.
    CollectFailed,
}

fn publish_options(root: &std::path::Path, args: &PublishArgs) -> anyhow::Result<PublishOptions> {
    let client = if args.no_issues && args.no_push {
        None
    } else {
        Some(Client::from_env()?)
    };
    let ports = crate::registry::ports::load(&root.join("plugins"))?
        .iter()
        .map(PortRef::from)
        .collect();
    Ok(PublishOptions {
        repo_dir: root.to_owned(),
        branch_dir: args
            .branch_dir
            .clone()
            .unwrap_or_else(|| root.join("target").join("upstream").join("branch")),
        remote: args.remote.clone(),
        push: !args.no_push,
        issues: !args.no_issues,
        dry_run: args.dry_run,
        ports,
        client,
        date: time::OffsetDateTime::now_utc().date().to_string(),
        run_url: std::env::var("RUN_URL").ok().filter(|u| !u.is_empty()),
        git_env: Vec::new(),
    })
}

fn publish_cli(
    root: &std::path::Path,
    from: &std::path::Path,
    args: &PublishArgs,
) -> anyhow::Result<()> {
    let report = publish(from, &publish_options(root, args)?)?;
    println!(
        "publish: committed={} pushed={} dispatched={} issues={}",
        report.committed,
        report.pushed,
        report.dispatched,
        report.actions.len()
    );
    Ok(())
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
        UpstreamCommand::Publish { from, args } => publish_cli(&root, &from, &args),
        UpstreamCommand::Issues { entry, args } => {
            let report = issues_for_entry(entry.as_deref(), &publish_options(&root, &args)?)?;
            println!(
                "issues: committed={} pushed={} issues={}",
                report.committed,
                report.pushed,
                report.actions.len()
            );
            Ok(())
        }
        UpstreamCommand::Alert { kind, run_url } => {
            let kind = match kind {
                AlertArg::CollectFailed => AlertKind::CollectFailed,
            };
            let action = alert(
                kind,
                "the collect job did not finish",
                run_url.as_deref(),
                &Client::from_env()?,
                &time::OffsetDateTime::now_utc().date().to_string(),
            )?;
            println!("alert: {} {action:?}", kind.name());
            Ok(())
        }
        UpstreamCommand::Run {
            state,
            work,
            emit,
            dry_run,
            github_output,
        } => {
            let mut tools = Tools::from_env();
            // 7-Zip older than 25.01 would write through links out of its output directory.
            let sevenzip = std::env::var_os("ONCL_7Z")
                .filter(|v| !v.is_empty())
                .map(|p| super::tools::sevenzip_version(std::path::Path::new(&p)));
            let sevenzip = match sevenzip {
                Some(Some(v)) if super::tools::sevenzip_supported(&v) => Some(v),
                Some(_) => {
                    eprintln!("ONCL_7Z is not 7-Zip 25.01 or newer: not used");
                    tools.sevenzip = None;
                    None
                }
                None => None,
            };
            let tool_versions = ToolVersions {
                innounp: tools.innounp.as_ref().map(|_| "2.71.2".to_owned()),
                sevenzip,
            };
            let outcome = cycle::run(&RunOptions {
                state_dir: state,
                work,
                emit: emit.clone(),
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
            if dry_run {
                return Ok(());
            }
            // The same code as `upstream publish --from <emit>`.
            publish_cli(
                &root,
                &emit,
                &PublishArgs {
                    remote: "origin".to_owned(),
                    ..PublishArgs::default()
                },
            )?;
            Ok(())
        }
    }
}
