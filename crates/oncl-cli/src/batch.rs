//! Mixed typed batch over `run_batch_with_outputs`. The manifest is host data:
//! it selects ordered operations/paths only; authority is the explicit
//! `--authorize` of this exact composition plus the host key/trust flags.
use crate::{args::Cli, bounded, local::Input, output, secrets};
use clap::{Args, Subcommand};
use oncl_core::{
    Engine, OperationContext, OperationError, SignRequest, VerifyRequest,
    batch::{BatchItem, BatchOperation, BatchOutcome, BatchOutput, BatchReport, BatchStop},
    keys::{KeyRequest, KeySelector},
};
use oncl_pki::{io::StagedArtifact, key::HashAlg, resource::ProcessingError, validation::Verdict};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

const MANIFEST_BYTES: usize = 1 << 20;
const MAX_ITEMS: usize = 256;

#[derive(Subcommand)]
pub enum BatchCommand {
    Run(BatchArgs),
}
#[derive(Args)]
pub struct BatchArgs {
    #[arg(long)]
    pub manifest: PathBuf,
    #[arg(long)]
    pub key: Option<PathBuf>,
    #[arg(long, requires = "key")]
    pub alias: Option<String>,
    #[arg(long, requires = "key")]
    pub secret_file: Option<PathBuf>,
    #[arg(long, requires = "key", conflicts_with = "secret_file")]
    pub secret_interactive: bool,
    /// Confirms this exact ordered composition, sources, key and destinations.
    #[arg(long)]
    pub authorize: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Algorithm {
    Sha256,
    Gost2004,
    #[serde(rename = "gost2015-512")]
    Gost2015_512,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SignProfile {
    Cms,
    CmsDetached,
    Raw,
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Item {
    Hash {
        id: String,
        algorithm: Algorithm,
        input: PathBuf,
    },
    Sign {
        id: String,
        profile: SignProfile,
        input: PathBuf,
        output: PathBuf,
    },
    Verify {
        id: String,
        input: PathBuf,
        detached: Option<PathBuf>,
    },
    Extract {
        id: String,
        input: PathBuf,
        output: PathBuf,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    items: Vec<Item>,
}
impl Item {
    fn id(&self) -> &str {
        match self {
            Self::Hash { id, .. }
            | Self::Sign { id, .. }
            | Self::Verify { id, .. }
            | Self::Extract { id, .. } => id,
        }
    }
    fn output(&self) -> Option<&Path> {
        match self {
            Self::Sign { output, .. } | Self::Extract { output, .. } => Some(output),
            _ => None,
        }
    }
    fn inputs(&self) -> Vec<&Path> {
        match self {
            Self::Hash { input, .. } | Self::Sign { input, .. } | Self::Extract { input, .. } => {
                vec![input]
            }
            Self::Verify {
                input, detached, ..
            } => std::iter::once(input.as_path())
                .chain(detached.as_deref())
                .collect(),
        }
    }
}
impl BatchCommand {
    pub fn args(&self) -> &BatchArgs {
        let Self::Run(args) = self;
        args
    }
    pub fn preflight(&self) -> Result<(), &'static str> {
        let args = self.args();
        if !args.authorize {
            return Err("AuthorityRequired");
        }
        Ok(())
    }
    pub fn key_selector(&self) -> Result<Option<KeySelector>, OperationError> {
        let args = self.args();
        args.key
            .as_ref()
            .map(|key| KeySelector::file(key, args.alias.clone()))
            .transpose()
    }
}
/// Complete admission of the host manifest before any source or key I/O.
fn parse(bytes: &[u8], has_key: bool) -> Result<Manifest, &'static str> {
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|_| "InvalidManifest")?;
    if manifest.items.is_empty() || manifest.items.len() > MAX_ITEMS {
        return Err("ManifestLimit");
    }
    let (mut ids, mut outputs) = (HashSet::new(), HashSet::new());
    for item in &manifest.items {
        let id = item.id();
        if id.is_empty()
            || id.len() > 128
            || id.chars().any(char::is_control)
            || !ids.insert(id.to_owned())
        {
            return Err("InvalidManifest");
        }
        if item.inputs().iter().any(|p| p.as_os_str() == "-")
            || item.output().is_some_and(|p| p.as_os_str() == "-")
        {
            return Err("InvalidManifest");
        }
        if let Some(path) = item.output()
            && (!outputs.insert(path.to_owned()) || std::fs::symlink_metadata(path).is_ok())
        {
            return Err("DestinationExists");
        }
        if matches!(item, Item::Sign { .. }) && !has_key {
            return Err("InvalidCombination");
        }
    }
    let inputs: HashSet<&Path> = manifest.items.iter().flat_map(Item::inputs).collect();
    if outputs
        .iter()
        .any(|output| inputs.contains(output.as_path()))
    {
        return Err("InvalidManifest");
    }
    Ok(manifest)
}
#[derive(Serialize)]
struct Row {
    id: String,
    status: &'static str,
    code: String,
    applied: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    published: Option<bool>,
}
#[derive(Serialize)]
struct Report {
    operation_id: u64,
    code: &'static str,
    attempted: usize,
    completed: usize,
    total: usize,
    stop: Option<String>,
    items: Vec<Row>,
}
fn verdict_rank(verdict: Verdict) -> (&'static str, i32) {
    crate::reports::verdict(verdict)
}
pub fn run(
    engine: &Engine,
    command: &BatchCommand,
    cli: &Cli,
    selector: Option<&KeySelector>,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    let args = command.args();
    let mut manifest_input = Input::open(
        args.manifest
            .to_str()
            .ok_or(ProcessingError::InvalidInput("manifest path"))?,
    )?;
    let raw = bounded::read(manifest_input.source(), MANIFEST_BYTES, ctx)?;
    let manifest = parse(raw.as_bytes(), selector.is_some())
        .map_err(|code| OperationError::Processing(ProcessingError::InvalidInput(code)))?;
    drop(raw);
    // Sources are opened only after the complete manifest is admitted. An
    // unreadable source is that item's local failure; healthy later items run.
    let mut inputs: Vec<(Input, Option<Input>)> = manifest
        .items
        .iter()
        .map(|item| {
            let paths = item.inputs();
            (
                Input::open_lenient(paths[0]),
                paths.get(1).map(|p| Input::open_lenient(p)),
            )
        })
        .collect();
    let _secret_memory = ctx.resources().reserve_memory(16384)?;
    let secret = match selector {
        Some(_) => Some(secrets::read(
            args.secret_file.as_deref(),
            args.secret_interactive,
            false,
            ctx,
        )?),
        None => None,
    };
    let mut destinations: Vec<Option<PathBuf>> = Vec::new();
    let mut stages: Vec<Option<StagedArtifact>> = Vec::new();
    for item in &manifest.items {
        destinations.push(item.output().map(Path::to_owned));
        stages.push(match item.output() {
            // Same-directory staging, exactly like the single-command path.
            Some(path) => Some(
                output::store(
                    cli,
                    path.to_str().ok_or(ProcessingError::InvalidInput("path"))?,
                )?
                .stage(ctx.resources())?,
            ),
            None => None,
        });
    }
    let secret_text = secret.as_ref().map(|s| s.as_str());
    let mut items = Vec::new();
    for ((item, (input, detached)), stage) in manifest
        .items
        .iter()
        .zip(inputs.iter_mut())
        .zip(stages.iter_mut())
    {
        let operation = match item {
            Item::Hash { algorithm, .. } => BatchOperation::Hash {
                algorithm: match algorithm {
                    Algorithm::Sha256 => HashAlg::Sha256,
                    Algorithm::Gost2004 => HashAlg::Gost34311,
                    Algorithm::Gost2015_512 => HashAlg::Streebog512,
                },
                input: input.source(),
            },
            Item::Verify { .. } => BatchOperation::Verify {
                request: VerifyRequest::cms(),
                input: input.source(),
                detached: detached.as_mut().map(Input::source),
            },
            Item::Extract { .. } => BatchOperation::Extract {
                input: input.source(),
                output: BatchOutput::OwnedStaged(
                    stage
                        .take()
                        .ok_or(ProcessingError::InvalidInput("missing output stage"))?,
                ),
            },
            Item::Sign { profile, .. } => {
                let selector = selector.ok_or(OperationError::InvalidKeySource)?;
                let request = match profile {
                    SignProfile::Cms => {
                        SignRequest::cms_create(vec![key_request(selector, secret_text)], true)
                    }
                    SignProfile::CmsDetached => {
                        SignRequest::cms_create(vec![key_request(selector, secret_text)], false)
                    }
                    SignProfile::Raw => {
                        SignRequest::raw_message(key_request(selector, secret_text))
                    }
                };
                BatchOperation::Sign {
                    request,
                    input: input.source(),
                    output: BatchOutput::OwnedStaged(
                        stage.take().ok_or(OperationError::InvalidKeySource)?,
                    ),
                }
            }
        };
        items.push(BatchItem::new(item.id(), operation));
    }
    let plan = engine.capture_batch(items, ctx).map_err(batch_error)?;
    for (index, view) in plan.items().enumerate() {
        crate::diagnostic(format_args!(
            "oncl: batch plan {index}: {} {:?}",
            view.id, view.action
        ));
    }
    let approval = plan.authorize(ctx).map_err(batch_error)?;
    let mut published = vec![false; manifest.items.len()];
    let mut finished = 0usize;
    let summary = engine
        .run_batch_with_outputs(
            plan,
            approval,
            ctx,
            |event| {
                if let oncl_core::batch::BatchEvent::ItemFinished { result, .. } = event {
                    finished += 1;
                    crate::diagnostic(format_args!("oncl: batch item {finished}: {}", result.id()));
                }
            },
            |index, _id, _report, completed| {
                let destination = destinations[index]
                    .as_deref()
                    .ok_or(OperationError::InvalidKeySource)?;
                completed.commit(destination)?;
                published[index] = true;
                Ok(())
            },
        )
        .map_err(batch_error)?;
    let mut worst = 0;
    let mut rows = Vec::new();
    for (index, result) in summary.results().iter().enumerate() {
        let (status, code, verdict) = match result.outcome() {
            BatchOutcome::Completed(report) => {
                let verdict = match report {
                    BatchReport::Verify(report) => Some(verdict_rank(report.verdict)),
                    _ => None,
                };
                if let Some((_, rank)) = verdict {
                    worst = worst_verdict(worst, rank);
                }
                ("Completed", "Completed".to_owned(), verdict.map(|v| v.0))
            }
            BatchOutcome::Failed(error) => ("Failed", format!("{:?}", error.code()), None),
            BatchOutcome::NotRun => ("NotRun", "NotRun".to_owned(), None),
        };
        rows.push(Row {
            id: result.id().to_owned(),
            status,
            code,
            applied: format!("{:?}", result.applied_state()),
            verdict,
            published: destinations[index].as_ref().map(|_| published[index]),
        });
    }
    let stop = summary.stop.as_ref().map(|stop| match stop {
        BatchStop::Control(error) => format!("{:?}", error.code()),
        BatchStop::Item {
            index,
            code,
            applied,
        } => format!("item {index}: {code:?}: {applied:?}"),
    });
    let cancelled = matches!(&summary.stop, Some(BatchStop::Control(error)) if error.code() == oncl_core::ErrorCode::Cancelled)
        || matches!(
            &summary.stop,
            Some(BatchStop::Item {
                code: oncl_core::ErrorCode::Cancelled,
                ..
            })
        );
    let incomplete = summary.completed != summary.total;
    let report = Report {
        operation_id: ctx.id().get(),
        code: "Completed",
        attempted: summary.attempted,
        completed: summary.completed,
        total: summary.total,
        stop,
        items: rows,
    };
    let human = format!("{}/{} items completed", summary.completed, summary.total);
    output::report(cli, &report, &human, ctx)?;
    Ok(if cancelled {
        130
    } else if incomplete {
        4
    } else {
        worst
    })
}
fn worst_verdict(current: i32, next: i32) -> i32 {
    // Invalid (2) outranks Indeterminate (3), which outranks Valid (0).
    let rank = |code: i32| match code {
        2 => 2,
        3 => 1,
        _ => 0,
    };
    if rank(next) > rank(current) {
        next
    } else {
        current
    }
}
fn batch_error(error: oncl_core::batch::BatchError) -> OperationError {
    match error {
        oncl_core::batch::BatchError::Operation(error) => error,
        oncl_core::batch::BatchError::ConsentMismatch => OperationError::PermissionDenied,
    }
}

fn key_request<'a>(selector: &'a KeySelector, secret: Option<&'a str>) -> KeyRequest<'a> {
    KeyRequest::new(selector, secret)
}
