use crate::{
    args::{Cli, Command},
    control::Control,
    output, reports,
};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationError, OperationPolicy,
    ValidationServices,
};
use oncl_pki::{
    io::{Source, TemporaryStore},
    pkix::CaSet,
    resource::{ProcessingError, ResourceLimits},
    validation::NetworkPolicy,
};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

fn io_error(error: io::Error) -> OperationError {
    ProcessingError::from(error).into()
}
pub enum Input {
    File(File, u64),
    Stdin(io::Stdin),
}
impl Input {
    pub fn open(path: &str) -> Result<Self, OperationError> {
        if path == "-" {
            Ok(Self::Stdin(io::stdin()))
        } else {
            let file = File::open(path).map_err(io_error)?;
            let len = file.metadata().map_err(io_error)?.len();
            Ok(Self::File(file, len))
        }
    }
    pub fn source(&mut self) -> Source<'_> {
        match self {
            Self::File(file, len) => Source::seekable(file, Some(*len)),
            Self::Stdin(input) => Source::sequential(input, None),
        }
    }
}
fn validation(cli: &Cli, control: &Control) -> Result<ValidationServices, OperationError> {
    fn certificates(
        paths: &[std::path::PathBuf],
        control: &Control,
    ) -> Result<Vec<oncl_pki::cert::Certificate>, OperationError> {
        let mut certificates = Vec::new();
        for path in paths {
            control.check()?;
            let mut file = File::open(path).map_err(io_error)?;
            if file.metadata().map_err(io_error)?.len() > 1024 * 1024 {
                return Err(ProcessingError::MetadataLimit.into());
            }
            let mut bytes = Vec::new();
            let read = Read::by_ref(&mut file)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes);
            control.check()?;
            read.map_err(io_error)?;
            if bytes.len() > 1024 * 1024 {
                return Err(ProcessingError::MetadataLimit.into());
            }
            certificates.push(
                oncl_pki::cert::parse(&bytes)
                    .map_err(|_| ProcessingError::InvalidInput("invalid host certificate"))?,
            );
        }
        Ok(certificates)
    }
    let clock: Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync> =
        if let Some(seconds) = cli.as_of {
            let now = time::OffsetDateTime::from_unix_timestamp(seconds)
                .map_err(|_| ProcessingError::InvalidInput("invalid host clock"))?;
            Arc::new(move || now)
        } else {
            Arc::new(time::OffsetDateTime::now_utc)
        };
    let network = NetworkPolicy::only_endpoints(cli.pki_endpoint.iter().map(String::as_str))
        .map_err(|_| ProcessingError::InvalidInput("invalid host PKI endpoint"))?;
    Ok(ValidationServices::new(
        CaSet::new(certificates(&cli.root, control)?),
        certificates(&cli.intermediate, control)?,
        Arc::new(oncl_pki::http::UreqTransport::with_proxy(
            oncl_pki::http::ProxySetting::None,
        )),
        network,
        clock,
    ))
}
pub fn run(cli: &Cli, control: Arc<Control>) -> Result<i32, OperationError> {
    control.check()?;
    let action = match &cli.command {
        Command::Hash { .. } => Action::Hash,
        Command::Verify { .. } => Action::Verify,
        Command::Extract { .. } => Action::Extract,
        Command::Sign(args) => crate::sign::action(args),
        Command::Inspect(..) => Action::Inspect,
        Command::Extend(..) => Action::Extend,
        Command::Timestamp {
            command: crate::families::TimestampCommand::Acquire { .. },
        } => Action::Stamp,
        Command::Timestamp {
            command: crate::families::TimestampCommand::Verify { .. },
        } => Action::VerifyStamp,
    };
    let validation = if matches!(
        cli.command,
        Command::Verify { .. }
            | Command::Sign(..)
            | Command::Extend(..)
            | Command::Timestamp { .. }
    ) {
        Some(validation(cli, &control)?)
    } else {
        None
    };
    let selector = if let Command::Sign(args) = &cli.command {
        Some(oncl_core::keys::KeySelector::file(
            &args.key,
            args.alias.clone(),
        )?)
    } else {
        None
    };
    let authority = selector.as_ref().map(|key| {
        Arc::new(crate::sign::Authority {
            key: key.key_id(),
            action,
            operation: AtomicU64::new(0),
        })
    });
    let store = if matches!(
        cli.command,
        Command::Sign(..) | Command::Verify { .. } | Command::Extend(..)
    ) {
        Some(TemporaryStore::new(
            cli.temporary_directory.as_deref().unwrap_or(Path::new(".")),
        )?)
    } else {
        None
    };
    let mut limits = ResourceLimits {
        operation_timeout: control.remaining()?,
        ..ResourceLimits::default()
    };
    if let Some(output) = cli.output_limit {
        limits.output_bytes = output;
    }
    let mut services = EngineServices::hash_only(limits);
    if let Some(validation) = validation {
        services = services.with_validation(validation);
    }
    if let Some(authority) = &authority {
        services = services.with_keys(
            Arc::new(oncl_core::keys::KeySources::new()),
            authority.clone(),
        );
    }
    if let Some(store) = &store {
        services = services.with_temporary_store(store.clone());
    }
    let engine = Engine::new(services)?;
    let mut policy = if cli.offline {
        OperationPolicy::offline_report()
    } else {
        OperationPolicy::strict_online()
    };
    policy.allow_prehashed = action == Action::SignDigest;
    let mut grant = ExecutionGrant::new([action])
        .with_keys(selector.iter().map(oncl_core::keys::KeySelector::key_id));
    if let Command::Inspect(args) = &cli.command {
        grant = grant.with_metadata_aliases(args.alias.iter().cloned());
    }
    let mut ctx = engine.begin(grant, policy, control)?;
    if let Some(authority) = &authority {
        authority.operation.store(ctx.id().get(), Ordering::SeqCst);
    }
    match &cli.command {
        Command::Hash { algorithm, input } => {
            let mut source = Input::open(input)?;
            let result = engine.hash(algorithm.sdk(), source.source(), &mut ctx)?;
            let digest = reports::Hex(result.digest.as_bytes());
            let human = digest.to_string();
            output::report(
                cli,
                &reports::Hash {
                    operation_id: result.id.get(),
                    code: "Completed",
                    applied: "NotApplied",
                    digest,
                    bytes_in: result.bytes_in,
                },
                &human,
                &mut ctx,
            )?;
            Ok(0)
        }
        Command::Verify {
            profile,
            input,
            detached,
        } => {
            let mut source = Input::open(input)?;
            let mut detached = detached.as_deref().map(Input::open).transpose()?;
            let result = engine.verify(
                &profile.sdk(),
                source.source(),
                detached.as_mut().map(Input::source),
                &mut ctx,
            )?;
            let (verdict, exit) = reports::verdict(result.verdict);
            output::report(cli, &reports::Verification(&result), verdict, &mut ctx)?;
            Ok(exit)
        }
        Command::Sign(args) => {
            let parent = if args.output == "-" {
                cli.temporary_directory.as_deref().unwrap_or(Path::new("."))
            } else {
                Path::new(&args.output)
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."))
            };
            let output_store = TemporaryStore::new(parent)?;
            let (stage, result) = crate::sign::execute(
                &engine,
                args,
                selector.as_ref().ok_or(OperationError::InvalidKeySource)?,
                &output_store,
                &mut ctx,
            )?;
            let complete = (|| {
                let prepared = output::prepare(
                    cli,
                    &reports::Written::from(&result),
                    "Completed",
                    true,
                    &mut ctx,
                )?;
                output::deliver(stage, &args.output)?;
                prepared.send(&mut ctx)
            })();
            complete.map_err(|error| OperationError::AfterKeyUse {
                source: Box::new(error),
                applied: result.applied,
            })?;
            Ok(0)
        }
        Command::Extract {
            input,
            output: destination,
        } => {
            let mut source = Input::open(input)?;
            let parent = if destination == "-" {
                cli.temporary_directory.as_deref().unwrap_or(Path::new("."))
            } else {
                Path::new(destination)
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."))
            };
            let output_store = TemporaryStore::new(parent)?;
            let mut stage = output_store.stage(ctx.resources())?;
            let result = engine.extract_staged(source.source(), &mut stage, &mut ctx)?;
            #[derive(serde::Serialize)]
            struct ExtractReport {
                operation_id: u64,
                code: &'static str,
                applied: &'static str,
                bytes_out: u64,
                verified: bool,
            }
            let report = ExtractReport {
                operation_id: result.id.get(),
                code: "Completed",
                applied: "NotApplied",
                bytes_out: result.bytes_written,
                verified: false,
            };
            let prepared = output::prepare(
                cli,
                &report,
                "Completed (unverified extraction)",
                true,
                &mut ctx,
            )?;
            output::deliver(stage, destination)?;
            prepared.send(&mut ctx)?;
            Ok(0)
        }
        Command::Inspect(args) => crate::public::inspect(&engine, args, cli, &mut ctx),
        Command::Extend(args) => crate::public::extend(&engine, args, cli, &mut ctx),
        Command::Timestamp { command } => crate::public::timestamp(&engine, command, cli, &mut ctx),
    }
}
