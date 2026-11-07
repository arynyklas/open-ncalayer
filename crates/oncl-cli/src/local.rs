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
    sync::{Arc, atomic::Ordering},
};

fn io_error(error: io::Error) -> OperationError {
    ProcessingError::from(error).into()
}
pub enum Input {
    File(File, u64),
    Stdin(io::Stdin),
    /// Preserves item order for a source that failed to open; reads fail locally.
    Unreadable(UnreadableSource),
}
pub struct UnreadableSource(io::ErrorKind);
impl Read for UnreadableSource {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(self.0, "source could not be opened"))
    }
}
impl Input {
    pub fn open_lenient(path: &std::path::Path) -> Self {
        match path
            .to_str()
            .ok_or(io::ErrorKind::InvalidInput)
            .and_then(|p| Self::open(p).map_err(|_| io::ErrorKind::NotFound))
        {
            Ok(input) => input,
            Err(kind) => Self::Unreadable(UnreadableSource(kind)),
        }
    }
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
            Self::Unreadable(input) => Source::sequential(input, None),
        }
    }
}
fn validation(
    cli: &Cli,
    control: &Control,
    budget: &Arc<oncl_pki::resource::SharedBudget>,
) -> Result<
    (
        ValidationServices,
        oncl_pki::resource::ConfigurationReservation,
        crate::evidence::Material,
    ),
    OperationError,
> {
    // Every duplicate is charged: encoded bytes directly, and a conservative CERTIFICATE_METADATA_FACTOR
    // parse/retained certificate metadata estimate, before the file is read.
    let mut reservation = budget.reserve_configuration(0, 0)?;
    let mut encoded_total = 0u64;
    fn certificates(
        paths: &[std::path::PathBuf],
        control: &Control,
        limit: u64,
        encoded_total: &mut u64,
        reservation: &mut oncl_pki::resource::ConfigurationReservation,
    ) -> Result<Vec<oncl_pki::cert::Certificate>, OperationError> {
        let mut certificates = Vec::new();
        for path in paths {
            control.check()?;
            let mut file = File::open(path).map_err(io_error)?;
            let length = file.metadata().map_err(io_error)?.len();
            let next = encoded_total
                .checked_add(length)
                .filter(|total| *total <= limit && length <= 1024 * 1024)
                .ok_or(ProcessingError::MetadataLimit)?;
            reservation.grow(
                length,
                length
                    .checked_mul(crate::bounded::CERTIFICATE_METADATA_FACTOR)
                    .ok_or(ProcessingError::MetadataLimit)?,
            )?;
            *encoded_total = next;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length as usize)
                .map_err(|_| ProcessingError::MemoryLimit)?;
            let read = Read::by_ref(&mut file)
                .take(length + 1)
                .read_to_end(&mut bytes);
            control.check()?;
            read.map_err(io_error)?;
            if bytes.len() as u64 != length {
                return Err(ProcessingError::InvalidInput(
                    "host certificate changed during intake",
                )
                .into());
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
    let mut network = NetworkPolicy::only_endpoints(cli.pki_endpoint.iter().map(String::as_str))
        .map_err(|_| ProcessingError::InvalidInput("invalid host PKI endpoint"))?;
    let mut pins: std::collections::BTreeMap<&str, Vec<std::net::SocketAddr>> = Default::default();
    for pin in &cli.pki_pin {
        let (origin, address) = pin
            .split_once('=')
            .ok_or(ProcessingError::InvalidInput("invalid PKI pin"))?;
        let address = address
            .parse()
            .map_err(|_| ProcessingError::InvalidInput("invalid PKI pin"))?;
        pins.entry(origin).or_default().push(address);
    }
    for (origin, addresses) in pins {
        network = network
            .with_resolved_endpoint(origin, addresses)
            .map_err(|_| ProcessingError::InvalidInput("invalid PKI pin"))?;
    }
    let roots = certificates(
        &cli.root,
        control,
        cli.configuration_bytes,
        &mut encoded_total,
        &mut reservation,
    )?;
    let intermediates = certificates(
        &cli.intermediate,
        control,
        cli.configuration_bytes,
        &mut encoded_total,
        &mut reservation,
    )?;
    let material = crate::evidence::load(cli, control, &mut reservation)?;
    Ok((
        ValidationServices::new(
            CaSet::new(roots),
            intermediates,
            Arc::new(oncl_pki::http::UreqTransport::with_proxy(
                oncl_pki::http::ProxySetting::None,
            )),
            network,
            clock,
        ),
        reservation,
        material,
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
        Command::Batch { command } => {
            if command.has_key() {
                Action::Sign
            } else {
                Action::Verify
            }
        }
        Command::Plugin { command } => {
            if command.has_key() {
                Action::Sign
            } else {
                Action::Hash
            }
        }
        Command::Jws { command } => command.action(),
        Command::Jwt { command } => command.action(),
    };
    let mut limits = ResourceLimits {
        operation_timeout: control.remaining()?,
        ..ResourceLimits::default()
    };
    if let Some(output) = cli.output_limit {
        limits.output_bytes = output;
    }
    // ONE application budget exists before host configuration is read; the
    // retained configuration reservation lives until Engine/context drop.
    let budget = Arc::new(oncl_pki::resource::SharedBudget::new(limits.clone())?);
    let (validation, _configuration, evidence) = if matches!(
        action,
        Action::Verify
            | Action::Sign
            | Action::SignDigest
            | Action::Extend
            | Action::Stamp
            | Action::VerifyStamp
    ) {
        let (services, reservation, material) = validation(cli, &control, &budget)?;
        (Some(services), Some(reservation), material)
    } else {
        (None, None, crate::evidence::Material::default())
    };
    // Key configuration bytes are charged to the same shared budget as roots.
    let mut key_configuration = budget.reserve_configuration(0, 0)?;
    let plan = if let Some(args) = cli.private_key() {
        Some(args.plan(&control, &mut key_configuration)?)
    } else if let Command::Plugin { command } = &cli.command {
        command.key_plan(&control, &mut key_configuration)?
    } else if let Command::Batch { command } = &cli.command {
        command.key_plan(&control, &mut key_configuration)?
    } else if let Command::Inspect(args) = &cli.command {
        match (&args.key_config, &args.key_name) {
            (Some(config), Some(name)) => Some(crate::keysrc::resolve(
                config,
                name,
                &control,
                &mut key_configuration,
            )?),
            _ => None,
        }
    } else {
        None
    };
    let selector = plan.as_ref().map(|plan| plan.selector.clone());
    let (plugin_registry, _plugin_configuration, plugin_id, mut plugin_checked) =
        if let Command::Plugin { command } = &cli.command {
            let (registry, reservation, id, checked) =
                crate::plugin::registry(command, selector.as_ref(), &budget)?;
            (Some(registry), Some(reservation), id, Some(checked))
        } else {
            (None, None, String::new(), None)
        };
    let private = !matches!(cli.command, Command::Inspect(..));
    let authority = selector.as_ref().filter(|_| private).map(|key| {
        Arc::new(crate::sign::Authority::new(
            key.key_id(),
            action,
            plugin_checked.as_mut().and_then(|c| c.bytes.take()),
        ))
    });
    let store = if matches!(
        cli.command,
        Command::Sign(..) | Command::Verify { .. } | Command::Extend(..) | Command::Batch { .. }
    ) {
        Some(TemporaryStore::new(
            cli.temporary_directory.as_deref().unwrap_or(Path::new(".")),
        )?)
    } else {
        None
    };
    let mut services = EngineServices::hash_only(limits).with_shared_budget(budget);
    if let Some(validation) = validation {
        services = services.with_validation(validation);
    }
    if let Some(authority) = &authority {
        let plan = plan.as_ref().ok_or(OperationError::InvalidKeySource)?;
        services = services.with_keys(Arc::new(crate::keysrc::sources(plan)?), authority.clone());
    } else if let (Some(plan), false) = (&plan, private) {
        // Public metadata of a named source: a read-only provider, no guard and
        // no private-use capability.
        services = services.with_metadata_provider(Arc::new(crate::keysrc::sources(plan)?));
    }
    if let Some(store) = &store {
        services = services.with_temporary_store(store.clone());
    }
    if let Some(url) = &cli.tsa_url {
        services = services.with_cades(oncl_core::CadesConfiguration::new(
            crate::args::evidence_limits(),
            crate::public::tsa(
                url,
                oncl_pki::key::HashAlg::Sha256,
                std::time::Duration::from_secs(cli.timeout_seconds),
                cli.tsa_policy.as_deref(),
            )?,
        ));
    }
    if let Some(registry) = plugin_registry {
        services = services.with_plugins(registry);
    }
    let engine = Engine::new(services)?;
    let mut policy = if cli.offline {
        OperationPolicy::offline_report()
    } else {
        OperationPolicy::strict_online()
    };
    policy.allow_prehashed = action == Action::SignDigest;
    let grant_actions: Vec<Action> = if matches!(cli.command, Command::Batch { .. }) {
        let mut actions = vec![Action::Hash, Action::Verify, Action::Extract];
        if action == Action::Sign {
            actions.push(Action::Sign);
        }
        actions
    } else {
        vec![action]
    };
    let mut grant = ExecutionGrant::new(grant_actions)
        .with_keys(selector.iter().map(oncl_core::keys::KeySelector::key_id));
    if let Command::Plugin { command } = &cli.command {
        let checked = plugin_checked
            .as_ref()
            .ok_or(OperationError::InvalidContext)?;
        grant = grant.with_plugins([crate::plugin::permission(
            command.args(),
            &plugin_id,
            selector.as_ref(),
            checked,
        )?]);
    }
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
            pem,
            wsse,
        } => {
            let mut source = Input::open(input)?;
            let mut detached = detached.as_deref().map(Input::open).transpose()?;
            let mut decoded: std::io::Cursor<Vec<u8>>;
            let _held;
            let primary = if *pem {
                // Explicit, bounded, decoded before parsing; the DER is charged like any
                // other retained input.
                let text =
                    crate::bounded::read(source.source(), crate::pem::MAX_PEM_BYTES, &mut ctx)?;
                let der = crate::pem::decode_cms(text.as_bytes())?;
                drop(text);
                _held = ctx.resources().reserve_memory(der.len() as u64)?;
                let length = der.len() as u64;
                decoded = std::io::Cursor::new(der);
                Source::sequential(&mut decoded, Some(length))
            } else {
                source.source()
            };
            let result = engine.verify(
                &profile.sdk(wsse),
                primary,
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
                cli,
                args,
                selector.as_ref().ok_or(OperationError::InvalidKeySource)?,
                &output_store,
                &evidence,
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
                prepared.send()
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
            prepared.send()?;
            Ok(0)
        }
        Command::Inspect(args) => {
            crate::public::inspect(&engine, args, selector.as_ref(), cli, &mut ctx)
        }
        Command::Extend(args) => crate::public::extend(&engine, args, cli, &evidence, &mut ctx),
        Command::Timestamp { command } => crate::public::timestamp(&engine, command, cli, &mut ctx),
        Command::Batch { command } => {
            crate::batch::run(&engine, command, cli, selector.as_ref(), &mut ctx)
        }
        Command::Plugin { command } => crate::plugin::call(
            &engine,
            command,
            &plugin_id,
            selector.as_ref(),
            cli,
            &mut ctx,
        ),
        Command::Jws { command } => {
            crate::jose::jws(&engine, command, cli, selector.as_ref(), &mut ctx)
        }
        Command::Jwt { command } => {
            crate::jose::jwt(&engine, command, cli, selector.as_ref(), &mut ctx)
        }
    }
}
