//! Runtime-only WASM plugin invocation. Installation is not authority: the
//! trusted operator names caller, operation, imports and key explicitly; guest
//! arguments cannot widen any of them. No GUI, browser origin or prompter.
use crate::{args::Cli, bounded, local::Input, output, secrets};
use clap::{Args, Subcommand};
use oncl_core::{
    Engine, OperationContext, OperationError,
    keys::{KeyRequest, KeySelector},
    plugins::{
        CallerContext, PluginBindings, PluginCall, PluginKeyBinding, PluginPermission,
        PluginRegistry,
    },
};
use oncl_pdk::abi::Import;
use oncl_pki::resource::{ConfigurationReservation, ProcessingError, SharedBudget};
use std::{path::PathBuf, sync::Arc};

#[derive(Subcommand)]
pub enum PluginCommand {
    Call(PluginCallArgs),
}
#[derive(Args)]
pub struct PluginCallArgs {
    #[arg(long)]
    pub manifest: PathBuf,
    #[arg(long)]
    pub module: PathBuf,
    #[arg(long)]
    pub operation: String,
    /// Trusted local operator label; never a browser origin or guest field.
    #[arg(long)]
    pub caller: String,
    /// Exact host import names the operator allows (for example `hash`).
    #[arg(long)]
    pub allow_import: Vec<String>,
    /// JSON arguments file (bounded; `-` is stdin).
    #[arg(long)]
    pub args_file: String,
    #[arg(long)]
    pub output: String,
    #[arg(long)]
    pub key: Option<PathBuf>,
    #[arg(long, requires = "key")]
    pub alias: Option<String>,
    /// Operator-configured key by name (see `--key-config`); no container path on the command line.
    #[arg(long, requires = "key_config", conflicts_with_all = ["key", "alias"])]
    pub key_name: Option<String>,
    #[arg(long, requires = "key_name")]
    pub key_config: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    pub key_handle: u32,
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "secret_file")]
    pub secret_interactive: bool,
    #[arg(long)]
    pub authorize: bool,
    /// Exact PKI base the guest's key validation may reach, as `GET=url`/`POST=url`.
    #[arg(long)]
    pub plugin_pki_endpoint: Vec<String>,
}
const MANIFEST_BYTES: u64 = 64 * 1024;
const MODULE_BYTES: u64 = 16 * 1024 * 1024;
const ARGUMENT_BYTES: usize = 1 << 18;

impl PluginCommand {
    pub fn args(&self) -> &PluginCallArgs {
        let Self::Call(args) = self;
        args
    }
    pub fn preflight(&self) -> Result<(), &'static str> {
        let args = self.args();
        if args.allow_import.len() > 80
            || args
                .allow_import
                .iter()
                .any(|n| Import::from_name(n).is_none())
        {
            return Err("InvalidCombination");
        }
        if args.plugin_pki_endpoint.len() > 16
            || args
                .plugin_pki_endpoint
                .iter()
                .any(|e| pki_endpoint(e).is_none())
        {
            return Err("InvalidCombination");
        }
        if self.has_key() && !args.authorize {
            return Err("AuthorityRequired");
        }
        if !self.has_key()
            && (args.authorize || args.secret_file.is_some() || args.secret_interactive)
        {
            return Err("InvalidCombination");
        }
        if args.args_file == "-" && args.secret_interactive {
            return Err("SecretRequiresSeparateInput");
        }
        Ok(())
    }
    pub fn key_plan(&self) -> Result<Option<crate::keysrc::Plan>, OperationError> {
        let args = self.args();
        if let (Some(config), Some(name)) = (&args.key_config, &args.key_name) {
            return crate::keysrc::resolve(config, name).map(Some);
        }
        args.key
            .as_ref()
            .map(|key| {
                KeySelector::file(key, args.alias.clone())
                    .map(|selector| crate::keysrc::Plan::direct(selector, false))
            })
            .transpose()
    }
    pub fn has_key(&self) -> bool {
        let args = self.args();
        args.key.is_some() || args.key_name.is_some()
    }
}
fn pki_endpoint(text: &str) -> Option<(oncl_pki::http::HttpMethod, &str)> {
    let (method, url) = text.split_once('=')?;
    let method = match method {
        "GET" => oncl_pki::http::HttpMethod::Get,
        "POST" => oncl_pki::http::HttpMethod::Post,
        _ => return None,
    };
    Some((method, url))
}
fn caller(args: &PluginCallArgs) -> CallerContext {
    CallerContext::LocalOperator(args.caller.clone())
}
pub fn permission(
    args: &PluginCallArgs,
    id: &str,
    selector: Option<&KeySelector>,
) -> Result<PluginPermission, OperationError> {
    let imports = args
        .allow_import
        .iter()
        .filter_map(|name| Import::from_name(name));
    PluginPermission::new(id, args.operation.clone(), caller(args), imports)
        .with_keys(selector.iter().map(|key| key.key_id()))
        .with_pki_endpoints(
            args.plugin_pki_endpoint
                .iter()
                .filter_map(|e| pki_endpoint(e)),
        )
}
fn read_bounded_file(
    path: &PathBuf,
    maximum: u64,
    reservation: &mut ConfigurationReservation,
    multiplier: u64,
) -> Result<Vec<u8>, OperationError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(ProcessingError::from)?;
    let length = file.metadata().map_err(ProcessingError::from)?.len();
    if length > maximum {
        return Err(ProcessingError::ContainerLimit.into());
    }
    reservation.grow(
        length,
        length
            .checked_mul(multiplier)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    file.by_ref()
        .take(length + 1)
        .read_to_end(&mut bytes)
        .map_err(ProcessingError::from)?;
    if bytes.len() as u64 != length {
        return Err(ProcessingError::InvalidInput("plugin file changed during intake").into());
    }
    Ok(bytes)
}
/// Installs exactly one operator-selected module. Configuration memory is held
/// by the returned reservation for as long as the registry exists.
pub fn registry(
    command: &PluginCommand,
    selector: Option<&KeySelector>,
    budget: &Arc<SharedBudget>,
) -> Result<(PluginRegistry, ConfigurationReservation, String), OperationError> {
    let args = command.args();
    let mut reservation = budget.reserve_configuration(0, 0)?;
    let manifest_bytes = read_bounded_file(&args.manifest, MANIFEST_BYTES, &mut reservation, 64)?;
    let wasm = read_bounded_file(&args.module, MODULE_BYTES, &mut reservation, 4)?;
    let text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| ProcessingError::InvalidInput("manifest is not UTF-8"))?;
    let manifest = oncl_plugin::Manifest::from_toml(text)
        .map_err(|_| ProcessingError::InvalidInput("invalid plugin manifest"))?;
    let id = manifest.id.clone();
    let mut registry = PluginRegistry::new();
    registry.install(
        manifest,
        &wasm,
        oncl_plugin::InstanceLimits {
            max_memory: 1 << 20,
            max_transfer: ARGUMENT_BYTES,
            ..Default::default()
        },
        vec![permission(args, &id, selector)?],
    )?;
    Ok((registry, reservation, id))
}
pub fn call(
    engine: &Engine,
    command: &PluginCommand,
    id: &str,
    selector: Option<&KeySelector>,
    cli: &Cli,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    let args = command.args();
    let _secret_memory = ctx.resources().reserve_memory(16384)?;
    let secret = if selector.is_some() {
        Some(secrets::read(
            args.secret_file.as_deref(),
            args.secret_interactive,
            args.args_file == "-",
            ctx,
        )?)
    } else {
        None
    };
    let mut input = Input::open(&args.args_file)?;
    let raw = bounded::read(input.source(), ARGUMENT_BYTES, ctx)?;
    let text = std::str::from_utf8(raw.as_bytes())
        .map_err(|_| ProcessingError::InvalidInput("plugin arguments are not UTF-8"))?;
    let caller = caller(args);
    let bindings = match (selector, &secret) {
        (Some(selector), Some(secret)) => {
            vec![PluginKeyBinding::new(
                args.key_handle,
                KeyRequest::new(selector, Some(secret.as_str())),
            )]
        }
        _ => Vec::new(),
    };
    let bound = PluginBindings::new(&caller, &bindings);
    let call = PluginCall {
        plugin_id: id,
        operation: &args.operation,
        args: text,
    };
    let result = engine.plugin_call(&call, &bound, ctx)?;
    let applied = result.applied_state();
    let store = output::store(cli, &args.output)?;
    let mut stage = store.stage(ctx.resources())?;
    stage.write_chunk(result.response().as_bytes())?;
    #[derive(serde::Serialize)]
    struct Report {
        operation_id: u64,
        code: &'static str,
        applied: String,
        response_bytes: usize,
    }
    let report = Report {
        operation_id: ctx.id().get(),
        code: "Completed",
        applied: format!("{applied:?}"),
        response_bytes: result.response().len(),
    };
    let prepared = output::prepare(
        cli,
        &report,
        "Completed (plugin response; not signature validity)",
        true,
        ctx,
    );
    output::finish_artifact(stage, &args.output, prepared, applied)?;
    Ok(0)
}
