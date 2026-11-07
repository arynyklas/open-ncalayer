//! Runtime-only WASM plugin invocation. Installation is not authority: the
//! trusted operator names caller, operation, imports and key explicitly; guest
//! arguments cannot widen any of them. No GUI, browser origin or prompter.
//!
//! A plugin that declares its operations (`[[operations]]` in the manifest) is validated
//! against the declaration (docs/design/manual-plugins.md 4.7): the operation must be
//! declared with `server = true`, `--allow-import` must be among the declared imports (none
//! given means all declared), a key needs a declared key use, and, because the CLI cannot
//! bind the signed bytes to a document, the key use needs the explicit `--plugin-bytes`. Core
//! forces the declared signature options (there is no `--profile`: the profile is the
//! manifest's). A plugin without declarations is unchanged.
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
use std::sync::Mutex;
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
    /// The operator accepts that the plugin chooses the bytes the key signs (needed for any
    /// key use of an operation the manifest declares; the CLI cannot bind them to a document).
    #[arg(long)]
    pub plugin_bytes: bool,
    /// Not accepted: the signature profile of a declared operation comes from the manifest.
    #[arg(long, hide = true)]
    pub profile: Option<String>,
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
        if args.profile.is_some() {
            return Err("ProfileFromManifest");
        }
        if args.plugin_bytes && !self.has_key() {
            return Err("InvalidCombination");
        }
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
    pub fn key_plan(
        &self,
        control: &crate::control::Control,
        reservation: &mut oncl_pki::resource::ConfigurationReservation,
    ) -> Result<Option<crate::keysrc::Plan>, OperationError> {
        let args = self.args();
        if let (Some(config), Some(name)) = (&args.key_config, &args.key_name) {
            return crate::keysrc::resolve(config, name, control, reservation).map(Some);
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
/// The subcode of the refusal that ended this process's one command (the CLI runs exactly one
/// operation per process, so a process-wide slot is unambiguous). Read by the failure line.
static SUBCODE: Mutex<Option<&'static str>> = Mutex::new(None);
/// Notes why the command is refused (a stable id of `oncl_core::plugins::PluginRefusalCode`).
pub fn record_subcode(id: &'static str) {
    *SUBCODE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(id);
}
/// The noted subcode, once.
pub fn take_subcode() -> Option<&'static str> {
    SUBCODE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

/// What the manifest declaration allows this command: the exact imports to grant and, for
/// a key use of a declared operation under `--plugin-bytes`, the grant its ticket is checked
/// against by the key guard.
pub struct Checked {
    pub imports: Vec<Import>,
    pub bytes: Option<BytesGrant>,
}
/// The CLI's `--plugin-bytes` grant of one declared operation (the operator accepted that the
/// plugin chooses the signed bytes); the ticket of the key use must otherwise match the
/// declaration exactly.
pub struct BytesGrant {
    plugin: String,
    operation: String,
    caller: String,
    uses: Vec<(oncl_plugin::operations::KeyKind, Option<[u8; 32]>)>,
}
impl BytesGrant {
    /// Whether `ticket` is the one key use this grant allows.
    pub fn check(
        &self,
        ticket: &oncl_core::plugins::PluginUse,
    ) -> Result<(), oncl_core::plugins::TicketRefusal> {
        use oncl_core::plugins::TicketRefusal as R;
        if !matches!(ticket.caller(), CallerContext::LocalOperator(label) if *label == self.caller)
        {
            return Err(R::Caller);
        }
        if ticket.identity().id != self.plugin || ticket.operation() != self.operation {
            return Err(R::NotGranted);
        }
        if ticket.max_uses() != oncl_plugin::operations::MAX_USES {
            return Err(R::Uses);
        }
        let Some((_, options)) = self.uses.iter().find(|(kind, _)| *kind == ticket.kind()) else {
            return Err(R::Kind);
        };
        // A profile that names a parameter cannot be matched without a value: refused.
        if *options != Some(*ticket.options_sha256()) {
            return Err(R::Options);
        }
        Ok(())
    }
}

/// Validates the command against the manifest declaration; `Err` is the stable subcode of the
/// refusal (nothing was opened). A plugin without declarations passes unchanged.
fn check_declaration(
    manifest: &oncl_plugin::Manifest,
    args: &PluginCallArgs,
    has_key: bool,
) -> Result<Checked, &'static str> {
    use oncl_plugin::operations::Network;
    let named: Vec<Import> = args
        .allow_import
        .iter()
        .filter_map(|name| Import::from_name(name))
        .collect();
    if manifest.operations().is_empty() {
        if args.plugin_bytes {
            crate::diagnostic(format_args!(
                "oncl: warning: --plugin-bytes has no effect: the plugin declares no operations"
            ));
        }
        return Ok(Checked {
            imports: named,
            bytes: None,
        });
    }
    let operation = manifest
        .operations()
        .iter()
        .find(|o| o.name() == args.operation && o.server() && o.runnable())
        .ok_or("not-declared")?;
    let declared = operation.uses().imports();
    let imports = if named.is_empty() {
        declared.to_vec()
    } else if named.iter().all(|import| declared.contains(import)) {
        named
    } else {
        return Err("not-declared");
    };
    let key_declared = !operation.uses().keys().is_empty();
    if has_key && !key_declared {
        return Err("no-key-use");
    }
    if !args.plugin_pki_endpoint.is_empty() && !matches!(operation.uses().network(), Network::Pki) {
        return Err("network-not-declared");
    }
    let none: &dyn Fn(&str) -> Option<String> = &|_| None;
    let bytes = (has_key && args.plugin_bytes).then(|| BytesGrant {
        plugin: manifest.id.clone(),
        operation: operation.name().to_owned(),
        caller: args.caller.clone(),
        uses: operation
            .uses()
            .keys()
            .iter()
            .map(|use_| (use_.kind(), use_.options_sha256(none)))
            .collect(),
    });
    Ok(Checked { imports, bytes })
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
    checked: &Checked,
) -> Result<PluginPermission, OperationError> {
    PluginPermission::new(
        id,
        args.operation.clone(),
        caller(args),
        checked.imports.iter().copied(),
    )
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
) -> Result<(PluginRegistry, ConfigurationReservation, String, Checked), OperationError> {
    let args = command.args();
    let mut reservation = budget.reserve_configuration(0, 0)?;
    let manifest_bytes = read_bounded_file(&args.manifest, MANIFEST_BYTES, &mut reservation, 64)?;
    let wasm = read_bounded_file(&args.module, MODULE_BYTES, &mut reservation, 4)?;
    let package_hash = oncl_core::plugins::loose_package_hash(&manifest_bytes, &wasm);
    let text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| ProcessingError::InvalidInput("manifest is not UTF-8"))?;
    let manifest = oncl_plugin::Manifest::from_toml(text)
        .map_err(|_| ProcessingError::InvalidInput("invalid plugin manifest"))?;
    let checked = check_declaration(&manifest, args, selector.is_some()).map_err(|subcode| {
        record_subcode(subcode);
        OperationError::PermissionDenied
    })?;
    let id = manifest.id.clone();
    let mut registry = PluginRegistry::new();
    registry.install(
        manifest,
        package_hash,
        &wasm,
        oncl_plugin::InstanceLimits {
            max_memory: 1 << 20,
            max_transfer: ARGUMENT_BYTES,
            ..Default::default()
        },
        vec![permission(args, &id, selector, &checked)?],
    )?;
    Ok((registry, reservation, id, checked))
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
    let result = match engine.plugin_call(&call, &bound, ctx) {
        Ok(result) => result,
        Err(error) => {
            if let Some(code) = ctx.plugin_refusal_code() {
                record_subcode(code.id());
            }
            return Err(error);
        }
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_core::plugins::{ContentBinding, PluginIdentity, PluginUse, TicketRefusal as R};
    use oncl_plugin::operations::KeyKind;

    const DECLARED_HASH: [u8; 32] = [3; 32];

    fn grant() -> BytesGrant {
        BytesGrant {
            plugin: "test.cli".into(),
            operation: "sign".into(),
            caller: "op".into(),
            uses: vec![(KeyKind::Raw, Some(DECLARED_HASH))],
        }
    }
    fn ticket(operation: &str, caller: &str, kind: KeyKind, options: [u8; 32]) -> PluginUse {
        PluginUse::for_tests(
            PluginIdentity {
                id: "test.cli".into(),
                package: oncl_core::plugins::loose_package_hash(b"m", b"w"),
                version: "1".into(),
            },
            operation,
            CallerContext::LocalOperator(caller.into()),
            kind,
            1,
            oncl_core::keys::KeyId::new("k").unwrap(),
            ContentBinding::bytes(b"x"),
            options,
            [0; 32],
        )
    }

    #[test]
    fn only_the_declared_use_of_the_named_operator_is_allowed() {
        let g = grant();
        g.check(&ticket("sign", "op", KeyKind::Raw, DECLARED_HASH))
            .unwrap();
        assert_eq!(
            g.check(&ticket("sign", "other", KeyKind::Raw, DECLARED_HASH)),
            Err(R::Caller)
        );
        assert_eq!(
            g.check(&ticket("legacy", "op", KeyKind::Raw, DECLARED_HASH)),
            Err(R::NotGranted)
        );
        assert_eq!(
            g.check(&ticket("sign", "op", KeyKind::Cms, DECLARED_HASH)),
            Err(R::Kind)
        );
        assert_eq!(
            g.check(&ticket("sign", "op", KeyKind::Raw, [9; 32])),
            Err(R::Options)
        );
        let mut param = grant();
        param.uses = vec![(KeyKind::Raw, None)];
        assert_eq!(
            param.check(&ticket("sign", "op", KeyKind::Raw, DECLARED_HASH)),
            Err(R::Options)
        );
    }
}
