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
//!
//! A declared operation may also be given typed parameters instead of a free `--args-file`
//! (`--param`, `--param-file`, `--param-flag`): the request is then built by Core from the
//! manifest's template exactly as the manual window builds it (docs/user/cli.md, "plugin").
//! The CLI never prompts for consent: the operator who runs the command is the consenting
//! party, and `--plugin-bytes` is that consent for a key use.
//!
//! `plugin operations` lists what a manifest declares (see [`crate::plugin_list`]).
use crate::{args::Cli, bounded, local::Input, output, secrets};
use clap::{Args, Subcommand};
use oncl_core::{
    Engine, ErrorCode, OperationContext, OperationError,
    keys::{KeyRequest, KeySelector},
    plugins::{
        CallerContext, ContentBinding, PluginBindings, PluginCall, PluginKeyBinding, PluginParam,
        PluginPermission, PluginRefusalCode, PluginRegistry, PluginRequestError,
    },
};
use oncl_pdk::abi::Import;
use oncl_pki::resource::{ConfigurationReservation, ProcessingError, SharedBudget};
use oncl_plugin::operations::{Param, ParamKind};
use std::sync::{Mutex, OnceLock};
use std::{path::PathBuf, sync::Arc};

#[derive(Subcommand)]
pub enum PluginCommand {
    /// Runs one operation of a plugin under the operator's grants.
    Call(Box<PluginCallArgs>),
    /// Lists the operations a plugin manifest declares (and optionally checks its module).
    Operations(crate::plugin_list::OperationsArgs),
}
#[derive(Args)]
pub struct PluginCallArgs {
    /// The plugin's `plugin.toml` (at most 64 KiB).
    #[arg(long)]
    pub manifest: PathBuf,
    /// The plugin's WebAssembly module (at most 16 MiB).
    #[arg(long)]
    pub module: PathBuf,
    /// The operation to run: a declared one (with `server = true`), or the label granted for a
    /// plugin without declarations.
    #[arg(long)]
    pub operation: String,
    /// Trusted local operator label; never a browser origin or guest field.
    #[arg(long)]
    pub caller: String,
    /// Exact host import names the operator allows (for example `hash`).
    #[arg(long)]
    pub allow_import: Vec<String>,
    /// Free JSON request for the module (bounded; `-` is stdin). A plugin without declared
    /// operations needs it; a declared operation takes `--param*` instead.
    #[arg(long)]
    pub args_file: Option<String>,
    /// Where the module's response is written (`-` is stdout); never overwrites.
    #[arg(long)]
    pub output: String,
    /// PKCS#12 or JKS key container to bind as key handle `--key-handle`.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// The entry of `--key` when it holds several.
    #[arg(long, requires = "key")]
    pub alias: Option<String>,
    /// Operator-configured key by name (see `--key-config`); no container path on the command line.
    #[arg(long, requires = "key_config", conflicts_with_all = ["key", "alias"])]
    pub key_name: Option<String>,
    /// The operator's JSON key configuration that `--key-name` is looked up in.
    #[arg(long, requires = "key_name")]
    pub key_config: Option<PathBuf>,
    /// The handle the module addresses the bound key by.
    #[arg(long, default_value_t = 1)]
    pub key_handle: u32,
    /// File holding the key password (an owner-only directory).
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
    /// Ask for the key password on the terminal.
    #[arg(long, conflicts_with = "secret_file")]
    pub secret_interactive: bool,
    /// Confirms this exact key use; required with a key. Nothing else ever asks.
    #[arg(long)]
    pub authorize: bool,
    /// Exact PKI base the guest's key validation may reach, as `GET=url`/`POST=url`.
    #[arg(long)]
    pub plugin_pki_endpoint: Vec<String>,
    /// The operator accepts that the plugin chooses the bytes the key signs (needed for any
    /// key use of an operation the manifest declares; the CLI cannot bind them to a document).
    #[arg(long)]
    pub plugin_bytes: bool,
    /// Text, choice or locale value of a declared parameter: `NAME=VALUE`.
    #[arg(long)]
    pub param: Vec<String>,
    /// A document parameter read from a file (`-` is stdin): `NAME=PATH`.
    #[arg(long)]
    pub param_file: Vec<String>,
    /// A flag parameter set to true (an unnamed flag parameter is false).
    #[arg(long)]
    pub param_flag: Vec<String>,
    /// Not accepted: the signature profile of a declared operation comes from the manifest.
    #[arg(long, hide = true)]
    pub profile: Option<String>,
}
pub(crate) const MANIFEST_BYTES: u64 = 64 * 1024;
pub(crate) const MODULE_BYTES: u64 = 16 * 1024 * 1024;
const ARGUMENT_BYTES: usize = 1 << 18;

impl PluginCommand {
    /// The `call` arguments; `None` for `operations`, which opens no key and no engine.
    pub fn call_args(&self) -> Option<&PluginCallArgs> {
        match self {
            Self::Call(args) => Some(args.as_ref()),
            Self::Operations(_) => None,
        }
    }
    /// The `--output` destination of `call`.
    pub fn output(&self) -> Option<&str> {
        self.call_args().map(|args| args.output.as_str())
    }
    pub fn preflight(&self) -> Result<(), &'static str> {
        let Some(args) = self.call_args() else {
            return Ok(());
        };
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
        args.preflight_params()?;
        let stdin = args.stdin_claims();
        if stdin > 1 {
            return Err("StdinConflict");
        }
        if stdin == 1 && args.secret_interactive {
            return Err("SecretRequiresSeparateInput");
        }
        Ok(())
    }
    pub fn key_plan(
        &self,
        control: &crate::control::Control,
        reservation: &mut oncl_pki::resource::ConfigurationReservation,
    ) -> Result<Option<crate::keysrc::Plan>, OperationError> {
        let Some(args) = self.call_args() else {
            return Ok(None);
        };
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
        self.call_args()
            .is_some_and(|args| args.key.is_some() || args.key_name.is_some())
    }
}
impl PluginCallArgs {
    /// Whether any typed parameter was given.
    fn typed(&self) -> bool {
        !(self.param.is_empty() && self.param_file.is_empty() && self.param_flag.is_empty())
    }
    /// Whether the request is built from the manifest's template and typed parameters rather
    /// than read from a free file: whenever there is no `--args-file`.
    fn builds_request(&self) -> bool {
        self.args_file.is_none()
    }
    /// How many of the document sources read standard input.
    fn stdin_claims(&self) -> usize {
        usize::from(self.args_file.as_deref() == Some("-"))
            + self
                .param_file
                .iter()
                .filter(|entry| entry.split_once('=').is_some_and(|(_, path)| path == "-"))
                .count()
    }
    /// Syntax of the typed parameters, before any file is opened. Values are never echoed.
    fn preflight_params(&self) -> Result<(), &'static str> {
        if self.typed() && self.args_file.is_some() {
            return Err("InvalidCombination");
        }
        if self.param.len() > MAX_TYPED || self.param_file.len() > MAX_TYPED {
            return Err("InvalidCombination");
        }
        if self.param_flag.len() > MAX_TYPED {
            return Err("InvalidCombination");
        }
        let text = |entry: &String| {
            entry
                .split_once('=')
                .is_some_and(|(name, _)| param_name(name))
        };
        let file = |entry: &String| {
            entry
                .split_once('=')
                .is_some_and(|(name, path)| param_name(name) && !path.is_empty())
        };
        if !self.param.iter().all(text)
            || !self.param_file.iter().all(file)
            || !self.param_flag.iter().all(|name| param_name(name))
        {
            return Err("InvalidCombination");
        }
        Ok(())
    }
    /// The value of a `--param NAME=VALUE`, for the options a profile reads from a parameter.
    fn text(&self, name: &str) -> Option<String> {
        self.param.iter().find_map(|entry| {
            entry
                .split_once('=')
                .filter(|(n, _)| *n == name)
                .map(|(_, value)| value.to_owned())
        })
    }
}
/// The most parameters of each kind the command line may carry (a declared operation has at
/// most [`oncl_plugin::operations::MAX_PARAMS`]).
const MAX_TYPED: usize = oncl_plugin::operations::MAX_PARAMS;
/// `^[a-z][a-z0-9_]{0,31}$`, the name of a declared parameter.
fn param_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
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
/// The operator's record of an authorised key use of a declared operation, written before the
/// key is used (so a failing signature is still recorded). The CLI has no journal: stderr is
/// the record. It names the trusted facts of the ticket, never the document, a parameter,
/// a secret or the nonce (a CLI use has none: the operator's `--plugin-bytes` is the
/// consent, recorded as `grant=cli-plugin-bytes`).
pub fn audit_line(operation_id: u64, ticket: &oncl_core::plugins::PluginUse) {
    let record = oncl_core::plugins::PluginAuditRecord::from_ticket(
        ticket,
        None,
        Some("cli-plugin-bytes".to_owned()),
    );
    crate::diagnostic(format_args!(
        "oncl: plugin_use operation_id={operation_id} plugin={} version={} package={}:{} \
         operation={} caller={} declared={} grant={} content_sha256={} content_len={} \
         prehashed={} options_sha256={} ticket={}",
        record.plugin_id,
        record.version,
        record.package_kind,
        crate::reports::Hex(&record.package_sha256),
        record.operation,
        record.caller.as_str(),
        record.declared,
        record.grant_id.as_deref().unwrap_or("none"),
        crate::reports::Hex(&record.content_sha256),
        record.content_len,
        record.prehashed,
        crate::reports::Hex(&record.options_sha256),
        crate::reports::Hex(&record.ticket_digest),
    ));
}

/// What the manifest declaration allows this command: the exact imports to grant and, for
/// a key use of a declared operation under `--plugin-bytes`, the grant its ticket is checked
/// against by the key guard.
pub struct Checked {
    pub imports: Vec<Import>,
    pub bytes: Option<BytesGrant>,
    /// The declared parameters of the operation (empty for a plugin without declarations).
    pub params: Vec<oncl_plugin::operations::Param>,
    /// Where the request builder leaves the bytes of the bound parameter for the grant.
    pub bound: Option<(String, Arc<OnceLock<oncl_core::plugins::ContentBinding>>)>,
}
/// The CLI's `--plugin-bytes` grant of one declared operation (the operator accepted that the
/// plugin chooses the signed bytes); the ticket of the key use must otherwise match the
/// declaration exactly.
pub struct BytesGrant {
    plugin: String,
    operation: String,
    caller: String,
    uses: Vec<(oncl_plugin::operations::KeyKind, Option<[u8; 32]>)>,
    /// With typed parameters: the bytes of the parameter the key use is bound to, set once the
    /// request is built. The ticket's content must equal them. `None`: a free request, which
    /// binds the operation and options only.
    bound: Option<Arc<OnceLock<oncl_core::plugins::ContentBinding>>>,
}
impl BytesGrant {
    /// Whether the grant binds content that Core would hand over as a digest, which the CLI
    /// cannot compute before the key is opened.
    pub fn content_unavailable(&self, ticket: &oncl_core::plugins::PluginUse) -> bool {
        self.bound.is_some() && ticket.content().prehashed
    }
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
        if let Some(slot) = &self.bound
            && slot.get() != Some(ticket.content())
        {
            return Err(R::Content);
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
        // A request built from typed parameters needs a declared operation.
        if args.builds_request() {
            return Err("not-declared");
        }
        if args.plugin_bytes {
            crate::diagnostic(format_args!(
                "oncl: warning: --plugin-bytes has no effect: the plugin declares no operations"
            ));
        }
        return Ok(Checked {
            imports: named,
            bytes: None,
            params: Vec::new(),
            bound: None,
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
    // A profile that names a text parameter is matched with the value `--param` gave it.
    let value = |name: &str| args.text(name);
    let bound = (has_key && args.plugin_bytes && args.builds_request())
        .then(|| {
            operation
                .uses()
                .keys()
                .iter()
                .find_map(|k| match k.content() {
                    oncl_plugin::operations::Content::Bound(name) => {
                        Some((name.clone(), Arc::new(OnceLock::new())))
                    }
                    _ => None,
                })
        })
        .flatten();
    let bytes = (has_key && args.plugin_bytes).then(|| BytesGrant {
        bound: bound.as_ref().map(|(_, slot)| slot.clone()),
        plugin: manifest.id.clone(),
        operation: operation.name().to_owned(),
        caller: args.caller.clone(),
        uses: operation
            .uses()
            .keys()
            .iter()
            .map(|use_| (use_.kind(), use_.options_sha256(&value)))
            .collect(),
    });
    Ok(Checked {
        imports,
        bytes,
        params: operation.params().to_vec(),
        bound,
    })
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
pub(crate) fn read_bounded_file(
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
    let args = command.call_args().ok_or(OperationError::InvalidContext)?;
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
/// One typed parameter, owned until the request is built.
enum Owned {
    Document(bounded::Bytes),
    Text(String),
    Flag(bool),
}
/// A refused request: the stable subcode is noted for the failure line, the error is the
/// one Core gives it. Nothing was opened and no key was touched.
fn refuse(error: PluginRequestError) -> OperationError {
    record_subcode(PluginRefusalCode::from(&error).id());
    error.into()
}
/// `NAME=VALUE`, already checked by the preflight.
fn pair(entry: &str) -> Result<(&str, &str), OperationError> {
    entry
        .split_once('=')
        .ok_or_else(|| ProcessingError::InvalidInput("malformed parameter").into())
}
/// The request of a declared operation: Core fills the manifest's template with the typed
/// parameters, exactly as the manual window does (documents as standard base64).
fn typed_request(
    engine: &Engine,
    id: &str,
    args: &PluginCallArgs,
    declared: &[Param],
    bound: Option<&(String, Arc<OnceLock<oncl_core::plugins::ContentBinding>>)>,
    ctx: &mut OperationContext,
) -> Result<String, OperationError> {
    let kind = |name: &str| declared.iter().find(|p| p.name == name).map(|p| &p.kind);
    let mut owned: Vec<(&str, Owned)> = Vec::new();
    for entry in &args.param {
        let (name, value) = pair(entry)?;
        owned.push((name, Owned::Text(value.to_owned())));
    }
    for entry in &args.param_file {
        let (name, path) = pair(entry)?;
        // A file is read only for a declared document, and never past its declared size (or
        // the request limit): a larger one is refused as `param-too-large`.
        let limit = match kind(name) {
            Some(ParamKind::Document { max_bytes }) => {
                usize::try_from((*max_bytes).min(ARGUMENT_BYTES as u64)).unwrap_or(ARGUMENT_BYTES)
            }
            None => return Err(refuse(PluginRequestError::UnknownParam(name.to_owned()))),
            Some(_) => return Err(refuse(PluginRequestError::WrongKind(name.to_owned()))),
        };
        let mut input = Input::open(path)?;
        let bytes = bounded::read(input.source(), limit, ctx).inspect_err(|error| {
            if error.code() == ErrorCode::InputLimit {
                record_subcode(PluginRefusalCode::ParamTooLarge.id());
            }
        })?;
        owned.push((name, Owned::Document(bytes)));
    }
    for name in &args.param_flag {
        owned.push((name, Owned::Flag(true)));
    }
    // A flag that is not named is off.
    for param in declared {
        if matches!(param.kind, ParamKind::Flag) && !owned.iter().any(|(n, _)| *n == param.name) {
            owned.push((&param.name, Owned::Flag(false)));
        }
    }
    if let Some((name, slot)) = bound
        && let Some((_, value)) = owned.iter().find(|(n, _)| n == name)
    {
        let binding = match value {
            Owned::Document(bytes) => ContentBinding::bytes(bytes.as_bytes()),
            Owned::Text(text) => ContentBinding::bytes(text.as_bytes()),
            Owned::Flag(_) => return Err(refuse(PluginRequestError::WrongKind(name.clone()))),
        };
        let _ = slot.set(binding);
    }
    let params: Vec<(&str, PluginParam<'_>)> = owned
        .iter()
        .map(|(name, value)| {
            let value = match value {
                Owned::Document(bytes) => PluginParam::Document(bytes.as_bytes()),
                Owned::Flag(on) => PluginParam::Flag(*on),
                Owned::Text(text) => match kind(name) {
                    Some(ParamKind::Choice { .. }) => PluginParam::Choice(text),
                    Some(ParamKind::Locale) => PluginParam::Locale(text),
                    _ => PluginParam::Text(text),
                },
            };
            (*name, value)
        })
        .collect();
    engine
        .plugin_server_request(id, &args.operation, &params)
        .map_err(refuse)
}
pub fn call(
    engine: &Engine,
    command: &PluginCommand,
    id: &str,
    checked: &Checked,
    selector: Option<&KeySelector>,
    cli: &Cli,
    ctx: &mut OperationContext,
) -> Result<i32, OperationError> {
    let args = command.call_args().ok_or(OperationError::InvalidContext)?;
    // A request built from typed parameters is refused before a secret is asked for.
    let built = if args.builds_request() {
        Some(typed_request(
            engine,
            id,
            args,
            &checked.params,
            checked.bound.as_ref(),
            ctx,
        )?)
    } else {
        None
    };
    let _secret_memory = ctx.resources().reserve_memory(16384)?;
    let secret = if selector.is_some() {
        Some(secrets::read(
            args.secret_file.as_deref(),
            args.secret_interactive,
            args.stdin_claims() > 0,
            ctx,
        )?)
    } else {
        None
    };
    let free = match &args.args_file {
        Some(path) => {
            let mut input = Input::open(path)?;
            Some(bounded::read(input.source(), ARGUMENT_BYTES, ctx)?)
        }
        None => None,
    };
    let text = match (&built, &free) {
        (Some(request), _) => request.as_str(),
        (None, Some(raw)) => std::str::from_utf8(raw.as_bytes())
            .map_err(|_| ProcessingError::InvalidInput("plugin arguments are not UTF-8"))?,
        (None, None) => return Err(OperationError::InvalidContext),
    };
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
            bound: None,
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

    const XML_DECLARED: &str = r#"id = "test.cli"
name.ru = "x"
name.kk = "x"
name.en = "x"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["test.cli.module"]
[capabilities]
keys = true
[[operations]]
name = "sign"
module = "test.cli.module"
server = true
request = '{"module":"test.cli.module","method":"m","args":["{file:base64}","{xp}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 4096
[[operations.params]]
name = "xp"
kind = "text"
max_chars = 64
[operations.uses]
imports = ["keys_sign_xml"]
network = "none"
[[operations.uses.key]]
kind = "xml"
content = "param:file"
[operations.uses.key.profile]
element = "param:xp"
"#;

    fn checked(extra: &[&str]) -> Checked {
        use clap::Parser;
        let mut argv = vec![
            "oncl",
            "plugin",
            "call",
            "--manifest",
            "m",
            "--module",
            "w",
            "--operation",
            "sign",
            "--caller",
            "op",
            "--output",
            "-",
            "--key",
            "k",
            "--authorize",
            "--plugin-bytes",
        ];
        argv.extend(extra);
        let cli = Cli::try_parse_from(argv).unwrap();
        let crate::args::Command::Plugin { command } = &cli.command else {
            panic!("a plugin command")
        };
        command.preflight().unwrap();
        let manifest = oncl_plugin::Manifest::from_toml(XML_DECLARED).unwrap();
        check_declaration(&manifest, command.call_args().unwrap(), true).unwrap()
    }
    /// The options hash the ticket of a use of the profile with this element carries.
    fn options_of(element: &str) -> [u8; 32] {
        let manifest = oncl_plugin::Manifest::from_toml(XML_DECLARED).unwrap();
        let use_ = &manifest.operations()[0].uses().keys()[0];
        use_.options_sha256(&|name| (name == "xp").then(|| element.to_owned()))
            .unwrap()
    }

    #[test]
    fn a_profile_parameter_is_granted_with_the_value_the_operator_gave() {
        // Typed: the grant covers exactly the profile with that element, and no other.
        let granted = checked(&["--param", "xp=/root/a", "--param-file", "file=f"])
            .bytes
            .unwrap();
        granted
            .bound
            .as_ref()
            .unwrap()
            .set(ContentBinding::bytes(b"x"))
            .unwrap();
        granted
            .check(&ticket("sign", "op", KeyKind::Xml, options_of("/root/a")))
            .unwrap();
        assert_eq!(
            granted.check(&ticket("sign", "op", KeyKind::Xml, options_of("/root/b"))),
            Err(R::Options)
        );
        // A text that is no XPath cannot be matched by anything.
        let invalid = checked(&["--param", "xp=root", "--param-file", "file=f"])
            .bytes
            .unwrap();
        assert_eq!(
            invalid.check(&ticket("sign", "op", KeyKind::Xml, options_of("/root"))),
            Err(R::Options)
        );
        // Free arguments carry no value for it: refused, as before.
        let free = checked(&["--args-file", "a.json"]).bytes.unwrap();
        assert_eq!(
            free.check(&ticket("sign", "op", KeyKind::Xml, options_of("/root/a"))),
            Err(R::Options)
        );
    }
}
