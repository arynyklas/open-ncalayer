//! `--endpoint`: every operation runs on an `oncl-server`; this process is only a streaming
//! client of the accepted typed HTTP contract (`oncl_api::client`).
//!
//! * Local paths are always read and written *here*: documents are streamed to the server as
//!   request parts, results are staged here and published only after the complete, verified
//!   response (terminal record + closing delimiter + end of the HTTP entity). A response
//!   that does not reach its terminal record commits nothing, is reported with the honest
//!   `applied` state (`Unknown` when a private key could have been applied) and is never
//!   retried.
//! * Authority stays with the operator: trust roots, validation policy, PKI network, TSA,
//!   claims policy and plugin installation are server configuration. Options that would
//!   configure them locally are refused instead of being ignored.
//! * Key material leaves this process only in the explicit `--inline-key` mode and only
//!   with the protected secret input; otherwise `--key-name` references an operator key.
mod batch;
mod ops;
mod reports;

use crate::{
    args::{Cli, Command, PrivateKeyArgs, SignProfile},
    control::Control,
    local::Input,
    secrets,
};
use oncl_api::{
    client::{
        ApiClient, ArtifactSink, ClientConfig, ClientError, Completed, ExecuteOptions, FailureKind,
        FinalRecord, Request, Route, Source, Stop,
    },
    dto::{
        EvidenceKind, EvidenceRef, ItemMetadata, KeyRef, Operation, OperationMetadata,
        PartMetadata, PartRole,
    },
    error::AppliedState as WireApplied,
};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy, keys::AppliedState,
};
use oncl_pki::{
    io::{StagedArtifact, TemporaryStore},
    resource::{ProcessingError, ResourceLimits},
};
use std::{
    io::{self, Read},
    path::Path,
    sync::Arc,
    time::Instant,
};
use zeroize::Zeroizing;

/// The failure shown as `oncl: <code>; applied=<state>` (the local contract) with its exit.
pub struct Failure {
    pub code: String,
    pub applied: AppliedState,
    pub cancelled: bool,
}
impl From<OperationError> for Failure {
    fn from(error: OperationError) -> Self {
        Self {
            code: format!("{:?}", error.code()),
            applied: error.applied_state(),
            cancelled: error.code() == oncl_core::ErrorCode::Cancelled,
        }
    }
}
impl From<ProcessingError> for Failure {
    fn from(error: ProcessingError) -> Self {
        OperationError::from(error).into()
    }
}
pub fn core_applied(state: WireApplied) -> AppliedState {
    match state {
        WireApplied::NotApplied => AppliedState::NotApplied,
        WireApplied::Applied => AppliedState::Applied,
        WireApplied::Unknown => AppliedState::Unknown,
    }
}
impl Failure {
    fn protocol(applied: AppliedState) -> Self {
        Self {
            code: FailureKind::Protocol.code().into(),
            applied,
            cancelled: false,
        }
    }
    fn client(error: &ClientError, staging: Option<OperationError>) -> Self {
        let applied = core_applied(error.applied);
        match staging {
            // A local staging failure keeps its own code; what the key did stays honest.
            Some(local) if error.kind == FailureKind::Artifact => Self {
                code: format!("{:?}", local.code()),
                applied: applied.combine(local.applied_state()),
                cancelled: local.code() == oncl_core::ErrorCode::Cancelled,
            },
            _ => Self {
                code: error.describe(),
                applied,
                cancelled: error.kind == FailureKind::Cancelled,
            },
        }
    }
    /// A failed terminal record, as the service stated it.
    fn record(error: &oncl_api::error::ApiError) -> Self {
        Self {
            code: format!("{:?}", error.code),
            applied: core_applied(error.applied),
            cancelled: error.code == oncl_api::error::ErrorCode::Cancelled,
        }
    }
}

const REFUSED: &str = "RemoteUnsupported";
const CA_FILE_LIMIT: u64 = 256 * 1024;

fn wsse_beyond_soap(options: &crate::wsse::WsseOptions, body_id_allowed: bool) -> bool {
    options.wsse_role.is_some()
        || !options.wsse_required_header.is_empty()
        || options.wsse_timestamp_required
        || options.wsse_timestamp_max_lifetime.is_some()
        || options.wsse_token_reference.is_some()
        || options.wsse_token_id.is_some()
        || (options.wsse_body_id.is_some() && !body_id_allowed)
        || options.wsse_timestamp_id.is_some()
        || options.wsse_timestamp_created.is_some()
        || options.wsse_timestamp_expires.is_some()
}
fn legacy_beyond_wire(options: &crate::legacy::LegacyOptions) -> bool {
    !options.legacy_namespace.is_empty()
        || options.legacy_other_prefix_uri.is_some()
        || options.legacy_placement.is_some()
        || options.legacy_signed_info_c14n.is_some()
        || !options.legacy_transform.is_empty()
        || options.legacy_signing_time_id.is_some()
        || options.legacy_signing_time.is_some()
        || options.legacy_signing_time_reference
        || options.legacy_line_breaks
        || options.legacy_base64_line_breaks.is_some()
        || options.legacy_output.is_some()
        || options.legacy_xml_declaration
        || options.legacy_standalone_no
        || options.legacy_keep_outer_whitespace
        || !options.legacy_chain.is_empty()
}
fn key_refused(key: &PrivateKeyArgs, cli: &Cli) -> Result<(), &'static str> {
    // A token reader is a local device; a key configuration file is a local operator file.
    if key.token_reader.is_some() || key.key_config.is_some() {
        return Err(REFUSED);
    }
    match (&key.key, &key.key_name) {
        (Some(_), None) => {
            // Key material is only ever sent in the explicit inline mode.
            if !cli.inline_key {
                return Err("InlineKeyRequired");
            }
            Ok(())
        }
        (None, Some(_)) => {
            // The password of a named key is the operator's, never a client value.
            if cli.inline_key || key.secret_file.is_some() || key.secret_interactive {
                return Err("InvalidCombination");
            }
            Ok(())
        }
        _ => Err("InvalidCombination"),
    }
}
fn uses_stdin(command: &Command) -> bool {
    use crate::families::TimestampCommand as T;
    let dash = |text: &str| text == "-";
    let optional = |text: &Option<String>| text.as_deref() == Some("-");
    match command {
        Command::Hash { input, .. } | Command::Extract { input, .. } => dash(input),
        Command::Verify {
            input, detached, ..
        } => dash(input) || optional(detached),
        Command::Sign(args) => dash(&args.input) || optional(&args.detached_input),
        Command::Inspect(args) => optional(&args.input),
        Command::Extend(args) => dash(&args.input) || optional(&args.detached),
        Command::Timestamp { command } => match command {
            T::Acquire { input, .. } => dash(input),
            T::Verify { input, data, .. } => dash(input) || optional(data),
        },
        Command::Batch { command } => command.args().manifest.as_os_str() == "-",
        Command::Plugin { .. } => false,
        Command::Jws { command } => match command {
            crate::jose_args::JwsCommand::Sign(args) => {
                dash(&args.input) || optional(&args.detached_input)
            }
            crate::jose_args::JwsCommand::Verify(args) => {
                dash(&args.input) || optional(&args.detached_input)
            }
        },
        Command::Jwt { command } => match command {
            crate::jose_args::JwtCommand::Encode(args) => dash(&args.input),
            crate::jose_args::JwtCommand::Verify(args) => dash(&args.input),
            crate::jose_args::JwtCommand::Decode { input, .. } => dash(input),
        },
    }
}

/// Refusals that need no I/O. Runs before any file, secret or network use.
pub fn preflight(cli: &Cli) -> Result<(), &'static str> {
    use crate::{
        families::{ExtendProfile, InspectProfile, Level, TimestampCommand as T},
        jose_args::{JwsCommand, JwtCommand},
    };
    let Some(endpoint) = cli.endpoint.as_deref() else {
        return Ok(());
    };
    // The endpoint is the only trusted address: parse (and refuse plain http to a remote
    // host) before anything else.
    let parsed = oncl_api::client::Endpoint::parse(endpoint, cli.allow_plain_http)
        .map_err(|error| error.kind.code())?;
    if !parsed.is_tls() && !cli.ca_file.is_empty() {
        return Err(FailureKind::InvalidEndpoint.code());
    }
    if cli.ca_file.len() > 16 {
        return Err("ConfigurationLimit");
    }
    if cli.token_file.is_some() && cli.token_stdin {
        return Err("InvalidCombination");
    }
    if cli.token_file.is_none() && !cli.token_stdin {
        return Err("TokenRequired");
    }
    if cli.token_stdin && uses_stdin(&cli.command) {
        return Err("StdinConflict");
    }
    // Trust, validation policy, PKI network and clocks are the operator's.
    if cli.offline
        || !cli.root.is_empty()
        || !cli.intermediate.is_empty()
        || !cli.pki_endpoint.is_empty()
        || !cli.pki_pin.is_empty()
        || cli.tsa_url.is_some()
        || cli.tsa_policy.is_some()
        || cli.as_of.is_some()
        || cli.configuration_bytes != 16_777_216
    {
        return Err(REFUSED);
    }
    match &cli.command {
        Command::Plugin { .. } => Err(REFUSED),
        Command::Hash { .. } | Command::Extract { .. } => Ok(()),
        Command::Verify { wsse, pem, .. } => {
            // PEM intake is a local-only convenience: the server's verify route takes DER.
            if *pem || wsse_beyond_soap(wsse, false) {
                return Err(REFUSED);
            }
            Ok(())
        }
        Command::Sign(args) => {
            ops::sign_kind(args)?;
            key_refused(&args.key_options, cli)?;
            if wsse_beyond_soap(&args.wsse, true) || legacy_beyond_wire(&args.legacy) {
                return Err(REFUSED);
            }
            if args.add
                && !matches!(
                    args.profile,
                    SignProfile::Cms
                        | SignProfile::CadesB
                        | SignProfile::CadesT
                        | SignProfile::CadesLt
                        | SignProfile::CadesLta
                )
            {
                return Err(REFUSED);
            }
            Ok(())
        }
        Command::Inspect(args) => {
            if !args.alias.is_empty() || args.key_config.is_some() {
                // Which aliases are shown is the token's grant, not a client request.
                return Err(REFUSED);
            }
            match args.profile {
                InspectProfile::Container if !cli.inline_key => Err("InlineKeyRequired"),
                InspectProfile::Container => Ok(()),
                _ if cli.inline_key => Err("InvalidCombination"),
                _ => Ok(()),
            }
        }
        Command::Extend(args) => match (args.profile, args.level) {
            (ExtendProfile::Cms | ExtendProfile::Pdf, Level::T | Level::Lt | Level::Lta) => Ok(()),
            (ExtendProfile::Xml, Level::Lt | Level::Lta) => Ok(()),
            _ => Err(REFUSED),
        },
        Command::Timestamp { command } => match command {
            T::Acquire { tsa, algorithm, .. } => {
                // The TSA is the operator's `[pki.tsa]`; the digest is fixed by the service.
                if tsa.is_some() || !matches!(algorithm, crate::args::Algorithm::Sha256) {
                    return Err(REFUSED);
                }
                Ok(())
            }
            T::Verify { policy_oid, .. } => {
                if policy_oid.is_some() {
                    return Err(REFUSED);
                }
                Ok(())
            }
        },
        Command::Jws { command } => match command {
            JwsCommand::Sign(args) => key_refused(&args.key, cli),
            JwsCommand::Verify(_) => Ok(()),
        },
        Command::Jwt { command } => match command {
            JwtCommand::Encode(args) => key_refused(&args.key, cli),
            JwtCommand::Verify(args) => {
                // Issuer, audience and leeway are the operator's `[pki.jwt]` policy.
                if args.issuer.is_some() || args.audience.is_some() || args.leeway_seconds != 0 {
                    return Err(REFUSED);
                }
                Ok(())
            }
            JwtCommand::Decode { .. } => Ok(()),
        },
        Command::Batch { command } => {
            let args = command.args();
            if args.key_config.is_some() {
                return Err(REFUSED);
            }
            match (&args.key, &args.key_name) {
                (Some(_), _) if !cli.inline_key => Err("InlineKeyRequired"),
                (None, Some(_))
                    if cli.inline_key || args.secret_file.is_some() || args.secret_interactive =>
                {
                    Err("InvalidCombination")
                }
                (None, None) if cli.inline_key => Err("InvalidCombination"),
                _ => Ok(()),
            }
        }
    }
}

/// Client-side scope: a context that only meters this process's own I/O (staging, reports,
/// secret reads). Its grant authorizes nothing remote; the server decides every operation.
fn scope(cli: &Cli, control: &Arc<Control>) -> Result<OperationContext, OperationError> {
    let mut limits = ResourceLimits {
        operation_timeout: control.remaining()?,
        ..ResourceLimits::default()
    };
    if let Some(output) = cli.output_limit {
        limits.output_bytes = output;
    }
    let engine = Engine::new(EngineServices::hash_only(limits))?;
    engine.begin(
        ExecutionGrant::new([Action::Hash]),
        OperationPolicy::offline_report(),
        control.clone(),
    )
}

fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>, OperationError> {
    let file = std::fs::File::open(path).map_err(ProcessingError::from)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(ProcessingError::from)?;
    if bytes.len() as u64 > limit {
        return Err(ProcessingError::InputLimit.into());
    }
    Ok(bytes)
}

fn token(cli: &Cli, ctx: &mut OperationContext) -> Result<Zeroizing<String>, OperationError> {
    if cli.token_stdin {
        secrets::read_stdin(ctx)
    } else {
        secrets::read(cli.token_file.as_deref(), false, false, ctx)
    }
}

/// One request's documents and declarations. Secrets are declared (and sent) first.
#[derive(Default)]
pub struct Builder {
    items: Vec<ItemMetadata>,
    parts: Vec<PartMetadata>,
    sources: Vec<(String, Source)>,
}
impl Builder {
    pub fn document(&mut self, item: &str, source: Source) -> String {
        self.part(item, source, PartRole::Document, 'd')
    }
    pub fn secret(&mut self, item: &str, bytes: Zeroizing<Vec<u8>>) -> String {
        self.part(item, Source::Memory(bytes), PartRole::Secret, 's')
    }
    fn part(&mut self, item: &str, source: Source, role: PartRole, prefix: char) -> String {
        let name = format!("{prefix}{}", self.parts.len() + 1);
        self.parts.push(PartMetadata {
            name: name.clone(),
            item_id: item.into(),
            role,
        });
        self.sources.push((name.clone(), source));
        name
    }
    pub fn item(&mut self, id: &str, operation: Operation) {
        self.items.push(ItemMetadata {
            id: id.into(),
            operation,
        });
    }
    /// Public DER evidence files (`--evidence-*`) as documents of `item`.
    pub fn evidence(&mut self, item: &str, cli: &Cli) -> Result<Vec<EvidenceRef>, OperationError> {
        let mut refs = Vec::new();
        for (kind, paths) in [
            (EvidenceKind::Certificate, &cli.evidence_certificate),
            (EvidenceKind::Ocsp, &cli.evidence_ocsp),
            (EvidenceKind::Crl, &cli.evidence_crl),
        ] {
            for path in paths {
                let source = source_of(path.to_str().ok_or(OperationError::InvalidKeySource)?)?;
                refs.push(EvidenceRef {
                    kind,
                    input: self.document(item, source),
                });
            }
        }
        Ok(refs)
    }
    pub fn request(mut self, route: Route) -> Result<Request, ClientError> {
        // Stable: secrets first, every document after them, each group in declaration order.
        self.parts
            .sort_by_key(|part| part.role == PartRole::Document);
        Request::new(
            route,
            &OperationMetadata {
                items: self.items,
                parts: self.parts,
            },
            self.sources,
        )
    }
}

/// A document source as the local commands open it (`-` is stdin), streamed to the server.
pub fn source_of(path: &str) -> Result<Source, OperationError> {
    Ok(source_from_input(Input::open(path)?))
}

pub fn source_from_input(input: Input) -> Source {
    match input {
        Input::File(file, length) => Source::Stream {
            reader: Box::new(file),
            length: Some(length),
        },
        Input::Stdin(stdin) => Source::Stream {
            reader: Box::new(stdin),
            length: None,
        },
        Input::Unreadable(unreadable) => Source::Stream {
            reader: Box::new(unreadable),
            length: None,
        },
    }
}

/// The container bytes of an inline key (at most the service's 4 MiB secret capacity), read
/// into wiped memory. Only used in the explicit `--inline-key` mode.
pub fn container_bytes(path: &str) -> Result<Zeroizing<Vec<u8>>, OperationError> {
    const LIMIT: u64 = 4 * 1024 * 1024;
    let mut bytes = Zeroizing::new(Vec::new());
    let take = |reader: &mut dyn Read, bytes: &mut Vec<u8>| {
        reader
            .take(LIMIT + 1)
            .read_to_end(bytes)
            .map_err(ProcessingError::from)
    };
    if path == "-" {
        take(&mut io::stdin(), &mut bytes)?;
    } else {
        take(
            &mut std::fs::File::open(path).map_err(ProcessingError::from)?,
            &mut bytes,
        )?;
    }
    if bytes.len() as u64 > LIMIT {
        return Err(ProcessingError::InputLimit.into());
    }
    Ok(bytes)
}

/// The key reference of one signing item: the operator's name, or (inline mode) the
/// container and password as secret parts of that item.
pub fn key_reference(
    builder: &mut Builder,
    item: &str,
    key: &PrivateKeyArgs,
    stdin_document: bool,
    ctx: &mut OperationContext,
) -> Result<KeyRef, OperationError> {
    if let Some(name) = &key.key_name {
        return Ok(KeyRef::Named { name: name.clone() });
    }
    let path = key.key.as_ref().ok_or(OperationError::InvalidKeySource)?;
    let _secret_memory = ctx.resources().reserve_memory(16384)?;
    let password = secrets::read(
        key.secret_file.as_deref(),
        key.secret_interactive,
        stdin_document,
        ctx,
    )?;
    let container = container_bytes(path.to_str().ok_or(OperationError::InvalidKeySource)?)?;
    let container = builder.secret(item, container);
    let password = builder.secret(item, Zeroizing::new(password.as_bytes().to_vec()));
    Ok(KeyRef::Inline {
        container,
        password: Some(password),
        alias: key.alias.clone(),
    })
}

/// Stages artifact parts in the client's private output store as they arrive.
struct Stager<'a> {
    ctx: &'a mut OperationContext,
    store: Option<&'a TemporaryStore>,
    maximum: usize,
    staged: Vec<(String, StagedArtifact)>,
    failure: Option<OperationError>,
}
impl ArtifactSink for Stager<'_> {
    fn begin(&mut self, content_id: &str, _length: u64) -> io::Result<()> {
        let Some(store) = self.store.filter(|_| self.staged.len() < self.maximum) else {
            return Err(io::Error::other("unexpected artifact"));
        };
        match store.stage(self.ctx.resources()) {
            Ok(stage) => {
                self.staged.push((content_id.to_owned(), stage));
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error.into());
                Err(io::Error::other("staging failed"))
            }
        }
    }
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let Some((_, stage)) = self.staged.last_mut() else {
            return Err(io::Error::other("no artifact"));
        };
        stage.write_chunk(bytes).map_err(|error| {
            self.failure = Some(error.into());
            io::Error::other("staging failed")
        })
    }
}

/// What one request produced: the terminal record and the staged (unpublished) artifacts.
pub struct Reply {
    pub record: FinalRecord,
    pub artifacts: Vec<(String, StagedArtifact)>,
    /// Document payload bytes this client sent.
    pub document_bytes: u64,
}
/// The staged artifact named by a record's Content-ID, removed from `artifacts`.
pub fn take_artifact(
    artifacts: &mut Vec<(String, StagedArtifact)>,
    content_id: Option<&str>,
) -> Option<StagedArtifact> {
    let id = content_id?;
    let at = artifacts.iter().position(|(known, _)| known == id)?;
    Some(artifacts.swap_remove(at).1)
}
impl Reply {
    pub fn take(&mut self, content_id: Option<&str>) -> Option<StagedArtifact> {
        take_artifact(&mut self.artifacts, content_id)
    }
}

pub struct Session<'a> {
    pub cli: &'a Cli,
    pub control: Arc<Control>,
    pub client: ApiClient,
    pub ctx: OperationContext,
}
impl Session<'_> {
    pub fn call(
        &mut self,
        request: Request,
        maximum_artifacts: usize,
        store: Option<&TemporaryStore>,
    ) -> Result<Reply, Failure> {
        let deadline = Instant::now() + self.control.remaining()?;
        let control = self.control.clone();
        let check = move || {
            control.check().map_err(|error| match error {
                ProcessingError::Cancelled => Stop::Cancelled,
                _ => Stop::DeadlineExceeded,
            })
        };
        let mut stager = Stager {
            ctx: &mut self.ctx,
            store,
            maximum: maximum_artifacts,
            staged: Vec::new(),
            failure: None,
        };
        let outcome = self.client.execute(
            request,
            &mut stager,
            &ExecuteOptions {
                deadline,
                control: Arc::new(check),
            },
        );
        let Stager {
            staged, failure, ..
        } = stager;
        match outcome {
            Ok(Completed {
                record,
                document_bytes,
                ..
            }) => Ok(Reply {
                record,
                artifacts: staged,
                document_bytes,
            }),
            // `staged` is dropped here: nothing the response delivered is published.
            Err(error) => Err(Failure::client(&error, failure)),
        }
    }
}

/// The only result of a single-item request, or the service's failure.
pub fn single(
    record: &FinalRecord,
    may_apply: bool,
) -> Result<(u64, &oncl_api::client::wire::ItemResult), Failure> {
    let unknown = if may_apply {
        AppliedState::Unknown
    } else {
        AppliedState::NotApplied
    };
    match record {
        FinalRecord::Final {
            operation_id,
            status: oncl_api::dto::FinalStatus::Completed,
            results,
            ..
        } if results.len() == 1 && results[0].item_id == "op" => Ok((*operation_id, &results[0])),
        FinalRecord::Final {
            status: oncl_api::dto::FinalStatus::Failed,
            error: Some(error),
            ..
        } => Err(Failure::record(error)),
        _ => Err(Failure::protocol(unknown)),
    }
}

/// Entry point of remote mode. Exits like the local command for the same outcome.
pub fn run(cli: &Cli, control: Arc<Control>) -> Result<i32, Failure> {
    control.check()?;
    let mut ctx = scope(cli, &control)?;
    let endpoint = cli
        .endpoint
        .as_deref()
        .ok_or(OperationError::InvalidKeySource)?;
    let mut anchors = Vec::new();
    for path in &cli.ca_file {
        control.check()?;
        anchors.push(read_file(path, CA_FILE_LIMIT)?);
    }
    let token = token(cli, &mut ctx)?;
    let client = ApiClient::new(
        endpoint,
        token,
        ClientConfig::new()
            .with_trust_anchor_files(anchors)
            .allow_plain_http(cli.allow_plain_http),
    )
    .map_err(|error| Failure::client(&error, None))?;
    if cli.allow_plain_http && !client.endpoint().is_tls() && !client.endpoint().is_loopback() {
        // Printed on every run: the explicit flag must stay a visible decision.
        crate::diagnostic(format_args!(
            "oncl: warning: --allow-plain-http sends the API token and every document over an unencrypted, unauthenticated connection to a non-loopback host"
        ));
    }
    let mut session = Session {
        cli,
        control,
        client,
        ctx,
    };
    ops::run(&mut session)
}

pub fn path_text(path: &Path) -> Result<&str, OperationError> {
    path.to_str().ok_or(OperationError::InvalidKeySource)
}
