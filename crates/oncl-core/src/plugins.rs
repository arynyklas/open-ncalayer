//! Real invocation-scoped WASM backed by the original Engine and OperationContext.
//! Installation is code availability, not caller, operation, import or key authority.
use crate::{
    Engine, OperationContext, OperationError,
    keys::{KeyId, KeyRequest},
};
use oncl_pdk::abi::{self, Import};
use oncl_pki::http::{HttpTransport, deadline::NetworkPolicy};
use oncl_pki::io::{FrozenInput, StagedArtifact};
use oncl_pki::key::AppliedState;
use oncl_pki::{
    io::Source,
    resource::{OperationLease, ProcessingError, ResourceReservation},
};
pub use oncl_plugin::headless::CallerContext;
use oncl_plugin::headless::{CapabilityBackend, HeadlessBindings, HeadlessError};
use oncl_plugin::{Compiled, InstanceLimits, Manifest};
use std::cell::RefCell;
use std::{collections::BTreeMap, io::Cursor, sync::Arc};
mod capabilities;
mod cms;

/// Host-issued exact invocation permission. No Deserialize and no wildcard methods/keys.
#[derive(Clone, Debug)]
pub struct PluginPermission {
    plugin_id: String,
    operation: String,
    caller: CallerContext,
    imports: Vec<Import>,
    keys: Vec<KeyId>,
    files: Vec<String>,
    endpoints: Vec<String>,
    pki_endpoints: Vec<String>,
}
impl PluginPermission {
    pub fn new(
        plugin_id: impl Into<String>,
        operation: impl Into<String>,
        caller: CallerContext,
        imports: impl IntoIterator<Item = Import>,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            operation: operation.into(),
            caller,
            imports: imports.into_iter().collect(),
            keys: Vec::new(),
            files: Vec::new(),
            endpoints: Vec::new(),
            pki_endpoints: Vec::new(),
        }
    }
    pub fn with_keys(mut self, keys: impl IntoIterator<Item = KeyId>) -> Self {
        self.keys = keys.into_iter().collect();
        self
    }
    pub fn with_files(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.files = names.into_iter().map(Into::into).collect();
        self
    }
    pub fn with_http_endpoints(
        mut self,
        endpoints: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, OperationError> {
        self.endpoints = checked_endpoints(endpoints)?;
        Ok(self)
    }
    pub fn with_pki_endpoints(
        mut self,
        endpoints: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, OperationError> {
        self.pki_endpoints = checked_endpoints(endpoints)?;
        Ok(self)
    }
    fn matches(&self, call: &PluginCall<'_>, caller: &CallerContext) -> bool {
        self.plugin_id == call.plugin_id
            && self.operation == call.operation
            && self.caller == *caller
    }
    fn permits(&self, import: Import, key: Option<&KeyId>) -> bool {
        self.imports.contains(&import) && key.is_none_or(|key| self.keys.contains(key))
    }
}

fn checked_endpoints(
    endpoints: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<String>, OperationError> {
    endpoints
        .into_iter()
        .map(|endpoint| {
            let mut url = oncl_plugin::Url::parse(endpoint.as_ref())
                .map_err(|_| ProcessingError::InvalidInput("invalid plugin HTTP endpoint"))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(ProcessingError::InvalidInput("invalid plugin HTTP endpoint").into());
            }
            url.set_fragment(None);
            Ok(url.to_string())
        })
        .collect()
}
struct Installed {
    compiled: Compiled,
    policy: Vec<PluginPermission>,
    capabilities: oncl_plugin::Capabilities,
    shared: Arc<oncl_plugin::SharedState>,
}
/// Trusted installed code plus explicit host policy. Never discovers, downloads or updates code.
#[derive(Default)]
pub struct PluginRegistry {
    installed: BTreeMap<String, Installed>,
}
impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("installed", &self.installed.len())
            .finish()
    }
}
impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn install(
        &mut self,
        manifest: Manifest,
        wasm: &[u8],
        limits: InstanceLimits,
        policy: Vec<PluginPermission>,
    ) -> Result<(), OperationError> {
        if self.installed.contains_key(&manifest.id)
            || policy.iter().any(|p| p.plugin_id != manifest.id)
            || limits.max_memory == 0
            || limits.fuel == 0
            || limits.max_transfer == 0
            || limits.max_memory > oncl_plugin::MAX_MEMORY
            || limits.max_transfer > oncl_plugin::MAX_TRANSFER
            || limits.max_kept != 0
        {
            return Err(
                ProcessingError::InvalidInput("invalid plugin installation or limits").into(),
            );
        }
        let compiled = oncl_plugin::Engine::new()
            .compile(&manifest, wasm)
            .map_err(|e| OperationError::Plugin(e.into()))?
            .with_limits(limits);
        self.installed.insert(
            manifest.id,
            Installed {
                compiled,
                policy,
                capabilities: manifest.capabilities,
                shared: Arc::default(),
            },
        );
        Ok(())
    }
}
/// Untrusted operation data. Authority comes from the separately supplied trusted bindings/grant.
pub struct PluginCall<'a> {
    pub plugin_id: &'a str,
    pub operation: &'a str,
    pub args: &'a str,
}
/// Opaque invocation-local handle to an explicitly trusted key source. No key/PIN reaches WASM.
pub struct PluginKeyBinding<'a> {
    pub handle: u32,
    pub key: KeyRequest<'a>,
    metadata: Option<PluginKeyMetadata<'a>>,
}
struct PluginKeyMetadata<'a> {
    alias: &'a str,
    certificate: &'a oncl_pki::cert::Certificate,
    chain: &'a [oncl_pki::cert::Certificate],
}
impl<'a> PluginKeyBinding<'a> {
    pub fn new(handle: u32, key: KeyRequest<'a>) -> Self {
        Self {
            handle,
            key,
            metadata: None,
        }
    }
    pub fn with_public_metadata(
        mut self,
        alias: &'a str,
        certificate: &'a oncl_pki::cert::Certificate,
        chain: &'a [oncl_pki::cert::Certificate],
    ) -> Self {
        self.metadata = Some(PluginKeyMetadata {
            alias,
            certificate,
            chain,
        });
        self
    }
}
/// Explicit borrowed resources; omitted bindings never consult ambient files,
/// the browser, a password cache, network configuration or GUI services.
pub struct PluginBindings<'a> {
    caller: &'a CallerContext,
    keys: &'a [PluginKeyBinding<'a>],
    inputs: &'a [PluginInputBinding<'a>],
    outputs: &'a [PluginOutputBinding<'a>],
    network: Option<(&'a dyn HttpTransport, &'a NetworkPolicy)>,
    settings: Option<&'a oncl_plugin::headless::BoundSettings>,
}
impl<'a> PluginBindings<'a> {
    pub fn new(caller: &'a CallerContext, keys: &'a [PluginKeyBinding<'a>]) -> Self {
        Self {
            caller,
            keys,
            inputs: &[],
            outputs: &[],
            network: None,
            settings: None,
        }
    }
    pub fn with_files(
        mut self,
        inputs: &'a [PluginInputBinding<'a>],
        outputs: &'a [PluginOutputBinding<'a>],
    ) -> Self {
        self.inputs = inputs;
        self.outputs = outputs;
        self
    }
    pub fn with_network(
        mut self,
        transport: &'a dyn HttpTransport,
        policy: &'a NetworkPolicy,
    ) -> Self {
        self.network = Some((transport, policy));
        self
    }
    pub fn with_settings(mut self, settings: &'a oncl_plugin::headless::BoundSettings) -> Self {
        self.settings = Some(settings);
        self
    }
}
pub struct PluginInputBinding<'a> {
    name: &'a str,
    input: RefCell<&'a mut FrozenInput>,
}
impl<'a> PluginInputBinding<'a> {
    pub fn new(name: &'a str, input: &'a mut FrozenInput) -> Self {
        Self {
            name,
            input: RefCell::new(input),
        }
    }
}
pub struct PluginOutputBinding<'a> {
    pub directory: &'a str,
    pub name: &'a str,
}
pub struct PluginResult {
    response: String,
    applied: AppliedState,
    outputs: Vec<(String, StagedArtifact)>,
    _memory: ResourceReservation,
    _root: OperationLease,
}
impl std::fmt::Debug for PluginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginResult")
            .field("response_bytes", &self.response.len())
            .finish_non_exhaustive()
    }
}
impl PluginResult {
    pub fn response(&self) -> &str {
        &self.response
    }
    pub fn applied_state(&self) -> AppliedState {
        self.applied
    }
    pub fn take_output(&mut self, name: &str) -> Option<StagedArtifact> {
        self.outputs
            .iter()
            .position(|(key, _)| key == name)
            .map(|i| self.outputs.remove(i).1)
    }
}

struct Backend<'a, 'b> {
    engine: &'a Engine,
    ctx: &'a mut OperationContext,
    call: PluginCall<'a>,
    bindings: &'a PluginBindings<'b>,
    host: &'a [PluginPermission],
    failure: Option<OperationError>,
    applied: AppliedState,
    capabilities: &'a oncl_plugin::Capabilities,
    shared: &'a oncl_plugin::SharedState,
    outputs: Vec<(String, StagedArtifact)>,
    released: Vec<u32>,
    transfer: usize,
}
impl Backend<'_, '_> {
    fn authorize(&self, import: Import, key: Option<&KeyId>) -> Result<(), OperationError> {
        let allowed = |permissions: &[PluginPermission]| {
            permissions
                .iter()
                .any(|p| p.matches(&self.call, self.bindings.caller) && p.permits(import, key))
        };
        if !allowed(&self.ctx.grant.plugins)
            || !allowed(self.host)
            || key.is_some_and(|key| !self.ctx.grant.allows_key(key))
        {
            return Err(OperationError::PermissionDenied);
        }
        Ok(())
    }
    fn execute(&mut self, import: Import, args: &[u8]) -> Result<Vec<u8>, OperationError> {
        self.authorize(import, None)?;
        match import {
            Import::Hash => {
                let args: abi::HashArgs = decode(args)?;
                let algorithm = match args.alg {
                    abi::HashAlg::Sha256 => oncl_pki::key::HashAlg::Sha256,
                    abi::HashAlg::Sha1 => oncl_pki::key::HashAlg::Sha1,
                    abi::HashAlg::Gost34311 => oncl_pki::key::HashAlg::Gost34311,
                    abi::HashAlg::Sha512 => oncl_pki::key::HashAlg::Sha512,
                    abi::HashAlg::Streebog256 => oncl_pki::key::HashAlg::Streebog256,
                    abi::HashAlg::Streebog512 => oncl_pki::key::HashAlg::Streebog512,
                };
                let report = self.engine.hash(
                    algorithm,
                    Source::sequential(
                        &mut Cursor::new(args.data.as_ref()),
                        Some(args.data.len() as u64),
                    ),
                    self.ctx,
                )?;
                Ok(abi::encode(&Ok::<_, abi::HostError>(abi::Bytes::from(
                    report.digest.as_bytes().to_vec(),
                ))))
            }
            Import::KeysSignRaw => {
                let args: abi::SignRawArgs = decode(args)?;
                if self.released.contains(&args.handle) {
                    return Err(OperationError::PermissionDenied);
                }
                let key = self
                    .bindings
                    .keys
                    .iter()
                    .find(|key| key.handle == args.handle)
                    .ok_or(OperationError::PermissionDenied)?;
                let id = key.key.selector().key_id();
                self.authorize(import, Some(&id))?;
                let request = KeyRequest::new(key.key.selector(), key.key.secret());
                let mut output = Vec::new();
                // Source-bound Sign, not signer()/SignDigest and not a new context or policy.
                let signed = self.engine.sign(
                    crate::SignRequest::raw_message(request),
                    Source::sequential(
                        &mut Cursor::new(args.data.as_ref()),
                        Some(args.data.len() as u64),
                    ),
                    &mut output,
                    self.ctx,
                );
                let applied = match &signed {
                    Ok(report) => report.applied,
                    Err(error) => error.applied_state(),
                };
                self.applied = match (self.applied, applied) {
                    (AppliedState::Unknown, _) | (_, AppliedState::Unknown) => {
                        AppliedState::Unknown
                    }
                    (AppliedState::Applied, _) | (_, AppliedState::Applied) => {
                        AppliedState::Applied
                    }
                    _ => AppliedState::NotApplied,
                };
                signed?;
                Ok(abi::encode(&Ok::<_, abi::HostError>(abi::Bytes::from(
                    output,
                ))))
            }
            _ => self.capability(import, args),
        }
    }
    fn failed<T>(&mut self, result: Result<T, OperationError>) -> Result<T, HeadlessError> {
        result.map_err(|error| {
            self.failure = Some(self.ctx.network_status().err().unwrap_or(error));
            HeadlessError::Backend
        })
    }
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, OperationError> {
    abi::decode(bytes)
        .map_err(|_| ProcessingError::InvalidInput("malformed plugin capability argument").into())
}
impl CapabilityBackend for Backend<'_, '_> {
    fn checkpoint(&mut self) -> Result<(), HeadlessError> {
        let result = self
            .ctx
            .scope
            .checkpoint()
            .map_err(OperationError::from)
            .and_then(|()| self.ctx.network_status());
        self.failed(result)
    }
    fn invoke(&mut self, import: Import, args: &[u8]) -> Result<Vec<u8>, HeadlessError> {
        let result = (|| {
            let workspace = (args.len() as u64)
                .checked_mul(128)
                .and_then(|n| n.checked_add(65536))
                .ok_or(ProcessingError::MemoryLimit)?;
            let _memory = self.ctx.scope.reserve_memory(workspace)?;
            let _metadata = self.ctx.scope.reserve_metadata(workspace)?;
            self.ctx.scope.account_container(args.len() as u64)?;
            self.execute(import, args)
        })();
        self.failed(result)
    }
}
fn after_use(error: OperationError, applied: AppliedState) -> OperationError {
    if applied == AppliedState::NotApplied || error.applied_state() == applied {
        error
    } else {
        OperationError::AfterKeyUse {
            source: Box::new(error),
            applied,
        }
    }
}
impl Engine {
    pub fn plugin_call(
        &self,
        call: &PluginCall<'_>,
        bindings: &PluginBindings<'_>,
        ctx: &mut OperationContext,
    ) -> Result<PluginResult, OperationError> {
        if !Arc::ptr_eq(&ctx.owner, &self.identity) {
            return Err(OperationError::InvalidContext);
        }
        ctx.scope.checkpoint()?;
        let matches = |p: &&PluginPermission| p.matches(call, bindings.caller);
        if !ctx
            .grant
            .plugins
            .iter()
            .any(|p| p.matches(call, bindings.caller))
        {
            return Err(OperationError::PermissionDenied);
        }
        let installed = self
            .plugins
            .as_ref()
            .and_then(|r| r.installed.get(call.plugin_id))
            .ok_or(OperationError::PermissionDenied)?;
        if !installed
            .policy
            .iter()
            .any(|p| p.matches(call, bindings.caller))
        {
            return Err(OperationError::PermissionDenied);
        }
        if bindings
            .keys
            .iter()
            .enumerate()
            .any(|(i, k)| k.handle == 0 || bindings.keys[..i].iter().any(|p| p.handle == k.handle))
        {
            return Err(
                ProcessingError::InvalidInput("duplicate or zero plugin key handle").into(),
            );
        }
        let invocation = InvocationScope::new(ctx);
        let ctx = &mut *invocation.ctx;
        let limits = installed.compiled.limits();
        if call.args.len() > limits.max_transfer {
            return Err(OperationError::Plugin(
                oncl_plugin::PluginError::TooLarge.into(),
            ));
        }
        let scratch = (limits.max_transfer as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add(limits.max_memory as u64))
            .ok_or(ProcessingError::MemoryLimit)?;
        let _workspace = ctx.scope.reserve_memory(scratch)?;
        ctx.scope.account_container(call.args.len() as u64)?;
        let _metadata = ctx.scope.reserve_metadata(limits.max_transfer as u64)?;
        let imports: Vec<_> = installed
            .compiled
            .imports()
            .iter()
            .copied()
            .filter(|import| {
                ctx.grant
                    .plugins
                    .iter()
                    .filter(matches)
                    .any(|p| p.permits(*import, None))
                    && installed
                        .policy
                        .iter()
                        .filter(matches)
                        .any(|p| p.permits(*import, None))
            })
            .collect();
        let mut backend = Backend {
            engine: self,
            ctx,
            call: PluginCall {
                plugin_id: call.plugin_id,
                operation: call.operation,
                args: call.args,
            },
            bindings,
            host: &installed.policy,
            failure: None,
            applied: AppliedState::NotApplied,
            capabilities: &installed.capabilities,
            outputs: Vec::new(),
            released: Vec::new(),
            transfer: limits.max_transfer,
            shared: &installed.shared,
        };
        let result = installed.compiled.call_headless(
            &mut backend,
            HeadlessBindings {
                caller: bindings.caller,
                imports: &imports,
            },
            call.args,
        );
        let applied = backend.applied;
        if let Some(error) = backend.failure {
            return Err(after_use(error, applied));
        }
        let response = result.map_err(|error| after_use(OperationError::Plugin(error), applied))?;
        backend
            .ctx
            .scope
            .account_output(response.len() as u64)
            .map_err(|error| after_use(error.into(), applied))?;
        let memory = backend
            .ctx
            .scope
            .reserve_memory(response.len() as u64)
            .map_err(|error| after_use(error.into(), applied))?;
        let root = backend.ctx.lease();
        Ok(PluginResult {
            response,
            applied,
            outputs: backend.outputs,
            _memory: memory,
            _root: root,
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct InvocationHttpBudget {
    requests: oncl_plugin::headless::RequestBudget,
    exhausted: Arc<std::sync::atomic::AtomicBool>,
}
impl std::fmt::Debug for InvocationHttpBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InvocationHttpBudget")
    }
}
impl InvocationHttpBudget {
    pub(crate) fn take(&self) -> Result<(), OperationError> {
        self.requests.take().map_err(|_| {
            self.exhausted
                .store(true, std::sync::atomic::Ordering::Release);
            OperationError::from(ProcessingError::CapacityExceeded)
        })
    }
    pub(crate) fn status(&self) -> Result<(), OperationError> {
        if self.exhausted.load(std::sync::atomic::Ordering::Acquire) {
            Err(ProcessingError::CapacityExceeded.into())
        } else {
            Ok(())
        }
    }
}
struct InvocationScope<'a> {
    ctx: &'a mut OperationContext,
    previous: Option<InvocationHttpBudget>,
}
impl<'a> InvocationScope<'a> {
    fn new(ctx: &'a mut OperationContext) -> Self {
        let previous = ctx.plugin_network.take();
        let budget = ctx
            .plugin_network_budget
            .get_or_insert_with(|| previous.clone().unwrap_or_default());
        ctx.plugin_network = Some(previous.clone().unwrap_or_else(|| budget.clone()));
        Self { ctx, previous }
    }
}
impl Drop for InvocationScope<'_> {
    fn drop(&mut self) {
        self.ctx.plugin_network = self.previous.take();
    }
}
