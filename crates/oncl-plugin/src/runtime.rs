//! The WebAssembly runtime of plugins: a module is checked against the ABI ([`Engine::compile`])
//! and instantiated per session ([`Compiled::instantiate`]); each request runs within
//! [`PROCESS_FUEL`] and [`MAX_MEMORY`] ([`Instance::process`]). A plugin that fails (traps,
//! runs out of fuel or memory, answers malformed) gets [`PLUGIN_ERROR_REPLY`] sent to the page
//! and its instance is not used again.

use crate::caps::{DialogTurn, SharedState};
use crate::host::{self, AbiState, HostServices, HostState, Phase};
use crate::manifest::{Capabilities, Localized, Manifest};
use oncl_pdk::abi::{self, ABI_VERSION, Capability, IMPORT_MODULE, Import, Output, exports};
use oncl_protocol::{AddInfo, Reply, SessionId};
use serde::Serialize;
use std::borrow::Cow;
use std::sync::Arc;
use wasmi::errors::{MemoryError, TableError};
use wasmi::{
    CompilationMode, Config, EnforcedLimits, ExternType, FuncType, Linker, Memory, Module,
    ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, TrapCode, TypedFunc, ValType,
};
use wasmi_core::LimiterError;

/// The largest linear memory of an instance: 1 GiB on 64-bit targets.
#[cfg(target_pointer_width = "64")]
pub const MAX_MEMORY: usize = 1 << 30;
/// The largest linear memory of an instance: 16 MiB on 32-bit targets, so that
/// [`MAX_INSTANCES`] instances at their largest fit the address space.
#[cfg(not(target_pointer_width = "64"))]
pub const MAX_MEMORY: usize = 16 << 20;

/// The linear memory the live instances of a process take together, as measured when their
/// calls return: over it, the idle instances used longest ago go, and with none idle a call
/// needing a new instance is refused. 2 GiB on 64-bit targets.
#[cfg(target_pointer_width = "64")]
pub const MEMORY_BUDGET: usize = 2 << 30;
/// The linear memory the live instances of a process take together: 256 MiB on 32-bit
/// targets.
#[cfg(not(target_pointer_width = "64"))]
pub const MEMORY_BUDGET: usize = 256 << 20;

/// An instance whose linear memory is over this after a call is dropped rather than kept
/// for its session (the guest's memory never shrinks): 128 MiB on 64-bit targets.
#[cfg(target_pointer_width = "64")]
pub const INSTANCE_HIGH_WATER: usize = 128 << 20;
/// An instance whose linear memory is over this after a call is dropped: 8 MiB on 32-bit
/// targets.
#[cfg(not(target_pointer_width = "64"))]
pub const INSTANCE_HIGH_WATER: usize = 8 << 20;

/// The fuel of one `oncl_process` call, the guest's allocator calls and the host functions'
/// buffers included: about that many WebAssembly instructions.
pub const PROCESS_FUEL: u64 = 20_000_000_000;

/// The most instances alive in the process; the one used longest ago and not busy goes
/// first.
pub const MAX_INSTANCES: usize = 64;

// Every instance at its largest fits a 32-bit address space with room to spare.
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(MAX_INSTANCES * MAX_MEMORY <= 1 << 30);

/// The largest buffer passed between the core and a plugin (a request, a reply, the
/// arguments or result of a host function), as the daemon's largest WebSocket message.
pub const MAX_TRANSFER: usize = 256 << 20;

/// The limits of one instance: its linear memory, the fuel of a call and the largest buffer
/// passed between it and the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceLimits {
    /// The largest linear memory.
    pub max_memory: usize,
    /// The fuel of one `oncl_process` call.
    pub fuel: u64,
    /// The largest request, reply, or argument or result of a host function.
    pub max_transfer: usize,
    /// The most bytes of data the core keeps for one call of a module with the capability
    /// `builtin` (`data_*`); `0` for a plugin's instance, which keeps none.
    pub max_kept: usize,
    /// Whether a module with the capability `builtin` gets the long strings of a request as
    /// markers of data the core keeps (see `DATA_KEPT_MIN`), as it does in the daemon. Off,
    /// only the tests that compare the replies without markers set it: the request reaches
    /// the module as the page sent it, and the `data_*` functions still keep what they make.
    pub keep_request: bool,
}

impl Default for InstanceLimits {
    /// A plugin's: [`MAX_MEMORY`], [`PROCESS_FUEL`] and [`MAX_TRANSFER`].
    fn default() -> Self {
        InstanceLimits {
            max_memory: MAX_MEMORY,
            fuel: PROCESS_FUEL,
            max_transfer: MAX_TRANSFER,
            max_kept: 0,
            keep_request: true,
        }
    }
}

/// The fuel of instantiation: the ABI version call.
const INIT_FUEL: u64 = 1_000_000;

/// The most table elements of an instance (function references of indirect calls).
const MAX_TABLE_ELEMENTS: usize = 1 << 20;

/// What the page gets when a plugin fails.
pub const PLUGIN_ERROR_REPLY: &str = r#"{"success":false,"errorCode":"PLUGIN_ERROR"}"#;

/// Why a plugin module cannot be loaded or instantiated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// Not a valid WebAssembly module, or over the engine's limits.
    #[error("the plugin module is invalid: {0}")]
    Invalid(String),
    /// An export of the ABI is missing.
    #[error("the plugin module does not export {0}")]
    MissingExport(&'static str),
    /// An export of the ABI has another kind or signature.
    #[error("the plugin module's export {0} has the wrong type")]
    WrongExport(&'static str),
    /// An import is not a host function of the ABI.
    #[error("the plugin module imports {0}, which is not a host function")]
    UnknownImport(String),
    /// A host function is imported with another signature.
    #[error("the plugin module imports the host function {0} with the wrong type")]
    WrongImport(String),
    /// A host function of a capability the manifest does not declare is imported.
    #[error("the plugin module imports {0}, whose capability the manifest does not declare")]
    Undeclared(String),
    /// An operation of the manifest may import a host function the module does not import.
    #[error("the operation {operation} lists the import {name}, which the module does not import")]
    OperationImport {
        operation: String,
        name: &'static str,
    },
    /// `oncl_abi_version` returned another version.
    #[error("the plugin is built for ABI version {0}, not {ABI_VERSION}")]
    AbiVersion(i32),
    /// The module could not be instantiated: its memory is over [`MAX_MEMORY`], or the
    /// version call failed.
    #[error("the plugin could not be instantiated: {0}")]
    Instantiate(String),
    /// A module the plugin serves is served already: by a built-in module or another
    /// plugin. `owner` is that plugin's id, or `OpenNCALayer` for a built-in module.
    #[error("the module {module} is served by {owner} already")]
    ModuleTaken { module: String, owner: String },
}

/// Why a request to a plugin failed: the page gets [`PLUGIN_ERROR_REPLY`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginError {
    /// The instance failed before; it is not called again.
    #[error("the plugin instance failed before")]
    Poisoned,
    /// The request ran out of [`PROCESS_FUEL`].
    #[error("the plugin ran out of fuel")]
    OutOfFuel,
    /// The guest's memory would grow over [`MAX_MEMORY`].
    #[error("the plugin's memory would grow over the limit")]
    MemoryLimit,
    /// The guest trapped, or broke the ABI (a buffer out of its memory, a host function
    /// called while not allowed, `oncl_alloc` failing).
    #[error("the plugin trapped: {0}")]
    Trap(String),
    /// A buffer is over [`MAX_TRANSFER`].
    #[error("a buffer of the plugin is over the limit")]
    TooLarge,
    /// The guest's answer is not an [`Output`].
    #[error("the plugin's answer is malformed: {0}")]
    Output(String),
}

/// The WebAssembly engine: one per process; modules compiled with it share its code cache.
#[derive(Clone)]
pub struct Engine {
    engine: wasmi::Engine,
    process_fuel: u64,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// An engine metering fuel, with Wasmi's strict limits on module structure, no start
    /// functions, and functions translated on first use; each request gets
    /// [`PROCESS_FUEL`].
    pub fn new() -> Engine {
        let mut config = Config::default();
        config
            .consume_fuel(true)
            .allow_start_fn(false)
            .enforced_limits(EnforcedLimits::strict())
            .compilation_mode(CompilationMode::LazyTranslation);
        Engine {
            engine: wasmi::Engine::new(&config),
            process_fuel: PROCESS_FUEL,
        }
    }

    /// [`Engine::new`] with every function translated when the module is compiled, not on its
    /// first call. Wasmi charges the translation of a function to the fuel of the call that
    /// first reaches it, and a call that runs out of fuel that way fails and cannot be resumed;
    /// the headless and manual calls of `oncl-core` meter their fuel in slices (see
    /// [`Compiled::call_headless`]) and a real port's entry function costs more to translate
    /// than a slice, so they run modules compiled by this engine. The cost is paid once, at
    /// load, and no call's fuel depends on which function ran first.
    pub fn eager() -> Engine {
        let mut config = Config::default();
        config
            .consume_fuel(true)
            .allow_start_fn(false)
            .enforced_limits(EnforcedLimits::strict())
            .compilation_mode(CompilationMode::Eager);
        Engine {
            engine: wasmi::Engine::new(&config),
            process_fuel: PROCESS_FUEL,
        }
    }

    /// The same engine giving each request `fuel` instead of [`PROCESS_FUEL`].
    #[must_use]
    pub fn with_process_fuel(self, fuel: u64) -> Engine {
        Engine {
            process_fuel: fuel,
            ..self
        }
    }

    /// Compiles `wasm` and checks it against the ABI and `manifest`: the exports with their
    /// exact types, and every import a host function of [`IMPORT_MODULE`] with the ABI's
    /// type, whose capability the manifest declares.
    ///
    /// # Errors
    ///
    /// [`LoadError`] naming the first problem.
    pub fn compile(&self, manifest: &Manifest, wasm: &[u8]) -> Result<Compiled, LoadError> {
        let module =
            Module::new(&self.engine, wasm).map_err(|e| LoadError::Invalid(e.to_string()))?;
        check_exports(&module)?;
        let mut imports = Vec::new();
        for import in module.imports() {
            let full_name = format!("{}.{}", import.module(), import.name());
            let host_fn = (import.module() == IMPORT_MODULE)
                .then(|| Import::from_name(import.name()))
                .flatten()
                .ok_or_else(|| LoadError::UnknownImport(full_name.clone()))?;
            if !matches!(import.ty(), ExternType::Func(ty) if *ty == host_fn_type()) {
                return Err(LoadError::WrongImport(full_name));
            }
            if !declares(&manifest.capabilities, host_fn) {
                return Err(LoadError::Undeclared(full_name));
            }
            if !imports.contains(&host_fn) {
                imports.push(host_fn);
            }
        }
        for operation in manifest.operations() {
            if let Some(import) = operation
                .uses()
                .imports()
                .iter()
                .find(|i| !imports.contains(i))
            {
                return Err(LoadError::OperationImport {
                    operation: operation.name().to_owned(),
                    name: import.name(),
                });
            }
        }
        Ok(Compiled {
            engine: self.engine.clone(),
            module,
            capabilities: Arc::new(manifest.capabilities.clone()),
            imports,
            limits: InstanceLimits {
                fuel: self.process_fuel,
                ..InstanceLimits::default()
            },
        })
    }
}

/// `(i32, i32) -> i64`: every host function.
fn host_fn_type() -> FuncType {
    FuncType::new([ValType::I32, ValType::I32], [ValType::I64])
}

/// Whether `capabilities` allow the host function `import`.
pub(crate) fn declares(capabilities: &Capabilities, import: Import) -> bool {
    match import.capability() {
        None => true,
        Some(Capability::Keys) => capabilities.keys,
        Some(Capability::Dialogs) => capabilities.dialogs,
        Some(Capability::Files) => capabilities.files,
        Some(Capability::Http) => {
            !capabilities.http.is_empty()
                || !capabilities.origins.is_empty()
                || !capabilities.http_insecure.is_empty()
        }
        Some(Capability::PageFiles) => capabilities.page_files,
        Some(Capability::Settings) => capabilities.settings,
        Some(Capability::Shared) => capabilities.shared,
        Some(Capability::Builtin) => capabilities.builtin,
    }
}

/// Whether `import` is one of the `data_*` functions (capability `builtin`). Only a module
/// importing one has the core keep its request's long strings: any other gets its requests
/// as the page sent them.
fn keeps_data(import: &Import) -> bool {
    matches!(
        import,
        Import::DataRead
            | Import::DataDecode
            | Import::DataEncode
            | Import::DataSignCms
            | Import::DataSignXml
            | Import::DataSignRaw
            | Import::DataStamp
            | Import::DataPageRead
    )
}

/// The ABI's exports, with their types.
fn check_exports(module: &Module) -> Result<(), LoadError> {
    let func = |params: &[ValType], results: &[ValType]| {
        FuncType::new(params.iter().copied(), results.iter().copied())
    };
    let i32_ = ValType::I32;
    let functions = [
        (exports::ABI_VERSION, func(&[], &[i32_])),
        (exports::ALLOC, func(&[i32_], &[i32_])),
        (exports::FREE, func(&[i32_, i32_], &[])),
        (exports::PROCESS, func(&[i32_, i32_], &[ValType::I64])),
    ];
    match module.get_export(exports::MEMORY) {
        None => return Err(LoadError::MissingExport(exports::MEMORY)),
        Some(ExternType::Memory(_)) => {}
        Some(_) => return Err(LoadError::WrongExport(exports::MEMORY)),
    }
    for (name, ty) in functions {
        match module.get_export(name) {
            None => return Err(LoadError::MissingExport(name)),
            Some(ExternType::Func(actual)) if actual == ty => {}
            Some(_) => return Err(LoadError::WrongExport(name)),
        }
    }
    Ok(())
}

/// A checked plugin module, ready to be instantiated.
#[derive(Clone)]
pub struct Compiled {
    engine: wasmi::Engine,
    module: Module,
    capabilities: Arc<Capabilities>,
    imports: Vec<Import>,
    limits: InstanceLimits,
}

/// How far the core trusts the code of an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// A plugin the user installed: its windows name it, a page file is read once the user
    /// allows it.
    Installed,
    /// A module built into the core: its windows are the core's own, it reads the page files
    /// the page names as the core's modules always did, and it may use the `builtin`
    /// functions.
    Builtin,
}

/// Whose an instance is: its session and its plugin.
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// The session the instance serves; `0`: one call without a session.
    pub session: SessionId,
    /// The plugin's id, in the log and the name of its settings file.
    pub plugin_id: String,
    /// The plugin's name, in the dialogs.
    pub plugin_name: Localized,
    /// The values the instances of the plugin's loaded generation share (`shared_*`).
    pub shared: Arc<SharedState>,
    /// How far the core trusts the plugin.
    pub trust: Trust,
}

impl Compiled {
    /// The host functions the module imports, in the order of its import section.
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// The same module, its instances limited by `limits` instead of a plugin's.
    #[must_use]
    pub fn with_limits(self, limits: InstanceLimits) -> Compiled {
        Compiled { limits, ..self }
    }

    /// A new instance for `ctx`, its host functions served by `services`: the memory and
    /// tables limited, `oncl_abi_version` checked.
    ///
    /// # Errors
    ///
    /// [`LoadError::Instantiate`] if the module's memory is over its limit or the version
    /// call fails; [`LoadError::AbiVersion`] for another version.
    pub fn instantiate(
        &self,
        services: &HostServices,
        ctx: SessionContext,
    ) -> Result<Instance, LoadError> {
        let limits = self.store_limits();
        let state = HostState::new(
            limits,
            services.clone(),
            ctx,
            Arc::clone(&self.capabilities),
            self.limits.max_transfer,
            if self.imports.iter().any(keeps_data) {
                self.limits.max_kept
            } else {
                0
            },
        );
        Ok(Instance {
            guest: Guest::new(self, state)?,
            poisoned: false,
        })
    }
}

/// A plugin instance: the guest's state between the requests of its session.
pub struct Instance {
    guest: Guest<HostState>,
    poisoned: bool,
}

/// The single ABI implementation, including instantiation, memory, fuel, phase
/// checks and output decoding. A scoped headless Store may borrow its backend.
pub(crate) struct Guest<T> {
    pub(crate) store: Store<T>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    free: TypedFunc<(i32, i32), ()>,
    process: TypedFunc<(i32, i32), i64>,
    pub(crate) limits: InstanceLimits,
}

/// The limits of an instance's memory and tables: wasmi's [`StoreLimits`] with a trap when a
/// growth is denied ([`PluginError::MemoryLimit`]), except that a `memory.grow` or
/// `table.grow` that ran out of fuel is not a failed growth. `StoreLimits` reports every
/// failed growth to its `*_grow_failed` hook, and with `trap_on_grow_failure` that hook
/// traps even for `OutOfFuel`, which the host resumes after refuelling (the fuel is handed
/// out in slices, `host::call_guest`): without this a call whose `memory.grow` fell on the
/// end of a slice failed with `MemoryLimit` whatever the memory limit was, depending on the
/// size of the document and nothing else.
pub(crate) struct GuestLimits(StoreLimits);

impl GuestLimits {
    pub(crate) fn new(limits: StoreLimits) -> Self {
        Self(limits)
    }
}

impl ResourceLimiter for GuestLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        self.0.memory_growing(current, desired, maximum)
    }
    fn memory_grow_failed(&mut self, error: &MemoryError) -> Result<(), LimiterError> {
        match error {
            MemoryError::OutOfFuel { .. } => Ok(()),
            other => self.0.memory_grow_failed(other),
        }
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        self.0.table_growing(current, desired, maximum)
    }
    fn table_grow_failed(&mut self, error: &TableError) -> Result<(), LimiterError> {
        match error {
            TableError::OutOfFuel { .. } => Ok(()),
            other => self.0.table_grow_failed(other),
        }
    }
    fn instances(&self) -> usize {
        self.0.instances()
    }
    fn tables(&self) -> usize {
        self.0.tables()
    }
    fn memories(&self) -> usize {
        self.0.memories()
    }
}

impl Compiled {
    pub(crate) fn store_limits(&self) -> GuestLimits {
        GuestLimits::new(
            StoreLimitsBuilder::new()
                .memory_size(self.limits.max_memory)
                .table_elements(MAX_TABLE_ELEMENTS)
                .instances(1)
                .memories(1)
                .tables(1)
                .trap_on_grow_failure(true)
                .build(),
        )
    }
    pub fn limits(&self) -> InstanceLimits {
        self.limits
    }
}

impl<T: AbiState> Guest<T> {
    pub(crate) fn new(compiled: &Compiled, state: T) -> Result<Self, LoadError> {
        let mut store = Store::new(&compiled.engine, state);
        store.limiter(|state| state.limits());
        let failed = |e: wasmi::Error| LoadError::Instantiate(e.to_string());
        store.set_fuel(INIT_FUEL).map_err(failed)?;
        let mut linker = Linker::<T>::new(&compiled.engine);
        for import in Import::ALL {
            if declares(&compiled.capabilities, import) {
                host::define(&mut linker, import).map_err(failed)?;
            }
        }
        let instance = linker
            .instantiate_and_start(&mut store, &compiled.module)
            .map_err(failed)?;
        let typed = |name: &'static str| {
            instance
                .get_func(&store, name)
                .ok_or(LoadError::MissingExport(name))
        };
        let version = typed(exports::ABI_VERSION)?
            .typed::<(), i32>(&store)
            .map_err(failed)?;
        let alloc = typed(exports::ALLOC)?
            .typed::<i32, i32>(&store)
            .map_err(failed)?;
        let free = typed(exports::FREE)?
            .typed::<(i32, i32), ()>(&store)
            .map_err(failed)?;
        let process = typed(exports::PROCESS)?
            .typed::<(i32, i32), i64>(&store)
            .map_err(failed)?;
        let memory = instance
            .get_memory(&store, exports::MEMORY)
            .ok_or(LoadError::MissingExport(exports::MEMORY))?;
        store.data_mut().attach(memory, alloc);
        let found = host::call_guest(version, &mut store, ()).map_err(failed)?;
        if u32::try_from(found) != Ok(ABI_VERSION) {
            return Err(LoadError::AbiVersion(found));
        }
        Ok(Self {
            store,
            memory,
            alloc,
            free,
            process,
            limits: compiled.limits,
        })
    }

    pub(crate) fn invoke(&mut self, input: &[u8]) -> Result<Output, PluginError> {
        let len = transfer_len(input.len(), self.limits.max_transfer)?;
        self.store
            .set_fuel(self.limits.fuel)
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        self.store.data_mut().set_phase(Phase::Host);
        let ptr = host::call_guest(self.alloc, &mut self.store, len).map_err(failure)?;
        host::write_guest(self.memory.data_mut(&mut self.store), ptr, input).map_err(failure)?;
        self.store.data_mut().set_phase(Phase::Guest);
        let packed =
            host::call_guest(self.process, &mut self.store, (ptr, len)).map_err(failure)?;
        self.store.data_mut().set_phase(Phase::Host);
        let (out_ptr, out_len) = abi::unpack(packed);
        if out_len as usize > self.limits.max_transfer {
            return Err(PluginError::TooLarge);
        }
        let output = host::read_guest(self.memory.data(&self.store), out_ptr, out_len)
            .map_err(failure)?
            .to_vec();
        host::call_guest(self.free, &mut self.store, (out_ptr as i32, out_len as i32))
            .map_err(failure)?;
        self.store.data_mut().set_phase(Phase::Idle);
        abi::decode(&output).map_err(|e| PluginError::Output(e.message))
    }
}

/// Instances move to the threads that run their requests.
const _: fn() = || {
    fn send<T: Send>() {}
    send::<Instance>();
};

impl Instance {
    /// The size of the guest's linear memory now, in bytes.
    pub fn memory_size(&self) -> usize {
        self.guest.memory.data(&self.guest.store).len()
    }

    /// Has the guest answer `request`: its reply, or [`Reply::Drop`] if it called
    /// `reply_drop` during this call. The dialog-flow turn, once a host function takes it,
    /// is held until this returns. After a failure the instance is spent: every later call
    /// is [`PluginError::Poisoned`] without running the guest, and its keys are let go.
    ///
    /// # Errors
    ///
    /// [`PluginError`]: the page gets [`PLUGIN_ERROR_REPLY`].
    pub fn process(&mut self, request: &str, add_info: &AddInfo) -> Result<Reply, PluginError> {
        if self.poisoned {
            return Err(PluginError::Poisoned);
        }
        let turn = DialogTurn::scope();
        let locale = (self.guest.store.data().services.locale)();
        self.guest
            .store
            .data_mut()
            .begin_call(add_info.origin.clone(), locale);
        let result = self.run(request, add_info, locale);
        let dropped = self.guest.store.data().call.drop;
        self.guest.store.data_mut().end_call();
        drop(turn);
        if let Err(e) = &result {
            tracing::warn!(
                plugin = %self.guest.store.data().session.plugin_id,
                session = self.guest.store.data().session.session,
                error = %e,
                "the plugin failed; its instance is dropped"
            );
            self.poisoned = true;
            self.guest.store.data_mut().release_all();
        }
        result.map(|text| if dropped { Reply::Drop } else { text.into() })
    }

    /// Whether a call failed: the instance only answers [`PluginError::Poisoned`] now.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Lets go of the keys, passwords and consents of the calls so far: what a pooled
    /// instance must not carry to its next call.
    pub(crate) fn release_all(&mut self) {
        self.guest.store.data_mut().release_all();
    }

    /// The fuel the last call used.
    pub(crate) fn fuel_used(&self) -> u64 {
        self.guest
            .limits
            .fuel
            .saturating_sub(self.guest.store.get_fuel().unwrap_or(0))
    }

    fn run(
        &mut self,
        request: &str,
        add_info: &AddInfo,
        locale: oncl_flows::Locale,
    ) -> Result<String, PluginError> {
        let max = self.guest.limits.max_transfer;
        let keep = self.guest.limits.keep_request;
        let (request, data_prefix) = match self.guest.store.data_mut().call.data.as_mut() {
            Some(data) => (
                if keep {
                    data.keep_request(request, max)
                        .map_err(|e| PluginError::Output(e.message))?
                } else {
                    Cow::Borrowed(request)
                },
                Some(data.prefix().to_owned()),
            ),
            None => (Cow::Borrowed(request), None),
        };
        // The input is longer than its request: one that is over the limit is refused
        // before it is encoded.
        if request.len() > max {
            return Err(PluginError::TooLarge);
        }
        let input = encode_input(
            &request,
            add_info.origin.as_deref(),
            locale_code(locale),
            data_prefix.as_deref(),
        );
        drop(request);
        let output = self.guest.invoke(&input)?;
        match &self.guest.store.data().call.data {
            Some(data) => data
                .splice(output.response, crate::BUILTIN_MAX_REPLY)
                .map_err(PluginError::Output),
            None => Ok(output.response),
        }
    }
}

/// `len` as the `i32` of the ABI, if within `max`.
fn transfer_len(len: usize, max: usize) -> Result<i32, PluginError> {
    if len > max {
        return Err(PluginError::TooLarge);
    }
    i32::try_from(len).map_err(|_| PluginError::TooLarge)
}

/// The [`PluginError`] of a failed call into the guest.
fn failure(e: wasmi::Error) -> PluginError {
    match e.as_trap_code() {
        Some(TrapCode::OutOfFuel) => PluginError::OutOfFuel,
        Some(TrapCode::GrowthOperationLimited) => PluginError::MemoryLimit,
        _ => PluginError::Trap(e.to_string()),
    }
}

/// The ABI's code of `locale`.
fn locale_code(locale: oncl_flows::Locale) -> &'static str {
    match locale {
        oncl_flows::Locale::Ru => "ru",
        oncl_flows::Locale::Kk => "kk",
        oncl_flows::Locale::En => "en",
    }
}

/// [`abi::Input`] by reference, encoded to the same bytes: the request is not copied to be
/// encoded.
#[derive(Serialize)]
struct InputRef<'a> {
    request: &'a str,
    origin: Option<&'a str>,
    locale: &'a str,
    data_prefix: Option<&'a str>,
}

pub(crate) fn encode_input(
    request: &str,
    origin: Option<&str>,
    locale: &str,
    data_prefix: Option<&str>,
) -> Vec<u8> {
    abi::encode(&InputRef {
        request,
        origin,
        locale,
        data_prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_by_reference_encodes_as_input() {
        for (origin, data_prefix) in [(None, None), (Some("https://x.kz"), Some("oncl-data:ab:"))] {
            let by_reference = abi::encode(&InputRef {
                request: r#"{"a":"б"}"#,
                origin,
                locale: "kk",
                data_prefix,
            });
            let owned = abi::encode(&abi::Input {
                request: r#"{"a":"б"}"#.to_owned(),
                origin: origin.map(str::to_owned),
                locale: "kk".to_owned(),
                data_prefix: data_prefix.map(str::to_owned),
            });
            assert_eq!(by_reference, owned);
        }
    }
}
