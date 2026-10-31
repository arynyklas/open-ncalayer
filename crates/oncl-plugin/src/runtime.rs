//! The WebAssembly runtime of plugins: a module is checked against the ABI ([`Engine::compile`])
//! and instantiated per session ([`Compiled::instantiate`]); each request runs within
//! [`PROCESS_FUEL`] and [`MAX_MEMORY`] ([`Instance::process`]). A plugin that fails (traps,
//! runs out of fuel or memory, answers malformed) gets [`PLUGIN_ERROR_REPLY`] sent to the page
//! and its instance is not used again.

use crate::caps::{DialogTurn, SharedState};
use crate::host::{self, HostServices, HostState, Phase};
use crate::manifest::{Capabilities, Localized, Manifest};
use oncl_pdk::abi::{self, ABI_VERSION, Capability, IMPORT_MODULE, Import, Input, Output, exports};
use oncl_protocol::{AddInfo, Reply, SessionId};
use std::sync::Arc;
use wasmi::{
    CompilationMode, Config, EnforcedLimits, ExternType, FuncType, Linker, Memory, Module, Store,
    StoreLimitsBuilder, TrapCode, TypedFunc, ValType,
};

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
}

impl Default for InstanceLimits {
    /// A plugin's: [`MAX_MEMORY`], [`PROCESS_FUEL`] and [`MAX_TRANSFER`].
    fn default() -> Self {
        InstanceLimits {
            max_memory: MAX_MEMORY,
            fuel: PROCESS_FUEL,
            max_transfer: MAX_TRANSFER,
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
    /// `oncl_abi_version` returned another version.
    #[error("the plugin is built for ABI version {0}, not {ABI_VERSION}")]
    AbiVersion(i32),
    /// The module could not be instantiated: its memory is over [`MAX_MEMORY`], or the
    /// version call failed.
    #[error("the plugin could not be instantiated: {0}")]
    Instantiate(String),
    /// A module the plugin serves is served already: by a built-in module or another
    /// plugin. `owner` is that plugin's id, or [`BUILT_IN`](crate::BUILT_IN).
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
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.max_memory)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(1)
            .memories(1)
            .tables(1)
            .trap_on_grow_failure(true)
            .build();
        let state = HostState::new(
            limits,
            services.clone(),
            ctx,
            Arc::clone(&self.capabilities),
            self.limits.max_transfer,
        );
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        let failed = |e: wasmi::Error| LoadError::Instantiate(e.to_string());
        store.set_fuel(INIT_FUEL).map_err(failed)?;

        let mut linker = <Linker<HostState>>::new(&self.engine);
        for import in Import::ALL {
            if declares(&self.capabilities, import) {
                host::define(&mut linker, import).map_err(failed)?;
            }
        }
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
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

        let found = version.call(&mut store, ()).map_err(failed)?;
        if u32::try_from(found) != Ok(ABI_VERSION) {
            return Err(LoadError::AbiVersion(found));
        }
        Ok(Instance {
            store,
            memory,
            alloc,
            free,
            process,
            limits: self.limits,
            poisoned: false,
        })
    }
}

/// A plugin instance: the guest's state between the requests of its session.
pub struct Instance {
    store: Store<HostState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    free: TypedFunc<(i32, i32), ()>,
    process: TypedFunc<(i32, i32), i64>,
    limits: InstanceLimits,
    poisoned: bool,
}

/// Instances move to the threads that run their requests.
const _: fn() = || {
    fn send<T: Send>() {}
    send::<Instance>();
};

impl Instance {
    /// The size of the guest's linear memory now, in bytes.
    pub fn memory_size(&self) -> usize {
        self.memory.data(&self.store).len()
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
        let locale = (self.store.data().services.locale)();
        self.store
            .data_mut()
            .begin_call(add_info.origin.clone(), locale);
        let result = self.run(request, add_info, locale);
        let dropped = self.store.data().call.drop;
        self.store.data_mut().end_call();
        drop(turn);
        if let Err(e) = &result {
            tracing::warn!(
                plugin = %self.store.data().session.plugin_id,
                session = self.store.data().session.session,
                error = %e,
                "the plugin failed; its instance is dropped"
            );
            self.poisoned = true;
            self.store.data_mut().release_all();
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
        self.store.data_mut().release_all();
    }

    /// The fuel the last call used.
    pub(crate) fn fuel_used(&self) -> u64 {
        self.limits
            .fuel
            .saturating_sub(self.store.get_fuel().unwrap_or(0))
    }

    fn run(
        &mut self,
        request: &str,
        add_info: &AddInfo,
        locale: oncl_basics::Locale,
    ) -> Result<String, PluginError> {
        let input = abi::encode(&Input {
            request: request.to_owned(),
            origin: add_info.origin.clone(),
            locale: locale_code(locale).to_owned(),
        });
        let len = transfer_len(input.len(), self.limits.max_transfer)?;
        self.store
            .set_fuel(self.limits.fuel)
            .map_err(|e| PluginError::Trap(e.to_string()))?;

        self.store.data_mut().phase = Phase::Host;
        let ptr = self.alloc.call(&mut self.store, len).map_err(failure)?;
        host::write_guest(self.memory.data_mut(&mut self.store), ptr, &input).map_err(failure)?;

        self.store.data_mut().phase = Phase::Guest;
        let packed = self
            .process
            .call(&mut self.store, (ptr, len))
            .map_err(failure)?;
        self.store.data_mut().phase = Phase::Host;

        let (out_ptr, out_len) = abi::unpack(packed);
        if out_len as usize > self.limits.max_transfer {
            return Err(PluginError::TooLarge);
        }
        let output = host::read_guest(self.memory.data(&self.store), out_ptr, out_len)
            .map_err(failure)?
            .to_vec();
        // Lengths within the limit fit an i32; the pointer is the guest's own, as given.
        self.free
            .call(&mut self.store, (out_ptr as i32, out_len as i32))
            .map_err(failure)?;
        self.store.data_mut().phase = Phase::Idle;
        let output: Output = abi::decode(&output).map_err(|e| PluginError::Output(e.message))?;
        Ok(output.response)
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
fn locale_code(locale: oncl_basics::Locale) -> &'static str {
    match locale {
        oncl_basics::Locale::Ru => "ru",
        oncl_basics::Locale::Kk => "kk",
        oncl_basics::Locale::En => "en",
    }
}
