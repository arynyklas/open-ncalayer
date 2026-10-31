//! The modules built into the core, run as WebAssembly guests ([`Builtins`]).
//!
//! A built-in module comes with the core (its `plugin.toml` and `plugin.wasm` embedded,
//! [`BuiltinSource`]), is trusted as the core's own ([`Trust::Builtin`]) and is neither
//! installed nor removed. Its instances belong to no session: a call takes any idle instance
//! of the module, or makes one, and after it the instance lets go of every key, password and
//! consent ([`Instance`]'s `release_all`) before it goes back to the pool, so nothing of one
//! page's call reaches another's. At most [`BuiltinLimits::idle`] idle instances are kept per
//! module, each within [`BuiltinLimits::high_water`]; while every instance is busy, a call
//! makes one more instead of being refused. The pool is apart from the plugins' and their
//! [`MAX_INSTANCES`](crate::MAX_INSTANCES): plugins cannot crowd the built-in modules out.
//!
//! A built-in module that fails (traps, runs out of fuel or memory, answers malformed, or
//! panics the host) has the connection dropped ([`Reply::Drop`]), as a native module's
//! panic did, the failure logged as an error; its instance goes, the next call gets another.

use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oncl_protocol::{AddInfo, Module, Reply};
use semver::Version;
use sha2::{Digest, Sha256};

use crate::core::CoreHooks;
use crate::{
    Compiled, Engine, HostServices, Instance, InstanceLimits, LoadError, Localized, Manifest,
    SessionContext, SharedState, Trust,
};

/// The id prefix of the built-in modules; no plugin package may use it.
pub const BUILTIN_ID_PREFIX: &str = "io.github.arynyklas.openncalayer.builtin.";

/// The largest linear memory of a built-in module's instance: 2 GiB on 64-bit targets.
#[cfg(target_pointer_width = "64")]
pub const BUILTIN_MAX_MEMORY: usize = 2 << 30;
/// The largest linear memory of a built-in module's instance: 384 MiB on 32-bit targets.
#[cfg(not(target_pointer_width = "64"))]
pub const BUILTIN_MAX_MEMORY: usize = 384 << 20;

/// An instance of a built-in module whose linear memory is over this after a call is
/// dropped rather than kept idle: 64 MiB on 64-bit targets.
#[cfg(target_pointer_width = "64")]
pub const BUILTIN_HIGH_WATER: usize = 64 << 20;
/// An instance of a built-in module whose linear memory is over this after a call is
/// dropped: 16 MiB on 32-bit targets.
#[cfg(not(target_pointer_width = "64"))]
pub const BUILTIN_HIGH_WATER: usize = 16 << 20;

/// The idle instances kept per built-in module.
pub const BUILTIN_IDLE: usize = 2;

/// The fuel of one call of a built-in module.
pub const BUILTIN_FUEL: u64 = 200_000_000_000;

/// The largest buffer passed between the core and a built-in module: 512 MiB on 64-bit
/// targets (a reply holding a CMS of a [`MAX_TRANSFER`](crate::MAX_TRANSFER) message is
/// larger than the message).
#[cfg(target_pointer_width = "64")]
pub const BUILTIN_MAX_TRANSFER: usize = 512 << 20;
/// The largest buffer passed between the core and a built-in module: its memory on 32-bit
/// targets.
#[cfg(not(target_pointer_width = "64"))]
pub const BUILTIN_MAX_TRANSFER: usize = BUILTIN_MAX_MEMORY;

/// A built-in module as the core embeds it (`'static`), or a test builds it.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinSource<'a> {
    /// Its `plugin.toml`.
    pub manifest: &'a str,
    /// Its `plugin.wasm`.
    pub wasm: &'a [u8],
}

/// The limits of the built-in modules' instances and pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinLimits {
    /// An instance's memory, fuel and buffers.
    pub instance: InstanceLimits,
    /// An instance whose memory is over this after a call is not kept.
    pub high_water: usize,
    /// The idle instances kept per module.
    pub idle: usize,
}

impl Default for BuiltinLimits {
    /// [`BUILTIN_MAX_MEMORY`], [`BUILTIN_FUEL`], [`BUILTIN_MAX_TRANSFER`],
    /// [`BUILTIN_HIGH_WATER`] and [`BUILTIN_IDLE`].
    fn default() -> Self {
        BuiltinLimits {
            instance: InstanceLimits {
                max_memory: BUILTIN_MAX_MEMORY,
                fuel: BUILTIN_FUEL,
                max_transfer: BUILTIN_MAX_TRANSFER,
            },
            high_water: BUILTIN_HIGH_WATER,
            idle: BUILTIN_IDLE,
        }
    }
}

/// A loaded built-in module, as [`Builtins::loaded`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinInfo {
    pub id: String,
    pub version: Version,
    pub modules: Vec<String>,
    /// The SHA-256 of its `plugin.wasm`.
    pub sha256: [u8; 32],
}

/// What the calls of a built-in module took so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuiltinStats {
    /// The calls answered or failed.
    pub calls: u64,
    /// The largest linear memory of an instance after a call.
    pub peak_memory: usize,
    /// The most fuel a call used.
    pub max_fuel: u64,
}

/// The built-in modules and their instances; see the [module](self).
pub struct Builtins {
    /// By module name.
    modules: HashMap<String, Arc<Pool>>,
    loaded: Vec<BuiltinInfo>,
}

/// One built-in module's instances.
struct Pool {
    id: String,
    name: Localized,
    compiled: Compiled,
    services: HostServices,
    /// The values its instances share (`shared_*`), for the life of the process.
    shared: Arc<SharedState>,
    limits: BuiltinLimits,
    idle: Mutex<Vec<Instance>>,
    stats: Mutex<BuiltinStats>,
}

impl Builtins {
    /// The module names `sources` serve, sorted; only their manifests are read.
    ///
    /// # Errors
    ///
    /// [`LoadError::Invalid`] for a manifest that is not a built-in module's,
    /// [`LoadError::ModuleTaken`] for a module two of them serve.
    pub fn names(sources: &[BuiltinSource<'_>]) -> Result<Vec<String>, LoadError> {
        let mut owners = HashMap::new();
        for source in sources {
            let manifest = manifest(source)?;
            claim(&mut owners, &manifest)?;
        }
        let mut names: Vec<String> = owners.into_keys().collect();
        names.sort_unstable();
        Ok(names)
    }

    /// The modules of `sources`, checked without running them: their manifests read and
    /// their code compiled with `engine` against the ABI.
    ///
    /// # Errors
    ///
    /// The [`LoadError`] of the first module that does not compile, or
    /// [`LoadError::ModuleTaken`] for a module two of them serve.
    pub fn check(
        engine: &Engine,
        sources: &[BuiltinSource<'_>],
    ) -> Result<Vec<BuiltinInfo>, LoadError> {
        let mut owners = HashMap::new();
        let mut checked = Vec::new();
        for source in sources {
            let manifest = manifest(source)?;
            claim(&mut owners, &manifest)?;
            engine.compile(&manifest, source.wasm)?;
            checked.push(info(manifest, source));
        }
        Ok(checked)
    }

    /// The modules of `sources`, compiled with `engine`, served by `services` with the
    /// `core_*` functions of `hooks`, and limited by `limits`: each instantiated once (its
    /// ABI version checked), that instance kept idle.
    ///
    /// # Errors
    ///
    /// The [`LoadError`] of the first module that does not load, or
    /// [`LoadError::ModuleTaken`] for a module two of them serve.
    pub fn load(
        engine: &Engine,
        services: HostServices,
        sources: &[BuiltinSource<'_>],
        limits: BuiltinLimits,
        hooks: Option<Arc<CoreHooks>>,
    ) -> Result<Builtins, LoadError> {
        let services = HostServices {
            core: hooks,
            ..services
        };
        let mut owners = HashMap::new();
        let mut modules = HashMap::new();
        let mut loaded = Vec::new();
        for source in sources {
            let manifest = manifest(source)?;
            claim(&mut owners, &manifest)?;
            let compiled = engine
                .compile(&manifest, source.wasm)?
                .with_limits(limits.instance);
            let pool = Arc::new(Pool {
                id: manifest.id.clone(),
                name: manifest.name.clone(),
                compiled,
                services: services.clone(),
                shared: Arc::default(),
                limits,
                idle: Mutex::new(Vec::new()),
                stats: Mutex::new(BuiltinStats::default()),
            });
            let first = pool.instantiate()?;
            if limits.idle > 0 {
                lock(&pool.idle).push(first);
            }
            let info = info(manifest, source);
            tracing::info!(
                module = %info.id,
                version = %info.version,
                sha256 = %hex(&info.sha256),
                "built-in module loaded"
            );
            for name in &info.modules {
                modules.insert(name.clone(), Arc::clone(&pool));
            }
            loaded.push(info);
        }
        Ok(Builtins { modules, loaded })
    }

    /// The built-in module serving `name`, if any.
    pub fn module(&self, name: &str) -> Option<Arc<dyn Module>> {
        self.modules
            .get(name)
            .map(|pool| Arc::clone(pool) as Arc<dyn Module>)
    }

    /// The loaded modules, in the order of their sources.
    pub fn loaded(&self) -> Vec<BuiltinInfo> {
        self.loaded.clone()
    }

    /// What the calls of the module serving `name` took so far.
    pub fn stats(&self, name: &str) -> Option<BuiltinStats> {
        self.modules.get(name).map(|pool| *lock(&pool.stats))
    }

    /// The idle instances of the module serving `name` now.
    pub fn idle(&self, name: &str) -> Option<usize> {
        self.modules.get(name).map(|pool| lock(&pool.idle).len())
    }
}

/// The info of the loaded `manifest` of `source`.
fn info(manifest: Manifest, source: &BuiltinSource<'_>) -> BuiltinInfo {
    BuiltinInfo {
        id: manifest.id,
        version: manifest.version,
        modules: manifest.modules,
        sha256: Sha256::digest(source.wasm).into(),
    }
}

/// `bytes` in lowercase hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The manifest of `source`, which must be a built-in module's.
fn manifest(source: &BuiltinSource<'_>) -> Result<Manifest, LoadError> {
    Manifest::from_toml_builtin(source.manifest).map_err(|e| LoadError::Invalid(e.to_string()))
}

/// Records the modules of `manifest` in `owners` (module name → id), each once.
fn claim(owners: &mut HashMap<String, String>, manifest: &Manifest) -> Result<(), LoadError> {
    for module in &manifest.modules {
        if let Some(owner) = owners.insert(module.clone(), manifest.id.clone()) {
            return Err(LoadError::ModuleTaken {
                module: module.clone(),
                owner,
            });
        }
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Pool {
    /// A new instance, of no session.
    fn instantiate(&self) -> Result<Instance, LoadError> {
        let ctx = SessionContext {
            session: 0,
            plugin_id: self.id.clone(),
            plugin_name: self.name.clone(),
            shared: Arc::clone(&self.shared),
            trust: Trust::Builtin,
        };
        self.compiled.instantiate(&self.services, ctx)
    }
}

impl Module for Pool {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        let idle = lock(&self.idle).pop();
        let mut instance = match idle.map_or_else(|| self.instantiate(), Ok) {
            Ok(instance) => instance,
            Err(e) => {
                tracing::error!(
                    module = %self.id,
                    error = %e,
                    "cannot instantiate the built-in module; the connection is dropped"
                );
                return Reply::Drop;
            }
        };
        let result = panic::catch_unwind(AssertUnwindSafe(|| instance.process(request, add_info)));
        let reply = match result {
            Ok(Ok(reply)) => Some(reply),
            Ok(Err(e)) => {
                tracing::error!(
                    module = %self.id,
                    error = %e,
                    "the built-in module failed; the connection is dropped"
                );
                None
            }
            Err(_) => {
                tracing::error!(
                    module = %self.id,
                    "a built-in module call panicked; the connection is dropped"
                );
                None
            }
        };
        let memory = instance.memory_size();
        {
            let mut stats = lock(&self.stats);
            stats.calls += 1;
            stats.peak_memory = stats.peak_memory.max(memory);
            stats.max_fuel = stats.max_fuel.max(instance.fuel_used());
        }
        let Some(reply) = reply else {
            return Reply::Drop;
        };
        instance.release_all();
        if memory > self.limits.high_water {
            tracing::info!(
                module = %self.id,
                memory,
                "the built-in module's instance has grown too large; it is dropped"
            );
        } else {
            let mut idle = lock(&self.idle);
            if idle.len() < self.limits.idle {
                idle.push(instance);
            }
        }
        reply
    }
}
