//! The loaded plugins as the daemon's dynamic modules ([`DynamicModules`]).
//!
//! A plugin is loaded as a *generation*: [`PluginModules::load`] of a plugin already loaded
//! (an update, a reload) replaces it with a new one, and [`PluginModules::unload`] ends it.
//! Instances are kept per session and plugin: a call of a session takes its instance of the
//! plugin's current generation (an instance of an older one is dropped and a new one made).
//! A call running while its plugin is replaced or unloaded finishes on its instance, which is
//! then dropped; the session's next call gets the new generation, or `MODULE_NOT_FOUND`. A
//! call that fails (or panics) answers [`PLUGIN_ERROR_REPLY`] and its instance is dropped;
//! the other instances and plugins carry on. A call without a session (`0`) gets an instance
//! of its own, dropped after it. At most [`MAX_INSTANCES`] instances live at once: the one
//! used longest ago and not busy goes first; with every one busy, a call needing a new one
//! answers [`PLUGIN_ERROR_REPLY`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use oncl_protocol::{AddInfo, DynamicModules, Module, SessionId, module_not_found};
use semver::Version;

use crate::{
    Compiled, Engine, HostServices, Instance, LoadError, Localized, MAX_INSTANCES, Manifest,
    PLUGIN_ERROR_REPLY, Package, Replaces, SessionContext,
};

/// The owner [`LoadError::ModuleTaken`] names for a module built into OpenNCALayer.
pub const BUILT_IN: &str = "OpenNCALayer";

/// What [`PluginModules::set_on_missing`] calls when a request names a module nothing
/// serves: the module name and the call's context.
pub type OnMissing = Arc<dyn Fn(&str, &AddInfo) + Send + Sync>;

/// A loaded plugin, as [`PluginModules::loaded`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedInfo {
    pub id: String,
    pub version: Version,
    pub modules: Vec<String>,
    pub replaces: Option<Replaces>,
    pub name: Localized,
}

/// The loaded plugins and their instances; see the [module](self).
pub struct PluginModules {
    inner: Arc<Inner>,
}

struct Inner {
    engine: Arc<Engine>,
    services: HostServices,
    builtin: HashSet<String>,
    state: Mutex<State>,
    /// Notified whenever a busy instance is given back or its slot freed.
    returned: Condvar,
    on_missing: Mutex<Option<OnMissing>>,
}

#[derive(Default)]
struct State {
    /// By id.
    plugins: BTreeMap<String, Plugin>,
    /// Module name → plugin id.
    modules: HashMap<String, String>,
    /// By session and plugin id.
    instances: HashMap<(SessionId, String), Slot>,
    /// Instances of calls without a session, alive now.
    transient: usize,
    next_generation: u64,
    /// Counts the takes of instances: the least recently used has the lowest.
    clock: u64,
}

struct Plugin {
    generation: u64,
    compiled: Compiled,
    manifest: Manifest,
}

struct Slot {
    generation: u64,
    /// `None` while a call runs on it.
    instance: Option<Instance>,
    last_used: u64,
}

impl PluginModules {
    /// No plugins yet. Instances are compiled with `engine` and served by `services`;
    /// `builtin` are the module names served by the core, which no plugin may take.
    pub fn new(engine: Arc<Engine>, services: HostServices, builtin: Vec<String>) -> Self {
        PluginModules {
            inner: Arc::new(Inner {
                engine,
                services,
                builtin: builtin.into_iter().collect(),
                state: Mutex::new(State::default()),
                returned: Condvar::new(),
                on_missing: Mutex::new(None),
            }),
        }
    }

    /// Whether `package` would load ([`PluginModules::load`]), without loading it.
    ///
    /// # Errors
    ///
    /// What [`PluginModules::load`] would fail with.
    pub fn check(&self, package: &Package) -> Result<(), LoadError> {
        let manifest = &package.manifest;
        let compiled = self.inner.engine.compile(manifest, &package.wasm)?;
        drop(compiled.instantiate(&self.inner.services, context(manifest, 0))?);
        self.inner.free_modules(&self.inner.lock(), manifest)
    }

    /// Loads `package` as the new generation of its plugin: compiled, instantiated once
    /// (the ABI version), its modules checked against the built-in ones and those of other
    /// plugins. A plugin of the same id loaded before is replaced; its idle instances go.
    ///
    /// # Errors
    ///
    /// [`LoadError`]; [`LoadError::ModuleTaken`] for a module served already. The plugin
    /// loaded before, if any, stays then.
    pub fn load(&self, package: Package) -> Result<(), LoadError> {
        let manifest = package.manifest;
        let compiled = self.inner.engine.compile(&manifest, &package.wasm)?;
        drop(compiled.instantiate(&self.inner.services, context(&manifest, 0))?);
        let mut garbage = Vec::new();
        let mut state = self.inner.lock();
        self.inner.free_modules(&state, &manifest)?;
        let id = manifest.id.clone();
        state.next_generation += 1;
        let generation = state.next_generation;
        state.modules.retain(|_, owner| *owner != id);
        for module in &manifest.modules {
            state.modules.insert(module.clone(), id.clone());
        }
        tracing::info!(plugin = %id, version = %manifest.version, generation, "plugin loaded");
        state.plugins.insert(
            id.clone(),
            Plugin {
                generation,
                compiled,
                manifest,
            },
        );
        drop_idle(&mut state, &mut garbage, |(_, owner), slot| {
            *owner == id && slot.generation != generation
        });
        drop(state);
        self.inner.returned.notify_all();
        Ok(())
    }

    /// Unloads the plugin `id`: its modules are not served from now on, its idle instances
    /// go, and those of running calls once they return. Whether it was loaded.
    pub fn unload(&self, id: &str) -> bool {
        let mut garbage = Vec::new();
        let mut state = self.inner.lock();
        let Some(plugin) = state.plugins.remove(id) else {
            return false;
        };
        state.modules.retain(|_, owner| owner != id);
        drop_idle(&mut state, &mut garbage, |(_, owner), _| owner == id);
        drop(state);
        self.inner.returned.notify_all();
        tracing::info!(plugin = %id, version = %plugin.manifest.version, "plugin unloaded");
        true
    }

    /// The loaded plugins, by id.
    pub fn loaded(&self) -> Vec<LoadedInfo> {
        self.inner
            .lock()
            .plugins
            .values()
            .map(|plugin| {
                let m = &plugin.manifest;
                LoadedInfo {
                    id: m.id.clone(),
                    version: m.version.clone(),
                    modules: m.modules.clone(),
                    replaces: m.replaces.clone(),
                    name: m.name.clone(),
                }
            })
            .collect()
    }

    /// Has `f` called for every request naming a module nothing serves.
    pub fn set_on_missing(&self, f: OnMissing) {
        *lock(&self.inner.on_missing) = Some(f);
    }
}

impl DynamicModules for PluginModules {
    fn module(&self, name: &str) -> Option<Arc<dyn Module>> {
        let state = self.inner.lock();
        let id = state.modules.get(name)?;
        Some(Arc::new(PluginModule {
            inner: Arc::clone(&self.inner),
            id: id.clone(),
            module: name.to_owned(),
        }))
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.inner.lock().modules.keys().cloned().collect();
        names.sort_unstable();
        names
    }

    fn session_closed(&self, session: SessionId) {
        let mut garbage = Vec::new();
        let mut state = self.inner.lock();
        drop_idle(&mut state, &mut garbage, |(of, _), _| *of == session);
        drop(state);
        self.inner.returned.notify_all();
    }

    fn missing(&self, name: &str, add_info: &AddInfo) {
        let hook = lock(&self.inner.on_missing).clone();
        if let Some(hook) = hook {
            hook(name, add_info);
        }
    }
}

/// Removes the idle instances whose key and slot `which` picks into `garbage`, to be dropped
/// once the lock is let go. Busy ones are left to their calls.
fn drop_idle(
    state: &mut State,
    garbage: &mut Vec<Instance>,
    which: impl Fn(&(SessionId, String), &Slot) -> bool,
) {
    state.instances.retain(|key, slot| {
        if slot.instance.is_none() || !which(key, slot) {
            return true;
        }
        garbage.extend(slot.instance.take());
        false
    });
}

fn context(manifest: &Manifest, session: SessionId) -> SessionContext {
    SessionContext {
        session,
        plugin_id: manifest.id.clone(),
        plugin_name: manifest.name.clone(),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A module of a plugin, as routed to.
struct PluginModule {
    inner: Arc<Inner>,
    id: String,
    module: String,
}

impl Module for PluginModule {
    fn process(&self, request: &str, add_info: &AddInfo) -> String {
        let mut lease = match self.inner.lease(&self.id, &self.module, add_info.session) {
            Ok(lease) => lease,
            Err(reply) => return reply,
        };
        let Some(instance) = lease.instance.as_mut() else {
            return PLUGIN_ERROR_REPLY.to_owned();
        };
        let result = panic::catch_unwind(AssertUnwindSafe(|| instance.process(request, add_info)));
        match result {
            Ok(Ok(reply)) => {
                lease.keep = true;
                reply
            }
            // The runtime has logged the failure.
            Ok(Err(_)) => PLUGIN_ERROR_REPLY.to_owned(),
            Err(_) => {
                tracing::error!(plugin = %self.id, "a plugin call panicked; its instance is dropped");
                PLUGIN_ERROR_REPLY.to_owned()
            }
        }
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Whether every module of `manifest` is free for it: served by neither a built-in
    /// module nor another plugin (its own earlier generation may serve it).
    fn free_modules(&self, state: &State, manifest: &Manifest) -> Result<(), LoadError> {
        for module in &manifest.modules {
            let owner = if self.builtin.contains(module) {
                BUILT_IN
            } else {
                match state.modules.get(module) {
                    Some(owner) if *owner != manifest.id => owner.as_str(),
                    _ => continue,
                }
            };
            return Err(LoadError::ModuleTaken {
                module: module.clone(),
                owner: owner.to_owned(),
            });
        }
        Ok(())
    }

    /// The instance a call of `session` to `module` of the plugin `id` runs on, taken for
    /// the call; or the reply when there is none: `MODULE_NOT_FOUND` if the plugin no longer
    /// serves `module`, [`PLUGIN_ERROR_REPLY`] if no instance can be made. Waits while the
    /// session's instance is busy with another call.
    fn lease(&self, id: &str, module: &str, session: SessionId) -> Result<Lease<'_>, String> {
        let mut garbage = Vec::new();
        let mut state = self.lock();
        let key = (session != 0).then(|| (session, id.to_owned()));
        let generation = loop {
            let Some(generation) = state.plugins.get(id).map(|p| p.generation) else {
                return Err(module_not_found());
            };
            if state.modules.get(module).map(String::as_str) != Some(id) {
                return Err(module_not_found());
            }
            let Some(key) = &key else {
                break generation;
            };
            let (busy, current) = match state.instances.get(key) {
                None => break generation,
                Some(slot) => (slot.instance.is_none(), slot.generation == generation),
            };
            if busy {
                state = self
                    .returned
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            if current {
                state.clock += 1;
                let clock = state.clock;
                let slot = state.instances.get_mut(key).expect("looked up");
                slot.last_used = clock;
                let instance = slot.instance.take();
                return Ok(Lease {
                    inner: self,
                    key: Some(key.clone()),
                    generation,
                    instance,
                    keep: false,
                });
            }
            // An idle instance of an older generation.
            garbage.extend(state.instances.remove(key).and_then(|s| s.instance));
            break generation;
        };
        if !make_room(&mut state, &mut garbage) {
            tracing::warn!(plugin = %id, "every plugin instance is busy; the call is refused");
            return Err(PLUGIN_ERROR_REPLY.to_owned());
        }
        let plugin = &state.plugins[id];
        let compiled = plugin.compiled.clone();
        let ctx = context(&plugin.manifest, session);
        state.clock += 1;
        match &key {
            Some(key) => {
                let slot = Slot {
                    generation,
                    instance: None,
                    last_used: state.clock,
                };
                state.instances.insert(key.clone(), slot);
            }
            None => state.transient += 1,
        }
        drop(state);
        drop(garbage);
        // From here on the lease frees the slot, whatever happens.
        let mut lease = Lease {
            inner: self,
            key,
            generation,
            instance: None,
            keep: false,
        };
        match compiled.instantiate(&self.services, ctx) {
            Ok(instance) => {
                lease.instance = Some(instance);
                Ok(lease)
            }
            Err(e) => {
                tracing::warn!(plugin = %id, error = %e, "cannot instantiate the plugin");
                Err(PLUGIN_ERROR_REPLY.to_owned())
            }
        }
    }
}

/// Frees room for one more instance: the idle ones used longest ago go into `garbage` while
/// [`MAX_INSTANCES`] are alive. Whether there is room.
fn make_room(state: &mut State, garbage: &mut Vec<Instance>) -> bool {
    while state.instances.len() + state.transient >= MAX_INSTANCES {
        let oldest = state
            .instances
            .iter()
            .filter(|(_, slot)| slot.instance.is_some())
            .min_by_key(|(_, slot)| slot.last_used)
            .map(|(key, _)| key.clone());
        let Some(oldest) = oldest else {
            return false;
        };
        garbage.extend(state.instances.remove(&oldest).and_then(|s| s.instance));
    }
    true
}

/// An instance taken for a call. Dropped, it goes back to its slot if the call succeeded
/// (`keep`) and its plugin's generation is still current; otherwise it is dropped and its
/// slot freed (a panic unwinding through the call included).
struct Lease<'a> {
    inner: &'a Inner,
    /// `None`: a call without a session.
    key: Option<(SessionId, String)>,
    generation: u64,
    instance: Option<Instance>,
    keep: bool,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut garbage = self.instance.take();
        let mut state = self.inner.lock();
        match &self.key {
            None => state.transient -= 1,
            Some(key) => {
                let current = state
                    .plugins
                    .get(&key.1)
                    .is_some_and(|p| p.generation == self.generation);
                let healthy = garbage.as_ref().is_some_and(|i| !i.is_poisoned());
                let slot = state
                    .instances
                    .get_mut(key)
                    .filter(|slot| slot.generation == self.generation && slot.instance.is_none());
                match slot {
                    Some(slot) if self.keep && current && healthy => slot.instance = garbage.take(),
                    Some(_) => {
                        state.instances.remove(key);
                    }
                    None => {}
                }
            }
        }
        drop(state);
        self.inner.returned.notify_all();
        drop(garbage);
    }
}
