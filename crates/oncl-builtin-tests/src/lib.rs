//! The built-in modules behind the [`Module`](oncl_protocol::Module) trait, for their tests:
//! each facade takes the settings the modules' former native types took (the same
//! constructors and builder methods) and builds the module's embedded WebAssembly guest the
//! first time it is called.

pub mod accessory;
pub mod applet;
pub mod basics;
pub mod commonutils;

use oncl_plugin::core::CoreHooks;
use oncl_plugin::{BuiltinLimits, Builtins, Engine, HostServices};
use oncl_protocol::{AddInfo, Module, Reply};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

include!(concat!(env!("OUT_DIR"), "/builtins.rs"));

/// The built-in module `name` of [`SOURCES`], served by `services` with `hooks`.
///
/// # Panics
///
/// When the modules do not load or none serves `name`.
fn guest(name: &str, services: HostServices, hooks: Option<Arc<CoreHooks>>) -> Box<dyn Module> {
    let builtins = Builtins::load(
        &Engine::new(),
        services,
        SOURCES,
        BuiltinLimits::default(),
        hooks,
    )
    .expect("the built-in modules load");
    Box::new(Guest(builtins.module(name).expect("a built-in module")))
}

/// A built-in module's pool.
struct Guest(Arc<dyn Module>);

impl Module for Guest {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0.process(request, add_info)
    }
}

/// A module built from settings `S` on its first call.
struct Lazy<S> {
    settings: Mutex<Option<S>>,
    module: OnceLock<Box<dyn Module>>,
}

impl<S> Lazy<S> {
    fn new(settings: S) -> Self {
        Lazy {
            settings: Mutex::new(Some(settings)),
            module: OnceLock::new(),
        }
    }

    /// The settings, while the module is not built yet.
    fn settings(&mut self) -> &mut S {
        self.settings
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .expect("the module is built on its first call; configure it before")
    }

    fn process(
        &self,
        request: &str,
        add_info: &AddInfo,
        build: impl FnOnce(S) -> Box<dyn Module>,
    ) -> Reply {
        self.module
            .get_or_init(|| {
                let settings = self
                    .settings
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                    .expect("built once");
                build(settings)
            })
            .process(request, add_info)
    }
}
