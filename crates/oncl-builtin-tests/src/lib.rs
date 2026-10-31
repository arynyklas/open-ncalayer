//! The built-in modules behind the [`Module`](oncl_protocol::Module) trait, for their tests:
//! each facade takes the settings of the module's native type (the same constructors and
//! builder methods) and builds the module the first time it is called, natively or as its
//! WebAssembly guest ([`Backend`]).

pub mod accessory;
pub mod applet;
pub mod basics;
pub mod commonutils;

use oncl_protocol::{AddInfo, Module, Reply};
use std::sync::{Mutex, OnceLock, PoisonError};

/// The variable choosing the implementation the facades build: `native` or `wasm`.
pub const BACKEND_VAR: &str = "ONCL_BUILTIN_BACKEND";

/// An implementation of a built-in module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The module's Rust code, linked into the test.
    Native,
    /// The module's WebAssembly guest, run by the plugin runtime.
    Wasm,
}

/// The implementation [`BACKEND_VAR`] names, [`Backend::Wasm`] when it is not set. A
/// module without a guest yet is native unless the variable names one.
///
/// # Panics
///
/// When the variable holds anything but `native` or `wasm`.
pub fn backend() -> Backend {
    from_env().unwrap_or(Backend::Wasm)
}

fn from_env() -> Option<Backend> {
    match std::env::var(BACKEND_VAR) {
        Ok(v) if v == "native" => Some(Backend::Native),
        Ok(v) if v == "wasm" => Some(Backend::Wasm),
        Ok(v) => panic!("{BACKEND_VAR} must be `native` or `wasm`, not `{v}`"),
        Err(_) => None,
    }
}

/// What a module has: native code, a guest, or both.
#[derive(Clone, Copy)]
struct Available {
    native: bool,
    wasm: bool,
}

/// The implementation of the module `name` to build: `explicit` (from `with_backend`), else
/// the variable's, else its guest if it has one.
fn resolve(name: &str, explicit: Option<Backend>, available: Available) -> Backend {
    let chosen = explicit.or_else(from_env).unwrap_or(if available.wasm {
        Backend::Wasm
    } else {
        Backend::Native
    });
    match chosen {
        Backend::Native if !available.native => {
            panic!("{name} has no native implementation any more; use {BACKEND_VAR}=wasm")
        }
        Backend::Wasm if !available.wasm => {
            panic!("{name} has no WebAssembly guest yet; use {BACKEND_VAR}=native")
        }
        b => b,
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
