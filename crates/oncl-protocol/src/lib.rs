//! The NCALayer wire protocol for OpenNCALayer: the server-level WebSocket envelope (greeting,
//! heartbeat, routing by `module`), the `CommonInvoker` dispatch semantics used by the
//! `kz.gov.pki.knca.basics` module, and the Java dialects of the original's modules shared by
//! the built-in modules and plugins: org.json reading and writing ([`orgjson`]) with the key
//! order of Java's `HashMap` ([`javamap`]), Java's and Kalkan's Base64 ([`javab64`]), Java
//! exception texts ([`javaexc`]) and the reflective dispatcher of `commonUtils` and its
//! clones ([`legacy`]).

mod envelope;
pub mod invoker;
pub mod javab64;
pub mod javaexc;
pub mod javamap;
pub mod legacy;
pub mod orgjson;

pub use envelope::{
    AddInfo, COMPAT_VERSION, DEFAULT_MODULE, DynamicModules, HEARTBEAT, Module, Registry, Reply,
    Route, SessionId, greeting, module_not_found,
};
