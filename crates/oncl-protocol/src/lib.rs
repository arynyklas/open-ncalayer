//! The NCALayer wire protocol for OpenNCALayer: the server-level WebSocket envelope (greeting,
//! heartbeat, routing by `module`), the `CommonInvoker` dispatch semantics used by the
//! `kz.gov.pki.knca.basics` module, and the org.json reading every module shares.

mod envelope;
pub mod invoker;
pub mod orgjson;

pub use envelope::{
    AddInfo, COMPAT_VERSION, DEFAULT_MODULE, DynamicModules, HEARTBEAT, Module, Registry, Reply,
    Route, SessionId, greeting, module_not_found,
};
