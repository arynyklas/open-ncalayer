//! The NCALayer wire protocol for OpenNCALayer: the server-level WebSocket envelope (greeting,
//! heartbeat, routing by `module`) and the `CommonInvoker` dispatch semantics used by the
//! `kz.gov.pki.knca.basics` module.

mod envelope;
pub mod invoker;

pub use envelope::{
    AddInfo, COMPAT_VERSION, DEFAULT_MODULE, HEARTBEAT, Module, Registry, Route, greeting,
    module_not_found,
};
