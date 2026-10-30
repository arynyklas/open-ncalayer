//! Server-level envelope: what the WebSocket server itself sends and how it routes a text frame
//! to a module.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Version announced in the greeting. Clients may key behaviour on it, so it stays the
/// original's value.
pub const COMPAT_VERSION: &str = "1.4";
/// Application-level ping: a text frame with exactly this payload is echoed back verbatim.
pub const HEARTBEAT: &str = "--heartbeat--";
/// Module used when a request has no `module` field (or it is `null`).
pub const DEFAULT_MODULE: &str = "kz.gov.pki.knca.applet.Applet";

/// A session: one WebSocket connection or one virtual socket of the extension bridge. `0` is
/// no session.
pub type SessionId = u64;

/// Per-connection context passed to every module call (`addInfo` in the original).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddInfo {
    /// The `Origin` header of the WebSocket handshake, if the client sent one.
    pub origin: Option<String>,
    /// The session the call belongs to; `0` without one.
    pub session: SessionId,
}

/// A module reachable through the `module` field of a request. It receives the raw request text
/// and parses it with its own grammar; its reply is sent back as is.
pub trait Module: Send + Sync {
    fn process(&self, request: &str, add_info: &AddInfo) -> String;
}

/// Modules that come and go while the daemon runs, looked up after the built-in ones.
pub trait DynamicModules: Send + Sync {
    /// The module serving `name` right now, if any.
    fn module(&self, name: &str) -> Option<Arc<dyn Module>>;
    /// The names of the modules served right now.
    fn names(&self) -> Vec<String>;
    /// `session` has ended: whatever was kept for it may go. Called once per session, after
    /// its last call has returned, possibly from async context (a runtime worker thread) and
    /// from a guard's `drop`: it must not block and must not panic.
    fn session_closed(&self, session: SessionId);
    /// A request named the module `name`, which nothing serves.
    fn missing(&self, name: &str, add_info: &AddInfo);
}

/// Modules keyed by their `module` name, and the dynamic modules, if any.
#[derive(Default)]
pub struct Registry {
    modules: HashMap<String, Arc<dyn Module>>,
    dynamic: Option<Arc<dyn DynamicModules>>,
}

/// What the server should do with an incoming text frame.
pub enum Route {
    /// Echo the frame back verbatim.
    Heartbeat,
    /// Pass the frame to this module and send back its reply.
    Module(Arc<dyn Module>),
    /// Reply with [`module_not_found`]. `module` is the requested name if it is a string.
    NotFound { module: Option<String> },
    /// The frame is not a JSON object: drop the TCP connection without a close frame, as the
    /// original does.
    InvalidJson,
}

impl Registry {
    /// Registers `m` under `name`. The first registration wins: returns `false` and keeps the
    /// existing module if `name` is taken.
    pub fn register(&mut self, name: &str, m: Arc<dyn Module>) -> bool {
        if self.modules.contains_key(name) {
            return false;
        }
        self.modules.insert(name.to_owned(), m);
        true
    }

    /// Sets the dynamic modules, looked up when no built-in module has the name.
    pub fn set_dynamic(&mut self, d: Arc<dyn DynamicModules>) {
        self.dynamic = Some(d);
    }

    /// The names of the built-in and dynamic modules, sorted and without repeats.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.modules.keys().cloned().collect();
        if let Some(d) = &self.dynamic {
            names.extend(d.names());
        }
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Tells the dynamic modules that `session` has ended.
    pub fn session_closed(&self, session: SessionId) {
        if let Some(d) = &self.dynamic {
            d.session_closed(session);
        }
    }

    /// Tells the dynamic modules that a request named the module `name`, which nothing serves.
    pub fn missing(&self, name: &str, add_info: &AddInfo) {
        if let Some(d) = &self.dynamic {
            d.missing(name, add_info);
        }
    }

    /// Routes a text frame. The `module` field is read from the top-level JSON object; an absent
    /// or `null` field selects [`DEFAULT_MODULE`], and any other non-string value matches no
    /// module. Built-in modules go before dynamic ones.
    pub fn route(&self, text: &str) -> Route {
        if text == HEARTBEAT {
            return Route::Heartbeat;
        }
        let Ok(ModuleField(module)) = serde_json::from_str::<ModuleField>(text) else {
            return Route::InvalidJson;
        };
        let (name, named) = match &module {
            None | Some(Value::Null) => (DEFAULT_MODULE, false),
            Some(Value::String(name)) => (name.as_str(), true),
            Some(_) => return Route::NotFound { module: None },
        };
        if let Some(m) = self.modules.get(name) {
            return Route::Module(Arc::clone(m));
        }
        match self.dynamic.as_ref().and_then(|d| d.module(name)) {
            Some(m) => Route::Module(m),
            None => Route::NotFound {
                module: named.then(|| name.to_owned()),
            },
        }
    }
}

/// The greeting pushed to a client right after the WebSocket upgrade.
pub fn greeting() -> String {
    #[derive(Serialize)]
    struct Greeting {
        result: Version,
    }
    #[derive(Serialize)]
    struct Version {
        version: &'static str,
    }
    to_json(&Greeting {
        result: Version {
            version: COMPAT_VERSION,
        },
    })
}

/// The reply to a request whose `module` is not registered.
pub fn module_not_found() -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ModuleNotFound {
        success: bool,
        error_code: &'static str,
    }
    to_json(&ModuleNotFound {
        success: false,
        error_code: "MODULE_NOT_FOUND",
    })
}

/// Serializes a protocol reply. Replies are structs with string keys and JSON values only, so
/// serialization cannot fail.
pub(crate) fn to_json<T: Serialize>(reply: &T) -> String {
    serde_json::to_string(reply).expect("protocol replies always serialize")
}

/// The `module` field of a request. Deserializes only from a JSON object (any other JSON value is
/// rejected) and skips every other field without building it, since requests can carry documents
/// of tens of megabytes.
struct ModuleField(Option<Value>);

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
enum Key {
    Module,
    #[serde(other)]
    Other,
}

impl<'de> Deserialize<'de> for ModuleField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ModuleFieldVisitor)
    }
}

struct ModuleFieldVisitor;

impl<'de> Visitor<'de> for ModuleFieldVisitor {
    type Value = ModuleField;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ModuleField, A::Error> {
        let mut module = None;
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Module => module = Some(map.next_value::<Value>()?),
                Key::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(ModuleField(module))
    }
}
