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

/// Per-connection context passed to every module call (`addInfo` in the original).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddInfo {
    /// The `Origin` header of the WebSocket handshake, if the client sent one.
    pub origin: Option<String>,
}

/// A module reachable through the `module` field of a request. It receives the raw request text
/// and parses it with its own grammar; its reply is sent back as is.
pub trait Module: Send + Sync {
    fn process(&self, request: &str, add_info: &AddInfo) -> String;
}

/// Modules keyed by their `module` name.
#[derive(Default)]
pub struct Registry {
    modules: HashMap<String, Arc<dyn Module>>,
}

/// What the server should do with an incoming text frame.
pub enum Route {
    /// Echo the frame back verbatim.
    Heartbeat,
    /// Pass the frame to this module and send back its reply.
    Module(Arc<dyn Module>),
    /// Reply with [`module_not_found`].
    NotFound,
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

    /// The names of the registered modules, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.modules.keys().cloned().collect();
        names.sort_unstable();
        names
    }

    /// Routes a text frame. The `module` field is read from the top-level JSON object; an absent
    /// or `null` field selects [`DEFAULT_MODULE`], and any other non-string value matches no
    /// module.
    pub fn route(&self, text: &str) -> Route {
        if text == HEARTBEAT {
            return Route::Heartbeat;
        }
        let Ok(ModuleField(module)) = serde_json::from_str::<ModuleField>(text) else {
            return Route::InvalidJson;
        };
        let name = match &module {
            None | Some(Value::Null) => DEFAULT_MODULE,
            Some(Value::String(name)) => name.as_str(),
            Some(_) => return Route::NotFound,
        };
        match self.modules.get(name) {
            Some(m) => Route::Module(Arc::clone(m)),
            None => Route::NotFound,
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
