//! Server-level envelope: what the WebSocket server itself sends and how it routes a text frame
//! to a module.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::orgjson::{self, JValue};

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

/// What a module answers a request with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// This text goes back to the page.
    Text(String),
    /// No reply: the connection is dropped without a close frame, as for a request that is
    /// not a JSON object ([`Route::InvalidJson`]).
    Drop,
}

impl Reply {
    /// The text of a [`Reply::Text`].
    pub fn text(&self) -> Option<&str> {
        match self {
            Reply::Text(text) => Some(text),
            Reply::Drop => None,
        }
    }

    /// The text of a [`Reply::Text`].
    pub fn into_text(self) -> Option<String> {
        match self {
            Reply::Text(text) => Some(text),
            Reply::Drop => None,
        }
    }
}

impl From<String> for Reply {
    fn from(text: String) -> Self {
        Reply::Text(text)
    }
}

impl From<&str> for Reply {
    fn from(text: &str) -> Self {
        Reply::Text(text.to_owned())
    }
}

impl PartialEq<str> for Reply {
    fn eq(&self, other: &str) -> bool {
        self.text() == Some(other)
    }
}

impl PartialEq<&str> for Reply {
    fn eq(&self, other: &&str) -> bool {
        self.text() == Some(*other)
    }
}

impl PartialEq<String> for Reply {
    fn eq(&self, other: &String) -> bool {
        self.text() == Some(other.as_str())
    }
}

/// A module reachable through the `module` field of a request. It receives the raw request text
/// (through the end of its JSON object, see [`Route::Module`]) and parses it with its own
/// grammar; its reply is sent back as is.
pub trait Module: Send + Sync {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply;
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
pub enum Route<'a> {
    /// Echo the frame back verbatim.
    Heartbeat,
    /// Pass `request` to `module` and send back its reply. `request` is the frame through
    /// the end of its JSON object: what follows it the original does not read.
    Module {
        module: Arc<dyn Module>,
        request: &'a str,
    },
    /// Reply with [`module_not_found`]. `module` is the requested name if it is a string.
    NotFound { module: Option<String> },
    /// The frame is not a JSON object org.json reads (a key repeated in an object is an
    /// error there): drop the TCP connection without a close frame, as the original does.
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

    /// Routes a text frame. The frame is read as org.json's `new JSONObject(text)` reads it
    /// ([`orgjson::scan`]): its leniency, a key repeated in any object is an error, and the
    /// text after the object is not read. The `module` field is read from that object; an
    /// absent or `null` field selects [`DEFAULT_MODULE`], and any other non-string value
    /// matches no module. Built-in modules go before dynamic ones.
    pub fn route<'a>(&self, text: &'a str) -> Route<'a> {
        if text == HEARTBEAT {
            return Route::Heartbeat;
        }
        let Ok(scanned) = orgjson::scan(text, "module") else {
            return Route::InvalidJson;
        };
        let request = &text[..scanned.len];
        let (name, named) = match &scanned.value {
            None | Some(JValue::Null) => (DEFAULT_MODULE, false),
            Some(JValue::Str(name)) => (name.as_str(), true),
            Some(_) => return Route::NotFound { module: None },
        };
        let module = match self.modules.get(name) {
            Some(m) => Arc::clone(m),
            None => match self.dynamic.as_ref().and_then(|d| d.module(name)) {
                Some(m) => m,
                None => {
                    return Route::NotFound {
                        module: named.then(|| name.to_owned()),
                    };
                }
            },
        };
        Route::Module { module, request }
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
