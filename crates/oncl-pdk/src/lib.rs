//! OpenNCALayer's plugin development kit.
//!
//! - [`abi`]: the ABI between the core and a plugin (exports, host functions, the CBOR
//!   values they exchange); the core builds on it too.
//! - On `wasm32`, the guest SDK: [`plugin!`] exports a request handler as a plugin, and the
//!   host functions are wrapped in [`host`], [`keys`], [`dialogs`], [`files`] and [`http`].
//!
//! A plugin answering in the `CommonInvoker` dialect of the basics module uses the same
//! [`invoker::invoke`] the built-in modules use:
//!
//! ```ignore
//! use oncl_pdk::invoker::{self, CallResult, NlClass};
//! use oncl_pdk::Request;
//!
//! struct Echo;
//!
//! impl NlClass for Echo {
//!     fn class_name(&self) -> &'static str {
//!         "Echo"
//!     }
//!     fn call(&self, method: &str, args: Option<&serde_json::Map<String, serde_json::Value>>,
//!             _: &oncl_pdk::AddInfo) -> Option<CallResult> {
//!         (method == "echo").then(|| Ok(args.and_then(|a| a.get("text")).cloned().unwrap_or_default()))
//!     }
//! }
//!
//! fn handle(request: &Request) -> String {
//!     invoker::invoke(&request.text, &request.add_info(), &[&Echo])
//! }
//!
//! oncl_pdk::plugin!(handle);
//! ```
//!
//! The format, the limits and what each capability allows are described in
//! `docs/design/plugins.md`.

pub mod abi;
#[cfg(target_arch = "wasm32")]
mod guest;

#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub use guest::__rt;
#[cfg(target_arch = "wasm32")]
pub use guest::{call_host, dialogs, files, host, http, keys};
pub use oncl_protocol::{AddInfo, invoker, orgjson};
pub use serde_json;

/// The language of OpenNCALayer's windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    /// Russian.
    Ru,
    /// Kazakh.
    Kk,
    /// English.
    En,
}

impl Locale {
    /// The locale of [`abi::Input::locale`]: `"ru"`, `"kk"`, anything else English.
    pub fn from_code(code: &str) -> Locale {
        match code {
            "ru" => Locale::Ru,
            "kk" => Locale::Kk,
            _ => Locale::En,
        }
    }

    /// `"ru"`, `"kk"` or `"en"`.
    pub fn code(self) -> &'static str {
        match self {
            Locale::Ru => "ru",
            Locale::Kk => "kk",
            Locale::En => "en",
        }
    }
}

/// A request to the plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request as the page sent it: a JSON text.
    pub text: String,
    /// The page's origin, if the connection sent one.
    pub origin: Option<String>,
    /// The language of OpenNCALayer's windows.
    pub locale: Locale,
}

impl Request {
    /// The request of `input`.
    pub fn from_input(input: abi::Input) -> Request {
        Request {
            locale: Locale::from_code(&input.locale),
            text: input.request,
            origin: input.origin,
        }
    }

    /// The call context the built-in modules get, for [`invoker::invoke`]: the origin. The
    /// session is not the plugin's to see (`0`).
    pub fn add_info(&self) -> AddInfo {
        AddInfo {
            origin: self.origin.clone(),
            session: 0,
        }
    }
}
