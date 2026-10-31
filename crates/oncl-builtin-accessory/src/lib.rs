//! The `kz.gov.pki.ncalayerservices.accessory` module (the original's `NCALayerServices`
//! `AccessoryService`), built into the core as a WebAssembly module.
//!
//! A request is `{"method", "symname"?, "uuid"?}`; `method` is read with org.json
//! `getString`, `symname` and `uuid` with `optString`. The reply is a JSON object, with the
//! request's `uuid` when it is not empty:
//!
//! - `getBundles`: `{symname: version}` of the original's OSGi framework
//!   (`org.apache.felix.framework`), of its core bundles whose functions this daemon
//!   implements ([`CORE_BUNDLES`]), of OpenNCALayer itself ([`SYMNAME`], the core's
//!   version), and of the original bundles the enabled plugins port;
//! - `getServices`: `{"services": [module names]}`: the daemon's built-in modules and those
//!   of its plugins now, sorted;
//! - `installBundle`: `SYMNAME_PARAMETER_IS_EMPTY` for an empty `symname`; then the
//!   original reads the page's `origin` with `getString` from the headers its WebSocket
//!   server always writes as `{"origin": <header or null>}`, so a connection without an
//!   `Origin` header fails with `JSONObject["origin"] is not a string.`; then, as the
//!   original, `NONE` at once if a plugin porting the bundle can be installed (the daemon
//!   asks the user meanwhile), else `BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED` after telling
//!   the daemon, which shows the user where plugins are listed;
//! - `showBundleManager`, `showSettings`, `showKeystoreExplorer`, `showAdesSigning`,
//!   `showAdesValidation`: `{}`, after asking the daemon to open the window.
//!
//! Any failure is `{"errorCode":"<exception.toString()>"}` without `uuid`, as the original's
//! `JSONStringer` writes it.

pub mod reply;

#[cfg(target_arch = "wasm32")]
mod guest;

pub use reply::{CORE_BUNDLES, MODULE_NAME, SYMNAME, bundles};

use oncl_pdk::abi::{CoreBundles, CoreModules, Window};
use oncl_pdk::orgjson::{get_string, opt_string};
use oncl_pdk::serde_json::{Map, Value, json};

/// What the module asks of the core.
pub trait Core {
    /// The built-in modules' names and the plugins'.
    fn modules(&self) -> CoreModules;
    /// The core's version and the bundles its plugins port.
    fn bundles(&self) -> CoreBundles;
    /// The page asks to install the bundle `symname`: whether a plugin porting it is
    /// offered; `None` when the page sent no origin.
    fn install_bundle(&self, symname: &str) -> Option<bool>;
    /// Opens `window`.
    fn open_window(&self, window: Window);
}

/// The reply to `request`: the object, or the exception the original's reply names.
pub fn handle(core: &impl Core, request: &str) -> Result<String, String> {
    let request: Map<String, Value> = oncl_pdk::serde_json::from_str(request).map_err(|_| {
        json_exception("A JSONObject text must begin with '{' at 1 [character 2 line 1]")
    })?;
    let method = get_string(&request, "method").map_err(|e| json_exception(&e))?;
    let uuid = opt_string(&request, "uuid").unwrap_or_default();
    let mut obj = Map::new();
    let window = match method {
        "getBundles" => {
            let bundles = core.bundles();
            for (symname, version) in CORE_BUNDLES {
                obj.insert(symname.to_owned(), json!(version));
            }
            obj.insert(SYMNAME.to_owned(), json!(bundles.core_version));
            for (symname, version) in bundles.plugins {
                obj.entry(symname).or_insert_with(|| json!(version));
            }
            None
        }
        "getServices" => {
            let modules = core.modules();
            let mut services = modules.builtin;
            // The built-in ones as given (sorted); with the plugins' added, sorted again.
            if !modules.plugins.is_empty() {
                services.extend(modules.plugins);
                services.sort_unstable();
                services.dedup();
            }
            obj.insert("services".to_owned(), json!(services));
            None
        }
        "installBundle" => {
            let symname = opt_string(&request, "symname").unwrap_or_default();
            // `String.trim()`: every char up to U+0020.
            let (code, window) = if symname.trim_matches(|c| c <= ' ').is_empty() {
                ("SYMNAME_PARAMETER_IS_EMPTY", None)
            } else {
                // No `Origin` header is the original's `{"origin":null}`.
                match core.install_bundle(&symname) {
                    None => return Err(json_exception("JSONObject[\"origin\"] is not a string.")),
                    Some(true) => ("NONE", None),
                    Some(false) => (
                        "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED",
                        Some(Window::BundleHint { symname }),
                    ),
                }
            };
            obj.insert("errorCode".to_owned(), json!(code));
            window
        }
        "showBundleManager" => Some(Window::BundleManager),
        "showSettings" => Some(Window::Settings),
        "showKeystoreExplorer" => Some(Window::KeystoreExplorer),
        "showAdesSigning" => Some(Window::AdesSigning),
        "showAdesValidation" => Some(Window::AdesValidation),
        _ => return Err("java.lang.NoSuchMethodException".to_owned()),
    };
    if let Some(window) = window {
        core.open_window(window);
    }
    if !uuid.is_empty() {
        obj.insert("uuid".to_owned(), json!(uuid));
    }
    Ok(Value::Object(obj).to_string())
}

/// The reply to a failure of [`handle`].
pub fn failure(exception: &str) -> String {
    json!({ "errorCode": exception }).to_string()
}

/// `org.json.JSONException.toString()`.
fn json_exception(message: &str) -> String {
    format!("org.json.JSONException: {message}")
}
