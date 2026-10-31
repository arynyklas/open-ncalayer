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
//!   version), and of the original bundles the enabled plugins port: a `HashMap` the `uuid`
//!   goes into too, so the keys are in its order ([`oncl_pdk::javamap`]);
//! - `getServices`: `{"services": [module names]}`: the daemon's built-in modules, those the
//!   original has in the order it lists them on the core's system ([`original_services`]),
//!   then those of its plugins now, sorted;
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
//! The replies but `getBundles` are written in the order of their keys, `uuid` last, as the
//! original's `JSONStringer` writes them. Any failure is `{"errorCode":"<exception.toString()>"}`
//! without `uuid`.

pub mod reply;

#[cfg(target_arch = "wasm32")]
mod guest;

pub use reply::{CORE_BUNDLES, MODULE_NAME, SYMNAME, bundles, original_services};

use oncl_pdk::abi::{CoreBundles, CoreModules, Os, Window};
use oncl_pdk::orgjson::{JObject, JValue, get_string, opt_string};
use oncl_pdk::serde_json::{Map, Value};

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
    /// The system the core runs on.
    fn os(&self) -> Os;
}

/// The reply to `request`: the object, or the exception the original's reply names.
pub fn handle(core: &impl Core, request: &str) -> Result<String, String> {
    let request: Map<String, Value> = oncl_pdk::serde_json::from_str(request).map_err(|_| {
        json_exception("A JSONObject text must begin with '{' at 1 [character 2 line 1]")
    })?;
    let method = get_string(&request, "method").map_err(|e| json_exception(&e))?;
    let uuid = opt_string(&request, "uuid").unwrap_or_default();
    let mut reply = JObject::stringer();
    let window = match method {
        "getBundles" => {
            reply = get_bundles(core.bundles());
            None
        }
        "getServices" => {
            let services = get_services(core.modules(), core.os());
            reply.put("services", services);
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
            reply.put("errorCode", code);
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
        reply.put("uuid", uuid);
    }
    Ok(reply.to_json())
}

/// `getBundles`: a `new HashMap()` of the bundles, in the order they go in; a plugin's
/// bundle of a name already present does not replace it.
fn get_bundles(bundles: CoreBundles) -> JObject {
    let mut reply = JObject::hash_map();
    for (symname, version) in CORE_BUNDLES {
        reply.put(symname, version);
    }
    reply.put(SYMNAME, bundles.core_version);
    for (symname, version) in bundles.plugins {
        if reply.get(&symname).is_none() {
            reply.put(symname, version);
        }
    }
    reply
}

/// `getServices`: the built-in modules the original has in its order on `os`, then the other
/// built-in ones as given (sorted), then the plugins' sorted, each once.
fn get_services(modules: CoreModules, os: Os) -> Vec<JValue> {
    let original = original_services(os);
    let mut services = modules.builtin;
    // Stable: the names the original lacks keep their order, after its own.
    services.sort_by_key(|name| {
        original
            .iter()
            .position(|o| o == name)
            .unwrap_or(original.len())
    });
    let mut plugins: Vec<String> = modules
        .plugins
        .into_iter()
        .filter(|name| !services.contains(name))
        .collect();
    plugins.sort_unstable();
    plugins.dedup();
    services.extend(plugins);
    services.into_iter().map(JValue::from).collect()
}

/// The reply to a failure of [`handle`].
pub fn failure(exception: &str) -> String {
    JObject::stringer().put("errorCode", exception).to_json()
}

/// `org.json.JSONException.toString()`.
fn json_exception(message: &str) -> String {
    format!("org.json.JSONException: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A core on `os` with the four built-in modules (sorted, as the daemon gives them) and
    /// the plugins' `plugins`.
    struct OnOs {
        os: Os,
        plugins: Vec<String>,
    }

    impl Core for OnOs {
        fn modules(&self) -> CoreModules {
            CoreModules {
                builtin: vec![
                    "kz.gov.pki.knca.applet.Applet".to_owned(),
                    "kz.gov.pki.knca.basics".to_owned(),
                    "kz.gov.pki.knca.commonUtils".to_owned(),
                    MODULE_NAME.to_owned(),
                ],
                plugins: self.plugins.clone(),
            }
        }

        fn bundles(&self) -> CoreBundles {
            CoreBundles::default()
        }

        fn install_bundle(&self, _: &str) -> Option<bool> {
            None
        }

        fn open_window(&self, _: Window) {}

        fn os(&self) -> Os {
            self.os
        }
    }

    #[test]
    fn get_services_in_the_original_order_of_each_os() {
        let windows = r#"{"services":["kz.gov.pki.knca.basics","kz.gov.pki.knca.applet.Applet","kz.gov.pki.knca.commonUtils","kz.gov.pki.ncalayerservices.accessory"],"uuid":"u-1"}"#;
        let unix = r#"{"services":["kz.gov.pki.knca.applet.Applet","kz.gov.pki.ncalayerservices.accessory","kz.gov.pki.knca.basics","kz.gov.pki.knca.commonUtils"],"uuid":"u-1"}"#;
        let request = r#"{"method":"getServices","uuid":"u-1"}"#;
        for (os, reply) in [(Os::Windows, windows), (Os::Linux, unix), (Os::Macos, unix)] {
            let core = OnOs {
                os,
                plugins: Vec::new(),
            };
            assert_eq!(handle(&core, request).unwrap(), reply, "{os:?}");
        }
        let core = OnOs {
            os: Os::Linux,
            plugins: vec!["kz.example.B".to_owned(), "kz.example.A".to_owned()],
        };
        assert_eq!(
            handle(&core, r#"{"method":"getServices"}"#).unwrap(),
            r#"{"services":["kz.gov.pki.knca.applet.Applet","kz.gov.pki.ncalayerservices.accessory","kz.gov.pki.knca.basics","kz.gov.pki.knca.commonUtils","kz.example.A","kz.example.B"]}"#
        );
    }
}
