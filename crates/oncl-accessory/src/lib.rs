//! The `kz.gov.pki.ncalayerservices.accessory` module (the original's `NCALayerServices`
//! `AccessoryService`).
//!
//! A request is `{"method", "symname"?, "uuid"?}`; `method` is read with org.json
//! `getString`, `symname` and `uuid` with `optString`. The reply is a JSON object, with the
//! request's `uuid` when it is not empty:
//!
//! - `getBundles`: `{symname: version}` of the original's core bundles whose functions this
//!   daemon implements, and of OpenNCALayer itself;
//! - `getServices`: `{"services": [module names]}` of the daemon's registry;
//! - `installBundle`: `SYMNAME_PARAMETER_IS_EMPTY` for an empty `symname`, else
//!   `BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED` (no bundle can be installed); the original reads
//!   the page's `origin` with `getString`, so a request without one fails;
//! - `showBundleManager`, `showSettings`, `showKeystoreExplorer`, `showAdesSigning`,
//!   `showAdesValidation`: `{}`, after asking the daemon to open the window.
//!
//! Any failure is `{"errorCode":"<exception.toString()>"}` without `uuid`, as the original's
//! `JSONStringer` writes it.

use std::sync::Arc;

use oncl_protocol::orgjson::opt_string;
use oncl_protocol::{AddInfo, Module};
use serde_json::{Map, Value, json};
use tracing::{error, info};

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.ncalayerservices.accessory";

/// The bundle symbolic name `getBundles` reports OpenNCALayer under.
pub const SYMNAME: &str = "io.github.arynyklas.openncalayer";

/// The original's core bundles whose functions this daemon implements, with the versions of
/// the original's update manifest `ncalayer.der` (manifest version 1.4, as published at
/// http://crl.pki.gov.kz/updates/ncalayer.der on 2026-10-24).
const CORE_BUNDLES: [(&str, &str); 7] = [
    ("kz.gov.pki.api.layer.NCALayerServices", "0.7.4"),
    ("kz.gov.pki.kalkan.knca_provider_jce_kalkan", "0.7.8"),
    ("kz.gov.pki.kalkan.xmldsig", "0.4"),
    ("kz.gov.pki.knca.applet.knca_applet", "0.4.10"),
    ("kz.gov.pki.osgi.layer.common", "0.3.4"),
    ("kz.gov.pki.osgi.layer.websocket", "0.4.2"),
    ("kz.gov.pki.provider.knca_provider_util", "0.8.8"),
];

/// A window a page asks the daemon to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiRequest {
    /// `showSettings` (the original's proxy settings).
    Settings,
    /// `showBundleManager`.
    BundleManager,
    /// `showKeystoreExplorer`.
    KeystoreExplorer,
    /// `showAdesSigning`.
    AdesSigning,
    /// `showAdesValidation`.
    AdesValidation,
}

/// What opens the daemon's windows.
pub type UiCallback = Arc<dyn Fn(UiRequest) + Send + Sync>;

/// The `kz.gov.pki.ncalayerservices.accessory` module.
pub struct Accessory {
    services: Vec<String>,
    ui: UiCallback,
}

impl Accessory {
    /// The module, reporting `services` as the registered modules and asking `ui` to open
    /// windows.
    pub fn new(services: Vec<String>, ui: UiCallback) -> Self {
        Accessory { services, ui }
    }

    fn handle(&self, request: &str, add_info: &AddInfo) -> Result<Map<String, Value>, String> {
        let request: Map<String, Value> = serde_json::from_str(request).map_err(|_| {
            json_exception("A JSONObject text must begin with '{' at 1 [character 2 line 1]")
        })?;
        let method = match request.get("method") {
            None => return Err(json_exception("JSONObject[\"method\"] not found.")),
            Some(Value::String(m)) => m.as_str(),
            Some(_) => return Err(json_exception("JSONObject[\"method\"] is not a string.")),
        };
        let uuid = opt_string(&request, "uuid").unwrap_or_default();
        let mut obj = Map::new();
        let ui = match method {
            "getBundles" => {
                for (symname, version) in CORE_BUNDLES {
                    obj.insert(symname.to_owned(), json!(version));
                }
                obj.insert(SYMNAME.to_owned(), json!(env!("CARGO_PKG_VERSION")));
                None
            }
            "getServices" => {
                obj.insert("services".to_owned(), json!(self.services));
                None
            }
            "installBundle" => {
                let symname = opt_string(&request, "symname").unwrap_or_default();
                // `String.trim()`: every char up to U+0020.
                let code = if symname.trim_matches(|c| c <= ' ').is_empty() {
                    "SYMNAME_PARAMETER_IS_EMPTY"
                } else {
                    let Some(origin) = &add_info.origin else {
                        return Err(json_exception("JSONObject[\"origin\"] not found."));
                    };
                    // Bundles cannot be installed until plugin ports exist (D21).
                    info!(%symname, %origin, "bundle installation requested; not available");
                    "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED"
                };
                obj.insert("errorCode".to_owned(), json!(code));
                None
            }
            "showBundleManager" => Some(UiRequest::BundleManager),
            "showSettings" => Some(UiRequest::Settings),
            "showKeystoreExplorer" => Some(UiRequest::KeystoreExplorer),
            "showAdesSigning" => Some(UiRequest::AdesSigning),
            "showAdesValidation" => Some(UiRequest::AdesValidation),
            _ => return Err("java.lang.NoSuchMethodException".to_owned()),
        };
        if let Some(window) = ui {
            (self.ui)(window);
        }
        if !uuid.is_empty() {
            obj.insert("uuid".to_owned(), json!(uuid));
        }
        Ok(obj)
    }
}

/// `org.json.JSONException.toString()`.
fn json_exception(message: &str) -> String {
    format!("org.json.JSONException: {message}")
}

impl Module for Accessory {
    fn process(&self, request: &str, add_info: &AddInfo) -> String {
        match self.handle(request, add_info) {
            Ok(obj) => Value::Object(obj).to_string(),
            Err(exception) => {
                error!(%exception, "accessory request failed");
                json!({ "errorCode": exception }).to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn module() -> (Accessory, Arc<Mutex<Vec<UiRequest>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let ui: UiCallback = Arc::new(move |r| log.lock().unwrap().push(r));
        let services = vec![MODULE_NAME.to_owned(), "kz.gov.pki.knca.basics".to_owned()];
        (Accessory::new(services, ui), seen)
    }

    fn call(m: &Accessory, request: Value, origin: Option<&str>) -> Value {
        let add_info = AddInfo {
            origin: origin.map(str::to_owned),
        };
        serde_json::from_str(&m.process(&request.to_string(), &add_info)).unwrap()
    }

    #[test]
    fn get_bundles() {
        let (m, _) = module();
        let reply = call(&m, json!({"method": "getBundles", "uuid": "u1"}), None);
        let obj = reply.as_object().unwrap();
        assert_eq!(obj.len(), 9);
        assert_eq!(obj["kz.gov.pki.api.layer.NCALayerServices"], "0.7.4");
        assert_eq!(obj["kz.gov.pki.kalkan.knca_provider_jce_kalkan"], "0.7.8");
        assert_eq!(obj["kz.gov.pki.kalkan.xmldsig"], "0.4");
        assert_eq!(obj["kz.gov.pki.knca.applet.knca_applet"], "0.4.10");
        assert_eq!(obj["kz.gov.pki.osgi.layer.common"], "0.3.4");
        assert_eq!(obj["kz.gov.pki.osgi.layer.websocket"], "0.4.2");
        assert_eq!(obj["kz.gov.pki.provider.knca_provider_util"], "0.8.8");
        assert_eq!(obj[SYMNAME], env!("CARGO_PKG_VERSION"));
        assert_eq!(obj["uuid"], "u1");
    }

    #[test]
    fn get_services() {
        let (m, _) = module();
        assert_eq!(
            call(&m, json!({"method": "getServices"}), None),
            json!({"services": [MODULE_NAME, "kz.gov.pki.knca.basics"]})
        );
    }

    #[test]
    fn install_bundle() {
        let (m, _) = module();
        let origin = Some("https://example.kz");
        for symname in [json!(""), json!(" \t"), Value::Null] {
            assert_eq!(
                call(
                    &m,
                    json!({"method": "installBundle", "symname": symname, "uuid": "u"}),
                    origin
                ),
                json!({"errorCode": "SYMNAME_PARAMETER_IS_EMPTY", "uuid": "u"})
            );
        }
        // An absent `symname` is empty too, even without an origin.
        assert_eq!(
            call(&m, json!({"method": "installBundle"}), None),
            json!({"errorCode": "SYMNAME_PARAMETER_IS_EMPTY"})
        );
        assert_eq!(
            call(
                &m,
                json!({"method": "installBundle", "symname": "kz.x", "uuid": "u"}),
                origin
            ),
            json!({"errorCode": "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED", "uuid": "u"})
        );
        // A non-string `symname` is its JSON text (`optString`).
        assert_eq!(
            call(&m, json!({"method": "installBundle", "symname": 5}), origin),
            json!({"errorCode": "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED"})
        );
        assert_eq!(
            call(
                &m,
                json!({"method": "installBundle", "symname": "kz.x", "uuid": "u"}),
                None
            ),
            json!({"errorCode": "org.json.JSONException: JSONObject[\"origin\"] not found."})
        );
    }

    #[test]
    fn show_windows() {
        let (m, seen) = module();
        let methods = [
            ("showBundleManager", UiRequest::BundleManager),
            ("showSettings", UiRequest::Settings),
            ("showKeystoreExplorer", UiRequest::KeystoreExplorer),
            ("showAdesSigning", UiRequest::AdesSigning),
            ("showAdesValidation", UiRequest::AdesValidation),
        ];
        for (method, _) in methods {
            assert_eq!(call(&m, json!({"method": method}), None), json!({}));
        }
        assert_eq!(
            call(&m, json!({"method": "showSettings", "uuid": "u"}), None),
            json!({"uuid": "u"})
        );
        let mut expected: Vec<UiRequest> = methods.iter().map(|(_, r)| *r).collect();
        expected.push(UiRequest::Settings);
        assert_eq!(*seen.lock().unwrap(), expected);
    }

    #[test]
    fn failures() {
        let (m, seen) = module();
        assert_eq!(
            call(&m, json!({"method": "nope", "uuid": "u"}), None),
            json!({"errorCode": "java.lang.NoSuchMethodException"})
        );
        assert_eq!(
            call(&m, json!({"uuid": "u"}), None),
            json!({"errorCode": "org.json.JSONException: JSONObject[\"method\"] not found."})
        );
        assert_eq!(
            call(&m, json!({"method": 1}), None),
            json!({"errorCode": "org.json.JSONException: JSONObject[\"method\"] is not a string."})
        );
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn non_string_uuid_is_its_text() {
        let (m, _) = module();
        assert_eq!(
            call(&m, json!({"method": "getServices", "uuid": 7}), None)["uuid"],
            "7"
        );
    }
}
