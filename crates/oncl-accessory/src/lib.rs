//! The `kz.gov.pki.ncalayerservices.accessory` module (the original's `NCALayerServices`
//! `AccessoryService`).
//!
//! A request is `{"method", "symname"?, "uuid"?}`; `method` is read with org.json
//! `getString`, `symname` and `uuid` with `optString`. The reply is a JSON object, with the
//! request's `uuid` when it is not empty:
//!
//! - `getBundles`: `{symname: version}` of the original's OSGi framework
//!   (`org.apache.felix.framework`), of its core bundles whose functions this daemon
//!   implements, and of OpenNCALayer itself;
//! - `getServices`: `{"services": [module names]}` of the daemon's registry;
//! - `installBundle`: `SYMNAME_PARAMETER_IS_EMPTY` for an empty `symname`, else
//!   `BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED` (no bundle can be installed); the original reads
//!   the page's `origin` with `getString` from the headers its WebSocket server always writes
//!   as `{"origin": <header or null>}`, so a connection without an `Origin` header fails with
//!   `JSONObject["origin"] is not a string.`;
//! - `showBundleManager`, `showSettings`, `showKeystoreExplorer`, `showAdesSigning`,
//!   `showAdesValidation`: `{}`, after asking the daemon to open the window.
//!
//! Any failure is `{"errorCode":"<exception.toString()>"}` without `uuid`, as the original's
//! `JSONStringer` writes it.

use std::sync::Arc;

use oncl_protocol::orgjson::{get_string, opt_string};
use oncl_protocol::{AddInfo, Module};
use serde_json::{Map, Value, json};
use tracing::{error, info};

/// Name the module is registered under.
pub const MODULE_NAME: &str = "kz.gov.pki.ncalayerservices.accessory";

/// The bundle symbolic name `getBundles` reports OpenNCALayer under.
pub const SYMNAME: &str = "io.github.arynyklas.openncalayer";

/// The bundles the original reports whose functions this daemon implements: its OSGi
/// framework and its core bundles. The versions are what the original's
/// `Bundle.getVersion().toString()` gives (OSGi `major.minor.micro`) once it has updated to
/// the live update manifest (http://crl.pki.gov.kz/updates/ncalayer.der, manifest version
/// 1.4, signed by `ncalayersigner2024_2`); the framework is the Apache Felix both
/// distributions embed (`org/apache/felix/framework/Felix.properties`: `felix.version=7.0.3`).
const CORE_BUNDLES: [(&str, &str); 8] = [
    ("org.apache.felix.framework", "7.0.3"),
    ("kz.gov.pki.api.layer.NCALayerServices", "0.8.3"),
    ("kz.gov.pki.kalkan.knca_provider_jce_kalkan", "0.7.8"),
    ("kz.gov.pki.kalkan.xmldsig", "0.5.2"),
    ("kz.gov.pki.knca.applet.knca_applet", "0.4.13"),
    ("kz.gov.pki.osgi.layer.common", "0.3.4"),
    ("kz.gov.pki.osgi.layer.websocket", "0.4.3"),
    ("kz.gov.pki.provider.knca_provider_util", "0.9.2"),
];

/// What `getBundles` reports, `(symname, version)` in order: the original's framework and
/// core bundles, then OpenNCALayer itself ([`SYMNAME`]). The About window lists them.
pub fn bundles() -> Vec<(&'static str, &'static str)> {
    let mut bundles = CORE_BUNDLES.to_vec();
    bundles.push((SYMNAME, env!("CARGO_PKG_VERSION")));
    bundles
}

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

/// What opens the daemon's windows. It is called synchronously from `Module::process` on a
/// blocking-pool thread, and the page's reply waits for it: it must hand the request to the
/// UI event loop and return at once, not run the window.
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
        let method = get_string(&request, "method").map_err(|e| json_exception(&e))?;
        let uuid = opt_string(&request, "uuid").unwrap_or_default();
        let mut obj = Map::new();
        let ui = match method {
            "getBundles" => {
                for (symname, version) in bundles() {
                    obj.insert(symname.to_owned(), json!(version));
                }
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
                    // No `Origin` header is the original's `{"origin":null}`.
                    let Some(origin) = &add_info.origin else {
                        return Err(json_exception("JSONObject[\"origin\"] is not a string."));
                    };
                    // Bundles cannot be installed until plugin ports exist (D21). Page strings
                    // are logged as `&str` fields, which the log escapes.
                    info!(
                        symname = symname.as_str(),
                        origin = origin.as_str(),
                        "bundle installation requested; not available"
                    );
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
        assert_eq!(obj.len(), 10);
        assert_eq!(obj["org.apache.felix.framework"], "7.0.3");
        assert_eq!(obj["kz.gov.pki.api.layer.NCALayerServices"], "0.8.3");
        assert_eq!(obj["kz.gov.pki.kalkan.knca_provider_jce_kalkan"], "0.7.8");
        assert_eq!(obj["kz.gov.pki.kalkan.xmldsig"], "0.5.2");
        assert_eq!(obj["kz.gov.pki.knca.applet.knca_applet"], "0.4.13");
        assert_eq!(obj["kz.gov.pki.osgi.layer.common"], "0.3.4");
        assert_eq!(obj["kz.gov.pki.osgi.layer.websocket"], "0.4.3");
        assert_eq!(obj["kz.gov.pki.provider.knca_provider_util"], "0.9.2");
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
            json!({"errorCode": "org.json.JSONException: JSONObject[\"origin\"] is not a string."})
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
            call(&m, json!({"method": null}), None),
            json!({"errorCode": "org.json.JSONException: JSONObject[\"method\"] is not a string."})
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
