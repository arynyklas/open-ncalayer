//! The `kz.gov.pki.ncalayerservices.accessory` module (the original's `NCALayerServices`
//! `AccessoryService`).
//!
//! A request is `{"method", "symname"?, "uuid"?}`; `method` is read with org.json
//! `getString`, `symname` and `uuid` with `optString`. The reply is a JSON object, with the
//! request's `uuid` when it is not empty:
//!
//! - `getBundles`: `{symname: version}` of the original's OSGi framework
//!   (`org.apache.felix.framework`), of its core bundles whose functions this daemon
//!   implements, of OpenNCALayer itself, and of the original bundles the enabled plugins
//!   port ([`Bundles::bundles`]);
//! - `getServices`: `{"services": [module names]}`: the daemon's built-in modules and those
//!   of its plugins now ([`Bundles::services`]), sorted;
//! - `installBundle`: `SYMNAME_PARAMETER_IS_EMPTY` for an empty `symname`; then the
//!   original reads the page's `origin` with `getString` from the headers its WebSocket
//!   server always writes as `{"origin": <header or null>}`, so a connection without an
//!   `Origin` header fails with `JSONObject["origin"] is not a string.`; then, as the
//!   original, `NONE` at once if a plugin porting the bundle can be installed (the daemon
//!   asks the user meanwhile, [`Bundles::request_install`]), else
//!   `BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED` after telling the daemon, which shows the user
//!   where plugins are listed;
//! - `showBundleManager`, `showSettings`, `showKeystoreExplorer`, `showAdesSigning`,
//!   `showAdesValidation`: `{}`, after asking the daemon to open the window.
//!
//! Any failure is `{"errorCode":"<exception.toString()>"}` without `uuid`, as the original's
//! `JSONStringer` writes it.

use std::sync::Arc;

use oncl_protocol::orgjson::{get_string, opt_string};
use oncl_protocol::{AddInfo, Module, Reply};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiRequest {
    /// `showSettings` (the original's proxy settings).
    Settings,
    /// `showBundleManager`.
    BundleManager,
    /// `showKeystoreExplorer`.
    KeystoreExplorer,
    /// `showAdesSigning`.
    AdesSigning,
    /// `installBundle` of `symname` by the page `origin`, which no plugin of the catalog
    /// ports (or one is installed already): the daemon points the user to the plugin
    /// registry.
    InstallBundle { symname: String, origin: String },
    /// `showAdesValidation`.
    AdesValidation,
}

/// What opens the daemon's windows. It is called synchronously from `Module::process` on a
/// blocking-pool thread, and the page's reply waits for it: it must hand the request to the
/// UI event loop and return at once, not run the window.
pub type UiCallback = Arc<dyn Fn(UiRequest) + Send + Sync>;

/// The daemon's plugins, as the module reports and installs them.
pub trait Bundles: Send + Sync {
    /// The modules the plugins serve now.
    fn services(&self) -> Vec<String>;
    /// `(symname, version)` of the original bundles the enabled plugins port.
    fn bundles(&self) -> Vec<(String, String)>;
    /// The page `origin` asks to install the bundle `symname`: whether a plugin porting it,
    /// not installed, is offered (its installation, which asks the user, then goes on in
    /// the background). Called on a blocking-pool thread; it may take seconds (the catalog
    /// is downloaded if none is in use).
    fn request_install(&self, symname: &str, origin: &str) -> bool;
}

/// The `kz.gov.pki.ncalayerservices.accessory` module.
pub struct Accessory {
    services: Vec<String>,
    bundles: Arc<dyn Bundles>,
    ui: UiCallback,
}

impl Accessory {
    /// The module, reporting `services` as the built-in modules, with the plugins of
    /// `bundles`, and asking `ui` to open windows.
    pub fn new(services: Vec<String>, bundles: Arc<dyn Bundles>, ui: UiCallback) -> Self {
        Accessory {
            services,
            bundles,
            ui,
        }
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
                for (symname, version) in self.bundles.bundles() {
                    obj.entry(symname).or_insert_with(|| json!(version));
                }
                None
            }
            "getServices" => {
                let plugins = self.bundles.services();
                let mut services = self.services.clone();
                // The built-in ones as given (the daemon gives them sorted); with the
                // plugins' added, sorted again.
                if !plugins.is_empty() {
                    services.extend(plugins);
                    services.sort_unstable();
                    services.dedup();
                }
                obj.insert("services".to_owned(), json!(services));
                None
            }
            "installBundle" => {
                let symname = opt_string(&request, "symname").unwrap_or_default();
                // `String.trim()`: every char up to U+0020.
                let (code, ui) = if symname.trim_matches(|c| c <= ' ').is_empty() {
                    ("SYMNAME_PARAMETER_IS_EMPTY", None)
                } else {
                    // No `Origin` header is the original's `{"origin":null}`.
                    let Some(origin) = &add_info.origin else {
                        return Err(json_exception("JSONObject[\"origin\"] is not a string."));
                    };
                    // Page strings are logged as `&str` fields, which the log escapes.
                    let offered = self.bundles.request_install(&symname, origin);
                    info!(
                        symname = symname.as_str(),
                        origin = origin.as_str(),
                        offered,
                        "bundle installation requested"
                    );
                    if offered {
                        ("NONE", None)
                    } else {
                        (
                            "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED",
                            Some(UiRequest::InstallBundle {
                                symname,
                                origin: origin.clone(),
                            }),
                        )
                    }
                };
                obj.insert("errorCode".to_owned(), json!(code));
                ui
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
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        match self.handle(request, add_info) {
            Ok(obj) => Value::Object(obj).to_string().into(),
            Err(exception) => {
                error!(%exception, "accessory request failed");
                json!({ "errorCode": exception }).to_string().into()
            }
        }
    }
}
