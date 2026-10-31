//! `kz.gov.pki.ncalayerservices.accessory`: bundles, services, bundle installation requests,
//! the windows and failures.

use oncl_builtin_tests::accessory::{
    Accessory, Bundles, MODULE_NAME, SYMNAME, UiCallback, UiRequest,
};
use oncl_protocol::{AddInfo, Module};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// Plugins serving `services`, porting `bundles`, and offering `offered` symnames; the
/// installs asked for.
#[derive(Default)]
struct FakeBundles {
    services: Mutex<Vec<String>>,
    bundles: Mutex<Vec<(String, String)>>,
    offered: Mutex<Vec<String>>,
    requested: Mutex<Vec<(String, String)>>,
}

impl Bundles for FakeBundles {
    fn services(&self) -> Vec<String> {
        self.services.lock().unwrap().clone()
    }

    fn bundles(&self) -> Vec<(String, String)> {
        self.bundles.lock().unwrap().clone()
    }

    fn request_install(&self, symname: &str, origin: &str) -> bool {
        self.requested
            .lock()
            .unwrap()
            .push((symname.to_owned(), origin.to_owned()));
        self.offered.lock().unwrap().iter().any(|s| s == symname)
    }
}

type Seen = Arc<Mutex<Vec<UiRequest>>>;

/// The built-in modules as the daemon gives them: sorted.
const BUILTINS: [&str; 4] = [
    "kz.gov.pki.knca.applet.Applet",
    "kz.gov.pki.knca.basics",
    "kz.gov.pki.knca.commonUtils",
    MODULE_NAME,
];

/// What `getServices` lists of [`BUILTINS`] on the system the tests run on: the original's
/// order there.
const SERVICES: &str = if cfg!(windows) {
    r#""kz.gov.pki.knca.basics","kz.gov.pki.knca.applet.Applet","kz.gov.pki.knca.commonUtils","kz.gov.pki.ncalayerservices.accessory""#
} else {
    r#""kz.gov.pki.knca.applet.Applet","kz.gov.pki.ncalayerservices.accessory","kz.gov.pki.knca.basics","kz.gov.pki.knca.commonUtils""#
};

fn module_with(plugins: Arc<FakeBundles>) -> (Accessory, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let ui: UiCallback = Arc::new(move |r| log.lock().unwrap().push(r));
    let services = BUILTINS.map(str::to_owned).to_vec();
    (Accessory::new(services, plugins, ui), seen)
}

/// Without plugins.
fn module() -> (Accessory, Seen) {
    module_with(Arc::default())
}

/// The reply's text.
fn call_text(m: &Accessory, request: &str, origin: Option<&str>) -> String {
    let add_info = AddInfo {
        origin: origin.map(str::to_owned),
        ..AddInfo::default()
    };
    m.process(request, &add_info).text().unwrap().to_owned()
}

fn call(m: &Accessory, request: Value, origin: Option<&str>) -> Value {
    serde_json::from_str(&call_text(m, &request.to_string(), origin)).unwrap()
}

fn not_found(symname: &str) -> UiRequest {
    UiRequest::InstallBundle {
        symname: symname.to_owned(),
        origin: "https://example.kz".to_owned(),
    }
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

/// The keys of `getBundles` in the order of the original's `HashMap`, which the `uuid` goes
/// into too; within a bucket, in the order they went in: the original's bundles, OpenNCALayer,
/// the plugins' bundles, the `uuid`.
#[test]
fn get_bundles_in_hashmap_order() {
    let plugins = Arc::new(FakeBundles::default());
    *plugins.bundles.lock().unwrap() = vec![
        ("kz.example.echo".to_owned(), "1.0.0".to_owned()),
        ("kz.example.alpha".to_owned(), "2.1.0".to_owned()),
    ];
    let (m, _) = module_with(plugins);
    assert_eq!(
        call_text(&m, r#"{"method":"getBundles","uuid":"u-1"}"#, None),
        concat!(
            r#"{"kz.gov.pki.osgi.layer.common":"0.3.4","#,
            r#""org.apache.felix.framework":"7.0.3","#,
            r#""kz.gov.pki.api.layer.NCALayerServices":"0.8.3","#,
            r#""kz.example.echo":"1.0.0","#,
            r#""kz.gov.pki.knca.applet.knca_applet":"0.4.13","#,
            r#""kz.gov.pki.kalkan.xmldsig":"0.5.2","#,
            r#""io.github.arynyklas.openncalayer":""#,
            env!("CARGO_PKG_VERSION"),
            r#"","kz.gov.pki.provider.knca_provider_util":"0.9.2","#,
            r#""kz.gov.pki.kalkan.knca_provider_jce_kalkan":"0.7.8","#,
            r#""kz.gov.pki.osgi.layer.websocket":"0.4.3","#,
            r#""uuid":"u-1","#,
            r#""kz.example.alpha":"2.1.0"}"#,
        )
    );
}

/// The built-in modules in the order the original lists them on this system (Windows:
/// basics, Applet, commonUtils, accessory; Linux and macOS: Applet, accessory, basics,
/// commonUtils), then the plugins' modules, sorted; `uuid` last.
#[test]
fn get_services_bytes() {
    let plugins = Arc::new(FakeBundles::default());
    let (m, _) = module_with(Arc::clone(&plugins));
    assert_eq!(
        call_text(&m, r#"{"method":"getServices"}"#, None),
        format!(r#"{{"services":[{SERVICES}]}}"#)
    );
    assert_eq!(
        call_text(&m, r#"{"method":"getServices","uuid":"u-1"}"#, None),
        format!(r#"{{"services":[{SERVICES}],"uuid":"u-1"}}"#)
    );
    *plugins.services.lock().unwrap() =
        vec!["kz.example.Zeta".to_owned(), "kz.example.Alpha".to_owned()];
    assert_eq!(
        call_text(&m, r#"{"method":"getServices","uuid":"u-1"}"#, None),
        format!(r#"{{"services":[{SERVICES},"kz.example.Alpha","kz.example.Zeta"],"uuid":"u-1"}}"#)
    );
}

#[test]
fn install_bundle() {
    let (m, seen) = module();
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
    // Only a bundle that could have been installed tells the daemon.
    assert_eq!(*seen.lock().unwrap(), [not_found("kz.x"), not_found("5")]);
}

#[test]
fn empty_symname_checked_before_origin() {
    let plugins = Arc::new(FakeBundles::default());
    let (m, seen) = module_with(Arc::clone(&plugins));
    assert_eq!(
        call(&m, json!({"method": "installBundle", "symname": ""}), None),
        json!({"errorCode": "SYMNAME_PARAMETER_IS_EMPTY"})
    );
    // The origin is checked before the plugins are asked.
    assert_eq!(
        call(
            &m,
            json!({"method": "installBundle", "symname": "kz.x"}),
            None
        ),
        json!({"errorCode": "org.json.JSONException: JSONObject[\"origin\"] is not a string."})
    );
    assert!(plugins.requested.lock().unwrap().is_empty());
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn install_bundle_found_returns_none_and_requests_install() {
    let plugins = Arc::new(FakeBundles::default());
    plugins
        .offered
        .lock()
        .unwrap()
        .push("kz.example.echo".to_owned());
    let (m, seen) = module_with(Arc::clone(&plugins));
    assert_eq!(
        call(
            &m,
            json!({"method": "installBundle", "symname": "kz.example.echo", "uuid": "u"}),
            Some("https://example.kz")
        ),
        json!({"errorCode": "NONE", "uuid": "u"})
    );
    assert_eq!(
        *plugins.requested.lock().unwrap(),
        [(
            "kz.example.echo".to_owned(),
            "https://example.kz".to_owned()
        )]
    );
    // No hint: the daemon asks the user instead.
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn install_bundle_not_found_keeps_code_and_hint() {
    let plugins = Arc::new(FakeBundles::default());
    plugins
        .offered
        .lock()
        .unwrap()
        .push("kz.example.echo".to_owned());
    let (m, seen) = module_with(Arc::clone(&plugins));
    assert_eq!(
        call(
            &m,
            json!({"method": "installBundle", "symname": "kz.other", "uuid": "u"}),
            Some("https://example.kz")
        ),
        json!({"errorCode": "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED", "uuid": "u"})
    );
    assert_eq!(*seen.lock().unwrap(), [not_found("kz.other")]);
    assert_eq!(plugins.requested.lock().unwrap().len(), 1);
}

#[test]
fn long_strings_reach_the_module_as_sent() {
    // The core keeps no data for accessory: its replies and windows show the page's text.
    let (m, seen) = module();
    let blank = " ".repeat(64 << 10);
    assert_eq!(
        call(
            &m,
            json!({"method": "installBundle", "symname": blank}),
            Some("https://example.kz")
        ),
        json!({"errorCode": "SYMNAME_PARAMETER_IS_EMPTY"})
    );
    assert!(seen.lock().unwrap().is_empty());
    let plugins = Arc::new(FakeBundles::default());
    let (m, seen) = module_with(Arc::clone(&plugins));
    let long = "kz.".to_owned() + &"x".repeat(64 << 10);
    let uuid = "u".repeat(32 << 10);
    assert_eq!(
        call(
            &m,
            json!({"method": "installBundle", "symname": long, "uuid": uuid}),
            Some("https://example.kz")
        ),
        json!({"errorCode": "BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED", "uuid": uuid})
    );
    assert_eq!(*seen.lock().unwrap(), [not_found(&long)]);
    assert_eq!(plugins.requested.lock().unwrap()[0].0, long);
}

#[test]
fn get_bundles_includes_plugin_replaces() {
    let plugins = Arc::new(FakeBundles::default());
    let (m, _) = module_with(Arc::clone(&plugins));
    *plugins.bundles.lock().unwrap() = vec![
        ("kz.example.echo".to_owned(), "1.0.0".to_owned()),
        // A core bundle's name keeps the core's version.
        ("kz.gov.pki.kalkan.xmldsig".to_owned(), "9.9.9".to_owned()),
    ];
    let reply = call(&m, json!({"method": "getBundles"}), None);
    let obj = reply.as_object().unwrap();
    assert_eq!(obj.len(), 10);
    assert_eq!(obj["kz.example.echo"], "1.0.0");
    assert_eq!(obj["kz.gov.pki.kalkan.xmldsig"], "0.5.2");
    plugins.bundles.lock().unwrap().clear();
    let reply = call(&m, json!({"method": "getBundles"}), None);
    assert!(reply.get("kz.example.echo").is_none());
}

#[test]
fn get_services_is_live() {
    let plugins = Arc::new(FakeBundles::default());
    let (m, _) = module_with(Arc::clone(&plugins));
    *plugins.services.lock().unwrap() = vec![
        "io.example.Plugin".to_owned(),
        "kz.gov.pki.knca.basics".to_owned(),
    ];
    // A plugin's module of a built-in name is listed once, in the built-in place.
    assert_eq!(
        call_text(&m, r#"{"method":"getServices"}"#, None),
        format!(r#"{{"services":[{SERVICES},"io.example.Plugin"]}}"#)
    );
    plugins.services.lock().unwrap().clear();
    assert_eq!(
        call_text(&m, r#"{"method":"getServices"}"#, None),
        format!(r#"{{"services":[{SERVICES}]}}"#)
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
    for (method, _) in &methods {
        assert_eq!(call(&m, json!({"method": method}), None), json!({}));
    }
    assert_eq!(
        call(&m, json!({"method": "showSettings", "uuid": "u"}), None),
        json!({"uuid": "u"})
    );
    let mut expected: Vec<UiRequest> = methods.iter().map(|(_, r)| r.clone()).collect();
    expected.push(UiRequest::Settings);
    assert_eq!(*seen.lock().unwrap(), expected);
}

/// `errorCode`, then `uuid` when the request has one.
#[test]
fn install_bundle_codes_bytes() {
    let plugins = Arc::new(FakeBundles::default());
    plugins
        .offered
        .lock()
        .unwrap()
        .push("kz.example.echo".to_owned());
    let (m, _) = module_with(plugins);
    let origin = Some("https://example.kz");
    for (request, reply) in [
        (
            r#"{"method":"installBundle","symname":"","uuid":"u-1"}"#,
            r#"{"errorCode":"SYMNAME_PARAMETER_IS_EMPTY","uuid":"u-1"}"#,
        ),
        (
            r#"{"method":"installBundle","symname":"   "}"#,
            r#"{"errorCode":"SYMNAME_PARAMETER_IS_EMPTY"}"#,
        ),
        (
            r#"{"method":"installBundle","symname":"kz.example.echo","uuid":"u-1"}"#,
            r#"{"errorCode":"NONE","uuid":"u-1"}"#,
        ),
        (
            r#"{"method":"installBundle","symname":"kz.example.echo"}"#,
            r#"{"errorCode":"NONE"}"#,
        ),
        (
            r#"{"method":"installBundle","symname":"kz.example.other","uuid":"u-1"}"#,
            r#"{"errorCode":"BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED","uuid":"u-1"}"#,
        ),
        (
            r#"{"method":"installBundle","symname":5}"#,
            r#"{"errorCode":"BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED"}"#,
        ),
        (r#"{"method":"showSettings"}"#, "{}"),
        (
            r#"{"method":"showBundleManager","uuid":"u-1"}"#,
            r#"{"uuid":"u-1"}"#,
        ),
    ] {
        assert_eq!(call_text(&m, request, origin), reply, "{request}");
    }
}

/// A failure is `{"errorCode": <exception>}`, without the request's `uuid`.
#[test]
fn errors_bytes() {
    let (m, seen) = module();
    for (request, reply) in [
        (
            r#"{"method":"nope","uuid":"u-1"}"#,
            r#"{"errorCode":"java.lang.NoSuchMethodException"}"#,
        ),
        (
            r#"{"uuid":"u-1"}"#,
            r#"{"errorCode":"org.json.JSONException: JSONObject[\"method\"] not found."}"#,
        ),
        (
            r#"{"method":null}"#,
            r#"{"errorCode":"org.json.JSONException: JSONObject[\"method\"] is not a string."}"#,
        ),
        (
            r#"{"method":42,"uuid":"u-1"}"#,
            r#"{"errorCode":"org.json.JSONException: JSONObject[\"method\"] is not a string."}"#,
        ),
        (
            r#"{"method":"installBundle","symname":"kz.example.echo","uuid":"u-1"}"#,
            r#"{"errorCode":"org.json.JSONException: JSONObject[\"origin\"] is not a string."}"#,
        ),
    ] {
        assert_eq!(call_text(&m, request, None), reply, "{request}");
    }
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
