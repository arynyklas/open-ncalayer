//! The same requests to both implementations of a module: the same reply bytes, the same
//! windows and the same requests to the daemon.

use oncl_builtin_tests::Backend;
use oncl_builtin_tests::accessory::{Accessory, Bundles, MODULE_NAME, UiRequest};
use oncl_protocol::{AddInfo, Module};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// Plugins serving and porting fixed lists, offering `kz.example.echo`; the installs asked
/// for.
struct Plugins {
    services: Vec<String>,
    bundles: Vec<(String, String)>,
    requested: Mutex<Vec<(String, String)>>,
}

impl Bundles for Plugins {
    fn services(&self) -> Vec<String> {
        self.services.clone()
    }

    fn bundles(&self) -> Vec<(String, String)> {
        self.bundles.clone()
    }

    fn request_install(&self, symname: &str, origin: &str) -> bool {
        let mut requested = self.requested.lock().unwrap();
        requested.push((symname.to_owned(), origin.to_owned()));
        symname == "kz.example.echo"
    }
}

/// What one implementation did with the requests: its replies, its windows, its installs.
type Run = (Vec<String>, Vec<UiRequest>, Vec<(String, String)>);

fn accessory_run(backend: Backend, plugins: bool, requests: &[(Value, Option<&str>)]) -> Run {
    let plugins = Arc::new(if plugins {
        Plugins {
            services: vec![
                "io.example.Plugin".to_owned(),
                "kz.gov.pki.knca.basics".to_owned(),
            ],
            bundles: vec![
                ("kz.example.echo".to_owned(), "1.0.0".to_owned()),
                ("kz.gov.pki.kalkan.xmldsig".to_owned(), "9.9.9".to_owned()),
            ],
            requested: Mutex::default(),
        }
    } else {
        Plugins {
            services: Vec::new(),
            bundles: Vec::new(),
            requested: Mutex::default(),
        }
    });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let services = vec![MODULE_NAME.to_owned(), "kz.gov.pki.knca.basics".to_owned()];
    let m = Accessory::new(
        services,
        Arc::clone(&plugins) as Arc<dyn Bundles>,
        Arc::new(move |r| log.lock().unwrap().push(r)),
    )
    .with_backend(backend);
    let replies = requests
        .iter()
        .map(|(request, origin)| {
            let add_info = AddInfo {
                origin: origin.map(str::to_owned),
                ..AddInfo::default()
            };
            let text = match request {
                Value::String(raw) => raw.clone(),
                other => other.to_string(),
            };
            m.process(&text, &add_info).text().unwrap().to_owned()
        })
        .collect();
    let seen = seen.lock().unwrap().clone();
    let requested = plugins.requested.lock().unwrap().clone();
    (replies, seen, requested)
}

/// Every method and failure of the module's tests.
fn accessory_requests() -> Vec<(Value, Option<&'static str>)> {
    let origin = Some("https://example.kz");
    let mut requests = vec![
        (json!({"method": "getBundles", "uuid": "u1"}), None),
        (json!({"method": "getBundles"}), None),
        (json!({"method": "getServices"}), None),
        (json!({"method": "getServices", "uuid": 7}), None),
        (json!({"method": "installBundle"}), None),
        (
            json!({"method": "installBundle", "symname": "", "uuid": "u"}),
            origin,
        ),
        (json!({"method": "installBundle", "symname": " \t"}), origin),
        (json!({"method": "installBundle", "symname": null}), origin),
        (
            json!({"method": "installBundle", "symname": "kz.x", "uuid": "u"}),
            origin,
        ),
        (json!({"method": "installBundle", "symname": 5}), origin),
        (json!({"method": "installBundle", "symname": "kz.x"}), None),
        (
            json!({"method": "installBundle", "symname": "kz.example.echo"}),
            origin,
        ),
        (json!({"method": "nope", "uuid": "u"}), None),
        (json!({"uuid": "u"}), None),
        (json!({"method": null}), None),
        (json!({"method": 1}), None),
        (json!("[1]"), None),
        (json!("not json"), None),
    ];
    for method in [
        "showBundleManager",
        "showSettings",
        "showKeystoreExplorer",
        "showAdesSigning",
        "showAdesValidation",
    ] {
        requests.push((json!({"method": method}), None));
        requests.push((json!({"method": method, "uuid": "u"}), origin));
    }
    requests
}

#[test]
fn accessory_without_plugins() {
    let requests = accessory_requests();
    assert_eq!(
        accessory_run(Backend::Wasm, false, &requests),
        accessory_run(Backend::Native, false, &requests)
    );
}

#[test]
fn accessory_with_plugins() {
    let requests = accessory_requests();
    assert_eq!(
        accessory_run(Backend::Wasm, true, &requests),
        accessory_run(Backend::Native, true, &requests)
    );
}
