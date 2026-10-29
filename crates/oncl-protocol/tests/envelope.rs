use std::sync::{Arc, Mutex};

use oncl_protocol::{
    AddInfo, COMPAT_VERSION, DEFAULT_MODULE, DynamicModules, HEARTBEAT, Module, Registry, Route,
    SessionId, greeting, module_not_found,
};

/// Answers every request with a fixed tag, so tests can tell modules apart.
struct Tagged(&'static str);

impl Module for Tagged {
    fn process(&self, request: &str, add_info: &AddInfo) -> String {
        format!(
            "{}|{}|{}",
            self.0,
            request,
            add_info.origin.as_deref().unwrap_or("-")
        )
    }
}

fn module(tag: &'static str) -> Arc<dyn Module> {
    Arc::new(Tagged(tag))
}

/// Routes `text` and returns the tag of the selected module, or the route kind.
fn routed(registry: &Registry, text: &str) -> String {
    match registry.route(text) {
        Route::Heartbeat => "heartbeat".into(),
        Route::NotFound { .. } => "not-found".into(),
        Route::InvalidJson => "invalid-json".into(),
        Route::Module(m) => m
            .process("", &AddInfo::default())
            .split('|')
            .next()
            .unwrap()
            .into(),
    }
}

#[test]
fn constants() {
    assert_eq!(COMPAT_VERSION, "1.4");
    assert_eq!(HEARTBEAT, "--heartbeat--");
    assert_eq!(DEFAULT_MODULE, "kz.gov.pki.knca.applet.Applet");
}

#[test]
fn greeting_exact() {
    assert_eq!(greeting(), r#"{"result":{"version":"1.4"}}"#);
}

#[test]
fn module_not_found_exact() {
    assert_eq!(
        module_not_found(),
        r#"{"success":false,"errorCode":"MODULE_NOT_FOUND"}"#
    );
}

#[test]
fn heartbeat_and_default_module() {
    let empty = Registry::default();
    assert!(matches!(empty.route("--heartbeat--"), Route::Heartbeat));
    assert!(matches!(
        empty.route(r#"{"method":"x"}"#),
        Route::NotFound { module: None }
    ));
    assert!(matches!(empty.route("[1]"), Route::InvalidJson));
    assert!(matches!(empty.route("nope"), Route::InvalidJson));

    let mut r = Registry::default();
    assert!(r.register(DEFAULT_MODULE, module("applet")));
    assert_eq!(routed(&r, r#"{"method":"x"}"#), "applet");
    assert_eq!(routed(&r, r#"{"module":null,"method":"x"}"#), "applet");
}

#[test]
fn heartbeat_is_exact_text() {
    let r = Registry::default();
    assert_eq!(routed(&r, " --heartbeat--"), "invalid-json");
    assert_eq!(routed(&r, "--heartbeat--\n"), "invalid-json");
    assert_eq!(routed(&r, r#""--heartbeat--""#), "invalid-json");
}

#[test]
fn routes_by_module_field() {
    let mut r = Registry::default();
    assert!(r.register(DEFAULT_MODULE, module("applet")));
    assert!(r.register("kz.gov.pki.knca.basics", module("basics")));
    assert_eq!(
        routed(&r, r#"{"module":"kz.gov.pki.knca.basics","method":"sign"}"#),
        "basics"
    );
    assert_eq!(
        routed(&r, r#"{"module":"kz.gov.pki.knca.commonUtils"}"#),
        "not-found"
    );
    assert_eq!(routed(&r, r#"{"module":7}"#), "not-found");
    assert_eq!(routed(&r, "{}"), "applet");
    assert_eq!(
        routed(&r, r#"{"module":"kz.gov.pki.knca.basics""#),
        "invalid-json"
    );
    assert_eq!(routed(&r, "null"), "invalid-json");
    assert_eq!(routed(&r, r#""text""#), "invalid-json");
    assert_eq!(routed(&r, ""), "invalid-json");
}

#[test]
fn first_registration_wins() {
    let mut r = Registry::default();
    assert!(r.register("m", module("a")));
    assert!(!r.register("m", module("b")));
    assert_eq!(routed(&r, r#"{"module":"m"}"#), "a");
}

#[test]
fn module_receives_raw_request_and_add_info() {
    let mut r = Registry::default();
    assert!(r.register("m", module("a")));
    let text = r#"{"module":"m", "uuid":"u"}"#;
    let Route::Module(m) = r.route(text) else {
        panic!("module not routed")
    };
    let add_info = AddInfo {
        origin: Some("https://example.kz".into()),
        ..AddInfo::default()
    };
    assert_eq!(
        m.process(text, &add_info),
        format!("a|{text}|https://example.kz")
    );
}

/// Dynamic modules keyed by name; records closed sessions.
#[derive(Default)]
struct Dynamic {
    modules: Vec<(&'static str, Arc<dyn Module>)>,
    closed: Mutex<Vec<SessionId>>,
}

impl DynamicModules for Dynamic {
    fn module(&self, name: &str) -> Option<Arc<dyn Module>> {
        self.modules
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, m)| Arc::clone(m))
    }

    fn names(&self) -> Vec<String> {
        self.modules.iter().map(|(n, _)| (*n).to_owned()).collect()
    }

    fn session_closed(&self, session: SessionId) {
        self.closed.lock().unwrap().push(session);
    }

    fn missing(&self, _name: &str, _add_info: &AddInfo) {}
}

fn with_dynamic(builtin: &[&'static str], dynamic: &[&'static str]) -> (Registry, Arc<Dynamic>) {
    let mut r = Registry::default();
    for name in builtin {
        assert!(r.register(name, module("builtin")));
    }
    let d = Arc::new(Dynamic {
        modules: dynamic.iter().map(|n| (*n, module("dynamic"))).collect(),
        ..Dynamic::default()
    });
    r.set_dynamic(Arc::clone(&d) as Arc<dyn DynamicModules>);
    (r, d)
}

#[test]
fn dynamic_module_is_routed() {
    let (r, _) = with_dynamic(&["a"], &["x.Y"]);
    assert_eq!(routed(&r, r#"{"module":"x.Y"}"#), "dynamic");
    assert_eq!(routed(&r, r#"{"module":"a"}"#), "builtin");
    assert_eq!(routed(&r, r#"{"module":"z"}"#), "not-found");
}

#[test]
fn builtin_wins_over_dynamic_with_same_name() {
    let (r, _) = with_dynamic(&["m"], &["m"]);
    assert_eq!(routed(&r, r#"{"module":"m"}"#), "builtin");
}

#[test]
fn names_merge_builtin_and_dynamic_sorted_unique() {
    let (r, _) = with_dynamic(&["b", "d"], &["c", "b", "a"]);
    assert_eq!(r.names(), ["a", "b", "c", "d"]);
}

#[test]
fn not_found_carries_module_name() {
    let r = Registry::default();
    match r.route(r#"{"module":"x.Y"}"#) {
        Route::NotFound { module } => assert_eq!(module.as_deref(), Some("x.Y")),
        _ => panic!("not routed as not found"),
    }
    assert!(matches!(
        r.route(r#"{"module":5}"#),
        Route::NotFound { module: None }
    ));
}

#[test]
fn session_closed_reaches_dynamic() {
    Registry::default().session_closed(7);
    let (r, d) = with_dynamic(&[], &[]);
    r.session_closed(7);
    r.session_closed(9);
    assert_eq!(*d.closed.lock().unwrap(), [7, 9]);
}
