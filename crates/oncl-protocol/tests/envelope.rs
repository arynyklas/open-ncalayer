use std::sync::Arc;

use oncl_protocol::{
    AddInfo, COMPAT_VERSION, DEFAULT_MODULE, HEARTBEAT, Module, Registry, Route, greeting,
    module_not_found,
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
        Route::NotFound => "not-found".into(),
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
    assert!(matches!(empty.route(r#"{"method":"x"}"#), Route::NotFound));
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
    };
    assert_eq!(
        m.process(text, &add_info),
        format!("a|{text}|https://example.kz")
    );
}
