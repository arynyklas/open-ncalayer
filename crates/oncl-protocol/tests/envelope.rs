use std::sync::{Arc, Mutex};

use oncl_protocol::orgjson::MAX_DEPTH;
use oncl_protocol::{
    AddInfo, COMPAT_VERSION, DEFAULT_MODULE, DynamicModules, HEARTBEAT, Module, Registry, Reply,
    Route, SessionId, greeting, module_not_found,
};

/// Answers every request with a fixed tag, so tests can tell modules apart.
struct Tagged(&'static str);

impl Module for Tagged {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        format!(
            "{}|{}|{}",
            self.0,
            request,
            add_info.origin.as_deref().unwrap_or("-")
        )
        .into()
    }
}

fn module(tag: &'static str) -> Arc<dyn Module> {
    Arc::new(Tagged(tag))
}

/// Routes `text` and returns `<tag>|<request the module gets>` of the selected module, or
/// the route kind.
fn routed_request(registry: &Registry, text: &str) -> String {
    match registry.route(text) {
        Route::Heartbeat => "heartbeat".into(),
        Route::NotFound { .. } => "not-found".into(),
        Route::InvalidJson => "invalid-json".into(),
        Route::Module { module, request } => {
            let reply = module.process(request, &AddInfo::default());
            let reply = reply.into_text().unwrap();
            reply.rsplit_once('|').unwrap().0.to_owned()
        }
    }
}

/// Routes `text` and returns the tag of the selected module, or the route kind.
fn routed(registry: &Registry, text: &str) -> String {
    let routed = routed_request(registry, text);
    match routed.split_once('|') {
        Some((tag, _)) => tag.to_owned(),
        None => routed,
    }
}

#[test]
fn reply_from_string_is_text() {
    let reply = Reply::from("{}".to_owned());
    assert_eq!(reply, Reply::Text("{}".to_owned()));
    assert_eq!(reply.text(), Some("{}"));
    assert_eq!(reply, "{}");
    assert_eq!(Reply::Drop.text(), None);
    assert_eq!(Reply::Drop.into_text(), None);
}

#[test]
fn constants() {
    assert_eq!(COMPAT_VERSION, "1.4");
    assert_eq!(HEARTBEAT, "--heartbeat--");
    assert_eq!(DEFAULT_MODULE, "kz.gov.pki.knca.applet.Applet");
}

#[test]
fn greeting_bytes() {
    assert_eq!(greeting(), r#"{"result":{"version":"1.4"}}"#);
}

/// The same bytes for every request, without its `uuid`.
#[test]
fn module_not_found_bytes() {
    assert_eq!(
        module_not_found(),
        r#"{"success":false,"errorCode":"MODULE_NOT_FOUND"}"#
    );
    let r = Registry::default();
    assert_eq!(
        routed(
            &r,
            r#"{"module":"kz.test.absent","method":"x","uuid":"u-1"}"#
        ),
        "not-found"
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

/// Only the exact text is the heartbeat; its variants are ordinary text.
#[test]
fn heartbeat_is_exact_text() {
    let mut r = Registry::default();
    assert!(r.register(DEFAULT_MODULE, module("applet")));
    assert_eq!(routed(&r, " --heartbeat--"), "invalid-json");
    assert_eq!(routed(&r, "--heartbeat--\n"), "invalid-json");
    assert_eq!(routed(&r, "--HEARTBEAT--"), "invalid-json");
    assert_eq!(routed(&r, r#""--heartbeat--""#), "invalid-json");
    assert_eq!(routed(&r, r#"{"module":"--heartbeat--"}"#), "not-found");
    assert_eq!(routed(&r, r#"{"method":"--heartbeat--"}"#), "applet");
}

/// A frame that is JSON but not an object is dropped like any text that is not JSON.
#[test]
fn non_object_json_routes_as_observed() {
    let mut r = Registry::default();
    assert!(r.register(DEFAULT_MODULE, module("applet")));
    for text in ["[]", r#""s""#, "1", "null", "true", r#"{"module":"#, ""] {
        assert_eq!(routed(&r, text), "invalid-json", "{text:?}");
    }
}

/// A key repeated in an object is org.json's `Duplicate key` error: the frame is dropped
/// whichever of the values names a module, and also for keys other than `module` and in
/// nested objects.
#[test]
fn duplicate_module_key_routes_as_observed() {
    let mut r = Registry::default();
    assert!(r.register("kz.test.m", module("m")));
    for text in [
        r#"{"module":"kz.test.absent","module":"kz.test.m","method":"x"}"#,
        r#"{"module":"kz.test.m","module":"kz.test.absent","method":"x"}"#,
        r#"{"module":"kz.test.m","module":"kz.test.m"}"#,
        r#"{"module":"kz.test.m","method":"x","method":"y"}"#,
        r#"{"module":"kz.test.m","args":{"a":1,"a":2}}"#,
        r#"{"module":"kz.test.m","args":[{"a":1,"a":1}]}"#,
        r#"{"module":"kz.test.m","\u006dodule":"kz.test.m"}"#,
    ] {
        assert_eq!(routed(&r, text), "invalid-json", "{text}");
    }
    // The same key in different objects is no repeat.
    assert_eq!(
        routed(
            &r,
            r#"{"module":"kz.test.m","args":{"module":1,"a":{"module":2}}}"#
        ),
        "m"
    );
}

/// A byte order mark before the object is not JSON to org.json. Text after the object is
/// not read: the module gets the object alone, and a second object is ignored.
#[test]
fn bom_and_trailing_text_route_as_observed() {
    let mut r = Registry::default();
    assert!(r.register("kz.test.m", module("m")));
    let request = r#"{"module":"kz.test.m","method":"x","args":[]}"#;
    assert_eq!(routed(&r, &format!("\u{feff}{request}")), "invalid-json");
    for text in [
        format!("{request} x"),
        format!("{request}{{}}"),
        format!("{request}{{\"module\":\"kz.test.absent\"}}"),
        format!("{request}}}]"),
        format!("{request}\u{feff}"),
    ] {
        assert_eq!(routed_request(&r, &text), format!("m|{request}"), "{text}");
    }
    // Whitespace before the object is part of the request.
    assert_eq!(
        routed_request(&r, &format!(" \r\n{request}\n")),
        format!("m| \r\n{request}")
    );
    // A name escaped in the request is the module's name.
    let escaped = r#"{"module":"kz.test.\u006d","method":"x"}"#;
    assert_eq!(routed_request(&r, escaped), format!("m|{escaped}"));
    // A first object org.json cannot read is not saved by a second one.
    assert_eq!(
        routed(&r, r#"{"module" "kz.test.m"} {"module":"kz.test.m"}"#),
        "invalid-json"
    );
}

/// The frame is read as org.json reads it: its leniency routes too.
#[test]
fn lenient_org_json_routes() {
    let mut r = Registry::default();
    assert!(r.register("kz.test.m", module("m")));
    assert_eq!(routed(&r, "{'module':'kz.test.m'}"), "m");
    assert_eq!(routed(&r, "{module:kz.test.m}"), "m");
    assert_eq!(routed(&r, r#"{"module":"kz.test.m";"method":"x",}"#), "m");
    assert_eq!(routed(&r, r#"{"module":"kz.test.m",} x"#), "m");
}

/// Deep nesting is no crash: up to [`MAX_DEPTH`] levels, the outer object included, it
/// routes, as deep as `serde_json` reads; one level more, and far more, the frame is
/// dropped.
#[test]
fn deep_nesting_is_dropped_not_overflowed() {
    let mut r = Registry::default();
    assert!(r.register("kz.test.m", module("m")));
    // `depth` levels in all.
    let nested = |depth: usize| {
        format!(
            r#"{{"module":"kz.test.m","args":{}{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        )
    };
    assert_eq!(routed(&r, &nested(MAX_DEPTH)), "m");
    assert!(serde_json::from_str::<serde_json::Value>(&nested(MAX_DEPTH)).is_ok());
    assert_eq!(routed(&r, &nested(MAX_DEPTH + 1)), "invalid-json");
    assert!(serde_json::from_str::<serde_json::Value>(&nested(MAX_DEPTH + 1)).is_err());
    assert_eq!(routed(&r, &nested(100_000)), "invalid-json");
    assert_eq!(
        routed(
            &r,
            &format!(
                r#"{{"module":"kz.test.m","args":{}"#,
                "{\"a\":".repeat(100_000)
            )
        ),
        "invalid-json"
    );
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
    for module in ["7", "1.5", "true", "[\"kz.gov.pki.knca.basics\"]", "{}"] {
        assert_eq!(
            routed(&r, &format!(r#"{{"module":{module}}}"#)),
            "not-found",
            "{module}"
        );
    }
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
    let Route::Module { module, request } = r.route(text) else {
        panic!("module not routed")
    };
    assert_eq!(request, text);
    let add_info = AddInfo {
        origin: Some("https://example.kz".into()),
        ..AddInfo::default()
    };
    assert_eq!(
        module.process(request, &add_info),
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
