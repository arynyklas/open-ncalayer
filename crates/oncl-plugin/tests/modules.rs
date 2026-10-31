//! The example plugin as a dynamic module: an instance per session, generations replaced
//! under running calls, module names that cannot be taken twice, the instance cap and the
//! memory budget.

mod common;

use common::*;
use oncl_basics::{
    Busy, BusyPrompt, ConfirmPrompt, CsrAnswer, CsrPrompt, FilePrompt, ImportAnswer, ImportPrompt,
    KeyPrompt, MessagePrompt, PasswordPrompt, Prompt, Prompter, SavePrompt, StorageAnswer,
    StoragePrompt,
};
use oncl_plugin::{
    BUILT_IN, Engine, HostServices, LoadError, MAX_INSTANCES, MemoryLimits, PLUGIN_ERROR_REPLY,
    Package, PluginModules,
};
use oncl_protocol::{AddInfo, DynamicModules, Registry, Route, module_not_found};
use oncl_testkit::plugin::{example_package, example_package_with};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

const ID: &str = "io.github.arynyklas.openncalayer.example";
const MODULE: &str = "io.github.arynyklas.openncalayer.Example";

fn example() -> Package {
    Package::read(&example_package()).unwrap()
}

fn modules_with(services: HostServices, builtin: Vec<String>) -> Arc<PluginModules> {
    Arc::new(PluginModules::new(
        Arc::new(Engine::new()),
        services,
        builtin,
    ))
}

fn loaded() -> Arc<PluginModules> {
    let modules = modules_with(services(), Vec::new());
    modules.load(example()).unwrap();
    modules
}

fn request(method: &str, args: Value) -> String {
    json!({"module": MODULE, "class": "Example", "method": method, "args": args}).to_string()
}

fn in_session(session: u64) -> AddInfo {
    AddInfo {
        origin: Some("https://a.kz".to_owned()),
        session,
    }
}

/// `method` of the example, in `session`, routed as the server routes it.
fn call(modules: &Arc<PluginModules>, session: u64, method: &str) -> String {
    let module = modules.module(MODULE).expect("the module is served");
    module
        .process(&request(method, json!({})), &in_session(session))
        .into_text()
        .unwrap()
}

fn count(modules: &Arc<PluginModules>, session: u64) -> u64 {
    let reply: Value = serde_json::from_str(&call(modules, session, "count")).unwrap();
    reply["body"].as_u64().unwrap()
}

#[test]
fn module_routes_to_plugin() {
    let modules = loaded();
    assert_eq!(modules.names(), [MODULE]);
    let mut registry = Registry::default();
    registry.set_dynamic(Arc::clone(&modules) as _);
    assert_eq!(registry.names(), [MODULE]);
    let text =
        json!({"module": MODULE, "class": "Example", "method": "echo", "args": {"text": "hi"}})
            .to_string();
    let Route::Module(module) = registry.route(&text) else {
        panic!("not routed to the plugin");
    };
    assert_eq!(
        module.process(&text, &in_session(1)),
        r#"{"body":"hi","status":true}"#
    );
    let info = modules.loaded();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].id, ID);
    assert_eq!(info[0].modules, [MODULE]);
    assert_eq!(
        info[0].replaces.as_ref().unwrap().symname,
        "kz.example.echo"
    );
    assert_eq!(info[0].name.en, "Example plugin");
    assert!(modules.module("kz.example.Other").is_none());
}

#[test]
fn sessions_have_separate_state() {
    let modules = loaded();
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(count(&modules, 1), 2);
    assert_eq!(count(&modules, 2), 1);
    assert_eq!(count(&modules, 1), 3);
    // No session: an instance per call.
    assert_eq!(count(&modules, 0), 1);
    assert_eq!(count(&modules, 0), 1);
}

#[test]
fn session_close_drops_state() {
    let modules = loaded();
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(count(&modules, 1), 2);
    assert_eq!(count(&modules, 2), 1);
    modules.session_closed(1);
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(count(&modules, 2), 2);
}

#[test]
fn reload_gives_existing_session_a_fresh_instance() {
    let modules = loaded();
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(count(&modules, 1), 2);
    modules.load(example()).unwrap();
    assert_eq!(count(&modules, 1), 1);
}

#[test]
fn unload_gives_module_not_found() {
    let modules = loaded();
    assert_eq!(count(&modules, 1), 1);
    // Routed before the plugin goes.
    let routed = modules.module(MODULE).unwrap();
    assert!(modules.unload(ID));
    assert!(!modules.unload(ID));
    assert_eq!(
        routed.process(&request("count", json!({})), &in_session(1)),
        module_not_found()
    );
    assert!(modules.module(MODULE).is_none());
    assert!(modules.names().is_empty());
    assert!(modules.loaded().is_empty());
}

#[test]
fn a_failing_call_drops_only_its_instance() {
    let modules = loaded();
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(count(&modules, 2), 1);
    assert_eq!(call(&modules, 1, "panic"), PLUGIN_ERROR_REPLY);
    // Session 1 starts over; session 2 and the plugin go on.
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(count(&modules, 2), 2);
}

/// Answers `confirm` with yes once the test lets it; cancels everything else.
struct GatedConfirm {
    entered: Mutex<Sender<()>>,
    release: Mutex<Receiver<()>>,
}

impl Prompter for GatedConfirm {
    fn storage(&self, _: &StoragePrompt) -> Prompt<StorageAnswer> {
        Prompt::Cancelled
    }
    fn busy(&self, _: &BusyPrompt) -> Busy {
        Busy::none()
    }
    fn key(&self, _: &KeyPrompt) -> Prompt<usize> {
        Prompt::Cancelled
    }
    fn csr(&self, _: &CsrPrompt) -> Prompt<CsrAnswer> {
        Prompt::Cancelled
    }
    fn import_cert(&self, _: &ImportPrompt) -> Prompt<ImportAnswer> {
        Prompt::Cancelled
    }
    fn file(&self, _: &FilePrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }
    fn password(&self, _: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        Prompt::Cancelled
    }
    fn message(&self, _: &MessagePrompt) -> Prompt<()> {
        Prompt::Cancelled
    }
    fn confirm(&self, _: &ConfirmPrompt) -> Prompt<bool> {
        self.entered.lock().unwrap().send(()).unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(60))
            .unwrap();
        Prompt::Answer(true)
    }
    fn save_file(&self, _: &SavePrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }
    fn choice(&self, _: &oncl_basics::ChoicePrompt) -> Prompt<oncl_basics::ChoiceAnswer> {
        Prompt::Cancelled
    }
    fn path(&self, _: &oncl_basics::PathPrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }
    fn reader(&self, _: &oncl_basics::ReaderPrompt) -> Prompt<String> {
        Prompt::Cancelled
    }
}

#[test]
fn in_flight_call_finishes_on_old_instance() {
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let mut services = services();
    services.prompter = Arc::new(GatedConfirm {
        entered: Mutex::new(entered_tx),
        release: Mutex::new(release_rx),
    });
    let modules = modules_with(services, Vec::new());
    modules.load(example()).unwrap();
    let routed = modules.module(MODULE).unwrap();
    let running = std::thread::spawn(move || {
        routed.process(
            &request("confirm", json!({"text": "sure?"})),
            &in_session(1),
        )
    });
    entered.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(modules.unload(ID));
    release.send(()).unwrap();
    assert_eq!(
        running.join().unwrap(),
        r#"{"body":true,"status":true}"#,
        "the running call finishes on its instance"
    );
    assert!(modules.module(MODULE).is_none());
    // Loaded again: the session gets a new instance.
    modules.load(example()).unwrap();
    assert_eq!(count(&modules, 1), 1);
}

#[test]
fn builtin_name_conflict_is_rejected() {
    let modules = modules_with(services(), vec![MODULE.to_owned()]);
    assert_eq!(
        modules.load(example()),
        Err(LoadError::ModuleTaken {
            module: MODULE.to_owned(),
            owner: BUILT_IN.to_owned(),
        })
    );
    assert!(modules.loaded().is_empty());
    assert!(modules.names().is_empty());
}

/// The example's module under another plugin id.
fn other(modules: &str) -> Package {
    let bytes = example_package_with(|m| {
        m.replacen(&format!("id = \"{ID}\""), "id = \"kz.example.other\"", 1)
            .replacen(
                &format!("modules = [\"{MODULE}\"]"),
                &format!("modules = [{modules}]"),
                1,
            )
    });
    Package::read(&bytes).unwrap()
}

#[test]
fn check_does_not_load() {
    let modules = modules_with(services(), Vec::new());
    modules.check(&example()).unwrap();
    assert!(modules.loaded().is_empty());
    assert!(modules.module(MODULE).is_none());
    modules.load(example()).unwrap();
    // Its own module again: fine; another plugin's taking it: not.
    modules.check(&example()).unwrap();
    assert!(matches!(
        modules.check(&other(&format!("\"{MODULE}\""))),
        Err(LoadError::ModuleTaken { .. })
    ));
}

#[test]
fn two_plugins_same_module_conflict() {
    let modules = loaded();
    assert_eq!(
        modules.load(other(&format!("\"kz.example.Mine\", \"{MODULE}\""))),
        Err(LoadError::ModuleTaken {
            module: MODULE.to_owned(),
            owner: ID.to_owned(),
        })
    );
    assert_eq!(modules.loaded().len(), 1);
    assert_eq!(modules.names(), [MODULE]);
    // Its own module: both serve.
    modules.load(other("\"kz.example.Mine\"")).unwrap();
    assert_eq!(
        modules.names(),
        [
            "io.github.arynyklas.openncalayer.Example",
            "kz.example.Mine"
        ]
    );
    let mine = modules.module("kz.example.Mine").unwrap();
    let reply = mine.process(
        &json!({"module": "kz.example.Mine", "class": "Example", "method": "count"}).to_string(),
        &in_session(1),
    );
    assert_eq!(reply, r#"{"body":1,"status":true}"#);
    // Separate plugins, separate instances in one session.
    assert_eq!(count(&modules, 1), 1);
}

#[test]
fn instance_cap_evicts_idle() {
    let modules = loaded();
    for session in 1..=MAX_INSTANCES as u64 {
        assert_eq!(count(&modules, session), 1);
    }
    assert_eq!(count(&modules, 2), 2);
    // One more session: the one used longest ago (session 1) goes.
    assert_eq!(count(&modules, MAX_INSTANCES as u64 + 1), 1);
    assert_eq!(count(&modules, 1), 1);
    // That evicted session 3, the oldest then; session 2 stays.
    assert_eq!(count(&modules, 2), 3);
    assert_eq!(count(&modules, 3), 1);
}

#[test]
fn missing_calls_hook() {
    let modules = loaded();
    // No hook yet: nothing happens.
    modules.missing("kz.example.Gone", &in_session(4));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    modules.set_on_missing(Arc::new(move |name: &str, add_info: &AddInfo| {
        log.lock()
            .unwrap()
            .push((name.to_owned(), add_info.clone()));
    }));
    let mut registry = Registry::default();
    registry.set_dynamic(Arc::clone(&modules) as _);
    registry.missing("kz.example.Gone", &in_session(4));
    assert_eq!(
        *seen.lock().unwrap(),
        [("kz.example.Gone".to_owned(), in_session(4))]
    );
}

/// Holds every request until it is opened; tells each one's start.
struct GatedHttp {
    entered: Mutex<Sender<()>>,
    open: Mutex<bool>,
    opened: std::sync::Condvar,
}

impl oncl_pki::http::HttpTransport for GatedHttp {
    fn send(
        &self,
        request: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        match request.method {
            oncl_pki::http::HttpMethod::Get => {
                let (_, _) = (request.url, request.opts);
                self.entered.lock().unwrap().send(()).unwrap();
                let mut open = self.open.lock().unwrap();
                while !*open {
                    open = self.opened.wait(open).unwrap();
                }
                Ok(oncl_pki::http::HttpReply {
                    status: 200,
                    content_type: None,
                    location: None,
                    body: b"ok".to_vec(),
                })
            }
            oncl_pki::http::HttpMethod::Post => {
                let (_, _, _, _) = (
                    request.url,
                    request.content_type.unwrap_or_default(),
                    request.body,
                    request.opts,
                );
                Err(oncl_pki::http::HttpError::other("no POST here"))
            }
        }
    }
}

#[test]
fn busy_instances_are_never_evicted() {
    let (entered_tx, entered) = channel();
    let http = Arc::new(GatedHttp {
        entered: Mutex::new(entered_tx),
        open: Mutex::new(false),
        opened: std::sync::Condvar::new(),
    });
    let mut services = services();
    services.http = Arc::clone(&http) as _;
    let modules = modules_with(services, Vec::new());
    modules.load(example()).unwrap();
    let fetch = json!({"module": MODULE, "class": "Example", "method": "fetch",
        "args": {"url": "https://example.invalid/x"}})
    .to_string();
    let calls: Vec<_> = (1..=MAX_INSTANCES as u64)
        .map(|session| {
            let module = modules.module(MODULE).unwrap();
            let fetch = fetch.clone();
            std::thread::spawn(move || {
                module
                    .process(&fetch, &in_session(session))
                    .into_text()
                    .unwrap()
            })
        })
        .collect();
    for _ in 0..MAX_INSTANCES {
        entered.recv_timeout(Duration::from_secs(120)).unwrap();
    }
    // Every instance is busy: another session's call is refused, none is evicted.
    assert_eq!(call(&modules, 1000, "count"), PLUGIN_ERROR_REPLY);
    assert_eq!(call(&modules, 0, "count"), PLUGIN_ERROR_REPLY);
    *http.open.lock().unwrap() = true;
    http.opened.notify_all();
    for running in calls {
        let reply: Value = serde_json::from_str(&running.join().unwrap()).unwrap();
        assert_eq!(reply["status"], true, "{reply}");
    }
    // Idle now: the one used longest ago makes room.
    assert_eq!(count(&modules, 1000), 1);
}

/// Holds every request until it is opened.
fn gated_http() -> (Arc<GatedHttp>, Receiver<()>) {
    let (entered_tx, entered) = channel();
    let http = Arc::new(GatedHttp {
        entered: Mutex::new(entered_tx),
        open: Mutex::new(false),
        opened: std::sync::Condvar::new(),
    });
    (http, entered)
}

fn open_gate(http: &GatedHttp) {
    *http.open.lock().unwrap() = true;
    http.opened.notify_all();
}

/// The example loaded with its instances' memory limited by `limits`.
fn limited(services: HostServices, limits: MemoryLimits) -> Arc<PluginModules> {
    let modules = Arc::new(PluginModules::with_memory_limits(
        Arc::new(Engine::new()),
        services,
        Vec::new(),
        limits,
    ));
    modules.load(example()).unwrap();
    modules
}

/// Has the example of `session` echo a 2 MiB text: its memory grows by several times that.
fn echo_big(modules: &Arc<PluginModules>, session: u64) {
    let text = "a".repeat(2 << 20);
    let module = modules.module(MODULE).unwrap();
    let reply = module.process(
        &request("echo", json!({"text": text})),
        &in_session(session),
    );
    let reply: Value = serde_json::from_str(reply.text().unwrap()).unwrap();
    assert_eq!(reply["body"].as_str().map(str::len), Some(text.len()));
}

/// The memory of a fresh instance, and of one after [`echo_big`].
fn sizes() -> (usize, usize) {
    let modules = loaded();
    assert_eq!(modules.memory_in_use(), 0);
    assert_eq!(count(&modules, 1), 1);
    let fresh = modules.memory_in_use();
    echo_big(&modules, 1);
    let big = modules.memory_in_use();
    assert!(big > 4 * fresh, "fresh {fresh}, big {big}");
    (fresh, big)
}

/// A call that waits in the gated HTTP transport.
fn fetch_in(modules: &Arc<PluginModules>, session: u64) -> std::thread::JoinHandle<String> {
    let module = modules.module(MODULE).unwrap();
    let fetch = request("fetch", json!({"url": "https://example.invalid/x"}));
    std::thread::spawn(move || {
        module
            .process(&fetch, &in_session(session))
            .into_text()
            .unwrap()
    })
}

#[test]
fn memory_budget_evicts_idle_used_longest_ago() {
    let (_, big) = sizes();
    let budget = big + big / 2;
    let modules = limited(
        services(),
        MemoryLimits {
            budget,
            high_water: 2 * big,
        },
    );
    assert_eq!(count(&modules, 1), 1);
    echo_big(&modules, 1);
    assert_eq!(count(&modules, 2), 1);
    echo_big(&modules, 2);
    // Two big instances are over the budget: session 1's, used longest ago, went.
    assert!(modules.memory_in_use() <= budget);
    assert_eq!(count(&modules, 2), 2);
    assert_eq!(count(&modules, 1), 1);
    assert!(modules.memory_in_use() <= budget);
}

#[test]
fn over_memory_budget_with_every_instance_busy_refuses_new_ones() {
    let (_, big) = sizes();
    let (http, entered) = gated_http();
    let mut services = services();
    services.http = Arc::clone(&http) as _;
    let modules = limited(
        services,
        MemoryLimits {
            budget: big + big / 2,
            high_water: 2 * big,
        },
    );
    assert_eq!(count(&modules, 1), 1);
    echo_big(&modules, 1);
    let first = fetch_in(&modules, 1);
    entered.recv_timeout(Duration::from_secs(120)).unwrap();
    assert_eq!(count(&modules, 2), 1);
    echo_big(&modules, 2);
    let second = fetch_in(&modules, 2);
    entered.recv_timeout(Duration::from_secs(120)).unwrap();
    // Over the budget with nothing idle: a call needing a new instance is refused.
    assert_eq!(call(&modules, 3, "count"), PLUGIN_ERROR_REPLY);
    assert_eq!(call(&modules, 0, "count"), PLUGIN_ERROR_REPLY);
    open_gate(&http);
    for running in [first, second] {
        let reply: Value = serde_json::from_str(&running.join().unwrap()).unwrap();
        assert_eq!(reply["status"], true, "{reply}");
    }
    // Idle again: the call that returned last has made the other instance go.
    assert!(modules.memory_in_use() <= big + big / 2);
    assert_eq!(count(&modules, 3), 1);
    let mut counts = [count(&modules, 1), count(&modules, 2)];
    counts.sort_unstable();
    assert_eq!(counts, [1, 2]);
}

#[test]
fn instance_over_high_water_is_dropped_after_its_call() {
    let (fresh, big) = sizes();
    let modules = limited(
        services(),
        MemoryLimits {
            budget: usize::MAX,
            high_water: (fresh + big) / 2,
        },
    );
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(count(&modules, 1), 2);
    echo_big(&modules, 1);
    // Grown over the mark: not kept for the session.
    assert_eq!(modules.memory_in_use(), 0);
    assert_eq!(count(&modules, 1), 1);
    assert_eq!(modules.memory_in_use(), fresh);
}
