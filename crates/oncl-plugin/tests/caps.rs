//! The capabilities through the example plugin (and, for the dialog-flow turn, guests in
//! WebAssembly text): keys chosen in scripted dialogs and used by handle, the dialogs, files
//! and HTTP within the manifest's prefixes.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_basics::{FileKind, MessageKind, lock_dialog_flow};
use oncl_pdk::abi::{self, Bytes, ConfirmArgs, ErrorCode, HttpArgs, HttpResponse, Import, Method};
use oncl_pki::http::{GetOptions, HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{
    Engine, HTTP_TIMEOUT, HostServices, Instance, MAX_HTTP_BODY, MAX_HTTP_REQUESTS,
    MAX_KEY_HANDLES, Manifest, PluginError, SessionContext,
};
use oncl_testkit::plugin::example_wasm;
use oncl_testkit::{read, synthetic};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

const KEY: &str = "user-gost2015-sign";
const ORIGIN: &str = "https://idp.egov.kz";

fn example_manifest() -> Manifest {
    Manifest::from_toml(&oncl_testkit::plugin::example_manifest()).unwrap()
}

fn example_on(services: &HostServices, session_id: u64) -> Instance {
    let manifest = example_manifest();
    let ctx = SessionContext {
        session: session_id,
        plugin_id: manifest.id.clone(),
        plugin_name: manifest.name.clone(),
        shared: Default::default(),
        trust: oncl_plugin::Trust::Installed,
    };
    Engine::new()
        .compile(&manifest, &read(example_wasm()))
        .unwrap()
        .instantiate(services, ctx)
        .unwrap()
}

fn request(method: &str, args: Value) -> String {
    json!({"class": "Example", "method": method, "args": args}).to_string()
}

fn reply(instance: &mut Instance, method: &str, args: Value) -> Value {
    let reply = instance
        .process(&request(method, args), &from(ORIGIN))
        .unwrap();
    serde_json::from_str(reply.text().unwrap()).unwrap()
}

/// The steps that open the synthetic key store and pick its first key.
fn pick_key() -> Vec<Step> {
    let key = synthetic(KEY);
    vec![
        Step::Storage {
            path: key.path,
            password: key.password,
        },
        Step::Key(0),
    ]
}

fn entry() -> KeyEntry {
    let key = synthetic(KEY);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

/// Signing arguments without a CA chain (no path, no OCSP) and with expired keys allowed.
fn sign_args(extra: Value) -> Value {
    let mut args = json!({"chain": [], "allowExpired": true});
    args.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    args
}

fn scripted(steps: Vec<Step>) -> (Arc<ScriptedPrompter>, HostServices) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let services = services_with(prompter.clone(), Arc::new(Offline));
    (prompter, services)
}

/// The DER of a PEM block.
fn pem_der(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(body).unwrap()
}

#[test]
fn sign_cms_with_chosen_key_verifies() {
    let mut steps = pick_key();
    steps.extend(pick_key());
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa = Arc::new(MockTsa::new({
        let key = synthetic("tsa-gost2015");
        load(&read(&key.path), &key.password)
            .unwrap()
            .swap_remove(0)
    }));
    let services = services_with(prompter.clone(), tsa.clone());
    let mut plugin = example_on(&services, 1);
    let data = b"contract text";

    let attached = reply(
        &mut plugin,
        "sign",
        sign_args(json!({"data_b64": STANDARD.encode(data)})),
    );
    assert_eq!(attached["status"], true, "{attached}");
    let der = pem_der(attached["body"].as_str().unwrap());
    let signers = oncl_pki::cms::verify(&der, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].cert, entry().cert);
    assert!(signers[0].timestamp_token.is_none());

    let detached = reply(
        &mut plugin,
        "sign",
        sign_args(json!({"data_b64": STANDARD.encode(data), "attached": false, "timestamp": true})),
    );
    let der = pem_der(detached["body"].as_str().unwrap());
    let signers = oncl_pki::cms::verify(&der, Some(data)).unwrap();
    assert!(signers[0].timestamp_token.is_some(), "time-stamped");
    assert_eq!(tsa.calls().len(), 1);
    assert!(oncl_pki::cms::verify(&der, Some(b"other text")).is_err());

    // The dialogs name the page and the plugin.
    let storages = prompter.storage_prompts();
    assert_eq!(storages[0].origin, ORIGIN);
    assert_eq!(storages[0].detail.as_deref(), Some("Пример плагина: CMS"));
    assert_eq!(
        prompter.key_prompts()[0].detail.as_deref(),
        Some("Пример плагина: CMS")
    );
}

#[test]
fn sign_raw_and_xml() {
    let mut steps = pick_key();
    steps.extend(pick_key());
    let (_, services) = scripted(steps);
    let mut plugin = example_on(&services, 1);
    let entry = entry();

    let raw = reply(
        &mut plugin,
        "signRaw",
        sign_args(json!({"data_b64": STANDARD.encode(b"raw data")})),
    );
    let signature = STANDARD
        .decode(raw["body"]["signature"].as_str().unwrap())
        .unwrap();
    let alg = match entry.key.alg() {
        KeyAlg::Gost2004 => SigAlg::Gost2004,
        KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
        KeyAlg::Rsa => SigAlg::RsaSha256,
    };
    entry
        .key
        .public_key()
        .verify(alg, b"raw data", &signature)
        .unwrap();
    let certificate = STANDARD
        .decode(raw["body"]["certificate"].as_str().unwrap())
        .unwrap();
    assert_eq!(certificate, der::Encode::to_der(&entry.cert).unwrap());

    let xml = reply(
        &mut plugin,
        "signXml",
        sign_args(json!({"xml": "<doc><a>1</a></doc>"})),
    );
    let signed = xml["body"].as_str().unwrap();
    let verified = oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].cert, entry.cert);
}

#[test]
fn cancelled_choice_returns_null_not_error() {
    let (prompter, services) = scripted(vec![Step::CancelStorage]);
    let mut plugin = example_on(&services, 1);
    let cancelled = plugin
        .process(
            &request("sign", sign_args(json!({"data_b64": "AA=="}))),
            &from(ORIGIN),
        )
        .unwrap();
    assert_eq!(cancelled, r#"{"body":null,"status":true}"#);
    assert_eq!(prompter.timeline(), ["storage"]);

    let mut steps = pick_key();
    steps.pop();
    steps.push(Step::CancelKey);
    let (_, services) = scripted(steps);
    let mut plugin = example_on(&services, 1);
    assert_eq!(
        reply(&mut plugin, "sign", sign_args(json!({"data_b64": "AA=="})))["body"],
        Value::Null
    );
}

/// `hold`: a key kept by the guest, its handle.
fn hold(plugin: &mut Instance) -> Value {
    reply(plugin, "hold", sign_args(json!({})))
}

fn raw_sign(plugin: &mut Instance, handle: &Value) -> Value {
    reply(
        plugin,
        "rawSign",
        json!({"handle": handle, "data_b64": "AQID"}),
    )
}

#[test]
fn handle_from_released_key_is_invalid() {
    let mut steps = pick_key();
    steps.extend(pick_key());
    let (_, services) = scripted(steps);
    let mut plugin = example_on(&services, 1);
    let handle = hold(&mut plugin)["body"].clone();
    assert_eq!(raw_sign(&mut plugin, &handle)["status"], true);
    assert_eq!(
        reply(&mut plugin, "release", json!({"handle": handle}))["body"],
        true
    );
    let stale = raw_sign(&mut plugin, &handle);
    assert_eq!(stale["code"], "HOST_INVALID", "{stale}");
    // A new key gets a new handle: the old one still names nothing.
    let again = hold(&mut plugin)["body"].clone();
    assert_ne!(again, handle);
    assert_eq!(raw_sign(&mut plugin, &handle)["code"], "HOST_INVALID");
    assert_eq!(raw_sign(&mut plugin, &again)["status"], true);
    assert_eq!(raw_sign(&mut plugin, &json!(999))["code"], "HOST_INVALID");
}

#[test]
fn seventeenth_handle_is_limit() {
    let steps = (0..MAX_KEY_HANDLES).flat_map(|_| pick_key()).collect();
    let (prompter, services) = scripted(steps);
    let mut plugin = example_on(&services, 1);
    for _ in 0..MAX_KEY_HANDLES {
        assert_eq!(hold(&mut plugin)["status"], true);
    }
    let over = hold(&mut plugin);
    assert_eq!(over["code"], "HOST_LIMIT", "{over}");
    assert_eq!(
        prompter.storage_prompts().len(),
        MAX_KEY_HANDLES,
        "no dialog for a key that would not fit"
    );
    // Releasing one makes room: the next choice shows its dialog (cancelled here).
    assert_eq!(
        reply(&mut plugin, "release", json!({"handle": 1}))["body"],
        true
    );
    assert_eq!(hold(&mut plugin)["body"], Value::Null);
    assert_eq!(prompter.storage_prompts().len(), MAX_KEY_HANDLES + 1);
}

#[test]
fn two_instances_do_not_share_handles() {
    let (_, services) = scripted(pick_key());
    let mut first = example_on(&services, 1);
    let mut second = example_on(&services, 2);
    let handle = hold(&mut first)["body"].clone();
    assert_eq!(raw_sign(&mut first, &handle)["status"], true);
    assert_eq!(raw_sign(&mut second, &handle)["code"], "HOST_INVALID");
}

#[test]
fn confirm_and_message_show_plugin_name_and_origin() {
    let (prompter, services) = scripted(vec![
        Step::Confirm { yes: true },
        Step::Confirm { yes: false },
        Step::CancelConfirm,
        Step::Message,
        Step::CancelMessage,
    ]);
    let mut plugin = example_on(&services, 1);
    let question = json!({"text": "Подписать <b>договор</b>?"});
    assert_eq!(
        reply(&mut plugin, "confirm", question.clone())["body"],
        true
    );
    assert_eq!(
        reply(&mut plugin, "confirm", question.clone())["body"],
        false
    );
    assert_eq!(
        reply(&mut plugin, "confirm", question)["body"],
        false,
        "closed is no"
    );
    for _ in 0..2 {
        let message = reply(&mut plugin, "message", json!({"text": "Готово"}));
        assert_eq!(message, json!({"status": true, "body": null}));
    }
    let confirm = &prompter.confirm_prompts()[0];
    assert_eq!(confirm.origin, ORIGIN);
    assert_eq!(confirm.source, "Пример плагина");
    assert_eq!(confirm.text, "Подписать <b>договор</b>?");
    let message = &prompter.message_prompts()[0];
    assert_eq!(
        (
            message.origin.as_str(),
            message.source.as_str(),
            message.kind,
            message.text.as_str()
        ),
        (ORIGIN, "Пример плагина", MessageKind::Info, "Готово")
    );
    // Without an origin the dialogs say so.
    let (prompter, services) = scripted(vec![Step::Confirm { yes: true }]);
    let mut plugin = example_on(&services, 1);
    plugin
        .process(
            &request("confirm", json!({"text": "?"})),
            &oncl_protocol::AddInfo::default(),
        )
        .unwrap();
    assert_eq!(prompter.confirm_prompts()[0].origin, "UNIDENTIFIED");
}

#[test]
fn open_reads_chosen_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"\x00file contents\xff").unwrap();
    let (prompter, services) = scripted(vec![Step::File(path.clone()), Step::CancelFile]);
    let mut plugin = example_on(&services, 1);
    let opened = reply(&mut plugin, "open", json!({}));
    assert_eq!(
        STANDARD
            .decode(opened["body"]["data_b64"].as_str().unwrap())
            .unwrap(),
        b"\x00file contents\xff"
    );
    assert!(
        opened["body"]["path"]
            .as_str()
            .unwrap()
            .ends_with("input.bin")
    );
    assert_eq!(prompter.file_prompts()[0].kind, FileKind::All);
    assert_eq!(prompter.file_prompts()[0].origin, ORIGIN);
    assert_eq!(
        prompter.file_prompts()[0].source.as_deref(),
        Some("Пример плагина")
    );
    assert_eq!(reply(&mut plugin, "open", json!({}))["body"], Value::Null);

    // A folder is not a file.
    let (_, services) = scripted(vec![Step::File(dir.path().to_owned())]);
    let mut plugin = example_on(&services, 1);
    assert_eq!(reply(&mut plugin, "open", json!({}))["code"], "HOST_FAILED");
}

#[test]
fn save_writes_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.txt");
    std::fs::write(&path, b"old contents that are longer").unwrap();
    let (prompter, services) = scripted(vec![Step::Save { path: path.clone() }, Step::CancelSave]);
    let mut plugin = example_on(&services, 1);
    let saved = reply(
        &mut plugin,
        "save",
        json!({"name": "../../report.txt", "data_b64": STANDARD.encode(b"new")}),
    );
    assert_eq!(saved["body"], path.to_str().unwrap());
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["out.txt"], "no temporary file is left");
    let prompt = &prompter.save_prompts()[0];
    assert_eq!(
        prompt.suggested_name, "report.txt",
        "only the file name is suggested"
    );
    assert_eq!(
        (prompt.origin.as_str(), prompt.source.as_str()),
        (ORIGIN, "Пример плагина")
    );

    let cancelled = reply(
        &mut plugin,
        "save",
        json!({"name": "x", "data_b64": "AA=="}),
    );
    assert_eq!(cancelled["body"], Value::Null);
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
}

/// What a transport was asked.
#[derive(Debug, Clone, PartialEq)]
struct Asked {
    url: String,
    post: Option<(String, Vec<u8>)>,
    opts: GetOptions,
}

/// Records requests and answers with `reply`.
struct Recording {
    asked: Mutex<Vec<Asked>>,
    reply: HttpReply,
}

impl Recording {
    fn new(reply: HttpReply) -> Arc<Recording> {
        Arc::new(Recording {
            asked: Mutex::new(Vec::new()),
            reply,
        })
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }
}

impl HttpTransport for Recording {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        match request.method {
            HttpMethod::Get => {
                let (url, opts) = (request.url, request.opts);
                self.asked.lock().unwrap().push(Asked {
                    url: url.to_owned(),
                    post: None,
                    opts,
                });
                Ok(self.reply.clone())
            }
            HttpMethod::Post => {
                let (url, content_type, body, opts) = (
                    request.url,
                    request.content_type.unwrap_or_default(),
                    request.body,
                    request.opts,
                );
                self.asked.lock().unwrap().push(Asked {
                    url: url.to_owned(),
                    post: Some((content_type.to_owned(), body.to_vec())),
                    opts,
                });
                Ok(self.reply.clone())
            }
        }
    }
}

fn http_example(transport: Arc<Recording>) -> Instance {
    let services = services_with(Arc::new(ScriptedPrompter::new(Vec::new())), transport);
    example_on(&services, 1)
}

#[test]
fn http_outside_allowlist_is_denied() {
    let redirect = HttpReply {
        status: 302,
        content_type: None,
        location: Some("https://evil.test/steal".to_owned()),
        body: Vec::new(),
    };
    let transport = Recording::new(redirect);
    let mut plugin = http_example(transport.clone());
    for url in [
        "https://example.invalid.evil/",
        "https://example.invalid@evil/",
        "https://user:pass@example.invalid/",
        "http://example.invalid/",
        "https://example.invalid:8443/",
        "https://evil.test/",
        "ftp://example.invalid/",
        "https://example.invalid\\@evil/",
        "example.invalid/x",
    ] {
        let denied = reply(&mut plugin, "fetch", json!({"url": url}));
        assert_eq!(denied["code"], "HOST_DENIED", "{url}: {denied}");
        let denied = reply(
            &mut plugin,
            "fetch",
            json!({"url": url, "body_b64": "AA=="}),
        );
        assert_eq!(denied["code"], "HOST_DENIED", "POST {url}: {denied}");
    }
    assert!(transport.asked().is_empty(), "nothing denied was sent");

    // A redirect to another host comes back to the guest, and following it is denied.
    let moved = reply(
        &mut plugin,
        "fetch",
        json!({"url": "https://EXAMPLE.invalid/start"}),
    );
    assert_eq!(moved["body"]["status"], 302);
    assert_eq!(moved["body"]["location"], "https://evil.test/steal");
    let followed = reply(
        &mut plugin,
        "fetch",
        json!({"url": moved["body"]["location"]}),
    );
    assert_eq!(followed["code"], "HOST_DENIED");
    assert_eq!(
        transport.asked().len(),
        1,
        "only the allowed request was sent"
    );
    assert!(!transport.asked()[0].opts.redirects);
}

#[test]
fn http_inside_allowlist_reaches_transport_https_only() {
    let transport = Recording::new(HttpReply {
        status: 200,
        content_type: Some("application/json".to_owned()),
        location: None,
        body: b"{\"ok\":true}".to_vec(),
    });
    let mut plugin = http_example(transport.clone());
    let got = reply(
        &mut plugin,
        "fetch",
        json!({"url": "https://EXAMPLE.invalid:443/a/./b/../c?q=1#frag"}),
    );
    assert_eq!(got["body"]["status"], 200, "{got}");
    assert_eq!(got["body"]["contentType"], "application/json");
    assert_eq!(
        STANDARD
            .decode(got["body"]["body_b64"].as_str().unwrap())
            .unwrap(),
        b"{\"ok\":true}"
    );
    let posted = reply(
        &mut plugin,
        "fetch",
        json!({"url": "https://example.invalid/api", "body_b64": STANDARD.encode(b"payload"), "contentType": "application/x-test"}),
    );
    assert_eq!(posted["body"]["status"], 200);

    let asked = transport.asked();
    assert_eq!(asked.len(), 2);
    // What was checked is what is sent: normalized, the fragment dropped.
    assert_eq!(asked[0].url, "https://example.invalid/a/c?q=1");
    assert_eq!(asked[0].post, None);
    assert_eq!(asked[1].url, "https://example.invalid/api");
    assert_eq!(
        asked[1].post,
        Some(("application/x-test".to_owned(), b"payload".to_vec()))
    );
    for asked in &asked {
        assert!(asked.opts.https_only);
        assert!(!asked.opts.redirects);
        assert_eq!(asked.opts.max_len, MAX_HTTP_BODY);
        assert_eq!(asked.opts.timeout, HTTP_TIMEOUT);
    }
}

/// A guest whose `oncl_process` sends `times` GET requests within its prefix.
fn fetching_instance(services: &HostServices, times: usize) -> Instance {
    let args = abi::encode(&HttpArgs {
        method: Method::Get,
        url: "https://example.invalid/".to_owned(),
        content_type: None,
        body: Bytes::default(),
    });
    let calls: Vec<_> = (0..times)
        .map(|_| (Import::HttpRequest, args.clone()))
        .collect();
    Engine::new()
        .compile(
            &manifest(r#"http = ["https://example.invalid/"]"#),
            &wasm(&probe(&calls)),
        )
        .unwrap()
        .instantiate(services, session(1))
        .unwrap()
}

#[test]
fn http_requests_per_call_are_capped() {
    let transport = Recording::new(HttpReply {
        status: 200,
        content_type: None,
        location: None,
        body: Vec::new(),
    });
    let services = services_with(
        Arc::new(ScriptedPrompter::new(Vec::new())),
        transport.clone(),
    );
    let cap = MAX_HTTP_REQUESTS as usize;
    // As many as allowed, call after call: the count starts again with each call.
    let mut at_cap = fetching_instance(&services, cap);
    for _ in 0..2 {
        let response = at_cap.process("{}", &from(ORIGIN)).unwrap();
        assert_eq!(
            probe_result::<HttpResponse>(response.text().unwrap())
                .unwrap()
                .status,
            200
        );
    }
    assert_eq!(transport.asked().len(), 2 * cap);
    // One more within a call is a limit error, not sent.
    let mut over = fetching_instance(&services, cap + 1);
    let response = over.process("{}", &from(ORIGIN)).unwrap();
    let error = probe_result::<HttpResponse>(response.text().unwrap()).unwrap_err();
    assert_eq!(error.code, ErrorCode::Limit, "{error:?}");
    assert_eq!(transport.asked().len(), 3 * cap);
}

/// A guest whose `oncl_process` asks `dialog_confirm` `times` times, then answers `{}` or,
/// with `trap`, traps.
fn confirming(times: usize, trap: bool) -> Vec<u8> {
    let args = abi::encode(&ConfirmArgs {
        text: "?".to_owned(),
    });
    let calls: Vec<_> = (0..times)
        .map(|_| (Import::DialogConfirm, args.clone()))
        .collect();
    let mut wat = probe(&calls);
    if trap {
        wat = wat.replacen(
            "    (local.set $src",
            "    (unreachable)\n    (local.set $src",
            1,
        );
    }
    wasm(&wat)
}

fn confirming_instance(services: &HostServices, times: usize, trap: bool) -> Instance {
    Engine::new()
        .compile(&manifest("dialogs = true"), &confirming(times, trap))
        .unwrap()
        .instantiate(services, session(1))
        .unwrap()
}

#[test]
fn dialog_turn_is_held_for_the_whole_call() {
    let opened = Arc::new(Barrier::new(2));
    let between = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let (prompter, services) = scripted(vec![
        Step::Wait(opened.clone()),
        Step::Confirm { yes: true },
        Step::Wait(between.clone()),
        Step::Wait(release.clone()),
        Step::Confirm { yes: true },
    ]);
    let mut plugin = confirming_instance(&services, 2, false);
    let finished = Arc::new(AtomicBool::new(false));
    let call = thread::spawn({
        let finished = finished.clone();
        move || {
            let result = plugin.process("{}", &from(ORIGIN));
            finished.store(true, Ordering::SeqCst);
            result
        }
    });
    // The first question is open: the plugin holds the turn.
    opened.wait();
    let (tx, rx) = mpsc::channel();
    let other = thread::spawn({
        let prompter = prompter.clone();
        move || {
            let _turn = lock_dialog_flow();
            tx.send(prompter.confirm_prompts().len()).unwrap();
        }
    });
    // Between the two questions the other flow still waits.
    between.wait();
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "another flow got the turn during the call"
    );
    assert!(!finished.load(Ordering::SeqCst));
    release.wait();
    let result = call.join().unwrap();
    assert!(result.is_ok(), "{result:?}");
    assert!(finished.load(Ordering::SeqCst));
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(2));
    other.join().unwrap();
}

#[test]
fn dialog_turn_released_after_trap() {
    let (prompter, services) = scripted(vec![Step::Confirm { yes: true }]);
    let mut plugin = confirming_instance(&services, 1, true);
    assert!(matches!(
        plugin.process("{}", &from(ORIGIN)),
        Err(PluginError::Trap(_))
    ));
    assert_eq!(
        prompter.confirm_prompts().len(),
        1,
        "the question was asked"
    );
    // The turn is free again, for this thread and any other.
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _turn = lock_dialog_flow();
        tx.send(()).unwrap();
    });
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(()));
    drop(lock_dialog_flow());
}
