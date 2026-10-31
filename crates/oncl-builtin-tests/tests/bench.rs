//! Timings of the built-in modules against the same work done by `oncl_pki` directly
//! (`pki_direct_*`) and by the native basics module, with their limits: the median of 7 runs
//! after a warm-up, a scripted prompter without delays, mock TSA and OCSP responders and a
//! fixed clock. Every measurement goes to `target/builtins-bench.json`.
//!
//! Ignored by default; run them in release, one at a time:
//! `cargo test --release -p oncl-builtin-tests --test bench -- --ignored --test-threads=1`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{
    Busy, BusyPrompt, ChoiceAnswer, ChoicePrompt, ConfirmPrompt, CsrAnswer, CsrPrompt, FilePrompt,
    ImportAnswer, ImportPrompt, KeyPrompt, MessagePrompt, PasswordPrompt, PathPrompt, Prompt,
    Prompter, ReaderPrompt, SavePrompt, StorageAnswer, StorageKind, StoragePrompt,
};
use oncl_builtin_tests::SOURCES;
use oncl_builtin_tests::basics::MODULE_NAME;
use oncl_pki::cms::SignOptions;
use oncl_pki::http::HttpTransport;
use oncl_pki::info::cert_info;
use oncl_pki::ocsp::MockOcsp;
use oncl_pki::pkcs12::{KeyEntry, WriteEntry, WriteOptions, load, write};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{BuiltinLimits, BuiltinStats, Builtins, Engine as WasmEngine, HostServices};
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_testkit::{read, synthetic, synthetic_cert};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;
const RUNS: usize = 7;

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn middle_of(name: &str) -> OffsetDateTime {
    let info = cert_info(&entry(name).cert);
    info.not_before + (info.not_after - info.not_before) / 2
}

fn rsa_time() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| middle_of("user-rsa-sign"));
    *AT
}

fn gost_time() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| middle_of("user-gost2015-sign"));
    *AT
}

fn inter_time() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| middle_of("inter-user-gost2015-sign"));
    *AT
}

/// `target/builtins-bench.json`.
fn results_path() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    target.join("builtins-bench.json")
}

/// Adds `value` under `key` to the results file.
fn record(key: &str, value: Value) {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    let path = results_path();
    let mut all: Map<String, Value> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    all.insert(key.to_owned(), value);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(&all).unwrap()).unwrap();
    eprintln!("{key}: {}", all[key]);
}

/// The median time of `RUNS` runs of `f` after one warm-up run.
fn median(mut f: impl FnMut()) -> Duration {
    f();
    let mut times: Vec<Duration> = (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            f();
            start.elapsed()
        })
        .collect();
    times.sort_unstable();
    times[RUNS / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn origin() -> AddInfo {
    AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    }
}

fn steps(name: &str, runs: usize) -> Vec<Step> {
    let key = synthetic(name);
    (0..runs)
        .flat_map(|_| {
            [
                Step::Storage {
                    path: key.path.clone(),
                    password: key.password.clone(),
                },
                Step::Key(0),
            ]
        })
        .collect()
}

/// The services of a module answering `prompter`, at `clock`, time-stamped by `tsa`.
fn services(
    prompter: Arc<dyn Prompter>,
    http: Arc<dyn HttpTransport>,
    clock: fn() -> OffsetDateTime,
) -> HostServices {
    let mut services = HostServices::new(
        prompter,
        Arc::new(MemoryRecentPath::new(None)),
        http,
        oncl_token::Tokens::disabled(),
    );
    services.clock = clock;
    services
}

fn load_builtins(services: HostServices, limits: BuiltinLimits) -> Builtins {
    Builtins::load(&WasmEngine::new(), services, SOURCES, limits, None).unwrap()
}

/// A native basics module answering `prompter`.
fn native(
    prompter: Arc<dyn Prompter>,
    http: Arc<dyn HttpTransport>,
    clock: fn() -> OffsetDateTime,
) -> oncl_basics::Basics {
    oncl_basics::Basics::new(prompter, Arc::new(MemoryRecentPath::new(None)), http)
        .with_clock(clock)
}

fn signed(reply: Reply) {
    let text = reply.into_text().expect("a text reply");
    assert!(
        text.starts_with(r#"{"status":true"#),
        "{}",
        &text[..text.len().min(300)]
    );
}

/// The data of `size` bytes.
fn data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn sign_request(format: &str, data: &str, signing_params: Value) -> String {
    json!({
        "module": MODULE_NAME,
        "method": "sign",
        "args": {
            "format": format,
            "data": data,
            "signingParams": signing_params,
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        },
    })
    .to_string()
}

/// What one module took: its median time, peak memory and fuel.
struct Measured {
    time: Duration,
    stats: BuiltinStats,
}

/// `request` signed by `key` `RUNS + 1` times by the built-in basics module.
fn wasm_sign(key: &str, request: &str, clock: fn() -> OffsetDateTime) -> Measured {
    let prompter = Arc::new(ScriptedPrompter::new(steps(key, RUNS + 1)));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let builtins = load_builtins(services(prompter, tsa, clock), BuiltinLimits::default());
    let module = builtins.module(MODULE_NAME).unwrap();
    let time = median(|| signed(module.process(request, &origin())));
    Measured {
        time,
        stats: builtins.stats(MODULE_NAME).unwrap(),
    }
}

/// `request` signed by `key` `RUNS + 1` times by the native basics module.
fn native_sign(key: &str, request: &str, clock: fn() -> OffsetDateTime) -> Duration {
    let prompter = Arc::new(ScriptedPrompter::new(steps(key, RUNS + 1)));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let module = native(prompter, tsa, clock);
    median(|| signed(module.process(request, &origin())))
}

/// One size of a signing scenario: its times, ratios and the guest's memory and fuel.
fn report(
    scenario: &str,
    size: usize,
    wasm: &Measured,
    native: Duration,
    direct: Duration,
) -> (f64, f64) {
    let ratio = wasm.time.as_secs_f64() / native.as_secs_f64();
    let diff = ms(wasm.time) - ms(native);
    let mib = size as f64 / MIB as f64;
    record(
        &format!("{scenario}/{size}"),
        json!({
            "wasm_ms": ms(wasm.time),
            "native_ms": ms(native),
            "pki_direct_ms": ms(direct),
            "wasm_minus_native_ms": diff,
            "wasm_over_native": ratio,
            "wasm_over_pki_direct": wasm.time.as_secs_f64() / direct.as_secs_f64(),
            "peak_memory": wasm.stats.peak_memory,
            "peak_memory_over_size": wasm.stats.peak_memory as f64 / size as f64,
            "fuel": wasm.stats.max_fuel,
            "fuel_per_mib": wasm.stats.max_fuel as f64 / mib,
        }),
    );
    (diff, ratio)
}

/// The threshold of the CMS and XML scenarios at `size`, if exceeded: at most 15 ms more
/// for 1 KiB (and any smaller size), at most 1.5 times for 1 MiB, 2.5 times above.
fn cms_threshold(size: usize, diff: f64, ratio: f64) -> Option<String> {
    match size {
        s if s < MIB && diff > 15.0 => Some(format!("{size}: {diff} ms more than native")),
        s if s == MIB && ratio > 1.5 => Some(format!("{size}: {ratio} times native")),
        s if s > MIB && ratio > 2.5 => Some(format!("{size}: {ratio} times native")),
        _ => None,
    }
}

/// Fails with every exceeded threshold, once all sizes are measured and recorded.
fn within(exceeded: Vec<String>) {
    assert!(exceeded.is_empty(), "{exceeded:#?}");
}

fn pki_cms(key: &KeyEntry, doc: &[u8], encapsulate: bool, at: OffsetDateTime) -> String {
    STANDARD.encode(
        oncl_pki::cms::sign(
            key,
            doc,
            &SignOptions {
                encapsulate,
                digested: false,
                signing_time: at,
            },
        )
        .unwrap(),
    )
}

#[test]
#[ignore = "a benchmark"]
fn bench_cms_attached_rsa() {
    let key = entry("user-rsa-sign");
    let mut exceeded = Vec::new();
    for size in [KIB, MIB, 16 * MIB, 64 * MIB] {
        let doc = data(size);
        let request = sign_request("cms", &STANDARD.encode(&doc), json!({"decode": true}));
        let direct = median(|| {
            let _ = STANDARD.decode(STANDARD.encode(&doc)).unwrap();
            let _ = pki_cms(&key, &doc, true, rsa_time());
        });
        let wasm = wasm_sign("user-rsa-sign", &request, rsa_time);
        let native = native_sign("user-rsa-sign", &request, rsa_time);
        let (diff, ratio) = report("bench_cms_attached_rsa", size, &wasm, native, direct);
        exceeded.extend(cms_threshold(size, diff, ratio));
    }
    within(exceeded);
}

#[test]
#[ignore = "a benchmark"]
fn bench_cms_detached_gost2015() {
    let key = entry("user-gost2015-sign");
    let mut exceeded = Vec::new();
    for (size, limit) in [(MIB, 1.3), (16 * MIB, 2.0)] {
        let doc = data(size);
        let request = sign_request(
            "cms",
            &STANDARD.encode(&doc),
            json!({"decode": true, "encapsulate": false}),
        );
        let direct = median(|| {
            let _ = STANDARD.decode(STANDARD.encode(&doc)).unwrap();
            let _ = pki_cms(&key, &doc, false, gost_time());
        });
        let wasm = wasm_sign("user-gost2015-sign", &request, gost_time);
        let native = native_sign("user-gost2015-sign", &request, gost_time);
        let (_, ratio) = report("bench_cms_detached_gost2015", size, &wasm, native, direct);
        if ratio > limit {
            exceeded.push(format!("{size}: {ratio} times native"));
        }
    }
    within(exceeded);
}

/// A document of about `size` bytes.
fn xml_document(size: usize) -> String {
    let mut doc = String::with_capacity(size + 64);
    doc.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>");
    let mut i = 0usize;
    while doc.len() < size {
        doc.push_str(&format!("<item n=\"{i}\">value {i}</item>"));
        i += 1;
    }
    doc.push_str("</doc>");
    doc
}

#[test]
#[ignore = "a benchmark"]
fn bench_xml_whole_document() {
    let key = entry("user-rsa-sign");
    let mut exceeded = Vec::new();
    for size in [4 * KIB, MIB, 16 * MIB] {
        let doc = xml_document(size);
        let request = sign_request("xml", &doc, json!({}));
        let direct = median(|| {
            let _ = oncl_pki::xmldsig::sign_enveloped(doc.as_bytes(), &key.key, &key.cert).unwrap();
        });
        let wasm = wasm_sign("user-rsa-sign", &request, rsa_time);
        let native = native_sign("user-rsa-sign", &request, rsa_time);
        let (diff, ratio) = report("bench_xml_whole_document", size, &wasm, native, direct);
        exceeded.extend(cms_threshold(size, diff, ratio));
    }
    within(exceeded);
}

/// A store of 32 keys under the intermediate PKI (one key, 32 certificates), in `dir`.
fn many_keys(dir: &Path) -> PathBuf {
    let issuer = entry("inter-gost2015.key");
    let user = entry("inter-user-gost2015-sign");
    let pkcs8 = user.key.to_pkcs8_der().unwrap();
    let entries: Vec<WriteEntry> = (0..32u8)
        .map(|i| {
            let mut spec = TestCertSpec::from_cert(&user.cert);
            spec.serial = vec![0x51, i + 1];
            let cert = issue_cert(&issuer, spec);
            WriteEntry {
                alias: format!("key{i}"),
                pkcs8_der: pkcs8.to_vec(),
                cert_der: Some(der::Encode::to_der(&cert).unwrap()),
            }
        })
        .collect();
    let p12 = write(
        &entries,
        &[],
        "Qwerty12",
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(7),
    )
    .unwrap();
    let path = dir.join("many.p12");
    std::fs::write(&path, p12).unwrap();
    path
}

/// Opens `path` and records the time from `start` to each key dialog, which it cancels.
struct Timed {
    path: PathBuf,
    start: Mutex<Instant>,
    shown: Mutex<Vec<Duration>>,
}

impl Prompter for Timed {
    fn storage(&self, _: &StoragePrompt) -> Prompt<StorageAnswer> {
        Prompt::Answer(StorageAnswer {
            storage: StorageKind::Pkcs12,
            path: self.path.clone(),
            password: "Qwerty12".to_owned().into(),
            reader: None,
        })
    }
    fn busy(&self, _: &BusyPrompt) -> Busy {
        Busy::none()
    }
    fn key(&self, p: &KeyPrompt) -> Prompt<usize> {
        let elapsed = self.start.lock().unwrap().elapsed();
        assert_eq!(p.candidates.len(), 32);
        self.shown.lock().unwrap().push(elapsed);
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
    fn password(&self, _: &PasswordPrompt) -> Prompt<zeroize::Zeroizing<String>> {
        Prompt::Cancelled
    }
    fn message(&self, _: &MessagePrompt) -> Prompt<()> {
        Prompt::Cancelled
    }
    fn confirm(&self, _: &ConfirmPrompt) -> Prompt<bool> {
        Prompt::Cancelled
    }
    fn save_file(&self, _: &SavePrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }
    fn choice(&self, _: &ChoicePrompt) -> Prompt<ChoiceAnswer> {
        Prompt::Cancelled
    }
    fn path(&self, _: &PathPrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }
    fn reader(&self, _: &ReaderPrompt) -> Prompt<String> {
        Prompt::Cancelled
    }
}

/// The median time from a request to its key dialog over `module`.
fn to_key_dialog(timed: &Timed, module: &dyn Module, request: &str) -> Duration {
    for _ in 0..=RUNS {
        *timed.start.lock().unwrap() = Instant::now();
        let reply = module.process(request, &origin()).into_text().unwrap();
        assert_eq!(reply, r#"{"status":true,"body":{}}"#);
    }
    let mut shown = std::mem::take(&mut *timed.shown.lock().unwrap());
    assert_eq!(shown.len(), RUNS + 1);
    shown.remove(0);
    shown.sort_unstable();
    shown[RUNS / 2]
}

fn pem(name: &str) -> String {
    oncl_pki::pem::encode("CERTIFICATE", &synthetic_cert(name))
}

#[test]
#[ignore = "a benchmark"]
fn bench_many_keys_live() {
    let dir = tempfile::tempdir().unwrap();
    let path = many_keys(dir.path());
    let request = json!({
        "module": MODULE_NAME,
        "method": "sign",
        "args": {
            "format": "cms",
            "data": "eA==",
            "signingParams": {"decode": true},
            "signerParams": {
                "extKeyUsageOids": [],
                "chain": [pem("inter-gost2015"), pem("root-gost2015")],
            },
        },
    })
    .to_string();
    let timed = |module: &dyn Fn(Arc<Timed>, Arc<dyn HttpTransport>) -> Box<dyn Module>| {
        let prompter = Arc::new(Timed {
            path: path.clone(),
            start: Mutex::new(Instant::now()),
            shown: Mutex::new(Vec::new()),
        });
        // A new responder (and OCSP memory) per module: each asks all 32 keys.
        let ocsp: Arc<dyn HttpTransport> = Arc::new(MockOcsp::new(entry("ocsp-gost2015")));
        let module = module(prompter.clone(), ocsp);
        to_key_dialog(&prompter, module.as_ref(), &request)
    };
    let wasm = timed(&|p, http| {
        let builtins = load_builtins(services(p, http, inter_time), BuiltinLimits::default());
        Box::new(Pooled(builtins))
    });
    let native = timed(&|p, http| Box::new(native(p, http, inter_time)));
    let diff = ms(wasm) - ms(native);
    record(
        "bench_many_keys_live",
        json!({"wasm_ms": ms(wasm), "native_ms": ms(native), "wasm_minus_native_ms": diff}),
    );
    assert!(diff <= 30.0, "{diff} ms more than native to the key dialog");
}

/// The basics module of loaded built-in modules.
struct Pooled(Builtins);

impl Module for Pooled {
    fn process(&self, request: &str, add_info: &AddInfo) -> Reply {
        self.0
            .module(MODULE_NAME)
            .unwrap()
            .process(request, add_info)
    }
}

fn inert_services() -> HostServices {
    services(
        Arc::new(ScriptedPrompter::new(Vec::<Step>::new())),
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
        rsa_time,
    )
}

#[test]
#[ignore = "a benchmark"]
fn bench_startup() {
    let time = median(|| drop(load_builtins(inert_services(), BuiltinLimits::default())));
    record("bench_startup", json!({"ms": ms(time)}));
    assert!(ms(time) <= 250.0, "{} ms to load", ms(time));
}

#[test]
#[ignore = "a benchmark"]
fn bench_first_call() {
    // No idle instance is kept: every call makes a new one.
    let limits = BuiltinLimits {
        idle: 0,
        ..BuiltinLimits::default()
    };
    let builtins = load_builtins(inert_services(), limits);
    let module = builtins.module(MODULE_NAME).unwrap();
    let request = json!({"module": MODULE_NAME, "method": "sign", "args": {}}).to_string();
    let time = median(|| {
        let reply = module.process(&request, &origin()).into_text().unwrap();
        assert!(reply.contains(r#""status":false"#), "{reply}");
    });
    record("bench_first_call", json!({"ms": ms(time)}));
    assert!(
        ms(time) <= 20.0,
        "{} ms for a call on a new instance",
        ms(time)
    );
}

#[test]
fn embedded_modules_are_small() {
    let total: usize = SOURCES.iter().map(|s| s.wasm.len()).sum();
    assert!(total <= 4 * MIB, "{total} bytes of built-in modules");
}

/// The synthetic roots, standing in for the NCA CAs.
fn synthetic_cas() -> oncl_pki::pkix::CaSet {
    oncl_pki::pkix::CaSet::new(
        ["root-gost2015", "root-rsa"]
            .into_iter()
            .map(|name| oncl_pki::cert::parse(&synthetic_cert(name)).unwrap())
            .collect(),
    )
}

#[test]
#[ignore = "a benchmark"]
fn bench_page_file_cades() {
    const SIZE: usize = 64 * MIB;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("doc.bin");
    let doc = data(SIZE);
    std::fs::write(&path, &doc).unwrap();
    let request = json!({
        "module": oncl_builtin_tests::commonutils::MODULE_NAME,
        "method": "createCAdESFromFile",
        "args": ["PKCS12", "", path.display().to_string(), false],
    })
    .to_string();
    let prompter = Arc::new(ScriptedPrompter::new(steps("user-rsa-sign", RUNS + 1)));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let mut services = services(prompter, tsa, rsa_time);
    services.cas = Arc::new(synthetic_cas());
    let builtins = load_builtins(services, BuiltinLimits::default());
    let module = builtins
        .module(oncl_builtin_tests::commonutils::MODULE_NAME)
        .unwrap();
    let wasm = median(|| {
        let reply = module.process(&request, &origin()).into_text().unwrap();
        assert!(
            reply.starts_with(r#"{"code":"200""#),
            "{}",
            &reply[..reply.len().min(300)]
        );
    });
    let key = entry("user-rsa-sign");
    let direct = median(|| {
        let doc = std::fs::read(&path).unwrap();
        let _ = pki_cms(&key, &doc, false, rsa_time());
    });
    let stats = builtins
        .stats(oncl_builtin_tests::commonutils::MODULE_NAME)
        .unwrap();
    let ratio = wasm.as_secs_f64() / direct.as_secs_f64();
    record(
        "bench_page_file_cades/67108864",
        json!({
            "wasm_ms": ms(wasm),
            "pki_direct_ms": ms(direct),
            "wasm_over_pki_direct": ratio,
            "peak_memory": stats.peak_memory,
            "peak_memory_over_size": stats.peak_memory as f64 / SIZE as f64,
            "fuel": stats.max_fuel,
        }),
    );
    assert!(ratio <= 3.0, "{ratio} times oncl_pki");
}
