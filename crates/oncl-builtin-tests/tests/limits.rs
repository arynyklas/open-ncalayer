//! The largest requests the built-in modules take within their limits, on 64- and 32-bit
//! targets: the largest page file signs, a reply may be larger than the largest message,
//! the fuel of a call covers the largest message, and running out of memory drops the
//! connection at once.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_builtin_tests::SOURCES;
use oncl_builtin_tests::accessory::MODULE_NAME as ACCESSORY;
use oncl_builtin_tests::applet::MODULE_NAME as APPLET;
use oncl_builtin_tests::basics::MODULE_NAME;
use oncl_builtin_tests::commonutils::MODULE_NAME as CU_MODULE;
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::info::cert_info;
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::load;
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{BUILTIN_FUEL, BuiltinLimits, Builtins, Engine as WasmEngine, HostServices};
use oncl_protocol::orgjson::MAX_DEPTH;
use oncl_protocol::{AddInfo, Reply};
use oncl_testkit::{read, synthetic};
use serde_json::json;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const MIB: usize = 1 << 20;
/// The daemon's largest WebSocket message (`openncalayer::server::MAX_MESSAGE`).
const MAX_MESSAGE: usize = 256 * MIB;

fn rsa_time() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| {
        let key = synthetic("user-rsa-sign");
        let entry = load(&read(&key.path), &key.password).unwrap().remove(0);
        let info = cert_info(&entry.cert);
        info.not_before + (info.not_after - info.not_before) / 2
    });
    *AT
}

/// The basics module of the built-in modules within `limits`, signing `calls` times with
/// the synthetic RSA key.
fn basics(limits: BuiltinLimits, calls: usize) -> Builtins {
    let services = basics_services(calls);
    Builtins::load(&WasmEngine::new(), services, SOURCES, limits, None).unwrap()
}

/// The services of [`basics`]: the prompter answers `calls` key choices with the synthetic
/// RSA key.
fn basics_services(calls: usize) -> HostServices {
    let key = synthetic("user-rsa-sign");
    let steps: Vec<Step> = (0..calls)
        .flat_map(|_| {
            [
                Step::Storage {
                    path: key.path.clone(),
                    password: key.password.clone(),
                },
                Step::Key(0),
            ]
        })
        .collect();
    let tsa = synthetic("tsa-gost2015");
    let tsa = load(&read(&tsa.path), &tsa.password).unwrap().remove(0);
    let mut services = HostServices::new(
        Arc::new(ScriptedPrompter::new(steps)),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new(tsa)),
        oncl_token::Tokens::disabled(),
    );
    services.clock = rsa_time;
    services
}

/// An attached CMS request of `size` bytes of data, base64-encoded.
fn cms_request(size: usize) -> String {
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    json!({
        "module": MODULE_NAME,
        "method": "sign",
        "args": {
            "format": "cms",
            "data": STANDARD.encode(&data),
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        },
    })
    .to_string()
}

fn origin() -> AddInfo {
    AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    }
}

/// Taken by the tests whose calls keep much data: what the process keeps at once is
/// bounded (`BUILTIN_KEPT_BUDGET`, 256 MiB on 32-bit targets), so their calls take turns.
fn one_large_call_at_a_time() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The reply's length, the reply a signature.
fn signed(reply: Reply) -> usize {
    let text = reply.into_text().expect("a text reply");
    assert!(
        text.starts_with(r#"{"body":"#) && text.ends_with(r#""status":true}"#),
        "{}",
        &text[..text.len().min(300)]
    );
    text.len()
}

/// The synthetic roots, standing in for the NCA CAs.
fn synthetic_cas() -> oncl_pki::pkix::CaSet {
    oncl_pki::pkix::CaSet::new(
        ["root-gost2015", "root-rsa"]
            .into_iter()
            .map(|name| oncl_pki::cert::parse(&oncl_testkit::synthetic_cert(name)).unwrap())
            .collect(),
    )
}

/// The default limits of a 32-bit target, on any target (the guest is the same wasm32
/// module on both; the process-wide budgets stay this target's).
fn limits_32_bit() -> BuiltinLimits {
    let mut limits = BuiltinLimits::default();
    limits.instance.max_memory = 16 * MIB;
    limits.instance.max_transfer = 16 * MIB;
    limits.instance.max_kept = 256 * MIB;
    limits.high_water = 8 * MIB;
    limits.max_live = 4;
    limits
}

#[cfg(not(target_pointer_width = "64"))]
#[test]
fn limits_32_bit_are_the_defaults_here() {
    assert_eq!(limits_32_bit(), BuiltinLimits::default());
}

#[test]
fn raw_of_a_large_document_fits() {
    // The core signs the document itself: it never comes back into the module.
    let _turn = one_large_call_at_a_time();
    let data: Vec<u8> = (0..64 * MIB).map(|i| (i % 251) as u8).collect();
    let request = json!({
        "module": MODULE_NAME,
        "method": "sign",
        "args": {
            "format": "raw",
            "data": STANDARD.encode(&data),
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        },
    })
    .to_string();
    let builtins = basics(limits_32_bit(), 1);
    let module = builtins.module(MODULE_NAME).unwrap();
    let reply: serde_json::Value = serde_json::from_str(
        module
            .process(&request, &origin())
            .text()
            .expect("a text reply"),
    )
    .unwrap();
    let key = synthetic("user-rsa-sign");
    let entry = load(&read(&key.path), &key.password).unwrap().remove(0);
    let signature = entry.key.sign(SigAlg::RsaSha256, &data).unwrap();
    assert_eq!(
        reply,
        json!({"body": {"result": STANDARD.encode(signature)}, "status": true})
    );
}

/// An XML document of exactly `len` bytes.
fn xml_doc(n: usize, len: usize) -> String {
    let head = format!("<doc n=\"{n}\">");
    format!(
        "{head}{}</doc>",
        "x".repeat(len - head.len() - "</doc>".len())
    )
}

#[test]
fn batches_of_short_documents_fit() {
    // Many documents, each shorter than a long string, add up: the core keeps them. The
    // storage window is cancelled, so nothing is signed; the modules answer.
    let _turn = one_large_call_at_a_time();
    for (doc, total) in [(8 << 10, 16 * MIB), (1 << 10, 4 * MIB)] {
        let docs: Vec<String> = (0..total / doc).map(|n| xml_doc(n, doc)).collect();
        let builtins = Builtins::load(
            &WasmEngine::new(),
            basics_services(0),
            SOURCES,
            limits_32_bit(),
            None,
        )
        .unwrap();
        let request = json!({
            "module": MODULE_NAME,
            "method": "sign",
            "args": {
                "format": "xml",
                "data": docs,
                "signingParams": {},
                "signerParams": {"extKeyUsageOids": [], "chain": []},
            },
        })
        .to_string();
        let module = builtins.module(MODULE_NAME).unwrap();
        assert_eq!(
            module.process(&request, &origin()),
            r#"{"body":{},"status":true}"#,
            "basics, {total} bytes of {doc}"
        );
        let request = json!({
            "module": CU_MODULE,
            "method": "signXmls",
            "args": ["PKCS12", "", docs, "", ""],
        })
        .to_string();
        let module = builtins.module(CU_MODULE).unwrap();
        assert_eq!(
            module.process(&request, &origin()),
            r#"{"code":"500","message":"action.canceled"}"#,
            "commonUtils, {total} bytes of {doc}"
        );
    }
}

#[test]
fn sign_max_page_file_fits() {
    // The largest file a page may name, signed by commonUtils as an attached CAdES.
    let _turn = one_large_call_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("doc.bin");
    let data: Vec<u8> = (0..64 * MIB).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, data).unwrap();
    let mut builtins = basics_services(1);
    builtins.cas = Arc::new(synthetic_cas());
    let builtins = Builtins::load(
        &WasmEngine::new(),
        builtins,
        SOURCES,
        BuiltinLimits::default(),
        None,
    )
    .unwrap();
    let module = builtins.module(CU_MODULE).unwrap();
    let request = json!({
        "module": CU_MODULE,
        "method": "createCAdESFromFile",
        "args": ["PKCS12", "", path.display().to_string(), true],
    })
    .to_string();
    let reply = module
        .process(&request, &origin())
        .into_text()
        .expect("a text reply");
    assert!(
        reply.starts_with(r#"{"responseObject":""#) && reply.ends_with(r#""code":"200"}"#),
        "{}",
        &reply[..reply.len().min(300)]
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn reply_over_256_mib_on_64_bit() {
    // The largest data a message carries base64-encoded, less room for the request's JSON.
    let _turn = one_large_call_at_a_time();
    let size = MAX_MESSAGE / 4 * 3 - MIB;
    let request = cms_request(size);
    assert!(request.len() <= MAX_MESSAGE);
    let builtins = basics(BuiltinLimits::default(), 1);
    let module = builtins.module(MODULE_NAME).unwrap();
    assert!(signed(module.process(&request, &origin())) > MAX_MESSAGE);
}

#[test]
fn fuel_covers_max_message() {
    let _turn = one_large_call_at_a_time();
    // The fuel grows linearly with the data: measured at two sizes, extrapolated to the
    // largest data a message carries, with a margin of four.
    let fuel = |size: usize| {
        let builtins = basics(BuiltinLimits::default(), 1);
        let module = builtins.module(MODULE_NAME).unwrap();
        signed(module.process(&cms_request(size), &origin()));
        builtins.stats(MODULE_NAME).unwrap().max_fuel
    };
    let (small, large) = (4 * MIB, 16 * MIB);
    let (at_small, at_large) = (fuel(small), fuel(large));
    let per_byte = at_large.saturating_sub(at_small) as f64 / (large - small) as f64;
    let at_max = at_large as f64 + per_byte * (MAX_MESSAGE / 4 * 3 - large) as f64;
    assert!(
        4.0 * at_max <= BUILTIN_FUEL as f64,
        "{at_max} fuel for the largest message; {BUILTIN_FUEL} per call"
    );
}

#[test]
fn memory_limit_is_a_drop_not_a_hang() {
    let _turn = one_large_call_at_a_time();
    // Over the guest's memory: data in strings short enough to reach the module itself.
    let short: Vec<String> = (0..64 * 1024).map(|_| "A".repeat(128)).collect();
    let in_guest = json!({
        "module": MODULE_NAME,
        "method": "sign",
        "args": {
            "format": "raw",
            "data": short,
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        },
    })
    .to_string();
    let mut small_memory = BuiltinLimits::default();
    small_memory.instance.max_memory = 4 * MIB;
    // Over what the core keeps for a call: data the module hands to the core, with the
    // request, and while signing (the request and its data decoded fit, the CMS not).
    let mut small_kept = BuiltinLimits::default();
    small_kept.instance.max_kept = 8 * MIB;
    let mut kept_mid_call = BuiltinLimits::default();
    kept_mid_call.instance.max_kept = 20 * MIB;
    for (limits, request) in [
        (small_memory, in_guest),
        (small_kept, cms_request(16 * MIB)),
        (kept_mid_call, cms_request(8 * MIB)),
    ] {
        let builtins = basics(limits, 2);
        let module = builtins.module(MODULE_NAME).unwrap();
        let start = Instant::now();
        assert_eq!(module.process(&request, &origin()), Reply::Drop);
        assert!(start.elapsed() < Duration::from_secs(60));
        // The next call gets a new instance.
        let reply = module
            .process(
                &json!({"module": MODULE_NAME, "method": "sign", "args": {}}).to_string(),
                &origin(),
            )
            .into_text()
            .unwrap();
        assert!(reply.contains(r#""status":false"#), "{reply}");
    }
}

/// The largest attached CMS data, in whole MiB up to 64, the basics module signs within
/// the default limits of this target; prints it.
#[test]
#[ignore = "a measurement"]
fn largest_cms_data() {
    let _turn = one_large_call_at_a_time();
    let fits = |mib: usize| {
        let builtins = basics(BuiltinLimits::default(), 1);
        let module = builtins.module(MODULE_NAME).unwrap();
        module.process(&cms_request(mib * MIB), &origin()) != Reply::Drop
    };
    let (mut low, mut high) = (0, 65);
    while high - low > 1 {
        let mid = (low + high) / 2;
        if fits(mid) {
            low = mid;
        } else {
            high = mid;
        }
    }
    eprintln!("largest attached CMS data: {low} MiB");
}

#[test]
fn calls_without_windows_do_not_wait_for_another_pages_window() {
    // One page's storage window stays open; the calls of other pages that open none
    // answer meanwhile, three at once (the 32-bit cap less the open window's call).
    let opened = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let prompter = Arc::new(ScriptedPrompter::new(vec![
        Step::Wait(Arc::clone(&opened)),
        Step::Wait(Arc::clone(&release)),
        Step::CancelStorage,
    ]));
    let services = HostServices::new(
        prompter,
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(oncl_pki::tsp::MockTsa::new(
            load(
                &read(synthetic("tsa-gost2015").path),
                &synthetic("tsa-gost2015").password,
            )
            .unwrap()
            .remove(0),
        )),
        oncl_token::Tokens::disabled(),
    );
    let builtins = Arc::new(
        Builtins::load(
            &WasmEngine::new(),
            services,
            SOURCES,
            BuiltinLimits::default(),
            None,
        )
        .unwrap(),
    );
    let page = |n: u32| AddInfo {
        origin: Some(format!("https://page{n}.kz")),
        ..AddInfo::default()
    };
    let window = {
        let builtins = Arc::clone(&builtins);
        std::thread::spawn(move || {
            builtins
                .module(MODULE_NAME)
                .unwrap()
                .process(&cms_request(16), &page(1))
        })
    };
    opened.wait();
    let (done, answers) = std::sync::mpsc::channel();
    let no_window = [
        (
            MODULE_NAME,
            json!({"module": MODULE_NAME, "method": "sign", "args": {}}),
        ),
        (
            MODULE_NAME,
            json!({"module": MODULE_NAME, "method": "nope"}),
        ),
        (
            MODULE_NAME,
            json!({"module": MODULE_NAME, "method": "sign", "args": {"format": "x"}}),
        ),
        (
            CU_MODULE,
            json!({"module": CU_MODULE, "method": "getActiveTokens", "args": []}),
        ),
    ];
    for (n, (module, request)) in no_window.into_iter().enumerate() {
        let builtins = Arc::clone(&builtins);
        let done = done.clone();
        std::thread::spawn(move || {
            let reply = builtins
                .module(module)
                .unwrap()
                .process(&request.to_string(), &page(2 + n as u32));
            done.send(reply).unwrap();
        });
    }
    for _ in 0..4 {
        let reply = answers
            .recv_timeout(Duration::from_secs(30))
            .expect("answered while another page's window is open");
        assert!(reply.text().is_some(), "{reply:?}");
    }
    release.wait();
    assert_eq!(
        window.join().unwrap().into_text().unwrap(),
        r#"{"body":{},"status":true}"#
    );
}

/// A request of each built-in module that opens no window, with `extra` (a text of
/// `"key":value` pairs, or nothing) among its top-level keys.
fn windowless_requests(extra: &str) -> Vec<(&'static str, String)> {
    let sep = if extra.is_empty() { "" } else { "," };
    vec![
        (
            MODULE_NAME,
            format!(r#"{{"module":"{MODULE_NAME}","method":"sign","args":{{}}{sep}{extra}}}"#),
        ),
        (
            CU_MODULE,
            format!(
                r#"{{"module":"{CU_MODULE}","method":"getActiveTokens","args":[]{sep}{extra}}}"#
            ),
        ),
        (
            APPLET,
            format!(r#"{{"module":"{APPLET}","method":"getTryCount","args":[]{sep}{extra}}}"#),
        ),
        (
            ACCESSORY,
            format!(r#"{{"module":"{ACCESSORY}","method":"getServices"{sep}{extra}}}"#),
        ),
    ]
}

/// The four built-in modules within the 32-bit limits, opening no window.
fn all_modules() -> Builtins {
    Builtins::load(
        &WasmEngine::new(),
        basics_services(0),
        SOURCES,
        limits_32_bit(),
        None,
    )
    .unwrap()
}

#[test]
fn many_keys_cost_linear_fuel() {
    // Each module reads a request of `keys` extra keys as without them, its fuel growing
    // with the keys' number, not with its square.
    let pairs = |keys: usize| {
        (0..keys)
            .map(|i| format!("\"k{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let plain = windowless_requests("");
    let replies: Vec<Reply> = {
        let builtins = all_modules();
        plain
            .iter()
            .map(|(module, request)| builtins.module(module).unwrap().process(request, &origin()))
            .collect()
    };
    let fuel = |keys: usize| -> Vec<u64> {
        let builtins = all_modules();
        let start = Instant::now();
        let fuel = windowless_requests(&pairs(keys))
            .iter()
            .zip(&replies)
            .map(|((module, request), reply)| {
                assert_eq!(
                    &builtins.module(module).unwrap().process(request, &origin()),
                    reply,
                    "{module}, {keys} keys"
                );
                builtins.stats(module).unwrap().max_fuel
            })
            .collect();
        assert!(start.elapsed() < Duration::from_secs(60), "{keys} keys");
        fuel
    };
    let (small, large) = (fuel(10_000), fuel(80_000));
    for (((module, _), small), large) in plain.iter().zip(small).zip(large) {
        // Eight times the keys: linear is about eight times the fuel, quadratic 64.
        assert!(large <= 12 * small, "{module}: {small} then {large}");
    }
}

#[test]
fn nesting_up_to_the_envelope_limit_answers() {
    // The deepest request the envelope routes (`MAX_DEPTH` levels, the outer object
    // included) is answered as without its deep value; one level more is no crash either.
    let builtins = all_modules();
    // A value of `levels - 1` levels, under the request's object.
    let deep = |levels: usize| {
        let (pairs, odd) = ((levels - 1) / 2, (levels - 1) % 2 == 1);
        format!(
            r#""deep":{}{}{}"#,
            "[{\"a\":".repeat(pairs),
            if odd { "[]" } else { "0" },
            "}]".repeat(pairs)
        )
    };
    let plain = windowless_requests("");
    for ((module, request), (_, at_limit)) in
        plain.iter().zip(windowless_requests(&deep(MAX_DEPTH)))
    {
        let module = builtins.module(module).unwrap();
        assert_eq!(
            module.process(&at_limit, &origin()),
            module.process(request, &origin())
        );
    }
    for (module, over) in windowless_requests(&deep(MAX_DEPTH + 1)) {
        let reply = builtins.module(module).unwrap().process(&over, &origin());
        assert!(reply.text().is_some(), "{module}: {reply:?}");
    }
}
