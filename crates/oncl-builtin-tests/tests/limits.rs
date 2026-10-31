//! The largest requests the built-in modules take within their limits, on 64- and 32-bit
//! targets: the largest page file signs, a reply may be larger than the largest message,
//! the fuel of a call covers the largest message, and running out of memory drops the
//! connection at once.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_builtin_tests::SOURCES;
use oncl_builtin_tests::basics::MODULE_NAME;
use oncl_pki::info::cert_info;
use oncl_pki::pkcs12::load;
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{BUILTIN_FUEL, BuiltinLimits, Builtins, Engine as WasmEngine, HostServices};
use oncl_protocol::{AddInfo, Reply};
use oncl_testkit::{read, synthetic};
use serde_json::json;
use std::sync::{Arc, LazyLock};
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
    Builtins::load(&WasmEngine::new(), services, SOURCES, limits, None).unwrap()
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

/// The reply's length, the reply a signature.
fn signed(reply: Reply) -> usize {
    let text = reply.into_text().expect("a text reply");
    assert!(
        text.starts_with(r#"{"status":true"#),
        "{}",
        &text[..text.len().min(300)]
    );
    text.len()
}

#[test]
#[cfg_attr(
    not(target_pointer_width = "64"),
    ignore = "over the 32-bit memory of an instance: 33 MiB of data fit (`largest_cms_data`)"
)]
fn sign_max_page_file_fits() {
    let builtins = basics(BuiltinLimits::default(), 1);
    let module = builtins.module(MODULE_NAME).unwrap();
    signed(module.process(&cms_request(48 * MIB), &origin()));
}

#[cfg(target_pointer_width = "64")]
#[test]
fn reply_over_256_mib_on_64_bit() {
    // The largest data a message carries base64-encoded, less room for the request's JSON.
    let size = MAX_MESSAGE / 4 * 3 - MIB;
    let request = cms_request(size);
    assert!(request.len() <= MAX_MESSAGE);
    let builtins = basics(BuiltinLimits::default(), 1);
    let module = builtins.module(MODULE_NAME).unwrap();
    assert!(signed(module.process(&request, &origin())) > MAX_MESSAGE);
}

#[test]
fn fuel_covers_max_message() {
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
    let per_byte = (at_large - at_small) as f64 / (large - small) as f64;
    let at_max = at_large as f64 + per_byte * (MAX_MESSAGE / 4 * 3 - large) as f64;
    assert!(
        4.0 * at_max <= BUILTIN_FUEL as f64,
        "{at_max} fuel for the largest message; {BUILTIN_FUEL} per call"
    );
}

#[test]
fn memory_limit_is_a_drop_not_a_hang() {
    let mut limits = BuiltinLimits::default();
    limits.instance.max_memory = 32 * MIB;
    let builtins = basics(limits, 1);
    let module = builtins.module(MODULE_NAME).unwrap();
    let start = Instant::now();
    assert_eq!(
        module.process(&cms_request(16 * MIB), &origin()),
        Reply::Drop
    );
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

/// The largest attached CMS data, in whole MiB up to 64, the basics module signs within
/// the default limits of this target; prints it.
#[test]
#[ignore = "a measurement"]
fn largest_cms_data() {
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
