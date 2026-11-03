//! The core keeps the long strings of a request for a built-in module and hands the module
//! markers in their place; a module must not tell the difference. Every string of the
//! requests of the built-in methods the tests cover is made long (more than the 16 KiB the
//! core keeps, and in a batch of more than 1 MiB), and the module with markers and the same
//! module without (`InstanceLimits::keep_request`) must give the same reply, show the same
//! windows and fail with the same causes.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oncl_builtin_tests::{SOURCES, accessory, applet, basics, commonutils};
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::cms::SignOptions;
use oncl_pki::info::cert_info;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::MockTsa;
use oncl_plugin::core::{Bundles, CoreHooks, UiCallback};
use oncl_plugin::{BuiltinLimits, Builtins, Engine, HostServices};
use oncl_protocol::{AddInfo, Reply};
use oncl_testkit::{read, synthetic, synthetic_cert};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use time::OffsetDateTime;

/// A string longer than the core keeps (16 KiB), in bytes.
const LONG: usize = 20_000;

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

/// The middle of the synthetic RSA key's validity: its signatures are deterministic.
fn at() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| {
        let info = cert_info(&entry("user-rsa-sign").cert);
        info.not_before + (info.not_after - info.not_before) / 2
    });
    *AT
}

/// The storage and key dialogs answered with the synthetic RSA key, `times` times.
fn rsa(times: usize) -> Vec<Step> {
    let key = synthetic("user-rsa-sign");
    (0..times)
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

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn cert_pem() -> String {
    oncl_pki::pem::encode("CERTIFICATE", &synthetic_cert("root-rsa"))
}

/// A copy of the synthetic RSA key's file as `k.p12` in `dir`: its path, password and alias.
fn key_file(dir: &Path) -> (String, String, String) {
    let key = synthetic("user-rsa-sign");
    let file = dir.join("k.p12");
    std::fs::copy(&key.path, &file).unwrap();
    (dir_text(&file), key.password, key.aliases[0].clone())
}

const XML: &str = "<a><b>x</b></a>";
const GOST2004: &str = "1.2.398.3.10.1.1.1.2";
const GOST2015: &str = "1.2.398.3.10.1.1.2.3.2";

/// What a case sends and answers the windows with, in a folder of its own.
struct Run {
    request: Value,
    steps: Vec<Step>,
}

/// A request of a built-in module.
struct Case {
    name: &'static str,
    module: &'static str,
    /// Replies carry keys or signatures that differ from call to call: compared with the
    /// long runs of base64 left out.
    random: bool,
    build: fn(&Path) -> Run,
}

fn case(name: &'static str, module: &'static str, random: bool, build: fn(&Path) -> Run) -> Case {
    Case {
        name,
        module,
        random,
        build,
    }
}

fn basics_sign(args: Value, steps: Vec<Step>) -> Run {
    Run {
        request: json!({"module": basics::MODULE_NAME, "method": "sign", "args": args}),
        steps,
    }
}

fn basics_args(format: &str, data: Value, signing: Value) -> Value {
    json!({
        "format": format,
        "data": data,
        "signingParams": signing,
        "signerParams": {"extKeyUsageOids": [], "chain": []},
    })
}

fn csr_args() -> Value {
    json!({
        "allowedStorages": ["PKCS12", "AKKaztokenStore"],
        "defaultPassword": "Default1",
        "dn": {"2.5.4.3": "ТЕСТОВ ТЕСТ", "2.5.4.5": "IIN123456789012", "2.5.4.6": "KZ"},
        "email": "test@example.kz",
        "params": [{"algorithm": GOST2015, "length": 512}],
        "locale": "ru",
    })
}

fn cu(method: &str, args: Value) -> Value {
    json!({"module": commonutils::MODULE_NAME, "method": method, "args": args, "uuid": "u-1"})
}

fn applet_request(method: &str, args: Value) -> Value {
    json!({"method": method, "args": args, "uuid": "u-1"})
}

fn dir_text(dir: &Path) -> String {
    dir.to_str().unwrap().to_owned()
}

fn cases() -> Vec<Case> {
    let basics_m = basics::MODULE_NAME;
    let cu_m = commonutils::MODULE_NAME;
    let applet_m = applet::MODULE_NAME;
    let acc_m = accessory::MODULE_NAME;
    vec![
        // --- basics -------------------------------------------------------------------------
        case("basics sign cms", basics_m, false, |_| {
            basics_sign(
                basics_args(
                    "cms",
                    json!(b64(b"hello document")),
                    json!({"decode": true, "encapsulate": true}),
                ),
                rsa(3),
            )
        }),
        case("basics sign cms batch", basics_m, false, |_| {
            basics_sign(
                basics_args(
                    "cms",
                    json!([b64(b"one"), b64(b"two")]),
                    json!({"decode": true}),
                ),
                rsa(3),
            )
        }),
        case("basics sign cms text", basics_m, false, |_| {
            let mut args = basics_args("cms", json!("hello"), json!({"encapsulate": false}));
            args["locale"] = json!("ru");
            args["allowedStorages"] = json!(["PKCS12", "JKS"]);
            basics_sign(args, rsa(3))
        }),
        case("basics sign cms time-stamped", basics_m, true, |_| {
            basics_sign(
                basics_args(
                    "cms",
                    json!(b64(b"stamped")),
                    json!({"decode": true, "tsaProfile": {"url": "http://tsp.pki.gov.kz"}}),
                ),
                rsa(3),
            )
        }),
        case("basics sign raw", basics_m, false, |_| {
            basics_sign(
                basics_args("raw", json!(b64(b"raw data")), json!({"decode": true})),
                rsa(3),
            )
        }),
        case("basics sign xml", basics_m, false, |_| {
            basics_sign(basics_args("xml", json!(XML), json!({})), rsa(3))
        }),
        case("basics sign filters", basics_m, false, |_| {
            let mut args = basics_args("cms", json!("x"), json!({}));
            args["signerParams"] = json!({
                "extKeyUsageOids": ["1.3.6.1.5.5.7.3.4"],
                "iin": "123456789012",
                "bin": "123456789012",
                "serialNumber": "1",
                "chain": [b64(&synthetic_cert("root-rsa"))],
            });
            // The key the chain does not allow is refused, then the user gives up.
            basics_sign(args, [rsa(1), vec![Step::CancelKey]].concat())
        }),
        case("basics generateCsr", basics_m, true, |dir| Run {
            request: json!({
                "module": basics::MODULE_NAME,
                "class": "PKIEssentials",
                "method": "generateCsr",
                "args": csr_args(),
            }),
            steps: vec![Step::Csr {
                dir: dir.to_path_buf(),
                password: String::new(),
            }],
        }),
        case("basics importCertificate", basics_m, false, |dir| Run {
            request: json!({
                "module": basics::MODULE_NAME,
                "class": "PKIEssentials",
                "method": "importCertificate",
                "args": {
                    "allowedStorage": "PKCS12",
                    "defaultPassword": "Default1",
                    "keystorePath": dir_text(dir),
                    "certificates": [cert_pem()],
                    "locale": "kk",
                },
            }),
            steps: vec![Step::Import {
                dir: dir.to_path_buf(),
                password: "NewSecret12".to_owned(),
            }],
        }),
        case("basics unknown method and class", basics_m, false, |_| {
            Run {
                request: json!({
                    "module": basics::MODULE_NAME,
                    "class": "PKIExtras",
                    "method": "nope",
                    "args": {},
                }),
                steps: Vec::new(),
            }
        }),
        // --- commonUtils --------------------------------------------------------------------
        case("commonUtils getActiveTokens", cu_m, false, |_| Run {
            request: cu("getActiveTokens", json!([])),
            steps: Vec::new(),
        }),
        case("commonUtils getKeyInfo", cu_m, false, |_| Run {
            request: cu("getKeyInfo", json!(["PKCS12"])),
            steps: rsa(2),
        }),
        case("commonUtils signXml", cu_m, false, |_| Run {
            request: cu("signXml", json!(["PKCS12", "", XML, "", ""])),
            steps: rsa(2),
        }),
        case("commonUtils signXml element", cu_m, false, |_| Run {
            request: cu(
                "signXml",
                json!(["PKCS12", "", r#"<a><b Id="b1">x</b></a>"#, "//b", "/a"]),
            ),
            steps: rsa(2),
        }),
        case("commonUtils signXmls", cu_m, false, |_| Run {
            request: cu("signXmls", json!(["PKCS12", "", [XML, "<c/>"], "", ""])),
            steps: rsa(2),
        }),
        case(
            "commonUtils createCMSSignatureFromBase64",
            cu_m,
            true,
            |_| Run {
                request: cu(
                    "createCMSSignatureFromBase64",
                    json!(["PKCS12", "", b64(b"doc"), true]),
                ),
                steps: rsa(2),
            },
        ),
        case(
            "commonUtils createCMSSignatureFromFile",
            cu_m,
            true,
            |dir| {
                let file = dir.join("doc.bin");
                std::fs::write(&file, b"file contents").unwrap();
                Run {
                    request: cu(
                        "createCMSSignatureFromFile",
                        json!(["PKCS12", "", dir_text(&file), false]),
                    ),
                    steps: [rsa(2), vec![Step::Confirm { yes: true }]].concat(),
                }
            },
        ),
        case("commonUtils createCAdESFromBase64", cu_m, false, |_| Run {
            request: cu(
                "createCAdESFromBase64",
                json!(["PKCS12", "", b64(b"doc"), true]),
            ),
            steps: rsa(2),
        }),
        case("commonUtils createCAdESFromFile", cu_m, false, |dir| {
            let file = dir.join("doc.bin");
            std::fs::write(&file, b"file contents").unwrap();
            Run {
                request: cu(
                    "createCAdESFromFile",
                    json!(["PKCS12", "", dir_text(&file), false]),
                ),
                steps: [rsa(2), vec![Step::Confirm { yes: true }]].concat(),
            }
        }),
        case("commonUtils createCAdESFromBase64Hash", cu_m, false, |_| {
            Run {
                request: cu(
                    "createCAdESFromBase64Hash",
                    json!(["PKCS12", "", b64(&[7u8; 32])]),
                ),
                steps: rsa(2),
            }
        }),
        case("commonUtils applyCAdEST", cu_m, true, |_| {
            let cms = oncl_pki::cms::sign(
                &entry("user-rsa-sign"),
                b"doc",
                &SignOptions {
                    encapsulate: true,
                    digested: false,
                    signing_time: at(),
                },
            )
            .unwrap();
            Run {
                request: cu("applyCAdEST", json!(["PKCS12", "", b64(&cms)])),
                steps: rsa(2),
            }
        }),
        case("commonUtils showFileChooser", cu_m, false, |dir| Run {
            request: cu("showFileChooser", json!(["ALL", dir_text(dir)])),
            steps: vec![Step::CancelFile],
        }),
        case("commonUtils changeLocale", cu_m, false, |_| Run {
            request: cu("changeLocale", json!(["ru"])),
            steps: Vec::new(),
        }),
        case("commonUtils private and unknown", cu_m, false, |dir| Run {
            request: cu("getBase64FromFile", json!([dir_text(dir)])),
            steps: Vec::new(),
        }),
        case("commonUtils unknown method", cu_m, false, |_| Run {
            request: cu("nope", json!(["x"])),
            steps: Vec::new(),
        }),
        // --- Applet -------------------------------------------------------------------------
        case("applet showFileChooser", applet_m, false, |dir| Run {
            request: applet_request("showFileChooser", json!(["P12", dir_text(dir)])),
            steps: vec![Step::CancelFile],
        }),
        case("applet browseKeyStore", applet_m, false, |dir| Run {
            request: applet_request(
                "browseKeyStore",
                json!(["PKCS12", "KEYSTORE", dir_text(dir)]),
            ),
            steps: vec![Step::CancelFile],
        }),
        case("applet setPassword", applet_m, false, |_| Run {
            request: applet_request("setPassword", json!(["Введите PIN:"])),
            steps: vec![Step::Password("1234".to_owned())],
        }),
        case("applet loadSlotList", applet_m, false, |_| Run {
            request: applet_request("loadSlotList", json!(["AKKaztokenStore"])),
            steps: Vec::new(),
        }),
        case("applet getPublicPartInfo", applet_m, false, |_| Run {
            request: applet_request("getPublicPartInfo", json!(["terminal"])),
            steps: Vec::new(),
        }),
        case("applet genKeyPairAndGetPKCS10", applet_m, true, |dir| Run {
            request: applet_request(
                "genKeyPairAndGetPKCS10",
                json!([
                    "PKCS12",
                    dir_text(dir),
                    "Default1",
                    ["alias"],
                    [GOST2004],
                    [256],
                    "2.5.4.3<:>2.5.4.6",
                    "Тест<:>KZ",
                    ""
                ]),
            ),
            steps: Vec::new(),
        }),
        case("applet setX509CertToKeyStore", applet_m, false, |dir| Run {
            request: applet_request(
                "setX509CertToKeyStore",
                json!(["PKCS12", dir_text(dir), "Default1", cert_pem()]),
            ),
            steps: Vec::new(),
        }),
        case(
            "applet setX509CertToKeyStoreAndChangePassword",
            applet_m,
            false,
            |dir| Run {
                request: applet_request(
                    "setX509CertToKeyStoreAndChangePassword",
                    json!([
                        "PKCS12",
                        dir_text(dir),
                        "Default1",
                        cert_pem(),
                        "NewSecret12"
                    ]),
                ),
                steps: Vec::new(),
            },
        ),
        case("applet changePassword", applet_m, false, |dir| {
            let (file, password, _) = key_file(dir);
            Run {
                request: applet_request(
                    "changePassword",
                    json!(["PKCS12", file, password, "Qwerty12#"]),
                ),
                steps: Vec::new(),
            }
        }),
        case("applet signXml", applet_m, false, |_| Run {
            request: applet_request("signXml", json!(["PKCS12", "", "SIGN", XML])),
            steps: rsa(2),
        }),
        case("applet deleteEntry", applet_m, false, |dir| {
            let (file, _, alias) = key_file(dir);
            Run {
                request: applet_request("deleteEntry", json!(["PKCS12", file, alias])),
                steps: Vec::new(),
            }
        }),
        case("applet resetStorage", applet_m, false, |dir| Run {
            request: applet_request(
                "resetStorage",
                json!(["PKCS12", dir_text(&dir.join("k.p12"))]),
            ),
            steps: Vec::new(),
        }),
        case("applet getTryCount", applet_m, false, |_| Run {
            request: applet_request("getTryCount", json!([])),
            steps: Vec::new(),
        }),
        case("applet unknown method", applet_m, false, |_| Run {
            request: applet_request("nope", json!(["x"])),
            steps: Vec::new(),
        }),
        // --- accessory ----------------------------------------------------------------------
        case("accessory getBundles", acc_m, false, |_| Run {
            request: json!({"method": "getBundles", "uuid": "u-1"}),
            steps: Vec::new(),
        }),
        case("accessory getServices", acc_m, false, |_| Run {
            request: json!({"method": "getServices", "uuid": "u-1"}),
            steps: Vec::new(),
        }),
        case("accessory installBundle", acc_m, false, |_| Run {
            request: json!({"method": "installBundle", "symname": "kz.example.A", "uuid": "u-1"}),
            steps: Vec::new(),
        }),
        case("accessory showSettings", acc_m, false, |_| Run {
            request: json!({"method": "showSettings", "uuid": "u-1"}),
            steps: Vec::new(),
        }),
    ]
}

/// Plugins the accessory module reports: none.
struct NoBundles;

impl Bundles for NoBundles {
    fn services(&self) -> Vec<String> {
        Vec::new()
    }

    fn bundles(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn request_install(&self, _: &str, _: &str) -> bool {
        false
    }
}

/// What a call came to.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    reply: String,
    windows: Vec<&'static str>,
    mismatches: Vec<String>,
}

/// `request` answered by the module `name` with or without the markers of long strings, the
/// windows answered with `steps`.
fn call(
    name: &str,
    request: &str,
    steps: Vec<Step>,
    keep_request: bool,
) -> (Outcome, Arc<Builtins>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let mut services = HostServices::interactive(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        tsa,
        oncl_token::Tokens::disabled(),
    );
    services.clock = at;
    services.cas = Arc::new(oncl_pki::pkix::CaSet::new(
        [
            "root-gost2015",
            "root-gost2004",
            "root-rsa",
            "inter-gost2015",
        ]
        .into_iter()
        .map(|n| oncl_pki::cert::parse(&synthetic_cert(n)).unwrap())
        .collect(),
    ));
    let hooks = Arc::new(CoreHooks {
        builtin_modules: vec![
            "kz.gov.pki.knca.applet.Applet".to_owned(),
            "kz.gov.pki.knca.basics".to_owned(),
            "kz.gov.pki.knca.commonUtils".to_owned(),
            accessory::MODULE_NAME.to_owned(),
        ],
        bundles: Arc::new(NoBundles),
        ui: Arc::new(|_| {}) as UiCallback,
        core_version: "0.0.0".to_owned(),
    });
    let source: Vec<_> = SOURCES
        .iter()
        .copied()
        .filter(|s| Builtins::names(&[*s]).is_ok_and(|names| names.iter().any(|n| n == name)))
        .collect();
    let mut limits = BuiltinLimits::default();
    limits.instance.keep_request = keep_request;
    let builtins = Arc::new(
        Builtins::load(&Engine::new(), services, &source, limits, Some(hooks)).expect("loads"),
    );
    let module = builtins.module(name).expect("a built-in module");
    let reply = module.process(
        request,
        &AddInfo {
            origin: Some("https://x.kz".to_owned()),
            ..AddInfo::default()
        },
    );
    let reply = match reply {
        Reply::Drop => "<the connection is dropped>".to_owned(),
        other => other.text().expect("a text reply").to_owned(),
    };
    let outcome = Outcome {
        reply,
        windows: prompter.timeline(),
        mismatches: prompter.mismatches(),
    };
    (outcome, builtins)
}

/// `text` without the `dir` of the call, and, for `random` replies, without the long runs
/// of base64 (the keys and signatures that differ from call to call).
fn normalized(text: &str, dir: &Path, random: bool) -> String {
    let dir = dir_text(dir);
    let escaped = dir.replace('\\', "\\\\");
    let text = text.replace(&escaped, "<dir>").replace(&dir, "<dir>");
    if !random {
        return text;
    }
    // The bodies of PEM blocks: their last line is short.
    let mut pem = String::new();
    let mut rest = text.as_str();
    while let Some(begin) = rest.find("-----BEGIN ") {
        let header = begin + "-----BEGIN ".len();
        let Some(close) = rest[header..].find("-----").map(|i| header + i + 5) else {
            break;
        };
        let Some(end) = rest[close..].find("-----END ").map(|i| close + i) else {
            break;
        };
        pem.push_str(&rest[..close]);
        pem.push_str("<b64>");
        rest = &rest[end..];
    }
    pem.push_str(rest);
    let text = pem;
    fn flush(out: &mut String, run: &mut String) {
        if run.len() >= 24 {
            out.push_str("<b64>");
        } else {
            out.push_str(run);
        }
        run.clear();
    }
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            run.push(c);
        } else {
            flush(&mut out, &mut run);
            out.push(c);
        }
    }
    flush(&mut out, &mut run);
    out
}

/// Where the strings of `value` are, as JSON pointers; object keys are not strings of the
/// request that the core keeps.
fn strings(value: &Value, at: &mut String, out: &mut Vec<String>) {
    match value {
        Value::String(_) => out.push(at.clone()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let len = at.len();
                at.push_str(&format!("/{i}"));
                strings(item, at, out);
                at.truncate(len);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let len = at.len();
                at.push('/');
                at.push_str(&key.replace('~', "~0").replace('/', "~1"));
                strings(item, at, out);
                at.truncate(len);
            }
        }
        _ => {}
    }
}

/// `text` made long in ways that keep it meaningful to the readers of different kinds of
/// parameters: base64 decodes to a long document, an XML document gets a long comment and
/// a long text, anything else a long tail or head.
fn variants(text: &str) -> Vec<(&'static str, String)> {
    let filler = "A".repeat(LONG);
    let mut out = vec![
        ("tail", format!("{text}{filler}")),
        ("head", format!("{filler}{text}")),
        ("whole", filler.clone()),
        // Not base64 in the middle of base64: the decoder's message names the place.
        (
            "bad base64",
            format!("{}!{}", &filler[..LONG / 2], &filler[..LONG / 2]),
        ),
        ("non-ASCII", "ж".repeat(LONG / 2)),
        (
            "escapes",
            format!("{text}{}", "\"\\\n\t/</é😀\u{1f}".repeat(LONG / 16)),
        ),
    ];
    if let Ok(data) = STANDARD.decode(text)
        && !text.is_empty()
    {
        let long: Vec<u8> = data.iter().copied().cycle().take(LONG).collect();
        out.push(("document", STANDARD.encode(long)));
    }
    if text.starts_with('<') {
        out.push(("xml comment", format!("{text}<!--{filler}-->")));
        out.push(("xml text", text.replacen('>', &format!(">{filler}"), 1)));
    }
    out
}

/// What the request of `case` with the string at `pointer` replaced by `replacement` (the
/// request as it is if `None`) gets with and without markers: the two outcomes, as compared.
fn both_ways(case: &Case, pointer: &str, replacement: Option<&str>) -> (Outcome, Outcome) {
    let mut outcomes = Vec::new();
    for keep in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let mut run = (case.build)(dir.path());
        if let Some(replacement) = replacement {
            *run.request.pointer_mut(pointer).expect("a string") = json!(replacement);
        }
        let (mut outcome, _) = call(case.module, &run.request.to_string(), run.steps, keep);
        outcome.reply = normalized(&outcome.reply, dir.path(), case.random);
        outcomes.push(outcome);
    }
    let without = outcomes.pop().unwrap();
    let with = outcomes.pop().unwrap();
    (with, without)
}

/// The first place two replies differ, with some of what surrounds it.
fn first_difference(a: &str, b: &str) -> String {
    let at = a
        .bytes()
        .zip(b.bytes())
        .position(|(x, y)| x != y)
        .unwrap_or_else(|| a.len().min(b.len()));
    let show = |s: &str| {
        let from = s.floor_char_boundary(at.saturating_sub(60));
        let to = s.ceil_char_boundary((at + 120).min(s.len()));
        format!("({} bytes) …{}…", s.len(), &s[from..to])
    };
    format!("at {at}: with {}; without {}", show(a), show(b))
}

/// Runs `work` for every item on as many threads as there are cores (at most 8), and gives
/// the lines the items complained with.
fn in_parallel<T: Sync>(items: &[T], work: impl Fn(&T) -> Option<String> + Sync) -> Vec<String> {
    let next = AtomicUsize::new(0);
    let complaints = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism()
        .map_or(2, usize::from)
        .min(8);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    if let Some(complaint) = work(item) {
                        complaints.lock().unwrap().push(complaint);
                    }
                }
            });
        }
    });
    let mut complaints = complaints.into_inner().unwrap();
    complaints.sort();
    complaints
}

/// Compares the two ways of one request; the line to complain with if they differ.
fn compare(case: &Case, pointer: &str, how: &str, replacement: Option<&str>) -> Option<String> {
    let (with, without) = both_ways(case, pointer, replacement);
    if with == without {
        return None;
    }
    let what = if with.reply != without.reply {
        first_difference(&with.reply, &without.reply)
    } else {
        format!(
            "windows {:?} / {:?}, mismatches {:?} / {:?}",
            with.windows, without.windows, with.mismatches, without.mismatches
        )
    };
    Some(format!("{} {pointer} [{how}]: {what}", case.name))
}

#[test]
fn every_long_string_gets_the_same_reply_with_and_without_markers() {
    let cases = cases();
    let mut items = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let run = (case.build)(dir.path());
        let mut found = Vec::new();
        strings(&run.request, &mut String::new(), &mut found);
        // The routing fields stay as they are: the core reads them before the module.
        found.retain(|p| p != "/module");
        items.push((i, String::new(), "as is".to_owned(), None));
        // The script of the case and its flow agree: no window met another kind of answer.
        let (with, _) = both_ways(case, "", None);
        assert_eq!(with.mismatches, Vec::<String>::new(), "{}", case.name);
        for pointer in found {
            let text = run.request.pointer(&pointer).unwrap().as_str().unwrap();
            for (how, long) in variants(text) {
                items.push((i, pointer.clone(), how.to_owned(), Some(long)));
            }
        }
    }
    let complaints = in_parallel(&items, |(i, pointer, how, long)| {
        compare(&cases[*i], pointer, how, long.as_deref())
    });
    assert!(
        complaints.is_empty(),
        "{} of {} calls differ:\n{}",
        complaints.len(),
        items.len(),
        complaints.join("\n")
    );
}

/// A batch of more than 1 MiB of short documents: the core keeps documents of 64 bytes.
#[test]
fn a_batch_of_short_documents_gets_the_same_reply_with_and_without_markers() {
    let batch = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| format!("<d n=\"{i}\">{}</d>", "x".repeat(70)))
            .collect()
    };
    let documents = batch(16_000);
    assert!(documents.iter().map(String::len).sum::<usize>() > 1 << 20);
    let basics_cms: Vec<String> = documents.iter().map(|d| b64(d.as_bytes())).collect();
    let requests = [
        (
            basics::MODULE_NAME,
            false,
            json!({
                "module": basics::MODULE_NAME,
                "method": "sign",
                "args": basics_args("cms", json!(basics_cms), json!({"decode": true})),
            }),
        ),
        (
            basics::MODULE_NAME,
            false,
            json!({
                "module": basics::MODULE_NAME,
                "method": "sign",
                "args": basics_args("xml", json!(documents), json!({})),
            }),
        ),
        (
            commonutils::MODULE_NAME,
            false,
            cu("signXmls", json!(["PKCS12", "", documents, "", ""])),
        ),
    ];
    // The key dialog is cancelled: no signature is made, but the batch is read and kept.
    for (module, _, request) in &requests {
        let steps = || vec![Step::CancelStorage];
        let (with, _) = call(module, &request.to_string(), steps(), true);
        let (without, _) = call(module, &request.to_string(), steps(), false);
        assert_eq!(with, without, "{request:.200}");
    }
}

/// The switch does what it says: a long document stays out of the module's memory with
/// markers, and goes through it without.
#[test]
fn markers_keep_a_long_document_out_of_the_module() {
    let request = json!({
        "module": basics::MODULE_NAME,
        "method": "sign",
        "args": basics_args("raw", json!(b64(&vec![9u8; 4 << 20])), json!({"decode": true})),
    })
    .to_string();
    let mut peaks = Vec::new();
    for keep in [true, false] {
        let (outcome, builtins) = call(basics::MODULE_NAME, &request, rsa(1), keep);
        assert!(
            outcome.reply.contains(r#""status":true"#),
            "{}",
            outcome.reply
        );
        peaks.push(builtins.stats(basics::MODULE_NAME).unwrap().peak_memory);
    }
    assert!(
        peaks[0] < peaks[1],
        "memory with markers {} and without {}",
        peaks[0],
        peaks[1]
    );
}
