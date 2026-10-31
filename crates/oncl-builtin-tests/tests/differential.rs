//! The Applet module's native code and its WebAssembly guest on the same requests: the
//! replies, every window the module showed (in order, with the busy indicator), the key
//! files left in the case's folder and the commands sent to emulated tokens must be the
//! same. Generated keys are random: their requests compare by their contents without the
//! key, their identifiers by their form.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::{Decode, Encode};
use oncl_basics::StorageKind;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_builtin_tests::Backend;
use oncl_builtin_tests::applet::Applet;
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{fixture, synthetic};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenKind, Tokens};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use x509_cert::request::{CertReq, ExtensionReq};

const GOST2004: &str = "1.2.398.3.10.1.1.1.2";
const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
const DEFAULT_PASSWORD: &str = "Default1";
const NEW_PASSWORD: &str = "NewSecret12";
const R0: &str = "OpenNCALayer Emulated Reader 0";
const R1: &str = "OpenNCALayer Emulated Reader 1";
const KAZTOKEN: StorageKind = StorageKind::Token("AKKaztokenStore");

/// One scenario: the answers, the requests (sent in order to one module), its tokens.
struct Case {
    steps: Vec<Step>,
    requests: Vec<Value>,
    /// Emulated cards in the readers R0, R1, …, and whether token support is on.
    cards: Option<(Vec<CardSpec>, bool)>,
}

impl Case {
    fn new(steps: Vec<Step>, requests: Vec<Value>) -> Self {
        Case {
            steps,
            requests,
            cards: None,
        }
    }
}

/// What one implementation did.
#[derive(Debug, PartialEq)]
struct Run {
    replies: Vec<Value>,
    windows: String,
    files: Vec<String>,
    commands: usize,
}

fn origin() -> AddInfo {
    AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    }
}

fn run(backend: Backend, case: Case, dir: &Path) -> Run {
    let prompter = Arc::new(ScriptedPrompter::new(case.steps));
    let mut applet = Applet::new(prompter.clone()).with_backend(backend);
    let mut readers = Vec::new();
    let mut emulator = None;
    if let Some((cards, enabled)) = case.cards {
        let emu = Arc::new(EmulatorBackend::new());
        for (i, spec) in cards.into_iter().enumerate() {
            let reader = format!("OpenNCALayer Emulated Reader {i}");
            emu.add_reader(&reader);
            emu.insert(&reader, card(spec));
            readers.push(reader);
        }
        applet = applet.with_tokens(Tokens::new(emu.clone(), enabled));
        emulator = Some(emu);
    }
    let replies = case
        .requests
        .iter()
        .map(|request| {
            let reply = applet.process(&request.to_string(), &origin());
            let reply: Value = serde_json::from_str(reply.text().unwrap()).unwrap();
            normalized(reply, dir)
        })
        .collect();
    let p = &prompter;
    let reader_prompts: Vec<_> = p
        .reader_prompts()
        .iter()
        .map(|r| (r.origin.clone(), r.locale, r.storage, r.readers.current()))
        .collect();
    let windows = format!(
        "{:#?}",
        (
            p.timeline(),
            p.storage_prompts(),
            p.busy_prompts(),
            p.opened_key_prompts(),
            p.key_prompts(),
            p.file_prompts(),
            p.password_prompts(),
            p.message_prompts(),
            reader_prompts,
        )
    );
    let mut files: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            // Generated key files are named after their (random) key.
            match name.rsplit_once('_') {
                Some((prefix, _)) => format!("{prefix}_<key>"),
                None => name,
            }
        })
        .collect();
    files.sort();
    let commands = emulator.map_or(0, |emu| {
        readers.iter().map(|r| emu.exchanges(r).len()).sum()
    });
    Run {
        replies,
        windows: without_dir(&windows, dir),
        files,
        commands,
    }
}

/// `text` with `dir` (as displayed or escaped) replaced by `<dir>`.
fn without_dir(text: &str, dir: &Path) -> String {
    let shown = dir.display().to_string();
    let escaped = shown.replace('\\', "\\\\");
    text.replace(&escaped, "<dir>").replace(&shown, "<dir>")
}

/// The reply with the case's folder and the random parts of generated keys replaced by
/// what they must be: requests by their contents without the key, key identifiers by their
/// form.
fn normalized(reply: Value, dir: &Path) -> Value {
    match reply {
        Value::Object(mut map) => {
            if let Some(Value::String(result)) = map.get("result")
                && result.starts_with("-----BEGIN NEW CERTIFICATE REQUEST-----")
            {
                let summary: Vec<String> = result.split("<:>").map(request_summary).collect();
                map.insert("result".to_owned(), json!(summary));
                let ids = map["secondResult"].as_str().unwrap();
                let forms: Vec<bool> = ids
                    .split("<:>")
                    .map(|id| id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit()))
                    .collect();
                map.insert("secondResult".to_owned(), json!(forms));
            }
            Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, normalized(v, dir)))
                    .collect(),
            )
        }
        Value::String(s) => Value::String(without_dir(&s, dir)),
        other => other,
    }
}

/// A request's subject, algorithm and extensions (without the key's identifier), its
/// signature checked with its key.
fn request_summary(pem: &str) -> String {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let req = CertReq::from_der(&STANDARD.decode(body).unwrap()).unwrap();
    let public = PublicKey::from_spki(&req.info.public_key).unwrap();
    let alg = [SigAlg::Gost2004, SigAlg::RsaSha256]
        .into_iter()
        .find(|a| a.signature_oid() == req.algorithm.oid)
        .unwrap();
    public
        .verify(
            alg,
            &req.info.to_der().unwrap(),
            req.signature.as_bytes().unwrap(),
        )
        .unwrap();
    let extensions: Vec<String> = req
        .info
        .attributes
        .iter()
        .flat_map(|a| a.values.iter())
        .flat_map(|v| ExtensionReq::from_der(&v.to_der().unwrap()).unwrap().0)
        .map(|e| format!("{} {}", e.extn_id, e.critical))
        .collect();
    format!(
        "CSR {:?} {} {:02x?} {extensions:?}",
        req.info.version,
        req.algorithm.oid,
        req.info.subject.to_der().unwrap()
    )
}

/// Runs `case(dir)` on both implementations, each in a fresh folder prepared by `prepare`:
/// what they both did.
fn same_with(prepare: impl Fn(&Path), case: impl Fn(&Path) -> Case) -> Run {
    let wasm_dir = tempfile::tempdir().unwrap();
    let native_dir = tempfile::tempdir().unwrap();
    prepare(wasm_dir.path());
    prepare(native_dir.path());
    let wasm = run(Backend::Wasm, case(wasm_dir.path()), wasm_dir.path());
    let native = run(Backend::Native, case(native_dir.path()), native_dir.path());
    assert_eq!(wasm, native);
    wasm
}

fn same(case: impl Fn(&Path) -> Case) -> Run {
    same_with(|_| {}, case)
}

/// The `errorCode`s of a run's replies.
fn codes(run: &Run) -> Vec<&str> {
    run.replies
        .iter()
        .map(|r| r["errorCode"].as_str().unwrap())
        .collect()
}

fn call(method: &str, args: Value) -> Value {
    json!({"method": method, "args": args})
}

fn d(dir: &Path) -> String {
    dir.display().to_string()
}

fn storage(name: &str) -> Step {
    let key = synthetic(name);
    Step::Storage {
        path: key.path,
        password: key.password,
    }
}

#[test]
fn applet_dispatcher_and_no_device() {
    let run = same(|_| {
        let mut requests = vec![
            json!({"method": "getTryCount", "uuid": "u1"}),
            json!({"class": "kz.gov.pki.knca.applet.MainApplet", "method": "getTryCount"}),
            json!({"class": null, "method": "getTryCount", "args": "x"}),
            json!({"method": "nope", "uuid": "u"}),
            json!({"method": ""}),
            json!({"args": []}),
            json!({"method": 5}),
            json!("not an object"),
            call("getTryCount", json!([1])),
            call("genExt", json!(["2.5.29.15"])),
            call("setTryCount", json!([5])),
            call("getStorage", json!([[1, 2]])),
            call("loadSlotList", json!([1])),
            call("loadSlotList", json!([["PKCS12"]])),
            json!({"method": "loadSlotList", "args": ["PKCS12"], "uuid": 42}),
            call(
                "genKeyPairAndGetPKCS10",
                json!(["PKCS12", "", "", ["a"], [1], [256], "", "", ""]),
            ),
            call(
                "genKeyPairAndGetPKCS10",
                json!(["PKCS12", "", "", ["a"], ["x"], ["a"], "", "", ""]),
            ),
            call("showFileChooser", json!([null, null])),
            call("showFileChooser", json!(["p12", null])),
            call("browseKeyStore", json!(["PKCS12", null, null])),
            call("browseKeyStore", json!(["nope", "P12", null])),
            call("signXml", json!(["PKCS12", "", null, "<a/>"])),
            call("signXml", json!(["nope", "", "SIGN", "<a/>"])),
            call("getPublicPartInfo", json!(["ACS ACR38U 0"])),
            call("getPublicPartInfo", json!([null])),
            call("resetStorage", json!([null, null])),
        ];
        for storage in [
            "AKKaztokenStore",
            "AKKZIDCardStore",
            "AKEToken72KStore",
            "AKEToken5110Store",
            "AKJaCartaStore",
            "AKAKEYStore",
            "PKCS12",
            "JKS",
            "ABCloudServiceStore",
            "nope",
        ] {
            requests.extend([
                call("loadSlotList", json!([storage])),
                call("browseKeyStore", json!([storage, null, null])),
                call("deleteEntry", json!([storage, "c", "alias"])),
                call("resetStorage", json!([storage, "c"])),
                call("signXml", json!([storage, "c", "SIGN", "<a/>"])),
                call("setX509CertToKeyStore", json!([storage, "c", "p", "pem"])),
                call("changePassword", json!([storage, "c", "old", "Pin12345"])),
                call("changePassword", json!([storage, "c", "old", "a b"])),
                call("changePassword", json!([storage, "c", "old", ""])),
                call(
                    "genKeyPairAndGetPKCS10",
                    json!([
                        storage,
                        "c",
                        "p",
                        ["a"],
                        [GOST2004],
                        [256],
                        "2.5.4.3",
                        "CN",
                        ""
                    ]),
                ),
            ]);
        }
        Case::new(vec![], requests)
    });
    assert_eq!(run.replies[0]["result"], -1);
    assert!(codes(&run).contains(&"EMPTY_SLOT"));
    // Only the file storages' signXml open a window (cancelled: no answer is scripted).
    assert_eq!(
        run.windows.matches("Prompt {").count(),
        2,
        "{}",
        run.windows
    );
}

#[test]
fn applet_file_chooser_and_password() {
    let run = same_with(
        |dir| fs::write(dir.join("k.p12"), b"x").unwrap(),
        |dir| {
            Case::new(
                vec![
                    Step::File(dir.join("k.p12")),
                    Step::CancelFile,
                    Step::File(dir.join("gone.p12")),
                    Step::File(dir.to_path_buf()),
                    Step::File(dir.to_path_buf()),
                    Step::CancelFile,
                    Step::Password("secret".to_owned()),
                    Step::CancelPassword,
                    Step::Password(String::new()),
                    Step::CancelPassword,
                ],
                vec![
                    call("showFileChooser", json!(["P12", d(dir)])),
                    call("showFileChooser", json!(["ALL", ""])),
                    call("showFileChooser", json!(["CER", null])),
                    call("showFileChooser", json!(["", "//host/share"])),
                    call("browseKeyStore", json!(["PKCS12", "KEYSTORE", d(dir)])),
                    call("browseKeyStore", json!(["JKS", "KEYSTORE", null])),
                    call("setPassword", json!([])),
                    call("setPassword", json!(["Введите PIN:"])),
                    call("setPassword", json!([""])),
                    call("setPassword", json!([null])),
                ],
            )
        },
    );
    assert!(codes(&run).iter().all(|c| *c == "NONE"));
    assert!(
        run.replies[0]["result"]
            .as_str()
            .unwrap()
            .ends_with("k.p12")
    );
    assert_eq!(run.replies[7]["result"], false);
}

#[test]
fn applet_sign_xml() {
    let rsa = synthetic("user-rsa-sign");
    let run = same(|dir| {
        Case::new(
            vec![
                // A wrong password, another storage, a missing file: asked again.
                Step::Storage {
                    path: rsa.path.clone(),
                    password: "wrong".to_owned(),
                },
                Step::Jks {
                    path: rsa.path.clone(),
                    password: rsa.password.clone(),
                },
                Step::Storage {
                    path: dir.join("gone.p12"),
                    password: rsa.password.clone(),
                },
                storage("user-rsa-sign"),
                Step::Key(5),
                Step::Key(0),
                // A document that does not sign keeps the key dialog open.
                storage("user-rsa-sign"),
                Step::Key(0),
                Step::Key(0),
                Step::CancelKey,
                storage("user-rsa-sign"),
                Step::Key(0),
                Step::CancelKey,
                // Key types.
                storage("user-gost2004-sign"),
                Step::CancelStorage,
                storage("user-gost2015-sign"),
                Step::CancelStorage,
                Step::Storage {
                    path: rsa.path.clone(),
                    password: String::new(),
                },
                Step::CancelStorage,
                storage("multi-gost2015"),
                Step::CancelKey,
                Step::Jks {
                    path: fixture("jks/rsa.jks"),
                    password: "Qwerty12".to_owned(),
                },
                Step::Key(0),
            ],
            vec![
                call(
                    "signXml",
                    json!(["PKCS12", rsa.path.display().to_string(), "SIGN", "<a>x</a>"]),
                ),
                call("signXml", json!(["PKCS12", "", "SIGN", "<!DOCTYPE a><a/>"])),
                call(
                    "signXml",
                    json!(["PKCS12", "//host/share/k.p12", "ALL", null]),
                ),
                call("signXml", json!(["PKCS12", null, "AUTH", "<a/>"])),
                call("signXml", json!(["PKCS12", null, "INSIGN", "<a/>"])),
                call("signXml", json!(["PKCS12", null, "ALL", "<a/>"])),
                call("signXml", json!(["PKCS12", "", "all", "<a/>"])),
                json!({"method": "signXml", "args": ["JKS", "", "ALL", "<a>й</a>"], "uuid": "u"}),
            ],
        )
    });
    let mut expected = vec!["SIGN_CANCEL"; 8];
    (expected[0], expected[7]) = ("NONE", "NONE");
    assert_eq!(codes(&run), expected);
    assert!(
        run.windows
            .contains("Не удалось подписать документ: документ не передан")
    );
}

#[test]
fn applet_key_files() {
    let key = synthetic("user-gost2015-sign");
    let prepare = |dir: &Path| {
        fs::copy(&key.path, dir.join("k.p12")).unwrap();
    };
    let run = same_with(prepare, |dir| {
        let file = dir.join("k.p12").display().to_string();
        let gen_key =
            |container: Value, algs: Value, lengths: Value, oids: &str, values: &str, san: &str| {
                call(
                    "genKeyPairAndGetPKCS10",
                    json!([
                        "PKCS12",
                        container,
                        DEFAULT_PASSWORD,
                        ["a"],
                        algs,
                        lengths,
                        oids,
                        values,
                        san
                    ]),
                )
            };
        let cn = "2.5.4.3<:>2.5.4.5<:>2.5.4.6";
        let values = "Тестов Тест<:>IIN123456789012<:>kz";
        Case::new(
            vec![],
            vec![
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004]),
                    json!([256]),
                    cn,
                    "host.kz<:>IIN123456789012<:>kz",
                    "a.kz, b.kz",
                ),
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004, GOST2004]),
                    json!([256, 256]),
                    cn,
                    values,
                    "",
                ),
                gen_key(
                    json!(d(dir)),
                    json!([SHA256_RSA]),
                    json!([1024]),
                    cn,
                    values,
                    "",
                ),
                gen_key(
                    json!(d(dir)),
                    json!(["1.2.398.3.10.1.1.2.3.2"]),
                    json!([512]),
                    cn,
                    values,
                    "",
                ),
                gen_key(json!(d(dir)), json!(["1.2."]), json!([256]), cn, values, ""),
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004]),
                    json!([256, 256]),
                    cn,
                    values,
                    "",
                ),
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004]),
                    json!([256]),
                    "9.9",
                    "x",
                    "",
                ),
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004]),
                    json!([256]),
                    cn,
                    "A<:>IIN1<:>KZ",
                    "",
                ),
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004]),
                    json!([256]),
                    "2.5.4.6",
                    "KZ",
                    "a.kz",
                ),
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004]),
                    json!(vec![256; 17]),
                    cn,
                    values,
                    "",
                ),
                gen_key(Value::Null, json!([GOST2004]), json!([256]), cn, values, ""),
                gen_key(
                    json!("relative"),
                    json!([GOST2004]),
                    json!([256]),
                    cn,
                    values,
                    "",
                ),
                gen_key(
                    json!("//host/share"),
                    json!([GOST2004]),
                    json!([256]),
                    cn,
                    values,
                    "",
                ),
                gen_key(json!(file), json!([GOST2004]), json!([256]), cn, values, ""),
                gen_key(json!(d(dir)), Value::Null, json!([256]), cn, values, ""),
                gen_key(
                    json!(d(dir)),
                    json!([GOST2004]),
                    Value::Null,
                    cn,
                    values,
                    "",
                ),
                call(
                    "genKeyPairAndGetPKCS10",
                    json!(["JKS", d(dir), "p", ["a"], [GOST2004], [256], cn, values, ""]),
                ),
                call(
                    "setX509CertToKeyStore",
                    json!(["PKCS12", d(dir), DEFAULT_PASSWORD, "garbage"]),
                ),
                call(
                    "setX509CertToKeyStore",
                    json!(["PKCS12", d(dir), DEFAULT_PASSWORD, "<@>"]),
                ),
                call(
                    "setX509CertToKeyStore",
                    json!(["PKCS12", d(dir), DEFAULT_PASSWORD, null]),
                ),
                call(
                    "setX509CertToKeyStore",
                    json!(["PKCS12", d(dir), null, "x"]),
                ),
                call(
                    "setX509CertToKeyStoreAndChangePassword",
                    json!([
                        "PKCS12",
                        d(dir),
                        DEFAULT_PASSWORD,
                        NEW_PASSWORD,
                        vec!["x"; 17].join("<@>")
                    ]),
                ),
                call(
                    "changePassword",
                    json!(["PKCS12", file, key.password, "short"]),
                ),
                call("changePassword", json!(["PKCS12", null, "x", "short"])),
                call(
                    "changePassword",
                    json!(["PKCS12", file, "wrong", NEW_PASSWORD]),
                ),
                call("getTryCount", json!([])),
                call(
                    "changePassword",
                    json!(["PKCS12", d(dir), key.password, NEW_PASSWORD]),
                ),
                call(
                    "changePassword",
                    json!(["PKCS12", null, key.password, NEW_PASSWORD]),
                ),
                call(
                    "changePassword",
                    json!(["PKCS12", "//host/share/k.p12", key.password, NEW_PASSWORD]),
                ),
                call(
                    "changePassword",
                    json!(["PKCS12", file, null, NEW_PASSWORD]),
                ),
                call(
                    "changePassword",
                    json!(["JKS", file, key.password, NEW_PASSWORD]),
                ),
                call(
                    "changePassword",
                    json!(["PKCS12", file, key.password, NEW_PASSWORD]),
                ),
                call(
                    "changePassword",
                    json!(["PKCS12", file, NEW_PASSWORD, "Another12"]),
                ),
            ],
        )
    });
    assert_eq!(codes(&run)[..2], ["NONE", "NONE"]);
    assert_eq!(run.replies[1]["secondResult"], json!([true, true]));
    // One, two, and the first of a request that throws at its second algorithm.
    assert_eq!(
        run.files.iter().filter(|f| *f == "GOSTKNCA_<key>").count(),
        4
    );
    assert_eq!(codes(&run).last(), Some(&"NONE"));
}

fn emu_key(name: &str) -> EmuKey {
    let k = synthetic(name);
    EmuKey::load(&k.path, &k.password).unwrap()
}

fn token(reader: &str, pin: &str) -> Step {
    Step::Token {
        storage: KAZTOKEN,
        reader: reader.to_owned(),
        pin: pin.to_owned(),
    }
}

#[test]
fn applet_tokens() {
    for enabled in [true, false] {
        let run = same(|_| {
            let kaztoken = CardSpec::new(
                TokenKind::Kaztoken,
                "123456",
                vec![emu_key("user-gost2015-sign")],
            );
            let etoken = CardSpec::new(
                TokenKind::EToken72K,
                "123456",
                vec![emu_key("user-gost2004-sign")],
            );
            Case {
                steps: vec![
                    Step::Reader(R1.to_owned()),
                    Step::CancelReader,
                    token(R0, ""),
                    token(R0, "000000"),
                    Step::CancelStorage,
                    token(R0, "123456"),
                    Step::CancelKey,
                ],
                requests: vec![
                    call("loadSlotList", json!(["AKKaztokenStore"])),
                    call("loadSlotList", json!(["AKEToken72KStore"])),
                    call("loadSlotList", json!(["AKAKEYStore"])),
                    call("loadSlotList", json!(["PKCS12"])),
                    call("browseKeyStore", json!(["AKKaztokenStore", null, null])),
                    call("browseKeyStore", json!(["AKAKEYStore", null, null])),
                    call("getPublicPartInfo", json!([R0])),
                    call("signXml", json!(["AKKaztokenStore", R1, "SIGN", "<a/>"])),
                    call("getTryCount", json!([])),
                    call(
                        "signXml",
                        json!(["AKKaztokenStore", "nope", "SIGN", "<a/>"]),
                    ),
                    call("signXml", json!(["AKAKEYStore", R0, "SIGN", "<a/>"])),
                    call(
                        "genKeyPairAndGetPKCS10",
                        json!([
                            "AKKaztokenStore",
                            "c",
                            "p",
                            ["a"],
                            [GOST2004],
                            [256],
                            "2.5.4.3",
                            "CN",
                            ""
                        ]),
                    ),
                    call(
                        "setX509CertToKeyStore",
                        json!(["AKEToken72KStore", "c", "p", "pem"]),
                    ),
                    call("deleteEntry", json!(["AKKaztokenStore", "c", "alias"])),
                    call("resetStorage", json!(["AKEToken72KStore", "c"])),
                    call(
                        "changePassword",
                        json!(["AKKaztokenStore", "c", "old", "Pin12345"]),
                    ),
                ],
                cards: Some((vec![kaztoken, etoken], enabled)),
            }
        });
        let tries = if enabled { 9 } else { -1 };
        assert_eq!(run.replies[8]["result"], tries);
        assert_eq!(run.commands > 0, enabled);
    }
}
