//! The same requests to both implementations of a module: the same replies and the same
//! windows. RSA keys sign deterministically, so their signatures are compared byte for
//! byte; what is random by nature (generated keys, a TSA's nonce and signature) is
//! compared by its structure.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_builtin_tests::Backend;
use oncl_builtin_tests::commonutils::{CommonUtils, MODULE_NAME as CU_MODULE};
use oncl_pki::cms::{SignOptions, verify};
use oncl_pki::info::cert_info;
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::{MockTsa, verify_token_for};
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{fixture, read, synthetic};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use time::OffsetDateTime;

/// What one implementation did: its replies, its windows and the key files left in the
/// case's folder.
#[derive(Debug, PartialEq)]
struct Run {
    replies: Vec<Value>,
    windows: String,
    files: Vec<String>,
    tsa_calls: usize,
}

fn origin(o: &str) -> AddInfo {
    AddInfo {
        origin: Some(o.to_owned()),
        ..AddInfo::default()
    }
}

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

/// A clock inside the validity of the synthetic user keys.
fn inside_user_validity() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| {
        let info = cert_info(&entry("user-rsa-sign").cert);
        info.not_before + (info.not_after - info.not_before) / 2
    });
    *AT
}

/// `text` with `dir` (as displayed or escaped) replaced by `<dir>`.
fn without_dir(text: &str, dir: &Path) -> String {
    let shown = dir.display().to_string();
    let escaped = shown.replace('\\', "\\\\");
    text.replace(&escaped, "<dir>").replace(&shown, "<dir>")
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    STANDARD.decode(body).unwrap()
}

/// A CMS as-is unless it carries a time-stamp; then its signers with their verified
/// tokens' policy, imprint and TSA, the token's own signature and nonce left out.
fn cms_summary(pem: &str) -> String {
    let der = pem_to_der(pem);
    let signers = match verify(&der, None) {
        Ok(signers) => signers,
        Err(_) => return pem.to_owned(),
    };
    if signers.iter().all(|s| s.timestamp_token.is_none()) {
        return pem.to_owned();
    }
    let signers: Vec<String> = signers
        .iter()
        .map(|s| {
            let token = s.timestamp_token.as_ref().map(|t| {
                let (tst, tsa) = verify_token_for(t, &s.signature).unwrap();
                (
                    tst.policy,
                    tst.imprint_alg,
                    tst.imprint,
                    tsa.to_der().unwrap(),
                )
            });
            format!(
                "{:02x?} {:?} {:?} {:02x?} {token:02x?}",
                s.cert.to_der().unwrap(),
                s.sig_alg,
                s.signing_time,
                s.signature
            )
        })
        .collect();
    format!("time-stamped CMS {signers:?}")
}

fn storage(name: &str, password: &str) -> Step {
    storage_at(synthetic(name).path, password)
}

fn storage_at(path: impl Into<PathBuf>, password: &str) -> Step {
    Step::Storage {
        path: path.into(),
        password: password.to_owned(),
    }
}

fn rsa() -> Vec<Step> {
    vec![storage("user-rsa-sign", "Qwerty12"), Step::Key(0)]
}

/// A CMS of `doc` by the synthetic RSA key at the fixed time.
fn rsa_cms(doc: &[u8], encapsulate: bool) -> String {
    STANDARD.encode(
        oncl_pki::cms::sign(
            &entry("user-rsa-sign"),
            doc,
            &SignOptions {
                encapsulate,
                digested: false,
                signing_time: inside_user_validity(),
            },
        )
        .unwrap(),
    )
}

// kz.gov.pki.knca.commonUtils

/// The synthetic roots and intermediate CA, standing in for the NCA CAs.
fn synthetic_cas() -> oncl_pki::pkix::CaSet {
    oncl_pki::pkix::CaSet::new(
        [
            "root-gost2015",
            "root-gost2004",
            "root-rsa",
            "inter-gost2015",
        ]
        .into_iter()
        .map(|name| oncl_pki::cert::parse(&oncl_testkit::synthetic_cert(name)).unwrap())
        .collect(),
    )
}

/// A base64 CMS with a time-stamp by its signers and verified tokens; anything else as is.
fn cu_normalized(reply: Value, dir: &Path) -> Value {
    match reply {
        Value::String(s) => match STANDARD.decode(&s) {
            Ok(der) if verify(&der, None).is_ok() => Value::String(cms_summary(&s)),
            _ => Value::String(without_dir(&s, dir)),
        },
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, cu_normalized(v, dir)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|v| cu_normalized(v, dir)).collect())
        }
        other => other,
    }
}

/// `requests` (with their sessions) to the commonUtils module of `backend`.
fn cu_run(backend: Backend, steps: Vec<Step>, requests: &[(Value, AddInfo)], dir: &Path) -> Run {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let cu = CommonUtils::new(prompter.clone(), tsa.clone())
        .with_cas(synthetic_cas())
        .with_clock(inside_user_validity)
        .with_backend(backend);
    let replies = requests
        .iter()
        .map(|(request, add_info)| {
            let reply = cu.process(&request.to_string(), add_info);
            cu_normalized(serde_json::from_str(reply.text().unwrap()).unwrap(), dir)
        })
        .collect();
    let p = &prompter;
    let windows = format!(
        "{:#?}",
        (
            p.timeline(),
            p.storage_prompts(),
            p.busy_prompts(),
            p.opened_key_prompts(),
            p.key_prompts(),
            p.file_prompts(),
            p.reader_prompts(),
        )
    );
    Run {
        replies,
        windows: without_dir(&windows, dir),
        files: Vec::new(),
        tsa_calls: tsa.calls().len(),
    }
}

/// Runs the commonUtils `case(dir)` on both implementations, each in a fresh folder with a
/// file `doc.txt` and a detached CMS `detached.p7s`.
fn cu_same(case: impl Fn(&Path) -> (Vec<Step>, Vec<Value>)) {
    let run = |backend| {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("doc.txt"), b"doc").unwrap();
        fs::write(
            dir.path().join("detached.p7s"),
            STANDARD.decode(rsa_cms(b"doc", false)).unwrap(),
        )
        .unwrap();
        let (steps, requests) = case(dir.path());
        let requests: Vec<_> = requests.into_iter().map(|r| (r, origin("o"))).collect();
        cu_run(backend, steps, &requests, dir.path())
    };
    assert_eq!(run(Backend::Wasm), run(Backend::Native));
}

fn cu(method: &str, args: Value) -> Value {
    json!({"module": CU_MODULE, "method": method, "args": args, "uuid": "u-1"})
}

#[test]
fn commonutils_signing() {
    let doc = STANDARD.encode(b"doc");
    let hash = STANDARD.encode(SigAlg::RsaSha256.digest(b"doc"));
    let attached = rsa_cms(b"doc", true);
    let detached = rsa_cms(b"doc", false);
    for (method, args) in [
        ("getKeyInfo", json!(["PKCS12"])),
        (
            "signXml",
            json!(["PKCS12", "SIGNATURE", "<a><b Id=\"x\">1</b></a>", "", ""]),
        ),
        (
            "signXml",
            json!(["PKCS12", "", "<a><b Id=\"x\">1</b></a>", "//b", ""]),
        ),
        (
            "signXml",
            json!(["PKCS12", "", "<a><b Id=\"x\">1</b></a>", "/a/b", "/A/B"]),
        ),
        ("signXml", json!(["PKCS12", "", "<a>", "", ""])),
        (
            "signXmls",
            json!(["PKCS12", "SIGNATURE", ["<a/>", "<b/>"], "", ""]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "SIGNATURE", doc, true]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "SIGNATURE", doc, false]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "", attached, true]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "", detached, true]),
        ),
        ("createCAdESFromBase64", json!(["PKCS12", "", "!!", true])),
        (
            "createCAdESFromBase64Hash",
            json!(["PKCS12", "SIGNATURE", hash]),
        ),
        (
            "createCMSSignatureFromBase64",
            json!(["PKCS12", "SIGNATURE", doc, true]),
        ),
        ("applyCAdEST", json!(["PKCS12", "SIGNATURE", attached])),
        (
            "applyCAdEST",
            json!(["PKCS12", "SIGNATURE", rsa_cms(b"x", true)]),
        ),
        ("applyCAdEST", json!(["PKCS12", "SIGNATURE", "AAAA"])),
    ] {
        cu_same(|_| (rsa(), vec![cu(method, args.clone())]));
    }
    for method in ["createCAdESFromFile", "createCMSSignatureFromFile"] {
        for file in ["doc.txt", "detached.p7s", "missing.txt"] {
            cu_same(|dir| {
                let path = dir.join(file).display().to_string();
                (rsa(), vec![cu(method, json!(["PKCS12", "", path, true]))])
            });
        }
    }
}

#[test]
fn commonutils_dialogs_and_errors() {
    let doc = STANDARD.encode(b"doc");
    let cases: Vec<(Vec<Step>, Value)> = vec![
        (
            vec![Step::CancelStorage],
            cu("getKeyInfo", json!(["PKCS12"])),
        ),
        (
            vec![storage("user-rsa-sign", "Qwerty12"), Step::CancelKey],
            cu("getKeyInfo", json!(["PKCS12"])),
        ),
        (
            vec![
                storage("user-rsa-sign", "bad"),
                storage("user-rsa-sign", "Qwerty12"),
                Step::Key(0),
            ],
            cu("createCAdESFromBase64", json!(["PKCS12", "", doc, true])),
        ),
        (
            vec![
                Step::Jks {
                    path: fixture("jks/rsa.jks"),
                    password: "Qwerty12".to_owned(),
                },
                Step::Key(0),
            ],
            cu("getKeyInfo", json!(["JKS"])),
        ),
        (
            vec![
                Step::Jks {
                    path: fixture("jks/rsa.jks"),
                    password: "Qwerty12".to_owned(),
                },
                Step::Key(0),
            ],
            cu("createCAdESFromBase64", json!(["JKS", "", doc, true])),
        ),
        (
            vec![storage("user-rsa-sign", "Qwerty12"), Step::CancelStorage],
            cu(
                "signXml",
                json!(["PKCS12", "AUTHENTICATION", "<a/>", "", ""]),
            ),
        ),
        (Vec::new(), cu("getKeyInfo", json!([" "]))),
        (Vec::new(), cu("getKeyInfo", json!(["pkcs12"]))),
        (Vec::new(), cu("getKeyInfo", json!(["AKKaztokenStore"]))),
        (Vec::new(), cu("getKeyInfo", json!([5]))),
        (Vec::new(), cu("getKeyInfo", json!([]))),
        (Vec::new(), cu("saveKey", json!(["a", "b"]))),
        (Vec::new(), cu("getJson", json!([[1, "x"]]))),
        (Vec::new(), cu("setKeyInfoServices", json!(["a"]))),
        (
            Vec::new(),
            cu("signXmls", json!(["PKCS12", "", [1], "", ""])),
        ),
        (Vec::new(), cu("getActiveTokens", json!([]))),
        (Vec::new(), json!({"method": 5})),
        (Vec::new(), json!([1])),
        (Vec::new(), cu("showFileChooser", json!(["NOPE", ""]))),
        (
            vec![Step::CancelFile],
            cu("showFileChooser", json!(["P12", ""])),
        ),
        (
            vec![Step::CancelFile],
            cu("showFileChooser", json!(["", "/nowhere"])),
        ),
    ];
    for (steps, request) in cases {
        cu_same(|_| (steps.clone(), vec![request.clone()]));
    }
    cu_same(|dir| {
        (
            vec![Step::File(dir.join("doc.txt"))],
            vec![cu(
                "showFileChooser",
                json!(["ALL", dir.display().to_string()]),
            )],
        )
    });
}

#[test]
fn commonutils_locale() {
    for language in ["kk", "en", "ru", "", "de"] {
        cu_same(|dir| {
            let path = dir.join("doc.txt").display().to_string();
            (
                vec![Step::CancelStorage, Step::CancelFile],
                vec![
                    cu("changeLocale", json!([language])),
                    cu("createCAdESFromFile", json!(["PKCS12", "", path, true])),
                    cu("showFileChooser", json!(["", ""])),
                ],
            )
        });
    }
}

/// Longer than what a built-in module gets as a data marker (`DATA_KEPT_MIN`).
fn long_text(seed: u8) -> String {
    (0..300 * 1024)
        .map(|i| char::from(b'a' + ((i as u8) ^ seed) % 26))
        .collect()
}

#[test]
fn commonutils_long_data() {
    let doc = long_text(6);
    let b64 = STANDARD.encode(doc.as_bytes());
    let attached = STANDARD.encode(STANDARD.decode(rsa_cms(doc.as_bytes(), true)).unwrap());
    for (method, args) in [
        ("createCAdESFromBase64", json!(["PKCS12", "", b64, true])),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "", format!("{b64}!"), true]),
        ),
        // A time-stamp is compared by its verified token: attached only.
        (
            "createCMSSignatureFromBase64",
            json!(["PKCS12", "", b64, true]),
        ),
        ("createCAdESFromBase64", json!(["PKCS12", "", b64, false])),
        ("applyCAdEST", json!(["PKCS12", "", attached])),
        (
            "signXml",
            json!(["PKCS12", "", format!("<a>{doc}</a>"), "", ""]),
        ),
        (
            "signXmls",
            json!(["PKCS12", "", [format!("<b>{doc}</b>"), "<c/>"], "", ""]),
        ),
    ] {
        cu_same(|_| (rsa(), vec![cu(method, args.clone())]));
    }
    // Long strings the module reads itself: echoed in its errors.
    for request in [
        cu(&long_text(7), json!([])),
        cu("showFileChooser", json!([long_text(8), ""])),
        cu("getKeyInfo", json!([long_text(9)])),
    ] {
        cu_same(|_| (Vec::new(), vec![request.clone()]));
    }
}
