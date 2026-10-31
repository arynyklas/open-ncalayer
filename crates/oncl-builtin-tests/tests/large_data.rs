//! Documents long enough for the core to keep them for the module (`data_*`): the replies
//! are byte for byte what `oncl_pki` makes of the same document, with the synthetic RSA key
//! (deterministic signatures) at a fixed clock; long strings the modules read themselves
//! come back as the page sent them.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_builtin_tests::applet::Applet;
use oncl_builtin_tests::basics::{self, Basics};
use oncl_builtin_tests::commonutils::{self, CommonUtils};
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::cms::SignOptions;
use oncl_pki::info::cert_info;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::MockTsa;
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{read, synthetic, synthetic_cert};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};
use time::OffsetDateTime;

const KEY: &str = "user-rsa-sign";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn at() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| {
        let info = cert_info(&entry(KEY).cert);
        info.not_before + (info.not_after - info.not_before) / 2
    });
    *AT
}

/// Longer than the shortest string the core keeps.
fn long_text(seed: u8) -> String {
    (0..300 * 1024)
        .map(|i| char::from(b'a' + ((i as u8) ^ seed) % 26))
        .collect()
}

fn steps(calls: usize) -> Vec<Step> {
    let key = synthetic(KEY);
    (0..calls)
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

fn origin() -> AddInfo {
    AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    }
}

fn reply(module: &dyn Module, request: Value) -> Value {
    let reply = module.process(&request.to_string(), &origin());
    serde_json::from_str(reply.text().expect("a text reply")).unwrap()
}

fn cms(doc: &[u8], encapsulate: bool) -> Vec<u8> {
    oncl_pki::cms::sign(
        &entry(KEY),
        doc,
        &SignOptions {
            encapsulate,
            digested: false,
            signing_time: at(),
        },
    )
    .unwrap()
}

fn basics(calls: usize) -> Basics {
    Basics::new(
        Arc::new(ScriptedPrompter::new(steps(calls))),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
    )
    .with_clock(at)
}

fn sign(args: Value) -> Value {
    json!({"module": basics::MODULE_NAME, "method": "sign", "args": args})
}

#[test]
fn basics_signs_long_documents_as_oncl_pki() {
    let doc = long_text(1);
    let b = basics(4);
    let r = reply(
        &b,
        sign(json!({
            "format": "cms",
            "data": [STANDARD.encode(&doc), STANDARD.encode(b"x")],
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        })),
    );
    assert_eq!(
        r,
        json!({"status": true, "body": {"result": [
            oncl_pki::pem::encode("CMS", &cms(doc.as_bytes(), true)),
            oncl_pki::pem::encode("CMS", &cms(b"x", true)),
        ]}})
    );
    // Not decoded: the text itself is signed.
    let r = reply(
        &b,
        sign(json!({
            "format": "cms",
            "data": doc,
            "signingParams": {"encapsulate": false},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        })),
    );
    assert_eq!(
        r["body"]["result"][0],
        oncl_pki::pem::encode("CMS", &cms(doc.as_bytes(), false))
    );
    // XML.
    let xml = format!("<a>{doc}</a>");
    let key = entry(KEY);
    let r = reply(
        &b,
        sign(json!({
            "format": "xml",
            "data": xml,
            "signingParams": {},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        })),
    );
    let signed = oncl_pki::xmldsig::sign_enveloped(xml.as_bytes(), &key.key, &key.cert).unwrap();
    assert_eq!(
        r["body"]["result"][0],
        Value::String(String::from_utf8(signed).unwrap())
    );
    // Raw.
    let r = reply(
        &b,
        sign(json!({
            "format": "raw",
            "data": STANDARD.encode(&doc),
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        })),
    );
    let signature = key
        .key
        .sign(oncl_pki::key::SigAlg::RsaSha256, doc.as_bytes())
        .unwrap();
    assert_eq!(r["body"]["result"], STANDARD.encode(signature));
}

#[test]
fn basics_long_strings_it_reads_come_back_as_sent() {
    let format = long_text(2);
    let b = basics(0);
    let r = reply(
        &b,
        sign(json!({
            "format": format,
            "data": "x",
            "signingParams": {},
            "signerParams": {},
        })),
    );
    assert_eq!(r["status"], false);
    assert_eq!(r["code"], "INVALID_SIGNING_PARAMS");
    // Bad base64 of a long text: the decoder's message, before any window.
    let r = reply(
        &b,
        sign(json!({
            "format": "cms",
            "data": format!("{}!", STANDARD.encode(long_text(3))),
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        })),
    );
    assert_eq!(r["code"], "SIGNING_FAILURE");
}

fn common_utils(calls: usize) -> CommonUtils {
    CommonUtils::new(
        Arc::new(ScriptedPrompter::new(steps(calls))),
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
    )
    .with_cas(CaSet::new(vec![
        oncl_pki::cert::parse(&synthetic_cert("root-rsa")).unwrap(),
    ]))
    .with_clock(at)
}

fn cu(method: &str, args: Value) -> Value {
    json!({"module": commonutils::MODULE_NAME, "method": method, "args": args})
}

#[test]
fn common_utils_signs_long_documents_as_oncl_pki() {
    let doc = long_text(4);
    let c = common_utils(3);
    for attached in [true, false] {
        let r = reply(
            &c,
            cu(
                "createCAdESFromBase64",
                json!(["PKCS12", "", STANDARD.encode(&doc), attached]),
            ),
        );
        assert_eq!(
            r,
            json!({"code": "200", "responseObject": STANDARD.encode(cms(doc.as_bytes(), attached))})
        );
    }
    let xml = format!("<a>{doc}</a>");
    let key = entry(KEY);
    let r = reply(&c, cu("signXml", json!(["PKCS12", "", xml, "", ""])));
    let signed = oncl_pki::xmldsig::sign_enveloped(xml.as_bytes(), &key.key, &key.cert).unwrap();
    assert_eq!(
        r,
        json!({"code": "200", "responseObject": String::from_utf8(signed).unwrap()})
    );
    // Long strings it reads itself: echoed in its errors as sent.
    let name = long_text(5);
    let r = reply(&c, cu(&name, json!([])));
    assert_eq!(
        r,
        json!({"code": "500", "message": format!("NoSuchMethodException {name}")})
    );
}

#[test]
fn applet_signs_long_documents_as_oncl_pki() {
    let a = Applet::new(Arc::new(ScriptedPrompter::new(steps(1))));
    let xml = format!("<a>{}</a>", long_text(6));
    let key = entry(KEY);
    let request = json!({"method": "signXml", "args": ["PKCS12", "", "SIGN", xml], "uuid": "u"});
    let signed = oncl_pki::xmldsig::sign_enveloped(xml.as_bytes(), &key.key, &key.cert).unwrap();
    assert_eq!(
        reply(&a, request),
        json!({
            "errorCode": "NONE",
            "result": String::from_utf8(signed).unwrap(),
            "secondResult": key.alias,
            "uuid": "u",
        })
    );
    // Long strings it reads itself: the document of another method, a long uuid.
    let uuid = long_text(7);
    let r = reply(
        &a,
        json!({"method": "setPassword", "args": [long_text(8), "x"], "uuid": uuid}),
    );
    assert_eq!(
        r,
        json!({"errorCode": "java.lang.NoSuchMethodException. Method: setPassword"})
    );
    let r = reply(
        &a,
        json!({"method": "loadSlotList", "args": [xml], "uuid": uuid}),
    );
    assert_eq!(r, json!({"errorCode": "EMPTY_SLOT", "uuid": uuid}));
}

/// The reply's text to the request `text`, sent as is.
fn reply_text(module: &dyn Module, text: &str) -> String {
    module
        .process(text, &origin())
        .text()
        .expect("a text reply")
        .to_owned()
}

#[test]
fn lone_surrogates_get_the_same_reply_long_or_short() {
    // `JSON.stringify` writes a lone surrogate as an escape (text cut inside an emoji): the
    // request is no valid JSON, and the modules answer it as they answer a short one.
    let b = basics(0);
    let basics_request = |data: &str| {
        format!(
            r#"{{"module":"{}","method":"sign","args":{{"format":"xml","data":"{data}\ud800","signingParams":{{}},"signerParams":{{}}}}}}"#,
            basics::MODULE_NAME
        )
    };
    let short = reply_text(&b, &basics_request("x"));
    assert!(short.contains(r#""code":"GENERAL_ERROR""#), "{short}");
    assert_eq!(reply_text(&b, &basics_request(&long_text(9))), short);

    let c = common_utils(0);
    for request in [
        // In the long string, and in a short one after it.
        format!(
            r#"{{"module":"{}","method":"signXml","args":["PKCS12","SIGNATURE","{}\ud800","",""]}}"#,
            commonutils::MODULE_NAME,
            long_text(10)
        ),
        format!(
            r#"{{"module":"{}","method":"signXml","args":["PKCS12","SIGNATURE","{}","\ud800",""]}}"#,
            commonutils::MODULE_NAME,
            long_text(11)
        ),
    ] {
        // serde_json's message, its column counted in the request as the page sent it.
        let message = serde_json::from_str::<Value>(&request)
            .unwrap_err()
            .to_string();
        let r: Value = serde_json::from_str(&reply_text(&c, &request)).unwrap();
        assert_eq!(r, json!({"code": "500", "message": message}));
    }
}
