//! The ports of the heavy plugins: Buhta NcaModule, Alatau City Bank.

use oncl_basics::testing::Step;
use oncl_basics::{Availability, DisabledReason};
use oncl_pki::key::SigAlg;
use oncl_port_tests::{Harness, entry, p12};
use oncl_protocol::Reply;
use oncl_protocol::javab64::decode_java;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};

/// Standard base64 with padding.
fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Base64url, padded or not.
fn unb64url(text: &str) -> Vec<u8> {
    let mut std: String = text
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    while !std.len().is_multiple_of(4) {
        std.push('=');
    }
    decode_java(&std).expect("base64url")
}

fn text(reply: Reply) -> String {
    match reply {
        Reply::Text(text) => text,
        Reply::Drop => panic!("the connection was dropped"),
    }
}

fn storage(name: &str) -> Step {
    let (path, password) = p12(name);
    Step::Storage {
        path,
        password: password.to_owned(),
    }
}

// Buhta.

const BUHTA_ORIGIN: Option<&str> = Some("https://app.buhta.kz");

fn buhta(args: Value) -> String {
    json!({"module": "com.buhta.cert.ncamodule", "method": "call", "args": args}).to_string()
}

/// The string body of a successful Buhta reply.
fn buhta_body(reply: Reply) -> String {
    let reply: Value = serde_json::from_str(&text(reply)).unwrap();
    assert_eq!(reply["status"], true, "{reply}");
    reply["body"].as_str().expect("a string body").to_owned()
}

fn rpc(handler: i32, payload: &Value) -> String {
    buhta(
        json!({"format": 0, "version": "v1alpha1", "handler": handler,
        "payload": payload.to_string()}),
    )
}

#[test]
fn buhta_missing_origin_drops() {
    let harness = Harness::new(vec![], vec![]);
    let request = rpc(1, &json!({"tin": "123456789011"}));
    assert_eq!(harness.call("buhta", &request, None), Reply::Drop);
    // A request org.json cannot read leaves the module too.
    assert_eq!(harness.call("buhta", "{", BUHTA_ORIGIN), Reply::Drop);
    assert_eq!(
        harness.call(
            "buhta",
            r#"{"module":"com.buhta.cert.ncamodule"}"#,
            BUHTA_ORIGIN
        ),
        Reply::Drop
    );
    assert!(harness.prompter().timeline().is_empty());
}

#[test]
fn buhta_unknown_format_quirk() {
    let harness = Harness::new(vec![], vec![]);
    let call = |args: Value| text(harness.call("buhta", &buhta(args), BUHTA_ORIGIN));
    let version = r#"{"code":"UNKNOWN_RPC_VERSION","message":"Unknown version, currently supported oldest version: `v1alpha1`","status":false}"#;
    // An unknown format is answered as an unknown version.
    assert_eq!(
        call(json!({"format": 2, "handler": 1, "payload": "{}"})),
        version
    );
    assert_eq!(
        call(json!({"format": 0, "version": "v1", "handler": 1, "payload": "{}"})),
        version
    );
    assert_eq!(
        call(json!({"handler": 0, "payload": "{}"})),
        r#"{"code":"UNKNOWN_COMMAND","message":"Unknown `handler`","status":false}"#
    );
    // No payload: the method's NullPointerException (EMPTY_PAYLOAD is never used).
    assert_eq!(
        call(json!({"handler": 1})),
        r#"{"code":"INVOCATION_ERROR","details":"java.lang.NullPointerException","message":"An invoked method threw an exception.","status":false}"#
    );
    assert_eq!(
        call(json!({"handler": 1, "payload": "{\"tin\": {}}"})),
        r#"{"code":"INVALID_PAYLOAD","message":"Invalid payload","status":false}"#
    );
    assert_eq!(
        call(json!({"handler": 2, "payload": "{\"signCert\": \"a\", \"signCertArgs\": {}}"})),
        r#"{"code":"INVALID_PAYLOAD","message":"Invalid payload","status":false}"#
    );
    // `call` demands its arguments.
    assert_eq!(
        text(harness.call(
            "buhta",
            r#"{"module":"com.buhta.cert.ncamodule","method":"call"}"#,
            BUHTA_ORIGIN
        )),
        r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: call demands arguments","message":"General error.","status":false}"#
    );
}

#[test]
fn buhta_select_tin_filter() {
    let harness = Harness::new(
        vec![
            storage("user-gost2015-sign"),
            Step::Key(0),
            storage("legal-gost2015-sign"),
            Step::CancelKey,
        ],
        vec![],
    );
    let mut session = harness.session("buhta");
    // An individual's IIN.
    let selected = buhta_body(session.call(&rpc(1, &json!({"tin": "123456789011"})), BUHTA_ORIGIN));
    let selected: Value = serde_json::from_str(&selected).unwrap();
    let uuid = selected["cert"]["cert"].as_str().unwrap();
    assert_eq!(uuid.len(), 36, "{uuid}");
    assert_eq!(&uuid[14..15], "4");
    // A legal entity's certificate is matched by its BIN, not its IIN.
    let none = buhta_body(session.call(&rpc(1, &json!({"tin": "123456789022"})), BUHTA_ORIGIN));
    assert_eq!(none, "{\n}");
    let prompts = harness.prompter().key_prompts();
    assert_eq!(prompts[0].candidates[0].availability, Availability::Enabled);
    assert_eq!(
        prompts[1].candidates[0].availability,
        Availability::Disabled(vec![DisabledReason::Tin])
    );
    assert_eq!(
        harness.prompter().storage_prompts()[0].storages,
        vec![oncl_basics::StorageKind::Pkcs12]
    );
}

#[test]
fn buhta_select_cancel_empty_message_json() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let mut session = harness.session("buhta");
    let body = buhta_body(session.call(&rpc(1, &json!({"tin": "123456789011"})), BUHTA_ORIGIN));
    assert_eq!(body, "{\n}");
    // An empty `tin` never selects a key: no dialog.
    for payload in [json!({}), json!({"tin": ""})] {
        assert_eq!(
            buhta_body(session.call(&rpc(1, &payload), BUHTA_ORIGIN)),
            "{\n}"
        );
    }
    assert_eq!(harness.prompter().timeline(), ["storage"]);
    // Nor does it sign: the certificate is invalid.
    let reply = text(session.call(
        &rpc(
            2,
            &json!({"signCertArgs": {}, "document": {"xml": {"data": "<a/>"}}}),
        ),
        BUHTA_ORIGIN,
    ));
    assert_eq!(
        reply,
        r#"{"code":"INVALID_CERT_SELECTED","message":"Selected signing certificate is either invalid or not supported","status":false}"#
    );
    // An unknown uuid likewise.
    let reply = text(session.call(
        &rpc(
            2,
            &json!({"signCert": "nope", "document": {"xml": {"data": "<a/>"}}}),
        ),
        BUHTA_ORIGIN,
    ));
    assert!(reply.contains("INVALID_CERT_SELECTED"), "{reply}");
}

/// A session with a key selected for IIN 123456789011 (from `store`), and its uuid.
fn buhta_selected(harness: &Harness) -> (oncl_port_tests::SessionHandle, String) {
    let mut session = harness.session("buhta");
    let body = buhta_body(session.call(&rpc(1, &json!({"tin": "123456789011"})), BUHTA_ORIGIN));
    let body: Value = serde_json::from_str(&body).unwrap();
    (session, body["cert"]["cert"].as_str().unwrap().to_owned())
}

#[test]
fn buhta_sign_file_cades_t() {
    let harness = Harness::new(vec![storage("user-gost2015-sign"), Step::Key(0)], vec![]);
    let (mut session, uuid) = buhta_selected(&harness);
    let payload = json!({"signCert": uuid, "document":
        {"id": "doc-1", "file": {"data": b64(b"hello"), "name": "a.txt", "attached": true}}});
    let body = buhta_body(session.call(&rpc(2, &payload), BUHTA_ORIGIN));
    let result: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(result["document"]["id"], "doc-1");
    let cms = decode_java(result["document"]["file"]["data"].as_str().unwrap()).unwrap();
    let signers = oncl_pki::cms::verify(&cms, None).expect("the CMS verifies");
    assert_eq!(signers.len(), 1);
    assert!(signers[0].signing_time.is_some());
    let token = signers[0].timestamp_token.as_ref().expect("CAdES-T");
    assert!(!token.is_empty());
    assert!(
        harness
            .http_log()
            .iter()
            .any(|line| line.contains("tsp.pki.gov.kz")),
        "{:?}",
        harness.http_log()
    );
    // Detached: the data is not in the CMS.
    let payload = json!({"signCert": uuid, "document": {"file": {"data": b64(b"hello")}}});
    let body = buhta_body(session.call(&rpc(2, &payload), BUHTA_ORIGIN));
    let result: Value = serde_json::from_str(&body).unwrap();
    let cms = decode_java(result["document"]["file"]["data"].as_str().unwrap()).unwrap();
    assert!(oncl_pki::cms::verify(&cms, Some(b"hello")).is_ok());
    assert!(result["document"].get("id").is_none());
}

#[test]
fn buhta_sign_xml_whitespace_and_no_line_breaks() {
    for (store, method) in [
        ("user-gost2015-sign", "gostr34102015-gostr34112015-512"),
        ("user-rsa-sign", "xmldsig-more#rsa-sha256"),
        ("user-gost2004-sign", "xmldsig-more#gost34310-gost34311"),
    ] {
        let harness = Harness::new(vec![storage(store), Step::Key(0)], vec![]);
        let mut session = harness.session("buhta");
        let payload = json!({"signCertArgs": {"tin": "123456789011"},
            "document": {"id": "x", "xml": {"data": "\n <root><a>1</a>\n</root> "}}});
        let body = buhta_body(session.call(&rpc(2, &payload), BUHTA_ORIGIN));
        // Gson's escapes in the JsonFormat text.
        assert!(body.contains("\\u003c?xml version\\u003d"), "{body}");
        let result: Value = serde_json::from_str(&body).unwrap();
        let xml = result["document"]["xml"]["data"].as_str().unwrap();
        assert!(
            xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>"),
            "{xml}"
        );
        assert!(xml.ends_with("</root>"), "{xml}");
        let signature = &xml[xml.find("<ds:Signature").unwrap()..];
        assert!(!signature.contains('\n'), "{signature}");
        assert!(!signature.contains("&#13;"), "{signature}");
        assert!(signature.contains(method), "{signature}");
        // The signature is the document element's last child.
        assert!(xml.ends_with("</ds:Signature></root>"), "{xml}");
        assert_eq!(oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap().len(), 1);
    }
}

#[test]
fn buhta_bulk_first_failure_aborts() {
    let harness = Harness::new(vec![storage("user-gost2015-sign"), Step::Key(0)], vec![]);
    let (mut session, uuid) = buhta_selected(&harness);
    let payload = json!({"signCert": uuid, "documents": [
        {"id": "a", "xml": {"data": "<a/>"}},
        {"id": "b"},
        {"id": "c", "xml": {"data": "<c/>"}}]});
    assert_eq!(
        text(session.call(&rpc(3, &payload), BUHTA_ORIGIN)),
        r#"{"code":"INVALID_PAYLOAD","message":"Invalid payload","status":false}"#
    );
    // The same documents without the bad one: both signed, in order, with one key.
    let payload = json!({"sign_cert": uuid, "documents": [
        {"id": "a", "xml": {"data": "<a/>"}},
        {"id": "c", "xml": {"data": "<c/>"}}]});
    let body = buhta_body(session.call(&rpc(3, &payload), BUHTA_ORIGIN));
    assert!(
        body.starts_with(
            "{\n  \"documents\": [{\n    \"id\": \"a\",\n    \"xml\": {\n      \"data\": \""
        ),
        "{body}"
    );
    assert!(
        body.contains("\"\n    }\n  }, {\n    \"id\": \"c\",\n"),
        "{body}"
    );
    assert!(body.ends_with("\"\n    }\n  }]\n}"), "{body}");
    assert_eq!(
        harness.prompter().timeline(),
        ["storage", "busy", "busy closed", "key"]
    );
}

#[test]
fn buhta_binary_format_base64_proto() {
    let harness = Harness::new(vec![storage("user-gost2015-sign"), Step::Key(0)], vec![]);
    let mut session = harness.session("buhta");
    // SelectSignCertArgs{tin}: field 1, length-delimited.
    let mut args = vec![0x0a, 12];
    args.extend_from_slice(b"123456789011");
    let request = buhta(json!({"format": 1, "handler": 1, "payload": b64(&args)}));
    let body = buhta_body(session.call(&request, BUHTA_ORIGIN));
    let result = decode_java(&body).unwrap();
    // SelectSignCertResult{cert: SignCert{cert: uuid}}.
    assert_eq!(&result[..4], &[0x0a, 38, 0x0a, 36]);
    assert_eq!(result.len(), 40);
    let uuid = String::from_utf8(result[4..].to_vec()).unwrap();
    // The empty result is empty base64.
    let request = buhta(json!({"format": 1, "handler": 1, "payload": ""}));
    assert_eq!(buhta_body(session.call(&request, BUHTA_ORIGIN)), "");
    // Bytes that are no message.
    let request = buhta(json!({"format": 1, "handler": 1, "payload": b64(&[0x0a, 5, 1])}));
    assert!(text(session.call(&request, BUHTA_ORIGIN)).contains("INVALID_PAYLOAD"));
    // SignDocumentArgs{sign_cert, document{xml{data}}} signs with the key of the uuid.
    let mut xml = vec![0x0a, 4];
    xml.extend_from_slice(b"<a/>");
    let mut signable = vec![0x1a, xml.len() as u8];
    signable.extend(xml);
    let mut sign = vec![0x0a, 36];
    sign.extend_from_slice(uuid.as_bytes());
    sign.extend([0x1a, signable.len() as u8]);
    sign.extend(signable);
    let request = buhta(json!({"format": 1, "handler": 2, "payload": b64(&sign)}));
    let result = decode_java(&buhta_body(session.call(&request, BUHTA_ORIGIN))).unwrap();
    assert_eq!(result[0], 0x0a);
    let signed = String::from_utf8_lossy(&result);
    assert!(signed.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?><a><ds:Signature"));
}

#[test]
fn buhta_json_format_printer() {
    let harness = Harness::new(vec![storage("user-gost2015-sign"), Step::Key(0)], vec![]);
    let (mut session, uuid) = buhta_selected(&harness);
    // Proto field names are read too; unknown fields are ignored.
    let payload = json!({"sign_cert": uuid, "unknown": [1], "include_x509": "true",
        "document": {"id": "", "meta": [{"name": "n"}], "xml": {"data": "<a>'&amp;'</a>"}}});
    let body = buhta_body(session.call(&rpc(2, &payload), BUHTA_ORIGIN));
    // A set optional field is printed even when empty; fields in number order.
    assert!(
        body.starts_with(
            "{\n  \"document\": {\n    \"id\": \"\",\n    \"xml\": {\n      \"data\": \"\\u003c?xml version\\u003d\\\"1.0\\\" encoding\\u003d\\\"UTF-8\\\"?\\u003e\\u003ca\\u003e\\u0027\\u0026amp;\\u0027"
        ),
        "{body}"
    );
    assert!(body.ends_with("\"\n    }\n  }\n}"), "{body}");
    let reply = text(session.call(&rpc(2, &payload), BUHTA_ORIGIN));
    // The JsonFormat text is the body's string, escaped once more by org.json.
    assert!(
        reply.starts_with(r#"{"body":"{\n  \"document\": {\n"#),
        "{reply}"
    );
    assert!(
        reply.ends_with(r#"\n    }\n  }\n}","status":true}"#),
        "{reply}"
    );
    let selected = harness.session("buhta");
    drop(selected);
    assert_eq!(
        buhta_body(harness.call("buhta", &rpc(1, &json!({"tin": ""})), BUHTA_ORIGIN)),
        "{\n}"
    );
}

// Alatau City Bank.

const ACBANK: &str = "kz.acbank.business.api.ncalayer.module";

fn acbank(method: &str, args: Option<Value>) -> String {
    let mut request = json!({"module": ACBANK, "method": method});
    if let Some(args) = args {
        request["args"] = args;
    }
    request.to_string()
}

fn acbank_error(code: &str) -> String {
    format!(r#"{{"code":"ncalayer.module.{code}","status":false}}"#)
}

fn item(id: &str, content: &str) -> Value {
    json!({"id": id, "name": format!("Документ {id}"), "content": content,
        "contentType": "application/json"})
}

/// The window answered with «Sign», then the key of `store`.
fn sign_steps(store: &str) -> Vec<Step> {
    vec![
        Step::Choice {
            button: 0,
            option: None,
        },
        storage(store),
        Step::Key(0),
    ]
}

fn acbank_body(reply: Reply) -> Value {
    let text = text(reply);
    assert!(
        text.starts_with(r#"{"code":"success","message":null,"body":{"#),
        "{text}"
    );
    assert!(text.ends_with(r#"},"status":true}"#), "{text}");
    let reply: Value = serde_json::from_str(&text).unwrap();
    reply["body"].clone()
}

#[test]
fn acbank_bad_request_drops() {
    let harness = Harness::new(vec![], vec![]);
    for request in [
        "not json",
        r#"{"module":"kz.acbank.business.api.ncalayer.module"}"#,
        r#"{"method":5}"#,
        r#"{"method":null}"#,
    ] {
        assert_eq!(
            harness.call("acbank", request, None),
            Reply::Drop,
            "{request}"
        );
    }
    assert_eq!(
        text(harness.call("acbank", &acbank("nope", None), None)),
        acbank_error("method.not-found")
    );
}

#[test]
fn acbank_validation_codes_order() {
    let harness = Harness::new(vec![], vec![]);
    let call = |method: &str, args: Option<Value>| {
        text(harness.call("acbank", &acbank(method, args), None))
    };
    let cases = [
        (None, "unexpected-error"),
        (
            Some(json!({"settings": {"locale": "de"}})),
            "settings.locale.incorrect",
        ),
        // The locale is checked before the items.
        (
            Some(json!({"settings": {"locale": "de"}, "signableItems": [5]})),
            "settings.locale.incorrect",
        ),
        (Some(json!({"signableItems": [5]})), "unexpected-error"),
        (
            Some(json!({"signableItems": [{"id": "1", "name": "n"}]})),
            "unexpected-error",
        ),
        (
            Some(json!({"signatureOperation": "initial"})),
            "sign.signable-data.has-incorrect-signature-operation",
        ),
        (Some(json!({})), "sign.signable-data.empty"),
        (
            Some(json!({"signableItems": []})),
            "sign.signable-data.empty",
        ),
        (
            Some(json!({"signableItems": [{"id": "1", "name": "n", "content": " "}]})),
            "sign.signable-data.has-no-content",
        ),
        (
            Some(json!({"signableItems": [{"id": "1", "name": "n", "content": "{}"}]})),
            "sign.signable-data.has-no-content-type",
        ),
        (
            Some(
                json!({"signableItems": [{"id": "1", "name": "n", "content": "{}", "contentType": "text/plain"}]}),
            ),
            "sign.signable-data.has-incorrect-content-type",
        ),
        (
            Some(json!({"signableItems": [item("1", "{}"), item("2", "[1]")]})),
            "sign.signable-data.has-incorrect-content",
        ),
    ];
    for (args, code) in cases {
        assert_eq!(
            call("signJsonWithJws", args.clone()),
            acbank_error(code),
            "{args:?}"
        );
    }
    // JWS JSON takes any content; `JSON` in any case is a JSON content type.
    let args = json!({"settings": {"locale": "KK"}, "signableItems":
        [{"id": "1", "name": "n", "content": "x", "contentType": "JSON"}]});
    assert_eq!(
        call("multiSignJsonWithJws", Some(args)),
        acbank_error("window.closed")
    );
    let choice = &harness.prompter().choice_prompts()[0];
    assert_eq!(
        choice.title.as_deref(),
        Some("ЭЦҚ арқылы деректерге қол қою модулі")
    );
}

#[test]
fn acbank_healthcheck_states() {
    let entered = Arc::new(Barrier::new(2));
    let leave = Arc::new(Barrier::new(2));
    let harness = Harness::new(
        vec![
            Step::Wait(Arc::clone(&entered)),
            Step::Wait(Arc::clone(&leave)),
            Step::CancelChoice,
        ],
        vec![],
    );
    let mut sessions = harness.shared_sessions("acbank", 2);
    let mut page = sessions.pop().unwrap();
    let mut signing = sessions.pop().unwrap();
    let mut health = |args: Option<Value>| text(page.call(&acbank("healthcheck", args), None));
    assert_eq!(health(None), acbank_error("unexpected-error"));
    assert_eq!(
        health(Some(json!({"ping": false}))),
        acbank_error("healthcheck.ping.what")
    );
    assert_eq!(
        health(Some(json!({}))),
        acbank_error("healthcheck.ping.what")
    );
    let ping = Some(json!({"ping": true}));
    assert_eq!(
        health(ping.clone()),
        acbank_error("healthcheck.session.inactive")
    );
    std::thread::scope(|scope| {
        let signer = scope.spawn(move || {
            let args = json!({"signableItems": [item("1", "{}")]});
            text(signing.call(&acbank("signJsonWithJws", Some(args)), None))
        });
        // The signing window is open in the other session.
        entered.wait();
        assert_eq!(
            health(ping.clone()),
            r#"{"code":"success","message":null,"body":{"healthcheck":true},"status":true}"#
        );
        leave.wait();
        assert_eq!(signer.join().unwrap(), acbank_error("window.closed"));
        assert_eq!(
            health(ping.clone()),
            acbank_error("healthcheck.session.inactive")
        );
    });
}

#[test]
fn acbank_already_running_in_another_session() {
    let entered = Arc::new(Barrier::new(2));
    let leave = Arc::new(Barrier::new(2));
    let harness = Harness::new(
        vec![
            Step::Wait(Arc::clone(&entered)),
            Step::Wait(Arc::clone(&leave)),
            Step::CancelChoice,
        ],
        vec![],
    );
    let mut sessions = harness.shared_sessions("acbank", 2);
    let mut other = sessions.pop().unwrap();
    let mut signing = sessions.pop().unwrap();
    let args = json!({"signableItems": [item("1", "{}")]});
    std::thread::scope(|scope| {
        let request = acbank("signJsonWithJws", Some(args.clone()));
        let signer = scope.spawn(move || text(signing.call(&request, None)));
        entered.wait();
        assert_eq!(
            text(other.call(&acbank("multiSignJsonWithJws", Some(args.clone())), None)),
            acbank_error("session.already-running")
        );
        leave.wait();
        signer.join().unwrap();
    });
}

/// The parts of a compact JWS, its header as text.
fn compact_parts(jws: &str) -> (String, Vec<u8>, Vec<u8>, String) {
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "{jws}");
    let header = String::from_utf8(unb64url(parts[0])).unwrap();
    let input = format!("{}.{}", parts[0], parts[1]);
    (header, unb64url(parts[1]), unb64url(parts[2]), input)
}

fn sha256_hex(text: &str) -> String {
    oncl_pki::key::HashAlg::Sha256
        .digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn acbank_compact_jws_structure_and_signature_verifies() {
    let harness = Harness::new(sign_steps("user-gost2015-sign"), vec![]);
    let args = json!({"signableItems": [item("1", "{\"amount\": 10}")]});
    let reply = text(harness.call("acbank", &acbank("signJsonWithJws", Some(args)), None));
    let body = acbank_body(Reply::Text(reply.clone()));
    // The item's keys in HashMap order.
    let at = reply.find(r#"{"signedItems":[{"#).unwrap();
    let keys = [
        "spanId",
        "signature",
        "name",
        "id",
        "contentType",
        "content",
    ];
    let mut last = at;
    for key in keys {
        let found = reply[last..].find(&format!("\"{key}\":")).expect(key) + last;
        assert!(found >= last, "{key} out of order in {reply}");
        last = found;
    }
    let signed = &body["signedItems"][0];
    assert_eq!(signed["spanId"], "");
    assert_eq!(signed["content"], "{\"amount\": 10}");
    let (header, payload, signature, input) = compact_parts(signed["signature"].as_str().unwrap());
    assert_eq!(payload, b"{\"amount\": 10}");
    let parsed: Value = serde_json::from_str(&header).unwrap();
    let ts = parsed["ts"].as_str().unwrap();
    assert!(ts.parse::<i64>().is_ok(), "{ts}");
    let expected = format!(
        r#"{{"spanid":"{}","x5c":{},"cty":"application/json","typ":"JOSE","alg":"ECGOST3410-2015-512","ts":"{ts}"}}"#,
        // The compact form hashes the content type where the content was meant.
        sha256_hex(&format!("application/json{ts}")),
        parsed["x5c"]
    );
    assert_eq!(header, expected);
    let key = entry("user-gost2015-sign");
    key.key
        .public_key()
        .verify(SigAlg::Gost2015_512, input.as_bytes(), &signature)
        .expect("the JWS verifies with the certificate's key");
    let detail = harness.prompter().storage_prompts()[0].detail.clone();
    assert!(detail.unwrap().ends_with(": Документ 1"));
    let choice = &harness.prompter().choice_prompts()[0];
    assert_eq!(choice.buttons, ["Подписать", "Посмотреть", "Отмена"]);
    assert_eq!(choice.text, "Документы для подписи:\n\n• Документ 1");
}

#[test]
fn acbank_json_initial_and_subsequent() {
    let mut steps = sign_steps("user-gost2015-sign");
    steps.extend(sign_steps("legal-gost2015-sign"));
    let harness = Harness::new(steps, vec![]);
    let mut session = harness.session("acbank");
    let args =
        json!({"signatureOperation": "INITIAL", "signableItems": [item("7", "payload text")]});
    let body = acbank_body(session.call(&acbank("multiSignJsonWithJws", Some(args)), None));
    let signed = &body["signedItems"][0];
    assert_eq!(signed["id"], "7");
    let jws = signed["jws"].as_str().unwrap();
    assert!(!jws.contains('='), "{jws}");
    let jws_json = String::from_utf8(unb64url(jws)).unwrap();
    assert!(
        jws_json.starts_with(r#"{"payload":"cGF5bG9hZCB0ZXh0","signatures":[{"protected":""#),
        "{jws_json}"
    );
    let first: Value = serde_json::from_str(&jws_json).unwrap();
    let protected = first["signatures"][0]["protected"].as_str().unwrap();
    let header: Value = serde_json::from_slice(&unb64url(protected)).unwrap();
    let ts = header["ts"].as_str().unwrap();
    assert_eq!(header["spanid"], sha256_hex(&format!("payload text{ts}")));
    let verify = |store: &str, signature: &Value, protected: &str| {
        entry(store)
            .key
            .public_key()
            .verify(
                SigAlg::Gost2015_512,
                format!("{protected}.cGF5bG9hZCB0ZXh0").as_bytes(),
                &unb64url(signature.as_str().unwrap()),
            )
            .expect("the signature verifies");
    };
    verify(
        "user-gost2015-sign",
        &first["signatures"][0]["signature"],
        protected,
    );

    // SUBSEQUENT adds a signature over the same payload.
    let args = json!({"signatureOperation": "SUBSEQUENT", "signableItems": [item("7", jws)]});
    let body = acbank_body(session.call(&acbank("multiSignJsonWithJws", Some(args)), None));
    let second: Value =
        serde_json::from_slice(&unb64url(body["signedItems"][0]["jws"].as_str().unwrap())).unwrap();
    assert_eq!(second["payload"], "cGF5bG9hZCB0ZXh0");
    let signatures = second["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0], first["signatures"][0]);
    let protected = signatures[1]["protected"].as_str().unwrap();
    let header: Value = serde_json::from_slice(&unb64url(protected)).unwrap();
    assert_eq!(header["spanid"], sha256_hex(header["ts"].as_str().unwrap()));
    verify(
        "legal-gost2015-sign",
        &signatures[1]["signature"],
        protected,
    );
}

#[test]
fn acbank_x5c_chain() {
    let harness = Harness::new(sign_steps("inter-user-gost2015-sign"), vec![]);
    let args = json!({"signableItems": [item("1", "{}")]});
    let body = acbank_body(harness.call("acbank", &acbank("signJsonWithJws", Some(args)), None));
    let (header, ..) = compact_parts(body["signedItems"][0]["signature"].as_str().unwrap());
    let header: Value = serde_json::from_str(&header).unwrap();
    let x5c: Vec<Vec<u8>> = header["x5c"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| decode_java(c.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(x5c.len(), 3);
    let leaf = oncl_pki::cert::parse(&x5c[0]).unwrap();
    assert_eq!(leaf, entry("inter-user-gost2015-sign").cert);
    assert_eq!(x5c[1], oncl_testkit::synthetic_cert("inter-gost2015"));
    assert_eq!(x5c[2], oncl_testkit::synthetic_cert("root-gost2015"));
}

#[test]
fn acbank_spanid_rules() {
    let harness = Harness::new(sign_steps("user-gost2015-sign"), vec![]);
    let mut given = item("1", "{}");
    given["spanId"] = json!("span-1");
    let args = json!({"signableItems": [given, item("2", "{}")]});
    let body = acbank_body(harness.call("acbank", &acbank("signJsonWithJws", Some(args)), None));
    let items = body["signedItems"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["spanId"], "span-1");
    assert_eq!(items[1]["spanId"], "");
    let span = |i: usize| {
        let (header, ..) = compact_parts(items[i]["signature"].as_str().unwrap());
        serde_json::from_str::<Value>(&header).unwrap()
    };
    assert_eq!(span(0)["spanid"], "span-1");
    let second = span(1);
    assert_eq!(
        second["spanid"],
        sha256_hex(&format!(
            "application/json{}",
            second["ts"].as_str().unwrap()
        ))
    );
    assert_eq!(
        harness.prompter().choice_prompts()[0].text,
        "Документы для подписи:\n\n• Документ 1\n• Документ 2"
    );
}

#[test]
fn acbank_window_closed() {
    let harness = Harness::new(
        vec![
            // «View» of a single document shows it, then the window again.
            Step::Choice {
                button: 1,
                option: None,
            },
            Step::Message,
            Step::CancelChoice,
            // «Cancel».
            Step::Choice {
                button: 2,
                option: None,
            },
            // «Sign», then no key.
            Step::Choice {
                button: 0,
                option: None,
            },
            Step::CancelStorage,
        ],
        vec![],
    );
    let args = json!({"signableItems": [item("1", "{\"a\":[1,2],\"b\":{}}")]});
    for _ in 0..3 {
        assert_eq!(
            text(harness.call(
                "acbank",
                &acbank("signJsonWithJws", Some(args.clone())),
                None
            )),
            acbank_error("window.closed")
        );
    }
    let message = &harness.prompter().message_prompts()[0];
    assert_eq!(
        message.text,
        "Содержимое документа\n\n{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": {}\n}"
    );
    assert_eq!(
        harness.prompter().timeline(),
        ["choice", "message", "choice", "choice", "choice", "storage"]
    );
}

#[test]
fn acbank_non_gost2015_unexpected_error() {
    for store in ["user-gost2004-sign", "user-rsa-sign"] {
        let harness = Harness::new(sign_steps(store), vec![]);
        let args = json!({"signableItems": [item("1", "{}")]});
        assert_eq!(
            text(harness.call("acbank", &acbank("signJsonWithJws", Some(args)), None)),
            acbank_error("unexpected-error"),
            "{store}"
        );
    }
    // JWS JSON without an operation fails on signing, after the key is chosen.
    let harness = Harness::new(sign_steps("user-gost2015-sign"), vec![]);
    let args = json!({"signableItems": [item("1", "x")]});
    assert_eq!(
        text(harness.call("acbank", &acbank("multiSignJsonWithJws", Some(args)), None)),
        acbank_error("unexpected-error")
    );
    assert_eq!(
        harness.prompter().timeline(),
        ["choice", "storage", "busy", "busy closed", "key"]
    );
}
