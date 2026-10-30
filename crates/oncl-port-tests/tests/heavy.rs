//! The ports of the heavy plugins: Buhta NcaModule, Alatau City Bank, KNP (ИС СОНО),
//! Documentolog.

use oncl_basics::testing::Step;
use oncl_basics::{Availability, DisabledReason};
use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::key::SigAlg;
use oncl_port_tests::{Harness, entry, p12};
use oncl_protocol::Reply;
use oncl_protocol::javab64::decode_java;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier, Mutex};

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

// KNP (ИС СОНО).

const KNP: &str = "kz.inessoft.kgd.knp.ncalayer.KNPModuleService";
const KGD: Option<&str> = Some("https://cabinet.kgd.gov.kz");
const KNP_ERROR: &str = r#"{"resultStatus":{"resultCode":"ERROR"},"requestId":"r1"}"#;

fn knp(command: &str, fields: Value) -> String {
    let mut request = json!({"module": KNP, "command": command, "requestId": "r1"});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    request.to_string()
}

/// A key store as the page sends it: a data URL of the file.
fn data_url(name: &str) -> String {
    let (path, _) = p12(name);
    format!(
        "data:application/x-pkcs12;base64,{}",
        b64(&oncl_testkit::read(path))
    )
}

fn alias(name: &str) -> String {
    oncl_testkit::synthetic(name).aliases[0].clone()
}

/// The SmartAuth service: canned answers by the end of the URL, the requests made.
#[derive(Default)]
struct SmartAuth {
    answers: Mutex<Vec<(String, u16, String)>>,
    requests: Mutex<Vec<(String, Option<String>, String)>>,
}

impl SmartAuth {
    fn with(answers: &[(&str, u16, Value)]) -> Arc<SmartAuth> {
        Arc::new(SmartAuth {
            answers: Mutex::new(
                answers
                    .iter()
                    .map(|(call, status, body)| ((*call).to_owned(), *status, body.to_string()))
                    .collect(),
            ),
            requests: Mutex::default(),
        })
    }

    /// `(url, content type, body)` of each request.
    fn requests(&self) -> Vec<(String, Option<String>, String)> {
        self.requests.lock().unwrap().clone()
    }
}

impl HttpTransport for SmartAuth {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        assert_eq!(request.method, HttpMethod::Post);
        self.requests.lock().unwrap().push((
            request.url.to_owned(),
            request.content_type.map(str::to_owned),
            String::from_utf8(request.body.to_vec()).unwrap(),
        ));
        let mut answers = self.answers.lock().unwrap();
        let Some(at) = answers
            .iter()
            .position(|(call, ..)| request.url.ends_with(call.as_str()))
        else {
            return Ok(HttpReply {
                status: 404,
                content_type: None,
                location: None,
                body: Vec::new(),
            });
        };
        let (_, status, body) = answers.remove(at);
        Ok(HttpReply {
            status,
            content_type: Some("application/json".to_owned()),
            location: None,
            body: body.into_bytes(),
        })
    }
}

fn kgd(server: &Arc<SmartAuth>) -> Vec<(String, Arc<dyn HttpTransport>)> {
    vec![(
        "https://cabinet.kgd.gov.kz/".to_owned(),
        Arc::clone(server) as Arc<dyn HttpTransport>,
    )]
}

#[test]
fn knp_drop_paths() {
    let harness = Harness::new(vec![], vec![]);
    let call = |request: &str, origin| harness.call("knp", request, origin);
    assert_eq!(call("{", KGD), Reply::Drop);
    assert_eq!(call(&json!({"module": KNP}).to_string(), KGD), Reply::Drop);
    assert_eq!(call(&knp("info", json!({})), None), Reply::Drop);
    assert_eq!(call(&knp("nope", json!({})), KGD), Reply::Drop);
    // Without a requestId the command fails, its reply without one.
    assert_eq!(
        text(call(
            &json!({"module": KNP, "command": "info"}).to_string(),
            KGD
        )),
        r#"{"resultStatus":{"resultCode":"ERROR"}}"#
    );
}

#[test]
fn knp_info_and_storage_types() {
    let harness = Harness::new(vec![], vec![]);
    let call = |command: &str, fields: Value| text(harness.call("knp", &knp(command, fields), KGD));
    assert_eq!(
        call("info", json!({})),
        r#"{"resultStatus":{"resultCode":"OK"},"requestId":"r1","type":"personal","version":"1.1.0","status":"READY"}"#
    );
    assert_eq!(
        call("getAuthAccounts", json!({})),
        r#"{"resultStatus":{"resultCode":"OK"},"requestId":"r1","accounts":[]}"#
    );
    assert_eq!(
        call("getStorageType", json!({})),
        r#"{"resultStatus":{"resultCode":"OK"},"storages":[{"name":"PKCS12","token":false},{"name":"KAZTOKEN","token":true},{"name":"KZIDCARD","token":true},{"name":"ETOKEN_72K","token":true},{"name":"JACARTA","token":true}],"requestId":"r1"}"#
    );
    // No token readers before tokens are supported.
    assert_eq!(
        call("getStorageDevicesByType", json!({"storage": "KAZTOKEN"})),
        r#"{"resultStatus":{"resultCode":"OK"},"requestId":"r1","tokenTerminals":[]}"#
    );
    for storage in ["PKCS12", "OTHER"] {
        assert_eq!(
            call("getStorageDevicesByType", json!({"storage": storage})),
            KNP_ERROR
        );
    }
    assert_eq!(
        call("hardwarePair", json!({})),
        r#"{"resultStatus":{"resultCode":"OK"},"requestId":"r1","hardwareKey":"hardwareKey","token":{"hardwareId":"hwtoken.hardwareId","id":"hwtoken.id","parentHash":"hwtoken.parentHash","hash":"hwtoken.hash","parentId":"hwtoken.parentId"}}"#
    );
}

#[test]
fn knp_attach_device_raw_null() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call("knp", &knp("attachDeviceToAccount", json!({})), KGD)),
        "null"
    );
}

/// The keys of `text` in the order they appear.
fn assert_key_order(text: &str, keys: &[&str]) {
    let mut last = 0;
    for key in keys {
        let at = text[last..]
            .find(&format!("\"{key}\":"))
            .unwrap_or_else(|| panic!("{key} missing or out of order in {text}"));
        last += at + 1;
    }
}

#[test]
fn knp_certificates_from_data_url() {
    let harness = Harness::new(vec![], vec![]);
    let request = knp(
        "getCertificates",
        json!({"type": "PKCS12", "storagePath": data_url("user-gost2015-sign"), "password": "Qwerty12"}),
    );
    let reply = text(harness.call("knp", &request, KGD));
    assert!(
        reply.starts_with(r#"{"resultStatus":{"resultCode":"OK"},"certificates":[{"keyUsage":{"#),
        "{reply}"
    );
    assert_key_order(
        &reply,
        &[
            "keyUsage",
            "keyEncipherment",
            "crlSign",
            "nonRepudiation",
            "digitalSignature",
            "keyAgreement",
            "keyCertSign",
            "issuerDN",
            "alias",
            "subjectDN",
            "algorithm",
            "validTo",
            "requestId",
        ],
    );
    let reply: Value = serde_json::from_str(&reply).unwrap();
    let cert = &reply["certificates"][0];
    let key = entry("user-gost2015-sign");
    let tbs = key.cert.tbs_certificate();
    assert_eq!(cert["subjectDN"], oncl_pki::info::kalkan_dn(tbs.subject()));
    assert_eq!(cert["issuerDN"], oncl_pki::info::kalkan_dn(tbs.issuer()));
    assert_eq!(cert["alias"], alias("user-gost2015-sign"));
    assert_eq!(cert["algorithm"], "ECGOST3410-2015");
    let valid_to = cert["validTo"].as_str().unwrap();
    let shape: String = valid_to
        .chars()
        .map(|c| if c.is_ascii_digit() { '9' } else { c })
        .collect();
    assert!(
        shape == "99-99-9999 99:99:99 +9999" || shape == "99-99-9999 99:99:99 -9999",
        "{valid_to}"
    );
    assert_eq!(cert["keyUsage"]["digitalSignature"], true);
    assert_eq!(cert["keyUsage"]["keyCertSign"], false);
    // Without `base64,` the whole path is the base64 of the store.
    let (path, _) = p12("user-rsa-sign");
    let request = knp(
        "getCertificates",
        json!({"type": "PKCS12", "storagePath": b64(&oncl_testkit::read(path)), "password": "Qwerty12"}),
    );
    let reply: Value = serde_json::from_str(&text(harness.call("knp", &request, KGD))).unwrap();
    assert_eq!(reply["certificates"][0]["algorithm"], "RSA");
    // An unknown storage type.
    let request = knp(
        "getCertificates",
        json!({"type": "JKS", "storagePath": "x"}),
    );
    assert_eq!(text(harness.call("knp", &request, KGD)), KNP_ERROR);
}

fn crypto_error(code: &str) -> String {
    format!(
        r#"{{"resultStatus":{{"resultCode":"ERROR"}},"requestId":"r1","error":{{"cryptoError":"{code}"}}}}"#
    )
}

#[test]
fn knp_wrong_password_code() {
    let harness = Harness::new(vec![], vec![]);
    let certificates = |path: &str, password: &str| {
        let request = knp(
            "getCertificates",
            json!({"type": "PKCS12", "storagePath": path, "password": password}),
        );
        text(harness.call("knp", &request, KGD))
    };
    assert_eq!(
        certificates(&data_url("user-gost2015-sign"), "wrong"),
        crypto_error("STORE_WRONG_PASSWORD")
    );
    assert_eq!(
        certificates(
            &format!("data:;base64,{}", b64(b"not a key store")),
            "Qwerty12"
        ),
        crypto_error("KEY_STORE_ERROR")
    );
    let sign = |store: &str| {
        let request = knp(
            "signDocument",
            json!({"xml": "<a/>", "inputFormat": "STRING", "outputFormat": "STRING",
                "storagePath": data_url(store), "alias": alias(store), "password": "Qwerty12",
                "storageType": "PKCS12"}),
        );
        text(harness.call("knp", &request, KGD))
    };
    assert_eq!(
        sign("expired-gost2015-sign"),
        crypto_error("SIGN_CERT_EXPIRED")
    );
}

fn sign_document(xml: &str, input: &str, output: &str, store: &str) -> String {
    knp(
        "signDocument",
        json!({"xml": xml, "inputFormat": input, "outputFormat": output,
            "storagePath": data_url(store), "alias": alias(store), "password": "Qwerty12",
            "storageType": "PKCS12"}),
    )
}

#[test]
fn knp_sign_document_layout() {
    let harness = Harness::new(vec![], vec![]);
    let reply = text(harness.call(
        "knp",
        &sign_document(
            "<root><a>1</a></root>",
            "STRING",
            "STRING",
            "user-gost2015-sign",
        ),
        KGD,
    ));
    assert!(
        reply.starts_with(r#"{"resultStatus":{"resultCode":"OK"},"signedXml":"#),
        "{reply}"
    );
    assert!(reply.ends_with(r#","requestId":"r1"}"#), "{reply}");
    let reply: Value = serde_json::from_str(&reply).unwrap();
    let xml = reply["signedXml"].as_str().unwrap();
    assert!(
        xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><root>"),
        "{xml}"
    );
    assert!(xml.contains("Id=\"1\">"), "{xml}");
    assert!(xml.contains("Target=\"#1\""), "{xml}");
    assert!(xml.contains("Id=\"signingTime\""), "{xml}");
    assert!(xml.contains("URI=\"#signingTime\""), "{xml}");
    assert!(xml.contains("gostr34102015-gostr34112015-512"), "{xml}");
    let at = xml.find("<timestamp").unwrap();
    let stamp = &xml[xml[at..].find('>').unwrap() + at + 1..xml.find("</timestamp>").unwrap()];
    assert_eq!(stamp.len(), "29-10-2026 17:00:00 +0500".len(), "{stamp}");
    assert_eq!(oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap().len(), 1);
    // The next signature's Id counts the signatures already there.
    let again = text(harness.call(
        "knp",
        &sign_document(&b64(xml.as_bytes()), "BASE64", "BASE64", "user-rsa-sign"),
        KGD,
    ));
    let again: Value = serde_json::from_str(&again).unwrap();
    let twice =
        String::from_utf8(decode_java(again["signedXml"].as_str().unwrap()).unwrap()).unwrap();
    assert!(twice.contains("Id=\"2\""), "{twice}");
    assert!(twice.contains("Target=\"#2\""), "{twice}");
    assert!(twice.contains("xmldsig-more#rsa-sha256"), "{twice}");
    // Both signatures carry `Id="signingTime"`, as the original's do: the document does not
    // verify as XMLDSig requires unique Ids.
    assert_eq!(twice.matches("<ds:Signature ").count(), 2);
    assert_eq!(twice.matches("Id=\"signingTime\"").count(), 2);
    // Unknown alias, input format: the general error.
    for request in [
        sign_document("<a/>", "XML", "STRING", "user-gost2015-sign"),
        knp(
            "signDocument",
            json!({"xml": "<a/>", "inputFormat": "STRING", "outputFormat": "STRING",
                "storagePath": data_url("user-gost2015-sign"), "alias": "nope",
                "password": "Qwerty12", "storageType": "PKCS12"}),
        ),
    ] {
        assert_eq!(text(harness.call("knp", &request, KGD)), KNP_ERROR);
    }
}

#[test]
fn knp_smartauth_account_status() {
    let server = SmartAuth::with(&[(
        "/SmartAuthService/getUserStatus",
        200,
        json!({"status": 0, "userRegistrationStatus": 1, "authAgreementStatus": 0,
            "authAgreementSignedFrom": 1_700_000_000_i64, "signAgreementStatus": 1, "rnn": "R"}),
    )]);
    let harness = Harness::new(vec![], kgd(&server));
    let request = knp(
        "accountStatus",
        json!({"uin": "123456789011", "type": "IIN_BIN"}),
    );
    let reply = text(harness.call("knp", &request, KGD));
    let parsed: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(parsed["resultStatus"]["resultCode"], "OK", "{reply}");
    assert_eq!(parsed["requestId"], "r1");
    // The original's misspelling.
    assert_eq!(parsed["userRegistrationStatus"], "USER_NOT_REGISTRED");
    assert_eq!(parsed["authAgreementStatus"], "AGREEMENT_SIGNED");
    assert_eq!(parsed["signAgreementStatus"], "AGREEMENT_NOT_SIGNED");
    assert_eq!(parsed["authAgreementSignedFrom"], 1_700_000_000_i64);
    assert!(parsed.get("authAgreementSignedTo").is_none());
    assert_eq!(parsed["rnn"], "R");
    assert_eq!(parsed["iinBin"], "");
    assert_eq!(
        server.requests(),
        [(
            "https://cabinet.kgd.gov.kz/SmartAuthService/getUserStatus".to_owned(),
            None,
            r#"{"uinInfo":{"type":0,"uin":"123456789011"}}"#.to_owned()
        )]
    );
    // The port of the page's origin is dropped: another origin, which is refused.
    let reply = harness.call("knp", &request, Some("https://cabinet.kgd.gov.kz:8443"));
    assert_eq!(text(reply), KNP_ERROR);
    // An unknown type name.
    let bad = knp("accountStatus", json!({"uin": "1", "type": "INN"}));
    assert_eq!(text(harness.call("knp", &bad, KGD)), KNP_ERROR);
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn knp_sign_agreement_flow() {
    let server = SmartAuth::with(&[
        (
            "/SmartAuthService/createAgreementXmlToSign",
            200,
            json!({"status": 0, "xmlToSign": "<agreement><text>Согласие</text></agreement>"}),
        ),
        (
            "/SmartAuthService/createAgreementXmlToSign",
            200,
            json!({"status": 0, "xmlToSign": "<cancel/>"}),
        ),
        (
            "/SmartAuthService/cancelAgreement",
            200,
            json!({"status": 0}),
        ),
    ]);
    let harness = Harness::new(vec![], kgd(&server));
    // Now is 2026-10-29 12:00 UTC.
    let from = 1_793_275_200_i64;
    let request = knp(
        "signAgreement",
        json!({"uin": "123456789011", "type": "IIN_BIN", "userAgreementType": "AGREEMENT_SIGN",
            "lang": "ru", "signFrom": from, "signTo": from + 86_400,
            "storagePath": data_url("user-gost2015-sign"), "alias": alias("user-gost2015-sign"),
            "password": "Qwerty12", "storageType": "PKCS12"}),
    );
    let reply: Value = serde_json::from_str(&text(harness.call("knp", &request, KGD))).unwrap();
    assert_eq!(reply["resultStatus"]["resultCode"], "OK", "{reply}");
    let signed = reply["signedAgreement"].as_str().unwrap();
    assert!(signed.contains("<text>Согласие</text>"), "{signed}");
    assert_eq!(
        oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap().len(),
        1
    );
    assert_eq!(
        server.requests()[0].2,
        format!(
            r#"{{"uinInfo":{{"type":0,"uin":"123456789011"}},"agreementType":1,"language":"ru","signFrom":{from},"signTo":{}}}"#,
            from + 86_400
        )
    );

    let request = knp(
        "cancelAgreement",
        json!({"uin": "123456789011", "type": "IIN_BIN", "userAgreementType": "AGREEMENT_CANCEL_SIGN",
            "language": "kk", "storagePath": data_url("user-gost2015-sign"),
            "alias": alias("user-gost2015-sign"), "password": "Qwerty12", "storageType": "PKCS12"}),
    );
    assert_eq!(
        text(harness.call("knp", &request, KGD)),
        r#"{"resultStatus":{"resultCode":"OK"},"requestId":"r1"}"#
    );
    let requests = server.requests();
    assert_eq!(
        requests[1].2,
        r#"{"uinInfo":{"type":0,"uin":"123456789011"},"agreementType":101,"language":"kk"}"#
    );
    assert!(requests[2].0.ends_with("/SmartAuthService/cancelAgreement"));
    let cancel: Value = serde_json::from_str(&requests[2].2).unwrap();
    let signed = cancel["signedCancelAgreementXml"].as_str().unwrap();
    assert!(
        signed.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><cancel>"),
        "{signed}"
    );
    assert_eq!(
        oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap().len(),
        1
    );
}

fn agreement_error(code: &str) -> String {
    format!(
        r#"{{"requestId":"r1","error":{{"createAgreementXmlToSignError":"AGREEMENT_XML_GENERATION_{code}"}}}}"#
    )
}

#[test]
fn knp_period_validation_errors() {
    let server = SmartAuth::with(&[]);
    let harness = Harness::new(vec![], kgd(&server));
    let now = 1_793_275_200_i64;
    let call = |kind: &str, from: Value, to: Value| {
        let request = knp(
            "signAgreement",
            json!({"uin": "1", "type": "IIN_BIN", "userAgreementType": kind, "lang": "ru",
                "signFrom": from, "signTo": to}),
        );
        text(harness.call("knp", &request, KGD))
    };
    assert_eq!(
        call("AGREEMENT_AUTH", Value::Null, json!(now)),
        agreement_error("MUST_BE_WITH_PERIOD")
    );
    assert_eq!(
        call("AGREEMENT_CANCEL_AUTH", json!(now), Value::Null),
        agreement_error("MUST_BE_WITHOUT_PERIOD")
    );
    assert_eq!(
        call("AGREEMENT_CANCEL_SIGN", Value::Null, json!(now)),
        agreement_error("MUST_BE_WITHOUT_PERIOD")
    );
    assert_eq!(
        call("AGREEMENT_SIGN", json!(now + 10), json!(now)),
        agreement_error("INVALID_PERIOD")
    );
    assert_eq!(
        call("AGREEMENT_SIGN", json!(now - 43_201), json!(now + 86_400)),
        agreement_error("FROM_IS_TOO_IN_PAST")
    );
    assert_eq!(
        call("AGREEMENT_SIGN", json!(now), json!(now + 3_599)),
        agreement_error("TOO_SHORT_PERIOD")
    );
    assert!(server.requests().is_empty());
}

#[test]
fn knp_server_error_mapping() {
    let server = SmartAuth::with(&[
        (
            "/SmartAuthService/getUserStatus",
            200,
            json!({"status": 10, "uinValidationError": 2}),
        ),
        (
            "/SmartAuthService/getUserStatus",
            200,
            json!({"status": 10}),
        ),
        (
            "/SmartAuthService/getUserStatus",
            200,
            json!({"status": 1000}),
        ),
        ("/SmartAuthService/getUserStatus", 500, json!({})),
        (
            "/SmartAuthService/getAgreementText",
            200,
            json!({"status": 10}),
        ),
        (
            "/SmartAuthService/getAgreementText",
            200,
            json!({"status": 0, "agreementTextInfos": [{"agreementType": 100, "text": "T", "version": "2"}]}),
        ),
        (
            "/SmartAuthService/setPasswordConfirmation",
            200,
            json!({"status": 10, "checkConfirmationError": 1}),
        ),
        (
            "/SmartAuthService/registerUser",
            200,
            json!({"status": 0, "sentConfirmationData": {"operationId": "op", "usedMethod": 1}}),
        ),
        (
            "/SmartAuthService/setPassword",
            200,
            json!({"status": 10, "newPasswordValidationError": 1}),
        ),
    ]);
    let harness = Harness::new(vec![], kgd(&server));
    let call = |command: &str, fields: Value| text(harness.call("knp", &knp(command, fields), KGD));
    let status = json!({"uin": "1", "type": "RNN"});
    assert_eq!(
        call("accountStatus", status.clone()),
        r#"{"requestId":"r1","error":{"uinValidationError":"UIN_INCORRECT"}}"#
    );
    assert_eq!(
        call("accountStatus", status.clone()),
        r#"{"requestId":"r1"}"#
    );
    assert_eq!(call("accountStatus", status.clone()), KNP_ERROR);
    assert_eq!(call("accountStatus", status), KNP_ERROR);
    let text_request = json!({"agreementTypes": ["AGREEMENT_CANCEL_AUTH"], "lang": "en"});
    assert_eq!(
        call("getAgreementText", text_request.clone()),
        r#"{"requestId":"r1","error":{"errorCause":"Undefined sever error!"}}"#
    );
    let texts: Value = serde_json::from_str(&call("getAgreementText", text_request)).unwrap();
    assert_eq!(
        texts["agreementTextInfos"],
        json!([{"text": "T", "userAgreementTypeEnum": "AGREEMENT_CANCEL_AUTH", "version": "2"}])
    );
    // The original fails on its own mapping here.
    assert_eq!(
        call(
            "confirmChangePassword",
            json!({"operationId": "o", "code": "1"})
        ),
        KNP_ERROR
    );
    // Address checks before the request.
    assert_eq!(
        call(
            "signUp",
            json!({"uin": "1", "type": "IIN_BIN", "signedAuthAgreementXml": "<a/>",
            "address": "not mail", "method": "MAIL", "confirmationLanguage": "ru",
            "oneTimeHardwareTokenBlock": false})
        ),
        r#"{"requestId":"r1","error":{"sendingConfirmationError":"SENDING_CONFIRMATION_ILLEGAL_MAIL_FORMAT"}}"#
    );
    assert_eq!(
        call(
            "changeConfirmationType",
            json!({"uin": "1", "type": "IIN_BIN", "password": "p",
            "address": "12", "method": "SMS", "confirmationLanguage": "ru"})
        ),
        r#"{"resultStatus":{"resultCode":"ERROR"},"requestId":"r1","error":{"sendingConfirmationError":"SENDING_CONFIRMATION_ILLEGAL_PHONE_FORMAT"}}"#
    );
    let signed_up: Value = serde_json::from_str(&call(
        "signUp",
        json!({"uin": "1", "type": "IIN_BIN", "signedAuthAgreementXml": "<a/>",
            "address": "+7 (701) 123-45-67", "method": "SMS", "confirmationLanguage": "ru",
            "oneTimeHardwareTokenBlock": true}),
    ))
    .unwrap();
    assert_eq!(
        signed_up["sentConfirmationData"],
        json!({"usedMethod": "SMS", "operationId": "op"})
    );
    assert_eq!(
        call(
            "changePassword",
            json!({"uin": "1", "type": "IIN_BIN", "password": "p",
            "newPassword": "q", "confirmationLanguage": "ru"})
        ),
        r#"{"requestId":"r1","error":{"newPasswordValidationError":"PASSWORD_TOO_SHORT"}}"#
    );
    let requests = server.requests();
    let register = requests
        .iter()
        .find(|(url, ..)| url.ends_with("/registerUser"))
        .unwrap();
    assert_eq!(
        register.2,
        r#"{"uinInfo":{"type":0,"uin":"1"},"confirmationsSetting":{"method":1,"address":"77011234567"},"confirmationLanguage":"ru","hardwareKey":"HWKEY","isOneTimeHardwareTokenBlock":true,"signedAuthAgreementXml":"\u003ca/\u003e"}"#
    );
    assert!(
        requests
            .iter()
            .all(|(_, content_type, _)| content_type.is_none())
    );
}

// Documentolog.

const SIGN_SERVICE: &str = "kz.documentolog.agent.SignService";
const KALKAN_SERVICE: &str = "kz.documentolog.agent.KalkanService";
const DOCLOG: Option<&str> = Some("https://app.documentolog.kz");

fn doclog(module: &str, method: &str, args: Value) -> String {
    json!({"module": module, "method": method, "args": args}).to_string()
}

fn doclog_result(result: &str) -> String {
    json!({"code": 200, "message": "success", "responseObject": {"result": result}}).to_string()
}

/// The result of a successful Documentolog reply.
fn doclog_ok(reply: Reply) -> String {
    let text = text(reply);
    assert!(
        text.starts_with(r#"{"code":200,"message":"success","responseObject":{"result":"#),
        "{text}"
    );
    let reply: Value = serde_json::from_str(&text).unwrap();
    reply["responseObject"]["result"]
        .as_str()
        .unwrap()
        .to_owned()
}

const UNKNOWN: &str = r#"{"code":500,"message":"unknown"}"#;

/// The p12 of `name` and the steps that open it: the password dialog, the consent.
fn doclog_store(name: &str) -> (String, Vec<Step>) {
    let (path, password) = p12(name);
    (
        path.to_string_lossy().into_owned(),
        vec![
            Step::Password(password.to_owned()),
            Step::Confirm { yes: true },
        ],
    )
}

/// A test key of the server flow: the port built with feature `test-key` encrypts its
/// challenge with it.
const TEST_P: &str = "F84A59355863773016CA3A43920D17E8A3DF9DE7162B273C8307F841081CEC95408698A95D9E0C4326AEAFB5ADFF9361CDCA27B445EC69771320283931C9AC620F5E6CFD4AD4CEE2424367875669EC628EEC706937503C46770330AD90C3AD477B33511095C19F624DB365FBB052B8C8F0FE1E862E59E4261F9AC91682233527";
const TEST_Q: &str = "B63F784EF7925B589C05B50AC6758E6F09B67F337A70C2A7FD1DFDD717128E784DBCC4D2B84C73771739E5A6002E34571F83593ADC883230151DCD641B6ABF726AF66E7DA5A7379A4FD9A72ACED69F91D419D48A54BD06407F648A541DF13F0FA0C40B8BDAE220AD5D7F3A312EFB2A8BC4F23C0FEDE551E6B2F913CABB3E9065";

/// The Documentolog port built with its test key, packaged.
fn documentolog_test_key_package() -> Vec<u8> {
    static WASM: std::sync::LazyLock<std::path::PathBuf> = std::sync::LazyLock::new(|| {
        let root = oncl_testkit::workspace_root();
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .map(|dir| {
                if dir.is_absolute() {
                    dir
                } else {
                    root.join(dir)
                }
            })
            .unwrap_or_else(|| root.join("target"))
            .join("plugin-ports-test-key");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = std::process::Command::new(cargo)
            .current_dir(&root)
            .args([
                "build",
                "--release",
                "--locked",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .args(["-p", "oncl-port-documentolog", "--features", "test-key"])
            .arg("--manifest-path")
            .arg(root.join("plugins/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .status()
            .expect("cargo runs");
        assert!(status.success(), "the test-key build failed");
        target.join("wasm32-unknown-unknown/release/oncl_port_documentolog.wasm")
    });
    let manifest =
        oncl_testkit::read(oncl_port_tests::port_dir("documentolog").join("plugin.toml"));
    oncl_plugin::archive(&manifest, &oncl_testkit::read(&*WASM)).unwrap()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// `iv` + base64 of AES-128-CBC/PKCS#5 of `plain` with the key `key`, the IV the first 16
/// characters.
fn doclog_encrypt(key: &str, iv: &str, plain: &str) -> String {
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    let encrypted = cbc::Encryptor::<aes::Aes128>::new_from_slices(key.as_bytes(), iv.as_bytes())
        .unwrap()
        .encrypt_padded_vec::<Pkcs7>(plain.as_bytes());
    format!("{iv}{}", b64(&encrypted))
}

/// A GET: its URL and headers.
type Get = (String, Vec<(String, String)>);

/// Documentolog's server: the challenge's answer (its fields encrypted with the challenge),
/// documents by URL; every GET with its headers.
struct Doclog {
    fields: Vec<(&'static str, String)>,
    plain: Vec<(&'static str, String)>,
    documents: Vec<(String, String)>,
    requests: Mutex<Vec<Get>>,
}

impl Doclog {
    fn requests(&self) -> Vec<Get> {
        self.requests.lock().unwrap().clone()
    }
}

impl HttpTransport for Doclog {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        assert_eq!(request.method, HttpMethod::Get);
        self.requests.lock().unwrap().push((
            request.url.to_owned(),
            request
                .headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
        ));
        let reply = |body: Vec<u8>| {
            Ok(HttpReply {
                status: 200,
                content_type: None,
                location: None,
                body,
            })
        };
        if let Some((_, code)) = request.url.split_once("&code=") {
            let challenge = decode_java(&percent_decode(code)).unwrap();
            let key = rsa::RsaPrivateKey::from_p_q(
                rsa::BigUint::parse_bytes(TEST_P.as_bytes(), 16).unwrap(),
                rsa::BigUint::parse_bytes(TEST_Q.as_bytes(), 16).unwrap(),
                rsa::BigUint::from(65_537_u32),
            )
            .unwrap();
            let s_rand =
                String::from_utf8(key.decrypt(rsa::Pkcs1v15Encrypt, &challenge).unwrap()).unwrap();
            assert_eq!(s_rand.len(), 16);
            let mut answer = serde_json::Map::new();
            answer.insert("status".into(), json!("1"));
            for (i, (name, value)) in self.fields.iter().enumerate() {
                let iv = format!("{i:016}");
                answer.insert((*name).into(), json!(doclog_encrypt(&s_rand, &iv, value)));
            }
            for (name, value) in &self.plain {
                answer.insert((*name).into(), json!(value));
            }
            return reply(Value::Object(answer).to_string().into_bytes());
        }
        match self.documents.iter().find(|(url, _)| *url == request.url) {
            Some((_, body)) => reply(body.clone().into_bytes()),
            None => Ok(HttpReply {
                status: 404,
                content_type: None,
                location: None,
                body: Vec::new(),
            }),
        }
    }
}

fn doclog_server(
    fields: Vec<(&'static str, String)>,
    plain: Vec<(&'static str, String)>,
    documents: Vec<(&str, &str)>,
) -> Arc<Doclog> {
    Arc::new(Doclog {
        fields,
        plain,
        documents: documents
            .into_iter()
            .map(|(u, b)| (u.to_owned(), b.to_owned()))
            .collect(),
        requests: Mutex::default(),
    })
}

fn doclog_routes(server: &Arc<Doclog>) -> Vec<(String, Arc<dyn HttpTransport>)> {
    vec![(
        "https://app.documentolog.kz/".to_owned(),
        Arc::clone(server) as Arc<dyn HttpTransport>,
    )]
}

#[test]
fn documentolog_module_field_routes() {
    let harness = Harness::new(vec![], vec![]);
    let call = |module, method| {
        text(harness.call("documentolog", &doclog(module, method, json!({})), DOCLOG))
    };
    assert_eq!(call(KALKAN_SERVICE, "init"), doclog_result("init"));
    assert_eq!(
        call(SIGN_SERVICE, "init"),
        r#"{"code":500,"message":"unknown method"}"#
    );
    assert_eq!(
        call(KALKAN_SERVICE, "nope"),
        r#"{"code":500,"message":"unknown method"}"#
    );
    assert_eq!(call(KALKAN_SERVICE, "getCurrentUser"), doclog_result(""));
    assert_eq!(
        call(KALKAN_SERVICE, "getCurrentStoragePath"),
        doclog_result("null")
    );
    assert!(harness.prompter().timeline().is_empty());
}

#[test]
fn documentolog_missing_args_drops() {
    let harness = Harness::new(vec![], vec![]);
    for request in [
        "{".to_owned(),
        json!({"module": KALKAN_SERVICE, "method": "init"}).to_string(),
        json!({"module": KALKAN_SERVICE, "method": "init", "args": "x"}).to_string(),
        json!({"module": SIGN_SERVICE, "method": "getKeys", "args": null}).to_string(),
    ] {
        assert_eq!(
            harness.call("documentolog", &request, DOCLOG),
            Reply::Drop,
            "{request}"
        );
    }
}

#[test]
fn documentolog_browse_directory_mode() {
    let dir = std::env::temp_dir();
    let (file, _) = p12("user-rsa-sign");
    let harness = Harness::new(
        vec![
            Step::Password("Qwerty12".to_owned()),
            Step::Path(dir.clone()),
            Step::Path(file.clone()),
            // The next browse: a cancelled chooser drops the connection.
            Step::CancelPath,
            // The other sessions ask for the password again.
            Step::Password("Qwerty12".to_owned()),
            Step::Password("Qwerty12".to_owned()),
        ],
        vec![],
    );
    let mut session = harness.session("documentolog");
    let browse = |ext: &str| {
        doclog(
            KALKAN_SERVICE,
            "browseKeyStore",
            json!({"storage_name": "PKCS12", "file_extension": ext}),
        )
    };
    assert_eq!(
        doclog_ok(session.call(&browse(""), DOCLOG)),
        dir.to_string_lossy()
    );
    assert_eq!(
        doclog_ok(session.call(&browse("P12"), DOCLOG)),
        file.to_string_lossy()
    );
    let paths = harness.prompter().path_prompts();
    assert_eq!(paths[0].mode, oncl_basics::PathMode::Directory);
    assert_eq!(paths[1].mode, oncl_basics::PathMode::File);
    assert_eq!(paths[1].filters[0].extensions, ["p12"]);
    // The password dialog once: it is kept.
    let passwords = harness.prompter().password_prompts();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].title.as_deref(), Some("Пароль для ЭЦП"));
    assert_eq!(passwords[0].message.as_deref(), Some("Пароль для ЭЦП: "));
    assert_eq!(session.call(&browse("P12"), DOCLOG), Reply::Drop);
    // The original's guard stays up after the exception: every browse fails now.
    assert_eq!(text(session.call(&browse("P12"), DOCLOG)), UNKNOWN);
    // An unknown file type drops the connection (in a new session).
    let mut other = harness.session("documentolog");
    assert_eq!(other.call(&browse("XYZ"), DOCLOG), Reply::Drop);
    // An unknown storage, in another session still.
    let mut third = harness.session("documentolog");
    assert_eq!(
        text(third.call(
            &doclog(
                SIGN_SERVICE,
                "browseKeyStore",
                json!({"storage_name": "NOPE", "file_extension": "P12"})
            ),
            DOCLOG
        )),
        UNKNOWN
    );
}

#[test]
fn documentolog_password_cached_in_session() {
    let (path, _) = doclog_store("user-rsa-sign");
    // A wrong password: cleared, asked again; the consent once per session and path.
    let steps = vec![
        Step::Password("wrong".to_owned()),
        Step::Confirm { yes: true },
        Step::Password("Qwerty12".to_owned()),
    ];
    let harness = Harness::new(steps, vec![]);
    let mut session = harness.session("documentolog");
    let keys = doclog(
        SIGN_SERVICE,
        "getKeys",
        json!({"storage_name": "PKCS12", "storage_path": path}),
    );
    assert_eq!(text(session.call(&keys, DOCLOG)), UNKNOWN);
    doclog_ok(session.call(&keys, DOCLOG));
    doclog_ok(session.call(&keys, DOCLOG));
    assert_eq!(harness.prompter().password_prompts().len(), 2);
    assert_eq!(harness.prompter().confirm_prompts().len(), 1);
}

#[test]
fn documentolog_get_keys_lines() {
    let (path, steps) = doclog_store("multi-gost2015");
    let harness = Harness::new(steps, vec![]);
    let keys = doclog(
        KALKAN_SERVICE,
        "getKeys",
        json!({"storage_name": "PKCS12", "storage_path": path}),
    );
    let lines = doclog_ok(harness.call("documentolog", &keys, DOCLOG));
    let aliases = oncl_testkit::synthetic("multi-gost2015").aliases;
    let lines: Vec<&str> = lines.split('\n').collect();
    assert_eq!(lines.len(), aliases.len(), "{lines:?}");
    for (line, alias) in lines.iter().zip(&aliases) {
        let parts: Vec<&str> = line.split('|').collect();
        assert_eq!(parts.len(), 4, "{line}");
        assert_eq!(parts[0], "ECGOST3410-2015");
        assert!(!parts[1].is_empty());
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()), "{line}");
        assert!(!parts[2].starts_with('0'), "{line}");
        assert_eq!(parts[3], alias);
    }
}

#[test]
fn documentolog_simple_cms_over_base64_text() {
    let server = doclog_server(
        vec![],
        vec![],
        vec![("https://app.documentolog.kz/data/1", "aGVsbG8=")],
    );
    let (path, steps) = doclog_store("user-rsa-sign");
    let harness = Harness::new(steps, doclog_routes(&server));
    let request = doclog(
        KALKAN_SERVICE,
        "createCMSSimpleSignature",
        json!({"storage_alias": "PKCS12", "storage_path": path, "key_index": alias("user-rsa-sign"),
            "sign_string_url": "https://app.documentolog.kz/data/1", "attached": "true"}),
    );
    let cms = decode_java(&doclog_ok(harness.call("documentolog", &request, DOCLOG))).unwrap();
    let signers = oncl_pki::cms::verify(&cms, None).expect("the CMS verifies");
    assert_eq!(signers.len(), 1);
    // The original signs the base64 text of the data, not the data.
    let content = oncl_pki::cms::verify(&cms, None).map(|_| ()).is_ok();
    assert!(content);
    assert!(cms.windows(8).any(|w| w == b"aGVsbG8="));
    // The whole chain: the signer and its CA.
    let root = oncl_testkit::synthetic_cert("root-rsa");
    assert!(cms.windows(root.len()).any(|w| w == root.as_slice()));
}

#[test]
fn documentolog_esedo_attrs() {
    let server = doclog_server(
        vec![],
        vec![],
        vec![("https://app.documentolog.kz/data/2", "ZG9jdW1lbnQ=")],
    );
    let (path, steps) = doclog_store("user-gost2004-sign");
    let harness = Harness::new(steps, doclog_routes(&server));
    let request = doclog(
        KALKAN_SERVICE,
        "createCMSEsedoSignature",
        json!({"storage_alias": "PKCS12", "storage_path": path, "key_index": alias("user-gost2004-sign"),
            "sign_string_url": "https://app.documentolog.kz/data/2", "attached": "false",
            "ocsp_notification": b64(b"OCSP"), "signed_files": "a.pdf"}),
    );
    let cms = decode_java(&doclog_ok(harness.call("documentolog", &request, DOCLOG))).unwrap();
    assert!(oncl_pki::cms::verify(&cms, Some(b"document")).is_ok());
    let has = |bytes: &[u8]| cms.windows(bytes.len()).any(|w| w == bytes);
    // fileNames: UTF8String.
    assert!(has(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x4d
    ]));
    assert!(has(b"\x0c\x05a.pdf"));
    // The page's OCSP answer, as an OCTET STRING.
    assert!(has(b"\x04\x04OCSP"));
    // The signer's name (1.3.6.1.4.1.6801.2.8) and the description with its NUL.
    assert!(has(&[
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xb5, 0x11, 0x02, 0x08
    ]));
    assert!(has(b"\x13\x06ESEDO\x00"));
    // A GOST 2015 certificate is not one the original signs with: an empty result.
    let (path, steps) = doclog_store("user-gost2015-sign");
    let harness = Harness::new(steps, doclog_routes(&server));
    let request = doclog(
        KALKAN_SERVICE,
        "createCMSEsedoSignature",
        json!({"storage_alias": "PKCS12", "storage_path": path, "key_index": alias("user-gost2015-sign"),
            "sign_string_url": "https://app.documentolog.kz/data/2", "attached": "true",
            "ocsp_notification": "", "signed_files": ""}),
    );
    assert_eq!(
        doclog_ok(harness.call("documentolog", &request, DOCLOG)),
        ""
    );
}

fn server_fields(
    path: &str,
    alias: &str,
    et: &str,
    ss: &str,
    sss: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("p", "Qwerty12".to_owned()),
        ("et", et.to_owned()),
        ("a", alias.to_owned()),
        ("f", path.to_owned()),
        ("fs", "doc.pdf".to_owned()),
        ("ss", ss.to_owned()),
        ("sss", sss.to_owned()),
        ("t", "1".to_owned()),
    ]
}

#[test]
fn documentolog_server_flow_decrypts_and_signs() {
    let (path, _) = p12("user-rsa-sign");
    let path = path.to_string_lossy().into_owned();
    let data_url = "https://app.documentolog.kz/data/3";
    let server = doclog_server(
        server_fields(&path, &alias("user-rsa-sign"), "esedo", data_url, "8"),
        vec![("ocsp", b64(b"OCSP"))],
        vec![(data_url, "ZG9jdW1l")],
    );
    // No password dialog: the server sends it. The key store: the user's consent.
    let harness = Harness::new(vec![Step::Confirm { yes: true }], doclog_routes(&server));
    let mut session = harness.session_of(&documentolog_test_key_package());
    let request = doclog(
        SIGN_SERVICE,
        "getSSAndSign",
        json!({"ca": "НУЦ", "store_type": "PKCS12", "path": "https://app.documentolog.kz/eds/sign?id=7"}),
    );
    let cms = decode_java(&doclog_ok(session.call(&request, DOCLOG))).unwrap();
    assert!(oncl_pki::cms::verify(&cms, Some(b"docume")).is_ok());
    assert!(cms.windows(9).any(|w| w == b"\x0c\x07doc.pdf"));
    assert!(cms.windows(6).any(|w| w == b"\x04\x04OCSP"));
    let requests = server.requests();
    assert!(
        requests[0]
            .0
            .starts_with("https://app.documentolog.kz/eds/sign?id=7&code="),
        "{requests:?}"
    );
    assert_eq!(
        requests[0].1,
        [
            ("User-Agent".to_owned(), "Mozilla/5.0".to_owned()),
            ("Accept-Language".to_owned(), "en-US,en;q=0.5".to_owned())
        ]
    );
    assert_eq!(requests[1].0, data_url);
    assert!(harness.prompter().password_prompts().is_empty());

    // SP: the server sends the document's hash, signed as it is.
    let digest = oncl_pki::key::HashAlg::Sha256.digest(b"document");
    let server = doclog_server(
        server_fields(&path, &alias("user-rsa-sign"), "cms", &b64(&digest), "-1"),
        vec![("ocsp", String::new())],
        vec![],
    );
    let harness = Harness::new(vec![Step::Confirm { yes: true }], doclog_routes(&server));
    let mut session = harness.session_of(&documentolog_test_key_package());
    let request = doclog(
        SIGN_SERVICE,
        "getSPAndSign",
        json!({"ca": "НУЦ", "store_type": "PKCS12", "path": "https://app.documentolog.kz/eds/sp?id=8"}),
    );
    let cms = decode_java(&doclog_ok(session.call(&request, DOCLOG))).unwrap();
    assert!(oncl_pki::cms::verify(&cms, Some(b"document")).is_ok());
    // A broken size of the data: an empty result.
    let server = doclog_server(
        server_fields(&path, &alias("user-rsa-sign"), "esedo", data_url, "9"),
        vec![("ocsp", String::new())],
        vec![(data_url, "ZG9jdW1l")],
    );
    let harness = Harness::new(vec![Step::Confirm { yes: true }], doclog_routes(&server));
    let mut session = harness.session_of(&documentolog_test_key_package());
    let request = doclog(
        SIGN_SERVICE,
        "getSSAndSign",
        json!({"ca": "НУЦ", "store_type": "PKCS12", "path": "https://app.documentolog.kz/eds/sign?id=9"}),
    );
    assert_eq!(doclog_ok(session.call(&request, DOCLOG)), "");
}

#[test]
fn documentolog_ucgo_branch_empty_result() {
    let (path, _) = p12("user-rsa-sign");
    let server = doclog_server(
        server_fields(&path.to_string_lossy(), "a", "esedo", "x", "-1"),
        vec![],
        vec![],
    );
    let harness = Harness::new(vec![], doclog_routes(&server));
    let mut session = harness.session_of(&documentolog_test_key_package());
    let request = doclog(
        SIGN_SERVICE,
        "getSSAndSign",
        json!({"ca": "УЦГО", "store_type": "AKKaztokenStore", "path": "https://app.documentolog.kz/eds/sign?id=1"}),
    );
    // The Tumar branch is not ported: the original's answer when it fails.
    assert_eq!(doclog_ok(session.call(&request, DOCLOG)), "");
    assert_eq!(server.requests().len(), 1);
    assert!(harness.prompter().timeline().is_empty());
}

#[test]
fn documentolog_get_cert_info_always_500() {
    let (path, steps) = doclog_store("user-rsa-sign");
    let harness = Harness::new(steps, vec![]);
    let mut session = harness.session("documentolog");
    let info = |alias: &str| {
        doclog(
            KALKAN_SERVICE,
            "getCertInfo",
            json!({"storage_alias": "PKCS12", "storage_path": path, "alias": alias}),
        )
    };
    assert_eq!(
        text(session.call(&info(&alias("user-rsa-sign")), DOCLOG)),
        r#"{"code":500,"message":"getX509Certificate is null"}"#
    );
    assert_eq!(
        text(session.call(&info("nope"), DOCLOG)),
        r#"{"code":500,"message":null}"#
    );
    // getSubjectDN: the DN and the certificate.
    let dn = doclog(
        KALKAN_SERVICE,
        "getSubjectDN",
        json!({"storage_alias": "PKCS12", "storage_path": path, "alias": alias("user-rsa-sign")}),
    );
    let result = doclog_ok(session.call(&dn, DOCLOG));
    let (subject, cert) = result.split_once("||").unwrap();
    let key = entry("user-rsa-sign");
    assert_eq!(
        subject,
        oncl_pki::info::kalkan_dn(key.cert.tbs_certificate().subject())
    );
    assert_eq!(
        oncl_pki::cert::parse(&decode_java(cert).unwrap()).unwrap(),
        key.cert
    );
}

#[test]
fn documentolog_file_url_denied() {
    let (path, steps) = doclog_store("user-rsa-sign");
    let server = doclog_server(vec![], vec![], vec![]);
    let harness = Harness::new(steps, doclog_routes(&server));
    let mut session = harness.session("documentolog");
    for url in ["file:///C:/data.txt", "https://other.example/data"] {
        let request = doclog(
            KALKAN_SERVICE,
            "createCMSSimpleSignature",
            json!({"storage_alias": "PKCS12", "storage_path": path, "key_index": alias("user-rsa-sign"),
                "sign_string_url": url, "attached": "true"}),
        );
        assert_eq!(doclog_ok(session.call(&request, DOCLOG)), "", "{url}");
    }
    let request = doclog(
        SIGN_SERVICE,
        "getSSAndSign",
        json!({"ca": "НУЦ", "store_type": "PKCS12", "path": "file:///C:/answer.json?x"}),
    );
    assert_eq!(doclog_ok(session.call(&request, DOCLOG)), "");
    assert!(server.requests().is_empty());
}

#[test]
fn documentolog_vendor_key_is_2048_bit() {
    use rsa::traits::PublicKeyParts;
    let source = String::from_utf8(oncl_testkit::read(
        oncl_port_tests::port_dir("documentolog").join("src/server.rs"),
    ))
    .unwrap();
    // The string literal of the constant, wherever rustfmt puts it.
    let at = source.find("pub const VENDOR_MODULUS").unwrap();
    let hex = source[at..].split('"').nth(1).unwrap();
    assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{hex}");
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::parse_bytes(hex.as_bytes(), 16).unwrap(),
        rsa::BigUint::from(65_537_u32),
    )
    .unwrap();
    assert_eq!(key.n().bits(), 2048);
}
