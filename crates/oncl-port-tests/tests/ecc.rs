//! The ecc.kz family of ports: MarketSign, EFactoringSign, NURSign and K2Sign answer as the
//! originals did, byte for byte where the replies are fixed.

use oncl_basics::testing::Step;
use oncl_basics::{Locale, MessageKind};
use oncl_pki::http::{HttpError, HttpErrorKind, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::tsp::MockTsa;
use oncl_port_tests::{Harness, entry, p12};
use oncl_protocol::Reply;
use oncl_protocol::javab64::decode_java;
use serde_json::Value;
use std::sync::Arc;

/// The key every test signs with.
const KEY: &str = "user-gost2015-sign";

/// The DER of the TSA policy Kalkan's default profile asks for, 1.2.398.3.3.2.6.2.
const KALKAN_POLICY: &[u8] = &[0x06, 0x08, 0x2a, 0x83, 0x0e, 0x03, 0x03, 0x02, 0x06, 0x02];

/// The DER of the signingCertificateV2 attribute type, 1.2.840.113549.1.9.16.2.47.
const SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
];

/// The steps that open the synthetic key store and pick its key.
fn pick() -> Vec<Step> {
    let (path, password) = p12(KEY);
    vec![
        Step::Storage {
            path,
            password: password.to_owned(),
        },
        Step::Key(0),
    ]
}

/// Steps in order.
fn steps(parts: Vec<Vec<Step>>) -> Vec<Step> {
    parts.into_iter().flatten().collect()
}

/// A transport that never reaches its server.
struct Down(HttpErrorKind);

impl HttpTransport for Down {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::new(self.0, format!("{} is down", request.url)))
    }
}

/// Routes of the TSA `tsa` (both schemes).
fn tsa_routes(tsa: Arc<dyn HttpTransport>) -> Vec<(String, Arc<dyn HttpTransport>)> {
    ["http", "https"]
        .map(|scheme| (format!("{scheme}://tsp.pki.gov.kz"), Arc::clone(&tsa)))
        .to_vec()
}

/// A TSA of the synthetic PKI that records its requests.
fn mock_tsa() -> Arc<MockTsa> {
    Arc::new(MockTsa::new(entry("tsa-gost2015")))
}

/// The text of a reply that is not a drop.
fn text(reply: &Reply) -> &str {
    reply.text().expect("a reply, not a drop")
}

/// The `result` of a JSON reply.
fn result(reply: &Reply) -> String {
    let value: Value = serde_json::from_str(text(reply)).unwrap();
    value["result"]
        .as_str()
        .expect("a string result")
        .to_owned()
}

/// The CMS of a reply's base64 `result`.
fn result_cms(reply: &Reply) -> Vec<u8> {
    decode_java(&result(reply)).expect("base64")
}

/// The dialogs shown, without the busy indicators of opening a key store.
fn timeline(harness: &Harness) -> Vec<&'static str> {
    harness
        .prompter()
        .timeline()
        .into_iter()
        .filter(|kind| !kind.starts_with("busy"))
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

const CANCEL: &str = r#"{"errorCode":"CANCEL"}"#;
const UNKNOWN_TYPE: &str = r#"{"errorMessage":" Неизвестный тип ","errorCode":"UNKNOWN TYPE"}"#;

// MarketSign.

#[test]
fn market_version() {
    let harness = Harness::new(vec![], vec![]);
    let reply = harness.call("market", r#"{"type":"version"}"#, None);
    assert_eq!(
        text(&reply),
        r#"{"result":{"version":"1.0.0"},"errorCode":"NONE"}"#
    );
    assert!(timeline(&harness).is_empty());
}

#[test]
fn market_text_detached_with_kalkan_tsa() {
    let tsa = mock_tsa();
    let harness = Harness::new(pick(), tsa_routes(tsa.clone()));
    let reply = harness.call(
        "market",
        r#"{"module":"MarketSign","type":"text","data":"Привет"}"#,
        Some("https://omarket.kz"),
    );
    let reply_text = text(&reply);
    assert!(reply_text.starts_with(r#"{"result":"MII"#), "{reply_text}");
    assert!(
        reply_text.ends_with(r#"","errorCode":"NONE"}"#),
        "{reply_text}"
    );

    let cms = result_cms(&reply);
    let signers = oncl_pki::cms::verify(&cms, Some("Привет".as_bytes())).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].cert, entry(KEY).cert);
    assert!(signers[0].timestamp_token.is_some(), "CAdES-T");
    assert!(contains(&cms, SIGNING_CERTIFICATE_V2));
    assert!(oncl_pki::cms::verify(&cms, Some(b"other")).is_err());
    // Detached: the content is not in the CMS.
    assert!(oncl_pki::cms::verify(&cms, None).is_err());

    // Kalkan's default profile: GET to tsp.pki.gov.kz, policy 1.2.398.3.3.2.6.2.
    let requests = tsa.requests();
    assert_eq!(requests.len(), 1);
    assert!(contains(&requests[0], KALKAN_POLICY));
    assert!(tsa.calls()[0].starts_with("http://tsp.pki.gov.kz"));
    assert_eq!(timeline(&harness), ["storage", "key"]);
}

#[test]
fn market_text_attached_no_timestamp() {
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call(
        "market",
        r#"{"type":"text","data":"hello","attach":"TRUE","has_timestamp":false}"#,
        None,
    );
    let cms = result_cms(&reply);
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert!(signers[0].timestamp_token.is_none());
    assert!(contains(&cms, b"hello"));
    assert!(harness.http_log().is_empty());
}

#[test]
fn market_text_signs_a_cms_text_as_text() {
    // The page sends text, signed as its UTF-8 bytes: an attached CMS in base64 is text too,
    // so it is signed as such, not co-signed (no DER is valid UTF-8).
    let first = Harness::new(pick(), vec![]);
    let attached = result(&first.call(
        "market",
        r#"{"type":"text","data":"hello","attach":true,"has_timestamp":false}"#,
        None,
    ));
    let harness = Harness::new(pick(), vec![]);
    let request = serde_json::json!({
        "type": "text",
        "data": attached,
        "attach": true,
        "has_timestamp": false,
    });
    let cms = result_cms(&harness.call("market", &request.to_string(), None));
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert!(contains(&cms, attached.as_bytes()));
}

#[test]
fn market_text_missing_data_drops_after_key() {
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call("market", r#"{"type":"text","data":null}"#, None);
    assert!(matches!(reply, Reply::Drop), "{reply:?}");
    // The key was picked first, as the original read `data` after its dialog.
    assert_eq!(timeline(&harness), ["storage", "key"]);
}

#[test]
fn market_cancel() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let reply = harness.call("market", r#"{"type":"text","data":"x"}"#, None);
    assert_eq!(text(&reply), CANCEL);
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let reply = harness.call("market", r#"{"type":"xml","data":"<a/>"}"#, None);
    assert_eq!(text(&reply), CANCEL);
}

#[test]
fn market_error_retry_then_cancel() {
    let harness = Harness::new(
        steps(vec![
            pick(),
            vec![Step::Choice {
                button: 0,
                option: None,
            }],
            pick(),
            vec![Step::Choice {
                button: 1,
                option: None,
            }],
        ]),
        tsa_routes(Arc::new(Down(HttpErrorKind::Connect))),
    );
    let reply = harness.call("market", r#"{"type":"text","data":"x"}"#, None);
    assert_eq!(text(&reply), CANCEL);
    assert_eq!(
        timeline(&harness),
        ["storage", "key", "choice", "storage", "key", "choice"]
    );
    let choices = harness.prompter().choice_prompts();
    assert_eq!(choices.len(), 2);
    for choice in choices {
        assert_eq!(choice.kind, MessageKind::Error);
        assert_eq!(choice.title.as_deref(), Some("Ошибка"));
        assert_eq!(choice.text, "Ошибка при подписании XML");
        assert_eq!(choice.buttons, ["Закрыть", "Отменить"]);
        assert_eq!(choice.default, 0);
        assert!(choice.options.is_empty());
    }
    // The window closed is a cancel too.
    let harness = Harness::new(
        steps(vec![pick(), vec![Step::CancelChoice]]),
        tsa_routes(Arc::new(Down(HttpErrorKind::Connect))),
    );
    let reply = harness.call("market", r#"{"type":"text","data":"x"}"#, None);
    assert_eq!(text(&reply), CANCEL);
}

#[test]
fn market_xml_escapes_closing_tags() {
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call(
        "market",
        r#"{"type":"xml","data":"<doc><a>x</a></doc>"}"#,
        None,
    );
    let reply_text = text(&reply);
    assert!(
        reply_text.starts_with(r#"{"result":"<doc><a>x<\/a>"#),
        "{reply_text}"
    );
    assert!(
        reply_text.ends_with(r#"<\/doc>","errorCode":"NONE"}"#),
        "{reply_text}"
    );
    let xml = result(&reply);
    let signatures = oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap();
    assert_eq!(signatures.len(), 1);
}

#[test]
fn market_xml_missing_data_is_a_bad_request() {
    let harness = Harness::new(steps(vec![pick(), vec![Step::CancelChoice]]), vec![]);
    let reply = harness.call("market", r#"{"type":"xml"}"#, None);
    assert_eq!(text(&reply), CANCEL);
    let choices = harness.prompter().choice_prompts();
    assert_eq!(choices[0].text, "Ошибка при разборе запроса");
}

#[test]
fn market_unknown_type_bytes() {
    let harness = Harness::new(vec![], vec![]);
    for request in [
        r#"{"type":"binary"}"#,
        r#"{}"#,
        r#"{"type":null}"#,
        r#"{"type":"unknown"}"#,
        r#"{"type":1}"#,
    ] {
        assert_eq!(text(&harness.call("market", request, None)), UNKNOWN_TYPE);
    }
    assert!(timeline(&harness).is_empty());
}

#[test]
fn market_kk_locale_uses_kz_texts() {
    for (locale, title, buttons) in [
        (Locale::Kk, "Ошибка", ["Закрыть", "Отменить"]),
        (Locale::En, "Error", ["Close", "Cancel"]),
    ] {
        let harness = Harness::new(
            steps(vec![pick(), vec![Step::CancelChoice]]),
            tsa_routes(Arc::new(Down(HttpErrorKind::UnknownHost))),
        )
        .with_locale(locale);
        let reply = harness.call("market", r#"{"type":"text","data":"x"}"#, None);
        assert_eq!(text(&reply), CANCEL);
        let choice = &harness.prompter().choice_prompts()[0];
        assert_eq!(choice.title.as_deref(), Some(title));
        assert_eq!(choice.text, "Ошибка при подписании XML");
        assert_eq!(choice.buttons, buttons);
    }
}

// EFactoringSign.

#[test]
fn efactoring_version_and_unknown_type() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(&harness.call("efactoring", r#"{"type":"version"}"#, None)),
        r#"{"result":{"version":"1.0.0"},"errorCode":"NONE"}"#
    );
    assert_eq!(
        text(&harness.call("efactoring", r#"{"type":"multitext"}"#, None)),
        UNKNOWN_TYPE
    );
}

#[test]
fn efactoring_text_as_market() {
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call(
        "efactoring",
        r#"{"type":"text","data":"hello","has_timestamp":false}"#,
        None,
    );
    let cms = result_cms(&reply);
    oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    assert!(text(&reply).ends_with(r#"","errorCode":"NONE"}"#));

    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call("efactoring", r#"{"type":"text"}"#, None);
    assert!(matches!(reply, Reply::Drop));
}

#[test]
fn efactoring_xml_element_with_parent() {
    let harness = Harness::new(pick(), vec![]);
    let request = serde_json::json!({
        "type": "xml",
        "data": "<root><data Id=\"d1\">x</data><sig/></root>",
        "sign_element": "/root/data",
        "signature_parent_element": "/root/sig",
    });
    let reply = harness.call("efactoring", &request.to_string(), None);
    assert!(text(&reply).ends_with(r#"","errorCode":"NONE"}"#));
    let xml = result(&reply);
    assert!(xml.contains(r##"URI="#d1""##), "{xml}");
    assert!(
        xml.contains("<sig><ds:Signature") || xml.contains("<sig><Signature"),
        "{xml}"
    );
    assert!(
        xml.contains(
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#""#
        ) || xml.contains(
            r#"<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#""#
        ),
        "{xml}"
    );
    let signatures = oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap();
    assert_eq!(signatures.len(), 1);
}

#[test]
fn efactoring_xml_element_without_parent_is_error() {
    for parent in [None, Some("/root/data"), Some("/ROOT/DATA")] {
        let harness = Harness::new(steps(vec![pick(), vec![Step::CancelChoice]]), vec![]);
        let mut request = serde_json::json!({
            "type": "xml",
            "data": "<root><data Id=\"d1\">x</data></root>",
            "sign_element": "/root/data",
        });
        if let Some(parent) = parent {
            request["signature_parent_element"] = parent.into();
        }
        let reply = harness.call("efactoring", &request.to_string(), None);
        assert_eq!(text(&reply), CANCEL, "{parent:?}");
        let choices = harness.prompter().choice_prompts();
        assert_eq!(choices.len(), 1, "{parent:?}");
        assert_eq!(choices[0].text, "Ошибка при подписании XML");
    }
}

#[test]
fn efactoring_soap_prefix_xpath() {
    let harness = Harness::new(pick(), vec![]);
    let envelope = concat!(
        r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">"#,
        r#"<SOAP-ENV:Header/>"#,
        r#"<SOAP-ENV:Body Id="body"><order>1</order></SOAP-ENV:Body>"#,
        r#"</SOAP-ENV:Envelope>"#,
    );
    let request = serde_json::json!({
        "type": "xml",
        "data": envelope,
        "sign_element": "/SOAP-ENV:Envelope/SOAP-ENV:Body",
        "signature_parent_element": "/SOAP-ENV:Envelope/SOAP-ENV:Header",
    });
    let reply = harness.call("efactoring", &request.to_string(), None);
    let xml = result(&reply);
    assert!(xml.contains(r##"URI="#body""##), "{xml}");
    let signatures = oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap();
    assert_eq!(signatures.len(), 1);
}

#[test]
fn efactoring_remote_xml_is_dead_path_no_http() {
    for request in [
        r#"{"type":"xml","source":"remote","upload_url":"https://efactoring.kz:90/api/doc.xml"}"#,
        r#"{"type":"binary","upload_url":"https://efactoring.kz:90/api/doc.pdf"}"#,
    ] {
        let harness = Harness::new(
            steps(vec![
                pick(),
                vec![Step::Choice {
                    button: 0,
                    option: None,
                }],
                pick(),
                vec![Step::Choice {
                    button: 1,
                    option: None,
                }],
            ]),
            vec![],
        );
        let reply = harness.call("efactoring", request, None);
        assert_eq!(text(&reply), CANCEL, "{request}");
        let choices = harness.prompter().choice_prompts();
        assert_eq!(choices.len(), 2);
        assert!(
            choices
                .iter()
                .all(|c| c.text == "Ошибка при разборе запроса")
        );
        assert!(harness.http_log().is_empty(), "{request}");
    }
}

#[test]
fn efactoring_binary_empty_url_cancel() {
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call("efactoring", r#"{"type":"binary","data":"aGk="}"#, None);
    assert_eq!(text(&reply), CANCEL);
    // After the key, and without a dialog.
    assert_eq!(timeline(&harness), ["storage", "key"]);
}
