//! The ecc.kz family of ports: MarketSign, EFactoringSign, NURSign and K2Sign answer as the
//! originals did, byte for byte where the replies are fixed.

use oncl_flows::testing::Step;
use oncl_flows::{Locale, MessageKind};
use oncl_pki::cms::SignOptions;
use oncl_pki::http::{HttpError, HttpErrorKind, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::tsp::MockTsa;
use oncl_port_tests::{Harness, default_clock, entry, p12};
use oncl_protocol::Reply;
use oncl_protocol::javab64::decode_java;
use oncl_protocol::javamap::iteration_order;
use oncl_protocol::orgjson::{JObject, JValue};
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

/// The original's serializer omits the XML declaration: a page's declaration is dropped.
#[test]
fn market_xml_drops_the_declaration() {
    let harness = Harness::new(pick(), vec![]);
    let request = serde_json::json!({
        "type": "xml",
        "data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><a>x</a></doc>",
    });
    let reply = harness.call("market", &request.to_string(), None);
    let xml = result(&reply);
    assert!(xml.starts_with("<doc><a>x</a>"), "{xml}");
    assert_eq!(oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap().len(), 1);
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

/// The original's serializer omits the XML declaration, for the document and an element.
#[test]
fn efactoring_xml_drops_the_declaration() {
    for (data, element, parent) in [
        ("<doc><a>x</a></doc>", None, None),
        (
            "<root><data Id=\"d1\">x</data><sig/></root>",
            Some("/root/data"),
            Some("/root/sig"),
        ),
    ] {
        let harness = Harness::new(pick(), vec![]);
        let mut request = serde_json::json!({
            "type": "xml",
            "data": format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{data}"),
        });
        if let (Some(element), Some(parent)) = (element, parent) {
            request["sign_element"] = element.into();
            request["signature_parent_element"] = parent.into();
        }
        let reply = harness.call("efactoring", &request.to_string(), None);
        let xml = result(&reply);
        assert!(xml.starts_with(&data[..6]), "{xml}");
        assert_eq!(oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap().len(), 1);
    }
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

// The servers the NURSign and K2Sign ports talk to.

/// A request a [`Server`] got.
#[derive(Clone, Debug)]
struct Seen {
    method: HttpMethod,
    url: String,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type Answer = Box<dyn Fn(&Seen) -> HttpReply + Send + Sync>;

/// A site: answers each request with `answer`, records them.
struct Server {
    seen: Mutex<Vec<Seen>>,
    answer: Answer,
}

impl Server {
    fn new(answer: impl Fn(&Seen) -> HttpReply + Send + Sync + 'static) -> Arc<Server> {
        Arc::new(Server {
            seen: Mutex::new(Vec::new()),
            answer: Box::new(answer),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl HttpTransport for Server {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let seen = Seen {
            method: request.method,
            url: request.url.to_owned(),
            headers: request
                .headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            content_type: request.content_type.map(str::to_owned),
            body: request.body.to_vec(),
        };
        let reply = (self.answer)(&seen);
        self.seen.lock().unwrap().push(seen);
        Ok(reply)
    }
}

fn http_reply(status: u16, body: &[u8]) -> HttpReply {
    HttpReply {
        status,
        content_type: None,
        location: None,
        body: body.to_vec(),
    }
}

fn route(prefix: &str, server: &Arc<Server>) -> (String, Arc<dyn HttpTransport>) {
    (
        prefix.to_owned(),
        Arc::clone(server) as Arc<dyn HttpTransport>,
    )
}

/// A file of the test `test` under the tests' temporary directory.
fn temp_file(test: &str, name: &str, data: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ecc")
        .join(test);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    path
}

fn base64(bytes: &[u8]) -> String {
    oncl_protocol::javab64::encode_mime(bytes).replace("\r\n", "")
}

/// A detached CMS of `data` by the synthetic key `key`, signed at the harness's time.
fn detached(key: &str, data: &[u8]) -> Vec<u8> {
    let opts = SignOptions {
        encapsulate: false,
        digested: false,
        signing_time: default_clock(),
    };
    oncl_pki::cms::sign(&entry(key), data, &opts).unwrap()
}

// NURSign.

const NUR_ORIGIN: &str = "https://portal.gov.kz";

#[test]
fn nursign_missing_origin_drops() {
    let harness = Harness::new(pick(), vec![]);
    for request in [r#"{"type":"version"}"#, r#"{"type":"text","data":"x"}"#] {
        let reply = harness.call("nursign", request, None);
        assert!(matches!(reply, Reply::Drop), "{reply:?}");
    }
    assert!(timeline(&harness).is_empty());
}

#[test]
fn nursign_version() {
    let harness = Harness::new(vec![], vec![]);
    let reply = harness.call("nursign", r#"{"type":"version"}"#, Some(NUR_ORIGIN));
    assert_eq!(
        text(&reply),
        r#"{"result":{"version":"1.0.0"},"errorCode":"NONE"}"#
    );
    let reply = harness.call("nursign", r#"{"type":"login"}"#, Some(NUR_ORIGIN));
    assert_eq!(text(&reply), r#"{"errorCode":"500"}"#);
    assert!(timeline(&harness).is_empty());
}

#[test]
fn nursign_text_cades_t_kalkan() {
    let tsa = mock_tsa();
    let harness = Harness::new(pick(), tsa_routes(tsa.clone()));
    let reply = harness.call(
        "nursign",
        r#"{"type":"text","data":"Привет"}"#,
        Some(NUR_ORIGIN),
    );
    assert!(text(&reply).ends_with(r#"","errorCode":"NONE"}"#));
    let cms = result_cms(&reply);
    let signers = oncl_pki::cms::verify(&cms, Some("Привет".as_bytes())).unwrap();
    assert!(signers[0].timestamp_token.is_some());
    assert!(contains(&cms, SIGNING_CERTIFICATE_V2));
    assert_eq!(tsa.requests().len(), 1);
    assert!(contains(&tsa.requests()[0], KALKAN_POLICY));
}

#[test]
fn nursign_text_missing_data_signs_empty() {
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call("nursign", r#"{"type":"text"}"#, Some(NUR_ORIGIN));
    let cms = result_cms(&reply);
    oncl_pki::cms::verify(&cms, Some(b"")).unwrap();
    // A number is signed as its JSON text.
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"text","data":1.50}"#,
        Some(NUR_ORIGIN),
    );
    oncl_pki::cms::verify(&result_cms(&reply), Some(b"1.5")).unwrap();
}

#[test]
fn nursign_multitext_items_hashmap_order() {
    let tsa = mock_tsa();
    let harness = Harness::new(pick(), tsa_routes(tsa.clone()));
    let reply = harness.call(
        "nursign",
        r#"{"type":"multitext","data":{"b":"two","a":"one","c":3}}"#,
        Some(NUR_ORIGIN),
    );
    let reply_text = text(&reply);
    // Java's HashMap of the page's keys: "a" (bucket 1), "b" (2), "c" (3).
    assert!(
        reply_text.starts_with(r#"{"result":{"items":{"a":"MII"#),
        "{reply_text}"
    );
    let b = reply_text.find(r#""b":"#).unwrap();
    let c = reply_text.find(r#""c":"#).unwrap();
    assert!(b < c);
    assert!(reply_text.ends_with(r#""}},"errorCode":"NONE"}"#));
    let value: Value = serde_json::from_str(reply_text).unwrap();
    let items = &value["result"]["items"];
    for (key, data) in [("a", "one"), ("b", "two"), ("c", "3")] {
        let cms = decode_java(items[key].as_str().unwrap()).unwrap();
        let signers = oncl_pki::cms::verify(&cms, Some(data.as_bytes())).unwrap();
        assert!(signers[0].timestamp_token.is_some());
    }
    assert_eq!(tsa.requests().len(), 3);
    assert_eq!(timeline(&harness), ["storage", "key"]);
}

#[test]
fn nursign_multitext_first_failure_fails_all() {
    let harness = Harness::new(
        steps(vec![pick(), vec![Step::Message]]),
        tsa_routes(Arc::new(Down(HttpErrorKind::UnknownHost))),
    );
    let reply = harness.call(
        "nursign",
        r#"{"type":"multitext","data":{"a":"1","b":"2"}}"#,
        Some(NUR_ORIGIN),
    );
    let expected =
        r#"{"errorMessage":"java.net.UnknownHostException: tsp.pki.gov.kz","errorCode":"500"}"#;
    assert_eq!(text(&reply), expected);
    let messages = harness.prompter().message_prompts();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].kind, MessageKind::Error);
    assert_eq!(
        messages[0].text,
        "java.net.UnknownHostException: tsp.pki.gov.kz"
    );

    // `data` that is not an object: before the key dialog.
    let harness = Harness::new(vec![Step::Message], vec![]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"multitext","data":"x"}"#,
        Some(NUR_ORIGIN),
    );
    assert_eq!(
        text(&reply),
        r#"{"errorMessage":"Ошибка при формировании ЭЦП","errorCode":"500"}"#
    );
    assert_eq!(timeline(&harness), ["message"]);
}

#[test]
fn nursign_binary_local_hash_over_base64_text() {
    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"binary","data":"aGVsbG8=","need_hash":false}"#,
        Some(NUR_ORIGIN),
    );
    let reply_text = text(&reply);
    assert!(reply_text.starts_with(r#"{"result":"MII"#), "{reply_text}");
    assert!(
        reply_text.ends_with(concat!(
            r#"","errorCode":"NONE","hash":{"SHA256":"#,
            r#""333d6b3a3c1f5db6c9bdda5939b136986d170f4649172a68368d54ecb44c2ff2","#,
            r#""MD5":"0733351879b2fa9bd05c7ca3061529c0"}}"#
        )),
        "{reply_text}"
    );
    let cms = result_cms(&reply);
    let signers = oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    // No time-stamp for binary.
    assert!(signers[0].timestamp_token.is_none());
    assert!(harness.http_log().is_empty());

    // Without need_hash: no hash; invalid base64 fails after the key.
    let harness = Harness::new(steps(vec![pick(), pick(), vec![Step::Message]]), vec![]);
    let mut session = harness.session("nursign");
    let reply = session.call(r#"{"type":"binary","data":"aGVsbG8="}"#, Some(NUR_ORIGIN));
    assert!(text(&reply).ends_with(r#"","errorCode":"NONE"}"#));
    let reply = session.call(r#"{"type":"binary","data":"%%%"}"#, Some(NUR_ORIGIN));
    assert_eq!(
        text(&reply),
        r#"{"errorMessage":"Ошибка при формировании ЭЦП","errorCode":"500"}"#
    );
    assert_eq!(
        timeline(&harness),
        ["storage", "key", "storage", "key", "message"]
    );
}

#[test]
fn nursign_binary_cosigns_attached_cms() {
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time: default_clock(),
    };
    let attached = oncl_pki::cms::sign(&entry("user-rsa-sign"), b"contract", &opts).unwrap();
    let harness = Harness::new(pick(), vec![]);
    let request = serde_json::json!({"type": "binary", "data": base64(&attached)});
    let reply = harness.call("nursign", &request.to_string(), Some(NUR_ORIGIN));
    let cms = result_cms(&reply);
    // Detached, as asked: the co-signed content is not kept in the CMS.
    assert!(!contains(&cms, b"contract"));
    let signers = oncl_pki::cms::verify(&cms, Some(b"contract")).unwrap();
    assert_eq!(signers.len(), 2);
    assert_eq!(signers[1].cert, entry(KEY).cert);
}

#[test]
fn nursign_binary_remote_under_wildcard() {
    let server = Server::new(|_| http_reply(200, b"hello"));
    let harness = Harness::new(pick(), vec![route("https://files.portal.gov.kz/", &server)]);
    let request =
        r#"{"type":"binary","source":"remote","upload_url":"https://files.portal.gov.kz/doc/1"}"#;
    let reply = harness.call("nursign", request, Some("https://other.site.kz"));
    let cms = result_cms(&reply);
    oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, HttpMethod::Get);
    assert_eq!(seen[0].url, "https://files.portal.gov.kz/doc/1");
    // Downloaded before the key dialog.
    assert_eq!(timeline(&harness), ["storage", "key"]);
}

#[test]
fn nursign_binary_remote_outside_allowlist_denied() {
    for url in [
        "https://evil.example.com/a",
        "https://evilgov.kz/a",
        "https://gov.kz.evil.com/a",
    ] {
        let harness = Harness::new(vec![Step::Message], vec![]);
        let request = serde_json::json!({"type": "binary", "source": "remote", "upload_url": url});
        let reply = harness.call("nursign", &request.to_string(), Some(NUR_ORIGIN));
        assert_eq!(
            text(&reply),
            r#"{"errorMessage":"Недопустимый адрес URL","errorCode":"500"}"#,
            "{url}"
        );
        assert!(harness.http_log().is_empty(), "{url}");
        assert_eq!(timeline(&harness), ["message"]);
    }
    // No URL at all.
    let harness = Harness::new(vec![Step::Message], vec![]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"binary","source":"remote"}"#,
        Some(NUR_ORIGIN),
    );
    assert_eq!(
        text(&reply),
        r#"{"errorMessage":"Недопустимый адрес URL","errorCode":"500"}"#
    );
}

#[test]
fn nursign_xml_remote_error_is_download_exception() {
    let server = Server::new(|_| http_reply(404, b"no"));
    for url in [
        "https://files.portal.gov.kz/doc.xml",
        "https://evil.example.com/doc.xml",
        "",
    ] {
        let harness = Harness::new(
            vec![Step::Message],
            vec![route("https://files.portal.gov.kz/", &server)],
        );
        let request = serde_json::json!({"type": "xml", "source": "remote", "upload_url": url});
        let reply = harness.call("nursign", &request.to_string(), Some(NUR_ORIGIN));
        let expected = if url.is_empty() {
            r#"{"errorMessage":"Недопустимый адрес URL","errorCode":"500"}"#
        } else {
            r#"{"errorMessage":"Ошибка при скачивании файла","errorCode":"500"}"#
        };
        assert_eq!(text(&reply), expected, "{url}");
    }
    assert_eq!(server.seen().len(), 1);
}

#[test]
fn nursign_xml_local_without_declaration() {
    let harness = Harness::new(pick(), vec![]);
    let request = serde_json::json!({
        "type": "xml",
        "data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><a>x</a></doc>",
    });
    let reply = harness.call("nursign", &request.to_string(), Some(NUR_ORIGIN));
    assert!(
        text(&reply).starts_with(r#"{"result":"<doc><a>x<\/a>"#),
        "{reply:?}"
    );
    let xml = result(&reply);
    assert_eq!(oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap().len(), 1);

    // No `data`: before the key dialog.
    let harness = Harness::new(vec![Step::Message], vec![]);
    let reply = harness.call("nursign", r#"{"type":"xml"}"#, Some(NUR_ORIGIN));
    assert_eq!(
        text(&reply),
        r#"{"errorMessage":"Ошибка при формировании ЭЦП","errorCode":"500"}"#
    );
    assert_eq!(timeline(&harness), ["message"]);
}

#[test]
fn nursign_multixml_not_array_drops() {
    let harness = Harness::new(vec![], vec![]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"multixml","data":"<a/>"}"#,
        Some(NUR_ORIGIN),
    );
    assert!(matches!(reply, Reply::Drop));
    // A cancelled key dialog drops too.
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"multixml","data":["<a/>"]}"#,
        Some(NUR_ORIGIN),
    );
    assert!(matches!(reply, Reply::Drop));

    let harness = Harness::new(pick(), vec![]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"multixml","data":["<a>1</a>","<b>2</b>"]}"#,
        Some(NUR_ORIGIN),
    );
    let value: Value = serde_json::from_str(text(&reply)).unwrap();
    assert_eq!(value["errorCode"], "NONE");
    let docs = value["result"].as_array().unwrap();
    assert_eq!(docs.len(), 2);
    assert!(docs[0].as_str().unwrap().starts_with("<a>1"));
    for doc in docs {
        assert_eq!(
            oncl_pki::xmldsig::verify(doc.as_str().unwrap().as_bytes())
                .unwrap()
                .len(),
            1
        );
    }
    assert!(text(&reply).starts_with(r#"{"result":["<a>1<"#));
    assert!(text(&reply).contains(r#"<\/a>","<b>2<"#));
}

/// The NURSign upload's multipart body: the fields in Java's `HashMap` order of `keys`
/// (put in this order), then the file part.
fn nursign_upload_body(
    boundary: &str,
    fields: &[(&str, &str)],
    file_name: &str,
    file: &[u8],
) -> Vec<u8> {
    let keys: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
    let mut body = Vec::new();
    for i in iteration_order(&keys, 16) {
        let (k, v) = fields[i];
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"userfile\"; \
             fileName=\"{file_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

const PDF: &[u8] = b"%PDF-1.4 test";
const PDF_MD5: &str = "83155f67b8df59857745bc0b4ca0ba19";
const PDF_SHA256: &str = "b49bd63eccc7b715bc4cc0959b54662c758263f1903d28fe7f4573594e583b47";

fn nursign_file_harness(
    test: &str,
    have_file: bool,
    upload_reply: &'static [u8],
    more: Vec<Step>,
) -> (Harness, Arc<Server>, PathBuf) {
    let path = temp_file(test, "doc.pdf", PDF);
    let server = Server::new(move |seen| {
        if seen.url.ends_with("/ru/files/check_by_hash/") {
            http_reply(200, if have_file { b"true" } else { b"false" })
        } else {
            http_reply(200, upload_reply)
        }
    });
    let harness = Harness::new(
        steps(vec![vec![Step::Path(path.clone())], pick(), more]),
        vec![route("https://portal.gov.kz/", &server)],
    );
    (harness, server, path)
}

const NUR_FILE_REQUEST: &str = r#"{"module":"NURSign","type":"file","token":"abc","url_upload":"https://portal.gov.kz/ru/files/upload/"}"#;

#[test]
fn nursign_file_flow_check_then_upload() {
    let (harness, server, _) = nursign_file_harness(
        "check_then_upload",
        false,
        br#"{"id":1.0,"ok":true}"#,
        vec![],
    );
    let reply = harness.call("nursign", NUR_FILE_REQUEST, Some(NUR_ORIGIN));
    let value: Value = serde_json::from_str(text(&reply)).unwrap();
    let signature = value["result"]["signature"].as_str().unwrap().to_owned();
    let file_path = value["result"]["filePath"].as_str().unwrap().to_owned();
    assert!(file_path.ends_with("doc.pdf"), "{file_path}");
    oncl_pki::cms::verify(&decode_java(&signature).unwrap(), Some(PDF)).unwrap();

    // The server's object, normalized by org.json, with filePath and signature, in Java's
    // HashMap order.
    let mut result = JObject::hash_map();
    result.put("id", JValue::Int(1));
    result.put("ok", true);
    result.put("filePath", file_path.as_str());
    result.put("signature", signature.as_str());
    let mut expected = JObject::hash_map();
    expected.put("result", JValue::Obj(result));
    expected.put("errorCode", "NONE");
    assert_eq!(text(&reply), expected.to_json());
    assert!(text(&reply).contains(r#""id":1"#));

    let seen = server.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, HttpMethod::Post);
    assert_eq!(seen[0].url, "https://portal.gov.kz/ru/files/check_by_hash/");
    assert_eq!(
        seen[0].content_type.as_deref(),
        Some("application/x-www-form-urlencoded; charset=UTF-8")
    );
    assert_eq!(
        String::from_utf8(seen[0].body.clone()).unwrap(),
        format!("md5={PDF_MD5}&sha256={PDF_SHA256}")
    );
    let boundary = format!("{:x}", default_clock().unix_timestamp() * 1000);
    assert_eq!(seen[1].url, "https://portal.gov.kz/ru/files/upload/");
    assert_eq!(
        seen[1].content_type.as_deref(),
        Some(format!("multipart/form-data; boundary={boundary}").as_str())
    );
    assert_eq!(
        seen[1].body,
        nursign_upload_body(
            &boundary,
            &[("signature", &signature), ("token", "abc")],
            "doc.pdf",
            PDF
        )
    );
    // The file first, then the key.
    assert_eq!(timeline(&harness), ["path", "storage", "key"]);
    assert_eq!(
        harness.prompter().path_prompts()[0].title.as_deref(),
        Some("Открыть файл")
    );
}

#[test]
fn nursign_file_already_on_server() {
    let (harness, server, _) =
        nursign_file_harness("already_on_server", true, br#"{"status":"ok"}"#, vec![]);
    let reply = harness.call("nursign", NUR_FILE_REQUEST, Some(NUR_ORIGIN));
    let value: Value = serde_json::from_str(text(&reply)).unwrap();
    assert_eq!(value["result"]["status"], "ok");
    let signature = value["result"]["signature"].as_str().unwrap().to_owned();
    let seen = server.seen();
    let boundary = format!("{:x}", default_clock().unix_timestamp() * 1000);
    assert_eq!(
        seen[1].body,
        nursign_upload_body(
            &boundary,
            &[
                ("SHA256", PDF_SHA256),
                ("signature", &signature),
                ("file_name", "doc.pdf"),
                ("token", "abc"),
                ("MD5", PDF_MD5),
            ],
            "doc.pdf",
            b""
        )
    );

    // No token: after the check, before the upload.
    let (harness, server, _) = nursign_file_harness("no_token", true, b"{}", vec![Step::Message]);
    let reply = harness.call(
        "nursign",
        r#"{"type":"file","url_upload":"https://portal.gov.kz/up"}"#,
        Some(NUR_ORIGIN),
    );
    assert_eq!(
        text(&reply),
        r#"{"errorMessage":"Ошибка при формировании ЭЦП","errorCode":"500"}"#
    );
    assert_eq!(server.seen().len(), 1, "the check only");
}

#[test]
fn nursign_file_too_large() {
    let path = temp_file("too_large", "big.bin", &vec![0u8; 20 * 1024 * 1024 + 1]);
    let harness = Harness::new(vec![Step::Path(path), Step::Message], vec![]);
    let reply = harness.call("nursign", NUR_FILE_REQUEST, Some(NUR_ORIGIN));
    assert_eq!(
        text(&reply),
        r#"{"errorMessage":"Превышен максимальный размер файла","errorCode":"500"}"#
    );
    assert_eq!(timeline(&harness), ["path", "message"]);
    assert!(harness.http_log().is_empty());
}

#[test]
fn nursign_tsa_unknown_host_message() {
    for (kind, message) in [
        (
            HttpErrorKind::UnknownHost,
            "java.net.UnknownHostException: tsp.pki.gov.kz",
        ),
        (
            HttpErrorKind::Connect,
            "java.net.ConnectException: Connection refused: connect",
        ),
    ] {
        let harness = Harness::new(
            steps(vec![pick(), vec![Step::Message]]),
            tsa_routes(Arc::new(Down(kind))),
        );
        let reply = harness.call("nursign", r#"{"type":"text","data":"x"}"#, Some(NUR_ORIGIN));
        let mut expected = JObject::hash_map();
        expected.put("errorCode", "500");
        expected.put("errorMessage", message);
        assert_eq!(text(&reply), expected.to_json());
        assert_eq!(harness.prompter().message_prompts()[0].text, message);
    }
}

#[test]
fn nursign_cancel_is_empty_object() {
    for request in [
        r#"{"type":"text","data":"x"}"#,
        r#"{"type":"multitext","data":{"a":"x"}}"#,
        r#"{"type":"binary","data":"aGk="}"#,
        r#"{"type":"xml","data":"<a/>"}"#,
    ] {
        let harness = Harness::new(vec![Step::CancelStorage], vec![]);
        assert_eq!(
            text(&harness.call("nursign", request, Some(NUR_ORIGIN))),
            "{}"
        );
        assert!(harness.prompter().message_prompts().is_empty());
    }
}

#[test]
fn nursign_en_locale_texts() {
    for (locale, cancel) in [
        (Locale::Ru, "Отменено"),
        (Locale::Kk, "Отменено"),
        (Locale::En, "Canceled"),
    ] {
        let harness =
            Harness::new(vec![Step::CancelPath, Step::Message], vec![]).with_locale(locale);
        let reply = harness.call("nursign", NUR_FILE_REQUEST, Some(NUR_ORIGIN));
        let mut expected = JObject::hash_map();
        expected.put("errorCode", "500");
        expected.put("errorMessage", cancel);
        assert_eq!(text(&reply), expected.to_json());
    }
    // An unreadable file; the typo is the original's, in both languages.
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ecc/no/such/file.pdf");
    let harness =
        Harness::new(vec![Step::Path(missing), Step::Message], vec![]).with_locale(Locale::En);
    let reply = harness.call("nursign", NUR_FILE_REQUEST, Some(NUR_ORIGIN));
    assert_eq!(
        text(&reply),
        r#"{"errorMessage":"Файл не нейден","errorCode":"500"}"#
    );
}

// K2Sign.

const K2_ORIGIN: &str = "https://k2.kazynashylyk.kz";
const K2_BOUNDARY: &str = "---------------------------24464570528145";

/// The fields and the zip of a K2 upload: `(name, value)` in order, the zip's file name and
/// bytes.
fn k2_upload(seen: &Seen) -> (Vec<(String, String)>, String, Vec<u8>) {
    assert_eq!(
        seen.content_type.as_deref(),
        Some(format!("multipart/form-data; boundary={K2_BOUNDARY}").as_str())
    );
    let body = &seen.body;
    let marker = b"Content-Type: application/zip\r\n\r\n";
    let at = body
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("a zip part");
    let tail = format!("\r\n--{K2_BOUNDARY}--\r\n");
    assert!(body.ends_with(tail.as_bytes()));
    let zip = body[at + marker.len()..body.len() - tail.len()].to_vec();
    let head = String::from_utf8(body[..at].to_vec()).unwrap();
    let mut fields = Vec::new();
    let mut file_name = String::new();
    for part in head.split(&format!("--{K2_BOUNDARY}\r\n")).skip(1) {
        if let Some(rest) = part.strip_prefix("Content-Disposition: form-data; name=\"") {
            let (name, value) = rest.split_once("\"\r\n\r\n").unwrap();
            fields.push((
                name.to_owned(),
                value.strip_suffix("\r\n").unwrap().to_owned(),
            ));
        } else {
            let rest = part
                .strip_prefix("Content-Disposition: form-data;name=\"file\"; filename=\"")
                .unwrap_or_else(|| panic!("{part}"));
            file_name = rest.split_once("\"\r\n").unwrap().0.to_owned();
        }
    }
    (fields, file_name, zip)
}

/// The entries of a zip: names and contents, in order.
fn unzip(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
    (0..archive.len())
        .map(|i| {
            let mut file = archive.by_index(i).unwrap();
            let mut data = Vec::new();
            file.read_to_end(&mut data).unwrap();
            (file.name().unwrap().into_owned(), data)
        })
        .collect()
}

fn k2_server(body: &'static [u8]) -> Arc<Server> {
    Server::new(move |_| http_reply(200, body))
}

#[test]
fn k2_missing_origin_drops() {
    let harness = Harness::new(pick(), vec![]);
    for request in [r#"{"type":"version"}"#, r#"{"type":"x"}"#] {
        let reply = harness.call("k2sign", request, None);
        assert!(matches!(reply, Reply::Drop));
    }
    assert!(timeline(&harness).is_empty());
    let reply = harness.call("k2sign", r#"{"type":"version"}"#, Some(K2_ORIGIN));
    assert_eq!(
        text(&reply),
        r#"{"result":{"version":"1.0.0"},"errorCode":"NONE"}"#
    );
}

#[test]
fn k2_login_zip_layout() {
    let server = k2_server(b" accepted\n");
    let harness = Harness::new(pick(), vec![route(K2_ORIGIN, &server)]);
    let request = r#"{"type":"login","sessionId":"S-123","uploadURL":"k2/upload","coockie":"JSESSIONID=abc","fileAttributes":"attrs"}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    // The body as it came, untrimmed.
    assert_eq!(
        text(&reply),
        r#"{"result":" accepted\n","errorCode":"NONE"}"#
    );
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, HttpMethod::Post);
    assert_eq!(seen[0].url, "https://k2.kazynashylyk.kz/k2/upload");
    let (fields, file_name, zip) = k2_upload(&seen[0]);
    assert_eq!(fields, [("fileAttributes".to_owned(), "attrs".to_owned())]);
    let number = file_name
        .strip_prefix("userdata")
        .and_then(|rest| rest.strip_suffix("_Signed.zip"))
        .unwrap();
    assert!(number.parse::<u64>().is_ok(), "{file_name}");
    let entries = unzip(&zip);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["file_1", "file_2", "file_3", "file_name_mappings.xml"]
    );
    assert_eq!(entries[0].1, b"S-123");
    let signers = oncl_pki::cms::verify(&entries[1].1, Some(b"S-123")).unwrap();
    assert!(signers[0].timestamp_token.is_none());
    assert_eq!(
        oncl_pki::cert::parse(&entries[2].1).unwrap(),
        entry(KEY).cert
    );
    let mapping = String::from_utf8(entries[3].1.clone()).unwrap();
    for line in [
        "<comment>file name mapping</comment>",
        r#"<entry key="file_1">userdata</entry>"#,
        r#"<entry key="file_2">userdata.p7s</entry>"#,
        r#"<entry key="file_3">public_key.cer</entry>"#,
    ] {
        assert!(mapping.contains(line), "{mapping}");
    }
    assert!(mapping.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"));
}

#[test]
fn k2_login_cookie_header() {
    let server = k2_server(b"ok");
    let tsa = mock_tsa();
    let mut routes = tsa_routes(tsa.clone());
    routes.push(route(K2_ORIGIN, &server));
    let harness = Harness::new(pick(), routes);
    let request = r#"{"type":"login","sessionId":"S","uploadURL":"/up","coockie":"JSESSIONID=abc","tsaURL":"http://any.example/tsa"}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"result":"ok","errorCode":"NONE"}"#);
    let seen = server.seen();
    assert_eq!(seen[0].header("Cookie"), Some("JSESSIONID=abc"));
    // `tsaURL` is a flag: Kalkan's default TSA stamps.
    assert_eq!(tsa.requests().len(), 1);
    assert!(contains(&tsa.requests()[0], KALKAN_POLICY));
    let (_, _, zip) = k2_upload(&seen[0]);
    let signers = oncl_pki::cms::verify(&unzip(&zip)[1].1, Some(b"S")).unwrap();
    assert!(signers[0].timestamp_token.is_some());

    // No `coockie`: an error after signing, no upload.
    let server = k2_server(b"ok");
    let harness = Harness::new(
        steps(vec![pick(), vec![Step::Message]]),
        vec![route(K2_ORIGIN, &server)],
    );
    let reply = harness.call(
        "k2sign",
        r#"{"type":"login","sessionId":"S","uploadURL":"/up"}"#,
        Some(K2_ORIGIN),
    );
    assert_eq!(text(&reply), r#"{"errorCode":"CREATE_REQUEST_ERROR"}"#);
    assert_eq!(
        harness.prompter().message_prompts()[0].text,
        "Ошибка при формировании запроса"
    );
    assert!(server.seen().is_empty());
    assert_eq!(timeline(&harness), ["storage", "key", "message"]);

    // No `sessionId` or `uploadURL`: no reply, no dialog.
    let harness = Harness::new(vec![], vec![]);
    for request in [
        r#"{"type":"login","uploadURL":"/up"}"#,
        r#"{"type":"login","sessionId":"S"}"#,
    ] {
        assert!(matches!(
            harness.call("k2sign", request, Some(K2_ORIGIN)),
            Reply::Drop
        ));
    }
}

#[test]
fn k2_file_signature_only() {
    let server = Server::new(|seen| {
        if seen.method == HttpMethod::Get {
            http_reply(200, b"server document")
        } else {
            http_reply(200, b"saved")
        }
    });
    let harness = Harness::new(pick(), vec![route(K2_ORIGIN, &server)]);
    let request = r#"{"type":"file","userName":"user","uploadURL":"/up","downloadURL":"/doc?id=1","coockie":"c=1","fileAttributes":"fa"}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"result":"saved","errorCode":"NONE"}"#);
    let seen = server.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].url, "https://k2.kazynashylyk.kz/doc?id=1");
    assert_eq!(seen[0].header("Cookie"), Some("c=1"));
    let (fields, file_name, zip) = k2_upload(&seen[1]);
    assert_eq!(
        fields,
        [
            (
                "SignatureOnly".to_owned(),
                "signedFileFromServer".to_owned()
            ),
            ("fileAttributes".to_owned(), "fa".to_owned()),
            ("userName".to_owned(), "user".to_owned()),
        ]
    );
    assert!(file_name.starts_with("eccserver"), "{file_name}");
    let entries = unzip(&zip);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["file_1", "file_2", "file_name_mappings.xml"]);
    oncl_pki::cms::verify(&entries[0].1, Some(b"server document")).unwrap();
    assert_eq!(
        oncl_pki::cert::parse(&entries[1].1).unwrap(),
        entry(KEY).cert
    );
    let mapping = String::from_utf8(entries[2].1.clone()).unwrap();
    assert!(mapping.contains(r#"<entry key="file_1">eccserver.p7s</entry>"#));
    // Downloaded before the key dialog.
    assert_eq!(timeline(&harness), ["storage", "key"]);
}

#[test]
fn k2_file_upload_only() {
    let path = temp_file("k2_upload_only", "Договор.pdf", PDF);
    let server = k2_server(b"stored");
    let harness = Harness::new(vec![Step::Path(path)], vec![route(K2_ORIGIN, &server)]);
    let request = r#"{"type":"file","userName":"user","uploadURL":"/up","uploadOnly":"y","fileAttributes":"fa"}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"result":"stored","errorCode":"NONE"}"#);
    // No key dialog.
    assert_eq!(timeline(&harness), ["path"]);
    let prompt = &harness.prompter().path_prompts()[0];
    assert_eq!(prompt.title.as_deref(), Some("Открыть файл"));
    assert_eq!(prompt.filters.len(), 1);
    assert_eq!(prompt.filters[0].name, "Файл");
    assert_eq!(prompt.filters[0].extensions, ["pdf"]);
    let (fields, _, zip) = k2_upload(&server.seen()[0]);
    assert_eq!(
        fields,
        [
            ("fileAttributes".to_owned(), "fa".to_owned()),
            ("userName".to_owned(), "user".to_owned()),
            ("NotSignedFile".to_owned(), "notSignedFile".to_owned()),
        ]
    );
    let entries = unzip(&zip);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["file_1", "file_name_mappings.xml"]);
    assert_eq!(entries[0].1, PDF);
    let mapping = String::from_utf8(entries[1].1.clone()).unwrap();
    assert!(mapping.contains(r#"<entry key="file_1">Договор.pdf</entry>"#));

    // Signed: the file, its signature and the certificate.
    let path = temp_file("k2_signed_file", "act.pdf", PDF);
    let server = k2_server(b"stored");
    let harness = Harness::new(
        steps(vec![vec![Step::Path(path)], pick()]),
        vec![route(K2_ORIGIN, &server)],
    );
    let request = r#"{"type":"file","userName":"user","uploadURL":"/up"}"#;
    assert_eq!(
        text(&harness.call("k2sign", request, Some(K2_ORIGIN))),
        r#"{"result":"stored","errorCode":"NONE"}"#
    );
    let (fields, _, zip) = k2_upload(&server.seen()[0]);
    assert_eq!(
        fields,
        [
            ("fileAttributes".to_owned(), String::new()),
            ("userName".to_owned(), "user".to_owned()),
        ]
    );
    let entries = unzip(&zip);
    assert_eq!(entries[0].1, PDF);
    oncl_pki::cms::verify(&entries[1].1, Some(PDF)).unwrap();
    let mapping = String::from_utf8(entries[3].1.clone()).unwrap();
    assert!(mapping.contains(r#"<entry key="file_2">act.pdf.p7s</entry>"#));
}

#[test]
fn k2_server_error_mapping() {
    for (status, body, code, dialog) in [
        (
            200,
            "error: WRONG_PASSWORD,x",
            "WRONG_PASSWORD",
            "Неверный пароль",
        ),
        (
            200,
            " Error:  not_yet_valid ",
            "NOT_YET_VALID",
            "Период действия сертификата еще не наступил.",
        ),
        (200, "error: NO_SUCH_TYPE", "OTHER", " "),
        // A text of the resources that is not a name of the original's error enum.
        (
            200,
            "error: ALL_SIGN_ARE_VALID",
            "OTHER",
            "Все ЭЦП подлинны.",
        ),
        (
            200,
            "error:",
            "CREATE_REQUEST_ERROR",
            "Ошибка при формировании запроса",
        ),
        (
            200,
            "Произошла ошибка сервера",
            "OTHER",
            "Неизвестная ошибка",
        ),
        (
            500,
            "fine",
            "UPLOAD_FILE_EXCEPTION",
            "Ошибка сохранения файла",
        ),
    ] {
        let path = temp_file("k2_errors", "a.pdf", PDF);
        let server = Server::new(move |_| http_reply(status, body.as_bytes()));
        let harness = Harness::new(
            vec![Step::Path(path), Step::Message],
            vec![route(K2_ORIGIN, &server)],
        );
        let request = r#"{"type":"file","userName":"u","uploadURL":"/up","uploadOnly":"Y"}"#;
        let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
        assert_eq!(
            text(&reply),
            format!(r#"{{"errorCode":"{code}"}}"#),
            "{body}"
        );
        let message = &harness.prompter().message_prompts()[0];
        assert_eq!(message.text, dialog, "{body}");
        assert_eq!(message.kind, MessageKind::Error);
    }
}

/// The upload never reaching the site is the original's request error; only a refused URL
/// and an HTTP status other than 200 are `UPLOAD_FILE_EXCEPTION`.
#[test]
fn k2_upload_network_failure_is_create_request_error() {
    for kind in [
        HttpErrorKind::Connect,
        HttpErrorKind::Timeout,
        HttpErrorKind::UnknownHost,
    ] {
        let path = temp_file("k2_down", "a.pdf", PDF);
        let down: Arc<dyn HttpTransport> = Arc::new(Down(kind));
        let harness = Harness::new(
            vec![Step::Path(path), Step::Message],
            vec![(K2_ORIGIN.to_owned(), down)],
        );
        let request = r#"{"type":"file","userName":"u","uploadURL":"/up","uploadOnly":"Y"}"#;
        let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
        assert_eq!(
            text(&reply),
            r#"{"errorCode":"CREATE_REQUEST_ERROR"}"#,
            "{kind:?}"
        );
        let message = &harness.prompter().message_prompts()[0];
        assert_eq!(message.text, "Ошибка при формировании запроса");
    }
}

#[test]
fn k2_absolute_foreign_url_denied() {
    let path = temp_file("k2_foreign", "a.pdf", PDF);
    let harness = Harness::new(vec![Step::Path(path), Step::Message], vec![]);
    let request = r#"{"type":"file","userName":"u","uploadURL":"https://evil.example.com/up","uploadOnly":"Y"}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"errorCode":"UPLOAD_FILE_EXCEPTION"}"#);

    let harness = Harness::new(vec![Step::Message], vec![]);
    let request = r#"{"type":"file","userName":"u","uploadURL":"/up","downloadURL":"https://evil.example.com/doc"}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"errorCode":"DOWNLOAD_FILE_EXCEPTION"}"#);
    assert!(harness.http_log().is_empty());

    // A page of a site the manifest does not name.
    let harness = Harness::new(vec![Step::Message], vec![]);
    let request = r#"{"type":"verify"}"#;
    let reply = harness.call("k2sign", request, Some("https://evil.example.com"));
    assert_eq!(text(&reply), r#"{"errorCode":"DOWNLOAD_FILE_EXCEPTION"}"#);
    assert!(harness.http_log().is_empty());
}

#[test]
fn k2_http_origin_same_origin_allowed() {
    let origin = "http://client2.kazynashylyk.kz";
    let server = k2_server(b"ok");
    let harness = Harness::new(pick(), vec![route(origin, &server)]);
    let request = r#"{"type":"login","sessionId":"S","uploadURL":"/up","coockie":""}"#;
    let reply = harness.call("k2sign", request, Some(origin));
    assert_eq!(text(&reply), r#"{"result":"ok","errorCode":"NONE"}"#);
    let seen = server.seen();
    assert_eq!(seen[0].url, "http://client2.kazynashylyk.kz/up");
    assert_eq!(seen[0].header("Cookie"), None);
}

/// A K2 site serving `data` and `signature` at the verify defaults.
fn k2_verify_server(data: &'static [u8], signature: Vec<u8>) -> Arc<Server> {
    Server::new(move |seen| {
        if seen.url.ends_with("fileDownloadServlet?signId=4357") {
            http_reply(200, &signature)
        } else if seen.url.ends_with("fileDownloadServlet?fileId=4368") {
            http_reply(200, data)
        } else {
            http_reply(404, b"")
        }
    })
}

#[test]
fn k2_verify_ok_and_expired() {
    let server = k2_verify_server(b"doc", detached(KEY, b"doc"));
    let harness = Harness::new(vec![Step::Message], vec![route(K2_ORIGIN, &server)]);
    let reply = harness.call("k2sign", r#"{"type":"verify"}"#, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"result":"OK","errorCode":"NONE"}"#);
    let message = &harness.prompter().message_prompts()[0];
    assert_eq!(message.kind, MessageKind::Info);
    assert_eq!(message.text, "ЭЦП подлинна.");
    let urls: Vec<String> = server.seen().into_iter().map(|s| s.url).collect();
    assert_eq!(
        urls,
        [
            "https://k2.kazynashylyk.kz/fileDownloadServlet?signId=4357",
            "https://k2.kazynashylyk.kz/fileDownloadServlet?fileId=4368",
        ]
    );

    for (signature, code, dialog) in [
        (
            detached("expired-gost2015-sign", b"doc"),
            "VALIDITY_EXPIRED",
            "Период действия сертификата истек.",
        ),
        (
            detached(KEY, b"other"),
            "SIGN_VERIFICATION_FAILED",
            "ЭЦП не подлинна!",
        ),
        (
            b"not a cms".to_vec(),
            "SIGN_VERIFICATION_FAILED",
            "ЭЦП не подлинна!",
        ),
    ] {
        let server = k2_verify_server(b"doc", signature);
        let harness = Harness::new(vec![Step::Message], vec![route(K2_ORIGIN, &server)])
            .with_locale(Locale::Ru);
        let reply = harness.call("k2sign", r#"{"type":"verify"}"#, Some(K2_ORIGIN));
        assert_eq!(text(&reply), format!(r#"{{"errorCode":"{code}"}}"#));
        assert_eq!(harness.prompter().message_prompts()[0].text, dialog);
    }
}

/// A K2 site serving the document `doc` at `files?id=1` and `signatures` at `signs?id=<id>`,
/// and taking the results.
fn k2_verify_all_server(signatures: Vec<(i32, Vec<u8>)>) -> Arc<Server> {
    Server::new(move |seen| {
        if seen.method == HttpMethod::Post {
            return http_reply(200, b"");
        }
        if seen.url.ends_with("/files?id=1") {
            return http_reply(200, b"doc");
        }
        for (id, signature) in &signatures {
            if seen.url.ends_with(&format!("/signs?id={id}")) {
                return http_reply(200, signature);
            }
        }
        http_reply(404, b"")
    })
}

const K2_VERIFY_ALL: &str = r#"{"type":"verifyAll","fileDataURL":"files?id=","fileSignURL":"signs?id=","userName":"Иван Иванов","signVerifyResURL":"k2/verifyResult","items":[{"fileId":"1","signaturesIds":[17,2,33]}]}"#;

#[test]
fn k2_verify_all_posts_results_in_hashmap_order() {
    let server = k2_verify_all_server(vec![
        (17, detached(KEY, b"doc")),
        (2, detached(KEY, b"doc")),
        (33, detached("user-rsa-sign", b"doc")),
    ]);
    let harness = Harness::new(vec![Step::Message], vec![route(K2_ORIGIN, &server)]);
    let reply = harness.call("k2sign", K2_VERIFY_ALL, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"result":"OK","errorCode":"NONE"}"#);
    let message = &harness.prompter().message_prompts()[0];
    assert_eq!(message.kind, MessageKind::Info);
    assert_eq!(message.text, "Все ЭЦП подлинны.");
    let seen = server.seen();
    let urls: Vec<&str> = seen.iter().map(|s| s.url.as_str()).collect();
    assert_eq!(
        urls,
        [
            "https://k2.kazynashylyk.kz/files?id=1",
            "https://k2.kazynashylyk.kz/signs?id=17",
            "https://k2.kazynashylyk.kz/signs?id=2",
            "https://k2.kazynashylyk.kz/signs?id=33",
            "https://k2.kazynashylyk.kz/k2/verifyResult",
        ]
    );
    let post = &seen[4];
    assert_eq!(post.method, HttpMethod::Post);
    assert_eq!(
        post.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    // Java's HashMap of the ids as strings ("33" in bucket 0, "2" in 2, "17" in 6).
    assert_eq!(
        String::from_utf8(post.body.clone()).unwrap(),
        "userName=%D0%98%D0%B2%D0%B0%D0%BD+%D0%98%D0%B2%D0%B0%D0%BD%D0%BE%D0%B2&verifyRes=33-Y;2-Y;17-Y;"
    );
}

#[test]
fn k2_verify_all_invalid_no_post() {
    let server = k2_verify_all_server(vec![
        (17, detached(KEY, b"doc")),
        (2, detached(KEY, b"another doc")),
        (33, detached(KEY, b"doc")),
    ]);
    let harness = Harness::new(vec![Step::Message], vec![route(K2_ORIGIN, &server)]);
    let reply = harness.call("k2sign", K2_VERIFY_ALL, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"result":"OK","errorCode":"NONE"}"#);
    let message = &harness.prompter().message_prompts()[0];
    assert_eq!(message.kind, MessageKind::Error);
    assert_eq!(message.text, "Обнаружены не подлинные ЭЦП!");
    assert!(server.seen().iter().all(|s| s.method == HttpMethod::Get));

    // One signature, invalid.
    let server = k2_verify_all_server(vec![(5, detached(KEY, b"x"))]);
    let harness = Harness::new(vec![Step::Message], vec![route(K2_ORIGIN, &server)]);
    let request = K2_VERIFY_ALL.replace("[17,2,33]", "[5]");
    let reply = harness.call("k2sign", &request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"result":"OK","errorCode":"NONE"}"#);
    assert_eq!(
        harness.prompter().message_prompts()[0].text,
        "ЭЦП не подлинна!"
    );

    // No `items`: no reply.
    let harness = Harness::new(vec![], vec![]);
    assert!(matches!(
        harness.call("k2sign", r#"{"type":"verifyAll"}"#, Some(K2_ORIGIN)),
        Reply::Drop
    ));
}

#[test]
fn k2_unknown_type() {
    for (locale, dialog) in [
        (Locale::Ru, "Не потдержиываемый тип сообщения"),
        (Locale::Kk, "Қолдау көрсетілмейтін хабар түрі"),
        (Locale::En, "Не потдержиываемый тип сообщения"),
    ] {
        let harness = Harness::new(vec![Step::Message], vec![]).with_locale(locale);
        let reply = harness.call("k2sign", r#"{"type":"text"}"#, Some(K2_ORIGIN));
        assert_eq!(text(&reply), r#"{"errorCode":"TYPE_NOT_SUPPORTED"}"#);
        assert_eq!(harness.prompter().message_prompts()[0].text, dialog);
    }
}

#[test]
fn k2_cancel() {
    let harness = Harness::new(vec![Step::CancelStorage, Step::Message], vec![]);
    let request = r#"{"type":"login","sessionId":"S","uploadURL":"/up","coockie":""}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"errorCode":"CANCEL"}"#);
    let message = &harness.prompter().message_prompts()[0];
    assert_eq!(message.kind, MessageKind::Error);
    assert_eq!(message.text, "Отменено пользователем");

    let harness =
        Harness::new(vec![Step::CancelPath, Step::Message], vec![]).with_locale(Locale::Kk);
    let request = r#"{"type":"file","userName":"u","uploadURL":"/up"}"#;
    let reply = harness.call("k2sign", request, Some(K2_ORIGIN));
    assert_eq!(text(&reply), r#"{"errorCode":"CANCEL"}"#);
    assert_eq!(
        harness.prompter().message_prompts()[0].text,
        "Пайдаланушы тоқтатқан"
    );
}
