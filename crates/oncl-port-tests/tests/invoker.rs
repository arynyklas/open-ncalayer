//! The ports of the original's `CommonInvoker` plugins: idocs, FHS Cabinet, doodocs, Devart
//! and ThunderCrypt. Replies are compared whole; every CMS is verified and its attributes
//! read from the DER.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::testing::Step;
use oncl_pki::http::{HttpError, HttpErrorKind, HttpReply, HttpRequest, HttpTransport};
use oncl_port_tests::{Harness, P12_PASSWORD, p12};
use oncl_protocol::Reply;
use serde_json::Value;
use std::sync::Arc;

// Helpers.

/// The text of a reply that is not a drop.
fn text(reply: Reply) -> String {
    match reply {
        Reply::Text(text) => text,
        Reply::Drop => panic!("the connection was dropped"),
    }
}

/// Dialog steps choosing the only key of the synthetic store `name`.
fn choose(name: &str) -> Vec<Step> {
    let (path, password) = p12(name);
    vec![
        Step::Storage {
            path,
            password: password.to_owned(),
        },
        Step::Key(0),
    ]
}

/// A transport whose requests all fail.
struct Down(HttpErrorKind);

impl HttpTransport for Down {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::new(self.0, "down"))
    }
}

/// A route of `prefix` that fails with `kind`.
fn down(prefix: &str, kind: HttpErrorKind) -> (String, Arc<dyn HttpTransport>) {
    (prefix.to_owned(), Arc::new(Down(kind)))
}

/// A transport answering every request with 200 and `body`.
struct Fixed(Vec<u8>);

impl HttpTransport for Fixed {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Ok(HttpReply {
            status: 200,
            content_type: Some("application/octet-stream".to_owned()),
            location: None,
            body: self.0.clone(),
        })
    }
}

/// The envelope's `body`.
fn body(reply: &str) -> Value {
    let envelope: Value = serde_json::from_str(reply).expect("a JSON reply");
    envelope["body"].clone()
}

/// A DER TLV: its tag and content.
fn tlvs(mut der: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let tag = der[0];
        let (len, skip) = match der[1] {
            n if n < 0x80 => (usize::from(n), 2),
            n => {
                let k = usize::from(n & 0x7f);
                let len = der[2..2 + k]
                    .iter()
                    .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
                (len, 2 + k)
            }
        };
        out.push((tag, &der[skip..skip + len]));
        der = &der[skip + len..];
    }
    out
}

/// The content of the only TLV of `der`.
fn inner(der: &[u8]) -> &[u8] {
    tlvs(der)[0].1
}

/// The DER of a dotted OID's content bytes.
fn oid(dotted: &str) -> Vec<u8> {
    der::asn1::ObjectIdentifier::new_unwrap(dotted)
        .as_bytes()
        .to_vec()
}

/// The parts of a SignedData: version, digest algorithms, encapsulated content info, then
/// the optional certificates/CRLs and the signer infos (last).
fn signed_data(cms: &[u8]) -> Vec<(u8, &[u8])> {
    let content_info = tlvs(inner(cms));
    let explicit = content_info[1].1;
    tlvs(inner(explicit))
}

/// The signer infos of a CMS, each its parts.
fn signer_infos(cms: &[u8]) -> Vec<Vec<(u8, &[u8])>> {
    let parts = signed_data(cms);
    tlvs(parts.last().unwrap().1)
        .into_iter()
        .map(|(_, info)| tlvs(info))
        .collect()
}

/// An attribute: the content bytes of its OID and the TLVs of its values.
type Attribute<'a> = (Vec<u8>, Vec<(u8, &'a [u8])>);

/// The attributes of `[tag]` of a signer info.
fn attributes<'a>(info: &[(u8, &'a [u8])], tag: u8) -> Vec<Attribute<'a>> {
    info.iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, attrs)| {
            tlvs(attrs)
                .into_iter()
                .map(|(_, attr)| {
                    let parts = tlvs(attr);
                    (parts[0].1.to_vec(), tlvs(parts[1].1))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The value TLVs of the signed attribute `dotted` of the signer `index`.
fn signed_attr(cms: &[u8], index: usize, dotted: &str) -> Option<Vec<(u8, Vec<u8>)>> {
    let infos = signer_infos(cms);
    attributes(&infos[index], 0xa0)
        .into_iter()
        .find(|(o, _)| *o == oid(dotted))
        .map(|(_, values)| values.into_iter().map(|(t, v)| (t, v.to_vec())).collect())
}

/// The OIDs of the unsigned attributes of the signer `index`.
fn unsigned_oids(cms: &[u8], index: usize) -> Vec<Vec<u8>> {
    let infos = signer_infos(cms);
    attributes(&infos[index], 0xa1)
        .into_iter()
        .map(|(o, _)| o)
        .collect()
}

/// The digest algorithm OID of the signer `index`.
fn digest_oid(cms: &[u8], index: usize) -> Vec<u8> {
    let infos = signer_infos(cms);
    tlvs(infos[index][2].1)[0].1.to_vec()
}

/// Whether the CMS carries its content.
fn attached(cms: &[u8]) -> bool {
    tlvs(signed_data(cms)[2].1).len() > 1
}

// idocs

const IDOCS: &str = "idocs";

fn idocs_error(code: &str, message: &str, details: &str) -> String {
    format!(
        r#"{{"code":"{code}","details":"{}","message":"{message}","status":false}}"#,
        details.replace('"', "\\\"")
    )
}

#[test]
fn idocs_missing_method_catch_all_bytes() {
    let harness = Harness::new(vec![], vec![]);
    let call = |request: &str| text(harness.call(IDOCS, request, None));
    assert_eq!(
        call(r#"{"module":"kz.idocs","args":{}}"#),
        idocs_error(
            "GENERAL_ERROR",
            "General error.",
            r#"org.json.JSONException: JSONObject["method"] not found."#
        )
    );
    assert_eq!(
        call(r#"{"module":"kz.idocs","method":7}"#),
        idocs_error(
            "GENERAL_ERROR",
            "General error.",
            r#"org.json.JSONException: JSONObject["method"] is not a string."#
        )
    );
    assert_eq!(
        call(r#"{"module":"kz.idocs","method":"x","args":{}}"#),
        idocs_error(
            "GENERAL_ERROR",
            "General error.",
            "java.lang.IllegalArgumentException: x is not defined in EsedoController"
        )
    );
    assert_eq!(
        call(r#"{"module":"kz.idocs","method":"sign"}"#),
        idocs_error(
            "GENERAL_ERROR",
            "General error.",
            "java.lang.IllegalArgumentException: sign demands arguments"
        )
    );
}

#[test]
fn idocs_validation_order_details() {
    let harness = Harness::new(vec![], vec![]);
    let invalid = "kz.idocs.units.esedo.exceptions.InvalidEsedoSignReq: ";
    let cases = [
        (
            r#"{"data":5}"#,
            format!(r#"{invalid}Поле "name" не найдено в теле запроса"#),
        ),
        (
            r#"{"name":5}"#,
            format!(r#"{invalid}Поле "data" не найдено в теле запроса"#),
        ),
        (
            r#"{"name":5,"data":"x"}"#,
            r#"org.json.JSONException: JSONObject["name"] is not a string."#.to_owned(),
        ),
        (
            r#"{"name":"a","data":null}"#,
            r#"org.json.JSONException: JSONObject["data"] is not a string."#.to_owned(),
        ),
        (
            r#"{"name":"","data":""}"#,
            format!(r#"{invalid}Поле "name" не может быть пустым"#),
        ),
        (
            r#"{"name":"a","data":""}"#,
            format!(r#"{invalid}Поле "data" не может быть пустым"#),
        ),
        (
            r#"{"name":"a","data":"-AAA"}"#,
            "java.lang.IllegalArgumentException: Illegal base64 character 2d".to_owned(),
        ),
    ];
    for (args, details) in cases {
        let request = format!(r#"{{"module":"kz.idocs","method":"sign","args":{args}}}"#);
        assert_eq!(
            text(harness.call(IDOCS, &request, None)),
            idocs_error(
                "INVOCATION_ERROR",
                "An invoked method threw an exception.",
                &details
            ),
            "{args}"
        );
    }
    assert!(harness.prompter().storage_prompts().is_empty());
}

/// An idocs `sign` of `data` named `name`: the reply.
fn idocs_sign(harness: &Harness, name: &str, data: &[u8]) -> String {
    let request = serde_json::json!({
        "module": "kz.idocs",
        "method": "sign",
        "args": {"name": name, "data": STANDARD.encode(data)},
    });
    text(harness.call(IDOCS, &request.to_string(), None))
}

/// The CMS of a successful idocs reply.
fn idocs_cms(reply: &str) -> Vec<u8> {
    let inner: Value = serde_json::from_str(body(reply).as_str().expect("a string body")).unwrap();
    assert_eq!(inner["status"], "success", "{reply}");
    STANDARD.decode(inner["content"].as_str().unwrap()).unwrap()
}

#[test]
fn idocs_sign_body_is_json_string() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let reply = idocs_sign(&harness, "a.pdf", b"hello");
    assert!(reply.starts_with(r#"{"body":"{\"content\":\""#), "{reply}");
    assert!(
        reply.ends_with(r#"\",\"status\":\"success\"}","status":true}"#),
        "{reply}"
    );
    let cms = idocs_cms(&reply);
    oncl_pki::cms::verify(&cms, Some(b"hello")).expect("the CMS verifies");
}

#[test]
fn idocs_cms_attrs() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let name = "Договор №1.pdf";
    let cms = idocs_cms(&idocs_sign(&harness, name, b"hello"));
    oncl_pki::cms::verify(&cms, Some(b"hello")).expect("the CMS verifies");
    assert!(!attached(&cms));
    assert_eq!(digest_oid(&cms, 0), oid("1.2.398.3.10.1.3.3"));
    assert_eq!(
        signed_attr(&cms, 0, "1.2.840.113549.1.9.77").unwrap(),
        vec![(0x0c, name.as_bytes().to_vec())]
    );
    assert_eq!(
        signed_attr(&cms, 0, "1.2.840.113549.1.9.13").unwrap(),
        vec![(0x0c, b"ESEDO".to_vec())]
    );
    let ocsp = signed_attr(&cms, 0, "1.3.6.1.5.5.7.48.1.1").unwrap();
    assert_eq!(ocsp.len(), 1);
    assert_eq!(ocsp[0].0, 0x04, "an OCTET STRING");
    // OCSPResponse { responseStatus successful, responseBytes }.
    let response = tlvs(inner(&ocsp[0].1));
    assert_eq!(response[0], (0x0a, &[0u8][..]));
    assert!(signed_attr(&cms, 0, "1.2.840.113549.1.9.16.2.47").is_none());
    assert!(signed_attr(&cms, 0, "1.2.840.113549.1.9.3").is_some());
    assert!(signed_attr(&cms, 0, "1.2.840.113549.1.9.5").is_some());
    assert!(unsigned_oids(&cms, 0).is_empty(), "no time-stamp");
    assert_eq!(harness.http_log(), vec!["POST http://ocsp.pki.gov.kz"]);
}

#[test]
fn idocs_ocsp_down_omits_attr() {
    let harness = Harness::new(
        choose("user-gost2015-sign"),
        vec![down("http://ocsp.pki.gov.kz", HttpErrorKind::Connect)],
    );
    let cms = idocs_cms(&idocs_sign(&harness, "a.pdf", b"hello"));
    oncl_pki::cms::verify(&cms, Some(b"hello")).expect("the CMS verifies");
    assert!(signed_attr(&cms, 0, "1.3.6.1.5.5.7.48.1.1").is_none());
    assert!(signed_attr(&cms, 0, "1.2.840.113549.1.9.77").is_some());
}

#[test]
fn idocs_cancel_cancelled() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        idocs_sign(&harness, "a.pdf", b"hello"),
        r#"{"body":"{\"status\":\"cancelled\"}","status":true}"#
    );
}

#[test]
fn idocs_non_gost2015_key_fails() {
    let harness = Harness::new(choose("user-rsa-sign"), vec![]);
    let reply = idocs_sign(&harness, "a.pdf", b"hello");
    let inner: Value = serde_json::from_str(body(&reply).as_str().unwrap()).unwrap();
    assert_eq!(inner["status"], "failure", "{reply}");
    assert!(inner["message"].is_string(), "{reply}");
}

// FHS Cabinet

const FHS: &str = "fhs";
const FHS_ORIGIN: Option<&str> = Some("https://cabinet.fhs.kz");

fn fhs_request(method: &str, args: &Value) -> String {
    serde_json::json!({
        "module": "kz.fhs.cabinet.FHSCabinetSigner",
        "method": method,
        "args": args,
    })
    .to_string()
}

/// The page path and password of the synthetic store `name`, as FHS V2 arguments.
fn fhs_key(name: &str) -> Value {
    let (path, password) = p12(name);
    serde_json::json!({"path": path.to_string_lossy(), "password": password})
}

/// `args` with `more` merged in.
fn merged(mut args: Value, more: Value) -> Value {
    let object = args.as_object_mut().unwrap();
    for (k, v) in more.as_object().unwrap() {
        object.insert(k.clone(), v.clone());
    }
    args
}

#[test]
fn fhs_missing_method_drops() {
    let harness = Harness::new(vec![], vec![]);
    for request in [
        r#"{"module":"kz.fhs.cabinet.FHSCabinetSigner","args":{}}"#,
        r#"{"module":"kz.fhs.cabinet.FHSCabinetSigner","method":1}"#,
    ] {
        assert_eq!(harness.call(FHS, request, None), Reply::Drop, "{request}");
    }
}

#[test]
fn fhs_version_bean_order() {
    let harness = Harness::new(vec![], vec![]);
    let call = |args: Value| {
        text(harness.call(
            FHS,
            &fhs_request("getTradeCabBundleVersion", &args),
            FHS_ORIGIN,
        ))
    };
    assert_eq!(
        call(serde_json::json!({"requestId": "r1"})),
        r#"{"body":{"code":"200","method":"getTradeCabBundleVersion","requestId":"r1","message":"OK","version":"2.0.0"},"status":true}"#
    );
    assert_eq!(
        call(serde_json::json!({})),
        r#"{"body":{"code":"200","method":"getTradeCabBundleVersion","requestId":"","message":"OK","version":"2.0.0"},"status":true}"#
    );
}

#[test]
fn fhs_demands_arguments_prefixed() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call(
            FHS,
            r#"{"module":"kz.fhs.cabinet.FHSCabinetSigner","method":"getTradeCabBundleVersion"}"#,
            FHS_ORIGIN,
        )),
        r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: getTradeCabBundleVersion demands arguments","message":"General error.","status":false}"#
    );
    assert_eq!(
        text(harness.call(
            FHS,
            r#"{"module":"kz.fhs.cabinet.FHSCabinetSigner","method":"signCms","args":{}}"#,
            FHS_ORIGIN,
        )),
        r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: signCms is not defined in FHSSignClassV2","message":"General error.","status":false}"#
    );
}

#[test]
fn fhs_certificate_path_cancel_keeps_code_200() {
    let (path, _) = p12("user-gost2015-sign");
    let harness = Harness::new(vec![Step::CancelPath, Step::Path(path.clone())], vec![]);
    let request = fhs_request("getCertificatePath", &serde_json::json!({}));
    assert_eq!(
        text(harness.call(FHS, &request, FHS_ORIGIN)),
        r#"{"body":{"code":"200","method":"getCertificatePath","requestId":"","storage":"PKCS12","message":"OK"},"status":true}"#
    );
    let chosen = text(harness.call(FHS, &request, FHS_ORIGIN));
    let expected = serde_json::json!(path.to_string_lossy()).to_string();
    assert_eq!(
        chosen,
        format!(
            r#"{{"body":{{"path":{expected},"code":"200","method":"getCertificatePath","requestId":"","storage":"PKCS12","message":"OK"}},"status":true}}"#
        )
    );
    let prompts = harness.prompter().path_prompts();
    assert_eq!(prompts[0].title.as_deref(), Some("Выберите сертификат"));
    assert_eq!(prompts[0].filters[0].extensions, vec!["p12".to_owned()]);
}

#[test]
fn fhs_certificate_info_fields() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let request = fhs_request(
        "getCertificateInfo",
        &merged(
            fhs_key("user-gost2015-sign"),
            serde_json::json!({"requestId": "7"}),
        ),
    );
    let reply = text(harness.call(FHS, &request, FHS_ORIGIN));
    let entry = oncl_port_tests::entry("user-gost2015-sign");
    let serial = oncl_pki::info::serial_dec(&entry.cert);
    let prefix = r#"{"body":{"code":"200","method":"getCertificateInfo","requestId":"7","message":"OK","certificateInfo":{"expiryDate":""#;
    assert!(reply.starts_with(prefix), "{reply}");
    let info = &body(&reply)["certificateInfo"];
    let keys: Vec<&str> = info
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    // serde_json sorts the keys; the order is checked on the text below.
    assert_eq!(keys.len(), 9, "{reply}");
    assert!(
        reply.contains(&format!(
            r#""serialNumber":"{serial}","surname":"ТЕСТОВ","fullName":"ТЕСТОВ ТЕСТ","middleName":"ТЕСТОВИЧ","algorithm":"ECGOST3410-2015","certificateType":["SIGNATURE","AUTHENTICATION"],"iin":"IIN123456789011"}}"#
        )),
        "{reply}"
    );
    let date = info["issuedDate"].as_str().unwrap();
    assert_eq!(date.len(), "2024-03-01T10:15:00.000+0500".len(), "{date}");
    assert_eq!(&date[10..11], "T");
    assert_eq!(&date[19..20], ".");
    assert!(matches!(&date[23..24], "+" | "-"), "{date}");

    let legal = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let reply = text(legal.call(
        FHS,
        &fhs_request("getCertificateInfo", &fhs_key("legal-gost2015-sign")),
        FHS_ORIGIN,
    ));
    let info = &body(&reply)["certificateInfo"];
    assert_eq!(info["orgName"], "ТОО СИНТЕТИКА");
    assert_eq!(info["bin"], "BIN123456789021");
    assert!(info.get("email").is_none());
}

#[test]
fn fhs_certificate_info_wrong_password_is_500() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let args = merged(
        fhs_key("user-gost2015-sign"),
        serde_json::json!({"password": "nope"}),
    );
    assert_eq!(
        text(harness.call(FHS, &fhs_request("getCertificateInfo", &args), FHS_ORIGIN)),
        r#"{"body":{"code":"500","method":"getCertificateInfo","requestId":""},"status":true}"#
    );
}

#[test]
fn fhs_sign_text_v2_kalkan_tsa() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let args = merged(
        fhs_key("user-gost2015-sign"),
        serde_json::json!({"base64data": STANDARD.encode(b"hello"), "requestId": "r"}),
    );
    let reply = text(harness.call(FHS, &fhs_request("signTextV2", &args), FHS_ORIGIN));
    assert!(
        reply.starts_with(
            r#"{"body":{"code":"200","method":"signTextV2","requestId":"r","message":""#
        ),
        "{reply}"
    );
    let cms = STANDARD
        .decode(body(&reply)["message"].as_str().unwrap())
        .unwrap();
    let signers = oncl_pki::cms::verify(&cms, Some(b"hello")).expect("the CMS verifies");
    assert!(signers[0].timestamp_token.is_some());
    assert!(!attached(&cms));
    assert!(signed_attr(&cms, 0, "1.2.840.113549.1.9.16.2.47").is_some());
    let log = harness.http_log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(log[0].starts_with("GET http://tsp.pki.gov.kz/"), "{log:?}");

    let bad = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let args = merged(
        fhs_key("user-gost2015-sign"),
        serde_json::json!({"base64data": "a b"}),
    );
    assert_eq!(
        text(bad.call(FHS, &fhs_request("signTextV2", &args), FHS_ORIGIN)),
        r#"{"body":{"code":"500","method":"signTextV2","requestId":"","message":"Illegal base64 character 20"},"status":true}"#
    );
}

#[test]
fn fhs_sign_text_v2_tsa_failure_message() {
    let harness = Harness::new(
        vec![Step::Confirm { yes: true }],
        vec![down("http://tsp.pki.gov.kz", HttpErrorKind::UnknownHost)],
    );
    let args = merged(
        fhs_key("user-gost2015-sign"),
        serde_json::json!({"base64data": STANDARD.encode(b"hello")}),
    );
    let reply = text(harness.call(FHS, &fhs_request("signTextV2", &args), FHS_ORIGIN));
    assert!(
        reply.starts_with(
            r#"{"body":{"code":"500","method":"signTextV2","requestId":"","message":"error code:TIMESTAMP_CREATION_FAILURE, error message"#
        ),
        "{reply}"
    );
}

#[test]
fn fhs_sign_xml_v2_missing_xml() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call(
            FHS,
            &fhs_request("signXmlV2", &fhs_key("user-gost2015-sign")),
            FHS_ORIGIN
        )),
        r#"{"code":"INVOCATION_ERROR","details":"org.json.JSONException: JSONObject[\"xml\"] not found.","message":"An invoked method threw an exception.","status":false}"#
    );
    let missing = serde_json::json!({"xml": "<a/>", "path": "Z:\\no\\such.p12", "password": "x"});
    assert_eq!(
        text(harness.call(FHS, &fhs_request("signXmlV2", &missing), FHS_ORIGIN)),
        r#"{"body":{"code":"500","method":"signXmlV2","requestId":""},"status":true}"#
    );
    assert!(harness.prompter().confirm_prompts().is_empty());
}

#[test]
fn fhs_sign_xml_v2_signs_document() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let args = merged(
        fhs_key("user-gost2015-sign"),
        serde_json::json!({"xml": "<doc><a>1</a></doc>"}),
    );
    let reply = text(harness.call(FHS, &fhs_request("signXmlV2", &args), FHS_ORIGIN));
    let signed = body(&reply)["message"].as_str().unwrap().to_owned();
    assert!(signed.contains("<ds:Signature"), "{reply}");
    assert!(reply.contains(r#"<\/doc>"#), "org.json escapes </");
}

#[test]
fn fhs_v1_cancel_dialog_and_500() {
    let harness = Harness::new(
        vec![
            Step::CancelStorage,
            Step::Choice {
                button: 0,
                option: None,
            },
        ],
        vec![],
    );
    let args = serde_json::json!({"base64data": STANDARD.encode(b"hello")});
    assert_eq!(
        text(harness.call(FHS, &fhs_request("signText", &args), FHS_ORIGIN)),
        r#"{"body":{"code":"500"},"status":true}"#
    );
    let choices = harness.prompter().choice_prompts();
    assert_eq!(choices.len(), 1);
    assert_eq!(choices[0].title.as_deref(), Some("Ошибка"));
    assert_eq!(choices[0].text, "Не выбран ключ ЭЦП");
    assert_eq!(choices[0].buttons, vec!["Закрыть".to_owned()]);
}

#[test]
fn fhs_v1_sign_text_and_xml() {
    let mut steps = choose("user-gost2015-sign");
    steps.extend(choose("user-gost2015-sign"));
    let harness = Harness::new(steps, vec![]);
    let mut session = harness.session(FHS);
    let args = serde_json::json!({"base64data": STANDARD.encode(b"hello")});
    let reply = text(session.call(&fhs_request("signText", &args), FHS_ORIGIN));
    assert!(
        reply.starts_with(r#"{"body":{"code":"200","message":""#),
        "{reply}"
    );
    let cms = STANDARD
        .decode(body(&reply)["message"].as_str().unwrap())
        .unwrap();
    oncl_pki::cms::verify(&cms, Some(b"hello")).expect("the CMS verifies");
    let reply = text(session.call(
        &fhs_request("signXml", &serde_json::json!({"xml": "<a>1</a>"})),
        FHS_ORIGIN,
    ));
    assert!(
        body(&reply)["message"]
            .as_str()
            .unwrap()
            .contains("Signature")
    );
}

#[test]
fn fhs_sign_file_foreign_url_denied() {
    let harness = Harness::new(
        vec![Step::Choice {
            button: 0,
            option: None,
        }],
        vec![],
    );
    let args = serde_json::json!({"url": "https://evil.example/doc.pdf"});
    assert_eq!(
        text(harness.call(FHS, &fhs_request("signFile", &args), FHS_ORIGIN)),
        r#"{"body":{"code":"500"},"status":true}"#
    );
    assert!(harness.http_log().is_empty());
    assert!(harness.prompter().storage_prompts().is_empty());
    assert_eq!(
        harness.prompter().choice_prompts()[0].text,
        "Ошибка при скачивании файла"
    );
    assert_eq!(
        text(harness.call(
            FHS,
            &fhs_request("signFile", &serde_json::json!({})),
            FHS_ORIGIN
        )),
        r#"{"code":"INVOCATION_ERROR","details":"org.json.JSONException: JSONObject[\"url\"] not found.","message":"An invoked method threw an exception.","status":false}"#
    );
}

#[test]
fn fhs_sign_file_same_origin() {
    let harness = Harness::new(
        choose("user-gost2015-sign"),
        vec![(
            "https://cabinet.fhs.kz/".to_owned(),
            Arc::new(Fixed(b"file".to_vec())) as Arc<dyn HttpTransport>,
        )],
    );
    let args = serde_json::json!({"url": "https://cabinet.fhs.kz/files/1.pdf"});
    let reply = text(harness.call(FHS, &fhs_request("signFile", &args), FHS_ORIGIN));
    let cms = STANDARD
        .decode(body(&reply)["message"].as_str().expect("signed"))
        .unwrap();
    oncl_pki::cms::verify(&cms, Some(b"file")).expect("the CMS verifies");
    assert_eq!(
        harness.http_log()[0],
        "GET https://cabinet.fhs.kz/files/1.pdf"
    );
}

// doodocs

const DOODOCS: &str = "doodocs";

thread_local! {
    /// Seconds the clock of [`moving_clock`] is ahead of the harness's default clock.
    static AHEAD: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

/// The default clock, `AHEAD` seconds later (the plugin runs on the test's thread).
fn moving_clock() -> time::OffsetDateTime {
    oncl_port_tests::default_clock() + time::Duration::seconds(AHEAD.with(std::cell::Cell::get))
}

fn doodocs_request(method: &str, args: Option<Value>) -> String {
    let mut request = serde_json::json!({
        "module": "kz.doodocs.moduleservice.SampleBundle",
        "method": method,
    });
    if let Some(args) = args {
        request["args"] = args;
    }
    request.to_string()
}

fn doodocs_auth(name: &str, password: &str) -> String {
    let (path, _) = p12(name);
    let store = std::fs::read(path).unwrap();
    doodocs_request(
        "auth",
        Some(serde_json::json!({"storagePath": STANDARD.encode(store), "password": password})),
    )
}

fn doodocs_sign(key_type: &str, data: &str, attached: bool) -> String {
    doodocs_request(
        "createCAdESFromBase64",
        Some(serde_json::json!({"keyType": key_type, "base64ToSign": data, "attached": attached})),
    )
}

fn doodocs_failure(code: &str, message: &str) -> String {
    format!(r#"{{"code":"{code}","message":"{message}","status":false}}"#)
}

const SUCCESS: &str = r#"{"body":"success","status":true}"#;

#[test]
fn doodocs_auth_and_sign() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session(DOODOCS);
    assert_eq!(
        text(session.call(&doodocs_auth("user-gost2015-sign", P12_PASSWORD), None)),
        SUCCESS
    );
    let data = STANDARD.encode(b"hello");
    let reply = text(session.call(&doodocs_sign("SIGN", &data, false), None));
    let cms = STANDARD.decode(body(&reply).as_str().unwrap()).unwrap();
    let signers = oncl_pki::cms::verify(&cms, Some(b"hello")).expect("the CMS verifies");
    assert!(signers[0].timestamp_token.is_some());
    assert!(!attached(&cms));
    assert!(harness.http_log()[0].starts_with("GET http://tsp.pki.gov.kz/"));

    let reply = text(session.call(&doodocs_sign("SIGN", &data, true), None));
    let attached_cms = STANDARD.decode(body(&reply).as_str().unwrap()).unwrap();
    assert!(attached(&attached_cms));
    let reply = text(session.call(
        &doodocs_sign("SIGN", &STANDARD.encode(&attached_cms), true),
        None,
    ));
    let cosigned = STANDARD.decode(body(&reply).as_str().unwrap()).unwrap();
    let signers = oncl_pki::cms::verify(&cosigned, None).expect("the co-signed CMS verifies");
    assert_eq!(signers.len(), 2);
}

#[test]
fn doodocs_auth_failure_keeps_session() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session(DOODOCS);
    let wrong = doodocs_failure("WRONG_PASSWORD", "wrong password");
    assert_eq!(
        text(session.call(&doodocs_auth("user-gost2015-sign", "nope"), None)),
        wrong
    );
    assert_eq!(
        text(session.call(&doodocs_request("isAuthorized", None), None)),
        r#"{"body":{"logged_in":false},"status":true}"#
    );
    assert_eq!(
        text(session.call(&doodocs_auth("user-gost2015-sign", P12_PASSWORD), None)),
        SUCCESS
    );
    for request in [
        doodocs_auth("user-gost2015-sign", "nope"),
        doodocs_auth("expired-gost2015-sign", P12_PASSWORD),
        doodocs_request(
            "auth",
            Some(serde_json::json!({"storagePath": "-", "password": P12_PASSWORD})),
        ),
        doodocs_request("auth", Some(serde_json::json!({}))),
    ] {
        assert_eq!(text(session.call(&request, None)), wrong, "{request}");
    }
    let reply = text(session.call(&doodocs_sign("SIGN", &STANDARD.encode(b"x"), false), None));
    assert!(
        body(&reply).is_string(),
        "the first key still signs: {reply}"
    );
}

#[test]
fn doodocs_is_authorized_countdown() {
    AHEAD.with(|a| a.set(0));
    let harness = Harness::new(vec![], vec![]).with_clock(moving_clock);
    let mut session = harness.session(DOODOCS);
    session.call(&doodocs_auth("user-gost2015-sign", P12_PASSWORD), None);
    let authorized = |session: &mut oncl_port_tests::SessionHandle| {
        text(session.call(r#"{"module":"kz.doodocs.moduleservice.SampleBundle","method":"isAuthorized","args":5}"#, None))
    };
    AHEAD.with(|a| a.set(12));
    assert_eq!(
        authorized(&mut session),
        r#"{"body":{"logged_in":true,"expire_after":"04:48"},"status":true}"#
    );
    AHEAD.with(|a| a.set(299));
    assert_eq!(
        authorized(&mut session),
        r#"{"body":{"logged_in":true,"expire_after":"00:01"},"status":true}"#
    );
    assert_eq!(
        text(session.call(&doodocs_request("logOut", None), None)),
        SUCCESS
    );
    assert_eq!(
        authorized(&mut session),
        r#"{"body":{"logged_in":false},"status":true}"#
    );
    AHEAD.with(|a| a.set(0));
}

#[test]
fn doodocs_session_expired() {
    AHEAD.with(|a| a.set(0));
    let harness = Harness::new(vec![], vec![]).with_clock(moving_clock);
    let mut session = harness.session(DOODOCS);
    session.call(&doodocs_auth("user-gost2015-sign", P12_PASSWORD), None);
    AHEAD.with(|a| a.set(300));
    let data = STANDARD.encode(b"x");
    assert_eq!(
        text(session.call(&doodocs_sign("SIGN", &data, false), None)),
        doodocs_failure("SESSION_EXPIRED", "session expired")
    );
    assert_eq!(
        text(session.call(&doodocs_sign("SIGN", &data, false), None)),
        doodocs_failure("USER_NOT_LOGGED_IN", "user is not logged in")
    );
    AHEAD.with(|a| a.set(0));
}

#[test]
fn doodocs_key_type_checks_order() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session(DOODOCS);
    assert_eq!(
        text(session.call(&doodocs_sign("SIGN", "!", false), None)),
        doodocs_failure("USER_NOT_LOGGED_IN", "user is not logged in")
    );
    session.call(&doodocs_auth("user-gost2015-sign", P12_PASSWORD), None);
    let unknown = doodocs_failure("UNKNOWN_KEY_TYPE", "unknown key type");
    assert_eq!(
        text(session.call(&doodocs_sign("sign", "!", false), None)),
        unknown
    );
    assert_eq!(
        text(session.call(
            &doodocs_request("createCAdESFromBase64", Some(serde_json::json!({}))),
            None
        )),
        unknown
    );
    assert_eq!(
        text(session.call(&doodocs_sign("AUTH", "!", false), None)),
        doodocs_failure("ILLEGAL_KEY_TYPE", "illegal key type")
    );
    assert_eq!(
        text(session.call(&doodocs_sign("SIGN", "!", false), None)),
        doodocs_failure("BAD_PAYLOAD_BASE64", "invalid payload for base64")
    );

    let mut auth = harness.session(DOODOCS);
    auth.call(&doodocs_auth("user-gost2015-auth", P12_PASSWORD), None);
    assert_eq!(
        text(auth.call(&doodocs_sign("SIGN", "!", false), None)),
        doodocs_failure("ILLEGAL_KEY_TYPE", "illegal key type")
    );
}

#[test]
fn doodocs_bad_payload() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session(DOODOCS);
    session.call(&doodocs_auth("user-gost2015-sign", P12_PASSWORD), None);
    let bad = doodocs_failure("BAD_PAYLOAD_BASE64", "invalid payload for base64");
    for data in ["", "a b", "@@@@"] {
        assert_eq!(
            text(session.call(&doodocs_sign("SIGN", data, false), None)),
            bad,
            "{data}"
        );
    }
    assert!(harness.http_log().is_empty());
}

#[test]
fn doodocs_dispatch() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        harness.call(
            DOODOCS,
            r#"{"module":"kz.doodocs.moduleservice.SampleBundle"}"#,
            None
        ),
        Reply::Drop
    );
    assert_eq!(
        text(harness.call(DOODOCS, &doodocs_request("auth", None), None)),
        r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: auth demands arguments","message":"General error.","status":false}"#
    );
    assert_eq!(
        text(harness.call(DOODOCS, &doodocs_request("logOut", None), None)),
        SUCCESS
    );
}

#[test]
fn doodocs_tsa_failure_is_provider_exception() {
    let harness = Harness::new(
        vec![],
        vec![down("http://tsp.pki.gov.kz", HttpErrorKind::Timeout)],
    );
    let mut session = harness.session(DOODOCS);
    session.call(&doodocs_auth("user-gost2015-sign", P12_PASSWORD), None);
    let reply = text(session.call(&doodocs_sign("SIGN", &STANDARD.encode(b"x"), false), None));
    assert!(
        reply.starts_with(
            r#"{"code":"INVOCATION_ERROR","details":"kz.gov.pki.provider.exception.ProviderUtilException: "#
        ),
        "{reply}"
    );
}

// Devart

const DEVART: &str = "devart";
const SIGNATURE_TIME_STAMP: &str = "1.2.840.113549.1.9.16.2.14";

fn devart_request(method: &str, args: &Value) -> String {
    serde_json::json!({"module": "kz.devart.bundle.Devart", "method": method, "args": args})
        .to_string()
}

/// The body of a Devart reply: the JSON text it carries, parsed.
fn devart_body(reply: &str) -> Value {
    let text = body(reply);
    serde_json::from_str(
        text.as_str()
            .unwrap_or_else(|| panic!("a text body: {reply}")),
    )
    .unwrap()
}

/// A Devart `{"errorCode":…}` body, as the envelope carries it.
fn devart_error(message: &str) -> String {
    let inner = serde_json::json!({ "errorCode": format!("Ошибка! {message}") }).to_string();
    format!(
        r#"{{"body":{},"status":true}}"#,
        serde_json::to_string(&inner).unwrap()
    )
}

/// `getSignerInfo` in `session`: the token.
fn devart_token(session: &mut oncl_port_tests::SessionHandle, check_ocsp: Value) -> String {
    let args =
        serde_json::json!({"storageName": "PKCS12", "checkOcsp": check_ocsp, "checkCrl": false});
    let reply = text(session.call(&devart_request("getSignerInfo", &args), None));
    devart_body(&reply)["token"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"))
        .to_owned()
}

/// The Sun `X500Name` text of the synthetic individual.
const INDIVIDUAL_DN: &str =
    "C=KZ, SERIALNUMBER=IIN123456789011, GIVENNAME=ТЕСТОВИЧ, SURNAME=ТЕСТОВ, CN=ТЕСТОВ ТЕСТ";

#[test]
fn devart_missing_method_drops() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        harness.call(DEVART, r#"{"module":"kz.devart.bundle.Devart"}"#, None),
        Reply::Drop
    );
}

#[test]
fn devart_unannotated_not_defined() {
    let harness = Harness::new(vec![], vec![]);
    for method in ["signCms", "signXmlData", "signEsfData"] {
        assert_eq!(
            text(harness.call(
                DEVART,
                &devart_request(method, &serde_json::json!({})),
                None
            )),
            format!(
                r#"{{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: {method} is not defined in DevartNLClass","message":"General error.","status":false}}"#
            )
        );
    }
}

#[test]
fn devart_double_encoded_body() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let args = serde_json::json!({"storageName": "PKCS12", "checkOcsp": false, "checkCrl": false});
    let reply = text(harness.call(DEVART, &devart_request("getSignerInfo", &args), None));
    let prefix = format!(r#"{{"body":"{{\"userCertInfo\":\"{INDIVIDUAL_DN}\",\"token\":\""#);
    assert!(reply.starts_with(&prefix), "{reply}");
    assert!(reply.ends_with(r#"\"}","status":true}"#), "{reply}");
    let token = devart_body(&reply)["token"].as_str().unwrap().to_owned();
    let decoded = String::from_utf8(STANDARD.decode(token).unwrap()).unwrap();
    assert!(decoded.ends_with(INDIVIDUAL_DN), "{decoded}");
    assert_eq!(&decoded[4..5], "-");
    assert_eq!(&decoded[10..11], "T", "{decoded}");
}

#[test]
fn devart_get_signer_info_order_and_dn() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let call =
        |args: Value| text(harness.call(DEVART, &devart_request("getSignerInfo", &args), None));
    assert_eq!(
        call(serde_json::json!({"dataList": [{"data": "x"}], "checkOcsp": true})),
        devart_error(r#"JSONObject["fileName"] not found."#)
    );
    assert_eq!(
        call(serde_json::json!({"checkOcsp": true})),
        devart_error(r#"JSONObject["storageName"] not found."#)
    );
    assert_eq!(
        call(serde_json::json!({"storageName": "PKCS12", "certificateKeyUser": "CEO"})),
        devart_error(r#"JSONObject["checkOcsp"] not found."#)
    );
    assert_eq!(
        call(serde_json::json!({"storageName": "PKCS12", "checkOcsp": "maybe", "checkCrl": false})),
        devart_error(r#"JSONObject["checkOcsp"] is not a Boolean."#)
    );
    assert_eq!(
        call(serde_json::json!({"storageName": "PKCS12", "checkOcsp": false})),
        devart_error(r#"JSONObject["checkCrl"] not found."#)
    );
    let storage = |name: &str| serde_json::json!({"storageName": name, "checkOcsp": false, "checkCrl": false});
    assert_eq!(call(storage("")), devart_error("storageName.param.empty"));
    assert_eq!(call(storage("FOO")), devart_error("storage.unknown"));
    assert_eq!(
        call(storage("AKKaztokenStore")),
        devart_error("storage.empty")
    );
    assert!(harness.prompter().storage_prompts().is_empty());
    assert_eq!(call(storage("PKCS12")), devart_error("action.canceled"));
}

#[test]
fn devart_check_ocsp_string_true() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let mut session = harness.session(DEVART);
    let token = devart_token(&mut session, serde_json::json!("TRUE"));
    let args = serde_json::json!({"token": token, "dataList": [
        {"data": STANDARD.encode("<a>1</a>"), "fileName": "a.xml", "dataType": "xml"},
    ]});
    let reply = text(session.call(&devart_request("signDevart", &args), None));
    assert!(
        devart_body(&reply)["signedResult"]["XML"].is_array(),
        "{reply}"
    );
    let log = harness.http_log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(
        log[0].starts_with("POST http://ocsp.pki.gov.kz/"),
        "{log:?}"
    );
}

#[test]
fn devart_sign_devart_groups_and_spacing() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let mut session = harness.session(DEVART);
    let token = devart_token(&mut session, serde_json::json!(false));
    let sign = |session: &mut oncl_port_tests::SessionHandle, list: Value| {
        let args = serde_json::json!({"token": token, "dataList": list});
        let reply = text(session.call(&devart_request("signDevart", &args), None));
        body(&reply).as_str().unwrap().to_owned()
    };
    assert_eq!(
        sign(&mut session, serde_json::json!([])),
        r#"{ "signedResult" : {} }"#
    );
    let item = |data: &[u8], name: &str, kind: &str| serde_json::json!({"data": STANDARD.encode(data), "fileName": name, "dataType": kind});
    let all = sign(
        &mut session,
        serde_json::json!([
            item(b"doc", "d.bin", "CMS"),
            item(b"<x>1</x>", "x.xml", "Xml"),
            item(b"skip", "s.pdf", "PDF"),
            item(b"<esf/>", "e.xml", "esf"),
        ]),
    );
    assert!(
        all.starts_with(r#"{ "signedResult" : {"ESF": [{"fileName":"e.xml","signature":""#),
        "{all}"
    );
    assert!(
        all.contains(r#"}], "XML": [{"fileName":"x.xml","signature":"null","signedData":""#),
        "{all}"
    );
    assert!(all.contains(r#","certificate":"null","message":"OK","status":200}], "CMS": [{"fileName":"d.bin","cms":""#), "{all}");
    assert!(
        all.ends_with(r#"","message":"OK","status":200}]} }"#),
        "{all}"
    );
    let parsed: Value = serde_json::from_str(&all).unwrap();
    let xml = parsed["signedResult"]["XML"][0]["signedData"]
        .as_str()
        .unwrap();
    assert!(xml.contains("Signature"), "{xml}");
    let cms = STANDARD
        .decode(parsed["signedResult"]["CMS"][0]["cms"].as_str().unwrap())
        .unwrap();
    oncl_pki::cms::verify(&cms, None).expect("the CMS verifies");
    assert!(attached(&cms));
    assert_eq!(
        sign(
            &mut session,
            serde_json::json!([{"data": "-AAA", "fileName": "a", "dataType": "CMS"}])
        ),
        r#"{ "signedResult" : {"CMS": {"errorCode":"Ошибка! Illegal base64 character 2d"}} }"#
    );
}

#[test]
fn devart_esf_raw_over_text_without_cr() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let mut session = harness.session(DEVART);
    let token = devart_token(&mut session, serde_json::json!(false));
    let args = serde_json::json!({"token": token, "dataList": [
        {"data": STANDARD.encode("<esf>\r\n<a>ы</a>\r\n</esf>"), "fileName": "e.xml", "dataType": "ESF"},
    ]});
    let reply = text(session.call(&devart_request("signDevart", &args), None));
    let parsed: Value = serde_json::from_str(body(&reply).as_str().unwrap()).unwrap();
    let item = &parsed["signedResult"]["ESF"][0];
    assert_eq!(item["signedData"], "<esf>\n<a>ы</a>\n</esf>");
    assert_eq!(item["message"], "OK");
    assert_eq!(item["status"], 200);
    let entry = oncl_port_tests::entry("user-gost2015-sign");
    assert_eq!(
        STANDARD
            .decode(item["certificate"].as_str().unwrap())
            .unwrap(),
        der::Encode::to_der(&entry.cert).unwrap()
    );
    assert!(
        !STANDARD
            .decode(item["signature"].as_str().unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn devart_cms_stamps_all_unstamped() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let mut session = harness.session(DEVART);
    let token = devart_token(&mut session, serde_json::json!(false));
    // An attached CMS of another signer, without a time-stamp.
    let other = oncl_port_tests::entry("legal-gost2015-sign");
    let unstamped = oncl_pki::cms::sign(
        &other,
        b"doc",
        &oncl_pki::cms::SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: oncl_port_tests::default_clock(),
        },
    )
    .unwrap();
    let args = serde_json::json!({"token": token, "dataList": [
        {"data": STANDARD.encode(&unstamped), "fileName": "d.cms", "dataType": "CMS"},
    ]});
    let reply = text(session.call(&devart_request("signDevart", &args), None));
    let parsed: Value = serde_json::from_str(body(&reply).as_str().unwrap()).unwrap();
    let cms = STANDARD
        .decode(
            parsed["signedResult"]["CMS"][0]["cms"]
                .as_str()
                .expect("signed"),
        )
        .unwrap();
    let signers = oncl_pki::cms::verify(&cms, None).expect("the CMS verifies");
    assert_eq!(signers.len(), 2);
    for index in 0..2 {
        assert!(
            unsigned_oids(&cms, index).contains(&oid(SIGNATURE_TIME_STAMP)),
            "signer {index} stamped"
        );
    }
    let posts: Vec<String> = harness
        .http_log()
        .into_iter()
        .filter(|r| r == "POST http://tsp.pki.gov.kz/")
        .collect();
    assert_eq!(posts.len(), 2);
}

#[test]
fn devart_ocsp_revoked_invocation_error() {
    let entry = oncl_port_tests::entry("user-gost2015-sign");
    let serial: String = entry
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let ocsp = oncl_pki::ocsp::MockOcsp::new(oncl_port_tests::entry("ocsp-gost2015")).status(
        &serial,
        oncl_pki::ocsp::CertStatus::Revoked {
            time: oncl_port_tests::default_clock() - time::Duration::days(1),
            reason: Some(1),
        },
    );
    let harness = Harness::new(
        choose("user-gost2015-sign"),
        vec![(
            "http://ocsp.pki.gov.kz".to_owned(),
            Arc::new(ocsp) as Arc<dyn HttpTransport>,
        )],
    );
    let mut session = harness.session(DEVART);
    let token = devart_token(&mut session, serde_json::json!(true));
    let args = serde_json::json!({"token": token, "dataList": []});
    assert_eq!(
        text(session.call(&devart_request("signDevart", &args), None)),
        r#"{"code":"INVOCATION_ERROR","details":"java.lang.RuntimeException: kz.devart.bundle.exception.CertificateRevokationException: Сертификат отозван","message":"An invoked method threw an exception.","status":false}"#
    );
}

#[test]
fn devart_certificate_key_user() {
    let harness = Harness::new(choose("user-gost2015-sign"), vec![]);
    let mut session = harness.session(DEVART);
    let token = devart_token(&mut session, serde_json::json!(false));
    let sign = |session: &mut oncl_port_tests::SessionHandle, users: &str| {
        let args = serde_json::json!({"token": token, "certificateKeyUser": users});
        text(session.call(&devart_request("signDevart", &args), None))
    };
    assert_eq!(
        sign(&mut session, "CEO,HR"),
        r#"{"code":"INVOCATION_ERROR","details":"java.lang.RuntimeException: java.security.cert.CertificateException: Не найден признак CEO,HR в сертификате!","message":"An invoked method threw an exception.","status":false}"#
    );
    assert_eq!(
        sign(&mut session, "CEO,individual"),
        r#"{"body":"{ \"signedResult\" : {} }","status":true}"#
    );
}

#[test]
fn devart_extract_detached_error() {
    let harness = Harness::new(vec![], vec![]);
    let entry = oncl_port_tests::entry("user-gost2015-sign");
    let make = |encapsulate: bool| {
        oncl_pki::cms::sign(
            &entry,
            b"content",
            &oncl_pki::cms::SignOptions {
                encapsulate,
                digested: false,
                signing_time: oncl_port_tests::default_clock(),
            },
        )
        .unwrap()
    };
    let extract = |data: &str| {
        let args =
            serde_json::json!({"dataList": [{"data": data, "fileName": "f", "dataType": "CMS"}]});
        text(harness.call(DEVART, &devart_request("extractFromCms", &args), None))
    };
    let content = STANDARD.encode(b"content");
    assert_eq!(
        extract(&STANDARD.encode(make(true))),
        format!(
            r#"{{"body":"[{{\"fileName\":\"f\",\"data\":\"{content}\",\"dataType\":\"CMS\"}}]","status":true}}"#
        )
    );
    assert_eq!(
        extract(&STANDARD.encode(make(false))),
        r#"{"code":"INVOCATION_ERROR","details":"java.lang.RuntimeException: CMS doesn't have signed content","message":"An invoked method threw an exception.","status":false}"#
    );
    assert_eq!(
        extract(&STANDARD.encode(b"junk")),
        devart_error("Не верный формат")
    );
    assert_eq!(
        extract("-AAA"),
        r#"{"code":"INVOCATION_ERROR","details":"java.lang.IllegalArgumentException: Illegal base64 character 2d","message":"An invoked method threw an exception.","status":false}"#
    );
    assert_eq!(
        text(harness.call(
            DEVART,
            &devart_request("extractFromCms", &serde_json::json!({})),
            None
        )),
        r#"{"code":"INVOCATION_ERROR","details":"org.json.JSONException: JSONObject[\"dataList\"] not found.","message":"An invoked method threw an exception.","status":false}"#
    );
    assert_eq!(
        text(harness.call(
            DEVART,
            &devart_request("extractFromCms", &serde_json::json!({"dataList": []})),
            None
        )),
        r#"{"body":"[]","status":true}"#
    );
}

#[test]
fn devart_unknown_token_null() {
    let harness = Harness::new(vec![], vec![]);
    let call = |args: Value| text(harness.call(DEVART, &devart_request("signDevart", &args), None));
    assert_eq!(
        call(serde_json::json!({"token": "x"})),
        devart_error("null")
    );
    assert_eq!(
        call(serde_json::json!({})),
        devart_error(r#"JSONObject["token"] not found."#)
    );
    assert_eq!(
        call(serde_json::json!({"token": "x", "dataList": [{"data": "a", "fileName": "b"}]})),
        devart_error(r#"JSONObject["dataType"] not found."#)
    );
}

// ThunderCrypt

const THUNDERCRYPT: &str = "thundercrypt";
/// A key of the intermediate PKI: its certificate names the OCSP responder and the CRL.
const TC_KEY: &str = "inter-user-gost2015-sign";

/// The serial number of the synthetic key `name`'s certificate, hex.
fn serial_hex(name: &str) -> String {
    oncl_port_tests::entry(name)
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A harness for ThunderCrypt: the real clock (the TSA's genTime is checked against it),
/// the synthetic responder and CRL server reachable; `extra` routes first.
fn tc_harness(steps: Vec<Step>, mut extra: Vec<(String, Arc<dyn HttpTransport>)>) -> Harness {
    extra.push((
        "http://ocsp.synthetic.test".to_owned(),
        Arc::new(oncl_pki::ocsp::MockOcsp::new(oncl_port_tests::entry(
            "ocsp-gost2015",
        ))),
    ));
    extra.push((
        "http://crl.synthetic.test".to_owned(),
        Arc::new(oncl_pki::crl::MockCrl::new(oncl_port_tests::entry(
            "inter-gost2015.key",
        ))),
    ));
    Harness::new(steps, extra)
        .with_pki_hosts(&["ocsp.synthetic.test", "crl.synthetic.test"])
        .with_clock(time::OffsetDateTime::now_utc)
}

/// The password, then the consent to the key file.
fn tc_steps() -> Vec<Step> {
    vec![
        Step::Password(P12_PASSWORD.to_owned()),
        Step::Confirm { yes: true },
    ]
}

/// The arguments of a `sign` of `data` with the synthetic key `name`.
fn tc_args(name: &str, data: &[u8]) -> Value {
    let (path, _) = p12(name);
    serde_json::json!({
        "keyType": "file",
        "filePath": path.to_string_lossy(),
        "filesNames": "act.pdf",
        "dataForSign": STANDARD.encode(data),
    })
}

fn tc_v2(args: &Value) -> String {
    serde_json::json!({
        "module": "asia.dbt.thundercrypt.osgi.ThunderCryptModule",
        "method": "sign",
        "args": args,
    })
    .to_string()
}

fn tc_legacy(args: &Value) -> String {
    let mut request = args.clone();
    request["module"] = "asia.dbt.thundercrypt.osgi.ThunderCryptModule".into();
    request.to_string()
}

/// A V2 failure without params.
fn tc_failure(code: &str) -> String {
    let quoted = serde_json::to_string(code).unwrap();
    let message = serde_json::to_string(&format!("Signing failed: {code}")).unwrap();
    format!(r#"{{"code":{quoted},"message":{message},"status":false}}"#)
}

/// The CMS of a successful V2 reply.
fn tc_cms(reply: &str) -> Vec<u8> {
    assert!(reply.starts_with(r#"{"body":{"result":""#), "{reply}");
    assert!(
        reply.ends_with(r#"","errorCode":"NONE"},"status":true}"#),
        "{reply}"
    );
    STANDARD
        .decode(body(reply)["result"].as_str().unwrap())
        .unwrap()
}

#[test]
fn thundercrypt_v2_success_body() {
    let harness = tc_harness(tc_steps(), vec![]);
    let reply = text(harness.call(THUNDERCRYPT, &tc_v2(&tc_args(TC_KEY, b"act")), None));
    let cms = tc_cms(&reply);
    let signers = oncl_pki::cms::verify(&cms, Some(b"act")).expect("the CMS verifies");
    assert!(signers[0].timestamp_token.is_some());
    assert!(!attached(&cms));
    assert_eq!(
        signed_attr(&cms, 0, "1.2.840.113549.1.9.77").unwrap(),
        vec![(0x0c, b"act.pdf".to_vec())]
    );
    assert_eq!(
        signed_attr(&cms, 0, "1.2.840.113549.1.9.13").unwrap(),
        vec![(0x0c, b"ESEDO".to_vec())]
    );
    let subject = der::Encode::to_der(
        oncl_port_tests::entry(TC_KEY)
            .cert
            .tbs_certificate()
            .subject(),
    )
    .unwrap();
    let dn = signed_attr(&cms, 0, "1.3.6.1.4.1.6801.2.8").unwrap();
    assert_eq!(dn[0].0, 0x30);
    assert_eq!(der_of(&dn[0]), subject);
    assert_eq!(
        signed_attr(&cms, 0, "1.3.6.1.5.5.7.48.1.1").unwrap()[0].0,
        0x04
    );
    assert!(signed_attr(&cms, 0, "1.2.840.113549.1.9.16.2.47").is_some());
    assert!(signed_attr(&cms, 0, "1.2.840.113549.1.9.5").is_some());
    let passwords = harness.prompter().password_prompts();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].title.as_deref(), Some("Подписание"));
    assert!(passwords[0].allow_empty);
    let log = harness.http_log();
    assert!(log[0].contains("ocsp.synthetic.test"), "{log:?}");
    assert!(
        log.contains(&"POST http://tsp.pki.gov.kz/".to_owned()),
        "{log:?}"
    );
}

/// The DER of a value TLV.
fn der_of((tag, content): &(u8, Vec<u8>)) -> Vec<u8> {
    let mut out = vec![*tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

#[test]
fn thundercrypt_non_string_method_drops() {
    let harness = tc_harness(vec![], vec![]);
    assert_eq!(
        harness.call(
            THUNDERCRYPT,
            r#"{"module":"asia.dbt.thundercrypt.osgi.ThunderCryptModule","method":5}"#,
            None
        ),
        Reply::Drop
    );
    assert_eq!(
        text(harness.call(
            THUNDERCRYPT,
            r#"{"module":"asia.dbt.thundercrypt.osgi.ThunderCryptModule","method":"x","args":{}}"#,
            None
        )),
        r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: x is not defined in SignNLClass","message":"General error.","status":false}"#
    );
    assert_eq!(
        text(harness.call(
            THUNDERCRYPT,
            r#"{"module":"asia.dbt.thundercrypt.osgi.ThunderCryptModule","method":"sign"}"#,
            None
        )),
        r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: sign demands arguments","message":"General error.","status":false}"#
    );
}

#[test]
fn thundercrypt_password_before_data_checks() {
    let harness = tc_harness(tc_steps(), vec![]);
    let mut args = tc_args(TC_KEY, b"act");
    args.as_object_mut().unwrap().remove("filesNames");
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_v2(&args), None)),
        tc_failure(r#""filesNames" argument could not be empty or NULL!"#)
    );
    assert_eq!(harness.prompter().password_prompts().len(), 1);
    assert_eq!(harness.prompter().confirm_prompts().len(), 1);
    assert!(harness.http_log().is_empty());
}

#[test]
fn thundercrypt_abort_on_cancel() {
    let harness = tc_harness(vec![Step::CancelPassword, Step::CancelPassword], vec![]);
    let args = tc_args(TC_KEY, b"act");
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_v2(&args), None)),
        tc_failure("ABORT")
    );
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_legacy(&args), None)),
        r#"{"errorCode":"ABORT"}"#
    );
    let harness = tc_harness(vec![], vec![]);
    let mut args = tc_args(TC_KEY, b"act");
    args.as_object_mut().unwrap().remove("keyType");
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_legacy(&args), None)),
        r#"{"errorCode":"JSONObject[\"keyType\"] not found."}"#
    );
}

#[test]
fn thundercrypt_files_names_empty_message() {
    let mut steps = tc_steps();
    steps.push(Step::Password(P12_PASSWORD.to_owned()));
    steps.push(Step::Password("wrong".to_owned()));
    let harness = tc_harness(steps, vec![]);
    let mut session = harness.session(THUNDERCRYPT);
    let mut args = tc_args(TC_KEY, b"act");
    args["filesNames"] = "".into();
    assert_eq!(
        text(session.call(&tc_v2(&args), None)),
        tc_failure(r#""filesNames" argument could not be empty or NULL!"#)
    );
    let mut args = tc_args(TC_KEY, b"act");
    args["dataForSign"] = "%%".into();
    assert_eq!(
        text(session.call(&tc_v2(&args), None)),
        tc_failure(r#""dataForSign" argument should use BASE64 format!"#)
    );
    assert_eq!(
        text(session.call(&tc_v2(&tc_args(TC_KEY, b"act")), None)),
        tc_failure("WRONG_PASSWORD")
    );
}

#[test]
fn thundercrypt_legacy_path_response_bean() {
    let mut steps = tc_steps();
    steps.push(Step::Password(P12_PASSWORD.to_owned()));
    let harness = tc_harness(steps, vec![]);
    let mut session = harness.session(THUNDERCRYPT);
    let mut args = tc_args(TC_KEY, b"act");
    args["skipCheckPermissions"] = true.into();
    let reply = text(session.call(&tc_legacy(&args), None));
    assert!(reply.starts_with(r#"{"result":""#), "{reply}");
    assert!(reply.ends_with(r#"","errorCode":"NONE"}"#), "{reply}");
    // An individual's certificate is not an employee's with the right to sign.
    assert_eq!(
        text(session.call(&tc_legacy(&tc_args(TC_KEY, b"act")), None)),
        r#"{"errorCode":"CERTIFICATE_NO_HAVE_PERM_FOR_SIGN"}"#
    );
    let harness = tc_harness(vec![], vec![]);
    let mut args = tc_args(TC_KEY, b"act");
    args["policies"] = serde_json::json!(["SIGN"]);
    args["skipCheckPermissions"] = true.into();
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_v2(&args), None)),
        r#"{"code":"INVALID_ARGUMENT","details":"{\"argument\":\"skipCheckPermissions,policies\"}","message":"Signing failed: INVALID_ARGUMENT","status":false}"#
    );
    let mut args = tc_args(TC_KEY, b"act");
    args["upgradeToLta"] = "true".into();
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_v2(&args), None)),
        r#"{"code":"INVALID_ARGUMENT","details":"{\"argument\":\"upgradeToLta\"}","message":"Signing failed: INVALID_ARGUMENT","status":false}"#
    );
    assert!(harness.prompter().password_prompts().is_empty());
}

#[test]
fn thundercrypt_tsp_timeout_code_and_details_order() {
    let harness = tc_harness(
        tc_steps(),
        vec![down("http://tsp.pki.gov.kz", HttpErrorKind::Timeout)],
    );
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_v2(&tc_args(TC_KEY, b"act")), None)),
        // `new JSONObject(map)` of three keys: a table of 4 buckets, `failure` (2) before
        // `address` and `detail` (3).
        r#"{"code":"TSP_TIMEOUT","details":"{\"failure\":\"TIMEOUT\",\"address\":\"http://tsp.pki.gov.kz/\",\"detail\":\"SocketTimeoutException: Read timed out\"}","message":"Signing failed: TSP_TIMEOUT at http://tsp.pki.gov.kz/","status":false}"#
    );
}

#[test]
fn thundercrypt_ocsp_down_is_remote_failure() {
    let harness = tc_harness(
        tc_steps(),
        vec![down(
            "http://ocsp.synthetic.test",
            HttpErrorKind::UnknownHost,
        )],
    );
    let reply = text(harness.call(THUNDERCRYPT, &tc_v2(&tc_args(TC_KEY, b"act")), None));
    assert!(
        reply.starts_with(r#"{"code":"UNKNOWN_OCSP_ADDRESS","details":"{\"failure\":\"DNS\",\"address\":\"http://ocsp.synthetic.test"#),
        "{reply}"
    );
}

#[test]
fn thundercrypt_clock_skew() {
    let tsa = oncl_pki::tsp::MockTsa::new(oncl_port_tests::entry("tsa-gost2015"))
        .with_gen_time(time::OffsetDateTime::now_utc() - time::Duration::minutes(10));
    let harness = tc_harness(
        tc_steps(),
        vec![(
            "http://tsp.pki.gov.kz".to_owned(),
            Arc::new(tsa) as Arc<dyn HttpTransport>,
        )],
    );
    let reply = text(harness.call(THUNDERCRYPT, &tc_v2(&tc_args(TC_KEY, b"act")), None));
    assert!(
        reply.starts_with(r#"{"code":"LOCAL_CLOCK_SKEW","#),
        "{reply}"
    );
}

#[test]
fn thundercrypt_revoked() {
    let ocsp = oncl_pki::ocsp::MockOcsp::new(oncl_port_tests::entry("ocsp-gost2015")).status(
        &serial_hex(TC_KEY),
        oncl_pki::ocsp::CertStatus::Revoked {
            time: time::OffsetDateTime::now_utc() - time::Duration::days(1),
            reason: Some(1),
        },
    );
    let harness = tc_harness(
        tc_steps(),
        vec![(
            "http://ocsp.synthetic.test".to_owned(),
            Arc::new(ocsp) as Arc<dyn HttpTransport>,
        )],
    );
    assert_eq!(
        text(harness.call(THUNDERCRYPT, &tc_v2(&tc_args(TC_KEY, b"act")), None)),
        tc_failure("CERTIFICATE_REVOKED")
    );
}

#[test]
fn thundercrypt_cert_policy_parse_and_eval() {
    let mut steps = tc_steps();
    for _ in 0..7 {
        steps.push(Step::Password(P12_PASSWORD.to_owned()));
    }
    let harness = tc_harness(steps, vec![]);
    let mut session = harness.session(THUNDERCRYPT);
    let mut call = |policy: Value| {
        let mut args = tc_args(TC_KEY, b"act");
        args["certPolicy"] = policy;
        text(session.call(&tc_v2(&args), None))
    };
    let failure = |code: &str, policy: &str| {
        let details = serde_json::json!({ "policy": policy }).to_string();
        format!(
            r#"{{"code":"{code}","details":{},"message":"Signing failed: {code}","status":false}}"#,
            serde_json::to_string(&details).unwrap()
        )
    };
    assert_eq!(
        call(serde_json::json!({"type": "foo"})),
        failure("INVALID_POLICY", "Unsupported certPolicy type: foo")
    );
    assert_eq!(
        call(serde_json::json!(5)),
        failure("INVALID_POLICY", "certPolicy must be a JSON object")
    );
    let mut deep = serde_json::json!({"type": "purpose", "value": "SIGN"});
    for _ in 0..10 {
        deep = serde_json::json!({"type": "not", "condition": deep});
    }
    assert_eq!(
        call(deep),
        failure("INVALID_POLICY", "Policy tree exceeds maximum depth of 10")
    );
    assert_eq!(
        call(serde_json::json!({"type": "eku", "value": "BOSS"})),
        failure("INVALID_POLICY", "Unsupported value 'BOSS' for eku")
    );
    assert!(harness.http_log().is_empty(), "parsed before signing");
    assert_eq!(
        call(serde_json::json!({"type": "eku", "value": "EMPLOYEE"})),
        failure(
            "CERTIFICATE_NO_HAVE_PERM_FOR_SIGN",
            "Certificate policy check failed: eku EMPLOYEE: certificate does not have required extended key usage"
        )
    );
    assert_eq!(
        call(serde_json::json!({"type": "and", "conditions": [
            {"type": "purpose", "value": "SIGN"},
            {"type": "not", "condition": {"type": "eku", "value": "PERSON"}},
        ]})),
        failure(
            "CERTIFICATE_POLICY_FAILED",
            "Certificate policy check failed: and[2/2]: not: certificate unexpectedly matches eku PERSON"
        )
    );
    let ok = call(serde_json::json!({"type": "or", "conditions": [
        {"type": "eku", "value": "EMPLOYEE"},
        {"type": "key_usage", "value": "NON_REPUDIATION_PERMISSION_INDEX"},
    ]}));
    tc_cms(&ok);
}

#[test]
fn thundercrypt_lta_upgrade_structure() {
    let harness = tc_harness(tc_steps(), vec![]);
    let mut args = tc_args(TC_KEY, b"act");
    args["upgradeToLta"] = true.into();
    let cms = tc_cms(&text(harness.call(THUNDERCRYPT, &tc_v2(&args), None)));
    oncl_pki::cms::verify(&cms, Some(b"act")).expect("the CMS still verifies");
    let parts = signed_data(&cms);
    // certificates: the signer and its chain.
    let certs = parts.iter().find(|(t, _)| *t == 0xa0).unwrap();
    assert!(tlvs(certs.1).len() >= 3, "signer, intermediate and root");
    // crls: the OCSP answer as id-ri-ocsp-response, and the CRL.
    let crls = tlvs(parts.iter().find(|(t, _)| *t == 0xa1).unwrap().1);
    let other: Vec<_> = crls.iter().filter(|(t, _)| *t == 0xa1).collect();
    assert_eq!(other.len(), 1);
    assert_eq!(tlvs(other[0].1)[0].1, &oid("1.3.6.1.5.5.7.16.2")[..]);
    assert!(crls.iter().any(|(t, _)| *t == 0x30), "a CRL");

    let infos = signer_infos(&cms);
    let unsigned = attributes(&infos[0], 0xa1);
    let (_, values) = unsigned
        .iter()
        .find(|(o, _)| *o == oid("0.4.0.1733.2.4"))
        .expect("an archive-time-stamp-v3");
    let token = der_of(&(values[0].0, values[0].1.to_vec()));
    let token_infos = signer_infos(&token);
    let (_, index) = attributes(&token_infos[0], 0xa1)
        .into_iter()
        .find(|(o, _)| *o == oid("0.4.0.19122.1.5"))
        .expect("an ats-hash-index-v3");
    let index = der_of(&(index[0].0, index[0].1.to_vec()));
    // hashIndAlgorithm: GOST 34.11-2015 (512).
    assert_eq!(tlvs(inner(&index))[0].1, &oid_tlv("1.2.398.3.10.1.3.3")[..]);

    // The imprint: eContentType, the content's hash, the signer's fields up to its
    // signature, the index.
    let encap = tlvs(parts[2].1);
    let mut input = der_of(&(encap[0].0, encap[0].1.to_vec()));
    input.extend_from_slice(&oncl_gost::streebog512(b"act"));
    for (tag, content) in infos[0].iter().filter(|(t, _)| *t != 0xa1) {
        input.extend(der_of(&(*tag, content.to_vec())));
    }
    input.extend_from_slice(&index);
    let tst_info = {
        let token_parts = signed_data(&token);
        let econtent = tlvs(tlvs(token_parts[2].1)[1].1)[0].1;
        tlvs(inner(econtent))
    };
    let imprint = tlvs(tst_info[2].1);
    assert_eq!(imprint[1].1, &oncl_gost::streebog512(&input)[..]);
}

/// The DER of a dotted OID (tag and length included).
fn oid_tlv(dotted: &str) -> Vec<u8> {
    der_of(&(0x06, oid(dotted)))
}
