//! The ports of the original's `commonUtils` clones: rating1c, xdox, eot (and the rest of
//! the family as they land), run with scripted dialogs and the mock PKI services.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_basics::testing::Step;
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::info::{cert_info, common_name, kalkan_dn};
use oncl_pki::key::HashAlg;
use oncl_pki::ocsp::MockOcsp;
use oncl_port_tests::{Harness, entry, p12};
use oncl_protocol::Reply;
use oncl_protocol::orgjson::{JObject, JValue};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------------------
// Helpers.

/// The storage dialog answered with the synthetic key store `name`.
fn storage(name: &str) -> Step {
    let (path, password) = p12(name);
    Step::Storage {
        path,
        password: password.to_owned(),
    }
}

/// The storage dialog answered with `name`, then its first key picked.
fn key(name: &str) -> Vec<Step> {
    vec![storage(name), Step::Key(0)]
}

/// A request of the reflective dispatcher.
fn call(method: &str, args: Value) -> String {
    json!({"module": "m", "method": method, "args": args}).to_string()
}

/// The text of a reply that is not a dropped connection.
fn text(reply: Reply) -> String {
    match reply {
        Reply::Text(text) => text,
        Reply::Drop => panic!("the connection was dropped"),
    }
}

fn parse(reply: &str) -> Value {
    serde_json::from_str(reply).unwrap_or_else(|e| panic!("{e}: {reply}"))
}

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn unb64(text: &str) -> Vec<u8> {
    STANDARD
        .decode(text)
        .unwrap_or_else(|e| panic!("{e}: {text}"))
}

fn der_of(cert: &x509_cert::Certificate) -> Vec<u8> {
    cert.to_der().unwrap()
}

/// A DER TLV: its tag, its content and what follows it.
fn tlv(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = bytes[0];
    let (len, header) = match bytes[1] {
        n if n < 0x80 => (usize::from(n), 2),
        n => {
            let count = usize::from(n & 0x7f);
            let len = bytes[2..2 + count]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
            (len, 2 + count)
        }
    };
    (tag, &bytes[header..header + len], &bytes[header + len..])
}

/// The TLVs in `content`: each tag, content and whole encoding.
fn children(mut content: &[u8]) -> Vec<(u8, &[u8], &[u8])> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tag, inner, rest) = tlv(content);
        out.push((tag, inner, &content[..content.len() - rest.len()]));
        content = rest;
    }
    out
}

/// An attribute: its dotted OID and the DER of its values.
type Attribute = (String, Vec<Vec<u8>>);

fn attributes(set: &[u8]) -> Vec<Attribute> {
    children(set)
        .into_iter()
        .map(|(_, attr, _)| {
            let parts = children(attr);
            let oid = der::asn1::ObjectIdentifier::from_bytes(parts[0].1)
                .unwrap()
                .to_string();
            let values = children(parts[1].1)
                .into_iter()
                .map(|(_, _, whole)| whole.to_vec())
                .collect();
            (oid, values)
        })
        .collect()
}

/// What a CMS holds: whether it has eContent, and each signer's signed and unsigned
/// attributes.
struct CmsView {
    econtent: Option<Vec<u8>>,
    signers: Vec<(Vec<Attribute>, Vec<Attribute>)>,
}

fn cms_view(cms: &[u8]) -> CmsView {
    let (_, content_info, _) = tlv(cms);
    let parts = children(content_info);
    assert_eq!(parts[1].0, 0xa0, "ContentInfo [0] content");
    let signed_data = children(tlv(parts[1].1).1);
    let encap = children(signed_data[2].1);
    let econtent = encap.get(1).map(|(_, octets, _)| tlv(octets).1.to_vec());
    let signer_infos = signed_data.last().unwrap().1;
    let signers = children(signer_infos)
        .into_iter()
        .map(|(_, info, _)| {
            let parts = children(info);
            let signed = parts
                .iter()
                .find(|(tag, _, _)| *tag == 0xa0)
                .map(|(_, set, _)| attributes(set))
                .unwrap_or_default();
            let unsigned = parts
                .iter()
                .find(|(tag, _, _)| *tag == 0xa1)
                .map(|(_, set, _)| attributes(set))
                .unwrap_or_default();
            (signed, unsigned)
        })
        .collect();
    CmsView { econtent, signers }
}

fn attribute<'a>(attrs: &'a [Attribute], oid: &str) -> Option<&'a [u8]> {
    attrs
        .iter()
        .find(|(o, _)| o == oid)
        .map(|(_, values)| values[0].as_slice())
}

const TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

/// Replies with `status` and `body` to any request.
struct Fixed {
    status: u16,
    body: Vec<u8>,
}

impl HttpTransport for Fixed {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Ok(HttpReply {
            status: self.status,
            content_type: Some("application/ocsp-response".to_owned()),
            location: None,
            body: self.body.clone(),
        })
    }
}

/// Passes requests to `inner`, recording their bodies.
struct Recorder {
    inner: Arc<dyn HttpTransport>,
    bodies: Mutex<Vec<(String, Vec<u8>)>>,
}

impl HttpTransport for Recorder {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.bodies
            .lock()
            .unwrap()
            .push((request.url.to_owned(), request.body.to_vec()));
        self.inner.send(request)
    }
}

// ---------------------------------------------------------------------------------------
// rating1c

const R1C: &str = "rating1c";

fn r1c(steps: Vec<Step>, method: &str, args: Value) -> String {
    text(Harness::new(steps, vec![]).call(R1C, &call(method, args), None))
}

#[test]
fn rating1c_no_such_method_texts() {
    let h = Harness::new(vec![], vec![]);
    let reply = |request: &str| text(h.call(R1C, request, None));
    assert_eq!(
        reply(&call("nope", json!([]))),
        r#"{"code":"500","message":"NoSuchMethodException nope"}"#
    );
    assert_eq!(
        reply(&call("", json!([]))),
        r#"{"code":"500","message":"NoSuchMethodException "}"#
    );
    assert_eq!(
        reply(r#"{"args":[]}"#),
        r#"{"code":"500","message":"JSONObject[\"method\"] not found."}"#
    );
    assert_eq!(
        reply("x"),
        r#"{"code":"500","message":"A JSONObject text must begin with '{' at 1 [character 2 line 1]"}"#
    );
    // A method is found by name and number of arguments.
    assert_eq!(
        reply(&call("getKeyInfo", json!([]))),
        r#"{"code":"500","message":"NoSuchMethodException getKeyInfo"}"#
    );
}

#[test]
fn rating1c_private_method_access_text() {
    let h = Harness::new(vec![], vec![]);
    let reply = |method: &str, args: Value| text(h.call(R1C, &call(method, args), None));
    assert_eq!(
        reply("saveKey", json!(["a", "b"])),
        r#"{"code":"500","message":"java.lang.IllegalAccessException: Class kz.rating1c.edo.NCALayerCommonActivator can not access a member of class kz.rating1c.edo.SignUtils with modifiers \"private\". Method: saveKey"}"#
    );
    assert_eq!(
        reply("setKeyInfoServices", json!(["x"])),
        r#"{"code":"500","message":"java.lang.IllegalArgumentException: argument type mismatch. Method: setKeyInfoServices"}"#
    );
    assert_eq!(
        reply("getJson", json!([["x"]])),
        r#"{"code":"500","message":"JSONArray[0] is not a int."}"#
    );
    assert_eq!(
        reply("TestKeyOwner", json!(["PKCS12", 1, ""])),
        r#"{"code":"500","message":"java.lang.IllegalArgumentException: argument type mismatch. Method: TestKeyOwner"}"#
    );
}

/// The module's `KeyInfo` of the synthetic key `name`, in the bean's field order.
fn rating1c_key_info(name: &str) -> JObject {
    let e = entry(name);
    let info = cert_info(&e.cert);
    let tbs = e.cert.tbs_certificate();
    let ms = |t: time::OffsetDateTime| (t.unix_timestamp_nanos() / 1_000_000) as i64;
    let almaty = |t: time::OffsetDateTime| {
        let local = t.to_offset(time::UtcOffset::from_hms(5, 0, 0).unwrap());
        format!(
            "{:02}.{:02}.{} ({:02}:{:02})",
            local.day(),
            u8::from(local.month()),
            local.year(),
            local.hour(),
            local.minute()
        )
    };
    let mut bean = JObject::hash_map();
    bean.put("alias", e.alias.as_str());
    bean.put_opt("keyId", oncl_pki::info::ski_hex(&e.cert));
    bean.put("algorithm", "ECGOST3410-2015");
    bean.put_opt("subjectCn", info.subject_cn.clone());
    bean.put(
        "subjectDn",
        "C=KZ, SERIALNUMBER=IIN123456789011, GIVENNAME=ТЕСТОВИЧ, SURNAME=ТЕСТОВ, CN=ТЕСТОВ ТЕСТ",
    );
    bean.put("serial", info.serial_hex.as_str());
    bean.put("serialNumber", info.serial_hex.as_str());
    bean.put_opt("issuerCn", common_name(tbs.issuer()));
    bean.put("issuerdn", kalkan_dn(tbs.issuer()));
    bean.put("certNotAfter", ms(info.not_after).to_string());
    bean.put("certNotBefore", ms(info.not_before).to_string());
    bean.put("datefrom", almaty(info.not_after));
    bean.put("dateto", almaty(info.not_before));
    bean.put_opt("authorityKeyIdentifier", oncl_pki::info::aki_hex(&e.cert));
    bean.put(
        "pem",
        oncl_pki::pem::encode("CERTIFICATE", &der_of(&e.cert)),
    );
    bean
}

#[test]
fn rating1c_get_key_info_bytes() {
    let h = Harness::new(key("user-gost2015-sign"), vec![]);
    let reply = text(h.call(R1C, &call("getKeyInfo", json!(["PKCS12"])), None));
    let mut expected = JObject::hash_map();
    expected.put("code", "200");
    expected.put(
        "responseObject",
        JValue::Obj(rating1c_key_info("user-gost2015-sign")),
    );
    assert_eq!(reply, expected.to_json());
    // The fifteen keys in Java's HashMap order (32 buckets): the swapped dates included.
    let keys: Vec<String> = parse(&reply)["responseObject"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(keys.len(), 15, "{reply}");
    assert!(h.http_log().is_empty());
    assert_eq!(
        r1c(vec![Step::CancelStorage], "getKeyInfo", json!(["PKCS12"])),
        r#"{"code":"500","message":"action.canceled"}"#
    );
    for (storage, message) in [
        ("", "storageName.param.empty"),
        ("pkcs12", "storage.unknown"),
        ("AKKaztokenStore", "storage.empty"),
    ] {
        assert_eq!(
            r1c(vec![], "getKeyInfo", json!([storage])),
            format!(r#"{{"code":"500","message":"{message}"}}"#)
        );
    }
}

#[test]
fn rating1c_test_key_owner_bin_mismatch() {
    let owner = |name: &str, bin: &str| {
        parse(&r1c(
            key(name),
            "TestKeyOwner",
            json!(["PKCS12", "SIGNATURE", bin]),
        ))
    };
    let legal = owner("legal-gost2015-sign", "123456789021");
    assert_eq!(legal["code"], "200");
    assert_eq!(legal["message"], "IsKeysValid result: true. ");
    let other = owner("legal-gost2015-sign", "000000000000");
    assert_eq!(
        other["message"],
        "IsKeysValid result: false.  Ключ не принадлежит указанному БИН"
    );
    // An individual's key compares its IIN.
    let person = owner("user-gost2015-sign", "123456789011");
    assert_eq!(person["message"], "IsKeysValid result: true. ");
    assert_eq!(
        person["responseObject"]["serial"],
        person["responseObject"]["serialNumber"]
    );
    let expired = owner("expired-gost2015-sign", "");
    assert_eq!(
        expired["message"],
        "IsKeysValid result: false.  Срок действия сертификата истек"
    );
}

#[test]
fn rating1c_test_key_owner_cancel_is_500() {
    assert_eq!(
        r1c(
            vec![Step::CancelStorage],
            "TestKeyOwner",
            json!(["PKCS12", "", ""])
        ),
        r#"{"code":"500"}"#
    );
    assert_eq!(
        r1c(
            vec![storage("user-gost2015-sign"), Step::CancelKey],
            "TestKeyOwner",
            json!(["PKCS12", "", ""])
        ),
        r#"{"code":"500"}"#
    );
}

#[test]
fn rating1c_sign_xml_six_args() {
    let xml = "<a><b Id=\"x\">1</b></a>";
    let reply = parse(&r1c(
        key("user-gost2015-sign"),
        "signXml",
        json!(["PKCS12", "SIGNATURE", xml, "", "", ""]),
    ));
    assert_eq!(reply["code"], "200", "{reply}");
    let signed = reply["responseObject"].as_str().unwrap();
    assert_eq!(
        oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap().len(),
        1
    );
    // The BIN check fails before signing: the message lists the failure.
    assert_eq!(
        r1c(
            key("user-gost2015-sign"),
            "signXml",
            json!(["PKCS12", "SIGNATURE", xml, "", "", "000000000000"])
        ),
        r#"{"code":"500","message":"action.canceled. Ключ не принадлежит указанному БИН"}"#
    );
    let many = parse(&r1c(
        key("user-gost2015-sign"),
        "signXmls",
        json!(["PKCS12", "SIGNATURE", [xml, "<c/>"], "", "", ""]),
    ));
    assert_eq!(many["responseObject"].as_array().unwrap().len(), 2);
}

#[test]
fn rating1c_five_args_no_such_method() {
    assert_eq!(
        r1c(
            vec![],
            "signXml",
            json!(["PKCS12", "SIGNATURE", "<a/>", "", ""])
        ),
        r#"{"code":"500","message":"NoSuchMethodException signXml"}"#
    );
}

#[test]
fn rating1c_create_cms_with_and_without_tsa() {
    let h = Harness::new(key("user-gost2015-sign"), vec![]);
    let reply = parse(&text(h.call(
        R1C,
        &call(
            "createCmsFromBase64",
            json!(["PKCS12", "SIGNATURE", b64(b"hello"), true, true, ""]),
        ),
        None,
    )));
    assert_eq!(reply["code"], "200", "{reply}");
    let cms = unb64(reply["responseObject"].as_str().unwrap());
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert!(signers[0].timestamp_token.is_some());
    let log = h.http_log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(log[0].starts_with("GET http://tsp.pki.gov.kz/"), "{log:?}");

    let h = Harness::new(key("user-gost2015-sign"), vec![]);
    let reply = parse(&text(h.call(
        R1C,
        &call(
            "createCmsFromBase64",
            json!(["PKCS12", "SIGNATURE", b64(b"hello"), false, false, ""]),
        ),
        None,
    )));
    let cms = unb64(reply["responseObject"].as_str().unwrap());
    let signers = oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    assert!(signers[0].timestamp_token.is_none());
    assert!(cms_view(&cms).econtent.is_none());
    assert!(h.http_log().is_empty());

    // Java's decoder, after the dialogs.
    assert_eq!(
        r1c(
            key("user-gost2015-sign"),
            "createCmsFromBase64",
            json!(["PKCS12", "SIGNATURE", "a b", true, false, ""])
        ),
        r#"{"code":"500","message":"Illegal base64 character 20"}"#
    );
    let many = parse(&r1c(
        key("user-gost2015-sign"),
        "createCmsesFromBase64",
        json!([
            "PKCS12",
            "SIGNATURE",
            [b64(b"a"), b64(b"b")],
            true,
            false,
            ""
        ]),
    ));
    assert_eq!(many["responseObject"].as_array().unwrap().len(), 2);
}

/// `KeyInfo.toString()` of the synthetic key `name`.
fn lombok(name: &str) -> String {
    let e = entry(name);
    let info = cert_info(&e.cert);
    let tbs = e.cert.tbs_certificate();
    let ms = |t: time::OffsetDateTime| (t.unix_timestamp_nanos() / 1_000_000) as i64;
    format!(
        "KeyInfo(alias={}, keyId={}, algorithm=ECGOST3410-2015, subjectCn={}, subjectDn=C=KZ, \
         SERIALNUMBER=IIN123456789011, GIVENNAME=ТЕСТОВИЧ, SURNAME=ТЕСТОВ, CN=ТЕСТОВ ТЕСТ, \
         issuerCn={}, issuerDn=, serialNumber={}, certNotAfter={}, certNotBefore={}, \
         authorityKeyIdentifier={}, pem={})",
        e.alias,
        oncl_pki::info::ski_hex(&e.cert).unwrap(),
        info.subject_cn.unwrap(),
        common_name(tbs.issuer()).unwrap(),
        info.serial_hex,
        ms(info.not_after),
        ms(info.not_before),
        oncl_pki::info::aki_hex(&e.cert).unwrap(),
        oncl_pki::pem::encode("CERTIFICATE", &der_of(&e.cert)),
    )
}

#[test]
fn rating1c_raw_sign_lombok_signer_cert() {
    let reply = parse(&r1c(
        key("user-gost2015-sign"),
        "createRawSignFromBase64",
        json!(["PKCS12", "SIGNATURE", b64(b"hello"), ""]),
    ));
    assert_eq!(reply["code"], "200", "{reply}");
    let object = &reply["responseObject"];
    assert_eq!(object["signerCert"], lombok("user-gost2015-sign"));
    // GOST 34.10-2015 (512): r and s of 64 bytes each.
    assert_eq!(unb64(object["signResult"].as_str().unwrap()).len(), 128);
}

#[test]
fn rating1c_raws_array_as_string() {
    let reply = parse(&r1c(
        key("user-gost2015-sign"),
        "createRawsSignFromBase64",
        json!(["PKCS12", "SIGNATURE", [b64(b"a"), b64(b"b")], ""]),
    ));
    let text = reply["responseObject"]["signResult"].as_str().unwrap();
    assert!(text.starts_with("[\""), "{text}");
    let array = parse(text);
    assert_eq!(array.as_array().unwrap().len(), 2);
}

#[test]
fn rating1c_uuid_echo_reorders() {
    let h = Harness::new(vec![], vec![]);
    let request = json!({"method": "TestConnect", "args": [], "uuid": 12}).to_string();
    let mut expected = JObject::hash_map();
    expected.put("responseObject", "Plugin connected successfully: 1.6.");
    expected.put("code", "200");
    expected.put("uuid", "12");
    assert_eq!(text(h.call(R1C, &request, None)), expected.to_json());
    assert_eq!(
        text(h.call(R1C, &call("TestConnect", json!([])), None)),
        r#"{"responseObject":"Plugin connected successfully: 1.6.","code":"200"}"#
    );
    // Errors of the dispatcher carry no uuid.
    let request = json!({"method": "nope", "uuid": "u"}).to_string();
    assert_eq!(
        text(h.call(R1C, &request, None)),
        r#"{"code":"500","message":"NoSuchMethodException nope"}"#
    );
    assert_eq!(
        text(h.call(R1C, &call("getActiveTokens", json!([])), None)),
        r#"{"responseObject":[],"code":"200"}"#
    );
}

// ---------------------------------------------------------------------------------------
// xdox

const XDOX: &str = "xdox";
const XDOX_ORIGIN: Option<&str> = Some("https://xdox.kz");

fn xdox_request(method: &str, params: Value) -> String {
    json!({"method": method, "params": params}).to_string()
}

#[test]
fn xdox_origin_substring_check() {
    let h = Harness::new(vec![], vec![]);
    let request = xdox_request("nope", json!({"storageName": "PKCS12"}));
    let refused = r#"{"success":false,"errorCode":"unknown_exception","message":"That module can be used only on https://xdox.kz"}"#;
    assert_eq!(
        text(h.call(XDOX, &request, Some("https://example.com"))),
        refused
    );
    assert_eq!(text(h.call(XDOX, &request, None)), refused);
    // Not anchored: any origin containing the text passes.
    assert_eq!(
        text(h.call(XDOX, &request, Some("https://evilxdox.kz.example"))),
        r#"{"success":false,"errorCode":"method_not_defined"}"#
    );
}

#[test]
fn xdox_missing_params_drops() {
    let h = Harness::new(vec![], vec![]);
    for request in [
        "x".to_owned(),
        json!({"method": "createCms"}).to_string(),
        json!({"method": "createCms", "params": "p"}).to_string(),
        xdox_request("createCms", json!({})),
        xdox_request("createCms", json!({"storageName": 1})),
    ] {
        assert_eq!(
            h.call(XDOX, &request, XDOX_ORIGIN),
            Reply::Drop,
            "{request}"
        );
    }
}

/// CREATECMS with the synthetic key `name`: the reply and the HTTP log.
fn xdox_create(name: &str, manifest: &str) -> (Value, Vec<String>) {
    let h = Harness::new(key(name), vec![]);
    let request = xdox_request(
        "createCms",
        json!({"storageName": "PKCS12", "ncaManifest": manifest}),
    );
    let reply = text(h.call(XDOX, &request, XDOX_ORIGIN));
    (parse(&reply), h.http_log())
}

#[test]
fn xdox_createcms_attached_kalkan_tsa() {
    let h = Harness::new(key("user-gost2015-sign"), vec![]);
    let request = xdox_request(
        "CreateCMS",
        json!({"storageName": "PKCS12", "ncaManifest": "{\"doc\":1}"}),
    );
    let reply = text(h.call(XDOX, &request, XDOX_ORIGIN));
    assert!(
        reply.starts_with(r#"{"success":true,"code":"200","responseObject":""#),
        "{reply}"
    );
    let cms = unb64(parse(&reply)["responseObject"].as_str().unwrap());
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert!(signers[0].timestamp_token.is_some());
    assert_eq!(cms_view(&cms).econtent.unwrap(), b"{\"doc\":1}");
    let log = h.http_log();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("GET http://tsp.pki.gov.kz/"), "{log:?}");
    // One key dialog.
    let prompts = h.prompter().key_prompts();
    assert_eq!(prompts.len(), 1);
}

#[test]
fn xdox_cancel_misplaced_key() {
    let h = Harness::new(vec![Step::CancelStorage], vec![]);
    let request = xdox_request("createCms", json!({"storageName": "PKCS12"}));
    assert_eq!(
        text(h.call(XDOX, &request, XDOX_ORIGIN)),
        r#"{"success":false,"errorCode":"unknown_exception","message":"Misplaced key."}"#
    );
    // No token is connected: StorageInfo's message.
    let h = Harness::new(vec![], vec![]);
    let request = xdox_request("createCms", json!({"storageName": "AKKZIDCardStore"}));
    assert_eq!(
        text(h.call(XDOX, &request, XDOX_ORIGIN)),
        r#"{"success":false,"errorCode":"unknown_exception","message":"storage.empty"}"#
    );
    // The manifest is read after the dialogs, inside the method's try.
    let h = Harness::new(key("user-gost2015-sign"), vec![]);
    let request = xdox_request("createCms", json!({"storageName": "garbage"}));
    assert_eq!(
        text(h.call(XDOX, &request, XDOX_ORIGIN)),
        r#"{"success":false,"errorCode":"unknown_exception","message":"JSONObject[\"ncaManifest\"] not found."}"#
    );
}

#[test]
fn xdox_add_signer_keeps_old_signers_detached() {
    let manifest = "{\"doc\":2}";
    let (first, _) = xdox_create("user-gost2015-sign", manifest);
    let old = first["responseObject"].as_str().unwrap().to_owned();
    let h = Harness::new(key("user-rsa-sign"), vec![]);
    let request = xdox_request(
        "addSignerToCms",
        json!({"storageName": "PKCS12", "ncaManifest": manifest, "cms": old}),
    );
    let reply = parse(&text(h.call(XDOX, &request, XDOX_ORIGIN)));
    assert_eq!(reply["success"], true, "{reply}");
    let cms = unb64(reply["responseObject"].as_str().unwrap());
    let view = cms_view(&cms);
    assert!(view.econtent.is_none(), "the output is detached");
    assert_eq!(view.signers.len(), 2);
    // Both signers keep (or get) their time-stamp; only the new one is stamped here.
    for (_, unsigned) in &view.signers {
        assert!(attribute(unsigned, TIMESTAMP_TOKEN).is_some());
    }
    assert_eq!(h.http_log().len(), 1);
    let signers = oncl_pki::cms::verify(&cms, Some(manifest.as_bytes())).unwrap();
    assert_eq!(signers.len(), 2);
    // Missing fields of ADDSIGNERTOCMS are read outside the try: the connection drops.
    let h = Harness::new(key("user-rsa-sign"), vec![]);
    let request = xdox_request(
        "addSignerToCms",
        json!({"storageName": "PKCS12", "ncaManifest": "m"}),
    );
    assert_eq!(h.call(XDOX, &request, XDOX_ORIGIN), Reply::Drop);
}

#[test]
fn xdox_add_signer_gost2015_unknown_algorithm() {
    let (first, _) = xdox_create("user-rsa-sign", "m");
    let h = Harness::new(key("user-gost2015-sign"), vec![]);
    let request = xdox_request(
        "ADDSIGNERTOCMS",
        json!({"storageName": "PKCS12", "ncaManifest": "m", "cms": first["responseObject"]}),
    );
    assert_eq!(
        text(h.call(XDOX, &request, XDOX_ORIGIN)),
        r#"{"success":false,"errorCode":"unknown_exception","message":"UNKNOWN_ALGORITHM"}"#
    );
    assert!(h.http_log().is_empty());
}

#[test]
fn xdox_unknown_method() {
    let h = Harness::new(vec![], vec![]);
    for method in ["", "sign"] {
        let request = xdox_request(method, json!({"storageName": "PKCS12"}));
        assert_eq!(
            text(h.call(XDOX, &request, XDOX_ORIGIN)),
            r#"{"success":false,"errorCode":"method_not_defined"}"#
        );
    }
    assert!(h.prompter().storage_prompts().is_empty());
}

// ---------------------------------------------------------------------------------------
// eot

const EOT: &str = "eot";

fn eot_sign(
    steps: Vec<Step>,
    extra: Vec<(String, Arc<dyn HttpTransport>)>,
    data: &str,
    flag: bool,
    names: &str,
) -> (Harness, String) {
    let h = Harness::new(steps, extra);
    let reply = text(h.call(
        EOT,
        &call(
            "signCmsWithSignedAttrs",
            json!(["PKCS12", "SIGNATURE", data, flag, names]),
        ),
        None,
    ));
    (h, reply)
}

#[test]
fn eot_cms_attrs_and_detached() {
    let document = b"the document";
    let digest = HashAlg::Sha256.digest(document);
    let (h, reply) = eot_sign(
        key("user-rsa-sign"),
        vec![],
        &b64(&digest),
        true,
        " a.pdf <> b.pdf ",
    );
    let parsed = parse(&reply);
    assert_eq!(parsed["code"], "200", "{reply}");
    assert_eq!(
        reply,
        format!(
            r#"{{"responseObject":"{}","code":"200"}}"#,
            parsed["responseObject"].as_str().unwrap()
        )
    );
    let cms = unb64(parsed["responseObject"].as_str().unwrap());
    // Detached; messageDigest is the page's bytes, so the CMS verifies over the document.
    let view = cms_view(&cms);
    assert!(view.econtent.is_none());
    oncl_pki::cms::verify(&cms, Some(document)).unwrap();
    let (signed, unsigned) = &view.signers[0];
    let octets = |bytes: &[u8]| [&[0x04, bytes.len() as u8][..], bytes].concat();
    assert_eq!(
        attribute(signed, "1.2.840.113549.1.9.4").unwrap(),
        octets(&digest)
    );
    let names = attribute(signed, "1.2.840.113549.1.9.77").unwrap();
    assert_eq!(names, [&[0x0c, 12][..], b"a.pdf<>b.pdf"].concat());
    assert_eq!(
        attribute(signed, "1.2.840.113549.1.9.13").unwrap(),
        b"\x13\x05ESEDO"
    );
    let ocsp = attribute(signed, "1.3.6.1.5.5.7.48.1.1").unwrap();
    // OCTET STRING { BasicOCSPResponse }: a SEQUENCE whose first element is tbsResponseData.
    let (tag, basic, _) = tlv(ocsp);
    assert_eq!(tag, 0x04);
    assert_eq!(tlv(basic).0, 0x30);
    assert_eq!(tlv(children(tlv(basic).1)[0].2).0, 0x30);
    let e = entry("user-rsa-sign");
    assert_eq!(
        attribute(signed, "1.3.6.1.4.1.6801.2.8").unwrap(),
        der_of_name(&e.cert)
    );
    assert_eq!(
        attribute(signed, "1.2.840.113549.1.9.5").unwrap()[0],
        0x17,
        "UTCTime"
    );
    assert!(attribute(signed, "1.2.840.113549.1.9.3").is_some());
    assert!(attribute(signed, "1.2.840.113549.1.9.16.2.47").is_some());
    assert!(attribute(unsigned, TIMESTAMP_TOKEN).is_some());
    let log = h.http_log();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(
        log[0].starts_with("POST http://ocsp.pki.gov.kz/"),
        "{log:?}"
    );
    assert!(log[1].starts_with("GET http://tsp.pki.gov.kz/"), "{log:?}");
    // No names: an empty UTF8String.
    let (_, reply) = eot_sign(key("user-rsa-sign"), vec![], &b64(&digest), true, "");
    let cms = unb64(parse(&reply)["responseObject"].as_str().unwrap());
    let view = cms_view(&cms);
    assert_eq!(
        attribute(&view.signers[0].0, "1.2.840.113549.1.9.77").unwrap(),
        [0x0c, 0]
    );
}

/// The subject of `cert`, DER: the 6801.2.8 value Kalkan's DN text gives back for the
/// synthetic certificates.
fn der_of_name(cert: &x509_cert::Certificate) -> Vec<u8> {
    cert.tbs_certificate().subject().to_der().unwrap()
}

#[test]
fn eot_flag_ignored() {
    let digest = HashAlg::Streebog512.digest(b"doc");
    for flag in [true, false] {
        let (_, reply) = eot_sign(key("user-gost2015-sign"), vec![], &b64(&digest), flag, "x");
        let cms = unb64(parse(&reply)["responseObject"].as_str().unwrap());
        assert!(cms_view(&cms).econtent.is_none(), "flag {flag}");
        oncl_pki::cms::verify(&cms, Some(b"doc")).unwrap();
    }
}

#[test]
fn eot_ocsp_post_with_path_request() {
    let recorder = Arc::new(Recorder {
        inner: Arc::new(MockOcsp::new(entry("ocsp-gost2015"))),
        bodies: Mutex::new(Vec::new()),
    });
    let route: Arc<dyn HttpTransport> = recorder.clone();
    let digest = HashAlg::Streebog512.digest(b"doc");
    let (_, reply) = eot_sign(
        key("user-gost2015-sign"),
        vec![("http://ocsp.pki.gov.kz".to_owned(), route)],
        &b64(&digest),
        false,
        "x",
    );
    assert_eq!(parse(&reply)["code"], "200", "{reply}");
    let bodies = recorder.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    let (url, body) = &bodies[0];
    // The request in the path (percent-encoded base64) and as the body.
    let path = url.strip_prefix("http://ocsp.pki.gov.kz/").unwrap();
    let decoded = path
        .replace("%2B", "+")
        .replace("%2F", "/")
        .replace("%3D", "=");
    assert_eq!(unb64(&decoded), *body);
    // CertID with SHA-1 (its AlgorithmIdentifier first), and an 8-byte nonce.
    let sha1 = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
    assert!(body.windows(sha1.len()).any(|w| w == sha1));
}

#[test]
fn eot_ocsp_failure_text() {
    let malformed: Arc<dyn HttpTransport> = Arc::new(Fixed {
        status: 200,
        body: vec![0x30, 0x03, 0x0a, 0x01, 0x01],
    });
    let digest = HashAlg::Streebog512.digest(b"doc");
    let (h, reply) = eot_sign(
        key("user-gost2015-sign"),
        vec![("http://ocsp.pki.gov.kz".to_owned(), malformed)],
        &b64(&digest),
        false,
        "x",
    );
    assert_eq!(
        reply,
        r#"{"code":"500","message":"OSCP Response Unsuccessfull: 1 reason: null"}"#
    );
    assert!(h.http_log().iter().all(|l| !l.contains("tsp")));
}

#[test]
fn eot_bad_base64_java_text() {
    let (h, reply) = eot_sign(key("user-gost2015-sign"), vec![], "a b", false, "");
    assert_eq!(
        reply,
        r#"{"code":"500","message":"Illegal base64 character 20"}"#
    );
    assert!(h.http_log().is_empty());
    let (_, reply) = eot_sign(vec![Step::CancelStorage], vec![], "", false, "");
    assert_eq!(reply, r#"{"code":"500","message":"action.canceled"}"#);
    let h = Harness::new(vec![], vec![]);
    assert_eq!(
        text(h.call(
            EOT,
            &call("signCmsWithSignedAttrs", json!(["PKCS12", "", "", 1, ""])),
            None
        )),
        r#"{"code":"500","message":"java.lang.IllegalArgumentException: argument type mismatch. Method: signCmsWithSignedAttrs"}"#
    );
    assert_eq!(
        text(h.call(EOT, &call("getJson", json!(["x"])), None)),
        r#"{"code":"500","message":"java.lang.IllegalAccessException: Class kz.gov.pki.eot.signmodule.Activator can not access a member of class kz.gov.pki.eot.signmodule.EotSignerModuleService with modifiers \"private\". Method: getJson"}"#
    );
}
