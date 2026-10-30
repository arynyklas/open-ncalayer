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

// ---------------------------------------------------------------------------------------
// ezSigner (NLDoc 1.2.1)

const EZ: &str = "ezsigner";

fn ez_request(method: &str, args: Value, lang: Option<&str>) -> String {
    let mut request = json!({"method": method, "args": args});
    if let Some(lang) = lang {
        request["lang"] = json!(lang);
    }
    request.to_string()
}

/// A temporary folder holding `doc.pdf`.
fn folder_with_document() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("doc.pdf");
    std::fs::write(&file, b"%PDF-1.4 the document").unwrap();
    let dir_text = dir.path().to_str().unwrap().to_owned();
    (dir, file.to_str().unwrap().to_owned(), dir_text)
}

fn yes() -> Step {
    Step::Confirm { yes: true }
}

#[test]
fn ezsigner_lang_kk_texts() {
    let h = Harness::new(vec![], vec![]);
    let mut s = h.session(EZ);
    let network = ["\\\\server\\share\\a.pdf", "\\\\server\\share", "PKCS12"];
    assert_eq!(
        text(s.call(
            &ez_request("signFilePath", json!(network), Some("kk")),
            None
        )),
        r#"{"code":"500","message":"Күтпеген қате"}"#
    );
    assert_eq!(
        text(s.call(
            &ez_request("getMessage", json!(["cms.signed"]), Some("kk")),
            None
        )),
        "Файлға сәтті қол қойылды"
    );
    // Any other language is Russian.
    assert_eq!(
        text(s.call(
            &ez_request("getMessage", json!(["cms.signed"]), Some("en")),
            None
        )),
        "Файл успешно подписан"
    );
    assert_eq!(
        text(s.call(&ez_request("getMessage", json!(["nope"]), None), None)),
        r#"{"code":"500","message":"java.lang.reflect.InvocationTargetException. Method: getMessage"}"#
    );
}

#[test]
fn ezsigner_no_such_method_previous_locale() {
    let h = Harness::new(vec![], vec![]);
    let mut s = h.session(EZ);
    // The first call has Russian, whatever it asks for.
    assert_eq!(
        text(s.call(&ez_request("nope", json!([]), Some("kk")), None)),
        r#"{"code":"500","message":"В модуле нет такого метода nope"}"#
    );
    // A method found sets the language before it runs.
    s.call(&ez_request("getMessage", json!(["404"]), Some("kk")), None);
    assert_eq!(
        text(s.call(&ez_request("nope", json!([]), Some("ru")), None)),
        r#"{"code":"500","message":"Модульде мұндай әдіс жоқ nope"}"#
    );
    // A private method sets it too.
    assert_eq!(
        text(s.call(&ez_request("checkCert", json!(["x"]), Some("ru")), None)),
        r#"{"code":"500","message":"java.lang.IllegalAccessException: Class kz.gov.pki.cms.NLDocSignerActivator can not access a member of class kz.gov.pki.cms.CMSSignUtil with modifiers \"private\". Method: checkCert"}"#
    );
    assert_eq!(
        text(s.call(&ez_request("nope", json!([]), None), None)),
        r#"{"code":"500","message":"В модуле нет такого метода nope"}"#
    );
}

#[test]
fn ezsigner_change_lang_without_uuid_drops() {
    let h = Harness::new(vec![], vec![]);
    let mut s = h.session(EZ);
    assert_eq!(
        s.call(&ez_request("changeLang", json!(["kk"]), None), None),
        Reply::Drop
    );
    assert_eq!(
        text(s.call(&ez_request("nope", json!([]), None), None)),
        r#"{"code":"500","message":"Модульде мұндай әдіс жоқ nope"}"#
    );
    let with_uuid = json!({"method": "changeLang", "args": ["ru"], "uuid": "1"}).to_string();
    assert_eq!(text(s.call(&with_uuid, None)), r#"{"code":"500"}"#);
    assert_eq!(
        text(s.call(&ez_request("showKeyChooser", json!([[]]), None), None)),
        r#"{"code":"500","message":"java.lang.IllegalArgumentException: argument type mismatch. Method: showKeyChooser"}"#
    );
}

#[test]
fn ezsigner_get_file_path_cancel_size_zero() {
    let h = Harness::new(vec![Step::CancelPath], vec![]);
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request("getFilePath", json!(["pkcs12", ""]), None),
            None
        )),
        r#"{"responseObject":{"size":0},"code":"200"}"#
    );
    assert_eq!(h.prompter().path_prompts().len(), 1);
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request("getFilePath", json!(["p12", ""]), None),
            None
        )),
        r#"{"code":"500","message":"java.lang.reflect.InvocationTargetException. Method: getFilePath"}"#
    );
    let (_dir, file, folder) = folder_with_document();
    let h = Harness::new(vec![Step::Path(file.clone().into())], vec![]);
    let reply = text(h.call(
        EZ,
        &ez_request("getFilePath", json!(["all", ""]), None),
        None,
    ));
    let mut info = JObject::hash_map();
    info.put("path", file.as_str());
    info.put("filename", "doc.pdf");
    info.put("size", JValue::Int(21));
    info.put("filedir", folder.as_str());
    let mut expected = JObject::hash_map();
    expected.put("code", "200");
    expected.put("responseObject", JValue::Obj(info));
    assert_eq!(reply, expected.to_json());
    let h = Harness::new(vec![Step::CancelPath], vec![]);
    assert_eq!(
        text(h.call(EZ, &ez_request("getDirectoryPath", json!([""]), None), None)),
        r#"{"code":"200"}"#
    );
}

#[cfg(windows)]
#[test]
fn ezsigner_sign_file_path_writes_cms() {
    let (dir, file, folder) = folder_with_document();
    let mut steps = vec![yes()];
    steps.extend(key("user-gost2015-sign"));
    steps.push(yes());
    let h = Harness::new(steps, vec![]);
    let reply = text(h.call(
        EZ,
        &ez_request("signFilePath", json!([file, folder, "PKCS12"]), Some("kk")),
        None,
    ));
    let written = dir.path().join("doc.pdf.cms");
    let mut expected = JObject::hash_map();
    expected.put("code", "200");
    expected.put("message", "Файлға сәтті қол қойылды");
    expected.put("responseObject", written.to_str().unwrap());
    assert_eq!(reply, expected.to_json());
    let cms = std::fs::read(&written).unwrap();
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert!(signers[0].timestamp_token.is_some());
    assert_eq!(cms_view(&cms).econtent.unwrap(), b"%PDF-1.4 the document");
    assert_eq!(h.prompter().confirm_prompts().len(), 2);
    // A blank storage name, after the paths.
    let h = Harness::new(vec![yes()], vec![]);
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request("signFilePath", json!([file, folder, " "]), None),
            None
        )),
        r#"{"code":"500","message":"Не заполнены обязательные входные параметры"}"#
    );
    // A certificate the core's CAs do not chain: refused before signing.
    let mut steps = vec![yes()];
    steps.extend(key("expired-gost2015-sign"));
    let h = Harness::new(steps, vec![]);
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request("signFilePath", json!([file, folder, "PKCS12"]), None),
            None
        )),
        r#"{"code":"500","message":"Срок действия сертфиката истек"}"#
    );
}

#[test]
fn ezsigner_network_path_internal_error() {
    let h = Harness::new(vec![], vec![]);
    for path in ["\\\\server\\share\\a.pdf", "/home/user/a.pdf", "a.pdf", ""] {
        assert_eq!(
            text(h.call(
                EZ,
                &ez_request("signFilePath", json!([path, "C:\\", "PKCS12"]), None),
                None
            )),
            r#"{"code":"500","message":"Непредвиденная ошибка"}"#,
            "{path}"
        );
    }
    assert!(h.prompter().confirm_prompts().is_empty());
}

#[cfg(windows)]
#[test]
fn ezsigner_missing_path_text_has_newline() {
    let (_dir, file, folder) = folder_with_document();
    let missing = file.replace("doc.pdf", "nope.pdf");
    let h = Harness::new(vec![], vec![]);
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request("signFilePath", json!([missing, folder, "PKCS12"]), None),
            None
        )),
        r#"{"code":"500","message":"Этот путь к файлу не существует на вашем компьютере.\n"}"#
    );
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request(
                "signFilePath",
                json!([missing, folder, "PKCS12"]),
                Some("kk")
            ),
            None
        )),
        r#"{"code":"500","message":"Бұл файлға жол сіздің компьютеріңіз де жоқ."}"#
    );
}

#[cfg(windows)]
#[test]
fn ezsigner_write_declined() {
    let (dir, file, folder) = folder_with_document();
    let mut steps = vec![yes()];
    steps.extend(key("user-gost2015-sign"));
    steps.push(Step::Confirm { yes: false });
    let h = Harness::new(steps, vec![]);
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request("signFilePath", json!([file, folder, "PKCS12"]), None),
            None
        )),
        r#"{"code":"500","message":"Ошибка при работе с файлом"}"#
    );
    assert!(!dir.path().join("doc.pdf.cms").exists());
    // Reading declined.
    let h = Harness::new(vec![Step::Confirm { yes: false }], vec![]);
    assert_eq!(
        text(h.call(
            EZ,
            &ez_request("signFilePath", json!([file, folder, "PKCS12"]), None),
            None
        )),
        r#"{"code":"500","message":"Ошибка при работе с файлом"}"#
    );
}

// ---------------------------------------------------------------------------------------
// uchet signUtil

const UCHET: &str = "uchet";
const LICENSE: &str = "http://ncalayer.uchet.kz:8080";

fn uchet(steps: Vec<Step>, method: &str, args: Value) -> String {
    text(Harness::new(steps, vec![]).call(UCHET, &call(method, args), None))
}

#[test]
fn uchet_test_raw_text() {
    assert_eq!(uchet(vec![], "test", json!(["abc"])), "trueabc");
    assert_eq!(
        uchet(vec![], "signFile", json!(["", "u", "d", "PKCS12"])),
        "no no no !!!"
    );
    assert_eq!(
        uchet(vec![], "getMessage", json!(["404"])),
        "Не заполнены обязательные входные параметры"
    );
    assert_eq!(
        uchet(vec![], "getActiveTokens", json!([])),
        r#"{"code":"500","message":"NoSuchMethodException getActiveTokens"}"#
    );
}

#[test]
fn uchet_raw_text_with_uuid_is_parse_error() {
    let h = Harness::new(vec![], vec![]);
    let request = json!({"method": "test", "args": ["x"], "uuid": "u"}).to_string();
    assert_eq!(
        text(h.call(UCHET, &request, None)),
        r#"{"code":"500","message":"A JSONObject text must begin with '{' at 1 [character 2 line 1]"}"#
    );
}

#[test]
fn uchet_get_version() {
    assert_eq!(
        uchet(vec![], "getVersion", json!(["x"])),
        r#"{"code":"200","message":"1.5"}"#
    );
    assert_eq!(
        uchet(vec![], "getJson", json!([["x"]])),
        r#"{"code":"500","message":"JSONArray[0] is not a int."}"#
    );
    assert_eq!(
        uchet(vec![], "sign", json!(["a", "b"])),
        r#"{"code":"500","message":"java.lang.IllegalAccessException: Class kz.uchet.signUtil.NCALayerCommonActivator can not access a member of class kz.uchet.signUtil.CommonUtils with modifiers \"private\". Method: sign"}"#
    );
}

/// An attached CAdES-T of `data` by the synthetic key `name` (made by the rating1c port).
fn cades_t(name: &str, data: &[u8]) -> Vec<u8> {
    let reply = parse(&r1c(
        key(name),
        "createCmsFromBase64",
        json!(["PKCS12", "SIGNATURE", b64(data), true, true, ""]),
    ));
    unb64(reply["responseObject"].as_str().unwrap())
}

/// `checkCMS` of a CMS file by `name`, the responder answering `status` for it.
fn uchet_check(name: &str, status: oncl_pki::ocsp::CertStatus) -> String {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("signed.cms");
    std::fs::write(&file, cades_t(name, b"data")).unwrap();
    let serial = cert_info(&entry(name).cert).serial_hex;
    let responder: Arc<dyn HttpTransport> =
        Arc::new(MockOcsp::new(entry("ocsp-gost2015")).status(&serial, status));
    let h = Harness::new(
        vec![yes()],
        vec![("http://ocsp.synthetic.test".to_owned(), responder)],
    )
    .with_pki_hosts(&["ocsp.synthetic.test"])
    // The mock responder answers at the real time.
    .with_clock(time::OffsetDateTime::now_utc);
    text(h.call(
        UCHET,
        &call("checkCMS", json!([file.to_str().unwrap()])),
        None,
    ))
}

#[test]
fn uchet_check_cms_report_bytes() {
    let reply = uchet_check("inter-user-gost2015-sign", oncl_pki::ocsp::CertStatus::Good);
    let parsed = parse(&reply);
    let signer = &parsed["responseObjects"][0];
    let period = signer["certificateValidityPeriod"].as_str().unwrap();
    let tsp_date = signer["tspDate"].as_str().unwrap();
    let date = |s: &str| {
        let b = s.as_bytes();
        s.len() == 19 && b[2] == b'/' && b[5] == b'/' && b[10] == b' ' && b[13] == b':'
    };
    assert!(
        date(&period[..19]) && &period[19..22] == " - " && date(&period[22..]),
        "{period}"
    );
    assert!(date(tsp_date), "{tsp_date}");
    let e = entry("inter-user-gost2015-sign");
    let info = cert_info(&e.cert);
    let verification = |valid: bool| {
        let mut r = JObject::hash_map();
        r.put("valid", valid);
        JValue::Obj(r)
    };
    let mut bean = JObject::hash_map();
    bean.put(
        "personCertificate",
        info.ext_key_usages.contains("1.2.398.3.3.4.1.1"),
    );
    bean.put("serialNumber", info.serial_hex.trim_start_matches('0'));
    bean.put("validSignature", true);
    bean.put("certificateValidityPeriod", period);
    bean.put("tspDate", tsp_date);
    bean.put("iin", "123456789011");
    bean.put("tspVerificationResult", verification(true));
    bean.put("number", 0);
    bean.put("certificateVerificationResult", verification(true));
    bean.put("name", "ТЕСТОВ ТЕСТ ТЕСТОВИЧ");
    bean.put("signatureVerificationResult", verification(true));
    let mut expected = JObject::hash_map();
    expected.put("code", "200");
    expected.put("responseObjects", JValue::Arr(vec![JValue::Obj(bean)]));
    assert_eq!(reply, expected.to_json());
}

#[test]
fn uchet_check_cms_revoked_text() {
    let revoked = oncl_pki::ocsp::CertStatus::Revoked {
        time: time::OffsetDateTime::from_unix_timestamp(1_768_464_000).unwrap(),
        reason: None,
    };
    let reply = parse(&uchet_check("inter-revoked-gost2015-sign", revoked));
    let signer = &reply["responseObjects"][0];
    assert_eq!(
        signer["certificateVerificationResult"],
        json!({"valid": false, "message": "Сертификат отозван"})
    );
    assert_eq!(signer["validSignature"], false);
    // A file the page names that does not exist; a blank path.
    assert_eq!(
        uchet(vec![], "checkCMS", json!(["C:\\no\\such.cms"])),
        r#"{"code":"500","message":"Ошибка при работе с файлом"}"#
    );
    assert_eq!(
        uchet(vec![], "checkCMS", json!([" "])),
        r#"{"code":"500","message":"Не заполнены обязательные входные параметры"}"#
    );
}

#[test]
fn uchet_check_cms_from_web_foreign_denied() {
    let h = Harness::new(vec![], vec![]);
    for url in ["https://evil.example/a.cms", "file:///C:/a.cms", "/a.cms"] {
        assert_eq!(
            text(h.call(
                UCHET,
                &call("checkCMSFromWeb", json!([url])),
                Some("https://uchet.kz")
            )),
            r#"{"code":"500","message":"Непредвиденная ошибка"}"#
        );
    }
    assert!(h.http_log().is_empty());
}

#[test]
fn uchet_sign_xml_api_consent_and_message() {
    let (path, password) = p12("user-gost2015-sign");
    let h = Harness::new(vec![yes()], vec![]);
    let mut s = h.session(UCHET);
    let request = call(
        "signXmlApi",
        json!([path.to_str().unwrap(), password, "<doc><a>1</a></doc>"]),
    );
    for _ in 0..2 {
        let reply = parse(&text(s.call(&request, None)));
        assert_eq!(reply["code"], "200");
        assert!(reply.get("responseObject").is_none());
        let xml = reply["message"].as_str().unwrap();
        assert!(
            xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><doc>"),
            "{xml}"
        );
        assert_eq!(oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap().len(), 1);
    }
    // Asked once for the session.
    assert_eq!(h.prompter().confirm_prompts().len(), 1);
}

#[test]
fn uchet_sign_xml_api_wrong_password() {
    let (path, _) = p12("user-gost2015-sign");
    let h = Harness::new(vec![yes()], vec![]);
    let request = call(
        "signXmlApi",
        json!([path.to_str().unwrap(), "wrong", "<a/>"]),
    );
    assert_eq!(
        text(h.call(UCHET, &request, None)),
        r#"{"code":"500","message":"Не удалось открыть хранилище"}"#
    );
    // Declined.
    let h = Harness::new(vec![Step::Confirm { yes: false }], vec![]);
    let request = call(
        "signXmlApi",
        json!([path.to_str().unwrap(), "Qwerty12", "<a/>"]),
    );
    assert_eq!(
        text(h.call(UCHET, &request, None)),
        r#"{"code":"500","message":"Не удалось открыть хранилище"}"#
    );
}

/// A request the license server got: its headers, `Content-Type` and body.
type Seen = (Vec<(String, String)>, Option<String>, Vec<u8>);

/// The license server answering `body` with `status`, recording what it was sent.
struct License {
    status: u16,
    body: &'static str,
    seen: Mutex<Vec<Seen>>,
}

impl HttpTransport for License {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.seen.lock().unwrap().push((
            request
                .headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            request.content_type.map(str::to_owned),
            request.body.to_vec(),
        ));
        Ok(HttpReply {
            status: self.status,
            content_type: Some("application/json".to_owned()),
            location: None,
            body: self.body.as_bytes().to_vec(),
        })
    }
}

fn license(status: u16, body: &'static str) -> Arc<License> {
    Arc::new(License {
        status,
        body,
        seen: Mutex::new(Vec::new()),
    })
}

#[test]
fn uchet_license_ok_then_sign() {
    let server = license(200, r#"{"error":"","result":"ok"}"#);
    let route: Arc<dyn HttpTransport> = server.clone();
    let (dir, file, folder) = folder_with_document();
    let (key_path, password) = p12("user-gost2015-sign");
    // The file, then the key file, then the folder.
    let h = Harness::new(vec![yes(), yes(), yes()], vec![(LICENSE.to_owned(), route)]);
    let reply = parse(&text(h.call(
        UCHET,
        &call(
            "signFileFromDiskAndSaveToDiskApi",
            json!([
                "tok",
                file,
                folder,
                key_path.to_str().unwrap(),
                password,
                "PKCS12"
            ]),
        ),
        None,
    )));
    assert_eq!(reply["code"], "200", "{reply}");
    assert_eq!(reply["message"], "Файл успешно подписан");
    let written = dir.path().join("doc.pdf.cms");
    assert_eq!(
        Some(reply["responseObject"].as_str().unwrap()),
        written.to_str()
    );
    oncl_pki::cms::verify(&std::fs::read(&written).unwrap(), None).unwrap();
    let seen = server.seen.lock().unwrap().clone();
    let (headers, content_type, body) = &seen[0];
    assert_eq!(body, br#"{"sign_token":"tok"}"#);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    assert!(headers.contains(&("User-Agent".to_owned(), "Mozilla/5.0".to_owned())));
    assert!(headers.contains(&("Accept-Language".to_owned(), "en-US,en;q=0.5".to_owned())));
    assert_eq!(
        h.http_log()[0],
        "POST http://ncalayer.uchet.kz:8080/checkSignToken"
    );

    let server = license(200, r#"{"error":"","result":"ok"}"#);
    let route: Arc<dyn HttpTransport> = server.clone();
    let h = Harness::new(vec![yes()], vec![(LICENSE.to_owned(), route)]);
    let reply = parse(&text(h.call(
        UCHET,
        &call(
            "signFileAndReturnBase64Api",
            json!([
                "tok",
                b64(b"bytes"),
                key_path.to_str().unwrap(),
                password,
                "PKCS12"
            ]),
        ),
        None,
    )));
    let cms = unb64(reply["responseObject"].as_str().unwrap());
    assert_eq!(cms_view(&cms).econtent.unwrap(), b"bytes");
}

#[test]
fn uchet_license_rejected_text() {
    let route: Arc<dyn HttpTransport> =
        license(200, r#"{"error":"Токен недействителен","result":""}"#);
    let h = Harness::new(vec![], vec![(LICENSE.to_owned(), route)]);
    assert_eq!(
        text(h.call(
            UCHET,
            &call(
                "signFileAndReturnBase64Api",
                json!(["tok", "", "", "", "PKCS12"])
            ),
            None
        )),
        r#"{"code":"500","message":"Токен недействителен"}"#
    );
    assert!(h.prompter().confirm_prompts().is_empty());
}

#[test]
fn uchet_license_down() {
    let down = r#"{"code":"500","message":"Сервер лицензирования не доступен"}"#;
    // No server at all.
    let h = Harness::new(vec![], vec![]);
    assert_eq!(
        text(h.call(
            UCHET,
            &call(
                "signFileAndReturnBase64Api",
                json!(["tok", "", "", "", "PKCS12"])
            ),
            None
        )),
        down
    );
    for (status, body) in [
        (500, r#"{"error":"","result":"ok"}"#),
        (200, "{}"),
        (200, "x"),
    ] {
        let route: Arc<dyn HttpTransport> = license(status, body);
        let h = Harness::new(vec![], vec![(LICENSE.to_owned(), route)]);
        assert_eq!(
            text(h.call(
                UCHET,
                &call(
                    "signFileAndReturnBase64Api",
                    json!(["tok", "", "", "", "PKCS12"])
                ),
                None
            )),
            down,
            "{status} {body}"
        );
    }
}

#[test]
fn uchet_license_test_token_not_local() {
    let h = Harness::new(vec![], vec![]);
    assert_eq!(
        text(h.call(
            UCHET,
            &call(
                "signFileFromDiskAndSaveToDiskApi",
                json!(["mytest1", "", "", "", "", "PKCS12"])
            ),
            None
        )),
        r#"{"code":"500","message":"Сервер лицензирования не доступен"}"#
    );
    assert!(h.http_log().is_empty());
}

/// A key store with two signing keys: the individual's and the legal entity's.
fn two_signing_keys(dir: &std::path::Path) -> std::path::PathBuf {
    use oncl_pki::pkcs12::{WriteEntry, WriteOptions, write};
    let entries: Vec<WriteEntry> = ["user-gost2015-sign", "legal-gost2015-sign"]
        .iter()
        .map(|name| {
            let e = entry(name);
            WriteEntry {
                alias: e.alias.clone(),
                pkcs8_der: e.key.to_pkcs8_der().to_vec(),
                cert_der: Some(der_of(&e.cert)),
            }
        })
        .collect();
    let mut counter = 0u8;
    let pfx = write(
        &entries,
        &[],
        "Qwerty12",
        &WriteOptions::default(),
        &mut |buf| {
            for b in buf {
                counter = counter.wrapping_add(1);
                *b = counter;
            }
        },
    )
    .unwrap();
    let path = dir.join("two.p12");
    std::fs::write(&path, pfx).unwrap();
    path
}

#[test]
fn uchet_multi_key_unexpected_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = two_signing_keys(dir.path());
    let (_docs, file, folder) = folder_with_document();
    // signFilePath: the module's storage dialog (the file, then its password).
    let h = Harness::new(
        vec![
            yes(),
            Step::Path(store.clone()),
            Step::Password("Qwerty12".to_owned()),
        ],
        vec![],
    );
    assert_eq!(
        text(h.call(
            UCHET,
            &call("signFilePath", json!([file, folder, "PKCS12"])),
            None
        )),
        r#"{"code":"500","message":"Непредвиденная ошибка"}"#
    );
    // signXmlApi: the same.
    let h = Harness::new(vec![yes()], vec![]);
    assert_eq!(
        text(h.call(
            UCHET,
            &call(
                "signXmlApi",
                json!([store.to_str().unwrap(), "Qwerty12", "<a/>"])
            ),
            None
        )),
        r#"{"code":"500","message":"Непредвиденная ошибка"}"#
    );
    // One signing key in the dialog's store signs; a wrong password is asked again.
    let (key_path, _) = p12("user-gost2015-sign");
    let h = Harness::new(
        vec![
            yes(),
            Step::Path(key_path),
            Step::Password("wrong".to_owned()),
            Step::Message,
            Step::Password("Qwerty12".to_owned()),
            yes(),
        ],
        vec![],
    );
    let reply = parse(&text(h.call(
        UCHET,
        &call("signFilePath", json!([file, folder, "PKCS12"])),
        None,
    )));
    assert_eq!(reply["message"], "Файл успешно подписан", "{reply}");
    // Closing the storage dialog.
    let h = Harness::new(vec![yes(), Step::CancelPath], vec![]);
    assert_eq!(
        text(h.call(
            UCHET,
            &call("signFilePath", json!([file, folder, "PKCS12"])),
            None
        )),
        r#"{"code":"500","message":"Не удалось открыть хранилище"}"#
    );
    // The file is read first, then the storage is checked.
    assert_eq!(
        uchet(
            vec![yes()],
            "signFilePath",
            json!([file, folder, "AKKaztokenStore"])
        ),
        r#"{"code":"500","message":"Носитель не обнаружен"}"#
    );
}
