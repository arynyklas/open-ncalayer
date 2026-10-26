//! `kz.gov.pki.knca.commonUtils`: the reflective dispatcher, every method through a
//! scripted prompter and a mock TSA, cancellation, `uuid` echo and the original's messages.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_basics::{Action, FileKind, Locale, OpenError, StorageKind};
use oncl_commonutils::{CommonUtils, MODULE_NAME};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{self, SignOptions, verify};
use oncl_pki::info::{cert_info, common_name, kalkan_dn};
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, WriteEntry, WriteOptions, load, write};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::{MockTsa, verify_token};
use oncl_pki::{oid, pem, xmldsig};
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{fixture, ncanode, read, synthetic, synthetic_cert};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use time::OffsetDateTime;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

const TSA_RSA_POLICY: &str = "1.2.398.3.3.2.6.2";

macro_rules! script {
    ($($step:expr),* $(,)?) => { vec![$($step),*] };
}

fn storage(name: &str) -> Step {
    let key = synthetic(name);
    Step::Storage {
        path: key.path,
        password: key.password,
    }
}

fn key(index: usize) -> Step {
    Step::Key(index)
}

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

fn synthetic_ca(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

/// The synthetic roots and intermediate CA, standing in for the NCA CAs.
fn synthetic_cas() -> CaSet {
    CaSet::new(
        [
            "root-gost2015",
            "root-gost2004",
            "root-rsa",
            "inter-gost2015",
        ]
        .into_iter()
        .map(synthetic_ca)
        .collect(),
    )
}

struct Setup {
    cu: CommonUtils,
    prompter: Arc<ScriptedPrompter>,
    tsa: Arc<MockTsa>,
}

/// The module with the synthetic CAs, answering dialogs with `steps`.
fn setup(steps: Vec<Step>) -> Setup {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let cu = CommonUtils::new(prompter.clone(), tsa.clone()).with_cas(synthetic_cas());
    Setup { cu, prompter, tsa }
}

fn origin() -> AddInfo {
    AddInfo {
        origin: Some("https://x.kz".to_owned()),
    }
}

/// The raw reply to `request`.
fn raw(cu: &CommonUtils, request: Value) -> String {
    cu.process(&request.to_string(), &origin())
}

/// The reply to `method(args)`.
fn call(cu: &CommonUtils, method: &str, args: Value) -> Value {
    let reply = raw(
        cu,
        json!({"module": MODULE_NAME, "method": method, "args": args}),
    );
    serde_json::from_str(&reply).unwrap()
}

/// The `responseObject` of a successful reply.
fn ok(reply: &Value) -> &Value {
    assert_eq!(reply["code"], "200", "{reply}");
    &reply["responseObject"]
}

/// The `message` of a failed reply.
fn failed(reply: &Value) -> &str {
    assert_eq!(reply["code"], "500", "{reply}");
    assert!(reply.get("responseObject").is_none(), "{reply}");
    reply["message"].as_str().unwrap()
}

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn unb64(reply: &Value) -> Vec<u8> {
    STANDARD.decode(ok(reply).as_str().unwrap()).unwrap()
}

fn sign_opts(encapsulate: bool) -> SignOptions {
    SignOptions {
        encapsulate,
        digested: false,
        signing_time: OffsetDateTime::now_utc(),
    }
}

fn temp_file(dir: &Path, name: &str, contents: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path.to_str().unwrap().to_owned()
}

#[test]
fn get_active_tokens_lists_no_tokens() {
    let s = setup(script![]);
    let req = |extra: Value| {
        let mut r = json!({"module": MODULE_NAME, "method": "getActiveTokens"});
        r.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        raw(&s.cu, r)
    };
    assert_eq!(req(json!({})), r#"{"code":"200","responseObject":[]}"#);
    assert_eq!(
        req(json!({"args": []})),
        r#"{"code":"200","responseObject":[]}"#
    );
    // Anything but an array is no arguments (`optJSONArray`).
    assert_eq!(
        req(json!({"args": "x"})),
        r#"{"code":"200","responseObject":[]}"#
    );
    assert_eq!(
        req(json!({"uuid": "u-1"})),
        r#"{"code":"200","responseObject":[],"uuid":"u-1"}"#
    );
    assert!(s.prompter.storage_prompts().is_empty());
}

#[test]
fn uuid_is_echoed_on_method_replies_only() {
    let s = setup(script![]);
    let req = |method: &str, args: Value, uuid: Value| {
        raw(
            &s.cu,
            json!({"module": MODULE_NAME, "method": method, "args": args, "uuid": uuid}),
        )
    };
    // A method's own failure carries the uuid; `optString` turns other values into text.
    assert_eq!(
        req("getKeyInfo", json!(["NOPE"]), json!("abc")),
        r#"{"code":"500","message":"storage.unknown","uuid":"abc"}"#
    );
    assert_eq!(
        req("getActiveTokens", json!([]), json!(42)),
        r#"{"code":"200","responseObject":[],"uuid":"42"}"#
    );
    assert_eq!(
        req("getActiveTokens", json!([]), json!(true)),
        r#"{"code":"200","responseObject":[],"uuid":"true"}"#
    );
    // Empty and null uuids are not echoed.
    for uuid in [json!(""), Value::Null] {
        assert_eq!(
            req("getActiveTokens", json!([]), uuid),
            r#"{"code":"200","responseObject":[]}"#
        );
    }
    // Dispatcher errors never carry it.
    assert_eq!(
        req("nope", json!([]), json!("abc")),
        r#"{"code":"500","message":"NoSuchMethodException nope"}"#
    );
    assert_eq!(
        req("saveKey", json!(["a", "b"]), json!("abc")),
        "{\"code\":\"500\",\"message\":\"java.lang.IllegalAccessException: Class \
         kz.gov.pki.knca.NCALayerCommonActivator can not access a member of class \
         kz.gov.pki.knca.CommonUtils with modifiers \\\"private\\\". Method: saveKey\"}"
    );
}

#[test]
fn methods_are_found_by_name_and_argument_count() {
    let s = setup(script![]);
    let message = |method: &str, args: Value| failed(&call(&s.cu, method, args)).to_owned();
    for (method, args) in [
        ("getKeyInfo", json!([])),
        ("getKeyInfo", json!(["PKCS12", "x"])),
        ("getActiveTokens", json!(["x"])),
        ("signXml", json!(["PKCS12", "", "<a/>", ""])),
        ("createCAdESFromBase64", json!(["PKCS12", "", "YQ=="])),
        ("changeLocale", json!([])),
        ("toString", json!([])),
        ("GetKeyInfo", json!(["PKCS12"])),
        ("", json!([])),
    ] {
        assert_eq!(
            message(method, args.clone()),
            format!("NoSuchMethodException {method}"),
            "{method} {args}"
        );
    }
    assert!(s.prompter.storage_prompts().is_empty());
}

#[test]
fn method_field_is_read_with_get_string() {
    let s = setup(script![]);
    let reply = |request: Value| raw(&s.cu, request);
    assert_eq!(
        reply(json!({"module": MODULE_NAME, "uuid": "u"})),
        r#"{"code":"500","message":"JSONObject[\"method\"] not found."}"#
    );
    for method in [json!(5), Value::Null, json!(["getActiveTokens"])] {
        assert_eq!(
            reply(json!({"module": MODULE_NAME, "method": method})),
            r#"{"code":"500","message":"JSONObject[\"method\"] is not a string."}"#
        );
    }
}

#[test]
fn private_and_unconvertible_methods_are_refused() {
    let s = setup(script![]);
    let private = |method: &str| {
        format!(
            "java.lang.IllegalAccessException: Class kz.gov.pki.knca.NCALayerCommonActivator \
             can not access a member of class kz.gov.pki.knca.CommonUtils with modifiers \
             \"private\". Method: {method}"
        )
    };
    for (method, args) in [
        ("saveKey", json!([{}, [1]])),
        ("getBase64FromFile", json!(["C:/x"])),
        ("chooseFile", json!(["P12", ""])),
        ("getJson", json!([null])),
        ("getJson", json!([[1, "2", -3.5, "+4"]])),
    ] {
        assert_eq!(failed(&call(&s.cu, method, args)), private(method));
    }
    // `getJson(Object)` takes an `int[]`, which the dispatcher converts first.
    for (array, index) in [
        (json!(["x"]), 0),
        (json!([1, true]), 1),
        (json!([1, "2147483648"]), 1),
        (json!([null]), 0),
        (json!([[1]]), 0),
    ] {
        assert_eq!(
            failed(&call(&s.cu, "getJson", json!([array]))),
            format!("JSONArray[{index}] is not a int.")
        );
    }
    // Other parameter types take an `Object[]`: no element conversion.
    assert_eq!(
        failed(&call(&s.cu, "saveKey", json!([["x"], [true]]))),
        private("saveKey")
    );
    // The setters take a `Function`, which no JSON value is.
    for args in [json!(["x"]), json!([{}]), json!([[]]), json!([null])] {
        assert_eq!(
            failed(&call(&s.cu, "setKeyInfoServices", args)),
            "java.lang.IllegalArgumentException: argument type mismatch. Method: \
             setKeyInfoServices"
        );
    }
    assert_eq!(
        failed(&call(&s.cu, "setKeyInfoSetterService", json!([1]))),
        "java.lang.IllegalArgumentException: argument type mismatch. Method: \
         setKeyInfoSetterService"
    );
}

#[test]
fn arguments_must_have_the_parameter_types() {
    let s = setup(script![]);
    let mismatch = |method: &str| {
        format!("java.lang.IllegalArgumentException: argument type mismatch. Method: {method}")
    };
    for (method, args) in [
        ("getKeyInfo", json!([5])),
        ("getKeyInfo", json!([null])),
        ("getKeyInfo", json!([["PKCS12"]])),
        ("getKeyInfo", json!([{"a": 1}])),
        ("changeLocale", json!([true])),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "", "YQ==", "true"]),
        ),
        ("createCAdESFromBase64", json!(["PKCS12", "", "YQ==", 1])),
        ("createCAdESFromBase64", json!(["PKCS12", "", "YQ==", null])),
        ("signXmls", json!(["PKCS12", "", "<a/>", "", ""])),
        ("signXml", json!(["PKCS12", "", ["<a/>"], "", ""])),
    ] {
        assert_eq!(
            failed(&call(&s.cu, method, args.clone())),
            mismatch(method),
            "{method} {args}"
        );
    }
    // A `String[]` parameter takes only strings; the conversion fails before the call.
    let reply = raw(
        &s.cu,
        json!({"module": MODULE_NAME, "method": "signXmls", "uuid": "u",
            "args": ["PKCS12", "", ["<a/>", 1], "", ""]}),
    );
    assert_eq!(
        reply,
        r#"{"code":"500","message":"JSONArray[1] is not a String."}"#
    );
    assert!(s.prompter.storage_prompts().is_empty());
}

#[test]
fn storage_name_is_checked_before_any_dialog() {
    let s = setup(script![]);
    for (name, message) in [
        ("", "storageName.param.empty"),
        ("  ", "storageName.param.empty"),
        ("pkcs12", "storage.unknown"),
        ("AKEToken", "storage.unknown"),
        ("AKKaztokenStore", "storage.empty"),
        ("AKKZIDCardStore", "storage.empty"),
        ("ABCloudServiceStore", "storage.empty"),
    ] {
        for (method, args) in [
            ("getKeyInfo", json!([name])),
            ("signXml", json!([name, "", "<a/>", "", ""])),
            ("createCAdESFromBase64", json!([name, "", "YQ==", true])),
            ("applyCAdEST", json!([name, "", "YQ=="])),
        ] {
            assert_eq!(
                failed(&call(&s.cu, method, args)),
                message,
                "{method} {name:?}"
            );
        }
    }
    assert!(s.prompter.storage_prompts().is_empty());
}

#[test]
fn get_key_info_reports_the_chosen_certificate() {
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(&s.cu, "getKeyInfo", json!(["PKCS12"]));
    let info = ok(&reply).as_object().unwrap();
    let e = entry("user-gost2015-sign");
    let tbs = e.cert.tbs_certificate();
    let ci = cert_info(&e.cert);
    let (_, ski) = tbs
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap();
    let (_, aki) = tbs
        .get_extension::<AuthorityKeyIdentifier>()
        .unwrap()
        .unwrap();
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let millis = |t: OffsetDateTime| (t.unix_timestamp() * 1000).to_string();
    let expected = json!({
        "alias": synthetic("user-gost2015-sign").aliases[0],
        "keyId": hex(ski.0.as_bytes()),
        "algorithm": "ECGOST3410-2015",
        "subjectCn": "ТЕСТОВ ТЕСТ",
        "subjectDn": "CN=ТЕСТОВ ТЕСТ,SURNAME=ТЕСТОВ,G=ТЕСТОВИЧ,SERIALNUMBER=IIN123456789011,C=KZ",
        "issuerCn": common_name(tbs.issuer()).unwrap(),
        "issuerDn": kalkan_dn(tbs.issuer()),
        "serialNumber": ci.serial_hex,
        "certNotAfter": millis(ci.not_after),
        "certNotBefore": millis(ci.not_before),
        "authorityKeyIdentifier": hex(aki.key_identifier.unwrap().as_bytes()),
        "pem": pem::encode("CERTIFICATE", &e.cert.to_der().unwrap()),
    });
    assert_eq!(Value::Object(info.clone()), expected);
    // The keyId is the key's alias for keys NCALayer generates.
    assert_eq!(info["keyId"], info["alias"]);

    let sp = &s.prompter.storage_prompts()[0];
    assert_eq!(sp.storages, [StorageKind::Pkcs12]);
    assert_eq!(sp.origin, "https://x.kz");
    assert_eq!(sp.locale, Locale::Ru);
    assert_eq!(sp.action, Action::KeyInfo);
    assert_eq!(sp.recent_path, None);
    assert_eq!(sp.detail, None);
    assert_eq!(s.prompter.key_prompts()[0].action, Action::KeyInfo);

    // Other algorithms by Kalkan's key names.
    for (name, algorithm) in [
        ("user-gost2004-sign", "ECGOST34310"),
        ("user-rsa-sign", "RSA"),
    ] {
        let s = setup(script![storage(name), key(0)]);
        let reply = call(&s.cu, "getKeyInfo", json!(["PKCS12"]));
        assert_eq!(ok(&reply)["algorithm"], algorithm);
    }
}

#[test]
fn cancel_is_action_canceled() {
    let methods = [
        ("getKeyInfo", json!(["PKCS12"])),
        ("signXml", json!(["PKCS12", "SIGNATURE", "<a/>", "", ""])),
        ("signXmls", json!(["PKCS12", "", ["<a/>"], "", ""])),
        ("createCAdESFromBase64", json!(["PKCS12", "", "YQ==", true])),
        ("createCAdESFromBase64Hash", json!(["PKCS12", "", "YQ=="])),
        (
            "createCMSSignatureFromBase64",
            json!(["PKCS12", "", "YQ==", false]),
        ),
        ("applyCAdEST", json!(["PKCS12", "", "YQ=="])),
    ];
    for (method, args) in &methods {
        let s = setup(script![Step::CancelStorage]);
        let reply = raw(
            &s.cu,
            json!({"module": MODULE_NAME, "method": method, "args": args, "uuid": "u"}),
        );
        assert_eq!(
            reply, r#"{"code":"500","message":"action.canceled","uuid":"u"}"#,
            "{method}"
        );
        assert!(s.prompter.key_prompts().is_empty());

        let s = setup(script![storage("user-gost2015-sign"), Step::CancelKey]);
        assert_eq!(
            failed(&call(&s.cu, method, args.clone())),
            "action.canceled",
            "{method}"
        );
        assert_eq!(s.prompter.key_prompts().len(), 1);
    }
    // An exhausted script cancels too.
    let s = setup(script![]);
    assert_eq!(
        failed(&call(&s.cu, "getKeyInfo", json!(["PKCS12"]))),
        "action.canceled"
    );
}

#[test]
fn unopenable_stores_are_asked_for_again() {
    let s = setup(script![
        Step::Storage {
            path: synthetic("user-gost2015-sign").path,
            password: "wrong".to_owned(),
        },
        storage("user-gost2015-sign"),
        key(0)
    ]);
    ok(&call(&s.cu, "getKeyInfo", json!(["PKCS12"])));
    let prompts = s.prompter.storage_prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[1].error, Some(OpenError::WrongPassword));
    assert_eq!(
        prompts[1].recent_path,
        Some(synthetic("user-gost2015-sign").path)
    );

    // JKS: the dialog offers it alone and refuses other storages; a PKCS#12 file named as
    // JKS is not a JKS.
    let s = setup(script![
        storage("user-gost2015-sign"),
        Step::Storage {
            path: synthetic("user-gost2015-sign").path,
            password: "Qwerty12".to_owned(),
        },
        Step::Jks {
            path: synthetic("user-gost2015-sign").path,
            password: "Qwerty12".to_owned(),
        },
        Step::CancelStorage
    ]);
    assert_eq!(
        failed(&call(&s.cu, "getKeyInfo", json!(["JKS"]))),
        "action.canceled"
    );
    let prompts = s.prompter.storage_prompts();
    assert_eq!(prompts[0].storages, [StorageKind::Jks]);
    assert_eq!(prompts[1].error, Some(OpenError::UnsupportedStorage));
    assert_eq!(prompts[3].error, Some(OpenError::NotJks));
}

#[test]
fn jks_keys_sign_read_only() {
    let jks = || Step::Jks {
        path: fixture("jks/rsa.jks"),
        password: "Qwerty12".to_owned(),
    };
    let s = setup(script![jks(), key(0)]);
    let reply = call(&s.cu, "getKeyInfo", json!(["JKS"]));
    assert_eq!(ok(&reply)["alias"], "openncalayer-rsa");
    assert_eq!(ok(&reply)["algorithm"], "RSA");

    let s = setup(script![jks(), key(0)]);
    let reply = call(
        &s.cu,
        "signXml",
        json!(["JKS", "SIGNATURE", "<doc>x</doc>", "", ""]),
    );
    let signed = ok(&reply).as_str().unwrap();
    assert_eq!(
        xmldsig::verify(signed.as_bytes()).unwrap()[0].sig_alg,
        SigAlg::RsaSha256
    );
    // The trusted root of the store is not offered as a key.
    assert_eq!(s.prompter.key_prompts()[0].candidates.len(), 1);

    // A wrong password is asked again.
    let s = setup(script![
        Step::Jks {
            path: fixture("jks/rsa.jks"),
            password: "wrong".to_owned(),
        },
        Step::CancelStorage
    ]);
    call(&s.cu, "getKeyInfo", json!(["JKS"]));
    assert_eq!(
        s.prompter.storage_prompts()[1].error,
        Some(OpenError::WrongPassword)
    );
}

#[test]
fn key_type_selects_the_keys_listed() {
    let candidates = |store: &str, key_type: &str| {
        let s = setup(script![storage(store), Step::CancelKey]);
        call(
            &s.cu,
            "signXml",
            json!(["PKCS12", key_type, "<a/>", "", ""]),
        );
        let prompts = s.prompter.key_prompts();
        assert_eq!(prompts.len(), 1, "{store} {key_type}");
        prompts[0].clone()
    };
    // Without a known keyType: SIGNATURE or AUTHENTICATION. The auth key of this store has
    // no keyEncipherment, so Kalkan classes it as neither.
    let p = candidates("multi-gost2015", "ALL");
    assert_eq!(p.candidates.len(), 1);
    assert_eq!(p.action, Action::Sign);
    // GOST 2015-512 signing keys are dual-use.
    let p = candidates("user-gost2015-sign", "AUTHENTICATION");
    assert_eq!(p.candidates.len(), 1);
    assert_eq!(p.action, Action::Authenticate);
    assert_eq!(
        candidates("tsa-gost2015", "TSP_SIGNING").candidates.len(),
        1
    );
    assert_eq!(
        candidates("ocsp-gost2015", "OCSP_RESPONSE_SIGNING")
            .candidates
            .len(),
        1
    );

    // A store without such keys is asked for again, with the original's message for the
    // type.
    for (key_type, store, error) in [
        ("SSL", "user-gost2015-sign", OpenError::NoKeys),
        ("AUTHENTICATION", "user-rsa-sign", OpenError::NoAuthKeys),
        ("SIGNATURE", "tsa-gost2015", OpenError::NoSigningKeys),
        ("", "tsa-gost2015", OpenError::NoKeys),
    ] {
        let s = setup(script![storage(store), Step::CancelStorage]);
        assert_eq!(
            failed(&call(
                &s.cu,
                "signXml",
                json!(["PKCS12", key_type, "<a/>", "", ""])
            )),
            "action.canceled"
        );
        let prompts = s.prompter.storage_prompts();
        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[1].error, Some(error), "{key_type} {store}");
        assert!(s.prompter.key_prompts().is_empty());
    }
}

#[test]
fn keys_are_listed_newest_first_and_expired_ones_may_sign() {
    // Store order (by alias): the expired key first.
    let old = entry("expired-gost2015-sign");
    let new = entry("user-gost2015-sign");
    let p12 = write(
        &[
            WriteEntry {
                alias: "a-old".to_owned(),
                pkcs8_der: old.key.to_pkcs8_der().to_vec(),
                cert_der: Some(old.cert.to_der().unwrap()),
            },
            WriteEntry {
                alias: "b-new".to_owned(),
                pkcs8_der: new.key.to_pkcs8_der().to_vec(),
                cert_der: Some(new.cert.to_der().unwrap()),
            },
        ],
        &[],
        "Qwerty12",
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(3),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two.p12");
    std::fs::write(&path, p12).unwrap();

    let s = setup(script![
        Step::Storage {
            path: path.clone(),
            password: "Qwerty12".to_owned(),
        },
        key(1)
    ]);
    let reply = call(&s.cu, "getKeyInfo", json!(["PKCS12"]));
    let aliases: Vec<_> = s.prompter.key_prompts()[0]
        .candidates
        .iter()
        .map(|c| c.alias.clone())
        .collect();
    assert_eq!(aliases, ["b-new", "a-old"]);
    // The expired key is offered and may be chosen.
    assert_eq!(ok(&reply)["alias"], "a-old");
}

#[test]
fn sign_xml_whole_document_and_element() {
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><a>текст</a></root>";
    let reply = call(
        &s.cu,
        "signXml",
        json!(["PKCS12", "SIGNATURE", xml, "", ""]),
    );
    let signed = ok(&reply).as_str().unwrap();
    assert!(signed.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root><a>текст</a>"));
    let sigs = xmldsig::verify(signed.as_bytes()).unwrap();
    assert_eq!(sigs.len(), 1);

    // An element with an Id, the signature into another element.
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let xml = "<root><data Id=\"d1\">x</data><sigs/></root>";
    let reply = call(
        &s.cu,
        "signXml",
        json!(["PKCS12", "", xml, "/root/data", "/root/sigs"]),
    );
    let signed = ok(&reply).as_str().unwrap();
    assert!(signed.contains("<sigs><ds:Signature"), "{signed}");
    assert!(signed.contains("URI=\"#d1\""), "{signed}");
    assert_eq!(xmldsig::verify(signed.as_bytes()).unwrap().len(), 1);

    // Into the document element when no parent is named.
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(&s.cu, "signXml", json!(["PKCS12", "", xml, "//data", ""]));
    let signed = ok(&reply).as_str().unwrap();
    assert!(signed.ends_with("</ds:Signature></root>"), "{signed}");
}

#[test]
fn sign_xml_failures_have_the_original_messages() {
    let message = |xml: &str, tbs: &str, parent: &str| {
        let s = setup(script![storage("user-gost2015-sign"), key(0)]);
        let reply = call(&s.cu, "signXml", json!(["PKCS12", "", xml, tbs, parent]));
        // The document is read after the dialogs, as in the original.
        assert_eq!(s.prompter.key_prompts().len(), 1);
        failed(&reply).to_owned()
    };
    let xml = "<root><data>x</data><sigs/></root>";
    assert_eq!(
        message(xml, "/root/data", ""),
        "Указанный для подписи элемент не содержит атрибут 'Id'"
    );
    assert_eq!(
        message(xml, "/root/none", ""),
        "Указанный для подписи элемент /root/none не найден"
    );
    assert_eq!(
        message(xml, "/root/data", "/ROOT/DATA"),
        "При подписи элемента XML, элемент подписи не может быть родительским элементом подписи."
    );
    assert_eq!(
        message("<!DOCTYPE r><r/>", "", ""),
        "DOCTYPE is not allowed in XML"
    );
    assert!(message("<r>", "", "").starts_with("malformed XML"));
}

#[test]
fn sign_xmls_signs_every_document_after_one_dialog() {
    let s = setup(script![storage("user-rsa-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "signXmls",
        json!(["PKCS12", "", ["<a>1</a>", "<b>2</b>"], "", ""]),
    );
    let signed = ok(&reply).as_array().unwrap();
    assert_eq!(signed.len(), 2);
    for (doc, start) in signed.iter().zip(["<a>1", "<b>2"]) {
        let doc = doc.as_str().unwrap();
        assert!(doc.starts_with(start));
        assert_eq!(
            xmldsig::verify(doc.as_bytes()).unwrap()[0].sig_alg,
            SigAlg::RsaSha256
        );
    }
    assert_eq!(s.prompter.storage_prompts().len(), 1);
    assert_eq!(s.prompter.key_prompts().len(), 1);

    // No documents: an empty array.
    let s = setup(script![storage("user-rsa-sign"), key(0)]);
    let reply = call(&s.cu, "signXmls", json!(["PKCS12", "", [], "", ""]));
    assert_eq!(ok(&reply), &json!([]));
}

#[test]
fn cades_from_base64_attached_detached_and_cosigned() {
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "SIGNATURE", b64(b"doc"), true]),
    );
    let der = unb64(&reply);
    let signers = verify(&der, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].sig_alg, SigAlg::Gost2015_512);
    assert!(signers[0].timestamp_token.is_none());
    assert!(s.tsa.calls().is_empty());

    let s = setup(script![storage("user-gost2004-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "", b64(b"doc"), false]),
    );
    let der = unb64(&reply);
    assert!(verify(&der, None).is_err());
    assert_eq!(
        verify(&der, Some(b"doc")).unwrap()[0].sig_alg,
        SigAlg::Gost2004
    );

    // A CMS with encapsulated content gets the new signer.
    let first = cms::sign(&entry("user-gost2004-sign"), b"doc", &sign_opts(true)).unwrap();
    let s = setup(script![storage("user-rsa-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "", b64(&first), true]),
    );
    let signers = verify(&unb64(&reply), None).unwrap();
    assert_eq!(signers.len(), 2);
    assert_eq!(signers[1].sig_alg, SigAlg::RsaSha256);

    // A detached CMS cannot be co-signed.
    let detached = cms::sign(&entry("user-gost2004-sign"), b"doc", &sign_opts(false)).unwrap();
    let s = setup(script![storage("user-rsa-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "", b64(&detached), true]),
    );
    assert_eq!(failed(&reply), "CMS_NO_ENCAPSULATED_DATA");
}

#[test]
fn cosigns_the_original_ncalayer_ber_cms() {
    // BER with indefinite lengths, made by the original NCALayer (GOST 2015-512).
    let original = read(ncanode("cades-test-signed-b.p7s"));
    let s = setup(script![storage("user-rsa-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "", b64(&original), true]),
    );
    let signers = verify(&unb64(&reply), None).unwrap();
    assert_eq!(signers.len(), 2);
    assert_eq!(signers[0].sig_alg, SigAlg::Gost2015_512);
    assert_eq!(signers[1].sig_alg, SigAlg::RsaSha256);
}

#[test]
fn base64_is_decoded_after_the_dialogs_with_java_messages() {
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "", "YQ@=", true]),
    );
    assert_eq!(failed(&reply), "Illegal base64 character 40");
    assert_eq!(s.prompter.key_prompts().len(), 1);

    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(&s.cu, "applyCAdEST", json!(["PKCS12", "", "Y"]));
    assert_eq!(
        failed(&reply),
        "Input byte[] should at least have 2 bytes for base64 bytes"
    );
}

#[test]
fn cades_methods_check_the_signer_chain() {
    // The default CAs are the NCA production ones: a synthetic key has no issuer there.
    let prompter = Arc::new(ScriptedPrompter::new(script![
        storage("user-gost2015-sign"),
        key(0),
        storage("user-gost2015-sign"),
        key(0),
        storage("user-gost2015-sign"),
        key(0),
        storage("user-gost2015-sign"),
        key(0),
    ]));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let cu = CommonUtils::new(prompter, tsa);
    for (method, args) in [
        ("createCAdESFromBase64", json!(["PKCS12", "", "YQ==", true])),
        ("createCAdESFromBase64Hash", json!(["PKCS12", "", "YQ=="])),
        ("applyCAdEST", json!(["PKCS12", "", "YQ=="])),
    ] {
        assert_eq!(
            failed(&call(&cu, method, args)),
            "ISSUER_CERT_NOT_FOUND",
            "{method}"
        );
    }
    // The deprecated CMS signature does not check it.
    ok(&call(
        &cu,
        "createCMSSignatureFromBase64",
        json!(["PKCS12", "", "YQ==", true]),
    ));

    // An expired key's chain is checked at its notAfter.
    let s = setup(script![storage("inter-expired-gost2015-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "", "YQ==", true]),
    );
    assert_eq!(verify(&unb64(&reply), None).unwrap().len(), 1);
    // A CA not valid at that time breaks the chain.
    let s = setup(script![storage("expired-gost2015-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCAdESFromBase64",
        json!(["PKCS12", "", "YQ==", true]),
    );
    assert!(
        failed(&reply).starts_with("java.security.cert.CertPathBuilderException: "),
        "{reply}"
    );
}

#[test]
fn cades_from_base64_hash_is_detached_and_digested() {
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let hash = SigAlg::Gost2015_512.digest(b"document");
    let reply = call(
        &s.cu,
        "createCAdESFromBase64Hash",
        json!(["PKCS12", "SIGNATURE", b64(&hash)]),
    );
    let der = unb64(&reply);
    assert!(verify(&der, None).is_err());
    assert_eq!(verify(&der, Some(b"document")).unwrap().len(), 1);
}

#[test]
fn files_are_read_first_and_shown_in_the_dialogs() {
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(dir.path(), "договор.txt", "содержимое".as_bytes());
    for method in ["createCAdESFromFile", "createCMSSignatureFromFile"] {
        let s = setup(script![storage("user-gost2015-sign"), key(0)]);
        let reply = call(&s.cu, method, json!(["PKCS12", "", path, true]));
        let signers = verify(&unb64(&reply), None).unwrap();
        assert_eq!(signers.len(), 1, "{method}");
        let detail = Some(format!("Файл: {}", shown(&path)));
        assert_eq!(s.prompter.storage_prompts()[0].detail, detail);
        assert_eq!(s.prompter.key_prompts()[0].detail, detail);

        // A missing file fails before any dialog, whatever the storage.
        let s = setup(script![]);
        for storage_name in ["PKCS12", "", "NOPE"] {
            let missing = dir.path().join("missing.txt");
            let reply = call(
                &s.cu,
                method,
                json!([storage_name, "", missing.to_str().unwrap(), true]),
            );
            assert_eq!(failed(&reply), "file.not_found", "{method}");
        }
        // A folder cannot be read either.
        let reply = call(
            &s.cu,
            method,
            json!(["PKCS12", "", dir.path().to_str().unwrap(), true]),
        );
        assert_eq!(failed(&reply), "file.not_found", "{method}");
        // Nor a file over the limit (sparse: no disk space used).
        let big = dir.path().join("big.bin");
        std::fs::File::create(&big)
            .unwrap()
            .set_len((64 << 20) + 1)
            .unwrap();
        let reply = call(
            &s.cu,
            method,
            json!(["PKCS12", "", big.to_str().unwrap(), true]),
        );
        assert_eq!(
            failed(&reply),
            "file.too_large: files over 64 MiB are not signed",
            "{method}"
        );
        assert!(s.prompter.storage_prompts().is_empty());
    }

    // The detail follows the dialog language.
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    ok(&call(&s.cu, "changeLocale", json!(["en"])));
    ok(&call(
        &s.cu,
        "createCAdESFromFile",
        json!(["PKCS12", "", path, false]),
    ));
    assert_eq!(
        s.prompter.storage_prompts()[0].detail,
        Some(format!("File: {}", shown(&path)))
    );

    // The dialogs show the absolute path of the file read, whatever the page wrote.
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let roundabout = sub.join("..").join("договор.txt");
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    ok(&call(
        &s.cu,
        "createCAdESFromFile",
        json!(["PKCS12", "", roundabout.to_str().unwrap(), false]),
    ));
    let detail = s.prompter.storage_prompts()[0].detail.clone().unwrap();
    assert_eq!(detail, format!("Файл: {}", shown(&path)));
    assert!(!detail.contains(".."), "{detail}");
}

/// The path the dialogs show for `path`.
fn shown(path: &str) -> String {
    #[cfg(windows)]
    let shown = std::path::absolute(path).unwrap();
    #[cfg(not(windows))]
    let shown = std::fs::canonicalize(path).unwrap();
    shown.display().to_string()
}

#[cfg(unix)]
#[test]
fn fifos_and_devices_are_refused_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let s = setup(script![]);
    for path in [fifo.to_str().unwrap(), "/dev/zero", "/dev/urandom"] {
        for method in ["createCAdESFromFile", "createCMSSignatureFromFile"] {
            let started = std::time::Instant::now();
            let reply = call(&s.cu, method, json!(["PKCS12", "", path, true]));
            assert_eq!(failed(&reply), "file.not_found", "{method} {path}");
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
        }
    }
    assert!(s.prompter.storage_prompts().is_empty());
}

#[test]
fn apply_cades_t_stamps_the_chosen_keys_signer() {
    // A detached signature: the stamp needs no content.
    let cms_der = cms::sign(&entry("user-gost2015-sign"), b"doc", &sign_opts(false)).unwrap();
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(&s.cu, "applyCAdEST", json!(["PKCS12", "", b64(&cms_der)]));
    let stamped = unb64(&reply);
    let signers = verify(&stamped, Some(b"doc")).unwrap();
    let token = signers[0].timestamp_token.as_ref().unwrap();
    let tst = verify_token(token).unwrap();
    assert_eq!(tst.policy.to_string(), TSA_RSA_POLICY);
    assert_eq!(tst.imprint_alg, oid::SHA256);
    let calls = s.tsa.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].starts_with("http://tsp.pki.gov.kz/"),
        "{}",
        calls[0]
    );

    // Only the chosen key's signer gets the stamp.
    let first = cms::sign(&entry("user-rsa-sign"), b"doc", &sign_opts(true)).unwrap();
    let both = cms::sign(&entry("user-gost2015-sign"), &first, &sign_opts(true)).unwrap();
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(&s.cu, "applyCAdEST", json!(["PKCS12", "", b64(&both)]));
    let signers = verify(&unb64(&reply), None).unwrap();
    assert!(signers[0].timestamp_token.is_none());
    assert!(signers[1].timestamp_token.is_some());

    // No signer of the chosen key: the original's NullPointerException, no message.
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = raw(
        &s.cu,
        json!({"module": MODULE_NAME, "method": "applyCAdEST",
            "args": ["PKCS12", "", b64(&first)]}),
    );
    assert_eq!(reply, r#"{"code":"500"}"#);

    // Not a CMS.
    let s = setup(script![storage("user-gost2015-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "applyCAdEST",
        json!(["PKCS12", "", b64(b"not a cms")]),
    );
    assert!(failed(&reply).starts_with("malformed CMS"), "{reply}");
}

#[test]
fn cms_signature_carries_a_time_stamp() {
    let s = setup(script![storage("user-gost2004-sign"), key(0)]);
    let reply = call(
        &s.cu,
        "createCMSSignatureFromBase64",
        json!(["PKCS12", "", b64(b"doc"), false]),
    );
    let der = unb64(&reply);
    let signers = verify(&der, Some(b"doc")).unwrap();
    assert_eq!(signers[0].sig_alg, SigAlg::Gost2004);
    let tst = verify_token(signers[0].timestamp_token.as_ref().unwrap()).unwrap();
    assert_eq!(tst.policy.to_string(), TSA_RSA_POLICY);
    assert_eq!(s.tsa.calls().len(), 1);
}

#[test]
fn show_file_chooser_kinds_and_answers() {
    let dir = tempfile::tempdir().unwrap();
    let file = temp_file(dir.path(), "c.cer", b"x");
    let dir_str = dir.path().to_str().unwrap().to_owned();

    let s = setup(script![
        Step::File(dir.path().to_path_buf()),
        Step::File(PathBuf::from(&file)),
        Step::File(dir.path().join("gone.p12")),
        Step::CancelFile,
    ]);
    // An empty extension chooses a folder.
    let reply = call(&s.cu, "showFileChooser", json!(["", ""]));
    assert_eq!(ok(&reply), &json!(dir_str));
    let reply = call(&s.cu, "showFileChooser", json!(["CER", dir_str]));
    assert_eq!(ok(&reply), &json!(file));
    // A path that does not exist, and a cancel: action.canceled.
    let reply = call(&s.cu, "showFileChooser", json!(["P12", ""]));
    assert_eq!(failed(&reply), "action.canceled");
    let reply = call(&s.cu, "showFileChooser", json!(["ALL", ""]));
    assert_eq!(failed(&reply), "action.canceled");

    let prompts = s.prompter.file_prompts();
    let kinds: Vec<_> = prompts.iter().map(|p| p.kind).collect();
    assert_eq!(
        kinds,
        [
            FileKind::Directory,
            FileKind::Cer,
            FileKind::P12,
            FileKind::All
        ]
    );
    assert_eq!(prompts[0].directory, None);
    assert_eq!(prompts[1].directory, Some(dir.path().to_path_buf()));
    assert_eq!(prompts[0].origin, "https://x.kz");
    assert_eq!(prompts[0].locale, Locale::Ru);

    // An unknown kind is Java's `valueOf` failure, before any dialog.
    let s = setup(script![]);
    for ext in ["xyz", "all", "Cer"] {
        assert_eq!(
            failed(&call(&s.cu, "showFileChooser", json!([ext, ""]))),
            format!("No enum constant kz.gov.pki.knca.gui.fileChooser.FileChooser.FileType.{ext}")
        );
    }
    assert!(s.prompter.file_prompts().is_empty());
}

#[test]
fn change_locale_switches_the_dialog_language() {
    let s = setup(script![]);
    let locale_after = |language: &str| {
        assert_eq!(
            raw(
                &s.cu,
                json!({"module": MODULE_NAME, "method": "changeLocale", "args": [language]})
            ),
            r#"{"code":"200"}"#
        );
        call(&s.cu, "showFileChooser", json!(["", ""]));
        s.prompter.file_prompts().last().unwrap().locale
    };
    assert_eq!(locale_after("kk"), Locale::Kk);
    // Unknown or differently cased languages change nothing.
    assert_eq!(locale_after("de"), Locale::Kk);
    assert_eq!(locale_after("EN"), Locale::Kk);
    assert_eq!(locale_after("en"), Locale::En);
    // Empty: back to Russian.
    assert_eq!(locale_after(""), Locale::Ru);
}

thread_local! {
    /// Formatted log lines of events on this thread.
    static THREAD_LOG: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Writes into [`THREAD_LOG`] of the writing thread.
struct ThreadLog;

impl io::Write for ThreadLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        THREAD_LOG.with(|log| log.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Every event of this test binary, at every level, goes to the emitting thread's
/// [`THREAD_LOG`]. A process-wide subscriber: a scoped one misses events while other tests
/// register the same callsites in parallel.
fn capture_logs() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(|| ThreadLog)
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

#[test]
fn page_paths_and_passwords_stay_out_of_the_log() {
    const SECRET: &str = "LogSecret741";
    capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let path = temp_file(dir.path(), "secret-contract.txt", b"doc");
    let missing = dir.path().join("secret-missing.txt");
    let missing = missing.to_str().unwrap();
    let store = synthetic("user-gost2015-sign");
    // A copy of the key file whose password is the secret.
    let e = entry("user-gost2015-sign");
    let p12 = write(
        &[WriteEntry {
            alias: e.alias.clone(),
            pkcs8_der: e.key.to_pkcs8_der().to_vec(),
            cert_der: Some(e.cert.to_der().unwrap()),
        }],
        &[],
        SECRET,
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(9),
    )
    .unwrap();
    let key_file = dir.path().join("secret-key.p12");
    std::fs::write(&key_file, p12).unwrap();
    let secret_store = || Step::Storage {
        path: key_file.clone(),
        password: SECRET.to_owned(),
    };
    for method in ["createCAdESFromFile", "createCMSSignatureFromFile"] {
        // Success, after a wrong password.
        let s = setup(script![
            Step::Storage {
                path: key_file.clone(),
                password: store.password.clone(),
            },
            secret_store(),
            key(0)
        ]);
        ok(&call(&s.cu, method, json!(["PKCS12", "", path, true])));
        // file.not_found.
        failed(&call(&s.cu, method, json!(["PKCS12", "", missing, true])));
        // Cancelled.
        let s = setup(script![secret_store(), Step::CancelKey]);
        failed(&call(&s.cu, method, json!(["PKCS12", "", path, true])));
        // A signing failure: a detached CMS cannot be co-signed.
        let detached = cms::sign(&e, b"doc", &sign_opts(false)).unwrap();
        let cms_path = temp_file(dir.path(), "secret-detached.p7s", &detached);
        let s = setup(script![secret_store(), key(0)]);
        failed(&call(&s.cu, method, json!(["PKCS12", "", cms_path, true])));
    }

    let log = THREAD_LOG.with(|log| String::from_utf8(log.borrow().clone()).unwrap());
    assert!(
        log.contains("commonUtils call failed"),
        "the flow logs: {log}"
    );
    for secret in [SECRET, "secret-", &dir.path().display().to_string()] {
        assert!(!log.contains(secret), "{secret:?} in the log:\n{log}");
    }
}
