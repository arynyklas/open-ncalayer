//! The medium ports: taxtech, energy, eproc, osdkz ESF, uchet esfSignUtil, qiwi, bas, eup,
//! dogovor24, workspace, Simourg and motiw, run as the daemon runs them.

use oncl_basics::testing::Step;
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_port_tests::{Harness, default_clock, entry, p12};
use oncl_protocol::Reply;
use oncl_protocol::javab64::decode_java;
use std::sync::atomic::{AtomicI64, Ordering};
use time::OffsetDateTime;

/// Answers the storage dialog with the synthetic store `name` and picks its key `n`.
fn pick(name: &str, n: usize) -> Vec<Step> {
    let (path, password) = p12(name);
    vec![
        Step::Storage {
            path,
            password: password.to_owned(),
        },
        Step::Key(n),
    ]
}

/// The text of a reply that is not a dropped connection.
fn text(reply: Reply) -> String {
    reply
        .into_text()
        .expect("a reply, not a dropped connection")
}

/// The Kalkan DN of the subject of the synthetic store `name`'s key.
fn subject_dn(name: &str) -> String {
    oncl_pki::info::kalkan_dn(entry(name).cert.tbs_certificate().subject())
}

/// The DER inside a PEM text, whatever its line separator.
fn pem_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    decode_java(&body).unwrap()
}

// taxtech

const TAXTECH: &str = "kz.digital.taxtech.documents.multisign.NCAModule";

fn taxtech(method: &str, args: &str) -> String {
    format!(r#"{{"module":"{TAXTECH}","method":"{method}","args":{args}}}"#)
}

const TAXTECH_SELECT: &str = r#"{"signerParams":{"extKeyUsageOids":[],"chain":[]}}"#;

#[test]
fn taxtech_select_key_reply() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("taxtech");
    let origin = Some("https://edo.example.kz/app");
    let reply = text(session.call(&taxtech("selectKey", TAXTECH_SELECT), origin));
    let dn = subject_dn("user-gost2015-sign");
    let iin = dn
        .split("SERIALNUMBER=IIN")
        .nth(1)
        .map(|rest| &rest[..12])
        .unwrap();
    assert_eq!(
        reply,
        format!(r#"{{"success":true,"subjectDN":"{dn}","iin":"{iin}"}}"#)
    );
    assert_eq!(
        text(session.call(&taxtech("selectedKeyInfo", "{}"), origin)),
        reply
    );
    assert_eq!(
        text(session.call(&taxtech("version", "{}"), origin)),
        r#"{"success":true,"version":"1.0"}"#
    );
    // The dialog offers every Kalkan storage.
    let storages = &harness.prompter().storage_prompts()[0].storages;
    assert_eq!(storages.len(), 9);
}

#[test]
fn taxtech_select_key_errors() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let mut session = harness.session("taxtech");
    assert_eq!(
        text(session.call(&taxtech("selectKey", "{}"), None)),
        r#"{"success":false,"errorMessage":"JSONObject[\"signerParams\"] not found.","errorCode":"TECH_ERROR"}"#
    );
    assert_eq!(
        text(session.call(
            &taxtech("selectKey", r#"{"signerParams":{"extKeyUsageOids":[1]}}"#),
            None
        )),
        r#"{"success":false,"errorMessage":"java.lang.Integer cannot be cast to java.lang.String","errorCode":"TECH_ERROR"}"#
    );
    assert_eq!(
        text(session.call(
            &taxtech(
                "selectKey",
                r#"{"signerParams":{"extKeyUsageOids":[],"chain":["AAAA"]}}"#
            ),
            None
        )),
        r#"{"success":false,"errorMessage":"Certificate parsing failure.","errorCode":"CERTIFICATE_PARSING_FAILURE"}"#
    );
    assert_eq!(
        text(session.call(&taxtech("selectKey", TAXTECH_SELECT), None)),
        r#"{"success":false,"errorMessage":"Key not selected.","errorCode":"KEY_NOT_SELECTED"}"#
    );
}

#[test]
fn taxtech_origin_binding() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("taxtech");
    session.call(
        &taxtech("selectKey", TAXTECH_SELECT),
        Some("https://edo.example.kz/a/b"),
    );
    let info = taxtech("selectedKeyInfo", "{}");
    // The same scheme, host and port: the same site.
    assert!(
        text(session.call(&info, Some("https://edo.example.kz"))).starts_with(r#"{"success":true"#)
    );
    let not_selected =
        r#"{"success":false,"errorMessage":"Key not selected.","errorCode":"KEY_NOT_SELECTED"}"#;
    for other in [Some("https://other.example.kz"), Some("null"), None] {
        assert_eq!(text(session.call(&info, other)), not_selected, "{other:?}");
        assert_eq!(
            text(session.call(&taxtech("sign", r#"{"format":"raw","data":"x"}"#), other)),
            not_selected
        );
    }
    assert_eq!(
        text(session.call(&taxtech("reset", "{}"), Some("https://edo.example.kz"))),
        r#"{"success":true}"#
    );
    assert_eq!(
        text(session.call(&info, Some("https://edo.example.kz"))),
        not_selected
    );
}

#[test]
fn taxtech_sign_cms_pem_lines() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("taxtech");
    let origin = Some("https://edo.example.kz");
    session.call(&taxtech("selectKey", TAXTECH_SELECT), origin);
    let reply = text(session.call(
        &taxtech(
            "sign",
            r#"{"format":"cms","data":["hello","ignored"],"signingParams":{}}"#,
        ),
        origin,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert!(
        reply.starts_with(r#"{"result":"-----BEGIN CMS-----"#),
        "{reply}"
    );
    assert!(reply.ends_with(r#"","success":true}"#));
    let pem = value["result"].as_str().unwrap();
    let nl = if cfg!(windows) { "\r\n" } else { "\n" };
    assert!(pem.starts_with(&format!("-----BEGIN CMS-----{nl}")));
    assert!(pem.ends_with(&format!("-----END CMS-----{nl}")));
    let lines: Vec<&str> = pem.split(nl).collect();
    let body = &lines[1..lines.len() - 2];
    assert!(body[..body.len() - 1].iter().all(|line| line.len() == 64));
    let cms = pem_der(pem);
    // Attached by default: the content is in the CMS.
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert!(signers[0].timestamp_token.is_none());
    assert!(harness.http_log().is_empty());
}

#[test]
fn taxtech_sign_cms_with_tsp_is_kalkan_profile() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("taxtech");
    session.call(&taxtech("selectKey", TAXTECH_SELECT), None);
    let reply = text(session.call(
        &taxtech(
            "sign",
            r#"{"format":"cms","data":"aGVsbG8=","signingParams":{"decode":true,"encapsulate":false,"tsaProfile":{"withTsp":true}}}"#,
        ),
        None,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let cms = pem_der(value["result"].as_str().unwrap());
    let signers = oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    assert!(signers[0].timestamp_token.is_some());
    let log = harness.http_log();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("GET http://tsp.pki.gov.kz"), "{log:?}");
}

#[test]
fn taxtech_sign_cms_digested() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("taxtech");
    session.call(&taxtech("selectKey", TAXTECH_SELECT), None);
    let digest = SigAlg::Gost2015_512.digest(b"document");
    let request = format!(
        r#"{{"format":"cms","data":["{}"],"signingParams":{{"decode":true,"encapsulate":false,"digested":true}}}}"#,
        oncl_protocol::javab64::encode_mime(&digest).replace("\r\n", "")
    );
    let reply = text(session.call(&taxtech("sign", &request), None));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let cms = pem_der(value["result"].as_str().unwrap());
    // messageDigest is the digest given: the CMS verifies over the document.
    oncl_pki::cms::verify(&cms, Some(b"document")).unwrap();
    // A digest is never encapsulated.
    let encapsulated = taxtech(
        "sign",
        &request.replace(r#""encapsulate":false"#, r#""encapsulate":true"#),
    );
    assert_eq!(
        text(session.call(&encapsulated, None)),
        r#"{"success":false,"errorMessage":"Signing has failed.","errorCode":"SIGNING_FAILURE"}"#
    );
    // Without signingParams, cms dereferences null.
    assert_eq!(
        text(session.call(&taxtech("sign", r#"{"format":"cms","data":"x"}"#), None)),
        r#"{"success":false,"errorCode":"TECH_ERROR"}"#
    );
}

#[test]
fn taxtech_sign_raw_rsa_sha256() {
    let harness = Harness::new(pick("user-rsa-sign", 0), vec![]);
    let mut session = harness.session("taxtech");
    session.call(&taxtech("selectKey", TAXTECH_SELECT), None);
    let reply = text(session.call(
        &taxtech(
            "sign",
            r#"{"format":"raw","data":["cmF3"],"signingParams":{"decode":true}}"#,
        ),
        None,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["success"], true);
    let signature = decode_java(value["result"].as_str().unwrap()).unwrap();
    let cert = entry("user-rsa-sign").cert;
    let key = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info()).unwrap();
    key.verify(SigAlg::RsaSha256, b"raw", &signature).unwrap();
    assert_eq!(
        text(session.call(&taxtech("sign", r#"{"format":"pdf","data":"x"}"#), None)),
        r#"{"success":false,"errorMessage":"Invalid signing parameters provided.","errorCode":"INVALID_SIGNING_PARAMS"}"#
    );
}

#[test]
fn taxtech_sign_xml_every_document() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("taxtech");
    session.call(&taxtech("selectKey", TAXTECH_SELECT), None);
    let reply = text(session.call(
        &taxtech("sign", r#"{"format":"xml","data":["<a>1</a>","<b>2</b>"]}"#),
        None,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let docs = value["result"].as_array().unwrap();
    assert_eq!(docs.len(), 2);
    for doc in docs {
        oncl_pki::xmldsig::verify(doc.as_str().unwrap().as_bytes()).unwrap();
    }
}

static TAXTECH_NOW: AtomicI64 = AtomicI64::new(0);

fn taxtech_clock() -> OffsetDateTime {
    match TAXTECH_NOW.load(Ordering::SeqCst) {
        0 => default_clock(),
        at => OffsetDateTime::from_unix_timestamp(at).unwrap(),
    }
}

#[test]
fn taxtech_expired_check_order() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]).with_clock(taxtech_clock);
    let mut session = harness.session("taxtech");
    session.call(&taxtech("selectKey", TAXTECH_SELECT), None);
    // 2200-01-01: the selected certificate has expired since.
    TAXTECH_NOW.store(7_258_118_400, Ordering::SeqCst);
    // The certificate is checked before the arguments.
    assert_eq!(
        text(session.call(
            &format!(r#"{{"module":"{TAXTECH}","method":"sign"}}"#),
            None
        )),
        r#"{"success":false,"errorMessage":"Certificate expired.","errorCode":"CERTIFICATE_EXPIRED"}"#
    );
    TAXTECH_NOW.store(0, Ordering::SeqCst);
    assert_eq!(
        text(session.call(
            &format!(r#"{{"module":"{TAXTECH}","method":"sign"}}"#),
            None
        )),
        r#"{"success":false,"errorMessage":"JSONObject[\"args\"] not found.","errorCode":"TECH_ERROR"}"#
    );
}

#[test]
fn taxtech_missing_method_drops() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("taxtech");
    assert_eq!(
        session.call(&format!(r#"{{"module":"{TAXTECH}"}}"#), None),
        Reply::Drop
    );
    assert_eq!(
        session.call(&format!(r#"{{"module":"{TAXTECH}","method":7}}"#), None),
        Reply::Drop
    );
    assert!(harness.prompter().timeline().is_empty());
}

#[test]
fn taxtech_unknown_method_tech_error() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call("taxtech", &taxtech("signXml", "{}"), None)),
        r#"{"success":false,"errorCode":"TECH_ERROR"}"#
    );
}

/// Asserts that `keys` appear in `json` in this order, each once.
fn assert_key_order(json: &str, keys: &[&str]) {
    let at: Vec<usize> = keys
        .iter()
        .map(|key| {
            let quoted = format!("\"{key}\":");
            assert_eq!(json.matches(&quoted).count(), 1, "{key} in {json}");
            json.find(&quoted).unwrap()
        })
        .collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "{keys:?} in {json}");
}

// energy

const ENERGY: &str = "kz.energy.sign.SignEnergy";

fn energy(method: &str, args: &str) -> String {
    format!(r#"{{"module":"{ENERGY}","method":"{method}","args":{args}}}"#)
}

const ENERGY_USER_ALIAS: &str = "a3c1901ac6b0bfaed7b9b4b0610ac07243210e31";

fn energy_sign(alias: Option<&str>) -> String {
    let alias = alias.map_or(String::new(), |a| format!(r#""alias":"{a}","#));
    energy(
        "sign",
        &format!(
            r#"{{{alias}"keyStoreType":"PKCS12","encapsulate":false,"data":[{{"id":"1","name":"a.pdf","base64":"aGVsbG8="}},{{"base64":"d29ybGQ="}}]}}"#
        ),
    )
}

const ENERGY_CANCELLED: &str =
    r#"{"success":false,"message":"signing_cancelled_by_user","body":{"result":[]}}"#;

#[test]
fn energy_ping_overflow_and_null_string() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("energy");
    let ping = |session: &mut oncl_port_tests::SessionHandle, args: &str| {
        text(session.call(&energy("ping", args), None))
    };
    assert_eq!(
        ping(&mut session, r#"{"number":41}"#),
        r#"{"success":true,"message":"null","body":{"result":"Pong=42"}}"#
    );
    assert_eq!(
        ping(&mut session, r#"{"number":2147483647}"#),
        r#"{"success":true,"message":"null","body":{"result":"Pong=-2147483648"}}"#
    );
    assert_eq!(
        ping(&mut session, r#"{"number":"5"}"#),
        r#"{"success":true,"message":"null","body":{"result":"Pong=6"}}"#
    );
    assert_eq!(
        ping(&mut session, r#"{"number":true}"#),
        r#"{"success":true,"message":"null","body":{"result":"Pong=1"}}"#
    );
    assert_eq!(
        text(session.call(&energy("pong", "{}"), None)),
        r#"{"success":false,"message":"method_not_defined"}"#
    );
    assert_eq!(
        text(session.call(&format!(r#"{{"module":"{ENERGY}","args":{{}}}}"#), None)),
        r#"{"success":false,"message":"method_not_defined"}"#
    );
    // args must be an object.
    for request in [
        format!(r#"{{"module":"{ENERGY}","method":"ping"}}"#),
        energy("ping", "[1]"),
    ] {
        assert_eq!(session.call(&request, None), Reply::Drop, "{request}");
    }
}

#[test]
fn energy_get_key_info_cancel_drops() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        harness.call(
            "energy",
            &energy("getKeyInfo", r#"{"keyStoreType":"PKCS12"}"#),
            None
        ),
        Reply::Drop
    );
    // A storage the core does not know: the original's load error, then no reply.
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        harness.call(
            "energy",
            &energy("getKeyInfo", r#"{"keyStoreType":"BKS"}"#),
            None
        ),
        Reply::Drop
    );
}

#[test]
fn energy_get_key_info_reply() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call("energy", &energy("getKeyInfo", "{}"), None));
    assert!(
        reply.starts_with(r#"{"code":"200","responseObject":{"#),
        "{reply}"
    );
    assert_key_order(
        &reply,
        &[
            "certNotBefore",
            "issuerCn",
            "authorityKeyIdentifier",
            "serialNumber",
            "certNotAfter",
            "issuerDn",
            "alias",
            "keyId",
            "pem",
            "subjectCn",
            "algorithm",
            "subjectDn",
        ],
    );
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let info = &value["responseObject"];
    assert_eq!(info["alias"], ENERGY_USER_ALIAS);
    assert_eq!(info["algorithm"], "ECGOST3410-2015");
    assert_eq!(info["subjectDn"], subject_dn("user-gost2015-sign"));
    let cert = entry("user-gost2015-sign").cert;
    assert_eq!(
        info["keyId"],
        oncl_pki::info::ski_hex(&cert).unwrap().as_str()
    );
    assert!(
        info["certNotAfter"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .is_ok()
    );
    assert!(
        info["pem"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
}

#[test]
fn energy_sign_reply_and_cms() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call("energy", &energy_sign(None), None));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert!(
        reply.starts_with(
            r#"{"success":true,"message":"null","body":{"result":[{"name":"a.pdf","signedBase64":""#
        ),
        "{reply}"
    );
    let docs = value["body"]["result"].as_array().unwrap();
    assert_eq!(docs.len(), 2);
    assert!(docs[1].get("id").is_none() && docs[1].get("name").is_none());
    for (doc, data) in docs.iter().zip([&b"hello"[..], b"world"]) {
        let cms = decode_java(doc["signedBase64"].as_str().unwrap()).unwrap();
        // Detached (encapsulate false), verified over the document.
        oncl_pki::cms::verify(&cms, Some(data)).unwrap();
    }
    assert!(harness.http_log().is_empty());
}

#[test]
fn energy_sign_remembered_alias_in_session_is_silent() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("energy");
    let first = text(session.call(&energy_sign(Some(ENERGY_USER_ALIAS)), None));
    assert!(first.starts_with(r#"{"success":true"#), "{first}");
    let shown = harness.prompter().timeline().len();
    let second = text(session.call(&energy_sign(Some(ENERGY_USER_ALIAS)), None));
    assert!(second.starts_with(r#"{"success":true"#), "{second}");
    assert_eq!(harness.prompter().timeline().len(), shown, "no dialog");
    // Another session (connection) asks again: the script is empty, so it cancels.
    assert_eq!(
        text(harness.call("energy", &energy_sign(Some(ENERGY_USER_ALIAS)), None)),
        ENERGY_CANCELLED
    );
}

#[test]
fn energy_settings_store_path_not_password() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("energy-settings");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let harness =
        Harness::new(pick("user-gost2015-sign", 0), vec![]).with_settings_dir(dir.clone());
    let reply = text(harness.call("energy", &energy_sign(Some(ENERGY_USER_ALIAS)), None));
    assert!(reply.starts_with(r#"{"success":true"#), "{reply}");
    let file = dir.join("io.github.arynyklas.openncalayer.port.energy.json");
    let stored = std::fs::read_to_string(&file).unwrap();
    assert!(!stored.contains(oncl_port_tests::P12_PASSWORD), "{stored}");
    assert!(!stored.contains("user-gost2015-sign.p12"), "{stored}");
    let settings: serde_json::Value = serde_json::from_str(&stored).unwrap();
    let record: serde_json::Value =
        serde_json::from_str(settings[ENERGY_USER_ALIAS].as_str().unwrap()).unwrap();
    let keys: Vec<&String> = record.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["alias", "certNotAfter", "certNotBefore", "subjectCn"]
    );
    assert_eq!(record["alias"], ENERGY_USER_ALIAS);
}

#[test]
fn energy_alias_mismatch_retries() {
    let mut steps = pick("user-gost2015-sign", 0);
    steps.push(Step::Message);
    steps.push(Step::CancelStorage);
    let harness = Harness::new(steps, vec![]);
    assert_eq!(
        text(harness.call("energy", &energy_sign(Some("another-alias")), None)),
        ENERGY_CANCELLED
    );
    let messages = harness.prompter().message_prompts();
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].text,
        "Сертификат ЭЦП не соответствует сертификату в профиле пользователя."
    );
    assert_eq!(harness.prompter().storage_prompts().len(), 2);
}

#[test]
fn energy_sign_error_retries_without_duplicates() {
    let mut steps = pick("user-gost2015-sign", 0);
    steps.push(Step::Message);
    steps.extend(pick("user-gost2015-sign", 0));
    steps.push(Step::Message);
    steps.push(Step::CancelStorage);
    let harness = Harness::new(steps, vec![]);
    let request = energy(
        "sign",
        r#"{"data":[{"id":"1","base64":"aGVsbG8="},{"id":"2","base64":"!!"}]}"#,
    );
    assert_eq!(
        text(harness.call("energy", &request, None)),
        ENERGY_CANCELLED
    );
    let messages = harness.prompter().message_prompts();
    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages[0].text,
        "Ошибка при подписи. Проверьте параметры ключа."
    );
}

#[test]
fn energy_cancel_reply() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        text(harness.call("energy", &energy_sign(None), None)),
        ENERGY_CANCELLED
    );
    // A document that is not an object drops the connection before any dialog.
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        harness.call("energy", &energy("sign", r#"{"data":["x"]}"#), None),
        Reply::Drop
    );
    assert!(harness.prompter().timeline().is_empty());
}

// eproc

const EPROC: &str = "kz.sapa.eproc.osgi.EprocModule";

fn eproc(fields: &str) -> String {
    format!(r#"{{"module":"{EPROC}",{fields}}}"#)
}

fn eproc_sign(extra: &str) -> String {
    eproc(&format!(
        r#""method":"signXml","uid":"r-1","storageName":"PKCS12","keyType":"SIGNATURE","xml":"<doc><a Id=\"x\">1</a></doc>"{extra}"#
    ))
}

/// `newChain` of an eproc reply.
fn new_chain(reply: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(reply).unwrap();
    value["newChain"].as_str().unwrap().to_owned()
}

#[test]
fn eproc_version() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call("eproc", &eproc(r#""method":"version""#), None)),
        r#"{"responseObject":"1","code":"200","message":"Первый релиз"}"#
    );
}

#[test]
fn eproc_missing_method_message() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call("eproc", &eproc(r#""uid":"1""#), None)),
        r#"{"code":"500","message":"JSONObject[\"method\"] not found."}"#
    );
    assert_eq!(
        text(harness.call("eproc", &eproc(r#""method":1"#), None)),
        r#"{"code":"500","message":"JSONObject[\"method\"] is not a string."}"#
    );
}

#[test]
fn eproc_unknown_method_400() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call("eproc", &eproc(r#""method":"signCms""#), None)),
        r#"{"code":"400","message":"Incorrect method: signCms"}"#
    );
}

#[test]
fn eproc_sign_xml_new_chain() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call("eproc", &eproc_sign(""), None));
    assert_key_order(&reply, &["uid", "newChain", "responseObject", "code"]);
    assert!(reply.starts_with(r#"{"uid":"r-1","newChain":""#), "{reply}");
    assert!(reply.ends_with(r#","code":"200"}"#));
    let chain = new_chain(&reply);
    // A random UUID.
    assert_eq!(chain.len(), 36);
    assert_eq!(chain.as_bytes()[14], b'4');
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let signed = value["responseObject"].as_str().unwrap();
    oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap();
    // The storage dialog offers the page's storage only.
    let prompts = harness.prompter().storage_prompts();
    assert_eq!(prompts[0].storages.len(), 1);
}

#[test]
fn eproc_sign_xml_element_and_errors() {
    let mut steps = pick("user-gost2015-sign", 0);
    steps.extend(pick("user-gost2015-sign", 0));
    steps.push(Step::CancelStorage);
    let harness = Harness::new(steps, vec![]);
    let mut session = harness.session("eproc");
    let reply = text(session.call(
        &eproc_sign(r#","tbsElementXPath":"/doc/a","signatureParentElementXPath":"/doc""#),
        None,
    ));
    assert!(reply.ends_with(r#","code":"200"}"#), "{reply}");
    let reply = text(session.call(
        &eproc_sign(r#","tbsElementXPath":"/doc/a","signatureParentElementXPath":"/DOC/A""#),
        None,
    ));
    assert_eq!(
        reply,
        r#"{"uid":"r-1","code":"500","message":"При подписи элемента XML, элемент подписи не может быть родительским элементом подписи."}"#
    );
    assert_eq!(
        text(session.call(&eproc_sign(""), None)),
        r#"{"uid":"r-1","code":"500","message":"action.canceled"}"#
    );
    for (storage, message) in [
        ("", "storageName.param.empty"),
        ("BKS", "storage.unknown"),
        ("AKKaztokenStore", "storage.empty"),
    ] {
        let request = eproc_sign("").replace(
            r#""storageName":"PKCS12""#,
            &format!(r#""storageName":"{storage}""#),
        );
        assert_eq!(
            text(session.call(&request, None)),
            format!(r#"{{"uid":"r-1","code":"500","message":"{message}"}}"#)
        );
    }
    assert_eq!(
        text(session.call(&eproc(r#""method":"signXml""#), None)),
        r#"{"code":"500","message":"JSONObject[\"uid\"] not found."}"#
    );
    assert_eq!(
        text(session.call(&eproc(r#""method":"signXml","uid":"u""#), None)),
        r#"{"uid":"u","code":"500","message":"JSONObject[\"storageName\"] not found."}"#
    );
}

#[test]
fn eproc_chain_fast_path_one_time() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let mut session = harness.session("eproc");
    let first = new_chain(&text(session.call(&eproc_sign(""), None)));
    let shown = harness.prompter().timeline().len();
    let fast = text(session.call(&eproc_sign(&format!(r#","chain":"{first}""#)), None));
    assert_eq!(harness.prompter().timeline().len(), shown, "no dialog");
    let second = new_chain(&fast);
    assert_ne!(second, first);
    // The used chain is gone: the normal path asks again (and the script cancels).
    assert_eq!(
        text(session.call(&eproc_sign(&format!(r#","chain":"{first}""#)), None)),
        r#"{"uid":"r-1","code":"500","message":"action.canceled"}"#
    );
    // The new one works, in this connection only.
    assert!(
        text(session.call(&eproc_sign(&format!(r#","chain":"{second}""#)), None))
            .ends_with(r#""code":"200"}"#)
    );
    assert_eq!(
        text(harness.call(
            "eproc",
            &eproc_sign(&format!(r#","chain":"{second}""#)),
            None
        )),
        r#"{"uid":"r-1","code":"500","message":"action.canceled"}"#
    );
}

#[test]
fn eproc_bad_key_type_enum_text() {
    let harness = Harness::new(vec![], vec![]);
    let request = eproc_sign("").replace("SIGNATURE", "SIGN");
    assert_eq!(
        text(harness.call("eproc", &request, None)),
        r#"{"uid":"r-1","code":"500","message":"No enum constant kz.gov.pki.reference.KNCACertificateType.SIGN"}"#
    );
    assert!(harness.prompter().timeline().is_empty());
}
