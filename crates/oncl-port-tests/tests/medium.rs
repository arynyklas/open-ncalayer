//! The medium ports: taxtech, energy, eproc, osdkz ESF, uchet esfSignUtil, qiwi, bas, eup,
//! dogovor24, workspace, Simourg and motiw, run as the daemon runs them.

use oncl_flows::testing::Step;
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

/// `s` as a JSON string literal.
fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// The certificate of the synthetic store `name`'s first key, DER.
fn cert_der(name: &str) -> Vec<u8> {
    use der::Encode;
    entry(name).cert.to_der().unwrap()
}

/// Verifies a raw signature (base64) of `data` by the synthetic store `name`'s key.
fn verify_raw(name: &str, alg: SigAlg, data: &[u8], signature: &str) {
    let cert = entry(name).cert;
    let key = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info()).unwrap();
    key.verify(alg, data, &decode_java(signature).unwrap())
        .unwrap();
}

/// The text of `json` from the key `key` on.
fn from_key<'a>(json: &'a str, key: &str) -> &'a str {
    &json[json.find(&format!("\"{key}\":")).unwrap()..]
}

// osdkz ESF signer

const ESF: &str = "com.osdkz.esf.signer.esfSigner";

fn esf(fields: &str) -> String {
    format!(r#"{{"module":"{ESF}",{fields}}}"#)
}

/// The keyInfo keys in the order a certificate with SKI and AKI gives.
const ESF_KEY_INFO: [&str; 13] = [
    "certNotBefore",
    "issuerCn",
    "authorityKeyIdentifier",
    "serialNumber",
    "certNotAfter",
    "issuerDn",
    "keyId",
    "base64Pem",
    "alias",
    "pem",
    "subjectCn",
    "algorithm",
    "subjectDn",
];

#[test]
fn esf_missing_fields_drop() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("esf-osdkz");
    for fields in [
        r#""storageName":"PKCS12","data":"x""#,
        r#""method":"signPlainData","data":"x""#,
        r#""method":"signPlainData","storageName":"PKCS12","data":{}"#,
        r#""method":"auth","storageName":"PKCS12""#,
        r#""method":"signPlainDataMap","storageName":"PKCS12","data":"x""#,
    ] {
        assert_eq!(session.call(&esf(fields), None), Reply::Drop, "{fields}");
    }
    assert!(harness.prompter().timeline().is_empty());
}

#[test]
fn esf_unknown_404() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call("esf-osdkz", &esf(r#""method":"sign""#), None)),
        r#"{"code":"404"}"#
    );
}

#[test]
fn esf_sign_plain_data_reply_order() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "esf-osdkz",
        &esf(r#""method":"signPlainData","storageName":"PKCS12","data":"счёт-фактура""#),
        None,
    ));
    assert!(
        reply.starts_with(r#"{"responseObject":{"signature":""#),
        "{reply}"
    );
    assert!(reply.ends_with(r#"},"code":"200"}"#));
    let response = from_key(&reply, "signature");
    assert!(response.find("\"pem\":").unwrap() < response.find("\"keyInfo\":").unwrap());
    assert_key_order(from_key(&reply, "keyInfo"), &ESF_KEY_INFO);
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let object = &value["responseObject"];
    verify_raw(
        "user-gost2015-sign",
        SigAlg::Gost2015_512,
        "счёт-фактура".as_bytes(),
        object["signature"].as_str().unwrap(),
    );
    let info = &object["keyInfo"];
    assert_eq!(info["alias"], "a3c1901ac6b0bfaed7b9b4b0610ac07243210e31");
    assert_eq!(info["algorithm"], "ECGOST3410-2015");
    assert_eq!(info["subjectDn"], subject_dn("user-gost2015-sign"));
    assert_eq!(
        decode_java(info["base64Pem"].as_str().unwrap()).unwrap(),
        cert_der("user-gost2015-sign")
    );
    assert_eq!(info["pem"], object["pem"]);
}

#[test]
fn esf_storage_errors_and_cancel() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let mut session = harness.session("esf-osdkz");
    for (storage, message) in [
        ("PKCS12", "action.canceled"),
        (" ", "storageName.param.empty"),
        ("BKS", "storage.unknown"),
        ("AKKaztokenStore", "storage.empty"),
    ] {
        assert_eq!(
            text(session.call(
                &esf(&format!(
                    r#""method":"signPlainData","storageName":"{storage}","data":"x""#
                )),
                None
            )),
            format!(r#"{{"code":"500","message":"{message}"}}"#)
        );
    }
}

#[test]
fn esf_map_non_string_value() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    assert_eq!(
        text(harness.call(
            "esf-osdkz",
            &esf(r#""method":"signPlainDataMap","storageName":"PKCS12","data":{"esf1":5}"#),
            None
        )),
        r#"{"code":"500","message":"java.lang.Integer cannot be cast to java.lang.String"}"#
    );
}

#[test]
fn esf_map_keyinfo_overwrite() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "esf-osdkz",
        &esf(r#""method":"signPlainDataMap","storageName":"PKCS12","data":{"esf1":"a","keyInfo":"b"}"#),
        None,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let object = value["responseObject"].as_object().unwrap();
    assert_eq!(object.len(), 2, "{reply}");
    for (key, data) in [("esf1", "a"), ("keyInfo", "b")] {
        verify_raw(
            "user-gost2015-sign",
            SigAlg::Gost2015_512,
            data.as_bytes(),
            object[key].as_str().unwrap(),
        );
    }
    // Without the page's keyInfo: the key's details, and no pem.
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "esf-osdkz",
        &esf(
            r#""method":"signPlainDataMap","storageName":"PKCS12","data":{"esf1":"a","esf2":"b"}"#,
        ),
        None,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let object = value["responseObject"].as_object().unwrap();
    assert_eq!(object.len(), 3, "{reply}");
    assert!(object["keyInfo"].is_object());
}

#[test]
fn esf_auth_fallback_to_gost2015_sign() {
    // The first dialog ends without a key (closed): the GOST 2015 signing keys are offered.
    let mut steps = vec![
        Step::Storage {
            path: p12("user-gost2015-sign").0,
            password: "Qwerty12".to_owned(),
        },
        Step::CancelKey,
    ];
    steps.extend(pick("user-gost2015-sign", 0));
    let harness = Harness::new(steps, vec![]);
    let reply = text(harness.call(
        "esf-osdkz",
        &esf(r#""method":"auth","storageName":"PKCS12","data":"challenge""#),
        None,
    ));
    assert!(
        reply.starts_with(r#"{"responseObject":{"data":"challenge","signature":""#),
        "{reply}"
    );
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    verify_raw(
        "user-gost2015-sign",
        SigAlg::Gost2015_512,
        b"challenge",
        value["responseObject"]["signature"].as_str().unwrap(),
    );
    assert_eq!(harness.prompter().storage_prompts().len(), 2);
    // A GOST 2015 signing certificate is an authentication one too for Kalkan: one dialog.
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "esf-osdkz",
        &esf(r#""method":"auth","storageName":"PKCS12","data":"c""#),
        None,
    ));
    assert!(reply.ends_with(r#""code":"200"}"#), "{reply}");
    assert_eq!(harness.prompter().storage_prompts().len(), 1);
    // A GOST 2004 signing key is not offered in its place.
    let mut steps = vec![
        Step::Storage {
            path: p12("user-gost2004-sign").0,
            password: "Qwerty12".to_owned(),
        },
        Step::CancelKey,
    ];
    steps.extend(pick("user-gost2004-sign", 0));
    let harness = Harness::new(steps, vec![]);
    assert_eq!(
        text(harness.call(
            "esf-osdkz",
            &esf(r#""method":"auth","storageName":"PKCS12","data":"c""#),
            None
        )),
        r#"{"code":"500","message":"action.canceled"}"#
    );
}

#[test]
fn esf_key_info_with_and_without_ski() {
    let harness = Harness::new(pick("inter-noaki-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "esf-osdkz",
        &esf(r#""method":"signPlainData","storageName":"PKCS12","data":"x""#),
        None,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let info = &value["responseObject"]["keyInfo"];
    let cert = entry("inter-noaki-gost2015-sign").cert;
    assert_eq!(
        info.get("keyId").and_then(|v| v.as_str()),
        oncl_pki::info::ski_hex(&cert).as_deref()
    );
    assert!(info.get("authorityKeyIdentifier").is_none(), "{reply}");
    assert!(info.get("certificate").is_none());
}

// uchet esfSignUtil

const UCHET_ESF: &str = "kz.uchet.esfSignUtil";

fn uchet_esf(method: &str, store: &str, password: &str, extra: &str) -> String {
    let path = p12(store).0.display().to_string();
    format!(
        r#"{{"module":"{UCHET_ESF}","method":"{method}","args":{{"pkcsPath":{},"pkcsPassword":"{password}",{extra}}}}}"#,
        js(&path)
    )
}

#[test]
fn uchet_esf_sign_xml_status_number() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let mut session = harness.session("uchet-esf");
    let request = uchet_esf(
        "signXml",
        "user-gost2015-sign",
        "Qwerty12",
        r#""data":"<esf><a>1</a></esf>""#,
    );
    let reply = text(session.call(&request, None));
    assert!(
        reply.starts_with(r#"{"signedXml":"<esf><a>1<\/a>"#),
        "{reply}"
    );
    assert!(reply.ends_with(r#"","status":200}"#));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    oncl_pki::xmldsig::verify(value["signedXml"].as_str().unwrap().as_bytes()).unwrap();
    // The page's file is allowed once in the session.
    assert!(text(session.call(&request, None)).ends_with(r#""status":200}"#));
    assert_eq!(harness.prompter().confirm_prompts().len(), 1);
}

#[test]
fn uchet_esf_list_reply() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let reply = text(harness.call(
        "uchet-esf",
        &uchet_esf(
            "signEsfList",
            "multi-gost2015",
            "Qwerty12",
            r#""esfList":["<a/>","<b/>"]"#,
        ),
        None,
    ));
    assert!(
        reply.starts_with(r#"{"signedEsf":[{"signature":""#),
        "{reply}"
    );
    assert_key_order(&reply, &["signedEsf", "x509"]);
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    // The last key of the store signs.
    let store =
        oncl_pki::pkcs12::load(&std::fs::read(p12("multi-gost2015").0).unwrap(), "Qwerty12")
            .unwrap();
    let last = &store.last().unwrap().cert;
    use der::Encode;
    assert_eq!(
        decode_java(value["x509"].as_str().unwrap()).unwrap(),
        last.to_der().unwrap()
    );
    let key = PublicKey::from_spki(last.tbs_certificate().subject_public_key_info()).unwrap();
    let items = value["signedEsf"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for (item, data) in items.iter().zip(["<a/>", "<b/>"]) {
        let signature = decode_java(item["signature"].as_str().unwrap()).unwrap();
        key.verify(SigAlg::Gost2015_512, data.as_bytes(), &signature)
            .unwrap();
        assert!(
            item["pem"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }
    // An empty list.
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let reply = text(harness.call(
        "uchet-esf",
        &uchet_esf(
            "signEsfList",
            "user-gost2015-sign",
            "Qwerty12",
            r#""esfList":[]"#,
        ),
        None,
    ));
    assert!(
        reply.starts_with(r#"{"signedEsf":[],"x509":"MII"#),
        "{reply}"
    );
}

#[test]
fn uchet_esf_wrong_password_drops() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![]);
    let mut session = harness.session("uchet-esf");
    assert_eq!(
        session.call(
            &uchet_esf("signXml", "user-gost2015-sign", "wrong", r#""data":"<a/>""#),
            None
        ),
        Reply::Drop
    );
    // Malformed requests and documents drop the connection too.
    for request in [
        uchet_esf(
            "signXml",
            "user-gost2015-sign",
            "Qwerty12",
            r#""data":"<a>""#,
        ),
        uchet_esf("signXml", "user-gost2015-sign", "Qwerty12", r#""x":1"#),
        uchet_esf(
            "signEsfList",
            "user-gost2015-sign",
            "Qwerty12",
            r#""esfList":[1]"#,
        ),
        format!(r#"{{"module":"{UCHET_ESF}","method":"signXml"}}"#),
    ] {
        assert_eq!(session.call(&request, None), Reply::Drop, "{request}");
    }
}

#[test]
fn uchet_esf_consent_declined_drops() {
    let harness = Harness::new(vec![Step::Confirm { yes: false }], vec![]);
    assert_eq!(
        harness.call(
            "uchet-esf",
            &uchet_esf(
                "signXml",
                "user-gost2015-sign",
                "Qwerty12",
                r#""data":"<a/>""#
            ),
            None
        ),
        Reply::Drop
    );
    assert_eq!(harness.prompter().confirm_prompts().len(), 1);
}

#[test]
fn uchet_esf_unknown_method() {
    let harness = Harness::new(vec![], vec![]);
    for request in [
        format!(r#"{{"module":"{UCHET_ESF}","method":"sign","args":{{}}}}"#),
        format!(r#"{{"module":"{UCHET_ESF}"}}"#),
    ] {
        assert_eq!(
            text(harness.call("uchet-esf", &request, None)),
            r#"{"success":false,"errorCode":"method_not_defined"}"#
        );
    }
}

// qiwi

const QIWI: &str = "kz.qiwi.osgi.SecurityUtils";

fn qiwi(method: &str, args: &str) -> String {
    format!(r#"{{"module":"{QIWI}","method":"{method}","args":{args}}}"#)
}

const QIWI_XML: &str = r#"["42","<?xml version=\"1.0\"?><root><a>1</a></root>"]"#;

const QIWI_500: &str = r#"{"code":"500"}"#;

#[test]
fn qiwi_prologue_drops() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("qiwi");
    for request in [
        format!(r#"{{"module":"{QIWI}","args":["1"]}}"#),
        format!(r#"{{"module":"{QIWI}","method":"logOut"}}"#),
        qiwi("logOut", r#"{"0":"1"}"#),
        qiwi("logOut", "[]"),
        qiwi("signXml", "[1]"),
    ] {
        assert_eq!(session.call(&request, None), Reply::Drop, "{request}");
    }
    assert_eq!(
        text(session.call(&qiwi("other", r#"["1"]"#), None)),
        QIWI_500
    );
}

#[test]
fn qiwi_sign_xml_reply_bytes() {
    let harness = Harness::new(pick("user-gost2004-sign", 0), vec![]);
    let reply = text(harness.call("qiwi", &qiwi("signXml", QIWI_XML), None));
    assert!(
        reply.starts_with(
            r#"{"responseObject":{"callID":"42","verificationResult":true,"logOutResult":false,"signedXml":"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><root><a>1<\/a><ds:Signature"#
        ),
        "{reply}"
    );
    assert!(
        reply.ends_with(r#"<\/ds:Signature><\/root>"},"code":"200"}"#),
        "{reply}"
    );
}

#[test]
fn qiwi_signature_layout_and_uris() {
    for (store, signature, digest) in [
        (
            "user-gost2004-sign",
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        ),
        (
            "user-rsa-sign",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
    ] {
        let harness = Harness::new(pick(store, 0), vec![]);
        let reply = text(harness.call("qiwi", &qiwi("signXml", QIWI_XML), None));
        let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
        let xml = value["responseObject"]["signedXml"].as_str().unwrap();
        for needle in [
            format!(r#"<ds:SignatureMethod Algorithm="{signature}""#),
            format!(r#"<ds:DigestMethod Algorithm="{digest}""#),
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315""#.to_owned(),
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature""#.to_owned(),
            r#"<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments""#.to_owned(),
            r#"<ds:Reference URI="""#.to_owned(),
            "<ds:X509Certificate>".to_owned(),
        ] {
            assert!(xml.contains(&needle), "{store}: {needle} in {xml}");
        }
        assert_eq!(
            value["responseObject"]["verificationResult"], true,
            "{store}"
        );
        oncl_pki::xmldsig::verify(xml.as_bytes()).unwrap();
    }
}

#[test]
fn qiwi_failure_200_without_signed_xml() {
    let harness = Harness::new(pick("user-gost2004-sign", 0), vec![]);
    let mut session = harness.session("qiwi");
    // The document's first node is a comment: the signature has nowhere to go.
    let failed = r#"{"responseObject":{"callID":"42","verificationResult":false,"logOutResult":false},"code":"200"}"#;
    assert_eq!(
        text(session.call(&qiwi("signXml", r#"["42","<!--c--><root/>"]"#), None)),
        failed
    );
    // The session stays: the next document is signed without a dialog.
    let shown = harness.prompter().timeline().len();
    let reply = text(session.call(&qiwi("signXml", QIWI_XML), None));
    assert!(reply.contains(r#""verificationResult":true"#), "{reply}");
    assert_eq!(harness.prompter().timeline().len(), shown);
    // A missing document is an error: the session ends.
    assert_eq!(
        text(session.call(&qiwi("signXml", r#"["42"]"#), None)),
        QIWI_500
    );
    assert_eq!(
        text(session.call(&qiwi("signXml", QIWI_XML), None)),
        QIWI_500
    );
}

#[test]
fn qiwi_logout() {
    let harness = Harness::new(pick("user-gost2004-sign", 0), vec![]);
    let mut session = harness.session("qiwi");
    session.call(&qiwi("signXml", QIWI_XML), None);
    assert_eq!(
        text(session.call(&qiwi("logOut", r#"["7"]"#), None)),
        r#"{"responseObject":{"callID":"7","verificationResult":false,"logOutResult":true},"code":"200"}"#
    );
    // Logged out: the dialog again (the script is empty: cancelled).
    assert_eq!(
        text(session.call(&qiwi("signXml", QIWI_XML), None)),
        QIWI_500
    );
}

static QIWI_NOW: AtomicI64 = AtomicI64::new(0);

fn qiwi_clock() -> OffsetDateTime {
    default_clock() + time::Duration::seconds(QIWI_NOW.load(Ordering::SeqCst))
}

#[test]
fn qiwi_session_expires_after_20_min() {
    let harness = Harness::new(pick("user-gost2004-sign", 0), vec![]).with_clock(qiwi_clock);
    let mut session = harness.session("qiwi");
    session.call(&qiwi("signXml", QIWI_XML), None);
    let shown = harness.prompter().timeline().len();
    QIWI_NOW.store(19 * 60, Ordering::SeqCst);
    assert!(text(session.call(&qiwi("signXml", QIWI_XML), None)).contains(r#""code":"200""#));
    assert_eq!(harness.prompter().timeline().len(), shown);
    // 20 minutes after the last signature, not the first.
    QIWI_NOW.store(38 * 60, Ordering::SeqCst);
    assert!(text(session.call(&qiwi("signXml", QIWI_XML), None)).contains(r#""code":"200""#));
    QIWI_NOW.store(58 * 60 + 1, Ordering::SeqCst);
    assert_eq!(
        text(session.call(&qiwi("signXml", QIWI_XML), None)),
        QIWI_500
    );
    assert!(harness.prompter().timeline().len() > shown);
}

#[test]
fn qiwi_cancel_500() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        text(harness.call("qiwi", &qiwi("signXml", QIWI_XML), None)),
        QIWI_500
    );
}

// DER of the CMS the ESEDO ports make.

/// The first DER TLV of `input`: its tag, the whole TLV, its content and what follows.
fn tlv(input: &[u8]) -> (u8, &[u8], &[u8], &[u8]) {
    let (len, head) = match input[1] {
        short if short < 0x80 => (usize::from(short), 2),
        long => {
            let n = usize::from(long & 0x7f);
            let len = input[2..2 + n]
                .iter()
                .fold(0usize, |len, b| (len << 8) | usize::from(*b));
            (len, 2 + n)
        }
    };
    (
        input[0],
        &input[..head + len],
        &input[head..head + len],
        &input[head + len..],
    )
}

/// The TLVs inside `content`: tag, whole TLV, content.
fn children(mut content: &[u8]) -> Vec<(u8, &[u8], &[u8])> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tag, whole, inner, rest) = tlv(content);
        out.push((tag, whole, inner));
        content = rest;
    }
    out
}

/// A dotted OID of the content of an OBJECT IDENTIFIER.
fn oid(content: &[u8]) -> String {
    let mut arcs = vec![u64::from(content[0] / 40), u64::from(content[0] % 40)];
    let mut arc = 0u64;
    for b in &content[1..] {
        arc = (arc << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(arc);
            arc = 0;
        }
    }
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// What the tests read of a CMS: eContentType, eContent, and the first signer's
/// attributes (type, values as whole TLVs).
struct CmsView {
    econtent_type: String,
    econtent: Option<Vec<u8>>,
    signed: Vec<(String, Vec<Vec<u8>>)>,
    unsigned: Vec<(String, Vec<Vec<u8>>)>,
}

fn attributes(content: &[u8]) -> Vec<(String, Vec<Vec<u8>>)> {
    children(content)
        .into_iter()
        .map(|(_, _, attr)| {
            let parts = children(attr);
            let values = children(parts[1].2)
                .into_iter()
                .map(|(_, whole, _)| whole.to_vec())
                .collect();
            (oid(parts[0].2), values)
        })
        .collect()
}

fn cms_view(der: &[u8]) -> CmsView {
    let (_, _, content_info, _) = tlv(der);
    let signed_data = children(children(content_info)[1].2)[0].2;
    let parts = children(signed_data);
    let encap = children(parts[2].2);
    let econtent = encap
        .get(1)
        .map(|(_, _, explicit)| children(explicit)[0].2.to_vec());
    let signer = children(parts.last().unwrap().2)[0].2;
    let mut view = CmsView {
        econtent_type: oid(encap[0].2),
        econtent,
        signed: Vec::new(),
        unsigned: Vec::new(),
    };
    for (tag, _, content) in children(signer) {
        match tag {
            0xa0 => view.signed = attributes(content),
            0xa1 => view.unsigned = attributes(content),
            _ => {}
        }
    }
    view
}

impl CmsView {
    /// The values of the signed attribute `oid`.
    fn signed(&self, oid: &str) -> &[Vec<u8>] {
        self.signed
            .iter()
            .find(|(t, _)| t == oid)
            .map(|(_, v)| v.as_slice())
            .unwrap_or_else(|| panic!("no signed attribute {oid}"))
    }

    /// The signed attribute types.
    fn signed_types(&self) -> Vec<&str> {
        self.signed.iter().map(|(t, _)| t.as_str()).collect()
    }

    /// The tokens of the signatureTimeStampToken attributes.
    fn tokens(&self) -> Vec<Vec<u8>> {
        self.unsigned
            .iter()
            .filter(|(t, _)| t == "1.2.840.113549.1.9.16.2.14")
            .flat_map(|(_, v)| v.clone())
            .collect()
    }
}

/// The policy and imprint hash OID of a time-stamp token.
fn token_policy_and_hash(token: &[u8]) -> (String, String) {
    let tst_info = cms_view(token).econtent.unwrap();
    let fields = children(tlv(&tst_info).2);
    let imprint = children(fields[2].2);
    let alg = children(imprint[0].2);
    (oid(fields[1].2), oid(alg[0].2))
}

/// The DER of the subject of the synthetic store `name`'s key.
fn subject_der(name: &str) -> Vec<u8> {
    use der::Encode;
    entry(name)
        .cert
        .tbs_certificate()
        .subject()
        .to_der()
        .unwrap()
}

/// An HTTP endpoint answering every request with `status` and no body.
struct Status(u16);

impl oncl_pki::http::HttpTransport for Status {
    fn send(
        &self,
        _: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        Ok(oncl_pki::http::HttpReply {
            status: self.0,
            content_type: None,
            location: None,
            body: Vec::new(),
        })
    }
}

/// `host` (`tsp`, `ocsp`) answering every request with `status`.
fn down(
    host: &str,
    status: u16,
) -> Vec<(String, std::sync::Arc<dyn oncl_pki::http::HttpTransport>)> {
    ["http", "https"]
        .map(|scheme| {
            (
                format!("{scheme}://{host}.pki.gov.kz"),
                std::sync::Arc::new(Status(status)) as _,
            )
        })
        .to_vec()
}

/// The base64 CMS of an ESEDO reply's `responseObject`.
fn reply_cms(reply: &str) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_str(reply).unwrap();
    decode_java(value["responseObject"].as_str().unwrap()).unwrap()
}

const ESEDO_DESCRIPTION: [u8; 8] = [0x13, 6, b'E', b'S', b'E', b'D', b'O', 0];

// bas

const BAS: &str = "kz.bas.nca.multiSignService";

fn bas(args: &str) -> String {
    format!(r#"{{"module":"{BAS}","uuid":"u-1","args":{args}}}"#)
}

const BAS_HELLO: &str = r#"["aGVsbG8=","a.pdf<>b.pdf"]"#;

#[test]
fn esedo_profiles_attribute_sets() {
    let names = "a.pdf<>b.pdf";
    let check_common = |view: &CmsView| {
        let mut types = view.signed_types();
        types.sort_unstable();
        assert_eq!(
            types,
            [
                "1.2.840.113549.1.9.13",
                "1.2.840.113549.1.9.3",
                "1.2.840.113549.1.9.4",
                "1.2.840.113549.1.9.5",
                "1.2.840.113549.1.9.77",
                "1.3.6.1.4.1.6801.2.8",
                "1.3.6.1.5.5.7.48.1.1",
            ]
        );
        assert_eq!(view.signed("1.2.840.113549.1.9.13")[0], ESEDO_DESCRIPTION);
        let names_value = &view.signed("1.2.840.113549.1.9.77")[0];
        assert_eq!(names_value[0], 0x0c);
        assert_eq!(tlv(names_value).2, names.as_bytes());
        // OCTET STRING { OCSPResponse { responseStatus, … } }.
        let ocsp = &view.signed("1.3.6.1.5.5.7.48.1.1")[0];
        assert_eq!(ocsp[0], 0x04);
        let response = tlv(ocsp).2;
        assert_eq!(children(tlv(response).2)[0].0, 0x0a);
        assert!(view.econtent.is_none(), "detached");
    };

    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let view = cms_view(&reply_cms(&text(harness.call(
        "bas",
        &bas(BAS_HELLO),
        None,
    ))));
    check_common(&view);
    assert_eq!(view.econtent_type, "1.3.6.1.4.1.6801.11.1.9");
    assert_eq!(
        oid(tlv(&view.signed("1.2.840.113549.1.9.3")[0]).2),
        "1.3.6.1.4.1.6801.11.1.9"
    );
    assert_eq!(view.signed("1.2.840.113549.1.9.5")[0][0], 0x17, "UTCTime");
    assert_eq!(
        view.signed("1.3.6.1.4.1.6801.2.8")[0],
        subject_der("user-gost2015-sign")
    );

    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "eup",
        &format!(r#"{{"module":"{EUP}","uuid":"u-7","args":{BAS_HELLO}}}"#),
        None,
    ));
    let view = cms_view(&reply_cms(&reply));
    check_common(&view);
    assert_eq!(view.econtent_type, "1.2.840.113549.1.7.1");
    assert_eq!(
        view.signed("1.2.840.113549.1.9.5")[0][0],
        0x18,
        "GeneralizedTime"
    );
    assert_eq!(
        view.signed("1.3.6.1.4.1.6801.2.8")[0],
        subject_der("user-gost2015-sign")
    );
    assert!(view.unsigned.is_empty(), "eup does not time-stamp");

    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "dogovor24",
        &format!(
            r#"{{"module":"{DOGOVOR24}","method":"signEsedo","uuid":"d","args":{BAS_HELLO}}}"#
        ),
        None,
    ));
    let view = cms_view(&reply_cms(&reply));
    check_common(&view);
    assert_eq!(view.econtent_type, "1.2.840.113549.1.7.1");
    assert_eq!(
        view.signed("1.2.840.113549.1.9.5")[0][0],
        0x18,
        "GeneralizedTime"
    );
    // The RFC 2253 text parsed in its order: the subject's RDNs reversed.
    let subject = subject_der("user-gost2015-sign");
    let mut rdns: Vec<&[u8]> = children(tlv(&subject).2)
        .into_iter()
        .map(|(_, whole, _)| whole)
        .collect();
    rdns.reverse();
    let reversed = view.signed("1.3.6.1.4.1.6801.2.8")[0].clone();
    assert_eq!(tlv(&reversed).2, rdns.concat());
    assert_ne!(reversed, subject);
}

#[test]
fn bas_reply_and_cms() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call("bas", &bas(BAS_HELLO), None));
    assert!(reply.starts_with(r#"{"responseObject":"MI"#), "{reply}");
    assert!(
        reply.ends_with(r#"","code":"200","uuid":"u-1"}"#),
        "{reply}"
    );
    oncl_pki::cms::verify(&reply_cms(&reply), Some(b"hello")).unwrap();
    assert_eq!(
        harness.http_log(),
        ["POST http://ocsp.pki.gov.kz", "POST http://tsp.pki.gov.kz"]
    );
    // The method is not read; the uuid defaults to "".
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        text(harness.call(
            "bas",
            &format!(r#"{{"module":"{BAS}","method":"x","args":{BAS_HELLO}}}"#),
            None
        )),
        r#"{"code":"500","uuid":""}"#
    );
}

#[test]
fn bas_argument_errors() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("bas");
    for (args, message) in [
        ("null", "Invalid arguments"),
        (r#"{"a":1}"#, "Invalid arguments"),
        (r#"["x"]"#, "Invalid arguments"),
        (r#"[1,"x"]"#, "JSONArray[0] is not a String."),
        (r#"["x",2]"#, "JSONArray[1] is not a String."),
    ] {
        assert_eq!(
            text(session.call(&bas(args), None)),
            format!(r#"{{"code":"500","message":"{message}","uuid":"u-1"}}"#)
        );
    }
    assert!(harness.prompter().timeline().is_empty());
    // Base64 is decoded after the dialog and the OCSP request.
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    assert_eq!(
        text(harness.call("bas", &bas(r#"["a-b=","x"]"#), None)),
        r#"{"code":"500","message":"Illegal base64 character 2d","uuid":"u-1"}"#
    );
    assert_eq!(harness.http_log(), ["POST http://ocsp.pki.gov.kz"]);
}

#[test]
fn bas_tsp_append_policy_by_alg() {
    for (store, policy, hash) in [
        (
            "user-gost2015-sign",
            "1.2.398.3.3.2.6.4",
            "1.2.398.3.10.1.3.1",
        ),
        (
            "user-gost2004-sign",
            "1.2.398.3.3.2.6.1",
            "1.2.398.3.10.1.3.1",
        ),
        (
            "user-rsa-sign",
            "1.2.398.3.3.2.6.2",
            "2.16.840.1.101.3.4.2.1",
        ),
    ] {
        let harness = Harness::new(pick(store, 0), vec![]);
        let view = cms_view(&reply_cms(&text(harness.call(
            "bas",
            &bas(BAS_HELLO),
            None,
        ))));
        let tokens = view.tokens();
        assert_eq!(tokens.len(), 1, "{store}");
        assert_eq!(
            token_policy_and_hash(&tokens[0]),
            (policy.to_owned(), hash.to_owned()),
            "{store}"
        );
    }
}

#[test]
fn bas_cms_error_code_200() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), down("tsp", 503));
    assert_eq!(
        text(harness.call("bas", &bas(BAS_HELLO), None)),
        r#"{"code":"200","message":"Invalid TSP response status: 503","uuid":"u-1"}"#
    );
    // The original's ten attempts.
    let posts = harness
        .http_log()
        .iter()
        .filter(|line| line.starts_with("POST http://tsp"))
        .count();
    assert_eq!(posts, 10);
}

#[test]
fn bas_expired_text() {
    let harness = Harness::new(pick("expired-gost2015-sign", 0), vec![]);
    assert_eq!(
        text(harness.call("bas", &bas(BAS_HELLO), None)),
        r#"{"code":"500","message":"The certificate has expired.","uuid":"u-1"}"#
    );
    assert!(harness.http_log().is_empty());
}

#[test]
fn bas_ocsp_failure_text() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), down("ocsp", 500));
    assert_eq!(
        text(harness.call("bas", &bas(BAS_HELLO), None)),
        r#"{"code":"500","message":"OCSP response generation error","uuid":"u-1"}"#
    );
}

#[test]
fn bas_rsa_message_digest_is_sha256() {
    let harness = Harness::new(pick("user-rsa-sign", 0), vec![]);
    let cms = reply_cms(&text(harness.call("bas", &bas(BAS_HELLO), None)));
    // The messageDigest matches the SHA-256 digestAlgorithm: the CMS verifies.
    oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    let digest = cms_view(&cms).signed("1.2.840.113549.1.9.4")[0].clone();
    let digest = &digest;
    assert_eq!(tlv(digest).2, SigAlg::RsaSha256.digest(b"hello"));
}

// eup

const EUP: &str = "kz.nitec.eup.eupsigner";

fn eup(args: &str) -> String {
    format!(r#"{{"module":"{EUP}","uuid":"u-7","args":{args}}}"#)
}

#[test]
fn eup_reply() {
    let harness = Harness::new(pick("user-gost2004-sign", 0), vec![]);
    let reply = text(harness.call("eup", &eup(BAS_HELLO), None));
    assert!(reply.starts_with(r#"{"responseObject":"MI"#), "{reply}");
    assert!(
        reply.ends_with(r#"","code":"200","uuid":"u-7"}"#),
        "{reply}"
    );
    oncl_pki::cms::verify(&reply_cms(&reply), Some(b"hello")).unwrap();
    assert_eq!(harness.http_log(), ["POST http://ocsp.pki.gov.kz"]);
}

#[test]
fn eup_error_null_null() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let mut session = harness.session("eup");
    let error = |message: &str| {
        format!(
            r#"{{"responseObject":"null null","code":"500","message":"{message}","uuid":"u-7"}}"#
        )
    };
    assert_eq!(
        text(session.call(&format!(r#"{{"module":"{EUP}","uuid":"u-7"}}"#), None)),
        error("java.lang.NullPointerException")
    );
    assert_eq!(
        text(session.call(&eup(r#"["x"]"#), None)),
        error("org.json.JSONException: JSONArray[1] not found.")
    );
    // The dialog closed.
    assert_eq!(
        text(session.call(&eup(BAS_HELLO), None)),
        error("java.lang.NullPointerException")
    );
    let harness = Harness::new(pick("user-gost2015-sign", 0), down("ocsp", 500));
    assert_eq!(
        text(harness.call("eup", &eup(BAS_HELLO), None)),
        r#"{"responseObject":"102 Ошибка при формировании подписи. Возможная причина: отсутствие соединения с интернет.","code":"500","message":"java.lang.Exception: OCSP response generation error. Check internet connection","uuid":"u-7"}"#
    );
}

#[test]
fn eup_gost2015_signs() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let cms = reply_cms(&text(harness.call("eup", &eup(BAS_HELLO), None)));
    oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
}

#[test]
fn eup_lenient_base64_errors() {
    let error = |message: &str| {
        format!(
            r#"{{"responseObject":"null null","code":"500","message":"{message}","uuid":"u-7"}}"#
        )
    };
    for (args, message) in [
        (
            r#"["ab","x"]"#,
            "java.lang.StringIndexOutOfBoundsException: String index out of range: -2",
        ),
        (
            r#"[123,"x"]"#,
            "java.lang.StringIndexOutOfBoundsException: String index out of range: -1",
        ),
        (
            r#"["абвгд","x"]"#,
            "java.lang.ArrayIndexOutOfBoundsException: 1072",
        ),
    ] {
        let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
        assert_eq!(
            text(harness.call("eup", &eup(args), None)),
            error(message),
            "{args}"
        );
    }
    // Whitespace is skipped, other characters outside the alphabet read as zero bits.
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let cms = reply_cms(&text(harness.call(
        "eup",
        &eup(r#"["aGVs bG8=",null]"#),
        None,
    )));
    oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    let names = cms_view(&cms).signed("1.2.840.113549.1.9.77")[0].clone();
    let names = &names;
    assert_eq!(tlv(names).2, b"null");
}

// dogovor24

const DOGOVOR24: &str = "kz.dogovor24.module";

fn dogovor24(method: &str, args: &str) -> String {
    format!(r#"{{"module":"{DOGOVOR24}","method":"{method}","uuid":"d-1","args":{args}}}"#)
}

#[test]
fn dogovor24_dialog_before_unknown_method_raw_text() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        text(harness.call("dogovor24", &dogovor24("signXml", "[]"), None)),
        "error: method not found [signXml]"
    );
    assert_eq!(harness.prompter().storage_prompts().len(), 1);
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    assert_eq!(
        text(harness.call("dogovor24", &format!(r#"{{"module":"{DOGOVOR24}"}}"#), None)),
        "error: method not found []"
    );
}

#[test]
fn dogovor24_sign_cms_kalkan_tsa() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call("dogovor24", &dogovor24("signCMS", r#"["aGVsbG8="]"#), None));
    assert!(reply.starts_with(r#"{"responseObject":"MI"#), "{reply}");
    assert!(reply.ends_with(r#"","code":"200"}"#), "{reply}");
    let cms = reply_cms(&reply);
    // Attached, time-stamped with Kalkan's default profile.
    oncl_pki::cms::verify(&cms, None).unwrap();
    let tokens = cms_view(&cms).tokens();
    assert_eq!(
        token_policy_and_hash(&tokens[0]),
        (
            "1.2.398.3.3.2.6.2".to_owned(),
            "2.16.840.1.101.3.4.2.1".to_owned()
        )
    );
    let log = harness.http_log();
    assert_eq!(log.len(), 1);
    assert!(log[0].starts_with("GET http://tsp.pki.gov.kz"), "{log:?}");
    // Errors: the arguments, the base64, a closed dialog.
    let harness = Harness::new(vec![Step::CancelStorage, Step::CancelStorage], vec![]);
    let mut session = harness.session("dogovor24");
    assert_eq!(
        text(session.call(
            &format!(r#"{{"module":"{DOGOVOR24}","method":"signCMS"}}"#),
            None
        )),
        r#"{"code":"500","message":"JSONObject[\"args\"] not found."}"#
    );
    assert_eq!(
        text(session.call(&dogovor24("signCMS", r#"["aGVsbG8="]"#), None)),
        r#"{"code":"500"}"#
    );
}

#[test]
fn dogovor24_batch_missing_args_code_100() {
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        text(harness.call(
            "dogovor24",
            &format!(r#"{{"module":"{DOGOVOR24}","method":"batchSignCMS"}}"#),
            None
        )),
        r#"{"code":"100","message":"JSONObject[\"args\"] not found."}"#
    );
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call(
        "dogovor24",
        &dogovor24("batchSignCMS", r#"["aGVsbG8=","d29ybGQ="]"#),
        None,
    ));
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let items = value["responseObject"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(value["code"], "200");
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    assert_eq!(
        text(harness.call(
            "dogovor24",
            &dogovor24("batchSignCMS", r#"["aGVsbG8=","!!"]"#),
            None
        )),
        r#"{"code":"500","message":"action canceled"}"#
    );
}

#[test]
fn dogovor24_sign_esedo_uuid_echo() {
    let harness = Harness::new(pick("user-gost2015-sign", 0), vec![]);
    let reply = text(harness.call("dogovor24", &dogovor24("signEsedo", BAS_HELLO), None));
    assert!(
        reply.ends_with(r#"","code":"200","uuid":"d-1"}"#),
        "{reply}"
    );
    oncl_pki::cms::verify(&reply_cms(&reply), Some(b"hello")).unwrap();
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    assert_eq!(
        text(harness.call("dogovor24", &dogovor24("signEsedo", BAS_HELLO), None)),
        r#"{"code":"500","message":"java.security.KeyStoreException: Uninitialized keystore","uuid":"d-1"}"#
    );
    // The OCSP answer is left out when the responder fails.
    let harness = Harness::new(pick("user-gost2015-sign", 0), down("ocsp", 500));
    let reply = text(harness.call("dogovor24", &dogovor24("signEsedo", BAS_HELLO), None));
    let view = cms_view(&reply_cms(&reply));
    assert!(!view.signed_types().contains(&"1.3.6.1.5.5.7.48.1.1"));
}

#[test]
fn dogovor24_client_auth_rejected() {
    let auth = entry("user-gost2015-auth");
    let info = oncl_pki::info::cert_info(&auth.cert);
    assert!(
        info.ext_key_usages.contains("1.3.6.1.5.5.7.3.2"),
        "a clientAuth key"
    );
    let harness = Harness::new(pick("user-gost2015-auth", 0), vec![]);
    assert_eq!(
        text(harness.call("dogovor24", &dogovor24("signCMS", r#"["aGVsbG8="]"#), None)),
        r#"{"code":"500","message":"Необходимо использовать ключ для подписи!"}"#
    );
    let harness = Harness::new(pick("user-gost2015-auth", 0), vec![]);
    assert_eq!(
        text(harness.call("dogovor24", &dogovor24("signEsedo", BAS_HELLO), None)),
        r#"{"code":"500","message":"Необходимо использовать ключ для подписи!","uuid":"d-1"}"#
    );
}

/// The synthetic certificate `name` (`fixtures/synthetic/<name>.cer`) as base64.
fn cer_b64(name: &str) -> String {
    oncl_protocol::javab64::encode_mime(&oncl_testkit::synthetic_cert(name)).replace("\r\n", "")
}

/// A harness whose `http://ocsp.synthetic.test`, the responder the certificates of the
/// intermediate CA name, is a PKI host answered by the synthetic responder. Its clock is
/// the system's: the responder dates its answers now, and checked answers must be fresh.
fn with_synthetic_ocsp(steps: Vec<Step>) -> Harness {
    let ocsp: std::sync::Arc<dyn oncl_pki::http::HttpTransport> =
        std::sync::Arc::new(oncl_pki::ocsp::MockOcsp::new(entry("ocsp-gost2015")));
    Harness::new(steps, vec![("http://ocsp.synthetic.test".to_owned(), ocsp)])
        .with_pki_hosts(&["ocsp.synthetic.test"])
        .with_clock(OffsetDateTime::now_utc)
}

// workspace

const WORKSPACE: &str = "kz.workspace.Signer";

fn workspace(method: &str, args: &str) -> String {
    format!(r#"{{"module":"{WORKSPACE}","method":"{method}","args":{args}}}"#)
}

/// `sign` of `files` (base64) for the user key under root-gost2015.
fn workspace_sign(files: &str) -> String {
    workspace(
        "sign",
        &format!(
            r#"{{"files":{files},"fileNames":"a.pdf<>b.pdf","storagePath":"C:\\ignored.p12","issuerCert":"{}"}}"#,
            cer_b64("inter-gost2015")
        ),
    )
}

/// The CMSs of a workspace reply's `body`.
fn workspace_body(reply: &str) -> Vec<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_str(reply).unwrap();
    value["body"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cms| decode_java(cms.as_str().unwrap()).unwrap())
        .collect()
}

#[test]
fn workspace_body_codes_numbers() {
    let harness = with_synthetic_ocsp(pick("inter-user-gost2015-sign", 0));
    let reply = text(harness.call(
        "workspace",
        &workspace_sign(r#"["aGVsbG8=","d29ybGQ="]"#),
        None,
    ));
    assert!(reply.starts_with(r#"{"code":200,"body":["MI"#), "{reply}");
    assert_eq!(workspace_body(&reply).len(), 2);
    let harness = Harness::new(vec![Step::CancelStorage], vec![]);
    let mut session = harness.session("workspace");
    for (request, reply) in [
        (
            workspace("signCms", "{}"),
            r#"{"code":500,"message":"Wrong method. Try 'createCMSSignature'"}"#,
        ),
        (
            format!(r#"{{"module":"{WORKSPACE}","method":"sign"}}"#),
            r#"{"code":500,"message":"JSONObject[\"args\"] not found."}"#,
        ),
        (
            workspace_sign(r#"["aGVsbG8="]"#),
            r#"{"code":500,"message":"отмена ввода пароля"}"#,
        ),
        // The password window comes first; closing it cancels.
        (
            workspace("getKaztokenKeys", "{}"),
            r#"{"code":500,"message":"отмена ввода пароля"}"#,
        ),
    ] {
        assert_eq!(text(session.call(&request, None)), reply, "{request}");
    }
}

#[test]
fn workspace_kaztoken_keys() {
    let name = "user-gost2015-sign";
    let harness = Harness::new(
        vec![
            Step::Password(TOKEN_PIN.to_owned()),
            Step::Password("000000".to_owned()),
        ],
        vec![],
    )
    .with_tokens(kaztoken_emulator(name));
    let mut session = harness.session("workspace");
    let reply = text(session.call(&workspace("getKaztokenKeys", "{}"), None));
    assert!(
        reply.starts_with(r#"{"code":200,"body":[{"notAfter":""#),
        "{reply}"
    );
    assert_key_order(&reply, &["notAfter", "alias", "dn", "alg"]);
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let keys = value["body"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["dn"], subject_dn(name));
    assert_eq!(keys[0]["alg"], "ECGOST3410-2015");
    let date = keys[0]["notAfter"].as_str().unwrap();
    assert!(
        date.len() == 10 && date.as_bytes()[2] == b'.' && date.as_bytes()[5] == b'.',
        "{date}"
    );
    assert!(keys[0]["alias"].as_str().is_some_and(|a| !a.is_empty()));
    assert_eq!(
        text(session.call(&workspace("getKaztokenKeys", "{}"), None)),
        r#"{"code":500,"message":"Неверный пароль"}"#
    );
    assert_eq!(harness.prompter().password_prompts().len(), 2);
}

#[test]
fn workspace_sled_and_attachments() {
    let harness = with_synthetic_ocsp(pick("inter-user-gost2015-sign", 0));
    let reply = text(harness.call(
        "workspace",
        &workspace_sign(r#"["aGVsbG8=","d29ybGQ="]"#),
        None,
    ));
    let body = workspace_body(&reply);
    // The SLED card: detached, the ESEDO attributes with the names and the OCSP answer.
    let sled = cms_view(&body[0]);
    oncl_pki::cms::verify(&body[0], Some(b"hello")).unwrap();
    assert!(sled.econtent.is_none());
    let mut types = sled.signed_types();
    types.sort_unstable();
    assert_eq!(
        types,
        [
            "1.2.840.113549.1.9.13",
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
            "1.2.840.113549.1.9.77",
            "1.3.6.1.4.1.6801.2.8",
            "1.3.6.1.5.5.7.48.1.1",
        ]
    );
    assert_eq!(sled.signed("1.2.840.113549.1.9.13")[0], ESEDO_DESCRIPTION);
    assert_eq!(sled.signed("1.2.840.113549.1.9.5")[0][0], 0x18);
    // OCTET STRING { BasicOCSPResponse { tbsResponseData, … } }.
    let ocsp = &sled.signed("1.3.6.1.5.5.7.48.1.1")[0];
    assert_eq!(ocsp[0], 0x04);
    assert_eq!(children(tlv(tlv(ocsp).2).2)[0].0, 0x30);
    assert!(sled.tokens().is_empty());
    // The attachment: attached, no names, no OCSP, a time-stamp (SHA-1, policy …6.1).
    let attachment = cms_view(&body[1]);
    assert_eq!(attachment.econtent.as_deref(), Some(&b"world"[..]));
    let mut types = attachment.signed_types();
    types.sort_unstable();
    assert_eq!(
        types,
        [
            "1.2.840.113549.1.9.13",
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
            "1.3.6.1.4.1.6801.2.8",
        ]
    );
    let tokens = attachment.tokens();
    assert_eq!(tokens.len(), 1);
    assert_eq!(
        token_policy_and_hash(&tokens[0]),
        ("1.2.398.3.3.2.6.1".to_owned(), "1.3.14.3.2.26".to_owned())
    );
    let log = harness.http_log();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(
        log[0].starts_with("GET http://ocsp.synthetic.test/"),
        "{log:?}"
    );
    assert!(log[1].starts_with("GET http://tsp.pki.gov.kz/"), "{log:?}");
}

#[test]
fn workspace_repeats_files_1() {
    let harness = with_synthetic_ocsp(pick("inter-user-gost2015-sign", 0));
    let reply = text(harness.call(
        "workspace",
        &workspace_sign(r#"["aGVsbG8=","d29ybGQ=","b3RoZXI="]"#),
        None,
    ));
    let body = workspace_body(&reply);
    assert_eq!(body.len(), 3);
    for cms in &body[1..] {
        assert_eq!(cms_view(cms).econtent.as_deref(), Some(&b"world"[..]));
    }
}

#[test]
fn workspace_argument_errors() {
    for (files, message) in [
        ("[]", "Index: 0, Size: 0"),
        (r#"["aGVsbG8=",5]"#, "JSONArray[1] is not a String."),
    ] {
        let harness = with_synthetic_ocsp(pick("inter-user-gost2015-sign", 0));
        assert_eq!(
            text(harness.call("workspace", &workspace_sign(files), None)),
            format!(r#"{{"code":500,"message":"{message}"}}"#),
            "{files}"
        );
    }
    // Without the page's issuer certificate the OCSP request cannot be made.
    let harness = with_synthetic_ocsp(pick("inter-user-gost2015-sign", 0));
    assert_eq!(
        text(harness.call(
            "workspace",
            &workspace("sign", r#"{"files":["aGVsbG8="]}"#),
            None
        )),
        r#"{"code":500,"message":"TARGET_CERT_ISSUER_NOT_FOUND"}"#
    );
}

static WORKSPACE_TICKS: AtomicI64 = AtomicI64::new(0);

/// The system's clock, moving 3 seconds more every time it is read.
fn workspace_clock() -> OffsetDateTime {
    OffsetDateTime::now_utc()
        + time::Duration::seconds(WORKSPACE_TICKS.fetch_add(3, Ordering::SeqCst))
}

#[test]
fn workspace_watchdog_timeout_text() {
    let harness =
        with_synthetic_ocsp(pick("inter-user-gost2015-sign", 0)).with_clock(workspace_clock);
    assert_eq!(
        text(harness.call(
            "workspace",
            &workspace_sign(r#"["aGVsbG8=","d29ybGQ=","d29ybGQ=","d29ybGQ=","d29ybGQ="]"#),
            None
        )),
        r#"{"code":500,"message":"процесс остановлен по таймауту"}"#
    );
}

// Simourg

const SIMOURG: &str = "kz.Simourg.SimBASEModule";

fn simourg(method: &str, args: &str) -> String {
    format!(r#"{{"module":"{SIMOURG}","method":"{method}","args":{args}}}"#)
}

/// Picks the synthetic key `name` and presses «Подписать».
fn simourg_pick(name: &str) -> Vec<Step> {
    let mut steps = pick(name, 0);
    steps.push(Step::Choice {
        button: 0,
        option: None,
    });
    steps
}

const SIMOURG_ARGS: &str = r#"["PKCS12","SIGNATURE","aGVsbG8=",true,"a.pdf<>b.pdf"]"#;

#[test]
fn simourg_salem_ait() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("simourg");
    assert_eq!(
        text(session.call(&simourg("salemAit", r#"{"username":"Aryn"}"#), None)),
        r#"{"success":true,"body":{"result":"Salem, Aryn"}}"#
    );
    assert_eq!(
        text(session.call(&simourg("salemAit", "{}"), None)),
        r#"{"success":true,"body":{"result":"Salem, Silent Bob"}}"#
    );
    assert_eq!(session.call(&simourg("salemAit", "[]"), None), Reply::Drop);
    assert_eq!(
        text(session.call(&simourg("sign", "{}"), None)),
        r#"{"success":false,"errorCode":"method_not_defined","message":"Error method sign is not defined"}"#
    );
}

#[test]
fn simourg_cades_bare_basic_ocsp_attr() {
    let harness = with_synthetic_ocsp(simourg_pick("inter-user-gost2015-sign"));
    let reply = text(harness.call(
        "simourg",
        &simourg("createCMSSignatureWithTspFromBase64", SIMOURG_ARGS),
        None,
    ));
    assert!(reply.starts_with(r#"{"responseObject":"MI"#), "{reply}");
    assert!(
        reply.ends_with(r#"","code":"200","message":"Ok"}"#),
        "{reply}"
    );
    let cms = reply_cms(&reply);
    oncl_pki::cms::verify(&cms, None).unwrap();
    let view = cms_view(&cms);
    assert_eq!(view.econtent.as_deref(), Some(&b"hello"[..]));
    let mut types = view.signed_types();
    types.sort_unstable();
    assert_eq!(
        types,
        [
            "1.2.840.113549.1.9.16.2.47",
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
            "1.2.840.113549.1.9.77",
            "1.3.6.1.5.5.7.48.1.1",
        ]
    );
    // The BasicOCSPResponse itself in the SET: SEQUENCE { tbsResponseData, … }.
    let ocsp = &view.signed("1.3.6.1.5.5.7.48.1.1")[0];
    assert_eq!(ocsp[0], 0x30);
    assert_eq!(children(tlv(ocsp).2)[0].0, 0x30);
    let tokens = view.tokens();
    assert_eq!(tokens.len(), 1);
    assert_eq!(token_policy_and_hash(&tokens[0]).0, "1.2.398.3.3.2.6.2");
    let log = harness.http_log();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(
        log[0].starts_with("GET http://ocsp.synthetic.test/"),
        "{log:?}"
    );
    assert!(log[1].starts_with("GET http://tsp.pki.gov.kz"), "{log:?}");
}

#[test]
fn simourg_esedo_double_stamp_replaced() {
    let harness = Harness::new(simourg_pick("user-gost2015-sign"), vec![]);
    let reply = text(harness.call("simourg", &simourg("createCMSForEsedo", SIMOURG_ARGS), None));
    assert!(
        reply.ends_with(r#"","code":"200","message":"Ok"}"#),
        "{reply}"
    );
    let cms = reply_cms(&reply);
    oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    let view = cms_view(&cms);
    assert!(view.econtent.is_none());
    let mut types = view.signed_types();
    types.sort_unstable();
    assert_eq!(
        types,
        [
            "1.2.840.113549.1.9.13",
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
            "1.2.840.113549.1.9.77",
            "1.3.6.1.5.5.7.48.1.1",
        ]
    );
    assert_eq!(
        view.signed("1.2.840.113549.1.9.13")[0],
        [0x13, 5, b'E', b'S', b'E', b'D', b'O']
    );
    assert_eq!(view.signed("1.3.6.1.5.5.7.48.1.1")[0][0], 0x04);
    // The GOST time-stamp is replaced by Kalkan's.
    let tokens = view.tokens();
    assert_eq!(tokens.len(), 1);
    assert_eq!(token_policy_and_hash(&tokens[0]).0, "1.2.398.3.3.2.6.2");
    let log = harness.http_log();
    assert_eq!(log.len(), 3, "{log:?}");
    assert_eq!(log[0], "POST http://ocsp.pki.gov.kz/");
    assert!(log[1].starts_with("GET http://tsp.pki.gov.kz/"), "{log:?}");
    assert!(log[2].starts_with("GET http://tsp.pki.gov.kz"), "{log:?}");
}

#[test]
fn simourg_choose_other_keys_loop() {
    let mut steps = pick("user-gost2004-sign", 0);
    steps.push(Step::Choice {
        button: 1,
        option: None,
    });
    steps.extend(simourg_pick("user-gost2015-sign"));
    let harness = Harness::new(steps, vec![]);
    let reply = text(harness.call("simourg", &simourg("createCMSForEsedo", SIMOURG_ARGS), None));
    assert!(
        reply.ends_with(r#""code":"200","message":"Ok"}"#),
        "{reply}"
    );
    let cms = reply_cms(&reply);
    let signers = oncl_pki::cms::verify(&cms, Some(b"hello")).unwrap();
    assert_eq!(signers[0].sig_alg, SigAlg::Gost2015_512);
    let choices = harness.prompter().choice_prompts();
    assert_eq!(choices.len(), 2);
}

#[test]
fn simourg_error_prefix() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("simourg");
    for (storage, message) in [
        ("", "Error: storageName.param.empty"),
        ("BKS", "Error: Unknown storage"),
        ("AKKaztokenStore", "Error: Empty storage"),
        // The empty script closes the dialog.
        ("PKCS12", "Cancel"),
    ] {
        assert_eq!(
            text(session.call(
                &simourg(
                    "createCMSForEsedo",
                    &format!(r#"["{storage}","SIGNATURE","aGVsbG8=",false,"x"]"#)
                ),
                None
            )),
            format!(r#"{{"code":"500","message":"{message}"}}"#)
        );
    }
    let harness = Harness::new(simourg_pick("user-gost2015-sign"), vec![]);
    assert_eq!(
        text(harness.call(
            "simourg",
            &simourg(
                "createCMSSignatureWithTspFromBase64",
                r#"["PKCS12","NONE","a-b=",false,"x"]"#
            ),
            None
        )),
        r#"{"code":"500","message":"Error: Illegal base64 character 2d"}"#
    );
}

#[test]
fn simourg_missing_args_drop() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("simourg");
    for request in [
        format!(r#"{{"module":"{SIMOURG}","method":"createCMSForEsedo"}}"#),
        simourg(
            "createCMSForEsedo",
            r#"["PKCS12","SIGNATURE","aGVsbG8=",false]"#,
        ),
        simourg("createCMSSignatureWithTspFromBase64", r#"{"a":1}"#),
    ] {
        assert_eq!(session.call(&request, None), Reply::Drop, "{request}");
    }
    assert!(harness.prompter().timeline().is_empty());
}

// motiw

const MOTIW: &str = "ru.motiw.ModuleService";

fn motiw(method: &str, args: &str) -> String {
    format!(r#"{{"module":"{MOTIW}","method":"{method}","uuid":"7","args":{args}}}"#)
}

#[test]
fn motiw_storages_list() {
    let harness = Harness::new(vec![], vec![]);
    assert_eq!(
        text(harness.call(
            "motiw",
            &format!(r#"{{"module":"{MOTIW}","method":"getStoragesList","uuid":"7"}}"#),
            None
        )),
        r#"{"responseObject":["PKCS12"],"code":"200","message":"","uuid":"7"}"#
    );
    assert_eq!(
        text(harness.call("motiw", &motiw("sing", "[]"), None)),
        r#"{"code":"404","message":"Method not found","uuid":"7"}"#
    );
}

#[test]
fn motiw_container_list_files_empty() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("motiw");
    assert_eq!(
        text(session.call(&motiw("getContainerList", r#"["PKCS12"]"#), None)),
        r#"{"responseObject":[],"code":"200","message":"","uuid":"7"}"#
    );
    assert_eq!(
        text(session.call(&motiw("getContainerList", r#"["AKKaztokenStore"]"#), None)),
        r#"{"responseObject":[],"code":"200","message":"","uuid":"7"}"#
    );
    assert_eq!(
        text(session.call(&motiw("getContainerList", "[]"), None)),
        r#"{"responseObject":"","code":"400","message":"Error length params. Actual 0, expected: 1","uuid":"7"}"#
    );
    assert_eq!(
        text(session.call(&motiw("getContainerList", "[1]"), None)),
        r#"{"responseObject":"","code":"400","message":"Error type param[0]. Actual class java.lang.Integer, expected: class java.lang.String","uuid":"7"}"#
    );
    // An unknown storage and missing arguments drop the connection.
    assert_eq!(
        session.call(&motiw("getContainerList", r#"["BKS"]"#), None),
        Reply::Drop
    );
    assert_eq!(
        session.call(
            &format!(r#"{{"module":"{MOTIW}","method":"getContainerList"}}"#),
            None
        ),
        Reply::Drop
    );
    assert_eq!(
        session.call(&format!(r#"{{"module":"{MOTIW}","uuid":"7"}}"#), None),
        Reply::Drop
    );
}

#[test]
fn motiw_certificate_list_404() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("motiw");
    assert_eq!(
        text(session.call(
            &motiw("getCertificateList", r#"["PKCS12","abc","Qwerty12"]"#),
            None
        )),
        r#"{"responseObject":"","code":"404","message":"Not found container by serial: abc","uuid":"7"}"#
    );
    assert_eq!(
        text(session.call(
            &motiw(
                "sign",
                r#"["PKCS12","abc","Qwerty12","alias","aGVsbG8=",1,true]"#
            ),
            None
        )),
        r#"{"responseObject":"","code":"404","message":"Not found container by serial: abc","uuid":"7"}"#
    );
    assert_eq!(
        text(session.call(
            &motiw(
                "sign",
                r#"["PKCS12","abc","Qwerty12","alias","aGVsbG8=","1",true]"#
            ),
            None
        )),
        r#"{"responseObject":"","code":"400","message":"Error type param[5]. Actual class java.lang.String, expected: class java.lang.Integer","uuid":"7"}"#
    );
}

/// A CMS of `data` by the synthetic key `name`, attached or not, signed at `default_clock`.
fn motiw_cms(name: &str, data: &[u8], attached: bool) -> String {
    let cms = oncl_pki::cms::sign(
        &entry(name),
        data,
        &oncl_pki::cms::SignOptions {
            encapsulate: attached,
            digested: false,
            signing_time: default_clock(),
        },
    )
    .unwrap();
    oncl_protocol::javab64::encode_mime(&cms).replace("\r\n", "")
}

#[test]
fn motiw_verify_ok_and_codes() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("motiw");
    let verify = |session: &mut oncl_port_tests::SessionHandle, cms: &str, data: &str| {
        text(session.call(&motiw("verify", &format!(r#"["{cms}","{data}"]"#)), None))
    };
    let reply = verify(
        &mut session,
        &motiw_cms("user-gost2015-sign", b"hello", true),
        "",
    );
    assert!(
        reply.starts_with(r#"{"responseObject":{"certificates":[{"#),
        "{reply}"
    );
    assert!(
        reply.ends_with(r#"}]},"code":"200","message":"","uuid":"7"}"#),
        "{reply}"
    );
    assert_key_order(
        &reply,
        &[
            "notAfter",
            "serialNumber",
            "subject",
            "issuer",
            "notBefore",
            "algorithm",
            "sigAlgName",
        ],
    );
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let info = &value["responseObject"]["certificates"][0];
    assert_eq!(info["sigAlgName"], "ECGOST3410-2015-512");
    assert_eq!(info["algorithm"], "ECGOST3410-2015");
    assert!(info["notAfter"].is_i64());
    let detached = motiw_cms("user-gost2015-sign", b"hello", false);
    assert!(verify(&mut session, &detached, "aGVsbG8=").contains(r#""code":"200""#));
    for (cms, data, code) in [
        (detached.clone(), "", "CMS_NO_ENCAPSULATED_DATA"),
        (detached, "d29ybGQ=", "CMS_SIGNATURE_NOT_VALID"),
        (
            motiw_cms("expired-gost2015-sign", b"hello", true),
            "",
            "CERTIFICATE_DATE_NOT_VALID",
        ),
    ] {
        assert_eq!(
            verify(&mut session, &cms, data),
            format!(r#"{{"code":"500","message":"{code}","uuid":"7"}}"#)
        );
    }
}

#[test]
fn motiw_bad_base64_drops() {
    let harness = Harness::new(vec![], vec![]);
    let mut session = harness.session("motiw");
    for args in [r#"["a-b=",""]"#, r#"["aGVsbG8=","!"]"#] {
        assert_eq!(
            session.call(&motiw("verify", args), None),
            Reply::Drop,
            "{args}"
        );
    }
}

#[test]
fn motiw_show_storage_key() {
    for steps in [pick("user-gost2015-sign", 0), vec![Step::CancelStorage]] {
        let harness = Harness::new(steps, vec![]);
        assert_eq!(
            text(harness.call("motiw", &motiw("showStorageKey", "[]"), None)),
            r#"{"code":"200","uuid":"7"}"#
        );
        assert_eq!(harness.prompter().storage_prompts().len(), 1);
    }
}

const TOKEN_READER: &str = "Emulated Reader 0";
const EMPTY_READER: &str = "Emulated Reader 1";
const TOKEN_PIN: &str = "123456";

/// A Kaztoken holding the synthetic key `name` in [`TOKEN_READER`] and an empty Kaztoken in
/// [`EMPTY_READER`].
fn kaztoken_emulator(name: &str) -> std::sync::Arc<oncl_token::emulator::EmulatorBackend> {
    use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
    let key = oncl_testkit::synthetic(name);
    let key = EmuKey::load(&key.path, &key.password).unwrap();
    let emu = std::sync::Arc::new(EmulatorBackend::new());
    for (reader, keys) in [(TOKEN_READER, vec![key]), (EMPTY_READER, vec![])] {
        emu.add_reader(reader);
        emu.insert(
            reader,
            card(CardSpec::new(
                oncl_token::TokenKind::Kaztoken,
                TOKEN_PIN,
                keys,
            )),
        );
    }
    emu
}

#[test]
fn motiw_token_storages_and_containers() {
    let harness = Harness::new(vec![], vec![]).with_tokens(kaztoken_emulator("user-gost2015-sign"));
    let mut session = harness.session("motiw");
    assert_eq!(
        text(session.call(&motiw("getStoragesList", "[]"), None)),
        r#"{"responseObject":["AKKaztokenStore","PKCS12"],"code":"200","message":"","uuid":"7"}"#
    );
    assert_eq!(
        text(session.call(&motiw("getContainerList", r#"["AKKaztokenStore"]"#), None)),
        format!(
            r#"{{"responseObject":[{{"path":"{TOKEN_READER}","serial":"AKKaztokenStore"}},{{"path":"{EMPTY_READER}","serial":"AKKaztokenStore"}}],"code":"200","message":"","uuid":"7"}}"#
        )
    );
}

#[test]
fn motiw_token_certificate_list_and_errors() {
    // The page's PIN reaches a reader only after the user allows it, once per reader.
    let yes = Step::Confirm { yes: true };
    let harness = Harness::new(vec![yes.clone(), yes], vec![])
        .with_tokens(kaztoken_emulator("user-gost2015-sign"));
    let mut session = harness.session("motiw");
    let list =
        |session: &mut oncl_port_tests::SessionHandle, storage: &str, reader: &str, pin: &str| {
            text(session.call(
                &motiw(
                    "getCertificateList",
                    &format!(r#"["{storage}","{reader}","{pin}"]"#),
                ),
                None,
            ))
        };
    let reply = list(&mut session, "AKKaztokenStore", TOKEN_READER, TOKEN_PIN);
    assert!(reply.starts_with(r#"{"responseObject":[{"#), "{reply}");
    assert!(
        reply.ends_with(r#"}],"code":"200","message":"","uuid":"7"}"#),
        "{reply}"
    );
    assert_key_order(
        &reply,
        &[
            "notAfter",
            "serialNumber",
            "subject",
            "alias",
            "issuer",
            "notBefore",
            "algorithm",
            "sigAlgName",
        ],
    );
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["responseObject"].as_array().unwrap().len(), 1);
    assert_eq!(
        value["responseObject"][0]["sigAlgName"],
        "ECGOST3410-2015-512"
    );
    // An empty token lists no certificates.
    assert_eq!(
        list(&mut session, "AKKaztokenStore", EMPTY_READER, TOKEN_PIN),
        r#"{"responseObject":[],"code":"200","message":"","uuid":"7"}"#
    );
    // Errors keep `"responseObject":""`.
    assert_eq!(
        list(&mut session, "AKKaztokenStore", TOKEN_READER, "000000"),
        r#"{"responseObject":"","code":"500","message":"Wrong password","uuid":"7"}"#
    );
    assert_eq!(
        list(&mut session, "AKKaztokenStore", "No such reader", TOKEN_PIN),
        r#"{"responseObject":"","code":"500","message":"Token not found","uuid":"7"}"#
    );
    assert_eq!(
        list(&mut session, "BKS", TOKEN_READER, TOKEN_PIN),
        r#"{"responseObject":"","code":"500","uuid":"7"}"#
    );
    // Two readers, two questions: the wrong PIN went through the allowance it already had,
    // and neither an unknown reader nor an unknown storage reaches the question.
    assert_eq!(harness.prompter().confirm_prompts().len(), 2);
}

#[test]
fn motiw_token_sign_and_verify_with_time_stamp() {
    let harness = Harness::new(vec![Step::Confirm { yes: true }], vec![])
        .with_tokens(kaztoken_emulator("user-gost2015-sign"));
    let mut session = harness.session("motiw");
    let listed = text(session.call(
        &motiw(
            "getCertificateList",
            &format!(r#"["AKKaztokenStore","{TOKEN_READER}","{TOKEN_PIN}"]"#),
        ),
        None,
    ));
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    let alias = listed["responseObject"][0]["alias"]
        .as_str()
        .unwrap()
        .to_owned();
    let sign = |session: &mut oncl_port_tests::SessionHandle, alias: &str, format: i32| {
        text(session.call(
            &motiw(
                "sign",
                &format!(
                    r#"["AKKaztokenStore","{TOKEN_READER}","{TOKEN_PIN}","{alias}","aGVsbG8=",{format},true]"#
                ),
            ),
            None,
        ))
    };
    // Without a time-stamp.
    let reply = sign(&mut session, &alias, 1);
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["code"], "200", "{reply}");
    let info = &value["responseObject"]["certificates"][0];
    assert!(
        info.get("alias").is_none() && info.get("timeStampDate").is_none(),
        "{reply}"
    );
    let cms = decode_java(value["responseObject"]["signature"].as_str().unwrap()).unwrap();
    oncl_pki::cms::verify(&cms, None).expect("the CMS verifies");

    // With one: sign and verify both carry it.
    let reply = sign(&mut session, &alias, 2);
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["code"], "200", "{reply}");
    let signed_info = value["responseObject"]["certificates"][0].clone();
    assert!(signed_info["timeStampDate"].is_i64(), "{reply}");
    assert!(signed_info["timeStampSerialNumber"].is_string(), "{reply}");
    let signature = value["responseObject"]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let verified = text(session.call(&motiw("verify", &format!(r#"["{signature}",""]"#)), None));
    let verified: serde_json::Value = serde_json::from_str(&verified).unwrap();
    assert_eq!(verified["code"], "200");
    let verified_info = &verified["responseObject"]["certificates"][0];
    for key in ["timeStampDate", "timeStampSerialNumber", "tsa"] {
        assert_eq!(verified_info[key], signed_info[key], "{key}");
    }

    // An alias the token lacks.
    assert_eq!(
        sign(&mut session, "nope", 1),
        r#"{"responseObject":"","code":"500","uuid":"7"}"#
    );
    // One question for the reader; the later calls of the session use that allowance.
    assert_eq!(harness.prompter().confirm_prompts().len(), 1);
}

/// [`with_synthetic_ocsp`] whose responder says the synthetic key `name` is revoked.
fn with_revoked_ocsp(steps: Vec<Step>, name: &str) -> Harness {
    let serial: String = entry(name)
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let ocsp = oncl_pki::ocsp::MockOcsp::new(entry("ocsp-gost2015")).status(
        &serial,
        oncl_pki::ocsp::CertStatus::Revoked {
            time: OffsetDateTime::now_utc() - time::Duration::days(1),
            reason: Some(1),
        },
    );
    let ocsp: std::sync::Arc<dyn oncl_pki::http::HttpTransport> = std::sync::Arc::new(ocsp);
    Harness::new(steps, vec![("http://ocsp.synthetic.test".to_owned(), ocsp)])
        .with_pki_hosts(&["ocsp.synthetic.test"])
        .with_clock(OffsetDateTime::now_utc)
}

#[test]
fn revoked_signer_texts_are_fixed() {
    let name = "inter-user-gost2015-sign";
    let harness = with_revoked_ocsp(pick(name, 0), name);
    assert_eq!(
        text(harness.call("workspace", &workspace_sign(r#"["aGVsbG8="]"#), None)),
        r#"{"code":500,"message":"Certificate is revoked"}"#
    );
    let harness = with_revoked_ocsp(simourg_pick(name), name);
    let reply = text(harness.call(
        "simourg",
        &simourg("createCMSSignatureWithTspFromBase64", SIMOURG_ARGS),
        None,
    ));
    assert!(
        reply.contains("Ошибка: Certificate is revoked\""),
        "{reply}"
    );
}
