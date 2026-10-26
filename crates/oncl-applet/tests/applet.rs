//! `kz.gov.pki.knca.applet.Applet`: the reflective dispatcher, every method of the subset
//! through a scripted prompter in temporary folders, the original's codes, and a full
//! cycle (request, certificate issued on it, installation, password change, signing).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::OctetString;
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use oncl_applet::{Applet, MODULE_NAME};
use oncl_basics::testing::{ScriptedPrompter, Step};
use oncl_basics::{Action, FileKind, Locale, OpenError, StorageKind};
use oncl_pki::cert::Certificate;
use oncl_pki::csr::KeyStoreInfo;
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_pki::keygen::MAX_KEYS_PER_REQUEST;
use oncl_pki::keystore::{MAX_CERTIFICATES_PER_REQUEST, change_password};
use oncl_pki::pkcs12::{KeyEntry, WriteOptions, load, load_contents, write};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::{oid, pem, xmldsig};
use oncl_protocol::{AddInfo, DEFAULT_MODULE, Module, Registry, Route};
use oncl_testkit::{fixture, read, synthetic};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::request::{CertReq, ExtensionReq};

const GOST2004: &str = "1.2.398.3.10.1.1.1.2";
const GOST2015: &str = "1.2.398.3.10.1.1.2.3.2";
const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
const DEFAULT_PASSWORD: &str = "Default1";
const NEW_PASSWORD: &str = "NewSecret12";
const ITE: &str = "java.lang.reflect.InvocationTargetException";
/// A password the internal systems' policy accepts (and the PKCS#12 pattern too).
const INNER_PASSWORD: &str = "Qwerty12#";

fn setup(steps: Vec<Step>) -> (Applet, Arc<ScriptedPrompter>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    (Applet::new(prompter.clone()), prompter)
}

fn origin() -> AddInfo {
    AddInfo {
        origin: Some("https://x.kz".to_owned()),
    }
}

/// The raw reply to `request`.
fn raw(a: &Applet, request: Value) -> String {
    a.process(&request.to_string(), &origin())
}

/// The reply to `method(args)`, sent without `module` as the original's pages do.
fn call(a: &Applet, method: &str, args: Value) -> Value {
    serde_json::from_str(&raw(a, json!({"method": method, "args": args}))).unwrap()
}

/// The `errorCode` of a reply.
fn code(reply: &Value) -> &str {
    reply["errorCode"].as_str().unwrap()
}

/// The reply has only `errorCode`, equal to `expected`.
fn assert_code(reply: &Value, expected: &str) {
    assert_eq!(reply, &json!({"errorCode": expected}));
}

/// The dispatcher's failure text for `exception` in `method`.
fn thrown(exception: &str, method: &str) -> Value {
    json!({"errorCode": format!("{exception}. Method: {method}")})
}

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn dir_arg(dir: &TempDir) -> String {
    dir.path().to_str().unwrap().to_owned()
}

// --- dispatcher ---------------------------------------------------------------------------

#[test]
fn is_the_default_module() {
    assert_eq!(MODULE_NAME, DEFAULT_MODULE);
    let (a, _) = setup(vec![]);
    let mut registry = Registry::default();
    registry.register(MODULE_NAME, Arc::new(a));
    let Route::Module(m) = registry.route(r#"{"method":"getTryCount","uuid":"u1"}"#) else {
        panic!("a request without module goes to the Applet");
    };
    assert_eq!(
        m.process(r#"{"method":"getTryCount","uuid":"u1"}"#, &origin()),
        r#"{"errorCode":"NONE","result":-1,"uuid":"u1"}"#
    );
}

#[test]
fn class_must_be_empty_or_the_applet() {
    let (a, _) = setup(vec![]);
    for class in [
        json!(""),
        Value::Null,
        json!("kz.gov.pki.knca.applet.Applet"),
    ] {
        assert_eq!(
            raw(&a, json!({"class": class, "method": "getTryCount"})),
            r#"{"errorCode":"NONE","result":-1}"#
        );
    }
    for class in [json!("kz.gov.pki.knca.applet.MainApplet"), json!(1)] {
        assert_eq!(
            raw(&a, json!({"class": class, "method": "getTryCount"})),
            r#"{"errorCode":"java.lang.NoSuchMethodException. Method: getTryCount"}"#
        );
    }
}

#[test]
fn dispatcher_failures() {
    let (a, _) = setup(vec![]);
    let reply = |request: Value| -> Value { serde_json::from_str(&raw(&a, request)).unwrap() };
    assert_eq!(
        reply(json!({"method": "nope", "uuid": "u"})),
        thrown("java.lang.NoSuchMethodException", "nope")
    );
    assert_eq!(
        reply(json!({"method": ""})),
        thrown("java.lang.NoSuchMethodException", "")
    );
    // The arity selects the method.
    assert_eq!(
        reply(json!({"method": "getTryCount", "args": [1]})),
        thrown("java.lang.NoSuchMethodException", "getTryCount")
    );
    assert_eq!(
        reply(json!({"args": []})),
        json!({"errorCode": "org.json.JSONException: JSONObject[\"method\"] not found.. Method: "})
    );
    assert_eq!(
        reply(json!({"method": 5})),
        json!({"errorCode": "org.json.JSONException: JSONObject[\"method\"] is not a string.. Method: "})
    );
    // Not offered: the original's extension dialogs, its JCE provider and its token chooser.
    for (method, args) in [
        ("genExt", json!(["2.5.29.15"])),
        ("getProvider", json!([])),
        ("setProvider", json!(["x"])),
        ("showTokenChooser", json!(["AKKaztokenStore"])),
    ] {
        assert_eq!(
            reply(json!({"method": method, "args": args})),
            thrown("java.lang.NoSuchMethodException", method)
        );
    }
    // Private methods.
    for method in ["setTryCount", "getStorage"] {
        assert_eq!(
            reply(json!({"method": method, "args": [5]})),
            thrown(
                "java.lang.IllegalAccessException: Class kz.gov.pki.knca.applet.osgi.KNCAAppletActivator \
                 can not access a member of class kz.gov.pki.knca.applet.Applet with modifiers \"private\"",
                method
            )
        );
    }
    // A String parameter takes a string or null only.
    for bad in [json!(1), json!(true), json!({}), json!(["PKCS12"])] {
        assert_eq!(
            reply(json!({"method": "loadSlotList", "args": [bad]})),
            thrown(
                "java.lang.IllegalArgumentException: argument type mismatch",
                "loadSlotList"
            )
        );
    }
    // Anything but an array is no arguments.
    assert_eq!(
        raw(&a, json!({"method": "getTryCount", "args": "x"})),
        r#"{"errorCode":"NONE","result":-1}"#
    );
}

#[test]
fn uuid_is_echoed_on_method_replies_only() {
    let (a, _) = setup(vec![]);
    let req = |method: &str, uuid: Value| {
        raw(
            &a,
            json!({"method": method, "args": ["PKCS12"], "uuid": uuid}),
        )
    };
    assert_eq!(
        req("loadSlotList", json!("abc")),
        r#"{"errorCode":"EMPTY_SLOT","uuid":"abc"}"#
    );
    assert_eq!(
        req("loadSlotList", json!(42)),
        r#"{"errorCode":"EMPTY_SLOT","uuid":"42"}"#
    );
    for uuid in [json!(""), Value::Null] {
        assert_eq!(req("loadSlotList", uuid), r#"{"errorCode":"EMPTY_SLOT"}"#);
    }
    assert_eq!(
        req("nope", json!("abc")),
        r#"{"errorCode":"java.lang.NoSuchMethodException. Method: nope"}"#
    );
}

// --- showFileChooser, browseKeyStore ------------------------------------------------------

#[test]
fn show_file_chooser() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("k.p12");
    fs::write(&file, b"x").unwrap();
    let (a, prompter) = setup(vec![
        Step::File(file.clone()),
        Step::CancelFile,
        Step::File(dir.path().join("gone.p12")),
        Step::File(dir.path().to_path_buf()),
    ]);
    let reply = call(&a, "showFileChooser", json!(["P12", dir_arg(&dir)]));
    assert_eq!(
        reply,
        json!({"errorCode": "NONE", "result": file.to_str().unwrap()})
    );
    // Cancelled, or a path that does not exist: NONE without a result.
    assert_code(&call(&a, "showFileChooser", json!(["ALL", ""])), "NONE");
    assert_code(&call(&a, "showFileChooser", json!(["CER", null])), "NONE");
    // An empty type is a folder.
    let reply = call(&a, "showFileChooser", json!(["", null]));
    assert_eq!(reply["result"], dir_arg(&dir));

    let prompts = prompter.file_prompts();
    assert_eq!(prompts[0].kind, FileKind::P12);
    assert_eq!(prompts[0].directory.as_deref(), Some(dir.path()));
    assert_eq!(prompts[0].origin, "https://x.kz");
    assert_eq!(prompts[0].locale, Locale::Ru);
    assert_eq!(
        (prompts[1].kind, prompts[1].directory.clone()),
        (FileKind::All, None)
    );
    assert_eq!(prompts[3].kind, FileKind::Directory);

    // A null or unknown type throws before any dialog.
    let (a, prompter) = setup(vec![]);
    for ext in [Value::Null, json!("p12"), json!("NOPE")] {
        assert_eq!(
            call(&a, "showFileChooser", json!([ext, null])),
            thrown(ITE, "showFileChooser")
        );
    }
    assert!(prompter.file_prompts().is_empty());
}

#[test]
fn browse_key_store() {
    let dir = tempfile::tempdir().unwrap();
    let (a, prompter) = setup(vec![
        Step::File(dir.path().to_path_buf()),
        Step::CancelFile,
        Step::CancelFile,
    ]);
    let reply = call(
        &a,
        "browseKeyStore",
        json!(["PKCS12", "KEYSTORE", dir_arg(&dir)]),
    );
    assert_eq!(reply["result"], dir_arg(&dir));
    assert_code(
        &call(&a, "browseKeyStore", json!(["JKS", "KEYSTORE", null])),
        "NONE",
    );
    assert_code(
        &call(&a, "browseKeyStore", json!(["PKCS12", "CER", null])),
        "NONE",
    );
    let kinds: Vec<FileKind> = prompter.file_prompts().iter().map(|p| p.kind).collect();
    assert_eq!(kinds, [FileKind::P12, FileKind::Jks, FileKind::Cer]);

    // Tokens: the token chooser finds none; unknown storages; a null type of a file storage.
    let (a, prompter) = setup(vec![]);
    for token in ["AKKaztokenStore", "AKKZIDCardStore", "ABCloudServiceStore"] {
        assert_code(
            &call(&a, "browseKeyStore", json!([token, null, null])),
            "TOKEN_CHOOSE_CANCEL",
        );
    }
    for unknown in [json!("pkcs12"), json!(""), Value::Null] {
        assert_code(
            &call(&a, "browseKeyStore", json!([unknown, "P12", null])),
            "UNKNOWN_STORAGE",
        );
    }
    assert_eq!(
        call(&a, "browseKeyStore", json!(["PKCS12", null, null])),
        thrown(ITE, "browseKeyStore")
    );
    assert!(prompter.file_prompts().is_empty());
}

// --- tokens ---------------------------------------------------------------------------------

#[test]
fn no_token_is_connected() {
    let (a, prompter) = setup(vec![]);
    for storage in [
        json!("AKKaztokenStore"),
        json!("PKCS12"),
        json!("x"),
        Value::Null,
    ] {
        assert_code(&call(&a, "loadSlotList", json!([storage])), "EMPTY_SLOT");
    }
    for terminal in [json!("ACS ACR38U 0"), Value::Null] {
        assert_code(
            &call(&a, "getPublicPartInfo", json!([terminal])),
            "GETPUBLICPART_EXCEPTION",
        );
    }

    // deleteEntry: file storages and ID cards have no deletion; other tokens fail.
    for (storage, expected) in [
        ("PKCS12", "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION"),
        ("JKS", "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION"),
        (
            "AKKZIDCardStore",
            "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION",
        ),
        ("AKKaztokenStore", "COMMON"),
        ("AKEToken72KStore", "COMMON"),
        ("nope", "UNKNOWN_STORAGE"),
    ] {
        assert_code(
            &call(&a, "deleteEntry", json!([storage, "c", "alias"])),
            expected,
        );
    }
    // resetStorage: only eTokens and JaCarta are formatted.
    for (storage, expected) in [
        ("AKEToken72KStore", "COMMON"),
        ("AKEToken5110Store", "COMMON"),
        ("AKJaCartaStore", "COMMON"),
        (
            "AKKaztokenStore",
            "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION",
        ),
        ("AKAKEYStore", "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION"),
        ("PKCS12", "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION"),
        ("nope", "UNKNOWN_STORAGE"),
    ] {
        assert_code(&call(&a, "resetStorage", json!([storage, "c"])), expected);
    }
    assert_code(
        &call(&a, "resetStorage", json!([null, null])),
        "UNKNOWN_STORAGE",
    );

    // Key file operations on a token: no slot.
    let dir = tempfile::tempdir().unwrap();
    let token = "AKKaztokenStore";
    for (method, args) in [
        (
            "genKeyPairAndGetPKCS10",
            json!([
                token,
                "c",
                "p",
                ["a"],
                [GOST2004],
                [256],
                "2.5.4.3",
                "CN",
                ""
            ]),
        ),
        ("setX509CertToKeyStore", json!([token, "c", "p", "pem"])),
        (
            "setX509CertToKeyStoreAndChangePassword",
            json!([token, "c", "p", "n", "pem"]),
        ),
        ("signXml", json!([token, "c", "SIGN", "<a/>"])),
    ] {
        assert_code(&call(&a, method, args), "EMPTY_SLOT");
    }
    // changePassword checks the new PIN by the storage's rule before the device is
    // opened; with a valid PIN the missing device is the generic failure.
    for (storage, new, expected) in [
        (
            "AKKaztokenStore",
            "",
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        (
            "AKKaztokenStore",
            "a b",
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        ("AKKaztokenStore", "Pin12345", "CHANGEPASS_COMMON"),
        ("AKAKEYStore", &"1".repeat(32), "CHANGEPASS_COMMON"),
        (
            "AKEToken72KStore",
            &"1".repeat(33),
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        ("AKJaCartaStore", "1234567890", "CHANGEPASS_COMMON"),
        (
            "AKEToken5110Store",
            "12345678901",
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        (
            "AKKZIDCardStore",
            "",
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        (
            "AKKZIDCardStore",
            "123456",
            "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION",
        ),
        (
            "ABCloudServiceStore",
            "a b",
            "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION",
        ),
    ] {
        assert_code(
            &call(&a, "changePassword", json!([storage, "c", "old", new])),
            expected,
        );
    }
    assert!(files(dir.path()).is_empty());
    assert!(prompter.storage_prompts().is_empty());
    assert!(prompter.password_prompts().is_empty());
}

// --- setPassword, getTryCount ---------------------------------------------------------------

#[test]
fn set_password() {
    let (a, prompter) = setup(vec![
        Step::Password("secret".to_owned()),
        Step::CancelPassword,
        Step::Password(String::new()),
        Step::CancelPassword,
    ]);
    assert_eq!(
        call(&a, "setPassword", json!([])),
        json!({"errorCode": "NONE", "result": true})
    );
    assert_eq!(
        call(&a, "setPassword", json!(["Введите PIN:"])),
        json!({"errorCode": "NONE", "result": false})
    );
    // An empty password is a password.
    assert_eq!(call(&a, "setPassword", json!([""]))["result"], true);
    assert_eq!(call(&a, "setPassword", json!([null]))["result"], false);
    let prompts = prompter.password_prompts();
    let messages: Vec<Option<&str>> = prompts.iter().map(|p| p.message.as_deref()).collect();
    assert_eq!(messages, [None, Some("Введите PIN:"), None, None]);
    assert_eq!(prompts[0].origin, "https://x.kz");
    assert_eq!(prompts[0].locale, Locale::Ru);
}

#[test]
fn try_count_is_the_modules() {
    let (a, _) = setup(vec![]);
    let get = || call(&a, "getTryCount", json!([]));
    assert_eq!(get(), json!({"errorCode": "NONE", "result": -1}));
    // A wrong key file password reports -1, which every connection reads.
    let p12 = synthetic("user-gost2015-sign");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("k.p12");
    fs::copy(&p12.path, &file).unwrap();
    assert_code(
        &call(
            &a,
            "changePassword",
            json!(["PKCS12", file.to_str().unwrap(), "wrong", NEW_PASSWORD]),
        ),
        "CHANGEPASS_WRONG_PASSWORD",
    );
    let other = AddInfo {
        origin: Some("https://other.kz".to_owned()),
    };
    assert_eq!(
        a.process(r#"{"method":"getTryCount"}"#, &other),
        r#"{"errorCode":"NONE","result":-1}"#
    );
}

// --- genKeyPairAndGetPKCS10 -----------------------------------------------------------------

/// `genKeyPairAndGetPKCS10` args for one GOST 2004 key in `dir`.
fn gen_args(dir: &str, oids: &str, values: &str, san: &str) -> Value {
    json!([
        "PKCS12",
        dir,
        DEFAULT_PASSWORD,
        ["alias"],
        [GOST2004],
        [256],
        oids,
        values,
        san
    ])
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    STANDARD.decode(body).unwrap()
}

fn request(pem: &str) -> CertReq {
    assert!(
        pem.starts_with("-----BEGIN NEW CERTIFICATE REQUEST-----\n")
            && pem.ends_with("\n-----END NEW CERTIFICATE REQUEST-----")
            && !pem.contains('\r'),
        "{pem}"
    );
    CertReq::from_der(&pem_to_der(pem)).unwrap()
}

fn request_extensions(req: &CertReq) -> Vec<Extension> {
    req.info
        .attributes
        .iter()
        .flat_map(|a| a.values.iter())
        .flat_map(|v| ExtensionReq::from_der(&v.to_der().unwrap()).unwrap().0)
        .collect()
}

/// The request's signature verifies with its own key.
fn assert_self_signed(req: &CertReq, alg: SigAlg) {
    let public = PublicKey::from_spki(&req.info.public_key).unwrap();
    public
        .verify(
            alg,
            &req.info.to_der().unwrap(),
            req.signature.as_bytes().unwrap(),
        )
        .unwrap();
}

#[test]
fn gen_key_pair_writes_key_files_and_requests() {
    let dir = tempfile::tempdir().unwrap();
    let (a, _) = setup(vec![]);
    let reply = call(
        &a,
        "genKeyPairAndGetPKCS10",
        json!([
            "PKCS12",
            dir_arg(&dir),
            DEFAULT_PASSWORD,
            ["a", "b"],
            [GOST2004, GOST2004],
            [256, 0],
            "2.5.4.6<:>9.9.9<:>2.5.4.3<:>2.5.4.4<:>2.5.4.5<:>2.5.4.11<:>1.2.840.113549.1.9.1",
            "kz<:>ignored<:>Host.kz<:> Тестов\nТест <:>iin123456789012<:>#bin<:>t@x.kz",
            "a.kz, 127.0.0.1"
        ]),
    );
    assert_eq!(code(&reply), "NONE", "{reply}");
    let pems: Vec<&str> = reply["result"].as_str().unwrap().split("<:>").collect();
    let key_ids: Vec<&str> = reply["secondResult"]
        .as_str()
        .unwrap()
        .split("<:>")
        .collect();
    assert_eq!((pems.len(), key_ids.len()), (2, 2));
    assert_ne!(key_ids[0], key_ids[1]);
    let mut expected_files: Vec<String> = key_ids
        .iter()
        .map(|id| format!("GOSTKNCA_{id}.p12"))
        .collect();
    expected_files.sort();
    assert_eq!(files(dir.path()), expected_files);

    for (pem, key_id_hex) in pems.iter().zip(&key_ids) {
        let req = request(pem);
        assert_self_signed(&req, SigAlg::Gost2004);
        assert_eq!(req.algorithm.oid.to_string(), GOST2004);
        // The page's order, values upper-cased, `#` kept as text.
        let subject: Vec<(String, Vec<u8>)> = req
            .info
            .subject
            .iter_rdn()
            .map(|rdn| {
                let atv = rdn.iter().next().unwrap();
                (atv.oid.to_string(), atv.value.to_der().unwrap())
            })
            .collect();
        let utf8 = |s: &str| [&[0x0c, s.len() as u8][..], s.as_bytes()].concat();
        let printable = |s: &str| [&[0x13, s.len() as u8][..], s.as_bytes()].concat();
        let ia5 = |s: &str| [&[0x16, s.len() as u8][..], s.as_bytes()].concat();
        assert_eq!(
            subject,
            [
                ("2.5.4.6".to_owned(), printable("KZ")),
                ("2.5.4.3".to_owned(), utf8("HOST.KZ")),
                ("2.5.4.4".to_owned(), utf8("ТЕСТОВТЕСТ")),
                ("2.5.4.5".to_owned(), printable("IIN123456789012")),
                ("2.5.4.11".to_owned(), utf8("#BIN")),
                ("1.2.840.113549.1.9.1".to_owned(), ia5("T@X.KZ")),
            ]
        );
        // SubjectKeyIdentifier = the key identifier; SubjectAltName led by the CN, which
        // the page did not list.
        let extensions = request_extensions(&req);
        let oids: Vec<_> = extensions.iter().map(|e| e.extn_id).collect();
        assert_eq!(oids, [SubjectKeyIdentifier::OID, SubjectAltName::OID]);
        assert!(extensions.iter().all(|e| !e.critical));
        // The applet's key identifier: SHA-1 of the whole SubjectPublicKeyInfo, not of
        // its BIT STRING (the provider's, `generateCsr`'s).
        let public = PublicKey::from_spki(&req.info.public_key).unwrap();
        let spki_der = req.info.public_key.to_der().unwrap();
        assert_eq!(hex(&Sha1::digest(&spki_der)), *key_id_hex);
        let bits = req.info.public_key.subject_public_key.raw_bytes();
        assert_ne!(hex(&Sha1::digest(bits)), *key_id_hex);
        let ski = SubjectKeyIdentifier::from_der(extensions[0].extn_value.as_bytes()).unwrap();
        assert_eq!(hex(ski.0.as_bytes()), *key_id_hex);
        let san = SubjectAltName::from_der(extensions[1].extn_value.as_bytes()).unwrap();
        let names: Vec<String> = san
            .0
            .iter()
            .map(|n| match n {
                GeneralName::DnsName(s) => s.to_string(),
                GeneralName::IpAddress(ip) => format!("ip {:?}", ip.as_bytes()),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            names,
            ["HOST.KZ", "a.kz", "127.0.0.1", "ip [127, 0, 0, 1]"].map(str::to_owned)
        );
        // The key file holds the key alone, under the key identifier.
        let file = dir.path().join(format!("GOSTKNCA_{key_id_hex}.p12"));
        let contents = load_contents(&fs::read(file).unwrap(), DEFAULT_PASSWORD).unwrap();
        assert_eq!(contents.keys.len(), 1);
        assert_eq!(contents.keys[0].alias, *key_id_hex);
        assert!(contents.keys[0].cert.is_none());
        assert_eq!(contents.keys[0].key.public_key(), public);
    }
}

#[test]
fn gen_key_pair_rsa_and_no_alt_names() {
    let dir = tempfile::tempdir().unwrap();
    let (a, _) = setup(vec![]);
    let reply = call(
        &a,
        "genKeyPairAndGetPKCS10",
        json!([
            "PKCS12",
            dir_arg(&dir),
            null,
            null,
            [SHA256_RSA],
            [2048],
            "2.5.4.3",
            "host",
            null
        ]),
    );
    assert_eq!(code(&reply), "NONE", "{reply}");
    let req = request(reply["result"].as_str().unwrap());
    assert_self_signed(&req, SigAlg::RsaSha256);
    let extensions = request_extensions(&req);
    assert_eq!(extensions.len(), 1, "no SubjectAltName");
    let id = reply["secondResult"].as_str().unwrap();
    // A null password is an empty one.
    let file = dir.path().join(format!("RSA256_{id}.p12"));
    assert_eq!(
        load_contents(&fs::read(file).unwrap(), "")
            .unwrap()
            .keys
            .len(),
        1
    );
}

#[test]
fn gen_key_pair_failures() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir_arg(&dir);
    let (a, _) = setup(vec![]);
    let generate = |args: Value| call(&a, "genKeyPairAndGetPKCS10", args);
    let with = |i: usize, v: Value| {
        let mut args = gen_args(&d, "2.5.4.3<:>2.5.4.6", "X<:>KZ", "");
        args[i] = v;
        args
    };

    for (args, expected) in [
        (with(0, json!("nope")), "UNKNOWN_STORAGE"),
        (with(0, Value::Null), "UNKNOWN_STORAGE"),
        (
            with(0, json!("JKS")),
            "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION",
        ),
        (
            gen_args(&d, "9.9<:>2.5.4.12", "a<:>b", ""),
            "GENKEY_EMPTY_DN",
        ),
        (
            gen_args(&d, "2.5.4.5", "IIN1", ""),
            "GENKEY_INCORRECT_DN_VALUE",
        ),
        (
            gen_args(&d, "2.5.4.6", "ru", ""),
            "GENKEY_INCORRECT_DN_VALUE",
        ),
        (
            gen_args(&d, "2.5.4.11", "BIN1", ""),
            "GENKEY_INCORRECT_DN_VALUE",
        ),
        // GOST 2015 is not an applet algorithm; sha1RSA and GammaTech GOST are refused.
        (with(4, json!([GOST2015])), "GENKEY_UNKNOWN_ALG"),
        (
            with(4, json!(["1.2.840.113549.1.1.5"])),
            "GENKEY_UNKNOWN_ALG",
        ),
        (
            with(4, json!(["1.3.6.1.4.1.6801.1.2.2"])),
            "GENKEY_UNKNOWN_ALG",
        ),
        (
            {
                let mut args = with(4, json!([SHA256_RSA]));
                args[5] = json!([1024]);
                args
            },
            "GENKEY_UNKNOWN_ALG",
        ),
        // The container: null, missing, relative, a file.
        (with(1, Value::Null), "GENKEY_COMMON"),
        (
            with(1, json!(dir.path().join("gone").to_str().unwrap())),
            "COMMON",
        ),
        (with(1, json!("relative")), "COMMON"),
        // SubjectAltName without a CN; a dNSName that is not ASCII (the CN leads them).
        (gen_args(&d, "2.5.4.6", "KZ", "host.kz"), "GENKEY_COMMON"),
        (gen_args(&d, "2.5.4.3", "Тест", "host.kz"), "GENKEY_COMMON"),
        // More keys than a request may generate (the original has no limit).
        (
            {
                let mut args = with(4, json!(vec![GOST2004; MAX_KEYS_PER_REQUEST + 1]));
                args[5] = json!(vec![256; MAX_KEYS_PER_REQUEST + 1]);
                args
            },
            "GENKEY_COMMON",
        ),
    ] {
        assert_code(&generate(args.clone()), expected);
    }
    assert!(files(dir.path()).is_empty(), "{:?}", files(dir.path()));

    // No key lengths: nothing.
    assert_code(&generate(with(5, json!([]))), "NONE");

    // What the original throws on.
    for args in [
        with(5, Value::Null),
        with(4, Value::Null),
        with(4, json!([])),
        with(4, json!(["not.an.oid"])),
        with(6, Value::Null),
        with(7, Value::Null),
        gen_args(&d, "2.5.4.6<:>2.5.4.3", "KZ<:>", ""),
    ] {
        assert_eq!(generate(args), thrown(ITE, "genKeyPairAndGetPKCS10"));
    }
    assert_eq!(
        generate(with(5, json!(["x"]))),
        thrown(
            "org.json.JSONException: JSONArray[0] is not a int.",
            "genKeyPairAndGetPKCS10"
        )
    );
    assert_eq!(
        generate(with(4, json!([1]))),
        thrown(
            "org.json.JSONException: JSONArray[0] is not a String.",
            "genKeyPairAndGetPKCS10"
        )
    );
    assert_eq!(
        generate(with(5, json!(256))),
        thrown(
            "java.lang.IllegalArgumentException: argument type mismatch",
            "genKeyPairAndGetPKCS10"
        )
    );
    assert!(files(dir.path()).is_empty());

    // A later bad algorithm keeps the key files written before it.
    let reply = generate(with(4, json!([GOST2004, GOST2015])).tap(|args| args[5] = json!([0, 0])));
    assert_code(&reply, "GENKEY_UNKNOWN_ALG");
    assert_eq!(files(dir.path()).len(), 1);
}

#[test]
fn gen_key_pair_makes_at_most_sixteen_keys() {
    assert_eq!(MAX_KEYS_PER_REQUEST, 16);
    let dir = tempfile::tempdir().unwrap();
    let (a, _) = setup(vec![]);
    let mut args = gen_args(&dir_arg(&dir), "2.5.4.3<:>2.5.4.6", "X<:>KZ", "");
    args[4] = json!(vec![GOST2004; MAX_KEYS_PER_REQUEST]);
    args[5] = json!(vec![256; MAX_KEYS_PER_REQUEST]);
    let reply = call(&a, "genKeyPairAndGetPKCS10", args);
    assert_eq!(code(&reply), "NONE", "{reply}");
    assert_eq!(
        reply["result"].as_str().unwrap().split("<:>").count(),
        MAX_KEYS_PER_REQUEST
    );
    assert_eq!(files(dir.path()).len(), MAX_KEYS_PER_REQUEST);
}

/// `value` changed by `f`.
trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&mut Self)) -> Self;
}

impl Tap for Value {
    fn tap(mut self, f: impl FnOnce(&mut Self)) -> Self {
        f(&mut self);
        self
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- setX509CertToKeyStore, changePassword, signXml: a full cycle ---------------------------

fn extension(extn_id: der::asn1::ObjectIdentifier, value: &impl Encode) -> Extension {
    Extension {
        extn_id,
        critical: false,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

/// A certificate on `req` issued by the synthetic key `issuer`: the request's subject, key
/// and extensions (SubjectKeyIdentifier among them), a signing or an authentication key.
fn issue(req: &CertReq, issuer: &str, auth: bool, serial: u8) -> Certificate {
    let issuer = entry(issuer);
    let mut extensions = request_extensions(req);
    if auth {
        extensions.push(extension(
            KeyUsage::OID,
            &KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment),
        ));
        extensions.push(extension(
            ExtendedKeyUsage::OID,
            &ExtendedKeyUsage(vec![oid::CLIENT_AUTH]),
        ));
    } else {
        extensions.push(extension(
            KeyUsage::OID,
            &KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
        ));
    }
    issue_cert(
        &issuer,
        TestCertSpec {
            subject: req.info.subject.clone(),
            public_key: req.info.public_key.clone(),
            serial: vec![serial],
            validity: *issuer.cert.tbs_certificate().validity(),
            extensions,
        },
    )
}

fn cert_pem(cert: &Certificate) -> String {
    pem::encode("CERTIFICATE", &cert.to_der().unwrap())
}

/// Two GOST 2004 key files made by `genKeyPairAndGetPKCS10` in a new folder, and their
/// requests.
fn generated(a: &Applet) -> (TempDir, Vec<CertReq>, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let mut args = gen_args(&dir_arg(&dir), "2.5.4.3<:>2.5.4.6", "Тест<:>KZ", "");
    args[4] = json!([GOST2004, GOST2004]);
    args[5] = json!([256, 256]);
    let reply = call(a, "genKeyPairAndGetPKCS10", args);
    assert_eq!(code(&reply), "NONE", "{reply}");
    let requests = reply["result"]
        .as_str()
        .unwrap()
        .split("<:>")
        .map(request)
        .collect();
    let ids = reply["secondResult"]
        .as_str()
        .unwrap()
        .split("<:>")
        .map(str::to_owned)
        .collect();
    (dir, requests, ids)
}

#[test]
fn full_cycle() {
    let (a, prompter) = setup(vec![]);
    let (dir, requests, ids) = generated(&a);
    // The issuer's algorithm is the certificate's: a GOST 2004 key signs with it.
    let sign_cert = issue(&requests[0], "user-gost2004-sign", false, 1);
    let auth_cert = issue(&requests[1], "user-gost2004-sign", true, 2);

    // Both certificates at once: the key files' paths, the authentication key file of a
    // non-GOST-2015 certificate renamed `AUTH_…`.
    let reply = call(
        &a,
        "setX509CertToKeyStore",
        json!([
            "PKCS12",
            dir_arg(&dir),
            DEFAULT_PASSWORD,
            format!("{}<@>{}", cert_pem(&sign_cert), cert_pem(&auth_cert))
        ]),
    );
    assert_eq!(code(&reply), "NONE", "{reply}");
    let sign_file = dir.path().join(format!("GOSTKNCA_{}.p12", ids[0]));
    let auth_file = dir.path().join(format!("AUTH_GOSTKNCA_{}.p12", ids[1]));
    assert_eq!(
        reply["result"],
        format!("{}<@>{}", sign_file.display(), auth_file.display())
    );
    assert!(reply.get("secondResult").is_none());
    let installed = load(&fs::read(&sign_file).unwrap(), DEFAULT_PASSWORD).unwrap();
    assert_eq!(installed[0].cert, sign_cert);

    // The password changes without a dialog.
    let reply = call(
        &a,
        "changePassword",
        json!([
            "PKCS12",
            sign_file.to_str().unwrap(),
            DEFAULT_PASSWORD,
            NEW_PASSWORD
        ]),
    );
    assert_eq!(reply, json!({"errorCode": "NONE"}));
    assert!(load(&fs::read(&sign_file).unwrap(), NEW_PASSWORD).is_ok());

    // Signing with the new key: the storage dialog pre-filled with the container.
    let (a, prompter2) = setup(vec![
        Step::Storage {
            path: sign_file.clone(),
            password: NEW_PASSWORD.to_owned(),
        },
        Step::Key(0),
    ]);
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<doc a=\"1\"><x>т</x></doc>";
    let reply = call(
        &a,
        "signXml",
        json!(["PKCS12", sign_file.to_str().unwrap(), "SIGN", xml]),
    );
    assert_eq!(code(&reply), "NONE", "{reply}");
    assert_eq!(reply["secondResult"], ids[0]);
    let signed = reply["result"].as_str().unwrap();
    assert!(signed.starts_with(&xml[..xml.len() - "</doc>".len()]));
    let signatures = xmldsig::verify(signed.as_bytes()).unwrap();
    assert_eq!(signatures[0].cert, sign_cert);
    let storage_prompt = &prompter2.storage_prompts()[0];
    assert_eq!(storage_prompt.storages, [StorageKind::Pkcs12]);
    assert_eq!(
        storage_prompt.recent_path.as_deref(),
        Some(sign_file.as_path())
    );
    assert_eq!(storage_prompt.action, Action::Sign);
    assert!(
        prompter.storage_prompts().is_empty(),
        "no dialog before signXml"
    );
}

#[test]
fn set_certificate_failures() {
    let (a, _) = setup(vec![]);
    let (dir, requests, ids) = generated(&a);
    let cert = issue(&requests[0], "user-gost2015-sign", false, 1);
    let set = |args: Value| call(&a, "setX509CertToKeyStore", args);
    let d = dir_arg(&dir);

    // A key file that opens with another password is not the key's.
    assert_code(
        &set(json!(["PKCS12", d, "Wrong123", cert_pem(&cert)])),
        "KEYSTORE_FILE_NOT_FOUND",
    );
    // A folder without the key; no folder at all.
    let other = tempfile::tempdir().unwrap();
    assert_code(
        &set(json!([
            "PKCS12",
            dir_arg(&other),
            DEFAULT_PASSWORD,
            cert_pem(&cert)
        ])),
        "KEYSTORE_FILE_NOT_FOUND",
    );
    assert_code(
        &set(json!(["PKCS12", null, DEFAULT_PASSWORD, cert_pem(&cert)])),
        "KEYSTORE_FILE_NOT_FOUND",
    );
    // The certificate is checked before the folder, as in the original: without a
    // SubjectKeyIdentifier, or for another storage, it is SETCERT_COMMON even without one.
    let mut no_ski = TestCertSpec::from_cert(&cert);
    no_ski
        .extensions
        .retain(|e| e.extn_id != SubjectKeyIdentifier::OID);
    let no_ski = issue_cert(&entry("user-gost2004-sign"), no_ski);
    let mut foreign = TestCertSpec::from_cert(&cert);
    foreign.extensions.push(Extension {
        extn_id: oid::KEYSTORE_INFO,
        critical: false,
        extn_value: OctetString::new(
            KeyStoreInfo {
                storage_oid: oid::STORAGE_JKS,
                path: None,
            }
            .to_der()
            .unwrap(),
        )
        .unwrap(),
    });
    let foreign = issue_cert(&entry("user-gost2004-sign"), foreign);
    for wrong in [&no_ski, &foreign] {
        for container in [Value::Null, json!("//host/share")] {
            assert_code(
                &set(json!([
                    "PKCS12",
                    container,
                    DEFAULT_PASSWORD,
                    cert_pem(wrong)
                ])),
                "SETCERT_COMMON",
            );
        }
    }
    // A path that is not a folder.
    let file = dir.path().join(format!("GOSTKNCA_{}.p12", ids[0]));
    assert_code(
        &set(json!([
            "PKCS12",
            file.to_str().unwrap(),
            DEFAULT_PASSWORD,
            cert_pem(&cert)
        ])),
        "SETCERT_COMMON",
    );
    // The certificate of another key under this key's identifier.
    let mut spec = TestCertSpec::from_cert(&cert);
    spec.public_key = requests[1].info.public_key.clone();
    let foreign = issue_cert(&entry("user-gost2015-sign"), spec);
    assert_code(
        &set(json!(["PKCS12", d, DEFAULT_PASSWORD, cert_pem(&foreign)])),
        "INAPPROPRIATE_CERT",
    );
    // Not PEM; base64 without the PEM lines; JKS is not written.
    let base64 = STANDARD.encode(cert.to_der().unwrap());
    for (storage, pems) in [
        ("PKCS12", "garbage".to_owned()),
        ("PKCS12", base64),
        ("JKS", cert_pem(&cert)),
    ] {
        assert_code(
            &set(json!([storage, d, DEFAULT_PASSWORD, pems])),
            "SETCERT_COMMON",
        );
    }
    assert_code(
        &set(json!(["nope", d, DEFAULT_PASSWORD, cert_pem(&cert)])),
        "UNKNOWN_STORAGE",
    );
    // Only separators: no certificate, nothing installed.
    assert_code(&set(json!(["PKCS12", d, DEFAULT_PASSWORD, "<@>"])), "NONE");
    for args in [
        json!(["PKCS12", d, DEFAULT_PASSWORD, null]),
        json!(["PKCS12", d, null, cert_pem(&cert)]),
    ] {
        assert_eq!(set(args), thrown(ITE, "setX509CertToKeyStore"));
    }
    // More certificates than a request may install, refused before any file is touched
    // (the original has no limit).
    let too_many = vec![cert_pem(&cert); MAX_CERTIFICATES_PER_REQUEST + 1].join("<@>");
    assert_code(
        &set(json!(["PKCS12", d, DEFAULT_PASSWORD, too_many])),
        "SETCERT_COMMON",
    );
    assert_code(
        &call(
            &a,
            "setX509CertToKeyStoreAndChangePassword",
            json!(["PKCS12", d, DEFAULT_PASSWORD, NEW_PASSWORD, too_many]),
        ),
        "SETCERT_COMMON",
    );
    // Nothing was installed.
    let contents = load_contents(&fs::read(&file).unwrap(), DEFAULT_PASSWORD).unwrap();
    assert!(contents.keys[0].cert.is_none());
}

#[test]
fn set_certificate_installs_at_most_sixteen_certificates() {
    assert_eq!(MAX_CERTIFICATES_PER_REQUEST, 16);
    let (a, _) = setup(vec![]);
    let (dir, requests, ids) = generated(&a);
    let cert = issue(&requests[0], "user-gost2015-sign", false, 1);
    let pems = vec![cert_pem(&cert); MAX_CERTIFICATES_PER_REQUEST].join("<@>");
    let reply = call(
        &a,
        "setX509CertToKeyStore",
        json!(["PKCS12", dir_arg(&dir), DEFAULT_PASSWORD, pems]),
    );
    assert_eq!(code(&reply), "NONE", "{reply}");
    assert_eq!(
        reply["result"].as_str().unwrap().split("<@>").count(),
        MAX_CERTIFICATES_PER_REQUEST
    );
    let file = dir.path().join(format!("GOSTKNCA_{}.p12", ids[0]));
    let contents = load_contents(&fs::read(&file).unwrap(), DEFAULT_PASSWORD).unwrap();
    assert_eq!(contents.keys[0].cert.as_ref(), Some(&cert));
}

#[test]
fn set_certificate_and_change_password_keeps_the_password() {
    let (a, _) = setup(vec![]);
    let (dir, requests, ids) = generated(&a);
    let cert = issue(&requests[0], "user-gost2015-sign", false, 1);
    let reply = call(
        &a,
        "setX509CertToKeyStoreAndChangePassword",
        json!([
            "PKCS12",
            dir_arg(&dir),
            DEFAULT_PASSWORD,
            NEW_PASSWORD,
            cert_pem(&cert)
        ]),
    );
    let file = dir.path().join(format!("GOSTKNCA_{}.p12", ids[0]));
    assert_eq!(
        reply,
        json!({"errorCode": "NONE", "result": file.to_str().unwrap()})
    );
    // `newPassword` is not used, as in the original.
    assert_eq!(
        load(&fs::read(&file).unwrap(), DEFAULT_PASSWORD).unwrap()[0].cert,
        cert
    );
    assert_code(
        &call(
            &a,
            "setX509CertToKeyStoreAndChangePassword",
            json!(["PKCS12", dir_arg(&dir), DEFAULT_PASSWORD, NEW_PASSWORD, "x"]),
        ),
        "SETCERT_COMMON",
    );
}

#[test]
fn change_password_failures() {
    let dir = tempfile::tempdir().unwrap();
    let p12 = synthetic("user-gost2015-sign");
    let file = dir.path().join("k.p12");
    fs::copy(&p12.path, &file).unwrap();
    let f = file.to_str().unwrap();
    // A key store without keys.
    let empty = dir.path().join("empty.p12");
    let bytes = write(
        &[],
        &[read(fixture("synthetic/root-gost2015.cer"))],
        &p12.password,
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(5),
    )
    .unwrap();
    fs::write(&empty, bytes).unwrap();

    let (a, prompter) = setup(vec![]);
    let change = |args: Value| call(&a, "changePassword", args);
    for (args, expected) in [
        (
            json!(["PKCS12", f, p12.password, "short"]),
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        (
            json!(["PKCS12", f, p12.password, ""]),
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        // The pattern is checked before the file.
        (
            json!(["PKCS12", null, "x", "short"]),
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        (
            json!(["PKCS12", f, "wrong", NEW_PASSWORD]),
            "CHANGEPASS_WRONG_PASSWORD",
        ),
        (
            json!([
                "PKCS12",
                empty.to_str().unwrap(),
                p12.password,
                NEW_PASSWORD
            ]),
            "CHANGEPASS_CONTAINS_EMPTY_ALIAS",
        ),
        (
            json!(["PKCS12", dir_arg(&dir), p12.password, NEW_PASSWORD]),
            "CHANGEPASS_COMMON",
        ),
        (
            json!(["PKCS12", null, p12.password, NEW_PASSWORD]),
            "CHANGEPASS_COMMON",
        ),
        (
            json!([
                "PKCS12",
                dir.path().join("gone.p12").to_str().unwrap(),
                "a",
                NEW_PASSWORD
            ]),
            "CHANGEPASS_COMMON",
        ),
        (
            json!(["PKCS12", f, null, NEW_PASSWORD]),
            "CHANGEPASS_COMMON",
        ),
        (
            json!(["PKCS12", f, p12.password, null]),
            "CHANGEPASS_COMMON",
        ),
        (
            json!(["JKS", f, p12.password, "a b"]),
            "CHANGEPASS_INCORRECT_NEWPASS_PATTERN",
        ),
        (
            json!(["JKS", f, p12.password, NEW_PASSWORD]),
            "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION",
        ),
        (json!(["nope", f, null, null]), "UNKNOWN_STORAGE"),
    ] {
        assert_code(&change(args.clone()), expected);
    }
    // The file is untouched.
    assert_eq!(fs::read(&file).unwrap(), read(&p12.path));
    assert!(prompter.storage_prompts().is_empty());
    assert!(prompter.password_prompts().is_empty());
}

// --- signXml --------------------------------------------------------------------------------

fn storage(name: &str) -> Step {
    let key = synthetic(name);
    Step::Storage {
        path: key.path,
        password: key.password,
    }
}

#[test]
fn sign_xml_with_a_synthetic_key() {
    // GOST 2015-512 signing keys are dual-use: an AUTH key.
    let key = synthetic("user-gost2015-sign");
    let (a, prompter) = setup(vec![storage("user-gost2015-sign"), Step::Key(0)]);
    let reply = call(
        &a,
        "signXml",
        json!(["PKCS12", key.path.to_str().unwrap(), "auth", "<a>x</a>"]),
    );
    assert_eq!(code(&reply), "NONE", "{reply}");
    assert_eq!(reply["secondResult"], key.aliases[0]);
    let signatures = xmldsig::verify(reply["result"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!(signatures[0].sig_alg, SigAlg::Gost2015_512);
    assert_eq!(prompter.storage_prompts()[0].action, Action::Authenticate);
    assert_eq!(prompter.key_prompts()[0].action, Action::Authenticate);
    let candidates = &prompter.key_prompts()[0].candidates;
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].alias, key.aliases[0]);
}

#[test]
fn sign_xml_key_types() {
    // The keys listed for each `keyType`.
    let listed = |store: &str, key_type: &str| {
        let (a, prompter) = setup(vec![storage(store), Step::CancelKey]);
        let reply = call(&a, "signXml", json!(["PKCS12", null, key_type, "<a/>"]));
        assert_code(&reply, "SIGN_CANCEL");
        prompter.key_prompts()[0].candidates.len()
    };
    assert_eq!(listed("user-gost2015-sign", "SIGN"), 1);
    assert_eq!(listed("user-gost2004-sign", "ALL"), 1);
    assert_eq!(listed("user-gost2004-sign", ""), 1);
    // Any key with a certificate, whatever its type.
    assert_eq!(listed("tsa-gost2015", "ALL"), 1);
    // A store without them is asked for again, with the original's text: only AUTH and
    // SIGN have their own.
    let refused = |store: &str, key_type: &str| {
        let (a, prompter) = setup(vec![storage(store), Step::CancelStorage]);
        let reply = call(&a, "signXml", json!(["PKCS12", null, key_type, "<a/>"]));
        assert_code(&reply, "SIGN_CANCEL");
        assert!(prompter.key_prompts().is_empty());
        prompter.storage_prompts()[1].error.unwrap()
    };
    assert_eq!(refused("user-gost2004-sign", "AUTH"), OpenError::NoAuthKeys);
    assert_eq!(refused("tsa-gost2015", "SIGN"), OpenError::NoSigningKeys);
    // INAUTH/INSIGN: the internal systems' password policy comes first.
    assert_eq!(
        refused("user-gost2015-sign", "INSIGN"),
        OpenError::InnerPasswordPolicy
    );
    let dir = tempfile::tempdir().unwrap();
    let inner = |name: &str| {
        let key = synthetic(name);
        let path = dir.path().join(format!("{name}.p12"));
        fs::copy(&key.path, &path).unwrap();
        change_password(&path, &key.password, INNER_PASSWORD).unwrap();
        Step::Storage {
            path,
            password: INNER_PASSWORD.to_owned(),
        }
    };
    let (a, prompter) = setup(vec![inner("user-gost2015-sign"), Step::CancelKey]);
    assert_code(
        &call(&a, "signXml", json!(["PKCS12", null, "insign", "<a/>"])),
        "SIGN_CANCEL",
    );
    assert_eq!(prompter.key_prompts()[0].candidates.len(), 1);
    let (a, prompter) = setup(vec![inner("user-gost2015-sign"), Step::CancelKey]);
    call(&a, "signXml", json!(["PKCS12", null, "INAUTH", "<a/>"]));
    assert_eq!(prompter.key_prompts()[0].candidates.len(), 1);
    for (store, key_type, error) in [
        ("user-gost2004-sign", "INAUTH", OpenError::NoKeys),
        ("tsa-gost2015", "INSIGN", OpenError::NoKeys),
    ] {
        let (a, prompter) = setup(vec![inner(store), Step::CancelStorage]);
        call(&a, "signXml", json!(["PKCS12", null, key_type, "<a/>"]));
        assert_eq!(prompter.storage_prompts()[1].error, Some(error));
    }
    // An empty password is refused for every keyType.
    let (a, prompter) = setup(vec![
        Step::Storage {
            path: synthetic("user-gost2015-sign").path,
            password: String::new(),
        },
        Step::CancelStorage,
    ]);
    call(&a, "signXml", json!(["PKCS12", null, "ALL", "<a/>"]));
    assert_eq!(
        prompter.storage_prompts()[1].error,
        Some(OpenError::EmptyPassword)
    );
    // Oldest certificate first.
    let (a, prompter) = setup(vec![storage("multi-gost2015"), Step::CancelKey]);
    call(&a, "signXml", json!(["PKCS12", "", "ALL", "<a/>"]));
    let candidates = &prompter.key_prompts()[0].candidates;
    assert_eq!(candidates.len(), 2);
    assert!(candidates[0].info.not_before <= candidates[1].info.not_before);
    assert_eq!(prompter.storage_prompts()[0].recent_path, None);
}

#[test]
fn sign_xml_dialog_outcomes() {
    let key = synthetic("user-gost2015-sign");
    // A wrong password, another storage, a missing file and a folder are asked again.
    let dir = tempfile::tempdir().unwrap();
    let (a, prompter) = setup(vec![
        Step::Storage {
            path: key.path.clone(),
            password: "wrong".to_owned(),
        },
        Step::Jks {
            path: key.path.clone(),
            password: key.password.clone(),
        },
        Step::Storage {
            path: dir.path().join("gone.p12"),
            password: key.password.clone(),
        },
        Step::Storage {
            path: dir.path().to_path_buf(),
            password: key.password.clone(),
        },
        Step::CancelStorage,
    ]);
    assert_code(
        &call(&a, "signXml", json!(["PKCS12", "", "SIGN", "<a/>"])),
        "SIGN_CANCEL",
    );
    let errors: Vec<Option<OpenError>> =
        prompter.storage_prompts().iter().map(|p| p.error).collect();
    assert_eq!(
        errors,
        [
            None,
            Some(OpenError::WrongPassword),
            Some(OpenError::UnsupportedStorage),
            Some(OpenError::FileNotFound),
            Some(OpenError::FileNotFound),
        ]
    );
    let paths: Vec<Option<PathBuf>> = prompter
        .storage_prompts()
        .iter()
        .map(|p| p.recent_path.clone())
        .collect();
    assert_eq!(paths[1].as_deref(), Some(key.path.as_path()));

    // The key dialog cancelled; an index past the keys is asked again.
    let (a, prompter) = setup(vec![
        storage("user-gost2015-sign"),
        Step::Key(5),
        Step::CancelKey,
    ]);
    assert_code(
        &call(&a, "signXml", json!(["PKCS12", "", "SIGN", "<a/>"])),
        "SIGN_CANCEL",
    );
    assert_eq!(prompter.key_prompts().len(), 2);

    // JKS is read.
    let (a, _) = setup(vec![
        Step::Jks {
            path: fixture("jks/rsa.jks"),
            password: "Qwerty12".to_owned(),
        },
        Step::Key(0),
    ]);
    let reply = call(&a, "signXml", json!(["JKS", "", "ALL", "<a/>"]));
    assert_eq!(reply["secondResult"], "openncalayer-rsa");

    // A document that does not sign keeps the key dialog open with the error, as the
    // original's dialog stays open; the user can only cancel.
    for xml in [json!("not xml"), json!("<!DOCTYPE a><a/>"), Value::Null] {
        let (a, prompter) = setup(vec![
            storage("user-gost2015-sign"),
            Step::Key(0),
            Step::Key(0),
            Step::CancelKey,
        ]);
        assert_code(
            &call(&a, "signXml", json!(["PKCS12", "", "SIGN", xml])),
            "SIGN_CANCEL",
        );
        let errors: Vec<Option<String>> = prompter
            .key_prompts()
            .into_iter()
            .map(|p| p.error)
            .collect();
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0], None);
        let error = errors[1].as_deref().unwrap();
        assert!(
            error.starts_with("Не удалось подписать документ: "),
            "{error}"
        );
        assert_eq!(errors[2], errors[1]);
    }

    // Before any dialog: an unknown storage, a null keyType.
    let (a, prompter) = setup(vec![]);
    assert_code(
        &call(&a, "signXml", json!(["nope", "", "SIGN", "<a/>"])),
        "UNKNOWN_STORAGE",
    );
    assert_eq!(
        call(&a, "signXml", json!(["PKCS12", "", null, "<a/>"])),
        thrown(ITE, "signXml")
    );
    assert!(prompter.storage_prompts().is_empty());
}

/// Page-named paths that are not regular disk files are not read.
#[test]
fn page_paths_are_regular_files_only() {
    let device = if cfg!(windows) {
        r"\\.\pipe\oncl-applet-test"
    } else {
        "/dev/null"
    };
    let key = synthetic("user-gost2015-sign");
    let (a, prompter) = setup(vec![
        Step::Storage {
            path: PathBuf::from(device),
            password: key.password.clone(),
        },
        Step::CancelStorage,
    ]);
    assert_code(
        &call(&a, "signXml", json!(["PKCS12", device, "SIGN", "<a/>"])),
        "SIGN_CANCEL",
    );
    assert_eq!(
        prompter.storage_prompts()[1].error,
        Some(OpenError::FileNotFound)
    );
    assert_code(
        &call(
            &a,
            "changePassword",
            json!(["PKCS12", device, key.password, NEW_PASSWORD]),
        ),
        "CHANGEPASS_COMMON",
    );
    let expected = if cfg!(windows) {
        "KEYSTORE_FILE_NOT_FOUND"
    } else {
        "SETCERT_COMMON"
    };
    let cert = cert_pem(&entry("user-gost2015-sign").cert);
    assert_code(
        &call(
            &a,
            "setX509CertToKeyStore",
            json!(["PKCS12", device, key.password, cert]),
        ),
        expected,
    );
}

/// Windows resolves `..` lexically, so `<key file>\a\..` reads the key file. The window-less
/// `changePassword` must not rewrite (or lose) the key file through such a path.
#[cfg(windows)]
#[test]
fn change_password_through_dot_dot_keeps_the_key_file() {
    let (a, _) = setup(vec![]);
    let (dir, _, ids) = generated(&a);
    let key_file = dir.path().join(format!("GOSTKNCA_{}.p12", ids[0]));
    let before = fs::read(&key_file).unwrap();
    let through = format!(r"{}\a\..", key_file.display());
    assert_eq!(
        fs::read(&through).unwrap(),
        before,
        "Windows opens the key file"
    );
    assert_code(
        &call(
            &a,
            "changePassword",
            json!(["PKCS12", through, DEFAULT_PASSWORD, NEW_PASSWORD]),
        ),
        "CHANGEPASS_COMMON",
    );
    assert_eq!(fs::read(&key_file).unwrap(), before);
    assert_eq!(files(dir.path()).len(), 2, "{:?}", files(dir.path()));
}

/// A FIFO among the key files would block a read: it is skipped.
#[cfg(unix)]
#[test]
fn fifo_key_files_are_skipped() {
    let (a, _) = setup(vec![]);
    let (dir, requests, ids) = generated(&a);
    let fifo = dir.path().join("0-fifo.p12");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let cert = issue(&requests[0], "user-gost2015-sign", false, 1);
    let reply = call(
        &a,
        "setX509CertToKeyStore",
        json!(["PKCS12", dir_arg(&dir), DEFAULT_PASSWORD, cert_pem(&cert)]),
    );
    let file = dir.path().join(format!("GOSTKNCA_{}.p12", ids[0]));
    assert_eq!(reply["result"], file.to_str().unwrap());
    assert_code(
        &call(
            &a,
            "changePassword",
            json!(["PKCS12", fifo.to_str().unwrap(), "a", NEW_PASSWORD]),
        ),
        "CHANGEPASS_COMMON",
    );
}

/// Paths of network locations a page names are refused before anything is looked up: the
/// daemon would connect to a host the page chose.
#[test]
fn network_paths_are_refused() {
    let mut paths = vec!["//oncl-test.invalid/share/keys"];
    if cfg!(windows) {
        paths.extend([
            r"\\oncl-test.invalid\share\keys",
            r"\/oncl-test.invalid/share",
            r"\\?\UNC\oncl-test.invalid\share\keys",
        ]);
    }
    let (a, _) = setup(vec![]);
    let (_dir, requests, _) = generated(&a);
    let cert = cert_pem(&issue(&requests[0], "user-gost2004-sign", false, 1));
    for path in paths {
        let (a, prompter) = setup(vec![Step::CancelStorage, Step::CancelFile]);
        assert_code(
            &call(
                &a,
                "setX509CertToKeyStore",
                json!(["PKCS12", path, DEFAULT_PASSWORD, cert]),
            ),
            "KEYSTORE_FILE_NOT_FOUND",
        );
        assert_code(
            &call(
                &a,
                "changePassword",
                json!(["PKCS12", path, DEFAULT_PASSWORD, NEW_PASSWORD]),
            ),
            "CHANGEPASS_COMMON",
        );
        assert_code(
            &call(
                &a,
                "genKeyPairAndGetPKCS10",
                gen_args(path, "2.5.4.3<:>2.5.4.6", "A<:>KZ", ""),
            ),
            "COMMON",
        );
        // signXml does not pre-fill the dialog with it.
        assert_code(
            &call(&a, "signXml", json!(["PKCS12", path, "SIGN", "<a/>"])),
            "SIGN_CANCEL",
        );
        assert_eq!(prompter.storage_prompts()[0].recent_path, None, "{path}");
        // The file chooser does not start there.
        assert_code(&call(&a, "showFileChooser", json!(["P12", path])), "NONE");
        assert_eq!(prompter.file_prompts()[0].directory, None, "{path}");
    }
}

/// A key file the user picks in the signXml dialog is read even on a network path: only
/// paths a page names are refused. On Unix a `//`-path is a network path by our rule and
/// reaches the local file; on Windows the drive's administrative share is used when it is
/// reachable.
#[test]
fn signxml_reads_a_user_picked_network_file() {
    let key = synthetic("user-gost2015-sign");
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("k.p12");
    fs::copy(&key.path, &local).unwrap();
    let local = std::path::absolute(&local).unwrap();
    let network = if cfg!(windows) {
        let text = local.to_str().unwrap();
        let (drive, rest) = text.split_at(2);
        format!(r"\\localhost\{}${rest}", &drive[..1])
    } else {
        format!("/{}", local.display())
    };
    assert!(oncl_basics::is_network_path(&network), "{network}");
    if fs::metadata(&network).is_err() {
        // No administrative share here: nothing to read through.
        eprintln!("skipped: {network} is not reachable");
        return;
    }
    let (a, prompter) = setup(vec![
        Step::Storage {
            path: PathBuf::from(&network),
            password: key.password.clone(),
        },
        Step::Key(0),
    ]);
    let reply = call(&a, "signXml", json!(["PKCS12", null, "SIGN", "<a/>"]));
    assert_eq!(code(&reply), "NONE", "{reply}");
    assert_eq!(prompter.storage_prompts().len(), 1);
}
