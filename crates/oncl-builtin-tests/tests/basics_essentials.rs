//! `kz.gov.pki.knca.basics` / `PKIEssentials`: `generateCsr` and `importCertificate` driven by
//! a scripted prompter in temporary folders, their error codes, and a full cycle (request,
//! certificate issued on it, import, signing with the new key).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::OctetString;
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use oncl_builtin_tests::basics::{Basics, MODULE_NAME};
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_flows::{Locale, StorageKind};
use oncl_pki::cert::Certificate;
use oncl_pki::csr::KeyStoreInfo;
use oncl_pki::info::cert_info;
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_pki::keygen::{MAX_KEYS_PER_REQUEST, key_id};
use oncl_pki::keystore::MAX_CERTIFICATES_PER_REQUEST;
use oncl_pki::oid;
use oncl_pki::pkcs12::{KeyEntry, load, load_contents};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::MockTsa;
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{read, synthetic};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use tempfile::TempDir;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::request::{CertReq, ExtensionReq};

const GOST2015: &str = "1.2.398.3.10.1.1.2.3.2";
const GOST2004: &str = "1.2.398.3.10.1.1.1.2";
const DEFAULT_PASSWORD: &str = "Default1";
const NEW_PASSWORD: &str = "NewSecret12";
const CN: &str = "ТЕСТОВ ТЕСТ";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

fn basics(steps: Vec<Step>) -> (Basics, Arc<ScriptedPrompter>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let basics = Basics::new(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
    );
    (basics, prompter)
}

fn call(b: &Basics, class: Option<&str>, method: &str, args: Value) -> Value {
    let mut request = json!({"module": MODULE_NAME, "method": method, "args": args});
    if let Some(class) = class {
        request["class"] = json!(class);
    }
    let reply = b.process(
        &request.to_string(),
        &AddInfo {
            origin: Some("https://test.pki.gov.kz".to_owned()),
            ..AddInfo::default()
        },
    );
    serde_json::from_str(reply.text().unwrap()).unwrap()
}

fn essentials(b: &Basics, method: &str, args: Value) -> Value {
    call(b, Some("PKIEssentials"), method, args)
}

fn csr_args(params: Value) -> Value {
    json!({
        "allowedStorages": ["PKCS12", "AKKaztokenStore"],
        "defaultPassword": DEFAULT_PASSWORD,
        "dn": {"2.5.4.3": CN, "2.5.4.5": "IIN123456789012", "2.5.4.6": "KZ"},
        "email": "test@example.kz",
        "params": params,
        "locale": "ru",
    })
}

fn gost2015() -> Value {
    json!({"algorithm": GOST2015, "length": 512})
}

fn csr_step(dir: &Path) -> Step {
    Step::Csr {
        dir: dir.to_path_buf(),
        password: String::new(),
    }
}

fn import_step(dir: &Path, password: &str) -> Step {
    Step::Import {
        dir: dir.to_path_buf(),
        password: password.to_owned(),
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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
        pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
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

/// The failure of a reply: `(code, message, details)`.
fn failure(r: &Value) -> (String, String, String) {
    assert_eq!(r["status"], false, "{r}");
    let text = |k: &str| r[k].as_str().unwrap_or_default().to_owned();
    (text("code"), text("message"), text("details"))
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn extension(extn_id: der::asn1::ObjectIdentifier, value: &impl Encode) -> Extension {
    Extension {
        extn_id,
        critical: false,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

/// A signing certificate on `req`, as the NCA issues one: the request's subject, key and
/// extensions, SubjectKeyIdentifier = the key identifier, issued by a synthetic GOST 2015
/// key.
fn issue(req: &CertReq, serial: &[u8]) -> Certificate {
    issue_by(
        "user-gost2015-sign",
        req,
        serial,
        KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
        &[],
    )
}

/// An authentication certificate on `req` (digitalSignature + keyEncipherment,
/// clientAuth) signed with sha256WithRSA, which the original names `AUTH_` key files for.
fn issue_auth(req: &CertReq, serial: &[u8]) -> Certificate {
    issue_by(
        "user-rsa-sign",
        req,
        serial,
        KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment,
        &[oid::CLIENT_AUTH],
    )
}

/// A certificate on `req` issued by the synthetic key `issuer` (whose algorithm signs
/// it), with `usages` and the extended key usages `eku` (none: no extension).
fn issue_by(
    issuer: &str,
    req: &CertReq,
    serial: &[u8],
    usages: der::flagset::FlagSet<KeyUsages>,
    eku: &[der::asn1::ObjectIdentifier],
) -> Certificate {
    let issuer = entry(issuer);
    let public = PublicKey::from_spki(&req.info.public_key).unwrap();
    let ski = SubjectKeyIdentifier(OctetString::new(hex_decode(&key_id(&public))).unwrap());
    let mut extensions = vec![
        extension(SubjectKeyIdentifier::OID, &ski),
        extension(KeyUsage::OID, &KeyUsage(usages)),
    ];
    if !eku.is_empty() {
        extensions.push(extension(
            ExtendedKeyUsage::OID,
            &ExtendedKeyUsage(eku.to_vec()),
        ));
    }
    extensions.extend(request_extensions(req));
    issue_cert(
        &issuer,
        TestCertSpec {
            subject: req.info.subject.clone(),
            public_key: req.info.public_key.clone(),
            serial: serial.to_vec(),
            validity: *issuer.cert.tbs_certificate().validity(),
            extensions,
        },
    )
}

fn cert_pem(cert: &Certificate) -> String {
    oncl_pki::pem::encode("CERTIFICATE", &cert.to_der().unwrap())
}

/// A GOST 2015 key file made by `generateCsr` in a new folder, and its request.
fn generated(password: &str) -> (TempDir, PathBuf, CertReq) {
    let dir = tempfile::tempdir().unwrap();
    let (b, _) = basics(vec![csr_step(dir.path())]);
    let mut args = csr_args(json!([gost2015()]));
    args["defaultPassword"] = json!(password);
    let r = essentials(&b, "generateCsr", args);
    assert_eq!(r["status"], true, "{r}");
    let req = request(r["body"]["pems"][0].as_str().unwrap());
    let file = dir.path().join(&files(dir.path())[0]);
    (dir, file, req)
}

fn import_args(dir: &Path, certs: &[&Certificate]) -> Value {
    json!({
        "allowedStorage": "PKCS12",
        "defaultPassword": DEFAULT_PASSWORD,
        "keystorePath": dir.display().to_string(),
        "certificates": certs.iter().map(|c| cert_pem(c)).collect::<Vec<_>>(),
        "locale": "kk",
    })
}

#[test]
fn two_params_make_two_requests_and_two_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let (b, p) = basics(vec![csr_step(dir.path())]);
    let r = essentials(
        &b,
        "generateCsr",
        csr_args(json!([gost2015(), {"algorithm": GOST2004, "length": 256}])),
    );
    assert_eq!(r["status"], true, "{r}");
    let pems = r["body"]["pems"].as_array().unwrap();
    assert_eq!(pems.len(), 2);

    let prompts = p.csr_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].origin, "https://test.pki.gov.kz");
    assert_eq!(prompts[0].locale, Locale::Ru);
    assert_eq!(
        prompts[0].storages,
        [StorageKind::Pkcs12, StorageKind::Token("AKKaztokenStore")]
    );
    assert!(!prompts[0].ask_password, "the page gave the password");

    let mut expected = Vec::new();
    for (pem, (alg, prefix)) in pems.iter().zip([
        (SigAlg::Gost2015_512, "GOST512_"),
        (SigAlg::Gost2004, "GOSTKNCA_"),
    ]) {
        let req = request(pem.as_str().unwrap());
        assert_eq!(req.algorithm.oid, alg.signature_oid());
        let public = PublicKey::from_spki(&req.info.public_key).unwrap();
        public
            .verify(
                alg,
                &req.info.to_der().unwrap(),
                req.signature.as_bytes().unwrap(),
            )
            .unwrap();
        let info = request_extensions(&req)
            .into_iter()
            .find(|e| e.extn_id == oid::KEYSTORE_INFO)
            .unwrap();
        assert_eq!(
            KeyStoreInfo::from_der(info.extn_value.as_bytes()).unwrap(),
            KeyStoreInfo {
                storage_oid: oid::STORAGE_PKCS12,
                path: Some(dir.path().display().to_string()),
            }
        );
        let alias = key_id(&public);
        let name = format!("{prefix}{alias}.p12");
        let contents = load_contents(&read(dir.path().join(&name)), DEFAULT_PASSWORD).unwrap();
        assert_eq!(contents.keys.len(), 1);
        assert_eq!(contents.keys[0].alias, alias);
        assert_eq!(contents.keys[0].key.public_key(), public);
        assert!(contents.keys[0].cert.is_none());
        expected.push(name);
    }
    expected.sort();
    assert_eq!(files(dir.path()), expected);
}

#[test]
fn cancel_answers_empty_and_writes_nothing() {
    let (b, p) = basics(vec![Step::CancelCsr]);
    let r = essentials(&b, "generateCsr", csr_args(json!([gost2015()])));
    assert_eq!(r, json!({"status": true, "body": {}}));
    assert_eq!(p.csr_prompts().len(), 1);

    // An installed certificate's key file is left alone when the import is cancelled.
    let (dir, file, req) = generated(DEFAULT_PASSWORD);
    let before = read(&file);
    let cert = issue(&req, &[0x41, 0x01]);
    let (b, p) = basics(vec![Step::CancelImport]);
    let r = essentials(&b, "importCertificate", import_args(dir.path(), &[&cert]));
    assert_eq!(r, json!({"status": true, "body": {}}));
    assert_eq!(p.import_prompts().len(), 1);
    assert_eq!(read(&file), before);
    assert_eq!(files(dir.path()).len(), 1);
}

#[test]
fn key_files_need_an_existing_absolute_folder() {
    let dir = tempfile::tempdir().unwrap();
    for answer in [
        PathBuf::new(),
        PathBuf::from("relative-keys"),
        dir.path().join("missing"),
    ] {
        let (b, _) = basics(vec![csr_step(&answer)]);
        let (code, _, _) = failure(&essentials(
            &b,
            "generateCsr",
            csr_args(json!([gost2015()])),
        ));
        assert_eq!(code, "CSR_GENERATING_FAILURE", "{}", answer.display());
    }
    assert!(files(dir.path()).is_empty());
    assert!(!Path::new("relative-keys").exists());
}

#[test]
fn methods_need_the_class() {
    let (b, p) = basics(vec![]);
    for method in ["generateCsr", "importCertificate"] {
        let r = call(&b, None, method, csr_args(json!([gost2015()])));
        assert_eq!(
            failure(&r),
            (
                "GENERAL_ERROR".to_owned(),
                "General error.".to_owned(),
                format!("{method} is not defined in PKIExtras")
            )
        );
        let r = call(&b, Some("PKIEssentials"), method, Value::Null);
        assert_eq!(failure(&r).2, format!("{method} demands arguments"));
    }
    assert!(p.csr_prompts().is_empty());
    assert!(p.import_prompts().is_empty());
}

#[test]
fn csr_argument_errors_come_before_the_dialog() {
    let npe = (
        "INVOCATION_ERROR".to_owned(),
        "java.lang.NullPointerException".to_owned(),
    );
    let cases = [
        // The original's `optJSONArray("allowedStorages").toList()`; a `-` key is removed.
        (json!({"-allowedStorages": null}), npe.clone()),
        (json!({"allowedStorages": null}), npe.clone()),
        (json!({"allowedStorages": "PKCS12"}), npe.clone()),
        (json!({"-dn": null}), npe.clone()),
        (json!({"dn": {"2.5.4.3": null}}), npe),
        (
            json!({"dn": {"CN": "x"}}),
            (
                "INVOCATION_ERROR".to_owned(),
                "java.lang.IllegalArgumentException: string CN not an OID".to_owned(),
            ),
        ),
        (
            json!({"params": null}),
            (
                "INVOCATION_ERROR".to_owned(),
                "org.json.JSONException: JSONObject[\"params\"] is not a JSONArray.".to_owned(),
            ),
        ),
        (
            json!({"params": [{"algorithm": "1.2.840.113549.1.1.5", "length": 2048}]}),
            (
                "UNKNOWN_ALGORITHM".to_owned(),
                "UNKNOWN_ALGORITHM".to_owned(),
            ),
        ),
        (
            json!({"params": [{"algorithm": GOST2015}]}),
            (
                "CSR_GENERATING_FAILURE".to_owned(),
                "org.json.JSONException: JSONObject[\"length\"] not found.".to_owned(),
            ),
        ),
        (
            json!({"omittedKeyIds": ["a", 1]}),
            (
                "INVOCATION_ERROR".to_owned(),
                "org.json.JSONException: JSONArray[1] is not a String.".to_owned(),
            ),
        ),
        (
            json!({"params": vec![gost2015(); MAX_KEYS_PER_REQUEST + 1]}),
            (
                "INVOCATION_ERROR".to_owned(),
                "java.lang.IllegalArgumentException: too many keys requested".to_owned(),
            ),
        ),
    ];
    for (patch, (code, details)) in cases {
        let mut args = csr_args(json!([gost2015()]));
        for (k, v) in patch.as_object().unwrap() {
            match k.strip_prefix('-') {
                Some(absent) => {
                    args.as_object_mut().unwrap().remove(absent);
                }
                None => args[k] = v.clone(),
            }
        }
        let (b, p) = basics(vec![]);
        let r = essentials(&b, "generateCsr", args);
        let (got_code, _, got_details) = failure(&r);
        assert_eq!((got_code, got_details), (code, details), "{patch}");
        assert!(p.csr_prompts().is_empty(), "{patch}: no dialog");
    }
}

/// A request may generate [`MAX_KEYS_PER_REQUEST`] keys; one more is refused before the
/// dialog (above).
#[test]
fn at_most_sixteen_keys_per_request() {
    assert_eq!(MAX_KEYS_PER_REQUEST, 16);
    let dir = tempfile::tempdir().unwrap();
    let (b, _) = basics(vec![csr_step(dir.path())]);
    let gost2004 = json!({"algorithm": GOST2004, "length": 256});
    let r = essentials(
        &b,
        "generateCsr",
        csr_args(json!(vec![gost2004; MAX_KEYS_PER_REQUEST])),
    );
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(
        r["body"]["pems"].as_array().unwrap().len(),
        MAX_KEYS_PER_REQUEST
    );
    assert_eq!(files(dir.path()).len(), MAX_KEYS_PER_REQUEST);
}

/// The dialog answers with a storage the page did not offer: nothing is generated.
#[test]
fn csr_answer_must_name_an_offered_storage() {
    let dir = tempfile::tempdir().unwrap();
    let (b, p) = basics(vec![csr_step(dir.path())]);
    let mut args = csr_args(json!([gost2015()]));
    args["allowedStorages"] = json!(["AKKaztokenStore"]);
    let (code, _, _) = failure(&essentials(&b, "generateCsr", args));
    assert_eq!(code, "UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION");
    assert_eq!(
        p.csr_prompts()[0].storages,
        [StorageKind::Token("AKKaztokenStore")]
    );
    assert!(files(dir.path()).is_empty());
}

#[test]
fn alternative_names_must_contain_the_common_name() {
    for (dn, details) in [
        (
            json!({"2.5.4.3": CN}),
            "java.lang.IllegalArgumentException: Subject alternative names do not contain corresponding common name",
        ),
        (
            json!({"2.5.4.5": "IIN123456789012"}),
            "org.json.JSONException: JSONObject[\"2.5.4.3\"] not found.",
        ),
    ] {
        let mut args = csr_args(json!([gost2015()]));
        args["dn"] = dn;
        args["subjectAltNames"] = json!(["test.kz"]);
        let (b, p) = basics(vec![]);
        let r = essentials(&b, "generateCsr", args);
        assert_eq!(
            failure(&r),
            (
                "INVOCATION_ERROR".to_owned(),
                "An invoked method threw an exception.".to_owned(),
                details.to_owned()
            )
        );
        assert!(p.csr_prompts().is_empty());
    }

    // With the CN among them, the names go into the request.
    let dir = tempfile::tempdir().unwrap();
    let mut args = csr_args(json!([gost2015()]));
    args["dn"] = json!({"2.5.4.3": "test.kz"});
    args["subjectAltNames"] = json!(["test.kz", "www.test.kz", "test.kz"]);
    let (b, _) = basics(vec![csr_step(dir.path())]);
    let r = essentials(&b, "generateCsr", args);
    assert_eq!(r["status"], true, "{r}");
    let req = request(r["body"]["pems"][0].as_str().unwrap());
    let san = request_extensions(&req)
        .into_iter()
        .find(|e| e.extn_id == x509_cert::ext::pkix::SubjectAltName::OID)
        .unwrap();
    let san = x509_cert::ext::pkix::SubjectAltName::from_der(san.extn_value.as_bytes()).unwrap();
    assert_eq!(san.0.len(), 3, "two dNSNames, then the email: {san:?}");
}

/// `subjectAltNames` are read before the dialog: any number is deduplicated in linear time,
/// keeping the first occurrence of each name in the page's order.
///
/// The bound scales with the machine's speed, and its 10 s floor absorbs load: the
/// baseline is the same call with as many names, all equal. It parses, converts and hashes
/// as much, but any deduplication is linear on it (one distinct name), even a quadratic one.
/// Over 101 000 distinct names a quadratic deduplication makes about 5·10⁹ comparisons:
/// measured at 27 s in a debug build (baseline 70 ms), well past the bound.
#[test]
fn many_alternative_names_are_deduplicated_quickly_in_order() {
    use std::time::{Duration, Instant};
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::ext::pkix::name::GeneralName;

    let mut names: Vec<String> = (0..100_000).map(|i| format!("h{i}.test.kz")).collect();
    names.extend(names[..1000].to_vec());
    // The call with `names`, timed; it shows the dialog (cancelled) unless `cn` is absent.
    let timed = |cn: &str, names: &[String], expect_dialog: bool| {
        let mut args = csr_args(json!([gost2015()]));
        args["dn"] = json!({"2.5.4.3": cn});
        args["subjectAltNames"] = json!(names);
        let (b, p) = basics(vec![Step::CancelCsr]);
        let started = Instant::now();
        let r = essentials(&b, "generateCsr", args);
        let elapsed = started.elapsed();
        if expect_dialog {
            assert_eq!(r, json!({"status": true, "body": {}}));
        } else {
            assert_eq!(failure(&r).0, "INVOCATION_ERROR");
        }
        assert_eq!(p.csr_prompts().len(), usize::from(expect_dialog), "{cn}");
        elapsed
    };
    let same = vec!["h0.test.kz".to_owned(); names.len()];
    let baseline = timed("h0.test.kz", &same, true);
    let bound = (baseline * 5 + Duration::from_secs(2)).max(Duration::from_secs(10));
    for (cn, expect_dialog) in [("h99999.test.kz", true), ("absent.kz", false)] {
        let elapsed = timed(cn, &names, expect_dialog);
        assert!(
            elapsed < bound,
            "{cn}: {elapsed:?}, bound {bound:?} (baseline {baseline:?})"
        );
    }

    // First-seen order, each name once, then the email.
    let dir = tempfile::tempdir().unwrap();
    let mut args = csr_args(json!([gost2015()]));
    args["dn"] = json!({"2.5.4.3": "test.kz"});
    args["subjectAltNames"] = json!(["b.test.kz", "test.kz", "b.test.kz", "a.test.kz", "test.kz"]);
    let (b, _) = basics(vec![csr_step(dir.path())]);
    let r = essentials(&b, "generateCsr", args);
    assert_eq!(r["status"], true, "{r}");
    let req = request(r["body"]["pems"][0].as_str().unwrap());
    let san = request_extensions(&req)
        .into_iter()
        .find(|e| e.extn_id == SubjectAltName::OID)
        .unwrap();
    let san = SubjectAltName::from_der(san.extn_value.as_bytes()).unwrap();
    let dns: Vec<&str> = san
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::DnsName(dns) => Some(dns.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(dns, ["b.test.kz", "test.kz", "a.test.kz"]);
}

#[test]
fn password_asked_without_default_password() {
    let dir = tempfile::tempdir().unwrap();
    let (b, p) = basics(vec![Step::Csr {
        dir: dir.path().to_path_buf(),
        password: "Typed123".to_owned(),
    }]);
    let mut args = csr_args(json!([gost2015()]));
    args.as_object_mut().unwrap().remove("defaultPassword");
    let r = essentials(&b, "generateCsr", args);
    assert_eq!(r["status"], true, "{r}");
    assert!(p.csr_prompts()[0].ask_password);
    let file = dir.path().join(&files(dir.path())[0]);
    assert_eq!(
        load_contents(&read(file), "Typed123").unwrap().keys.len(),
        1
    );
}

#[test]
fn full_cycle_generate_issue_import_sign() {
    let (dir, file, req) = generated(DEFAULT_PASSWORD);
    let cert = issue(&req, &[0x41, 0x02, 0x03]);

    let (b, p) = basics(vec![import_step(dir.path(), NEW_PASSWORD)]);
    let r = essentials(&b, "importCertificate", import_args(dir.path(), &[&cert]));
    assert_eq!(r, json!({"status": true, "body": {"result": true}}));
    let prompts = p.import_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].storage, StorageKind::Pkcs12);
    assert_eq!(prompts[0].locale, Locale::Kk);
    assert_eq!(prompts[0].path.as_deref(), Some(dir.path()));
    assert_eq!(prompts[0].certificates, [cert_info(&cert)]);

    // A signing certificate keeps the file name; the password is the user's now.
    assert_eq!(
        files(dir.path()),
        [file.file_name().unwrap().to_string_lossy()]
    );
    assert!(load_contents(&read(&file), DEFAULT_PASSWORD).is_err());
    let entries = load(&read(&file), NEW_PASSWORD).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cert, cert);

    let (b, _) = basics(vec![
        Step::Storage {
            path: file.clone(),
            password: NEW_PASSWORD.to_owned(),
        },
        Step::Key(0),
    ]);
    let r = call(
        &b,
        None,
        "sign",
        json!({
            "format": "cms",
            "data": STANDARD.encode(b"hello"),
            "signingParams": {"decode": true},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        }),
    );
    assert_eq!(r["status"], true, "{r}");
    let cms = pem_to_der(r["body"]["result"][0].as_str().unwrap());
    let signers = oncl_pki::cms::verify(&cms, None).unwrap();
    assert_eq!(signers.len(), 1);
}

/// The NCA portal's flow: an authentication (RSA, clientAuth) and a signing certificate
/// imported in one call. The authentication key file is renamed `AUTH_…` and its password
/// is changed under the new name; both files end up with the user's password.
#[test]
fn auth_and_sign_certificates_import_in_one_call() {
    let dir = tempfile::tempdir().unwrap();
    let (b, _) = basics(vec![csr_step(dir.path())]);
    let r = essentials(
        &b,
        "generateCsr",
        csr_args(json!([
            {"algorithm": "1.2.840.113549.1.1.11", "length": 2048},
            gost2015(),
        ])),
    );
    assert_eq!(r["status"], true, "{r}");
    let pems = r["body"]["pems"].as_array().unwrap();
    let auth_req = request(pems[0].as_str().unwrap());
    let sign_req = request(pems[1].as_str().unwrap());
    let auth = issue_auth(&auth_req, &[0x41, 0x07, 0x01]);
    let sign = issue(&sign_req, &[0x41, 0x07, 0x02]);
    let auth_name = format!(
        "AUTH_RSA256_{}.p12",
        key_id(&PublicKey::from_spki(&auth_req.info.public_key).unwrap())
    );
    let sign_name = format!(
        "GOST512_{}.p12",
        key_id(&PublicKey::from_spki(&sign_req.info.public_key).unwrap())
    );

    let (b, p) = basics(vec![import_step(dir.path(), NEW_PASSWORD)]);
    let r = essentials(
        &b,
        "importCertificate",
        import_args(dir.path(), &[&auth, &sign]),
    );
    assert_eq!(r, json!({"status": true, "body": {"result": true}}));
    assert_eq!(
        p.import_prompts()[0].certificates,
        [cert_info(&auth), cert_info(&sign)]
    );
    // `AUTH_…` sorts before `GOST512_…`.
    assert_eq!(files(dir.path()), [auth_name.as_str(), sign_name.as_str()]);
    for (name, cert) in [(&auth_name, &auth), (&sign_name, &sign)] {
        let p12 = read(dir.path().join(name));
        assert!(load_contents(&p12, DEFAULT_PASSWORD).is_err(), "{name}");
        let entries = load(&p12, NEW_PASSWORD).unwrap();
        assert_eq!(entries.len(), 1, "{name}");
        assert_eq!(&entries[0].cert, cert, "{name}");
    }
}

/// A `keystorePath` a page may not name is not shown in the dialog, so Browse and Confirm
/// never reach a host the page chose; a local one is.
#[test]
fn network_keystore_path_does_not_prefill_the_import_dialog() {
    let (dir, _, req) = generated(DEFAULT_PASSWORD);
    let cert = issue(&req, &[0x41, 0x08]);
    let mut refused = vec!["//host/share", "//host/share/keys", ""];
    if cfg!(windows) {
        refused.extend([
            r"\\host\share",
            r"\\?\UNC\host\share",
            r"\\.\pipe\keys",
            r"\\?\GLOBALROOT\Device\Null",
        ]);
    }
    for path in refused {
        let mut args = import_args(dir.path(), &[&cert]);
        args["keystorePath"] = json!(path);
        let (b, p) = basics(vec![Step::CancelImport]);
        let r = essentials(&b, "importCertificate", args);
        assert_eq!(r, json!({"status": true, "body": {}}), "{path}");
        assert_eq!(p.import_prompts()[0].path, None, "{path}");
    }
    let (b, p) = basics(vec![Step::CancelImport]);
    essentials(&b, "importCertificate", import_args(dir.path(), &[&cert]));
    assert_eq!(p.import_prompts()[0].path.as_deref(), Some(dir.path()));
}

/// The folder the user picks is searched whole, as the original searches it: the key file
/// is found behind more key files than a page-named folder is searched for.
#[test]
fn import_searches_every_key_file_of_the_folder() {
    let (dir, file, req) = generated(DEFAULT_PASSWORD);
    let cert = issue(&req, &[0x41, 0x02, 0x04]);
    // Key files sorting first: copies under another password (skipped as not opening
    // with the default password) and broken ones.
    let other = fs::read(&file).unwrap();
    for i in 0..(oncl_pki::keystore::MAX_KEY_FILES + 6) {
        let contents: &[u8] = if i % 2 == 0 {
            &other
        } else {
            b"not a key store"
        };
        let path = dir.path().join(format!("0-{i:03}.p12"));
        fs::write(&path, contents).unwrap();
        if i % 2 == 0 {
            oncl_pki::keystore::change_password(&path, DEFAULT_PASSWORD, "Another12").unwrap();
        }
    }
    let (b, _) = basics(vec![import_step(dir.path(), NEW_PASSWORD)]);
    let r = essentials(&b, "importCertificate", import_args(dir.path(), &[&cert]));
    assert_eq!(r, json!({"status": true, "body": {"result": true}}));
    let entries = load(&read(&file), NEW_PASSWORD).unwrap();
    assert_eq!(entries[0].cert, cert);
}

#[test]
fn wrong_new_password_pattern_changes_nothing() {
    let (dir, file, req) = generated(DEFAULT_PASSWORD);
    let before = read(&file);
    let cert = issue(&req, &[0x41, 0x04]);
    let serial = cert_info(&cert).serial_hex;
    for password in ["sh1", "NoDigitsHere", "пароль123", ""] {
        let (b, _) = basics(vec![import_step(dir.path(), password)]);
        let r = essentials(&b, "importCertificate", import_args(dir.path(), &[&cert]));
        let (code, message, _) = failure(&r);
        assert_eq!(code, "WRONG_PASSWORD_PATTERN", "{password:?}");
        assert!(message.starts_with(&format!("[{serial}] ")), "{message}");
        assert_eq!(
            read(&file),
            before,
            "{password:?}: the key file is unchanged"
        );
    }
}

#[test]
fn provider_errors_name_the_certificate_serial() {
    let (dir, _, req) = generated(DEFAULT_PASSWORD);
    let cert = issue(&req, &[0x41, 0x05, 0xa0]);
    let serial = cert_info(&cert).serial_hex;
    assert_eq!(serial, "4105a0");

    // The page's password does not open the key file.
    let mut args = import_args(dir.path(), &[&cert]);
    args["defaultPassword"] = json!("Other123");
    let (b, _) = basics(vec![import_step(dir.path(), NEW_PASSWORD)]);
    let (code, message, _) = failure(&essentials(&b, "importCertificate", args));
    assert_eq!(code, "KEYSTORE_FILE_NOT_FOUND");
    assert!(message.starts_with("[4105a0] "), "{message}");

    // JKS is read-only; the certificate's own checks come first, as in the original, and
    // its KeyStoreInfo names PKCS#12.
    let mut args = import_args(dir.path(), &[&cert]);
    args["allowedStorage"] = json!("JKS");
    let (b, p) = basics(vec![import_step(dir.path(), NEW_PASSWORD)]);
    let (code, message, _) = failure(&essentials(&b, "importCertificate", args));
    assert_eq!(code, "UNSUITED_STORAGE");
    assert!(message.starts_with("[4105a0] "), "{message}");
    assert_eq!(p.import_prompts()[0].storage, StorageKind::Jks);

    // A certificate whose key is elsewhere.
    let other = tempfile::tempdir().unwrap();
    let (b, _) = basics(vec![import_step(other.path(), NEW_PASSWORD)]);
    let (code, message, _) = failure(&essentials(
        &b,
        "importCertificate",
        import_args(dir.path(), &[&cert]),
    ));
    assert_eq!(code, "KEYSTORE_FILE_NOT_FOUND");
    assert!(message.starts_with("[4105a0] "), "{message}");
}

#[test]
fn import_argument_errors() {
    let (dir, _, req) = generated(DEFAULT_PASSWORD);
    let cert = issue(&req, &[0x41, 0x06]);
    let cases = [
        (
            json!({"allowedStorage": "PKCS11"}),
            "INVOCATION_ERROR",
            "java.lang.NullPointerException: Unsupported storage: PKCS11",
        ),
        (
            json!({"certificates": ["not a certificate"]}),
            "INVALID_IMPORTING_CERTIFICATE",
            "",
        ),
        (
            json!({"certificates": [null]}),
            "INVALID_IMPORTING_CERTIFICATE",
            "",
        ),
        (
            json!({"certificates": "x"}),
            "INVOCATION_ERROR",
            "org.json.JSONException: JSONObject[\"certificates\"] is not a JSONArray.",
        ),
        // More certificates than a request may install (the original has no limit).
        (
            json!({"certificates": vec![cert_pem(&cert); MAX_CERTIFICATES_PER_REQUEST + 1]}),
            "INVOCATION_ERROR",
            "java.lang.IllegalArgumentException: too many certificates",
        ),
    ];
    for (patch, code, details) in cases {
        let mut args = import_args(dir.path(), &[&cert]);
        for (k, v) in patch.as_object().unwrap() {
            args[k] = v.clone();
        }
        let (b, p) = basics(vec![]);
        let (got_code, _, got_details) = failure(&essentials(&b, "importCertificate", args));
        assert_eq!((got_code.as_str(), got_details.as_str()), (code, details));
        assert!(p.import_prompts().is_empty());
    }
}

/// A request may install [`MAX_CERTIFICATES_PER_REQUEST`] certificates; one more is refused
/// before the dialog (above).
#[test]
fn at_most_sixteen_certificates_per_import() {
    assert_eq!(MAX_CERTIFICATES_PER_REQUEST, 16);
    let (dir, file, req) = generated(DEFAULT_PASSWORD);
    let before = read(&file);
    let cert = issue(&req, &[0x41, 0x09]);
    let certs = vec![&cert; MAX_CERTIFICATES_PER_REQUEST];
    let (b, p) = basics(vec![Step::CancelImport]);
    let r = essentials(&b, "importCertificate", import_args(dir.path(), &certs));
    assert_eq!(r, json!({"status": true, "body": {}}));
    assert_eq!(
        p.import_prompts()[0].certificates.len(),
        MAX_CERTIFICATES_PER_REQUEST
    );
    assert_eq!(read(&file), before);
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
/// [`THREAD_LOG`]. A process-wide subscriber: a scoped one (`with_default`) misses events
/// while other tests register the same callsites in parallel.
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
fn passwords_and_folders_stay_out_of_the_log() {
    const SECRET_DEFAULT: &str = "PageDefault987";
    capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (b, _) = basics(vec![csr_step(dir.path())]);
    let mut args = csr_args(json!([gost2015()]));
    args["defaultPassword"] = json!(SECRET_DEFAULT);
    let r = essentials(&b, "generateCsr", args);
    assert_eq!(r["status"], true, "{r}");
    let req = request(r["body"]["pems"][0].as_str().unwrap());
    let cert = issue(&req, &[0x41, 0x07]);
    let mut args = import_args(dir.path(), &[&cert]);
    args["defaultPassword"] = json!(SECRET_DEFAULT);
    let (b, _) = basics(vec![import_step(dir.path(), NEW_PASSWORD)]);
    let r = essentials(&b, "importCertificate", args);
    assert_eq!(r["status"], true, "{r}");

    let log = THREAD_LOG.with(|log| String::from_utf8(log.borrow().clone()).unwrap());
    assert!(log.contains("generateCsr"), "the flow logs: {log}");
    assert!(log.contains("importCertificate"), "the flow logs: {log}");
    for secret in [
        SECRET_DEFAULT.to_owned(),
        NEW_PASSWORD.to_owned(),
        dir.path().display().to_string(),
    ] {
        assert!(!log.contains(&secret), "{secret:?} in the log:\n{log}");
    }
}
