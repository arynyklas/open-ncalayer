//! The same requests to both implementations of a module: the same replies and the same
//! windows. RSA keys sign deterministically, so their signatures are compared byte for
//! byte; what is random by nature (generated keys, a TSA's nonce and signature) is
//! compared by its structure.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::{Decode, Encode};
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_builtin_tests::Backend;
use oncl_builtin_tests::basics::{Basics, MODULE_NAME};
use oncl_builtin_tests::commonutils::{CommonUtils, MODULE_NAME as CU_MODULE};
use oncl_pki::cms::{SignOptions, verify};
use oncl_pki::csr::KeyStoreInfo;
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::info::cert_info;
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_pki::keygen::MAX_KEYS_PER_REQUEST;
use oncl_pki::keystore::MAX_CERTIFICATES_PER_REQUEST;
use oncl_pki::oid;
use oncl_pki::pkcs12::{KeyEntry, WriteEntry, WriteOptions, load, write};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::{MockTsa, TsaProfile, verify_token_for};
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{fixture, read, synthetic};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::request::{CertReq, ExtensionReq};

const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const GOST2015: &str = "1.2.398.3.10.1.1.2.3.2";
const GOST2004: &str = "1.2.398.3.10.1.1.1.2";
const DEFAULT_PASSWORD: &str = "Default1";
const NEW_PASSWORD: &str = "NewSecret12";

/// The transport the module's TSA requests go to.
#[derive(Clone, Copy)]
enum Http {
    Tsa,
    Down,
}

/// A transport failing every request.
struct Down;

impl HttpTransport for Down {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("down"))
    }
}

/// One scenario: the answers, the requests (sent in order to one module), the module's
/// settings.
struct Case {
    steps: Vec<Step>,
    requests: Vec<(Value, AddInfo)>,
    recent: Option<PathBuf>,
    http: Http,
    tsa: Option<TsaProfile>,
    clock: fn() -> OffsetDateTime,
}

impl Case {
    fn new(steps: Vec<Step>, requests: Vec<Value>) -> Self {
        Case {
            steps,
            requests: requests.into_iter().map(|r| (r, origin("o"))).collect(),
            recent: None,
            http: Http::Tsa,
            tsa: None,
            clock: inside_user_validity,
        }
    }
}

/// What one implementation did: its replies, its windows and the key files left in the
/// case's folder.
#[derive(Debug, PartialEq)]
struct Run {
    replies: Vec<Value>,
    windows: String,
    files: Vec<String>,
    tsa_calls: usize,
}

fn origin(o: &str) -> AddInfo {
    AddInfo {
        origin: Some(o.to_owned()),
        ..AddInfo::default()
    }
}

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

/// A clock inside the validity of the synthetic user keys.
fn inside_user_validity() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| {
        let info = cert_info(&entry("user-rsa-sign").cert);
        info.not_before + (info.not_after - info.not_before) / 2
    });
    *AT
}

/// A clock inside the validity of `openssl/rsa.cer`.
fn inside_openssl_validity() -> OffsetDateTime {
    static AT: LazyLock<OffsetDateTime> = LazyLock::new(|| {
        let cert = oncl_pki::cert::parse(&read(fixture("openssl/rsa.cer"))).unwrap();
        let info = cert_info(&cert);
        info.not_before + (info.not_after - info.not_before) / 2
    });
    *AT
}

fn run(backend: Backend, case: Case, dir: &Path) -> Run {
    let prompter = Arc::new(ScriptedPrompter::new(case.steps));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let http: Arc<dyn HttpTransport> = match case.http {
        Http::Tsa => tsa.clone(),
        Http::Down => Arc::new(Down),
    };
    let mut basics = Basics::new(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(case.recent)),
        http,
    )
    .with_clock(case.clock)
    .with_backend(backend);
    if let Some(profile) = case.tsa {
        basics = basics.with_tsa(profile);
    }
    let replies = case
        .requests
        .iter()
        .map(|(request, add_info)| {
            let text = match request {
                Value::String(raw) => raw.clone(),
                other => other.to_string(),
            };
            let reply = basics.process(&text, add_info);
            let reply: Value = serde_json::from_str(reply.text().unwrap()).unwrap();
            normalized(reply, dir)
        })
        .collect();
    let p = &prompter;
    let windows = format!(
        "{:#?}",
        (
            p.timeline(),
            p.storage_prompts(),
            p.busy_prompts(),
            p.opened_key_prompts(),
            p.key_prompts(),
            p.csr_prompts(),
            p.import_prompts(),
            p.file_prompts(),
            p.password_prompts(),
            p.message_prompts(),
            p.reader_prompts(),
        )
    );
    let mut files: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            // Generated key files are named after their (random) key.
            match name.rsplit_once('_') {
                Some((prefix, _)) => format!("{prefix}_<key>"),
                None => name,
            }
        })
        .collect();
    files.sort();
    Run {
        replies,
        windows: without_dir(&windows, dir),
        files,
        tsa_calls: tsa.calls().len(),
    }
}

/// `text` with `dir` (as displayed or escaped) replaced by `<dir>`.
fn without_dir(text: &str, dir: &Path) -> String {
    let shown = dir.display().to_string();
    let escaped = shown.replace('\\', "\\\\");
    text.replace(&escaped, "<dir>").replace(&shown, "<dir>")
}

/// The reply with the case's folder and the random parts of its results replaced by what
/// they must be: generated requests by their contents without the key, time-stamped CMS
/// by their signers and verified tokens.
fn normalized(reply: Value, dir: &Path) -> Value {
    match reply {
        Value::String(s) if s.starts_with("-----BEGIN CERTIFICATE REQUEST-----") => {
            Value::String(request_summary(&s, dir))
        }
        Value::String(s) if s.starts_with("-----BEGIN CMS-----") => Value::String(cms_summary(&s)),
        Value::String(s) => Value::String(without_dir(&s, dir)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|v| normalized(v, dir)).collect())
        }
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, normalized(v, dir)))
                .collect(),
        ),
        other => other,
    }
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    STANDARD.decode(body).unwrap()
}

fn request_extensions(req: &CertReq) -> Vec<Extension> {
    req.info
        .attributes
        .iter()
        .flat_map(|a| a.values.iter())
        .flat_map(|v| ExtensionReq::from_der(&v.to_der().unwrap()).unwrap().0)
        .collect()
}

/// A request's subject, algorithm and extensions (KeyStoreInfo decoded), its signature
/// checked with its key.
fn request_summary(pem: &str, dir: &Path) -> String {
    let req = CertReq::from_der(&pem_to_der(pem)).unwrap();
    let public = PublicKey::from_spki(&req.info.public_key).unwrap();
    let alg = [SigAlg::Gost2015_512, SigAlg::Gost2004, SigAlg::RsaSha256]
        .into_iter()
        .find(|a| a.signature_oid() == req.algorithm.oid)
        .unwrap();
    public
        .verify(
            alg,
            &req.info.to_der().unwrap(),
            req.signature.as_bytes().unwrap(),
        )
        .unwrap();
    let extensions: Vec<String> = request_extensions(&req)
        .iter()
        .map(|e| {
            if e.extn_id == oid::KEYSTORE_INFO {
                let info = KeyStoreInfo::from_der(e.extn_value.as_bytes()).unwrap();
                let path = info.path.as_deref().map(|p| without_dir(p, dir));
                format!("{} {} {path:?}", e.extn_id, info.storage_oid)
            } else {
                format!(
                    "{} {} {:02x?}",
                    e.extn_id,
                    e.critical,
                    e.extn_value.as_bytes()
                )
            }
        })
        .collect();
    format!(
        "CSR {:?} {} {:02x?} {extensions:?}",
        req.info.version,
        req.algorithm.oid,
        req.info.subject.to_der().unwrap()
    )
}

/// A CMS as-is unless it carries a time-stamp; then its signers with their verified
/// tokens' policy, imprint and TSA, the token's own signature and nonce left out.
fn cms_summary(pem: &str) -> String {
    let der = pem_to_der(pem);
    let signers = match verify(&der, None) {
        Ok(signers) => signers,
        Err(_) => return pem.to_owned(),
    };
    if signers.iter().all(|s| s.timestamp_token.is_none()) {
        return pem.to_owned();
    }
    let signers: Vec<String> = signers
        .iter()
        .map(|s| {
            let token = s.timestamp_token.as_ref().map(|t| {
                let (tst, tsa) = verify_token_for(t, &s.signature).unwrap();
                (
                    tst.policy,
                    tst.imprint_alg,
                    tst.imprint,
                    tsa.to_der().unwrap(),
                )
            });
            format!(
                "{:02x?} {:?} {:?} {:02x?} {token:02x?}",
                s.cert.to_der().unwrap(),
                s.sig_alg,
                s.signing_time,
                s.signature
            )
        })
        .collect();
    format!("time-stamped CMS {signers:?}")
}

/// Runs `case(dir)` on both implementations, each in a fresh folder prepared by `prepare`.
fn same_with(prepare: impl Fn(&Path), case: impl Fn(&Path) -> Case) {
    let wasm_dir = tempfile::tempdir().unwrap();
    let native_dir = tempfile::tempdir().unwrap();
    prepare(wasm_dir.path());
    prepare(native_dir.path());
    let wasm = run(Backend::Wasm, case(wasm_dir.path()), wasm_dir.path());
    let native = run(Backend::Native, case(native_dir.path()), native_dir.path());
    assert_eq!(wasm, native);
}

fn same(case: impl Fn(&Path) -> Case) {
    same_with(|_| {}, case);
}

fn storage(name: &str, password: &str) -> Step {
    storage_at(synthetic(name).path, password)
}

fn storage_at(path: impl Into<PathBuf>, password: &str) -> Step {
    Step::Storage {
        path: path.into(),
        password: password.to_owned(),
    }
}

fn rsa() -> Vec<Step> {
    vec![storage("user-rsa-sign", "Qwerty12"), Step::Key(0)]
}

fn sign(args: Value) -> Value {
    json!({"module": MODULE_NAME, "method": "sign", "args": args})
}

fn with_format(format: &str, data: Value, signing_params: Value) -> Value {
    sign(json!({
        "format": format,
        "data": data,
        "signingParams": signing_params,
        "signerParams": {"extKeyUsageOids": [], "chain": []},
    }))
}

fn cms(data: Value, signing_params: Value) -> Value {
    with_format("cms", data, signing_params)
}

fn raw(data: Value, signing_params: Value) -> Value {
    with_format("raw", data, signing_params)
}

fn xml(data: Value, signing_params: Value) -> Value {
    with_format("xml", data, signing_params)
}

fn raw_args() -> Value {
    json!({
        "format": "raw",
        "data": "x",
        "signingParams": {},
        "signerParams": {"extKeyUsageOids": [], "chain": []},
    })
}

/// A CMS of `doc` by the synthetic RSA key at the fixed time.
fn rsa_cms(doc: &[u8], encapsulate: bool) -> String {
    STANDARD.encode(
        oncl_pki::cms::sign(
            &entry("user-rsa-sign"),
            doc,
            &SignOptions {
                encapsulate,
                digested: false,
                signing_time: inside_user_validity(),
            },
        )
        .unwrap(),
    )
}

#[test]
fn basics_cms() {
    let hash = STANDARD.encode(SigAlg::RsaSha256.digest(b"doc"));
    for (request, signing) in [
        (cms(json!("aGVsbG8="), json!({"decode": true})), true),
        (cms(json!("привет"), json!({"encapsulate": false})), true),
        (
            cms(
                json!(hash),
                json!({"decode": true, "digested": true, "encapsulate": false}),
            ),
            true,
        ),
        (cms(json!(["YQ==", "Yg=="]), json!({"decode": true})), true),
        (
            cms(json!(rsa_cms(b"doc", true)), json!({"decode": true})),
            true,
        ),
        (
            cms(json!(rsa_cms(b"doc", false)), json!({"decode": true})),
            true,
        ),
        (cms(json!("x"), json!({"allowExpired": true})), true),
        (cms(json!("x"), json!({})), false),
    ] {
        let steps = if signing {
            rsa()
        } else {
            vec![Step::CancelStorage]
        };
        same(|_| Case::new(steps.clone(), vec![request.clone()]));
    }
    // JKS keys.
    same(|_| {
        let mut case = Case::new(
            vec![
                Step::Jks {
                    path: fixture("jks/rsa.jks"),
                    password: "Qwerty12".to_owned(),
                },
                Step::Key(0),
            ],
            vec![cms(json!("aGVsbG8="), json!({"decode": true}))],
        );
        case.clock = inside_openssl_validity;
        case
    });
}

#[test]
fn basics_time_stamps() {
    // A new signature and a co-signature, time-stamped by the basics profile.
    for data in [json!("aGVsbG8="), json!(rsa_cms(b"doc", true))] {
        same(|_| {
            Case::new(
                rsa(),
                vec![cms(data.clone(), json!({"decode": true, "tsaProfile": {}}))],
            )
        });
    }
    // Another profile.
    same(|_| {
        let mut profile = TsaProfile::basics_default();
        profile.url = "http://tsa.test/x".to_owned();
        let mut case = Case::new(
            rsa(),
            vec![cms(
                json!("x"),
                json!({"tsaProfile": {"url": "http://ignored"}}),
            )],
        );
        case.tsa = Some(profile);
        case
    });
    // The TSA is down.
    same(|_| {
        let mut case = Case::new(rsa(), vec![cms(json!("x"), json!({"tsaProfile": {}}))]);
        case.http = Http::Down;
        case
    });
}

#[test]
fn basics_raw_and_xml() {
    for request in [
        raw(json!("aGVsbG8="), json!({"decode": true})),
        raw(json!(["a"]), json!({})),
        raw(json!(["a", "b"]), json!({})),
        raw(json!("a"), json!({"outputCert": true})),
        raw(json!("hello"), json!({})),
        xml(
            json!(["<a>1</a>", "<b xmlns=\"urn:x\"><c/></b>"]),
            json!({}),
        ),
        xml(
            json!("<?xml version=\"1.0\"?>\n<!-- c --><?pi x?>\n<a>1</a>"),
            json!({}),
        ),
        xml(json!("PGEvPg=="), json!({"decode": true})),
        xml(json!(["<a/>", "<b>"]), json!({})),
        sign(json!({
            "data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><login><client-type>PORTAL</client-type></login>",
            "allowedStorages": ["PKCS12", "AKKaztokenStore", "AKKZIDCardStore"],
            "format": "xml",
            "signingParams": {},
            "signerParams": {"extKeyUsageOids": [CLIENT_AUTH], "chain": []},
            "locale": "ru",
        })),
    ] {
        same(|_| Case::new(rsa(), vec![request.clone()]));
    }
    for bad in ["<a>", "not xml", "<!DOCTYPE a><a/>", "<a/><b/>"] {
        same(|_| Case::new(rsa(), vec![xml(json!(bad), json!({}))]));
    }
}

/// A PKCS#12 file (`Qwerty12`) in `dir` with the OpenSSL RSA key under its certificate
/// whose signature algorithm is patched to 1.2.840.113549.1.1.`last`.
fn rsa_store_with_signature_oid(dir: &Path, last: u8) -> PathBuf {
    const SHA256_RSA: [u8; 11] = [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 0x0b];
    let mut cert = read(fixture("openssl/rsa.cer"));
    for i in 0..=cert.len() - SHA256_RSA.len() {
        if cert[i..i + SHA256_RSA.len()] == SHA256_RSA {
            cert[i + SHA256_RSA.len() - 1] = last;
        }
    }
    let p12 = write(
        &[WriteEntry {
            alias: "rsa".to_owned(),
            pkcs8_der: read(fixture("openssl/rsa.pk8.der")),
            cert_der: Some(cert),
        }],
        &[],
        "Qwerty12",
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(7),
    )
    .unwrap();
    let path = dir.join(format!("rsa-oid-{last}.p12"));
    fs::write(&path, p12).unwrap();
    path
}

#[test]
fn basics_certificate_algorithms() {
    for (last, request) in [
        (5, cms(json!("x"), json!({}))),
        (5, xml(json!("<a/>"), json!({}))),
        (13, xml(json!("<a/>"), json!({}))),
        (13, xml(json!("<a>"), json!({}))),
    ] {
        same_with(
            |dir| {
                rsa_store_with_signature_oid(dir, last);
            },
            |dir| {
                let mut case = Case::new(
                    vec![
                        storage_at(dir.join(format!("rsa-oid-{last}.p12")), "Qwerty12"),
                        Step::Key(0),
                    ],
                    vec![request.clone()],
                );
                case.clock = inside_openssl_validity;
                case
            },
        );
    }
}

#[test]
fn basics_dialogs() {
    let cases: Vec<(Vec<Step>, Value)> = vec![
        (vec![Step::CancelStorage], cms(json!("x"), json!({}))),
        (
            vec![storage("user-gost2015-sign", "Qwerty12"), Step::CancelKey],
            cms(json!("x"), json!({})),
        ),
        (vec![], raw(json!("x"), json!({}))),
        (
            vec![
                storage("user-rsa-sign", "bad"),
                storage("user-rsa-sign", "Qwerty12"),
                Step::Key(0),
            ],
            cms(json!("x"), json!({})),
        ),
        (
            vec![
                storage_at(
                    synthetic("user-gost2015-sign")
                        .path
                        .with_extension("missing"),
                    "Qwerty12",
                ),
                storage_at(fixture("synthetic/root-gost2015.cer"), "Qwerty12"),
            ],
            cms(json!("x"), json!({})),
        ),
        (
            vec![
                storage("expired-gost2015-sign", "Qwerty12"),
                Step::Key(0),
                Step::Key(0),
            ],
            cms(json!("x"), json!({})),
        ),
        (
            vec![
                storage("user-rsa-sign", "Qwerty12"),
                Step::Key(5),
                Step::Key(0),
            ],
            raw(json!("x"), json!({})),
        ),
        (
            vec![
                storage("inter-expired-gost2015-sign", "Qwerty12"),
                Step::Key(0),
            ],
            xml(json!("<a/>"), json!({})),
        ),
        (
            vec![
                storage("inter-expired-gost2015-sign", "Qwerty12"),
                Step::CancelKey,
            ],
            xml(json!("<a/>"), json!({"allowExpired": true})),
        ),
    ];
    for (steps, request) in cases {
        same(|_| Case::new(steps.clone(), vec![request.clone()]));
    }
    // A key store without keys.
    same_with(
        |dir| {
            let p12 = write(
                &[],
                &[],
                "Qwerty12",
                &WriteOptions::default(),
                &mut |buf: &mut [u8]| buf.fill(3),
            )
            .unwrap();
            fs::write(dir.join("keyless.p12"), p12).unwrap();
        },
        |dir| {
            Case::new(
                vec![
                    storage_at(dir.join("keyless.p12"), "Qwerty12"),
                    storage("user-rsa-sign", "Qwerty12"),
                    Step::Key(0),
                ],
                vec![raw(json!("x"), json!({}))],
            )
        },
    );
    // Storages offered, the recent path, origin and locale.
    let recent = PathBuf::from("C:/keys/old.p12");
    for allowed in [
        Some(json!(["PKCS12", "FOO", "pkcs12", null, "JKS", "PKCS12"])),
        None,
        Some(Value::Null),
        Some(json!([])),
        Some(json!(["AKKaztokenStore", "PKCS12"])),
    ] {
        let mut args = raw_args();
        if let Some(allowed) = allowed {
            args["allowedStorages"] = allowed;
        }
        args["locale"] = json!("ru");
        same(|_| {
            let mut case = Case::new(vec![Step::CancelStorage], vec![]);
            case.requests = vec![(sign(args.clone()), AddInfo::default())];
            case.recent = Some(recent.clone());
            case
        });
    }
    same(|_| {
        let mut args = raw_args();
        args["allowedStorages"] = json!(["AKKaztokenStore", "PKCS12"]);
        let mut case = Case::new(rsa(), vec![sign(args.clone())]);
        case.recent = Some(recent.clone());
        case
    });
}

#[test]
fn basics_key_filters() {
    let legal_serial = cert_info(&entry("legal-gost2015-sign").cert)
        .serial_hex
        .to_uppercase();
    for (store, signer_params) in [
        (
            "multi-gost2015",
            json!({"extKeyUsageOids": [CLIENT_AUTH], "chain": []}),
        ),
        (
            "multi-gost2015",
            json!({"extKeyUsageOids": [], "iin": "999999999999", "chain": []}),
        ),
        (
            "legal-gost2015-sign",
            json!({"extKeyUsageOids": [], "iin": "123456789022", "bin": "123456789021",
                   "serialNumber": legal_serial, "chain": []}),
        ),
        (
            "user-gost2015-sign",
            json!({"extKeyUsageOids": [CLIENT_AUTH], "iin": "1", "bin": "2",
                   "serialNumber": "3", "chain": []}),
        ),
    ] {
        let request = sign(json!({
            "format": "raw",
            "data": "x",
            "signingParams": {},
            "signerParams": signer_params,
        }));
        same(|_| {
            Case::new(
                vec![storage(store, "Qwerty12"), Step::CancelKey],
                vec![request.clone()],
            )
        });
    }
}

#[test]
fn basics_argument_errors() {
    let mut requests = vec![
        sign(json!({"data":"x","signingParams":{},"signerParams":{"extKeyUsageOids":[]}})),
        sign(json!({"format":"cms","data":"x","signerParams":{"extKeyUsageOids":[]}})),
        sign(json!({"format":"cms","signingParams":{},"signerParams":{"extKeyUsageOids":[]}})),
        sign(json!({"format":"raw","data":"x","signingParams":{}})),
        sign(json!({"format":"raw","data":"x","signingParams":{},"signerParams":{}})),
        sign(
            json!({"format":"cms","data":"не base64","signingParams":{"decode":true},"signerParams":{"extKeyUsageOids":[]}}),
        ),
        raw(json!(["YQ==", "YQ= ="]), json!({"decode": true})),
        sign(
            json!({"format": 1, "data": "x", "signingParams": {}, "signerParams": {"extKeyUsageOids": []}}),
        ),
        raw(json!(["a", 1]), json!({})),
        json!({"module": MODULE_NAME, "method": "sign"}),
        json!({"module": MODULE_NAME, "method": "sign", "args": ["x"]}),
        json!({"module": MODULE_NAME, "class": "PKIExtras", "method": "sign", "args": null}),
        json!({"module": MODULE_NAME, "class": "PKIEssentials", "method": "sign", "args": {}}),
        json!({"module": MODULE_NAME, "method": "generateCsr", "args": {}}),
        json!({"module": MODULE_NAME, "class": "PKIExtras", "method": "importCertificate", "args": {}}),
        json!({"module": MODULE_NAME, "method": "nope", "args": {}}),
        json!({"module": MODULE_NAME}),
        json!("not json"),
        json!("[1]"),
    ];
    for format in ["XML", "CMS", ""] {
        requests.push(sign(
            json!({"format":format,"data":"x","signingParams":{},"signerParams":{"extKeyUsageOids":[]}}),
        ));
    }
    for bad in ["YQ=", "YQ==\n", " YQ==", "Y", "YQ===", "YQ-_"] {
        requests.push(raw(json!(bad), json!({"decode": true})));
    }
    for (key, value) in [
        ("allowedStorages", json!(["PKCS12", 5])),
        ("allowedStorages", json!([1.5])),
        ("allowedStorages", json!("PKCS12")),
    ] {
        let mut args = raw_args();
        args[key] = value;
        requests.push(sign(args));
    }
    let mut args = raw_args();
    args["signerParams"]["extKeyUsageOids"] = json!([null]);
    requests.push(sign(args));
    // Accepted base64: the dialog opens (and is cancelled).
    for ok in ["YQ", "YQ==", "aGVsbG8"] {
        requests.push(raw(json!(ok), json!({"decode": true})));
    }
    same(|_| Case::new(vec![], requests.clone()));
}

fn essentials(method: &str, args: Value) -> Value {
    json!({"module": MODULE_NAME, "class": "PKIEssentials", "method": method, "args": args})
}

fn csr_args(params: Value) -> Value {
    json!({
        "allowedStorages": ["PKCS12", "AKKaztokenStore"],
        "defaultPassword": DEFAULT_PASSWORD,
        "dn": {"2.5.4.3": "ТЕСТОВ ТЕСТ", "2.5.4.5": "IIN123456789012", "2.5.4.6": "KZ"},
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

#[test]
fn basics_generate_csr() {
    same(|dir| {
        Case::new(
            vec![csr_step(dir)],
            vec![essentials(
                "generateCsr",
                csr_args(json!([
                    gost2015(),
                    {"algorithm": GOST2004, "length": 256},
                    {"algorithm": "1.2.840.113549.1.1.11", "length": 2048},
                ])),
            )],
        )
    });
    same(|_| {
        Case::new(
            vec![Step::CancelCsr],
            vec![essentials("generateCsr", csr_args(json!([gost2015()])))],
        )
    });
    for answer in ["", "relative-keys", "<dir>/missing"] {
        same(|dir| {
            let answer = PathBuf::from(answer.replace("<dir>", &dir.display().to_string()));
            Case::new(
                vec![csr_step(&answer)],
                vec![essentials("generateCsr", csr_args(json!([gost2015()])))],
            )
        });
    }
    assert!(!Path::new("relative-keys").exists());
    // The page names a storage the dialog's answer is not.
    same(|dir| {
        let mut args = csr_args(json!([gost2015()]));
        args["allowedStorages"] = json!(["AKKaztokenStore"]);
        Case::new(vec![csr_step(dir)], vec![essentials("generateCsr", args)])
    });
    // Alternative names.
    same(|dir| {
        let mut args = csr_args(json!([gost2015()]));
        args["dn"] = json!({"2.5.4.3": "test.kz"});
        args["subjectAltNames"] =
            json!(["b.test.kz", "test.kz", "b.test.kz", "a.test.kz", "test.kz"]);
        Case::new(vec![csr_step(dir)], vec![essentials("generateCsr", args)])
    });
    // The password typed in the dialog.
    same(|dir| {
        let mut args = csr_args(json!([gost2015()]));
        args.as_object_mut().unwrap().remove("defaultPassword");
        Case::new(
            vec![Step::Csr {
                dir: dir.to_path_buf(),
                password: "Typed123".to_owned(),
            }],
            vec![essentials("generateCsr", args)],
        )
    });
}

#[test]
fn basics_csr_argument_errors() {
    let mut requests = Vec::new();
    for method in ["generateCsr", "importCertificate"] {
        requests.push(
            json!({"module": MODULE_NAME, "method": method, "args": csr_args(json!([gost2015()]))}),
        );
        requests.push(essentials(method, Value::Null));
    }
    for patch in [
        json!({"-allowedStorages": null}),
        json!({"allowedStorages": null}),
        json!({"allowedStorages": "PKCS12"}),
        json!({"-dn": null}),
        json!({"dn": {"2.5.4.3": null}}),
        json!({"dn": {"CN": "x"}}),
        json!({"params": null}),
        json!({"params": [{"algorithm": "1.2.840.113549.1.1.5", "length": 2048}]}),
        json!({"params": [{"algorithm": GOST2015}]}),
        json!({"omittedKeyIds": ["a", 1]}),
        json!({"params": vec![gost2015(); MAX_KEYS_PER_REQUEST + 1]}),
        json!({"dn": {"2.5.4.3": "ТЕСТОВ ТЕСТ"}, "subjectAltNames": ["test.kz"]}),
        json!({"dn": {"2.5.4.5": "IIN123456789012"}, "subjectAltNames": ["test.kz"]}),
    ] {
        let mut args = csr_args(json!([gost2015()]));
        for (k, v) in patch.as_object().unwrap() {
            match k.strip_prefix('-') {
                Some(absent) => {
                    args.as_object_mut().unwrap().remove(absent);
                }
                None => args[k] = v.clone(),
            }
        }
        requests.push(essentials("generateCsr", args));
    }
    same(|_| Case::new(vec![], requests.clone()));
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
        extn_value: der::asn1::OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

/// A certificate on `req` issued by the synthetic key `issuer`, as the NCA issues one.
fn issue_by(
    issuer: &str,
    req: &CertReq,
    serial: &[u8],
    eku: &[der::asn1::ObjectIdentifier],
) -> Certificate {
    use der::oid::AssociatedOid;
    let issuer = entry(issuer);
    let public = PublicKey::from_spki(&req.info.public_key).unwrap();
    let ski = SubjectKeyIdentifier(
        der::asn1::OctetString::new(hex_decode(&oncl_pki::keygen::key_id(&public))).unwrap(),
    );
    let usages = if eku.is_empty() {
        KeyUsages::DigitalSignature | KeyUsages::NonRepudiation
    } else {
        KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment
    };
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

/// Key files generated once (their names and contents) and the certificates issued on
/// them: an RSA authentication key's and a GOST 2015 signing key's.
type Generated = (Vec<(String, Vec<u8>)>, [Certificate; 2]);

/// The [`Generated`] key files and certificates of the import cases.
fn generated() -> &'static Generated {
    static GENERATED: LazyLock<Generated> = LazyLock::new(|| {
        let dir = tempfile::tempdir().unwrap();
        let basics = Basics::new(
            Arc::new(ScriptedPrompter::new(vec![csr_step(dir.path())])),
            Arc::new(MemoryRecentPath::new(None)),
            Arc::new(MockTsa::new(entry("tsa-gost2015"))),
        )
        .with_backend(Backend::Native);
        let request = essentials(
            "generateCsr",
            csr_args(json!([
                {"algorithm": "1.2.840.113549.1.1.11", "length": 2048},
                gost2015(),
            ])),
        );
        let reply = basics.process(&request.to_string(), &origin("o"));
        let reply: Value = serde_json::from_str(reply.text().unwrap()).unwrap();
        let pems = reply["body"]["pems"].as_array().unwrap();
        let req = |i: usize| CertReq::from_der(&pem_to_der(pems[i].as_str().unwrap())).unwrap();
        let auth = issue_by(
            "user-rsa-sign",
            &req(0),
            &[0x41, 0x07, 0x01],
            &[oid::CLIENT_AUTH],
        );
        let sign = issue_by("user-gost2015-sign", &req(1), &[0x41, 0x07, 0x02], &[]);
        let files = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        (files, [auth, sign])
    });
    &GENERATED
}

fn copy_generated(dir: &Path) {
    for (name, contents) in &generated().0 {
        fs::write(dir.join(name), contents).unwrap();
    }
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
fn basics_import_certificate() {
    let [auth, sign_cert] = &generated().1;
    // Both certificates, one of them only, cancelled, the page's folder refused.
    for certs in [vec![auth, sign_cert], vec![sign_cert]] {
        same_with(copy_generated, |dir| {
            Case::new(
                vec![import_step(dir, NEW_PASSWORD)],
                vec![essentials("importCertificate", import_args(dir, &certs))],
            )
        });
    }
    same_with(copy_generated, |dir| {
        Case::new(
            vec![Step::CancelImport],
            vec![essentials(
                "importCertificate",
                import_args(dir, &[sign_cert; MAX_CERTIFICATES_PER_REQUEST]),
            )],
        )
    });
    for path in ["//host/share", "//host/share/keys", ""] {
        same_with(copy_generated, |dir| {
            let mut args = import_args(dir, &[sign_cert]);
            args["keystorePath"] = json!(path);
            Case::new(
                vec![Step::CancelImport],
                vec![essentials("importCertificate", args)],
            )
        });
    }
    // Wrong new passwords, the page's password, JKS, a folder without the key.
    for password in ["sh1", "NoDigitsHere", "пароль123", ""] {
        same_with(copy_generated, |dir| {
            Case::new(
                vec![import_step(dir, password)],
                vec![essentials(
                    "importCertificate",
                    import_args(dir, &[sign_cert]),
                )],
            )
        });
    }
    for (key, value) in [
        ("defaultPassword", json!("Other123")),
        ("allowedStorage", json!("JKS")),
    ] {
        same_with(copy_generated, |dir| {
            let mut args = import_args(dir, &[sign_cert]);
            args[key] = value.clone();
            Case::new(
                vec![import_step(dir, NEW_PASSWORD)],
                vec![essentials("importCertificate", args)],
            )
        });
    }
    same_with(copy_generated, |dir| {
        let empty = dir.join("empty");
        fs::create_dir_all(&empty).unwrap();
        Case::new(
            vec![import_step(&empty, NEW_PASSWORD)],
            vec![essentials(
                "importCertificate",
                import_args(dir, &[sign_cert]),
            )],
        )
    });
    // Argument errors, before the dialog.
    for (key, value) in [
        ("allowedStorage", json!("PKCS11")),
        ("certificates", json!(["not a certificate"])),
        ("certificates", json!([null])),
        ("certificates", json!("x")),
        (
            "certificates",
            json!(vec![cert_pem(sign_cert); MAX_CERTIFICATES_PER_REQUEST + 1]),
        ),
    ] {
        same_with(copy_generated, |dir| {
            let mut args = import_args(dir, &[sign_cert]);
            args[key] = value.clone();
            Case::new(vec![], vec![essentials("importCertificate", args)])
        });
    }
}

// kz.gov.pki.knca.commonUtils

/// The synthetic roots and intermediate CA, standing in for the NCA CAs.
fn synthetic_cas() -> oncl_pki::pkix::CaSet {
    oncl_pki::pkix::CaSet::new(
        [
            "root-gost2015",
            "root-gost2004",
            "root-rsa",
            "inter-gost2015",
        ]
        .into_iter()
        .map(|name| oncl_pki::cert::parse(&oncl_testkit::synthetic_cert(name)).unwrap())
        .collect(),
    )
}

/// A base64 CMS with a time-stamp by its signers and verified tokens; anything else as is.
fn cu_normalized(reply: Value, dir: &Path) -> Value {
    match reply {
        Value::String(s) => match STANDARD.decode(&s) {
            Ok(der) if verify(&der, None).is_ok() => Value::String(cms_summary(&s)),
            _ => Value::String(without_dir(&s, dir)),
        },
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, cu_normalized(v, dir)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|v| cu_normalized(v, dir)).collect())
        }
        other => other,
    }
}

/// `requests` (with their sessions) to the commonUtils module of `backend`.
fn cu_run(backend: Backend, steps: Vec<Step>, requests: &[(Value, AddInfo)], dir: &Path) -> Run {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let cu = CommonUtils::new(prompter.clone(), tsa.clone())
        .with_cas(synthetic_cas())
        .with_clock(inside_user_validity)
        .with_backend(backend);
    let replies = requests
        .iter()
        .map(|(request, add_info)| {
            let reply = cu.process(&request.to_string(), add_info);
            cu_normalized(serde_json::from_str(reply.text().unwrap()).unwrap(), dir)
        })
        .collect();
    let p = &prompter;
    let windows = format!(
        "{:#?}",
        (
            p.timeline(),
            p.storage_prompts(),
            p.busy_prompts(),
            p.opened_key_prompts(),
            p.key_prompts(),
            p.file_prompts(),
            p.reader_prompts(),
        )
    );
    Run {
        replies,
        windows: without_dir(&windows, dir),
        files: Vec::new(),
        tsa_calls: tsa.calls().len(),
    }
}

/// Runs the commonUtils `case(dir)` on both implementations, each in a fresh folder with a
/// file `doc.txt` and a detached CMS `detached.p7s`.
fn cu_same(case: impl Fn(&Path) -> (Vec<Step>, Vec<Value>)) {
    let run = |backend| {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("doc.txt"), b"doc").unwrap();
        fs::write(
            dir.path().join("detached.p7s"),
            STANDARD.decode(rsa_cms(b"doc", false)).unwrap(),
        )
        .unwrap();
        let (steps, requests) = case(dir.path());
        let requests: Vec<_> = requests.into_iter().map(|r| (r, origin("o"))).collect();
        cu_run(backend, steps, &requests, dir.path())
    };
    assert_eq!(run(Backend::Wasm), run(Backend::Native));
}

fn cu(method: &str, args: Value) -> Value {
    json!({"module": CU_MODULE, "method": method, "args": args, "uuid": "u-1"})
}

#[test]
fn commonutils_signing() {
    let doc = STANDARD.encode(b"doc");
    let hash = STANDARD.encode(SigAlg::RsaSha256.digest(b"doc"));
    let attached = rsa_cms(b"doc", true);
    let detached = rsa_cms(b"doc", false);
    for (method, args) in [
        ("getKeyInfo", json!(["PKCS12"])),
        (
            "signXml",
            json!(["PKCS12", "SIGNATURE", "<a><b Id=\"x\">1</b></a>", "", ""]),
        ),
        (
            "signXml",
            json!(["PKCS12", "", "<a><b Id=\"x\">1</b></a>", "//b", ""]),
        ),
        (
            "signXml",
            json!(["PKCS12", "", "<a><b Id=\"x\">1</b></a>", "/a/b", "/A/B"]),
        ),
        ("signXml", json!(["PKCS12", "", "<a>", "", ""])),
        (
            "signXmls",
            json!(["PKCS12", "SIGNATURE", ["<a/>", "<b/>"], "", ""]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "SIGNATURE", doc, true]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "SIGNATURE", doc, false]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "", attached, true]),
        ),
        (
            "createCAdESFromBase64",
            json!(["PKCS12", "", detached, true]),
        ),
        ("createCAdESFromBase64", json!(["PKCS12", "", "!!", true])),
        (
            "createCAdESFromBase64Hash",
            json!(["PKCS12", "SIGNATURE", hash]),
        ),
        (
            "createCMSSignatureFromBase64",
            json!(["PKCS12", "SIGNATURE", doc, true]),
        ),
        ("applyCAdEST", json!(["PKCS12", "SIGNATURE", attached])),
        (
            "applyCAdEST",
            json!(["PKCS12", "SIGNATURE", rsa_cms(b"x", true)]),
        ),
        ("applyCAdEST", json!(["PKCS12", "SIGNATURE", "AAAA"])),
    ] {
        cu_same(|_| (rsa(), vec![cu(method, args.clone())]));
    }
    for method in ["createCAdESFromFile", "createCMSSignatureFromFile"] {
        for file in ["doc.txt", "detached.p7s", "missing.txt"] {
            cu_same(|dir| {
                let path = dir.join(file).display().to_string();
                (rsa(), vec![cu(method, json!(["PKCS12", "", path, true]))])
            });
        }
    }
}

#[test]
fn commonutils_dialogs_and_errors() {
    let doc = STANDARD.encode(b"doc");
    let cases: Vec<(Vec<Step>, Value)> = vec![
        (
            vec![Step::CancelStorage],
            cu("getKeyInfo", json!(["PKCS12"])),
        ),
        (
            vec![storage("user-rsa-sign", "Qwerty12"), Step::CancelKey],
            cu("getKeyInfo", json!(["PKCS12"])),
        ),
        (
            vec![
                storage("user-rsa-sign", "bad"),
                storage("user-rsa-sign", "Qwerty12"),
                Step::Key(0),
            ],
            cu("createCAdESFromBase64", json!(["PKCS12", "", doc, true])),
        ),
        (
            vec![
                Step::Jks {
                    path: fixture("jks/rsa.jks"),
                    password: "Qwerty12".to_owned(),
                },
                Step::Key(0),
            ],
            cu("getKeyInfo", json!(["JKS"])),
        ),
        (
            vec![
                Step::Jks {
                    path: fixture("jks/rsa.jks"),
                    password: "Qwerty12".to_owned(),
                },
                Step::Key(0),
            ],
            cu("createCAdESFromBase64", json!(["JKS", "", doc, true])),
        ),
        (
            vec![storage("user-rsa-sign", "Qwerty12"), Step::CancelStorage],
            cu(
                "signXml",
                json!(["PKCS12", "AUTHENTICATION", "<a/>", "", ""]),
            ),
        ),
        (Vec::new(), cu("getKeyInfo", json!([" "]))),
        (Vec::new(), cu("getKeyInfo", json!(["pkcs12"]))),
        (Vec::new(), cu("getKeyInfo", json!(["AKKaztokenStore"]))),
        (Vec::new(), cu("getKeyInfo", json!([5]))),
        (Vec::new(), cu("getKeyInfo", json!([]))),
        (Vec::new(), cu("saveKey", json!(["a", "b"]))),
        (Vec::new(), cu("getJson", json!([[1, "x"]]))),
        (Vec::new(), cu("setKeyInfoServices", json!(["a"]))),
        (
            Vec::new(),
            cu("signXmls", json!(["PKCS12", "", [1], "", ""])),
        ),
        (Vec::new(), cu("getActiveTokens", json!([]))),
        (Vec::new(), json!({"method": 5})),
        (Vec::new(), json!([1])),
        (Vec::new(), cu("showFileChooser", json!(["NOPE", ""]))),
        (
            vec![Step::CancelFile],
            cu("showFileChooser", json!(["P12", ""])),
        ),
        (
            vec![Step::CancelFile],
            cu("showFileChooser", json!(["", "/nowhere"])),
        ),
    ];
    for (steps, request) in cases {
        cu_same(|_| (steps.clone(), vec![request.clone()]));
    }
    cu_same(|dir| {
        (
            vec![Step::File(dir.join("doc.txt"))],
            vec![cu(
                "showFileChooser",
                json!(["ALL", dir.display().to_string()]),
            )],
        )
    });
}

#[test]
fn commonutils_locale() {
    for language in ["kk", "en", "ru", "", "de"] {
        cu_same(|dir| {
            let path = dir.join("doc.txt").display().to_string();
            (
                vec![Step::CancelStorage, Step::CancelFile],
                vec![
                    cu("changeLocale", json!([language])),
                    cu("createCAdESFromFile", json!(["PKCS12", "", path, true])),
                    cu("showFileChooser", json!(["", ""])),
                ],
            )
        });
    }
}
