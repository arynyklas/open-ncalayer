//! `kz.gov.pki.knca.basics` / `PKIExtras.sign`: argument parsing, the storage → key → sign
//! flow driven by a scripted prompter, cms, raw and xml results, TSP and error codes.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_builtin_tests::basics::{Basics, MODULE_NAME};
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_flows::{
    Action, Availability, Busy, BusyPrompt, ChainPolicy, CsrAnswer, CsrPrompt, DisabledReason,
    FilePrompt, FilterMore, ImportAnswer, ImportPrompt, KeyFilter, KeyPrompt, Locale, OcspCache,
    OpenError, PasswordPrompt, Prompt, Prompter, RecentPathStore, StorageAnswer, StorageKind,
    StoragePrompt, availabilities,
};
use oncl_pki::cert::Certificate;
use oncl_pki::cms::{SignOptions, verify};
use oncl_pki::http::HttpTransport;
use oncl_pki::info::{CertInfo, KeyUsageBits, KncaCertType, cert_info};
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_pki::pkcs12::{KeyEntry, WriteEntry, WriteOptions, load, write};
use oncl_pki::tsp::{MockTsa, verify_token};
use oncl_protocol::{AddInfo, Module, Reply};
use oncl_testkit::{fixture, ncanode, read, synthetic};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use time::macros::datetime;
use zeroize::Zeroizing;

const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
const EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const BASICS_POLICY: &str = "1.2.398.3.3.2.6.4";

macro_rules! script {
    ($($step:expr),* $(,)?) => { vec![$($step),*] };
}

fn storage(name: &str, password: &str) -> Step {
    Step::Storage {
        path: synthetic(name).path,
        password: password.to_owned(),
    }
}

fn storage_at(path: impl Into<PathBuf>, password: &str) -> Step {
    Step::Storage {
        path: path.into(),
        password: password.to_owned(),
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

struct Setup {
    basics: Basics,
    prompter: Arc<ScriptedPrompter>,
    recent: Arc<MemoryRecentPath>,
    tsa: Arc<MockTsa>,
}

fn setup(steps: Vec<Step>, recent: Option<PathBuf>) -> Setup {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let recent = Arc::new(MemoryRecentPath::new(recent));
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let basics = Basics::new(prompter.clone(), recent.clone(), tsa.clone());
    Setup {
        basics,
        prompter,
        recent,
        tsa,
    }
}

fn basics(steps: Vec<Step>) -> (Basics, Arc<ScriptedPrompter>) {
    let s = setup(steps, None);
    (s.basics, s.prompter)
}

fn req(args: Value) -> String {
    json!({"module": MODULE_NAME, "method": "sign", "args": args}).to_string()
}

fn origin(o: &str) -> AddInfo {
    AddInfo {
        origin: Some(o.to_owned()),
        ..AddInfo::default()
    }
}

fn json(reply: Reply) -> Value {
    serde_json::from_str(reply.text().expect("a text reply")).unwrap()
}

/// The failure `code` of a request answered without any prompt.
fn code(args: Value) -> String {
    let (b, p) = basics(script![]);
    let r = json(b.process(&req(args), &origin("https://x.kz")));
    assert_eq!(r["status"], false, "{r}");
    assert!(p.storage_prompts().is_empty(), "no dialog before the error");
    r["code"].as_str().unwrap().to_owned()
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    STANDARD.decode(body).unwrap()
}

fn cms_args(data: Value, signing_params: Value) -> Value {
    json!({
        "format": "cms",
        "data": data,
        "signingParams": signing_params,
        "signerParams": {"extKeyUsageOids": [], "chain": []},
    })
}

fn raw_args(data: Value, signing_params: Value) -> Value {
    json!({
        "format": "raw",
        "data": data,
        "signingParams": signing_params,
        "signerParams": {"extKeyUsageOids": [], "chain": []},
    })
}

fn public_key(e: &KeyEntry) -> PublicKey {
    PublicKey::from_spki(e.cert.tbs_certificate().subject_public_key_info()).unwrap()
}

#[test]
fn cms_attached_happy_path() {
    let (b, p) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(json!({"format":"cms","data":"aGVsbG8=","signingParams":{"decode":true},"signerParams":{"extKeyUsageOids":[],"chain":[]}})),
        &origin("https://x.kz"),
    ));
    assert_eq!(r["status"], true);
    let pem = r["body"]["result"][0].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CMS-----"));
    let der = pem_to_der(pem);
    let signers = verify(&der, None).unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].sig_alg, SigAlg::Gost2015_512);
    assert!(signers[0].timestamp_token.is_none());
    assert_eq!(p.storage_prompts()[0].origin, "https://x.kz");
    assert_eq!(p.storage_prompts()[0].locale, Locale::Kk);
    assert_eq!(p.storage_prompts()[0].action, Action::Sign);
    assert_eq!(p.storage_prompts()[0].error, None);
    let kp = &p.key_prompts()[0];
    assert_eq!(kp.origin, "https://x.kz");
    assert_eq!(kp.candidates.len(), 1);
    assert_eq!(
        kp.candidates[0].alias,
        synthetic("user-gost2015-sign").aliases[0]
    );
    assert_eq!(kp.candidates[0].availability, Availability::Enabled);
}

#[test]
fn cms_content_detached_and_digested() {
    // The content is the UTF-8 text when `decode` is off; detached signatures verify over it.
    let (b, _) = basics(script![storage("user-gost2004-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(cms_args(json!("привет"), json!({"encapsulate": false}))),
        &origin("o"),
    ));
    let der = pem_to_der(r["body"]["result"][0].as_str().unwrap());
    assert_eq!(
        verify(&der, None),
        Err(oncl_pki::cms::CmsError::NoEncapsulatedData)
    );
    let signers = verify(&der, Some("привет".as_bytes())).unwrap();
    assert_eq!(signers[0].sig_alg, SigAlg::Gost2004);

    // `digested`: the data is the hash; the detached signature verifies over the document.
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let hash = STANDARD.encode(SigAlg::Gost2015_512.digest(b"doc"));
    let r = json(b.process(
        &req(cms_args(
            json!(hash),
            json!({"decode": true, "digested": true, "encapsulate": false}),
        )),
        &origin("o"),
    ));
    let der = pem_to_der(r["body"]["result"][0].as_str().unwrap());
    assert_eq!(verify(&der, Some(b"doc")).unwrap().len(), 1);

    // Several data items: one PEM each, always an array; RSA keys sign too.
    let (b, _) = basics(script![storage("user-rsa-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(cms_args(json!(["YQ==", "Yg=="]), json!({"decode": true}))),
        &origin("o"),
    ));
    let results = r["body"]["result"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    for (pem, content) in results.iter().zip([b"a", b"b"]) {
        let der = pem_to_der(pem.as_str().unwrap());
        let signers = verify(&der, None).unwrap();
        assert_eq!(signers[0].sig_alg, SigAlg::RsaSha256);
        assert_eq!(verify(&der, Some(content)).unwrap().len(), 1);
    }
}

#[test]
fn cms_signing_time_comes_from_the_clock() {
    fn clock() -> OffsetDateTime {
        datetime!(2030-05-06 07:08:09 UTC)
    }
    let s = setup(
        script![storage("user-gost2015-sign", "Qwerty12"), key(0)],
        None,
    );
    let b = s.basics.with_clock(clock);
    let r = json(b.process(&req(cms_args(json!("x"), json!({}))), &origin("o")));
    let der = pem_to_der(r["body"]["result"][0].as_str().unwrap());
    assert_eq!(verify(&der, None).unwrap()[0].signing_time, Some(clock()));
}

#[test]
fn cosign_appends_a_signer() {
    let first = oncl_pki::cms::sign(
        &entry("user-gost2004-sign"),
        b"doc",
        &SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: OffsetDateTime::now_utc(),
        },
    )
    .unwrap();
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(cms_args(
            json!(STANDARD.encode(&first)),
            json!({"decode": true, "tsaProfile": {}}),
        )),
        &origin("o"),
    ));
    assert_eq!(r["status"], true, "{r}");
    let signers = verify(&pem_to_der(r["body"]["result"][0].as_str().unwrap()), None).unwrap();
    assert_eq!(signers.len(), 2);
    // The time-stamp goes to the new signer, the last one.
    assert!(signers[0].timestamp_token.is_none());
    assert!(signers[1].timestamp_token.is_some());
    assert_eq!(signers[1].sig_alg, SigAlg::Gost2015_512);
}

#[test]
fn cancel_returns_empty_body() {
    let (b, p) = basics(script![Step::CancelStorage]);
    assert_eq!(
        b.process(&req(cms_args(json!("x"), json!({}))), &origin("o")),
        r#"{"body":{},"status":true}"#
    );
    assert_eq!(p.storage_prompts().len(), 1);
    assert!(p.key_prompts().is_empty());

    let (b, p) = basics(script![
        storage("user-gost2015-sign", "Qwerty12"),
        Step::CancelKey
    ]);
    assert_eq!(
        b.process(&req(cms_args(json!("x"), json!({}))), &origin("o")),
        r#"{"body":{},"status":true}"#
    );
    assert_eq!(p.key_prompts().len(), 1);

    // An exhausted script cancels.
    let (b, _) = basics(script![]);
    assert_eq!(
        b.process(&req(raw_args(json!("x"), json!({}))), &origin("o")),
        r#"{"body":{},"status":true}"#
    );
}

#[test]
fn wrong_password_reprompts_with_error() {
    let s = setup(
        script![
            storage("user-gost2015-sign", "bad"),
            storage("user-gost2015-sign", "Qwerty12"),
            key(0)
        ],
        None,
    );
    let r = json(
        s.basics
            .process(&req(cms_args(json!("x"), json!({}))), &origin("o")),
    );
    assert_eq!(r["status"], true);
    let prompts = s.prompter.storage_prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[0].error, None);
    assert_eq!(prompts[1].error, Some(OpenError::WrongPassword));
    // The retry keeps the path the user typed.
    assert_eq!(
        prompts[1].recent_path,
        Some(synthetic("user-gost2015-sign").path)
    );
}

/// Remembers the prompter's timeline whenever the opened path is saved: right after the key
/// store opened.
struct TimelineAtSave {
    prompter: Arc<ScriptedPrompter>,
    seen: Mutex<Vec<Vec<&'static str>>>,
}

impl RecentPathStore for TimelineAtSave {
    fn load(&self) -> Option<PathBuf> {
        None
    }

    fn save(&self, _: &Path) {
        self.seen.lock().unwrap().push(self.prompter.timeline());
    }
}

#[test]
fn busy_indicator_shows_while_the_store_opens() {
    let prompter = Arc::new(ScriptedPrompter::new(script![
        storage("user-gost2015-sign", "bad"),
        storage("user-gost2015-sign", "Qwerty12"),
        key(0)
    ]));
    let recent = Arc::new(TimelineAtSave {
        prompter: prompter.clone(),
        seen: Mutex::new(Vec::new()),
    });
    let b = Basics::new(
        prompter.clone(),
        recent.clone(),
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
    );
    let r = json(b.process(&req(cms_args(json!("x"), json!({}))), &origin("o")));
    assert_eq!(r["status"], true, "{r}");
    // Each answer opens under the indicator, which goes before the next dialog.
    assert_eq!(
        *recent.seen.lock().unwrap(),
        [vec!["storage", "busy", "busy closed", "storage", "busy"]]
    );
    assert_eq!(
        prompter.timeline(),
        [
            "storage",
            "busy",
            "busy closed",
            "storage",
            "busy",
            "busy closed",
            "key"
        ]
    );
    let storage = &prompter.storage_prompts()[0];
    assert_eq!(
        prompter.busy_prompts(),
        vec![
            BusyPrompt {
                origin: storage.origin.clone(),
                locale: storage.locale,
            };
            2
        ]
    );
}

#[test]
fn unreadable_storages_reprompt_with_error() {
    let missing = synthetic("user-gost2015-sign")
        .path
        .with_extension("missing");
    let s = setup(
        script![
            storage_at(&missing, "Qwerty12"),
            storage_at(fixture("synthetic/root-gost2015.cer"), "Qwerty12"),
        ],
        None,
    );
    let r = s
        .basics
        .process(&req(cms_args(json!("x"), json!({}))), &origin("o"));
    assert_eq!(r, r#"{"body":{},"status":true}"#);
    let errors: Vec<_> = s
        .prompter
        .storage_prompts()
        .iter()
        .map(|p| p.error)
        .collect();
    assert_eq!(
        errors,
        [
            None,
            Some(OpenError::FileNotFound),
            Some(OpenError::NotPkcs12)
        ]
    );
    // Nothing opened: nothing saved.
    assert_eq!(s.recent.saved(), None);
}

#[test]
fn keyless_store_reprompts_with_no_keys() {
    let p12 = write(
        &[],
        &[],
        "Qwerty12",
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(3),
    )
    .unwrap();
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("oncl-flows-keyless.p12");
    std::fs::write(&path, p12).unwrap();
    let s = setup(
        script![
            storage_at(&path, "Qwerty12"),
            storage("user-gost2015-sign", "Qwerty12"),
            key(0)
        ],
        None,
    );
    let r = json(
        s.basics
            .process(&req(raw_args(json!("x"), json!({}))), &origin("o")),
    );
    assert_eq!(r["status"], true, "{r}");
    let prompts = s.prompter.storage_prompts();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[1].error, Some(OpenError::NoKeys));
    assert_eq!(prompts[1].recent_path, Some(path));
}

/// Answers a token first, then a JKS answer naming a PKCS#12 file, then a working PKCS#12,
/// then key 0.
struct JksFirst {
    storage_prompts: Mutex<Vec<StoragePrompt>>,
}

impl Prompter for JksFirst {
    fn storage(&self, p: &StoragePrompt) -> Prompt<StorageAnswer> {
        let mut prompts = self.storage_prompts.lock().unwrap();
        prompts.push(p.clone());
        let kind = match prompts.len() {
            1 => StorageKind::Token("AKKaztokenStore"),
            2 => StorageKind::Jks,
            _ => StorageKind::Pkcs12,
        };
        let key = synthetic("user-gost2015-sign");
        Prompt::Answer(StorageAnswer {
            storage: kind,
            path: key.path,
            password: Zeroizing::new(key.password),
            reader: None,
        })
    }

    fn busy(&self, _: &BusyPrompt) -> Busy {
        Busy::none()
    }

    fn key(&self, _: &KeyPrompt) -> Prompt<usize> {
        Prompt::Answer(0)
    }

    fn csr(&self, _: &CsrPrompt) -> Prompt<CsrAnswer> {
        Prompt::Cancelled
    }

    fn import_cert(&self, _: &ImportPrompt) -> Prompt<ImportAnswer> {
        Prompt::Cancelled
    }

    fn file(&self, _: &FilePrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }

    fn password(&self, _: &PasswordPrompt) -> Prompt<Zeroizing<String>> {
        Prompt::Cancelled
    }

    fn message(&self, _: &oncl_flows::MessagePrompt) -> Prompt<()> {
        Prompt::Cancelled
    }

    fn confirm(&self, _: &oncl_flows::ConfirmPrompt) -> Prompt<bool> {
        Prompt::Cancelled
    }

    fn save_file(&self, _: &oncl_flows::SavePrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }

    fn choice(&self, _: &oncl_flows::ChoicePrompt) -> Prompt<oncl_flows::ChoiceAnswer> {
        Prompt::Cancelled
    }

    fn path(&self, _: &oncl_flows::PathPrompt) -> Prompt<PathBuf> {
        Prompt::Cancelled
    }

    fn reader(&self, _: &oncl_flows::ReaderPrompt) -> Prompt<String> {
        Prompt::Cancelled
    }
}

#[test]
fn unsupported_storage_reprompts() {
    let prompter = Arc::new(JksFirst {
        storage_prompts: Mutex::new(Vec::new()),
    });
    let b = Basics::new(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new(entry("tsa-gost2015"))),
    );
    let r = json(b.process(&req(raw_args(json!("x"), json!({}))), &origin("o")));
    assert_eq!(r["status"], true);
    let prompts = prompter.storage_prompts.lock().unwrap();
    assert_eq!(prompts.len(), 3);
    assert_eq!(prompts[1].error, Some(OpenError::UnsupportedStorage));
    assert_eq!(prompts[2].error, Some(OpenError::NotJks));
}

#[test]
fn jks_keys_sign() {
    let (b, p) = basics(script![
        Step::Jks {
            path: fixture("jks/rsa.jks"),
            password: "Qwerty12".to_owned(),
        },
        key(0)
    ]);
    let r = json(b.process(
        &req(cms_args(json!("aGVsbG8="), json!({"decode": true}))),
        &origin("o"),
    ));
    assert_eq!(r["status"], true, "{r}");
    let der = pem_to_der(r["body"]["result"][0].as_str().unwrap());
    assert_eq!(verify(&der, None).unwrap()[0].sig_alg, SigAlg::RsaSha256);
    assert_eq!(p.key_prompts()[0].candidates[0].alias, "openncalayer-rsa");
}

#[test]
fn ekus_iin_bin_serial_filters() {
    let multi = synthetic("multi-gost2015");
    let infos: Vec<_> = load(&read(&multi.path), &multi.password)
        .unwrap()
        .iter()
        .map(|e| cert_info(&e.cert))
        .collect();
    let is_auth: Vec<bool> = infos
        .iter()
        .map(|i| i.ext_key_usages.contains(CLIENT_AUTH))
        .collect();
    assert_eq!(is_auth.iter().filter(|a| **a).count(), 1, "one auth key");

    // clientAuth requested: only the auth key is enabled, and the dialog says "authenticate".
    let (b, p) = basics(script![
        storage("multi-gost2015", "Qwerty12"),
        Step::CancelKey
    ]);
    b.process(
        &req(json!({"format":"cms","data":"x","signingParams":{},"signerParams":{"extKeyUsageOids":[CLIENT_AUTH],"chain":[]}})),
        &origin("o"),
    );
    let kp = &p.key_prompts()[0];
    assert_eq!(kp.action, Action::Authenticate);
    assert_eq!(p.storage_prompts()[0].action, Action::Authenticate);
    assert_eq!(
        kp.candidates
            .iter()
            .map(|c| c.alias.clone())
            .collect::<Vec<_>>(),
        multi.aliases
    );
    for (c, auth) in kp.candidates.iter().zip(&is_auth) {
        let expected = if *auth {
            Availability::Enabled
        } else {
            Availability::Disabled(vec![DisabledReason::ExtKeyUsage])
        };
        assert_eq!(c.availability, expected, "{}", c.alias);
    }

    // A foreign IIN disables every key.
    let (b, p) = basics(script![
        storage("multi-gost2015", "Qwerty12"),
        Step::CancelKey
    ]);
    b.process(
        &req(json!({"format":"cms","data":"x","signingParams":{},"signerParams":{"extKeyUsageOids":[],"iin":"999999999999","chain":[]}})),
        &origin("o"),
    );
    for c in &p.key_prompts()[0].candidates {
        assert_eq!(
            c.availability,
            Availability::Disabled(vec![DisabledReason::Iin])
        );
    }
    assert_eq!(p.key_prompts()[0].action, Action::Sign);

    // Everything matches a legal entity's key; the serial compares case-insensitively.
    let legal = cert_info(&entry("legal-gost2015-sign").cert);
    let serial = legal.serial_hex.to_uppercase();
    let (b, p) = basics(script![
        storage("legal-gost2015-sign", "Qwerty12"),
        Step::CancelKey
    ]);
    b.process(
        &req(json!({"format":"raw","data":"x","signingParams":{},"signerParams":{
            "extKeyUsageOids":[], "iin":"123456789022", "bin":"123456789021", "serialNumber": serial, "chain":[]}})),
        &origin("o"),
    );
    assert_eq!(
        p.key_prompts()[0].candidates[0].availability,
        Availability::Enabled
    );

    // Nothing matches: every reason, in order.
    let (b, p) = basics(script![
        storage("user-gost2015-sign", "Qwerty12"),
        Step::CancelKey
    ]);
    b.process(
        &req(
            json!({"format":"raw","data":"x","signingParams":{},"signerParams":{
            "extKeyUsageOids":[CLIENT_AUTH], "iin":"1", "bin":"2", "serialNumber":"3", "chain":[]}}),
        ),
        &origin("o"),
    );
    assert_eq!(
        p.key_prompts()[0].candidates[0].availability,
        Availability::Disabled(vec![
            DisabledReason::ExtKeyUsage,
            DisabledReason::Iin,
            DisabledReason::Bin,
            DisabledReason::SerialNumber,
        ])
    );
}

#[test]
fn key_filter_availability() {
    let key = |name: &str| {
        let cert = entry(name).cert;
        let info = cert_info(&cert);
        (cert, info)
    };
    let user = key("user-gost2015-sign");
    let filter = |ekus: &[&str], allow_expired: bool| KeyFilter {
        ext_key_usages: ekus
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>(),
        iin: String::new(),
        bin: String::new(),
        serial_number: String::new(),
        allow_expired,
        // No path building, no OCSP: the transport is never used.
        chain: ChainPolicy::Empty,
        allow_revoked: false,
        more: Default::default(),
    };
    let tsa = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let http: Arc<dyn HttpTransport> = tsa.clone();
    let availability = |filter: KeyFilter, key: &(Certificate, CertInfo), now| {
        let cache = Arc::new(OcspCache::new());
        let live = availabilities(&filter, std::slice::from_ref(key), &http, &cache, now);
        assert!(live.is_settled(), "nothing to check");
        live.current().remove(0)
    };
    let inside = datetime!(2026-01-01 0:00 UTC);
    let after = datetime!(2100-01-01 0:00 UTC);
    assert_eq!(
        availability(filter(&[], false), &user, inside),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[], false), &user, after),
        Availability::Expired
    );
    assert_eq!(
        availability(filter(&[], true), &user, after),
        Availability::Enabled
    );
    let requested: Vec<&str> = user.1.ext_key_usages.iter().map(String::as_str).collect();
    assert_eq!(
        availability(filter(&requested, false), &user, inside),
        Availability::Enabled
    );
    // Disabled wins over expired.
    assert_eq!(
        availability(
            filter(&[EMAIL_PROTECTION, CLIENT_AUTH], false),
            &user,
            after
        ),
        Availability::Disabled(vec![DisabledReason::ExtKeyUsage])
    );
    // The obsolete-auth rule: a GOST 2015 key with keyAgreement counts as clientAuth.
    let legacy = key("legacy-gost2015-auth");
    assert!(!legacy.1.ext_key_usages.contains(CLIENT_AUTH));
    assert_eq!(
        availability(filter(&[CLIENT_AUTH], false), &legacy, inside),
        Availability::Enabled
    );
    assert!(tsa.calls().is_empty());
}

#[test]
fn filter_more_reasons() {
    let key = |name: &str| {
        let cert = entry(name).cert;
        let info = cert_info(&cert);
        (cert, info)
    };
    let filter = |ekus: &[&str], more: FilterMore| KeyFilter {
        ext_key_usages: ekus.iter().map(|s| (*s).to_owned()).collect(),
        iin: String::new(),
        bin: String::new(),
        serial_number: String::new(),
        allow_expired: true,
        chain: ChainPolicy::Empty,
        allow_revoked: false,
        more,
    };
    let http: Arc<dyn HttpTransport> = Arc::new(MockTsa::new(entry("tsa-gost2015")));
    let availability = |filter: KeyFilter, key: &(Certificate, CertInfo)| {
        let cache = Arc::new(OcspCache::new());
        let now = datetime!(2026-01-01 0:00 UTC);
        let live = availabilities(&filter, std::slice::from_ref(key), &http, &cache, now);
        live.current().remove(0)
    };
    let set = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect();
    let user = key("user-gost2015-sign");
    let legal = key("legal-gost2015-sign");
    let auth = key("user-gost2015-auth");
    let rsa = key("user-rsa-sign");
    let disabled = |reasons: &[DisabledReason]| Availability::Disabled(reasons.to_vec());

    // At least one of.
    let any = || FilterMore {
        any_ext_key_usages: set(&["1.2.398.3.3.4.1.2.1", "1.3.6.1.5.5.7.3.2"]),
        ..FilterMore::default()
    };
    assert_eq!(
        availability(filter(&[], any()), &legal),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[], any()), &auth),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[], any()), &user),
        disabled(&[DisabledReason::AnyExtKeyUsage])
    );
    // None of.
    let exclude = FilterMore {
        exclude_ext_key_usages: set(&["1.2.398.3.3.4.1.2.1"]),
        ..FilterMore::default()
    };
    assert_eq!(
        availability(filter(&[], exclude.clone()), &legal),
        disabled(&[DisabledReason::ExcludedExtKeyUsage])
    );
    assert_eq!(
        availability(filter(&[], exclude), &user),
        Availability::Enabled
    );
    // Kalkan types: a GOST 2015 signing key is both, an authentication key with
    // keyAgreement and no keyEncipherment is neither.
    let types = |names: &[KncaCertType]| FilterMore {
        knca_types: names.iter().copied().collect(),
        ..FilterMore::default()
    };
    assert_eq!(
        availability(filter(&[], types(&[KncaCertType::Signature])), &user),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[], types(&[KncaCertType::Signature])), &auth),
        disabled(&[DisabledReason::KncaType])
    );
    // The BIN, else the IIN.
    let tin = |tin: &str| FilterMore {
        tin: tin.to_owned(),
        ..FilterMore::default()
    };
    assert_eq!(
        availability(filter(&[], tin("123456789021")), &legal),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[], tin("123456789022")), &legal),
        disabled(&[DisabledReason::Tin]),
        "a legal entity's certificate is matched by its BIN only"
    );
    assert_eq!(
        availability(filter(&[], tin("123456789011")), &user),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[], tin("123456789021")), &user),
        disabled(&[DisabledReason::Tin])
    );
    // Every bit.
    let bits = FilterMore {
        key_usage: KeyUsageBits {
            digital_signature: true,
            non_repudiation: true,
            ..KeyUsageBits::default()
        },
        ..FilterMore::default()
    };
    assert_eq!(
        availability(filter(&[], bits.clone()), &user),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[], bits), &auth),
        disabled(&[DisabledReason::KeyUsage])
    );
    // Obsolete authentication: any GOST 2015-512 certificate counts as clientAuth; a
    // sha256RSA one only with keyEncipherment.
    let obsolete = || FilterMore {
        obsolete_auth: true,
        ..FilterMore::default()
    };
    assert_eq!(
        availability(filter(&[CLIENT_AUTH], FilterMore::default()), &user),
        disabled(&[DisabledReason::ExtKeyUsage])
    );
    assert_eq!(
        availability(filter(&[CLIENT_AUTH], obsolete()), &user),
        Availability::Enabled
    );
    assert_eq!(
        availability(filter(&[CLIENT_AUTH], obsolete()), &rsa),
        disabled(&[DisabledReason::ExtKeyUsage]),
        "an RSA signing key has no keyEncipherment"
    );
    // Every failed condition, in order.
    let all = FilterMore {
        any_ext_key_usages: set(&["1.3.6.1.5.5.7.3.2"]),
        exclude_ext_key_usages: set(&["1.2.398.3.3.4.1.2.1"]),
        knca_types: [KncaCertType::Ssl].into_iter().collect(),
        tin: "1".to_owned(),
        key_usage: KeyUsageBits {
            key_encipherment: true,
            ..KeyUsageBits::default()
        },
        obsolete_auth: false,
    };
    assert_eq!(
        availability(filter(&[], all), &legal),
        disabled(&[
            DisabledReason::AnyExtKeyUsage,
            DisabledReason::ExcludedExtKeyUsage,
            DisabledReason::KncaType,
            DisabledReason::Tin,
            DisabledReason::KeyUsage,
        ])
    );
}

#[test]
fn expired_key_cannot_be_chosen() {
    let (b, p) = basics(script![
        storage("expired-gost2015-sign", "Qwerty12"),
        key(0),
        key(0)
    ]);
    let r = b.process(&req(cms_args(json!("x"), json!({}))), &origin("o"));
    assert_eq!(r, r#"{"body":{},"status":true}"#);
    let kps = p.key_prompts();
    assert_eq!(kps.len(), 3, "two refused picks, then the exhausted script");
    assert_eq!(kps[0].candidates[0].availability, Availability::Expired);
    assert_eq!(kps[0], kps[2]);
}

#[test]
fn a_prompter_panic_drops_only_the_connection() {
    // The refused expired key is prompted for again, and the script answers that prompt
    // with a storage: the scripted prompter panics. The call's connection is dropped; the
    // module, and the process, carry on with the next call.
    let (b, p) = basics(script![
        storage("expired-gost2015-sign", "Qwerty12"),
        key(0),
        storage("user-gost2015-sign", "Qwerty12"),
        storage("user-gost2015-sign", "Qwerty12"),
        key(0)
    ]);
    let args = cms_args(json!("x"), json!({}));
    assert_eq!(b.process(&req(args.clone()), &origin("o")), Reply::Drop);
    let r = json(b.process(&req(args), &origin("o")));
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(p.key_prompts().len(), 3);
}

#[test]
fn out_of_range_key_index_reprompts() {
    let (b, p) = basics(script![
        storage("user-gost2015-sign", "Qwerty12"),
        key(5),
        key(0)
    ]);
    let r = json(b.process(&req(raw_args(json!("x"), json!({}))), &origin("o")));
    assert_eq!(r["status"], true);
    assert_eq!(p.key_prompts().len(), 2);
}

#[test]
fn tsa_profile_adds_timestamp() {
    let s = setup(
        script![storage("user-gost2015-sign", "Qwerty12"), key(0)],
        None,
    );
    let r = json(s.basics.process(
        &req(cms_args(
            json!("aGVsbG8="),
            json!({"decode": true, "tsaProfile": {}}),
        )),
        &origin("o"),
    ));
    assert_eq!(r["status"], true, "{r}");
    let der = pem_to_der(r["body"]["result"][0].as_str().unwrap());
    let signers = verify(&der, None).unwrap();
    let token = signers[0].timestamp_token.as_ref().unwrap();
    assert_eq!(
        verify_token(token).unwrap().policy.to_string(),
        BASICS_POLICY
    );
    let calls = s.tsa.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].starts_with("http://tsp.pki.gov.kz/"),
        "{}",
        calls[0]
    );

    // The profile's contents are ignored; another profile comes from `with_tsa`.
    let s = setup(
        script![storage("user-gost2015-sign", "Qwerty12"), key(0)],
        None,
    );
    let mut profile = oncl_pki::tsp::TsaProfile::basics_default();
    profile.url = "http://tsa.test/x".to_owned();
    let b = s.basics.with_tsa(profile);
    let r = json(b.process(
        &req(cms_args(
            json!("x"),
            json!({"tsaProfile": {"url": "http://ignored"}}),
        )),
        &origin("o"),
    ));
    assert_eq!(r["status"], true, "{r}");
    assert!(s.tsa.calls()[0].starts_with("http://tsa.test/x/"));
}

#[test]
fn tsp_failure_code() {
    struct Down;
    impl oncl_pki::http::HttpTransport for Down {
        fn send(
            &self,
            request: &oncl_pki::http::HttpRequest<'_>,
        ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
            match request.method {
                oncl_pki::http::HttpMethod::Get => {
                    let (_, _) = (request.url, request.opts);
                    Err(oncl_pki::http::HttpError::other("down"))
                }
                oncl_pki::http::HttpMethod::Post => {
                    let (_, _, _, _) = (
                        request.url,
                        request.content_type.unwrap_or_default(),
                        request.body,
                        request.opts,
                    );
                    Err(oncl_pki::http::HttpError::other("down"))
                }
            }
        }
    }
    let prompter = Arc::new(ScriptedPrompter::new(script![
        storage("user-gost2015-sign", "Qwerty12"),
        key(0)
    ]));
    let b = Basics::new(
        prompter,
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(Down),
    );
    let r = json(b.process(
        &req(cms_args(json!("x"), json!({"tsaProfile": {}}))),
        &origin("o"),
    ));
    assert_eq!(r["status"], false);
    assert_eq!(r["code"], "TIMESTAMP_CREATION_FAILURE");
    assert_eq!(r["message"], "HTTP request to the TSA failed: down", "{r}");
    assert_eq!(r["details"], r["message"]);
}

#[test]
fn raw_result_shapes() {
    let signer = entry("user-gost2015-sign");
    let public = public_key(&signer);
    let raw = |data: Value, params: Value| {
        let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
        let r = json(b.process(&req(raw_args(data, params)), &origin("o")));
        assert_eq!(r["status"], true, "{r}");
        r["body"]["result"].clone()
    };
    let sig = |v: &Value| STANDARD.decode(v.as_str().unwrap()).unwrap();

    // One data item: a single string.
    let one = raw(json!("aGVsbG8="), json!({"decode": true}));
    assert_eq!(
        public.verify(SigAlg::Gost2015_512, b"hello", &sig(&one)),
        Ok(())
    );

    // A one-element array is still one signature: a string.
    let one = raw(json!(["a"]), json!({}));
    assert!(one.is_string());

    // Several: an array, in order.
    let two = raw(json!(["a", "b"]), json!({}));
    let two = two.as_array().unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(
        public.verify(SigAlg::Gost2015_512, b"a", &sig(&two[0])),
        Ok(())
    );
    assert_eq!(
        public.verify(SigAlg::Gost2015_512, b"b", &sig(&two[1])),
        Ok(())
    );

    // outputCert: signatures and the certificate PEM.
    let with_cert = raw(json!("a"), json!({"outputCert": true}));
    let certificate = with_cert["certificate"].as_str().unwrap();
    assert!(certificate.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(
        certificate
            .trim_end()
            .ends_with("-----END CERTIFICATE-----")
    );
    assert_eq!(pem_to_der(certificate), signer.cert.to_der().unwrap());
    let signatures = with_cert["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 1);
    assert_eq!(
        public.verify(SigAlg::Gost2015_512, b"a", &sig(&signatures[0])),
        Ok(())
    );
}

/// A raw GOST 2015-512 signature is the 128 bytes the key verifies as they are (the order
/// and byte order of its halves as Kalkan writes them); the reply is `{"body":…,"status"}`.
#[test]
fn raw_gost2015_512_layout() {
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let reply = b.process(
        &req(raw_args(json!("aGVsbG8="), json!({"decode": true}))),
        &origin("o"),
    );
    let text = reply.text().unwrap();
    let r: Value = serde_json::from_str(text).unwrap();
    let encoded = r["body"]["result"].as_str().unwrap();
    assert_eq!(
        text,
        format!(r#"{{"body":{{"result":"{encoded}"}},"status":true}}"#)
    );
    let sig = STANDARD.decode(encoded).unwrap();
    assert_eq!(sig.len(), 128);
    let public = public_key(&entry("user-gost2015-sign"));
    assert_eq!(public.verify(SigAlg::Gost2015_512, b"hello", &sig), Ok(()));
    let swapped = [&sig[64..], &sig[..64]].concat();
    assert!(
        public
            .verify(SigAlg::Gost2015_512, b"hello", &swapped)
            .is_err()
    );
}

#[test]
fn raw_gost2004_verifies() {
    let (b, _) = basics(script![storage("user-gost2004-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(raw_args(json!("aGVsbG8="), json!({"decode": true}))),
        &origin("o"),
    ));
    let sig = STANDARD
        .decode(r["body"]["result"].as_str().unwrap())
        .unwrap();
    let public = public_key(&entry("user-gost2004-sign"));
    assert_eq!(public.verify(SigAlg::Gost2004, b"hello", &sig), Ok(()));
}

#[test]
fn raw_rsa_is_sha256() {
    let (b, _) = basics(script![storage("user-rsa-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(&req(raw_args(json!("hello"), json!({}))), &origin("o")));
    let sig = STANDARD
        .decode(r["body"]["result"].as_str().unwrap())
        .unwrap();
    let public = public_key(&entry("user-rsa-sign"));
    assert_eq!(public.verify(SigAlg::RsaSha256, b"hello", &sig), Ok(()));
}

#[test]
fn ncanode_test_keys_sign_within_their_validity() {
    fn gost2015_clock() -> OffsetDateTime {
        datetime!(2023-01-01 00:00 UTC)
    }
    fn rsa_clock() -> OffsetDateTime {
        datetime!(2021-06-01 00:00 UTC)
    }
    // A clock within each certificate's validity.
    type Clock = fn() -> OffsetDateTime;
    let keys: [(&str, &str, SigAlg, Clock); 2] = [
        (
            "individual_valid_2015.p12",
            "Aa123456",
            SigAlg::Gost2015_512,
            gost2015_clock,
        ),
        (
            "individual_valid_sign_2004.p12",
            "Qwerty12",
            SigAlg::RsaSha256,
            rsa_clock,
        ),
    ];
    for (file, password, alg, clock) in keys {
        let path = ncanode(file);
        let signer = || script![storage_at(&path, password), key(0)];
        let public = public_key(&load(&read(&path), password).unwrap()[0]);

        // Both certificates have expired: today the key is offered but cannot be chosen.
        let (b, p) = basics(signer());
        let r = b.process(&req(cms_args(json!("x"), json!({}))), &origin("o"));
        assert_eq!(r, r#"{"body":{},"status":true}"#, "{file}");
        assert_eq!(
            p.key_prompts()[0].candidates[0].availability,
            Availability::Expired
        );

        let (b, _) = basics(signer());
        let r = json(b.with_clock(clock).process(
            &req(cms_args(json!("aGVsbG8="), json!({"decode": true}))),
            &origin("o"),
        ));
        let der = pem_to_der(r["body"]["result"][0].as_str().unwrap());
        assert_eq!(verify(&der, None).unwrap()[0].sig_alg, alg, "{file}");

        let (b, _) = basics(signer());
        let r = json(b.with_clock(clock).process(
            &req(raw_args(json!("aGVsbG8="), json!({"decode": true}))),
            &origin("o"),
        ));
        let sig = STANDARD
            .decode(r["body"]["result"].as_str().unwrap())
            .unwrap();
        assert_eq!(public.verify(alg, b"hello", &sig), Ok(()), "{file}");

        let (b, _) = basics(signer());
        let r = json(b.with_clock(clock).process(
            &req(json!({
                "format": "xml",
                "data": "<a>x</a>",
                "signingParams": {},
                "signerParams": {"extKeyUsageOids": [], "chain": []},
            })),
            &origin("o"),
        ));
        assert_eq!(r["status"], true, "{file}: {r}");
        assert!(
            r["body"]["result"][0]
                .as_str()
                .unwrap()
                .contains("<ds:SignatureValue>"),
            "{file}: {r}"
        );
    }
}

#[test]
fn param_errors() {
    // Missing required fields: INVOCATION_ERROR with org.json's details.
    let invocation = |args: Value, field: &str| {
        let (b, _) = basics(script![]);
        let r = json(b.process(&req(args), &origin("o")));
        assert_eq!(r["code"], "INVOCATION_ERROR", "{r}");
        assert_eq!(r["message"], "An invoked method threw an exception.");
        assert_eq!(
            r["details"],
            format!("org.json.JSONException: JSONObject[\"{field}\"] not found."),
            "{r}"
        );
    };
    assert_eq!(
        code(json!({"data":"x","signingParams":{},"signerParams":{"extKeyUsageOids":[]}})),
        "INVOCATION_ERROR"
    );
    invocation(
        json!({"data":"x","signingParams":{},"signerParams":{"extKeyUsageOids":[]}}),
        "format",
    );
    invocation(
        json!({"format":"cms","data":"x","signerParams":{"extKeyUsageOids":[]}}),
        "signingParams",
    );
    invocation(
        json!({"format":"cms","signingParams":{},"signerParams":{"extKeyUsageOids":[]}}),
        "data",
    );
    invocation(
        json!({"format":"raw","data":"x","signingParams":{}}),
        "signerParams",
    );
    invocation(
        json!({"format":"raw","data":"x","signingParams":{},"signerParams":{}}),
        "extKeyUsageOids",
    );

    // Unsupported formats.
    for format in ["XML", "CMS", ""] {
        let (b, _) = basics(script![]);
        let r = json(b.process(
            &req(json!({"format":format,"data":"x","signingParams":{},"signerParams":{"extKeyUsageOids":[]}})),
            &origin("o"),
        ));
        assert_eq!(r["status"], false);
        assert_eq!(r["code"], "INVALID_SIGNING_PARAMS");
        assert_eq!(r["message"], "Invalid signing parameters provided.", "{r}");
        assert!(r.get("details").is_none(), "{r}");
    }

    // Invalid base64 with `decode`: SIGNING_FAILURE before any dialog.
    assert_eq!(
        code(
            json!({"format":"cms","data":"не base64","signingParams":{"decode":true},"signerParams":{"extKeyUsageOids":[]}})
        ),
        "SIGNING_FAILURE"
    );
    let (b, _) = basics(script![]);
    let r = json(b.process(
        &req(raw_args(json!(["YQ==", "YQ= ="]), json!({"decode": true}))),
        &origin("o"),
    ));
    assert_eq!(r["code"], "SIGNING_FAILURE");
    assert_eq!(r["message"], "Signing has failed.");
    // Java's basic decoder: padding optional, no whitespace.
    for ok in ["YQ", "YQ==", "aGVsbG8"] {
        let (b, p) = basics(script![Step::CancelStorage]);
        let r = b.process(
            &req(raw_args(json!(ok), json!({"decode": true}))),
            &origin("o"),
        );
        assert_eq!(r, r#"{"body":{},"status":true}"#, "{ok}");
        assert_eq!(p.storage_prompts().len(), 1);
    }
    for bad in ["YQ=", "YQ==\n", " YQ==", "Y", "YQ===", "YQ-_"] {
        assert_eq!(
            code(raw_args(json!(bad), json!({"decode": true}))),
            "SIGNING_FAILURE",
            "{bad:?}"
        );
    }
    // `details`: the `IllegalArgumentException` of Java's decoder.
    let (b, _) = basics(script![]);
    assert_eq!(
        b.process(
            &req(raw_args(json!("Q"), json!({"decode": true}))),
            &origin("o")
        ),
        r#"{"code":"SIGNING_FAILURE","details":"java.lang.IllegalArgumentException: Input byte[] should at least have 2 bytes for base64 bytes","message":"Signing has failed.","status":false}"#
    );
    let (b, _) = basics(script![]);
    assert_eq!(
        b.process(
            &req(raw_args(json!("YQ-_"), json!({"decode": true}))),
            &origin("o")
        ),
        r#"{"code":"SIGNING_FAILURE","details":"java.lang.IllegalArgumentException: Illegal base64 character 2d","message":"Signing has failed.","status":false}"#
    );

    // Other Java exceptions from argument reading: INVOCATION_ERROR with the exception.
    let details = |args: Value| {
        let (b, p) = basics(script![]);
        let r = json(b.process(&req(args), &origin("o")));
        assert_eq!(r["code"], "INVOCATION_ERROR", "{r}");
        assert!(p.storage_prompts().is_empty());
        r["details"].as_str().unwrap().to_owned()
    };
    let mut args = raw_args(json!("x"), json!({}));
    args["allowedStorages"] = json!(["PKCS12", 5]);
    assert_eq!(
        details(args),
        "java.lang.ClassCastException: java.lang.Integer cannot be cast to java.lang.String"
    );
    let mut args = raw_args(json!("x"), json!({}));
    args["allowedStorages"] = json!([1.5]);
    assert_eq!(
        details(args),
        "java.lang.ClassCastException: java.math.BigDecimal cannot be cast to java.lang.String"
    );
    let mut args = raw_args(json!("x"), json!({}));
    args["signerParams"]["extKeyUsageOids"] = json!([null]);
    assert_eq!(details(args), "java.lang.NullPointerException");
    assert_eq!(
        details(
            json!({"format": 1, "data": "x", "signingParams": {}, "signerParams": {"extKeyUsageOids": []}})
        ),
        "org.json.JSONException: JSONObject[\"format\"] is not a string."
    );
    assert_eq!(
        details(raw_args(json!(["a", 1]), json!({}))),
        "org.json.JSONException: JSONArray[1] is not a String."
    );
}

/// `CommonResponse` as org.json writes it: `body,status` and `code,details,message,status`.
#[test]
fn invoker_reply_key_order_success_and_failure() {
    let (b, _) = basics(script![Step::CancelStorage]);
    assert_eq!(
        b.process(&req(raw_args(json!("u-1"), json!({}))), &origin("o")),
        r#"{"body":{},"status":true}"#
    );
    let (b, _) = basics(script![]);
    assert_eq!(
        b.process(
            &req(raw_args(json!("Q"), json!({"decode": true}))),
            &origin("o")
        ),
        r#"{"code":"SIGNING_FAILURE","details":"java.lang.IllegalArgumentException: Input byte[] should at least have 2 bytes for base64 bytes","message":"Signing has failed.","status":false}"#
    );
}

/// `details` is `Throwable.toString()`: the exception's class, then its message.
#[test]
fn failure_details_have_exception_class() {
    let (b, p) = basics(script![]);
    for api_version in [json!(1), json!(3), json!("3")] {
        assert_eq!(
            b.process(
                &json!({"module": MODULE_NAME, "apiVersion": api_version, "method": "sign", "args": {}})
                    .to_string(),
                &origin("o"),
            ),
            r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: Supported apiVersion is 2","message":"General error.","status":false}"#
        );
    }
    assert!(p.storage_prompts().is_empty());
}

/// An unknown class (`optString`: a number is its text; names match with case) is a
/// `GENERAL_ERROR` with its `IllegalArgumentException`.
#[test]
fn unknown_class_details() {
    let (b, p) = basics(script![]);
    for (class, name) in [
        (json!("NoClass"), "NoClass"),
        (json!("pkiextras"), "pkiextras"),
        (json!(7), "7"),
    ] {
        assert_eq!(
            b.process(
                &json!({"module": MODULE_NAME, "class": class, "method": "sign", "args": {}})
                    .to_string(),
                &origin("o"),
            ),
            format!(
                r#"{{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: {name} is not found","message":"General error.","status":false}}"#
            )
        );
    }
    assert!(p.storage_prompts().is_empty());
}

#[test]
fn method_without_args_demands_arguments() {
    for request in [
        json!({"module": MODULE_NAME, "method": "sign"}),
        json!({"module": MODULE_NAME, "method": "sign", "args": ["x"]}),
        json!({"module": MODULE_NAME, "class": "PKIExtras", "method": "sign", "args": null}),
        json!({"module": MODULE_NAME, "class": "", "method": "sign", "args": "{}"}),
    ] {
        let (b, p) = basics(script![]);
        assert_eq!(
            b.process(&request.to_string(), &origin("o")),
            r#"{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: sign demands arguments","message":"General error.","status":false}"#
        );
        assert!(p.storage_prompts().is_empty());
    }
}

/// A request without a string `method` fails before the dispatcher: a `GENERAL_ERROR` whose
/// `details` is org.json's `JSONException`, not a dropped connection.
#[test]
fn missing_method_is_a_general_error_with_the_json_exception() {
    let not_found = r#"{"code":"GENERAL_ERROR","details":"org.json.JSONException: JSONObject[\"method\"] not found.","message":"General error.","status":false}"#;
    let not_a_string = r#"{"code":"GENERAL_ERROR","details":"org.json.JSONException: JSONObject[\"method\"] is not a string.","message":"General error.","status":false}"#;
    for (request, reply) in [
        (json!({"module": MODULE_NAME}), not_found),
        (json!({"module": MODULE_NAME, "args": {}}), not_found),
        (
            json!({"module": MODULE_NAME, "apiVersion": 3, "class": "NoClass"}),
            not_found,
        ),
        (
            json!({"module": MODULE_NAME, "method": null, "args": {}}),
            not_a_string,
        ),
        (
            json!({"module": MODULE_NAME, "method": 7, "args": {}}),
            not_a_string,
        ),
        (
            json!({"module": MODULE_NAME, "method": ["sign"], "args": {}}),
            not_a_string,
        ),
    ] {
        let (b, p) = basics(script![]);
        assert_eq!(
            b.process(&request.to_string(), &origin("o")),
            reply,
            "{request}"
        );
        assert!(p.storage_prompts().is_empty());
    }
}

#[test]
fn classes() {
    let (b, _) = basics(script![]);
    let r = json(
        b.process(
            &json!({"module": MODULE_NAME, "class": "PKIEssentials", "method": "sign", "args": {}})
                .to_string(),
            &origin("o"),
        ),
    );
    assert_eq!(r["code"], "GENERAL_ERROR");
    assert_eq!(
        r["details"],
        "java.lang.IllegalArgumentException: sign is not defined in PKIEssentials"
    );
    let r = json(b.process(
        &json!({"module": MODULE_NAME, "method": "generateCsr", "args": {}}).to_string(),
        &origin("o"),
    ));
    assert_eq!(
        r["details"],
        "java.lang.IllegalArgumentException: generateCsr is not defined in PKIExtras"
    );
    let r = json(b.process(
        &json!({"module": MODULE_NAME, "class": "PKIExtras", "method": "importCertificate", "args": {}})
            .to_string(),
        &origin("o"),
    ));
    assert_eq!(
        r["details"],
        "java.lang.IllegalArgumentException: importCertificate is not defined in PKIExtras"
    );
    // The method name matches with case; an empty one matches nothing.
    for method in ["Sign", ""] {
        assert_eq!(
            b.process(
                &json!({"module": MODULE_NAME, "method": method, "args": {}}).to_string(),
                &origin("o"),
            ),
            format!(
                r#"{{"code":"GENERAL_ERROR","details":"java.lang.IllegalArgumentException: {method} is not defined in PKIExtras","message":"General error.","status":false}}"#
            )
        );
    }
}

#[test]
fn cosign_detached_cms_error_code() {
    let detached = oncl_pki::cms::sign(
        &entry("user-gost2004-sign"),
        b"doc",
        &SignOptions {
            encapsulate: false,
            digested: false,
            signing_time: OffsetDateTime::now_utc(),
        },
    )
    .unwrap();
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(cms_args(
            json!(STANDARD.encode(&detached)),
            json!({"decode": true}),
        )),
        &origin("o"),
    ));
    assert_eq!(r["status"], false);
    assert_eq!(r["code"], "CMS_NO_ENCAPSULATED_DATA");
    assert_eq!(r["message"], "CMS_NO_ENCAPSULATED_DATA", "{r}");
}

/// Replaces sha256WithRSAEncryption (1.2.840.113549.1.1.11) by 1.2.840.113549.1.1.`last`
/// in a DER certificate: same length, signature left as is.
fn with_rsa_signature_oid(cert: &[u8], last: u8) -> Vec<u8> {
    const SHA256_RSA: [u8; 11] = [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 0x0b];
    let mut out = cert.to_vec();
    let mut patched = 0;
    for i in 0..=out.len() - SHA256_RSA.len() {
        if out[i..i + SHA256_RSA.len()] == SHA256_RSA {
            out[i + SHA256_RSA.len() - 1] = last;
            patched += 1;
        }
    }
    assert_eq!(
        patched, 2,
        "tbsCertificate.signature and signatureAlgorithm"
    );
    out
}

/// A PKCS#12 file (`Qwerty12`) with the OpenSSL RSA key under its certificate whose
/// signature algorithm is patched to 1.2.840.113549.1.1.`last`.
fn rsa_store_with_signature_oid(last: u8) -> PathBuf {
    let cert_der = with_rsa_signature_oid(&read(fixture("openssl/rsa.cer")), last);
    let p12 = write(
        &[WriteEntry {
            alias: "rsa".to_owned(),
            pkcs8_der: read(fixture("openssl/rsa.pk8.der")),
            cert_der: Some(cert_der),
        }],
        &[],
        "Qwerty12",
        &WriteOptions::default(),
        &mut |buf: &mut [u8]| buf.fill(7),
    )
    .unwrap();
    let path =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("oncl-flows-rsa-oid-{last}.p12"));
    std::fs::write(&path, p12).unwrap();
    path
}

/// A clock inside the validity of `openssl/rsa.cer`.
fn inside_rsa_validity() -> OffsetDateTime {
    let cert = oncl_pki::cert::parse(&read(fixture("openssl/rsa.cer"))).unwrap();
    let info = cert_info(&cert);
    info.not_before + (info.not_after - info.not_before) / 2
}

#[test]
fn sha1_with_rsa_certificate_is_not_upgraded() {
    let path = rsa_store_with_signature_oid(5);
    let entries = load(&read(&path), "Qwerty12").unwrap();
    assert_eq!(
        cert_info(&entries[0].cert).signing_alg(),
        Ok(SigAlg::RsaSha1)
    );

    // Refused for cms and, unlike the original (rsa-sha1), for xml too.
    for args in [
        cms_args(json!("x"), json!({})),
        xml_args(json!("<a/>"), json!({})),
    ] {
        let s = setup(script![storage_at(&path, "Qwerty12"), key(0)], None);
        let b = s.basics.with_clock(inside_rsa_validity);
        let r = json(b.process(&req(args), &origin("o")));
        assert_eq!(r["status"], false, "{r}");
        assert_eq!(r["code"], "UNKNOWN_ALGORITHM");
        assert_eq!(r["message"], "UNKNOWN_ALGORITHM", "{r}");
    }
}

#[test]
fn xml_unknown_certificate_algorithm_is_incorrect_algorithm() {
    // sha512WithRSAEncryption: `XMLUtil` throws IllegalArgumentException("Incorrect
    // algorithm: …"), which `PKIExtras.sign` reports as SIGNING_FAILURE.
    let path = rsa_store_with_signature_oid(13);
    let s = setup(script![storage_at(&path, "Qwerty12"), key(0)], None);
    let b = s.basics.with_clock(inside_rsa_validity);
    let r = json(b.process(&req(xml_args(json!("<a/>"), json!({}))), &origin("o")));
    assert_eq!(
        r,
        json!({
            "status": false,
            "code": "SIGNING_FAILURE",
            "message": "Signing has failed.",
            "details": "java.lang.IllegalArgumentException: Incorrect algorithm: 1.2.840.113549.1.1.13",
        })
    );

    // `XMLUtil` parses before it looks at the algorithm: malformed XML wins.
    let s = setup(script![storage_at(&path, "Qwerty12"), key(0)], None);
    let b = s.basics.with_clock(inside_rsa_validity);
    let r = json(b.process(&req(xml_args(json!("<a>"), json!({}))), &origin("o")));
    assert_eq!(r["code"], "UNABLE_TO_PARSE_XML", "{r}");
}

#[test]
fn xml_leading_comment_and_pi_are_kept_and_signed() {
    // The original appends to the document's first child and fails here; we sign.
    let doc = "<?xml version=\"1.0\"?>\n<!-- c --><?pi x?>\n<a>1</a>";
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(&req(xml_args(json!(doc), json!({}))), &origin("o")));
    let signed = r["body"]["result"][0].as_str().unwrap();
    assert!(
        signed.starts_with("<!-- c --><?pi x?>\n<a>1<ds:Signature"),
        "{r}"
    );
    oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap();
}

#[test]
fn unknown_storages_dropped_and_recent_path_used() {
    let recent = PathBuf::from("C:/keys/old.p12");
    let s = setup(script![Step::CancelStorage], Some(recent.clone()));
    let mut args = raw_args(json!("x"), json!({}));
    args["allowedStorages"] = json!(["PKCS12", "FOO", "pkcs12", null, "JKS", "PKCS12"]);
    s.basics.process(&req(args), &origin("o"));
    let prompt = &s.prompter.storage_prompts()[0];
    // Unknown names and null are dropped; duplicates stay, as in the original.
    assert_eq!(
        prompt.storages,
        [StorageKind::Pkcs12, StorageKind::Jks, StorageKind::Pkcs12]
    );
    assert_eq!(prompt.recent_path, Some(recent.clone()));
    assert_eq!(s.recent.saved(), None);

    for allowed in [None, Some(Value::Null)] {
        let s = setup(script![Step::CancelStorage], None);
        let mut args = raw_args(json!("x"), json!({}));
        if let Some(v) = allowed {
            args["allowedStorages"] = v;
        }
        s.basics.process(&req(args), &origin("o"));
        let prompt = &s.prompter.storage_prompts()[0];
        assert_eq!(prompt.storages, StorageKind::all());
        assert_eq!(prompt.recent_path, None);
    }

    // After a successful open the path is saved.
    let s = setup(
        script![storage("user-gost2015-sign", "Qwerty12"), key(0)],
        Some(recent),
    );
    let mut args = raw_args(json!("x"), json!({}));
    args["allowedStorages"] = json!(["AKKaztokenStore", "PKCS12"]);
    let r = json(s.basics.process(&req(args), &origin("o")));
    assert_eq!(r["status"], true);
    assert_eq!(
        s.prompter.storage_prompts()[0].storages,
        [StorageKind::Token("AKKaztokenStore"), StorageKind::Pkcs12]
    );
    assert_eq!(s.recent.saved(), Some(synthetic("user-gost2015-sign").path));
}

#[test]
fn storage_kinds() {
    let names: Vec<_> = StorageKind::all().iter().map(StorageKind::name).collect();
    assert_eq!(
        names,
        [
            "AKKaztokenStore",
            "AKKZIDCardStore",
            "AKEToken72KStore",
            "AKEToken5110Store",
            "AKJaCartaStore",
            "AKAKEYStore",
            "PKCS12",
            "JKS",
            "ABCloudServiceStore",
        ]
    );
    for kind in StorageKind::all() {
        assert_eq!(StorageKind::from_name(kind.name()), Some(kind));
        assert_eq!(
            kind.readable(),
            matches!(kind, StorageKind::Pkcs12 | StorageKind::Jks)
        );
        assert_eq!(kind.writable(), kind == StorageKind::Pkcs12);
    }
    assert_eq!(StorageKind::from_name("PKCS12"), Some(StorageKind::Pkcs12));
    assert_eq!(StorageKind::from_name("JKS"), Some(StorageKind::Jks));
    assert_eq!(StorageKind::from_name("pkcs12"), None);
    assert_eq!(StorageKind::from_name("AKEToken"), None);
}

#[test]
fn origin_and_locale_reach_the_prompts() {
    let (b, p) = basics(script![Step::CancelStorage]);
    let mut args = raw_args(json!("x"), json!({}));
    args["locale"] = json!("ru");
    b.process(&req(args), &AddInfo::default());
    assert_eq!(p.storage_prompts()[0].origin, "UNIDENTIFIED");
    assert_eq!(p.storage_prompts()[0].locale, Locale::Ru);
}

#[test]
fn sign_flows_are_serialized() {
    let barrier = Arc::new(Barrier::new(2));
    let s = setup(
        script![
            Step::Wait(barrier.clone()),
            storage("user-gost2015-sign", "Qwerty12"),
            key(0),
            storage("user-gost2015-sign", "Qwerty12"),
            key(0),
        ],
        None,
    );
    let basics = Arc::new(s.basics);
    let prompter = s.prompter;
    let run = |o: &'static str| {
        let basics = Arc::clone(&basics);
        thread::spawn(move || {
            json(basics.process(&req(cms_args(json!("x"), json!({}))), &origin(o)))
        })
    };

    let a = run("a");
    let deadline = Instant::now() + Duration::from_secs(30);
    while prompter.storage_prompts().is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    // A records its prompt before it takes the `Wait` step, so once it is seen A will reach
    // the barrier. Observe now, release A, assert after: a failed assertion must not leave
    // A blocked on the barrier.
    let a_shown = !prompter.storage_prompts().is_empty();
    let b = run("b");
    // B waits for A's flow instead of showing a second dialog.
    thread::sleep(Duration::from_millis(300));
    let storage_prompts_while_a_open = prompter.storage_prompts().len();
    let key_prompts_while_a_open = prompter.key_prompts().len();
    if a_shown {
        barrier.wait();
    }
    assert!(a_shown, "A never showed its dialog");
    assert_eq!(storage_prompts_while_a_open, 1);
    assert_eq!(key_prompts_while_a_open, 0);

    assert_eq!(a.join().unwrap()["status"], true);
    assert_eq!(b.join().unwrap()["status"], true);
    let storage_origins: Vec<String> = prompter
        .storage_prompts()
        .into_iter()
        .map(|p| p.origin)
        .collect();
    let key_origins: Vec<String> = prompter
        .key_prompts()
        .into_iter()
        .map(|p| p.origin)
        .collect();
    assert_eq!(storage_origins, ["a", "b"]);
    assert_eq!(key_origins, ["a", "b"]);
}

#[test]
fn locale_mapping() {
    assert_eq!(Locale::from_arg(Some("ru")), Locale::Ru);
    assert_eq!(Locale::from_arg(Some("kk")), Locale::Kk);
    assert_eq!(Locale::from_arg(Some("de")), Locale::En);
    assert_eq!(Locale::from_arg(Some("en")), Locale::En);
    assert_eq!(Locale::from_arg(Some("")), Locale::En);
    // Java's `new Locale(…)` lower-cases the language.
    assert_eq!(Locale::from_arg(Some("RU")), Locale::Ru);
    assert_eq!(Locale::from_arg(None), Locale::Kk);
}

/// The eGov login request as the portal sends it, plus `chain: []` so the synthetic key is
/// not disabled by the embedded production CAs.
fn egov_login_args() -> Value {
    json!({
        "data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><login><client-type>PORTAL</client-type></login>",
        "allowedStorages": ["PKCS12", "AKKaztokenStore", "AKKZIDCardStore"],
        "format": "xml",
        "signingParams": {},
        "signerParams": {"extKeyUsageOids": ["1.3.6.1.5.5.7.3.2"], "chain": []},
        "locale": "ru",
    })
}

fn xml_args(data: Value, signing_params: Value) -> Value {
    json!({
        "format": "xml",
        "data": data,
        "signingParams": signing_params,
        "signerParams": {"extKeyUsageOids": [], "chain": []},
    })
}

#[test]
fn xml_egov_login_signs_with_the_chosen_key() {
    let (b, p) = basics(script![storage("user-gost2015-auth", "Qwerty12"), key(0)]);
    let r = json(b.process(&req(egov_login_args()), &origin("https://idp.egov.kz")));
    // `{"body":{"result":["<signed xml>"]},"status":true}`, nothing more.
    assert_eq!(r.as_object().unwrap().len(), 2, "{r}");
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(r["body"].as_object().unwrap().len(), 1, "{r}");
    let result = r["body"]["result"].as_array().unwrap();
    assert_eq!(result.len(), 1);
    let signed = result[0].as_str().unwrap();
    assert!(
        signed.starts_with("<login><client-type>PORTAL</client-type><ds:Signature"),
        "{signed}"
    );
    let infos = oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].cert, entry("user-gost2015-auth").cert);
    assert_eq!(infos[0].sig_alg, SigAlg::Gost2015_512);
    assert_eq!(p.storage_prompts()[0].action, Action::Authenticate);
    assert_eq!(
        p.key_prompts()[0].candidates[0].availability,
        Availability::Enabled
    );
}

#[test]
fn xml_array_of_documents() {
    let (b, _) = basics(script![storage("user-gost2004-sign", "Qwerty12"), key(0)]);
    let docs = ["<a>1</a>", "<b xmlns=\"urn:x\"><c/></b>"];
    let r = json(b.process(&req(xml_args(json!(docs), json!({}))), &origin("o")));
    assert_eq!(r.as_object().unwrap().len(), 2, "{r}");
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(r["body"].as_object().unwrap().len(), 1, "{r}");
    let result = r["body"]["result"].as_array().unwrap();
    assert_eq!(result.len(), 2, "{r}");
    for (signed, doc) in result.iter().zip(docs) {
        let signed = signed.as_str().unwrap();
        let root_end = doc.rfind("</").unwrap();
        assert!(signed.starts_with(&doc[..root_end]), "{signed}");
        let infos = oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap();
        assert_eq!(infos[0].cert, entry("user-gost2004-sign").cert);
    }
}

#[test]
fn xml_data_is_never_decoded() {
    // `decode` is not read for xml: base64 text is signed as the (malformed) XML it is.
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(xml_args(json!("PGEvPg=="), json!({"decode": true}))),
        &origin("o"),
    ));
    assert_eq!(r["code"], "UNABLE_TO_PARSE_XML", "{r}");
}

#[test]
fn xml_allow_expired_makes_expired_keys_selectable() {
    let (b, p) = basics(script![
        storage("inter-expired-gost2015-sign", "Qwerty12"),
        key(0)
    ]);
    let r = json(b.process(
        &req(xml_args(json!("<a/>"), json!({"allowExpired": true}))),
        &origin("o"),
    ));
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(
        p.key_prompts()[0].candidates[0].availability,
        Availability::Enabled
    );
    let signed = r["body"]["result"][0].as_str().unwrap();
    oncl_pki::xmldsig::verify(signed.as_bytes()).unwrap();

    // Without it (and for other formats) the expired key stays unselectable.
    for args in [
        xml_args(json!("<a/>"), json!({})),
        cms_args(json!("x"), json!({"allowExpired": true})),
    ] {
        let (b, p) = basics(script![
            storage("inter-expired-gost2015-sign", "Qwerty12"),
            key(0)
        ]);
        let r = b.process(&req(args), &origin("o"));
        assert_eq!(r, r#"{"body":{},"status":true}"#);
        assert_eq!(
            p.key_prompts()[0].candidates[0].availability,
            Availability::Expired
        );
    }
}

#[test]
fn xml_malformed_is_unable_to_parse_xml_after_the_dialog() {
    for bad in ["<a>", "not xml", "<!DOCTYPE a><a/>", "<a/><b/>"] {
        let (b, p) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
        let r = json(b.process(&req(xml_args(json!(bad), json!({}))), &origin("o")));
        // `ProviderUtilFailure(UNABLE_TO_PARSE_XML, <parser error>)`, as the original: the
        // message and the `ProviderUtilException` carrying it.
        assert_eq!(r.as_object().unwrap().len(), 4, "{r}");
        assert_eq!(r["status"], false, "{r}");
        assert_eq!(r["code"], "UNABLE_TO_PARSE_XML", "{r}");
        let message = r["message"].as_str().unwrap();
        assert!(!message.is_empty(), "{r}");
        assert_eq!(
            r["details"],
            format!("kz.gov.pki.provider.exception.ProviderUtilException: {message}"),
            "{r}"
        );
        // Parsed after the key was chosen, as `XMLUtil.createXmlSignature` is.
        assert_eq!(p.storage_prompts().len(), 1, "{bad}");
        assert_eq!(p.key_prompts().len(), 1, "{bad}");
    }
    // The first bad document fails the request.
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let r = json(b.process(
        &req(xml_args(json!(["<a/>", "<b>"]), json!({}))),
        &origin("o"),
    ));
    assert_eq!(r["code"], "UNABLE_TO_PARSE_XML", "{r}");
}

/// A document that ends inside its root element: the JDK parser's `SAXParseException` as
/// the message, the `ProviderUtilException` carrying it as `details`.
#[test]
fn xml_unclosed_root_has_the_jdk_parsers_text() {
    let (b, _) = basics(script![storage("user-gost2015-sign", "Qwerty12"), key(0)]);
    let reply = b.process(
        &req(xml_args(json!("<doc>\n<open>"), json!({}))),
        &origin("o"),
    );
    let sax = "org.xml.sax.SAXParseException; lineNumber: 2; columnNumber: 7; \
               XML document structures must start and end within the same entity.";
    assert_eq!(
        reply,
        format!(
            r#"{{"code":"UNABLE_TO_PARSE_XML","details":"kz.gov.pki.provider.exception.ProviderUtilException: {sax}","message":"{sax}","status":false}}"#
        )
    );
}
