//! `PKIExtras.sign` key validation: `signerParams.chain` (path building to the embedded NCA
//! CAs, none, or the given CAs), the OCSP status of the keys through the module's transport,
//! `signingParams.allowRevoked`, and the parse errors of `chain`. The synthetic intermediate
//! PKI (`inter-gost2015` under `root-gost2015`) has its responder at
//! `http://ocsp.synthetic.test`, played by `MockOcsp`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_basics::{
    Availability, Basics, ChainPolicy, DisabledReason, KeyFilter, MODULE_NAME, OCSP_DEADLINE,
    availabilities,
};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::http::{GetOptions, HttpError, HttpReply, HttpTransport};
use oncl_pki::info::{CertInfo, cert_info};
use oncl_pki::ocsp::{CertStatus, MockOcsp, OcspTamper};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::{fixture, read, synthetic, synthetic_cert};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use time::macros::datetime;

const OCSP_URL: &str = "http://ocsp.synthetic.test/";
/// When `MockOcsp` says `inter-revoked-…` was revoked.
const REVOKED_AT: OffsetDateTime = datetime!(2026-02-03 04:05:06 UTC);
const EMPTY: &str = r#"{"status":true,"body":{}}"#;

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn serial(name: &str) -> String {
    cert_info(&entry(name).cert).serial_hex
}

/// The synthetic responder, answering `revoked` for `inter-revoked-…` and `good` otherwise.
fn responder() -> MockOcsp {
    MockOcsp::new(entry("ocsp-gost2015")).status(
        &serial("inter-revoked-gost2015-sign"),
        CertStatus::Revoked {
            time: REVOKED_AT,
            reason: Some(1),
        },
    )
}

/// PEM of the synthetic certificate `name`, lines ended by `nl`.
fn pem(name: &str, nl: &str) -> String {
    let body = STANDARD.encode(synthetic_cert(name));
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----{nl}{}{nl}-----END CERTIFICATE-----{nl}",
        lines.join(nl)
    )
}

/// `chain` of the intermediate PKI: the intermediate CA, then the root.
fn inter_chain() -> Value {
    json!([pem("inter-gost2015", "\n"), pem("root-gost2015", "\n")])
}

/// A `sign` request of `format` over `"x"`, with `chain` unless `None`.
fn args(format: &str, chain: Option<Value>, signing_params: Value) -> Value {
    let mut args = json!({
        "format": format,
        "data": "x",
        "signingParams": signing_params,
        "signerParams": {"extKeyUsageOids": []},
    });
    if let Some(chain) = chain {
        args["signerParams"]["chain"] = chain;
    }
    args
}

fn process(basics: &Basics, args: Value) -> String {
    let request = json!({"module": MODULE_NAME, "method": "sign", "args": args}).to_string();
    basics.process(
        &request,
        &AddInfo {
            origin: Some("https://x.kz".to_owned()),
        },
    )
}

/// A module answering the prompts with `steps`, its HTTP transport `http`.
fn module(steps: Vec<Step>, http: Arc<dyn HttpTransport>) -> (Basics, Arc<ScriptedPrompter>) {
    let prompter = Arc::new(ScriptedPrompter::new(steps));
    let basics = Basics::new(
        prompter.clone(),
        Arc::new(MemoryRecentPath::new(None)),
        http,
    );
    (basics, prompter)
}

fn open(store: &str) -> Step {
    Step::Storage {
        path: synthetic(store).path,
        password: "Qwerty12".to_owned(),
    }
}

/// The availability the key dialog shows for the only key of `store` when `args` are
/// signed with `http` as the transport; the dialog is cancelled.
fn shown(store: &str, args: Value, http: Arc<dyn HttpTransport>) -> Availability {
    let (basics, prompter) = module(vec![open(store), Step::CancelKey], http);
    assert_eq!(process(&basics, args), EMPTY);
    let prompts = prompter.key_prompts();
    assert_eq!(prompts.len(), 1);
    prompts[0].candidates[0].availability.clone()
}

/// The reply to `args` sent before any dialog.
fn refused(args: Value) -> String {
    let ocsp = Arc::new(responder());
    let (basics, prompter) = module(vec![open("user-gost2015-sign")], ocsp.clone());
    let reply = process(&basics, args);
    assert!(prompter.storage_prompts().is_empty(), "no dialog: {reply}");
    assert!(ocsp.calls().is_empty());
    reply
}

const CERTIFICATE_PARSING_FAILURE: &str = r#"{"status":false,"code":"CERTIFICATE_PARSING_FAILURE","message":"Certificate parsing failure."}"#;

#[test]
fn default_chain_disables_synthetic_key() {
    // Without `chain` (or with `null`, or anything but an array, as `optJSONArray` reads
    // it) the path goes to the embedded NCA CAs, which the synthetic keys do not reach.
    for chain in [None, Some(Value::Null), Some(json!(5)), Some(json!("[]"))] {
        let ocsp = Arc::new(responder());
        for store in ["user-gost2015-sign", "inter-user-gost2015-sign"] {
            assert_eq!(
                shown(store, args("cms", chain.clone(), json!({})), ocsp.clone()),
                Availability::Disabled(vec![DisabledReason::Chain]),
                "{store}, chain {chain:?}"
            );
        }
        // A disabled key is not asked about.
        assert!(ocsp.calls().is_empty());
    }
    // The chain reason comes after the others.
    let mut request = args("raw", None, json!({}));
    request["signerParams"]["iin"] = json!("1");
    assert_eq!(
        shown("user-gost2015-sign", request, Arc::new(responder())),
        Availability::Disabled(vec![DisabledReason::Iin, DisabledReason::Chain])
    );
}

#[test]
fn empty_chain_skips_pkix_and_ocsp() {
    let ocsp = Arc::new(responder());
    for store in [
        "user-gost2015-sign",
        "inter-user-gost2015-sign",
        "inter-revoked-gost2015-sign",
    ] {
        for format in ["cms", "raw"] {
            assert_eq!(
                shown(
                    store,
                    args(format, Some(json!([])), json!({})),
                    ocsp.clone()
                ),
                Availability::Enabled,
                "{store} {format}"
            );
        }
    }
    assert!(ocsp.calls().is_empty(), "{:?}", ocsp.calls());
}

#[test]
fn custom_chain_enables_and_revoked_is_marked() {
    let ocsp = Arc::new(responder());
    assert_eq!(
        shown(
            "inter-user-gost2015-sign",
            args("cms", Some(inter_chain()), json!({})),
            ocsp.clone()
        ),
        Availability::Enabled
    );
    assert_eq!(
        shown(
            "inter-revoked-gost2015-sign",
            args("cms", Some(inter_chain()), json!({})),
            ocsp.clone()
        ),
        Availability::Revoked { time: REVOKED_AT }
    );
    let calls = ocsp.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls.iter().all(|c| c.starts_with(OCSP_URL)), "{calls:?}");

    // Keys outside the given CAs are disabled: a root-issued key with only the
    // intermediate CA, the intermediate's keys with only the root.
    assert_eq!(
        shown(
            "user-gost2004-sign",
            args("cms", Some(inter_chain()), json!({})),
            ocsp.clone()
        ),
        Availability::Disabled(vec![DisabledReason::Chain])
    );
    assert_eq!(
        shown(
            "inter-user-gost2015-sign",
            args("cms", Some(json!([pem("root-gost2015", "\n")])), json!({})),
            ocsp.clone()
        ),
        Availability::Disabled(vec![DisabledReason::Chain])
    );
    // A root-issued key without OCSP responder: nothing to ask.
    assert_eq!(
        shown(
            "user-gost2015-sign",
            args("cms", Some(json!([pem("root-gost2015", "\n")])), json!({})),
            ocsp.clone()
        ),
        Availability::Enabled
    );
    assert_eq!(ocsp.calls().len(), 2);

    // The intermediate CA alone is the anchor, as in the original: its keys are enabled,
    // checked by OCSP (the responder chains to it as well), and others stay disabled.
    let inter_only = || Some(json!([pem("inter-gost2015", "\n")]));
    assert_eq!(
        shown(
            "inter-user-gost2015-sign",
            args("cms", inter_only(), json!({})),
            ocsp.clone()
        ),
        Availability::Enabled
    );
    assert_eq!(
        shown(
            "inter-revoked-gost2015-sign",
            args("cms", inter_only(), json!({})),
            ocsp.clone()
        ),
        Availability::Revoked { time: REVOKED_AT }
    );
    assert_eq!(
        shown(
            "user-gost2015-sign",
            args("cms", inter_only(), json!({})),
            ocsp.clone()
        ),
        Availability::Disabled(vec![DisabledReason::Chain])
    );
    assert_eq!(ocsp.calls().len(), 4);
}

#[test]
fn expired_key_is_validated_at_its_not_after_and_still_checked() {
    // Valid 2025-01-01 … 2026-01-01 inside the intermediate CA: the path holds at its
    // notAfter, so the key is expired, not disabled, and its revocation is still asked.
    let ocsp = Arc::new(responder());
    assert_eq!(
        shown(
            "inter-expired-gost2015-sign",
            args("cms", Some(inter_chain()), json!({})),
            ocsp.clone()
        ),
        Availability::Expired
    );
    assert_eq!(ocsp.calls().len(), 1);
    // Revoked wins over expired.
    let revoked = Arc::new(responder().status(
        &serial("inter-expired-gost2015-sign"),
        CertStatus::Revoked {
            time: REVOKED_AT,
            reason: None,
        },
    ));
    assert_eq!(
        shown(
            "inter-expired-gost2015-sign",
            args("cms", Some(inter_chain()), json!({})),
            revoked
        ),
        Availability::Revoked { time: REVOKED_AT }
    );
}

#[test]
fn allow_revoked_skips_ocsp() {
    let ocsp = Arc::new(responder());
    for allow in [json!(true), json!("TRUE")] {
        assert_eq!(
            shown(
                "inter-revoked-gost2015-sign",
                args("cms", Some(inter_chain()), json!({"allowRevoked": allow})),
                ocsp.clone()
            ),
            Availability::Enabled
        );
    }
    assert!(ocsp.calls().is_empty());
    // The path is still required.
    assert_eq!(
        shown(
            "inter-revoked-gost2015-sign",
            args("cms", None, json!({"allowRevoked": true})),
            ocsp.clone()
        ),
        Availability::Disabled(vec![DisabledReason::Chain])
    );
    // `false` or no boolean: checked.
    assert_eq!(
        shown(
            "inter-revoked-gost2015-sign",
            args("cms", Some(inter_chain()), json!({"allowRevoked": 1})),
            ocsp.clone()
        ),
        Availability::Revoked { time: REVOKED_AT }
    );
    assert_eq!(ocsp.calls().len(), 1);
}

#[test]
fn raw_always_checks_ocsp() {
    let ocsp = Arc::new(responder());
    assert_eq!(
        shown(
            "inter-revoked-gost2015-sign",
            args("raw", Some(inter_chain()), json!({"allowRevoked": true})),
            ocsp.clone()
        ),
        Availability::Revoked { time: REVOKED_AT }
    );
    assert_eq!(ocsp.calls().len(), 1);
}

/// A transport that never answers within any timeout: it ignores [`GetOptions`].
struct Stuck;

impl HttpTransport for Stuck {
    fn get(&self, _: &str) -> Result<HttpReply, HttpError> {
        thread::sleep(Duration::from_secs(30));
        Err(HttpError("stuck".to_owned()))
    }

    fn get_with(&self, url: &str, _: GetOptions) -> Result<HttpReply, HttpError> {
        self.get(url)
    }

    fn post(&self, url: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
        self.get(url)
    }
}

fn key(name: &str) -> (Certificate, CertInfo) {
    let cert = entry(name).cert;
    let info = cert_info(&cert);
    (cert, info)
}

fn inter_filter() -> KeyFilter {
    let cas = ["inter-gost2015", "root-gost2015"]
        .map(|name| cert::parse(&synthetic_cert(name)).unwrap())
        .to_vec();
    KeyFilter {
        ext_key_usages: BTreeSet::new(),
        iin: String::new(),
        bin: String::new(),
        serial_number: String::new(),
        allow_expired: false,
        chain: ChainPolicy::Custom(Arc::new(CaSet::new(cas))),
        allow_revoked: false,
    }
}

#[test]
fn ocsp_unreachable_keeps_key_enabled_within_6_s() {
    // A responder hanging past the request timeout: the request fails, the key stays
    // enabled and the dialog opens.
    let ocsp = Arc::new(responder().tamper(OcspTamper::Hang(Duration::from_secs(30))));
    assert_eq!(
        shown(
            "inter-revoked-gost2015-sign",
            args("cms", Some(inter_chain()), json!({})),
            ocsp.clone()
        ),
        Availability::Enabled
    );
    assert_eq!(ocsp.calls().len(), 1);

    // A transport ignoring the timeout: every key is checked at once, and the checks are
    // abandoned at the deadline, which counts from the start of the key checks (path
    // building included): the dialog is never more than 6 s away.
    let keys = [
        key("inter-user-gost2015-sign"),
        key("inter-revoked-gost2015-sign"),
        key("inter-noaki-gost2015-sign"),
    ];
    let http: Arc<dyn HttpTransport> = Arc::new(Stuck);
    let start = Instant::now();
    let shown = availabilities(&inter_filter(), &keys, &http, OffsetDateTime::now_utc());
    let elapsed = start.elapsed();
    assert_eq!(shown, vec![Availability::Enabled; 3]);
    assert_eq!(OCSP_DEADLINE, Duration::from_secs(6));
    assert!(
        elapsed >= OCSP_DEADLINE && elapsed < OCSP_DEADLINE + Duration::from_secs(1),
        "{elapsed:?}"
    );
}

#[test]
fn ocsp_checks_run_in_parallel() {
    let keys = [
        key("inter-user-gost2015-sign"),
        key("inter-revoked-gost2015-sign"),
        key("inter-noaki-gost2015-sign"),
    ];
    let expected = [
        Availability::Enabled,
        Availability::Revoked { time: REVOKED_AT },
        Availability::Enabled,
    ];
    let timed = |ocsp: MockOcsp| {
        let ocsp = Arc::new(ocsp);
        let http: Arc<dyn HttpTransport> = ocsp.clone();
        let start = Instant::now();
        let shown = availabilities(&inter_filter(), &keys, &http, OffsetDateTime::now_utc());
        let elapsed = start.elapsed();
        assert_eq!(shown, expected);
        assert_eq!(ocsp.calls().len(), 3);
        elapsed
    };
    // Path building, signing and checking the answers, without network delay.
    let baseline = timed(responder());
    // Each answer delayed by `hang`: at once they add about `hang`, one after the other
    // they would add three times as much.
    let hang = Duration::from_millis(1500);
    let elapsed = timed(responder().tamper(OcspTamper::Hang(hang)));
    assert!(
        elapsed < baseline + 2 * hang,
        "{elapsed:?}, baseline {baseline:?}"
    );
}

#[test]
fn tampered_ocsp_never_revokes() {
    let check = |ocsp: MockOcsp| {
        let ocsp = Arc::new(ocsp);
        let http: Arc<dyn HttpTransport> = ocsp.clone();
        let shown = availabilities(
            &inter_filter(),
            &[key("inter-revoked-gost2015-sign")],
            &http,
            OffsetDateTime::now_utc(),
        );
        assert_eq!(ocsp.calls().len(), 1);
        shown.into_iter().next().unwrap()
    };
    let hour = Duration::from_secs(3600);
    // Answers `ocsp::check` refuses: the key stays enabled.
    for tamper in [
        OcspTamper::WrongKey,
        OcspTamper::NoCerts,
        OcspTamper::OtherResponderId,
        OcspTamper::OtherCertId,
        OcspTamper::NoSingleResponse,
        OcspTamper::Stale,
        OcspTamper::FutureThisUpdate,
        OcspTamper::ThisUpdateAhead(hour),
        OcspTamper::NoNextUpdate { age: hour },
        OcspTamper::HttpStatus(503),
        OcspTamper::ContentType("text/html"),
        OcspTamper::Garbage,
    ] {
        assert_eq!(
            check(responder().tamper(tamper)),
            Availability::Enabled,
            "{tamper:?}"
        );
    }
    // A responder without id-pkix-ocsp-nocheck is not trusted.
    let nocheckless = MockOcsp::new(entry("ocsp-nocheckless-gost2015")).status(
        &serial("inter-revoked-gost2015-sign"),
        CertStatus::Revoked {
            time: REVOKED_AT,
            reason: None,
        },
    );
    assert_eq!(check(nocheckless), Availability::Enabled);
    // Variants that still give a valid answer revoke.
    let minute = Duration::from_secs(60);
    for tamper in [
        OcspTamper::None,
        OcspTamper::ByKeyResponderId,
        OcspTamper::ContentType("application/ocsp-response"),
        OcspTamper::ThisUpdateAhead(minute),
        OcspTamper::NoNextUpdate { age: minute },
        OcspTamper::Hang(Duration::from_millis(100)),
    ] {
        assert_eq!(
            check(responder().tamper(tamper)),
            Availability::Revoked { time: REVOKED_AT },
            "{tamper:?}"
        );
    }
}

#[test]
fn chain_entry_forms() {
    let der = synthetic_cert("root-gost2015");
    let base64 = STANDARD.encode(&der);
    let spaced: String = base64
        .as_bytes()
        .chunks(10)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" \n\t");
    let unpadded = base64.trim_end_matches('=').to_owned();
    for entry in [
        pem("root-gost2015", "\n"),
        pem("root-gost2015", "\r\n"),
        format!("  \r\n{}  ", pem("root-gost2015", "\r\n")),
        pem("root-gost2015", "\n").replace('\n', ""),
        base64.clone(),
        spaced,
        format!("\r\n{base64}\r\n"),
        unpadded,
    ] {
        let ocsp = Arc::new(responder());
        assert_eq!(
            shown(
                "user-gost2015-sign",
                args("cms", Some(json!([entry])), json!({})),
                ocsp
            ),
            Availability::Enabled,
            "{entry:?}"
        );
    }
}

#[test]
fn chain_garbage_is_certificate_parsing_failure() {
    // A PEM private key (PKCS#8) instead of a certificate.
    let key_label = ["PRIVATE", "KEY"].join(" ");
    let key_pem = format!(
        "-----BEGIN {key_label}-----\n{}\n-----END {key_label}-----\n",
        STANDARD.encode(read(fixture("openssl/rsa.pk8.der")))
    );
    let root = pem("root-gost2015", "\n");
    let truncated = root.replace("-----END CERTIFICATE-----", "");
    for chain in [
        json!([""]),
        json!(["abc"]),
        json!(["   "]),
        json!([key_pem]),
        json!([truncated]),
        json!(["-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"]),
        // Every entry is parsed: a good one first does not help.
        json!([root, "abc"]),
        // The first bad entry decides.
        json!(["abc", 5]),
    ] {
        for format in ["cms", "raw"] {
            assert_eq!(
                refused(args(format, Some(chain.clone()), json!({}))),
                CERTIFICATE_PARSING_FAILURE,
                "{chain}"
            );
        }
    }
}

#[test]
fn chain_non_string_is_invocation_error() {
    // The original casts each entry with `(String) e` and hands it to
    // `X509Util.getX509Certificate`, outside the catch of CERTIFICATE_PARSING_FAILURE.
    let class_cast = |class: &str| {
        format!("java.lang.ClassCastException: {class} cannot be cast to java.lang.String")
    };
    let root = pem("root-gost2015", "\n");
    for (chain, details) in [
        (json!([5]), class_cast("java.lang.Integer")),
        (json!([1.5]), class_cast("java.math.BigDecimal")),
        (json!([true]), class_cast("java.lang.Boolean")),
        (json!([{}]), class_cast("java.util.HashMap")),
        (json!([[root]]), class_cast("java.util.ArrayList")),
        (json!([root, 5]), class_cast("java.lang.Integer")),
        (json!([5, "abc"]), class_cast("java.lang.Integer")),
        (json!([null]), "java.lang.NullPointerException".to_owned()),
    ] {
        for format in ["cms", "raw"] {
            let reply: Value =
                serde_json::from_str(&refused(args(format, Some(chain.clone()), json!({}))))
                    .unwrap();
            assert_eq!(
                reply,
                json!({
                    "status": false,
                    "code": "INVOCATION_ERROR",
                    "message": "An invoked method threw an exception.",
                    "details": details,
                }),
                "{chain}"
            );
        }
    }
}

#[test]
fn selecting_revoked_key_is_impossible() {
    let ocsp = Arc::new(responder());
    let (basics, prompter) = module(
        vec![
            open("inter-revoked-gost2015-sign"),
            Step::Key(0),
            Step::Key(0),
        ],
        ocsp.clone(),
    );
    // Both picks are refused; the exhausted script then cancels: no signature.
    assert_eq!(
        process(&basics, args("raw", Some(inter_chain()), json!({}))),
        EMPTY
    );
    let prompts = prompter.key_prompts();
    assert_eq!(prompts.len(), 3);
    assert_eq!(
        prompts[0].candidates[0].availability,
        Availability::Revoked { time: REVOKED_AT }
    );
    // The keys are checked once, not per prompt.
    assert_eq!(ocsp.calls().len(), 1);
}
