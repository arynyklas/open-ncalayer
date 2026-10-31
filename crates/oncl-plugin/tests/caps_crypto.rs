//! CMS by profile, time-stamps, OCSP and CRL for plugins (`keys_sign_cms_ex`, `tsp_stamp`,
//! `tsp_request`, `ocsp_fetch`, `crl_fetch`): the core makes every request, only to the PKI
//! hosts, against the mock TSA, OCSP responder and CRL distribution point.

mod common;

use common::*;
use der::Encode;
use der::asn1::ObjectIdentifier;
use oncl_pdk::abi::{
    self, Bytes, CertStatusAbi, CmsContent, CmsOutcome, CoSign, CrlArgs, CrlOutcome, ErrorCode,
    HashAlg, HostResult, Import, IssuerSel, KeySource, NetKind, NetStage, Nonce, OcspArgs,
    OcspOutcome, OpenArgs, Password, PkiMethod, PkiUrl, RawAttribute, SignCmsExArgs, SignedAttrs,
    SignerSel, SigningTime, StampArgs, StampMode, StampOutcome, TimeForm, TimeSource, TokenForm,
    TsaChoice, TsaSpec, TspOutcome, TspRequestArgs,
};
use oncl_pki::cert;
use oncl_pki::crl::MockCrl;
use oncl_pki::http::{
    HttpError, HttpErrorKind, HttpReply, HttpRequest, HttpTransport, RouteTransport,
};
use oncl_pki::ocsp::{CertStatus, MockOcsp};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{Engine, HostServices, Instance, MAX_HTTP_REQUESTS};
use oncl_testkit::{read, synthetic, synthetic_cert};
use serde::de::DeserializeOwned;
use std::sync::{Arc, Mutex};
use time::macros::datetime;

const ORIGIN: &str = "https://idp.egov.kz";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn cert_der(name: &str) -> Vec<u8> {
    synthetic_cert(name)
}

/// The services with the synthetic CAs, `http` and the real clock, the PKI hosts the NCA's
/// plus `extra_hosts`.
fn services(http: Arc<dyn HttpTransport>, extra_hosts: &[&str]) -> HostServices {
    let mut services = services_with(
        Arc::new(oncl_flows::testing::ScriptedPrompter::new(Vec::<
            oncl_flows::testing::Step,
        >::new())),
        http,
    );
    services.cas = Arc::new(CaSet::new(
        ["root-gost2015", "inter-gost2015"]
            .map(|name| cert::parse(&cert_der(name)).unwrap())
            .to_vec(),
    ));
    // The mocks answer at the real time.
    services.clock = time::OffsetDateTime::now_utc;
    services.pki_hosts = oncl_plugin::NCA_PKI_HOSTS
        .iter()
        .chain(extra_hosts)
        .map(|h| (*h).to_owned())
        .collect();
    services
}

/// The mock TSA, OCSP responder and CRL server on the NCA's PKI hosts.
struct Pki {
    tsa: Arc<MockTsa>,
    ocsp: Arc<MockOcsp>,
}

fn pki(tsa: MockTsa) -> (Pki, Arc<dyn HttpTransport>) {
    let tsa = Arc::new(tsa);
    let leaf = entry("inter-revoked-gost2015-sign").cert;
    let serial: String = leaf
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let ocsp = Arc::new(MockOcsp::new(entry("ocsp-gost2015")).status(
        &serial,
        CertStatus::Revoked {
            time: datetime!(2026-01-15 08:00 UTC),
            reason: Some(1),
        },
    ));
    let http = RouteTransport::new(vec![
        (
            "http://tsp.pki.gov.kz".to_owned(),
            Arc::clone(&tsa) as Arc<dyn HttpTransport>,
        ),
        (
            "http://ocsp.pki.gov.kz".to_owned(),
            Arc::clone(&ocsp) as Arc<dyn HttpTransport>,
        ),
    ]);
    (Pki { tsa, ocsp }, Arc::new(http))
}

fn tsa() -> MockTsa {
    MockTsa::new(entry("tsa-gost2015"))
}

fn guest(services: &HostServices, calls: &[(Import, Vec<u8>)]) -> Instance {
    Engine::new()
        .compile(&manifest("keys = true"), &wasm(&probe(calls)))
        .unwrap()
        .instantiate(services, session(1))
        .unwrap()
}

/// The last call's result of one request.
fn run<T: DeserializeOwned>(services: &HostServices, calls: &[(Import, Vec<u8>)]) -> HostResult<T> {
    let mut instance = guest(services, calls);
    let reply = instance.process("{}", &from(ORIGIN)).unwrap();
    probe_result(reply.text().unwrap())
}

/// Opens the synthetic key `name` by its bytes: handle 1.
fn open(name: &str) -> (Import, Vec<u8>) {
    let key = synthetic(name);
    (
        Import::KeysOpen,
        abi::encode(&OpenArgs {
            storage: "PKCS12".to_owned(),
            source: KeySource::Bytes(Bytes::from(read(&key.path))),
            password: Password::Text(key.password),
        }),
    )
}

fn cades() -> SignedAttrs {
    SignedAttrs {
        content_type: true,
        message_digest: true,
        signing_certificate_v2: true,
        signing_time: Some(SigningTime {
            at: TimeSource::Now,
            form: TimeForm::Auto,
        }),
        extra: Vec::new(),
    }
}

fn sign_args(content: &[u8], attrs: SignedAttrs, timestamp: Option<TsaChoice>) -> SignCmsExArgs {
    SignCmsExArgs {
        handle: 1,
        content: CmsContent::Data(Bytes::from(content.to_vec())),
        encapsulate: false,
        cosign: CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs,
        certificates: abi::CmsCerts::Signer,
        timestamp,
        output: abi::CmsOutput::Der,
    }
}

fn signed(outcome: CmsOutcome) -> Vec<u8> {
    match outcome {
        CmsOutcome::Signed(cms) => cms.into_vec(),
        CmsOutcome::TspFailed(failure) => panic!("time-stamp failed: {failure:?}"),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn sign_cms_ex_esedo_like_attrs_verify() {
    let (_, http) = pki(tsa());
    let services = services(http, &[]);
    let mut attrs = cades();
    attrs.signing_time = Some(SigningTime {
        at: TimeSource::UnixMs(1_772_359_200_000),
        form: TimeForm::Utc,
    });
    attrs.extra = vec![
        RawAttribute {
            oid: "1.2.398.3.3.2.9.77".to_owned(),
            values: vec![Bytes::from(b"\x0c\x05hello".to_vec())],
        },
        RawAttribute {
            oid: "1.2.398.3.3.2.1".to_owned(),
            values: vec![Bytes::from(b"\x04\x06ESEDO\x00".to_vec())],
        },
    ];
    let mut args = sign_args(b"document", attrs, None);
    args.econtent_type = Some("1.3.6.1.4.1.6801.11.1.9".to_owned());
    let cms = signed(
        run(
            &services,
            &[
                open("user-gost2015-sign"),
                (Import::KeysSignCmsEx, abi::encode(&args)),
            ],
        )
        .unwrap(),
    );
    assert!(contains(&cms, b"\x04\x06ESEDO\x00"));
    assert!(contains(&cms, b"\x0c\x05hello"));
    // 2026-03-01 10:00:00 UTC as UTCTime.
    assert!(contains(&cms, b"\x17\x0d260301100000Z"));
    let econtent_type = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.6801.11.1.9")
        .to_der()
        .unwrap();
    assert!(contains(&cms, &econtent_type));
    assert_eq!(
        oncl_pki::cms::verify(&cms, Some(b"document"))
            .unwrap()
            .len(),
        1
    );

    // An attribute a flag adds, a bad OID, a value that is not DER: invalid.
    for extra in [
        RawAttribute {
            oid: "1.2.840.113549.1.9.4".to_owned(),
            values: vec![Bytes::from(b"\x04\x00".to_vec())],
        },
        RawAttribute {
            oid: "not an oid".to_owned(),
            values: Vec::new(),
        },
        RawAttribute {
            oid: "1.2.3".to_owned(),
            values: vec![Bytes::from(vec![0x04, 0x05])],
        },
    ] {
        let mut attrs = cades();
        attrs.extra = vec![extra];
        let args = sign_args(b"document", attrs, None);
        let e = run::<CmsOutcome>(
            &services,
            &[
                open("user-gost2015-sign"),
                (Import::KeysSignCmsEx, abi::encode(&args)),
            ],
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Invalid, "{e}");
    }
}

#[test]
fn sign_cms_ex_writes_the_output_form_asked() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let (_, http) = pki(tsa());
    let services = services(http, &[]);
    let mut attrs = cades();
    attrs.signing_time = Some(SigningTime {
        at: TimeSource::UnixMs(1_772_359_200_000),
        form: TimeForm::Auto,
    });
    let sign = |output| {
        let mut args = sign_args(&[7u8; 300], attrs.clone(), None);
        args.output = output;
        signed(
            run(
                &services,
                &[
                    open("user-rsa-sign"),
                    (Import::KeysSignCmsEx, abi::encode(&args)),
                ],
            )
            .unwrap(),
        )
    };
    let der = sign(abi::CmsOutput::Der);
    let body = STANDARD.encode(&der);
    assert_eq!(sign(abi::CmsOutput::Base64), body.as_bytes());
    let nl = if cfg!(windows) { "\r\n" } else { "\n" };
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    let pem = format!(
        "-----BEGIN CMS-----{nl}{}{nl}-----END CMS-----{nl}",
        lines.join(nl)
    );
    assert_eq!(String::from_utf8(sign(abi::CmsOutput::Pem)).unwrap(), pem);
}

#[test]
fn sign_cms_ex_kalkan_tsa_profile() {
    let (pki, http) = pki(tsa());
    let services = services(http, &[]);
    let args = sign_args(b"document", cades(), Some(TsaChoice::Kalkan));
    let cms = signed(
        run(
            &services,
            &[
                open("user-gost2015-sign"),
                (Import::KeysSignCmsEx, abi::encode(&args)),
            ],
        )
        .unwrap(),
    );
    let signers = oncl_pki::cms::verify(&cms, Some(b"document")).unwrap();
    assert!(signers[0].timestamp_token.is_some());
    // The NCA GET binding, SHA-256, the TSA_RSA policy.
    let calls = pki.tsa.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].starts_with("http://tsp.pki.gov.kz/"), "{calls:?}");
    let request = &pki.tsa.requests()[0];
    let sha256 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1")
        .to_der()
        .unwrap();
    let policy = ObjectIdentifier::new_unwrap("1.2.398.3.3.2.6.2")
        .to_der()
        .unwrap();
    assert!(contains(request, &sha256) && contains(request, &policy));
}

/// A transport whose names never resolve.
struct NoHost;

impl HttpTransport for NoHost {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::new(
            HttpErrorKind::UnknownHost,
            format!("{}: no such host", request.url),
        ))
    }
}

#[test]
fn sign_cms_ex_tsp_failure_is_outcome_not_error() {
    let services = services(Arc::new(NoHost), &[]);
    let args = sign_args(b"document", cades(), Some(TsaChoice::Kalkan));
    let outcome: CmsOutcome = run(
        &services,
        &[
            open("user-gost2015-sign"),
            (Import::KeysSignCmsEx, abi::encode(&args)),
        ],
    )
    .unwrap();
    let CmsOutcome::TspFailed(failure) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(failure.stage, NetStage::Tsp);
    assert_eq!(failure.kind, NetKind::UnknownHost);
    assert_eq!(failure.address, "tsp.pki.gov.kz");
}

fn ocsp_args(url: PkiUrl, issuer: IssuerSel) -> OcspArgs {
    OcspArgs {
        cert: Bytes::from(der::Encode::to_der(&entry("inter-revoked-gost2015-sign").cert).unwrap()),
        issuer,
        cert_id_hash: HashAlg::Sha1,
        nonce: Nonce::Random(16),
        url,
        method: PkiMethod::Post { content_type: None },
        timeout_ms: 5000,
        check: true,
    }
}

#[test]
fn pki_url_outside_hosts_is_denied() {
    let (_, http) = pki(tsa());
    let services = services(http, &[]);
    let leaf = Bytes::from(der::Encode::to_der(&entry("inter-user-gost2015-sign").cert).unwrap());
    // The synthetic certificates name responders outside the PKI hosts.
    for url in [
        PkiUrl::FromCert(leaf),
        PkiUrl::Fixed("http://evil.example/ocsp".to_owned()),
        PkiUrl::Fixed("http://evilpki.gov.kz/".to_owned()),
        PkiUrl::Fixed("http://ocsp.pki.gov.kz.evil/".to_owned()),
        PkiUrl::Fixed("ftp://ocsp.pki.gov.kz/".to_owned()),
    ] {
        let args = ocsp_args(url.clone(), IssuerSel::HostCas);
        let e =
            run::<OcspOutcome>(&services, &[(Import::OcspFetch, abi::encode(&args))]).unwrap_err();
        assert_eq!(e.code, ErrorCode::Denied, "{url:?}: {e}");
    }
    // A subdomain of a PKI host is asked (and has no route here).
    let args = ocsp_args(
        PkiUrl::Fixed("http://x.ocsp.pki.gov.kz/".to_owned()),
        IssuerSel::HostCas,
    );
    let outcome: OcspOutcome = run(&services, &[(Import::OcspFetch, abi::encode(&args))]).unwrap();
    assert!(matches!(outcome, OcspOutcome::Failed(_)), "{outcome:?}");
    // A TSA likewise, and limits are checked.
    let custom = TsaSpec {
        url: PkiUrl::Fixed("https://tsa.example.com/".to_owned()),
        method: PkiMethod::Post { content_type: None },
        hash: HashAlg::Sha256,
        policy: None,
        nonce: Nonce::Random(8),
        cert_req: true,
        retries: 0,
        timeout_ms: 5000,
        check_skew_ms: None,
        require_tsa_eku: true,
    };
    let request = |tsa: TsaSpec| TspRequestArgs {
        tsa,
        imprint: Bytes::from(vec![7; 32]),
    };
    let e = run::<TspOutcome>(
        &services,
        &[(Import::TspRequest, abi::encode(&request(custom.clone())))],
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Denied);
    for bad in [
        TsaSpec {
            url: PkiUrl::Default,
            retries: abi::MAX_TSP_RETRIES + 1,
            ..custom.clone()
        },
        TsaSpec {
            url: PkiUrl::Default,
            timeout_ms: abi::MAX_PKI_TIMEOUT_MS + 1,
            ..custom.clone()
        },
    ] {
        let e = run::<TspOutcome>(
            &services,
            &[(Import::TspRequest, abi::encode(&request(bad)))],
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Invalid);
    }
}

#[test]
fn tsp_request_returns_gen_time() {
    let at = datetime!(2026-03-01 10:20:30 UTC);
    let (pki, http) = pki(tsa().with_gen_time(at));
    let services = services(http, &[]);
    let args = TspRequestArgs {
        tsa: TsaSpec {
            url: PkiUrl::Default,
            method: PkiMethod::Get,
            hash: HashAlg::Sha256,
            policy: Some("1.2.398.3.3.2.6.2".to_owned()),
            nonce: Nonce::Random(8),
            cert_req: true,
            retries: 0,
            timeout_ms: 5000,
            check_skew_ms: None,
            require_tsa_eku: true,
        },
        imprint: Bytes::from(vec![7; 32]),
    };
    let outcome: TspOutcome = run(&services, &[(Import::TspRequest, abi::encode(&args))]).unwrap();
    let TspOutcome::Ok {
        response,
        token,
        gen_time_ms,
        tsa_cert,
    } = outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(gen_time_ms, at.unix_timestamp() * 1000);
    assert_eq!(
        tsa_cert.unwrap().into_vec(),
        der::Encode::to_der(&entry("tsa-gost2015").cert).unwrap()
    );
    let (parsed, _) = oncl_pki::tsp::parse_response(&response).unwrap();
    assert_eq!(parsed, token.into_vec());
    assert_eq!(pki.tsa.calls().len(), 1);
}

#[test]
fn ocsp_fetch_given_issuer() {
    let (pki, http) = pki(tsa());
    let services = services(http, &[]);
    let inter = Bytes::from(cert_der("inter-gost2015"));
    for issuer in [
        IssuerSel::Given(inter.clone()),
        IssuerSel::HostCas,
        IssuerSel::VerifiesCert(vec![Bytes::from(cert_der("root-gost2015")), inter.clone()]),
    ] {
        let args = ocsp_args(PkiUrl::Default, issuer);
        let outcome: OcspOutcome =
            run(&services, &[(Import::OcspFetch, abi::encode(&args))]).unwrap();
        let OcspOutcome::Ok {
            http_status,
            basic,
            response_status,
            cert_status,
            produced_at_ms,
            problem,
            ..
        } = outcome
        else {
            panic!("{outcome:?}");
        };
        assert_eq!((http_status, response_status, problem), (200, 0, None));
        assert!(basic.is_some() && produced_at_ms.is_some());
        assert_eq!(
            cert_status,
            Some(CertStatusAbi::Revoked {
                at_ms: datetime!(2026-01-15 08:00 UTC).unix_timestamp() * 1000,
                reason: Some(1)
            })
        );
    }
    assert_eq!(pki.ocsp.calls(), ["http://ocsp.pki.gov.kz"; 3]);
    // No certificate given verifies the leaf.
    let args = ocsp_args(
        PkiUrl::Default,
        IssuerSel::VerifiesCert(vec![Bytes::from(cert_der("root-gost2015"))]),
    );
    let e = run::<OcspOutcome>(&services, &[(Import::OcspFetch, abi::encode(&args))]).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
}

#[test]
fn crl_fetch_status() {
    let leaf = entry("inter-revoked-gost2015-sign").cert;
    let revoked_at = datetime!(2026-01-15 08:00 UTC);
    let crl = MockCrl::new(entry("inter-gost2015.key")).revoke_with_reason(
        leaf.tbs_certificate().serial_number().as_bytes(),
        revoked_at,
        1,
    );
    // The synthetic certificates' distribution point, here a PKI host.
    let services = services(Arc::new(crl), &["crl.synthetic.test"]);
    let args = CrlArgs {
        cert: Bytes::from(der::Encode::to_der(&leaf).unwrap()),
        issuer: IssuerSel::HostCas,
        timeout_ms: 5000,
    };
    let outcome: CrlOutcome = run(&services, &[(Import::CrlFetch, abi::encode(&args))]).unwrap();
    let CrlOutcome::Ok { crls, status } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(crls.len(), 1);
    assert_eq!(
        status,
        CertStatusAbi::Revoked {
            at_ms: revoked_at.unix_timestamp() * 1000,
            reason: Some(1)
        }
    );
    // On the NCA's hosts only, the same distribution point is refused.
    let (_, http) = pki(tsa());
    let e = run::<CrlOutcome>(
        &services_nca(http),
        &[(Import::CrlFetch, abi::encode(&args))],
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::Denied);
    // A CRL of another issuer is invalid, not a network failure.
    let other = MockCrl::new(entry("root-gost2015.key"));
    let outcome: CrlOutcome = run(
        &services_with_crl(other),
        &[(Import::CrlFetch, abi::encode(&args))],
    )
    .unwrap();
    assert_eq!(outcome, CrlOutcome::Invalid(abi::Problem::CrlInvalid));
}

fn services_nca(http: Arc<dyn HttpTransport>) -> HostServices {
    services(http, &[])
}

fn services_with_crl(crl: MockCrl) -> HostServices {
    services(Arc::new(crl), &["crl.synthetic.test"])
}

/// Passes requests on to `inner`, recording each one's URL and whether it may follow
/// redirects.
struct Recorder {
    inner: Arc<dyn HttpTransport>,
    sent: Mutex<Vec<(String, bool)>>,
}

impl Recorder {
    fn new(inner: Arc<dyn HttpTransport>) -> Arc<Recorder> {
        Arc::new(Recorder {
            inner,
            sent: Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<(String, bool)> {
        self.sent.lock().unwrap().clone()
    }
}

impl HttpTransport for Recorder {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.sent
            .lock()
            .unwrap()
            .push((request.url.to_owned(), request.opts.redirects));
        self.inner.send(request)
    }
}

#[test]
fn pki_requests_never_follow_redirects() {
    let (_, http) = pki(tsa());
    let recorder = Recorder::new(http);
    let crl = Recorder::new(Arc::new(MockCrl::new(entry("inter-gost2015.key"))));
    let crl_services = services(crl.clone(), &["crl.synthetic.test"]);
    let services = services(recorder.clone(), &[]);
    // keys_sign_cms_ex with a time-stamp.
    let stamped = sign_args(b"document", cades(), Some(TsaChoice::Kalkan));
    signed(
        run(
            &services,
            &[
                open("user-gost2015-sign"),
                (Import::KeysSignCmsEx, abi::encode(&stamped)),
            ],
        )
        .unwrap(),
    );
    // tsp_stamp of a signature without one.
    let plain = signed(
        run(
            &services,
            &[
                open("user-gost2015-sign"),
                (
                    Import::KeysSignCmsEx,
                    abi::encode(&sign_args(b"document", cades(), None)),
                ),
            ],
        )
        .unwrap(),
    );
    let stamp = StampArgs {
        cms: Bytes::from(plain),
        signers: SignerSel::Last,
        tsa: TsaChoice::Kalkan,
        mode: StampMode::Replace,
        token: TokenForm::Token,
    };
    let outcome: StampOutcome = run(&services, &[(Import::TspStamp, abi::encode(&stamp))]).unwrap();
    assert!(matches!(outcome, StampOutcome::Stamped(_)), "{outcome:?}");
    // tsp_request.
    let request = TspRequestArgs {
        tsa: TsaSpec {
            url: PkiUrl::Default,
            method: PkiMethod::Post { content_type: None },
            hash: HashAlg::Sha256,
            policy: None,
            nonce: Nonce::Random(8),
            cert_req: true,
            retries: 0,
            timeout_ms: 5000,
            check_skew_ms: None,
            require_tsa_eku: true,
        },
        imprint: Bytes::from(vec![7; 32]),
    };
    let outcome: TspOutcome =
        run(&services, &[(Import::TspRequest, abi::encode(&request))]).unwrap();
    assert!(matches!(outcome, TspOutcome::Ok { .. }), "{outcome:?}");
    // ocsp_fetch.
    let ocsp = ocsp_args(PkiUrl::Default, IssuerSel::HostCas);
    let outcome: OcspOutcome = run(&services, &[(Import::OcspFetch, abi::encode(&ocsp))]).unwrap();
    assert!(matches!(outcome, OcspOutcome::Ok { .. }), "{outcome:?}");
    // crl_fetch.
    let leaf = entry("inter-revoked-gost2015-sign").cert;
    let args = CrlArgs {
        cert: Bytes::from(der::Encode::to_der(&leaf).unwrap()),
        issuer: IssuerSel::HostCas,
        timeout_ms: 5000,
    };
    let outcome: CrlOutcome =
        run(&crl_services, &[(Import::CrlFetch, abi::encode(&args))]).unwrap();
    assert!(matches!(outcome, CrlOutcome::Ok { .. }), "{outcome:?}");

    let sent: Vec<(String, bool)> = recorder.sent().into_iter().chain(crl.sent()).collect();
    assert!(sent.len() >= 5, "{sent:?}");
    for (url, redirects) in &sent {
        assert!(!redirects, "{url} may follow redirects");
    }
}

#[test]
fn pki_requests_count_towards_the_call_limit() {
    let (_, http) = pki(tsa());
    let recorder = Recorder::new(http);
    let services = services(recorder.clone(), &[]);
    let ocsp = (
        Import::OcspFetch,
        abi::encode(&ocsp_args(PkiUrl::Default, IssuerSel::HostCas)),
    );
    let calls = vec![ocsp; MAX_HTTP_REQUESTS as usize + 1];
    let outcome: OcspOutcome = run(&services, &calls).unwrap();
    let OcspOutcome::Failed(failure) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(failure.stage, NetStage::Ocsp);
    assert!(failure.detail.contains("HTTP requests"), "{failure:?}");
    assert_eq!(recorder.sent().len(), MAX_HTTP_REQUESTS as usize);
}
