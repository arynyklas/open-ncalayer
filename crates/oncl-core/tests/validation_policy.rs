//! F03 tests-first: real signed synthetic evidence; controller owns RED/GREEN.
use der::asn1::AnyRef;
use der::{Decode, Encode, Reader, SliceReader};
use oncl_core::keys::{
    KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy, ValidationServices,
};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
use oncl_pki::crl::MockCrl;
use oncl_pki::digest::HashState;
use oncl_pki::http::{
    GetOptions, HttpError, HttpReply, HttpRequest, HttpTransport, RouteTransport, UreqTransport,
};
use oncl_pki::key::{AppliedState, HashAlg, SigAlg};
use oncl_pki::ocsp::{CertStatus, MockOcsp};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
use oncl_pki::tsp::{self, MockTsa, SignerSel, StampMode, TokenForm, TsaProfile, TsaSpec};
use oncl_pki::validation::{CheckStatus, NetworkPolicy, TimeBasis, Verdict};
use oncl_testkit::{read, synthetic, synthetic_cert};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};
use time::{OffsetDateTime, macros::datetime};

const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const CLAIM: OffsetDateTime = datetime!(2025-06-01 10:00 UTC);
const PROVEN: OffsetDateTime = datetime!(2025-06-01 10:05 UTC);
const REVOKED: OffsetDateTime = datetime!(2026-01-15 08:00 UTC);
const DATA: &[u8] = b"F03 real signed synthetic document";
fn entry(name: &str) -> KeyEntry {
    let f = synthetic(name);
    load(&read(f.path), &f.password).unwrap().remove(0)
}
fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}
fn roots() -> CaSet {
    CaSet::new(vec![cer("root-gost2015")])
}
fn chain() -> Vec<Certificate> {
    vec![cer("inter-gost2015")]
}
fn signed(name: &str) -> Vec<u8> {
    signed_entry(&entry(name))
}
fn signed_entry(key: &KeyEntry) -> Vec<u8> {
    cms::sign_spec(
        key,
        &chain(),
        &SignSpec {
            content: Content::Data(DATA),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec::cades(CLAIM),
            certificates: CertSpec::Extra(vec![cer("inter-gost2015"), cer("root-gost2015")]),
        },
    )
    .unwrap()
}
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("fixture unavailable"))
    }
}
fn services(http: Arc<dyn HttpTransport>, network: NetworkPolicy) -> ValidationServices {
    ValidationServices::new(roots(), chain(), http, network, Arc::new(|| NOW))
}
fn network() -> NetworkPolicy {
    NetworkPolicy::only_endpoints(["http://ocsp.synthetic.test", "http://crl.synthetic.test"])
        .unwrap()
}
fn engine(validation: ValidationServices, timeout: Duration) -> Engine {
    let limits = ResourceLimits {
        operation_timeout: timeout,
        ..ResourceLimits::default()
    };
    Engine::new(EngineServices::hash_only(limits).with_validation(validation)).unwrap()
}
fn context(engine: &Engine, policy: OperationPolicy) -> OperationContext {
    engine
        .begin(
            ExecutionGrant::new([Action::Validate]),
            policy,
            Arc::new(Control),
        )
        .unwrap()
}
fn verify(engine: &Engine, input: &[u8], policy: OperationPolicy) -> oncl_core::VerificationReport {
    engine
        .validate_cms(input, None, &mut context(engine, policy))
        .unwrap()
}

// Small DER reconstruction utilities, only for issuing deterministic signed evidence.
fn children(input: &[u8]) -> Vec<Vec<u8>> {
    let any = AnyRef::from_der(input).unwrap();
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut out = vec![];
    while !reader.is_finished() {
        out.push(reader.decode::<AnyRef<'_>>().unwrap().to_der().unwrap());
    }
    out
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let bytes: Vec<_> = value
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend(value);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn bit_signature(key: &KeyEntry, tbs: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend(key.key.sign(SigAlg::Gost2015_512, tbs).unwrap());
    tlv(3, &bits)
}
// Preserve CertID, nonce, responder identity and certificate; replace signed times
// and re-sign ResponseData with the genuine delegated responder key.
struct FixedOcsp {
    inner: MockOcsp,
    stale: bool,
}
impl HttpTransport for FixedOcsp {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let mut reply = self.inner.send(request)?;
        let mut response = children(&reply.body);
        let mut bytes = children(&children(&response[1])[0]);
        let basic_der = AnyRef::from_der(&bytes[1]).unwrap().value().to_vec();
        let mut basic = children(&basic_der);
        let mut tbs = children(&basic[0]);
        let produced = tbs.iter().position(|p| p[0] == 0x18).unwrap();
        tbs[produced] = tlv(0x18, b"20261102120000Z");
        let mut responses = children(&tbs[produced + 1]);
        for single in &mut responses {
            let mut fields = children(single);
            fields[2] = tlv(0x18, b"20261102115900Z");
            fields[3] = tlv(
                0xa0,
                &tlv(
                    0x18,
                    if self.stale {
                        b"20261102115930Z"
                    } else {
                        b"20261102130000Z"
                    },
                ),
            );
            *single = seq(&fields);
        }
        tbs[produced + 1] = seq(&responses);
        basic[0] = seq(&tbs);
        basic[2] = bit_signature(&entry("ocsp-gost2015"), &basic[0]);
        bytes[1] = tlv(4, &seq(&basic));
        response[1] = tlv(0xa0, &seq(&bytes));
        reply.body = seq(&response);
        Ok(reply)
    }
}
struct FixedCrl {
    revoked: bool,
    stale: bool,
}
impl HttpTransport for FixedCrl {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let issuer = if request.url.ends_with("/root-gost2015.crl") {
            "root-gost2015.key"
        } else {
            "inter-gost2015.key"
        };
        let key = entry(issuer);
        let mut source = MockCrl::new(entry(issuer));
        if self.revoked && issuer == "inter-gost2015.key" {
            source = source.revoke(
                entry("inter-revoked-gost2015-sign")
                    .cert
                    .tbs_certificate()
                    .serial_number()
                    .as_bytes(),
                REVOKED,
            );
        }
        let mut crl = children(&source.der());
        let mut tbs = children(&crl[0]);
        tbs[3] = tlv(0x17, b"261102115900Z");
        tbs[4] = tlv(
            0x17,
            if self.stale {
                b"261102115930Z"
            } else {
                b"261102130000Z"
            },
        );
        crl[0] = seq(&tbs);
        crl[2] = bit_signature(&key, &crl[0]);
        Ok(HttpReply {
            status: 200,
            content_type: Some("application/pkix-crl".into()),
            location: None,
            body: seq(&crl),
        })
    }
}
fn pki(status: CertStatus, stale: bool) -> Arc<dyn HttpTransport> {
    let leaf = entry("inter-revoked-gost2015-sign");
    let serial: String = leaf
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Arc::new(RouteTransport::new(vec![
        (
            "http://ocsp.synthetic.test".into(),
            Arc::new(FixedOcsp {
                inner: MockOcsp::new(entry("ocsp-gost2015")).status(&serial, status),
                stale,
            }),
        ),
        (
            "http://crl.synthetic.test".into(),
            Arc::new(FixedCrl {
                revoked: matches!(status, CertStatus::Revoked { .. }),
                stale,
            }),
        ),
    ]))
}
#[test]
fn unknown_is_not_valid() {
    let engine = engine(
        services(Arc::new(Offline), network()),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &signed("inter-user-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.signers[0].revocation, CheckStatus::Unavailable);
}
#[test]
fn client_chain_is_not_anchor() {
    let validation = ValidationServices::new(
        CaSet::new(vec![]),
        vec![],
        pki(CertStatus::Good, false),
        network(),
        Arc::new(|| NOW),
    );
    let engine = engine(validation, Duration::from_secs(5));
    let report = verify(
        &engine,
        &signed("inter-user-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_ne!(report.verdict, Verdict::Valid);
    assert_eq!(report.signers[0].chain, CheckStatus::Failed);
}
struct CountTransport(AtomicUsize);
impl HttpTransport for CountTransport {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(HttpError::other("unexpected fetch"))
    }
}
struct RecordingTransport(std::sync::Mutex<Vec<String>>);
impl HttpTransport for RecordingTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.0.lock().unwrap().push(request.url.to_owned());
        Err(HttpError::other("fixture status unavailable"))
    }
}
#[test]
fn untrusted_pki_url_is_not_fetched() {
    let transport = Arc::new(CountTransport(AtomicUsize::new(0)));
    let engine = engine(
        services(transport.clone(), NetworkPolicy::deny_all()),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &signed("inter-user-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(transport.0.load(Ordering::SeqCst), 0);
}
#[test]
fn offline_report_does_not_fetch_or_claim_valid() {
    let transport = Arc::new(CountTransport(AtomicUsize::new(0)));
    let engine = engine(
        services(transport.clone(), network()),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &signed("inter-user-gost2015-sign"),
        OperationPolicy::offline_report(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.signers[0].revocation, CheckStatus::Unavailable);
    assert_eq!(transport.0.load(Ordering::SeqCst), 0);
}
#[test]
fn signed_online_evidence_is_valid_but_stale_evidence_is_not() {
    let input = signed("inter-user-gost2015-sign");
    for stale in [false, true] {
        let engine = engine(
            services(pki(CertStatus::Good, stale), network()),
            Duration::from_secs(5),
        );
        let report = verify(&engine, &input, OperationPolicy::strict_online());
        assert_eq!(
            report.verdict,
            if stale {
                Verdict::Indeterminate
            } else {
                Verdict::Valid
            }
        );
        assert_eq!(report.signers[0].validity, CheckStatus::Passed);
        assert_eq!(
            report.policy,
            oncl_pki::validation::ValidationPolicy::StrictOnline
        );
        assert_eq!(report.checked_at, NOW);
    }
}
#[test]
fn claimed_signing_time_is_not_verified_time() {
    let engine = engine(
        services(
            pki(
                CertStatus::Revoked {
                    time: REVOKED,
                    reason: Some(1),
                },
                false,
            ),
            network(),
        ),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &signed("inter-revoked-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_ne!(report.verdict, Verdict::Valid);
    assert_eq!(report.signers[0].claimed_signing_time, Some(CLAIM));
    assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
    assert_eq!(report.signers[0].revocation, CheckStatus::Failed);
}
#[test]
fn verified_tsa_time_and_current_freshness_are_separate() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let input = tsa.stamp(&signed("inter-revoked-gost2015-sign"));
    for stale in [false, true] {
        let engine = engine(
            tsa.services_with_document(
                TsaStatus::Good,
                pki(
                    CertStatus::Revoked {
                        time: REVOKED,
                        reason: Some(1),
                    },
                    stale,
                ),
            ),
            Duration::from_secs(5),
        );
        let report = verify(&engine, &input, OperationPolicy::strict_online());
        assert_eq!(
            report.signers[0].time_basis,
            TimeBasis::VerifiedTimestamp(PROVEN)
        );
        assert_eq!(report.signers[0].timestamp, CheckStatus::Passed);
        assert_eq!(
            report.verdict,
            if stale {
                Verdict::Indeterminate
            } else {
                Verdict::Valid
            }
        );
    }
}

// A real socket accepts a PKI request and holds the response behind an explicit
// release channel. Drop releases and joins even when an assertion unwinds.
struct Server {
    url: String,
    seen: mpsc::Receiver<()>,
    release: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn held() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (seen_tx, seen) = mpsc::channel();
        let (release, rx) = mpsc::channel();
        let join = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let start = Instant::now();
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if start.elapsed() > Duration::from_secs(8) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = [0; 4096];
            let _ = socket.read(&mut buf).unwrap();
            seen_tx.send(()).unwrap();
            let _ = rx.recv_timeout(Duration::from_secs(8));
            let _ = socket.write_all(
                b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });
        Self {
            url,
            seen,
            release: Some(release),
            join: Some(join),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(tx) = self.release.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}
#[test]
fn network_wait_obeys_operation_deadline() {
    let server = Server::held();
    let engine = engine(
        services(
            Arc::new(UreqTransport::default()),
            NetworkPolicy::only_endpoints([server.url.as_str()]).unwrap(),
        ),
        Duration::from_millis(350),
    );
    let mut ctx = context(&engine, OperationPolicy::strict_online());
    // Exercise the same scoped transport used by validation, not copied GetOptions.
    let (tx, rx) = mpsc::channel();
    let url = server.url.clone();
    let worker = thread::spawn(move || {
        let start = Instant::now();
        let result =
            engine.validation_http(&HttpRequest::get(&url, GetOptions::default()), &mut ctx);
        tx.send((result, start.elapsed())).unwrap();
    });
    server
        .seen
        .recv_timeout(Duration::from_secs(2))
        .expect("real request reached fixture");
    let (result, elapsed) = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("operation must end while HTTP response is still held");
    assert!(matches!(
        result,
        Err(OperationError::Processing(
            ProcessingError::DeadlineExceeded
        ))
    ));
    assert!(elapsed < Duration::from_secs(2));
    assert!(server.release.is_some(), "barrier has not been released");
    worker.join().unwrap();
}

struct Guard(AtomicUsize);
impl KeyUseGuard for Guard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(&self, _: KeyUseReceipt, _: KeyUseOutcome) -> Result<(), OperationError> {
        Ok(())
    }
}
fn private_attempt(
    policy: OperationPolicy,
    validation: Option<ValidationServices>,
) -> (OperationError, usize) {
    let fixture = synthetic("inter-user-gost2015-sign");
    let selector = KeySelector::file(fixture.path, Some(fixture.aliases[0].clone())).unwrap();
    let guard = Arc::new(Guard(AtomicUsize::new(0)));
    let mut services = EngineServices::hash_only(ResourceLimits::default())
        .with_keys(Arc::new(KeySources::new()), guard.clone());
    if let Some(validation) = validation {
        services = services.with_validation(validation);
    }
    let engine = Engine::new(services).unwrap();
    let mut policy = policy;
    policy.allow_prehashed = true;
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::SignDigest]).with_keys([selector.key_id()]),
            policy,
            Arc::new(Control),
        )
        .unwrap();
    let mut hash = HashState::new(HashAlg::Streebog512);
    hash.update(DATA);
    let error = engine
        .signer(
            &KeyRequest::new(&selector, Some(&fixture.password)),
            &mut ctx,
        )
        .and_then(|mut signer| signer.sign_digest(&hash.finish()))
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    (error, guard.0.load(Ordering::SeqCst))
}
#[test]
fn strict_private_use_requires_validation_services_before_guard() {
    let (error, guards) = private_attempt(OperationPolicy::strict_online(), None);
    assert!(matches!(error, OperationError::MissingValidationServices));
    assert_eq!(guards, 0);
}
#[test]
fn offline_report_cannot_bypass_private_use_revocation() {
    let (error, guards) = private_attempt(
        OperationPolicy::offline_report(),
        Some(services(Arc::new(Offline), network())),
    );
    assert!(matches!(error, OperationError::ValidationRequired));
    assert_eq!(guards, 0);
}

// Rewrite only URI GeneralNames, then issue a genuinely signed variant leaf.
fn with_internal_urls() -> Vec<u8> {
    fn rewrite(input: &[u8]) -> Vec<u8> {
        let any = AnyRef::from_der(input).unwrap();
        if input[0] == 0x86 {
            return tlv(0x86, b"http://127.0.0.1:9/private-pki");
        }
        if input[0] & 0x20 != 0 {
            return tlv(
                input[0],
                &children(input)
                    .iter()
                    .flat_map(|c| rewrite(c))
                    .collect::<Vec<_>>(),
            );
        }
        tlv(input[0], any.value())
    }
    let mut leaf = entry("inter-user-gost2015-sign");
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&leaf.cert);
    for extension in &mut spec.extensions {
        let oid = extension.extn_id.to_string();
        if oid == "1.3.6.1.5.5.7.1.1" || oid == "2.5.29.31" {
            extension.extn_value =
                der::asn1::OctetString::new(rewrite(extension.extn_value.as_bytes())).unwrap();
        }
    }
    leaf.cert = oncl_pki::testing::issue_cert(&entry("inter-gost2015.key"), spec);
    signed_entry(&leaf)
}
#[test]
fn certificate_internal_urls_do_not_expand_host_network_authority() {
    let transport = Arc::new(RecordingTransport(std::sync::Mutex::new(vec![])));
    let engine = engine(
        services(transport.clone(), network()),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &with_internal_urls(),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    let urls = transport.0.lock().unwrap();
    // Only the leaf's AIA/CDP were replaced with forbidden loopback URLs.
    // Its intermediate still has an independently approved root CRL endpoint.
    assert_eq!(
        urls.as_slice(),
        ["http://crl.synthetic.test/root-gost2015.crl"],
        "{urls:?}"
    );
}
#[test]
fn network_failure_with_live_budget_is_not_deadline_or_bad_signature() {
    let engine = engine(
        services(Arc::new(Offline), network()),
        Duration::from_secs(10),
    );
    let report = verify(
        &engine,
        &signed("inter-user-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
}
#[test]
fn expired_claim_without_tsa_does_not_validate_at_caller_time() {
    let engine = engine(
        services(pki(CertStatus::Good, false), network()),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &signed("inter-expired-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_ne!(report.verdict, Verdict::Valid);
    assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
    assert_eq!(report.signers[0].validity, CheckStatus::Failed);
}
#[test]
fn tampered_content_is_invalid_even_with_good_online_status() {
    let mut input = signed("inter-user-gost2015-sign");
    let offset = input.windows(DATA.len()).position(|w| w == DATA).unwrap();
    input[offset] ^= 1;
    let engine = engine(
        services(pki(CertStatus::Good, false), network()),
        Duration::from_secs(5),
    );
    let report = verify(&engine, &input, OperationPolicy::strict_online());
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].signature, CheckStatus::Failed);
}

struct Redirect {
    target: String,
    calls: AtomicUsize,
}
impl HttpTransport for Redirect {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            !request.opts.redirects,
            "policy wrapper must inspect each redirect"
        );
        Ok(HttpReply {
            status: 302,
            content_type: None,
            body: vec![],
            location: Some(self.target.clone()),
        })
    }
}
#[test]
fn approved_endpoint_redirect_cannot_escape_to_internal_endpoint() {
    let redirect = Arc::new(Redirect {
        target: "http://127.0.0.1:9/private".into(),
        calls: AtomicUsize::new(0),
    });
    let engine = engine(
        services(redirect.clone(), network()),
        Duration::from_secs(5),
    );
    let mut ctx = context(&engine, OperationPolicy::strict_online());
    let result = engine.validation_http(
        &HttpRequest::get("http://ocsp.synthetic.test", GetOptions::default()),
        &mut ctx,
    );
    assert!(result.is_err());
    assert_eq!(redirect.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn signed_unknown_ocsp_without_crl_is_indeterminate() {
    let leaf = entry("inter-revoked-gost2015-sign");
    let serial: String = leaf
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let http = Arc::new(RouteTransport::new(vec![(
        "http://ocsp.synthetic.test".into(),
        Arc::new(FixedOcsp {
            inner: MockOcsp::new(entry("ocsp-gost2015")).status(&serial, CertStatus::Unknown),
            stale: false,
        }),
    )]));
    let engine = engine(services(http, network()), Duration::from_secs(5));
    let report = verify(
        &engine,
        &signed("inter-revoked-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.signers[0].revocation, CheckStatus::Unavailable);
}
#[test]
fn strict_private_use_rejects_unavailable_status_before_guard() {
    let (error, guards) = private_attempt(
        OperationPolicy::strict_online(),
        Some(services(Arc::new(Offline), network())),
    );
    assert!(matches!(error, OperationError::ValidationRequired));
    assert_eq!(guards, 0);
}
#[test]
fn offline_private_use_also_requires_validation_dependency() {
    let (error, guards) = private_attempt(OperationPolicy::offline_report(), None);
    assert!(matches!(error, OperationError::MissingValidationServices));
    assert_eq!(guards, 0);
}

#[test]
fn strict_private_use_with_real_validation_applies_real_signature() {
    let fixture = synthetic("inter-user-gost2015-sign");
    let selector = KeySelector::file(fixture.path, Some(fixture.aliases[0].clone())).unwrap();
    let guard = Arc::new(Guard(AtomicUsize::new(0)));
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_keys(Arc::new(KeySources::new()), guard.clone())
            .with_validation(services(pki(CertStatus::Good, false), network())),
    )
    .unwrap();
    let mut policy = OperationPolicy::strict_online();
    policy.allow_prehashed = true;
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::SignDigest]).with_keys([selector.key_id()]),
            policy,
            Arc::new(Control),
        )
        .unwrap();
    let mut hash = HashState::new(HashAlg::Streebog512);
    hash.update(DATA);
    let signature = engine
        .signer(
            &KeyRequest::new(&selector, Some(&fixture.password)),
            &mut ctx,
        )
        .unwrap()
        .sign_digest(&hash.finish())
        .unwrap();
    entry("inter-user-gost2015-sign")
        .key
        .public_key()
        .verify(SigAlg::Gost2015_512, DATA, &signature)
        .unwrap();
    assert_eq!(guard.0.load(Ordering::SeqCst), 1);
}

#[test]
fn approved_internal_pki_endpoint_returns_real_signed_crl() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let fixture = FixedCrl {
        revoked: false,
        stale: false,
    }
    .send(&HttpRequest::get(
        "http://crl.synthetic.test/root-gost2015.crl",
        GetOptions::default(),
    ))
    .unwrap()
    .body;
    let worker = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(5) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0; 4096];
        let mut used = 0;
        while !request[..used].windows(4).any(|part| part == b"\r\n\r\n") {
            assert!(used < request.len(), "fixture request headers too large");
            let read = socket.read(&mut request[used..]).unwrap();
            assert!(
                read > 0,
                "fixture request truncated before headers completed"
            );
            used += read;
        }
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", fixture.len()).unwrap();
        socket.write_all(&fixture).unwrap();
    });
    let engine = engine(
        services(
            Arc::new(UreqTransport::default()),
            NetworkPolicy::only_endpoints([url.as_str()]).unwrap(),
        ),
        Duration::from_secs(3),
    );
    let reply = engine
        .validation_http(
            &HttpRequest::get(&url, GetOptions::default()),
            &mut context(&engine, OperationPolicy::strict_online()),
        )
        .unwrap();
    oncl_pki::crl::verify_crl(&reply.body, &cer("root-gost2015"), NOW).unwrap();
    worker.join().unwrap();
}

#[test]
fn ureq_uses_operator_pins_without_resolving_and_preserves_host_header() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://operator-pki.invalid:{}", address.port());
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let start = Instant::now();
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(3) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("{e}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut data = Vec::new();
        while !data.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut chunk = [0; 4096];
            let n = socket.read(&mut chunk).unwrap();
            assert!(
                n > 0 && data.len() + n <= 16 * 1024,
                "incomplete or oversized fixture headers"
            );
            data.extend_from_slice(&chunk[..n]);
        }
        tx.send(String::from_utf8(data).unwrap()).unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let policy = NetworkPolicy::deny_all()
        .with_resolved_endpoint(&origin, vec![address])
        .unwrap();
    let engine = engine(
        services(Arc::new(UreqTransport::default()), policy),
        Duration::from_secs(2),
    );
    let reply = engine
        .validation_http(
            &HttpRequest::get(&origin, GetOptions::default()),
            &mut context(&engine, OperationPolicy::strict_online()),
        )
        .unwrap();
    assert_eq!(reply.body, b"ok");
    let header = rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .to_ascii_lowercase();
    assert!(header.contains(&format!("host: operator-pki.invalid:{}", address.port())));
    worker.join().unwrap();
}
#[test]
fn ureq_unpinned_hostname_is_refused_without_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!(
        "http://operator-pki.invalid:{}",
        listener.local_addr().unwrap().port()
    );
    let engine = engine(
        services(
            Arc::new(UreqTransport::default()),
            NetworkPolicy::only_endpoints([origin.as_str()]).unwrap(),
        ),
        Duration::from_secs(2),
    );
    let result = engine.validation_http(
        &HttpRequest::get(&origin, GetOptions::default()),
        &mut context(&engine, OperationPolicy::strict_online()),
    );
    assert!(matches!(result, Err(OperationError::ValidationRequired)));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

struct SwitchPki {
    online: std::sync::atomic::AtomicBool,
    inner: Arc<dyn HttpTransport>,
}
impl HttpTransport for SwitchPki {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        if self.online.load(Ordering::SeqCst) {
            self.inner.send(request)
        } else {
            Err(HttpError::other("fixture status became unavailable"))
        }
    }
}
#[test]
fn held_signer_revalidates_each_application_and_preserves_trait_failure_kind() {
    use oncl_pki::key::{DigestSigner, KeyError, KeyFailureKind};
    let fixture = synthetic("inter-user-gost2015-sign");
    let selector = KeySelector::file(fixture.path, Some(fixture.aliases[0].clone())).unwrap();
    let guard = Arc::new(Guard(AtomicUsize::new(0)));
    let http = Arc::new(SwitchPki {
        online: std::sync::atomic::AtomicBool::new(true),
        inner: pki(CertStatus::Good, false),
    });
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_keys(Arc::new(KeySources::new()), guard.clone())
            .with_validation(services(http.clone(), network())),
    )
    .unwrap();
    let mut policy = OperationPolicy::strict_online();
    policy.allow_prehashed = true;
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::SignDigest]).with_keys([selector.key_id()]),
            policy,
            Arc::new(Control),
        )
        .unwrap();
    let mut hash = HashState::new(HashAlg::Streebog512);
    hash.update(DATA);
    let digest = hash.finish();
    let mut signer = engine
        .signer(
            &KeyRequest::new(&selector, Some(&fixture.password)),
            &mut ctx,
        )
        .unwrap();
    let signature = signer.sign_digest(&digest).unwrap();
    entry("inter-user-gost2015-sign")
        .key
        .public_key()
        .verify(SigAlg::Gost2015_512, DATA, &signature)
        .unwrap();
    http.online.store(false, Ordering::SeqCst);
    let error = DigestSigner::sign_digest(&mut signer, &digest).unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(
        matches!(&error, KeyError::Execution(cause) if cause.kind == KeyFailureKind::ValidationRequired)
    );
    assert_eq!(guard.0.load(Ordering::SeqCst), 1);
}

#[test]
fn validation_cancellation_remains_typed_execution_error() {
    struct Cancel(std::sync::atomic::AtomicBool);
    impl OperationControl for Cancel {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }
    let engine = engine(
        services(pki(CertStatus::Good, false), network()),
        Duration::from_secs(5),
    );
    let control = Arc::new(Cancel(std::sync::atomic::AtomicBool::new(false)));
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::strict_online(),
            control.clone(),
        )
        .unwrap();
    let input = signed("inter-user-gost2015-sign");
    control.0.store(true, Ordering::SeqCst);
    assert!(matches!(
        engine.validate_cms(&input, None, &mut ctx),
        Err(OperationError::Processing(ProcessingError::Cancelled))
    ));
}

fn with_carried_crls(input: &[u8], revoked: bool, stale: bool) -> Vec<u8> {
    let mut lists = vec![];
    for url in [
        "http://crl.synthetic.test/inter-gost2015.crl",
        "http://crl.synthetic.test/root-gost2015.crl",
    ] {
        lists.extend(
            FixedCrl { revoked, stale }
                .send(&HttpRequest::get(url, GetOptions::default()))
                .unwrap()
                .body,
        );
    }
    let mut ci = children(input);
    let mut sd = children(&children(&ci[1])[0]);
    sd.insert(sd.len() - 1, tlv(0xa1, &lists));
    ci[1] = tlv(0xa0, &seq(&sd));
    seq(&ci)
}
#[test]
fn offline_embedded_signed_crls_validate_only_when_current() {
    let transport = Arc::new(CountTransport(AtomicUsize::new(0)));
    let engine = engine(
        services(transport.clone(), network()),
        Duration::from_secs(5),
    );
    let input = signed("inter-user-gost2015-sign");
    for stale in [false, true] {
        let report = verify(
            &engine,
            &with_carried_crls(&input, false, stale),
            OperationPolicy::offline_report(),
        );
        assert_eq!(
            report.verdict,
            if stale {
                Verdict::Indeterminate
            } else {
                Verdict::Valid
            }
        );
        assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    }
    assert_eq!(transport.0.load(Ordering::SeqCst), 0);
}
#[test]
fn offline_embedded_revocation_reports_invalid_without_network() {
    let transport = Arc::new(CountTransport(AtomicUsize::new(0)));
    let engine = engine(
        services(transport.clone(), network()),
        Duration::from_secs(5),
    );
    let input = with_carried_crls(&signed("inter-revoked-gost2015-sign"), true, false);
    let report = verify(&engine, &input, OperationPolicy::offline_report());
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.signers[0].revocation, CheckStatus::Failed);
    assert!(
        report.signers[0]
            .reasons
            .contains(&oncl_pki::validation::ValidationReason::Revoked { at: REVOKED })
    );
    assert_eq!(transport.0.load(Ordering::SeqCst), 0);
}

#[test]
fn trusted_but_unrelated_ocsp_responder_cannot_authorize_signer_status() {
    let mut responder = entry("ocsp-gost2015");
    responder.cert = oncl_pki::testing::issue_cert(
        &entry("root-gost2015.key"),
        oncl_pki::testing::TestCertSpec::from_cert(&responder.cert),
    );
    let transport = Arc::new(RouteTransport::new(vec![(
        "http://ocsp.synthetic.test".into(),
        Arc::new(FixedOcsp {
            inner: MockOcsp::new(responder),
            stale: false,
        }),
    )]));
    let engine = engine(services(transport, network()), Duration::from_secs(5));
    let report = verify(
        &engine,
        &signed("inter-user-gost2015-sign"),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(report.signers[0].revocation, CheckStatus::Unavailable);
}

#[test]
fn bounded_cms_checks_input_container_and_metadata_before_network() {
    let input = signed("inter-user-gost2015-sign");
    for (quota, expected) in [
        (0, oncl_core::ErrorCode::InputLimit),
        (1, oncl_core::ErrorCode::ContainerLimit),
        (2, oncl_core::ErrorCode::MetadataLimit),
    ] {
        let transport = Arc::new(CountTransport(AtomicUsize::new(0)));
        let mut limits = ResourceLimits::default();
        match quota {
            0 => limits.input_bytes = 1,
            1 => limits.container_bytes = 1,
            _ => limits.metadata_bytes = 1,
        }
        let engine = Engine::new(
            EngineServices::hash_only(limits)
                .with_validation(services(transport.clone(), network())),
        )
        .unwrap();
        let error = engine
            .validate_cms(
                &input,
                None,
                &mut context(&engine, OperationPolicy::strict_online()),
            )
            .unwrap_err();
        assert_eq!(error.code(), expected);
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
    }
}

// Review R2: a TSA has a distinct real CA/status source, so document-signer
// status cannot accidentally satisfy the timestamp's independent prerequisite.
const TSA_OCSP: &str = "http://tsa-status.synthetic.test";
const TSA_CRL: &str = "http://tsa-crl.synthetic.test/tsa.crl";
const TSA_ROOT_CRL: &str = "http://tsa-crl.synthetic.test/root.crl";
#[derive(Clone, Copy)]
enum TsaStatus {
    Good,
    Missing,
    Stale,
    Revoked(OffsetDateTime),
}
struct TsaFixture {
    authority: KeyEntry,
    signer: KeyEntry,
    responder: KeyEntry,
}
fn rewrite_fixture_uris(input: &[u8], uri: &[u8]) -> Vec<u8> {
    let any = AnyRef::from_der(input).unwrap();
    if input[0] == 0x86 {
        return tlv(0x86, uri);
    }
    if input[0] & 0x20 != 0 {
        return tlv(
            input[0],
            &children(input)
                .iter()
                .flat_map(|child| rewrite_fixture_uris(child, uri))
                .collect::<Vec<_>>(),
        );
    }
    tlv(input[0], any.value())
}
impl TsaFixture {
    fn new(ocsp_url: &str) -> Self {
        let mut authority = entry("user-gost2015-sign");
        let original = oncl_pki::testing::TestCertSpec::from_cert(&authority.cert);
        let mut ca_spec =
            oncl_pki::testing::TestCertSpec::from_cert(&entry("inter-gost2015.key").cert);
        ca_spec.subject = original.subject;
        ca_spec.public_key = original.public_key;
        ca_spec.serial = vec![0x71, 0x04];
        for extension in &mut ca_spec.extensions {
            if extension.extn_id.to_string() == "2.5.29.31" {
                extension.extn_value = der::asn1::OctetString::new(rewrite_fixture_uris(
                    extension.extn_value.as_bytes(),
                    TSA_ROOT_CRL.as_bytes(),
                ))
                .unwrap();
            }
        }
        authority.cert = oncl_pki::testing::issue_cert(&entry("root-gost2015.key"), ca_spec);
        let mut signer = entry("tsa-gost2015");
        let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&signer.cert);
        let leaf =
            oncl_pki::testing::TestCertSpec::from_cert(&entry("inter-user-gost2015-sign").cert);
        spec.extensions.retain(|ext| {
            !matches!(
                ext.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        });
        for mut extension in leaf.extensions {
            let uri = match extension.extn_id.to_string().as_str() {
                "1.3.6.1.5.5.7.1.1" => Some(ocsp_url),
                "2.5.29.31" => Some(TSA_CRL),
                _ => None,
            };
            if let Some(uri) = uri {
                extension.extn_value = der::asn1::OctetString::new(rewrite_fixture_uris(
                    extension.extn_value.as_bytes(),
                    uri.as_bytes(),
                ))
                .unwrap();
                spec.extensions.push(extension);
            }
        }
        signer.cert = oncl_pki::testing::issue_cert(&authority, spec);
        let mut responder = entry("ocsp-gost2015");
        responder.cert = oncl_pki::testing::issue_cert(
            &authority,
            oncl_pki::testing::TestCertSpec::from_cert(&responder.cert),
        );
        Self {
            authority,
            signer,
            responder,
        }
    }
    fn stamp(&self, input: &[u8]) -> Vec<u8> {
        tsp::stamp(
            input,
            SignerSel::Last,
            &TsaSpec::from(TsaProfile::basics_default()),
            StampMode::Replace,
            TokenForm::Token,
            &MockTsa::new(self.signer.clone()).with_gen_time(PROVEN),
        )
        .unwrap()
    }
    fn crl(&self, status: TsaStatus) -> Option<Vec<u8>> {
        if matches!(status, TsaStatus::Missing) {
            return None;
        }
        let stale = matches!(status, TsaStatus::Stale);
        let mut crl = MockCrl::new(self.authority.clone())
            // Embedded status is judged at the proof time: stale is issued before it.
            .with_this_update(if stale {
                PROVEN - time::Duration::hours(2)
            } else {
                NOW - time::Duration::MINUTE
            })
            .next_update(Some(if stale {
                PROVEN - time::Duration::HOUR
            } else {
                NOW + time::Duration::HOUR
            }));
        if let TsaStatus::Revoked(at) = status {
            crl = crl.revoke(
                self.signer
                    .cert
                    .tbs_certificate()
                    .serial_number()
                    .as_bytes(),
                at,
            );
        }
        Some(crl.der())
    }
    fn services(&self, status: TsaStatus, document_status: CertStatus) -> ValidationServices {
        self.services_with_document(status, pki(document_status, false))
    }
    fn services_with_document(
        &self,
        status: TsaStatus,
        document: Arc<dyn HttpTransport>,
    ) -> ValidationServices {
        let mut routes: Vec<(String, Arc<dyn HttpTransport>)> = vec![
            ("http://ocsp.synthetic.test".into(), document.clone()),
            ("http://crl.synthetic.test".into(), document),
        ];
        let root = MockCrl::new(entry("root-gost2015.key"))
            .with_this_update(NOW - time::Duration::MINUTE)
            .next_update(Some(NOW + time::Duration::HOUR))
            .der();
        routes.push((TSA_ROOT_CRL.into(), Arc::new(StaticCrl(root))));
        if !matches!(status, TsaStatus::Missing) {
            let serial: String = self
                .signer
                .cert
                .tbs_certificate()
                .serial_number()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let answer = match status {
                TsaStatus::Revoked(time) => CertStatus::Revoked {
                    time,
                    reason: Some(1),
                },
                _ => CertStatus::Good,
            };
            let issued = if matches!(status, TsaStatus::Stale) {
                NOW - time::Duration::hours(2)
            } else {
                NOW
            };
            routes.push((
                TSA_OCSP.into(),
                Arc::new(
                    MockOcsp::new(self.responder.clone())
                        .status(&serial, answer)
                        .with_now(issued),
                ),
            ));
            routes.push((
                TSA_CRL.into(),
                Arc::new(StaticCrl(self.crl(status).unwrap())),
            ));
        }
        ValidationServices::new(
            roots(),
            vec![cer("inter-gost2015"), self.authority.cert.clone()],
            Arc::new(RouteTransport::new(routes)),
            NetworkPolicy::only_endpoints([
                "http://ocsp.synthetic.test",
                "http://crl.synthetic.test",
                TSA_OCSP,
                TSA_CRL,
            ])
            .unwrap(),
            Arc::new(|| NOW),
        )
    }
    fn offline_services(&self, transport: Arc<dyn HttpTransport>) -> ValidationServices {
        ValidationServices::new(
            roots(),
            vec![cer("inter-gost2015"), self.authority.cert.clone()],
            transport,
            NetworkPolicy::only_endpoints([
                "http://ocsp.synthetic.test",
                "http://crl.synthetic.test",
                TSA_OCSP,
                TSA_CRL,
            ])
            .unwrap(),
            Arc::new(|| NOW),
        )
    }
}
struct StaticCrl(Vec<u8>);
impl HttpTransport for StaticCrl {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Ok(HttpReply {
            status: 200,
            content_type: Some("application/pkix-crl".into()),
            location: None,
            body: self.0.clone(),
        })
    }
}
fn carry_crl_values(input: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    let mut ci = children(input);
    let mut sd = children(&children(&ci[1])[0]);
    sd.insert(sd.len() - 1, tlv(0xa1, &values.concat()));
    ci[1] = tlv(0xa0, &seq(&sd));
    seq(&ci)
}
fn document_crls(revoked: bool) -> Vec<Vec<u8>> {
    [
        "http://crl.synthetic.test/inter-gost2015.crl",
        "http://crl.synthetic.test/root-gost2015.crl",
    ]
    .into_iter()
    .map(|url| {
        FixedCrl {
            revoked,
            stale: false,
        }
        .send(&HttpRequest::get(url, GetOptions::default()))
        .unwrap()
        .body
    })
    .collect()
}
fn assert_unproven_tsa(report: &oncl_core::VerificationReport, expected: CheckStatus) {
    assert_eq!(report.signers.len(), 1);
    let signer = &report.signers[0];
    assert_eq!(signer.signature, CheckStatus::Passed);
    assert_eq!(signer.chain, CheckStatus::Passed);
    assert_eq!(signer.timestamp, expected);
    assert_eq!(signer.time_basis, TimeBasis::Current(NOW));
    assert!(
        !signer.reasons.is_empty(),
        "unavailable/failed proof must explain its prerequisite"
    );
    assert_ne!(report.verdict, Verdict::Valid);
}
#[test]
fn tsa_revoked_before_proof_is_not_promoted() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let engine = engine(
        tsa.services(
            TsaStatus::Revoked(PROVEN - time::Duration::SECOND),
            CertStatus::Good,
        ),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &tsa.stamp(&signed("inter-user-gost2015-sign")),
        OperationPolicy::strict_online(),
    );
    assert_unproven_tsa(&report, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.signers[0].revocation,
        CheckStatus::Passed,
        "TSA failure is not document revocation"
    );
    assert!(report.signers[0].reasons.contains(
        &oncl_pki::validation::ValidationReason::TimestampRevoked {
            at: PROVEN - time::Duration::SECOND
        }
    ));
}
#[test]
fn tsa_revoked_at_proof_is_not_promoted() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let engine = engine(
        tsa.services(TsaStatus::Revoked(PROVEN), CertStatus::Good),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &tsa.stamp(&signed("inter-user-gost2015-sign")),
        OperationPolicy::strict_online(),
    );
    assert_unproven_tsa(&report, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}
#[test]
fn tsa_missing_current_status_is_unavailable_not_proof() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let engine = engine(
        tsa.services(TsaStatus::Missing, CertStatus::Good),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &tsa.stamp(&signed("inter-user-gost2015-sign")),
        OperationPolicy::strict_online(),
    );
    assert_unproven_tsa(&report, CheckStatus::Unavailable);
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert!(
        report.signers[0]
            .reasons
            .contains(&oncl_pki::validation::ValidationReason::TimestampRevocationUnavailable)
    );
    assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
}
#[test]
fn tsa_stale_current_status_is_unavailable_not_proof() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let engine = engine(
        tsa.services(TsaStatus::Stale, CertStatus::Good),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &tsa.stamp(&signed("inter-user-gost2015-sign")),
        OperationPolicy::strict_online(),
    );
    assert_unproven_tsa(&report, CheckStatus::Unavailable);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}
#[test]
fn tsa_revoked_after_proof_allows_historical_signer_with_current_evidence() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let engine = engine(
        tsa.services(
            TsaStatus::Revoked(PROVEN + time::Duration::SECOND),
            CertStatus::Revoked {
                time: REVOKED,
                reason: Some(1),
            },
        ),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &tsa.stamp(&signed("inter-revoked-gost2015-sign")),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Passed);
    assert_eq!(
        report.signers[0].time_basis,
        TimeBasis::VerifiedTimestamp(PROVEN)
    );
    assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
}
#[test]
fn stale_tsa_status_cannot_excuse_current_document_revocation() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let engine = engine(
        tsa.services(
            TsaStatus::Stale,
            CertStatus::Revoked {
                time: REVOKED,
                reason: Some(1),
            },
        ),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &tsa.stamp(&signed("inter-revoked-gost2015-sign")),
        OperationPolicy::strict_online(),
    );
    assert_unproven_tsa(&report, CheckStatus::Unavailable);
    assert_eq!(report.signers[0].revocation, CheckStatus::Failed);
    assert_eq!(
        report.verdict,
        Verdict::Invalid,
        "definite document failure still dominates unavailable TSA proof"
    );
}
#[test]
fn offline_tsa_missing_or_stale_carried_status_never_fetches_or_promotes() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let input = tsa.stamp(&signed("inter-user-gost2015-sign"));
    for status in [TsaStatus::Missing, TsaStatus::Stale] {
        let transport = Arc::new(CountTransport(AtomicUsize::new(0)));
        let mut values = document_crls(false);
        values.extend(tsa.crl(status));
        let engine = engine(
            tsa.offline_services(transport.clone()),
            Duration::from_secs(5),
        );
        let report = verify(
            &engine,
            &carry_crl_values(&input, &values),
            OperationPolicy::offline_report(),
        );
        assert_unproven_tsa(&report, CheckStatus::Unavailable);
        assert_eq!(report.verdict, Verdict::Indeterminate);
        assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn offline_tsa_carried_current_status_checks_revocation_at_proof_time() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let input = tsa.stamp(&signed("inter-user-gost2015-sign"));
    for revoked in [
        PROVEN - time::Duration::SECOND,
        PROVEN,
        PROVEN + time::Duration::SECOND,
    ] {
        let transport = Arc::new(CountTransport(AtomicUsize::new(0)));
        let mut values = document_crls(false);
        values.push(tsa.crl(TsaStatus::Revoked(revoked)).unwrap());
        let engine = engine(
            tsa.offline_services(transport.clone()),
            Duration::from_secs(5),
        );
        let report = verify(
            &engine,
            &carry_crl_values(&input, &values),
            OperationPolicy::offline_report(),
        );
        if revoked <= PROVEN {
            assert_unproven_tsa(&report, CheckStatus::Failed);
            assert_eq!(report.verdict, Verdict::Invalid);
        } else {
            assert_eq!(report.verdict, Verdict::Valid);
            assert_eq!(report.signers[0].timestamp, CheckStatus::Passed);
            assert_eq!(
                report.signers[0].time_basis,
                TimeBasis::VerifiedTimestamp(PROVEN)
            );
        }
        assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn all_signers_are_reported_and_later_revocation_dominates_good_signer() {
    let first = signed("inter-user-gost2015-sign");
    let input = cms::sign_spec(
        &entry("inter-revoked-gost2015-sign"),
        &chain(),
        &SignSpec {
            content: Content::Data(DATA),
            encapsulate: true,
            cosign: CoSign::Into(&first),
            econtent_type: None,
            digest: None,
            attrs: AttrSpec::cades(CLAIM),
            certificates: CertSpec::Signer,
        },
    )
    .unwrap();
    let engine = engine(
        services(
            pki(
                CertStatus::Revoked {
                    time: REVOKED,
                    reason: Some(1),
                },
                false,
            ),
            network(),
        ),
        Duration::from_secs(5),
    );
    let report = verify(&engine, &input, OperationPolicy::strict_online());
    assert_eq!(report.signers.len(), 2);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert!(report.signers.iter().all(
        |signer| signer.signature == CheckStatus::Passed && signer.chain == CheckStatus::Passed
    ));
    assert_eq!(
        report
            .signers
            .iter()
            .filter(|signer| signer.revocation == CheckStatus::Passed)
            .count(),
        1
    );
    assert_eq!(
        report
            .signers
            .iter()
            .filter(|signer| signer.revocation == CheckStatus::Failed)
            .count(),
        1
    );
}
#[test]
fn tsa_status_network_deadline_remains_typed_execution_error() {
    let server = Server::held();
    let tsa = TsaFixture::new(&server.url);
    let input = tsa.stamp(&signed("inter-user-gost2015-sign"));
    let document = pki(CertStatus::Good, false);
    let transport = RouteTransport::new(vec![
        (
            server.url.clone(),
            Arc::new(UreqTransport::default()) as Arc<dyn HttpTransport>,
        ),
        ("http://ocsp.synthetic.test".into(), document.clone()),
        ("http://crl.synthetic.test".into(), document),
    ]);
    let validation = ValidationServices::new(
        roots(),
        vec![cer("inter-gost2015"), tsa.authority.cert],
        Arc::new(transport),
        NetworkPolicy::only_endpoints([
            server.url.as_str(),
            "http://ocsp.synthetic.test",
            "http://crl.synthetic.test",
        ])
        .unwrap(),
        Arc::new(|| NOW),
    );
    let engine = engine(validation, Duration::from_millis(750));
    let mut ctx = context(&engine, OperationPolicy::strict_online());
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        tx.send(engine.validate_cms(&input, None, &mut ctx))
            .unwrap();
    });
    let result = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("TSA network wait obeys owning operation deadline");
    assert!(matches!(
        result,
        Err(OperationError::Processing(
            ProcessingError::DeadlineExceeded
        ))
    ));
    server
        .seen
        .recv_timeout(Duration::from_secs(1))
        .expect("real TSA request reached held local HTTP fixture");
    assert!(
        server.release.is_some(),
        "deadline result arrived before fixture response release"
    );
    worker.join().unwrap();
}

#[test]
fn tsa_good_current_status_establishes_independent_proof() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let engine = engine(
        tsa.services(TsaStatus::Good, CertStatus::Good),
        Duration::from_secs(5),
    );
    let report = verify(
        &engine,
        &tsa.stamp(&signed("inter-user-gost2015-sign")),
        OperationPolicy::strict_online(),
    );
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.signers[0].timestamp, CheckStatus::Passed);
    assert_eq!(
        report.signers[0].time_basis,
        TimeBasis::VerifiedTimestamp(PROVEN)
    );
    assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
}

#[test]
fn returned_validation_report_keeps_original_admission_until_dropped() {
    let engine = engine(
        services(pki(CertStatus::Good, false), network()),
        Duration::from_secs(5),
    );
    let mut first = context(&engine, OperationPolicy::strict_online());
    let report = engine
        .validate_cms(&signed("inter-user-gost2015-sign"), None, &mut first)
        .unwrap();
    assert_eq!(report.verdict, Verdict::Valid);
    drop(first);
    let error = engine
        .begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap_err();
    assert_eq!(error.code(), oncl_core::ErrorCode::CapacityExceeded);
    drop(report);
    let _next = context(&engine, OperationPolicy::strict_online());
}

#[test]
fn moved_scoped_signers_keep_exact_buffers_and_admission_until_collection_drop() {
    let engine = engine(
        services(pki(CertStatus::Good, false), network()),
        Duration::from_secs(5),
    );
    let mut first = context(&engine, OperationPolicy::strict_online());
    let (retained, original_buffer) = {
        let report = engine
            .validate_cms(&signed("inter-user-gost2015-sign"), None, &mut first)
            .unwrap();
        assert_eq!(report.verdict, Verdict::Valid);
        let original_buffer = report.signers.as_ptr();
        // Public consumer moves the whole owning collection out of the report.
        // The rest of the report is discarded at this block boundary.
        (report.signers, original_buffer)
    };
    drop(first);
    assert_eq!(
        retained.as_ptr(),
        original_buffer,
        "the same SDK buffers were moved, not copied"
    );
    {
        let view: &[oncl_pki::validation::SignerValidation] = &retained;
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].signature, CheckStatus::Passed);
        assert_eq!(view[0].revocation, CheckStatus::Passed);
        assert!(view[0].reasons.is_empty());
    }
    let error = engine
        .begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap_err();
    assert_eq!(error.code(), oncl_core::ErrorCode::CapacityExceeded);
    drop(retained);
    let _next = context(&engine, OperationPolicy::strict_online());
}

/// The `NcalayerCompatibility` relaxation (an anchored time-stamp fixes the validation time
/// although its TSA's status is unobtainable) with its negative contrasts: it never makes a
/// signature `Valid`, never hides a revocation before the token's time, is not applied to a
/// token of another signature, and does not exist in the strict and offline profiles.
#[test]
fn compat_time_relaxation_is_narrow_and_never_validates() {
    let tsa = TsaFixture::new(TSA_OCSP);
    let stamped = tsa.stamp(&signed("inter-revoked-gost2015-sign"));
    let run = |input: &[u8], document: CertStatus, policy: OperationPolicy| {
        let engine = engine(
            tsa.services(TsaStatus::Missing, document),
            Duration::from_secs(5),
        );
        verify(&engine, input, policy)
    };
    // Revoked AFTER the token's time: judged at the token's time, still not Valid.
    let after = CertStatus::Revoked {
        time: REVOKED,
        reason: None,
    };
    let report = run(&stamped, after, OperationPolicy::ncalayer_compatibility());
    let signer = &report.signers[0];
    assert_eq!(signer.time_basis, TimeBasis::VerifiedTimestamp(PROVEN));
    assert_eq!(signer.timestamp, CheckStatus::Unavailable);
    assert_eq!(signer.revocation, CheckStatus::Passed);
    assert_ne!(report.verdict, Verdict::Valid, "{signer:?}");

    // Revoked BEFORE the token's time: the revocation still counts.
    let before = CertStatus::Revoked {
        time: PROVEN - time::Duration::HOUR,
        reason: None,
    };
    let report = run(&stamped, before, OperationPolicy::ncalayer_compatibility());
    assert_eq!(report.signers[0].revocation, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);

    // Strict and offline profiles: the very same input does not move the time.
    for policy in [
        OperationPolicy::strict_online(),
        OperationPolicy::offline_report(),
    ] {
        let report = run(&stamped, after, policy);
        assert_ne!(report.verdict, Verdict::Valid);
        assert_eq!(report.signers[0].time_basis, TimeBasis::Current(NOW));
        assert_eq!(report.signers[0].timestamp, CheckStatus::Unavailable);
    }

    // A token of another signature is not a time proof, in any profile.
    let other = signed("inter-revoked-gost2015-sign");
    let old = oncl_pki::cms::verify(&stamped, None)
        .unwrap()
        .swap_remove(0)
        .signature;
    let new = oncl_pki::cms::verify(&other, None)
        .unwrap()
        .swap_remove(0)
        .signature;
    assert_eq!(old.len(), new.len());
    let at = stamped
        .windows(old.len())
        .position(|w| w == old.as_slice())
        .unwrap();
    let mut forged = stamped.clone();
    forged[at..at + new.len()].copy_from_slice(&new);
    let report = run(&forged, after, OperationPolicy::ncalayer_compatibility());
    let signer = &report.signers[0];
    assert_eq!(signer.time_basis, TimeBasis::Current(NOW), "{signer:?}");
    assert_eq!(signer.timestamp, CheckStatus::Failed);
    assert_ne!(report.verdict, Verdict::Valid);
}
