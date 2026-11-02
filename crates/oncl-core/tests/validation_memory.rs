//! Isolated R1 regression: peak live Rust allocations during real CMS validation.
//! The controller runs this separate integration binary; no source-text or RSS claim.
use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationError, OperationPolicy,
    ValidationServices,
};
use oncl_pki::{
    cert,
    cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec},
    crl::MockCrl,
    http::{GetOptions, HttpError, HttpReply, HttpRequest, HttpTransport},
    ocsp::{self, MockOcsp},
    pkcs12::{KeyEntry, load},
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
    validation::{CheckStatus, NetworkPolicy, Verdict},
};
use oncl_testkit::{read, synthetic, synthetic_cert};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use time::{OffsetDateTime, macros::datetime};

struct MeasuredSystem;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
fn added(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::SeqCst) + bytes;
    if ACTIVE.load(Ordering::SeqCst) {
        PEAK.fetch_max(live, Ordering::SeqCst);
    }
}
// SAFETY: every request is delegated unchanged to System. Counters use only
// atomics, allocate nothing and never inspect or change caller memory/layout.
unsafe impl GlobalAlloc for MeasuredSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated allocator contract is identical to the caller's.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            added(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated allocator contract is identical to the caller's.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            added(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // Every allocation is counted from process startup, including those
        // predating the measurement interval; freeing one cannot underflow a
        // reset interval-only counter. No counters are reset on deallocation.
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: caller supplies the original pointer and layout as required.
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: caller supplies a live allocation and valid requested size.
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            if size >= layout.size() {
                added(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::SeqCst);
            }
        }
        // A failed realloc leaves the old allocation live, so changes nothing.
        result
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredSystem = MeasuredSystem;
fn measured<T>(work: impl FnOnce() -> T) -> (T, usize) {
    assert!(!ACTIVE.load(Ordering::SeqCst));
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    ACTIVE.store(true, Ordering::SeqCst);
    let result = work();
    ACTIVE.store(false, Ordering::SeqCst);
    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    (result, peak)
}
const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const SIGNERS: usize = 64;
const RESPONSES: usize = 512;
const DATA: &[u8] = b"many real certificate renewals over one synthetic document";
fn entry(name: &str) -> KeyEntry {
    let f = synthetic(name);
    load(&read(f.path), &f.password).unwrap().remove(0)
}
fn children(input: &[u8]) -> Vec<Vec<u8>> {
    let any = AnyRef::from_der(input).unwrap();
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut result = vec![];
    while !reader.is_finished() {
        result.push(reader.decode::<AnyRef<'_>>().unwrap().to_der().unwrap());
    }
    result
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let length: Vec<_> = value
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | length.len() as u8);
        out.extend(length);
    }
    out.extend(value);
    out
}
fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn fixture() -> (Vec<u8>, usize) {
    let issuer = entry("inter-gost2015.key");
    let original = entry("inter-user-gost2015-sign");
    let responder = MockOcsp::new(entry("ocsp-gost2015")).with_now(NOW);
    let mut input = Vec::new();
    let mut common = Vec::new();
    let ri_ocsp = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.16.2")
        .to_der()
        .unwrap();
    for index in 0..RESPONSES {
        // Distinct genuinely issued renewal certificates reuse a test public key;
        // each signed status binds its own issuer/serial, with no dummy padding.
        let mut key = original.clone();
        let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&key.cert);
        spec.serial = (0x4000_u32 + index as u32).to_be_bytes().to_vec();
        key.cert = oncl_pki::testing::issue_cert(&issuer, spec);
        let request = ocsp::request_der(&key.cert, &issuer.cert);
        let reply = responder
            .send(&HttpRequest::post(
                "http://ocsp.synthetic.test",
                Some("application/ocsp-request"),
                &request,
                GetOptions::default(),
            ))
            .unwrap();
        assert_eq!(reply.status, 200);
        let mut carried = ri_ocsp.clone();
        carried.extend(reply.body);
        common.extend(tlv(0xa1, &carried));
        if index < SIGNERS {
            let spec = SignSpec {
                content: Content::Data(DATA),
                encapsulate: true,
                cosign: if input.is_empty() {
                    CoSign::Never
                } else {
                    CoSign::Into(&input)
                },
                econtent_type: None,
                digest: None,
                attrs: AttrSpec::cades(NOW),
                certificates: CertSpec::Extra(vec![
                    issuer.cert.clone(),
                    entry("root-gost2015.key").cert,
                ]),
            };
            input = cms::sign_spec(&key, &[], &spec).unwrap();
        }
    }
    // The common evidence consists of real signed OCSPResponses. A current root
    // CRL separately completes the document intermediate's required status.
    let common_bytes = common.len();
    let root_crl = MockCrl::new(entry("root-gost2015.key"))
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR))
        .der();
    common.extend(root_crl);
    let mut ci = children(&input);
    let mut sd = children(&children(&ci[1])[0]);
    sd.insert(sd.len() - 1, tlv(0xa1, &common));
    ci[1] = tlv(0xa0, &sequence(&sd));
    (sequence(&ci), common_bytes)
}
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct NoNetwork(AtomicUsize);
impl HttpTransport for NoNetwork {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(HttpError::other("offline fixture must not fetch"))
    }
}
fn validate(
    input: &[u8],
    memory: usize,
    network: Arc<NoNetwork>,
) -> (Result<oncl_core::VerificationReport, OperationError>, usize) {
    let limits = ResourceLimits {
        memory_bytes: memory as u64,
        metadata_bytes: 4 << 20,
        operation_timeout: Duration::from_secs(60),
        ..ResourceLimits::default()
    };
    let services = ValidationServices::new(
        CaSet::new(vec![cert::parse(&synthetic_cert("root-gost2015")).unwrap()]),
        vec![entry("inter-gost2015.key").cert],
        network,
        NetworkPolicy::only_endpoints(["http://ocsp.synthetic.test", "http://crl.synthetic.test"])
            .unwrap(),
        Arc::new(|| NOW),
    );
    let engine = Engine::new(EngineServices::hash_only(limits).with_validation(services)).unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Validate]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    measured(|| engine.validate_cms(input, None, &mut ctx))
}
fn assert_all_signers(report: &oncl_core::VerificationReport) {
    assert_eq!(report.signers.len(), SIGNERS);
    assert_eq!(report.verdict, Verdict::Valid);
    assert!(
        report
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed
                && s.chain == CheckStatus::Passed
                && s.validity == CheckStatus::Passed
                && s.revocation == CheckStatus::Passed)
    );
}
#[test]
fn many_signers_share_common_signed_evidence_within_operation_memory_budget() {
    let (input, common_bytes) = fixture();
    assert!(
        input.len() < 2 << 20,
        "fixture must remain moderate, not an OOM probe"
    );
    // Host selects a small linear envelope, not a signer*evidence allowance.
    // Actual peak is measured independently of the resource reservation counters.
    let memory = input.len() * 20 + (1 << 20);
    assert!(
        common_bytes * SIGNERS > memory * 2,
        "fixture must expose multiplicative retention with a wide margin"
    );
    let network = Arc::new(NoNetwork(AtomicUsize::new(0)));
    let (result, peak) = validate(&input, memory, network.clone());
    assert!(
        peak <= memory,
        "actual additional peak {peak} exceeds configured operation memory {memory}"
    );
    match result {
        Ok(report) => assert_all_signers(&report),
        Err(OperationError::Processing(ProcessingError::MemoryLimit)) => {}
        Err(error) => panic!("bounded evidence handling returned unrelated error: {error}"),
    }
    assert_eq!(network.0.load(Ordering::SeqCst), 0);
    // A genuine quota refusal is acceptable above, but the same signed input
    // must complete with all signer results when the host supplies more memory.
    let (result, peak) = validate(&input, memory * 4, network.clone());
    assert!(peak <= memory * 4);
    assert_all_signers(&result.unwrap());
    assert_eq!(network.0.load(Ordering::SeqCst), 0);
}
