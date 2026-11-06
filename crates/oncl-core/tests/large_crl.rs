//! D1: an NCANode/Kalkan LT signature embeds the complete NCA CRL (about 20 MB). Real
//! verification must admit it under the default limits, scan it instead of decoding it
//! into a tree, still find a revoked signer (and not invent one), and still refuse a
//! hostile declaration with a typed error instead of allocating it.
//! Peak live Rust allocations are measured independently of the reservation counters.
use der::asn1::AnyRef;
use der::{Decode, Encode, Reader, SliceReader};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationError, OperationPolicy,
    ValidationServices, VerifyRequest,
};
use oncl_pki::{
    cert,
    cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec},
    crl::MockCrl,
    evidence::{AdesLevel, EvidenceLimits},
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::{Source, TemporaryStore},
    pkcs12::{KeyEntry, load},
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
    validation::{CheckStatus, NetworkPolicy, Verdict},
};
use oncl_testkit::{read, synthetic, synthetic_cert};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
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
        // Allocations made before the measured interval may be freed inside it.
        let _ = LIVE.try_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
            Some(live.saturating_sub(layout.size()))
        });
        // SAFETY: the pointer and layout are exactly those of the matching allocation.
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: delegated allocator contract is identical to the caller's.
        let result = unsafe { System.realloc(pointer, layout, new_size) };
        if !result.is_null() {
            let _ = LIVE.try_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
                Some(live.saturating_sub(layout.size()))
            });
            added(new_size);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredSystem = MeasuredSystem;
fn measured<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    ACTIVE.store(true, Ordering::SeqCst);
    let result = work();
    ACTIVE.store(false, Ordering::SeqCst);
    (result, PEAK.load(Ordering::SeqCst).saturating_sub(baseline))
}
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// The tests of this binary allocate concurrently and share one allocator counter:
/// each holds this for its whole duration.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poison| poison.into_inner())
}

const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const DATA: &[u8] = b"document signed with an LT-style complete CRL";
/// Entries of the big CRL: about 6.5 MB of DER, over the 4 MiB where a 16x container
/// charge exceeds the default 64 MiB metadata budget.
const REVOKED: u32 = 260_000;

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
/// A CMS signed by `signer` with `revocation` as its [1] revocation set.
fn with_revocation_set(signer: &KeyEntry, revocation: &[u8]) -> Vec<u8> {
    let spec = SignSpec {
        content: Content::Data(DATA),
        encapsulate: true,
        cosign: CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs: AttrSpec::cades(NOW),
        certificates: CertSpec::Extra(vec![
            entry("inter-gost2015.key").cert,
            entry("root-gost2015.key").cert,
        ]),
    };
    let signed = cms::sign_spec(signer, &[], &spec).unwrap();
    let mut ci = children(&signed);
    let mut sd = children(&children(&ci[1])[0]);
    sd.insert(sd.len() - 1, revocation.to_vec());
    ci[1] = tlv(0xa0, &sequence(&sd));
    sequence(&ci)
}
fn signer() -> KeyEntry {
    entry("inter-user-gost2015-sign")
}
/// The intermediate's complete CRL revoking `REVOKED` unrelated serials and, when
/// asked, the signer too (in the middle of the list). The root CRL completes the chain.
fn revocation_set(revoked: u32, revoke_signer: bool) -> (Vec<u8>, usize) {
    type Built = ((u32, bool), (Vec<u8>, usize));
    static CACHE: std::sync::Mutex<Vec<Built>> = std::sync::Mutex::new(Vec::new());
    let mut cache = CACHE.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some((_, value)) = cache
        .iter()
        .find(|(key, _)| *key == (revoked, revoke_signer))
    {
        return value.clone();
    }
    let value = build_revocation_set(revoked, revoke_signer);
    cache.push(((revoked, revoke_signer), value.clone()));
    value
}
fn build_revocation_set(revoked: u32, revoke_signer: bool) -> (Vec<u8>, usize) {
    let signer_serial = signer()
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .to_vec();
    let mut crl = MockCrl::new(entry("inter-gost2015.key"))
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR));
    for index in 0..revoked {
        if revoke_signer && index == revoked / 2 {
            crl = crl.revoke_with_reason(&signer_serial, NOW - time::Duration::DAY, 1);
        }
        let serial = (0x0100_0000_u32 + index).to_be_bytes();
        crl = crl.revoke(&serial, NOW - time::Duration::DAY);
    }
    let big = crl.der();
    let root = MockCrl::new(entry("root-gost2015.key"))
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR))
        .der();
    let size = big.len();
    (tlv(0xa1, &[big, root].concat()), size)
}

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct NoNetwork;
impl HttpTransport for NoNetwork {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline fixture must not fetch"))
    }
}
fn engine(dir: &std::path::Path) -> Engine {
    let services = ValidationServices::new(
        CaSet::new(vec![cert::parse(&synthetic_cert("root-gost2015")).unwrap()]),
        vec![entry("inter-gost2015.key").cert],
        Arc::new(NoNetwork),
        NetworkPolicy::only_endpoints(Vec::<String>::new()).unwrap(),
        Arc::new(|| NOW),
    );
    Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(services)
            .with_temporary_store(TemporaryStore::new(dir).unwrap()),
    )
    .unwrap()
}
fn evidence_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 64,
        max_bytes: 32 << 20,
        max_item_bytes: 16 << 20,
        max_crl_bytes: 32 << 20,
        max_crl_item_bytes: 16 << 20,
        max_total_bytes: 32 << 20,
        max_chain_len: 8,
        max_proofs: 8,
        max_coverage_parts: 1024,
        max_coverage_bytes: 1 << 30,
    }
}
type Verified = Result<oncl_core::VerificationReport, OperationError>;
fn verify(request: &VerifyRequest, input: &[u8]) -> (Verified, usize) {
    let dir = tempfile::tempdir().unwrap();
    let engine = engine(dir.path());
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    measured(|| {
        engine.verify(
            request,
            Source::sequential(&mut Cursor::new(input), Some(input.len() as u64)),
            None,
            &mut ctx,
        )
    })
}
fn requests() -> [(&'static str, VerifyRequest); 2] {
    [
        ("cms", VerifyRequest::cms()),
        (
            "cades-b",
            VerifyRequest::cades(AdesLevel::B, evidence_limits()),
        ),
    ]
}

#[test]
fn a_complete_crl_of_the_nca_size_is_scanned_not_materialised() {
    let _serial = serial();
    let (set, crl_len) = revocation_set(REVOKED, false);
    assert!(crl_len > 4 << 20, "fixture must exceed 4 MiB: {crl_len}");
    let (small_set, small_len) = revocation_set(REVOKED / 4, false);
    let small_input = with_revocation_set(&signer(), &small_set);
    let input = with_revocation_set(&signer(), &set);
    for (name, request) in requests() {
        let (result, peak) = verify(&request, &input);
        let report = result.unwrap_or_else(|error| panic!("{name}: {error}"));
        let signer = &report.signers[0];
        assert_eq!(signer.signature, CheckStatus::Passed, "{name}");
        assert_eq!(signer.chain, CheckStatus::Passed, "{name}");
        // The signer is absent from the complete CRL of its issuer: good, not unknown.
        assert_eq!(signer.revocation, CheckStatus::Passed, "{name}");
        assert_eq!(report.verdict, Verdict::Valid, "{name}");
        // Fixed reader buffers aside, each further CRL byte costs a few copies at most,
        // never a decoded tree (the old charge was 16x to 128x per byte).
        let (small, small_peak) = verify(&request, &small_input);
        assert_eq!(small.unwrap().verdict, Verdict::Valid, "{name}");
        let marginal = peak.saturating_sub(small_peak);
        eprintln!("{name}: peak {peak} (crl {crl_len}) vs {small_peak} (crl {small_len})");
        assert!(
            marginal <= (crl_len - small_len) * 4,
            "{name}: {} extra bytes cost {marginal}",
            crl_len - small_len
        );
    }
}

#[test]
fn a_revoked_signer_is_found_inside_a_complete_crl_of_the_nca_size() {
    let _serial = serial();
    let (set, crl_len) = revocation_set(REVOKED, true);
    assert!(crl_len > 4 << 20);
    let input = with_revocation_set(&signer(), &set);
    for (name, request) in requests() {
        let (result, peak) = verify(&request, &input);
        let report = result.unwrap_or_else(|error| panic!("{name}: {error}"));
        let signer = &report.signers[0];
        assert_eq!(signer.signature, CheckStatus::Passed, "{name}");
        assert_eq!(signer.revocation, CheckStatus::Failed, "{name}");
        assert_eq!(report.verdict, Verdict::Invalid, "{name}");
        eprintln!("{name}: revoked-signer peak {peak} (crl {crl_len})");
    }
}

#[test]
fn a_crl_signed_by_another_key_is_not_scanned_into_a_status() {
    let _serial = serial();
    // The serial IS listed, but the list is not issued by the signer's issuer.
    let signer_serial = signer()
        .cert
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .to_vec();
    let mut crl = MockCrl::new(entry("inter-gost2015.key"))
        .with_this_update(NOW - time::Duration::MINUTE)
        .next_update(Some(NOW + time::Duration::HOUR))
        .wrong_key();
    for index in 0..REVOKED {
        crl = crl.revoke(
            &(0x0100_0000_u32 + index).to_be_bytes(),
            NOW - time::Duration::DAY,
        );
    }
    crl = crl.revoke(&signer_serial, NOW - time::Duration::DAY);
    let set = tlv(0xa1, &crl.der());
    let input = with_revocation_set(&signer(), &set);
    let (result, _) = verify(&VerifyRequest::cms(), &input);
    let report = result.unwrap();
    // Not authenticated, so neither "revoked" nor "good": no usable status at all.
    assert_ne!(report.signers[0].revocation, CheckStatus::Passed);
    assert_ne!(report.signers[0].revocation, CheckStatus::Failed);
}

/// A TLV whose declared length is `extra` bytes more than its value: the stream is cut
/// short, as a hostile or corrupt file is.
fn declared(tag: u8, value: &[u8], extra: u64) -> Vec<u8> {
    let total = value.len() as u64 + extra;
    let length: Vec<_> = total
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let mut out = vec![tag, 0x80 | length.len() as u8];
    out.extend(length);
    out.extend(value);
    out
}

#[test]
fn a_hostile_crl_set_length_is_refused_with_a_typed_error_before_it_is_allocated() {
    let _serial = serial();
    const CLAIM: u64 = 4 << 30;
    let intact = with_revocation_set(&signer(), &tlv(0xa1, &[]));
    let mut ci = children(&intact);
    let mut sd = children(&children(&ci[1])[0]);
    let position = sd.len() - 2;
    // The [1] set claims 4 GiB more than the file holds; every parent claims it too.
    let set_header = {
        let mut header = vec![0xa1, 0x85];
        header.extend(CLAIM.to_be_bytes()[3..].iter().copied());
        header
    };
    sd[position] = set_header;
    let signed = declared(0x30, &sd.concat(), CLAIM);
    ci[1] = declared(0xa0, &signed, CLAIM);
    let hostile = declared(0x30, &ci.concat(), CLAIM);
    for (name, request) in requests() {
        let (result, peak) = verify(&request, &hostile);
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{name}: must not verify"));
        assert!(
            matches!(
                error,
                OperationError::Processing(
                    ProcessingError::MemoryLimit
                        | ProcessingError::MetadataLimit
                        | ProcessingError::InputLimit
                )
            ),
            "{name}: untyped refusal {error:?}"
        );
        assert!(peak < 8 << 20, "{name}: hostile length allocated {peak}");
    }
}

#[test]
fn a_big_crl_must_be_minimal_der_not_renormalized_ber() {
    let _serial = serial();
    let (set, _) = revocation_set(REVOKED, false);
    // Re-wrap the big CRL with a redundant leading zero length octet: BER-valid, not
    // DER, and over the size up to which a CRL may be BER-normalized.
    let mut parts = children(&set);
    let first = parts.remove(0);
    let value = AnyRef::from_der(&first).unwrap().value().to_vec();
    let mut padded = vec![0x30, 0x85, 0x00];
    padded.extend((value.len() as u32).to_be_bytes());
    padded.extend(value);
    parts.insert(0, padded);
    let input = with_revocation_set(&signer(), &tlv(0xa1, &parts.concat()));
    for (name, request) in requests() {
        let (result, _) = verify(&request, &input);
        assert!(result.is_err(), "{name}: a non-DER big CRL must be refused");
    }
}
