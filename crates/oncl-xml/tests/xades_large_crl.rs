//! NCANode/Kalkan XAdES-LT carries the complete CA CRL (about 20 MB) as base64 in
//! `xades:EncapsulatedCRLValue`. The metadata cap bounds markup only: that text streams
//! from the source into the evidence store, charged to the host's evidence quotas before
//! anything is allocated, and is never materialised as a string or a DOM.
//! Peak live Rust allocations are measured independently of the reservation counters.
#[path = "support/xades_pki.rs"]
mod xades_pki;
use oncl_pki::{
    evidence::{AdesLevel, EvidenceError, EvidenceLimits},
    io::{Source, TemporaryStore},
    resource::{ProcessingError, ResourceLimits, SharedBudget},
    validation::{CheckStatus, NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
};
use oncl_xml::{XmlSourceError, XmlVerification, XmlVerifyProfile};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use xades_pki::{Control, NOW, Offline, Pki, REVOKED};

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
/// The tests of this binary share one allocator counter: each holds this throughout.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Base64 in the lines Santuario/NCANode write: 76 characters and `&#13;` + LF.
fn wrapped(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("&#13;\n")
}
/// `lt` with the signer's OCSP answer (the last of the signature: the one of the
/// timestamp authority precedes it) replaced by `crls` as the only revocation data.
fn with_crls(lt: &str, crls: &[String]) -> String {
    let start = lt.rfind("<xades:OCSPValues>").expect("OCSP values");
    let end =
        start + lt[start..].find("</xades:OCSPValues>").unwrap() + "</xades:OCSPValues>".len();
    let values: String = crls
        .iter()
        .map(|text| format!("<xades:EncapsulatedCRLValue>{text}</xades:EncapsulatedCRLValue>"))
        .collect();
    format!(
        "{}<xades:CRLValues>{values}</xades:CRLValues>{}",
        &lt[..start],
        &lt[end..]
    )
}

fn limits(crl_item: u64, crl_total: u64) -> EvidenceLimits {
    EvidenceLimits {
        max_items: 64,
        max_bytes: 4 << 20,
        max_item_bytes: 1 << 20,
        max_crl_bytes: crl_total,
        max_crl_item_bytes: crl_item,
        max_total_bytes: crl_total + (4 << 20),
        max_chain_len: 8,
        max_proofs: 8,
        max_coverage_parts: 1024,
        max_coverage_bytes: 1 << 30,
    }
}
fn verify(
    pki: &Pki,
    xml: &str,
    evidence: Option<EvidenceLimits>,
) -> (Result<XmlVerification, XmlSourceError>, usize) {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let http = Offline;
    let context = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: NOW,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &http,
    };
    let profile = XmlVerifyProfile {
        required_level: Some(AdesLevel::Lt),
        evidence_limits: evidence,
        ..Default::default()
    };
    measured(|| {
        oncl_xml::verify_source(
            Source::sequential(&mut Cursor::new(xml.as_bytes()), Some(xml.len() as u64)),
            &profile,
            &store,
            &context,
            &NetworkPolicy::deny_all(),
            &mut scope,
        )
    })
}

#[test]
fn a_complete_crl_over_the_markup_cap_verifies_and_costs_one_copy_not_a_tree() {
    let _serial = serial();
    let mut pki = Pki::new();
    let lt = pki.lt();
    let big = pki.crl(REVOKED, false, false);
    assert!(
        big.len() > 4 << 20,
        "fixture must exceed 4 MiB: {}",
        big.len()
    );
    let big_doc = with_crls(&lt, &[wrapped(&big)]);
    assert!(big_doc.len() > 4 * 262144);
    let big_limits = limits(32 << 20, 32 << 20);
    let (result, peak) = verify(&pki, &big_doc, Some(big_limits));
    let report = result.unwrap_or_else(|error| panic!("big CRL: {error:?}"));
    let signer = &report.validation.signers[0];
    assert_eq!(signer.signature, CheckStatus::Passed);
    assert_eq!(signer.chain, CheckStatus::Passed);
    assert_eq!(signer.timestamp, CheckStatus::Passed);
    // The signer is absent from the complete CRL of its issuer: good, not unknown.
    assert_eq!(signer.revocation, CheckStatus::Passed);
    assert_eq!(report.validation.verdict, Verdict::Valid);
    assert_eq!(report.signatures()[0].level, Some(AdesLevel::Lt));
    assert!(
        report.signatures()[0]
            .references()
            .iter()
            .all(|r| r.digest_matches)
    );
    drop(report);
    eprintln!(
        "peak {peak} B for a {} B CRL in a {} B document",
        big.len(),
        big_doc.len()
    );
    // The readback of the CRL for its scan is the one copy; fixed buffers apart, nothing
    // else is proportional to it. The string + DOM + decode path this replaces cost
    // more than the document size alone, and a CRL under 1 MiB (normalized from BER, so
    // amplified) is a different regime: the figure here is for a scanned DER CRL.
    assert!(
        peak <= 2 * big.len() + (1 << 20),
        "{peak} live bytes for a {} B CRL (document {} B)",
        big.len(),
        big_doc.len()
    );
}

#[test]
fn a_revoked_signer_is_found_inside_a_complete_crl_over_the_markup_cap() {
    let _serial = serial();
    let mut pki = Pki::new();
    let lt = pki.lt();
    let big = pki.crl(REVOKED, true, false);
    let doc = with_crls(&lt, &[wrapped(&big)]);
    let (result, _) = verify(&pki, &doc, Some(limits(32 << 20, 32 << 20)));
    let report = result.unwrap_or_else(|error| panic!("{error:?}"));
    let signer = &report.validation.signers[0];
    assert_eq!(signer.signature, CheckStatus::Passed);
    assert_eq!(signer.revocation, CheckStatus::Failed);
    assert_eq!(report.validation.verdict, Verdict::Invalid);
}

#[test]
fn a_crl_signed_by_another_key_gives_no_status_even_when_it_lists_the_signer() {
    let _serial = serial();
    let mut pki = Pki::new();
    let lt = pki.lt();
    let big = pki.crl(REVOKED / 4, true, true);
    let doc = with_crls(&lt, &[wrapped(&big)]);
    let (result, _) = verify(&pki, &doc, Some(limits(32 << 20, 32 << 20)));
    let report = result.unwrap_or_else(|error| panic!("{error:?}"));
    let signer = &report.validation.signers[0];
    assert_eq!(signer.signature, CheckStatus::Passed);
    // Not authenticated: neither "revoked" nor "good".
    assert_ne!(signer.revocation, CheckStatus::Passed);
    assert_ne!(signer.revocation, CheckStatus::Failed);
    assert_ne!(report.validation.verdict, Verdict::Valid);
}

#[test]
fn crl_quotas_bound_the_decoded_bytes_item_aggregate_and_limit_plus_one() {
    let _serial = serial();
    let mut pki = Pki::new();
    let lt = pki.lt();
    let crl = pki.crl(REVOKED / 10, false, false);
    let exact = crl.len() as u64;
    assert!(exact > 262144, "must be over the markup cap: {exact}");
    let doc = with_crls(&lt, &[wrapped(&crl)]);
    let (ok, _) = verify(&pki, &doc, Some(limits(exact, exact)));
    assert_eq!(ok.unwrap().validation.verdict, Verdict::Valid, "limit");
    let (item, _) = verify(&pki, &doc, Some(limits(exact - 1, exact)));
    assert!(
        matches!(item, Err(XmlSourceError::Evidence(EvidenceError::Limit))),
        "item limit + 1: {item:?}"
    );
    let (total, _) = verify(&pki, &doc, Some(limits(exact, exact - 1)));
    assert!(
        matches!(total, Err(XmlSourceError::Evidence(EvidenceError::Limit))),
        "aggregate limit + 1: {total:?}"
    );
    // Two CRLs, each within the item quota, over the aggregate one.
    let two = with_crls(&lt, &[wrapped(&crl), wrapped(&crl)]);
    let (aggregate, _) = verify(&pki, &two, Some(limits(exact, exact + exact / 2)));
    assert!(
        matches!(
            aggregate,
            Err(XmlSourceError::Evidence(EvidenceError::Limit))
        ),
        "aggregate: {aggregate:?}"
    );
    // Unconfigured hosts keep the small defaults scaled from the metadata cap.
    let (defaults, _) = verify(&pki, &doc, None);
    assert!(
        matches!(
            defaults,
            Err(XmlSourceError::Evidence(EvidenceError::Limit))
        ),
        "defaults: {defaults:?}"
    );
}

#[test]
fn a_hostile_crl_claim_is_refused_by_the_quota_before_it_is_allocated() {
    let _serial = serial();
    let mut pki = Pki::new();
    let lt = pki.lt();
    // 24 MiB of base64 (18 MiB decoded) against a 1 MiB CRL quota.
    let claim = "A".repeat(24 << 20);
    let doc = with_crls(&lt, &[claim]);
    let (result, peak) = verify(&pki, &doc, Some(limits(1 << 20, 1 << 20)));
    assert!(
        matches!(result, Err(XmlSourceError::Evidence(EvidenceError::Limit))),
        "untyped refusal {result:?}"
    );
    assert!(peak < 8 << 20, "hostile claim allocated {peak}");
}

/// Structural markup, unlike evidence text, stays bounded by the metadata cap, to the byte.
#[test]
fn the_metadata_cap_still_bounds_markup_to_the_byte_and_ignores_only_evidence_text() {
    let _serial = serial();
    let mut pki = Pki::new();
    let lt = pki.lt();
    let crl = pki.crl(2_000, false, false);
    let text = wrapped(&crl);
    let doc = with_crls(&lt, std::slice::from_ref(&text));
    let open = doc.rfind("<xades:RevocationValues").unwrap();
    let close = open
        + doc[open..].find("</xades:RevocationValues>").unwrap()
        + "</xades:RevocationValues>".len();
    let markup = close - open - text.len();
    let cap = XmlVerifyProfile::default().max_metadata_bytes;
    let filler = |bytes: usize| format!("<!--{}-->", "x".repeat(bytes - 7));
    let padded = |markup_bytes: usize| {
        let extra = markup_bytes - markup;
        doc.replacen(
            "<xades:CRLValues>",
            &format!("<xades:CRLValues>{}", filler(extra)),
            1,
        )
    };
    let wide = Some(limits(32 << 20, 32 << 20));
    let (at, _) = verify(&pki, &padded(cap), wide);
    assert_eq!(at.unwrap().validation.verdict, Verdict::Valid, "cap");
    let (over, _) = verify(&pki, &padded(cap + 1), wide);
    assert!(
        matches!(
            over,
            Err(XmlSourceError::Processing(ProcessingError::MetadataLimit))
        ),
        "cap + 1: {over:?}"
    );
}

#[test]
fn text_is_decoded_like_the_dom_and_hostile_text_is_typed() {
    let _serial = serial();
    let mut pki = Pki::new();
    let lt = pki.lt();
    let crl = pki.crl(500, false, false);
    let plain = wrapped(&crl);
    // Entity references, CDATA and comments split the text; whitespace is ignored.
    let (head, tail) = plain.split_at(plain.len() / 2);
    let cut = tail.find("&#13;").unwrap();
    let (a, b) = tail.split_at(cut);
    let mixed = format!("{head}<!-- c --><![CDATA[{a}]]>{b}&#32;&#x9;");
    let (reference, _) = verify(&pki, &with_crls(&lt, std::slice::from_ref(&plain)), None);
    let (decoded, _) = verify(&pki, &with_crls(&lt, &[mixed]), None);
    let (reference, decoded) = (reference.unwrap(), decoded.unwrap());
    assert_eq!(reference.validation.verdict, Verdict::Valid);
    assert_eq!(decoded.validation.verdict, Verdict::Valid);
    assert_eq!(
        decoded.validation.signers[0].revocation,
        reference.validation.signers[0].revocation
    );
    for (name, bad) in [
        ("nested markup", format!("{plain}<x/>")),
        (
            "foreign element",
            format!("<ds:Foreign>{plain}</ds:Foreign>"),
        ),
        ("bad character", format!("{plain}*")),
        ("bad reference", format!("{plain}&amp;")),
        ("unknown reference", format!("{plain}&bogus;")),
    ] {
        let (result, _) = verify(&pki, &with_crls(&lt, &[bad]), None);
        assert!(
            !matches!(&result, Ok(v) if v.validation.verdict == Verdict::Valid),
            "{name} must not be Valid"
        );
        assert!(
            matches!(
                result,
                Err(XmlSourceError::Malformed(_)
                    | XmlSourceError::Xml(_)
                    | XmlSourceError::Unsupported(_)
                    | XmlSourceError::Processing(ProcessingError::InvalidInput(_)))
            ),
            "{name}: untyped {result:?}"
        );
    }
}
