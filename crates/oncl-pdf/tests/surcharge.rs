//! Own signed PDF readback: the signature container is a surcharge on top of the
//! document allowance, never a second document and never unbounded.
use oncl_pdf::{PdfError, PdfLimits, PdfSignProfile, sign_source, verify_source};
use oncl_pki::{
    cms::stream::CmsSignServices,
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::{Source, TemporaryStore},
    key::SigAlg,
    pkix::CaSet,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
    validation::{ValidationContext, ValidationPolicy},
};
use std::{io::Cursor, sync::Arc};

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        panic!("offline")
    }
}
fn scope(limits: ResourceLimits) -> ResourceScope {
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
fn sign(source: &[u8]) -> Vec<u8> {
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let mut s = scope(ResourceLimits::default());
    let f = oncl_testkit::synthetic("user-rsa-sign");
    let mut key = oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0);
    let mut out = store.stage(&mut s).unwrap();
    sign_source(
        Source::seekable(&mut Cursor::new(source), None),
        &PdfSignProfile::default(),
        &mut key,
        &CmsSignServices::new(None, Some(&store)),
        &mut out,
        &s,
    )
    .unwrap();
    let mut v = Vec::new();
    out.copy_to(&mut v).unwrap();
    v
}
fn verify(bytes: &[u8], limits: ResourceLimits) -> (Result<(), PdfError>, ResourceScope) {
    verify_with(bytes, limits, &PdfLimits::default())
}
fn verify_with(
    bytes: &[u8],
    limits: ResourceLimits,
    pdf: &PdfLimits,
) -> (Result<(), PdfError>, ResourceScope) {
    let mut s = scope(limits);
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let anchors = CaSet::new(vec![
        oncl_pki::cert::parse(include_bytes!("fixtures/external-cert.der")).unwrap(),
    ]);
    let r = verify_source(
        Source::seekable(&mut Cursor::new(bytes), None),
        pdf,
        &store,
        &ValidationContext {
            policy: ValidationPolicy::OfflineReport,
            now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
            anchors: &anchors,
            intermediates: &[],
            http: &Offline,
        },
        &[SigAlg::RsaSha256],
        &mut s,
    )
    .map(|_| ());
    (r, s)
}

#[test]
fn own_signed_pdf_verifies_with_document_exact_input_limit() {
    let source = include_bytes!("fixtures/external-multipage.pdf");
    let signed = sign(source);
    let surcharge = signed.len() as u64 - source.len() as u64;
    assert!(surcharge > 0);
    let limits = |input_bytes: u64, container_bytes: u64| ResourceLimits {
        input_bytes,
        container_bytes,
        ..ResourceLimits::default()
    };
    // Honest readback of own result: document allowance unchanged.
    let (r, s) = verify(&signed, limits(source.len() as u64, 1 << 20));
    r.unwrap();
    assert_eq!(s.progress().bytes_in, signed.len() as u64);
    // Document limit+1 is still rejected.
    let (r, _) = verify(&signed, limits(source.len() as u64 - 1, 1 << 20));
    assert!(matches!(
        r,
        Err(PdfError::Processing(ProcessingError::InputLimit))
    ));
    // Surcharge beyond the container allowance is not accepted as overhead.
    let (r, _) = verify(&signed, limits(source.len() as u64, surcharge - 1));
    assert!(matches!(
        r,
        Err(PdfError::Processing(ProcessingError::InputLimit))
    ));
    // Tail beyond the format-derived increment bound (4 objects per appended
    // revision) is rejected even though container_bytes (1 GiB) would allow it.
    let tiny = PdfLimits {
        max_revisions: 2,
        max_object_bytes: (surcharge as usize - 1) / 4,
        max_evidence_bytes: 0,
        ..PdfLimits::default()
    };
    assert!(super_cap(&tiny) < surcharge);
    let (r, _) = verify_with(&signed, limits(source.len() as u64, 1 << 30), &tiny);
    assert!(matches!(
        r,
        Err(PdfError::Processing(ProcessingError::InputLimit))
    ));
    // Exactly at the format cap verifies; cap-1 is rejected (cap+1 above).
    let exact = |cap: u64| {
        let mob = (cap / 4) as usize;
        PdfLimits {
            max_revisions: 2,
            max_object_bytes: mob,
            max_evidence_bytes: cap - 4 * mob as u64,
            ..PdfLimits::default()
        }
    };
    let at = exact(surcharge);
    assert_eq!(super_cap(&at), surcharge);
    // Capture accepts; later object parsing may need larger objects, so only
    // the intake verdict is pinned here: not InputLimit.
    let (r, taken) = verify_with(&signed, limits(source.len() as u64, 1 << 30), &at);
    assert_eq!(taken.progress().bytes_in, signed.len() as u64);
    assert!(!matches!(
        r,
        Err(PdfError::Processing(ProcessingError::InputLimit))
    ));
    let below = exact(surcharge - 1);
    assert_eq!(super_cap(&below), surcharge - 1);
    let (r, _) = verify_with(&signed, limits(source.len() as u64, 1 << 30), &below);
    assert!(matches!(
        r,
        Err(PdfError::Processing(ProcessingError::InputLimit))
    ));
    // Unsigned larger PDFs never ride the surcharge: one byte, and a large
    // appended junk tail within the cap (no appended revision).
    for extra in [1usize, 4096] {
        let mut padded = source.to_vec();
        padded.resize(source.len() + extra, b'\n');
        let (r, _) = verify(&padded, limits(source.len() as u64, 1 << 30));
        assert!(
            matches!(r, Err(PdfError::Processing(ProcessingError::InputLimit))),
            "extra {extra}: {r:?}"
        );
    }
    // A document-sized payload is never surcharge: signed PDF + same again.
    let mut doubled = signed.clone();
    doubled.extend_from_slice(source);
    let (r, _) = verify(&doubled, limits(source.len() as u64, 1 << 30));
    assert!(matches!(
        r,
        Err(PdfError::Processing(ProcessingError::InputLimit))
    ));
}
fn super_cap(l: &PdfLimits) -> u64 {
    (l.max_revisions as u64 - 1) * 4 * l.max_object_bytes as u64 + l.max_evidence_bytes
}

fn find_last(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .rposition(|w| w == needle)
        .unwrap()
}
fn number_after(bytes: &[u8], at: usize, skip: usize) -> u64 {
    let end = (at + skip + 32).min(bytes.len());
    String::from_utf8_lossy(&bytes[at + skip..end])
        .trim_start()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
// D1 streams DSS evidence (a ~20 MB CRL) as a stream object per appended LT/LTA
// revision. Such a tail must fit the evidence allowance without any document
// credit; intake is the only layer asserted (progress == full wire).
#[test]
fn twenty_megabyte_evidence_revisions_fit_the_default_surcharge() {
    let source = include_bytes!("fixtures/external-multipage.pdf");
    let mut chain = sign(source);
    let crl = vec![0x5au8; 20 * 1024 * 1024];
    for revision in 0..3u32 {
        let prev = number_after(&chain, find_last(&chain, b"startxref"), 9);
        let root_at = find_last(&chain, b"/Root");
        let root = number_after(&chain, root_at, 5);
        let size = 100 + revision;
        let offset = chain.len();
        chain.extend_from_slice(
            format!("\n{size} 0 obj\n<</Length {}>>\nstream\n", crl.len()).as_bytes(),
        );
        chain.extend_from_slice(&crl);
        chain.extend_from_slice(b"\nendstream\nendobj\n");
        let xref = chain.len();
        chain.extend_from_slice(
            format!(
                "xref\n{size} 1\n{offset:010} 00000 n \ntrailer\n<</Size {} /Root {root} 0 R /Prev {prev}>>\nstartxref\n{xref}\n%%EOF\n",
                size + 1
            )
            .as_bytes(),
        );
    }
    let signed_len = sign(source).len() as u64;
    assert!(chain.len() as u64 - signed_len > 3 * 20 * 1024 * 1024);
    let limits = ResourceLimits {
        input_bytes: source.len() as u64,
        ..ResourceLimits::default()
    };
    let (result, taken) = verify(&chain, limits.clone());
    assert_eq!(taken.progress().bytes_in, chain.len() as u64);
    assert!(
        !matches!(
            result,
            Err(PdfError::Processing(ProcessingError::InputLimit))
        ),
        "{result:?}"
    );
    // Without the evidence allowance the same wire is an oversized document.
    let none = PdfLimits {
        max_evidence_bytes: 0,
        ..PdfLimits::default()
    };
    let (result, _) = verify_with(&chain, limits, &none);
    assert!(matches!(
        result,
        Err(PdfError::Processing(ProcessingError::InputLimit))
    ));
}
