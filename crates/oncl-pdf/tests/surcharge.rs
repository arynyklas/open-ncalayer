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
        ..PdfLimits::default()
    };
    assert!(super_cap(&tiny) < surcharge);
    let (r, _) = verify_with(&signed, limits(source.len() as u64, 1 << 30), &tiny);
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
    (l.max_revisions as u64 - 1) * 4 * l.max_object_bytes as u64
}
