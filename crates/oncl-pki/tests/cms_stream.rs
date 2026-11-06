//! C01 tests-first contract. The controller owns RED/GREEN; no production shim.
use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader};
use oncl_pki::cms::stream::{self, StreamError};
use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::io::{Region, Source};
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::resource::{
    IO_CHUNK_BYTES, OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope,
    SharedBudget,
};
use oncl_pki::validation::{
    CheckStatus, TimeBasis, ValidationContext, ValidationPolicy, ValidationReason, Verdict,
};
use oncl_testkit::{read, synthetic, synthetic_cert};
use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, Cursor, Read, Write};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use time::{OffsetDateTime, macros::datetime};

const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const CLAIM: OffsetDateTime = datetime!(2025-06-01 10:00 UTC);
const DATA: &[u8] = b"abc";
const ALGORITHMS: &[SigAlg] = &[SigAlg::RsaSha256, SigAlg::Gost2004, SigAlg::Gost2015_512];
// SHA-256("abc"), FIPS 180-4 example; not computed by the CMS implementation.
const ABC_SHA256: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

// A per-thread allocation-request witness catches a hidden read_to_end/BER->DER
// allocation without counting fixture allocations or concurrent test threads.
struct AllocationWitness;
thread_local! { static MAX_ALLOCATION: Cell<Option<usize>> = const { Cell::new(None) }; }
fn observe_allocation(size: usize) {
    let _ = MAX_ALLOCATION.try_with(|v| {
        if let Some(old) = v.get() {
            v.set(Some(old.max(size)));
        }
    });
}
unsafe impl GlobalAlloc for AllocationWitness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe_allocation(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: AllocationWitness = AllocationWitness;
struct AllocationGuard;
impl AllocationGuard {
    fn start() -> Self {
        MAX_ALLOCATION.with(|v| v.set(Some(0)));
        Self
    }
    fn maximum(&self) -> usize {
        MAX_ALLOCATION.with(|v| v.get().unwrap())
    }
}
impl Drop for AllocationGuard {
    fn drop(&mut self) {
        MAX_ALLOCATION.with(|v| v.set(None));
    }
}

#[derive(Default)]
struct Control(AtomicBool);
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
fn scope(limits: ResourceLimits) -> ResourceScope {
    controlled(limits, Arc::new(Control::default()))
}
fn controlled(limits: ResourceLimits, control: Arc<dyn OperationControl>) -> ResourceScope {
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, control)
        .unwrap()
}
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        panic!("OfflineReport must not fetch network evidence")
    }
}
fn entry(name: &str) -> KeyEntry {
    let f = synthetic(name);
    load(&read(f.path), &f.password).unwrap().remove(0)
}
fn roots() -> CaSet {
    CaSet::new(
        ["root-gost2015", "root-gost2004", "root-rsa"]
            .into_iter()
            .map(|name| oncl_pki::cert::parse(&synthetic_cert(name)).unwrap())
            .collect(),
    )
}
fn intermediate() -> Vec<oncl_pki::cert::Certificate> {
    vec![oncl_pki::cert::parse(&synthetic_cert("inter-gost2015")).unwrap()]
}
fn signed(name: &str, data: &[u8], attached: bool, digest: bool) -> Vec<u8> {
    cms::sign_spec(
        &entry(name),
        &intermediate(),
        &SignSpec {
            content: if digest {
                Content::Digest(data)
            } else {
                Content::Data(data)
            },
            encapsulate: attached,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs: AttrSpec::cades(CLAIM),
            certificates: CertSpec::Chain,
        },
    )
    .unwrap()
}
fn verify(
    input: Source<'_>,
    detached: Option<Source<'_>>,
    resources: &mut ResourceScope,
) -> Result<oncl_pki::validation::ValidationReport, StreamError> {
    stream::verify(
        input,
        detached,
        &ValidationContext {
            policy: ValidationPolicy::OfflineReport,
            now: NOW,
            anchors: &roots(),
            intermediates: &intermediate(),
            http: &Offline,
        },
        ALGORITHMS,
        resources,
    )
}
fn verify_bytes(bytes: &[u8]) -> oncl_pki::validation::ValidationReport {
    verify(
        Source::sequential(&mut Cursor::new(bytes), None),
        None,
        &mut scope(ResourceLimits::default()),
    )
    .unwrap()
}
fn children(bytes: &[u8]) -> Vec<Vec<u8>> {
    let any = AnyRef::from_der(bytes).unwrap();
    let mut r = SliceReader::new(any.value()).unwrap();
    let mut result = vec![];
    while !r.is_finished() {
        result.push(r.decode::<AnyRef<'_>>().unwrap().to_der().unwrap());
    }
    result
}
fn length(len: u64) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap();
    let mut result = vec![0x80 | (8 - first) as u8];
    result.extend_from_slice(&bytes[first..]);
    result
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length(body.len() as u64));
    out.extend(body);
    out
}
fn indefinite(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, 0x80];
    out.extend(body);
    out.extend([0, 0]);
    out
}
fn sd(der: &[u8]) -> Vec<Vec<u8>> {
    children(&children(&children(der)[1])[0])
}
fn wrap(fields: &[Vec<u8>]) -> Vec<u8> {
    let oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2")
        .to_der()
        .unwrap();
    tlv(
        0x30,
        &[oid, tlv(0xa0, &tlv(0x30, &fields.concat()))].concat(),
    )
}
// Small metadata-only fixture reconstruction. The signed digest/attributes are
// preserved; these builders never parse or hash the content under test.
fn with_octets(der: &[u8], octets: &[u8]) -> Vec<u8> {
    let mut fields = sd(der);
    let content_type = children(&fields[2])[0].clone();
    fields[2] = indefinite(0x30, &[content_type, indefinite(0xa0, octets)].concat());
    let oid = children(der)[0].clone();
    indefinite(
        0x30,
        &[oid, indefinite(0xa0, &indefinite(0x30, &fields.concat()))].concat(),
    )
}
fn ber(der: &[u8]) -> Vec<u8> {
    // Includes an empty chunk, nested constructed chunks, and EOC-looking data
    // only in the separate extraction test; EOCs are structural, not byte scans.
    with_octets(
        der,
        &indefinite(
            0x24,
            &[
                tlv(4, b"a"),
                indefinite(0x24, &[tlv(4, b""), tlv(4, b"bc")].concat()),
            ]
            .concat(),
        ),
    )
}
fn corrupt_signer(der: &[u8], index: usize) -> Vec<u8> {
    let mut fields = sd(der);
    let last = fields.len() - 1;
    let mut signers = children(&fields[last]);
    let mut signer = children(&signers[index]);
    let mut signature = AnyRef::from_der(&signer[5]).unwrap().value().to_vec();
    signature[0] ^= 1;
    signer[5] = tlv(4, &signature);
    signers[index] = tlv(0x30, &signer.concat());
    fields[last] = tlv(0x31, &signers.concat());
    wrap(&fields)
}

#[test]
fn der_attached_unknown_and_seekable_sources_verify_real_rsa_and_gost() {
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let der = signed(name, DATA, true, false);
        let unknown = verify_bytes(&der);
        assert_eq!(unknown.signers.len(), 1, "{name}");
        assert_eq!(unknown.signers[0].signature, CheckStatus::Passed, "{name}");
        // Signature integrity is not complete PKI trust: no fresh offline status.
        assert_eq!(unknown.verdict, Verdict::Indeterminate);
        let mut cursor = Cursor::new([b"prefix".as_slice(), &der].concat());
        cursor.set_position(6);
        let result = verify(
            Source::seekable(&mut cursor, Some(der.len() as u64)),
            None,
            &mut scope(ResourceLimits::default()),
        )
        .unwrap();
        assert_eq!(result.signers[0].signature, CheckStatus::Passed);
        assert_eq!(result.signers[0].time_basis, TimeBasis::Current(NOW));
    }
}

#[test]
fn rsa_fixture_has_independent_known_digest_and_signed_attribute_signature() {
    let der = signed("user-rsa-sign", &ABC_SHA256, false, true);
    let fields = sd(&der);
    let signer = children(&children(fields.last().unwrap())[0]);
    let attrs = children(&signer[3]);
    let digest_attr = attrs
        .iter()
        .find(|a| {
            AnyRef::from_der(&children(a)[0])
                .unwrap()
                .decode_as::<ObjectIdentifier>()
                .unwrap()
                == ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4")
        })
        .unwrap();
    let values = children(&children(digest_attr)[1]);
    assert_eq!(AnyRef::from_der(&values[0]).unwrap().value(), ABC_SHA256);
    let signed_set = tlv(0x31, AnyRef::from_der(&signer[3]).unwrap().value());
    let key = entry("user-rsa-sign");
    PublicKey::from_spki(key.cert.tbs_certificate().subject_public_key_info())
        .unwrap()
        .verify(
            SigAlg::RsaSha256,
            &signed_set,
            AnyRef::from_der(&signer[5]).unwrap().value(),
        )
        .unwrap();
    let report = verify(
        Source::sequential(&mut Cursor::new(der), None),
        Some(Source::sequential(&mut Cursor::new(DATA), None)),
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
}

#[test]
fn ber_chunks_and_64bit_lengths() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let encoded = ber(&der);
    let report = verify_bytes(&encoded);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    let mut output = vec![];
    let extracted = stream::extract(
        Source::sequential(&mut Cursor::new(&encoded), None),
        &mut output,
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(output, DATA);
    assert_eq!(extracted.bytes_written, 3);
    // A five-octet length must not wrap to three or allocate four GiB. The
    // declared payload exceeds the explicit wire intake limit before any body.
    let huge = with_octets(&der, &[4, 0x85, 1, 0, 0, 0, 3]);
    let result = stream::inspect(
        Source::sequential(&mut Cursor::new(huge), None),
        &mut scope(ResourceLimits {
            input_bytes: 4096,
            ..ResourceLimits::default()
        }),
    );
    assert!(matches!(
        result,
        Err(StreamError::Processing(ProcessingError::InputLimit))
    ));
}

#[test]
fn detached_missing_data_is_never_valid_and_wrong_data_is_invalid() {
    let der = signed("user-rsa-sign", DATA, false, false);
    let mut fields = sd(&der);
    fields[2] = indefinite(0x30, AnyRef::from_der(&fields[2]).unwrap().value());
    let encoded = indefinite(
        0x30,
        &[
            children(&der)[0].clone(),
            indefinite(0xa0, &indefinite(0x30, &fields.concat())),
        ]
        .concat(),
    );
    for bytes in [&der, &encoded] {
        let good = verify(
            Source::sequential(&mut Cursor::new(bytes), None),
            Some(Source::sequential(&mut Cursor::new(DATA), None)),
            &mut scope(ResourceLimits::default()),
        )
        .unwrap();
        assert_eq!(good.signers[0].signature, CheckStatus::Passed);
    }
    let missing = verify_bytes(&der);
    assert_ne!(missing.verdict, Verdict::Valid);
    assert_eq!(missing.signers[0].signature, CheckStatus::Failed);
    assert!(
        missing.signers[0]
            .reasons
            .contains(&ValidationReason::Signature(cms::Problem::NoContent))
    );
    let report = verify(
        Source::sequential(&mut Cursor::new(&der), None),
        Some(Source::sequential(&mut Cursor::new(b"abd"), None)),
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(report.verdict, Verdict::Invalid);
    assert!(
        report.signers[0]
            .reasons
            .contains(&ValidationReason::Signature(cms::Problem::DigestMismatch))
    );
    let mut output = vec![];
    assert!(matches!(
        stream::extract(
            Source::sequential(&mut Cursor::new(der), None),
            &mut output,
            &mut scope(ResourceLimits::default())
        ),
        Err(StreamError::Cms(cms::CmsError::NoEncapsulatedData))
    ));
    assert!(output.is_empty());
}

#[test]
fn every_signer_is_reported_when_later_signature_is_corrupted() {
    let first = signed("user-rsa-sign", DATA, true, false);
    // Same-key second signer avoids changing F04's documented mixed issuer-OID
    // producer limitation. Verification must still visit both SignerInfos.
    let two = cms::sign(
        &entry("user-rsa-sign"),
        &first,
        &cms::SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: CLAIM,
        },
    )
    .unwrap();
    let good = verify_bytes(&two);
    assert_eq!(good.signers.len(), 2);
    assert!(
        good.signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed)
    );
    let bad = verify_bytes(&corrupt_signer(&two, 1));
    assert_eq!(bad.signers.len(), 2);
    assert_eq!(bad.signers[0].signature, CheckStatus::Passed);
    assert_eq!(bad.signers[1].signature, CheckStatus::Failed);
    assert_eq!(bad.verdict, Verdict::Invalid);
}

#[test]
fn content_tamper_fails_but_extract_remains_explicitly_unverified() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let changed = with_octets(
        &der,
        &indefinite(0x24, &[tlv(4, b"a"), tlv(4, b"bd")].concat()),
    );
    let report = verify_bytes(&changed);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert!(
        report.signers[0]
            .reasons
            .contains(&ValidationReason::Signature(cms::Problem::DigestMismatch))
    );
    let mut output = vec![];
    let report = stream::extract(
        Source::sequential(&mut Cursor::new(changed), None),
        &mut output,
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(output, b"abd");
    assert_eq!(report.bytes_written, 3); // ExtractionReport has no verdict/signers.
}

#[test]
fn inspect_regions_are_source_relative_and_ber_does_not_invent_contiguity() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let inspected = stream::inspect(
        Source::sequential(&mut Cursor::new(&der), None),
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert!(!inspected.detached);
    assert_eq!(inspected.signer_count, 1);
    assert_eq!(inspected.content_len, 3);
    let Region { offset, len } = inspected.content_region.unwrap();
    assert_eq!(len, 3);
    assert_eq!(&der[offset as usize..(offset + len) as usize], DATA);
    let mut cursor = Cursor::new([b"prefix".as_slice(), &der].concat());
    cursor.set_position(6);
    let at_offset = stream::inspect(
        Source::seekable(&mut cursor, None),
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(at_offset.content_region, inspected.content_region);
    let chunks = stream::inspect(
        Source::sequential(&mut Cursor::new(ber(&der)), None),
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(chunks.content_len, 3);
    assert_eq!(chunks.content_region, None);
}

#[test]
fn zero_octets_in_primitive_data_are_not_end_of_contents() {
    let data = b"a\0\0b\0\0c";
    let der = signed("user-rsa-sign", data, true, false);
    let encoded = with_octets(
        &der,
        &indefinite(0x24, &[tlv(4, &data[..3]), tlv(4, &data[3..])].concat()),
    );
    let mut output = vec![];
    stream::extract(
        Source::sequential(&mut Cursor::new(&encoded), None),
        &mut output,
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(output, data);
    assert_eq!(
        verify_bytes(&encoded).signers[0].signature,
        CheckStatus::Passed
    );
}

#[test]
fn malformed_eoc_primitive_indefinite_and_truncation_are_rejected() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let cases = [
        with_octets(&der, &[4, 0x80, b'a', 0, 0]),
        with_octets(&der, &[0x24, 0x80, 0, 1, 0, 0, 0]),
        with_octets(&der, &[0x24, 0x80, 0, 0, 0, 0]),
        with_octets(&der, &indefinite(0x24, &tlv(2, &[1]))),
        with_octets(&der, &[0x24, 3, 4, 2, b'a']),
    ];
    for (index, bytes) in cases.iter().enumerate() {
        assert!(
            stream::inspect(
                Source::sequential(&mut Cursor::new(bytes), None),
                &mut scope(ResourceLimits::default())
            )
            .is_err(),
            "malformed BER case {index}"
        );
    }
    let encoded = ber(&der);
    for cut in [1, encoded.len() / 2, encoded.len() - 1, encoded.len() - 2] {
        assert!(
            stream::inspect(
                Source::sequential(&mut Cursor::new(&encoded[..cut]), None),
                &mut scope(ResourceLimits::default())
            )
            .is_err(),
            "truncated at {cut}"
        );
    }
    let trailing = [&encoded[..], &[0, 0]].concat();
    assert!(
        stream::inspect(
            Source::sequential(&mut Cursor::new(trailing), None),
            &mut scope(ResourceLimits::default())
        )
        .is_err()
    );
}

#[test]
fn offset_overflow_and_overlong_lengths_fail_without_document_allocation() {
    for bad in [
        vec![0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x30, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        let allocations = AllocationGuard::start();
        let result = stream::inspect(
            Source::sequential(&mut Cursor::new(bad), None),
            &mut scope(ResourceLimits::default()),
        );
        assert!(matches!(
            result,
            Err(StreamError::Cms(cms::CmsError::Malformed(_)))
        ));
        assert!(allocations.maximum() <= IO_CHUNK_BYTES);
    }
}

#[test]
fn depth_and_chunk_work_are_bounded_independently_of_content_size() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let mut nested = tlv(4, DATA);
    for _ in 0..1024 {
        nested = indefinite(0x24, &nested);
    }
    assert!(
        stream::inspect(
            Source::sequential(&mut Cursor::new(with_octets(&der, &nested)), None),
            &mut scope(ResourceLimits::default())
        )
        .is_err()
    );
    // Empty chunks still consume framing/work allowance; they cannot create a
    // zero-byte-content route to unlimited parser work or Region growth.
    let chunks = with_octets(&der, &indefinite(0x24, &[4, 0].repeat(4096)));
    let result = stream::inspect(
        Source::sequential(&mut Cursor::new(chunks), None),
        &mut scope(ResourceLimits {
            framing_bytes: 1024,
            ..ResourceLimits::default()
        }),
    );
    assert!(matches!(
        result,
        Err(StreamError::Processing(ProcessingError::FramingLimit))
    ));
}

struct NoRead;
impl Read for NoRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("operation must reject before read")
    }
}
#[test]
fn cancelled_expired_and_known_oversize_operations_do_not_read() {
    let control = Arc::new(Control::default());
    control.0.store(true, Ordering::SeqCst);
    let mut cancelled = controlled(ResourceLimits::default(), control);
    assert!(matches!(
        stream::inspect(Source::sequential(&mut NoRead, None), &mut cancelled),
        Err(StreamError::Processing(ProcessingError::Cancelled))
    ));
    let mut expired = scope(ResourceLimits {
        operation_timeout: Duration::from_nanos(1),
        ..ResourceLimits::default()
    });
    while !expired.deadline().is_expired() {
        std::hint::spin_loop();
    }
    assert!(matches!(
        stream::inspect(Source::sequential(&mut NoRead, None), &mut expired),
        Err(StreamError::Processing(ProcessingError::DeadlineExceeded))
    ));
    let mut small = scope(ResourceLimits {
        input_bytes: 3,
        container_bytes: 0,
        ..ResourceLimits::default()
    });
    assert!(matches!(
        stream::inspect(Source::sequential(&mut NoRead, Some(4)), &mut small),
        Err(StreamError::Processing(ProcessingError::InputLimit))
    ));
}

struct CancelAfterRead<'a> {
    bytes: Cursor<&'a [u8]>,
    control: Arc<Control>,
    consumed: usize,
}
impl Read for CancelAfterRead<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let cap = out.len().min(7);
        let n = self.bytes.read(&mut out[..cap])?;
        self.consumed += n;
        self.control.0.store(true, Ordering::SeqCst);
        Ok(n)
    }
}
#[test]
fn cancellation_after_read_retains_consumed_wire_bytes() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let control = Arc::new(Control::default());
    let mut resources = controlled(ResourceLimits::default(), control.clone());
    let mut source = CancelAfterRead {
        bytes: Cursor::new(&der),
        control,
        consumed: 0,
    };
    assert!(matches!(
        stream::inspect(Source::sequential(&mut source, None), &mut resources),
        Err(StreamError::Processing(ProcessingError::Cancelled))
    ));
    assert!(source.consumed > 0);
    assert_eq!(resources.progress().bytes_in, source.consumed as u64);
}

#[test]
fn unknown_source_quota_failure_is_terminal_and_bytes_are_not_forgotten() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let mut cursor = Cursor::new(&der);
    let mut resources = scope(ResourceLimits {
        input_bytes: 1,
        container_bytes: 0,
        ..ResourceLimits::default()
    });
    assert!(matches!(
        stream::inspect(Source::sequential(&mut cursor, None), &mut resources),
        Err(StreamError::Processing(ProcessingError::InputLimit))
    ));
    assert_eq!(cursor.position(), 2);
    assert_eq!(resources.progress().bytes_in, cursor.position());
    let before = cursor.position();
    assert!(matches!(
        stream::inspect(Source::sequential(&mut cursor, None), &mut resources),
        Err(StreamError::Processing(ProcessingError::InputLimit))
    ));
    assert_eq!(cursor.position(), before);
}

struct FailingSink {
    written: usize,
}
impl Write for FailingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.written != 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture closed"));
        }
        self.written = bytes.len().min(1);
        Ok(self.written)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_failure_and_output_limit_are_typed_execution_failures() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let mut sink = FailingSink { written: 0 };
    let mut resources = scope(ResourceLimits::default());
    let result = stream::extract(
        Source::sequential(&mut Cursor::new(&der), None),
        &mut sink,
        &mut resources,
    );
    assert!(
        matches!(&result, Err(StreamError::Processing(ProcessingError::Io(e))) if e.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(sink.written, 1); // Arbitrary sinks may retain partial bytes.
    let mut output = vec![];
    assert!(matches!(
        stream::extract(
            Source::sequential(&mut Cursor::new(der), None),
            &mut output,
            &mut scope(ResourceLimits {
                output_bytes: 2,
                ..ResourceLimits::default()
            })
        ),
        Err(StreamError::Processing(ProcessingError::OutputLimit))
    ));
    assert!(output.len() <= 2);
}

#[test]
fn metadata_and_container_overhead_have_separate_limits() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let result = verify(
        Source::sequential(&mut Cursor::new(&der), None),
        None,
        &mut scope(ResourceLimits {
            metadata_bytes: 16,
            ..ResourceLimits::default()
        }),
    );
    assert!(matches!(
        result,
        Err(StreamError::Processing(ProcessingError::MetadataLimit))
    ));
    let result = stream::inspect(
        Source::sequential(&mut Cursor::new(der), None),
        &mut scope(ResourceLimits {
            container_bytes: 16,
            ..ResourceLimits::default()
        }),
    );
    assert!(matches!(
        result,
        Err(StreamError::Processing(ProcessingError::ContainerLimit))
    ));
}

// A real generated multichunk stream: no full content/container Vec, mmap,
// sparse file, tempfile, or preallocated caller buffer can hide library copying.
struct Generated {
    remaining: u64,
    byte: u8,
}
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        assert!(out.len() <= IO_CHUNK_BYTES, "unbounded read request");
        let n = self.remaining.min(out.len() as u64) as usize;
        out[..n].fill(self.byte);
        self.remaining -= n as u64;
        Ok(n)
    }
}
fn generated_parts(bytes: u64, chunk: usize) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha256::new();
    let block = vec![0x61; chunk];
    let mut remaining = bytes;
    while remaining != 0 {
        let n = remaining.min(chunk as u64) as usize;
        hasher.update(&block[..n]);
        remaining -= n as u64;
    }
    let detached = signed("user-rsa-sign", &hasher.finalize(), false, true);
    let fields = sd(&detached);
    let content_type = children(&fields[2])[0].clone();
    let mut prefix = vec![0x30, 0x80];
    prefix.extend(children(&detached)[0].clone());
    prefix.extend([0xa0, 0x80, 0x30, 0x80]);
    prefix.extend(&fields[0]);
    prefix.extend(&fields[1]);
    prefix.extend([0x30, 0x80]);
    prefix.extend(content_type);
    prefix.extend([0xa0, 0x80, 0x24, 0x80]);
    let mut suffix = vec![0, 0, 0, 0, 0, 0]; // OCTET, explicit, encap EOCs.
    for field in &fields[3..] {
        suffix.extend(field);
    }
    suffix.extend([0, 0, 0, 0, 0, 0]);
    (prefix, suffix)
}
struct ChunkedGenerated {
    remaining: u64,
    chunk: u64,
    in_chunk: u64,
    header: Cursor<Vec<u8>>,
}
impl ChunkedGenerated {
    fn new(bytes: u64, chunk: u64) -> Self {
        Self {
            remaining: bytes,
            chunk,
            in_chunk: 0,
            header: Cursor::new(vec![]),
        }
    }
}
impl Read for ChunkedGenerated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        assert!(out.len() <= IO_CHUNK_BYTES);
        if out.is_empty() {
            return Ok(0);
        }
        if self.header.position() < self.header.get_ref().len() as u64 {
            return self.header.read(out);
        }
        if self.in_chunk != 0 {
            let mut body = Generated {
                remaining: self.in_chunk,
                byte: 0x61,
            };
            let n = body.read(out)?;
            self.in_chunk -= n as u64;
            self.remaining -= n as u64;
            return Ok(n);
        }
        if self.remaining == 0 {
            return Ok(0);
        }
        self.in_chunk = self.remaining.min(self.chunk);
        let mut header = vec![4];
        header.extend(length(self.in_chunk));
        self.header = Cursor::new(header);
        self.header.read(out)
    }
}
struct DigestSink {
    digest: Sha256,
    len: u64,
}
impl Write for DigestSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.digest.update(bytes);
        self.len += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn generated_multichunk_document_exceeds_working_memory_without_large_allocations() {
    const BYTES: u64 = 8 * 1024 * 1024 + 19;
    const MEMORY: u64 = 1024 * 1024;
    const CHUNK: u64 = 65537;
    let (prefix, suffix) = generated_parts(BYTES, CHUNK as usize);
    let limits = ResourceLimits {
        memory_bytes: MEMORY,
        metadata_bytes: 128 * 1024,
        container_bytes: 128 * 1024,
        framing_bytes: 4096,
        ..ResourceLimits::default()
    };
    let mut source = Cursor::new(&prefix)
        .chain(ChunkedGenerated::new(BYTES, CHUNK))
        .chain(Cursor::new(&suffix));
    let mut resources = scope(limits.clone());
    let allocations = AllocationGuard::start();
    let report = verify(Source::sequential(&mut source, None), None, &mut resources).unwrap();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert!(
        allocations.maximum() <= MEMORY as usize,
        "document-sized allocation"
    );
    drop(allocations);
    // Independently recompute expected digest through RustCrypto, not HashState
    // or the new reader. The sink never retains document bytes.
    let mut expected = Sha256::new();
    let block = [0x61; 4096];
    let mut remaining = BYTES;
    while remaining != 0 {
        let n = remaining.min(block.len() as u64) as usize;
        expected.update(&block[..n]);
        remaining -= n as u64;
    }
    let mut source = Cursor::new(prefix)
        .chain(ChunkedGenerated::new(BYTES, CHUNK))
        .chain(Cursor::new(suffix));
    let mut sink = DigestSink {
        digest: Sha256::new(),
        len: 0,
    };
    let mut extract_resources = scope(limits);
    let allocations = AllocationGuard::start();
    let extraction = stream::extract(
        Source::sequential(&mut source, None),
        &mut sink,
        &mut extract_resources,
    )
    .unwrap();
    assert_eq!(extraction.bytes_written, BYTES);
    assert_eq!(sink.len, BYTES);
    assert_eq!(
        sink.digest.finalize().as_slice(),
        expected.finalize().as_slice()
    );
    assert!(allocations.maximum() <= MEMORY as usize);
}

#[test]
fn header_digest_algorithms_cannot_hide_an_unhashed_signer() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let mut fields = sd(&der);
    fields[1] = tlv(0x31, &[]);
    assert!(matches!(
        verify(
            Source::sequential(&mut Cursor::new(wrap(&fields)), None),
            None,
            &mut scope(ResourceLimits::default())
        ),
        Err(StreamError::Cms(cms::CmsError::Malformed(_)))
    ));
}

#[test]
fn signed_content_type_and_ess_binding_are_not_bypassed_by_streaming() {
    let der = signed("user-rsa-sign", DATA, true, false);
    for target in ["1.2.840.113549.1.9.3", "1.2.840.113549.1.9.16.2.47"] {
        let mut fields = sd(&der);
        let last = fields.len() - 1;
        let mut signers = children(&fields[last]);
        let mut signer = children(&signers[0]);
        let mut attrs = children(&signer[3]);
        let index = attrs
            .iter()
            .position(|a| {
                AnyRef::from_der(&children(a)[0])
                    .unwrap()
                    .decode_as::<ObjectIdentifier>()
                    .unwrap()
                    .to_string()
                    == target
            })
            .unwrap();
        let mut attr = children(&attrs[index]);
        if target.ends_with(".3") {
            attr[1] = tlv(
                0x31,
                &ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2")
                    .to_der()
                    .unwrap(),
            );
        } else {
            // ESSCertIDv2 SHA256 digest is the only 32-byte OCTET STRING here.
            let mut value = attr[1].clone();
            let position = value.windows(2).position(|b| b == [4, 32]).unwrap();
            value[position + 2] ^= 1;
            attr[1] = value;
        }
        attrs[index] = tlv(0x30, &attr.concat());
        attrs.sort();
        signer[3] = tlv(0xa0, &attrs.concat());
        // Re-sign altered attributes: rejection must come from contentType/ESS
        // checking, not merely the changed signed-attribute RSA signature.
        let message = tlv(0x31, &attrs.concat());
        signer[5] = tlv(
            4,
            &entry("user-rsa-sign")
                .key
                .sign(SigAlg::RsaSha256, &message)
                .unwrap(),
        );
        signers[0] = tlv(0x30, &signer.concat());
        fields[last] = tlv(0x31, &signers.concat());
        let report = verify_bytes(&wrap(&fields));
        assert_eq!(report.verdict, Verdict::Invalid, "{target}");
        assert_eq!(report.signers[0].signature, CheckStatus::Failed, "{target}");
    }
}

#[test]
fn mixed_digest_signers_use_all_declared_algorithms_without_replaying_content() {
    let containers: Vec<_> = ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"]
        .into_iter()
        .map(|name| signed(name, DATA, true, false))
        .collect();
    let mut fields = sd(&containers[0]);
    let mut algorithms = vec![];
    let mut certificates = vec![];
    let mut signers = vec![];
    for container in &containers {
        let parts = sd(container);
        algorithms.extend(children(&parts[1]));
        certificates.extend(children(&parts[3]));
        signers.extend(children(parts.last().unwrap()));
    }
    algorithms.sort();
    algorithms.dedup();
    certificates.sort();
    certificates.dedup();
    fields[1] = tlv(0x31, &algorithms.concat());
    fields[3] = tlv(0xa0, &certificates.concat());
    let last = fields.len() - 1;
    fields[last] = tlv(0x31, &signers.concat());
    let report = verify_bytes(&ber(&wrap(&fields)));
    assert_eq!(report.signers.len(), 3);
    assert!(
        report
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed)
    );
}

#[test]
fn genuine_embedded_current_crl_can_complete_offline_validation_as_valid() {
    let der = signed("user-gost2015-sign", DATA, true, false);
    let root = entry("root-gost2015.key");
    let mut crl = children(&oncl_pki::crl::MockCrl::new(entry("root-gost2015.key")).der());
    let mut tbs = children(&crl[0]);
    tbs[3] = tlv(0x17, b"261102115900Z");
    tbs[4] = tlv(0x17, b"261102130000Z");
    crl[0] = tlv(0x30, &tbs.concat());
    let mut signature = vec![0]; // BIT STRING unused-bits count.
    signature.extend(root.key.sign(SigAlg::Gost2015_512, &crl[0]).unwrap());
    crl[2] = tlv(3, &signature);
    let mut fields = sd(&der);
    fields.insert(fields.len() - 1, tlv(0xa1, &tlv(0x30, &crl.concat())));
    for bytes in [wrap(&fields), ber(&wrap(&fields))] {
        let report = verify_bytes(&bytes);
        assert_eq!(report.signers[0].signature, CheckStatus::Passed);
        assert_eq!(report.signers[0].chain, CheckStatus::Passed);
        assert_eq!(report.signers[0].revocation, CheckStatus::Passed);
        assert_eq!(report.verdict, Verdict::Valid);
    }
}

#[test]
fn definite_constructed_octets_and_empty_attached_content_are_real_content() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let constructed = with_octets(&der, &tlv(0x24, &[tlv(4, b"a"), tlv(4, b"bc")].concat()));
    assert_eq!(
        verify_bytes(&constructed).signers[0].signature,
        CheckStatus::Passed
    );
    let empty = signed("user-rsa-sign", b"", true, false);
    let report = verify_bytes(&empty);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    let inspection = stream::inspect(
        Source::sequential(&mut Cursor::new(&empty), None),
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert!(!inspection.detached);
    assert_eq!(inspection.content_len, 0);
    let mut output = vec![];
    assert_eq!(
        stream::extract(
            Source::sequential(&mut Cursor::new(empty), None),
            &mut output,
            &mut scope(ResourceLimits::default())
        )
        .unwrap()
        .bytes_written,
        0
    );
    assert!(output.is_empty());
}

#[test]
fn attached_content_takes_precedence_without_consuming_detached_source() {
    let der = signed("user-rsa-sign", DATA, true, false);
    let result = verify(
        Source::sequential(&mut Cursor::new(der), None),
        Some(Source::sequential(&mut NoRead, None)),
        &mut scope(ResourceLimits::default()),
    )
    .unwrap();
    assert_eq!(result.signers[0].signature, CheckStatus::Passed);
}

struct InterruptedThenShort<'a> {
    input: Cursor<&'a [u8]>,
    interrupted: bool,
}
impl Read for InterruptedThenShort<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "fixture retry"));
        }
        let count = output.len().min(1);
        self.input.read(&mut output[..count])
    }
}
#[test]
fn interrupted_and_single_octet_reads_preserve_accounting_and_signature() {
    let der = ber(&signed("user-rsa-sign", DATA, true, false));
    let mut input = InterruptedThenShort {
        input: Cursor::new(&der),
        interrupted: false,
    };
    let mut resources = scope(ResourceLimits::default());
    let result = verify(Source::sequential(&mut input, None), None, &mut resources).unwrap();
    assert_eq!(result.signers[0].signature, CheckStatus::Passed);
    assert_eq!(resources.progress().bytes_in, der.len() as u64);
}

// Re-sign after deletion: these tests isolate mandatory contentType semantics,
// not a stale signature produced by mutating signedAttrs without authorization.
fn without_content_type(der: &[u8], index: usize) -> Vec<u8> {
    let mut fields = sd(der);
    let last = fields.len() - 1;
    let mut signers = children(&fields[last]);
    let mut signer = children(&signers[index]);
    let mut attrs = children(&signer[3]);
    let before = attrs.len();
    attrs.retain(|attr| {
        AnyRef::from_der(&children(attr)[0])
            .unwrap()
            .decode_as::<ObjectIdentifier>()
            .unwrap()
            != ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3")
    });
    assert_eq!(attrs.len() + 1, before);
    attrs.sort();
    let message = tlv(0x31, &attrs.concat());
    let key = entry("user-rsa-sign");
    let signature = key.key.sign(SigAlg::RsaSha256, &message).unwrap();
    PublicKey::from_spki(key.cert.tbs_certificate().subject_public_key_info())
        .unwrap()
        .verify(SigAlg::RsaSha256, &message, &signature)
        .unwrap();
    signer[3] = tlv(0xa0, &attrs.concat());
    signer[5] = tlv(4, &signature);
    signers[index] = tlv(0x30, &signer.concat());
    fields[last] = tlv(0x31, &signers.concat());
    wrap(&fields)
}

fn bounded_validation(bytes: &[u8]) -> oncl_pki::validation::ValidationReport {
    oncl_pki::validation::validate_cms(
        bytes,
        None,
        &ValidationContext {
            policy: ValidationPolicy::OfflineReport,
            now: NOW,
            anchors: &roots(),
            intermediates: &intermediate(),
            http: &Offline,
        },
        &scope(ResourceLimits::default()),
    )
    .unwrap()
}

#[test]
fn mandatory_content_type_cannot_be_omitted_from_resigned_signed_attrs() {
    let original = signed("user-rsa-sign", DATA, true, false);
    assert_eq!(
        verify_bytes(&original).signers[0].signature,
        CheckStatus::Passed
    );
    let missing = without_content_type(&original, 0);
    assert!(matches!(
        cms::verify(&missing, None),
        Err(cms::CmsError::Malformed(_))
    ));
    for report in [bounded_validation(&missing), verify_bytes(&missing)] {
        assert_eq!(report.signers.len(), 1);
        assert_eq!(report.signers[0].signature, CheckStatus::Failed);
        assert!(
            report.signers[0]
                .reasons
                .contains(&ValidationReason::Signature(cms::Problem::Malformed))
        );
        assert_eq!(report.verdict, Verdict::Invalid);
    }
}

#[test]
fn later_resigned_signer_without_content_type_invalidates_bounded_and_stream_reports() {
    let first = signed("user-rsa-sign", DATA, true, false);
    let original = cms::sign(
        &entry("user-rsa-sign"),
        &first,
        &cms::SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: CLAIM,
        },
    )
    .unwrap();
    assert!(
        verify_bytes(&original)
            .signers
            .iter()
            .all(|signer| signer.signature == CheckStatus::Passed)
    );
    let missing = without_content_type(&original, 1);
    assert!(matches!(
        cms::verify(&missing, None),
        Err(cms::CmsError::Malformed(_))
    ));
    for report in [
        bounded_validation(&missing),
        verify_bytes(&missing),
        verify_bytes(&ber(&missing)),
    ] {
        assert_eq!(report.signers.len(), 2);
        assert_eq!(report.signers[0].signature, CheckStatus::Passed);
        assert_eq!(report.signers[1].signature, CheckStatus::Failed);
        assert_eq!(report.verdict, Verdict::Invalid);
    }
}

#[test]
fn staged_extraction_charges_once_and_rejects_output_n_minus_one() {
    let encoded = signed("user-rsa-sign", DATA, true, false);
    let dir = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(dir.path()).unwrap();
    for (cap, succeeds) in [(3, true), (2, false)] {
        let mut resources = scope(ResourceLimits {
            output_bytes: cap,
            ..ResourceLimits::default()
        });
        let mut stage = store.stage(&mut resources).unwrap();
        let result = stream::extract_staged(
            Source::sequential(&mut Cursor::new(&encoded), None),
            &mut stage,
            &mut resources,
        );
        assert_eq!(result.is_ok(), succeeds);
        assert!(resources.progress().bytes_in <= encoded.len() as u64);
        let destination = dir.path().join(format!("result-{cap}"));
        if succeeds {
            assert_eq!(resources.progress().bytes_in, encoded.len() as u64);
            assert_eq!(resources.progress().bytes_out, 3);
            stage.commit(&destination).unwrap();
            assert_eq!(std::fs::read(destination).unwrap(), DATA);
        } else {
            assert!(stage.commit(&destination).is_err());
            assert!(!destination.exists());
        }
    }
}

#[test]
fn staged_extraction_cancel_is_sticky_but_foreign_and_source_are_untouched() {
    let encoded = signed("user-rsa-sign", DATA, true, false);
    let dir = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(dir.path()).unwrap();
    let control = Arc::new(Control::default());
    let mut original = controlled(ResourceLimits::default(), control.clone());
    let mut stage = store.stage(&mut original).unwrap();
    control.0.store(true, Ordering::SeqCst);
    assert!(
        stream::extract_staged(
            Source::sequential(&mut Cursor::new(&encoded), None),
            &mut stage,
            &mut original
        )
        .is_err()
    );
    control.0.store(false, Ordering::SeqCst);
    assert!(stage.commit(&dir.path().join("cancelled")).is_err());
    let mut stage = store.stage(&mut original).unwrap();
    let mut foreign = scope(ResourceLimits::default());
    assert!(
        stream::extract_staged(
            Source::sequential(&mut Cursor::new(&encoded), None),
            &mut stage,
            &mut foreign
        )
        .is_err()
    );
    stage.write_chunk(DATA).unwrap();
    stage.commit(&dir.path().join("foreign-untouched")).unwrap();
    let mut source = store.stage_source(&mut original).unwrap();
    assert!(
        stream::extract_staged(
            Source::sequential(&mut Cursor::new(&encoded), None),
            &mut source,
            &mut original
        )
        .is_err()
    );
    source.write_chunk(DATA).unwrap();
    assert_eq!(source.len(), 3);
}

#[test]
fn publication_finish_rechecks_failure_marked_by_original_control() {
    struct DropOnCheckpoint {
        armed: AtomicBool,
        guard: std::sync::Mutex<Option<oncl_pki::io::OutputPublicationGuard>>,
    }
    impl OperationControl for DropOnCheckpoint {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.armed.load(Ordering::SeqCst) {
                drop(self.guard.lock().unwrap().take());
            }
            Ok(())
        }
    }
    let control = Arc::new(DropOnCheckpoint {
        armed: AtomicBool::new(false),
        guard: std::sync::Mutex::new(None),
    });
    let mut resources = controlled(ResourceLimits::default(), control.clone());
    let dir = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(dir.path()).unwrap();
    let mut stage = store.stage(&mut resources).unwrap();
    let outer = stage.publication_guard(&resources).unwrap();
    *control.guard.lock().unwrap() = Some(stage.publication_guard(&resources).unwrap());
    control.armed.store(true, Ordering::SeqCst);
    assert!(outer.finish().is_err());
    assert!(stage.commit(&dir.path().join("must-not-publish")).is_err());
}

#[test]
fn last_commit_control_transition_cannot_publish_a_poisoned_stage() {
    #[derive(Clone, Copy)]
    enum Phase {
        Idle,
        CommitEntry,
        AfterSync,
    }
    struct Control {
        phase: std::sync::Mutex<Phase>,
        guard: std::sync::Mutex<Option<oncl_pki::io::OutputPublicationGuard>>,
    }
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            let mut phase = self.phase.lock().unwrap();
            match *phase {
                Phase::Idle => {}
                Phase::CommitEntry => *phase = Phase::AfterSync,
                Phase::AfterSync => {
                    drop(self.guard.lock().unwrap().take());
                    *phase = Phase::Idle;
                }
            }
            Ok(())
        }
    }
    let control = Arc::new(Control {
        phase: std::sync::Mutex::new(Phase::Idle),
        guard: std::sync::Mutex::new(None),
    });
    let mut resources = controlled(ResourceLimits::default(), control.clone());
    let dir = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(dir.path()).unwrap();
    let mut stage = store.stage(&mut resources).unwrap();
    *control.guard.lock().unwrap() = Some(stage.publication_guard(&resources).unwrap());
    stage.write_chunk(DATA).unwrap();
    // The public commit entry and its mandatory post-sync checkpoint form this
    // semantic schedule; no global operation/crypto checkpoint count is pinned.
    *control.phase.lock().unwrap() = Phase::CommitEntry;
    let destination = dir.path().join("must-not-publish");
    assert!(stage.commit(&destination).is_err());
    assert!(!destination.exists());
}

#[test]
fn final_delivery_control_transition_is_failure_even_after_complete_prefix() {
    struct Control {
        armed: AtomicBool,
        guard: std::sync::Mutex<Option<oncl_pki::io::OutputPublicationGuard>>,
    }
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                drop(self.guard.lock().unwrap().take());
            }
            Ok(())
        }
    }
    struct Writer {
        bytes: Vec<u8>,
        control: Arc<Control>,
    }
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.control.armed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
    let control = Arc::new(Control {
        armed: AtomicBool::new(false),
        guard: std::sync::Mutex::new(None),
    });
    let mut resources = controlled(ResourceLimits::default(), control.clone());
    let dir = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(dir.path()).unwrap();
    let mut stage = store.stage(&mut resources).unwrap();
    *control.guard.lock().unwrap() = Some(stage.publication_guard(&resources).unwrap());
    stage.write_chunk(DATA).unwrap();
    let mut writer = Writer {
        bytes: Vec::new(),
        control,
    };
    assert!(stage.copy_to(&mut writer).is_err());
    assert_eq!(writer.bytes, DATA);
}

// Own attached result: document allowance is the payload, the envelope is
// container surcharge and must not consume the document allowance.
#[test]
fn own_attached_result_reads_back_with_document_exact_input_limit() {
    let der = signed("user-rsa-sign", DATA, true, false);
    assert!(der.len() > DATA.len());
    let limits = |input_bytes| ResourceLimits {
        input_bytes,
        ..ResourceLimits::default()
    };
    let mut output = vec![];
    stream::extract(
        Source::sequential(&mut Cursor::new(&der), None),
        &mut output,
        &mut scope(limits(DATA.len() as u64)),
    )
    .unwrap();
    assert_eq!(output, DATA);
    // limit+1 of document is still rejected.
    assert!(matches!(
        stream::extract(
            Source::sequential(&mut Cursor::new(&der), None),
            &mut vec![],
            &mut scope(limits(DATA.len() as u64 - 1)),
        ),
        Err(StreamError::Processing(ProcessingError::InputLimit))
    ));
    // Wire beyond document + container_bytes is rejected as intake overflow.
    assert!(matches!(
        stream::extract(
            Source::sequential(&mut Cursor::new(&der), None),
            &mut vec![],
            &mut scope(ResourceLimits {
                input_bytes: DATA.len() as u64,
                container_bytes: 16,
                ..ResourceLimits::default()
            }),
        ),
        Err(StreamError::Processing(ProcessingError::InputLimit))
    ));
}
