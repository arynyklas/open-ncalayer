use oncl_pdf::{ByteRange, PdfDocument, PdfError, PdfLimits, verify_source};
use oncl_pki::{
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::Source,
    key::SigAlg,
    pkix::CaSet,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
    validation::{CheckStatus, ValidationContext, ValidationPolicy, Verdict},
};
use std::{io::Cursor, sync::Arc};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope() -> ResourceScope {
    let limits = ResourceLimits::default();
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
struct Offline;
impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        panic!("PDF offline verification attempted network access")
    }
}
fn verify(bytes: &[u8]) -> oncl_pdf::Result<oncl_pdf::PdfVerification> {
    let mut cursor = Cursor::new(bytes);
    let mut scope = scope();
    let anchors = CaSet::new(vec![
        oncl_pki::cert::parse(include_bytes!("fixtures/external-cert.der")).unwrap(),
    ]);
    let temp = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(temp.path()).unwrap();
    verify_source(
        Source::seekable(&mut cursor, Some(1)),
        &PdfLimits::default(),
        &store,
        &ValidationContext {
            policy: ValidationPolicy::OfflineReport,
            now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
            anchors: &anchors,
            intermediates: &[],
            http: &Offline,
        },
        &[SigAlg::RsaSha256],
        &mut scope,
    )
}
#[test]
fn overlapping_or_out_of_bounds_ranges() {
    assert!(ByteRange::new([0, 20, 19, 30], 49).is_err());
    assert!(ByteRange::new([0, 20, 30, 21], 50).is_err());
    assert!(ByteRange::new([0, 20, u64::MAX, 2], u64::MAX).is_err());
    let ranges = ByteRange::new([0, 20, 30, 20], 50).unwrap();
    assert_eq!(ranges.signed_end(), 50);
    assert_eq!(ranges.gap(), 20..30);
}
#[test]
fn xref_offset_above_4gib() {
    // Arithmetic-only virtual boundary, not a large-document/RSS proof.
    let offset = (1u64 << 32) + 137;
    let ranges = ByteRange::new([0, 64, offset, 12], offset + 12).unwrap();
    struct Virtual {
        position: u64,
        extent: u64,
        chunks: Vec<(u64, Vec<u8>)>,
    }
    impl std::io::Read for Virtual {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let count = (self.extent.saturating_sub(self.position)).min(out.len() as u64) as usize;
            out[..count].fill(0);
            for (offset, bytes) in &self.chunks {
                let start = self.position.max(*offset);
                let end = (self.position + count as u64).min(*offset + bytes.len() as u64);
                if start < end {
                    out[(start - self.position) as usize..(end - self.position) as usize]
                        .copy_from_slice(
                            &bytes[(start - offset) as usize..(end - offset) as usize],
                        );
                }
            }
            self.position += count as u64;
            Ok(count)
        }
    }
    impl std::io::Seek for Virtual {
        fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
            self.position = match from {
                std::io::SeekFrom::Start(n) => Some(n),
                std::io::SeekFrom::Current(n) => self.position.checked_add_signed(n),
                std::io::SeekFrom::End(n) => self.extent.checked_add_signed(n),
            }
            .ok_or_else(|| std::io::Error::other("seek overflow"))?;
            Ok(self.position)
        }
    }
    let table=format!("xref\n0 2\n0000000000 65535 f \n{:010} 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{offset}\n%%EOF\n",offset-50).into_bytes();
    let extent = offset + table.len() as u64;
    let mut virtual_source = Virtual {
        position: 0,
        extent,
        chunks: vec![
            (0, b"%PDF-1.7\n".to_vec()),
            (
                offset - 50,
                b"1 0 obj\n<< /Type /Catalog >>\nendobj\n".to_vec(),
            ),
            (offset, table),
        ],
    };
    let mut scope = scope();
    let doc = PdfDocument::open(
        Source::seekable(&mut virtual_source, None),
        &PdfLimits::default(),
        &mut scope,
    )
    .unwrap();
    assert_eq!(doc.revision_count(), 1);
    assert_eq!(doc.extent(), extent);
    assert_eq!(ranges.signed_end(), offset + 12);
    assert!(ByteRange::new([0, 64, offset, 12], offset + 11).is_err());
}
#[test]
fn externally_signed_revision_and_mutations() {
    let report = verify(include_bytes!("fixtures/external-signed.pdf")).unwrap();
    assert_eq!(report.signatures.len(), 1);
    let signature = &report.signatures[0];
    assert_eq!(signature.byte_range.values(), [0, 1055, 5313, 493]);
    assert_eq!(signature.revision, 1);
    assert_eq!(signature.revision_end, 5806);
    assert!(!signature.later_changes);
    assert_eq!(
        signature.validation.signers[0].signature,
        CheckStatus::Passed
    );
    // A cryptographically correct self-signed test fixture is not full online trust.
    assert_ne!(report.verdict, Verdict::Valid);
    let inside = verify(include_bytes!("fixtures/external-mutated.pdf")).unwrap();
    assert_eq!(inside.verdict, Verdict::Invalid);
    assert_eq!(
        inside.signatures[0].validation.signers[0].signature,
        CheckStatus::Failed
    );
    let outside = verify(include_bytes!("fixtures/external-later.pdf")).unwrap();
    assert!(outside.signatures[0].later_changes);
    assert_eq!(outside.signatures[0].revision, 1);
    assert_eq!(
        outside.signatures[0].validation.signers[0].signature,
        CheckStatus::Passed
    );
}
#[test]
fn object_stream_revision_chain() {
    let mut cursor = Cursor::new(include_bytes!("fixtures/external-later.pdf").as_slice());
    let mut scope = scope();
    let doc = PdfDocument::open(
        Source::seekable(&mut cursor, None),
        &PdfLimits::default(),
        &mut scope,
    )
    .unwrap();
    assert_eq!(doc.revision_count(), 3);
    assert_eq!(doc.revision_ends().nth(1), Some(5806));
    drop(doc);
    // lopdf is only an independent small-document oracle, never production DOM.
    let oracle = lopdf::Document::load_mem(include_bytes!("fixtures/external-signed.pdf")).unwrap();
    assert_eq!(oracle.get_pages().len(), 1);
}
#[test]
fn source_origin_hint_truncation_and_limits() {
    let fixture = include_bytes!("fixtures/external-signed.pdf");
    let mut prefixed = b"ignored prefix".to_vec();
    prefixed.extend_from_slice(fixture);
    let mut cursor = Cursor::new(prefixed);
    cursor.set_position(14);
    let mut scope = scope();
    let doc = PdfDocument::open(
        Source::seekable(&mut cursor, Some(u64::MAX)),
        &PdfLimits::default(),
        &mut scope,
    )
    .unwrap();
    assert_eq!(doc.extent(), fixture.len() as u64);
    drop(doc);
    assert!(verify(&fixture[..fixture.len() - 16]).is_err());
    assert!(verify(b"not a PDF").is_err());
    let mut cursor = Cursor::new(fixture.as_slice());
    let limits = PdfLimits {
        max_revisions: 1,
        ..PdfLimits::default()
    };
    assert!(matches!(
        PdfDocument::open(Source::seekable(&mut cursor, None), &limits, &mut scope),
        Err(PdfError::Limit("revision count"))
    ));
}
#[test]
fn cancellation_and_typed_resource_failure() {
    struct Cancel;
    impl OperationControl for Cancel {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            Err(ProcessingError::Cancelled)
        }
    }
    let limits = ResourceLimits::default();
    let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Cancel))
        .unwrap();
    let mut cursor = Cursor::new(include_bytes!("fixtures/external-signed.pdf").as_slice());
    assert!(matches!(
        PdfDocument::open(
            Source::seekable(&mut cursor, None),
            &PdfLimits::default(),
            &mut scope
        ),
        Err(PdfError::Processing(ProcessingError::Cancelled))
    ));
    let limits = ResourceLimits {
        metadata_bytes: 1,
        ..ResourceLimits::default()
    };
    let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap();
    assert!(matches!(
        PdfDocument::open(
            Source::seekable(&mut cursor, None),
            &PdfLimits::default(),
            &mut scope
        ),
        Err(PdfError::Processing(ProcessingError::MetadataLimit))
    ));
}

#[test]
fn classic_xref_and_decode_work_limit() {
    use lopdf::{Document, dictionary};
    let mut oracle = Document::with_version("1.4");
    let root = oracle.add_object(dictionary! {"Type"=>"Catalog"});
    oracle.trailer.set("Root", root);
    let mut bytes = Vec::new();
    oracle.save_to(&mut bytes).unwrap();
    let mut cursor = Cursor::new(bytes);
    let mut scope = scope();
    assert_eq!(
        PdfDocument::open(
            Source::seekable(&mut cursor, None),
            &PdfLimits::default(),
            &mut scope
        )
        .unwrap()
        .revision_count(),
        1
    );
    let mut cursor = Cursor::new(include_bytes!("fixtures/external-signed.pdf").as_slice());
    let limits = PdfLimits {
        max_decode_work: 1,
        ..PdfLimits::default()
    };
    assert!(matches!(
        PdfDocument::open(Source::seekable(&mut cursor, None), &limits, &mut scope),
        Err(PdfError::Limit("decompression work"))
    ));
}

#[test]
fn exact_contents_gap_and_revision_boundary_are_required() {
    let original = include_bytes!("fixtures/external-signed.pdf");
    let marker = b"/ByteRange [0 1055 5313 493]";
    let start = original
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap();
    let mut bytes = original.to_vec();
    bytes[start..start + marker.len()].copy_from_slice(b"/ByteRange [0 1054 5313 493]");
    assert!(matches!(
        verify(&bytes),
        Err(PdfError::Malformed(
            "ByteRange must exclude exactly Contents token"
        ))
    ));
    bytes[start..start + marker.len()].copy_from_slice(b"/ByteRange [0 1055 5313 492]");
    assert!(matches!(
        verify(&bytes),
        Err(PdfError::Malformed(
            "signature not reachable in protected revision"
        ))
    ));
}

#[test]
fn multiple_signatures_replay_one_actual_intake_and_keep_all_reports() {
    let bytes = include_bytes!("fixtures/external-two-signatures.pdf");
    let limits = ResourceLimits {
        input_bytes: bytes.len() as u64,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(temp.path()).unwrap();
    let anchors = CaSet::new(vec![
        oncl_pki::cert::parse(include_bytes!("fixtures/external-cert.der")).unwrap(),
    ]);
    let context = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let mut cursor = Cursor::new(bytes.as_slice());
    let report = verify_source(
        Source::seekable(&mut cursor, None),
        &PdfLimits::default(),
        &store,
        &context,
        &[SigAlg::RsaSha256],
        &mut scope,
    )
    .unwrap();
    assert_eq!(scope.progress().bytes_in, bytes.len() as u64);
    assert_eq!(report.signatures.len(), 2);
    assert!(report.signatures[0].later_changes);
    assert!(!report.signatures[1].later_changes);
    assert_eq!(
        report.signatures[1].byte_range.values(),
        [0, 6236, 10494, 501]
    );
    assert!(
        report
            .signatures
            .iter()
            .all(|s| s.validation.signers[0].signature == CheckStatus::Passed)
    );
    let (mut validation, facts) = report.into_aggregate(&scope).unwrap();
    assert_eq!(validation.signers.len(), 2);
    assert_eq!(facts.signatures[0].signers, 0..1);
    assert_eq!(facts.signatures[1].signers, 1..2);
    let (foreign, _) = verify(include_bytes!("fixtures/external-signed.pdf"))
        .unwrap()
        .into_aggregate(&scope)
        .unwrap();
    let other = foreign.signers;
    assert!(matches!(
        validation.signers.append(other, &scope),
        Err(ProcessingError::InvalidInput(_))
    ));
    assert_eq!(validation.signers.len(), 2);
    drop(facts);
    drop(scope);
    assert!(matches!(
        budget.begin(limits.clone(), Arc::new(Control)),
        Err(ProcessingError::CapacityExceeded)
    ));
    drop(validation);
    assert!(budget.begin(limits, Arc::new(Control)).is_ok());
}

#[test]
fn png_predictor_xref_stream_is_decoded_with_work_bounds() {
    use std::io::Write;
    let mut bytes = b"%PDF-1.5\n".to_vec();
    let root = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    let xref = bytes.len() as u64;
    let mut raw = Vec::new();
    for (kind, offset, generation) in [(0u8, 0u64, 65535u16), (1, root, 0), (1, xref, 0)] {
        raw.push(kind);
        raw.extend_from_slice(&offset.to_be_bytes());
        raw.extend_from_slice(&generation.to_be_bytes());
    }
    let mut predicted = Vec::new();
    let mut previous = [0u8; 11];
    for row in raw.as_chunks::<11>().0 {
        predicted.push(2);
        for i in 0..11 {
            predicted.push(row[i].wrapping_sub(previous[i]));
        }
        previous.copy_from_slice(row);
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&predicted).unwrap();
    let compressed = encoder.finish().unwrap();
    bytes.extend_from_slice(format!("2 0 obj\n<< /Type /XRef /Size 3 /Root 1 0 R /W [1 8 2] /Length {} /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 11 >> >>\nstream\n",compressed.len()).as_bytes());
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(format!("\nendstream\nendobj\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    let mut scope = scope();
    let mut cursor = Cursor::new(bytes);
    assert_eq!(
        PdfDocument::open(
            Source::seekable(&mut cursor, None),
            &PdfLimits::default(),
            &mut scope
        )
        .unwrap()
        .revision_count(),
        1
    );
}

#[test]
fn valid_real_metadata_does_not_break_signature_field_discovery() {
    let mut bytes = b"%PDF-1.4\n".to_vec();
    let catalog = bytes.len();
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Extra [0.25 -1.5 +12 .5] >>\nendobj\n");
    let xref = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 2\n0000000000 65535 f \n{catalog:010} 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    assert!(matches!(
        verify(&bytes),
        Err(PdfError::Unsupported(
            "no supported revision-bound signature"
        ))
    ));
}

#[test]
fn hybrid_xref_and_inherited_root_revisions_are_resolved() {
    let mut bytes = b"%PDF-1.5\n".to_vec();
    let root = bytes.len() as u64;
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    let stream = bytes.len() as u64;
    let mut entries = Vec::new();
    for (kind, offset, generation) in [(0u8, 0u64, 65535u16), (1, root, 0), (1, stream, 0)] {
        entries.push(kind);
        entries.extend_from_slice(&offset.to_be_bytes());
        entries.extend_from_slice(&generation.to_be_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "2 0 obj\n<< /Type /XRef /Size 3 /W [1 8 2] /Length {} >>\nstream\n",
            entries.len()
        )
        .as_bytes(),
    );
    bytes.extend_from_slice(&entries);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 3 /Root 1 0 R /XRefStm {stream} >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    assert!(matches!(
        verify(&bytes),
        Err(PdfError::Unsupported(
            "no supported revision-bound signature"
        ))
    ));
    let mut signed = include_bytes!("fixtures/external-signed.pdf").to_vec();
    let marker = signed.windows(9).rposition(|w| w == b"startxref").unwrap();
    let previous = std::str::from_utf8(&signed[marker + 9..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let new_xref = signed.len();
    signed.extend_from_slice(format!("xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 100 /Prev {previous} >>\nstartxref\n{new_xref}\n%%EOF\n").as_bytes());
    let result = verify(&signed).unwrap();
    assert_eq!(result.signatures.len(), 1);
    assert!(result.signatures[0].later_changes);
    assert_eq!(
        result.signatures[0].validation.signers[0].signature,
        CheckStatus::Passed
    );
}

#[test]
fn forward_prev_cycles_and_xref_outside_revision_are_rejected() {
    let mut bytes = b"%PDF-1.4\n".to_vec();
    let xref = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R /Prev {xref} >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    assert!(matches!(
        verify(&bytes),
        Err(PdfError::Malformed("forward Prev"))
    ));
    let mut bytes = b"%PDF-1.4\n".to_vec();
    let xref = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 2\n0000000000 65535 f \n9999999999 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    assert!(matches!(
        verify(&bytes),
        Err(PdfError::Malformed("xref entry outside its revision"))
    ));
}

#[test]
fn genuine_pdf_verification_accepts_authentic_frozen_source_at_exact_input_quota() {
    use oncl_pki::io::{FrozenInput, Region, TemporaryStore};
    let bytes = include_bytes!("fixtures/external-signed.pdf");
    let limits = ResourceLimits {
        input_bytes: bytes.len() as u64,
        ..ResourceLimits::default()
    };
    let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(temp.path()).unwrap();
    let anchors = CaSet::new(vec![
        oncl_pki::cert::parse(include_bytes!("fixtures/external-cert.der")).unwrap(),
    ]);
    let mut input = Cursor::new(bytes.as_slice());
    let mut frozen =
        FrozenInput::capture(Source::seekable(&mut input, None), &store, &mut scope).unwrap();
    let mut source = frozen
        .reader(
            &[Region {
                offset: 0,
                len: bytes.len() as u64,
            }],
            &scope,
        )
        .unwrap();
    let report = verify_source(
        source.source(),
        &PdfLimits::default(),
        &store,
        &ValidationContext {
            policy: ValidationPolicy::OfflineReport,
            now: time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
            anchors: &anchors,
            intermediates: &[],
            http: &Offline,
        },
        &[SigAlg::RsaSha256],
        &mut scope,
    )
    .unwrap();
    source.finish().unwrap();
    assert_eq!(scope.progress().bytes_in, bytes.len() as u64);
    assert_eq!(
        report.signatures[0].validation.signers[0].signature,
        CheckStatus::Passed
    );
    assert_eq!(
        report.signatures[0].byte_range.values(),
        [0, 1055, 5313, 493]
    );
    assert_eq!(report.signatures[0].revision_end, 5806);
}
