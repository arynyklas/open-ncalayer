//! Real signed XML boundaries: document quota is not raw signed-wire quota.
use oncl_pki::{
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::{FrozenInput, Region, Source, TemporaryStore},
    key::HashAlg,
    pkix::CaSet,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
    validation::{CheckStatus, NetworkPolicy, ValidationContext, ValidationPolicy},
};
use oncl_xml::{
    XmlSignMode, XmlSignProfile, XmlSourceError, XmlVerifyProfile, capture_signed_input,
    verify_source,
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
        panic!("offline verification must not fetch")
    }
}
fn key() -> oncl_pki::pkcs12::KeyEntry {
    let f = oncl_testkit::synthetic("user-rsa-sign");
    oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn scope(document: u64) -> ResourceScope {
    let limits = ResourceLimits {
        input_bytes: document,
        container_bytes: 64 * 1024,
        output_bytes: document + 64 * 1024,
        ..Default::default()
    };
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
fn anchors() -> CaSet {
    CaSet::new(vec![
        oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap(),
    ])
}
fn context(root: &CaSet) -> ValidationContext<'_> {
    ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: time::macros::datetime!(2026-11-02 12:00 UTC),
        anchors: root,
        intermediates: &[],
        http: &Offline,
    }
}
#[test]
fn new_operation_accepts_document_n_plus_signature_but_not_n_plus_one_document() {
    let key = key();
    let unsigned = b"<r><data>actual protected payload</data></r>";
    let signed = oncl_xml::sign_enveloped(unsigned, &key.key, &key.cert).unwrap();
    let root = anchors();
    let ctx = context(&root);
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut quota = scope(unsigned.len() as u64);
    let report = verify_source(
        Source::sequential(&mut Cursor::new(&signed), Some(signed.len() as u64)),
        &XmlVerifyProfile::default(),
        &store,
        &ctx,
        &NetworkPolicy::deny_all(),
        &mut quota,
    )
    .unwrap();
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    assert_eq!(quota.progress().bytes_in, signed.len() as u64);
    assert_eq!(quota.input_remaining(), 0);
    assert_eq!(
        quota.container_remaining(),
        64 * 1024 - (signed.len() - unsigned.len()) as u64
    );
    drop(report);
    let wider = b"<r><data>actual protected payload!</data></r>";
    assert_eq!(wider.len(), unsigned.len() + 1);
    let signed_wider = oncl_xml::sign_enveloped(wider, &key.key, &key.cert).unwrap();
    oncl_xml::verify(&signed_wider).unwrap();
    let mut quota = scope(unsigned.len() as u64);
    assert!(matches!(
        verify_source(
            Source::sequential(&mut Cursor::new(&signed_wider), None),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut quota
        ),
        Err(XmlSourceError::Processing(ProcessingError::InputLimit))
    ));
    assert_eq!(quota.progress().bytes_in, signed_wider.len() as u64);
    let mut quota = scope(unsigned.len() as u64);
    assert!(matches!(
        oncl_xml::prepare_source(
            Source::sequential(&mut Cursor::new(wider), None),
            &XmlSignProfile {
                mode: XmlSignMode::Add,
                ..Default::default()
            },
            &store,
            &mut quota
        ),
        Err(XmlSourceError::Processing(ProcessingError::InputLimit))
    ));
}
#[test]
fn classified_capture_replays_same_scope_digest_without_original_input_capability() {
    let key = key();
    let unsigned = b"<r><data>approval-bound immutable payload</data></r>";
    let signed = oncl_xml::sign_enveloped(unsigned, &key.key, &key.cert).unwrap();
    let root = anchors();
    let ctx = context(&root);
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut quota = scope(unsigned.len() as u64);
    let mut captured = capture_signed_input(
        Source::sequential(&mut Cursor::new(&signed), None),
        &XmlVerifyProfile::default(),
        &store,
        &mut quota,
    )
    .unwrap();
    assert_eq!(
        captured.wire_digest().as_bytes(),
        HashAlg::Sha256.digest(&signed)
    );
    assert_eq!(quota.progress().bytes_in, signed.len() as u64);
    assert_eq!(quota.input_remaining(), 0);
    {
        let mut reader = captured.reader(&quota).unwrap();
        assert!(reader.source().is_snapshot_for(&quota).is_err());
        assert!(matches!(
            FrozenInput::capture(reader.source(), &store, &mut quota),
            Err(ProcessingError::InvalidInput(_))
        ));
    }
    {
        let mut reader = captured.reader(&quota).unwrap();
        assert!(matches!(
            oncl_pki::digest::hash_source(reader.source(), HashAlg::Sha256, &mut quota),
            Err(ProcessingError::InvalidInput(_))
        ));
    }
    let mut reader = captured.reader(&quota).unwrap();
    let report = verify_source(
        reader.source(),
        &XmlVerifyProfile::default(),
        &store,
        &ctx,
        &NetworkPolicy::deny_all(),
        &mut quota,
    )
    .unwrap();
    reader.finish().unwrap();
    assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    assert_eq!(
        quota.progress().bytes_in,
        signed.len() as u64,
        "classification replay must not charge or refund wire bytes"
    );
    assert_eq!(quota.input_remaining(), 0);
}
#[test]
fn empty_parent_expansion_is_bounded_and_charged_once_for_two_signatures() {
    let key = key();
    let root = anchors();
    let ctx = context(&root);
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    for (unsigned, parent, delta) in [
        (
            b"<r><d Id='d'>protected</d><s/></r>".as_slice(),
            "/r/s",
            3u64,
        ),
        (
            b"<r xmlns:p='urn:p'><d Id='d'>protected</d><p:s/></r>".as_slice(),
            "/r/p:s",
            5u64,
        ),
    ] {
        let first =
            oncl_xml::sign_element(unsigned, "/r/d", Some(parent), &key.key, &key.cert).unwrap();
        let second =
            oncl_xml::sign_element(&first, "/r/d", Some(parent), &key.key, &key.cert).unwrap();
        oncl_xml::verify(&second).unwrap();
        let mut quota = scope(unsigned.len() as u64);
        let report = verify_source(
            Source::sequential(&mut Cursor::new(&second), None),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut quota,
        )
        .unwrap();
        assert_eq!(report.signatures().len(), 2);
        assert!(
            report
                .validation
                .signers
                .iter()
                .all(|s| s.signature == CheckStatus::Passed)
        );
        assert_eq!(quota.input_remaining(), 0);
        assert_eq!(quota.progress().bytes_in, second.len() as u64);
        let signatures = report
            .signatures()
            .iter()
            .map(|s| s.signature.len)
            .sum::<u64>();
        assert_eq!(
            quota.container_remaining(),
            64 * 1024 - signatures - delta,
            "same parent expansion must be counted ONCE"
        );
    }
}
#[test]
fn existing_original_snapshot_is_not_rebucketed_or_refunded() {
    let key = key();
    let signed =
        oncl_xml::sign_enveloped(b"<r>original paid whole wire</r>", &key.key, &key.cert).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut quota = scope(signed.len() as u64);
    let mut original = FrozenInput::capture(
        Source::sequential(&mut Cursor::new(&signed), None),
        &store,
        &mut quota,
    )
    .unwrap();
    assert_eq!(quota.input_remaining(), 0);
    let mut reader = original
        .reader(
            &[Region {
                offset: 0,
                len: signed.len() as u64,
            }],
            &quota,
        )
        .unwrap();
    let captured = capture_signed_input(
        reader.source(),
        &XmlVerifyProfile::default(),
        &store,
        &mut quota,
    )
    .unwrap();
    reader.finish().unwrap();
    assert_eq!(
        captured.wire_digest().as_bytes(),
        HashAlg::Sha256.digest(&signed)
    );
    assert_eq!(quota.progress().bytes_in, signed.len() as u64);
    assert_eq!(
        quota.input_remaining(),
        0,
        "already paid input cannot be credited back"
    );
    assert_eq!(quota.container_remaining(), 64 * 1024);
}

#[test]
fn signed_batch_precursor_retains_small_ledgers_not_parser_reservations() {
    let key = key();
    let unsigned = (0..6)
        .map(|i| format!("<r><data>batch {i}</data></r>"))
        .collect::<Vec<_>>();
    let signed = unsigned
        .iter()
        .map(|xml| oncl_xml::sign_enveloped(xml.as_bytes(), &key.key, &key.cert).unwrap())
        .collect::<Vec<_>>();
    let total = unsigned.iter().map(|x| x.len() as u64).sum();
    let mut quota = scope(total);
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let root = anchors();
    let ctx = context(&root);
    let mut captures = Vec::new();
    for bytes in &signed {
        captures.push(
            capture_signed_input(
                Source::sequential(&mut Cursor::new(bytes), None),
                &XmlVerifyProfile::default(),
                &store,
                &mut quota,
            )
            .unwrap(),
        );
    }
    let actual_wire = signed.iter().map(|x| x.len() as u64).sum::<u64>();
    assert_eq!(quota.progress().bytes_in, actual_wire);
    assert_eq!(quota.input_remaining(), 0);
    for (capture, bytes) in captures.iter_mut().zip(&signed) {
        assert_eq!(
            capture.wire_digest().as_bytes(),
            HashAlg::Sha256.digest(bytes)
        );
        let mut reader = capture.reader(&quota).unwrap();
        let report = verify_source(
            reader.source(),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut quota,
        )
        .unwrap();
        reader.finish().unwrap();
        assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
    }
    assert_eq!(quota.progress().bytes_in, actual_wire);
}

#[test]
fn application_object_unknown_namespace_and_fake_metadata_never_get_free_document_credit() {
    let key = key();
    let unsigned = b"<r><data>protected</data></r>";
    let signed = oncl_xml::sign_enveloped(unsigned, &key.key, &key.cert).unwrap();
    let text = String::from_utf8(signed).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let root = anchors();
    let ctx = context(&root);
    let object = text.replace(
        "</ds:Signature>",
        "<ds:Object Id='application'>THIS IS ORDINARY APPLICATION DATA</ds:Object></ds:Signature>",
    );
    oncl_xml::verify(object.as_bytes()).unwrap();
    let mut quota = scope(unsigned.len() as u64);
    assert!(matches!(
        verify_source(
            Source::sequential(&mut Cursor::new(object), None),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut quota
        ),
        Err(XmlSourceError::Processing(ProcessingError::InputLimit))
    ));
    let bogus = text.replacen(
        "<ds:Signature xmlns:ds=",
        &format!(
            "<ds:Signature unrecognized='{}' xmlns:ds=",
            "x".repeat(4096)
        ),
        1,
    );
    oncl_xml::verify(bogus.as_bytes()).unwrap();
    let mut quota = scope(unsigned.len() as u64);
    assert!(
        capture_signed_input(
            Source::sequential(&mut Cursor::new(bogus), None),
            &XmlVerifyProfile::default(),
            &store,
            &mut quota
        )
        .is_err()
    );
    let fake = text.replace("http://www.w3.org/2000/09/xmldsig#", "urn:fake-signature");
    let mut quota = scope(unsigned.len() as u64);
    assert!(matches!(
        capture_signed_input(
            Source::sequential(&mut Cursor::new(fake), None),
            &XmlVerifyProfile::default(),
            &store,
            &mut quota
        ),
        Err(XmlSourceError::Processing(ProcessingError::InputLimit))
    ));
    let parsed = roxmltree::Document::parse(&text).unwrap();
    let value = parsed
        .descendants()
        .find(|n| n.tag_name().name() == "SignatureValue")
        .unwrap()
        .first_child()
        .unwrap()
        .range();
    let mut huge = text.clone();
    huge.replace_range(value, &"A".repeat(8192));
    let mut quota = scope(unsigned.len() as u64);
    assert!(matches!(
        capture_signed_input(
            Source::sequential(&mut Cursor::new(huge), None),
            &XmlVerifyProfile {
                max_metadata_bytes: 4096,
                ..Default::default()
            },
            &store,
            &mut quota
        ),
        Err(XmlSourceError::Processing(ProcessingError::MetadataLimit))
    ));
}

#[test]
fn declaration_credit_uses_actual_parser_geometry_and_never_fake_pi_or_whitespace() {
    let key = key();
    let unsigned = b"<r><data>protected</data></r>";
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let root = anchors();
    let ctx = context(&root);
    for standalone in [false, true] {
        let signed = oncl_xml::sign_spec(
            unsigned,
            &oncl_xml::XmlSignSpec {
                output: oncl_xml::XmlOutput::Serialize {
                    declaration: true,
                    standalone_no: standalone,
                    trim: true,
                },
                ..oncl_xml::XmlSignSpec::kalkan(None, None)
            },
            &key.key,
            &key.cert,
        )
        .unwrap();
        let mut quota = scope(unsigned.len() as u64);
        let report = verify_source(
            Source::sequential(&mut Cursor::new(&signed), None),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut quota,
        )
        .unwrap();
        assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
        assert_eq!(quota.input_remaining(), 0);
        assert_eq!(quota.progress().bytes_in, signed.len() as u64);
        drop(report);
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend(&signed);
        let mut quota = scope(unsigned.len() as u64);
        let report = verify_source(
            Source::sequential(&mut Cursor::new(&bom), None),
            &XmlVerifyProfile::default(),
            &store,
            &ctx,
            &NetworkPolicy::deny_all(),
            &mut quota,
        )
        .unwrap();
        assert_eq!(report.validation.signers[0].signature, CheckStatus::Passed);
        assert_eq!(quota.input_remaining(), 0);
        drop(report);
    }
    let signed =
        String::from_utf8(oncl_xml::sign_enveloped(unsigned, &key.key, &key.cert).unwrap())
            .unwrap();
    for (prefix, label) in [
        ("<?xml-stylesheet href='x'?>", "ordinary PI"),
        ("<!--not metadata-->", "comment"),
        ("  \n", "outside whitespace"),
    ] {
        let mutation = format!("{prefix}{signed}");
        let mut quota = scope(unsigned.len() as u64);
        assert!(
            matches!(
                capture_signed_input(
                    Source::sequential(&mut Cursor::new(mutation), None),
                    &XmlVerifyProfile::default(),
                    &store,
                    &mut quota
                ),
                Err(XmlSourceError::Processing(ProcessingError::InputLimit))
            ),
            "{label} must remain document bytes"
        );
    }
    let huge = format!("<?xml version='1.0'{}?>{signed}", " ".repeat(2048));
    let mut quota = scope(unsigned.len() as u64);
    assert!(matches!(
        capture_signed_input(
            Source::sequential(&mut Cursor::new(huge), None),
            &XmlVerifyProfile::default(),
            &store,
            &mut quota
        ),
        Err(XmlSourceError::Processing(ProcessingError::InputLimit))
    ));
    for prefix in [
        "<?xml version='1.0'?><?xml version='1.0'?>",
        "\u{feff}\u{feff}",
    ] {
        let mut quota = scope(unsigned.len() as u64);
        assert!(
            capture_signed_input(
                Source::sequential(&mut Cursor::new(format!("{prefix}{signed}")), None),
                &XmlVerifyProfile::default(),
                &store,
                &mut quota
            )
            .is_err()
        );
    }
}

#[test]
fn foreign_classified_source_and_forged_geometry_cannot_gain_crypto_authority() {
    use oncl_pki::io::ProvisionalInput;
    let key = key();
    let unsigned = b"<r>owner bound</r>";
    let signed = oncl_xml::sign_enveloped(unsigned, &key.key, &key.cert).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut owner = scope(unsigned.len() as u64);
    let mut foreign = scope(unsigned.len() as u64);
    let mut captured = capture_signed_input(
        Source::sequential(&mut Cursor::new(&signed), None),
        &XmlVerifyProfile::default(),
        &store,
        &mut owner,
    )
    .unwrap();
    assert!(captured.reader(&foreign).is_err());
    let mut reader = captured.reader(&owner).unwrap();
    assert!(
        capture_signed_input(
            reader.source(),
            &XmlVerifyProfile::default(),
            &store,
            &mut foreign
        )
        .is_err()
    );
    reader.finish().unwrap();
    assert_eq!(foreign.progress().bytes_in, 0);
    let bytes = b"<r>ordinary application</r>";
    let mut quota = scope(1);
    let mut forged = ProvisionalInput::capture(
        Source::sequential(&mut Cursor::new(bytes), None),
        &store,
        &mut quota,
        64 * 1024,
    )
    .unwrap();
    forged
        .classify(
            &[Region {
                offset: 0,
                len: bytes.len() as u64,
            }],
            &quota,
        )
        .unwrap();
    let mut reader = forged
        .reader(
            &[Region {
                offset: 0,
                len: bytes.len() as u64,
            }],
            &quota,
        )
        .unwrap();
    assert!(matches!(
        capture_signed_input(
            reader.source(),
            &XmlVerifyProfile::default(),
            &store,
            &mut quota
        ),
        Err(XmlSourceError::Processing(ProcessingError::InputLimit))
    ));
    assert_eq!(quota.progress().bytes_in, bytes.len() as u64);
}

#[test]
fn one_trusted_time_sample_is_shared_after_all_real_signer_preparation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let key = key();
    let unsigned = b"<r><d Id='d'>both real signers</d><s/></r>";
    let first =
        oncl_xml::sign_element(unsigned, "/r/d", Some("/r/s"), &key.key, &key.cert).unwrap();
    let second = oncl_xml::sign_element(&first, "/r/d", Some("/r/s"), &key.key, &key.cert).unwrap();
    let root = anchors();
    let ctx = context(&root);
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut quota = scope(unsigned.len() as u64);
    let calls = AtomicUsize::new(0);
    let clock =
        || ctx.now + time::Duration::seconds(20 + calls.fetch_add(1, Ordering::SeqCst) as i64);
    let report = oncl_xml::verify_source_with_clock(
        Source::sequential(&mut Cursor::new(second), None),
        &XmlVerifyProfile::default(),
        &store,
        &ctx,
        &NetworkPolicy::deny_all(),
        &clock,
        &mut quota,
    )
    .unwrap();
    assert_eq!(report.validation.signers.len(), 2);
    assert!(
        report
            .validation
            .signers
            .iter()
            .all(|s| s.signature == CheckStatus::Passed)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one host policy instant, not one per signer"
    );
    assert_eq!(
        report.validation.checked_at,
        ctx.now + time::Duration::seconds(20)
    );
}

#[test]
fn nonempty_parent_content_never_receives_empty_tag_expansion_credit() {
    let key = key();
    let unsigned = b"<r><d Id='d'>protected</d><s/></r>";
    let signed = String::from_utf8(
        oncl_xml::sign_element(unsigned, "/r/d", Some("/r/s"), &key.key, &key.cert).unwrap(),
    )
    .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    for content in [
        " ",
        "<!--application comment-->",
        "<?app value?>",
        "<![CDATA[data]]>",
        "<a/>",
        "application",
    ] {
        let wire = signed.replace("</s>", &format!("{content}</s>"));
        oncl_xml::verify(wire.as_bytes()).unwrap();
        let expected = unsigned.len() as u64 + 3 + content.len() as u64;
        let mut exact = scope(expected);
        let captured = capture_signed_input(
            Source::sequential(&mut Cursor::new(&wire), None),
            &XmlVerifyProfile::default(),
            &store,
            &mut exact,
        )
        .unwrap();
        assert_eq!(captured.document_bytes(), expected, "{content}");
        assert_eq!(exact.progress().bytes_in, wire.len() as u64);
        drop(captured);
        let mut short = scope(expected - 1);
        assert!(
            matches!(
                capture_signed_input(
                    Source::sequential(&mut Cursor::new(&wire), None),
                    &XmlVerifyProfile::default(),
                    &store,
                    &mut short
                ),
                Err(XmlSourceError::Processing(ProcessingError::InputLimit))
            ),
            "{content}"
        );
    }
}

#[test]
fn malformed_output_derived_signed_intake_permanently_poison_its_original_output() {
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut quota = scope(1);
    let mut stage = store.stage(&mut quota).unwrap();
    let mut output = oncl_pki::io::XmlSignatureOutput::new(&mut stage, &quota).unwrap();
    output.append(b"<r>").unwrap();
    assert!(
        capture_signed_input(
            output.source().unwrap(),
            &XmlVerifyProfile::default(),
            &store,
            &mut quota
        )
        .is_err()
    );
    assert_eq!(
        quota.progress().bytes_in,
        0,
        "output projection is never original document intake"
    );
    assert!(
        output.finish(&quota).is_err(),
        "a failed format capture must poison its originating output"
    );
    assert!(stage.copy_to(&mut Vec::new()).is_err());
}
