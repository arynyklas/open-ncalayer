#![cfg(feature = "pdf")]
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationPolicy, ValidationServices,
    VerifyRequest,
};
use oncl_pki::{
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::Source,
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
    validation::{CheckStatus, Verdict},
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
        panic!("offline PDF network")
    }
}
#[test]
fn pdf_engine_keeps_revision_facts_and_scoped_signers() {
    let services = ValidationServices::new(
        CaSet::new(vec![
            oncl_pki::cert::parse(include_bytes!(
                "../../oncl-pdf/tests/fixtures/external-cert.der"
            ))
            .unwrap(),
        ]),
        vec![],
        Arc::new(Offline),
        oncl_pki::validation::NetworkPolicy::deny_all(),
        Arc::new(|| time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap()),
    );
    let temp = tempfile::tempdir().unwrap();
    let store = oncl_pki::io::TemporaryStore::new(temp.path()).unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(services)
            .with_temporary_store(store),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let mut input =
        Cursor::new(include_bytes!("../../oncl-pdf/tests/fixtures/external-later.pdf").as_slice());
    let report = engine
        .verify(
            &VerifyRequest::pdf(),
            Source::seekable(&mut input, None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.signers.len(), 1);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_ne!(report.verdict, Verdict::Valid);
    let facts = report.pdf.as_ref().unwrap();
    assert_eq!(facts.signatures.len(), 1);
    assert!(facts.signatures[0].later_changes);
    assert_eq!(facts.signatures[0].revision_end, 5806);
}

#[test]
fn pades_nonprivate_extend_and_private_sign_have_distinct_grants() {
    use oncl_core::{
        ErrorCode, ExtendRequest, SignRequest,
        keys::{KeyRequest, KeySelector},
    };
    use oncl_pki::{
        cms::ades::ValidationMaterial,
        evidence::{AdesLevel, EvidenceLimits},
    };
    struct NoRead;
    impl std::io::Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("must preflight before intake")
        }
    }
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let limits = EvidenceLimits {
        max_items: 64,
        max_bytes: 8 << 20,
        max_item_bytes: 1 << 20,
        max_chain_len: 8,
        max_proofs: 8,
        max_coverage_parts: 1024,
        max_coverage_bytes: 10_737_418_240,
    };
    let key = KeySelector::inline(vec![], None);
    for grant in [Action::Sign, Action::SignDigest] {
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([grant]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let error = engine
            .sign(
                SignRequest::pades(
                    KeyRequest::new(&key, None),
                    oncl_pdf::PdfSignProfile::default(),
                    AdesLevel::T,
                    ValidationMaterial {
                        certificates: &[],
                        ocsp: &[],
                        crls: &[],
                    },
                    limits,
                ),
                Source::sequential(&mut NoRead, None),
                &mut Vec::new(),
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(
            error.code(),
            if grant == Action::Sign {
                ErrorCode::MissingCadesConfiguration
            } else {
                ErrorCode::PermissionDenied
            }
        );
        assert_eq!(
            error.applied_state(),
            oncl_pki::key::AppliedState::NotApplied
        );
    }
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]),
            OperationPolicy::strict_online(),
            Arc::new(Control),
        )
        .unwrap();
    let error = engine
        .extend(
            &ExtendRequest::pdf(AdesLevel::Lta, oncl_pdf::PdfLimits::default()),
            Source::sequential(&mut NoRead, None),
            &mut Vec::new(),
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
}

#[test]
fn pades_engine_samples_final_host_time_after_actual_pdf_intake() {
    use oncl_pki::{
        cms::ades::{AdesServices, ValidationMaterial},
        crl::MockCrl,
        evidence::{AdesLevel, EvidenceLimits},
        io::TemporaryStore,
        pkcs12::{KeyEntry, load},
        resource::SharedBudget,
        testing::{TestCertSpec, issue_cert},
        validation::{NetworkPolicy, ValidationContext, ValidationPolicy},
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    fn entry(name: &str) -> KeyEntry {
        let fixture = oncl_testkit::synthetic(name);
        load(&oncl_testkit::read(fixture.path), &fixture.password)
            .unwrap()
            .remove(0)
    }
    let started = time::macros::datetime!(2026-11-03 12:00 UTC);
    let checked = started + time::Duration::MINUTE;
    let root = entry("root-gost2015.key");
    let mut signer = entry("user-rsa-sign");
    let mut spec = TestCertSpec::from_cert(&signer.cert);
    spec.extensions.retain(|extension| {
        !matches!(
            extension.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    signer.cert = issue_cert(&root, spec);
    let anchors = CaSet::new(vec![root.cert.clone()]);
    let crl = MockCrl::new(root)
        .with_this_update(started - time::Duration::MINUTE)
        .next_update(Some(checked + time::Duration::HOUR))
        .der();
    let scratch = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(scratch.path()).unwrap();
    let limits = ResourceLimits::default();
    let mut scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap();
    let validation = ValidationContext {
        policy: ValidationPolicy::StrictOnline,
        now: started,
        anchors: &anchors,
        intermediates: &[],
        http: &Offline,
    };
    let network = NetworkPolicy::deny_all();
    let crls = [crl.as_slice()];
    let evidence_limits = EvidenceLimits {
        max_items: 64,
        max_bytes: 8 << 20,
        max_item_bytes: 1 << 20,
        max_chain_len: 8,
        max_proofs: 8,
        max_coverage_parts: 1024,
        max_coverage_bytes: 10_737_418_240,
    };
    let services = AdesServices {
        validation: &validation,
        host_clock: None,
        network: &network,
        temporary: &store,
        limits: evidence_limits,
        tsa: None,
        material: ValidationMaterial {
            certificates: &[],
            ocsp: &[],
            crls: &crls,
        },
    };
    let mut output = store.stage(&mut scope).unwrap();
    oncl_pdf::ades::sign(
        AdesLevel::B,
        Source::sequential(
            &mut Cursor::new(include_bytes!(
                "../../oncl-pdf/tests/fixtures/external-multipage.pdf"
            )),
            None,
        ),
        &oncl_pdf::PdfSignProfile::default(),
        &mut signer,
        &services,
        &mut output,
        &scope,
    )
    .unwrap();
    let mut bytes = Vec::new();
    output.copy_to(&mut bytes).unwrap();
    let complete = Arc::new(AtomicBool::new(false));
    let late_samples = Arc::new(AtomicUsize::new(0));
    let clock = {
        let complete = complete.clone();
        let late_samples = late_samples.clone();
        Arc::new(move || {
            if complete.load(Ordering::SeqCst) {
                late_samples.fetch_add(1, Ordering::SeqCst);
                checked
            } else {
                started
            }
        })
    };
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_temporary_store(store.clone())
            .with_validation(ValidationServices::new(
                anchors.clone(),
                vec![],
                Arc::new(Offline),
                network,
                clock,
            )),
    )
    .unwrap();
    struct CompletePdfRead {
        input: Cursor<Vec<u8>>,
        complete: Arc<AtomicBool>,
    }
    impl std::io::Read for CompletePdfRead {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let count = std::io::Read::read(&mut self.input, output)?;
            if count == 0 {
                self.complete.store(true, Ordering::SeqCst);
            }
            Ok(count)
        }
    }
    let mut input = CompletePdfRead {
        input: Cursor::new(bytes),
        complete,
    };
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let report = engine
        .verify(
            &VerifyRequest::pades(AdesLevel::B, evidence_limits),
            Source::sequential(&mut input, None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.checked_at, checked);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_eq!(late_samples.load(Ordering::SeqCst), 1);
}
