#![cfg(feature = "xml")]
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationPolicy, ValidationServices,
    VerifyRequest,
};
use oncl_pki::{
    http::{HttpError, HttpReply, HttpRequest, HttpTransport},
    io::{Source, TemporaryStore},
    pkix::CaSet,
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
    validation::CheckStatus,
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
        panic!("offline Core XML must not fetch")
    }
}
#[test]
fn xml_dispatch_retains_actual_reference_facts() {
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let key = oncl_pki::pkcs12::load(&oncl_testkit::read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    let bytes = oncl_xml::sign_element(
        b"<r><a Id='x'>covered</a><u>plain</u></r>",
        "/r/a",
        None,
        &key.key,
        &key.cert,
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let services = ValidationServices::new(
        CaSet::new(vec![]),
        vec![],
        Arc::new(Offline),
        oncl_pki::validation::NetworkPolicy::deny_all(),
        Arc::new(|| time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap()),
    );
    let limits = ResourceLimits {
        output_bytes: 0,
        ..ResourceLimits::default()
    };
    let engine = Engine::new(
        EngineServices::hash_only(limits)
            .with_validation(services)
            .with_temporary_store(TemporaryStore::new(temp.path()).unwrap()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let report = engine
        .verify(
            &VerifyRequest::xml(),
            Source::sequential(&mut Cursor::new(&bytes), None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    let facts = report.xml.as_ref().unwrap();
    assert_eq!(facts.signatures().len(), 1);
    assert!(facts.signatures()[0].references()[0].digest_matches);
    #[cfg(feature = "pdf")]
    assert!(report.pdf.is_none());
}

#[test]
fn xml_timestamp_dispatch_uses_f03_without_final_output_credit_or_trust_promotion() {
    use oncl_pki::tsp::{MockTsa, TsaProfile, TsaSpec};
    use oncl_xml::xades::{XadesLevel, XadesSpec};
    let load = |name: &str| {
        let fixture = oncl_testkit::synthetic(name);
        oncl_pki::pkcs12::load(&oncl_testkit::read(&fixture.path), &fixture.password)
            .unwrap()
            .remove(0)
    };
    let key = load("user-rsa-sign");
    let spec = XadesSpec {
        level: XadesLevel::T,
        tsa: Some(TsaSpec::from(TsaProfile::basics_default())),
        chain: vec![],
        signature_method: None,
        digest_method: None,
    };
    let signed = oncl_xml::xades::sign(
        b"<r>covered</r>",
        &spec,
        &key.key,
        &key.cert,
        &MockTsa::new(load("tsa-gost2015")),
        time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap(),
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let services = ValidationServices::new(
        CaSet::new(vec![]),
        vec![],
        Arc::new(Offline),
        oncl_pki::validation::NetworkPolicy::deny_all(),
        Arc::new(|| time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap()),
    );
    let limits = ResourceLimits {
        output_bytes: 0,
        ..ResourceLimits::default()
    };
    let engine = Engine::new(
        EngineServices::hash_only(limits)
            .with_validation(services)
            .with_temporary_store(TemporaryStore::new(temp.path()).unwrap()),
    )
    .unwrap();
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let report = engine
        .verify(
            &VerifyRequest::xml(),
            Source::sequential(&mut Cursor::new(&signed), None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert_ne!(report.signers[0].timestamp, CheckStatus::NotApplicable);
    assert!(report.signers[0].proof_time.is_none());
    assert_ne!(report.verdict, oncl_pki::validation::Verdict::Valid);
    assert!(
        report.xml.unwrap().signatures()[0]
            .references()
            .iter()
            .all(|r| r.digest_matches)
    );
}

#[test]
fn wsse_legacy_rsa_sha1_is_host_selected_verification_only() {
    let source = include_bytes!("../../oncl-xml/tests/support/wsse-legacy-rsa-sha1.xml");
    let temp = tempfile::tempdir().unwrap();
    let services = ValidationServices::new(
        CaSet::new(vec![]),
        vec![],
        Arc::new(Offline),
        oncl_pki::validation::NetworkPolicy::deny_all(),
        Arc::new(|| time::OffsetDateTime::from_unix_timestamp(1793707200).unwrap()),
    );
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(services)
            .with_temporary_store(TemporaryStore::new(temp.path()).unwrap()),
    )
    .unwrap();
    let mut profile = oncl_xml::wsse::WsseVerifyProfile::default();
    profile.xml.allowed_signature_algorithms = &[oncl_pki::key::SigAlg::RsaSha1];
    let mut policy = OperationPolicy::offline_report();
    policy.allowed_signature_algorithms = &[oncl_pki::key::SigAlg::RsaSha1];
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            policy,
            Arc::new(Control),
        )
        .unwrap();
    let report = engine
        .verify(
            &VerifyRequest::wsse(profile),
            Source::sequential(&mut Cursor::new(source), None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    assert!(report.xml.unwrap().wsse().unwrap().signers()[0].body_digest_matches());
}
