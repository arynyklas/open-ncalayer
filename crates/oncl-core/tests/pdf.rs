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
