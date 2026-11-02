//! C01 tests-first: functioning CMS-only Core methods, never fake format dispatch.
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationContext, OperationPolicy,
    ValidationServices, VerifyRequest,
};
use oncl_pki::cms::{self, AttrSpec, CertSpec, CoSign, Content, SignSpec};
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::io::Source;
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::load;
use oncl_pki::pkix::CaSet;
use oncl_pki::resource::{
    OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget,
};
use oncl_pki::validation::{CheckStatus, NetworkPolicy, TimeBasis, ValidationPolicy, Verdict};
use oncl_testkit::{read, synthetic};
use std::io::{self, Cursor, Read};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use time::{OffsetDateTime, macros::datetime};

const NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);
const CLAIM: OffsetDateTime = datetime!(2025-06-01 10:00 UTC);
const DATA: &[u8] = b"C01 verified document, not an extraction verdict";
struct NoNetwork;
impl HttpTransport for NoNetwork {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline fixture"))
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
fn certificate(path: &std::path::Path) -> oncl_pki::cert::Certificate {
    oncl_pki::cert::parse(&read(path)).unwrap()
}
fn services() -> ValidationServices {
    let fixture = synthetic("user-rsa-sign");
    ValidationServices::new(
        CaSet::new(vec![certificate(&fixture.root)]),
        vec![certificate(&fixture.issuer)],
        Arc::new(NoNetwork),
        NetworkPolicy::only_endpoints(Vec::<String>::new()).unwrap(),
        Arc::new(|| NOW),
    )
}
fn engine() -> Engine {
    Engine::new(EngineServices::hash_only(ResourceLimits::default()).with_validation(services()))
        .unwrap()
}
fn context(engine: &Engine, actions: &[Action], policy: OperationPolicy) -> OperationContext {
    engine
        .begin(
            ExecutionGrant::new(actions.iter().copied()),
            policy,
            Arc::new(Control::default()),
        )
        .unwrap()
}
fn signed(attached: bool) -> Vec<u8> {
    let fixture = synthetic("user-rsa-sign");
    let key = load(&read(&fixture.path), &fixture.password)
        .unwrap()
        .remove(0);
    cms::sign_spec(
        &key,
        &[certificate(&fixture.issuer)],
        &SignSpec {
            content: Content::Data(DATA),
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
struct NoRead;
impl Read for NoRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("must reject before consuming input")
    }
}

#[test]
fn source_verify_reuses_full_validation_and_host_policy_for_every_report() {
    let input = signed(true);
    for policy in [
        OperationPolicy::strict_online(),
        OperationPolicy::offline_report(),
        OperationPolicy::ncalayer_compatibility(),
    ] {
        let engine = engine();
        let mut old = context(&engine, &[Action::Validate], policy.clone());
        let expected = engine.validate_cms(&input, None, &mut old).unwrap();
        drop(old);
        // The old report owns admission until its scoped signer storage drops.
        let expected_verdict = expected.verdict;
        let expected_checks = (
            expected.signers[0].signature,
            expected.signers[0].chain,
            expected.signers[0].validity,
            expected.signers[0].revocation,
        );
        drop(expected);
        let mut ctx = context(&engine, &[Action::Verify], policy.clone());
        let id = ctx.id();
        let result = engine
            .verify(
                &VerifyRequest::cms(),
                Source::sequential(&mut Cursor::new(&input), None),
                None,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(result.id, id);
        assert_eq!(result.policy, policy.validation);
        assert_eq!(result.checked_at, NOW);
        assert_eq!(result.signers.len(), 1);
        assert_eq!(result.verdict, expected_verdict);
        assert_eq!(
            (
                result.signers[0].signature,
                result.signers[0].chain,
                result.signers[0].validity,
                result.signers[0].revocation
            ),
            expected_checks
        );
        assert_eq!(result.signers[0].signature, CheckStatus::Passed);
        assert_eq!(result.signers[0].time_basis, TimeBasis::Current(NOW));
        assert_eq!(
            result.verdict,
            Verdict::Indeterminate,
            "unavailable status is not Valid, including compatibility presentation"
        );
    }
}

#[test]
fn detached_sources_are_verified_and_missing_data_is_not_valid() {
    let input = signed(false);
    let engine = engine();
    let mut ctx = context(
        &engine,
        &[Action::Verify],
        OperationPolicy::offline_report(),
    );
    let good = engine
        .verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(&input), None),
            Some(Source::sequential(&mut Cursor::new(DATA), None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(good.signers[0].signature, CheckStatus::Passed);
    drop(good);
    let missing = engine
        .verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(&input), None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_ne!(missing.verdict, Verdict::Valid);
    assert_eq!(missing.signers[0].signature, CheckStatus::Failed);
}

#[test]
fn verify_and_extract_require_distinct_grants_before_reading() {
    let engine = engine();
    let mut ctx = context(&engine, &[Action::Hash], OperationPolicy::offline_report());
    let error = engine
        .verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut NoRead, None),
            None,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    let error = engine
        .extract(Source::sequential(&mut NoRead, None), &mut vec![], &mut ctx)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    drop(ctx);
    let mut ctx = context(
        &engine,
        &[Action::Verify],
        OperationPolicy::offline_report(),
    );
    assert_eq!(
        engine
            .extract(Source::sequential(&mut NoRead, None), &mut vec![], &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
}

#[test]
fn verify_requires_host_validation_but_raw_extract_does_not() {
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = context(
        &engine,
        &[Action::Verify, Action::Extract],
        OperationPolicy::offline_report(),
    );
    assert_eq!(
        engine
            .verify(
                &VerifyRequest::cms(),
                Source::sequential(&mut NoRead, None),
                None,
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::MissingValidationServices
    );
    let input = signed(true);
    let mut output = vec![];
    let result = engine
        .extract(
            Source::sequential(&mut Cursor::new(input), None),
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(result.id, ctx.id());
    assert_eq!(result.bytes_written, DATA.len() as u64);
    assert_eq!(output, DATA);
    // ExtractionReport intentionally has no signature/validation verdict.
}

#[test]
fn foreign_context_and_cancellation_remain_typed_fatal_errors() {
    let a = engine();
    let b = engine();
    let mut ctx = context(
        &a,
        &[Action::Verify, Action::Extract],
        OperationPolicy::offline_report(),
    );
    assert_eq!(
        b.verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut NoRead, None),
            None,
            &mut ctx
        )
        .unwrap_err()
        .code(),
        ErrorCode::InvalidInput
    );
    assert_eq!(
        b.extract(Source::sequential(&mut NoRead, None), &mut vec![], &mut ctx)
            .unwrap_err()
            .code(),
        ErrorCode::InvalidInput
    );
    drop(ctx);
    let control = Arc::new(Control::default());
    let mut ctx = a
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::offline_report(),
            control.clone(),
        )
        .unwrap();
    control.0.store(true, Ordering::SeqCst);
    assert_eq!(
        a.verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut NoRead, None),
            None,
            &mut ctx
        )
        .unwrap_err()
        .code(),
        ErrorCode::Cancelled
    );
}

#[test]
fn disallowed_signer_algorithm_is_not_silently_verified() {
    let input = signed(true);
    let engine = engine();
    let mut policy = OperationPolicy::offline_report();
    policy.allowed_signature_algorithms = &[SigAlg::Gost2015_512];
    let mut ctx = context(&engine, &[Action::Verify], policy);
    let error = engine
        .verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(input), None),
            None,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsupportedAlgorithm);
}

#[test]
fn returned_scoped_signers_retain_global_admission_after_context_drop() {
    let limits = ResourceLimits::default();
    let shared = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let engine = Engine::new(
        EngineServices::hash_only(limits)
            .with_shared_budget(shared)
            .with_validation(services()),
    )
    .unwrap();
    let input = signed(true);
    let mut ctx = context(
        &engine,
        &[Action::Verify],
        OperationPolicy::offline_report(),
    );
    let report = engine
        .verify(
            &VerifyRequest::cms(),
            Source::sequential(&mut Cursor::new(input), None),
            None,
            &mut ctx,
        )
        .unwrap();
    drop(ctx);
    assert_eq!(
        engine
            .begin(
                ExecutionGrant::new([Action::Verify]),
                OperationPolicy::offline_report(),
                Arc::new(Control::default())
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    assert_eq!(report.policy, ValidationPolicy::OfflineReport);
    assert_eq!(report.signers[0].signature, CheckStatus::Passed);
    drop(report);
    let _next = context(
        &engine,
        &[Action::Verify],
        OperationPolicy::offline_report(),
    );
}
