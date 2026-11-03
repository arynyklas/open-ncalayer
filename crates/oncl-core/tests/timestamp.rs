#[path = "support/i01.rs"]
mod fixture;
use fixture::{NOW, SignedFixtures, Status};
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationContext, OperationPolicy,
    StampRequest, StampVerifyRequest, TimestampReport,
};
use oncl_pki::{
    digest::HashState,
    io::Source,
    key::{AppliedState, HashAlg},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
    tsp::DocumentImprint,
    validation::{CheckStatus, Verdict},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
const DATA: &[u8] = b"I01 actual document; never transmitted to the timestamp authority";
#[derive(Default)]
struct Control {
    cancel: AtomicBool,
}
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.cancel.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
fn engine(fixture: &Arc<SignedFixtures>, trusted: bool) -> Engine {
    Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(fixture.services(trusted)),
    )
    .unwrap()
}
fn begin(engine: &Engine, action: Action) -> OperationContext {
    engine
        .begin(
            ExecutionGrant::new([action]),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap()
}
fn token(fixture: &SignedFixtures) -> Vec<u8> {
    let mut spec = fixture.spec();
    spec.check_skew = None;
    oncl_pki::tsp::request(&spec, &HashAlg::Sha256.digest(DATA), fixture)
        .unwrap()
        .token
}
fn verify(
    engine: &Engine,
    token: &[u8],
    data: Option<&[u8]>,
    request: &StampVerifyRequest,
) -> TimestampReport {
    let mut ctx = begin(engine, Action::VerifyStamp);
    let mut token = token;
    let mut data = data;
    let source = data.as_mut().map(|data| {
        let length = data.len() as u64;
        Source::sequential(data, Some(length))
    });
    engine
        .verify_stamp(
            request,
            Source::sequential(&mut token, None),
            source,
            &mut ctx,
        )
        .unwrap()
}
#[test]
fn wrong_imprint_or_untrusted_tsa() {
    let fixture = SignedFixtures::new("http://127.0.0.1:19001", NOW, Status::Good);
    let token = token(&fixture);
    let trusted = engine(&fixture, true);
    let report = verify(&trusted, &token, Some(DATA), &StampVerifyRequest::new());
    assert_eq!(report.verdict(), Verdict::Valid);
    assert_eq!(report.facts().imprint(), DocumentImprint::Matched);
    assert_eq!(report.facts().tsa_policy().to_string(), "1.2.3.19.1");
    assert_eq!(report.facts().nonce(), Some(&[0x19, 1, 0xff][..]));
    assert_eq!(report.facts().gen_time(), NOW);
    assert_eq!(report.facts().checked_at(), NOW);
    assert_eq!(report.facts().revocation(), CheckStatus::Passed);
    assert_eq!(report.bytes_in(), (token.len() + DATA.len()) as u64);
    drop(report);
    let changed = verify(
        &trusted,
        &token,
        Some(b"altered actual document"),
        &StampVerifyRequest::new(),
    );
    assert_eq!(changed.verdict(), Verdict::Invalid);
    assert_eq!(changed.facts().imprint(), DocumentImprint::Mismatched);
    drop(changed);
    let untrusted = engine(&fixture, false);
    let report = verify(&untrusted, &token, Some(DATA), &StampVerifyRequest::new());
    assert_eq!(report.verdict(), Verdict::Invalid);
    assert_eq!(report.facts().chain(), CheckStatus::Failed);
}
#[test]
fn absent_data_is_not_a_matched_or_viewed_document() {
    let fixture = SignedFixtures::new("http://127.0.0.1:19002", NOW, Status::Good);
    let token = token(&fixture);
    let engine = engine(&fixture, true);
    let report = verify(&engine, &token, None, &StampVerifyRequest::new());
    assert_eq!(report.verdict(), Verdict::Indeterminate);
    assert_eq!(report.facts().imprint(), DocumentImprint::NotProvided);
    assert_eq!(report.facts().signature(), CheckStatus::Passed);
    assert_eq!(report.facts().chain(), CheckStatus::Passed);
    assert_eq!(report.facts().revocation(), CheckStatus::Passed);
}
#[test]
fn same_length_wrong_algorithm_nonce_policy_and_age_are_rejected() {
    let fixture = SignedFixtures::new(
        "http://127.0.0.1:19003",
        NOW - time::Duration::SECOND,
        Status::Good,
    );
    let token = token(&fixture);
    let engine = engine(&fixture, true);
    for request in [
        StampVerifyRequest::new().with_algorithm(HashAlg::Streebog256),
        StampVerifyRequest::new().with_nonce(vec![1]),
        StampVerifyRequest::new().with_policy(der::asn1::ObjectIdentifier::new_unwrap("1.2.3.9")),
        StampVerifyRequest::new().with_maximum_age(std::time::Duration::ZERO),
    ] {
        let report = verify(&engine, &token, Some(DATA), &request);
        assert_eq!(report.verdict(), Verdict::Invalid);
        assert_eq!(report.facts().expectations(), CheckStatus::Failed);
    }
}
#[test]
fn actual_token_signature_tamper_is_invalid_not_transport_failure() {
    let fixture = SignedFixtures::new("http://127.0.0.1:19004", NOW, Status::Good);
    let mut token = token(&fixture);
    *token.last_mut().unwrap() ^= 1;
    let report = verify(
        &engine(&fixture, true),
        &token,
        Some(DATA),
        &StampVerifyRequest::new(),
    );
    assert_eq!(report.verdict(), Verdict::Invalid);
    assert_eq!(report.facts().signature(), CheckStatus::Failed);
}
#[test]
fn current_revocation_and_freshness_are_evaluated_at_real_proof_time() {
    let proven = NOW - time::Duration::MINUTE;
    for (status, expected, check) in [
        (
            Status::Revoked(proven - time::Duration::SECOND),
            Verdict::Invalid,
            CheckStatus::Failed,
        ),
        (
            Status::Revoked(proven + time::Duration::SECOND),
            Verdict::Valid,
            CheckStatus::Passed,
        ),
        (
            Status::Stale,
            Verdict::Indeterminate,
            CheckStatus::Unavailable,
        ),
    ] {
        let fixture = SignedFixtures::new("http://127.0.0.1:19005", proven, status);
        let token = token(&fixture);
        let engine = engine(&fixture, true);
        let report = verify(&engine, &token, Some(DATA), &StampVerifyRequest::new());
        assert_eq!(report.verdict(), expected);
        assert_eq!(report.facts().revocation(), check);
        assert_eq!(report.facts().gen_time(), proven);
        assert_eq!(report.facts().checked_at(), NOW);
    }
}
#[test]
fn future_and_outside_certificate_validity_tokens_do_not_establish_proof() {
    for at in [
        NOW + time::Duration::SECOND,
        time::macros::datetime!(1990-01-01 00:00 UTC),
    ] {
        let fixture = SignedFixtures::new("http://127.0.0.1:19006", at, Status::Good);
        let mut spec = fixture.spec();
        spec.check_skew = None;
        let token = oncl_pki::tsp::request(&spec, &HashAlg::Sha256.digest(DATA), fixture.as_ref())
            .unwrap()
            .token;
        let report = verify(
            &engine(&fixture, true),
            &token,
            Some(DATA),
            &StampVerifyRequest::new(),
        );
        assert_eq!(report.verdict(), Verdict::Invalid);
    }
}
#[test]
fn streaming_stamp_needs_no_local_key_provider_guard_or_temp_store() {
    let fixture = SignedFixtures::new("http://127.0.0.1:19007", NOW, Status::Good);
    let engine = engine(&fixture, true);
    let mut ctx = begin(&engine, Action::Stamp);
    let mut data = DATA;
    let mut output = Vec::new();
    let report = engine
        .stamp(
            &StampRequest::new(fixture.spec()),
            Source::sequential(&mut data, None),
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict(), Verdict::Valid);
    assert_eq!(report.facts().token(), output);
    assert_eq!(report.bytes_in(), DATA.len() as u64);
    assert_eq!(report.bytes_out(), output.len() as u64);
    let requests = fixture.tsa.requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].windows(DATA.len()).any(|window| window == DATA));
}
#[test]
fn stamp_and_verify_grants_and_missing_services_are_pre_intake() {
    let fixture = SignedFixtures::new("http://127.0.0.1:19008", NOW, Status::Good);
    for action in [Action::Sign, Action::Hash, Action::Verify] {
        let engine = engine(&fixture, true);
        let mut ctx = begin(&engine, action);
        let mut data = DATA;
        let error = engine
            .stamp(
                &StampRequest::new(fixture.spec()),
                Source::sequential(&mut data, None),
                &mut Vec::new(),
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert_eq!(data, DATA);
        let error = engine
            .verify_stamp(
                &StampVerifyRequest::new(),
                Source::sequential(&mut data, None),
                None,
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert_eq!(data, DATA);
    }
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = begin(&engine, Action::VerifyStamp);
    let mut data = DATA;
    assert_eq!(
        engine
            .verify_stamp(
                &StampVerifyRequest::new(),
                Source::sequential(&mut data, None),
                None,
                &mut ctx
            )
            .unwrap_err()
            .code(),
        ErrorCode::MissingValidationServices
    );
    assert_eq!(data, DATA);
}
#[test]
fn token_input_output_metadata_and_lifetime_are_charged_separately() {
    let fixture = SignedFixtures::new("http://127.0.0.1:19009", NOW, Status::Good);
    let token = token(&fixture);
    let limits = ResourceLimits {
        output_bytes: 0,
        ..ResourceLimits::default()
    };
    let engine = Engine::new(
        EngineServices::hash_only(limits.clone()).with_validation(fixture.services(true)),
    )
    .unwrap();
    let mut ctx = begin(&engine, Action::VerifyStamp);
    let mut bytes = token.as_slice();
    let mut data = DATA;
    let report = engine
        .verify_stamp(
            &StampVerifyRequest::new(),
            Source::sequential(&mut bytes, None),
            Some(Source::sequential(&mut data, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.bytes_out(), 0);
    drop(report);
    drop(ctx);
    let mut ctx = begin(&engine, Action::Stamp);
    let mut data = DATA;
    let mut output = Vec::new();
    let error = engine
        .stamp(
            &StampRequest::new(fixture.spec()),
            Source::sequential(&mut data, None),
            &mut output,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::OutputLimit);
    assert!(output.is_empty());
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    let shared = Arc::new(SharedBudget::new(ResourceLimits::default()).unwrap());
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_shared_budget(shared)
            .with_validation(fixture.services(true)),
    )
    .unwrap();
    let report = verify(&engine, &token, Some(DATA), &StampVerifyRequest::new());
    assert_eq!(
        engine
            .begin(
                ExecutionGrant::new([Action::VerifyStamp]),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    drop(report);
    drop(begin(&engine, Action::VerifyStamp));
}
#[test]
fn actual_digest_tag_not_only_length_is_checked_by_timestamp_adapter() {
    let fixture = SignedFixtures::new("http://127.0.0.1:19010", NOW, Status::Good);
    let token = token(&fixture);
    let budget = Arc::new(SharedBudget::new(ResourceLimits::default()).unwrap());
    let scope = budget
        .begin(ResourceLimits::default(), Arc::new(Control::default()))
        .unwrap();
    let anchors = oncl_pki::pkix::CaSet::new(vec![fixture.root.clone()]);
    let context = oncl_pki::validation::ValidationContext {
        policy: oncl_pki::validation::ValidationPolicy::StrictOnline,
        now: NOW,
        anchors: &anchors,
        intermediates: &[],
        http: fixture.as_ref(),
    };
    let mut report = oncl_pki::tsp::validate_document_token(&token, &context, &scope).unwrap();
    let mut wrong = HashState::new(HashAlg::Streebog256);
    wrong.update(DATA);
    report.check_document(&wrong.finish());
    assert_eq!(report.imprint(), DocumentImprint::Mismatched);
    assert_eq!(report.verdict(), Verdict::Invalid);
}

#[test]
fn host_intermediates_are_candidates_but_never_promoted_to_anchors() {
    use oncl_pki::{
        crl::MockCrl,
        http::{HttpTransport, RouteTransport},
        ocsp::MockOcsp,
        pkix::CaSet,
        testing::{TestCertSpec, issue_cert},
        tsp::MockTsa,
        validation::NetworkPolicy,
    };
    let root = fixture::entry("root-gost2015.key");
    let intermediate = fixture::entry("inter-gost2015.key");
    let mut tsa = fixture::entry("tsa-gost2015");
    let mut spec = TestCertSpec::from_cert(&tsa.cert);
    spec.extensions.retain(|extension| {
        !matches!(
            extension.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions.extend(
        TestCertSpec::from_cert(&fixture::entry("inter-user-gost2015-sign").cert)
            .extensions
            .into_iter()
            .filter(|extension| {
                matches!(
                    extension.extn_id.to_string().as_str(),
                    "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                )
            }),
    );
    tsa.cert = issue_cert(&intermediate, spec);
    let http = MockTsa::new(tsa).with_gen_time(NOW);
    let f = SignedFixtures::new("http://127.0.0.1:19011", NOW, Status::Good);
    let mut spec = f.spec();
    spec.check_skew = None;
    let token = oncl_pki::tsp::request(&spec, &HashAlg::Sha256.digest(DATA), &http)
        .unwrap()
        .token;
    let routes: Arc<dyn HttpTransport> = Arc::new(RouteTransport::new(vec![
        (
            "http://ocsp.synthetic.test".into(),
            Arc::new(MockOcsp::new(fixture::entry("ocsp-gost2015")).with_now(NOW)),
        ),
        (
            "http://crl.synthetic.test/root-gost2015.crl".into(),
            Arc::new(
                MockCrl::new(root.clone())
                    .with_this_update(NOW - time::Duration::MINUTE)
                    .next_update(Some(NOW + time::Duration::HOUR)),
            ),
        ),
        (
            "http://crl.synthetic.test/inter-gost2015.crl".into(),
            Arc::new(
                MockCrl::new(intermediate.clone())
                    .with_this_update(NOW - time::Duration::MINUTE)
                    .next_update(Some(NOW + time::Duration::HOUR)),
            ),
        ),
    ]));
    for trusted in [true, false] {
        let services = oncl_core::ValidationServices::new(
            CaSet::new(if trusted {
                vec![root.cert.clone()]
            } else {
                vec![]
            }),
            vec![intermediate.cert.clone()],
            routes.clone(),
            NetworkPolicy::only_endpoints([
                "http://ocsp.synthetic.test",
                "http://crl.synthetic.test",
            ])
            .unwrap(),
            Arc::new(|| NOW),
        );
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default()).with_validation(services),
        )
        .unwrap();
        let report = verify(&engine, &token, Some(DATA), &StampVerifyRequest::new());
        assert_eq!(
            report.verdict(),
            if trusted {
                Verdict::Valid
            } else {
                Verdict::Invalid
            }
        );
    }
}
#[test]
fn required_tsa_eku_and_validity_at_proven_time_are_real_checks() {
    use oncl_pki::tsp::MockTamper;
    let proven = NOW - time::Duration::MINUTE;
    for (eku, expires, expected, validity) in [
        (false, None, Verdict::Invalid, CheckStatus::Passed),
        (
            true,
            Some(proven - time::Duration::SECOND),
            Verdict::Invalid,
            CheckStatus::Failed,
        ),
        (
            true,
            Some(proven + time::Duration::SECOND),
            Verdict::Valid,
            CheckStatus::Passed,
        ),
    ] {
        let f = SignedFixtures::variant(
            "http://127.0.0.1:19012",
            proven,
            Status::Good,
            eku,
            expires,
            MockTamper::None,
        );
        let mut spec = f.spec();
        spec.check_skew = None;
        spec.require_tsa_eku = false;
        let token = oncl_pki::tsp::request(&spec, &HashAlg::Sha256.digest(DATA), f.as_ref())
            .unwrap()
            .token;
        let report = verify(
            &engine(&f, true),
            &token,
            Some(DATA),
            &StampVerifyRequest::new(),
        );
        assert_eq!(report.verdict(), expected);
        assert_eq!(report.facts().validity(), validity);
        assert_eq!(
            report.facts().eku(),
            if eku {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            }
        );
    }
}
#[test]
fn acquisition_nonce_mismatch_preserves_original_tsp_cause_without_output() {
    let f = SignedFixtures::variant(
        "http://127.0.0.1:19013",
        NOW,
        Status::Good,
        true,
        None,
        oncl_pki::tsp::MockTamper::Nonce,
    );
    let engine = engine(&f, true);
    let mut ctx = begin(&engine, Action::Stamp);
    let mut data = DATA;
    let mut output = Vec::new();
    let error = engine
        .stamp(
            &StampRequest::new(f.spec()),
            Source::sequential(&mut data, None),
            &mut output,
            &mut ctx,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        oncl_core::OperationError::Timestamp(oncl_pki::tsp::TspError::NonceMismatch)
    ));
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(output.is_empty());
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
}
struct InterruptRead {
    control: Arc<Control>,
    delay: bool,
}
impl std::io::Read for InterruptRead {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = output.len().min(DATA.len());
        output[..count].copy_from_slice(&DATA[..count]);
        if self.delay {
            std::thread::sleep(std::time::Duration::from_millis(150));
        } else {
            self.control.cancel.store(true, Ordering::SeqCst);
        }
        Ok(count)
    }
}
#[test]
fn stamp_preserves_post_read_cancel_and_monotonic_deadline_without_issuance() {
    for delay in [false, true] {
        let f = SignedFixtures::new("http://127.0.0.1:19014", NOW, Status::Good);
        let limits = ResourceLimits {
            operation_timeout: std::time::Duration::from_millis(100),
            ..ResourceLimits::default()
        };
        let engine =
            Engine::new(EngineServices::hash_only(limits).with_validation(f.services(true)))
                .unwrap();
        let control = Arc::new(Control::default());
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Stamp]),
                OperationPolicy::strict_online(),
                control.clone(),
            )
            .unwrap();
        let mut input = InterruptRead { control, delay };
        let mut output = Vec::new();
        let error = engine
            .stamp(
                &StampRequest::new(f.spec()),
                Source::sequential(&mut input, None),
                &mut output,
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(
            error.code(),
            if delay {
                ErrorCode::DeadlineExceeded
            } else {
                ErrorCode::Cancelled
            }
        );
        assert_eq!(ctx.resources().progress().bytes_in, DATA.len() as u64);
        assert!(output.is_empty());
        assert!(f.tsa.requests().is_empty());
    }
}
#[test]
fn live_http_response_decode_admission_restores_original_resource_failure() {
    for (memory, metadata, expected) in [
        (1_073_741_824, 100_000, ErrorCode::MetadataLimit),
        (100_000, 67_108_864, ErrorCode::MemoryLimit),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let f = SignedFixtures::new(&origin, NOW, Status::Good);
        let server = fixture::Server::start(listener, f.clone());
        let transport = Arc::new(oncl_pki::http::UreqTransport::with_proxy(
            oncl_pki::http::ProxySetting::None,
        ));
        let limits = ResourceLimits {
            memory_bytes: memory,
            metadata_bytes: metadata,
            ..ResourceLimits::default()
        };
        let engine = Engine::new(
            EngineServices::hash_only(limits).with_validation(f.services_with(true, transport)),
        )
        .unwrap();
        let mut ctx = begin(&engine, Action::Stamp);
        let mut input = DATA;
        let mut output = Vec::new();
        let error = engine
            .stamp(
                &StampRequest::new(f.spec()),
                Source::sequential(&mut input, None),
                &mut output,
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.code(), expected);
        assert!(output.is_empty());
        assert_eq!(f.requests.load(Ordering::SeqCst), 1); // actual HTTP body, not a fabricated parser failure
        server.finish().unwrap();
    }
}
#[test]
fn authentic_document_snapshot_stamp_counts_source_once_and_token_as_output_only() {
    use oncl_pki::io::{FrozenInput, Region, TemporaryStore};
    let f = SignedFixtures::new("http://127.0.0.1:19015", NOW, Status::Good);
    let engine = engine(&f, true);
    let mut ctx = begin(&engine, Action::Stamp);
    let scratch = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(scratch.path()).unwrap();
    let mut input = DATA;
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut input, None),
        &store,
        ctx.resources(),
    )
    .unwrap();
    let mut reader = frozen
        .reader(
            &[Region {
                offset: 0,
                len: DATA.len() as u64,
            }],
            ctx.resources(),
        )
        .unwrap();
    let mut output = Vec::new();
    let report = engine
        .stamp(
            &StampRequest::new(f.spec()),
            reader.source(),
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict(), Verdict::Valid);
    assert_eq!(report.bytes_in(), 0);
    assert_eq!(ctx.resources().progress().bytes_in, DATA.len() as u64);
    assert_eq!(ctx.resources().progress().bytes_out, output.len() as u64);
}

#[test]
fn refused_real_tsa_connection_is_io_and_retains_original_transport_cause() {
    use oncl_pki::http::{HttpErrorKind, ProxySetting, UreqTransport};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let fixture = SignedFixtures::new(&origin, NOW, Status::Good);
    let transport = Arc::new(UreqTransport::with_proxy(ProxySetting::None));
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits::default())
            .with_validation(fixture.services_with(true, transport)),
    )
    .unwrap();
    drop(listener); // The actual pinned destination refuses TCP, not a fake parser.
    let mut ctx = begin(&engine, Action::Stamp);
    let mut data = DATA;
    let mut output = Vec::new();
    let error = engine
        .stamp(
            &StampRequest::new(fixture.spec()),
            Source::sequential(&mut data, None),
            &mut output,
            &mut ctx,
        )
        .unwrap_err();
    assert!(
        matches!(&error, oncl_core::OperationError::Timestamp(oncl_pki::tsp::TspError::Http(cause))
        if matches!(cause.kind, HttpErrorKind::Connect | HttpErrorKind::Timeout) && !cause.message.is_empty()),
        "{error:?}"
    );
    assert_eq!(error.code(), ErrorCode::Io);
    let cause = match &error {
        oncl_core::OperationError::Timestamp(oncl_pki::tsp::TspError::Http(cause)) => cause,
        _ => unreachable!("the typed transport variant was checked"),
    };
    let nested = std::error::Error::source(&error)
        .and_then(std::error::Error::source)
        .and_then(|source| source.downcast_ref::<oncl_pki::http::HttpError>());
    assert_eq!(nested, Some(cause));
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(output.is_empty());
    let bridge: oncl_pki::key::KeyError = error.into();
    assert_eq!(ErrorCode::from(&bridge), ErrorCode::Io);
}

#[test]
fn timestamp_protocol_mismatches_remain_invalid_input_with_distinct_causes() {
    use oncl_pki::tsp::TspError;
    for cause in [
        TspError::NonceMismatch,
        TspError::PolicyMismatch,
        TspError::ImprintMismatch,
        TspError::Malformed("invalid TimeStampResp".into()),
    ] {
        let error = oncl_core::OperationError::Timestamp(cause);
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(std::error::Error::source(&error).is_some());
    }
}

struct ReplyClock {
    fixture: Arc<SignedFixtures>,
    now: Arc<std::sync::Mutex<time::OffsetDateTime>>,
    after_reply: time::OffsetDateTime,
    wrong_imprint: bool,
}
impl oncl_pki::http::HttpTransport for ReplyClock {
    fn send(
        &self,
        request: &oncl_pki::http::HttpRequest<'_>,
    ) -> Result<oncl_pki::http::HttpReply, oncl_pki::http::HttpError> {
        let mut body;
        let actual = if self.wrong_imprint && request.url.ends_with("/tsa") {
            body = request.body.to_vec();
            let digest = HashAlg::Sha256.digest(DATA);
            let offset = body
                .windows(digest.len())
                .position(|bytes| bytes == digest)
                .unwrap();
            body[offset] ^= 1;
            oncl_pki::http::HttpRequest {
                body: &body,
                ..*request
            }
        } else {
            *request
        };
        let reply = oncl_pki::http::HttpTransport::send(self.fixture.as_ref(), &actual)?;
        if request.url.ends_with("/tsa") {
            *self.now.lock().unwrap() = self.after_reply;
        }
        Ok(reply)
    }
}
fn clocked_engine(
    fixture: &Arc<SignedFixtures>,
    trusted: bool,
    http: Arc<dyn oncl_pki::http::HttpTransport>,
    clock: Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>,
) -> Engine {
    let services = oncl_core::ValidationServices::new(
        oncl_pki::pkix::CaSet::new(if trusted {
            vec![fixture.root.clone()]
        } else {
            vec![]
        }),
        vec![],
        http,
        oncl_pki::validation::NetworkPolicy::only_endpoints([&fixture.origin]).unwrap(),
        clock,
    );
    Engine::new(EngineServices::hash_only(ResourceLimits::default()).with_validation(services))
        .unwrap()
}
struct ClockAfterRead<'a> {
    input: &'a [u8],
    done: Arc<AtomicBool>,
    now: Arc<std::sync::Mutex<time::OffsetDateTime>>,
    after_read: time::OffsetDateTime,
}
impl std::io::Read for ClockAfterRead<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = std::io::Read::read(&mut self.input, output)?;
        if count == 0 {
            *self.now.lock().unwrap() = self.after_read;
            self.done.store(true, Ordering::SeqCst);
        }
        Ok(count)
    }
}
#[test]
fn acquisition_samples_host_after_actual_hash_and_signed_reply() {
    let issued = NOW + time::Duration::SECOND;
    let checked = NOW + time::Duration::seconds(2);
    let f = SignedFixtures::new("http://127.0.0.1:19015", issued, Status::Good);
    let now = Arc::new(std::sync::Mutex::new(NOW - time::Duration::MINUTE));
    let done = Arc::new(AtomicBool::new(false));
    let http = Arc::new(ReplyClock {
        fixture: f.clone(),
        now: now.clone(),
        after_reply: checked,
        wrong_imprint: false,
    });
    let clock = {
        let now = now.clone();
        let done = done.clone();
        Arc::new(move || {
            assert!(
                done.load(Ordering::SeqCst),
                "host time must follow the whole document hash"
            );
            *now.lock().unwrap()
        })
    };
    let engine = clocked_engine(&f, true, http, clock);
    let mut input = ClockAfterRead {
        input: DATA,
        done,
        now,
        after_read: NOW,
    };
    let mut ctx = begin(&engine, Action::Stamp);
    let mut output = Vec::new();
    let mut spec = f.spec();
    spec.nonce = oncl_pki::http::NonceSpec::Random(16);
    let report = engine
        .stamp(
            &StampRequest::new(spec),
            Source::sequential(&mut input, None),
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict(), Verdict::Valid);
    assert_eq!(report.facts().gen_time(), issued);
    assert_eq!(report.facts().checked_at(), checked);
    assert_eq!(report.facts().imprint(), DocumentImprint::Matched);
    assert_eq!(report.facts().token(), output);
    assert_eq!(f.tsa.requests().len(), 1);
}
#[test]
fn post_reply_host_clock_does_not_relax_timestamp_rejection_checks() {
    use oncl_pki::tsp::{MockTamper, TspError};
    let checked = NOW + time::Duration::seconds(2);
    for (issued, started, post, status, trusted, tamper, expected) in [
        (
            checked + time::Duration::SECOND,
            NOW,
            checked,
            Status::Good,
            true,
            MockTamper::None,
            "future",
        ),
        (
            NOW,
            checked,
            NOW,
            Status::Good,
            true,
            MockTamper::None,
            "backwards",
        ),
        (
            NOW + time::Duration::SECOND,
            NOW,
            checked,
            Status::Stale,
            true,
            MockTamper::None,
            "validation",
        ),
        (
            NOW + time::Duration::SECOND,
            NOW,
            checked,
            Status::Good,
            false,
            MockTamper::None,
            "validation",
        ),
        (
            NOW + time::Duration::SECOND,
            NOW,
            checked,
            Status::Good,
            true,
            MockTamper::Nonce,
            "nonce",
        ),
        (
            NOW + time::Duration::SECOND,
            NOW,
            checked,
            Status::Good,
            true,
            MockTamper::None,
            "imprint",
        ),
    ] {
        let f =
            SignedFixtures::variant("http://127.0.0.1:19016", issued, status, true, None, tamper);
        let now = Arc::new(std::sync::Mutex::new(started));
        let http = Arc::new(ReplyClock {
            fixture: f.clone(),
            now: now.clone(),
            after_reply: post,
            wrong_imprint: expected == "imprint",
        });
        let clock = Arc::new(move || *now.lock().unwrap());
        let engine = clocked_engine(&f, trusted, http, clock);
        let mut ctx = begin(&engine, Action::Stamp);
        let mut input = DATA;
        let mut output = Vec::new();
        let error = engine
            .stamp(
                &StampRequest::new(f.spec()),
                Source::sequential(&mut input, None),
                &mut output,
                &mut ctx,
            )
            .unwrap_err();
        match expected {
            "future" | "backwards" => assert!(matches!(
                error,
                oncl_core::OperationError::Timestamp(TspError::ClockSkew)
            )),
            "nonce" => assert!(matches!(
                error,
                oncl_core::OperationError::Timestamp(TspError::NonceMismatch)
            )),
            "imprint" => assert!(matches!(
                error,
                oncl_core::OperationError::Timestamp(TspError::ImprintMismatch)
            )),
            _ => assert!(matches!(
                error,
                oncl_core::OperationError::ValidationRequired
            )),
        }
        assert!(output.is_empty());
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
    }
}
#[test]
fn verification_hashes_actual_document_before_current_host_validation() {
    let issued = NOW + time::Duration::SECOND;
    let checked = NOW + time::Duration::seconds(2);
    let f = SignedFixtures::new("http://127.0.0.1:19017", issued, Status::Good);
    let encoded = token(&f);
    let now = Arc::new(std::sync::Mutex::new(NOW));
    let done = Arc::new(AtomicBool::new(false));
    let late_samples = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let clock = {
        let now = now.clone();
        let done = done.clone();
        let late_samples = late_samples.clone();
        Arc::new(move || {
            if done.load(Ordering::SeqCst) {
                late_samples.fetch_add(1, Ordering::SeqCst);
            }
            *now.lock().unwrap()
        })
    };
    let engine = clocked_engine(&f, true, f.clone(), clock);
    let mut input = ClockAfterRead {
        input: DATA,
        done,
        now,
        after_read: checked,
    };
    let mut ctx = begin(&engine, Action::VerifyStamp);
    let mut encoded = encoded.as_slice();
    let report = engine
        .verify_stamp(
            &StampVerifyRequest::new(),
            Source::sequential(&mut encoded, None),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict(), Verdict::Valid);
    assert_eq!(report.facts().gen_time(), issued);
    assert_eq!(report.facts().checked_at(), checked);
    assert_eq!(report.facts().imprint(), DocumentImprint::Matched);
    assert_eq!(late_samples.load(Ordering::SeqCst), 1);
    assert_eq!(
        report.bytes_in(),
        (report.facts().token().len() + DATA.len()) as u64
    );
}

#[test]
fn final_document_hash_time_does_not_reuse_pre_hash_tsa_status_freshness() {
    let f = SignedFixtures::new("http://127.0.0.1:19018", NOW, Status::Good);
    let encoded = token(&f);
    let checked = NOW + time::Duration::hours(2);
    let now = Arc::new(std::sync::Mutex::new(NOW));
    let clock = {
        let now = now.clone();
        Arc::new(move || *now.lock().unwrap())
    };
    let engine = clocked_engine(&f, true, f.clone(), clock);
    let mut input = ClockAfterRead {
        input: DATA,
        done: Arc::new(AtomicBool::new(false)),
        now,
        after_read: checked,
    };
    let mut ctx = begin(&engine, Action::VerifyStamp);
    let mut encoded = encoded.as_slice();
    let report = engine
        .verify_stamp(
            &StampVerifyRequest::new(),
            Source::sequential(&mut encoded, None),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict(), Verdict::Indeterminate);
    assert_eq!(report.facts().revocation(), CheckStatus::Unavailable);
    assert_eq!(report.facts().gen_time(), NOW);
    assert_eq!(report.facts().checked_at(), checked);
    assert_eq!(report.facts().imprint(), DocumentImprint::Matched);
}
#[test]
fn data_read_failure_precedes_timestamp_status_network_and_preserves_io_cause() {
    struct FailedData;
    impl std::io::Read for FailedData {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "actual document read",
            ))
        }
    }
    let f = SignedFixtures::new("http://127.0.0.1:19019", NOW, Status::Good);
    let encoded = token(&f);
    let requests_before = f.requests.load(Ordering::SeqCst);
    let engine = engine(&f, true);
    let mut ctx = begin(&engine, Action::VerifyStamp);
    let mut encoded = encoded.as_slice();
    let error = engine
        .verify_stamp(
            &StampVerifyRequest::new(),
            Source::sequential(&mut encoded, None),
            Some(Source::sequential(&mut FailedData, None)),
            &mut ctx,
        )
        .unwrap_err();
    assert!(matches!(
        &error,
        oncl_core::OperationError::Processing(ProcessingError::Io(cause))
            if cause.kind() == std::io::ErrorKind::BrokenPipe
    ));
    assert_eq!(error.code(), ErrorCode::Io);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(f.requests.load(Ordering::SeqCst), requests_before);
}
#[test]
fn static_document_acquisition_retains_explicit_as_of_semantics() {
    let f = SignedFixtures::new("http://127.0.0.1:19020", NOW, Status::Good);
    let mut hash = HashState::new(HashAlg::Sha256);
    hash.update(DATA);
    let anchors = oncl_pki::pkix::CaSet::new(vec![f.root.clone()]);
    let checked = NOW + time::Duration::seconds(3);
    let validation = oncl_pki::validation::ValidationContext {
        policy: oncl_pki::validation::ValidationPolicy::StrictOnline,
        now: checked,
        anchors: &anchors,
        intermediates: &[],
        http: f.as_ref(),
    };
    let limits = ResourceLimits::default();
    let scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control::default()))
        .unwrap();
    let report =
        oncl_pki::tsp::acquire_document_timestamp(&f.spec(), &hash.finish(), &validation, &scope)
            .unwrap();
    assert_eq!(report.verdict(), Verdict::Valid);
    assert_eq!(report.gen_time(), NOW);
    assert_eq!(report.checked_at(), checked);
    assert_eq!(report.imprint(), DocumentImprint::Matched);
}

#[test]
fn backwards_final_host_clock_cannot_validate_an_otherwise_historical_token() {
    let f = SignedFixtures::new(
        "http://127.0.0.1:19021",
        NOW - time::Duration::MINUTE,
        Status::Good,
    );
    let encoded = token(&f);
    let now = Arc::new(std::sync::Mutex::new(NOW));
    let clock = {
        let now = now.clone();
        Arc::new(move || *now.lock().unwrap())
    };
    let engine = clocked_engine(&f, true, f.clone(), clock);
    let mut input = ClockAfterRead {
        input: DATA,
        done: Arc::new(AtomicBool::new(false)),
        now,
        after_read: NOW - time::Duration::SECOND,
    };
    let mut ctx = begin(&engine, Action::VerifyStamp);
    let mut encoded = encoded.as_slice();
    let error = engine
        .verify_stamp(
            &StampVerifyRequest::new(),
            Source::sequential(&mut encoded, None),
            Some(Source::sequential(&mut input, None)),
            &mut ctx,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        oncl_core::OperationError::Timestamp(oncl_pki::tsp::TspError::ClockSkew)
    ));
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
}
