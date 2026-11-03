//! Real Core batch + strict synthetic PKI + production durable guard, not a writer mock.
use super::support::{ActualKey, Control, MESSAGE};
use oncl_core::batch::{BatchItem, BatchOperation, BatchOutcome, BatchReport, BatchSummary};
use oncl_core::keys::{
    KeyId, KeyLease, KeyProvider, KeyRequest, KeySelector, KeyUseEvent, KeyUseGuard, KeyUseOutcome,
    KeyUseReceipt,
};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy, SignRequest, ValidationServices, VerifyRequest,
};
use oncl_pki::{
    io::{Source, TemporaryStore},
    key::{AppliedState, HashAlg, PublicKey, SigAlg, TokenSigner},
    pkcs12::KeyEntry,
    resource::ResourceLimits,
    validation::Verdict,
};
use oncl_server::audit::{AuditHealth, AuditLabel, DurableAuditGuard, FaultPoint};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex, atomic::Ordering},
};
const NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
fn raw(name: &str) -> KeyEntry {
    let fixture = oncl_testkit::synthetic(name);
    oncl_pki::pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}
fn issued(name: &str) -> KeyEntry {
    // Same real synthetic issuer/status profile used by the accepted Core B01 fixture.
    let mut entry = raw(name);
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&entry.cert);
    let template =
        oncl_pki::testing::TestCertSpec::from_cert(&raw("inter-user-gost2015-sign").cert);
    spec.extensions.retain(|extension| {
        !matches!(
            extension.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions
        .extend(template.extensions.into_iter().filter(|extension| {
            matches!(
                extension.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        }));
    entry.cert = oncl_pki::testing::issue_cert(&raw("inter-gost2015.key"), spec);
    entry
}
fn validation() -> ValidationServices {
    use oncl_pki::{
        crl::MockCrl,
        http::{HttpTransport, RouteTransport},
        ocsp::MockOcsp,
        pkix::CaSet,
        validation::NetworkPolicy,
    };
    let ocsp: Arc<dyn HttpTransport> = Arc::new(MockOcsp::new(raw("ocsp-gost2015")).with_now(NOW));
    let root: Arc<dyn HttpTransport> = Arc::new(
        MockCrl::new(raw("root-gost2015.key"))
            .with_this_update(NOW - time::Duration::MINUTE)
            .next_update(Some(NOW + time::Duration::HOUR)),
    );
    let inter: Arc<dyn HttpTransport> = Arc::new(
        MockCrl::new(raw("inter-gost2015.key"))
            .with_this_update(NOW - time::Duration::MINUTE)
            .next_update(Some(NOW + time::Duration::HOUR)),
    );
    ValidationServices::new(
        CaSet::new(vec![raw("root-gost2015.key").cert]),
        vec![raw("inter-gost2015.key").cert],
        Arc::new(RouteTransport::new(vec![
            ("http://ocsp.synthetic.test".into(), ocsp),
            ("http://crl.synthetic.test/root-gost2015.crl".into(), root),
            ("http://crl.synthetic.test/inter-gost2015.crl".into(), inter),
        ])),
        NetworkPolicy::only_endpoints(["http://ocsp.synthetic.test", "http://crl.synthetic.test"])
            .unwrap(),
        Arc::new(|| NOW),
    )
}
pub struct Observation {
    pub event: KeyUseEvent,
    pub correlation: (u64, u64),
    pub outcome: Option<KeyUseOutcome>,
    pub acknowledged: bool,
}
pub struct ObservedAudit {
    audit: DurableAuditGuard,
    pub before: Mutex<Vec<Observation>>,
    pub finished: Mutex<Vec<Observation>>,
}
impl KeyUseGuard for ObservedAudit {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        let receipt = self.audit.before_use(event)?;
        self.before.lock().unwrap().push(Observation {
            event: receipt.event().clone(),
            correlation: receipt.correlation().unwrap(),
            outcome: None,
            acknowledged: true,
        });
        Ok(receipt)
    }
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        let event = receipt.event().clone();
        let correlation = receipt.correlation().unwrap();
        let result = self.audit.finish(receipt, outcome);
        self.finished.lock().unwrap().push(Observation {
            event,
            correlation,
            outcome: Some(outcome),
            acknowledged: result.is_ok(),
        });
        result
    }
}
struct Provider(HashMap<KeyId, KeyEntry>);
impl KeyProvider for Provider {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError> {
        let id = request.selector().key_id();
        let entry = self.0.get(&id).ok_or(OperationError::KeyNotFound)?;
        KeyLease::new(id, entry.clone(), ctx)
    }
}
pub struct BatchRig {
    pub engine: Arc<Engine>,
    pub audit: DurableAuditGuard,
    pub observed: Arc<ObservedAudit>,
    actual: [Arc<ActualKey>; 2],
    selectors: [KeySelector; 2],
}
pub struct Proof {
    pub operation: u64,
    pub summary: BatchSummary,
    pub raw_zero: Vec<u8>,
    pub cms: Vec<u8>,
    pub gost: Vec<u8>,
    pub outside: Vec<u8>,
    /// Public synthetic signature proof from the failed operation, NOT delivery.
    pub actual_proof: Vec<u8>,
}
impl BatchRig {
    pub fn new(audit: DurableAuditGuard, scratch: &Path) -> Self {
        let ids = [
            KeyId::new("host-mapped-rsa").unwrap(),
            KeyId::new("host-mapped-gost").unwrap(),
        ];
        let (rsa, rsa_actual) = ActualKey::wrap(issued("user-rsa-sign"), audit.clone());
        let (gost, gost_actual) = ActualKey::wrap(issued("user-gost2015-sign"), audit.clone());
        let provider = Arc::new(Provider(HashMap::from([
            (ids[0].clone(), rsa),
            (ids[1].clone(), gost),
        ])));
        let observed = Arc::new(ObservedAudit {
            audit: audit.clone(),
            before: Mutex::new(Vec::new()),
            finished: Mutex::new(Vec::new()),
        });
        let engine = Arc::new(
            Engine::new(
                EngineServices::hash_only(ResourceLimits {
                    max_in_flight: 32,
                    ..ResourceLimits::default()
                })
                .with_temporary_store(TemporaryStore::new(scratch).unwrap())
                .with_keys(provider, observed.clone())
                .with_validation(validation()),
            )
            .unwrap(),
        );
        Self {
            engine,
            audit,
            observed,
            actual: [rsa_actual, gost_actual],
            selectors: ids.map(KeySelector::named),
        }
    }
    pub fn counts(&self) -> [usize; 2] {
        self.actual
            .each_ref()
            .map(|actual| actual.calls.load(Ordering::SeqCst))
    }
    pub fn rsa_public(&self) -> &PublicKey {
        self.actual[0].public_key()
    }
    fn context(&self) -> (OperationContext, oncl_server::audit::AuditBinding) {
        let ctx = self
            .engine
            .begin(
                ExecutionGrant::new([Action::Hash, Action::Sign, Action::Verify])
                    .with_keys(self.selectors.iter().map(KeySelector::key_id)),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap();
        let binding = self
            .audit
            .bind(
                &ctx,
                AuditLabel::new([0x55; 16]),
                [
                    (self.selectors[0].key_id(), AuditLabel::new([0x61; 16])),
                    (self.selectors[1].key_id(), AuditLabel::new([0x62; 16])),
                ],
            )
            .unwrap();
        (ctx, binding)
    }
    pub fn nonbatch(&self) -> Result<Vec<u8>, OperationError> {
        let (mut ctx, _binding) = self.context();
        let mut input = MESSAGE;
        let mut output = Vec::new();
        self.engine.sign(
            SignRequest::raw_message(KeyRequest::new(&self.selectors[0], None)),
            Source::sequential(&mut input, None),
            &mut output,
            &mut ctx,
        )?;
        self.rsa_public()
            .verify(SigAlg::RsaSha256, MESSAGE, &output)
            .unwrap();
        Ok(output)
    }
    pub fn exercise(&self, finish_fault: Option<FaultPoint>) -> Proof {
        let (mut ctx, _binding) = self.context();
        let operation = ctx.id().get();
        // A genuine audited non-batch signature supplies the independent VERIFY gap.
        let mut prelude = Vec::new();
        let mut input = MESSAGE;
        self.engine
            .sign(
                SignRequest::cms_create(vec![KeyRequest::new(&self.selectors[0], None)], true),
                Source::sequential(&mut input, None),
                &mut prelude,
                &mut ctx,
            )
            .unwrap();
        let mut zero = MESSAGE;
        let mut gap1 = &b"real hash gap one"[..];
        let mut multi = MESSAGE;
        let mut verify = prelude.as_slice();
        let mut gap4 = &b"real hash gap four"[..];
        let mut last = MESSAGE;
        let mut raw_zero = Vec::new();
        let mut cms = Vec::new();
        let mut gost = Vec::new();
        let plan = self
            .engine
            .capture_batch(
                [
                    BatchItem::new(
                        "guest-private-document.pdf",
                        BatchOperation::Sign {
                            request: SignRequest::raw_message(KeyRequest::new(
                                &self.selectors[0],
                                None,
                            )),
                            input: Source::sequential(&mut zero, None),
                            output: &mut raw_zero,
                        },
                    ),
                    BatchItem::new(
                        "hash-gap-one",
                        BatchOperation::Hash {
                            algorithm: HashAlg::Sha256,
                            input: Source::sequential(&mut gap1, None),
                        },
                    ),
                    BatchItem::new(
                        "two-private-keys",
                        BatchOperation::Sign {
                            request: SignRequest::cms_create(
                                vec![
                                    KeyRequest::new(&self.selectors[0], None),
                                    KeyRequest::new(&self.selectors[1], None),
                                ],
                                true,
                            ),
                            input: Source::sequential(&mut multi, None),
                            output: &mut cms,
                        },
                    ),
                    BatchItem::new(
                        "verified-gap",
                        BatchOperation::Verify {
                            request: VerifyRequest::cms(),
                            input: Source::sequential(&mut verify, None),
                            detached: None,
                        },
                    ),
                    BatchItem::new(
                        "hash-gap-four",
                        BatchOperation::Hash {
                            algorithm: HashAlg::Sha256,
                            input: Source::sequential(&mut gap4, None),
                        },
                    ),
                    BatchItem::new(
                        "last-private",
                        BatchOperation::Sign {
                            request: SignRequest::raw_message(KeyRequest::new(
                                &self.selectors[1],
                                None,
                            )),
                            input: Source::sequential(&mut last, None),
                            output: &mut gost,
                        },
                    ),
                ],
                &mut ctx,
            )
            .unwrap();
        assert_eq!(plan.items().len(), 6);
        let approval = plan.authorize(&ctx).unwrap();
        *self.actual[0].after.lock().unwrap() = finish_fault;
        let summary = self
            .engine
            .run_batch(plan, approval, &mut ctx, |_| {})
            .unwrap();
        let mut outside = Vec::new();
        if finish_fault.is_none() {
            assert_eq!(summary.completed, 6);
            assert!(summary.stop.is_none());
            assert!(
                matches!(summary.results()[3].outcome(),BatchOutcome::Completed(BatchReport::Verify(report)) if report.verdict == Verdict::Valid)
            );
            assert_eq!(
                summary
                    .results()
                    .iter()
                    .map(|item| item.applied_state())
                    .collect::<Vec<_>>(),
                [
                    AppliedState::Applied,
                    AppliedState::NotApplied,
                    AppliedState::Applied,
                    AppliedState::NotApplied,
                    AppliedState::NotApplied,
                    AppliedState::Applied
                ]
            );
            self.rsa_public()
                .verify(SigAlg::RsaSha256, MESSAGE, &raw_zero)
                .unwrap();
            self.actual[1]
                .public_key()
                .verify(SigAlg::Gost2015_512, MESSAGE, &gost)
                .unwrap();
            let mut signed = cms.as_slice();
            let checked = self
                .engine
                .verify(
                    &VerifyRequest::cms(),
                    Source::sequential(&mut signed, None),
                    None,
                    &mut ctx,
                )
                .unwrap();
            assert_eq!(checked.verdict, Verdict::Valid);
            assert_eq!(checked.signers.len(), 2);
            let mut input = MESSAGE;
            self.engine
                .sign(
                    SignRequest::raw_message(KeyRequest::new(&self.selectors[0], None)),
                    Source::sequential(&mut input, None),
                    &mut outside,
                    &mut ctx,
                )
                .unwrap();
            self.rsa_public()
                .verify(SigAlg::RsaSha256, MESSAGE, &outside)
                .unwrap();
            assert_eq!(self.counts(), [4, 2]);
        } else {
            assert_eq!(summary.attempted, 1);
            assert_eq!(summary.completed, 0);
            assert_eq!(summary.results()[0].applied_state(), AppliedState::Applied);
            assert!(
                summary.results()[1..]
                    .iter()
                    .all(|item| matches!(item.outcome(), BatchOutcome::NotRun))
            );
            assert!(raw_zero.is_empty() && cms.is_empty() && gost.is_empty());
            assert_eq!(self.counts(), [2, 0]);
            assert_eq!(self.audit.health(), AuditHealth::Failed);
            self.rsa_public()
                .verify(
                    SigAlg::RsaSha256,
                    MESSAGE,
                    self.actual[0].signatures.lock().unwrap().last().unwrap(),
                )
                .unwrap();
        }
        let before = self.observed.before.lock().unwrap();
        let finished = self.observed.finished.lock().unwrap();
        assert_eq!(before.len(), finished.len());
        for (begin, final_call) in before.iter().zip(finished.iter()) {
            assert!(begin.acknowledged && begin.outcome.is_none());
            assert_eq!(begin.correlation, final_call.correlation);
            assert_eq!(begin.event.operation_id, final_call.event.operation_id);
            assert_eq!(begin.event.key_id, final_call.event.key_id);
            assert_eq!(begin.event.batch_item(), final_call.event.batch_item());
            assert!(final_call.outcome.is_some());
        }
        assert_eq!(
            finished.last().unwrap().acknowledged,
            finish_fault.is_none()
        );
        let actual_proof = if finish_fault.is_some() {
            self.actual[0].signatures.lock().unwrap().pop().unwrap()
        } else {
            Vec::new()
        };
        Proof {
            operation,
            summary,
            raw_zero,
            cms,
            gost,
            outside,
            actual_proof,
        }
    }
}
