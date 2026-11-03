//! Public synthetic fixtures only, shared by J01's executable probe and tests.
use der::Encode;
use oncl_core::keys::{
    KeySelector, KeySources, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy, ValidationServices,
};
use oncl_pki::{
    pkcs12::{self, KeyEntry},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
pub const NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
pub fn raw(name: &str) -> KeyEntry {
    let fixture = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}
pub fn issued(name: &str) -> KeyEntry {
    let mut entry = raw(name);
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&entry.cert);
    let template =
        oncl_pki::testing::TestCertSpec::from_cert(&raw("inter-user-gost2015-sign").cert);
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions
        .extend(template.extensions.into_iter().filter(|e| {
            matches!(
                e.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        }));
    entry.cert = oncl_pki::testing::issue_cert(&raw("inter-gost2015.key"), spec);
    entry
}
pub fn selector(name: &str) -> KeySelector {
    let entry = issued(name);
    let bytes = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: entry.alias,
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        }],
        &[],
        "J01 synthetic",
        &pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x71),
    )
    .unwrap();
    KeySelector::inline(bytes, None)
}
pub fn validation(trusted: bool, statuses: bool) -> ValidationServices {
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
        CaSet::new(if trusted {
            vec![raw("root-gost2015.key").cert]
        } else {
            vec![]
        }),
        vec![raw("inter-gost2015.key").cert],
        Arc::new(RouteTransport::new(if statuses {
            vec![
                ("http://ocsp.synthetic.test".into(), ocsp),
                ("http://crl.synthetic.test/root-gost2015.crl".into(), root),
                ("http://crl.synthetic.test/inter-gost2015.crl".into(), inter),
            ]
        } else {
            vec![]
        })),
        NetworkPolicy::only_endpoints(["http://ocsp.synthetic.test", "http://crl.synthetic.test"])
            .unwrap(),
        Arc::new(|| NOW),
    )
}
#[derive(Default)]
pub struct Control(pub AtomicBool);
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
pub struct Guard {
    pub calls: AtomicUsize,
    pub fail_finish: AtomicBool,
    pub deny_at: AtomicUsize,
    pub events: Mutex<Vec<KeyUseEvent>>,
}
impl KeyUseGuard for Guard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.deny_at.load(Ordering::SeqCst) == n + 1 {
            return Err(OperationError::PermissionDenied);
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(&self, _: KeyUseReceipt, _: KeyUseOutcome) -> Result<(), OperationError> {
        if self.fail_finish.load(Ordering::SeqCst) {
            Err(OperationError::AuditFailed)
        } else {
            Ok(())
        }
    }
}
pub fn engine(guard: Arc<Guard>, limits: ResourceLimits, trusted: bool, statuses: bool) -> Engine {
    Engine::new(
        EngineServices::hash_only(limits)
            .with_keys(Arc::new(KeySources::new()), guard)
            .with_validation(validation(trusted, statuses)),
    )
    .unwrap()
}
pub fn begin(engine: &Engine, keys: &[&KeySelector], actions: &[Action]) -> OperationContext {
    engine
        .begin(
            ExecutionGrant::new(actions.iter().copied()).with_keys(keys.iter().map(|k| k.key_id())),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap()
}
