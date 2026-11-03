//! Synthetic-only batch fixtures, shared by the real probe and integration tests.
use der::Encode;
use oncl_core::{Engine, EngineServices, OperationError, ValidationServices, keys::*};
use oncl_pki::{
    io::TemporaryStore,
    pkcs12::{self, KeyEntry},
    resource::ResourceLimits,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
pub(crate) const NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
pub(crate) const PASSWORD: &str = "B01 synthetic";
pub(crate) fn raw(name: &str) -> KeyEntry {
    let fixture = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}
pub(crate) fn issued(name: &str) -> KeyEntry {
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
pub(crate) fn selector(name: &str) -> KeySelector {
    selector_with_certificate(name).0
}
pub(crate) fn selector_with_certificate(name: &str) -> (KeySelector, oncl_pki::cert::Certificate) {
    let (container, certificate) = container_with_certificate(name);
    (KeySelector::inline(container, None), certificate)
}
pub(crate) fn container_with_certificate(name: &str) -> (Vec<u8>, oncl_pki::cert::Certificate) {
    let entry = issued(name);
    let certificate = entry.cert.clone();
    let container = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: entry.alias,
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        }],
        &[],
        PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x62),
    )
    .unwrap();
    (container, certificate)
}
pub(crate) fn validation() -> ValidationServices {
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
#[derive(Default)]
pub(crate) struct Guard {
    pub before: AtomicUsize,
    pub applied: AtomicUsize,
    pub audit_fail: AtomicBool,
    pub deny: AtomicBool,
    pub preuse_local_error: AtomicBool,
    pub finish_io_fail: AtomicBool,
    pub events: Mutex<Vec<KeyUseEvent>>,
    pub finished: Mutex<Vec<KeyUseEvent>>,
    pub hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}
impl KeyUseGuard for Guard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        self.before.fetch_add(1, Ordering::SeqCst);
        self.events.lock().unwrap().push(event.clone());
        if let Some(hook) = &*self.hook.lock().unwrap() {
            hook();
        }
        if self.preuse_local_error.swap(false, Ordering::SeqCst) {
            return Err(OperationError::ValidationRequired);
        }
        if self.deny.load(Ordering::SeqCst) {
            return Err(OperationError::PermissionDenied);
        }
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(&self, receipt: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        self.finished.lock().unwrap().push(receipt.event().clone());
        if outcome.applied == AppliedState::Applied {
            self.applied.fetch_add(1, Ordering::SeqCst);
        }
        if self.finish_io_fail.load(Ordering::SeqCst) {
            return Err(
                oncl_pki::resource::ProcessingError::Io(std::io::Error::other(
                    "synthetic finish I/O failure",
                ))
                .into(),
            );
        }
        if self.audit_fail.load(Ordering::SeqCst) {
            Err(OperationError::AuditFailed)
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
pub(crate) struct Provider {
    pub opens: AtomicUsize,
}
impl KeyProvider for Provider {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut oncl_core::OperationContext,
    ) -> Result<KeyLease, OperationError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        KeySources::new().open(request, ctx)
    }
}
pub(crate) fn engine(
    store: TemporaryStore,
    guard: Arc<Guard>,
    provider: Arc<Provider>,
    limits: ResourceLimits,
) -> Engine {
    Engine::new(
        EngineServices::hash_only(limits)
            .with_temporary_store(store)
            .with_keys(provider, guard)
            .with_validation(validation()),
    )
    .unwrap()
}
