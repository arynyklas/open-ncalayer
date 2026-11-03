use oncl_core::keys::{KeyId, KeyLease, KeyProvider, KeyRequest, KeySelector};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy,
};
use oncl_pki::digest::{DigestValue, HashState};
use oncl_pki::key::{KeyAlg, KeyError, PrivateKey, PublicKey, SigAlg, TokenKey, TokenSigner};
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::resource::{OperationControl, ProcessingError, Progress, ResourceLimits};
use oncl_server::audit::{AuditBinding, AuditLabel, DurableAuditGuard, FaultPoint};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub const MESSAGE: &[u8] = b"S01 actual synthetic RSA private use and durable audit";
pub struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
pub struct ActualKey {
    pub key: PrivateKey,
    public: PublicKey,
    pub calls: AtomicUsize,
    pub signatures: Mutex<Vec<Vec<u8>>>,
    pub after: Mutex<Option<FaultPoint>>,
    pub lose_response: AtomicBool,
    pub pause: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    pub audit: DurableAuditGuard,
}
impl TokenSigner for ActualKey {
    fn alg(&self) -> KeyAlg {
        self.key.alg()
    }
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
    fn sign_digest(&self, alg: SigAlg, bytes: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((entered, release)) = self.pause.lock().unwrap().take() {
            entered.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(20))
                .unwrap();
        }
        let signature = self
            .key
            .sign_digest(alg, &DigestValue::from_bytes(alg.hash_alg(), bytes)?)?;
        self.signatures.lock().unwrap().push(signature.clone());
        if let Some(point) = self.after.lock().unwrap().take() {
            self.audit.inject_fault(point);
        }
        if self.lose_response.swap(false, Ordering::SeqCst) {
            return Err(oncl_pki::key::KeyExecutionError {
                kind: oncl_pki::key::KeyFailureKind::Backend,
                applied: oncl_pki::key::AppliedState::Unknown,
            }
            .into());
        }
        Ok(signature)
    }
    fn describe(&self) -> String {
        "synthetic test private key".to_owned()
    }
}
struct Provider {
    entry: KeyEntry,
    id: KeyId,
}
impl KeyProvider for Provider {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError> {
        if request.selector().key_id() != self.id {
            return Err(OperationError::PermissionDenied);
        }
        KeyLease::new(self.id.clone(), self.entry.clone(), ctx)
    }
}
pub struct Rig {
    pub engine: Arc<Engine>,
    pub actual: Arc<ActualKey>,
    pub selector: KeySelector,
    pub audit: DurableAuditGuard,
}
impl Rig {
    pub fn new(audit: DurableAuditGuard) -> Self {
        Self::with_key(audit, "user-rsa-sign")
    }
    pub fn with_key(audit: DurableAuditGuard, name: &str) -> Self {
        let fixture = oncl_testkit::synthetic(name);
        let mut entry =
            oncl_pki::pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
                .unwrap()
                .remove(0);
        let actual = Arc::new(ActualKey {
            public: entry.key.public_key(),
            key: entry.key.clone(),
            calls: AtomicUsize::new(0),
            signatures: Mutex::new(Vec::new()),
            after: Mutex::new(None),
            lose_response: AtomicBool::new(false),
            pause: Mutex::new(None),
            audit: audit.clone(),
        });
        entry.key = PrivateKey::Token(TokenKey::new(actual.clone()));
        let id = KeyId::new("host-private-path/password-must-not-appear").unwrap();
        let provider = Arc::new(Provider {
            entry,
            id: id.clone(),
        });
        let engine = Arc::new(
            Engine::new(
                EngineServices::hash_only(ResourceLimits {
                    max_in_flight: 32,
                    ..ResourceLimits::default()
                })
                .with_keys(provider, Arc::new(audit.clone())),
            )
            .unwrap(),
        );
        Self {
            engine,
            actual,
            selector: KeySelector::named(id),
            audit,
        }
    }
    pub fn begin(&self) -> (OperationContext, AuditBinding) {
        self.begin_labeled(AuditLabel::new([0x11; 16]), AuditLabel::new([0x22; 16]))
    }
    pub fn begin_labeled(
        &self,
        principal: AuditLabel,
        key_label: AuditLabel,
    ) -> (OperationContext, AuditBinding) {
        // Explicit trusted host compatibility policy, not client-controlled and
        // not a bypass added by audit. Core still enforces grant + key authority.
        let mut policy = OperationPolicy::ncalayer_compatibility();
        policy.allow_prehashed = true;
        let ctx = self
            .engine
            .begin(
                ExecutionGrant::new([Action::SignDigest]).with_keys([self.selector.key_id()]),
                policy,
                Arc::new(Control),
            )
            .unwrap();
        let binding = self
            .audit
            .bind(&ctx, principal, [(self.selector.key_id(), key_label)])
            .unwrap();
        (ctx, binding)
    }
    pub fn sign(&self, ctx: &mut OperationContext) -> Result<Vec<u8>, OperationError> {
        let alg = oncl_pki::key::leaf_signature_algorithm(self.actual.key.alg());
        let mut hash = HashState::new(alg.hash_alg());
        hash.update(MESSAGE);
        self.engine
            .signer(&KeyRequest::new(&self.selector, None), ctx)?
            .sign_digest(&hash.finish())
    }
    pub fn calls(&self) -> usize {
        self.actual.calls.load(Ordering::SeqCst)
    }
    pub fn verify(&self, signature: &[u8]) {
        let alg = oncl_pki::key::leaf_signature_algorithm(self.actual.key.alg());
        self.actual.public.verify(alg, MESSAGE, signature).unwrap();
        if let PublicKey::Rsa(der) = &self.actual.public {
            use rsa::pkcs1::DecodeRsaPublicKey;
            let public = rsa::RsaPublicKey::from_pkcs1_der(der).unwrap();
            let mut hash = HashState::new(alg.hash_alg());
            hash.update(MESSAGE);
            // Independent rsa crate PKCS#1 padding verifier with the standard
            // SHA256 DigestInfo prefix; production private RSA is native CNG.
            let mut info = vec![
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ];
            info.extend(hash.finish().as_bytes());
            public
                .verify(rsa::Pkcs1v15Sign::new_unprefixed(), &info, signature)
                .unwrap();
            info[20] ^= 1;
            assert!(
                public
                    .verify(rsa::Pkcs1v15Sign::new_unprefixed(), &info, signature)
                    .is_err()
            );
        }
    }
}
