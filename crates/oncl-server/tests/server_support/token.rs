use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationPolicy,
    keys::{KeyId, KeyRequest, KeySelector},
};
use oncl_pki::{digest::HashState, key::SigAlg, resource::ResourceLimits};
use oncl_server::{
    audit::{AuditBinding, AuditConfig, AuditLabel, DurableAuditGuard},
    executor::Cancellation,
    keys::{KeyBinding, OperatorKeys},
};
use oncl_token::{
    TokenKind, Tokens,
    backend::{Backend, BackendError, Connection, Protocol, ReaderState},
    emulator::{CardSpec, EmuKey, EmulatorBackend, card},
    execution::TokenGateRegistry,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
const PIN: &str = "123456";
pub const MESSAGE: &[u8] = b"actual S02 worker and durable card application";
struct Probe {
    emu: Arc<EmulatorBackend>,
    armed: Arc<AtomicBool>,
    entered: tokio::sync::mpsc::UnboundedSender<String>,
}
struct ProbeConnection {
    inner: Box<dyn Connection>,
    reader: String,
    armed: Arc<AtomicBool>,
    entered: tokio::sync::mpsc::UnboundedSender<String>,
}
impl Backend for Probe {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        self.emu.readers()
    }
    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        Ok(Box::new(ProbeConnection {
            inner: self.emu.connect(reader)?,
            reader: reader.into(),
            armed: self.armed.clone(),
            entered: self.entered.clone(),
        }))
    }
}
impl Connection for ProbeConnection {
    fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }
    fn atr(&self) -> &[u8] {
        self.inner.atr()
    }
    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        if self.armed.load(Ordering::SeqCst) {
            let _ = self.entered.send(self.reader.clone());
        }
        self.inner.begin_transaction()
    }
    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.inner.end_transaction()
    }
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.inner.transmit(apdu)
    }
    fn reset_on_disconnect(&mut self) {
        self.inner.reset_on_disconnect()
    }
    fn begin_private_operation(&mut self) {
        self.inner.begin_private_operation()
    }
}
pub struct TokenRig {
    pub emu: Arc<EmulatorBackend>,
    pub engine: Arc<Engine>,
    pub audit: DurableAuditGuard,
    pub entered: tokio::sync::mpsc::UnboundedReceiver<String>,
    armed: Arc<AtomicBool>,
    _directory: tempfile::TempDir,
}
impl TokenRig {
    pub fn new() -> Self {
        let emu = Arc::new(EmulatorBackend::new());
        for reader in ["reader-a", "reader-b"] {
            emu.add_reader(reader);
            let entries = ["user-rsa-sign", "user-gost2004-sign"]
                .into_iter()
                .map(|name| {
                    let f = oncl_testkit::synthetic(name);
                    EmuKey {
                        entry: oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
                            .unwrap()
                            .remove(0),
                    }
                })
                .collect();
            let mut spec = CardSpec::new(TokenKind::Kaztoken, PIN, entries);
            spec.fixed_k = Some(vec![1; 16]);
            emu.insert(reader, card(spec));
        }
        let armed = Arc::new(AtomicBool::new(false));
        let (send, entered) = tokio::sync::mpsc::unbounded_channel();
        let tokens = Tokens::new(
            Arc::new(Probe {
                emu: emu.clone(),
                armed: armed.clone(),
                entered: send,
            }),
            true,
        );
        tokens.set_trace(false);
        let mut bindings = Vec::new();
        for (name, reader, fixture) in [
            ("card-a-rsa", "reader-a", "user-rsa-sign"),
            ("card-a-gost", "reader-a", "user-gost2004-sign"),
            ("card-b-gost", "reader-b", "user-gost2004-sign"),
        ] {
            bindings.push(
                KeyBinding::token(
                    name,
                    reader.into(),
                    TokenKind::Kaztoken,
                    oncl_testkit::synthetic(fixture).aliases[0].clone(),
                    PIN.into(),
                )
                .unwrap(),
            );
        }
        let keys = Arc::new(
            OperatorKeys::new(
                bindings,
                Some((tokens, Arc::new(TokenGateRegistry::new(2, 0).unwrap()))),
                false,
            )
            .unwrap(),
        );
        let directory = super::sandbox();
        let audit = DurableAuditGuard::create(
            AuditConfig::new(directory.path().join("audit"), 4096, 65536, 8, 16).unwrap(),
        )
        .unwrap();
        let engine = Arc::new(
            Engine::new(
                EngineServices::hash_only(ResourceLimits {
                    max_in_flight: 8,
                    ..ResourceLimits::default()
                })
                .with_keys(keys, Arc::new(audit.clone())),
            )
            .unwrap(),
        );
        Self {
            emu,
            engine,
            audit,
            entered,
            armed,
            _directory: directory,
        }
    }
    pub fn begin(&self, name: &str) -> (OperationContext, AuditBinding) {
        let id = KeyId::new(name).unwrap();
        let mut policy = OperationPolicy::ncalayer_compatibility();
        policy.allow_prehashed = true;
        let ctx = self
            .engine
            .begin(
                ExecutionGrant::new([Action::SignDigest]).with_keys([id.clone()]),
                policy,
                Arc::new(Cancellation::new()),
            )
            .unwrap();
        let binding = self
            .audit
            .bind(
                &ctx,
                AuditLabel::new([1; 16]),
                [(id, AuditLabel::new([2; 16]))],
            )
            .unwrap();
        (ctx, binding)
    }
    pub fn arm(&self) {
        self.emu.clear_exchanges("reader-a");
        self.emu.clear_exchanges("reader-b");
        self.armed.store(true, Ordering::SeqCst);
    }
    pub fn verify(name: &str, alg: SigAlg, signature: &[u8]) {
        let f = oncl_testkit::synthetic(name);
        let e = oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
            .unwrap()
            .remove(0);
        let mut hash = HashState::new(alg.hash_alg());
        hash.update(MESSAGE);
        e.key
            .public_key()
            .verify_digest(alg, &hash.finish(), signature)
            .unwrap();
    }
    pub fn signer(
        engine: &Engine,
        ctx: &mut OperationContext,
        name: &str,
        alg: SigAlg,
    ) -> Result<Vec<u8>, oncl_core::OperationError> {
        let selector = KeySelector::named(KeyId::new(name).unwrap());
        let mut hash = HashState::new(alg.hash_alg());
        hash.update(MESSAGE);
        engine
            .signer(&KeyRequest::new(&selector, None), ctx)?
            .sign_digest(&hash.finish())
    }
}
