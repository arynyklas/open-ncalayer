//! F02 tests-first contract, including real card transactions and synthetic signatures.
//! No production implementation is supplied here. Controller runs RED/GREEN.

use der::Encode;
use oncl_core::keys::{
    AppliedState, KeyId, KeyLease, KeyProvider, KeyRequest, KeySelector, KeySources, KeyUseEvent,
    KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
};
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy,
};
use oncl_pki::digest::{DigestValue, HashState};
use oncl_pki::key::{HashAlg, KeyAlg, PublicKey, SigAlg};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::resource::{
    OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget,
};
use oncl_testkit::read;
use oncl_token::backend::{Backend, BackendError, Connection, Protocol, ReaderState};
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::execution::{TokenDeviceId, TokenGateRegistry};
use oncl_token::{TokenKind, Tokens};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

const MESSAGE: &[u8] = b"F02 authorized synthetic document";
const PIN: &str = "123456";
const READER_A: &str = "F02 reader A";
const READER_B: &str = "F02 reader B";
const WATCHDOG: Duration = Duration::from_secs(10);

fn entry(name: &str) -> KeyEntry {
    let f = synthetic(name);
    load(&read(f.path), &f.password).unwrap().remove(0)
}
fn digest(alg: HashAlg) -> DigestValue {
    let mut state = HashState::new(alg);
    state.update(MESSAGE);
    state.finish()
}
fn file(name: &str) -> KeySelector {
    let f = synthetic(name);
    KeySelector::file(f.path, Some(f.aliases[0].clone())).unwrap()
}
fn policy() -> OperationPolicy {
    let mut policy = OperationPolicy::strict_online();
    policy.allow_prehashed = true;
    policy
}
fn grant(keys: impl IntoIterator<Item = KeyId>) -> ExecutionGrant {
    ExecutionGrant::new([Action::SignDigest]).with_keys(keys)
}
#[derive(Default)]
struct Control {
    cancelled: AtomicBool,
}
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
fn begin(engine: &Engine, ids: impl IntoIterator<Item = KeyId>) -> OperationContext {
    engine
        .begin(grant(ids), policy(), Arc::new(Control::default()))
        .unwrap()
}

// This is an explicit host-consent policy, not an auto-yes server audit backend.
// All signatures below still run through the actual software/card private operation.
struct Consent {
    allowed: Vec<KeyId>,
    consent: AtomicBool,
    fail_before: AtomicBool,
    fail_finish: AtomicBool,
    events: Mutex<Vec<KeyUseEvent>>,
    outcomes: Mutex<Vec<KeyUseOutcome>>,
}
impl Consent {
    fn new(allowed: Vec<KeyId>) -> Arc<Self> {
        Arc::new(Self {
            allowed,
            consent: AtomicBool::new(true),
            fail_before: AtomicBool::new(false),
            fail_finish: AtomicBool::new(false),
            events: Mutex::new(vec![]),
            outcomes: Mutex::new(vec![]),
        })
    }
}
impl KeyUseGuard for Consent {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        if !self.consent.load(Ordering::SeqCst)
            || !self.allowed.contains(&event.key_id)
            || event.action != Action::SignDigest
        {
            return Err(OperationError::PermissionDenied);
        }
        if self.fail_before.load(Ordering::SeqCst) {
            return Err(OperationError::AuditFailed);
        }
        self.events.lock().unwrap().push(event.clone());
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(&self, _: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        self.outcomes.lock().unwrap().push(outcome);
        if self.fail_finish.load(Ordering::SeqCst) {
            Err(OperationError::AuditFailed)
        } else {
            Ok(())
        }
    }
}
struct Opens {
    inner: KeySources,
    count: AtomicUsize,
}
impl KeyProvider for Opens {
    fn open(
        &self,
        request: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.open(request, ctx)
    }
}
fn engine(
    provider: Arc<dyn KeyProvider>,
    guard: Arc<dyn KeyUseGuard>,
    limits: ResourceLimits,
) -> Arc<Engine> {
    Arc::new(
        Engine::new(
            EngineServices::hash_only(limits)
                .with_keys(provider, guard)
                .with_validation(validation_services()),
        )
        .unwrap(),
    )
}
fn sign(
    engine: &Engine,
    ctx: &mut OperationContext,
    selector: &KeySelector,
    secret: Option<&str>,
    alg: SigAlg,
) -> Result<Vec<u8>, OperationError> {
    engine
        .signer(&KeyRequest::new(selector, secret), ctx)?
        .sign_digest(&digest(alg.hash_alg()))
}
fn assert_signature(name: &str, alg: SigAlg, signature: &[u8]) {
    let public = entry(name).key.public_key();
    public.verify(alg, MESSAGE, signature).unwrap();
    public
        .verify_digest(alg, &digest(alg.hash_alg()), signature)
        .unwrap();
    let mut wrong = HashState::new(alg.hash_alg());
    wrong.update(b"another document");
    assert!(
        public
            .verify_digest(alg, &wrong.finish(), signature)
            .is_err()
    );
}

#[test]
fn foreign_key_denied_before_use() {
    // Break caught: checking key scope after provider open, or treating an action grant as all-key authority.
    let a = file("user-rsa-sign");
    let b = file("user-gost2004-sign");
    let guard = Consent::new(vec![a.key_id(), b.key_id()]);
    let provider = Arc::new(Opens {
        inner: KeySources::new(),
        count: AtomicUsize::new(0),
    });
    let engine = engine(provider.clone(), guard.clone(), ResourceLimits::default());
    let mut ctx = begin(&engine, [a.key_id()]);
    let error = sign(
        &engine,
        &mut ctx,
        &b,
        Some("wrong secret must never be inspected"),
        SigAlg::Gost2004,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(provider.count.load(Ordering::SeqCst), 0);
    assert!(guard.events.lock().unwrap().is_empty());
    let f = synthetic("user-rsa-sign");
    assert_signature(
        "user-rsa-sign",
        SigAlg::RsaSha256,
        &sign(&engine, &mut ctx, &a, Some(&f.password), SigAlg::RsaSha256).unwrap(),
    );
}

#[test]
fn lease_dies_with_operation() {
    // Break caught: caching desktop-unlocked software material across independent contexts.
    let selector = file("user-rsa-sign");
    let guard = Consent::new(vec![selector.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard,
        ResourceLimits::default(),
    );
    let password = synthetic("user-rsa-sign").password;
    {
        let mut ctx = begin(&engine, [selector.key_id()]);
        assert_signature(
            "user-rsa-sign",
            SigAlg::RsaSha256,
            &sign(
                &engine,
                &mut ctx,
                &selector,
                Some(&password),
                SigAlg::RsaSha256,
            )
            .unwrap(),
        );
        // Reuse is allowed inside this one explicitly authorized operation, without re-supplying the secret.
        assert_signature(
            "user-rsa-sign",
            SigAlg::RsaSha256,
            &sign(&engine, &mut ctx, &selector, None, SigAlg::RsaSha256).unwrap(),
        );
    }
    let mut next = begin(&engine, [selector.key_id()]);
    let error = sign(&engine, &mut next, &selector, None, SigAlg::RsaSha256).unwrap_err();
    assert_eq!(error.code(), ErrorCode::SecretRequired);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_signature(
        "user-rsa-sign",
        SigAlg::RsaSha256,
        &sign(
            &engine,
            &mut next,
            &selector,
            Some(&password),
            SigAlg::RsaSha256,
        )
        .unwrap(),
    );
}

#[test]
fn named_inline_and_file_sources_sign_real_keys() {
    // Break caught: one selector branch silently opening another/default key, or alias being ignored.
    let fixture = synthetic("user-rsa-sign");
    let source = file("user-rsa-sign");
    let inline = KeySelector::inline(read(&fixture.path), Some(fixture.aliases[0].clone()));
    let id = KeyId::new("host-configured-rsa").unwrap();
    let named = KeySelector::named(id.clone());
    let provider = KeySources::new().with_named(id, source.clone()).unwrap();
    let guard = Consent::new(vec![source.key_id(), inline.key_id(), named.key_id()]);
    let engine = engine(Arc::new(provider), guard, ResourceLimits::default());
    let mut ctx = begin(&engine, [source.key_id(), inline.key_id(), named.key_id()]);
    for selector in [&source, &inline, &named] {
        assert_signature(
            "user-rsa-sign",
            SigAlg::RsaSha256,
            &sign(
                &engine,
                &mut ctx,
                selector,
                Some(&fixture.password),
                SigAlg::RsaSha256,
            )
            .unwrap(),
        );
    }
}

#[test]
fn named_id_cannot_be_rebound_and_alias_is_part_of_authority() {
    // Break caught: letting a caller attach granted key-A's identity to key-B or another alias.
    let id = KeyId::new("fixed-host-name").unwrap();
    assert!(
        KeySources::new()
            .with_named(id.clone(), file("user-rsa-sign"))
            .unwrap()
            .with_named(id, file("user-gost2004-sign"))
            .is_err()
    );
    let f = synthetic("user-rsa-sign");
    let a = file("user-rsa-sign");
    let b = KeySelector::file(f.path, Some("not-the-authorized-alias".to_owned())).unwrap();
    let guard = Consent::new(vec![a.key_id(), b.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard,
        ResourceLimits::default(),
    );
    let mut ctx = begin(&engine, [a.key_id()]);
    assert_eq!(
        sign(&engine, &mut ctx, &b, Some(&f.password), SigAlg::RsaSha256)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
}

#[test]
fn missing_provider_and_missing_secret_are_typed_not_success() {
    // Break caught: missing services fabricating a key/signature, or absence silently selecting an unlocked key.
    let selector = file("user-rsa-sign");
    let bare = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = begin(&bare, [selector.key_id()]);
    assert_eq!(
        sign(&bare, &mut ctx, &selector, None, SigAlg::RsaSha256)
            .unwrap_err()
            .code(),
        ErrorCode::MissingKeyProvider
    );
    drop(ctx);
    let guard = Consent::new(vec![selector.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard,
        ResourceLimits::default(),
    );
    let mut ctx = begin(&engine, [selector.key_id()]);
    assert_eq!(
        sign(&engine, &mut ctx, &selector, None, SigAlg::RsaSha256)
            .unwrap_err()
            .code(),
        ErrorCode::SecretRequired
    );
}

#[test]
fn action_denial_and_foreign_engine_context_precede_provider_use() {
    // Break caught: begin still requiring Hash for signing, or signer accepting another engine's context.
    let selector = file("user-rsa-sign");
    let provider = Arc::new(Opens {
        inner: KeySources::new(),
        count: AtomicUsize::new(0),
    });
    let guard = Consent::new(vec![selector.key_id()]);
    let one = engine(provider.clone(), guard.clone(), ResourceLimits::default());
    let two = engine(provider.clone(), guard, ResourceLimits::default());
    let mut hash_only = one
        .begin(
            ExecutionGrant::new([Action::Hash]).with_keys([selector.key_id()]),
            policy(),
            Arc::new(Control::default()),
        )
        .unwrap();
    assert_eq!(
        sign(&one, &mut hash_only, &selector, None, SigAlg::RsaSha256)
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    drop(hash_only);
    let mut ctx = begin(&one, [selector.key_id()]); // no Hash action: valid signing operation
    assert!(matches!(
        two.signer(&KeyRequest::new(&selector, None), &mut ctx),
        Err(OperationError::InvalidContext)
    ));
    assert_eq!(provider.count.load(Ordering::SeqCst), 0);
}

// A host provider for a genuinely cross-signed leaf, not a certificate-OID byte patch.
struct CrossSigned {
    entry: KeyEntry,
    id: KeyId,
}
impl KeyProvider for CrossSigned {
    fn open(
        &self,
        _: &KeyRequest<'_>,
        ctx: &mut OperationContext,
    ) -> Result<KeyLease, OperationError> {
        KeyLease::new(self.id.clone(), self.entry.clone(), ctx)
    }
}
#[test]
fn leaf_algorithm_not_issuer_signature() {
    // Break caught: selecting GOST from the issuer's signatureAlgorithm for an RSA leaf.
    let mut rsa = entry("user-rsa-sign");
    let issuer = cross_issuer();
    rsa.cert = cross_leaf(&rsa, &issuer);
    oncl_pki::cert::verify_signature(&rsa.cert, &issuer.cert).unwrap();
    assert_eq!(
        oncl_pki::info::cert_info(&rsa.cert).signing_alg().unwrap(),
        SigAlg::Gost2004
    ); // preserve legacy semantics
    assert_eq!(rsa.key.alg(), KeyAlg::Rsa);
    let id = KeyId::new("cross-signed-rsa").unwrap();
    let selector = KeySelector::named(id.clone());
    let guard = Consent::new(vec![id.clone()]);
    let engine = engine(
        Arc::new(CrossSigned {
            entry: rsa,
            id: id.clone(),
        }),
        guard,
        ResourceLimits::default(),
    );
    let mut ctx = begin(&engine, [id]);
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, None), &mut ctx)
        .unwrap();
    assert_eq!(signer.algorithm(), SigAlg::RsaSha256);
    let signature = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap();
    PublicKey::from_spki(
        signer
            .certificate()
            .tbs_certificate()
            .subject_public_key_info(),
    )
    .unwrap()
    .verify(SigAlg::RsaSha256, MESSAGE, &signature)
    .unwrap();
}

#[test]
fn policy_rejects_prehash_and_disallowed_leaf_algorithm_before_use() {
    // Break caught: treating an imported digest as an implicit allow_prehashed privilege.
    let selector = file("user-rsa-sign");
    let guard = Consent::new(vec![selector.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard.clone(),
        ResourceLimits::default(),
    );
    let password = synthetic("user-rsa-sign").password;
    let mut ctx = engine
        .begin(
            grant([selector.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap();
    let error = sign(
        &engine,
        &mut ctx,
        &selector,
        Some(&password),
        SigAlg::RsaSha256,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    drop(ctx);
    let mut restricted = policy();
    restricted.allowed_signature_algorithms = &[SigAlg::Gost2004];
    let mut ctx = engine
        .begin(
            grant([selector.key_id()]),
            restricted,
            Arc::new(Control::default()),
        )
        .unwrap();
    assert_eq!(
        sign(
            &engine,
            &mut ctx,
            &selector,
            Some(&password),
            SigAlg::RsaSha256
        )
        .unwrap_err()
        .code(),
        ErrorCode::PermissionDenied
    );
    assert!(guard.events.lock().unwrap().is_empty());
}

#[test]
fn guard_rechecks_every_use_and_finish_failure_reports_applied() {
    // Break caught: guarding only lease open, audit failure permitting private use, or hiding an already-used key.
    let selector = file("user-rsa-sign");
    let guard = Consent::new(vec![selector.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard.clone(),
        ResourceLimits::default(),
    );
    let mut ctx = begin(&engine, [selector.key_id()]);
    let password = synthetic("user-rsa-sign").password;
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(&password)), &mut ctx)
        .unwrap();
    let signature = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap();
    assert_signature("user-rsa-sign", SigAlg::RsaSha256, &signature);
    guard.consent.store(false, Ordering::SeqCst);
    let denied = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap_err();
    assert_eq!(denied.code(), ErrorCode::PermissionDenied);
    assert_eq!(denied.applied_state(), AppliedState::NotApplied);
    guard.consent.store(true, Ordering::SeqCst);
    guard.fail_before.store(true, Ordering::SeqCst);
    let error = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuditFailed);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(guard.outcomes.lock().unwrap().len(), 1);
    guard.fail_before.store(false, Ordering::SeqCst);
    guard.fail_finish.store(true, Ordering::SeqCst);
    let error = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuditFailed);
    assert_eq!(error.applied_state(), AppliedState::Applied);
    assert_eq!(
        guard.outcomes.lock().unwrap().last().unwrap().applied,
        AppliedState::Applied
    );
}

// A transparent transport probe. All transaction/reset/APDU behavior is delegated
// to the real emulator, including its holder/Condvar. No fake signature responses.
struct Probe {
    emu: Arc<EmulatorBackend>,
    armed: Arc<AtomicBool>,
    begins: mpsc::Sender<String>,
    lost_sign_reply: Arc<AtomicBool>,
}
struct ProbeConnection {
    inner: Box<dyn Connection>,
    reader: String,
    armed: Arc<AtomicBool>,
    begins: mpsc::Sender<String>,
    lost_sign_reply: Arc<AtomicBool>,
}
impl Backend for Probe {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        self.emu.readers()
    }
    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        Ok(Box::new(ProbeConnection {
            inner: self.emu.connect(reader)?,
            reader: reader.to_owned(),
            armed: self.armed.clone(),
            begins: self.begins.clone(),
            lost_sign_reply: self.lost_sign_reply.clone(),
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
            let _ = self.begins.send(self.reader.clone());
        }
        self.inner.begin_transaction()
    }
    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.inner.end_transaction()
    }
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        let response = self.inner.transmit(apdu)?;
        if apdu.starts_with(&[0x00, 0x2A, 0x9E, 0x9A])
            && self.lost_sign_reply.swap(false, Ordering::SeqCst)
        {
            // The card REALLY signed, but the caller cannot know whether the command applied.
            return Err(BackendError::Failed(
                "synthetic response lost after real PSO".to_owned(),
            ));
        }
        Ok(response)
    }
    fn reset_on_disconnect(&mut self) {
        self.inner.reset_on_disconnect();
    }
}
struct Rig {
    emu: Arc<EmulatorBackend>,
    tokens: Arc<Tokens>,
    gates: Arc<TokenGateRegistry>,
    armed: Arc<AtomicBool>,
    begins: mpsc::Receiver<String>,
    lost_sign_reply: Arc<AtomicBool>,
}
impl Rig {
    fn new(waiters: usize) -> Self {
        let emu = Arc::new(EmulatorBackend::new());
        for reader in [READER_A, READER_B] {
            emu.add_reader(reader);
            let keys = ["user-rsa-sign", "user-gost2004-sign"]
                .into_iter()
                .map(|name| EmuKey { entry: entry(name) })
                .collect();
            let mut spec = CardSpec::new(TokenKind::Kaztoken, PIN, keys);
            spec.fixed_k = Some(vec![1; 16]);
            emu.insert(reader, card(spec));
        }
        let armed = Arc::new(AtomicBool::new(false));
        let (send, begins) = mpsc::channel();
        let lost_sign_reply = Arc::new(AtomicBool::new(false));
        let tokens = Tokens::new(
            Arc::new(Probe {
                emu: emu.clone(),
                armed: armed.clone(),
                begins: send,
                lost_sign_reply: lost_sign_reply.clone(),
            }),
            true,
        );
        Self {
            emu,
            tokens,
            gates: Arc::new(TokenGateRegistry::new(2, waiters).unwrap()),
            armed,
            begins,
            lost_sign_reply,
        }
    }
    fn selector(&self, reader: &str, name: &str) -> KeySelector {
        KeySelector::token(
            TokenDeviceId::new(reader).unwrap(),
            TokenKind::Kaztoken,
            synthetic(name).aliases[0].clone(),
        )
    }
    fn engine(&self, ids: Vec<KeyId>, limits: ResourceLimits) -> (Arc<Engine>, Arc<Consent>) {
        let guard = Consent::new(ids);
        let provider = KeySources::new().with_tokens(self.tokens.clone(), self.gates.clone());
        (engine(Arc::new(provider), guard.clone(), limits), guard)
    }
    fn arm(&self) {
        self.emu.clear_exchanges(READER_A);
        self.emu.clear_exchanges(READER_B);
        self.armed.store(true, Ordering::SeqCst);
    }
}
struct Job {
    go: mpsc::Sender<()>,
    result: mpsc::Receiver<Result<Vec<u8>, OperationError>>,
    join: thread::JoinHandle<()>,
}
// Open while no foreign transaction exists, then retain owned context+reservation
// in the real worker. The controller can independently time out its response wait.
fn job(engine: Arc<Engine>, selector: KeySelector, ctx: OperationContext, alg: SigAlg) -> Job {
    secret_job(engine, selector, ctx, alg, PIN.to_owned())
}
fn secret_job(
    engine: Arc<Engine>,
    selector: KeySelector,
    ctx: OperationContext,
    alg: SigAlg,
    secret: String,
) -> Job {
    let (ready_send, ready) = mpsc::sync_channel(0);
    let (go, start) = mpsc::channel();
    let (done, result) = mpsc::channel();
    let join = thread::spawn(move || {
        let mut ctx = ctx;
        let _reservation = ctx.resources().reserve_memory(4096).unwrap();
        let mut signer = engine
            .signer(&KeyRequest::new(&selector, Some(&secret)), &mut ctx)
            .unwrap();
        ready_send.send(()).unwrap();
        start.recv().unwrap();
        let result = signer.sign_digest(&digest(alg.hash_alg()));
        drop(signer);
        drop(ctx);
        done.send(result).unwrap();
    });
    ready
        .recv_timeout(WATCHDOG)
        .expect("worker opened the real token");
    Job { go, result, join }
}
fn finish(job: Job, name: &str, alg: SigAlg) {
    let signature = job.result.recv_timeout(WATCHDOG).unwrap().unwrap();
    job.join.join().unwrap();
    assert_signature(name, alg, &signature);
}

#[test]
fn same_device_two_keys_serialized() {
    // Break caught: key-based (rather than physical-reader) admission, or unbounded native begin threads.
    // With zero waiting slots a second key must be rejected, not enter native begin.
    let rig = Rig::new(0);
    let rsa = rig.selector(READER_A, "user-rsa-sign");
    let gost = rig.selector(READER_A, "user-gost2004-sign");
    let limits = ResourceLimits {
        max_in_flight: 3,
        ..ResourceLimits::default()
    };
    let (engine, _) = rig.engine(vec![rsa.key_id(), gost.key_id()], limits);
    let first = job(
        engine.clone(),
        rsa.clone(),
        begin(&engine, [rsa.key_id()]),
        SigAlg::RsaSha256,
    );
    let second = job(
        engine.clone(),
        gost.clone(),
        begin(&engine, [gost.key_id()]),
        SigAlg::Gost2004,
    );
    let foreign = rig.emu.foreign_transaction(READER_A);
    rig.arm();
    first.go.send(()).unwrap();
    assert_eq!(rig.begins.recv_timeout(WATCHDOG).unwrap(), READER_A);
    second.go.send(()).unwrap();
    let error = second.result.recv_timeout(WATCHDOG).unwrap().unwrap_err();
    second.join.join().unwrap();
    assert_eq!(error.code(), ErrorCode::CapacityExceeded);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(rig.begins.try_recv().is_err());
    assert!(rig.emu.exchanges(READER_A).is_empty());
    drop(foreign);
    finish(first, "user-rsa-sign", SigAlg::RsaSha256);
    let mut ctx = begin(&engine, [gost.key_id()]);
    assert_signature(
        "user-gost2004-sign",
        SigAlg::Gost2004,
        &sign(&engine, &mut ctx, &gost, Some(PIN), SigAlg::Gost2004).unwrap(),
    );
}

#[test]
fn distinct_devices_not_globally_locked() {
    // Break caught: one global token/software lock that stalls unrelated work behind blocked PC/SC.
    let rig = Rig::new(1);
    let a = rig.selector(READER_A, "user-rsa-sign");
    let b = rig.selector(READER_B, "user-gost2004-sign");
    let software = file("user-rsa-sign");
    let limits = ResourceLimits {
        max_in_flight: 3,
        ..ResourceLimits::default()
    };
    let (engine, _) = rig.engine(vec![a.key_id(), b.key_id(), software.key_id()], limits);
    let first = job(
        engine.clone(),
        a.clone(),
        begin(&engine, [a.key_id()]),
        SigAlg::RsaSha256,
    );
    let second = job(
        engine.clone(),
        b.clone(),
        begin(&engine, [b.key_id()]),
        SigAlg::Gost2004,
    );
    let foreign = rig.emu.foreign_transaction(READER_A);
    rig.arm();
    first.go.send(()).unwrap();
    assert_eq!(rig.begins.recv_timeout(WATCHDOG).unwrap(), READER_A);
    second.go.send(()).unwrap();
    finish(second, "user-gost2004-sign", SigAlg::Gost2004); // completes while A is still held
    let password = synthetic("user-rsa-sign").password;
    let software_ctx = begin(&engine, [software.key_id()]);
    let software_work = secret_job(
        engine.clone(),
        software,
        software_ctx,
        SigAlg::RsaSha256,
        password,
    );
    software_work.go.send(()).unwrap();
    finish(software_work, "user-rsa-sign", SigAlg::RsaSha256);
    assert!(rig.emu.exchanges(READER_A).is_empty());
    drop(foreign);
    finish(first, "user-rsa-sign", SigAlg::RsaSha256);
}

#[test]
fn token_wait_deadline_sends_no_apdu() {
    // Break caught: entering PC/SC while a bounded device slot is occupied, or restarting the deadline at the gate.
    let rig = Rig::new(1);
    let a = rig.selector(READER_A, "user-rsa-sign");
    let b = rig.selector(READER_A, "user-gost2004-sign");
    let limits = ResourceLimits {
        max_in_flight: 2,
        ..ResourceLimits::default()
    };
    let (engine, guard) = rig.engine(vec![a.key_id(), b.key_id()], limits);
    let first = job(
        engine.clone(),
        a.clone(),
        begin(&engine, [a.key_id()]),
        SigAlg::RsaSha256,
    );
    // A separate engine supplies the shorter end-to-end timeout; both share the same device registry.
    let short = ResourceLimits {
        operation_timeout: Duration::from_secs(2),
        ..ResourceLimits::default()
    };
    let (short_engine, _) = rig.engine(vec![b.key_id()], short);
    let second = job(
        short_engine.clone(),
        b.clone(),
        begin(&short_engine, [b.key_id()]),
        SigAlg::Gost2004,
    );
    let foreign = rig.emu.foreign_transaction(READER_A);
    rig.arm();
    first.go.send(()).unwrap();
    assert_eq!(rig.begins.recv_timeout(WATCHDOG).unwrap(), READER_A);
    second.go.send(()).unwrap();
    let error = second.result.recv_timeout(WATCHDOG).unwrap().unwrap_err();
    second.join.join().unwrap();
    assert_eq!(error.code(), ErrorCode::DeadlineExceeded);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(rig.begins.try_recv().is_err());
    assert!(rig.emu.exchanges(READER_A).is_empty());
    drop(foreign);
    finish(first, "user-rsa-sign", SigAlg::RsaSha256);
    assert_eq!(
        guard.outcomes.lock().unwrap().last().unwrap().applied,
        AppliedState::Applied
    );
}

#[test]
fn blocked_native_transaction_keeps_reservation() {
    // Break caught: declaring SCardBeginTransaction interrupted, releasing admission early,
    // or sending a PIN/sign command after the blocked call returns beyond the deadline.
    let rig = Rig::new(0);
    let selector = rig.selector(READER_A, "user-rsa-sign");
    let limits = ResourceLimits {
        operation_timeout: Duration::from_secs(2),
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let guard = Consent::new(vec![selector.key_id()]);
    let provider = KeySources::new().with_tokens(rig.tokens.clone(), rig.gates.clone());
    let engine = Arc::new(
        Engine::new(
            EngineServices::hash_only(limits)
                .with_shared_budget(budget)
                .with_keys(Arc::new(provider), guard)
                .with_validation(validation_services()),
        )
        .unwrap(),
    );
    let ctx = begin(&engine, [selector.key_id()]);
    let deadline = ctx.deadline();
    let work = job(engine.clone(), selector.clone(), ctx, SigAlg::RsaSha256);
    let foreign = rig.emu.foreign_transaction(READER_A);
    rig.arm();
    work.go.send(()).unwrap();
    assert_eq!(rig.begins.recv_timeout(WATCHDOG).unwrap(), READER_A);
    // This is a caller wait timeout, NOT an invented completion/error from the native worker.
    assert!(matches!(
        work.result.recv_timeout(deadline.remaining()),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(deadline.is_expired());
    assert_eq!(
        engine
            .begin(
                grant([selector.key_id()]),
                policy(),
                Arc::new(Control::default())
            )
            .unwrap_err()
            .code(),
        ErrorCode::CapacityExceeded
    );
    assert!(rig.emu.exchanges(READER_A).is_empty());
    // A different root budget must still see the occupied physical-device slot.
    let (other, _) = rig.engine(vec![selector.key_id()], ResourceLimits::default());
    let mut other_ctx = begin(&other, [selector.key_id()]);
    let error = sign(
        &other,
        &mut other_ctx,
        &selector,
        Some(PIN),
        SigAlg::RsaSha256,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CapacityExceeded);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(rig.begins.try_recv().is_err());
    drop(other_ctx);
    drop(foreign);
    let error = work.result.recv_timeout(WATCHDOG).unwrap().unwrap_err();
    work.join.join().unwrap();
    assert_eq!(error.code(), ErrorCode::DeadlineExceeded);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(
        rig.emu.exchanges(READER_A).is_empty(),
        "no SELECT/PIN/sign after expired native begin"
    );
    let mut next = begin(&engine, [selector.key_id()]);
    assert_signature(
        "user-rsa-sign",
        SigAlg::RsaSha256,
        &sign(&engine, &mut next, &selector, Some(PIN), SigAlg::RsaSha256).unwrap(),
    );
}

#[test]
fn token_consent_denial_sends_no_private_command_and_no_signature() {
    // Break caught: consent checked only at token unlock instead of every private use.
    let rig = Rig::new(1);
    let selector = rig.selector(READER_A, "user-rsa-sign");
    let (engine, guard) = rig.engine(vec![selector.key_id()], ResourceLimits::default());
    let mut ctx = begin(&engine, [selector.key_id()]);
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(PIN)), &mut ctx)
        .unwrap();
    rig.arm();
    guard.consent.store(false, Ordering::SeqCst);
    let error = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(rig.emu.exchanges(READER_A).is_empty());
    assert!(rig.begins.try_recv().is_err());
    guard.consent.store(true, Ordering::SeqCst);
    guard.fail_before.store(true, Ordering::SeqCst);
    let audit_error = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap_err();
    assert_eq!(audit_error.code(), ErrorCode::AuditFailed);
    assert_eq!(audit_error.applied_state(), AppliedState::NotApplied);
    assert!(
        rig.emu.exchanges(READER_A).is_empty(),
        "audit failure must precede private use"
    );
    assert!(rig.begins.try_recv().is_err());
    guard.fail_before.store(false, Ordering::SeqCst);
    assert_signature(
        "user-rsa-sign",
        SigAlg::RsaSha256,
        &signer.sign_digest(&digest(HashAlg::Sha256)).unwrap(),
    );
}

#[test]
fn cancelled_operation_never_reuses_unlocked_token() {
    // Break caught: an already-open lease bypassing operation control on subsequent private use.
    let rig = Rig::new(1);
    let selector = rig.selector(READER_A, "user-rsa-sign");
    let (engine, _) = rig.engine(vec![selector.key_id()], ResourceLimits::default());
    let control = Arc::new(Control::default());
    let mut ctx = engine
        .begin(grant([selector.key_id()]), policy(), control.clone())
        .unwrap();
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(PIN)), &mut ctx)
        .unwrap();
    rig.arm();
    control.cancelled.store(true, Ordering::SeqCst);
    let error = signer.sign_digest(&digest(HashAlg::Sha256)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::Cancelled);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(rig.emu.exchanges(READER_A).is_empty());
    assert!(rig.begins.try_recv().is_err());
}

#[test]
fn token_lost_sign_response_reports_unknown_not_not_applied() {
    // Break caught: transport failure after dispatch reported as no private-key use.
    let rig = Rig::new(1);
    let selector = rig.selector(READER_A, "user-gost2004-sign");
    let (engine, guard) = rig.engine(vec![selector.key_id()], ResourceLimits::default());
    let mut ctx = begin(&engine, [selector.key_id()]);
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(PIN)), &mut ctx)
        .unwrap();
    rig.arm();
    rig.lost_sign_reply.store(true, Ordering::SeqCst);
    let error = signer.sign_digest(&digest(HashAlg::Gost34311)).unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::Unknown);
    assert_eq!(
        guard.outcomes.lock().unwrap().last().unwrap().applied,
        AppliedState::Unknown
    );
    let exchanges = rig.emu.exchanges(READER_A);
    let actual = exchanges
        .iter()
        .find(|exchange| exchange.command.starts_with(&[0x00, 0x2A, 0x9E, 0x9A]))
        .expect("actual private command reached the card");
    assert_eq!(&actual.response[actual.response.len() - 2..], &[0x90, 0x00]);
    assert_signature(
        "user-gost2004-sign",
        SigAlg::Gost2004,
        &actual.response[..actual.response.len() - 2],
    );
}

#[test]
fn token_lease_dies_with_operation_and_pin_is_reacquired() {
    // Break caught: retaining an OpenToken/PIN in the provider after its owning operation ends.
    let rig = Rig::new(1);
    let selector = rig.selector(READER_A, "user-rsa-sign");
    let (engine, _) = rig.engine(vec![selector.key_id()], ResourceLimits::default());
    {
        let mut ctx = begin(&engine, [selector.key_id()]);
        assert_signature(
            "user-rsa-sign",
            SigAlg::RsaSha256,
            &sign(&engine, &mut ctx, &selector, Some(PIN), SigAlg::RsaSha256).unwrap(),
        );
    }
    rig.arm();
    let mut next = begin(&engine, [selector.key_id()]);
    assert_eq!(
        sign(&engine, &mut next, &selector, None, SigAlg::RsaSha256)
            .unwrap_err()
            .code(),
        ErrorCode::SecretRequired
    );
    assert!(rig.emu.exchanges(READER_A).is_empty());
    assert!(rig.begins.try_recv().is_err());
    assert_signature(
        "user-rsa-sign",
        SigAlg::RsaSha256,
        &sign(&engine, &mut next, &selector, Some(PIN), SigAlg::RsaSha256).unwrap(),
    );
}

#[test]
fn file_and_inline_jks_resolve_exact_alias_and_verify() {
    // Break caught: treating every source as PKCS#12 or selecting the first key despite a bad alias.
    // Reissue only the certificate field in a private test copy; encrypted key,
    // JKS layout and exact aliases remain unchanged (no product JKS writer).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rsa.jks");
    let original = read(oncl_testkit::fixture("jks/rsa.jks"));
    let mut expected = oncl_pki::jks::load(&original, "Qwerty12")
        .unwrap()
        .remove(0);
    let old = expected.cert.to_der().unwrap();
    expected = reissue(expected);
    let new = expected.cert.to_der().unwrap();
    let at = original.windows(old.len()).position(|w| w == old).unwrap();
    let mut bytes = original[..at - 4].to_vec();
    bytes.extend((new.len() as u32).to_be_bytes());
    bytes.extend(new);
    bytes.extend_from_slice(&original[at + old.len()..original.len() - 20]);
    let mut integrity = HashState::new(HashAlg::Sha1);
    for unit in "Qwerty12".encode_utf16() {
        integrity.update(&unit.to_be_bytes());
    }
    integrity.update(b"Mighty Aphrodite");
    integrity.update(&bytes);
    bytes.extend(integrity.finish().as_bytes());
    std::fs::write(&path, &bytes).unwrap();
    let file = KeySelector::file(path.clone(), Some("openncalayer-rsa".to_owned())).unwrap();
    let inline = KeySelector::inline(bytes, Some("openncalayer-rsa".to_owned()));
    let bad = KeySelector::file(path, Some("not-a-key-alias".to_owned())).unwrap();
    let guard = Consent::new(vec![file.key_id(), inline.key_id(), bad.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard,
        ResourceLimits::default(),
    );
    let mut ctx = begin(&engine, [file.key_id(), inline.key_id(), bad.key_id()]);
    for selector in [&file, &inline] {
        let signature = sign(
            &engine,
            &mut ctx,
            selector,
            Some("Qwerty12"),
            SigAlg::RsaSha256,
        )
        .unwrap();
        expected
            .key
            .public_key()
            .verify(SigAlg::RsaSha256, MESSAGE, &signature)
            .unwrap();
    }
    let error = sign(&engine, &mut ctx, &bad, Some("Qwerty12"), SigAlg::RsaSha256).unwrap_err();
    assert_eq!(error.code(), ErrorCode::KeyNotFound);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
}

#[test]
fn direct_provider_open_cannot_bypass_key_grant() {
    // Break caught: callers using the prescribed KeyProvider::open interface bypassing Engine admission.
    let a = file("user-rsa-sign");
    let b = file("user-gost2004-sign");
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = begin(&engine, [a.key_id()]);
    let error = match KeySources::new().open(
        &KeyRequest::new(&b, Some("never inspect this secret")),
        &mut ctx,
    ) {
        Err(error) => error,
        Ok(_) => panic!("key-B must be denied"),
    };
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
}

#[test]
fn compatibility_issuer_selection_requires_explicit_policy_and_cannot_use_wrong_key() {
    // Break caught: silently changing legacy issuer-OID selection, or applying it to strict operations.
    let mut rsa = entry("user-rsa-sign");
    let issuer = cross_issuer();
    rsa.cert = cross_leaf(&rsa, &issuer);
    let id = KeyId::new("explicit-compatibility-rsa").unwrap();
    let selector = KeySelector::named(id.clone());
    let guard = Consent::new(vec![id.clone()]);
    let engine = engine(
        Arc::new(CrossSigned {
            entry: rsa,
            id: id.clone(),
        }),
        guard.clone(),
        ResourceLimits::default(),
    );
    let mut compatibility = OperationPolicy::ncalayer_compatibility();
    compatibility.allow_prehashed = true;
    let mut ctx = engine
        .begin(
            grant([id.clone()]),
            compatibility,
            Arc::new(Control::default()),
        )
        .unwrap();
    let error = sign(&engine, &mut ctx, &selector, None, SigAlg::RsaSha256).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsupportedAlgorithm);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(guard.events.lock().unwrap().is_empty());
    drop(ctx);
    let mut strict = begin(&engine, [id]);
    assert_signature(
        "user-rsa-sign",
        SigAlg::RsaSha256,
        &sign(&engine, &mut strict, &selector, None, SigAlg::RsaSha256).unwrap(),
    );
}

#[test]
fn foreign_token_key_denied_without_unlock_or_apdu() {
    // Break caught: a grant for one token alias opening/signing another alias before permission checks.
    let rig = Rig::new(1);
    let a = rig.selector(READER_A, "user-rsa-sign");
    let b = rig.selector(READER_A, "user-gost2004-sign");
    let (engine, guard) = rig.engine(vec![a.key_id(), b.key_id()], ResourceLimits::default());
    let mut ctx = begin(&engine, [a.key_id()]);
    rig.arm();
    let error = sign(&engine, &mut ctx, &b, Some(PIN), SigAlg::Gost2004).unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(rig.emu.exchanges(READER_A).is_empty());
    assert!(rig.begins.try_recv().is_err());
    assert!(guard.events.lock().unwrap().is_empty());
}

#[test]
fn token_prehash_profiles_verify_real_emulator_signatures() {
    // Break caught: an unimplemented token prehash branch, double hashing, or wrong GOST signature encoding.
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER_A);
    let names = ["user-gost2004-sign", "user-gost2015-sign", "user-rsa-sign"];
    let keys = names
        .iter()
        .map(|name| EmuKey { entry: entry(name) })
        .collect();
    let mut spec = CardSpec::new(TokenKind::Kaztoken, PIN, keys);
    spec.fixed_k = Some(vec![1; 16]);
    emu.insert(READER_A, card(spec));
    let selectors: Vec<_> = names
        .iter()
        .map(|name| {
            KeySelector::token(
                TokenDeviceId::new(READER_A).unwrap(),
                TokenKind::Kaztoken,
                synthetic(name).aliases[0].clone(),
            )
        })
        .collect();
    let ids: Vec<_> = selectors.iter().map(KeySelector::key_id).collect();
    let guard = Consent::new(ids.clone());
    let provider = KeySources::new().with_tokens(
        Tokens::new(emu.clone(), true),
        Arc::new(TokenGateRegistry::new(1, 1).unwrap()),
    );
    let engine = engine(Arc::new(provider), guard, ResourceLimits::default());
    let mut ctx = begin(&engine, ids);
    for ((name, selector), alg) in names.iter().zip(&selectors).zip([
        SigAlg::Gost2004,
        SigAlg::Gost2015_512,
        SigAlg::RsaSha256,
    ]) {
        assert_signature(
            name,
            alg,
            &sign(&engine, &mut ctx, selector, Some(PIN), alg).unwrap(),
        );
    }
    assert!(
        emu.exchanges(READER_A)
            .iter()
            .any(|exchange| exchange.command.starts_with(&[0x00, 0x2A, 0x9E, 0x9A]))
    );
}

#[test]
fn format_digest_signer_cannot_bypass_guard() {
    // Break caught: AuthorizedSigner's low-level format trait delegating directly to the raw lease.
    let rig = Rig::new(1);
    let selector = rig.selector(READER_A, "user-rsa-sign");
    let (engine, guard) = rig.engine(vec![selector.key_id()], ResourceLimits::default());
    let mut ctx = begin(&engine, [selector.key_id()]);
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(PIN)), &mut ctx)
        .unwrap();
    rig.arm();
    guard.consent.store(false, Ordering::SeqCst);
    assert!(
        oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Sha256)).is_err()
    );
    assert!(rig.emu.exchanges(READER_A).is_empty());
    assert!(rig.begins.try_recv().is_err());
    guard.consent.store(true, Ordering::SeqCst);
    let signature =
        oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Sha256)).unwrap();
    assert_signature("user-rsa-sign", SigAlg::RsaSha256, &signature);
}

#[test]
fn format_trait_retains_supported_cause_and_application_state() {
    use oncl_pki::key::DigestSigner;
    let selector = file("user-rsa-sign");
    let guard = Consent::new(vec![selector.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard.clone(),
        ResourceLimits::default(),
    );
    let control = Arc::new(Control::default());
    let mut ctx = engine
        .begin(grant([selector.key_id()]), policy(), control.clone())
        .unwrap();
    let password = synthetic("user-rsa-sign").password;
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(&password)), &mut ctx)
        .unwrap();
    let hash = digest(HashAlg::Sha256);
    let error = OperationError::from(
        DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Gost34311)).unwrap_err(),
    );
    assert_eq!(error.code(), ErrorCode::UnsupportedAlgorithm);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    guard.consent.store(false, Ordering::SeqCst);
    let error = OperationError::from(DigestSigner::sign_digest(&mut signer, &hash).unwrap_err());
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    guard.consent.store(true, Ordering::SeqCst);
    control.cancelled.store(true, Ordering::SeqCst);
    let error = OperationError::from(DigestSigner::sign_digest(&mut signer, &hash).unwrap_err());
    assert_eq!(error.code(), ErrorCode::Cancelled);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    control.cancelled.store(false, Ordering::SeqCst);
    let signature = DigestSigner::sign_digest(&mut signer, &hash).unwrap();
    assert_signature("user-rsa-sign", SigAlg::RsaSha256, &signature);
    guard.fail_finish.store(true, Ordering::SeqCst);
    let error = OperationError::from(DigestSigner::sign_digest(&mut signer, &hash).unwrap_err());
    assert_eq!(error.code(), ErrorCode::AuditFailed);
    assert_eq!(error.applied_state(), AppliedState::Applied);
}

#[test]
fn format_trait_retains_unknown_after_real_lost_private_response() {
    let rig = Rig::new(1);
    let selector = rig.selector(READER_A, "user-gost2004-sign");
    let (engine, _) = rig.engine(vec![selector.key_id()], ResourceLimits::default());
    let mut ctx = begin(&engine, [selector.key_id()]);
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(PIN)), &mut ctx)
        .unwrap();
    rig.arm();
    rig.lost_sign_reply.store(true, Ordering::SeqCst);
    let error = OperationError::from(
        oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Gost34311))
            .unwrap_err(),
    );
    assert_eq!(error.code(), ErrorCode::KeyFailure);
    assert_eq!(error.applied_state(), AppliedState::Unknown);
    let exchanges = rig.emu.exchanges(READER_A);
    let actual = exchanges
        .iter()
        .find(|e| e.command.starts_with(&[0x00, 0x2A, 0x9E, 0x9A]))
        .unwrap();
    assert_signature(
        "user-gost2004-sign",
        SigAlg::Gost2004,
        &actual.response[..actual.response.len() - 2],
    );
}

#[test]
fn scoped_token_control_retains_memory_failure_before_apdu() {
    struct MemoryControl(AtomicBool);
    impl OperationControl for MemoryControl {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0.load(Ordering::SeqCst) {
                Err(ProcessingError::MemoryLimit)
            } else {
                Ok(())
            }
        }
    }
    struct AfterBegin {
        inner: Arc<EmulatorBackend>,
        control: Arc<MemoryControl>,
        began: Arc<AtomicUsize>,
    }
    struct AfterBeginConnection {
        inner: Box<dyn Connection>,
        control: Arc<MemoryControl>,
        began: Arc<AtomicUsize>,
    }
    impl Backend for AfterBegin {
        fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
            self.inner.readers()
        }
        fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
            Ok(Box::new(AfterBeginConnection {
                inner: self.inner.connect(reader)?,
                control: self.control.clone(),
                began: self.began.clone(),
            }))
        }
    }
    impl Connection for AfterBeginConnection {
        fn protocol(&self) -> Protocol {
            self.inner.protocol()
        }
        fn atr(&self) -> &[u8] {
            self.inner.atr()
        }
        fn begin_transaction(&mut self) -> Result<(), BackendError> {
            self.inner.begin_transaction()?;
            self.began.fetch_add(1, Ordering::SeqCst);
            self.control.0.store(true, Ordering::SeqCst);
            Ok(())
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
    }
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER_A);
    emu.insert(
        READER_A,
        card(CardSpec::new(
            TokenKind::Kaztoken,
            PIN,
            vec![EmuKey {
                entry: entry("user-rsa-sign"),
            }],
        )),
    );
    let control = Arc::new(MemoryControl(AtomicBool::new(false)));
    let began = Arc::new(AtomicUsize::new(0));
    let tokens = Tokens::new(
        Arc::new(AfterBegin {
            inner: emu.clone(),
            control: control.clone(),
            began: began.clone(),
        }),
        true,
    );
    let host = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = host
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            control,
        )
        .unwrap();
    let execution = oncl_token::execution::TokenExecution::new(
        TokenDeviceId::new(READER_A).unwrap(),
        ctx.lease(),
        ctx.resources().operation_control(),
        Arc::new(TokenGateRegistry::new(1, 1).unwrap()),
    );
    let error = tokens
        .open_scoped(READER_A, TokenKind::Kaztoken, PIN, execution)
        .unwrap_err();
    let oncl_token::TokenError::Execution(error) = error else {
        panic!("structured execution failure required")
    };
    let error = OperationError::from(oncl_pki::key::KeyError::Execution(error));
    assert_eq!(error.code(), ErrorCode::MemoryLimit);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(began.load(Ordering::SeqCst), 1);
    assert!(emu.exchanges(READER_A).is_empty());
}

#[test]
fn format_trait_retains_every_live_control_category_before_private_use() {
    // A real unlocked signer must not turn host resource enforcement into
    // generic Backend/InvalidInput or reach its private-use guard.
    struct ResourceControl(AtomicUsize);
    impl OperationControl for ResourceControl {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            let error = match self.0.load(Ordering::SeqCst) {
                0 => return Ok(()),
                1 => ProcessingError::Cancelled,
                2 => ProcessingError::DeadlineExceeded,
                3 => ProcessingError::CapacityExceeded,
                4 => ProcessingError::InputLimit,
                5 => ProcessingError::ContainerLimit,
                6 => ProcessingError::FramingLimit,
                7 => ProcessingError::OutputLimit,
                8 => ProcessingError::MemoryLimit,
                9 => ProcessingError::TempLimit,
                10 => ProcessingError::MetadataLimit,
                11 => ProcessingError::InvalidLimits,
                12 => ProcessingError::InvalidInput("host rejected the operation"),
                13 => ProcessingError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic control I/O refusal",
                )),
                _ => panic!("invalid test control mode"),
            };
            Err(error)
        }
    }
    let selector = file("user-rsa-sign");
    let guard = Consent::new(vec![selector.key_id()]);
    let engine = engine(
        Arc::new(KeySources::new()),
        guard.clone(),
        ResourceLimits::default(),
    );
    let control = Arc::new(ResourceControl(AtomicUsize::new(0)));
    let mut ctx = engine
        .begin(grant([selector.key_id()]), policy(), control.clone())
        .unwrap();
    let password = synthetic("user-rsa-sign").password;
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(&password)), &mut ctx)
        .unwrap();
    for (mode, expected) in [
        (1, ErrorCode::Cancelled),
        (2, ErrorCode::DeadlineExceeded),
        (3, ErrorCode::CapacityExceeded),
        (4, ErrorCode::InputLimit),
        (5, ErrorCode::ContainerLimit),
        (6, ErrorCode::FramingLimit),
        (7, ErrorCode::OutputLimit),
        (8, ErrorCode::MemoryLimit),
        (9, ErrorCode::TempLimit),
        (10, ErrorCode::MetadataLimit),
        (11, ErrorCode::InvalidInput),
        (12, ErrorCode::InvalidInput),
        (13, ErrorCode::Io),
    ] {
        control.0.store(mode, Ordering::SeqCst);
        let error = OperationError::from(
            oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Sha256))
                .unwrap_err(),
        );
        assert_eq!(error.code(), expected, "live control mode {mode}");
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert!(
            guard.events.lock().unwrap().is_empty(),
            "control refusal precedes private-use guard"
        );
    }
    control.0.store(0, Ordering::SeqCst);
    let signature =
        oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Sha256)).unwrap();
    assert_signature("user-rsa-sign", SigAlg::RsaSha256, &signature);
    assert_eq!(
        guard.outcomes.lock().unwrap().last().unwrap().applied,
        AppliedState::Applied
    );
}

#[test]
fn format_trait_retains_original_key_payload_and_outer_actual_application() {
    // Real signing followed by nested host-finalization failure must preserve
    // the key cause/payload with the OUTER known Applied state.
    struct KeyFailureGuard {
        inner: Arc<Consent>,
        fail: AtomicBool,
    }
    impl KeyUseGuard for KeyFailureGuard {
        fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
            self.inner.before_use(event)
        }
        fn finish(
            &self,
            receipt: KeyUseReceipt,
            outcome: KeyUseOutcome,
        ) -> Result<(), OperationError> {
            self.inner.finish(receipt, outcome)?;
            if self.fail.load(Ordering::SeqCst) {
                Err(OperationError::AfterKeyUse {
                    source: Box::new(OperationError::Key(oncl_pki::key::KeyError::Malformed(
                        "synthetic audit record rejected".to_owned(),
                    ))),
                    applied: AppliedState::Unknown,
                })
            } else {
                Ok(())
            }
        }
    }
    let selector = file("user-rsa-sign");
    let consent = Consent::new(vec![selector.key_id()]);
    let guard = Arc::new(KeyFailureGuard {
        inner: consent.clone(),
        fail: AtomicBool::new(false),
    });
    let engine = engine(
        Arc::new(KeySources::new()),
        guard.clone(),
        ResourceLimits::default(),
    );
    let mut ctx = begin(&engine, [selector.key_id()]);
    let password = synthetic("user-rsa-sign").password;
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(&password)), &mut ctx)
        .unwrap();
    let hash = digest(HashAlg::Sha256);
    let wrong_tag =
        oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Gost34311))
            .unwrap_err();
    assert_eq!(
        wrong_tag,
        oncl_pki::key::KeyError::UnsupportedAlgorithm,
        "original pre-use key category is retained"
    );
    let signature = oncl_pki::key::DigestSigner::sign_digest(&mut signer, &hash).unwrap();
    assert_signature("user-rsa-sign", SigAlg::RsaSha256, &signature);
    guard.fail.store(true, Ordering::SeqCst);
    let failure = oncl_pki::key::DigestSigner::sign_digest(&mut signer, &hash).unwrap_err();
    match &failure {
        oncl_pki::key::KeyError::WithAppliedState { source, applied } => {
            assert_eq!(*applied, AppliedState::Applied);
            assert_eq!(
                source.as_ref(),
                &oncl_pki::key::KeyError::Malformed("synthetic audit record rejected".to_owned())
            );
        }
        other => panic!("original key cause and application state required: {other:?}"),
    }
    let error = OperationError::from(failure);
    assert_eq!(error.code(), ErrorCode::KeyFailure);
    assert_eq!(error.applied_state(), AppliedState::Applied);
    assert_eq!(consent.outcomes.lock().unwrap().len(), 2);
    assert_eq!(
        consent.outcomes.lock().unwrap().last().unwrap().applied,
        AppliedState::Applied
    );
}

#[test]
fn scoped_private_transport_retains_known_pre_dispatch_failure() {
    // A structured resource refusal before the first private-stage dispatch is
    // not generic Backend/Unknown just because a surrounding wrapper was ready
    // to transmit. All other traffic still uses the real card/transactions.
    struct RefuseSetup {
        inner: Arc<EmulatorBackend>,
        refuse: Arc<AtomicBool>,
    }
    struct RefuseSetupConnection {
        inner: Box<dyn Connection>,
        refuse: Arc<AtomicBool>,
    }
    impl Backend for RefuseSetup {
        fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
            self.inner.readers()
        }
        fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
            Ok(Box::new(RefuseSetupConnection {
                inner: self.inner.connect(reader)?,
                refuse: self.refuse.clone(),
            }))
        }
    }
    impl Connection for RefuseSetupConnection {
        fn protocol(&self) -> Protocol {
            self.inner.protocol()
        }
        fn atr(&self) -> &[u8] {
            self.inner.atr()
        }
        fn begin_transaction(&mut self) -> Result<(), BackendError> {
            self.inner.begin_transaction()
        }
        fn end_transaction(&mut self) -> Result<(), BackendError> {
            self.inner.end_transaction()
        }
        fn reset_on_disconnect(&mut self) {
            self.inner.reset_on_disconnect();
        }
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
            if apdu.starts_with(&[0x00, 0x22, 0x41, 0xB6])
                && self.refuse.swap(false, Ordering::SeqCst)
            {
                return Err(BackendError::Execution(oncl_pki::key::KeyExecutionError {
                    kind: oncl_pki::key::KeyFailureKind::TempLimit,
                    applied: AppliedState::NotApplied,
                }));
            }
            self.inner.transmit(apdu)
        }
    }
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER_A);
    emu.insert(
        READER_A,
        card(CardSpec::new(
            TokenKind::Kaztoken,
            PIN,
            vec![EmuKey {
                entry: entry("user-rsa-sign"),
            }],
        )),
    );
    let refuse = Arc::new(AtomicBool::new(false));
    let tokens = Tokens::new(
        Arc::new(RefuseSetup {
            inner: emu.clone(),
            refuse: refuse.clone(),
        }),
        true,
    );
    let selector = KeySelector::token(
        TokenDeviceId::new(READER_A).unwrap(),
        TokenKind::Kaztoken,
        synthetic("user-rsa-sign").aliases[0].clone(),
    );
    let guard = Consent::new(vec![selector.key_id()]);
    let provider =
        KeySources::new().with_tokens(tokens, Arc::new(TokenGateRegistry::new(1, 1).unwrap()));
    let engine = engine(Arc::new(provider), guard.clone(), ResourceLimits::default());
    let mut ctx = begin(&engine, [selector.key_id()]);
    let mut signer = engine
        .signer(&KeyRequest::new(&selector, Some(PIN)), &mut ctx)
        .unwrap();
    emu.clear_exchanges(READER_A);
    refuse.store(true, Ordering::SeqCst);
    let error = OperationError::from(
        oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Sha256))
            .unwrap_err(),
    );
    assert_eq!(error.code(), ErrorCode::TempLimit);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(
        guard.outcomes.lock().unwrap().last().unwrap().applied,
        AppliedState::NotApplied
    );
    assert!(
        !emu.exchanges(READER_A)
            .iter()
            .any(|exchange| exchange.command.starts_with(&[0x00, 0x2A, 0x9E, 0x9A])),
        "no private PSO reached the card"
    );
    let signature =
        oncl_pki::key::DigestSigner::sign_digest(&mut signer, &digest(HashAlg::Sha256)).unwrap();
    assert_signature("user-rsa-sign", SigAlg::RsaSha256, &signature);
}

// F03 migration: retained private test copies carry the same software/token keys,
// aliases and usages, but a real CA chain and deterministic status evidence.
const VALIDATION_NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
fn raw_entry(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    load(&read(f.path), &f.password).unwrap().remove(0)
}
fn reissue(mut key: KeyEntry) -> KeyEntry {
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&key.cert);
    let template =
        oncl_pki::testing::TestCertSpec::from_cert(&raw_entry("inter-user-gost2015-sign").cert);
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
    key.cert = oncl_pki::testing::issue_cert(&raw_entry("inter-gost2015.key"), spec);
    key
}
fn synthetic(name: &str) -> oncl_testkit::SyntheticKey {
    type Copies =
        std::collections::HashMap<String, (tempfile::TempDir, oncl_testkit::SyntheticKey)>;
    static COPIES: std::sync::LazyLock<Mutex<Copies>> =
        std::sync::LazyLock::new(|| Mutex::new(Copies::new()));
    let mut copies = COPIES.lock().unwrap();
    if let Some((_, fixture)) = copies.get(name) {
        return fixture.clone();
    }
    let mut fixture = oncl_testkit::synthetic(name);
    let entries = load(&read(&fixture.path), &fixture.password).unwrap();
    let output: Vec<_> = entries
        .into_iter()
        .map(reissue)
        .map(|entry| oncl_pki::pkcs12::WriteEntry {
            alias: entry.alias,
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        })
        .collect();
    let bytes = oncl_pki::pkcs12::write(
        &output,
        &[],
        &fixture.password,
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x53),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    fixture.path = dir.path().join("keys.p12");
    std::fs::write(&fixture.path, bytes).unwrap();
    copies.insert(name.to_owned(), (dir, fixture.clone()));
    fixture
}
fn cross_issuer() -> KeyEntry {
    let mut issuer = raw_entry("user-gost2004-sign");
    let mut spec =
        oncl_pki::testing::TestCertSpec::from_cert(&raw_entry("inter-gost2015.key").cert);
    let original = oncl_pki::testing::TestCertSpec::from_cert(&issuer.cert);
    spec.subject = original.subject;
    spec.public_key = original.public_key;
    spec.serial = vec![0x71, 0x03];
    issuer.cert = oncl_pki::testing::issue_cert(&raw_entry("root-gost2015.key"), spec);
    issuer
}
fn validation_services() -> oncl_core::ValidationServices {
    use oncl_pki::{
        cert,
        crl::MockCrl,
        http::{HttpTransport, RouteTransport},
        ocsp::MockOcsp,
        pkix::CaSet,
    };
    let now = VALIDATION_NOW;
    // This genuine responder is issued by the same known CA as every reissued leaf.
    let ocsp: Arc<dyn HttpTransport> =
        Arc::new(MockOcsp::new(raw_entry("ocsp-gost2015")).with_now(now));
    let root_crl: Arc<dyn HttpTransport> = Arc::new(
        MockCrl::new(raw_entry("root-gost2015.key"))
            .with_this_update(now - time::Duration::MINUTE)
            .next_update(Some(now + time::Duration::HOUR)),
    );
    let leaf_crl: Arc<dyn HttpTransport> = Arc::new(
        MockCrl::new(raw_entry("inter-gost2015.key"))
            .with_this_update(now - time::Duration::MINUTE)
            .next_update(Some(now + time::Duration::HOUR)),
    );
    oncl_core::ValidationServices::new(
        CaSet::new(vec![
            cert::parse(&oncl_testkit::synthetic_cert("root-gost2015")).unwrap(),
        ]),
        vec![raw_entry("inter-gost2015.key").cert, cross_issuer().cert],
        Arc::new(RouteTransport::new(vec![
            ("http://ocsp.synthetic.test".into(), ocsp),
            (
                "http://cross.synthetic.test".into(),
                Arc::new(MockOcsp::new(cross_responder()).with_now(now)),
            ),
            (
                "http://crl.synthetic.test/root-gost2015.crl".into(),
                root_crl,
            ),
            (
                "http://crl.synthetic.test/inter-gost2015.crl".into(),
                leaf_crl,
            ),
        ])),
        oncl_pki::validation::NetworkPolicy::only_endpoints([
            "http://ocsp.synthetic.test",
            "http://crl.synthetic.test",
            "http://cross.synthetic.test",
        ])
        .unwrap(),
        Arc::new(|| VALIDATION_NOW),
    )
}

fn cross_leaf(key: &KeyEntry, issuer: &KeyEntry) -> oncl_pki::cert::Certificate {
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&key.cert);
    let uri = b"http://cross.synthetic.test";
    let mut inner = vec![
        0x06,
        0x08,
        0x2b,
        0x06,
        0x01,
        0x05,
        0x05,
        0x07,
        0x30,
        0x01,
        0x86,
        uri.len() as u8,
    ];
    inner.extend(uri);
    let mut aia = vec![0x30, (inner.len() + 2) as u8, 0x30, inner.len() as u8];
    aia.extend(inner);
    for extension in &mut spec.extensions {
        if extension.extn_id.to_string() == "1.3.6.1.5.5.7.1.1" {
            extension.extn_value = der::asn1::OctetString::new(aia.clone()).unwrap();
        }
    }
    oncl_pki::testing::issue_cert(issuer, spec)
}

fn cross_responder() -> KeyEntry {
    let mut responder = raw_entry("ocsp-gost2015");
    responder.cert = oncl_pki::testing::issue_cert(
        &cross_issuer(),
        oncl_pki::testing::TestCertSpec::from_cert(&responder.cert),
    );
    responder
}
