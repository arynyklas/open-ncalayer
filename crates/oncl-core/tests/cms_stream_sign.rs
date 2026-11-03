//! C02 real Engine sign contract. NOTRUN: controller owns all checks.
use der::Encode;
use oncl_core::keys::{
    AppliedState, KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard, KeyUseOutcome,
    KeyUseReceipt,
};
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationContext, OperationError,
    OperationPolicy, SignRequest, ValidationServices,
};
use oncl_pki::{
    cms,
    digest::DigestValue,
    io::{Source, TemporaryStore},
    key::{HashAlg, SigAlg},
    pkcs12::{self, KeyEntry},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
};
use std::{
    io::{self, Cursor, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
const DATA: &[u8] = b"abc";
const NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
fn raw(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn issued(name: &str) -> KeyEntry {
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
fn selector(name: &str) -> KeySelector {
    key_selector(issued(name))
}
fn key_selector(entry: KeyEntry) -> KeySelector {
    // Only deterministic public synthetic fixtures are repackaged; no host/user key is exported.
    let bytes = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: entry.alias,
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        }],
        &[],
        "C02 synthetic",
        &pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x62),
    )
    .unwrap();
    KeySelector::inline(bytes, None)
}
fn validation() -> ValidationServices {
    validation_status(false)
}
fn validation_status(revoked: bool) -> ValidationServices {
    use oncl_pki::{
        crl::MockCrl,
        http::{HttpTransport, RouteTransport},
        ocsp::MockOcsp,
        pkix::CaSet,
        validation::NetworkPolicy,
    };
    let mut responder = MockOcsp::new(raw("ocsp-gost2015")).with_now(NOW);
    if revoked {
        let serial: String = issued("user-rsa-sign")
            .cert
            .tbs_certificate()
            .serial_number()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        responder = responder.status(
            &serial,
            oncl_pki::ocsp::CertStatus::Revoked {
                time: NOW - time::Duration::DAY,
                reason: None,
            },
        );
    }
    let ocsp: Arc<dyn HttpTransport> = Arc::new(responder);
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
#[derive(Default)]
struct Guard {
    events: Mutex<Vec<KeyUseEvent>>,
    outcomes: Mutex<Vec<KeyUseOutcome>>,
    finish_fail: AtomicBool,
    cancel_after: Mutex<Option<Arc<Control>>>,
    deny_after: AtomicUsize,
}
impl KeyUseGuard for Guard {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        let mut events = self.events.lock().unwrap();
        let limit = self.deny_after.load(Ordering::SeqCst);
        if limit != 0 && events.len() >= limit {
            return Err(OperationError::PermissionDenied);
        }
        events.push(event.clone());
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(&self, _: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        self.outcomes.lock().unwrap().push(outcome);
        if let Some(c) = &*self.cancel_after.lock().unwrap() {
            c.0.store(true, Ordering::SeqCst);
        }
        if self.finish_fail.load(Ordering::SeqCst) {
            Err(OperationError::AuditFailed)
        } else {
            Ok(())
        }
    }
}
fn engine(
    guard: Arc<Guard>,
    provider: KeySources,
    store: Option<TemporaryStore>,
    validate: bool,
) -> Engine {
    let mut services =
        EngineServices::hash_only(ResourceLimits::default()).with_keys(Arc::new(provider), guard);
    if validate {
        services = services.with_validation(validation());
    }
    if let Some(store) = store {
        services = services.with_temporary_store(store);
    }
    Engine::new(services).unwrap()
}
fn begin(
    engine: &Engine,
    key: &KeySelector,
    actions: &[Action],
    policy: OperationPolicy,
    control: Arc<Control>,
) -> OperationContext {
    engine
        .begin(
            ExecutionGrant::new(actions.iter().copied()).with_keys([key.key_id()]),
            policy,
            control,
        )
        .unwrap()
}
fn sign(
    engine: &Engine,
    key: &KeySelector,
    ctx: &mut OperationContext,
    output: &mut dyn Write,
) -> Result<oncl_core::OperationReport, OperationError> {
    engine.sign(
        SignRequest::raw_message(KeyRequest::new(key, Some("C02 synthetic"))),
        Source::sequential(&mut Cursor::new(DATA), None),
        output,
        ctx,
    )
}
#[test]
fn normal_message_sign_needs_only_sign_and_never_enables_prehash() {
    let key = selector("user-rsa-sign");
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), None, true);
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut out = vec![];
    let report = sign(&engine, &key, &mut ctx, &mut out).unwrap();
    raw("user-rsa-sign")
        .key
        .public_key()
        .verify(SigAlg::RsaSha256, DATA, &out)
        .unwrap();
    assert_eq!(report.bytes_in, 3);
    assert_eq!(report.bytes_out, out.len() as u64);
    assert!(!ctx.policy().allow_prehashed);
    assert_eq!(guard.events.lock().unwrap()[0].action, Action::Sign);
    assert_eq!(
        engine
            .signer(&KeyRequest::new(&key, None), &mut ctx)
            .err()
            .unwrap()
            .code(),
        ErrorCode::PermissionDenied
    );
}
#[test]
fn action_key_and_algorithm_denials_precede_private_use() {
    let key = selector("user-rsa-sign");
    let other = selector("user-gost2004-sign");
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), None, true);
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::SignDigest],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    assert_eq!(
        sign(&engine, &key, &mut ctx, &mut vec![])
            .unwrap_err()
            .applied_state(),
        AppliedState::NotApplied
    );
    drop(ctx);
    let mut ctx = begin(
        &engine,
        &other,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    assert_eq!(
        sign(&engine, &key, &mut ctx, &mut vec![])
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    drop(ctx);
    let mut policy = OperationPolicy::strict_online();
    policy.allowed_signature_algorithms = &[];
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::Sign],
        policy,
        Arc::new(Control::default()),
    );
    assert!(sign(&engine, &key, &mut ctx, &mut vec![]).is_err());
    assert!(guard.events.lock().unwrap().is_empty());
}
#[test]
fn supplied_hash_requires_explicit_privilege_and_rejects_equal_length_wrong_tag() {
    let key = selector("user-rsa-sign");
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), None, true);
    for allow in [false, true] {
        let mut policy = OperationPolicy::strict_online();
        policy.allow_prehashed = allow;
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::SignDigest],
            policy,
            Arc::new(Control::default()),
        );
        let wrong = DigestValue::from_bytes(HashAlg::Gost34311, &[0; 32]).unwrap();
        let request = SignRequest::raw_digest(KeyRequest::new(&key, Some("C02 synthetic")), wrong);
        let error = engine
            .sign(
                request,
                Source::sequential(&mut Cursor::new([]), Some(0)),
                &mut vec![],
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
    }
    assert!(guard.events.lock().unwrap().is_empty());
    assert!(DigestValue::from_bytes(HashAlg::Sha256, &[0; 31]).is_err());
}
#[test]
fn missing_validation_is_not_bypassed_by_offline_report() {
    let key = selector("user-rsa-sign");
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), None, false);
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::offline_report(),
        Arc::new(Control::default()),
    );
    let error = sign(&engine, &key, &mut ctx, &mut vec![]).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingValidationServices);
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(guard.events.lock().unwrap().is_empty());
}
struct BrokenWriter {
    prefix: Vec<u8>,
}
impl Write for BrokenWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.prefix.is_empty() {
            return Err(io::Error::other("C02 sink failure"));
        }
        self.prefix.push(bytes[0]);
        Ok(1)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_finish_and_post_key_cancel_errors_remain_applied() {
    for mode in 0..3 {
        let key = selector("user-rsa-sign");
        let guard = Arc::new(Guard::default());
        let control = Arc::new(Control::default());
        if mode == 1 {
            guard.finish_fail.store(true, Ordering::SeqCst);
        }
        if mode == 2 {
            *guard.cancel_after.lock().unwrap() = Some(control.clone());
        }
        let engine = engine(guard.clone(), KeySources::new(), None, true);
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            control,
        );
        let mut writer = BrokenWriter { prefix: vec![] };
        let error = sign(&engine, &key, &mut ctx, &mut writer).unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::Applied);
        assert_eq!(
            guard.outcomes.lock().unwrap()[0].applied,
            AppliedState::Applied
        );
        if mode == 0 {
            assert_eq!(writer.prefix.len(), 1);
        }
    }
}
#[cfg(feature = "tokens")]
#[test]
fn token_message_sign_uses_real_card_prehash_backend() {
    use oncl_token::{
        TokenKind, Tokens,
        emulator::{CardSpec, EmuKey, EmulatorBackend, card},
        execution::{TokenDeviceId, TokenGateRegistry},
    };
    for (name, alg) in [
        ("user-rsa-sign", SigAlg::RsaSha256),
        ("user-gost2004-sign", SigAlg::Gost2004),
        ("user-gost2015-sign", SigAlg::Gost2015_512),
    ] {
        let entry = issued(name);
        let alias = entry.alias.clone();
        let emu = Arc::new(EmulatorBackend::new());
        emu.add_reader("C02 reader");
        let mut spec = CardSpec::new(TokenKind::Kaztoken, "C02 synthetic", vec![EmuKey { entry }]);
        spec.fixed_k = Some(vec![1; 16]);
        emu.insert("C02 reader", card(spec));
        let key = KeySelector::token(
            TokenDeviceId::new("C02 reader").unwrap(),
            TokenKind::Kaztoken,
            alias,
        );
        let provider = KeySources::new().with_tokens(
            Tokens::new(emu.clone(), true),
            Arc::new(TokenGateRegistry::new(1, 1).unwrap()),
        );
        let guard = Arc::new(Guard::default());
        let engine = engine(guard.clone(), provider, None, true);
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut out = vec![];
        sign(&engine, &key, &mut ctx, &mut out).unwrap();
        raw(name).key.public_key().verify(alg, DATA, &out).unwrap();
        assert!(
            emu.exchanges("C02 reader")
                .iter()
                .any(|e| e.command.starts_with(&[0x00, 0x2a, 0x9e, 0x9a]))
        );
        assert_eq!(guard.events.lock().unwrap().len(), 1);
    }
}

#[test]
fn cosign_preserves_existing_signers() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let first = selector("user-rsa-sign");
    let second = selector("user-gost2004-sign");
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), Some(store), true);
    for attached in [true, false] {
        let mut ctx = begin(
            &engine,
            &first,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut original = vec![];
        engine
            .sign(
                SignRequest::cms_create(
                    vec![KeyRequest::new(&first, Some("C02 synthetic"))],
                    attached,
                ),
                Source::sequential(&mut Cursor::new(DATA), None),
                &mut original,
                &mut ctx,
            )
            .unwrap();
        drop(ctx);
        let old = signer_infos(&original);
        let mut ctx = begin(
            &engine,
            &second,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut output = vec![];
        let mut data = Cursor::new(DATA);
        let detached = (!attached).then(|| Source::sequential(&mut data, None));
        engine
            .sign(
                SignRequest::cms_add(
                    vec![KeyRequest::new(&second, Some("C02 synthetic"))],
                    detached,
                ),
                Source::sequential(&mut Cursor::new(&original), None),
                &mut output,
                &mut ctx,
            )
            .unwrap();
        drop(ctx);
        assert_eq!(
            cms::verify(&output, (!attached).then_some(DATA))
                .unwrap()
                .len(),
            2
        );
        let new = signer_infos(&output);
        for signer in &old {
            assert!(
                new.contains(signer),
                "old SignerInfo must be byte-preserved"
            );
        }
        for wrong in [None, Some(b"abd".as_slice())] {
            if attached {
                continue;
            }
            let before = guard.events.lock().unwrap().len();
            let mut ctx = begin(
                &engine,
                &second,
                &[Action::Sign],
                OperationPolicy::strict_online(),
                Arc::new(Control::default()),
            );
            let mut wrong_cursor = Cursor::new(wrong.unwrap_or_default());
            let source = wrong.map(|_| Source::sequential(&mut wrong_cursor, None));
            assert!(
                engine
                    .sign(
                        SignRequest::cms_add(
                            vec![KeyRequest::new(&second, Some("C02 synthetic"))],
                            source
                        ),
                        Source::sequential(&mut Cursor::new(&original), None),
                        &mut vec![],
                        &mut ctx
                    )
                    .is_err()
            );
            assert_eq!(guard.events.lock().unwrap().len(), before);
        }
        // Flip the actual old signature OCTET STRING rather than corrupting ASN.1 framing.
        let signature = signature_octets(&old[0]);
        let at = original
            .windows(signature.len())
            .position(|w| w == signature)
            .unwrap();
        let mut tampered = original.clone();
        tampered[at] ^= 1;
        let before = guard.events.lock().unwrap().len();
        let mut ctx = begin(
            &engine,
            &second,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut data = Cursor::new(DATA);
        let request = SignRequest::cms_add(
            vec![KeyRequest::new(&second, Some("C02 synthetic"))],
            (!attached).then(|| Source::sequential(&mut data, None)),
        );
        let error = engine
            .sign(
                request,
                Source::sequential(&mut Cursor::new(&tampered), None),
                &mut vec![],
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(guard.events.lock().unwrap().len(), before);
        drop(ctx);
        // Signed contentType value must agree with eContentType, even if its TLV remains well formed.
        let data_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
        ];
        let signer_at = original
            .windows(old[0].len())
            .position(|w| w == old[0])
            .unwrap();
        let value_at = old[0]
            .windows(data_oid.len())
            .position(|w| w == data_oid)
            .unwrap();
        let mut malformed = original.clone();
        malformed[signer_at + value_at + data_oid.len() - 1] = 2;
        let before = guard.events.lock().unwrap().len();
        let mut ctx = begin(
            &engine,
            &second,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut data = Cursor::new(DATA);
        let request = SignRequest::cms_add(
            vec![KeyRequest::new(&second, Some("C02 synthetic"))],
            (!attached).then(|| Source::sequential(&mut data, None)),
        );
        let error = engine
            .sign(
                request,
                Source::sequential(&mut Cursor::new(&malformed), None),
                &mut vec![],
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(guard.events.lock().unwrap().len(), before);
    }
}
fn children(bytes: &[u8]) -> Vec<Vec<u8>> {
    use der::{Decode, Reader, SliceReader, asn1::AnyRef};
    let any = AnyRef::from_der(bytes).unwrap();
    let mut r = SliceReader::new(any.value()).unwrap();
    let mut out = vec![];
    while !r.is_finished() {
        out.push(r.decode::<AnyRef<'_>>().unwrap().to_der().unwrap());
    }
    out
}
fn signer_infos(bytes: &[u8]) -> Vec<Vec<u8>> {
    let ci = children(bytes);
    let content = children(&ci[1]);
    let sd = children(&content[0]);
    children(sd.last().unwrap())
}
fn signature_octets(signer: &[u8]) -> Vec<u8> {
    use der::{Decode, asn1::AnyRef};
    let fields = children(signer);
    let signature = fields.iter().rev().find(|f| f[0] == 4).unwrap();
    AnyRef::from_der(signature).unwrap().value().to_vec()
}

#[test]
fn provided_sha256_is_explicitly_tagged_and_never_claims_document_consumption() {
    let bytes = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let key = selector("user-rsa-sign");
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), None, true);
    for allow in [false, true] {
        let mut policy = OperationPolicy::strict_online();
        policy.allow_prehashed = allow;
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::SignDigest],
            policy,
            Arc::new(Control::default()),
        );
        let mut out = vec![];
        let request = SignRequest::raw_digest(
            KeyRequest::new(&key, Some("C02 synthetic")),
            DigestValue::from_bytes(HashAlg::Sha256, &bytes).unwrap(),
        );
        let result = engine.sign(
            request,
            Source::sequential(&mut Cursor::new([]), Some(0)),
            &mut out,
            &mut ctx,
        );
        if allow {
            let report = result.unwrap();
            assert_eq!(report.bytes_in, 0);
            assert_eq!(report.provenance, oncl_core::SignProvenance::ProvidedDigest);
            raw("user-rsa-sign")
                .key
                .public_key()
                .verify(SigAlg::RsaSha256, DATA, &out)
                .unwrap();
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.code(), ErrorCode::PermissionDenied);
            assert_eq!(error.applied_state(), AppliedState::NotApplied);
            assert!(out.is_empty());
        }
    }
    assert_eq!(guard.events.lock().unwrap().len(), 1);
    assert_eq!(guard.events.lock().unwrap()[0].action, Action::SignDigest);
}

#[test]
fn partial_multi_signer_application_is_applied_error_and_never_publishable() {
    let first = selector("user-rsa-sign");
    let second = selector("user-gost2004-sign");
    let guard = Arc::new(Guard::default());
    guard.deny_after.store(1, Ordering::SeqCst);
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let engine = engine(guard.clone(), KeySources::new(), Some(store.clone()), true);
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([first.key_id(), second.key_id()]),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap();
    let mut artifact = store.stage(ctx.resources()).unwrap();
    let request = SignRequest::cms_create(
        vec![
            KeyRequest::new(&first, Some("C02 synthetic")),
            KeyRequest::new(&second, Some("C02 synthetic")),
        ],
        true,
    );
    let error = engine
        .sign_staged(
            request,
            Source::sequential(&mut Cursor::new(DATA), None),
            &mut artifact,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::Applied);
    assert_eq!(guard.events.lock().unwrap().len(), 1);
    assert_eq!(
        guard.outcomes.lock().unwrap()[0].applied,
        AppliedState::Applied
    );
    let destination = parent.path().join("partial.p7s");
    assert!(artifact.commit(&destination).is_err());
    assert!(!destination.exists());
}

#[test]
fn revoked_and_expired_leaves_fail_strict_private_validation_even_offline() {
    for expired in [false, true] {
        let mut entry = issued("user-rsa-sign");
        if expired {
            let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&entry.cert);
            spec.validity.not_after = spec.validity.not_before;
            entry.cert = oncl_pki::testing::issue_cert(&raw("inter-gost2015.key"), spec);
        }
        let key = key_selector(entry);
        for policy in [
            OperationPolicy::strict_online(),
            OperationPolicy::offline_report(),
        ] {
            let guard = Arc::new(Guard::default());
            let engine = Engine::new(
                EngineServices::hash_only(ResourceLimits::default())
                    .with_keys(Arc::new(KeySources::new()), guard.clone())
                    .with_validation(validation_status(!expired)),
            )
            .unwrap();
            let mut ctx = begin(
                &engine,
                &key,
                &[Action::Sign],
                policy,
                Arc::new(Control::default()),
            );
            let error = sign(&engine, &key, &mut ctx, &mut vec![]).unwrap_err();
            assert_eq!(error.code(), ErrorCode::ValidationRequired);
            assert_eq!(error.applied_state(), AppliedState::NotApplied);
            assert!(guard.events.lock().unwrap().is_empty());
        }
    }
}

fn indefinite_encoding(der: &[u8]) -> Vec<u8> {
    use der::{Decode, asn1::AnyRef};
    let any = AnyRef::from_der(der).unwrap();
    if der[0] & 0x20 != 0 {
        let mut output = vec![der[0], 0x80];
        for child in children(der) {
            output.extend(indefinite_encoding(&child));
        }
        output.extend([0, 0]);
        output
    } else if der[0] == 4 && any.value() == DATA {
        vec![0x24, 0x80, 4, 1, DATA[0], 4, 2, DATA[1], DATA[2], 0, 0]
    } else {
        der.to_vec()
    }
}
#[test]
fn add_preserves_ber_content_and_old_signer_info_bytes() {
    let first = selector("user-rsa-sign");
    let second = selector("user-gost2004-sign");
    let guard = Arc::new(Guard::default());
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let engine = engine(guard, KeySources::new(), Some(store), true);
    let original = {
        let mut ctx = begin(
            &engine,
            &first,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut output = vec![];
        engine
            .sign(
                SignRequest::cms_create(vec![KeyRequest::new(&first, Some("C02 synthetic"))], true),
                Source::sequential(&mut Cursor::new(DATA), None),
                &mut output,
                &mut ctx,
            )
            .unwrap();
        output
    };
    let old_signer = indefinite_encoding(&signer_infos(&original)[0]);
    let ci = children(&original);
    let explicit = children(&ci[1]);
    let signed = children(&explicit[0]);
    let old_encap = indefinite_encoding(&signed[2]);
    let original = indefinite_encoding(&original);
    assert_eq!(original[1], 0x80);
    cms::verify(&original, None).unwrap();
    let mut ctx = begin(
        &engine,
        &second,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut output = vec![];
    engine
        .sign(
            SignRequest::cms_add(vec![KeyRequest::new(&second, Some("C02 synthetic"))], None),
            Source::sequential(&mut Cursor::new(&original), None),
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(output[1], 0x80);
    assert!(
        output
            .windows(old_signer.len())
            .any(|window| window == old_signer)
    );
    assert!(
        output
            .windows(old_encap.len())
            .any(|window| window == old_encap)
    );
    assert_eq!(cms::verify(&output, None).unwrap().len(), 2);
}

#[test]
fn engine_staged_raw_output_uses_the_single_original_output_allowance() {
    let key = selector("user-rsa-sign");
    let guard = Arc::new(Guard::default());
    let expected = raw("user-rsa-sign")
        .key
        .sign(SigAlg::RsaSha256, DATA)
        .unwrap()
        .len() as u64;
    let limits = ResourceLimits {
        output_bytes: expected,
        ..ResourceLimits::default()
    };
    let engine = Engine::new(
        EngineServices::hash_only(limits)
            .with_keys(Arc::new(KeySources::new()), guard.clone())
            .with_validation(validation()),
    )
    .unwrap();
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut artifact = store.stage(ctx.resources()).unwrap();
    let report = engine
        .sign_staged(
            SignRequest::raw_message(KeyRequest::new(&key, Some("C02 synthetic"))),
            Source::sequential(&mut Cursor::new(DATA), None),
            &mut artifact,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.bytes_out, expected);
    assert_eq!(ctx.resources().progress().bytes_out, expected);
    let mut signature = vec![];
    artifact.copy_to(&mut signature).unwrap();
    assert_eq!(ctx.resources().progress().bytes_out, expected);
    raw("user-rsa-sign")
        .key
        .public_key()
        .verify(SigAlg::RsaSha256, DATA, &signature)
        .unwrap();
}

#[test]
fn probe_sized_detached_staged_create_completes_after_real_private_application() {
    // Exact probe source, not a guessed DER framing fixture or a fake signer.
    let document = b"C02 source-bound streaming signature: public synthetic acceptance document.\n"
        .repeat(257);
    let key = selector("user-rsa-sign");
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), None, true);
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut artifact = store.stage(ctx.resources()).unwrap();
    let result = engine.sign_staged(
        SignRequest::cms_create(vec![KeyRequest::new(&key, Some("C02 synthetic"))], false),
        Source::sequential(&mut Cursor::new(&document), None),
        &mut artifact,
        &mut ctx,
    );
    assert_eq!(guard.events.lock().unwrap().len(), 1);
    assert_eq!(
        guard.outcomes.lock().unwrap()[0].applied,
        AppliedState::Applied
    );
    assert!(
        result.is_ok(),
        "probe-sized detached source failed after real private application: {result:?}"
    );
    let report = result.unwrap();
    assert_eq!(report.applied, AppliedState::Applied);
    assert_eq!(report.bytes_in, document.len() as u64);
    assert_eq!(report.bytes_out, artifact.len());
    assert!(
        artifact.len() < document.len() as u64,
        "detached output contains metadata only"
    );
    let mut output = vec![];
    artifact.copy_to(&mut output).unwrap();
    assert_eq!(cms::verify(&output, Some(&document)).unwrap().len(), 1);
    let mut wrong = document.clone();
    wrong[0] ^= 1;
    assert!(cms::verify(&output, Some(&wrong)).is_err());
}

fn collision_entries(same_key: bool) -> (KeyEntry, KeyEntry) {
    let mut first = issued("user-rsa-sign");
    let mut second = issued(if same_key {
        "user-rsa-sign"
    } else {
        "user-gost2004-sign"
    });
    let mut first_spec = oncl_pki::testing::TestCertSpec::from_cert(&first.cert);
    first_spec.serial = vec![0x63, 0x02];
    let mut second_spec = oncl_pki::testing::TestCertSpec::from_cert(&second.cert);
    second_spec.serial = first_spec.serial.clone();
    if same_key {
        second_spec.subject =
            oncl_pki::testing::TestCertSpec::from_cert(&raw("user-gost2004-sign").cert).subject;
    }
    let issuer = raw("inter-gost2015.key");
    first.cert = oncl_pki::testing::issue_cert(&issuer, first_spec);
    second.cert = oncl_pki::testing::issue_cert(&issuer, second_spec);
    assert_eq!(
        first.cert.tbs_certificate().issuer(),
        second.cert.tbs_certificate().issuer()
    );
    assert_eq!(
        first.cert.tbs_certificate().serial_number(),
        second.cert.tbs_certificate().serial_number()
    );
    assert_ne!(first.cert.to_der().unwrap(), second.cert.to_der().unwrap());
    assert_eq!(first.key.public_key() == second.key.public_key(), same_key);
    (first, second)
}

#[test]
fn create_and_add_reject_conflicting_certificate_union_before_any_new_guard_use() {
    for same_key in [false, true] {
        for add in [false, true] {
            let (first_entry, second_entry) = collision_entries(same_key);
            let old_certificate = first_entry.cert.to_der().unwrap();
            let first = key_selector(first_entry);
            let second = key_selector(second_entry);
            let guard = Arc::new(Guard::default());
            let parent = tempfile::tempdir().unwrap();
            let store = TemporaryStore::new(parent.path()).unwrap();
            let engine = engine(guard.clone(), KeySources::new(), Some(store.clone()), true);
            let mut original = vec![];
            if add {
                let mut ctx = begin(
                    &engine,
                    &first,
                    &[Action::Sign],
                    OperationPolicy::strict_online(),
                    Arc::new(Control::default()),
                );
                engine
                    .sign(
                        SignRequest::cms_create(
                            vec![KeyRequest::new(&first, Some("C02 synthetic"))],
                            true,
                        ),
                        Source::sequential(&mut Cursor::new(DATA), None),
                        &mut original,
                        &mut ctx,
                    )
                    .unwrap();
                assert_eq!(
                    cms::verify(&original, None).unwrap()[0]
                        .cert
                        .to_der()
                        .unwrap(),
                    old_certificate
                );
            }
            let old_signers = add.then(|| signer_infos(&original));
            guard.events.lock().unwrap().clear();
            guard.outcomes.lock().unwrap().clear();
            let mut ctx = engine
                .begin(
                    ExecutionGrant::new([Action::Sign])
                        .with_keys([first.key_id(), second.key_id()]),
                    OperationPolicy::strict_online(),
                    Arc::new(Control::default()),
                )
                .unwrap();
            let mut artifact = store.stage(ctx.resources()).unwrap();
            let request = if add {
                SignRequest::cms_add(vec![KeyRequest::new(&second, Some("C02 synthetic"))], None)
            } else {
                SignRequest::cms_create(
                    vec![
                        KeyRequest::new(&first, Some("C02 synthetic")),
                        KeyRequest::new(&second, Some("C02 synthetic")),
                    ],
                    true,
                )
            };
            let input = if add { original.as_slice() } else { DATA };
            let error = engine
                .sign_staged(
                    request,
                    Source::sequential(&mut Cursor::new(input), None),
                    &mut artifact,
                    &mut ctx,
                )
                .unwrap_err();
            assert_eq!(
                error.applied_state(),
                AppliedState::NotApplied,
                "same_key={same_key}, add={add}"
            );
            assert!(
                guard.events.lock().unwrap().is_empty(),
                "new private guard reached; same_key={same_key}, add={add}"
            );
            assert!(guard.outcomes.lock().unwrap().is_empty());
            assert_eq!(artifact.len(), 0);
            let destination = parent.path().join("conflicting.p7s");
            assert!(artifact.commit(&destination).is_err());
            assert!(!destination.exists());
            if let Some(old_signers) = old_signers {
                assert_eq!(signer_infos(&original), old_signers);
                let old = cms::verify(&original, None).unwrap();
                assert_eq!(old.len(), 1);
                assert_eq!(old[0].cert.to_der().unwrap(), old_certificate);
            }
        }
    }
}

#[test]
fn byte_identical_certificate_reuse_remains_valid_for_create_and_add() {
    let entry = issued("user-rsa-sign");
    let certificate = entry.cert.to_der().unwrap();
    let key = key_selector(entry);
    let guard = Arc::new(Guard::default());
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let engine = engine(guard.clone(), KeySources::new(), Some(store), true);
    let mut original = vec![];
    {
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        engine
            .sign(
                SignRequest::cms_create(
                    vec![
                        KeyRequest::new(&key, Some("C02 synthetic")),
                        KeyRequest::new(&key, None),
                    ],
                    true,
                ),
                Source::sequential(&mut Cursor::new(DATA), None),
                &mut original,
                &mut ctx,
            )
            .unwrap();
    }
    let verified = cms::verify(&original, None).unwrap();
    assert_eq!(verified.len(), 2);
    assert!(
        verified
            .iter()
            .all(|signer| signer.cert.to_der().unwrap() == certificate)
    );
    assert_eq!(guard.events.lock().unwrap().len(), 2);
    let old_signers = signer_infos(&original);
    let mut output = vec![];
    {
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        engine
            .sign(
                SignRequest::cms_add(vec![KeyRequest::new(&key, Some("C02 synthetic"))], None),
                Source::sequential(&mut Cursor::new(&original), None),
                &mut output,
                &mut ctx,
            )
            .unwrap();
    }
    let verified = cms::verify(&output, None).unwrap();
    assert_eq!(verified.len(), 3);
    assert!(
        verified
            .iter()
            .all(|signer| signer.cert.to_der().unwrap() == certificate)
    );
    let new_signers = signer_infos(&output);
    assert!(old_signers.iter().all(|old| new_signers.contains(old)));
    assert_eq!(guard.events.lock().unwrap().len(), 3);
    let ci = children(&output);
    let explicit = children(&ci[1]);
    let sd = children(&explicit[0]);
    let certificates = sd.iter().find(|field| field[0] == 0xa0).unwrap();
    assert_eq!(
        children(certificates).len(),
        1,
        "exactly equal certificates remain deduplicated"
    );
}

fn with_subject_key_identifier_sid(cms: &[u8], ski: &[u8]) -> Vec<u8> {
    use der::asn1::AnyRef;
    fn wrap(tag: der::Tag, body: &[u8]) -> Vec<u8> {
        AnyRef::new(tag, body).unwrap().to_der().unwrap()
    }
    let mut ci = children(cms);
    let explicit = children(&ci[1]);
    let mut sd = children(&explicit[0]);
    let signers = children(sd.last().unwrap());
    assert_eq!(signers.len(), 1);
    let mut fields = children(&signers[0]);
    fields[0] = 3u8.to_der().unwrap();
    fields[1] = wrap(
        der::Tag::ContextSpecific {
            constructed: false,
            number: der::TagNumber(0),
        },
        ski,
    );
    *sd.last_mut().unwrap() = wrap(der::Tag::Set, &wrap(der::Tag::Sequence, &fields.concat()));
    sd[0] = 3u8.to_der().unwrap();
    ci[1] = wrap(
        der::Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber(0),
        },
        &wrap(der::Tag::Sequence, &sd.concat()),
    );
    wrap(der::Tag::Sequence, &ci.concat())
}

#[test]
fn add_rejects_union_that_changes_an_existing_ski_signer_association() {
    use der::{Decode, asn1::OctetStringRef};
    let mut first_entry = issued("user-rsa-sign");
    let mut incoming_entry = issued("user-gost2004-sign");
    let mut first_spec = oncl_pki::testing::TestCertSpec::from_cert(&first_entry.cert);
    first_spec.serial = vec![0x63, 0x02];
    let old_ski = first_spec
        .extensions
        .iter()
        .find(|extension| extension.extn_id.to_string() == "2.5.29.14")
        .expect("real fixture has SKI")
        .extn_value
        .clone();
    let ski_bytes = <&OctetStringRef>::from_der(old_ski.as_bytes())
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut incoming_spec = oncl_pki::testing::TestCertSpec::from_cert(&incoming_entry.cert);
    incoming_spec.serial = vec![0x63, 0x03];
    let incoming_ski = incoming_spec
        .extensions
        .iter_mut()
        .find(|extension| extension.extn_id.to_string() == "2.5.29.14")
        .expect("real fixture has SKI");
    incoming_ski.extn_value = old_ski;
    let issuer = raw("inter-gost2015.key");
    first_entry.cert = oncl_pki::testing::issue_cert(&issuer, first_spec);
    incoming_entry.cert = oncl_pki::testing::issue_cert(&issuer, incoming_spec);
    assert_ne!(
        first_entry.cert.tbs_certificate().serial_number(),
        incoming_entry.cert.tbs_certificate().serial_number()
    );
    assert_ne!(
        first_entry.key.public_key(),
        incoming_entry.key.public_key()
    );
    let old_certificate = first_entry.cert.to_der().unwrap();
    let first = key_selector(first_entry);
    let incoming = key_selector(incoming_entry);
    let guard = Arc::new(Guard::default());
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let engine = engine(guard.clone(), KeySources::new(), Some(store.clone()), true);
    let original = {
        let mut ctx = begin(
            &engine,
            &first,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut output = vec![];
        engine
            .sign(
                SignRequest::cms_create(vec![KeyRequest::new(&first, Some("C02 synthetic"))], true),
                Source::sequential(&mut Cursor::new(DATA), None),
                &mut output,
                &mut ctx,
            )
            .unwrap();
        with_subject_key_identifier_sid(&output, &ski_bytes)
    };
    let verified = cms::verify(&original, None).unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].cert.to_der().unwrap(), old_certificate);
    let old_signers = signer_infos(&original);
    guard.events.lock().unwrap().clear();
    guard.outcomes.lock().unwrap().clear();
    let mut ctx = begin(
        &engine,
        &incoming,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut artifact = store.stage(ctx.resources()).unwrap();
    let error = engine
        .sign_staged(
            SignRequest::cms_add(
                vec![KeyRequest::new(&incoming, Some("C02 synthetic"))],
                None,
            ),
            Source::sequential(&mut Cursor::new(&original), None),
            &mut artifact,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(guard.events.lock().unwrap().is_empty());
    assert!(guard.outcomes.lock().unwrap().is_empty());
    assert_eq!(artifact.len(), 0);
    let destination = parent.path().join("ambiguous-ski.p7s");
    assert!(artifact.commit(&destination).is_err());
    assert!(!destination.exists());
    assert_eq!(signer_infos(&original), old_signers);
    assert_eq!(
        cms::verify(&original, None).unwrap()[0]
            .cert
            .to_der()
            .unwrap(),
        old_certificate
    );
}

#[test]
fn issuer_serial_signers_allow_same_ski_renewal_with_a_distinct_serial() {
    let (first_entry, mut renewed_entry) = collision_entries(true);
    let original_certificate = first_entry.cert.to_der().unwrap();
    let mut spec = oncl_pki::testing::TestCertSpec::from_cert(&renewed_entry.cert);
    spec.serial = vec![0x63, 0x03];
    renewed_entry.cert = oncl_pki::testing::issue_cert(&raw("inter-gost2015.key"), spec);
    let renewed_certificate = renewed_entry.cert.to_der().unwrap();
    let old_spec = oncl_pki::testing::TestCertSpec::from_cert(&first_entry.cert);
    let new_spec = oncl_pki::testing::TestCertSpec::from_cert(&renewed_entry.cert);
    let old_ski = old_spec
        .extensions
        .iter()
        .find(|extension| extension.extn_id.to_string() == "2.5.29.14")
        .unwrap();
    let new_ski = new_spec
        .extensions
        .iter()
        .find(|extension| extension.extn_id.to_string() == "2.5.29.14")
        .unwrap();
    assert_eq!(old_ski.extn_value, new_ski.extn_value);
    assert_ne!(
        first_entry.cert.tbs_certificate().serial_number(),
        renewed_entry.cert.tbs_certificate().serial_number()
    );
    let first = key_selector(first_entry);
    let renewed = key_selector(renewed_entry);
    let guard = Arc::new(Guard::default());
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let engine = engine(guard.clone(), KeySources::new(), Some(store), true);
    let mut original = vec![];
    {
        let mut ctx = begin(
            &engine,
            &first,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        engine
            .sign(
                SignRequest::cms_create(vec![KeyRequest::new(&first, Some("C02 synthetic"))], true),
                Source::sequential(&mut Cursor::new(DATA), None),
                &mut original,
                &mut ctx,
            )
            .unwrap();
    }
    let old_signers = signer_infos(&original);
    let mut output = vec![];
    {
        let mut ctx = begin(
            &engine,
            &renewed,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        engine
            .sign(
                SignRequest::cms_add(vec![KeyRequest::new(&renewed, Some("C02 synthetic"))], None),
                Source::sequential(&mut Cursor::new(&original), None),
                &mut output,
                &mut ctx,
            )
            .unwrap();
    }
    let verified = cms::verify(&output, None).unwrap();
    assert_eq!(verified.len(), 2);
    let certificates: Vec<_> = verified
        .iter()
        .map(|signer| signer.cert.to_der().unwrap())
        .collect();
    assert!(certificates.contains(&original_certificate));
    assert!(certificates.contains(&renewed_certificate));
    let signers = signer_infos(&output);
    assert!(old_signers.iter().all(|old| signers.contains(old)));
    assert_eq!(guard.events.lock().unwrap().len(), 2);
}

#[cfg(feature = "pdf")]
fn unsigned_pdf() -> Vec<u8> {
    use lopdf::{Document, Object, dictionary};
    let mut doc = Document::with_version("1.7");
    let pages = doc.new_object_id();
    let page = doc.add_object(dictionary! {"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![0.into(),0.into(),612.into(),792.into()]});
    doc.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1}.into(),
    );
    let root = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    doc.trailer.set("Root", root);
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

#[cfg(feature = "pdf")]
#[test]
fn pdf_sign_and_add_use_sign_authority_and_preserve_both_keys() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), Some(store.clone()), true);
    let input = unsigned_pdf();
    let mut previous = input;
    for name in ["user-rsa-sign", "user-gost2015-sign"] {
        let key = selector(name);
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut stage = store.stage(ctx.resources()).unwrap();
        let report = engine
            .sign_staged(
                SignRequest::pdf(
                    KeyRequest::new(&key, Some("C02 synthetic")),
                    oncl_pdf::PdfSignProfile::default(),
                ),
                Source::sequential(&mut Cursor::new(&previous), None),
                &mut stage,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(report.applied, AppliedState::Applied);
        assert_eq!(report.bytes_in, previous.len() as u64);
        assert_eq!(report.bytes_out, stage.len());
        let mut output = Vec::new();
        stage.copy_to(&mut output).unwrap();
        assert!(output.starts_with(&previous));
        previous = output;
    }
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap();
    let report = engine
        .verify(
            &oncl_core::VerifyRequest::pdf(),
            Source::sequential(&mut Cursor::new(&previous), None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.verdict, oncl_pki::validation::Verdict::Valid);
    assert_eq!(report.signers.len(), 2);
    assert!(
        report
            .signers
            .iter()
            .all(|s| s.signature == oncl_pki::validation::CheckStatus::Passed)
    );
    assert_eq!(guard.events.lock().unwrap().len(), 2);
    assert!(
        guard
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|e| e.action == Action::Sign)
    );
}

#[cfg(feature = "pdf")]
fn pdf_once(engine: &Engine, key: &KeySelector, input: &[u8]) -> Result<Vec<u8>, OperationError> {
    let mut ctx = begin(
        engine,
        key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut output = Vec::new();
    engine.sign(
        SignRequest::pdf(
            KeyRequest::new(key, Some("C02 synthetic")),
            oncl_pdf::PdfSignProfile::default(),
        ),
        Source::sequential(&mut Cursor::new(input), None),
        &mut output,
        &mut ctx,
    )?;
    Ok(output)
}

#[cfg(feature = "pdf")]
#[test]
fn pdf_impossible_reservation_is_not_applied_and_poisoned() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), Some(store.clone()), true);
    let key = selector("user-rsa-sign");
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut stage = store.stage(ctx.resources()).unwrap();
    let error = engine
        .sign_staged(
            SignRequest::pdf(
                KeyRequest::new(&key, Some("C02 synthetic")),
                oncl_pdf::PdfSignProfile::new(8).unwrap(),
            ),
            Source::sequential(&mut Cursor::new(unsigned_pdf()), None),
            &mut stage,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert!(guard.events.lock().unwrap().is_empty());
    assert!(guard.outcomes.lock().unwrap().is_empty());
    let mut bytes = Vec::new();
    assert!(stage.copy_to(&mut bytes).is_err());
    assert!(bytes.is_empty());
}

#[cfg(feature = "pdf")]
#[test]
fn pdf_invalid_and_unsigned_latest_revisions_cannot_be_laundered_by_add() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), KeySources::new(), Some(store), true);
    let key = selector("user-rsa-sign");
    let signed = pdf_once(&engine, &key, &unsigned_pdf()).unwrap();
    let mut modified = signed.clone();
    let at = modified.windows(3).position(|w| w == b"612").unwrap();
    modified[at + 2] = b'1';
    assert_eq!(
        pdf_once(&engine, &key, &modified)
            .unwrap_err()
            .applied_state(),
        AppliedState::NotApplied
    );
    // Independently construct an actual unsigned /Info incremental revision.
    let parsed = lopdf::Document::load_mem(&signed).unwrap();
    let root = parsed.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let next = parsed.max_id + 1;
    let marker = signed.windows(9).rposition(|w| w == b"startxref").unwrap() + 9;
    let previous: u64 = std::str::from_utf8(&signed[marker..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut later = signed.clone();
    later.push(b'\n');
    let offset = later.len();
    later.extend_from_slice(
        format!("{next} 0 obj\n<< /Title (Unsigned later change) >>\nendobj\n").as_bytes(),
    );
    let xref = later.len();
    later.extend_from_slice(format!("xref\n{next} 1\n{offset:010} 00000 n \ntrailer\n<< /Size {} /Root {} {} R /Info {next} 0 R /Prev {previous} >>\nstartxref\n{xref}\n%%EOF\n", next+1,root.0,root.1).as_bytes());
    assert!(later.starts_with(&signed));
    assert!(lopdf::Document::load_mem(&later).is_ok());
    assert_eq!(
        pdf_once(&engine, &key, &later).unwrap_err().applied_state(),
        AppliedState::NotApplied
    );
    assert_eq!(guard.events.lock().unwrap().len(), 1);
}

#[cfg(feature = "pdf")]
#[test]
fn pdf_post_use_audit_and_cancel_errors_remain_applied() {
    for cancel in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let guard = Arc::new(Guard::default());
        let engine = engine(guard.clone(), KeySources::new(), Some(store.clone()), true);
        let control = Arc::new(Control::default());
        if cancel {
            *guard.cancel_after.lock().unwrap() = Some(control.clone());
        } else {
            guard.finish_fail.store(true, Ordering::SeqCst);
        }
        let key = selector("user-rsa-sign");
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            control,
        );
        let mut stage = store.stage(ctx.resources()).unwrap();
        let error = engine
            .sign_staged(
                SignRequest::pdf(
                    KeyRequest::new(&key, Some("C02 synthetic")),
                    oncl_pdf::PdfSignProfile::default(),
                ),
                Source::sequential(&mut Cursor::new(unsigned_pdf()), None),
                &mut stage,
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::Applied);
        assert_eq!(guard.events.lock().unwrap().len(), 1);
        let mut bytes = Vec::new();
        assert!(stage.copy_to(&mut bytes).is_err());
        assert!(bytes.is_empty());
    }
}

#[cfg(feature = "pdf")]
#[test]
fn pdf_sign_digest_authority_does_not_authorize_pdf_sign() {
    let parent = tempfile::tempdir().unwrap();
    let guard = Arc::new(Guard::default());
    let engine = engine(
        guard.clone(),
        KeySources::new(),
        Some(TemporaryStore::new(parent.path()).unwrap()),
        true,
    );
    let key = selector("user-rsa-sign");
    let mut policy = OperationPolicy::strict_online();
    policy.allow_prehashed = true;
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::SignDigest],
        policy,
        Arc::new(Control::default()),
    );
    let mut output = Vec::new();
    let error = engine
        .sign(
            SignRequest::pdf(
                KeyRequest::new(&key, Some("C02 synthetic")),
                oncl_pdf::PdfSignProfile::default(),
            ),
            Source::sequential(&mut Cursor::new(unsigned_pdf()), None),
            &mut output,
            &mut ctx,
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert!(output.is_empty());
    assert!(guard.events.lock().unwrap().is_empty());
}

#[cfg(feature = "pdf")]
#[test]
fn pdf_staged_precheck_rejects_nonempty_and_foreign_before_intake() {
    struct NeverRead;
    impl io::Read for NeverRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("invalid PDF output admitted input")
        }
    }
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let guard = Arc::new(Guard::default());
    let engine = Engine::new(
        EngineServices::hash_only(ResourceLimits {
            max_in_flight: 2,
            ..ResourceLimits::default()
        })
        .with_keys(Arc::new(KeySources::new()), guard.clone())
        .with_validation(validation())
        .with_temporary_store(store.clone()),
    )
    .unwrap();
    let key = selector("user-rsa-sign");
    let mut first = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut second = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let mut foreign = store.stage(second.resources()).unwrap();
    let error = engine
        .sign_staged(
            SignRequest::pdf(
                KeyRequest::new(&key, Some("C02 synthetic")),
                oncl_pdf::PdfSignProfile::default(),
            ),
            Source::sequential(&mut NeverRead, None),
            &mut foreign,
            &mut first,
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(foreign.len(), 0);
    let mut nonempty = store.stage(first.resources()).unwrap();
    nonempty.write_chunk(b"old artifact").unwrap();
    let error = engine
        .sign_staged(
            SignRequest::pdf(
                KeyRequest::new(&key, Some("C02 synthetic")),
                oncl_pdf::PdfSignProfile::default(),
            ),
            Source::sequential(&mut NeverRead, None),
            &mut nonempty,
            &mut first,
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::NotApplied);
    assert_eq!(nonempty.len(), 12);
    assert_eq!(first.resources().progress().bytes_in, 0);
    assert!(guard.events.lock().unwrap().is_empty());
}

#[cfg(all(feature = "tokens", feature = "pdf"))]
#[test]
fn pdf_token_backends_verify_real_rsa_and_gost_signatures() {
    use oncl_token::{
        TokenKind, Tokens,
        emulator::{CardSpec, EmuKey, EmulatorBackend, card},
        execution::{TokenDeviceId, TokenGateRegistry},
    };
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let entry = issued(name);
        let alias = entry.alias.clone();
        let emu = Arc::new(EmulatorBackend::new());
        emu.add_reader("P02 reader");
        let mut spec = CardSpec::new(TokenKind::Kaztoken, "C02 synthetic", vec![EmuKey { entry }]);
        spec.fixed_k = Some(vec![1; 16]);
        emu.insert("P02 reader", card(spec));
        let key = KeySelector::token(
            TokenDeviceId::new("P02 reader").unwrap(),
            TokenKind::Kaztoken,
            alias,
        );
        let provider = KeySources::new().with_tokens(
            Tokens::new(emu.clone(), true),
            Arc::new(TokenGateRegistry::new(1, 1).unwrap()),
        );
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let guard = Arc::new(Guard::default());
        let engine = engine(guard.clone(), provider, Some(store), true);
        let input = include_bytes!("../../oncl-pdf/tests/fixtures/external-multipage.pdf");
        let output = pdf_once(&engine, &key, input).unwrap();
        assert!(output.starts_with(input));
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Verify]),
                OperationPolicy::strict_online(),
                Arc::new(Control::default()),
            )
            .unwrap();
        let checked = engine
            .verify(
                &oncl_core::VerifyRequest::pdf(),
                Source::sequential(&mut Cursor::new(&output), None),
                None,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(checked.verdict, oncl_pki::validation::Verdict::Valid);
        assert_eq!(checked.signers.len(), 1);
        assert_eq!(
            checked.signers[0].signature,
            oncl_pki::validation::CheckStatus::Passed
        );
        assert!(
            emu.exchanges("P02 reader")
                .iter()
                .any(|e| e.command.starts_with(&[0x00, 0x2a, 0x9e, 0x9a]))
        );
        assert_eq!(guard.events.lock().unwrap().len(), 1);
        assert_eq!(guard.events.lock().unwrap()[0].action, Action::Sign);
    }
}

#[cfg(feature = "xml")]
#[test]
fn xml_core_source_guard_reports_and_keyless_lta_renewal() {
    use oncl_core::{CadesConfiguration, ExtendRequest, VerifyRequest};
    use oncl_pki::{
        crl::MockCrl,
        evidence::{AdesLevel, EvidenceLimits},
        http::{HttpTransport, RouteTransport},
        ocsp::MockOcsp,
        tsp::{MockTsa, TsaProfile, TsaSpec},
        validation::{NetworkPolicy, Verdict},
    };
    let guard = Arc::new(Guard::default());
    let key = selector("user-rsa-sign");
    let mut tsa = TsaSpec::from(TsaProfile::kalkan_default());
    tsa.url = "http://tsa.synthetic.test".into();
    let routes = Arc::new(RouteTransport::new(vec![
        (
            tsa.url.clone(),
            Arc::new(MockTsa::new(issued("tsa-gost2015")).with_gen_time(NOW))
                as Arc<dyn HttpTransport>,
        ),
        (
            "http://ocsp.synthetic.test".into(),
            Arc::new(MockOcsp::new(raw("ocsp-gost2015")).with_now(NOW)),
        ),
        (
            "http://crl.synthetic.test/root-gost2015.crl".into(),
            Arc::new(
                MockCrl::new(raw("root-gost2015.key"))
                    .with_this_update(NOW - time::Duration::MINUTE)
                    .next_update(Some(NOW + time::Duration::HOUR)),
            ),
        ),
        (
            "http://crl.synthetic.test/inter-gost2015.crl".into(),
            Arc::new(
                MockCrl::new(raw("inter-gost2015.key"))
                    .with_this_update(NOW - time::Duration::MINUTE)
                    .next_update(Some(NOW + time::Duration::HOUR)),
            ),
        ),
    ]));
    let validation = || {
        ValidationServices::new(
            oncl_pki::pkix::CaSet::new(vec![raw("root-gost2015.key").cert]),
            vec![raw("inter-gost2015.key").cert],
            routes.clone(),
            NetworkPolicy::only_endpoints([
                "http://tsa.synthetic.test",
                "http://ocsp.synthetic.test",
                "http://crl.synthetic.test",
            ])
            .unwrap(),
            Arc::new(|| NOW),
        )
    };
    let cap = ResourceLimits::default();
    let shared = Arc::new(oncl_pki::resource::SharedBudget::new(cap.clone()).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let engine = Engine::new(
        EngineServices::hash_only(cap.clone())
            .with_shared_budget(shared.clone())
            .with_keys(Arc::new(KeySources::new()), guard.clone())
            .with_validation(validation())
            .with_temporary_store(store.clone()),
    )
    .unwrap();
    let mut ctx = begin(
        &engine,
        &key,
        &[Action::Sign],
        OperationPolicy::strict_online(),
        Arc::new(Control::default()),
    );
    let profile = oncl_xml::XmlSignProfile {
        target: Some("p"),
        parent: Some("s"),
        signature_id: Some("sig"),
        ..Default::default()
    };
    let mut bytes = Vec::new();
    let report = engine
        .sign(
            SignRequest::xades(
                KeyRequest::new(&key, Some("C02 synthetic")),
                profile,
                AdesLevel::B,
            ),
            Source::sequential(
                &mut Cursor::new(b"<r><p Id='p'>protected</p><s Id='s'/></r>"),
                None,
            ),
            &mut bytes,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.applied, AppliedState::Applied);
    assert_eq!(report.xml().unwrap().validation.verdict, Verdict::Valid);
    assert_eq!(guard.events.lock().unwrap().len(), 1);
    drop(report);
    drop(ctx);
    // A completely keyless host can extend and renew; no fake missing-provider branch.
    let keyless = Engine::new(
        EngineServices::hash_only(cap)
            .with_shared_budget(shared)
            .with_validation(validation())
            .with_temporary_store(store)
            .with_cades(CadesConfiguration::new(
                EvidenceLimits {
                    max_items: 24,
                    max_bytes: 6291456,
                    max_item_bytes: 262144,
                    max_chain_len: 16,
                    max_proofs: 8,
                    max_coverage_parts: 256,
                    max_coverage_bytes: 1 << 40,
                },
                tsa,
            )),
    )
    .unwrap();
    for level in [AdesLevel::T, AdesLevel::Lt, AdesLevel::Lta, AdesLevel::Lta] {
        let mut ctx = keyless
            .begin(
                ExecutionGrant::new([Action::Extend]),
                OperationPolicy::strict_online(),
                Arc::new(Control::default()),
            )
            .unwrap();
        let mut out = Vec::new();
        let report = keyless
            .extend(
                &ExtendRequest::xml(level),
                Source::sequential(&mut Cursor::new(&bytes), None),
                &mut out,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(report.applied, AppliedState::NotApplied);
        assert_eq!(report.xml().unwrap().signatures()[0].level, Some(level));
        assert_eq!(report.xml().unwrap().validation.verdict, Verdict::Valid);
        bytes = out;
    }
    assert_eq!(guard.events.lock().unwrap().len(), 1);
    let mut ctx = keyless
        .begin(
            ExecutionGrant::new([Action::Verify]),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )
        .unwrap();
    let report = keyless
        .verify(
            &VerifyRequest::xades(AdesLevel::Lta),
            Source::sequential(&mut Cursor::new(&bytes), None),
            None,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.ades_level, Some(AdesLevel::Lta));
    assert_eq!(
        report.xml.unwrap().signatures()[0].level,
        Some(AdesLevel::Lta)
    );
}

#[cfg(feature = "xml")]
#[test]
fn xml_tsa_preflight_rejects_configuration_before_intake_key_open_and_guard() {
    use oncl_core::{
        CadesConfiguration,
        keys::{KeyLease, KeyProvider},
    };
    use oncl_pki::{
        evidence::{AdesLevel, EvidenceLimits},
        http::NonceSpec,
        tsp::{TsaProfile, TsaSpec},
    };
    struct Provider {
        opens: Arc<AtomicUsize>,
        inner: KeySources,
    }
    impl KeyProvider for Provider {
        fn open(
            &self,
            r: &KeyRequest<'_>,
            ctx: &mut OperationContext,
        ) -> Result<KeyLease, OperationError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.inner.open(r, ctx)
        }
    }
    struct Input {
        reads: Arc<AtomicUsize>,
        inner: Cursor<&'static [u8]>,
    }
    impl io::Read for Input {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            io::Read::read(&mut self.inner, b)
        }
    }
    let key = selector("user-rsa-sign");
    let dir = tempfile::tempdir().unwrap();
    for case in 0..6 {
        let opens = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let guard = Arc::new(Guard::default());
        let mut tsa = TsaSpec::from(TsaProfile::kalkan_default());
        match case {
            0 => tsa.cert_req = false,
            1 => tsa.policy = None,
            2 => tsa.nonce = NonceSpec::None,
            3 => tsa.retries = 3,
            4 => tsa.timeout = std::time::Duration::ZERO,
            _ => tsa.nonce = NonceSpec::Random(0),
        }
        let engine = Engine::new(
            EngineServices::hash_only(ResourceLimits::default())
                .with_validation(validation())
                .with_temporary_store(TemporaryStore::new(dir.path()).unwrap())
                .with_keys(
                    Arc::new(Provider {
                        opens: opens.clone(),
                        inner: KeySources::new(),
                    }),
                    guard.clone(),
                )
                .with_cades(CadesConfiguration::new(
                    EvidenceLimits {
                        max_items: 24,
                        max_bytes: 6291456,
                        max_item_bytes: 262144,
                        max_chain_len: 16,
                        max_proofs: 8,
                        max_coverage_parts: 256,
                        max_coverage_bytes: 1 << 40,
                    },
                    tsa,
                )),
        )
        .unwrap();
        let mut ctx = begin(
            &engine,
            &key,
            &[Action::Sign],
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        );
        let mut input = Input {
            reads: reads.clone(),
            inner: Cursor::new(b"<r/>"),
        };
        let mut out = Vec::new();
        let error = engine
            .sign(
                SignRequest::xades(
                    KeyRequest::new(&key, Some("C02 synthetic")),
                    oncl_xml::XmlSignProfile {
                        signature_id: Some("sig"),
                        ..Default::default()
                    },
                    AdesLevel::T,
                ),
                Source::sequential(&mut input, None),
                &mut out,
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(reads.load(Ordering::SeqCst), 0, "case {case}");
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert!(guard.events.lock().unwrap().is_empty());
        assert!(out.is_empty());
    }
}
