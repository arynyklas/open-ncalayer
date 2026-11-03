#![cfg(feature = "jose")]
//! Mutations caught: algorithm confusion; old-signature laundering; header-driven
//! authority; collapsing trust/claims into crypto; escaping resource/root guards.
#[path = "../examples/sdk_probe/jose_fixtures.rs"]
mod fixtures;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use der::Encode;
use fixtures::*;
use oncl_core::jose::{
    ClaimsFailure, JoseAlgorithm, JoseProfile, JwsSerialization, JwsVerifyRequest,
    JwtValidationPolicy, MAX_CLAIMS_BYTES, MAX_CONTAINER_BYTES, MAX_PAYLOAD_BYTES,
};
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationPolicy,
    keys::{AppliedState, KeyRequest, KeySelector},
};
use oncl_pki::{
    resource::{ResourceLimits, SharedBudget},
    validation::{CheckStatus, Verdict},
};
use std::{
    io::{self, Write},
    sync::{Arc, atomic::Ordering},
};
const DATA: &[u8] = b"J01 detached payload\0with binary\xff";
fn profile(serialization: JwsSerialization, detached: bool) -> JoseProfile {
    JoseProfile::new(serialization, detached)
}
fn create(engine: &Engine, keys: &[&KeySelector], profile: JoseProfile, data: &[u8]) -> Vec<u8> {
    let mut ctx = begin(engine, keys, &[Action::Sign]);
    let mut output = Vec::new();
    let report = engine
        .jws_create(
            profile,
            keys.iter()
                .map(|key| KeyRequest::new(key, Some("J01 synthetic")))
                .collect(),
            data,
            &mut output,
            &mut ctx,
        )
        .unwrap();
    assert_eq!(report.applied, AppliedState::Applied);
    assert!(!ctx.policy().allow_prehashed);
    assert_eq!(report.bytes_in, data.len() as u64);
    assert_eq!(report.bytes_out, output.len() as u64);
    output
}
fn jwt(engine: &Engine, key: &KeySelector, claims: &[u8]) -> Vec<u8> {
    let mut ctx = begin(engine, &[key], &[Action::Sign]);
    let mut output = Vec::new();
    engine
        .jwt_encode(
            KeyRequest::new(key, Some("J01 synthetic")),
            claims,
            &mut output,
            &mut ctx,
        )
        .unwrap();
    output
}
fn verify(
    engine: &Engine,
    wire: &[u8],
    p: JoseProfile,
    data: Option<&[u8]>,
) -> oncl_core::jose::JwsVerificationReport {
    engine
        .jws_verify(
            JwsVerifyRequest::new(p),
            wire,
            data,
            &mut begin(engine, &[], &[Action::Verify]),
        )
        .unwrap()
}
fn altered_header(wire: &[u8], name: &str, value: serde_json::Value) -> Vec<u8> {
    let wire = std::str::from_utf8(wire).unwrap();
    let mut parts: Vec<_> = wire.split('.').map(str::to_owned).collect();
    let mut header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[0]).unwrap()).unwrap();
    header[name] = value;
    parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    parts.join(".").into_bytes()
}
#[test]
fn algorithm_confusion_rejected() {
    for alg in [
        "none",
        "HS256",
        "ES512",
        "PS256",
        "EdDSA",
        "GOST2004",
        "GOST3410-2015-512",
    ] {
        assert!(JoseAlgorithm::from_name(alg).is_err());
    }
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let key = selector("user-rsa-sign");
    let wire = create(
        &engine,
        &[&key],
        profile(JwsSerialization::Compact, false),
        DATA,
    );
    let before = guard.calls.load(Ordering::SeqCst);
    for alg in ["none", "HS256", "ES512", "ECGOST3410-2015-512"] {
        let bad = altered_header(&wire, "alg", alg.into());
        let result = engine.jws_verify(
            JwsVerifyRequest::new(profile(JwsSerialization::Compact, false)),
            &bad,
            None,
            &mut begin(&engine, &[], &[Action::Verify]),
        );
        assert!(
            result.is_err() || result.unwrap().verdict() == Verdict::Invalid,
            "accepted {alg}"
        );
        let mut output = Vec::new();
        let error = engine
            .jws_add(
                JwsVerifyRequest::new(profile(JwsSerialization::Compact, false)),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                &bad,
                None,
                &mut output,
                &mut begin(&engine, &[&key], &[Action::Sign]),
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert!(output.is_empty());
    }
    assert_eq!(guard.calls.load(Ordering::SeqCst), before);
    // The unsupported GOST-2004 JOSE name is not fabricated from key size/OID.
    let unsupported = selector("user-gost2004-sign");
    let mut output = Vec::new();
    assert!(
        engine
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&unsupported, Some("J01 synthetic"))],
                DATA,
                &mut output,
                &mut begin(&engine, &[&unsupported], &[Action::Sign])
            )
            .is_err()
    );
    assert_eq!(guard.calls.load(Ordering::SeqCst), before);
}
#[test]
fn multiple_signers_and_detached() {
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let rsa = selector("user-rsa-sign");
    let gost = selector("user-gost2015-sign");
    for serialization in [
        JwsSerialization::Compact,
        JwsSerialization::Flattened,
        JwsSerialization::General,
    ] {
        for detached in [false, true] {
            let p = profile(serialization, detached);
            let wire = create(&engine, &[&rsa], p, DATA);
            let report = verify(&engine, &wire, p, detached.then_some(DATA));
            assert_eq!(report.payload(), DATA);
            assert_eq!(report.verdict(), Verdict::Valid);
            assert_eq!(report.signers()[0].crypto(), CheckStatus::Passed);
            assert_eq!(report.signers()[0].trust().verdict(), Verdict::Valid);
            drop(report);
            let old = if serialization == JwsSerialization::General {
                serde_json::from_slice::<serde_json::Value>(&wire).unwrap()["signatures"][0].clone()
            } else if serialization == JwsSerialization::Flattened {
                let old: serde_json::Value = serde_json::from_slice(&wire).unwrap();
                serde_json::json!({"protected":old["protected"],"signature":old["signature"]})
            } else {
                let parts: Vec<_> = std::str::from_utf8(&wire).unwrap().split('.').collect();
                serde_json::json!({"protected":parts[0],"signature":parts[2]})
            };
            let mut added = Vec::new();
            let report = engine
                .jws_add(
                    JwsVerifyRequest::new(p),
                    vec![KeyRequest::new(&gost, Some("J01 synthetic"))],
                    &wire,
                    detached.then_some(DATA),
                    &mut added,
                    &mut begin(&engine, &[&gost], &[Action::Sign]),
                )
                .unwrap();
            assert_eq!(report.signer_count, 2);
            drop(report);
            let json: serde_json::Value = serde_json::from_slice(&added).unwrap();
            assert_eq!(json["signatures"][0], old);
            let report = verify(
                &engine,
                &added,
                profile(JwsSerialization::General, detached),
                detached.then_some(DATA),
            );
            assert_eq!(report.verdict(), Verdict::Valid);
            assert_eq!(report.signers().len(), 2);
            assert_eq!(
                report.signers()[1].algorithm(),
                JoseAlgorithm::EcGost3410_2015_512
            );
            drop(report);
            let mut corrupt: serde_json::Value = serde_json::from_slice(&added).unwrap();
            corrupt["signatures"][0]["signature"] = URL_SAFE_NO_PAD.encode([0u8; 256]).into();
            let corrupt = serde_json::to_vec(&corrupt).unwrap();
            let before = guard.calls.load(Ordering::SeqCst);
            let mut rejected = Vec::new();
            let error = engine
                .jws_add(
                    JwsVerifyRequest::new(profile(JwsSerialization::General, detached)),
                    vec![KeyRequest::new(&rsa, Some("J01 synthetic"))],
                    &corrupt,
                    detached.then_some(DATA),
                    &mut rejected,
                    &mut begin(&engine, &[&rsa], &[Action::Sign]),
                )
                .unwrap_err();
            assert_eq!(error.applied_state(), AppliedState::NotApplied);
            assert_eq!(guard.calls.load(Ordering::SeqCst), before);
            assert!(rejected.is_empty());
        }
    }
    assert!(
        guard
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|event| event.action == Action::Sign)
    );
}
#[test]
fn jwt_exp_nbf_aud_boundaries() {
    let engine = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        true,
    );
    let key = selector("user-rsa-sign");
    let mut policy = JwtValidationPolicy::new(10);
    policy.expected_issuer = Some("issuer".into());
    policy.expected_audience = Some("audience".into());
    for (claims, expected, failure) in [
        (
            r#"{"iss":"issuer","aud":"audience","exp":11,"nbf":10}"#,
            Verdict::Valid,
            None,
        ),
        (
            r#"{"iss":"issuer","aud":["other","audience"],"exp":11,"nbf":10}"#,
            Verdict::Valid,
            None,
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":10}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::Expired),
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":11,"nbf":11}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::NotYetValid),
        ),
        (
            r#"{"iss":"issuer","aud":"wrong","exp":11}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::Audience),
        ),
        (
            r#"{"iss":"wrong","aud":"audience","exp":11}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::Issuer),
        ),
        (
            r#"{"iss":"issuer","aud":"audience"}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::MissingExpiration),
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":1e40}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::InvalidNumericDate),
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":1e400}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::InvalidNumericDate),
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":11.5}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::InvalidNumericDate),
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":null}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::InvalidNumericDate),
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":9223372036854775807}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::InvalidNumericDate),
        ),
        (
            r#"{"iss":"issuer","aud":"audience","exp":11,"iat":"bad"}"#,
            Verdict::Invalid,
            Some(ClaimsFailure::InvalidNumericDate),
        ),
    ] {
        let token = jwt(&engine, &key, claims.as_bytes());
        let report = engine
            .jwt_verify(
                None,
                &token,
                &policy,
                &mut begin(&engine, &[], &[Action::Verify]),
            )
            .unwrap();
        assert_eq!(report.jws().verdict(), Verdict::Valid, "{claims}");
        assert_eq!(report.jws().signers()[0].crypto(), CheckStatus::Passed);
        assert_eq!(report.claims().verdict(), expected, "{claims}");
        assert_eq!(report.verdict(), expected);
        if let Some(failure) = failure {
            assert!(report.claims().failures().contains(&failure), "{claims}");
        }
    }
    let token = jwt(
        &engine,
        &key,
        br#"{"iss":"issuer","aud":"audience","exp":10,"nbf":11}"#,
    );
    policy.leeway_seconds = 1;
    assert_eq!(
        engine
            .jwt_verify(
                None,
                &token,
                &policy,
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .unwrap()
            .verdict(),
        Verdict::Valid
    );
    policy.leeway_seconds = 0;
    assert_eq!(
        engine
            .jwt_verify(
                None,
                &token,
                &policy,
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .unwrap()
            .verdict(),
        Verdict::Invalid
    );
}
#[test]
fn unverified_decode_never_proves_crypto_or_claims() {
    let engine = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        true,
    );
    let key = selector("user-rsa-sign");
    let token = jwt(&engine, &key, br#"{"exp":0,"iss":"untrusted"}"#);
    let decoded = engine
        .jwt_decode_unverified(&token, &mut begin(&engine, &[], &[Action::Extract]))
        .unwrap();
    assert!(!decoded.is_verified());
    assert_eq!(decoded.expiration(), Some(0));
    assert_eq!(decoded.issuer(), Some("untrusted"));
    drop(decoded);
    let mut parts: Vec<_> = std::str::from_utf8(&token)
        .unwrap()
        .split('.')
        .map(str::to_owned)
        .collect();
    parts[2] = URL_SAFE_NO_PAD.encode([0u8; 256]);
    let forged = parts.join(".");
    assert!(
        !engine
            .jwt_decode_unverified(
                forged.as_bytes(),
                &mut begin(&engine, &[], &[Action::Extract])
            )
            .unwrap()
            .is_verified()
    );
    let report = engine
        .jwt_verify(
            None,
            forged.as_bytes(),
            &JwtValidationPolicy::new(0),
            &mut begin(&engine, &[], &[Action::Verify]),
        )
        .unwrap();
    assert_eq!(report.jws().signers()[0].crypto(), CheckStatus::Failed);
    assert_eq!(report.claims().verdict(), Verdict::Invalid);
    assert_eq!(report.verdict(), Verdict::Invalid);
}
#[test]
fn header_authority_extensions_duplicates_and_urls_rejected_before_key_use() {
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let key = selector("user-rsa-sign");
    let wire = create(
        &engine,
        &[&key],
        profile(JwsSerialization::Compact, false),
        DATA,
    );
    let before = guard.calls.load(Ordering::SeqCst);
    for (name, value) in [
        ("kid", serde_json::json!("../../other-key")),
        ("jku", serde_json::json!("http://127.0.0.1:9/key")),
        ("x5u", serde_json::json!("file:///private/key")),
        ("jwk", serde_json::json!({"kty":"RSA"})),
        ("crit", serde_json::json!(["unknown"])),
        ("b64", serde_json::json!(false)),
        ("clock", serde_json::json!(0)),
    ] {
        let bad = altered_header(&wire, name, value);
        let mut output = Vec::new();
        assert!(
            engine
                .jws_add(
                    JwsVerifyRequest::new(profile(JwsSerialization::Compact, false)),
                    vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                    &bad,
                    None,
                    &mut output,
                    &mut begin(&engine, &[&key], &[Action::Sign])
                )
                .is_err()
        );
        assert!(output.is_empty());
    }
    let parts: Vec<_> = std::str::from_utf8(&wire).unwrap().split('.').collect();
    let bad = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","alg":"none"}"#),
        parts[1],
        parts[2]
    );
    assert!(
        engine
            .jws_verify(
                JwsVerifyRequest::new(profile(JwsSerialization::Compact, false)),
                bad.as_bytes(),
                None,
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .is_err()
    );
    assert_eq!(guard.calls.load(Ordering::SeqCst), before);
    for payload in [
        br#"{"exp":20,"exp":30}"#.as_slice(),
        br#"{"exp":20,"app":{"x":1,"x":2}}"#.as_slice(),
    ] {
        let mut output = Vec::new();
        assert!(
            engine
                .jwt_encode(
                    KeyRequest::new(&key, Some("J01 synthetic")),
                    payload,
                    &mut output,
                    &mut begin(&engine, &[&key], &[Action::Sign])
                )
                .is_err()
        );
    }
    assert_eq!(guard.calls.load(Ordering::SeqCst), before);
}
#[test]
fn trust_roots_and_revocation_are_not_header_authority() {
    let signer = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        true,
    );
    let key = selector("user-rsa-sign");
    let wire = create(
        &signer,
        &[&key],
        profile(JwsSerialization::Compact, false),
        DATA,
    );
    let untrusted = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        false,
        true,
    );
    let report = verify(
        &untrusted,
        &wire,
        profile(JwsSerialization::Compact, false),
        None,
    );
    assert_eq!(report.signers()[0].crypto(), CheckStatus::Passed);
    assert_eq!(report.signers()[0].trust().chain, CheckStatus::Failed);
    assert_eq!(report.verdict(), Verdict::Invalid);
    drop(report);
    let offline = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        false,
    );
    let report = verify(
        &offline,
        &wire,
        profile(JwsSerialization::Compact, false),
        None,
    );
    assert_eq!(report.signers()[0].crypto(), CheckStatus::Passed);
    assert_eq!(report.verdict(), Verdict::Indeterminate);
    // Even a root in x5c is only an untrusted candidate, never promoted to anchor.
    let bad = altered_header(
        &wire,
        "x5c",
        serde_json::json!([
            STANDARD.encode(issued("user-rsa-sign").cert.to_der().unwrap()),
            STANDARD.encode(raw("inter-gost2015.key").cert.to_der().unwrap()),
            STANDARD.encode(raw("root-gost2015.key").cert.to_der().unwrap())
        ]),
    );
    let report = verify(
        &untrusted,
        &bad,
        profile(JwsSerialization::Compact, false),
        None,
    );
    assert_eq!(report.signers()[0].trust().chain, CheckStatus::Failed);
}
#[test]
fn scope_key_algorithm_and_action_boundaries_precede_guard() {
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let key = selector("user-rsa-sign");
    let other = selector("user-gost2015-sign");
    for (scope_key, action) in [(&other, Action::Sign), (&key, Action::SignDigest)] {
        let mut output = Vec::new();
        let error = engine
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                DATA,
                &mut output,
                &mut begin(&engine, &[scope_key], &[action]),
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert!(output.is_empty());
    }
    let mut ctx = begin(&engine, &[&key], &[Action::Sign]);
    // A different engine must not consume the capability or its resource scope.
    let different = fixtures::engine(guard.clone(), ResourceLimits::default(), true, true);
    assert!(
        different
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                DATA,
                &mut Vec::new(),
                &mut ctx
            )
            .is_err()
    );
    drop(ctx);
    let mut policy = OperationPolicy::strict_online();
    policy.allowed_signature_algorithms = &[oncl_pki::key::SigAlg::Gost2015_512];
    let mut ctx = engine
        .begin(
            ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
            policy,
            Arc::new(Control::default()),
        )
        .unwrap();
    assert!(
        engine
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                DATA,
                &mut Vec::new(),
                &mut ctx
            )
            .is_err()
    );
    assert_eq!(guard.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn partial_application_output_and_audit_failures_are_honest() {
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let key = selector("user-rsa-sign");
    let other = selector("user-gost2015-sign");
    guard.deny_at.store(2, Ordering::SeqCst);
    let error = engine
        .jws_create(
            profile(JwsSerialization::General, false),
            vec![
                KeyRequest::new(&key, Some("J01 synthetic")),
                KeyRequest::new(&other, Some("J01 synthetic")),
            ],
            DATA,
            &mut Vec::new(),
            &mut begin(&engine, &[&key, &other], &[Action::Sign]),
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::Applied);
    guard.deny_at.store(0, Ordering::SeqCst);
    guard.fail_finish.store(true, Ordering::SeqCst);
    let error = engine
        .jws_create(
            profile(JwsSerialization::Compact, false),
            vec![KeyRequest::new(&key, Some("J01 synthetic"))],
            DATA,
            &mut Vec::new(),
            &mut begin(&engine, &[&key], &[Action::Sign]),
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::Applied);
    guard.fail_finish.store(false, Ordering::SeqCst);
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("output failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = engine
        .jws_create(
            profile(JwsSerialization::Compact, false),
            vec![KeyRequest::new(&key, Some("J01 synthetic"))],
            DATA,
            &mut Broken,
            &mut begin(&engine, &[&key], &[Action::Sign]),
        )
        .unwrap_err();
    assert_eq!(error.applied_state(), AppliedState::Applied);
}
#[test]
fn quotas_and_cancel_precede_decoding_and_private_use() {
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let key = selector("user-rsa-sign");
    let mut output = Vec::new();
    assert!(
        engine
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                &vec![0; MAX_PAYLOAD_BYTES + 1],
                &mut output,
                &mut begin(&engine, &[&key], &[Action::Sign])
            )
            .is_err()
    );
    assert!(
        engine
            .jwt_encode(
                KeyRequest::new(&key, Some("J01 synthetic")),
                &vec![b' '; MAX_CLAIMS_BYTES + 1],
                &mut output,
                &mut begin(&engine, &[&key], &[Action::Sign])
            )
            .is_err()
    );
    assert!(
        engine
            .jws_verify(
                JwsVerifyRequest::new(profile(JwsSerialization::Compact, false)),
                &vec![b'A'; MAX_CONTAINER_BYTES + 1],
                None,
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .is_err()
    );
    let control = Arc::new(Control::default());
    control.0.store(true, Ordering::SeqCst);
    let mut ctx = engine.begin(
        ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
        OperationPolicy::strict_online(),
        control,
    );
    // Cancellation may reject at begin, before any operation is admitted.
    if let Ok(ctx) = &mut ctx {
        assert!(
            engine
                .jws_create(
                    profile(JwsSerialization::Compact, false),
                    vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                    DATA,
                    &mut output,
                    ctx
                )
                .is_err()
        );
    }
    assert_eq!(guard.calls.load(Ordering::SeqCst), 0);
    assert!(output.is_empty());
    let limited = fixtures::engine(
        guard.clone(),
        ResourceLimits {
            metadata_bytes: 1024,
            ..ResourceLimits::default()
        },
        true,
        true,
    );
    assert!(
        limited
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                DATA,
                &mut Vec::new(),
                &mut begin(&limited, &[&key], &[Action::Sign])
            )
            .is_err()
    );
    assert_eq!(guard.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn retained_parsed_claims_reports_hold_root_admission() {
    let producer = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        true,
    );
    let key = selector("user-rsa-sign");
    let token = jwt(&producer, &key, br#"{"exp":10,"aud":"app"}"#);
    let limits = ResourceLimits {
        max_in_flight: 1,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let engine = Engine::new(
        EngineServices::hash_only(limits)
            .with_shared_budget(budget)
            .with_validation(validation(true, true)),
    )
    .unwrap();
    let mut ctx = begin(&engine, &[], &[Action::Extract]);
    let decoded = engine.jwt_decode_unverified(&token, &mut ctx).unwrap();
    drop(ctx);
    assert!(
        engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .is_err()
    );
    drop(decoded);
    let mut ctx = begin(&engine, &[], &[Action::Verify]);
    let report = engine
        .jwt_verify(None, &token, &JwtValidationPolicy::new(0), &mut ctx)
        .unwrap();
    drop(ctx);
    assert_eq!(report.verdict(), Verdict::Valid);
    assert!(
        engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .is_err()
    );
    drop(report);
    assert!(
        engine
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control::default())
            )
            .is_ok()
    );
}

/// These fixed vectors were created by OpenSSL 3.5.4 `dgst -sha256 -keyform DER
/// -sign` over the exact standard signing inputs, not by the SDK. The public
/// synthetic RSA fixture supplies the verification certificate; no key is stored
/// alongside the vectors. The executable J01 probe also creates NEW oracle input.
#[test]
fn independent_openssl_rs256_vectors_and_negative_controls() {
    let engine = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        true,
    );
    let cert = issued("user-rsa-sign").cert;
    let p = profile(JwsSerialization::Compact, false);
    for vector in [
        include_bytes!("fixtures/jose/openssl-jws.txt").as_slice(),
        include_bytes!("fixtures/jose/openssl-jwt.txt").as_slice(),
    ] {
        let request = JwsVerifyRequest {
            profile: p,
            certificate: Some(&cert),
        };
        let report = engine
            .jws_verify(
                request,
                vector,
                None,
                &mut begin(&engine, &[], &[Action::Verify]),
            )
            .unwrap();
        assert_eq!(report.verdict(), Verdict::Valid);
        assert_eq!(report.signers()[0].crypto(), CheckStatus::Passed);
        drop(report);
        let mut parts: Vec<_> = std::str::from_utf8(vector)
            .unwrap()
            .split('.')
            .map(str::to_owned)
            .collect();
        parts[1] = URL_SAFE_NO_PAD.encode(b"tampered");
        let report = engine
            .jws_verify(
                request,
                parts.join(".").as_bytes(),
                None,
                &mut begin(&engine, &[], &[Action::Verify]),
            )
            .unwrap();
        assert_eq!(report.signers()[0].crypto(), CheckStatus::Failed);
        assert_eq!(report.signers()[0].trust().verdict(), Verdict::Valid);
        assert_eq!(report.verdict(), Verdict::Invalid);
        drop(report);
        let mut parts: Vec<_> = std::str::from_utf8(vector)
            .unwrap()
            .split('.')
            .map(str::to_owned)
            .collect();
        parts[2] = URL_SAFE_NO_PAD.encode([0u8; 256]);
        assert_eq!(
            engine
                .jws_verify(
                    request,
                    parts.join(".").as_bytes(),
                    None,
                    &mut begin(&engine, &[], &[Action::Verify])
                )
                .unwrap()
                .verdict(),
            Verdict::Invalid
        );
    }
    let vector = include_bytes!("fixtures/jose/openssl-jwt.txt");
    let mut policy = JwtValidationPolicy::new(0);
    policy.expected_issuer = Some("J01 issuer".into());
    policy.expected_audience = Some("J01 audience".into());
    assert_eq!(
        engine
            .jwt_verify(
                Some(&cert),
                vector,
                &policy,
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .unwrap()
            .verdict(),
        Verdict::Valid
    );
    policy.expected_audience = Some("wrong".into());
    let report = engine
        .jwt_verify(
            Some(&cert),
            vector,
            &policy,
            &mut begin(&engine, &[], &[Action::Verify]),
        )
        .unwrap();
    assert_eq!(report.jws().verdict(), Verdict::Valid);
    assert_eq!(report.verdict(), Verdict::Invalid);
}

#[test]
fn altered_payload_all_signers_and_detachment_cannot_be_laundered() {
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let rsa = selector("user-rsa-sign");
    let gost = selector("user-gost2015-sign");
    let p = profile(JwsSerialization::General, false);
    let wire = create(&engine, &[&rsa, &gost], p, DATA);
    let mut altered: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    altered["signatures"][1]["signature"] = URL_SAFE_NO_PAD.encode([0u8; 128]).into();
    let altered = serde_json::to_vec(&altered).unwrap();
    let report = verify(&engine, &altered, p, None);
    assert_eq!(report.signers().len(), 2);
    assert_eq!(report.signers()[0].crypto(), CheckStatus::Passed);
    assert_eq!(report.signers()[1].crypto(), CheckStatus::Failed);
    assert_eq!(report.verdict(), Verdict::Invalid);
    drop(report);
    let mut altered: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    altered["payload"] = URL_SAFE_NO_PAD.encode(b"different").into();
    let altered = serde_json::to_vec(&altered).unwrap();
    let report = verify(&engine, &altered, p, None);
    assert!(
        report
            .signers()
            .iter()
            .all(|s| s.crypto() == CheckStatus::Failed)
    );
    assert_eq!(report.verdict(), Verdict::Invalid);
    drop(report);
    let before = guard.calls.load(Ordering::SeqCst);
    assert!(
        engine
            .jws_add(
                JwsVerifyRequest::new(p),
                vec![KeyRequest::new(&rsa, Some("J01 synthetic"))],
                &altered,
                None,
                &mut Vec::new(),
                &mut begin(&engine, &[&rsa], &[Action::Sign])
            )
            .is_err()
    );
    assert_eq!(guard.calls.load(Ordering::SeqCst), before);
    let p = profile(JwsSerialization::Compact, true);
    let wire = create(&engine, &[&rsa], p, DATA);
    assert_eq!(
        verify(&engine, &wire, p, Some(b"different")).verdict(),
        Verdict::Invalid
    );
    assert!(
        engine
            .jws_verify(
                JwsVerifyRequest::new(p),
                &wire,
                None,
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .is_err()
    );
}

#[test]
fn trusted_policy_not_claims_controls_clock_leeway_and_exp_requirement() {
    let engine = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        true,
    );
    let key = selector("user-rsa-sign");
    let token = jwt(&engine, &key, br#"{"exp":0,"now":-100,"clock":-100,"leeway":999999,"require_exp":false,"expected_audience":"evil"}"#);
    let report = engine
        .jwt_verify(
            None,
            &token,
            &JwtValidationPolicy::new(0),
            &mut begin(&engine, &[], &[Action::Verify]),
        )
        .unwrap();
    assert_eq!(report.jws().verdict(), Verdict::Valid);
    assert!(report.claims().failures().contains(&ClaimsFailure::Expired));
    drop(report);
    let token = jwt(&engine, &key, br#"{"aud":"app"}"#);
    assert_eq!(
        engine
            .jwt_verify(
                None,
                &token,
                &JwtValidationPolicy::new(0),
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .unwrap()
            .verdict(),
        Verdict::Invalid
    );
    let mut policy = JwtValidationPolicy::new(0);
    policy.require_exp = false;
    assert_eq!(
        engine
            .jwt_verify(
                None,
                &token,
                &policy,
                &mut begin(&engine, &[], &[Action::Verify])
            )
            .unwrap()
            .verdict(),
        Verdict::Valid
    );
}

#[test]
fn bounded_headers_claims_inputs_and_noncanonical_encodings() {
    let guard = Arc::new(Guard::default());
    let producer = engine(guard.clone(), ResourceLimits::default(), true, true);
    let key = selector("user-rsa-sign");
    let wire = create(
        &producer,
        &[&key],
        profile(JwsSerialization::Compact, false),
        DATA,
    );
    let small = engine(
        guard.clone(),
        ResourceLimits {
            input_bytes: 2,
            ..ResourceLimits::default()
        },
        true,
        true,
    );
    let before = guard.calls.load(Ordering::SeqCst);
    assert!(
        small
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                DATA,
                &mut Vec::new(),
                &mut begin(&small, &[&key], &[Action::Sign])
            )
            .is_err()
    );
    assert!(
        small
            .jws_verify(
                JwsVerifyRequest::new(profile(JwsSerialization::Compact, false)),
                &wire,
                None,
                &mut begin(&small, &[], &[Action::Verify])
            )
            .is_err()
    );
    let parts: Vec<_> = std::str::from_utf8(&wire).unwrap().split('.').collect();
    for bad in [
        format!("{}=.{}.{}", parts[0], parts[1], parts[2]),
        format!("{}.{}=.{}", parts[0], parts[1], parts[2]),
        format!("{}.{}.{}=", parts[0], parts[1], parts[2]),
        format!("{}.{}.{}", "A".repeat(30_000), parts[1], parts[2]),
    ] {
        assert!(
            producer
                .jws_verify(
                    JwsVerifyRequest::new(profile(JwsSerialization::Compact, false)),
                    bad.as_bytes(),
                    None,
                    &mut begin(&producer, &[], &[Action::Verify])
                )
                .is_err()
        );
    }
    let large_claims = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(vec![b' '; MAX_CLAIMS_BYTES + 1]),
        parts[2]
    );
    assert!(
        producer
            .jwt_decode_unverified(
                large_claims.as_bytes(),
                &mut begin(&producer, &[], &[Action::Extract])
            )
            .is_err()
    );
    let null_payload =
        serde_json::json!({"payload":null,"protected":parts[0],"signature":parts[2]});
    assert!(
        producer
            .jws_verify(
                JwsVerifyRequest::new(profile(JwsSerialization::Flattened, true)),
                &serde_json::to_vec(&null_payload).unwrap(),
                Some(DATA),
                &mut begin(&producer, &[], &[Action::Verify])
            )
            .is_err()
    );
    assert_eq!(guard.calls.load(Ordering::SeqCst), before);
}

#[test]
fn strict_private_validation_cannot_be_relaxed_by_compatibility_policy() {
    let key = selector("user-rsa-sign");
    for (trusted, statuses) in [(false, true), (true, false)] {
        let guard = Arc::new(Guard::default());
        let engine = engine(guard.clone(), ResourceLimits::default(), trusted, statuses);
        let mut ctx = engine
            .begin(
                ExecutionGrant::new([Action::Sign]).with_keys([key.key_id()]),
                OperationPolicy::ncalayer_compatibility(),
                Arc::new(Control::default()),
            )
            .unwrap();
        let mut output = Vec::new();
        let error = engine
            .jws_create(
                profile(JwsSerialization::Compact, false),
                vec![KeyRequest::new(&key, Some("J01 synthetic"))],
                DATA,
                &mut output,
                &mut ctx,
            )
            .unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(guard.calls.load(Ordering::SeqCst), 0);
        assert!(output.is_empty());
    }
}

#[test]
fn maximum_bounded_payload_is_real_binary_data_not_a_length_hint() {
    let engine = engine(
        Arc::new(Guard::default()),
        ResourceLimits::default(),
        true,
        true,
    );
    let key = selector("user-rsa-sign");
    let payload: Vec<_> = (0..MAX_PAYLOAD_BYTES)
        .map(|n| (n.wrapping_mul(31) % 251) as u8)
        .collect();
    for detached in [false, true] {
        let p = profile(JwsSerialization::Compact, detached);
        let wire = create(&engine, &[&key], p, &payload);
        let report = verify(&engine, &wire, p, detached.then_some(payload.as_slice()));
        assert_eq!(report.verdict(), Verdict::Valid);
        assert_eq!(report.payload(), payload);
    }
}

#[test]
fn host_certificate_pin_and_bounded_signer_count_are_enforced() {
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let key = selector("user-rsa-sign");
    let wire = create(
        &engine,
        &[&key],
        profile(JwsSerialization::Compact, false),
        DATA,
    );
    let other = issued("user-gost2015-sign").cert;
    assert!(
        engine
            .jws_verify(
                JwsVerifyRequest {
                    profile: profile(JwsSerialization::Compact, false),
                    certificate: Some(&other)
                },
                &wire,
                None,
                &mut begin(&engine, &[], &[Action::Verify]),
            )
            .is_err()
    );
    let before = guard.calls.load(Ordering::SeqCst);
    for (p, count) in [
        (profile(JwsSerialization::General, false), 0),
        (profile(JwsSerialization::General, false), 9),
        (profile(JwsSerialization::Compact, false), 2),
        (profile(JwsSerialization::Flattened, false), 2),
    ] {
        let mut output = Vec::new();
        assert!(
            engine
                .jws_create(
                    p,
                    (0..count)
                        .map(|_| KeyRequest::new(&key, Some("J01 synthetic")))
                        .collect(),
                    DATA,
                    &mut output,
                    &mut begin(&engine, &[&key], &[Action::Sign]),
                )
                .is_err()
        );
        assert!(output.is_empty());
    }
    assert_eq!(guard.calls.load(Ordering::SeqCst), before);
}
