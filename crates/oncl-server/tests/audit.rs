#[path = "support/batch.rs"]
mod batch_support;
mod support;
use oncl_core::keys::{
    AppliedState, KeyId, KeyUseEvent, KeyUseGuard, KeyUseOutcome, KeyUseReceipt,
};
use oncl_core::{
    Action, Engine, EngineServices, ErrorCode, ExecutionGrant, OperationContext, OperationPolicy,
};
use oncl_pki::resource::ResourceLimits;
use oncl_server::audit::{
    AuditConfig, AuditHealth, AuditLabel, DurableAuditGuard, FRAME_BYTES, FaultPoint, RecordKind,
};
use std::sync::Arc;
use support::{Control, Rig};
fn context() -> OperationContext {
    Engine::new(EngineServices::hash_only(ResourceLimits::default()))
        .unwrap()
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap()
}
fn event(ctx: &OperationContext, key: &KeyId) -> KeyUseEvent {
    KeyUseEvent::new(ctx, key.clone(), Action::SignDigest)
}
fn config(path: &std::path::Path) -> AuditConfig {
    AuditConfig::new(path.to_owned(), 4096, 16384, 3, 32).unwrap()
}
fn done() -> KeyUseOutcome {
    KeyUseOutcome {
        applied: AppliedState::Applied,
        succeeded: true,
    }
}
fn journal(path: &std::path::Path) -> std::path::PathBuf {
    std::fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "log"))
        .unwrap()
}
fn binding(
    guard: &DurableAuditGuard,
    ctx: &OperationContext,
    key: &KeyId,
) -> oncl_server::audit::AuditBinding {
    guard
        .bind(
            ctx,
            AuditLabel::new([1; 16]),
            [(key.clone(), AuditLabel::new([2; 16]))],
        )
        .unwrap()
}

#[test]
fn begin_failure_blocks_key() {
    for point in [
        FaultPoint::BeforeWrite,
        FaultPoint::PartialWrite,
        FaultPoint::BeforeSync,
        FaultPoint::AfterSync,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
        let rig = Rig::new(guard.clone());
        let (mut ctx, _binding) = rig.begin();
        guard.inject_fault(point);
        let error = rig.sign(&mut ctx).unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuditFailed);
        assert_eq!(error.applied_state(), AppliedState::NotApplied);
        assert_eq!(rig.calls(), 0);
        assert!(rig.actual.signatures.lock().unwrap().is_empty());
        assert_eq!(guard.health(), AuditHealth::Failed);
        let (mut other, _other_binding) = rig.begin();
        assert!(rig.sign(&mut other).is_err());
        assert_eq!(rig.calls(), 0);
        guard.recover().unwrap();
        assert_eq!(guard.health(), AuditHealth::Healthy);
        for final_record in guard
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.kind.is_final())
        {
            assert_eq!(final_record.applied, AppliedState::NotApplied);
            assert!(!final_record.succeeded);
        }
        let (mut fresh, _fresh_binding) = rig.begin();
        let signature = rig.sign(&mut fresh).unwrap();
        rig.verify(&signature);
        assert_eq!(rig.calls(), 1);
    }
}
#[test]
fn finish_failure_is_applied_not_rollback() {
    for point in [
        FaultPoint::BeforeWrite,
        FaultPoint::PartialWrite,
        FaultPoint::BeforeSync,
        FaultPoint::AfterSync,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
        let rig = Rig::new(guard.clone());
        let (mut ctx, _binding) = rig.begin();
        *rig.actual.after.lock().unwrap() = Some(point);
        let mut published = Vec::new();
        let result = rig.sign(&mut ctx);
        if let Ok(signature) = &result {
            published.extend_from_slice(signature);
        }
        let error = result.unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuditFailed);
        assert_eq!(error.applied_state(), AppliedState::Applied);
        assert_eq!(rig.calls(), 1);
        assert!(published.is_empty());
        rig.verify(&rig.actual.signatures.lock().unwrap()[0]);
        assert_eq!(guard.health(), AuditHealth::Failed);
        let (mut other, _other_binding) = rig.begin();
        assert!(rig.sign(&mut other).is_err());
        assert_eq!(rig.calls(), 1);
        let repair = guard.recover().unwrap();
        assert_eq!(repair.resolved_unknown, 0);
        assert_eq!(guard.health(), AuditHealth::Healthy);
        let finals: Vec<_> = guard
            .records()
            .unwrap()
            .into_iter()
            .filter(|r| r.kind.is_final())
            .collect();
        assert_eq!(finals.len(), 1);
        assert_eq!(finals[0].applied, AppliedState::Applied);
        assert!(finals[0].succeeded);
    }
}
#[test]
fn partial_record_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    {
        let guard = DurableAuditGuard::create(config(&path)).unwrap();
        let rig = Rig::new(guard.clone());
        let (mut ctx, _binding) = rig.begin();
        *rig.actual.after.lock().unwrap() = Some(FaultPoint::PartialWrite);
        let error = rig.sign(&mut ctx).unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::Applied);
        assert_eq!(rig.calls(), 1);
    }
    let reopened = DurableAuditGuard::open(config(&path)).unwrap();
    assert_eq!(reopened.health(), AuditHealth::RecoveryRequired);
    let repair = reopened.recover().unwrap();
    assert_eq!(repair.resolved_unknown, 1);
    assert_eq!(repair.truncated_bytes, 79);
    assert_eq!(reopened.health(), AuditHealth::Healthy);
    let records = reopened.records().unwrap();
    let final_record = records.iter().find(|r| r.kind.is_final()).unwrap();
    assert_eq!(final_record.applied, AppliedState::Unknown);
    assert!(!final_record.succeeded);
    let recovery = records
        .iter()
        .find(|r| r.kind == RecordKind::Recovery)
        .unwrap();
    assert_eq!(recovery.repair_from - recovery.repair_to, 79);
}
#[test]
fn writable_real_rsa_and_gost_signatures_have_correlated_frames() {
    for name in ["user-rsa-sign", "user-gost2004-sign", "user-gost2015-sign"] {
        let temp = tempfile::tempdir().unwrap();
        let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
        let rig = Rig::with_key(guard.clone(), name);
        let (mut ctx, _binding) = rig.begin();
        let signature = rig.sign(&mut ctx).unwrap();
        rig.verify(&signature);
        assert_eq!(rig.calls(), 1);
        let records = guard.records().unwrap();
        assert_eq!(records.len(), 3);
        let begin = &records[1];
        let final_record = &records[2];
        assert_eq!(begin.kind, RecordKind::Begin);
        assert_eq!(final_record.kind, RecordKind::Final);
        assert_eq!(begin.use_id, final_record.use_id);
        assert_eq!(begin.operation_id, ctx.id().get());
        assert_eq!(begin.principal, final_record.principal);
        assert_eq!(begin.key, final_record.key);
        assert_eq!(final_record.applied, AppliedState::Applied);
        assert!(final_record.succeeded);
        let bytes = std::fs::read(journal(&temp.path().join("audit"))).unwrap();
        assert_eq!(bytes.len() as u64, FRAME_BYTES * 3);
        for frame in bytes.as_chunks::<{ FRAME_BYTES as usize }>().0 {
            assert_eq!(&frame[..8], b"ONCLAU02");
        }
        for forbidden in [
            b"host-private-path/password-must-not-appear".as_slice(),
            b"Qwerty12".as_slice(),
            support::MESSAGE,
        ] {
            assert!(
                !bytes
                    .windows(forbidden.len())
                    .any(|window| window == forbidden)
            );
        }
        drop(_binding);
        drop(ctx);
        drop(rig);
        drop(guard);
        let identity = std::fs::read(temp.path().join("audit/oncl-audit.identity")).unwrap();
        assert_eq!(&identity[..8], b"ONCLAU02");
    }
}
#[test]
fn incomplete_begin_restart_is_unknown_and_never_auto_healthy() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    {
        let guard = DurableAuditGuard::create(config(&path)).unwrap();
        let ctx = context();
        let key = KeyId::new("sensitive host key").unwrap();
        let _binding = binding(&guard, &ctx, &key);
        let _receipt = guard.before_use(&event(&ctx, &key)).unwrap();
        assert!(guard.recover().is_err());
    }
    let guard = DurableAuditGuard::open(config(&path)).unwrap();
    assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
    assert_eq!(guard.recover().unwrap().resolved_unknown, 1);
    let records = guard.records().unwrap();
    assert_eq!(records.last().unwrap().applied, AppliedState::Unknown);
}
#[test]
fn complete_corrupt_frame_and_foreign_header_are_not_repaired() {
    for header in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit");
        {
            let guard = DurableAuditGuard::create(config(&path)).unwrap();
            let rig = Rig::new(guard);
            let (mut ctx, _binding) = rig.begin();
            rig.sign(&mut ctx).unwrap();
        }
        let file = journal(&path);
        let mut bytes = std::fs::read(&file).unwrap();
        let offset = if header { 8 } else { FRAME_BYTES as usize + 80 };
        bytes[offset] ^= 0x80;
        std::fs::write(&file, &bytes).unwrap();
        match DurableAuditGuard::open(config(&path)) {
            Ok(guard) => {
                assert!(!header);
                assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
                assert!(guard.recover().is_err());
            }
            Err(_) => assert!(header),
        }
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
    }
}
#[test]
fn rotation_retention_quota_preserve_foreign_entries_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let config = AuditConfig::new(path.clone(), 800, 1120, 1, 32).unwrap();
    let guard = DurableAuditGuard::create(config.clone()).unwrap();
    std::fs::write(path.join("foreign-note"), b"unchanged").unwrap();
    let rig = Rig::new(guard.clone());
    for _ in 0..12 {
        let (mut ctx, _binding) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
    }
    assert_eq!(rig.calls(), 12);
    assert_eq!(
        std::fs::read(path.join("foreign-note")).unwrap(),
        b"unchanged"
    );
    let files: Vec<_> = std::fs::read_dir(&path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "log"))
        .collect();
    assert_eq!(files.len(), 1);
    assert!(
        files[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("000000000000000b")
    );
    let bytes: u64 = files.iter().map(|p| p.metadata().unwrap().len()).sum();
    assert!(bytes + FRAME_BYTES <= 1120);
    drop(rig);
    drop(guard);
    let reopened = DurableAuditGuard::open(config).unwrap();
    assert_eq!(reopened.health(), AuditHealth::RecoveryRequired);
    assert_eq!(reopened.records().unwrap().len(), 3);
    reopened.recover().unwrap();
    assert_eq!(reopened.health(), AuditHealth::Healthy);
}
#[test]
fn quota_never_evicts_unresolved_begin() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard =
        DurableAuditGuard::create(AuditConfig::new(path, 640, 960, 1, 32).unwrap()).unwrap();
    let first = context();
    let second = context();
    let key = KeyId::new("key").unwrap();
    let _a = binding(&guard, &first, &key);
    let _b = binding(&guard, &second, &key);
    let receipt = guard.before_use(&event(&first, &key)).unwrap();
    assert!(guard.before_use(&event(&second, &key)).is_err());
    assert_eq!(
        guard
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.kind == RecordKind::Begin)
            .count(),
        1
    );
    assert!(guard.finish(receipt, done()).is_err());
    assert_eq!(
        guard.records().unwrap().last().unwrap().applied,
        AppliedState::Applied
    );
    guard.recover().unwrap();
}
#[test]
fn binding_drop_still_finalizes_and_wrong_receipt_cannot_consume_pending() {
    let temp = tempfile::tempdir().unwrap();
    let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
    let ctx = context();
    let key = KeyId::new("key").unwrap();
    let bound = binding(&guard, &ctx, &key);
    let receipt = guard.before_use(&event(&ctx, &key)).unwrap();
    let correlation = receipt.correlation().unwrap();
    drop(bound);
    let wrong =
        KeyUseReceipt::with_correlation(event(&ctx, &key), correlation.0, correlation.1 + 1);
    assert!(guard.finish(wrong, done()).is_err());
    assert!(guard.finish(receipt, done()).is_err());
    let records = guard.records().unwrap();
    assert_eq!(records.iter().filter(|r| r.kind.is_final()).count(), 1);
    assert_eq!(records.last().unwrap().applied, AppliedState::Applied);
    guard.recover().unwrap();
    assert!(guard.before_use(&event(&ctx, &key)).is_err());
}
#[test]
fn stale_untagged_cross_guard_and_double_receipts_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
    let ctx = context();
    let key = KeyId::new("key").unwrap();
    let _bound = binding(&guard, &ctx, &key);
    let receipt = guard.before_use(&event(&ctx, &key)).unwrap();
    let old = receipt.correlation().unwrap();
    guard.finish(receipt, done()).unwrap();
    let receipt = guard.before_use(&event(&ctx, &key)).unwrap();
    assert!(
        guard
            .finish(
                KeyUseReceipt::with_correlation(event(&ctx, &key), old.0, old.1),
                done()
            )
            .is_err()
    );
    assert!(
        guard
            .finish(KeyUseReceipt::new(event(&ctx, &key)), done())
            .is_err()
    );
    assert!(
        guard
            .finish(
                KeyUseReceipt::with_correlation(
                    event(&ctx, &key),
                    old.0 ^ 1,
                    receipt.correlation().unwrap().1
                ),
                done()
            )
            .is_err()
    );
    assert!(guard.recover().is_err());
    assert!(guard.finish(receipt, done()).is_err());
    assert_eq!(
        guard
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.kind.is_final())
            .count(),
        2
    );
    guard.recover().unwrap();
}
#[test]
fn concurrent_actual_calls_keep_actor_correlation_and_shared_failure() {
    use std::sync::mpsc;
    for partial in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
        let rig = Arc::new(Rig::new(guard.clone()));
        let second = Rig::new(guard.clone());
        let (entered_rx, release_tx) = {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            *rig.actual.pause.lock().unwrap() = Some((entered_tx, release_rx));
            (entered_rx, release_tx)
        };
        let (mut first_ctx, first_binding) =
            rig.begin_labeled(AuditLabel::new([0x33; 16]), AuditLabel::new([0x44; 16]));
        let first_rig = rig.clone();
        let first = std::thread::spawn(move || first_rig.sign(&mut first_ctx));
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .unwrap();
        drop(first_binding);
        let (mut ctx, _binding) = second.begin();
        *second.actual.after.lock().unwrap() = Some(if partial {
            FaultPoint::PartialWrite
        } else {
            FaultPoint::BeforeWrite
        });
        let error = second.sign(&mut ctx).unwrap_err();
        assert_eq!(error.applied_state(), AppliedState::Applied);
        assert!(guard.recover().is_err());
        let (mut new_ctx, _new_binding) = second.begin();
        assert!(second.sign(&mut new_ctx).is_err());
        assert_eq!(second.calls(), 1);
        release_tx.send(()).unwrap();
        assert_eq!(
            first.join().unwrap().unwrap_err().applied_state(),
            AppliedState::Applied
        );
        assert_eq!(rig.calls(), 1);
        rig.verify(&rig.actual.signatures.lock().unwrap()[0]);
        second.verify(&second.actual.signatures.lock().unwrap()[0]);
        assert_eq!(guard.health(), AuditHealth::Failed);
        guard.recover().unwrap();
        let records = guard.records().unwrap();
        let begins: Vec<_> = records
            .iter()
            .filter(|r| r.kind == RecordKind::Begin)
            .collect();
        let finals: Vec<_> = records
            .iter()
            .filter(|r| r.kind == RecordKind::Final)
            .collect();
        assert_eq!(begins.len(), 2);
        assert_eq!(finals.len(), 2);
        assert_ne!(begins[0].principal, begins[1].principal);
        assert_ne!(begins[0].key, begins[1].key);
        for begin in begins {
            let final_record = finals.iter().find(|r| r.use_id == begin.use_id).unwrap();
            assert_eq!(final_record.operation_id, begin.operation_id);
            assert_eq!(final_record.principal, begin.principal);
            assert_eq!(final_record.key, begin.key);
            assert_eq!(final_record.applied, AppliedState::Applied);
        }
    }
}
#[test]
fn configuration_and_bindings_are_bounded_and_immutable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    assert!(AuditConfig::new(path.clone(), 0, 0, 0, 0).is_err());
    assert!(AuditConfig::new(path.clone(), u64::MAX, u64::MAX, 1, 1).is_err());
    assert!(AuditConfig::new(path.clone(), 640, 800, 0, 1).is_err());
    let guard = DurableAuditGuard::create(AuditConfig::new(path, 640, 960, 1, 1).unwrap()).unwrap();
    let ctx = context();
    let key = KeyId::new("password/filename").unwrap();
    assert!(
        guard
            .bind(
                &ctx,
                AuditLabel::new([1; 16]),
                (0..33).map(|n| (KeyId::new(n.to_string()).unwrap(), AuditLabel::new([2; 16])))
            )
            .is_err()
    );
    let _bound = binding(&guard, &ctx, &key);
    assert!(
        guard
            .bind(
                &ctx,
                AuditLabel::new([3; 16]),
                [(key.clone(), AuditLabel::new([4; 16]))]
            )
            .is_err()
    );
    assert!(
        guard
            .bind(
                &context(),
                AuditLabel::new([3; 16]),
                [(key, AuditLabel::new([4; 16]))]
            )
            .is_err()
    );
}

#[test]
fn interrupted_repair_preserves_begin_and_truthful_unknown_outcome() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    {
        let guard = DurableAuditGuard::create(config(&path)).unwrap();
        let rig = Rig::new(guard.clone());
        let (mut ctx, _binding) = rig.begin();
        *rig.actual.after.lock().unwrap() = Some(FaultPoint::PartialWrite);
        assert_eq!(
            rig.sign(&mut ctx).unwrap_err().applied_state(),
            AppliedState::Applied
        );
        assert_eq!(rig.calls(), 1);
        guard.inject_fault(FaultPoint::BeforeWrite);
        assert!(guard.recover().is_err());
        assert_eq!(
            guard
                .records()
                .unwrap()
                .iter()
                .filter(|r| r.kind == RecordKind::Begin)
                .count(),
            1
        );
    }
    let guard = DurableAuditGuard::open(config(&path)).unwrap();
    assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
    assert_eq!(guard.recover().unwrap().resolved_unknown, 1);
    let records = guard.records().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == RecordKind::Begin)
            .count(),
        1
    );
    let final_record = records.iter().find(|r| r.kind.is_final()).unwrap();
    assert_eq!(final_record.applied, AppliedState::Unknown);
    assert!(!final_record.succeeded);
    let recovery = records
        .iter()
        .find(|r| r.kind == RecordKind::Recovery)
        .unwrap();
    assert_eq!(recovery.repair_from, recovery.repair_to);
    assert_eq!(guard.health(), AuditHealth::Healthy);
}

#[test]
fn restart_cannot_clear_failure_without_explicit_durable_probe() {
    for point in [FaultPoint::BeforeWrite, FaultPoint::AfterSync] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit");
        {
            let guard = DurableAuditGuard::create(config(&path)).unwrap();
            let rig = Rig::new(guard.clone());
            let (mut ctx, _binding) = rig.begin();
            guard.inject_fault(point);
            assert!(rig.sign(&mut ctx).is_err());
            assert_eq!(rig.calls(), 0);
        }
        let guard = DurableAuditGuard::open(config(&path)).unwrap();
        assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
        let rig = Rig::new(guard.clone());
        let (mut ctx, _binding) = rig.begin();
        assert!(rig.sign(&mut ctx).is_err());
        assert_eq!(rig.calls(), 0);
        guard.recover().unwrap();
        let (mut ctx, _binding) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
        assert_eq!(rig.calls(), 1);
    }
}

#[test]
fn closed_binding_cannot_rebind_actor_and_tombstone_releases_admission() {
    let temp = tempfile::tempdir().unwrap();
    let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
        max_in_flight: 1,
        ..ResourceLimits::default()
    }))
    .unwrap();
    let grant = || ExecutionGrant::new([Action::Hash]);
    let ctx = engine
        .begin(
            grant(),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let key = KeyId::new("key").unwrap();
    let bound = binding(&guard, &ctx, &key);
    drop(bound);
    assert!(
        guard
            .bind(
                &ctx,
                AuditLabel::new([3; 16]),
                [(key, AuditLabel::new([4; 16]))]
            )
            .is_err()
    );
    drop(ctx);
    assert!(
        engine
            .begin(
                grant(),
                OperationPolicy::offline_report(),
                Arc::new(Control)
            )
            .is_ok()
    );
}

#[test]
fn closed_binding_capacity_expires_only_at_original_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let guard = DurableAuditGuard::create(
        AuditConfig::new(temp.path().join("audit"), 4096, 16384, 3, 1).unwrap(),
    )
    .unwrap();
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
        operation_timeout: std::time::Duration::from_millis(30),
        max_in_flight: 4,
        ..ResourceLimits::default()
    }))
    .unwrap();
    let first = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    let key = KeyId::new("key").unwrap();
    drop(binding(&guard, &first, &key));
    let second = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    assert!(
        guard
            .bind(
                &second,
                AuditLabel::new([3; 16]),
                [(key.clone(), AuditLabel::new([4; 16]))]
            )
            .is_err()
    );
    std::thread::sleep(std::time::Duration::from_millis(60));
    assert!(
        guard
            .bind(
                &first,
                AuditLabel::new([3; 16]),
                [(key.clone(), AuditLabel::new([4; 16]))]
            )
            .is_err()
    );
    let third = engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::offline_report(),
            Arc::new(Control),
        )
        .unwrap();
    assert!(
        guard
            .bind(
                &third,
                AuditLabel::new([3; 16]),
                [(key, AuditLabel::new([4; 16]))]
            )
            .is_ok()
    );
}

#[test]
fn pending_receipt_retains_original_admission_until_durable_final() {
    for fail in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
        let engine = Engine::new(EngineServices::hash_only(ResourceLimits {
            max_in_flight: 1,
            ..ResourceLimits::default()
        }))
        .unwrap();
        let start = || {
            engine.begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::offline_report(),
                Arc::new(Control),
            )
        };
        let ctx = start().unwrap();
        let key = KeyId::new("key").unwrap();
        let bound = binding(&guard, &ctx, &key);
        let receipt = guard.before_use(&event(&ctx, &key)).unwrap();
        drop(bound);
        drop(ctx);
        assert!(start().is_err());
        if fail {
            guard.inject_fault(FaultPoint::BeforeWrite);
            assert!(guard.finish(receipt, done()).is_err());
            assert!(start().is_err());
            guard.recover().unwrap();
        } else {
            guard.finish(receipt, done()).unwrap();
        }
        assert!(start().is_ok());
    }
}
#[test]
fn legitimate_receipt_from_another_guard_does_not_consume_this_begin() {
    let temp = tempfile::tempdir().unwrap();
    let first = DurableAuditGuard::create(config(&temp.path().join("first"))).unwrap();
    let second = DurableAuditGuard::create(config(&temp.path().join("second"))).unwrap();
    let ctx = context();
    let key = KeyId::new("key").unwrap();
    let _a = binding(&first, &ctx, &key);
    let _b = binding(&second, &ctx, &key);
    let first_receipt = first.before_use(&event(&ctx, &key)).unwrap();
    let second_receipt = second.before_use(&event(&ctx, &key)).unwrap();
    assert!(second.finish(first_receipt, done()).is_err());
    assert!(second.recover().is_err());
    assert!(second.finish(second_receipt, done()).is_err());
    assert_eq!(
        second
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.kind.is_final())
            .count(),
        1
    );
    second.recover().unwrap();
}

#[test]
fn foreign_partial_tail_is_not_truncated_as_an_own_record() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    {
        let _guard = DurableAuditGuard::create(config(&path)).unwrap();
    }
    let file = journal(&path);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(b"FOREIGN partial data")
        .unwrap();
    let original = std::fs::read(&file).unwrap();
    let guard = DurableAuditGuard::open(config(&path)).unwrap();
    assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
    assert!(guard.recover().is_err());
    assert_eq!(std::fs::read(file).unwrap(), original);
}

#[test]
fn observed_complete_record_corruption_poison_blocks_fresh_private_contexts() {
    use std::io::{Seek, SeekFrom, Write};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard = DurableAuditGuard::create(config(&path)).unwrap();
    let rig = Rig::new(guard.clone());
    let (mut ctx, _bound) = rig.begin();
    rig.verify(&rig.sign(&mut ctx).unwrap());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(journal(&path))
        .unwrap();
    file.seek(SeekFrom::Start(FRAME_BYTES + 80)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    assert!(guard.records().is_err());
    assert_eq!(guard.health(), AuditHealth::Failed);
    let (mut fresh, _fresh_bound) = rig.begin();
    assert_eq!(
        rig.sign(&mut fresh).unwrap_err().applied_state(),
        AppliedState::NotApplied
    );
    assert_eq!(rig.calls(), 1);
    assert!(guard.recover().is_err());
}

#[test]
fn actual_lost_private_response_and_failed_final_stay_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
    let rig = Rig::new(guard.clone());
    let (mut ctx, _bound) = rig.begin();
    rig.actual
        .lose_response
        .store(true, std::sync::atomic::Ordering::SeqCst);
    *rig.actual.after.lock().unwrap() = Some(FaultPoint::BeforeWrite);
    assert_eq!(
        rig.sign(&mut ctx).unwrap_err().applied_state(),
        AppliedState::Unknown
    );
    assert_eq!(rig.calls(), 1);
    rig.verify(&rig.actual.signatures.lock().unwrap()[0]);
    assert_eq!(guard.health(), AuditHealth::Failed);
    assert_eq!(guard.recover().unwrap().resolved_unknown, 1);
    let final_record = guard
        .records()
        .unwrap()
        .into_iter()
        .find(|record| record.kind.is_final())
        .unwrap();
    assert_eq!(final_record.applied, AppliedState::Unknown);
    assert!(!final_record.succeeded);
}

#[test]
fn live_retained_nonfinal_partial_segment_never_recovers_or_admits_key_use() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard =
        DurableAuditGuard::create(AuditConfig::new(path.clone(), 800, 5000, 3, 32).unwrap())
            .unwrap();
    let rig = Rig::new(guard.clone());
    for _ in 0..2 {
        let (mut ctx, _bound) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
    }
    let mut segments: Vec<_> = std::fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect();
    segments.sort();
    assert_eq!(segments.len(), 2);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&segments[0])
        .unwrap()
        .write_all(b"foreign")
        .unwrap();
    let before: Vec<_> = segments
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    assert!(guard.records().is_err());
    assert_eq!(guard.health(), AuditHealth::Failed);
    assert!(guard.recover().is_err());
    assert_eq!(guard.health(), AuditHealth::Failed);
    let (mut fresh, _fresh_bound) = rig.begin();
    assert_eq!(
        rig.sign(&mut fresh).unwrap_err().applied_state(),
        AppliedState::NotApplied
    );
    assert_eq!(rig.calls(), 2);
    for (path, expected) in segments.iter().zip(before) {
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }
}

fn minimum_config(path: &std::path::Path) -> AuditConfig {
    AuditConfig::new(path.to_owned(), 640, 960, 1, 32).unwrap()
}

#[test]
fn minimum_journal_repeated_clean_reopen_recovery_stays_writable() {
    for (segment, quota, retained) in [(640, 960, 1), (800, 1600, 3), (960, 1280, 2)] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit");
        let config = AuditConfig::new(path.clone(), segment, quota, retained, 32).unwrap();
        {
            let guard = DurableAuditGuard::create(config.clone()).unwrap();
            let rig = Rig::new(guard);
            let (mut ctx, _bound) = rig.begin();
            rig.verify(&rig.sign(&mut ctx).unwrap());
            assert_eq!(rig.calls(), 1);
        }
        for _ in 0..16 {
            let guard = DurableAuditGuard::open(config.clone()).unwrap();
            assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
            guard.recover().unwrap();
            assert_eq!(guard.health(), AuditHealth::Healthy);
            let files: Vec<_> = std::fs::read_dir(&path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            let segments = files
                .iter()
                .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
                .count();
            assert!(segments >= 1 && segments <= retained);
            assert!(
                files
                    .iter()
                    .map(|path| path.metadata().unwrap().len())
                    .sum::<u64>()
                    <= quota
            );
        }
        let guard = DurableAuditGuard::open(config).unwrap();
        guard.recover().unwrap();
        let rig = Rig::new(guard);
        let (mut ctx, _bound) = rig.begin();
        let signature = rig.sign(&mut ctx).unwrap_or_else(|error| panic!("segment={segment} quota={quota} retained={retained} actual_calls={} file_lengths={:?}: {error:?}", rig.calls(), std::fs::read_dir(&path).unwrap().map(|entry|entry.unwrap().metadata().unwrap().len()).collect::<Vec<_>>()));
        rig.verify(&signature);
        assert_eq!(rig.calls(), 1);
    }
}

#[test]
fn complete_recovery_probe_retry_preserves_final_capacity_at_minimum_config() {
    for point in [
        FaultPoint::BeforeWrite,
        FaultPoint::PartialWrite,
        FaultPoint::BeforeSync,
        FaultPoint::AfterSync,
    ] {
        for restart in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("audit");
            {
                let guard = DurableAuditGuard::create(minimum_config(&path)).unwrap();
                let rig = Rig::new(guard);
                let (mut ctx, _bound) = rig.begin();
                *rig.actual.after.lock().unwrap() = Some(FaultPoint::BeforeWrite);
                assert_eq!(
                    rig.sign(&mut ctx).unwrap_err().applied_state(),
                    AppliedState::Applied
                );
                assert_eq!(rig.calls(), 1);
                rig.verify(&rig.actual.signatures.lock().unwrap()[0]);
            }
            let guard = DurableAuditGuard::open(minimum_config(&path)).unwrap();
            guard.inject_fault(point);
            assert!(guard.recover().is_err());
            assert_eq!(guard.health(), AuditHealth::Failed);
            let guard = if restart {
                drop(guard);
                let guard = DurableAuditGuard::open(minimum_config(&path)).unwrap();
                assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
                guard
            } else {
                guard
            };
            assert_eq!(guard.recover().unwrap().resolved_unknown, 1);
            assert_eq!(guard.health(), AuditHealth::Healthy);
            let records = guard.records().unwrap();
            assert_eq!(
                records
                    .iter()
                    .filter(|record| record.kind == RecordKind::Begin)
                    .count(),
                1
            );
            let finals: Vec<_> = records
                .iter()
                .filter(|record| record.kind.is_final())
                .collect();
            assert_eq!(finals.len(), 1);
            assert_eq!(finals[0].applied, AppliedState::Unknown);
            assert!(!finals[0].succeeded);
        }
    }
}

#[test]
fn interrupted_probe_then_owned_torn_final_recovers_without_losing_begin() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    {
        let guard = DurableAuditGuard::create(minimum_config(&path)).unwrap();
        let rig = Rig::new(guard);
        let (mut ctx, _bound) = rig.begin();
        *rig.actual.after.lock().unwrap() = Some(FaultPoint::BeforeWrite);
        assert_eq!(
            rig.sign(&mut ctx).unwrap_err().applied_state(),
            AppliedState::Applied
        );
        assert_eq!(rig.calls(), 1);
        rig.verify(&rig.actual.signatures.lock().unwrap()[0]);
    }
    {
        let guard = DurableAuditGuard::open(minimum_config(&path)).unwrap();
        guard.inject_fault(FaultPoint::AfterSync);
        assert!(guard.recover().is_err());
        let records = guard.records().unwrap();
        assert_eq!(records.last().unwrap().kind, RecordKind::Recovery);
    }
    let file = journal(&path);
    let bytes = std::fs::read(&file).unwrap();
    // The first 79 bytes of a FINAL equal its genuine BEGIN except for sequence:
    // simulate a crash during that actual own pending FINAL, not foreign data.
    let mut final_prefix = bytes[FRAME_BYTES as usize..FRAME_BYTES as usize + 79].to_vec();
    final_prefix[24..32].copy_from_slice(&3u64.to_le_bytes());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(&final_prefix)
        .unwrap();
    let guard = DurableAuditGuard::open(minimum_config(&path)).unwrap();
    let report = guard.recover().unwrap();
    assert_eq!(report.truncated_bytes, 79);
    assert_eq!(report.resolved_unknown, 1);
    assert_eq!(guard.health(), AuditHealth::Healthy);
    let records = guard.records().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| record.kind == RecordKind::Begin)
            .count(),
        1
    );
    let final_record = records
        .iter()
        .find(|record| record.kind.is_final())
        .unwrap();
    assert_eq!(final_record.applied, AppliedState::Unknown);
    assert!(!final_record.succeeded);
    assert_eq!(final_record.repair_from - final_record.repair_to, 79);
}

#[test]
fn failed_replacement_creation_keeps_durable_records_and_foreign_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard = DurableAuditGuard::create(minimum_config(&path)).unwrap();
    let rig = Rig::new(guard.clone());
    let (mut first, _first_bound) = rig.begin();
    rig.verify(&rig.sign(&mut first).unwrap());
    let original = journal(&path);
    let before = std::fs::read(&original).unwrap();
    let foreign = path.join("oncl-audit-0000000000000001.log");
    std::fs::write(&foreign, b"foreign existing segment name").unwrap();
    let (mut next, _next_bound) = rig.begin();
    assert_eq!(
        rig.sign(&mut next).unwrap_err().applied_state(),
        AppliedState::NotApplied
    );
    assert_eq!(rig.calls(), 1);
    assert_eq!(guard.health(), AuditHealth::Failed);
    assert_eq!(std::fs::read(original).unwrap(), before);
    assert_eq!(
        std::fs::read(foreign).unwrap(),
        b"foreign existing segment name"
    );
}

#[test]
fn real_mixed_batch_persists_original_zero_gaps_multi_key_and_nonbatch_ordinals() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard = DurableAuditGuard::create(config(&path)).unwrap();
    let rig = batch_support::BatchRig::new(guard.clone(), temp.path());
    let proof = rig.exercise(None);
    assert_eq!(proof.summary.completed, 6);
    assert!(
        !proof.raw_zero.is_empty()
            && !proof.cms.is_empty()
            && !proof.gost.is_empty()
            && !proof.outside.is_empty()
    );
    assert!(proof.actual_proof.is_empty());
    let before = rig.observed.before.lock().unwrap();
    let finished = rig.observed.finished.lock().unwrap();
    let expected = [None, Some(0), Some(2), Some(2), Some(5), None];
    assert_eq!(
        before
            .iter()
            .map(|observed| observed.event.batch_item().map(|item| item.get()))
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        finished
            .iter()
            .map(|observed| observed.event.batch_item().map(|item| item.get()))
            .collect::<Vec<_>>(),
        expected
    );
    let records = guard.records().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| record.kind == RecordKind::Begin)
            .map(|record| record.batch_item)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record.kind == RecordKind::Final)
            .map(|record| record.batch_item)
            .collect::<Vec<_>>(),
        expected
    );
    let bytes = std::fs::read(journal(&path)).unwrap();
    let frames: Vec<_> = bytes
        .as_chunks::<{ FRAME_BYTES as usize }>()
        .0
        .iter()
        .skip(1)
        .collect();
    assert_eq!(frames.len(), expected.len() * 2);
    for (index, observed) in before.iter().enumerate() {
        let begin = frames[index * 2];
        let final_record = frames[index * 2 + 1];
        for frame in [begin, final_record] {
            let item = match frame[126] {
                0 => None,
                1 => Some(u16::from_le_bytes(frame[124..126].try_into().unwrap())),
                _ => panic!("unknown item framing"),
            };
            assert_eq!(item, expected[index]);
            assert_eq!(
                u64::from_le_bytes(frame[32..40].try_into().unwrap()),
                observed.correlation.1
            );
            assert_eq!(
                u64::from_le_bytes(frame[40..48].try_into().unwrap()),
                proof.operation
            );
            assert_eq!(&frame[64..80], &[0x55; 16]);
        }
        assert_eq!(begin[104], 1);
        assert_eq!(final_record[104], 2);
        assert_eq!(final_record[106], 1);
        assert_eq!(final_record[107], 1);
    }
    assert!(
        !bytes
            .windows(b"drive_C:/guest/secret-name".len())
            .any(|window| window == b"drive_C:/guest/secret-name")
    );
}

#[test]
fn real_batch_post_use_audit_failure_keeps_item_zero_applied_and_no_publish() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard = DurableAuditGuard::create(config(&path)).unwrap();
    let rig = batch_support::BatchRig::new(guard.clone(), temp.path());
    let proof = rig.exercise(Some(FaultPoint::PartialWrite));
    assert_eq!(proof.summary.completed, 0);
    assert_eq!(rig.counts(), [2, 0]);
    rig.rsa_public()
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            support::MESSAGE,
            &proof.actual_proof,
        )
        .unwrap();
    assert!(
        proof.raw_zero.is_empty()
            && proof.cms.is_empty()
            && proof.gost.is_empty()
            && proof.outside.is_empty()
    );
    let before = rig.observed.before.lock().unwrap();
    let finished = rig.observed.finished.lock().unwrap();
    assert_eq!(before.last().unwrap().event.batch_item().unwrap().get(), 0);
    assert_eq!(
        finished.last().unwrap().event.batch_item().unwrap().get(),
        0
    );
    assert_eq!(
        finished.last().unwrap().outcome.unwrap().applied,
        AppliedState::Applied
    );
    assert!(!finished.last().unwrap().acknowledged);
    drop(before);
    drop(finished);
    assert_eq!(
        rig.nonbatch().unwrap_err().applied_state(),
        AppliedState::NotApplied
    );
    assert_eq!(rig.counts(), [2, 0]);
    guard.recover().unwrap();
    let bytes = std::fs::read(journal(&path)).unwrap();
    let finals: Vec<_> = bytes
        .as_chunks::<{ FRAME_BYTES as usize }>()
        .0
        .iter()
        .filter(|frame| frame[104] == 2)
        .collect();
    assert_eq!(finals.len(), 2);
    let repaired = finals.last().unwrap();
    assert_eq!(repaired[126], 1);
    assert_eq!(
        u16::from_le_bytes(repaired[124..126].try_into().unwrap()),
        0
    );
    assert_eq!(repaired[106], 1);
    let records = guard.records().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| record.kind.is_final())
            .map(|record| record.batch_item)
            .collect::<Vec<_>>(),
        [None, Some(0)]
    );
    assert!(!rig.nonbatch().unwrap().is_empty());
    assert_eq!(rig.counts(), [3, 0]);
}

#[test]
fn original_context_event_constructor_cannot_swap_another_pending_use() {
    let temp = tempfile::tempdir().unwrap();
    let guard = DurableAuditGuard::create(config(&temp.path().join("audit"))).unwrap();
    let first = context();
    let other = context();
    let key = KeyId::new("host key").unwrap();
    let _first = binding(&guard, &first, &key);
    let _other = guard
        .bind(
            &other,
            AuditLabel::new([9; 16]),
            [(key.clone(), AuditLabel::new([8; 16]))],
        )
        .unwrap();
    let receipt = guard.before_use(&event(&first, &key)).unwrap();
    let correlation = receipt.correlation().unwrap();
    let wrong = KeyUseReceipt::with_correlation(
        KeyUseEvent::new(&other, key.clone(), Action::SignDigest),
        correlation.0,
        correlation.1,
    );
    let outcome = KeyUseOutcome {
        applied: AppliedState::NotApplied,
        succeeded: false,
    };
    assert!(guard.finish(wrong, outcome).is_err());
    assert_eq!(
        guard
            .records()
            .unwrap()
            .iter()
            .filter(|record| record.kind.is_final())
            .count(),
        0
    );
    assert!(guard.finish(receipt, outcome).is_err());
    let records = guard.records().unwrap();
    let final_record = records
        .iter()
        .find(|record| record.kind.is_final())
        .unwrap();
    assert_eq!(final_record.operation_id, first.id().get());
    assert_eq!(final_record.principal, AuditLabel::new([1; 16]));
    assert_eq!(final_record.key, AuditLabel::new([2; 16]));
    assert_eq!(final_record.batch_item, None);
    assert_eq!(final_record.applied, AppliedState::NotApplied);
}

#[test]
fn bounded_item_codec_checks_numeric_domain_even_with_complete_checksums() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard = DurableAuditGuard::create(config(&path)).unwrap();
    let rig = Rig::new(guard.clone());
    let (mut ctx, _bound) = rig.begin();
    rig.verify(&rig.sign(&mut ctx).unwrap());
    let file = journal(&path);
    let original = std::fs::read(&file).unwrap();
    // Journal decoder input, not authority or a claim that this non-batch call
    // came from item1023: owner-edited frames are intentionally not nonrepudiation.
    let with_item = |item: u16| {
        let mut bytes = original.clone();
        for frame in bytes
            .as_chunks_mut::<{ FRAME_BYTES as usize }>()
            .0
            .iter_mut()
            .skip(1)
        {
            frame[124..126].copy_from_slice(&item.to_le_bytes());
            frame[126] = 1;
            let mut hash = oncl_pki::digest::HashState::new(oncl_pki::key::HashAlg::Sha256);
            hash.update(&frame[..128]);
            frame[128..].copy_from_slice(hash.finish().as_bytes());
        }
        bytes
    };
    std::fs::write(&file, with_item(1023)).unwrap();
    let records = guard.records().unwrap();
    assert_eq!(records[1].batch_item, Some(1023));
    assert_eq!(records[2].batch_item, Some(1023));
    let invalid = with_item(1024);
    std::fs::write(&file, &invalid).unwrap();
    assert!(guard.records().is_err());
    assert_eq!(guard.health(), AuditHealth::Failed);
    assert!(guard.recover().is_err());
    assert_eq!(std::fs::read(file).unwrap(), invalid);
    assert_eq!(rig.calls(), 1);
}

#[test]
fn real_batch_restart_preserves_item_zero_and_unknown_applied_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let (operation, public, signature) = {
        let guard = DurableAuditGuard::create(config(&path)).unwrap();
        let rig = batch_support::BatchRig::new(guard, temp.path());
        let proof = rig.exercise(Some(FaultPoint::PartialWrite));
        assert_eq!(rig.counts(), [2, 0]);
        (
            proof.operation,
            rig.rsa_public().clone(),
            proof.actual_proof,
        )
    };
    public
        .verify(
            oncl_pki::key::SigAlg::RsaSha256,
            support::MESSAGE,
            &signature,
        )
        .unwrap();
    let guard = DurableAuditGuard::open(config(&path)).unwrap();
    assert_eq!(guard.health(), AuditHealth::RecoveryRequired);
    let repaired = guard.recover().unwrap();
    assert_eq!(repaired.truncated_bytes, 79);
    assert_eq!(repaired.resolved_unknown, 1);
    let records = guard.records().unwrap();
    let final_record = records
        .iter()
        .find(|record| record.kind.is_final() && record.batch_item == Some(0))
        .unwrap();
    assert_eq!(final_record.operation_id, operation);
    assert_eq!(final_record.applied, AppliedState::Unknown);
    assert!(!final_record.succeeded);
    assert_eq!(final_record.principal, AuditLabel::new([0x55; 16]));
    assert_eq!(final_record.key, AuditLabel::new([0x61; 16]));
}

fn legacy_format_image(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len().is_multiple_of(FRAME_BYTES as usize));
    let mut legacy = bytes.to_vec();
    for frame in legacy.as_chunks_mut::<{ FRAME_BYTES as usize }>().0 {
        frame[..8].copy_from_slice(b"ONCLAU01");
        frame[124..128].fill(0);
        let mut hash = oncl_pki::digest::HashState::new(oncl_pki::key::HashAlg::Sha256);
        hash.update(&frame[..128]);
        frame[128..].copy_from_slice(hash.finish().as_bytes());
    }
    legacy
}

fn journal_images(
    path: &std::path::Path,
    identity: bool,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| identity || path.file_name().unwrap() != "oncl-audit.identity")
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

#[test]
fn legacy_own_complete_and_pending_batch_journals_are_refused_without_mutation() {
    for pending in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit");
        {
            let guard = DurableAuditGuard::create(config(&path)).unwrap();
            let rig = batch_support::BatchRig::new(guard, temp.path());
            let proof = rig.exercise(pending.then_some(FaultPoint::BeforeWrite));
            assert_eq!(rig.counts(), if pending { [2, 0] } else { [4, 2] });
            if pending {
                rig.rsa_public()
                    .verify(
                        oncl_pki::key::SigAlg::RsaSha256,
                        support::MESSAGE,
                        &proof.actual_proof,
                    )
                    .unwrap();
                assert!(
                    proof.raw_zero.is_empty()
                        && proof.cms.is_empty()
                        && proof.gost.is_empty()
                        && proof.outside.is_empty()
                );
            } else {
                assert_eq!(proof.summary.completed, 6);
            }
        }
        for (file, bytes) in journal_images(&path, true) {
            // Real own identity/headers and actual private-use history rendered
            // exactly as v01: valid checksums, reserved zero, item unknowable.
            std::fs::write(file, legacy_format_image(&bytes)).unwrap();
        }
        let before = journal_images(&path, true);
        let mut accepted = false;
        let mut extra_calls = 0;
        if let Ok(guard) = DurableAuditGuard::open(config(&path)) {
            accepted = true;
            if guard.recover().is_ok() {
                let rig = Rig::new(guard);
                let (mut ctx, _bound) = rig.begin();
                if let Ok(signature) = rig.sign(&mut ctx) {
                    rig.verify(&signature);
                }
                extra_calls = rig.calls();
            }
        }
        assert!(
            !accepted,
            "legacy accepted; extra actual key calls={extra_calls}"
        );
        assert_eq!(extra_calls, 0);
        assert_eq!(journal_images(&path, true), before);
    }
}

#[test]
fn legacy_identity_header_and_records_fail_closed_in_live_read_and_recovery() {
    let components: &[usize] = if cfg!(windows) {
        &[1, 2, 3]
    } else {
        &[0, 1, 2, 3]
    };
    for &component in components {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit");
        let guard = DurableAuditGuard::create(config(&path)).unwrap();
        let rig = Rig::new(guard.clone());
        let (mut ctx, _bound) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
        #[cfg(windows)]
        assert!(
            std::fs::read(path.join("oncl-audit.identity")).is_err(),
            "exclusive Windows identity lock must refuse an unrelated handle"
        );
        let file = if component == 0 {
            path.join("oncl-audit.identity")
        } else {
            journal(&path)
        };
        let mut bytes = std::fs::read(&file).unwrap();
        let frame = if component == 0 { 0 } else { component - 1 };
        let start = frame * FRAME_BYTES as usize;
        let legacy = legacy_format_image(&bytes[start..start + FRAME_BYTES as usize]);
        bytes[start..start + FRAME_BYTES as usize].copy_from_slice(&legacy);
        std::fs::write(&file, bytes).unwrap();
        let before = journal_images(&path, cfg!(unix));
        assert!(guard.records().is_err(), "legacy component={component}");
        assert_eq!(guard.health(), AuditHealth::Failed);
        assert!(guard.recover().is_err());
        let (mut fresh, _fresh_bound) = rig.begin();
        assert_eq!(
            rig.sign(&mut fresh).unwrap_err().applied_state(),
            AppliedState::NotApplied
        );
        assert_eq!(rig.calls(), 1);
        assert_eq!(journal_images(&path, cfg!(unix)), before);
    }
}

#[test]
fn legacy_mixed_identity_header_and_record_versions_refuse_open_without_repair() {
    for component in [0, 1, 2, 3] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit");
        {
            let guard = DurableAuditGuard::create(config(&path)).unwrap();
            let rig = Rig::new(guard);
            let (mut ctx, _bound) = rig.begin();
            rig.verify(&rig.sign(&mut ctx).unwrap());
            assert_eq!(rig.calls(), 1);
        }
        let file = if component == 0 {
            path.join("oncl-audit.identity")
        } else {
            journal(&path)
        };
        let mut bytes = std::fs::read(&file).unwrap();
        let frame = if component == 0 { 0 } else { component - 1 };
        let start = frame * FRAME_BYTES as usize;
        let legacy = legacy_format_image(&bytes[start..start + FRAME_BYTES as usize]);
        bytes[start..start + FRAME_BYTES as usize].copy_from_slice(&legacy);
        std::fs::write(&file, bytes).unwrap();
        let before = journal_images(&path, true);
        assert!(
            DurableAuditGuard::open(config(&path)).is_err(),
            "legacy component={component}"
        );
        assert_eq!(journal_images(&path, true), before);
    }
}

#[test]
fn current_presence_reserved_and_header_item_fields_fail_closed_without_mutation() {
    for (target, item, presence, reserved) in
        [(1, 0u16, 2, 0), (1, 1, 0, 0), (1, 0, 0, 1), (0, 0, 1, 0)]
    {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("audit");
        let guard = DurableAuditGuard::create(config(&path)).unwrap();
        let rig = Rig::new(guard.clone());
        let (mut ctx, _bound) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
        let file = journal(&path);
        let mut bytes = std::fs::read(&file).unwrap();
        let start = target * FRAME_BYTES as usize;
        let frame = &mut bytes[start..start + FRAME_BYTES as usize];
        frame[124..126].copy_from_slice(&item.to_le_bytes());
        frame[126] = presence;
        frame[127] = reserved;
        let mut hash = oncl_pki::digest::HashState::new(oncl_pki::key::HashAlg::Sha256);
        hash.update(&frame[..128]);
        frame[128..].copy_from_slice(hash.finish().as_bytes());
        std::fs::write(&file, &bytes).unwrap();
        assert!(guard.records().is_err());
        assert_eq!(guard.health(), AuditHealth::Failed);
        assert!(guard.recover().is_err());
        let (mut fresh, _fresh_bound) = rig.begin();
        assert_eq!(
            rig.sign(&mut fresh).unwrap_err().applied_state(),
            AppliedState::NotApplied
        );
        assert_eq!(rig.calls(), 1);
        assert_eq!(std::fs::read(file).unwrap(), bytes);
    }
}
