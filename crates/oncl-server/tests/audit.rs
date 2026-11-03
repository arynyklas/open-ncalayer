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
    KeyUseEvent {
        operation_id: ctx.id(),
        key_id: key.clone(),
        action: Action::SignDigest,
    }
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
fn cross_process_exclusive_journal_lock() {
    if let Some(path) = std::env::var_os("ONCL_AUDIT_LOCK_CHILD") {
        assert!(DurableAuditGuard::open(config(std::path::Path::new(&path))).is_err());
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let _guard = DurableAuditGuard::create(config(&path)).unwrap();
    assert!(DurableAuditGuard::open(config(&path)).is_err());
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cross_process_exclusive_journal_lock",
            "--nocapture",
        ])
        .env("ONCL_AUDIT_LOCK_CHILD", &path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
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
