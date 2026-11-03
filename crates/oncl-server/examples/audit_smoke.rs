//! Local synthetic-only acceptance harness; never reads operator private keys.
#[path = "../tests/support/mod.rs"]
mod support;
use oncl_core::keys::AppliedState;
use oncl_server::audit::{AuditConfig, AuditHealth, DurableAuditGuard, FaultPoint, RecordKind};
use support::{MESSAGE, Rig};
fn config(path: std::path::PathBuf) -> AuditConfig {
    AuditConfig::new(path, 4096, 16384, 3, 32).unwrap()
}
fn main() {
    let output = std::path::PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("synthetic smoke output directory"),
    );
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("message.bin"), MESSAGE).unwrap();
    for mode in ["writable", "before", "after", "restart"] {
        let path = output.join(mode);
        let audit = DurableAuditGuard::create(config(path.clone())).unwrap();
        let rig = Rig::new(audit.clone());
        let (mut ctx, _binding) = rig.begin();
        if mode == "before" {
            audit.inject_fault(FaultPoint::BeforeWrite);
        }
        if mode == "after" {
            *rig.actual.after.lock().unwrap() = Some(FaultPoint::BeforeSync);
        }
        if mode == "restart" {
            *rig.actual.after.lock().unwrap() = Some(FaultPoint::PartialWrite);
        }
        let result = rig.sign(&mut ctx);
        let (applied, publish) = match result {
            Ok(signature) => {
                rig.verify(&signature);
                std::fs::write(output.join(format!("{mode}.published.sig")), signature).unwrap();
                (AppliedState::Applied, "Published")
            }
            Err(error) => (error.applied_state(), "NoPublish"),
        };
        let signatures = rig.actual.signatures.lock().unwrap();
        if let Some(signature) = signatures.first() {
            rig.verify(signature);
            std::fs::write(output.join(format!("{mode}.actual-proof.sig")), signature).unwrap();
        }
        if let oncl_pki::key::PublicKey::Rsa(der) = rig.actual.key.public_key() {
            std::fs::write(output.join("public-rsa.pkcs1.der"), der).unwrap();
        }
        let frames = audit.records().unwrap();
        println!(
            "{mode}: actual_key_calls={} Applied={applied:?} Artifact={publish} health={:?} complete_frames={} begin={} final={}",
            rig.calls(),
            audit.health(),
            frames.len(),
            frames
                .iter()
                .filter(|e| e.kind == RecordKind::Begin)
                .count(),
            frames
                .iter()
                .filter(|e| e.kind == RecordKind::Final)
                .count()
        );
        assert_eq!(rig.calls(), usize::from(mode != "before"));
        assert_eq!(
            applied,
            if mode == "before" {
                AppliedState::NotApplied
            } else {
                AppliedState::Applied
            }
        );
        drop(signatures);
        drop(_binding);
        drop(ctx);
        drop(rig);
        drop(audit);
        let audit = DurableAuditGuard::open(config(path)).unwrap();
        if mode == "restart" {
            assert_eq!(audit.health(), AuditHealth::RecoveryRequired);
            let repair = audit.recover().unwrap();
            assert_eq!(repair.truncated_bytes, 79);
            assert_eq!(repair.resolved_unknown, 1);
            let final_record = audit
                .records()
                .unwrap()
                .into_iter()
                .find(|e| e.kind.is_final())
                .unwrap();
            assert_eq!(final_record.applied, AppliedState::Unknown);
            println!(
                "restart: explicit durable recovery truncated=79 FINAL=Unknown health={:?}",
                audit.health()
            );
        }
    }
    let path = output.join("rotation");
    let audit =
        DurableAuditGuard::create(AuditConfig::new(path.clone(), 800, 1120, 1, 32).unwrap())
            .unwrap();
    std::fs::write(path.join("foreign"), b"untouched").unwrap();
    let rig = Rig::new(audit.clone());
    for _ in 0..10 {
        let (mut ctx, _binding) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
    }
    let files: Vec<_> = std::fs::read_dir(&path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "log"))
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(std::fs::read(path.join("foreign")).unwrap(), b"untouched");
    let bytes = files[0].metadata().unwrap().len() + oncl_server::audit::FRAME_BYTES;
    assert!(bytes <= 1120);
    println!(
        "rotation: actual_key_calls={} retained_segments=1 quota_bytes={bytes}/1120 foreign=untouched",
        rig.calls()
    );
    let path = output.join("minimum-restarts");
    let minimum = || AuditConfig::new(path.clone(), 640, 960, 1, 32).unwrap();
    let mut calls = 0;
    {
        let rig = Rig::new(DurableAuditGuard::create(minimum()).unwrap());
        let (mut ctx, _binding) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
        calls += rig.calls();
    }
    for _ in 0..16 {
        let audit = DurableAuditGuard::open(minimum()).unwrap();
        assert_eq!(audit.health(), AuditHealth::RecoveryRequired);
        audit.recover().unwrap();
        assert_eq!(audit.health(), AuditHealth::Healthy);
    }
    {
        let audit = DurableAuditGuard::open(minimum()).unwrap();
        audit.recover().unwrap();
        let rig = Rig::new(audit);
        let (mut ctx, _binding) = rig.begin();
        rig.verify(&rig.sign(&mut ctx).unwrap());
        calls += rig.calls();
    }
    assert_eq!(calls, 2);
    let bytes: u64 = std::fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert!(bytes <= 960);
    println!(
        "minimum-restarts: segment=640 quota_bytes={bytes}/960 retained=1 explicit_recoveries=17 actual_key_calls={calls} writable=true"
    );
    let path = output.join("probe-retry");
    let minimum = || AuditConfig::new(path.clone(), 640, 960, 1, 32).unwrap();
    {
        let rig = Rig::new(DurableAuditGuard::create(minimum()).unwrap());
        let (mut ctx, _binding) = rig.begin();
        *rig.actual.after.lock().unwrap() = Some(FaultPoint::BeforeWrite);
        assert_eq!(
            rig.sign(&mut ctx).unwrap_err().applied_state(),
            AppliedState::Applied
        );
        assert_eq!(rig.calls(), 1);
        rig.verify(&rig.actual.signatures.lock().unwrap()[0]);
    }
    {
        let audit = DurableAuditGuard::open(minimum()).unwrap();
        audit.inject_fault(FaultPoint::AfterSync);
        assert!(audit.recover().is_err());
    }
    let audit = DurableAuditGuard::open(minimum()).unwrap();
    assert_eq!(audit.recover().unwrap().resolved_unknown, 1);
    assert_eq!(audit.health(), AuditHealth::Healthy);
    let records = audit.records().unwrap();
    assert_eq!(records.len(), 4);
    let final_record = records.last().unwrap();
    assert_eq!(final_record.applied, AppliedState::Unknown);
    assert!(!final_record.succeeded);
    println!(
        "probe-retry: segment=640 quota=960 actual_key_calls=1 Artifact=NoPublish FINAL={:?} complete_frames=4 health={:?}",
        final_record.applied,
        audit.health()
    );
}
