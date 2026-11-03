//! Fork/exec ownership checks run in their own test process: a POSIX child can
//! briefly inherit unrelated parallel-test journal descriptors until exec.
use oncl_server::audit::{AuditConfig, AuditHealth, DurableAuditGuard};

fn config(path: &std::path::Path) -> AuditConfig {
    AuditConfig::new(path.to_owned(), 4096, 16384, 3, 32).unwrap()
}
#[test]
fn cross_process_exclusive_journal_lock() {
    if let Some(path) = std::env::var_os("ONCL_AUDIT_LOCK_CHILD") {
        assert!(DurableAuditGuard::open(config(std::path::Path::new(&path))).is_err());
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit");
    let guard = DurableAuditGuard::create(config(&path)).unwrap();
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
    drop(guard);
    let reopened = DurableAuditGuard::open(config(&path)).unwrap();
    assert_eq!(reopened.health(), AuditHealth::RecoveryRequired);
    reopened.recover().unwrap();
    assert_eq!(reopened.health(), AuditHealth::Healthy);
}
