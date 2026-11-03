use oncl_pki::private_fs::{NamespaceSync, PrivateDirectory};
use std::io::{Read, Write};
#[test]
fn persistent_private_namespace_reopens_without_repairing_foreign_objects() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("private");
    let root = PrivateDirectory::create(&path).unwrap();
    let mut file = root.create_file("own-journal").unwrap();
    file.write_all(b"durable").unwrap();
    file.sync_all().unwrap();
    let sync = root.sync().unwrap();
    assert_eq!(
        sync,
        if cfg!(windows) {
            NamespaceSync::Unsupported
        } else {
            NamespaceSync::Synced
        }
    );
    assert!(root.create_file("own-journal").is_err());
    assert!(PrivateDirectory::create(&path).is_err());
    for name in ["../foreign", ".", "..", "a/b", "a\\b", "C:drive", ""] {
        assert!(root.create_file(name).is_err());
        assert!(root.open_file(name).is_err());
        assert!(root.remove_file(name).is_err());
    }
    std::fs::write(path.join("foreign"), b"do not touch").unwrap();
    drop(file);
    drop(root);
    let root = PrivateDirectory::open(&path).unwrap();
    let mut bytes = Vec::new();
    root.open_file("own-journal")
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"durable");
    assert!(root.names().unwrap().contains(&"foreign".to_owned()));
    assert_eq!(
        std::fs::read(path.join("foreign")).unwrap(),
        b"do not touch"
    );
}
#[test]
fn permissive_existing_root_is_rejected_without_chmod() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("foreign");
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(PrivateDirectory::open(&path).is_err());
    assert!(path.is_dir());
}
#[test]
fn hardlinked_journal_is_rejected_and_not_removed() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("private");
    let root = PrivateDirectory::create(&path).unwrap();
    let mut file = root.create_file("journal").unwrap();
    file.write_all(b"original").unwrap();
    drop(file);
    std::fs::hard_link(path.join("journal"), parent.path().join("foreign-link")).unwrap();
    assert!(root.open_file("journal").is_err());
    assert!(root.remove_file("journal").is_err());
    assert_eq!(
        std::fs::read(parent.path().join("foreign-link")).unwrap(),
        b"original"
    );
}
#[cfg(unix)]
#[test]
fn unix_modes_symlinks_and_pinned_root_identity() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("private");
    let root = PrivateDirectory::create(&path).unwrap();
    root.create_file("journal").unwrap();
    assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        path.join("journal").metadata().unwrap().mode() & 0o777,
        0o600
    );
    symlink(&path, parent.path().join("root-link")).unwrap();
    assert!(PrivateDirectory::open(&parent.path().join("root-link")).is_err());
    symlink(parent.path().join("outside"), path.join("file-link")).unwrap();
    assert!(root.open_file("file-link").is_err());
    assert!(root.create_file("file-link").is_err());
    assert!(root.remove_file("file-link").is_err());
    std::fs::rename(&path, parent.path().join("moved")).unwrap();
    std::fs::create_dir(&path).unwrap();
    root.create_file("after-rename").unwrap();
    assert!(parent.path().join("moved/after-rename").exists());
    assert!(!path.join("after-rename").exists());
}
#[cfg(windows)]
#[test]
fn windows_root_acl_pinning_and_actual_junction_refusal() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("private");
    let root = PrivateDirectory::create(&path).unwrap();
    root.create_file("journal").unwrap();
    assert!(std::fs::rename(&path, parent.path().join("moved")).is_err());
    let output = std::process::Command::new("icacls")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("(OI)(CI)(F)"), "{text}");
    assert!(!text.contains("(I)"), "{text}");
    let junction = parent.path().join("junction");
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(PrivateDirectory::open(&junction).is_err());
    drop(root);
    std::fs::remove_dir(junction).unwrap();
}
