//! The built-in modules' build: reproducible, of this version, checked when taken built.

use oncl_builtins_build::{
    BUILTIN_ID_PREFIX, GUESTS, SUMS, WORKSPACE_VERSION, build, check_manifest, hex, take,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn two_builds_are_identical() {
    let dir = tempfile::tempdir().unwrap();
    let first = build(
        &workspace(),
        &dir.path().join("target-1"),
        &dir.path().join("out-1"),
    )
    .unwrap();
    let second = build(
        &workspace(),
        &dir.path().join("target-2"),
        &dir.path().join("out-2"),
    )
    .unwrap();
    assert_eq!(first.len(), GUESTS.len());
    for (a, b) in first.iter().zip(&second) {
        assert_eq!(a.package, b.package);
        assert_eq!(a.sha256, b.sha256, "{}", a.package);
        assert_eq!(fs::read(&a.wasm).unwrap(), fs::read(&b.wasm).unwrap());
        assert!(fs::read(&a.wasm).unwrap().starts_with(b"\0asm"));
    }
    assert_eq!(
        fs::read(dir.path().join("out-1").join(SUMS)).unwrap(),
        fs::read(dir.path().join("out-2").join(SUMS)).unwrap()
    );
    // What one build laid out, another takes as it is.
    let taken = take(&dir.path().join("out-1"), &dir.path().join("out-3")).unwrap();
    assert_eq!(
        taken.iter().map(|b| b.sha256).collect::<Vec<_>>(),
        first.iter().map(|b| b.sha256).collect::<Vec<_>>()
    );
}

#[test]
fn manifest_version_is_the_workspace_version() {
    assert_eq!(BUILTIN_ID_PREFIX, oncl_plugin::BUILTIN_ID_PREFIX);
    for guest in GUESTS {
        let manifest = fs::read_to_string(workspace().join(guest.dir).join("plugin.toml")).unwrap();
        check_manifest(&manifest).unwrap();
        // The core reads it as a built-in module's.
        let parsed = oncl_plugin::Manifest::from_toml_builtin(&manifest).unwrap();
        assert_eq!(parsed.version.to_string(), WORKSPACE_VERSION);
        assert_eq!(parsed.min_core.to_string(), WORKSPACE_VERSION);
        let other = manifest.replace(
            &format!("version = \"{WORKSPACE_VERSION}\""),
            "version = \"0.0.1\"",
        );
        let err = check_manifest(&other).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let plain = manifest.replace(BUILTIN_ID_PREFIX, "kz.example.");
        assert!(check_manifest(&plain).is_err());
    }
}

/// A folder of modules as `build` lays it out, with `wasm` as every module's code.
fn laid_out(dir: &Path, wasm: &[u8]) {
    let mut sums = String::new();
    for guest in GUESTS {
        let manifest = fs::read(workspace().join(guest.dir).join("plugin.toml")).unwrap();
        fs::create_dir_all(dir.join(guest.package)).unwrap();
        fs::write(dir.join(guest.package).join("plugin.toml"), &manifest).unwrap();
        fs::write(dir.join(guest.package).join("plugin.wasm"), wasm).unwrap();
        for (name, bytes) in [("plugin.toml", &manifest[..]), ("plugin.wasm", wasm)] {
            use sha2::Digest;
            sums.push_str(&format!(
                "{}  {}/{name}\n",
                hex(&sha2::Sha256::digest(bytes)),
                guest.package
            ));
        }
    }
    fs::write(dir.join(SUMS), sums).unwrap();
}

#[test]
fn take_rejects_sha_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let built = dir.path().join("built");
    laid_out(&built, b"\0asm\x01\0\0\0");
    let taken = take(&built, &dir.path().join("out")).unwrap();
    assert_eq!(taken.len(), GUESTS.len());
    assert_eq!(fs::read(&taken[0].wasm).unwrap(), b"\0asm\x01\0\0\0");
    assert!(dir.path().join("out").join(SUMS).exists());

    fs::write(
        built.join(GUESTS[0].package).join("plugin.wasm"),
        b"\0asm\x01\0\0\x01",
    )
    .unwrap();
    let err = take(&built, &dir.path().join("out-2")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    assert!(err.to_string().contains("does not match"), "{err}");

    fs::write(built.join(SUMS), "").unwrap();
    let err = take(&built, &dir.path().join("out-3")).unwrap_err();
    assert!(err.to_string().contains("no checksum"), "{err}");
}
