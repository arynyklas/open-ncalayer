//! The built-in modules' build: reproducible, of this version, checked when taken built.

use oncl_builtins_build::{
    BUILTIN_ID_PREFIX, GUESTS, SOURCE, SUMS, WORKSPACE_VERSION, build, check_manifest, hex,
    source_digest, take,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A copy of the workspace's tracked files in `dir`, as they are now.
fn copy_workspace(dir: &Path) {
    let listed = std::process::Command::new("git")
        .current_dir(workspace())
        .args(["ls-files", "-z"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    for name in listed.stdout.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let name = std::str::from_utf8(name).unwrap();
        let from = workspace().join(name);
        if !from.is_file() {
            continue;
        }
        let to = dir.join(name);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(&from, &to).unwrap();
    }
}

/// The printable runs of `wasm` ending in `.rs`, from their first `/` or `\\`.
fn source_paths(wasm: &[u8]) -> Vec<String> {
    let mut paths = Vec::new();
    for run in wasm.split(|b| !(0x20..0x7f).contains(b)) {
        let text = String::from_utf8_lossy(run);
        let mut rest = text.as_ref();
        while let Some(end) = rest.find(".rs") {
            let candidate = &rest[..end + 3];
            if let Some(start) = candidate.find(['/', '\\']) {
                paths.push(candidate[start..].to_owned());
            }
            rest = &rest[end + 3..];
        }
    }
    paths
}

/// Whether `haystack` holds `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Two builds, of the workspace and of a copy of it elsewhere, each in a target folder of its
/// own: the same bytes, and no path of the machine in them.
#[test]
fn two_builds_are_identical() {
    let dir = tempfile::tempdir().unwrap();
    let first = build(
        &workspace(),
        &dir.path().join("target-1"),
        &dir.path().join("out-1"),
    )
    .unwrap();
    let copy = dir.path().join("elsewhere").join("workspace");
    copy_workspace(&copy);
    let second = build(
        &copy,
        &dir.path().join("target-2"),
        &dir.path().join("out-2"),
    )
    .unwrap();
    let root = std::path::absolute(workspace()).unwrap();
    let mut machine: Vec<String> = vec![
        "\\Users\\".to_owned(),
        "/home/".to_owned(),
        ".cargo".to_owned(),
        ".rustup".to_owned(),
        root.display().to_string(),
        copy.display().to_string(),
    ];
    if let Some(home) = std::env::home_dir() {
        machine.push(home.display().to_string());
    }
    for a in &first {
        let wasm = fs::read(&a.wasm).unwrap();
        for path in &machine {
            assert!(!contains(&wasm, path.as_bytes()), "{}: {path}", a.package);
        }
        // The only source paths left are those of the prebuilt standard library, the same
        // on every host: none of the workspace or the registry, no `\` separator.
        for path in source_paths(&wasm) {
            assert!(
                (path.starts_with("/rustc/") || path.starts_with("/rust/deps/"))
                    && !path.contains('\\'),
                "{}: {path}",
                a.package
            );
        }
    }
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
    let taken = take(
        &workspace(),
        &dir.path().join("out-1"),
        &dir.path().join("out-3"),
    )
    .unwrap();
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
        let older_core = manifest.replace(
            &format!("min_core = \"{WORKSPACE_VERSION}\""),
            "min_core = \"0.0.1\"",
        );
        assert_ne!(older_core, manifest);
        assert!(check_manifest(&older_core).is_err());
    }
}

/// A folder of modules as `build` lays it out, with `wasm` as every module's code, built
/// from the workspace's sources.
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
    let digest = source_digest(&workspace()).unwrap();
    fs::write(dir.join(SOURCE), format!("{digest}\n")).unwrap();
}

#[test]
fn take_rejects_sha_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let built = dir.path().join("built");
    laid_out(&built, b"\0asm\x01\0\0\0");
    let taken = take(&workspace(), &built, &dir.path().join("out")).unwrap();
    assert_eq!(taken.len(), GUESTS.len());
    assert_eq!(fs::read(&taken[0].wasm).unwrap(), b"\0asm\x01\0\0\0");
    assert!(dir.path().join("out").join(SUMS).exists());
    assert!(dir.path().join("out").join(SOURCE).exists());

    fs::write(
        built.join(GUESTS[0].package).join("plugin.wasm"),
        b"\0asm\x01\0\0\x01",
    )
    .unwrap();
    let err = take(&workspace(), &built, &dir.path().join("out-2")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    assert!(err.to_string().contains("does not match"), "{err}");

    fs::write(built.join(SUMS), "").unwrap();
    let err = take(&workspace(), &built, &dir.path().join("out-3")).unwrap_err();
    assert!(err.to_string().contains("no checksum"), "{err}");
}

/// Modules built from other sources, or with another manifest than the workspace's, are not
/// taken, even when their checksums are right.
#[test]
fn take_rejects_other_sources_and_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let built = dir.path().join("built");
    laid_out(&built, b"\0asm\x01\0\0\0");
    fs::write(built.join(SOURCE), format!("{}\n", "0".repeat(64))).unwrap();
    let err = take(&workspace(), &built, &dir.path().join("out")).unwrap_err();
    assert!(err.to_string().contains("other sources"), "{err}");
    fs::remove_file(built.join(SOURCE)).unwrap();
    assert!(take(&workspace(), &built, &dir.path().join("out")).is_err());

    // A manifest of this version with another capability, its checksum updated.
    let built = dir.path().join("built-2");
    laid_out(&built, b"\0asm\x01\0\0\0");
    let path = built.join(GUESTS[0].package).join("plugin.toml");
    let manifest = fs::read_to_string(&path).unwrap() + "\n[capabilities.extra]\n";
    fs::write(&path, &manifest).unwrap();
    let sums = fs::read_to_string(built.join(SUMS)).unwrap();
    let file = format!("{}/plugin.toml", GUESTS[0].package);
    let sums: String = sums
        .lines()
        .map(|line| match line.split_once("  ") {
            Some((_, path)) if path == file => {
                use sha2::Digest;
                format!("{}  {file}\n", hex(&sha2::Sha256::digest(&manifest)))
            }
            _ => format!("{line}\n"),
        })
        .collect();
    fs::write(built.join(SUMS), sums).unwrap();
    let err = take(&workspace(), &built, &dir.path().join("out-2")).unwrap_err();
    assert!(err.to_string().contains("not the workspace's"), "{err}");
}

/// The digest reads CRLF as LF: a Windows checkout and a Unix one agree.
#[test]
fn source_digest_ignores_line_endings() {
    let dir = tempfile::tempdir().unwrap();
    let lf = dir.path().join("lf");
    let crlf = dir.path().join("crlf");
    for (root, eol) in [(&lf, "\n"), (&crlf, "\r\n")] {
        for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
            let text = fs::read_to_string(workspace().join(name))
                .unwrap()
                .replace("\r\n", "\n")
                .replace('\n', eol);
            fs::create_dir_all(root).unwrap();
            fs::write(root.join(name), text).unwrap();
        }
        fs::create_dir_all(root.join("crates/oncl-builtin-x/src")).unwrap();
        fs::write(
            root.join("crates/oncl-builtin-x/src/lib.rs"),
            format!("//! x{eol}pub fn x() {{}}{eol}"),
        )
        .unwrap();
    }
    let a = source_digest(&lf).unwrap();
    assert_eq!(a, source_digest(&crlf).unwrap());
    fs::write(
        lf.join("crates/oncl-builtin-x/src/lib.rs"),
        "pub fn y() {}\n",
    )
    .unwrap();
    assert_ne!(a, source_digest(&lf).unwrap());
}
