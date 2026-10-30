//! Format detection, unpacking without running anything and the inventory, with hostile
//! archives.

mod upstream_common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oncl_testkit::{fixture, read};
use upstream_common::{MockServer, Response};
use xtask::upstream::artifact::{ArtifactError, Format, check_artifact, detect_format, head_tail};
use xtask::upstream::http::{Downloaded, Fetcher};
use xtask::upstream::inventory::{FileKind, inventory};
use xtask::upstream::sha256_hex;
use xtask::upstream::sources::{Source, SourceKind};
use xtask::upstream::tools::fetch_innounp;
#[cfg(unix)]
use xtask::upstream::unpack::Extractor;
use xtask::upstream::unpack::{
    Limits, Tools, Tree, TreeRoot, UnpackError, Unpacked, innounp_args, run_tool, sevenzip_args,
    unpack,
};

fn format_of(path: &Path) -> Format {
    let (head, tail) = head_tail(path).unwrap();
    detect_format(&head, &tail)
}

fn downloaded(path: PathBuf, content_type: &str) -> Downloaded {
    let bytes = std::fs::read(&path).unwrap();
    use sha1::Digest;
    Downloaded {
        size: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
        sha1: sha1::Sha1::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        content_type: Some(content_type.to_owned()),
        filename: None,
        path,
    }
}

fn source(format: Format, sha256: Option<&str>, sha1: Option<&str>) -> Source {
    Source {
        id: "test".to_owned(),
        kind: match sha1 {
            Some(s) => SourceKind::Page {
                label: "x".to_owned(),
                published_sha1: Some(s.to_owned()),
            },
            None => SourceKind::Fixed,
        },
        url: "http://example.test/x".to_owned(),
        expected_sha256: sha256.map(str::to_owned),
        expected_format: Some(format),
    }
}

fn unpack_inventory(
    name: &str,
    format: Format,
) -> (Unpacked, xtask::upstream::inventory::Inventory) {
    let work = tempfile::tempdir().unwrap();
    let unpacked = unpack(
        &fixture(&format!("upstream/{name}")),
        format,
        work.path(),
        &Tools::default(),
        &Limits::default(),
    )
    .unwrap();
    let Unpacked::Tree(tree) = &unpacked else {
        panic!("{unpacked:?}")
    };
    let inv = inventory(tree, &Limits::default()).unwrap();
    (unpacked, inv)
}

#[test]
fn detects_format_by_magic() {
    let dir = tempfile::tempdir().unwrap();
    let renamed = dir.path().join("x.exe");
    std::fs::copy(fixture("upstream/bundle-a.jar"), &renamed).unwrap();
    assert_eq!(format_of(&renamed), Format::Jar);
    for (name, format) in [
        ("inno-like.exe", Format::InnoExe),
        ("lite.exe", Format::GoDropper),
        ("msi-like.msi", Format::Msi),
        ("fake.dmg", Format::Dmg),
        ("installer.sh", Format::Sh),
        ("manifest.der", Format::Der),
        ("error.html", Format::Html),
        ("dist.zip", Format::Zip),
    ] {
        assert_eq!(
            format_of(&fixture(&format!("upstream/{name}"))),
            format,
            "{name}"
        );
    }
}

#[test]
fn html_error_page_rejected() {
    let path = fixture("upstream/error.html");
    for content_type in ["text/html", "application/octet-stream"] {
        assert_eq!(
            check_artifact(
                &downloaded(path.clone(), content_type),
                &source(Format::Jar, None, None)
            ),
            Err(ArtifactError::UnexpectedHtml)
        );
    }
    // A JAR served as text/html is refused too.
    assert_eq!(
        check_artifact(
            &downloaded(fixture("upstream/bundle-a.jar"), "text/html"),
            &source(Format::Jar, None, None)
        ),
        Err(ArtifactError::UnexpectedHtml)
    );
}

#[test]
fn hash_mismatch_rejected() {
    let d = downloaded(fixture("upstream/bundle-a.jar"), "application/java-archive");
    assert!(matches!(
        check_artifact(&d, &source(Format::Jar, Some(&"0".repeat(64)), None)),
        Err(ArtifactError::HashMismatch { .. })
    ));
    assert_eq!(
        check_artifact(
            &d,
            &source(Format::Jar, Some(&d.sha256.to_uppercase()), None)
        ),
        Ok(Format::Jar)
    );
}

#[test]
fn sha1_mismatch_rejected() {
    let d = downloaded(fixture("upstream/dist.zip"), "application/zip");
    assert!(matches!(
        check_artifact(&d, &source(Format::Zip, None, Some(&"1".repeat(40)))),
        Err(ArtifactError::Sha1Mismatch { .. })
    ));
    assert_eq!(
        check_artifact(&d, &source(Format::Zip, None, Some(&d.sha1.clone()))),
        Ok(Format::Zip)
    );
}

#[test]
fn sh_payload_found() {
    let (unpacked, inv) = unpack_inventory("installer.sh", Format::Sh);
    let Unpacked::Tree(tree) = unpacked else {
        unreachable!()
    };
    let sh = tree.meta.sh.unwrap();
    assert_eq!(sh.payload_offset, 4096);
    let bytes = read(fixture("upstream/installer.sh"));
    assert_eq!(sh.header_sha256, sha256_hex(&bytes[..4096]));
    assert_eq!(&bytes[4096..], read(fixture("upstream/app.jar")));
    assert!(inv.files.contains_key("kz/example/launcher/Main.class"));
}

#[test]
fn lite_dropper_yields_launcher_jar() {
    let (unpacked, inv) = unpack_inventory("lite.exe", Format::GoDropper);
    let Unpacked::Tree(tree) = unpacked else {
        unreachable!()
    };
    let lite = tree.meta.lite.unwrap();
    assert_eq!(lite.go_version.as_deref(), Some("go1.0-synthetic"));
    assert_eq!(inv.files["ncalayer.der"].kind, FileKind::Manifest);
    assert!(inv.blobs.contains_key("ncalayer.der"));
    assert_eq!(inv.files["trusted.jks"].kind, FileKind::Keystore);
}

#[test]
fn nested_jar_inventory() {
    let (_, inv) = unpack_inventory("dist.zip", Format::Zip);
    assert!(inv.files.contains_key("NCALayer/ncalayer.sh"));
    assert!(
        !inv.files
            .keys()
            .any(|k| k.starts_with("NCALayer/ncalayer.sh!/"))
    );
    assert!(
        !inv.files.keys().any(|k| k.contains("jre/")),
        "{:?}",
        inv.files.keys()
    );
    let jre = inv.jre.unwrap();
    assert_eq!(jre.java_version.as_deref(), Some("1.8.0_000"));
    assert_eq!(jre.implementor.as_deref(), Some("Synthetic"));
    assert_eq!(jre.files, 3);

    // A JAR inside a ZIP is listed as `outer!/inner`.
    let zip = zip_of(&[("lib/bundle-a.jar", read(fixture("upstream/bundle-a.jar")))]);
    let inv = inventory_of_bytes(&zip, &Limits::default()).unwrap();
    assert_eq!(inv.files["lib/bundle-a.jar"].kind, FileKind::Jar);
    assert!(
        inv.files
            .contains_key("lib/bundle-a.jar!/kz/example/demo/DemoModule.class")
    );
    assert!(inv.nested.contains_key("lib/bundle-a.jar"));
}

fn zip_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut out);
        for (name, bytes) in entries {
            w.start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            w.write_all(bytes).unwrap();
        }
        w.finish().unwrap();
    }
    out.into_inner()
}

fn inventory_of_bytes(
    bytes: &[u8],
    limits: &Limits,
) -> Result<xtask::upstream::inventory::Inventory, UnpackError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, bytes).unwrap();
    inventory(
        &Tree {
            root: TreeRoot::Archive(path),
            meta: Default::default(),
        },
        limits,
    )
}

#[test]
fn zip_bomb_limits() {
    let zip = zip_of(&[("zeros", vec![0; 2 << 20])]);
    assert!(zip.len() < 64 * 1024);
    let limits = Limits {
        entry_bytes: 1 << 20,
        ..Limits::default()
    };
    assert_eq!(
        inventory_of_bytes(&zip, &limits),
        Err(UnpackError::Limit("entry_bytes"))
    );
    // The size the headers claim is not trusted: the bytes are counted.
    let mut lying = zip.clone();
    let needle = (2u32 << 20).to_le_bytes();
    let mut at = 0;
    while let Some(i) = lying[at..].windows(4).position(|w| w == needle) {
        lying[at + i..at + i + 4].copy_from_slice(&16u32.to_le_bytes());
        at += i + 4;
    }
    assert!(inventory_of_bytes(&lying, &limits).is_err());
    let total = Limits {
        total_bytes: 1 << 20,
        ..Limits::default()
    };
    assert_eq!(
        inventory_of_bytes(&zip, &total),
        Err(UnpackError::Limit("total_bytes"))
    );
}

#[test]
fn nested_depth_limit() {
    let mut bytes = zip_of(&[("leaf.txt", b"leaf".to_vec())]);
    for n in 0..6 {
        bytes = zip_of(&[(&format!("level{n}.zip"), bytes)]);
    }
    let limits = Limits {
        depth: 4,
        ..Limits::default()
    };
    assert_eq!(
        inventory_of_bytes(&bytes, &limits),
        Err(UnpackError::Limit("depth"))
    );
}

#[test]
fn parent_and_absolute_paths_are_not_written() {
    let zip = zip_of(&[("../x", b"x".to_vec()), ("/abs", b"y".to_vec())]);
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let path = work.join("a.zip");
    std::fs::write(&path, &zip).unwrap();
    let inv = inventory(
        &Tree {
            root: TreeRoot::Archive(path),
            meta: Default::default(),
        },
        &Limits::default(),
    )
    .unwrap();
    assert!(inv.files.contains_key("x"));
    assert!(inv.files.contains_key("abs"));
    assert!(!dir.path().join("x").exists());
    assert_eq!(std::fs::read_dir(&work).unwrap().count(), 1);
}

/// An extractor that makes a file and a symbolic link to a system file.
#[cfg(unix)]
struct LinkMaker;

#[cfg(unix)]
impl Extractor for LinkMaker {
    fn name(&self) -> &'static str {
        "links"
    }

    fn extract(&self, _: &Path, out: &Path) -> Result<(), UnpackError> {
        std::fs::create_dir_all(out).unwrap();
        std::fs::write(out.join("file.txt"), b"file").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", out.join("passwd")).unwrap();
        Ok(())
    }
}

#[test]
#[cfg(unix)]
fn walk_skips_symlinks() {
    let work = tempfile::tempdir().unwrap();
    let tools = Tools {
        innounp: Some(Box::new(LinkMaker)),
        sevenzip: None,
    };
    let Unpacked::Tree(tree) = unpack(
        &fixture("upstream/inno-like.exe"),
        Format::InnoExe,
        work.path(),
        &tools,
        &Limits::default(),
    )
    .unwrap() else {
        panic!()
    };
    let inv = inventory(&tree, &Limits::default()).unwrap();
    assert_eq!(inv.files.keys().collect::<Vec<_>>(), ["file.txt"]);
}

#[test]
fn missing_tool_is_skipped() {
    let work = tempfile::tempdir().unwrap();
    for (name, format, reason) in [
        ("inno-like.exe", Format::InnoExe, "no innounp"),
        ("msi-like.msi", Format::Msi, "no 7z"),
        ("fake.dmg", Format::Dmg, "no 7z"),
    ] {
        assert_eq!(
            unpack(
                &fixture(&format!("upstream/{name}")),
                format,
                work.path(),
                &Tools::default(),
                &Limits::default()
            ),
            Ok(Unpacked::Skipped {
                reason: reason.to_owned()
            })
        );
    }
}

#[test]
fn innounp_command_line() {
    let args = innounp_args(Path::new("setup.exe"), Path::new("out"));
    assert_eq!(args, ["-x", "-m", "-a", "-y", "-dout", "setup.exe"]);
}

#[test]
fn sevenzip_command_line() {
    let args = sevenzip_args(Path::new("a.msi"), Path::new("out"));
    assert_eq!(args, ["x", "-y", "-bd", "-bso0", "-bsp0", "-oout", "a.msi"]);
}

#[test]
fn extractor_timeout_kills() {
    let dir = tempfile::tempdir().unwrap();
    let (exe, args): (&str, Vec<std::ffi::OsString>) = if cfg!(windows) {
        ("ping", vec!["-n".into(), "30".into(), "127.0.0.1".into()])
    } else {
        ("sleep", vec!["30".into()])
    };
    let start = std::time::Instant::now();
    assert_eq!(
        run_tool(
            "slow",
            Path::new(exe),
            &args,
            &dir.path().join("out"),
            Duration::from_secs(1)
        ),
        Err(UnpackError::Timeout("slow"))
    );
    assert!(start.elapsed() < Duration::from_secs(15));
}

#[test]
fn inventory_is_sorted_and_stable() {
    let (_, a) = unpack_inventory("bundle-a.jar", Format::Jar);
    let (_, b) = unpack_inventory("bundle-a.jar", Format::Jar);
    let json = |i: &xtask::upstream::inventory::Inventory| serde_json::to_vec(&i.files).unwrap();
    assert_eq!(json(&a), json(&b));
    assert_eq!(a.files["keystores/trusted.jks"].kind, FileKind::Keystore);
    assert_eq!(
        a.files["natives/linux-x86-64/libdemo.so"].kind,
        FileKind::Native
    );
    assert_eq!(
        a.files["kz/example/demo/DemoModule.class"].kind,
        FileKind::Class
    );
}

#[test]
fn tools_rejects_wrong_sha256() {
    let server = MockServer::start();
    let zip = zip_of(&[("innounp.exe", b"MZ not innounp".to_vec())]);
    server.route("GET", "/innounp-2.zip", Response::ok(zip.clone()));
    let out = tempfile::tempdir().unwrap();
    let fetcher = Fetcher::for_tests();
    let url = server.url("/innounp-2.zip");
    assert!(fetch_innounp(&fetcher, &url, &"0".repeat(64), &"0".repeat(64), out.path()).is_err());
    assert!(!out.path().join("innounp.exe").exists());
    // The zip's hash right, the program's wrong.
    assert!(
        fetch_innounp(
            &fetcher,
            &url,
            &sha256_hex(&zip),
            &"0".repeat(64),
            out.path()
        )
        .is_err()
    );
    assert!(!out.path().join("innounp.exe").exists());
    let exe = fetch_innounp(
        &fetcher,
        &url,
        &sha256_hex(&zip),
        &sha256_hex(b"MZ not innounp"),
        out.path(),
    )
    .unwrap();
    assert!(exe.exists());
}

#[test]
fn sevenzip_version_gate() {
    use xtask::upstream::tools::sevenzip_supported;
    assert!(sevenzip_supported(
        "7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov"
    ));
    assert!(sevenzip_supported("7-Zip 26.00 (x64)"));
    assert!(sevenzip_supported("7-Zip (z) 25.02 (x64)"));
    assert!(!sevenzip_supported("7-Zip 25.00 (x64)"));
    assert!(!sevenzip_supported(
        "7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov"
    ));
    assert!(!sevenzip_supported("p7zip Version 16.02"));
    assert!(!sevenzip_supported(""));
}

/// A ZIP with a symbolic link `link` to `target` and a file written through it.
fn zip_with_link(target: &str) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut out);
        let opts = zip::write::SimpleFileOptions::default();
        w.add_symlink("link", target, opts).unwrap();
        w.start_file("link/pwned.txt", opts).unwrap();
        w.write_all(b"pwned").unwrap();
        w.start_file("plain.txt", opts).unwrap();
        w.write_all(b"plain").unwrap();
        w.finish().unwrap();
    }
    out.into_inner()
}

#[test]
fn zip_symlink_entries_are_skipped() {
    let inv = inventory_of_bytes(&zip_with_link("../outside"), &Limits::default()).unwrap();
    assert!(!inv.files.contains_key("link"), "{:?}", inv.files.keys());
    assert!(inv.files.contains_key("plain.txt"));
}

#[test]
fn sevenzip_does_not_follow_a_link_out_of_the_output() {
    use xtask::upstream::tools::{find_7z, sevenzip_supported, sevenzip_version};
    use xtask::upstream::unpack::{Extractor, SevenZip};
    let Some(exe) =
        find_7z().filter(|e| sevenzip_version(e).is_some_and(|v| sevenzip_supported(&v)))
    else {
        eprintln!("no 7-Zip 25.01 or newer: the watcher does not use older ones");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let archive = dir.path().join("a.zip");
    std::fs::write(&archive, zip_with_link("../outside")).unwrap();
    let out = dir.path().join("out");
    // Refused (an error) or extracted without the link: never written outside `out`.
    let _ = SevenZip { exe }.extract(&archive, &out);
    assert!(!outside.join("pwned.txt").exists());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    if out.exists() {
        let tree = Tree {
            root: TreeRoot::Dir(out),
            meta: Default::default(),
        };
        let inv = inventory(&tree, &Limits::default()).unwrap();
        assert!(
            inv.files
                .keys()
                .all(|k| !k.contains("pwned") || k.starts_with("link/"))
        );
    }
}
