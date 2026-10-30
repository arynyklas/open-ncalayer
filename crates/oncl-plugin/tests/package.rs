//! The plugin package (`.onclp`) and its manifest (`plugin.toml`): packages are built here
//! with the `zip` crate, some of them patched afterwards into what no writer would produce.

use oncl_basics::Locale;
use oncl_plugin::{
    HttpPrefix, MAX_MANIFEST, MAX_PACKAGE, MAX_WASM, Manifest, PACKAGE_EXT, Package, PackageError,
};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

/// The smallest valid module: the magic and version 1, no sections.
const WASM: &[u8] = b"\0asm\x01\0\0\0";

const MANIFEST: &str = r#"
id = "kz.example.echo"
version = "1.0.0"
min_core = "0.2.0"
modules = ["kz.example.Echo"]

[name]
ru = "Эхо"
kk = "Жаңғырық"
en = "Echo"
"#;

/// A zip of `entries`; a name ending with `/` is a directory.
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        if name.ends_with('/') {
            zip.add_directory(*name, options).unwrap();
        } else {
            zip.start_file(*name, options).unwrap();
            zip.write_all(data).unwrap();
        }
    }
    zip.finish().unwrap().into_inner()
}

fn package_with(manifest: &str, wasm: &[u8]) -> Vec<u8> {
    zip_of(&[("plugin.toml", manifest.as_bytes()), ("plugin.wasm", wasm)])
}

/// Every occurrence of `from` in `bytes` replaced with `to`, of the same length.
fn replace_all(bytes: &mut [u8], from: &[u8], to: &[u8]) -> usize {
    assert_eq!(from.len(), to.len());
    let mut count = 0;
    let mut i = 0;
    while i + from.len() <= bytes.len() {
        if &bytes[i..i + from.len()] == from {
            bytes[i..i + from.len()].copy_from_slice(to);
            count += 1;
            i += from.len();
        } else {
            i += 1;
        }
    }
    count
}

/// Sets the uncompressed size of the entry `name` in its local header and in the central
/// directory to `size`.
fn set_declared_size(bytes: &mut [u8], name: &[u8], size: u32) {
    let u16_at = |b: &[u8], at: usize| usize::from(u16::from_le_bytes([b[at], b[at + 1]]));
    let mut patched = 0;
    for i in 0..bytes.len().saturating_sub(46) {
        // Local file header: name length at 26, name at 30, uncompressed size at 22.
        if bytes[i..i + 4] == *b"PK\x03\x04"
            && u16_at(bytes, i + 26) == name.len()
            && bytes[i + 30..i + 30 + name.len()] == *name
        {
            bytes[i + 22..i + 26].copy_from_slice(&size.to_le_bytes());
            patched += 1;
        }
        // Central directory header: name length at 28, name at 46, uncompressed size at 24.
        if bytes[i..i + 4] == *b"PK\x01\x02"
            && u16_at(bytes, i + 28) == name.len()
            && bytes[i + 46..i + 46 + name.len()] == *name
        {
            bytes[i + 24..i + 28].copy_from_slice(&size.to_le_bytes());
            patched += 1;
        }
    }
    assert_eq!(patched, 2, "one local and one central header");
}

fn entries_error(bytes: &[u8]) -> String {
    match Package::read(bytes) {
        Err(PackageError::Entries(why)) => why,
        other => panic!("expected Entries, got {other:?}"),
    }
}

fn manifest_error(toml: &str) -> String {
    match Manifest::from_toml(toml) {
        Err(PackageError::Manifest(why)) => why,
        other => panic!("expected Manifest, got {other:?}"),
    }
}

/// [`MANIFEST`] with the line starting with `key =` replaced by `line`.
fn with_line(key: &str, line: &str) -> String {
    let prefix = format!("{key} =");
    let out: Vec<&str> = MANIFEST
        .lines()
        .map(|l| if l.starts_with(&prefix) { line } else { l })
        .collect();
    assert_ne!(
        out.join("\n"),
        MANIFEST.trim_end(),
        "{key} is in the manifest"
    );
    out.join("\n")
}

#[test]
fn reads_minimal_package() {
    assert_eq!(PACKAGE_EXT, "onclp");
    assert_eq!(MAX_PACKAGE, 32 << 20);
    assert_eq!(MAX_WASM, 16 << 20);
    assert_eq!(MAX_MANIFEST, 64 << 10);

    let bytes = package_with(MANIFEST, WASM);
    let package = Package::read(&bytes).unwrap();
    let m = &package.manifest;
    assert_eq!(m.id, "kz.example.echo");
    assert_eq!(m.version, semver::Version::new(1, 0, 0));
    assert_eq!(m.min_core, semver::Version::new(0, 2, 0));
    assert_eq!(m.modules, ["kz.example.Echo"]);
    assert_eq!(m.name.get(Locale::Ru), "Эхо");
    assert_eq!(m.name.get(Locale::Kk), "Жаңғырық");
    assert_eq!(m.name.get(Locale::En), "Echo");
    assert_eq!(m.description, None);
    assert_eq!(m.replaces, None);
    assert!(!m.capabilities.keys && !m.capabilities.dialogs && !m.capabilities.files);
    assert!(m.capabilities.http.is_empty());
    assert_eq!(package.wasm, WASM);
    assert_eq!(package.sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));

    // The same from a file.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("echo.{PACKAGE_EXT}"));
    std::fs::write(&path, &bytes).unwrap();
    let from_file = Package::read_file(&path).unwrap();
    assert_eq!(from_file.manifest, package.manifest);
    assert_eq!(from_file.wasm, package.wasm);
    assert_eq!(from_file.sha256, package.sha256);
    assert!(matches!(
        Package::read_file(&dir.path().join("missing.onclp")),
        Err(PackageError::Io(_))
    ));
}

#[test]
fn reads_full_manifest() {
    let toml = format!(
        "{MANIFEST}
[description]
ru = \"Повторяет запрос\"
kk = \"Сұрауды қайталайды\"
en = \"Repeats the request\"

[replaces]
symname = \"kz.example.echo\"
version = \"1.2.1\"

[capabilities]
keys = true
dialogs = true
files = true
http = [\"https://tsp.pki.gov.kz/\", \"https://A.kz:8443/api/\"]
"
    );
    let m = Manifest::from_toml(&toml).unwrap();
    let description = m.description.unwrap();
    assert_eq!(description.get(Locale::En), "Repeats the request");
    let replaces = m.replaces.unwrap();
    assert_eq!(replaces.symname, "kz.example.echo");
    assert_eq!(replaces.version, "1.2.1");
    let caps = m.capabilities;
    assert!(caps.keys && caps.dialogs && caps.files);
    assert_eq!(caps.http.len(), 2);
    assert_eq!(caps.http[1].host(), "a.kz");
    assert_eq!(caps.http[1].port(), 8443);
    assert_eq!(caps.http[1].path(), "/api/");
    assert_eq!(caps.http[1].to_string(), "https://a.kz:8443/api/");
    assert_eq!(caps.http[0].to_string(), "https://tsp.pki.gov.kz/");
}

#[test]
fn key_files_needs_keys() {
    let with = |caps: &str| format!("{MANIFEST}\n[capabilities]\n{caps}\n");
    let m = Manifest::from_toml(&with("keys = true\nkey_files = true")).unwrap();
    assert!(m.capabilities.key_files);
    assert!(
        !Manifest::from_toml(&with("keys = true"))
            .unwrap()
            .capabilities
            .key_files
    );
    let why = manifest_error(&with("key_files = true"));
    assert!(why.contains("key_files"), "{why}");
}

#[test]
fn rejects_package_over_limit() {
    let too_big = vec![0u8; usize::try_from(MAX_PACKAGE).unwrap() + 1];
    assert!(matches!(
        Package::read(&too_big),
        Err(PackageError::TooLarge)
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.onclp");
    std::fs::write(&path, &too_big).unwrap();
    assert!(matches!(
        Package::read_file(&path),
        Err(PackageError::TooLarge)
    ));
}

#[test]
fn rejects_not_zip() {
    assert!(matches!(
        Package::read(b"not a zip"),
        Err(PackageError::NotZip)
    ));
    assert!(matches!(Package::read(b""), Err(PackageError::NotZip)));
}

#[test]
fn rejects_extra_entry() {
    let bytes = zip_of(&[
        ("plugin.toml", MANIFEST.as_bytes()),
        ("plugin.wasm", WASM),
        ("README.txt", b"hello"),
    ]);
    let why = entries_error(&bytes);
    assert!(why.contains("README.txt"), "{why}");
    // A name of the package in another case is another name.
    let bytes = zip_of(&[("plugin.toml", MANIFEST.as_bytes()), ("Plugin.wasm", WASM)]);
    entries_error(&bytes);
}

#[test]
fn rejects_directory_entry() {
    let bytes = zip_of(&[
        ("plugin.toml", MANIFEST.as_bytes()),
        ("plugin.wasm", WASM),
        ("lib/", b""),
    ]);
    let why = entries_error(&bytes);
    assert!(why.contains("lib/") && why.contains("directory"), "{why}");
    // The right files, but inside a directory.
    let bytes = zip_of(&[
        ("echo/", b""),
        ("echo/plugin.toml", MANIFEST.as_bytes()),
        ("echo/plugin.wasm", WASM),
    ]);
    entries_error(&bytes);
    // A directory under the name of a file.
    let bytes = zip_of(&[("plugin.toml", MANIFEST.as_bytes()), ("plugin.wasm/", b"")]);
    entries_error(&bytes);
}

#[test]
fn rejects_parent_path() {
    for name in [
        "../plugin.wasm",
        "/plugin.wasm",
        "\\plugin.wasm",
        "x/../plugin.wasm",
        "C:/plugin.wasm",
        "./plugin.wasm",
    ] {
        let bytes = zip_of(&[("plugin.toml", MANIFEST.as_bytes()), (name, WASM)]);
        let why = entries_error(&bytes);
        assert!(why.contains(&format!("{name:?}")), "{why}");
    }
}

#[test]
fn rejects_missing_wasm() {
    let why = entries_error(&zip_of(&[("plugin.toml", MANIFEST.as_bytes())]));
    assert!(why.contains("plugin.wasm"), "{why}");
    let why = entries_error(&zip_of(&[("plugin.wasm", WASM)]));
    assert!(why.contains("plugin.toml"), "{why}");
    entries_error(&zip_of(&[]));
}

#[test]
fn rejects_duplicate_entry() {
    // The writer refuses a repeated name: a third entry is renamed in the bytes afterwards.
    let mut bytes = zip_of(&[
        ("plugin.toml", MANIFEST.as_bytes()),
        ("plugin.wasm", WASM),
        ("plugin.wasx", WASM),
    ]);
    assert_eq!(replace_all(&mut bytes, b"plugin.wasx", b"plugin.wasm"), 2);
    let why = entries_error(&bytes);
    assert!(why.contains("repeated"), "{why}");
    // Two entries only, both `plugin.wasm`: no manifest, and a repeat.
    let mut bytes = zip_of(&[("plugin.wasx", WASM), ("plugin.wasm", WASM)]);
    assert_eq!(replace_all(&mut bytes, b"plugin.wasx", b"plugin.wasm"), 2);
    let why = entries_error(&bytes);
    assert!(why.contains("repeated"), "{why}");
}

#[test]
fn rejects_wasm_over_limit_by_content_not_header() {
    let mut wasm = WASM.to_vec();
    wasm.resize(usize::try_from(MAX_WASM).unwrap() + 1, 0);
    // Zeros compress to a small package.
    let honest = zip_of(&[("plugin.wasm", &wasm), ("plugin.toml", MANIFEST.as_bytes())]);
    assert!((honest.len() as u64) < MAX_PACKAGE);
    assert!(matches!(
        Package::read(&honest),
        Err(PackageError::TooLarge)
    ));

    // The headers claim 8 bytes, the data inflates past the limit.
    let mut lying = honest.clone();
    set_declared_size(&mut lying, b"plugin.wasm", 8);
    let err = Package::read(&lying).unwrap_err();
    assert!(
        matches!(err, PackageError::TooLarge | PackageError::NotZip),
        "{err:?}"
    );

    // The same for the manifest.
    let mut manifest = MANIFEST.as_bytes().to_vec();
    manifest.resize(usize::try_from(MAX_MANIFEST).unwrap() + 1, b'\n');
    let mut lying = zip_of(&[("plugin.toml", &manifest), ("plugin.wasm", WASM)]);
    assert!(matches!(Package::read(&lying), Err(PackageError::TooLarge)));
    set_declared_size(&mut lying, b"plugin.toml", 64);
    let err = Package::read(&lying).unwrap_err();
    assert!(
        matches!(err, PackageError::TooLarge | PackageError::NotZip),
        "{err:?}"
    );

    // Exactly at the limits is accepted.
    wasm.truncate(usize::try_from(MAX_WASM).unwrap());
    manifest.truncate(usize::try_from(MAX_MANIFEST).unwrap());
    let at_limit = zip_of(&[("plugin.toml", &manifest), ("plugin.wasm", &wasm)]);
    let package = Package::read(&at_limit).unwrap();
    assert_eq!(package.wasm.len() as u64, MAX_WASM);
}

#[test]
fn rejects_bad_magic() {
    for wasm in [
        &b"\0asm\x02\0\0\0"[..],
        b"\0asm\x01\0\0",
        b"\0asm",
        b"",
        b"notwasm!",
        b"\0ASM\x01\0\0\0",
    ] {
        let why = entries_error(&package_with(MANIFEST, wasm));
        assert!(why.contains("plugin.wasm"), "{why}");
    }
}

#[test]
fn rejects_bad_manifest_in_package() {
    let bytes = package_with("id = ", WASM);
    assert!(matches!(
        Package::read(&bytes),
        Err(PackageError::Manifest(_))
    ));
    let bytes = zip_of(&[("plugin.toml", b"\xff\xfe"), ("plugin.wasm", WASM)]);
    assert!(matches!(
        Package::read(&bytes),
        Err(PackageError::Manifest(_))
    ));
}

#[test]
fn rejects_unknown_key() {
    manifest_error(&format!("extra = 1\n{MANIFEST}"));
    manifest_error(&format!("{MANIFEST}\n[capabilities]\nnetwork = true\n"));
    manifest_error(&MANIFEST.replace("en = \"Echo\"", "en = \"Echo\"\nde = \"Echo\""));
    manifest_error(&format!(
        "{MANIFEST}\n[replaces]\nsymname = \"a\"\nversion = \"1\"\nextra = 1\n"
    ));
    manifest_error(&format!(
        "{MANIFEST}\n[description]\nru = \"а\"\nkk = \"а\"\nen = \"a\"\nde = \"a\"\n"
    ));
}

#[test]
fn rejects_missing_key() {
    for key in ["id", "version", "min_core", "modules"] {
        manifest_error(&with_line(key, ""));
    }
    manifest_error(&MANIFEST.replace("[name]", "[title]"));
}

#[test]
fn rejects_bad_id() {
    for id in [
        "Kz.x", "kz", "-kz.x", "kz.x-", "kzx", ".kz", "kz.", "kz_x.y", "kz x.y", "",
    ] {
        manifest_error(&with_line("id", &format!("id = \"{id}\"")));
    }
    let long = format!("kz.{}", "a".repeat(62));
    assert_eq!(long.len(), 65);
    manifest_error(&with_line("id", &format!("id = \"{long}\"")));
    for id in ["kz.x", "a.b", "kz.example-1.echo", "0.0", &long[1..]] {
        let m = Manifest::from_toml(&with_line("id", &format!("id = \"{id}\""))).unwrap();
        assert_eq!(m.id, id);
    }
}

#[test]
fn rejects_bad_versions() {
    manifest_error(&with_line("version", "version = \"1.0\""));
    manifest_error(&with_line("version", "version = 1"));
    manifest_error(&with_line("min_core", "min_core = \"latest\""));
    let m = Manifest::from_toml(&with_line("version", "version = \"2.0.0-beta.1\"")).unwrap();
    assert_eq!(m.version, semver::Version::parse("2.0.0-beta.1").unwrap());
}

#[test]
fn rejects_duplicate_module() {
    manifest_error(&with_line(
        "modules",
        "modules = [\"kz.a\", \"kz.b\", \"kz.a\"]",
    ));
}

#[test]
fn rejects_33_modules() {
    let list = |n: usize| {
        let names: Vec<String> = (0..n).map(|i| format!("\"kz.m{i}\"")).collect();
        format!("modules = [{}]", names.join(", "))
    };
    manifest_error(&with_line("modules", &list(33)));
    manifest_error(&with_line("modules", &list(0)));
    let m = Manifest::from_toml(&with_line("modules", &list(32))).unwrap();
    assert_eq!(m.modules.len(), 32);
}

#[test]
fn rejects_bad_module_name() {
    let long = "a".repeat(129);
    for name in ["", "kz example", "kz/x", "kz:x", "kz\\x", "ж", &long] {
        manifest_error(&with_line("modules", &format!("modules = [\"{name}\"]")));
    }
    let longest = "A".repeat(128);
    for name in ["kz.gov.pki.knca.basics", "A-b_c.9", &longest] {
        Manifest::from_toml(&with_line("modules", &format!("modules = [\"{name}\"]"))).unwrap();
    }
}

#[test]
fn rejects_empty_name_translation() {
    for key in ["ru", "kk", "en"] {
        // Empty, blank, missing.
        manifest_error(&with_line(key, &format!("{key} = \"\"")));
        manifest_error(&with_line(key, &format!("{key} = \"  \"")));
        manifest_error(&with_line(key, ""));
    }
    let long = "ы".repeat(129);
    manifest_error(&with_line("ru", &format!("ru = \"{long}\"")));
    let longest = "ы".repeat(128);
    Manifest::from_toml(&with_line("ru", &format!("ru = \"{longest}\""))).unwrap();
}

#[test]
fn rejects_bad_description_and_replaces() {
    let description =
        |ru: &str| format!("{MANIFEST}\n[description]\nru = \"{ru}\"\nkk = \"а\"\nen = \"a\"\n");
    Manifest::from_toml(&description(&"ы".repeat(2048))).unwrap();
    manifest_error(&description(&"ы".repeat(2049)));
    manifest_error(&format!("{MANIFEST}\n[description]\nru = \"а\"\n"));

    let replaces = |symname: &str, version: &str| {
        format!("{MANIFEST}\n[replaces]\nsymname = \"{symname}\"\nversion = \"{version}\"\n")
    };
    Manifest::from_toml(&replaces("kz.gov.pki.Some_Bundle-1", "1.2.1.v20200101")).unwrap();
    Manifest::from_toml(&replaces(&"s".repeat(128), &"1".repeat(64))).unwrap();
    manifest_error(&replaces("", "1.0"));
    manifest_error(&replaces("kz x", "1.0"));
    manifest_error(&replaces(&"s".repeat(129), "1.0"));
    manifest_error(&replaces("kz.x", ""));
    manifest_error(&replaces("kz.x", " "));
    manifest_error(&replaces("kz.x", &"1".repeat(65)));
    manifest_error(&format!("{MANIFEST}\n[replaces]\nsymname = \"kz.x\"\n"));
}

#[test]
fn rejects_33_http_prefixes() {
    let http = |n: usize| {
        let prefixes: Vec<String> = (0..n).map(|i| format!("\"https://h{i}.kz/\"")).collect();
        format!(
            "{MANIFEST}\n[capabilities]\nhttp = [{}]\n",
            prefixes.join(", ")
        )
    };
    assert_eq!(
        Manifest::from_toml(&http(32))
            .unwrap()
            .capabilities
            .http
            .len(),
        32
    );
    manifest_error(&http(33));
    manifest_error(&format!(
        "{MANIFEST}\n[capabilities]\nhttp = [\"http://tsp.pki.gov.kz/\"]\n"
    ));
}

#[test]
fn http_prefix_rules() {
    let prefix: HttpPrefix = "https://tsp.pki.gov.kz/".parse().unwrap();
    assert_eq!(prefix.host(), "tsp.pki.gov.kz");
    assert_eq!(prefix.port(), 443);
    assert_eq!(prefix.path(), "/");

    let upper: HttpPrefix = "https://TSP.pki.gov.kz:443/Api/".parse().unwrap();
    assert_eq!(upper.host(), "tsp.pki.gov.kz");
    assert_eq!(upper.port(), 443);
    assert_eq!(upper.path(), "/Api/");
    assert_eq!(upper.to_string(), "https://tsp.pki.gov.kz/Api/");

    for bad in [
        "http://tsp.pki.gov.kz/",
        "https://a.kz",
        "https://u@a.kz/",
        "https://u:p@a.kz/",
        "https://@a.kz/",
        "https://a.kz/?x",
        "https://a.kz/?",
        "https://a.kz/#x",
        "https://a.kz/#",
        "https://a.kz/api",
        "https:\\\\a.kz\\",
        "https://a.kz\\api/",
        " https://a.kz/",
        "https://a.kz/\n",
        "https://a.kz/a\tb/",
        "HTTPS://a.kz/",
        "https:a.kz/",
        "https:///",
        "https://a.kz:0x1/",
        "ftp://a.kz/",
        "",
    ] {
        assert!(
            matches!(bad.parse::<HttpPrefix>(), Err(PackageError::Manifest(_))),
            "{bad:?} accepted"
        );
    }
}

#[test]
fn http_prefix_allows() {
    let prefix: HttpPrefix = "https://tsp.pki.gov.kz/".parse().unwrap();
    for url in [
        "https://tsp.pki.gov.kz/tsp",
        "https://TSP.pki.gov.kz/x",
        "https://tsp.pki.gov.kz/",
        "https://tsp.pki.gov.kz",
        "https://tsp.pki.gov.kz:443/x",
        "https://tsp.pki.gov.kz/x?y=1#z",
    ] {
        assert!(prefix.allows(url), "{url} refused");
    }
    for url in [
        "https://tsp.pki.gov.kz.evil/",
        "https://tsp.pki.gov.kz@evil/",
        "https://tsp.pki.gov.kz:x@evil/",
        "https://evil\\@tsp.pki.gov.kz/",
        "https://tsp.pki.gov.kz\\@evil/",
        "https://tsp.pki.gov.kz:8443/",
        "http://tsp.pki.gov.kz/",
        "https://u@tsp.pki.gov.kz/",
        "https://evil/tsp.pki.gov.kz/",
        "https://tsp.pki.gov.kz/\n",
        "not a url",
        "",
    ] {
        assert!(!prefix.allows(url), "{url:?} allowed");
    }

    let api: HttpPrefix = "https://a.kz/api/".parse().unwrap();
    assert!(api.allows("https://a.kz/api/x"));
    assert!(api.allows("https://a.kz/api/"));
    assert!(!api.allows("https://a.kz/apix"));
    assert!(!api.allows("https://a.kz/api"));
    assert!(!api.allows("https://a.kz/"));
    // Dot segments are resolved before the comparison.
    assert!(!api.allows("https://a.kz/api/../secret"));
    assert!(!api.allows("https://a.kz/api/%2e%2e/secret"));
    // Encoded separators and path parameters, which servers may resolve outside `/api/`.
    for url in [
        "https://a.kz/api/..%2fsecret",
        "https://a.kz/api/%2e%2e%2Fsecret",
        "https://a.kz/api/..;/secret",
        "https://a.kz/api/..%5csecret",
        "https://a.kz/api/..%5Csecret",
        "https://a.kz/api/x;y",
    ] {
        assert!(!api.allows(url), "{url:?} allowed");
        assert_eq!(api.check(url), None);
    }
    // Under `/` there is nothing to escape from.
    assert!(prefix.allows("https://tsp.pki.gov.kz/a;b%2Fc%5c"));
    // A prefix with them could allow nothing.
    for bad in [
        "https://a.kz/x;y/",
        "https://a.kz/x%2Fy/",
        "https://a.kz/x%5cy/",
    ] {
        assert!(bad.parse::<HttpPrefix>().is_err(), "{bad:?} accepted");
    }

    let port: HttpPrefix = "https://a.kz:8443/".parse().unwrap();
    assert!(port.allows("https://a.kz:8443/x"));
    assert!(!port.allows("https://a.kz/x"));

    // `check` gives the URL to send: normalized, the same parse `allows` judged.
    let sent = api.check("https://A.kz:443/api/./x/../y?q=1#f").unwrap();
    assert_eq!(sent.as_str(), "https://a.kz/api/y?q=1#f");
    assert_eq!(api.check("https://a.kz/apix"), None);
}
