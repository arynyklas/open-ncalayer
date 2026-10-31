//! Facts from bytecode, `MANIFEST.MF`, keystores and installer metadata; merging and the
//! stable JSON.

use std::collections::BTreeMap;

use base64::Engine;
use oncl_testkit::{fixture, read};
use xtask::upstream::classfile::parse_class;
use xtask::upstream::facts::{
    BundleUpdate, DistFacts, FetchStatus, JarFacts, UnpackStatus, Updates, key8, merge, to_json,
};
use xtask::upstream::jar::{jar_entries, jar_facts, manifest_mf};
use xtask::upstream::manifest::verify_and_parse;
use xtask::upstream::meta::{inno_meta, tzdb_meta};
use xtask::upstream::sha256_hex;
use xtask::upstream::testkit::synthetic_issuers;
use xtask::upstream::unpack::Limits;

fn entries(name: &str) -> BTreeMap<String, Vec<u8>> {
    jar_entries(
        &read(fixture(&format!("upstream/{name}"))),
        &Limits::default(),
    )
    .unwrap()
}

fn facts(name: &str) -> JarFacts {
    let bytes = read(fixture(&format!("upstream/{name}")));
    jar_facts(
        &jar_entries(&bytes, &Limits::default()).unwrap(),
        bytes.len() as u64,
        &synthetic_issuers(),
    )
}

const DEMO: &str = "kz.example.demo.DemoModule";
const SIGN: &str = "sign(Ljava/lang/String;)Ljava/lang/String;";

#[test]
fn class_parser_reads_members_and_constants() {
    let bytes = entries("bundle-a.jar")["kz/example/demo/DemoModule.class"].clone();
    let class = parse_class(&bytes).unwrap();
    assert_eq!(class.name, "kz/example/demo/DemoModule");
    assert_eq!(class.super_name.as_deref(), Some("java/lang/Object"));
    let sign = class.methods.iter().find(|m| m.name == "sign").unwrap();
    assert_eq!(sign.descriptor, "(Ljava/lang/String;)Ljava/lang/String;");
    assert_eq!(sign.access & 1, 1);
    assert!(class.strings.iter().any(|s| s == "SIGN_ERROR"));
    assert!(class.ints.contains(&13579));
    for len in 0..bytes.len() {
        assert!(parse_class(&bytes[..len]).is_err(), "{len}");
    }
}

#[test]
fn module_names_error_codes_urls_ports() {
    let api = facts("bundle-a.jar").api;
    assert!(api.names.contains(DEMO));
    assert!(api.error_codes.contains("SIGN_ERROR"));
    assert!(api.urls.contains("http://tsp.example.invalid/"));
    assert!(api.ports.contains(&13579));
}

#[test]
fn private_and_package_methods_excluded() {
    let api = facts("bundle-a.jar").api;
    let demo = &api.classes[DEMO];
    assert_eq!(demo.kind, "class");
    assert!(demo.methods.contains(SIGN));
    assert!(demo.methods.contains("calls()I"));
    assert!(demo.methods.contains("<init>()V"));
    assert!(!demo.methods.iter().any(|m| m.starts_with("packageHelper")));
    assert!(!demo.methods.iter().any(|m| m.starts_with("privateHelper")));
    assert!(demo.fields.contains("calls:I"));
    assert!(demo.fields.contains("SIGN_ERROR:Ljava/lang/String;"));
    assert!(!demo.fields.iter().any(|f| f.starts_with("last:")));
    assert_eq!(
        api.classes["kz.example.annotations.NCALayerMethod"].kind,
        "annotation"
    );
}

#[test]
fn ncalayer_method_annotation_found() {
    let api = facts("bundle-a.jar").api;
    assert_eq!(
        api.ncalayer_methods.iter().collect::<Vec<_>>(),
        [&format!("{DEMO}.{SIGN}")]
    );
    let v2 = facts("bundle-a-v2.jar").api;
    assert!(v2.ncalayer_methods.contains(&format!(
        "{DEMO}.verify(Ljava/lang/String;)Ljava/lang/String;"
    )));
}

#[test]
fn third_party_classes_only_counted() {
    let f = facts("bundle-a.jar");
    assert_eq!(f.libraries["com.thirdparty"], 1);
    assert!(!f.api.classes.contains_key("com.thirdparty.lib.Util"));
}

#[test]
fn manifest_mf_continuation_and_params() {
    let f = facts("bundle-a.jar");
    assert_eq!(f.symname.as_deref(), Some("kz.example.demo"));
    assert_eq!(f.version.as_deref(), Some("1.0.0"));
    let import = &f.manifest_mf["Import-Package"];
    assert!(import.ends_with("javax.security.auth.x500"), "{import}");
    assert!(!import.contains('\n'));
    assert!(!f.manifest_mf.contains_key("Manifest-Version"));
    let mf = manifest_mf(b"A: 1\r\nB: lo\r\n ng\r\n\r\nName: x\r\nC: 2\r\n");
    assert_eq!(mf["B"], "long");
    assert!(!mf.contains_key("C"));
}

/// The encrypted key block of the first private-key entry of a JKS.
fn key_block(jks: &[u8]) -> Vec<u8> {
    let u32_at = |p: usize| u32::from_be_bytes(jks[p..p + 4].try_into().unwrap()) as usize;
    let mut pos = 12;
    assert_eq!(u32_at(pos), 1, "first entry is a private key");
    pos += 4;
    let alias_len = u16::from_be_bytes([jks[pos], jks[pos + 1]]) as usize;
    pos += 2 + alias_len + 8;
    let len = u32_at(pos);
    jks[pos + 4..pos + 4 + len].to_vec()
}

#[test]
fn jks_trusted_and_private_aliases() {
    let f = facts("bundle-a.jar");
    let trusted = &f.keystores["keystores/trusted.jks"].trusted;
    assert_eq!(
        trusted["synthetic-root-rsa"].sha256,
        sha256_hex(&read(fixture("synthetic/root-rsa.cer")))
    );
    let local = &f.keystores["keystores/local.jks"];
    assert_eq!(local.private["demo-key"].len(), 1);
    let json = String::from_utf8(serde_json::to_vec(&f).unwrap()).unwrap();
    let block = key_block(&entries("bundle-a.jar")["keystores/local.jks"]);
    for window in block.windows(16) {
        let hex: String = window.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!json.contains(&hex));
        assert!(!json.contains(&hex.to_uppercase()));
        let b64 = base64::engine::general_purpose::STANDARD.encode(window);
        assert!(!json.contains(&b64[..20]));
    }
}

#[test]
fn natives_listed() {
    let f = facts("bundle-a.jar");
    assert!(f.natives.contains_key("natives/linux-x86-64/libdemo.so"));
}

#[test]
fn embedded_manifest_summarised() {
    let f = facts("app.jar");
    let m = &f.embedded_manifests["ncalayer.der"];
    assert_eq!(m.version, "1.4");
    assert_eq!(m.bundles, 4);
    assert!(m.verified);
    assert!(m.signer_sha256.is_some());
}

#[test]
fn repack_keeps_content_sha_and_api() {
    let a = read(fixture("upstream/bundle-a.jar"));
    let b = read(fixture("upstream/bundle-a-repack.jar"));
    assert_ne!(sha256_hex(&a), sha256_hex(&b));
    let fa = facts("bundle-a.jar");
    let fb = facts("bundle-a-repack.jar");
    assert_eq!(fa.content_sha256, fb.content_sha256);
    assert_eq!(fa.api, fb.api);
    assert_ne!(fa.content_sha256, facts("bundle-a-v2.jar").content_sha256);
}

#[test]
fn tzdb_version_read() {
    assert_eq!(
        tzdb_meta(&read(fixture("upstream/tzdb.dat")))
            .unwrap()
            .versions,
        ["2026z"]
    );
    assert_eq!(tzdb_meta(b"\x01\x00\x04TZDB"), None);
}

#[test]
fn inno_meta_from_script() {
    let script = "\
[Setup]
AppId={{00000000-0000-0000-0000-000000000000}
AppName=Example
AppVersion=1.2.3
LicenseFile=license.txt
PrivilegesRequired=lowest

[Registry]
Root: HKCU; Subkey: \"Software\\Example\\Run\"; ValueType: string; ValueName: \"\"; Flags: uninsdeletekey

[Run]
Filename: \"{app}\\example.exe\"; Description: \"Run\"; Flags: postinstall
";
    let meta = inno_meta(script);
    assert_eq!(meta.setup["AppName"], "Example");
    assert_eq!(meta.setup["AppVersion"], "1.2.3");
    assert_eq!(meta.setup["PrivilegesRequired"], "lowest");
    assert!(!meta.setup.contains_key("LicenseFile"));
    assert_eq!(
        meta.registry.iter().collect::<Vec<_>>(),
        ["HKCU\\Software\\Example\\Run\\"]
    );
    assert_eq!(meta.run.iter().collect::<Vec<_>>(), ["{app}\\example.exe"]);
}

fn verified() -> xtask::upstream::manifest::Verified {
    verify_and_parse(
        &read(fixture("upstream/manifest.der")),
        &synthetic_issuers(),
    )
    .unwrap()
}

fn dist(jar: &str) -> DistFacts {
    DistFacts {
        url: "http://example.test/d.zip".to_owned(),
        page: None,
        label: None,
        filename: None,
        size: Some(1),
        sha256: Some("ab".to_owned()),
        published_sha1: None,
        format: None,
        status: FetchStatus::Ok,
        unpack: UnpackStatus::Ok,
        files: BTreeMap::new(),
        jre: None,
        jars: [("lib/x.jar".to_owned(), jar.to_owned())].into(),
        embedded_manifests: BTreeMap::new(),
        meta: Default::default(),
    }
}

#[test]
fn merge_keeps_unchanged_sources_and_drops_orphan_jars() {
    let v = verified();
    let jar_a = facts("bundle-a.jar");
    let sha_a = sha256_hex(&read(fixture("upstream/bundle-a.jar")));
    let first = merge(
        None,
        &v,
        Updates {
            bundles: [(
                "kz.example.demo".to_owned(),
                BundleUpdate {
                    fetch: FetchStatus::Ok,
                    jar: Some(sha_a.clone()),
                },
            )]
            .into(),
            distributions: [
                ("dist:one".to_owned(), Some(dist("j1"))),
                ("dist:two".to_owned(), Some(dist("j2"))),
            ]
            .into(),
            jars: [
                (sha_a.clone(), jar_a.clone()),
                ("j1".to_owned(), jar_a.clone()),
                ("j2".to_owned(), jar_a.clone()),
            ]
            .into(),
        },
    );
    assert_eq!(
        first.bundles["kz.example.demo"].jar.as_deref(),
        Some(sha_a.as_str())
    );
    assert_eq!(first.bundles["kz.example.core"].fetch, FetchStatus::Pending);
    assert_eq!(first.jars.len(), 3);
    // dist:two goes away: its JAR goes with it; the rest is carried over.
    let second = merge(
        Some(&first),
        &v,
        Updates {
            distributions: [("dist:two".to_owned(), None)].into(),
            ..Updates::default()
        },
    );
    assert!(second.distributions.contains_key("dist:one"));
    assert!(!second.distributions.contains_key("dist:two"));
    assert!(second.jars.contains_key("j1"));
    assert!(!second.jars.contains_key("j2"));
    assert_eq!(
        second.bundles["kz.example.demo"],
        first.bundles["kz.example.demo"]
    );
}

#[test]
fn facts_json_is_stable() {
    let v = verified();
    let build = || {
        let sha_a = sha256_hex(&read(fixture("upstream/bundle-a.jar")));
        merge(
            None,
            &v,
            Updates {
                bundles: [(
                    "kz.example.demo".to_owned(),
                    BundleUpdate {
                        fetch: FetchStatus::Ok,
                        jar: Some(sha_a.clone()),
                    },
                )]
                .into(),
                distributions: BTreeMap::new(),
                jars: [(sha_a, facts("bundle-a.jar"))].into(),
            },
        )
    };
    let a = to_json(&build());
    let b = to_json(&build());
    assert_eq!(a, b);
    assert_eq!(key8(&a), key8(&b));
    assert_eq!(key8(&a).len(), 8);
    assert!(a.ends_with(b"}\n"));
    let back: xtask::upstream::facts::Facts = serde_json::from_slice(&a).unwrap();
    assert_eq!(to_json(&back), a);
}
