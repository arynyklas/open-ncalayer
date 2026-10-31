//! The manifest of the original NCALayer: signature, signer, issuer and JSON.

use oncl_pki::cert;
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_testkit::{fixture, read, synthetic_cert};
use xtask::upstream::manifest::{ManifestError, parse_json, verify_and_parse};
use xtask::upstream::sha256_hex;
use xtask::upstream::testkit::{
    sign_manifest, synthetic_entry, synthetic_issuers, synthetic_signer,
};

fn der() -> Vec<u8> {
    read(fixture("upstream/manifest.der"))
}

#[test]
fn synthetic_manifest_verifies_and_parses() {
    let der = der();
    let v = verify_and_parse(&der, &synthetic_issuers()).unwrap();
    let m = &v.manifest;
    assert_eq!(m.version, "1.4");
    assert_eq!(m.disturls.len(), 5);
    assert_eq!(m.bundles.len(), 4);
    let demo = m
        .bundles
        .iter()
        .find(|b| b.symname == "kz.example.demo")
        .unwrap();
    assert!(!demo.required);
    assert!(m.bundles.iter().filter(|b| b.required).count() == 2);
    assert_eq!(m.syspkgs, ["a.b", "c.d", "e.f"]);
    assert!(
        v.signer.subject.contains("CN=NCALayer"),
        "{}",
        v.signer.subject
    );
    assert_eq!(v.sha256, sha256_hex(&der));
    assert_eq!(v.size, der.len() as u64);
    assert!(v.signing_time.is_some());
}

#[test]
fn committed_manifest_matches_json() {
    let v = verify_and_parse(&der(), &synthetic_issuers()).unwrap();
    assert_eq!(
        v.content,
        read(fixture("upstream/manifest.json")),
        "run `cargo xtask upstream make-fixtures`"
    );
}

#[test]
fn tampered_manifest_is_cms_error() {
    let mut der = der();
    let needle = b"\"version\":\"1.4\"";
    let at = der.windows(needle.len()).position(|w| w == needle).unwrap();
    der[at + 12] = b'5';
    assert!(matches!(
        verify_and_parse(&der, &synthetic_issuers()),
        Err(ManifestError::Cms(_))
    ));
}

#[test]
fn wrong_cn_is_not_ncalayer_signer() {
    let json = read(fixture("upstream/manifest.json"));
    let der = sign_manifest(&json, &synthetic_signer("NCALayer2"));
    assert_eq!(
        verify_and_parse(&der, &synthetic_issuers()),
        Err(ManifestError::NotNcaLayerSigner("NCALayer2".to_owned()))
    );
}

#[test]
fn unknown_issuer() {
    let rsa = cert::parse(&synthetic_cert("root-rsa")).unwrap();
    assert!(matches!(
        verify_and_parse(&der(), &[rsa]),
        Err(ManifestError::UnknownIssuer(_))
    ));
}

#[test]
fn issuer_with_same_dn_wrong_key_is_bad_issuer_signature() {
    let root = cert::parse(&synthetic_cert("root-gost2015")).unwrap();
    let auth = synthetic_entry("user-gost2015-auth");
    let spec = TestCertSpec {
        public_key: auth
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .clone(),
        ..TestCertSpec::from_cert(&root)
    };
    let twin = issue_cert(
        &KeyEntry {
            alias: "twin".to_owned(),
            key: auth.key,
            cert: root.clone(),
        },
        spec,
    );
    assert_eq!(
        verify_and_parse(&der(), std::slice::from_ref(&twin)),
        Err(ManifestError::BadIssuerSignature)
    );
    assert!(verify_and_parse(&der(), &[twin, root]).is_ok());
}

#[test]
fn unknown_fields_are_kept_in_extra() {
    let json =
        br#"{"ncalayer":{"version":"2","newtop":"x","bundles":[{"symname":"a.b","newfield":1}]}}"#;
    let m = parse_json(json).unwrap();
    assert_eq!(m.bundles[0].extra["newfield"], serde_json::json!(1));
    assert_eq!(m.extra["newtop"], serde_json::json!("x"));
    assert!(!m.bundles[0].required);
    assert_eq!(m.bundles[0].url, "");
}

#[test]
fn oversized_manifest_rejected() {
    let big = vec![b' '; (1 << 20) + 1];
    assert!(matches!(
        verify_and_parse(&big, &synthetic_issuers()),
        Err(ManifestError::TooLarge(_))
    ));
    assert!(matches!(parse_json(&big), Err(ManifestError::TooLarge(_))));
}

#[test]
#[ignore = "network: the live manifest of the original"]
fn live_manifest_verifies() {
    let body = xtask::upstream::http::Fetcher::new()
        .get(
            xtask::upstream::MANIFEST_URL,
            xtask::upstream::MANIFEST_MAX,
            &Default::default(),
        )
        .unwrap()
        .body;
    let v = verify_and_parse(&body, oncl_pki::roots::nca_production()).unwrap();
    assert!(!v.manifest.version.is_empty());
    assert!(v.manifest.bundles.iter().any(|b| b.required));
    assert!(
        v.signer.subject.contains("CN=NCALayer"),
        "{}",
        v.signer.subject
    );
}
