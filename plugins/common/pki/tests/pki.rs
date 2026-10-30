//! The guest DER library against the synthetic PKI of the core's tests.

use der::{Decode, Encode};
use oncl_port_pki::{attr, cms_read, x509text};
use std::path::PathBuf;
use x509_cert::Certificate;

fn fixture(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn subject(name: &str) -> Vec<u8> {
    let cert = Certificate::from_der(&fixture(&format!("synthetic/{name}.cer"))).unwrap();
    cert.tbs_certificate().subject().to_der().unwrap()
}

#[test]
fn x509_name_round_trip_kalkan() {
    // The DNs `oncl_pki::info::kalkan_dn` gives these certificates' subjects.
    for (name, dn) in [
        (
            "root-gost2015",
            "CN=OpenNCALayer Synthetic Root GOST 2015,O=OpenNCALayer,C=KZ",
        ),
        ("inter-gost2015", "CN=SYNTHETIC NCA (GOST) 2015,C=KZ"),
        (
            "root-rsa",
            "CN=OpenNCALayer Synthetic Root RSA,O=OpenNCALayer,C=KZ",
        ),
    ] {
        assert_eq!(
            attr::x509_name_from_kalkan_dn(dn).unwrap(),
            subject(name),
            "{name}"
        );
    }
}

#[test]
fn rfc2253_reverses_rdns() {
    let name = subject("root-gost2015");
    assert_eq!(
        x509text::rfc2253(&name).unwrap(),
        "C=KZ,O=OpenNCALayer,CN=OpenNCALayer Synthetic Root GOST 2015"
    );
    assert_eq!(
        x509text::x500_principal(&name).unwrap(),
        "C=KZ, O=OpenNCALayer, CN=OpenNCALayer Synthetic Root GOST 2015"
    );
    // A type RFC 2253 does not name: its OID and the value's DER.
    let serial = attr::x509_name_from_kalkan_dn("SERIALNUMBER=IIN1,CN=a\\+b,C=KZ").unwrap();
    assert_eq!(
        x509text::rfc2253(&serial).unwrap(),
        "C=KZ,CN=a\\+b,2.5.4.5=#130449494e31"
    );
    assert_eq!(
        x509text::x500_principal(&serial).unwrap(),
        "C=KZ, CN=\"a+b\", SERIALNUMBER=IIN1"
    );
    // RFC 2253 text back through Kalkan's parser: the name comes out reversed.
    let reversed = attr::x509_name_from_rfc2253(&x509text::rfc2253(&serial).unwrap()).unwrap();
    assert_eq!(
        x509text::rfc2253(&reversed).unwrap(),
        "2.5.4.5=#130449494e31,CN=a\\+b,C=KZ"
    );
}

#[test]
fn ldap_and_algorithm_names() {
    let dn = "CN=ИВАНОВ ИВАН,SURNAME=ИВАНОВ,SERIALNUMBER=IIN123456789012,C=KZ,OU=BIN1,OU=BIN2";
    assert_eq!(x509text::ldap_first(dn, "OU").as_deref(), Some("BIN2"));
    assert_eq!(
        x509text::ldap_first(dn, "CN").as_deref(),
        Some("ИВАНОВ ИВАН")
    );
    assert_eq!(x509text::ldap_first(dn, "cn"), None);
    assert_eq!(
        x509text::ldap_first("CN=a\\,b", "CN").as_deref(),
        Some("a,b")
    );
    assert_eq!(
        x509text::kalkan_sig_alg_name("1.2.398.3.10.1.1.2.3.2"),
        Some("ECGOST3410-2015-512")
    );
    assert_eq!(
        x509text::kalkan_key_alg_name("1.2.398.3.10.1.1.2.2"),
        Some("ECGOST3410-2015")
    );
}

#[test]
fn cms_read_content_and_signers() {
    // A CMS `oncl_pki::cms::sign` made of `hello` with the synthetic key `user-rsa-sign`,
    // attached.
    let cms = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/cms-attached.der"),
    )
    .unwrap();
    assert_eq!(cms_read::content(&cms).as_deref(), Some(&b"hello"[..]));
    let certs = cms_read::certificates(&cms);
    assert!(!certs.is_empty());
    let signers = cms_read::signers(&cms);
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].sid_cert.as_ref(), Some(&certs[0]));
    assert!(
        signers[0]
            .signed_attrs
            .as_ref()
            .unwrap()
            .starts_with(&[0x31])
    );
    assert!(!signers[0].signature.is_empty());
    assert!(cms_read::content(b"not a cms").is_none());
    assert!(cms_read::signers(b"not a cms").is_empty());
}
