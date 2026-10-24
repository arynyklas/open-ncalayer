//! Certificate info of the synthetic NCA-like certificates: KZ subject attributes, serial,
//! validity, key usages and the signing algorithm.

use oncl_pki::info::{CertInfo, cert_info};
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::load;
use oncl_testkit::{read, synthetic};
use std::collections::BTreeSet;
use time::macros::datetime;
use x509_cert::der::Decode;
use x509_cert::der::{Encode, asn1::AnyRef};

const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

fn leaf(name: &str) -> x509_cert::Certificate {
    let key = synthetic(name);
    let mut entries = load(&read(&key.path), &key.password).unwrap();
    entries.swap_remove(0).cert
}

fn info(name: &str) -> CertInfo {
    cert_info(&leaf(name))
}

fn set<const N: usize>(oids: [&str; N]) -> BTreeSet<String> {
    oids.into_iter().map(str::to_owned).collect()
}

#[test]
fn person_fields() {
    let i = info("user-gost2015-sign");
    assert_eq!(i.iin.as_deref(), Some("123456789011"));
    assert!(i.bin.is_none());
    assert!(i.organization.is_none());
    assert!(i.subject_cn.is_some());
}

#[test]
fn legal_fields() {
    let i = info("legal-gost2015-sign");
    assert_eq!(i.bin.as_deref(), Some("123456789021"));
    assert_eq!(i.iin.as_deref(), Some("123456789022"));
    assert_eq!(i.organization.as_deref(), Some("ТОО СИНТЕТИКА"));
}

#[test]
fn serial_keeps_leading_zero() {
    // The serial of this fixture has its top bit set.
    assert!(info("legal-gost2015-sign").serial_hex.starts_with("00"));
}

#[test]
fn serial_hex_is_lowercase_der_integer_content() {
    for name in ["user-gost2015-sign", "legal-gost2015-sign", "user-rsa-sign"] {
        let cert = leaf(name);
        let der = cert.tbs_certificate().serial_number().to_der().unwrap();
        let content = AnyRef::from_der(&der).unwrap().value().to_vec();
        let expected: String = content.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(cert_info(&cert).serial_hex, expected, "{name}");
    }
}

#[test]
fn obsolete_auth_rule() {
    let req = set([CLIENT_AUTH]);
    // GOST 2015-512, keyAgreement, no clientAuth in the EKU.
    let legacy = info("legacy-gost2015-auth");
    assert!(!legacy.ext_key_usages.contains(CLIENT_AUTH));
    assert!(legacy.key_usage.key_agreement);
    // Added by the rule, not by the EKU.
    assert!(legacy.effective_ekus(&req).contains(CLIENT_AUTH));
    assert!(
        legacy
            .effective_ekus(&req)
            .is_superset(&legacy.ext_key_usages)
    );
    // Not requested: nothing is added.
    assert_eq!(
        legacy.effective_ekus(&BTreeSet::new()),
        legacy.ext_key_usages
    );
    // No keyAgreement.
    assert!(
        !info("user-gost2015-sign")
            .effective_ekus(&req)
            .contains(CLIENT_AUTH)
    );
}

#[test]
fn key_usage_and_ekus() {
    let sign = info("user-gost2015-sign");
    assert!(sign.key_usage.digital_signature && sign.key_usage.non_repudiation);
    assert!(!sign.key_usage.key_encipherment && !sign.key_usage.key_agreement);
    assert!(sign.ext_key_usages.contains("1.3.6.1.5.5.7.3.4"));
    let auth = info("user-gost2015-auth");
    assert!(auth.ext_key_usages.contains(CLIENT_AUTH));
}

#[test]
fn algorithm_oids() {
    let gost = info("user-gost2015-sign");
    assert_eq!(gost.signature_alg_oid, "1.2.398.3.10.1.1.2.3.2");
    assert_eq!(gost.spki_alg_oid, "1.2.398.3.10.1.1.2.2");
    assert_eq!(gost.signing_alg().unwrap(), SigAlg::Gost2015_512);
    assert_eq!(
        info("user-gost2004-sign").signing_alg().unwrap(),
        SigAlg::Gost2004
    );
    assert_eq!(info("user-rsa-sign").spki_alg_oid, "1.2.840.113549.1.1.1");
}

#[test]
fn signing_alg_from_cert_sigalg() {
    assert_eq!(
        info("user-rsa-sign").signing_alg().unwrap(),
        SigAlg::RsaSha256
    );
}

#[test]
fn validity_window() {
    let expired = info("expired-gost2015-sign");
    assert_eq!(expired.not_before, datetime!(2020-01-01 0:00 UTC));
    assert_eq!(expired.not_after, datetime!(2021-01-01 0:00 UTC));
    assert!(!expired.is_within_validity(datetime!(2026-10-24 0:00 UTC)));
    assert!(expired.is_within_validity(datetime!(2020-06-01 0:00 UTC)));
    let valid = info("user-gost2015-sign");
    assert!(valid.is_within_validity(datetime!(2026-10-24 0:00 UTC)));
}
