//! Certification path building: the embedded NCA CAs, the synthetic intermediate PKI and
//! certificates issued on the fly that break one rule each.

use der::Encode;
use der::asn1::{Null, ObjectIdentifier, OctetString};
use der::oid::AssociatedOid;
use oncl_pki::cert::{self, Certificate};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::{CaSet, PathError, build_path, validation_time};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_testkit::{fixture, read, synthetic, synthetic_cert};
use time::OffsetDateTime;
use time::macros::datetime;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};

const NOW: OffsetDateTime = datetime!(2026-10-25 12:00 UTC);

fn nca(alias: &str) -> Certificate {
    cert::parse(&read(fixture(&format!("nca/prod/{alias}.der")))).unwrap()
}

fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn extension(extn_id: ObjectIdentifier, critical: bool, value: &impl Encode) -> Extension {
    Extension {
        extn_id,
        critical,
        extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
    }
}

/// The synthetic intermediate CA, then its root.
fn inter_and_root() -> Vec<Certificate> {
    vec![cer("inter-gost2015"), cer("root-gost2015")]
}

#[test]
fn nca_2022_gost_intermediate_chains_to_root() {
    let path = build_path(&nca("ncagost22"), &CaSet::nca_production(), NOW).unwrap();
    assert_eq!(path, [nca("ncagost22"), nca("rcagost22")]);
}

#[test]
fn rsa_2022_intermediate_chains_to_rsa_2020_root() {
    let path = build_path(&nca("ncarsa22"), &CaSet::nca_production(), NOW).unwrap();
    assert_eq!(path, [nca("ncarsa22"), nca("rcarsa20")]);
}

#[test]
fn anchor_alone_is_a_path_of_one() {
    let root = nca("rcagost22");
    let path = build_path(&root, &CaSet::nca_production(), NOW).unwrap();
    assert_eq!(path, [root]);
}

#[test]
fn synthetic_leaf_via_intermediate() {
    let leaf = entry("inter-user-gost2015-sign").cert;
    let path = build_path(&leaf, &CaSet::new(inter_and_root()), NOW).unwrap();
    assert_eq!(path, [leaf, cer("inter-gost2015"), cer("root-gost2015")]);
}

#[test]
fn same_subject_twin_ca_in_either_order() {
    let (inter, twin, root) = (
        cer("inter-gost2015"),
        cer("inter-gost2015-twin"),
        cer("root-gost2015"),
    );
    let leaf = entry("inter-noaki-gost2015-sign").cert;
    for set in [
        [twin.clone(), inter.clone(), root.clone()],
        [inter.clone(), twin.clone(), root.clone()],
    ] {
        let path = build_path(&leaf, &CaSet::new(set.to_vec()), NOW).unwrap();
        assert_eq!(path, [leaf.clone(), inter.clone(), root.clone()]);
    }
    // Only the twin carries the name: the signature decides.
    assert_eq!(
        build_path(&leaf, &CaSet::new(vec![twin, root]), NOW),
        Err(PathError::BadSignature)
    );
}

#[test]
fn issuers_of_puts_the_key_identifier_match_first() {
    let (inter, twin) = (cer("inter-gost2015"), cer("inter-gost2015-twin"));
    let set = CaSet::new(vec![twin.clone(), cer("root-gost2015"), inter.clone()]);
    let with_aki = entry("inter-user-gost2015-sign").cert;
    assert_eq!(
        set.issuers_of(&with_aki).collect::<Vec<_>>(),
        [&inter, &twin]
    );
    let without_aki = entry("inter-noaki-gost2015-sign").cert;
    assert_eq!(
        set.issuers_of(&without_aki).collect::<Vec<_>>(),
        [&twin, &inter]
    );
}

#[test]
fn missing_intermediate_is_issuer_not_found() {
    let leaf = entry("inter-user-gost2015-sign").cert;
    let set = CaSet::new(vec![cer("root-gost2015")]);
    assert_eq!(build_path(&leaf, &set, NOW), Err(PathError::IssuerNotFound));
    assert_eq!(
        build_path(&leaf, &CaSet::default(), NOW),
        Err(PathError::IssuerNotFound)
    );
}

#[test]
fn topmost_ca_of_the_set_is_the_anchor() {
    // As the original's `PKIXUtil`: without the root, the intermediate CA is the anchor.
    let leaf = entry("inter-user-gost2015-sign").cert;
    let inter_only = CaSet::new(vec![cer("inter-gost2015")]);
    assert_eq!(
        build_path(&leaf, &inter_only, NOW).unwrap(),
        [leaf.clone(), cer("inter-gost2015")]
    );
    // The certificate itself still needs its issuer in the set.
    assert_eq!(
        build_path(&leaf, &CaSet::new(vec![nca("ncagost22")]), NOW),
        Err(PathError::IssuerNotFound)
    );
    // The anchor is still checked like any issuer: dates, keyCertSign, cA.
    let mut expired = entry("user-gost2015-sign");
    let mut spec = TestCertSpec::from_cert(&expired.cert);
    spec.extensions = ca_extensions(KeyUsages::KeyCertSign);
    spec.validity = *entry("inter-expired-gost2015-sign")
        .cert
        .tbs_certificate()
        .validity();
    expired.cert = issue_cert(&entry("inter-gost2015.key"), spec);
    let under_expired = issue_cert(
        &expired,
        TestCertSpec::from_cert(&entry("inter-user-gost2015-sign").cert),
    );
    assert_eq!(
        build_path(&under_expired, &CaSet::new(vec![expired.cert]), NOW),
        Err(PathError::NotValidAt { index: 1 })
    );
    let (sub_ca, sub_leaf) = sub_ca_and_leaf(KeyUsages::CRLSign);
    assert_eq!(
        build_path(&sub_leaf, &CaSet::new(vec![sub_ca.clone()]), NOW),
        Err(PathError::KeyCertSignMissing { index: 1 })
    );
    let (sub_ca, sub_leaf) = sub_ca_and_leaf(KeyUsages::KeyCertSign);
    assert_eq!(
        build_path(&sub_leaf, &CaSet::new(vec![sub_ca.clone()]), NOW).unwrap(),
        [sub_leaf.clone(), sub_ca.clone()]
    );
    // A non-CA in the set is not an anchor.
    let user = entry("user-gost2015-sign");
    let by_user = issue_cert(
        &user,
        TestCertSpec::from_cert(&entry("inter-user-gost2015-sign").cert),
    );
    assert_eq!(
        build_path(&by_user, &CaSet::new(vec![user.cert]), NOW),
        Err(PathError::NotCa { index: 1 })
    );
}

#[test]
fn expired_leaf_validates_at_not_after() {
    let leaf = entry("inter-expired-gost2015-sign").cert;
    let set = CaSet::new(inter_and_root());
    let at = validation_time(&leaf, NOW);
    assert_eq!(at, datetime!(2026-01-01 0:00 UTC));
    assert_eq!(build_path(&leaf, &set, at).unwrap().len(), 3);
    assert_eq!(
        build_path(&leaf, &set, NOW),
        Err(PathError::NotValidAt { index: 0 })
    );
    // A valid leaf is checked at `now`.
    let valid = entry("inter-user-gost2015-sign").cert;
    assert_eq!(validation_time(&valid, NOW), NOW);
    // Before notBefore the leaf is not valid either.
    assert_eq!(
        build_path(&valid, &set, datetime!(2024-06-01 0:00 UTC)),
        Err(PathError::NotValidAt { index: 0 })
    );
}

#[test]
fn leaf_with_unknown_critical_extension_fails() {
    let inter = entry("inter-gost2015.key");
    let set = CaSet::new(inter_and_root());
    let template = entry("inter-user-gost2015-sign").cert;
    let unknown = ObjectIdentifier::new_unwrap("1.2.3.4");
    for critical in [false, true] {
        let mut spec = TestCertSpec::from_cert(&template);
        spec.extensions.push(extension(unknown, critical, &Null));
        let leaf = issue_cert(&inter, spec);
        let result = build_path(&leaf, &set, NOW).map(|p| p.len());
        if critical {
            assert_eq!(
                result,
                Err(PathError::UnknownCriticalExtension {
                    index: 0,
                    oid: "1.2.3.4".to_owned()
                })
            );
        } else {
            assert_eq!(result, Ok(3));
        }
    }
}

#[test]
fn non_ca_issuer_is_rejected() {
    let user = entry("user-gost2015-sign");
    let template = entry("inter-user-gost2015-sign").cert;
    let leaf = issue_cert(&user, TestCertSpec::from_cert(&template));
    let set = CaSet::new(vec![user.cert.clone(), cer("root-gost2015")]);
    assert_eq!(
        build_path(&leaf, &set, NOW),
        Err(PathError::NotCa { index: 1 })
    );
}

/// basicConstraints cA without pathLen and keyUsage `usage`, both critical.
fn ca_extensions(usage: KeyUsages) -> Vec<Extension> {
    let constraints = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    vec![
        extension(BasicConstraints::OID, true, &constraints),
        extension(KeyUsage::OID, true, &KeyUsage(usage.into())),
    ]
}

/// The `user-gost2015-sign` key turned into a CA under `inter-gost2015` with keyUsage
/// `usage`, and a leaf it issued.
fn sub_ca_and_leaf(usage: KeyUsages) -> (Certificate, Certificate) {
    let mut user = entry("user-gost2015-sign");
    let mut spec = TestCertSpec::from_cert(&user.cert);
    spec.extensions = ca_extensions(usage);
    user.cert = issue_cert(&entry("inter-gost2015.key"), spec);
    let leaf = issue_cert(
        &user,
        TestCertSpec::from_cert(&entry("inter-user-gost2015-sign").cert),
    );
    (user.cert, leaf)
}

#[test]
fn cross_signed_loop_is_too_long() {
    // A: the inter-user name and key, signed by the user key; B: the user name and key,
    // signed by the inter-user key. Each issues the other, so no anchor is ever reached.
    let (user, inter_user) = (
        entry("user-gost2015-sign"),
        entry("inter-user-gost2015-sign"),
    );
    let mut a = TestCertSpec::from_cert(&inter_user.cert);
    a.extensions = ca_extensions(KeyUsages::KeyCertSign);
    let mut b = TestCertSpec::from_cert(&user.cert);
    b.extensions = ca_extensions(KeyUsages::KeyCertSign);
    let set = CaSet::new(vec![issue_cert(&user, a), issue_cert(&inter_user, b)]);
    let leaf = issue_cert(
        &inter_user,
        TestCertSpec::from_cert(&entry("legal-gost2015-sign").cert),
    );
    assert_eq!(build_path(&leaf, &set, NOW), Err(PathError::TooLong));
}

#[test]
fn issuer_path_len_and_key_usage_are_enforced() {
    // inter-gost2015 has pathLen 0: no CA may follow it.
    let (sub_ca, leaf) = sub_ca_and_leaf(KeyUsages::KeyCertSign);
    let mut set = inter_and_root();
    set.insert(0, sub_ca);
    assert_eq!(
        build_path(&leaf, &CaSet::new(set), NOW),
        Err(PathError::PathLenExceeded { index: 2 })
    );

    let (sub_ca, leaf) = sub_ca_and_leaf(KeyUsages::CRLSign);
    let mut set = inter_and_root();
    set.insert(0, sub_ca);
    assert_eq!(
        build_path(&leaf, &CaSet::new(set), NOW),
        Err(PathError::KeyCertSignMissing { index: 1 })
    );
}
