//! The committed synthetic PKI (`fixtures/synthetic/`) matches `cargo xtask gen-fixtures` and
//! is usable: every container opens and chains through its issuer to its root, and the
//! validation subjects (intermediate CA, OCSP responders, revocation subjects) carry the
//! extensions the validation code relies on.

use der::Decode;
use der::asn1::Ia5String;
use oncl_pki::key::{PublicKey, SigAlg};
use oncl_pki::{cert, pkcs12};
use oncl_testkit::{read, synthetic, synthetic_all, synthetic_cert, workspace_root};
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints,
    ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};

const OCSP_URL: &str = "http://ocsp.synthetic.test";
const ROOT_CRL_URL: &str = "http://crl.synthetic.test/root-gost2015.crl";
const INTER_CRL_URL: &str = "http://crl.synthetic.test/inter-gost2015.crl";
const EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const ID_PKIX_OCSP_NOCHECK: &str = "1.3.6.1.5.5.7.48.1.5";

#[test]
fn committed_fixtures_are_fresh() {
    assert!(
        xtask::fixtures::check(&workspace_root()).unwrap(),
        "fixtures/synthetic is stale: run `cargo xtask gen-fixtures`"
    );
}

#[test]
fn every_p12_loads_and_chains_through_its_issuer_to_its_root() {
    let all = synthetic_all();
    assert_eq!(all.len(), 18);
    for f in all {
        let entries =
            pkcs12::load(&read(&f.path), &f.password).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        let aliases: Vec<&str> = entries.iter().map(|e| e.alias.as_str()).collect();
        assert_eq!(aliases, f.aliases, "{}", f.name);
        let issuer = cert::parse(&read(&f.issuer)).unwrap();
        let root = cert::parse(&read(&f.root)).unwrap();
        cert::verify_signature(&issuer, &root).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        for entry in &entries {
            cert::verify_signature(&entry.cert, &issuer)
                .unwrap_or_else(|e| panic!("{} / {}: {e}", f.name, entry.alias));
        }
    }
    let multi = synthetic("multi-gost2015");
    assert_eq!(multi.aliases.len(), 2);
    assert_eq!(multi.issuer, multi.root);
    let leaf = synthetic("inter-user-gost2015-sign");
    assert!(leaf.issuer.ends_with("inter-gost2015.cer"));
    assert!(leaf.root.ends_with("root-gost2015.cer"));
}

/// The CA key containers hold the CA certificates and keys that sign for them, so tests can
/// issue CRLs as these CAs.
#[test]
fn ca_key_containers_sign_for_the_ca_certificates() {
    for (container, cer) in [
        ("inter-gost2015.key", "inter-gost2015"),
        ("root-gost2015.key", "root-gost2015"),
    ] {
        let f = synthetic(container);
        let entries = pkcs12::load(&read(&f.path), &f.password).unwrap();
        assert_eq!(entries.len(), 1, "{container}");
        let entry = &entries[0];
        assert_eq!(der(&entry.cert), synthetic_cert(cer), "{container}");
        let sig = entry.key.sign(SigAlg::Gost2015_512, b"crl").unwrap();
        PublicKey::from_spki(entry.cert.tbs_certificate().subject_public_key_info())
            .unwrap()
            .verify(SigAlg::Gost2015_512, b"crl", &sig)
            .unwrap_or_else(|e| panic!("{container}: {e}"));
    }
}

#[test]
fn intermediate_and_twin_are_constrained_cas_under_root_gost2015() {
    let root = parse(&synthetic_cert("root-gost2015"));
    let inter = parse(&synthetic_cert("inter-gost2015"));
    let twin = parse(&synthetic_cert("inter-gost2015-twin"));
    // RFC 4514 lists the RDNs last first: in DER the order is CN, C, as in NCA certificates.
    assert_eq!(
        inter.tbs_certificate().subject().to_string(),
        "C=KZ,CN=SYNTHETIC NCA (GOST) 2015"
    );
    assert_eq!(
        twin.tbs_certificate().subject(),
        inter.tbs_certificate().subject()
    );
    assert_ne!(
        twin.tbs_certificate().subject_public_key_info(),
        inter.tbs_certificate().subject_public_key_info()
    );
    assert_ne!(
        twin.tbs_certificate().serial_number(),
        inter.tbs_certificate().serial_number()
    );
    for ca in [&inter, &twin] {
        assert_eq!(
            ca.tbs_certificate().issuer(),
            root.tbs_certificate().subject()
        );
        cert::verify_signature(ca, &root).unwrap();
        let (critical, bc) = ext::<BasicConstraints>(ca).unwrap();
        assert!(critical && bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
        let (critical, ku) = ext::<KeyUsage>(ca).unwrap();
        assert!(critical);
        assert_eq!(ku.0, KeyUsages::KeyCertSign | KeyUsages::CRLSign);
        assert_eq!(crl_urls(ca), [ROOT_CRL_URL]);
    }
}

#[test]
fn leaves_under_intermediate_point_to_ocsp_and_crl() {
    let inter = parse(&synthetic_cert("inter-gost2015"));
    let mut serials = Vec::new();
    for name in [
        "inter-user-gost2015-sign",
        "inter-revoked-gost2015-sign",
        "inter-expired-gost2015-sign",
        "inter-noaki-gost2015-sign",
    ] {
        let cert = leaf(name);
        assert_eq!(
            cert.tbs_certificate().issuer(),
            inter.tbs_certificate().subject(),
            "{name}"
        );
        let (critical, aia) = ext::<AuthorityInfoAccessSyntax>(&cert).unwrap();
        assert!(!critical, "{name}");
        assert_eq!(aia.0.len(), 1, "{name}");
        assert_eq!(aia.0[0].access_method.to_string(), ID_AD_OCSP, "{name}");
        assert_eq!(aia.0[0].access_location, uri(OCSP_URL), "{name}");
        assert_eq!(crl_urls(&cert), [INTER_CRL_URL], "{name}");
        serials.push(cert.tbs_certificate().serial_number().as_bytes().to_vec());
    }
    serials.sort();
    serials.dedup();
    assert_eq!(serials.len(), 4, "serial numbers are distinct");
}

/// The expired leaf lies inside the validity of its CAs, so its chain builds at its
/// `notAfter`.
#[test]
fn expired_leaf_is_inside_ca_validity() {
    let expired = leaf("inter-expired-gost2015-sign");
    let validity = expired.tbs_certificate().validity();
    assert_eq!(validity.not_before.to_string(), "2025-01-01T00:00:00Z");
    assert_eq!(validity.not_after.to_string(), "2026-01-01T00:00:00Z");
    for ca in ["inter-gost2015", "root-gost2015"] {
        let ca = parse(&synthetic_cert(ca));
        let ca_validity = ca.tbs_certificate().validity();
        assert!(
            ca_validity.not_before.to_unix_duration() <= validity.not_before.to_unix_duration()
        );
        assert!(validity.not_after.to_unix_duration() < ca_validity.not_after.to_unix_duration());
    }
}

/// Every leaf under the intermediate names it by AuthorityKeyIdentifier except
/// `inter-noaki-…`, which only its signature ties to `inter-gost2015` rather than the twin.
#[test]
fn noaki_leaf_is_told_from_the_twin_only_by_signature() {
    let inter = parse(&synthetic_cert("inter-gost2015"));
    let twin = parse(&synthetic_cert("inter-gost2015-twin"));
    let (_, inter_ski) = ext::<SubjectKeyIdentifier>(&inter).unwrap();
    for name in [
        "inter-user-gost2015-sign",
        "inter-revoked-gost2015-sign",
        "inter-expired-gost2015-sign",
    ] {
        let (_, aki) = ext::<AuthorityKeyIdentifier>(&leaf(name)).unwrap();
        assert_eq!(aki.key_identifier, Some(inter_ski.0.clone()), "{name}");
    }
    let noaki = leaf("inter-noaki-gost2015-sign");
    assert!(ext::<AuthorityKeyIdentifier>(&noaki).is_none());
    assert_eq!(
        noaki.tbs_certificate().issuer(),
        twin.tbs_certificate().subject()
    );
    cert::verify_signature(&noaki, &inter).unwrap();
    assert!(cert::verify_signature(&noaki, &twin).is_err());
}

#[test]
fn ocsp_responders_differ_only_in_nocheck() {
    let with = leaf("ocsp-gost2015");
    let without = leaf("ocsp-nocheckless-gost2015");
    assert_eq!(
        with.tbs_certificate().subject(),
        without.tbs_certificate().subject()
    );
    assert_eq!(
        with.tbs_certificate().issuer(),
        without.tbs_certificate().issuer()
    );
    assert_eq!(
        with.tbs_certificate().issuer(),
        parse(&synthetic_cert("inter-gost2015"))
            .tbs_certificate()
            .subject()
    );
    for (name, cert, nocheck) in [
        ("ocsp-gost2015", &with, true),
        ("ocsp-nocheckless-gost2015", &without, false),
    ] {
        let (critical, ku) = ext::<KeyUsage>(cert).unwrap();
        assert!(critical, "{name}");
        assert_eq!(ku, KeyUsage(KeyUsages::DigitalSignature.into()), "{name}");
        let (_, eku) = ext::<ExtendedKeyUsage>(cert).unwrap();
        let eku: Vec<String> = eku.0.iter().map(ToString::to_string).collect();
        assert_eq!(eku, [EKU_OCSP_SIGNING], "{name}");
        let found = cert
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.extn_id.to_string() == ID_PKIX_OCSP_NOCHECK);
        match found {
            Some(e) => {
                assert!(nocheck, "{name} has id-pkix-ocsp-nocheck");
                assert!(!e.critical, "{name}");
                assert_eq!(e.extn_value.as_bytes(), [0x05, 0x00], "{name}");
            }
            None => assert!(!nocheck, "{name} lacks id-pkix-ocsp-nocheck"),
        }
        assert!(ext::<AuthorityInfoAccessSyntax>(cert).is_none(), "{name}");
        assert!(ext::<CrlDistributionPoints>(cert).is_none(), "{name}");
    }
}

/// The certificate of the only entry of the synthetic container `name`.
fn leaf(name: &str) -> Certificate {
    let f = synthetic(name);
    let mut entries = pkcs12::load(&read(&f.path), &f.password).unwrap();
    assert_eq!(entries.len(), 1, "{name}");
    entries.remove(0).cert
}

fn parse(der: &[u8]) -> Certificate {
    cert::parse(der).unwrap()
}

fn der(cert: &Certificate) -> Vec<u8> {
    der::Encode::to_der(cert).unwrap()
}

/// Criticality and decoded value of the extension `T` of `cert`, if present.
fn ext<'a, T>(cert: &'a Certificate) -> Option<(bool, T)>
where
    T: Decode<'a> + der::oid::AssociatedOid,
    <T as Decode<'a>>::Error: std::fmt::Debug,
{
    cert.tbs_certificate()
        .get_extension::<T>()
        .expect("decodable extension")
}

/// URIs of the CRLDistributionPoints `fullName`s of `cert`.
fn crl_urls(cert: &Certificate) -> Vec<String> {
    let (critical, cdp) = ext::<CrlDistributionPoints>(cert).expect("CRLDistributionPoints");
    assert!(!critical);
    cdp.0
        .iter()
        .flat_map(|dp| match &dp.distribution_point {
            Some(DistributionPointName::FullName(names)) => names.clone(),
            other => panic!("unexpected distributionPoint {other:?}"),
        })
        .map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => uri.to_string(),
            other => panic!("unexpected CRL location {other:?}"),
        })
        .collect()
}

fn uri(url: &str) -> GeneralName {
    GeneralName::UniformResourceIdentifier(Ia5String::new(url).unwrap())
}
