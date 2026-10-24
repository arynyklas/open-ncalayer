//! Certificate signature checks against the NCA CA certificates (GOST and RSA).

use oncl_pki::cert::{self, CertError, Certificate};
use oncl_pki::key::SigAlg;
use oncl_testkit::{fixture, read};
use std::path::PathBuf;
use x509_cert::der::{Decode, Encode};

fn nca_certificates() -> Vec<(PathBuf, Certificate)> {
    let mut certs = Vec::new();
    for dir in ["nca/prod", "nca/test"] {
        for entry in std::fs::read_dir(fixture(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "der") {
                let cert = cert::parse(&read(&path)).unwrap();
                certs.push((path, cert));
            }
        }
    }
    certs
}

fn issuer_of<'a>(certs: &'a [(PathBuf, Certificate)], cert: &Certificate) -> &'a Certificate {
    certs
        .iter()
        .map(|(_, c)| c)
        .find(|c| c.tbs_certificate().subject() == cert.tbs_certificate().issuer())
        .expect("issuer present")
}

#[test]
fn all_nca_certificates_verify_by_issuer() {
    let certs = nca_certificates();
    assert_eq!(certs.len(), 16);
    let mut algs = Vec::new();
    for (path, cert) in &certs {
        let issuer = issuer_of(&certs, cert);
        cert::verify_signature(cert, issuer).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        algs.push(SigAlg::from_signature_oid(&cert.signature_algorithm().oid).unwrap());
    }
    for alg in [SigAlg::Gost2004, SigAlg::Gost2015_512, SigAlg::RsaSha256] {
        assert!(algs.contains(&alg), "{alg:?} covered");
    }
}

#[test]
fn wrong_issuer_or_tampered_signature_is_rejected() {
    let certs = nca_certificates();
    let by_name = |name: &str| {
        &certs
            .iter()
            .find(|(p, _)| p.file_name().unwrap() == name)
            .unwrap()
            .1
    };
    let gost = by_name("ncagost22.der");
    let rsa = by_name("ncarsa22.der");

    // Same algorithm, different key: the GOST 2022 NCA certificate is not self-signed.
    assert!(matches!(
        cert::verify_signature(gost, gost),
        Err(CertError::BadSignature)
    ));
    assert!(matches!(
        cert::verify_signature(rsa, rsa),
        Err(CertError::BadSignature)
    ));
    // Algorithm of the signature does not fit the issuer key.
    assert!(cert::verify_signature(gost, issuer_of(&certs, rsa)).is_err());

    for cert in [gost, rsa] {
        let mut der = cert.to_der().unwrap();
        let last = der.len() - 1;
        der[last] ^= 0x01; // last byte of the signature value
        let tampered = Certificate::from_der(&der).unwrap();
        assert!(matches!(
            cert::verify_signature(&tampered, issuer_of(&certs, cert)),
            Err(CertError::BadSignature)
        ));
    }
}

#[test]
fn parse_accepts_ber_and_rejects_garbage() {
    let der = read(fixture("nca/prod/ncagost22.der"));
    // Same certificate with an indefinite outer length.
    let mut ber = vec![0x30, 0x80];
    let header = 2 + usize::from(der[1] & 0x7f);
    ber.extend(&der[header..]);
    ber.extend([0, 0]);
    assert_eq!(cert::parse(&ber).unwrap().to_der().unwrap(), der);
    assert!(cert::parse(b"garbage").is_err());
}
