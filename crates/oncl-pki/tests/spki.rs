//! `PublicKey::to_spki` against Kalkan-made `SubjectPublicKeyInfo`s: the legacy Applet's key
//! identifier ([`applet_key_id`], SHA-1 of the whole DER SPKI) is only Kalkan's if our
//! encoding of a key is byte for byte the one in NCA-issued certificates.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::{Decode, Encode};
use oncl_gost::CurveId;
use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};
use oncl_pki::keygen::applet_key_id;
use oncl_pki::pkcs12::{load, load_contents};
use oncl_testkit::{fixture, ncanode, read};
use sha1::{Digest, Sha1};
use std::collections::BTreeSet;
use x509_cert::Certificate;

fn key_alg(key: &PublicKey) -> KeyAlg {
    match key {
        PublicKey::Gost(key) => match key.curve() {
            CurveId::Pkigovkz2004A => KeyAlg::Gost2004,
            CurveId::Tc26_512A => KeyAlg::Gost2015_512,
        },
        PublicKey::Rsa(_) => KeyAlg::Rsa,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes the strict-DER certificate `der`, checks that its SPKI survives
/// `from_spki` → `to_spki` unchanged (and is the certificate's own bytes) and returns the
/// key type.
fn assert_round_trip(name: &str, der: &[u8]) -> KeyAlg {
    let cert = Certificate::from_der(der).unwrap_or_else(|e| panic!("{name}: not DER: {e}"));
    let spki = cert.tbs_certificate().subject_public_key_info();
    let original = spki.to_der().unwrap();
    assert!(
        der.windows(original.len()).any(|w| w == original),
        "{name}: the SPKI re-encodes to the certificate's bytes"
    );
    let key = PublicKey::from_spki(spki).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
        hex(&key.to_spki().to_der().unwrap()),
        hex(&original),
        "{name}: to_spki encodes like Kalkan"
    );
    assert_eq!(applet_key_id(&key), hex(&Sha1::digest(&original)), "{name}");
    key_alg(&key)
}

/// The DER of a PEM certificate file.
fn pem_der(path: &std::path::Path) -> Vec<u8> {
    let text = String::from_utf8(read(path)).expect("PEM is text");
    let body = text
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END CERTIFICATE-----").next())
        .unwrap_or_else(|| panic!("{}: no PEM certificate", path.display()));
    let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(base64).expect("PEM base64")
}

/// Every NCA root and intermediate certificate committed to the repository.
#[test]
fn nca_certificates_round_trip() {
    let mut algs = BTreeSet::new();
    let mut count = 0;
    for dir in ["nca/prod", "nca/test"] {
        for entry in std::fs::read_dir(fixture(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "der") {
                algs.insert(format!(
                    "{:?}",
                    assert_round_trip(&path.display().to_string(), &read(&path))
                ));
                count += 1;
            }
        }
    }
    assert_eq!(count, 16, "all NCA certificates are checked");
    assert_eq!(
        algs.into_iter().collect::<Vec<_>>(),
        ["Gost2004", "Gost2015_512", "Rsa"]
    );
}

/// The NCANode test keys' certificates and their CA certificates (GOST 2015-512,
/// GOST 34.310-2004 and RSA), and the public keys we derive from their private keys.
#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn ncanode_certificates_round_trip() {
    let mut algs = BTreeSet::new();
    for name in [
        "ceo_valid_sign_2004_gost.cer",
        "individual_valid_sign_2004_rsa.cer",
    ] {
        algs.insert(format!(
            "{:?}",
            assert_round_trip(name, &pem_der(&ncanode(name)))
        ));
    }
    for (name, password) in [
        ("individual_valid_2015.p12", "Aa123456"),
        ("individual_valid_sign_2004.p12", "Qwerty12"),
        ("ceo_sign_revoked_2004.p12", "Qwerty12"),
    ] {
        let contents = load_contents(&read(ncanode(name)), password).unwrap();
        assert!(!contents.keys.is_empty(), "{name}");
        for key in &contents.keys {
            let cert = key.cert.as_ref().expect("NCANode keys have certificates");
            let der = cert.to_der().unwrap();
            let alg = assert_round_trip(&format!("{name}/{}", key.alias), &der);
            assert_eq!(key.key.alg(), alg, "{name}/{}", key.alias);
            assert_eq!(
                key.key.public_key().to_spki(),
                *cert.tbs_certificate().subject_public_key_info(),
                "{name}/{}: the key's own SPKI is the certificate's",
                key.alias
            );
            algs.insert(format!("{alg:?}"));
        }
        for (i, cert) in contents.other_certs.iter().enumerate() {
            assert_round_trip(&format!("{name}/other[{i}]"), &cert.to_der().unwrap());
        }
    }
    assert_eq!(
        algs.into_iter().collect::<Vec<_>>(),
        ["Gost2004", "Gost2015_512", "Rsa"]
    );
}

/// The NCANode GOST 34.310-2004 key loads as such and signs what its certificate verifies.
#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn ncanode_gost2004_key_signs() {
    let entries = load(&read(ncanode("ceo_sign_revoked_2004.p12")), "Qwerty12").unwrap();
    assert!(!entries.is_empty());
    for e in &entries {
        assert_eq!(e.key.alg(), KeyAlg::Gost2004, "{}", e.alias);
        let public = PublicKey::from_spki(e.cert.tbs_certificate().subject_public_key_info())
            .expect("certificate public key");
        let message = b"OpenNCALayer GOST 2004 key check";
        let sig = e.key.sign(SigAlg::Gost2004, message).expect("sign");
        public
            .verify(SigAlg::Gost2004, message, &sig)
            .unwrap_or_else(|err| panic!("{}: {err}", e.alias));
        assert!(public.verify(SigAlg::Gost2004, b"other", &sig).is_err());
    }
}
