//! PKCS#12 reading (Kalkan rules) against NCANode and OpenSSL containers, and the writer.

use oncl_pki::key::{KeyAlg, PublicKey, SigAlg};
use oncl_pki::oid;
use oncl_pki::pkcs12::{KeyEntry, MAX_ITERATIONS, Pkcs12Error, load};
use oncl_testkit::{fixture, ncanode, read};

/// Signs with the entry's key using the certificate's signature algorithm and verifies the
/// result with the certificate's public key.
fn assert_key_matches_cert(entry: &KeyEntry) {
    let alg = SigAlg::from_signature_oid(&entry.cert.signature_algorithm().oid)
        .expect("known certificate signature algorithm");
    assert_eq!(alg.key_alg(), entry.key.alg(), "{}", entry.alias);
    let public = PublicKey::from_spki(entry.cert.tbs_certificate().subject_public_key_info())
        .expect("certificate public key");
    let message = b"OpenNCALayer PKCS#12 key check";
    let sig = entry.key.sign(alg, message).expect("sign");
    public
        .verify(alg, message, &sig)
        .unwrap_or_else(|e| panic!("{}: {e}", entry.alias));
    assert!(public.verify(alg, b"another message", &sig).is_err());
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn ncanode_2015_p12() {
    let e = load(&read(ncanode("individual_valid_2015.p12")), "Aa123456").unwrap();
    assert!(
        e.iter()
            .any(|k| k.alias == "8ff06211dc82beb00253ffa000f1de84abef454f")
    );
    for k in &e {
        assert_key_matches_cert(k);
    }
    assert!(e.iter().any(|k| k.key.alg() == KeyAlg::Gost2015_512));
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn ncanode_2004_p12() {
    let e = load(&read(ncanode("individual_valid_sign_2004.p12")), "Qwerty12").unwrap();
    assert!(
        e.iter()
            .any(|k| k.alias == "e3fe35adda3b45cbea3a3f1ed48f263dc55c556e")
    );
    for k in &e {
        assert_key_matches_cert(k);
    }
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn wrong_password() {
    let p12 = read(ncanode("individual_valid_2015.p12"));
    assert!(matches!(
        load(&p12, "wrong"),
        Err(Pkcs12Error::WrongPassword)
    ));
    assert!(matches!(load(&p12, ""), Err(Pkcs12Error::WrongPassword)));
}

fn load_openssl(name: &str, password: &str) -> Vec<KeyEntry> {
    let entries = load(&read(fixture(&format!("openssl/{name}"))), password).unwrap();
    for e in &entries {
        assert_eq!(e.alias, "openssl-rsa");
        assert_eq!(e.key.alg(), KeyAlg::Rsa);
        assert_key_matches_cert(e);
    }
    entries
}

#[test]
fn openssl_cyrillic_password() {
    assert_eq!(load_openssl("rsa-cyrillic.p12", "Пароль123").len(), 1);
    let p12 = read(fixture("openssl/rsa-cyrillic.p12"));
    assert!(matches!(
        load(&p12, "Пароль124"),
        Err(Pkcs12Error::WrongPassword)
    ));
}

#[test]
fn openssl_empty_password_double_zero() {
    assert_eq!(load_openssl("rsa-empty.p12", "").len(), 1);
    let p12 = read(fixture("openssl/rsa-empty.p12"));
    assert!(matches!(load(&p12, "x"), Err(Pkcs12Error::WrongPassword)));
}

#[test]
fn openssl_pbes2_explicit_prf() {
    assert_eq!(load_openssl("rsa-modern.p12", "Qwerty12").len(), 1);
    let p12 = read(fixture("openssl/rsa-modern.p12"));
    assert!(matches!(
        load(&p12, "Qwerty13"),
        Err(Pkcs12Error::WrongPassword)
    ));
}

#[test]
fn garbage_is_malformed() {
    assert!(matches!(
        load(b"not a pkcs12 file", "x"),
        Err(Pkcs12Error::Malformed(_))
    ));
    let cert = read(fixture("openssl/rsa.cer"));
    assert!(matches!(load(&cert, "x"), Err(Pkcs12Error::Malformed(_))));
}

/// DER TLV with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid_tlv(oid: der::asn1::ObjectIdentifier) -> Vec<u8> {
    tlv(0x06, oid.as_bytes())
}

/// Unsigned INTEGER.
fn int(n: u32) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&n.to_be_bytes());
    let skip = bytes
        .windows(2)
        .take_while(|w| w[0] == 0 && w[1] < 0x80)
        .count();
    tlv(0x02, &bytes[skip..])
}

/// A PFX whose authenticated safe is `infos` (`ContentInfo`s), with `mac` as its `MacData`.
fn pfx(infos: &[&[u8]], mac: Option<&[u8]>) -> Vec<u8> {
    let auth_safe = seq(infos);
    let data = seq(&[&oid_tlv(oid::DATA), &tlv(0xa0, &tlv(0x04, &auth_safe))]);
    seq(&[&int(3), &data, mac.unwrap_or_default()])
}

/// A SHA-1 `MacData` with `iterations` and an all-zero MAC.
fn mac_data(iterations: u32) -> Vec<u8> {
    let digest_info = seq(&[
        &seq(&[&oid_tlv(oid::SHA1), &[0x05, 0x00]]),
        &tlv(0x04, &[0; 20]),
    ]);
    seq(&[&digest_info, &tlv(0x04, &[7; 8]), &int(iterations)])
}

/// An encryptedData `ContentInfo` encrypted with `alg` (a DER `AlgorithmIdentifier`).
fn encrypted_data(alg: &[u8]) -> Vec<u8> {
    let eci = seq(&[&oid_tlv(oid::DATA), alg, &tlv(0x80, &[0x55; 16])]);
    let encrypted = seq(&[&int(0), &eci]);
    seq(&[&oid_tlv(oid::ENCRYPTED_DATA), &tlv(0xa0, &encrypted)])
}

fn assert_too_many_iterations(r: Result<Vec<KeyEntry>, Pkcs12Error>, n: u32) {
    match r {
        Err(Pkcs12Error::Unsupported(e)) => {
            assert!(e.contains(&format!("iteration count {n}")), "{e}");
        }
        other => panic!("{n} iterations: {:?}", other.map(|e| e.len())),
    }
}

/// Hostile iteration counts are refused before the KDF runs: without the cap, 2³² − 1 rounds
/// of the MAC KDF, the PKCS#12 PBE or PBKDF2 would keep `load` busy for hours.
#[test]
fn iteration_counts_are_capped() {
    let salt = tlv(0x04, &[7; 8]);
    for n in [MAX_ITERATIONS + 1, u32::MAX] {
        assert_too_many_iterations(load(&pfx(&[], Some(&mac_data(n))), ""), n);

        let pbe = seq(&[&oid_tlv(oid::PBE_SHA_3DES), &seq(&[&salt, &int(n)])]);
        assert_too_many_iterations(load(&pfx(&[&encrypted_data(&pbe)], None), ""), n);

        let pbkdf2 = seq(&[
            &oid_tlv(oid::PBKDF2),
            &seq(&[
                &salt,
                &int(n),
                &seq(&[&oid_tlv(oid::HMAC_SHA256), &[0x05, 0x00]]),
            ]),
        ]);
        let aes = seq(&[&oid_tlv(oid::AES_256_CBC), &tlv(0x04, &[0; 16])]);
        let pbes2 = seq(&[&oid_tlv(oid::PBES2), &seq(&[&pbkdf2, &aes])]);
        assert_too_many_iterations(load(&pfx(&[&encrypted_data(&pbes2)], None), ""), n);
    }
    // The crafted header is otherwise readable: a small count gets as far as the MAC.
    assert!(matches!(
        load(&pfx(&[], Some(&mac_data(1))), "x"),
        Err(Pkcs12Error::WrongPassword)
    ));
}

#[cfg(feature = "write")]
mod write {
    use super::*;
    use oncl_pki::cert;
    use oncl_pki::pkcs12::{Pbe, WriteEntry, WriteOptions, write};
    use x509_cert::der::Encode;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    /// Deterministic stand-in for an RNG.
    fn counter() -> impl FnMut(&mut [u8]) {
        let mut n = 0u8;
        move |buf: &mut [u8]| {
            for b in buf {
                n = n.wrapping_add(37);
                *b = n;
            }
        }
    }

    /// DER of an OID: tag, length, contents.
    fn oid_der(oid: &str) -> Vec<u8> {
        x509_cert::der::asn1::ObjectIdentifier::new_unwrap(oid)
            .to_der()
            .unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn kalkan_profile_is_the_default() {
        let opts = WriteOptions::default();
        assert_eq!(opts.key, Pbe::TripleDes);
        assert_eq!(opts.certs, Pbe::Rc2_40);
        assert_eq!(opts.iterations, 1024);
    }

    #[test]
    fn write_read_roundtrip_all_pbes() {
        let pkcs8 = read(fixture("openssl/rsa.pk8.der"));
        let cert_der = read(fixture("openssl/rsa.cer"));
        let certificate = cert::parse(&cert_der).unwrap();
        let (_, ski) = certificate
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()
            .unwrap()
            .expect("make.sh certificate has a SKI");
        let ski = ski.0.as_bytes().to_vec();
        let mut local_key_id = oid_der("1.2.840.113549.1.9.21");
        local_key_id.extend([0x31, ski.len() as u8 + 2, 0x04, ski.len() as u8]);
        local_key_id.extend(&ski);
        let prf_oids = [oid_der("1.2.840.113549.2.7"), oid_der("1.2.840.113549.2.9")];
        let pbes2 = oid_der("1.2.840.113549.1.5.13");

        let entry = WriteEntry {
            alias: "Тест-alias".to_owned(),
            pkcs8_der: pkcs8,
            cert_der: cert_der.clone(),
        };
        for key in [Pbe::TripleDes, Pbe::Pbes2Aes256NoPrf] {
            for certs in [Pbe::Rc2_40, Pbe::TripleDes, Pbe::Pbes2Aes256NoPrf] {
                let opts = WriteOptions {
                    key,
                    certs,
                    iterations: 1024,
                };
                let label = format!("{key:?}/{certs:?}");
                let p12 = write(
                    std::slice::from_ref(&entry),
                    "Пароль123",
                    &opts,
                    &mut counter(),
                );
                assert_eq!(
                    p12,
                    write(
                        std::slice::from_ref(&entry),
                        "Пароль123",
                        &opts,
                        &mut counter()
                    ),
                    "{label}: output depends only on fill_random"
                );

                let loaded = load(&p12, "Пароль123").unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(loaded.len(), 1, "{label}");
                assert_eq!(loaded[0].alias, entry.alias, "{label}");
                assert_eq!(loaded[0].cert.to_der().unwrap(), cert_der, "{label}");
                assert_key_matches_cert(&loaded[0]);
                assert!(
                    matches!(load(&p12, "Пароль12"), Err(Pkcs12Error::WrongPassword)),
                    "{label}"
                );

                // The key bag attributes are in the clear: localKeyId carries the SKI.
                assert!(contains(&p12, &local_key_id), "{label}: localKeyId = SKI");
                let uses_pbes2 = key == Pbe::Pbes2Aes256NoPrf || certs == Pbe::Pbes2Aes256NoPrf;
                assert_eq!(contains(&p12, &pbes2), uses_pbes2, "{label}");
                for prf in &prf_oids {
                    assert!(!contains(&p12, prf), "{label}: no PRF OID written");
                }
            }
        }
    }

    #[test]
    fn empty_password_roundtrip() {
        let entry = WriteEntry {
            alias: "empty".to_owned(),
            pkcs8_der: read(fixture("openssl/rsa.pk8.der")),
            cert_der: read(fixture("openssl/rsa.cer")),
        };
        let p12 = write(&[entry], "", &WriteOptions::default(), &mut counter());
        let loaded = load(&p12, "").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_key_matches_cert(&loaded[0]);
    }
}
