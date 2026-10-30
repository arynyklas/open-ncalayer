//! JKS files: keytool-made RSA stores (`fixtures/jks/`) and GOST stores built here by the
//! format of Kalkan's `JavaKeyStore` and `KeyProtector`, which keytool cannot write.

use der::Encode;
use oncl_pki::jks::{JksEntryKind, JksError, entries, is_jks, load};
use oncl_pki::key::{KeyAlg, SigAlg};
use oncl_pki::pkcs12::{self, KeyEntry};
use oncl_testkit::{fixture, read, synthetic};
use sha1::{Digest, Sha1};

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    pkcs12::load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

fn sign_verifies(e: &KeyEntry, alg: SigAlg) {
    let sig = e.key.sign(alg, b"message").unwrap();
    let public =
        oncl_pki::key::PublicKey::from_spki(e.cert.tbs_certificate().subject_public_key_info())
            .unwrap();
    public.verify(alg, b"message", &sig).unwrap();
}

#[test]
fn keytool_rsa_store() {
    let data = read(fixture("jks/rsa.jks"));
    assert!(is_jks(&data));
    let entries = load(&data, "Qwerty12").unwrap();
    // The trusted root entry is not a key.
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].alias, "openncalayer-rsa");
    assert_eq!(entries[0].key.alg(), KeyAlg::Rsa);
    sign_verifies(&entries[0], SigAlg::RsaSha256);

    assert_eq!(
        load(&data, "Qwerty13").unwrap_err(),
        JksError::WrongPassword
    );
    assert_eq!(load(&data, "").unwrap_err(), JksError::WrongPassword);
}

#[test]
fn keytool_store_with_a_cyrillic_password() {
    let data = read(fixture("jks/rsa-cyrillic.jks"));
    let entries = load(&data, "Пароль123").unwrap();
    assert_eq!(entries.len(), 1);
    sign_verifies(&entries[0], SigAlg::RsaSha256);
    assert_eq!(
        load(&data, "Qwerty12").unwrap_err(),
        JksError::WrongPassword
    );
}

#[test]
fn damaged_stores() {
    let data = read(fixture("jks/rsa.jks"));
    for cut in [0, 3, 12, 40, data.len() - 21, data.len() - 1] {
        assert!(
            matches!(load(&data[..cut], "Qwerty12"), Err(JksError::Malformed(_))),
            "cut at {cut}"
        );
    }
    // A flipped byte inside the entries fails the integrity digest (or the certificate).
    let mut flipped = data.clone();
    flipped[data.len() - 100] ^= 1;
    assert!(load(&flipped, "Qwerty12").is_err());
    // Not a JKS (a PKCS#12 file).
    let p12 = read(synthetic("user-rsa-sign").path);
    assert!(!is_jks(&p12));
    assert!(matches!(
        load(&p12, "Qwerty12"),
        Err(JksError::Malformed(_))
    ));
    // An entry count far beyond the data.
    let mut huge = data[..8].to_vec();
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        load(&huge, "Qwerty12"),
        Err(JksError::Malformed(_))
    ));
}

/// `EncryptedPrivateKeyInfo`.
#[derive(der::Sequence)]
struct Epki {
    alg: spki::AlgorithmIdentifierOwned,
    data: der::asn1::OctetString,
}

/// A JKS of `entries` as Kalkan's `JavaKeyStore.engineStore` writes it (`version` 1 or 2),
/// keys protected as its `KeyProtector.protect` does (salt from `salt`).
fn build(version: u32, entries: &[(&str, &KeyEntry)], password: &str, salt: u8) -> Vec<u8> {
    let passwd: Vec<u8> = password.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let utf = |out: &mut Vec<u8>, s: &str| {
        out.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    };
    let mut out = Vec::new();
    out.extend_from_slice(&0xFEED_FEED_u32.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&u32::try_from(entries.len() + 1).unwrap().to_be_bytes());
    for (alias, e) in entries {
        out.extend_from_slice(&1u32.to_be_bytes());
        utf(&mut out, alias);
        out.extend_from_slice(&0u64.to_be_bytes());
        let plain = e.key.to_pkcs8_der().unwrap();
        let salt = [salt; 20];
        let mut protected = salt.to_vec();
        let mut block = salt.to_vec();
        for chunk in plain.chunks(20) {
            block = Sha1::new()
                .chain_update(&passwd)
                .chain_update(&block)
                .finalize()
                .to_vec();
            protected.extend(chunk.iter().zip(&block).map(|(p, k)| p ^ k));
        }
        protected.extend(
            Sha1::new()
                .chain_update(&passwd)
                .chain_update(&*plain)
                .finalize(),
        );
        let epki = Epki {
            alg: spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.42.2.17.1.1"),
                parameters: None,
            },
            data: der::asn1::OctetString::new(protected).unwrap(),
        }
        .to_der()
        .unwrap();
        out.extend_from_slice(&u32::try_from(epki.len()).unwrap().to_be_bytes());
        out.extend(epki);
        out.extend_from_slice(&1u32.to_be_bytes());
        cert(&mut out, version, &e.cert.to_der().unwrap());
    }
    // A trusted certificate entry.
    out.extend_from_slice(&2u32.to_be_bytes());
    utf(&mut out, "root");
    out.extend_from_slice(&0u64.to_be_bytes());
    cert(
        &mut out,
        version,
        &read(fixture("synthetic/root-gost2015.cer")),
    );
    let digest = Sha1::new()
        .chain_update(&passwd)
        .chain_update(b"Mighty Aphrodite")
        .chain_update(&out)
        .finalize();
    out.extend(digest);
    out
}

fn cert(out: &mut Vec<u8>, version: u32, der: &[u8]) {
    if version == 2 {
        out.extend_from_slice(&5u16.to_be_bytes());
        out.extend_from_slice(b"X.509");
    }
    out.extend_from_slice(&u32::try_from(der.len()).unwrap().to_be_bytes());
    out.extend_from_slice(der);
}

#[test]
fn gost_keys_in_both_versions() {
    let gost2015 = entry("user-gost2015-sign");
    let gost2004 = entry("user-gost2004-sign");
    for version in [1, 2] {
        let data = build(
            version,
            &[("b-2004", &gost2004), ("a-2015", &gost2015)],
            "Qwerty12",
            7,
        );
        let entries = load(&data, "Qwerty12").unwrap();
        let aliases: Vec<_> = entries.iter().map(|e| e.alias.as_str()).collect();
        assert_eq!(aliases, ["a-2015", "b-2004"], "sorted by alias");
        assert_eq!(entries[0].key.alg(), KeyAlg::Gost2015_512);
        assert_eq!(entries[1].key.alg(), KeyAlg::Gost2004);
        sign_verifies(&entries[0], SigAlg::Gost2015_512);
        sign_verifies(&entries[1], SigAlg::Gost2004);
        assert_eq!(entries[0].cert, gost2015.cert);
        assert_eq!(
            load(&data, "qwerty12").unwrap_err(),
            JksError::WrongPassword
        );
    }
}

#[test]
fn key_check_and_certificate_mismatch() {
    let gost = entry("user-gost2015-sign");
    let mut data = build(2, &[("k", &gost)], "Qwerty12", 1);
    // A key whose certificate is another key's: malformed.
    let other = KeyEntry {
        alias: "x".to_owned(),
        key: gost.key.clone(),
        cert: entry("user-gost2004-sign").cert,
    };
    let mismatched = build(2, &[("k", &other)], "Qwerty12", 1);
    assert!(matches!(
        load(&mismatched, "Qwerty12"),
        Err(JksError::Malformed(_))
    ));
    // A protected key byte changed and the digest fixed up: the key check fails.
    let digest_at = data.len() - 20;
    data[60] ^= 0x55;
    let passwd: Vec<u8> = "Qwerty12"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    let digest = Sha1::new()
        .chain_update(&passwd)
        .chain_update(b"Mighty Aphrodite")
        .chain_update(&data[..digest_at])
        .finalize();
    data[digest_at..].copy_from_slice(&digest);
    assert!(load(&data, "Qwerty12").is_err());
}

#[test]
fn entries_without_password() {
    let data = read(fixture("jks/rsa.jks"));
    let list = entries(&data).unwrap();
    assert_eq!(list.len(), 2);
    let key = list.iter().find(|e| e.alias == "openncalayer-rsa").unwrap();
    assert!(matches!(&key.kind, JksEntryKind::PrivateKey { chain } if chain.len() == 1));
    let root = list
        .iter()
        .find(|e| e.alias == "synthetic-root-rsa")
        .unwrap();
    let JksEntryKind::TrustedCert(c) = &root.kind else {
        panic!("{root:?}")
    };
    assert_eq!(c.to_der().unwrap(), read(fixture("synthetic/root-rsa.cer")));
}

#[test]
fn entries_rejects_truncated() {
    let data = read(fixture("jks/rsa.jks"));
    for len in [0, 4, 12, 40, data.len() / 2] {
        assert!(
            matches!(entries(&data[..len]), Err(JksError::Malformed(_))),
            "{len}"
        );
    }
}

#[test]
fn entries_ignore_password_digest() {
    let mut data = read(fixture("jks/rsa.jks"));
    let last = data.len() - 1;
    data[last] ^= 0xff;
    assert_eq!(entries(&data).unwrap().len(), 2);
    assert!(matches!(
        load(&data, "Qwerty12"),
        Err(JksError::WrongPassword)
    ));
}
