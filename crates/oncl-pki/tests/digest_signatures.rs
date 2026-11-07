//! F02 behavioral contract for digest signing (`DigestSigner`, `HashState`); these tests
//! use synthetic keys only, never user keys.

use oncl_pki::digest::{DigestValue, HashState};
use oncl_pki::key::{DigestSigner, HashAlg, KeyError, PrivateKey, PublicKey, SigAlg};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_testkit::{read, synthetic};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;

const MESSAGE: &[u8] = b"F02: prehashed means exactly one document hash";

fn entry(name: &str) -> KeyEntry {
    let fixture = synthetic(name);
    load(&read(fixture.path), &fixture.password)
        .unwrap()
        .remove(0)
}

fn digest(alg: HashAlg, message: &[u8]) -> DigestValue {
    let mut state = HashState::new(alg);
    state.update(message);
    state.finish()
}

#[test]
fn software_prehash_signatures_verify_without_double_hashing() {
    // Break caught: passing digest bytes to a message-signing API, or changing GOST encoding.
    for (name, alg) in [
        ("user-gost2004-sign", SigAlg::Gost2004),
        ("user-gost2015-sign", SigAlg::Gost2015_512),
        ("user-rsa-sign", SigAlg::RsaSha256),
    ] {
        let mut key = entry(name);
        let hash = digest(alg.hash_alg(), MESSAGE);
        assert_eq!(DigestSigner::algorithm(&key), alg);
        let signature = DigestSigner::sign_digest(&mut key, &hash).unwrap();
        key.key
            .public_key()
            .verify(alg, MESSAGE, &signature)
            .unwrap();
        key.key
            .public_key()
            .verify_digest(alg, &hash, &signature)
            .unwrap();
        assert_eq!(
            key.key.public_key().verify_digest(
                alg,
                &digest(alg.hash_alg(), b"other document"),
                &signature
            ),
            Err(KeyError::BadSignature),
            "{name}",
        );
    }
}

#[test]
fn rsa_pkcs1v15_signature_bytes_match_independent_legacy_ring_path() {
    // Break caught: PSS, double hashing, byte reversal or changing the legacy v1.5 signature.
    // ring is an independent message-sign oracle, not another route through PrivateKey::sign.
    let key = entry("user-rsa-sign");
    let pkcs8 = key.key.to_pkcs8_der().unwrap(); // existing synthetic-fixture export only
    let legacy = ring::rsa::KeyPair::from_pkcs8(&pkcs8).unwrap();
    let mut expected = vec![0; legacy.public().modulus_len()];
    legacy
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            MESSAGE,
            &mut expected,
        )
        .unwrap();
    let actual = key
        .key
        .sign_digest(SigAlg::RsaSha256, &digest(HashAlg::Sha256, MESSAGE))
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(key.key.sign(SigAlg::RsaSha256, MESSAGE).unwrap(), expected);
}

#[test]
fn digest_import_validates_every_algorithm_length_before_crypto() {
    // Break caught: unchecked/truncated foreign digests entering a native prehash API.
    for (alg, length) in [
        (HashAlg::Sha1, 20),
        (HashAlg::Sha256, 32),
        (HashAlg::Sha512, 64),
        (HashAlg::Gost34311, 32),
        (HashAlg::Streebog256, 32),
        (HashAlg::Streebog512, 64),
    ] {
        let bytes = vec![0xA5; length];
        let imported = DigestValue::from_bytes(alg, &bytes).unwrap();
        assert_eq!(imported.algorithm(), alg);
        assert_eq!(imported.as_bytes(), bytes);
        for bad_length in [0, length - 1, length + 1, 65] {
            assert!(
                DigestValue::from_bytes(alg, &vec![0xA5; bad_length]).is_err(),
                "{alg:?}/{bad_length}"
            );
        }
    }
}

#[test]
fn same_length_wrong_digest_algorithm_is_not_accepted() {
    // Break caught: validating only digest length instead of the digest algorithm tag.
    let key = entry("user-rsa-sign");
    let wrong = digest(HashAlg::Gost34311, MESSAGE); // also 32 bytes
    assert_eq!(
        key.key.sign_digest(SigAlg::RsaSha256, &wrong),
        Err(KeyError::UnsupportedAlgorithm)
    );
    let signature = key.key.sign(SigAlg::RsaSha256, MESSAGE).unwrap();
    assert_eq!(
        key.key
            .public_key()
            .verify_digest(SigAlg::RsaSha256, &wrong, &signature),
        Err(KeyError::UnsupportedAlgorithm)
    );
    let gost = entry("user-gost2004-sign");
    assert_eq!(
        gost.key
            .sign_digest(SigAlg::Gost2004, &digest(HashAlg::Sha256, MESSAGE)),
        Err(KeyError::UnsupportedAlgorithm)
    );
}

#[test]
fn mismatched_key_algorithm_and_malformed_signature_are_rejected() {
    // Break caught: using an issuer-selected algorithm without checking the actual leaf key.
    let key = entry("user-rsa-sign");
    let hash = digest(HashAlg::Gost34311, MESSAGE);
    assert_eq!(
        key.key.sign_digest(SigAlg::Gost2004, &hash),
        Err(KeyError::UnsupportedAlgorithm)
    );
    assert_eq!(
        key.key
            .public_key()
            .verify_digest(SigAlg::Gost2004, &hash, &[0; 64]),
        Err(KeyError::UnsupportedAlgorithm)
    );
    let hash = digest(HashAlg::Sha256, MESSAGE);
    for signature in [vec![], vec![0; 255], vec![0; 256], vec![0; 257]] {
        assert_eq!(
            key.key
                .public_key()
                .verify_digest(SigAlg::RsaSha256, &hash, &signature),
            Err(KeyError::BadSignature)
        );
    }
}

#[test]
fn rsa_sha1_remains_verify_only_for_prehash_operations() {
    // Break caught: adding RSA-SHA1 signing through the new prehash entry point.
    let key = entry("user-rsa-sign");
    assert_eq!(
        key.key
            .sign_digest(SigAlg::RsaSha1, &digest(HashAlg::Sha1, MESSAGE)),
        Err(KeyError::UnsupportedAlgorithm)
    );
    assert_eq!(
        key.key.sign(SigAlg::RsaSha1, MESSAGE),
        Err(KeyError::UnsupportedAlgorithm)
    );
    // Independent synthetic-fixture oracle, identical to the existing token-key test
    // technique. This does not enable any application/private RSA-SHA1 signing API.
    let raw = rsa::RsaPrivateKey::from_pkcs8_der(&key.key.to_pkcs8_der().unwrap()).unwrap();
    let hash = digest(HashAlg::Sha1, MESSAGE);
    let encoded = oncl_pki::key::digest_info(SigAlg::RsaSha1, hash.as_bytes()).unwrap();
    let signature = raw
        .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &encoded)
        .unwrap();
    key.key
        .public_key()
        .verify(SigAlg::RsaSha1, MESSAGE, &signature)
        .unwrap();
    key.key
        .public_key()
        .verify_digest(SigAlg::RsaSha1, &hash, &signature)
        .unwrap();
    assert_eq!(
        key.key.public_key().verify_digest(
            SigAlg::RsaSha1,
            &digest(HashAlg::Sha1, b"wrong"),
            &signature
        ),
        Err(KeyError::BadSignature)
    );
}

// Deliberately deterministic TEST-ONLY OAEP seed; never used by a production private op.
struct Seed(u8);
impl rsa::rand_core::RngCore for Seed {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }
    fn next_u64(&mut self) -> u64 {
        let mut out = [0; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rsa::rand_core::CryptoRng for Seed {}

#[test]
fn rsa_oaep_sha256_decrypts_public_oracle_and_binds_label() {
    // Break caught: OAEP-SHA1/MGF1-SHA1 defaults, wrong label, or private raw-RSA fallback.
    let key = entry("user-rsa-sign");
    let PublicKey::Rsa(der) = key.key.public_key() else {
        panic!("RSA fixture")
    };
    let public = rsa::RsaPublicKey::from_pkcs1_der(&der).unwrap();
    let plaintext = b"synthetic CEK: 0123456789abcdef";
    let ciphertext = public
        .encrypt(
            &mut Seed(1),
            rsa::Oaep::new_with_label::<rsa::sha2::Sha256, _>("F02-envelope"),
            plaintext,
        )
        .unwrap();
    assert_eq!(
        key.key
            .decrypt_oaep_sha256(&ciphertext, b"F02-envelope")
            .unwrap(),
        plaintext
    );
    assert!(
        key.key
            .decrypt_oaep_sha256(&ciphertext, b"other-envelope")
            .is_err()
    );
    let mut corrupt = ciphertext.clone();
    corrupt[7] ^= 0x80;
    assert!(
        key.key
            .decrypt_oaep_sha256(&corrupt, b"F02-envelope")
            .is_err()
    );
    assert!(
        key.key
            .decrypt_oaep_sha256(&ciphertext[..ciphertext.len() - 1], b"F02-envelope")
            .is_err()
    );
    let empty_label = public
        .encrypt(
            &mut Seed(32),
            rsa::Oaep::new::<rsa::sha2::Sha256>(),
            plaintext,
        )
        .unwrap();
    assert_eq!(
        key.key.decrypt_oaep_sha256(&empty_label, b"").unwrap(),
        plaintext
    );
    let gost: PrivateKey = entry("user-gost2004-sign").key;
    assert_eq!(
        gost.decrypt_oaep_sha256(&ciphertext, b"F02-envelope"),
        Err(KeyError::UnsupportedAlgorithm)
    );
}
