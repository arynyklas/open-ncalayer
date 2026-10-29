//! Keys that sign on a hardware token: the signature is checked against the key's public
//! key before it is returned, the key never leaves the token, and CMS and XMLDSig sign with
//! it as with a software key.

use oncl_pki::cms::{self, SignOptions};
use oncl_pki::key::{
    KeyAlg, KeyError, PrivateKey, PublicKey, SigAlg, TokenKey, TokenSigner, digest_info,
};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::xmldsig;
use oncl_testkit::{read, synthetic};
use rsa::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::macros::datetime;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Right,
    SwapHalves,
    Fail,
}

/// A token stand-in: signs digests with a software key the way a card does.
struct FakeToken {
    entry: KeyEntry,
    public: PublicKey,
    mode: Mode,
    calls: AtomicUsize,
}

impl FakeToken {
    fn new(name: &str, mode: Mode) -> Arc<FakeToken> {
        let entry = entry(name);
        let public = entry.key.public_key();
        Arc::new(FakeToken {
            entry,
            public,
            mode,
            calls: AtomicUsize::new(0),
        })
    }
}

impl TokenSigner for FakeToken {
    fn alg(&self) -> KeyAlg {
        self.entry.key.alg()
    }

    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign_digest(&self, alg: SigAlg, digest: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.mode == Mode::Fail {
            return Err(KeyError::Token("the card refused".to_owned()));
        }
        let mut sig = match &self.entry.key {
            PrivateKey::Gost(k) => k.sign_digest(digest),
            PrivateKey::Rsa(_) => {
                let der = self.entry.key.to_pkcs8_der().unwrap();
                let key = rsa::RsaPrivateKey::from_pkcs8_der(&der).unwrap();
                key.sign(Pkcs1v15Sign::new_unprefixed(), &digest_info(alg, digest)?)
                    .unwrap()
            }
            PrivateKey::Token(_) => unreachable!("the fake wraps a software key"),
        };
        if self.mode == Mode::SwapHalves {
            let half = sig.len() / 2;
            sig.rotate_left(half);
        }
        Ok(sig)
    }

    fn describe(&self) -> String {
        "AKKaztokenStore in Fake Reader 0, fake".to_owned()
    }
}

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

fn token_entry(fake: &Arc<FakeToken>) -> KeyEntry {
    KeyEntry {
        alias: fake.entry.alias.clone(),
        key: PrivateKey::Token(TokenKey::new(fake.clone())),
        cert: fake.entry.cert.clone(),
    }
}

fn cert_public(entry: &KeyEntry) -> PublicKey {
    PublicKey::from_spki(entry.cert.tbs_certificate().subject_public_key_info()).unwrap()
}

#[test]
fn token_key_signs_like_software_gost2015() {
    let fake = FakeToken::new("user-gost2015-sign", Mode::Right);
    let token = token_entry(&fake);
    assert_eq!(token.key.alg(), KeyAlg::Gost2015_512);
    assert_eq!(token.key.public_key(), cert_public(&token));
    let sig = token.key.sign(SigAlg::Gost2015_512, b"message").unwrap();
    assert_eq!(sig.len(), 128);
    cert_public(&token)
        .verify(SigAlg::Gost2015_512, b"message", &sig)
        .unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn token_key_signs_like_software_rsa() {
    let fake = FakeToken::new("user-rsa-sign", Mode::Right);
    let token = token_entry(&fake);
    let sig = token.key.sign(SigAlg::RsaSha256, b"message").unwrap();
    let software = fake.entry.key.sign(SigAlg::RsaSha256, b"message").unwrap();
    assert_eq!(sig, software);
}

#[test]
fn swapped_halves_are_caught() {
    let fake = FakeToken::new("user-gost2015-sign", Mode::SwapHalves);
    let token = token_entry(&fake);
    match token.key.sign(SigAlg::Gost2015_512, b"message") {
        Err(KeyError::Token(msg)) => assert!(msg.contains("does not verify"), "{msg}"),
        other => panic!("expected a token error, got {other:?}"),
    }
}

#[test]
fn token_errors_pass_through() {
    let fake = FakeToken::new("user-gost2004-sign", Mode::Fail);
    let token = token_entry(&fake);
    assert_eq!(
        token.key.sign(SigAlg::Gost2004, b"message"),
        Err(KeyError::Token("the card refused".to_owned()))
    );
}

#[test]
fn token_key_refuses_wrong_alg_and_sha1() {
    let gost = FakeToken::new("user-gost2015-sign", Mode::Right);
    let key = PrivateKey::Token(TokenKey::new(gost.clone()));
    for alg in [SigAlg::Gost2004, SigAlg::RsaSha256, SigAlg::RsaSha1] {
        assert_eq!(key.sign(alg, b"m"), Err(KeyError::UnsupportedAlgorithm));
    }
    let rsa = FakeToken::new("user-rsa-sign", Mode::Right);
    let key = PrivateKey::Token(TokenKey::new(rsa.clone()));
    for alg in [SigAlg::RsaSha1, SigAlg::Gost2004, SigAlg::Gost2015_512] {
        assert_eq!(key.sign(alg, b"m"), Err(KeyError::UnsupportedAlgorithm));
    }
    assert_eq!(gost.calls.load(Ordering::SeqCst), 0);
    assert_eq!(rsa.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn token_key_is_not_exportable() {
    let fake = FakeToken::new("user-gost2015-sign", Mode::Right);
    let key = PrivateKey::Token(TokenKey::new(fake));
    assert_eq!(key.to_pkcs8_der().unwrap_err(), KeyError::NotExportable);
}

#[test]
fn cms_with_token_key_verifies() {
    for name in ["user-gost2015-sign", "user-gost2004-sign", "user-rsa-sign"] {
        let fake = FakeToken::new(name, Mode::Right);
        let token = token_entry(&fake);
        let opts = SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: datetime!(2026-03-01 10:20:30 UTC),
        };
        let signed = cms::sign(&token, b"data", &opts).unwrap();
        let signers = cms::verify(&signed, None).unwrap();
        assert_eq!(signers.len(), 1, "{name}");
        assert_eq!(signers[0].cert, token.cert, "{name}");
    }
}

#[test]
fn xml_with_token_key_verifies() {
    for name in ["user-gost2015-sign", "user-gost2004-sign", "user-rsa-sign"] {
        let fake = FakeToken::new(name, Mode::Right);
        let token = token_entry(&fake);
        let signed =
            xmldsig::sign_enveloped(b"<root><a>1</a></root>", &token.key, &token.cert).unwrap();
        let signers = xmldsig::verify(&signed).unwrap();
        assert_eq!(signers.len(), 1, "{name}");
        assert_eq!(signers[0].cert, token.cert, "{name}");
    }
}

#[test]
fn digest_info_sha256_layout() {
    let digest = [0xAB; 32];
    let di = digest_info(SigAlg::RsaSha256, &digest).unwrap();
    assert_eq!(di.len(), 51);
    assert_eq!(
        di[..19],
        [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20
        ]
    );
    assert_eq!(di[19..], digest);
    let sha1 = digest_info(SigAlg::RsaSha1, &[1; 20]).unwrap();
    assert_eq!(sha1.len(), 35);
    assert_eq!(
        digest_info(SigAlg::Gost2015_512, &[0; 64]),
        Err(KeyError::UnsupportedAlgorithm)
    );
    assert!(matches!(
        digest_info(SigAlg::RsaSha256, &[0; 20]),
        Err(KeyError::Malformed(_))
    ));
}

#[test]
fn debug_does_not_leak() {
    let fake = FakeToken::new("user-gost2015-sign", Mode::Right);
    let key = TokenKey::new(fake.clone());
    assert_eq!(format!("{key:?}"), fake.describe());
}
