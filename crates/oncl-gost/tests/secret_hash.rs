//! Tests-first gate for additive secret-input variants, not a CT/cleanup claim.
//!
//! Primary sources:
//! - RFC 6986 §§4.2, 10.1, 10.2: complete Streebog bit-vector examples.
//!   https://www.rfc-editor.org/rfc/rfc6986#section-10
//! - RFC 7836 Appendix B examples 1/2: complete HMAC byte-vector examples.
//!   https://www.rfc-editor.org/rfc/rfc7836#appendix-B
//!
//! The secret types (`HmacSecret`, `Streebog256Secret`, `Streebog512Secret`) come from
//! the workspace's modified `hmac`/`streebog` copies under `vendor/` (feature
//! `secret-input`); crates.io's releases do not have them. The imports must stay the real
//! types: never replace them with ordinary ones to make this target compile.

use hmac::{HmacSecret, KeyInit, Mac};
use streebog::{Digest, Streebog256, Streebog256Secret, Streebog512, Streebog512Secret};

fn hex(literal: &str) -> Vec<u8> {
    assert_eq!(literal.len() % 2, 0, "hex fixture must contain whole bytes");
    literal
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// The RFC prints a bit vector with the highest-numbered component on the
// left; RustCrypto consumes/returns byte strings in the opposite byte order.
// Reverse each COMPLETE decoded RFC message/digest once, never each block or
// word. This conversion does not call the implementation under test.
fn rfc6986_bytes(literal: &str) -> Vec<u8> {
    let mut bytes = hex(literal);
    bytes.reverse();
    bytes
}

const M1: &str = concat!(
    "32313039383736353433323130393837",
    "36353433323130393837363534333231",
    "30393837363534333231303938373635",
    "343332313039383736353433323130"
);
const M2: &str = concat!(
    "fbe2e5f0eee3c820fbeafaebef20fffb",
    "f0e1e0f0f520e0ed20e8ece0ebe5f0f2",
    "f120fff0eeec20f120faf2fee5e2202c",
    "e8f6f3ede220e8e6eee1e8f0f2d1202c",
    "e8f0f2e5e220e5d1"
);
const H256_M1: &str = concat!(
    "00557be5e584fd52a449b16b0251d05d",
    "27f94ab76cbaa6da890b59d8ef1e159d"
);
const H256_M2: &str = concat!(
    "508f7e553c06501d749a66fc28c6cac0",
    "b005746d97537fa85d9e40904efed29d"
);
const H512_M1: &str = concat!(
    "486f64c1917879417fef082b3381a4e2",
    "11c324f074654c38823a7b76f830ad00",
    "fa1fbae42b1285c0352f227524bc9ab1",
    "6254288dd6863dccd5b9f54a1ad0541b"
);
const H512_M2: &str = concat!(
    "28fbc9bada033b1460642bdcddb90c3f",
    "b3e56c497ccd0f62b8a2ad4935e85f03",
    "7613966de4ee00531ae60f3b5a47f8da",
    "e06915d5f2f194996fcabf2622e6881e"
);

fn published_digest<D: Digest + Clone>(message: &str, digest: &str, length: usize) {
    let input = rfc6986_bytes(message);
    let expected = rfc6986_bytes(digest);
    assert_eq!(input.len(), length, "published message length");
    let actual = D::digest(&input);
    assert_eq!(
        &actual[..],
        expected.as_slice(),
        "one-shot published digest"
    );
    // M1 is 63 bytes; M2 is 72 bytes and actually crosses the block boundary.
    // These detect dropped/reordered tails and full-block padding mistakes.
    for chunk_size in [1, 7, 31, 63, 64, 65] {
        let mut state = D::new();
        for chunk in input.chunks(chunk_size) {
            Digest::update(&mut state, chunk);
        }
        let actual = state.finalize();
        assert_eq!(&actual[..], expected.as_slice(), "chunk size {chunk_size}");
    }
    // Required EagerHash Clone must copy retained state AND a partial buffer
    // into a fresh live owner. Both copies use the independent RFC oracle.
    for split in [1, 63, 64, 65] {
        let split = split.min(input.len());
        let mut original = D::new();
        Digest::update(&mut original, &input[..split]);
        let mut cloned = original.clone();
        Digest::update(&mut original, &input[split..]);
        Digest::update(&mut cloned, &input[split..]);
        assert_eq!(
            &original.finalize()[..],
            expected.as_slice(),
            "original split {split}"
        );
        assert_eq!(
            &cloned.finalize()[..],
            expected.as_slice(),
            "clone split {split}"
        );
    }
}

#[test]
fn secret_streebog256_rfc6986_examples() {
    // Catches wrong IV, truncation side, LPS selection or partial-block state.
    published_digest::<Streebog256Secret>(M1, H256_M1, 63);
    published_digest::<Streebog256Secret>(M2, H256_M2, 72);
}

#[test]
fn secret_streebog512_rfc6986_examples() {
    // Catches wrong LPS/compression/state transition on the real multi-block M2.
    published_digest::<Streebog512Secret>(M1, H512_M1, 63);
    published_digest::<Streebog512Secret>(M2, H512_M2, 72);
}

#[test]
fn ordinary_hash_outputs_remain_the_published_values() {
    // Each expectation is primary-source literal bytes, never secret==ordinary.
    // Functional output compatibility is NOT proof that the fast path stayed fast.
    published_digest::<Streebog256>(M1, H256_M1, 63);
    published_digest::<Streebog256>(M2, H256_M2, 72);
    published_digest::<Streebog512>(M1, H512_M1, 63);
    published_digest::<Streebog512>(M2, H512_M2, 72);
}

const HMAC_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
// RFC 7836 prints bytes directly: DO NOT reverse these or the expected MACs.
// The same message is the exact B9 KDF encoding for label 26bdb878,
// seed af21434145656378 and L=256; this tests HMAC, not a new public KDF API.
const HMAC_MESSAGE: &str = "0126bdb87800af214341456563780100";
const HMAC256: &str = concat!(
    "a1aa5f7de402d7b3d323f2991c8d4534",
    "013137010a83754fd0af6d7cd4922ed9"
);
const HMAC512: &str = concat!(
    "a59bab22ecae19c65fbde6e5f4e9f5d8",
    "549d31f037f9df9b905500e171923a77",
    "3d5f1530f2ed7e964cb2eedc29e9ad2f",
    "3afe93b2814f79f5000ffc0366c251e6"
);

#[test]
fn secret_hmac256_rfc7836_example_1() {
    // Catches swapped pads, wrong hash variant, lost partial buffer or wrong
    // inner-digest handling; the expected bytes are independent of our code.
    let key = hex(HMAC_KEY);
    let message = hex(HMAC_MESSAGE);
    let expected = hex(HMAC256);
    assert_eq!(key.len(), 32);
    assert_eq!(message.len(), 16);
    for chunk_size in [1, 7, 15, 16, 17] {
        let mut mac = <HmacSecret<Streebog256Secret> as KeyInit>::new_from_slice(&key).unwrap();
        for chunk in message.chunks(chunk_size) {
            Mac::update(&mut mac, chunk);
        }
        let actual = mac.finalize().into_bytes();
        assert_eq!(&actual[..], expected.as_slice(), "chunk size {chunk_size}");
    }
}

#[test]
fn secret_hmac512_rfc7836_example_2() {
    // All 64 expected bytes are asserted, not a digest prefix or truncated256.
    let key = hex(HMAC_KEY);
    let message = hex(HMAC_MESSAGE);
    let expected = hex(HMAC512);
    assert_eq!(key.len(), 32);
    assert_eq!(message.len(), 16);
    for chunk_size in [1, 7, 15, 16, 17] {
        let mut mac = <HmacSecret<Streebog512Secret> as KeyInit>::new_from_slice(&key).unwrap();
        for chunk in message.chunks(chunk_size) {
            Mac::update(&mut mac, chunk);
        }
        let actual = mac.finalize().into_bytes();
        assert_eq!(&actual[..], expected.as_slice(), "chunk size {chunk_size}");
    }
}
