//! What an emulated card computes: signatures with the software key, its public key in the
//! card's byte orders, compressed certificates, and the PIN counter.

use oncl_pki::key::PrivateKey;
use oncl_pki::pkcs12::KeyEntry;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

fn gost_key(entry: &KeyEntry) -> &oncl_gost::SigningKey {
    match &entry.key {
        PrivateKey::Gost(key) => key,
        _ => panic!("{} is not a software GOST key", entry.alias),
    }
}

fn rsa_key(entry: &KeyEntry) -> RsaPrivateKey {
    let der = entry
        .key
        .to_pkcs8_der()
        .unwrap_or_else(|e| panic!("{} is not a software key: {e}", entry.alias));
    RsaPrivateKey::from_pkcs8_der(&der).expect("an RSA PKCS#8 key")
}

/// GOST signature `r_LE ‖ s_LE` of `digest`, with the nonce `fixed_k` (big-endian) when
/// given.
///
/// # Panics
///
/// For a key that is not a software GOST key, or a `fixed_k` out of range.
pub fn gost_sign(entry: &KeyEntry, digest: &[u8], fixed_k: Option<&[u8]>) -> Vec<u8> {
    let key = gost_key(entry);
    match fixed_k {
        Some(k) => key
            .sign_digest_with_k(digest, k)
            .expect("the fixed nonce is a valid scalar"),
        None => key.sign_digest(digest),
    }
}

/// PKCS#1 v1.5 signature (big-endian) of a DER `DigestInfo`: the card pads.
///
/// # Panics
///
/// For a key that is not a software RSA key.
pub fn rsa_sign_digest_info(entry: &KeyEntry, digest_info: &[u8]) -> Vec<u8> {
    rsa_key(entry)
        .sign(Pkcs1v15Sign::new_unprefixed(), digest_info)
        .expect("the DigestInfo fits the modulus")
}

/// Private RSA operation on a PKCS#1 type 1 block the driver padded: the block must be
/// `00 01 FF…FF 00 DigestInfo`, exactly the modulus long, with at least 8 bytes `FF`;
/// else the card answers `6A80`.
///
/// # Errors
///
/// `0x6A80` for any other block.
///
/// # Panics
///
/// For a key that is not a software RSA key.
pub fn rsa_sign_block(entry: &KeyEntry, block: &[u8]) -> Result<Vec<u8>, u16> {
    let key = rsa_key(entry);
    if block.len() != key.size() || !block.starts_with(&[0x00, 0x01]) {
        return Err(0x6A80);
    }
    let padding = block[2..].iter().take_while(|&&b| b == 0xFF).count();
    let rest = &block[2 + padding..];
    if padding < 8 || rest.first() != Some(&0x00) || rest.len() < 2 {
        return Err(0x6A80);
    }
    key.sign(Pkcs1v15Sign::new_unprefixed(), &rest[1..])
        .map_err(|_| 0x6A80)
}

/// Public key of a GOST key: `X_LE ‖ Y_LE`.
///
/// # Panics
///
/// For a key that is not a software GOST key.
pub fn gost_point_le(entry: &KeyEntry) -> Vec<u8> {
    gost_key(entry).verifying_key().to_kz_bytes()
}

/// Modulus of an RSA key, big-endian.
///
/// # Panics
///
/// For a key that is not a software RSA key.
pub fn rsa_modulus_be(entry: &KeyEntry) -> Vec<u8> {
    rsa_key(entry).n().to_bytes_be()
}

/// Gzip of a certificate, as most tokens store it.
pub fn gzip(cert: &[u8]) -> Vec<u8> {
    crate::gzip::compress(cert)
}

/// Swaps the halves of a signature (the emulator's broken-card test mode).
pub fn swap_halves(sig: &mut [u8]) {
    let half = sig.len() / 2;
    sig.rotate_left(half);
}

/// Result of a PIN verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinCheck {
    /// The PIN is right.
    Ok,
    /// The PIN is wrong: tries left (at least one).
    Wrong(u8),
    /// The PIN is blocked (now or already).
    Blocked,
}

/// A card's PIN and its counter: a wrong PIN takes a try, none left blocks the PIN, a right
/// PIN restores all tries; a reset ends the verification.
#[derive(Clone, Debug)]
pub struct PinState {
    pin: Vec<u8>,
    tries: u8,
    max_tries: u8,
    verified: bool,
}

impl PinState {
    /// `pin` with `tries` left of `max_tries`.
    pub fn new(pin: &str, tries: u8, max_tries: u8) -> PinState {
        PinState {
            pin: pin.as_bytes().to_vec(),
            tries,
            max_tries,
            verified: false,
        }
    }

    /// Checks `pin`.
    pub fn verify(&mut self, pin: &[u8]) -> PinCheck {
        if self.tries == 0 {
            self.verified = false;
            return PinCheck::Blocked;
        }
        if pin == self.pin {
            self.tries = self.max_tries;
            self.verified = true;
            return PinCheck::Ok;
        }
        self.verified = false;
        self.tries -= 1;
        match self.tries {
            0 => PinCheck::Blocked,
            n => PinCheck::Wrong(n),
        }
    }

    /// Tries left.
    pub fn tries(&self) -> u8 {
        self.tries
    }

    /// No tries left.
    pub fn is_blocked(&self) -> bool {
        self.tries == 0
    }

    /// The PIN was verified since the last reset.
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Ends the verification.
    pub fn reset(&mut self) {
        self.verified = false;
    }
}
