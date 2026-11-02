//! CEK-only RFC 7836 §4.6 wrap: KDF, GOST28147 TC26-Z ECB and IMIT.
//! Not RFC4357 plain/CryptoPro wrap, nor a proven KZ CMS profile.

use crypto_bigint::CtEq;
use hmac::{HmacSecret, KeyInit, Mac};
use streebog::Streebog256Secret;
use zeroize::{Zeroize, Zeroizing};

/// Explicit wrap primitive identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapProfile {
    /// RFC7836 KDF wrap, fixed TC26-Z parameters, 32-byte content keys only.
    Rfc7836Tc26Z,
}

/// Structural error or authenticated-key recovery failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WrapError {
    /// RFC7836 seed must contain 8–16 bytes.
    #[error("invalid GOST wrap seed length")]
    InvalidSeedLength,
    /// CEK-only raw record must contain 44–52 bytes.
    #[error("invalid GOST wrapped key length")]
    InvalidWrappedLength,
    /// No tentative plaintext key is returned on this failure.
    #[error("GOST wrapped key authentication failed")]
    AuthenticationFailed,
}

/// Public raw wrapped record, without ASN.1 CMS framing.
pub struct WrappedCek {
    bytes: [u8; 52],
    len: usize,
}
impl WrappedCek {
    /// Complete seed || CEK_ENC || CEK_MAC bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Zeroizing recovered content key; no Debug, Clone or serialization.
pub struct SecretCek(Box<Zeroizing<[u8; 32]>>);
impl core::ops::Deref for SecretCek {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wrap one 32-byte content key using an explicitly supplied random seed.
/// Caller owns generation/freshness and must propagate RNG failures; this
/// deterministic primitive never substitutes a fixed/generated seed.
///
/// # Errors
/// Returns InvalidSeedLength unless seed length is 8–16 bytes.
pub fn wrap_cek(
    profile: WrapProfile,
    export_key: &[u8; 32],
    cek: &[u8; 32],
    seed: &[u8],
) -> Result<WrappedCek, WrapError> {
    let WrapProfile::Rfc7836Tc26Z = profile;
    if !(8..=16).contains(&seed.len()) {
        return Err(WrapError::InvalidSeedLength);
    }
    let mut cipher = Gost28147::zeroed_owner();
    kdf_into(export_key, seed, &mut cipher.key_bytes);
    cipher.expand_key_in_place();
    let mut result = WrappedCek {
        bytes: [0; 52],
        len: seed.len() + 36,
    };
    result.bytes[..seed.len()].copy_from_slice(seed);
    for (input, output) in cek.as_chunks::<8>().0.iter().zip(
        result.bytes[seed.len()..seed.len() + 32]
            .as_chunks_mut::<8>()
            .0,
    ) {
        cipher.block(input, output, false);
    }
    cipher.mac(&seed[..8], cek);
    result.bytes[seed.len() + 32..result.len].copy_from_slice(&cipher.tag[..]);
    Ok(result)
}

/// Recover a CEK only after the complete four-byte MAC has been checked.
/// The standard has a 32-bit forgery bound; it does not authenticate content
/// or establish sender identity.
///
/// # Errors
/// Rejects a malformed record or authentication failure (including changed
/// seed/ciphertext/MAC or export key), without exposing tentative plaintext.
pub fn unwrap_cek(
    profile: WrapProfile,
    export_key: &[u8; 32],
    wrapped: &[u8],
) -> Result<SecretCek, WrapError> {
    let WrapProfile::Rfc7836Tc26Z = profile;
    if !(44..=52).contains(&wrapped.len()) {
        return Err(WrapError::InvalidWrappedLength);
    }
    let seed_len = wrapped.len() - 36;
    let seed = &wrapped[..seed_len];
    let mut cek = SecretCek(Box::new(Zeroizing::new([0; 32])));
    let mut cipher = Gost28147::zeroed_owner();
    kdf_into(export_key, seed, &mut cipher.key_bytes);
    cipher.expand_key_in_place();
    for (input, output) in wrapped[seed_len..seed_len + 32]
        .as_chunks::<8>()
        .0
        .iter()
        .zip(cek.0.as_chunks_mut::<8>().0)
    {
        cipher.block(input, output, true);
    }
    cipher.mac(&seed[..8], &cek);
    let actual = u32::from_le_bytes(*cipher.tag);
    let received = u32::from_le_bytes(wrapped[seed_len + 32..].try_into().expect("four-byte MAC"));
    if !actual.ct_eq(&received).to_bool() {
        return Err(WrapError::AuthenticationFailed);
    }
    Ok(cek)
}

fn kdf_into(key: &[u8; 32], seed: &[u8], destination: &mut [u8; 32]) {
    let mut state = <HmacSecret<Streebog256Secret> as KeyInit>::new_from_slice(key)
        .expect("HMAC permits a fixed 32-byte key");
    // RFC7836 §4.5: counter || label || 00 || seed || L_be, R=1,L=256.
    Mac::update(&mut state, &[1, 0x26, 0xbd, 0xb8, 0x78, 0]);
    Mac::update(&mut state, seed);
    Mac::update(&mut state, &[1, 0]);
    let output: &mut hmac::digest::Output<HmacSecret<Streebog256Secret>> = destination
        .as_mut_slice()
        .try_into()
        .expect("fixed KDF output width");
    hmac::digest::FixedOutput::finalize_into(state, output);
}

// Exact primary RFC7836 Appendix C columns K1..K8. No KZ/Russian alias guess.
const Z: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

const fn pack() -> [[u32; 2]; 8] {
    let mut rows = [[0u32; 2]; 8];
    let mut row = 0;
    while row < 8 {
        let mut n = 0;
        while n < 16 {
            rows[row][n / 8] |= (Z[row][n] as u32) << (4 * (n % 8));
            n += 1;
        }
        row += 1;
    }
    rows
}
const PACKED: [[u32; 2]; 8] = pack();

// Pointer-only inlined substitution over the stable round workspace. Actual
// spill inspection remains mandatory: black_box is not an erasure guarantee.
#[inline(always)]
fn substitute_into(work: &mut [u32; 8], row: usize) {
    let work = core::hint::black_box(work);
    work[2] = 4 * (work[1] & 7);
    work[3] = (PACKED[row][0] >> work[2]) & 15;
    work[4] = (PACKED[row][1] >> work[2]) & 15;
    work[5] = 0u32.wrapping_sub(work[1] >> 3);
    work[3] = (work[3] & !work[5]) | (work[4] & work[5]);
}

struct Gost28147 {
    key_bytes: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u32; 8]>,
    block_state: Zeroizing<[u32; 2]>,
    round_state: Zeroizing<[u32; 8]>,
    tag: Zeroizing<[u8; 4]>,
}
impl Gost28147 {
    fn zeroed_owner() -> Box<Self> {
        Box::new(Self {
            key_bytes: Zeroizing::new([0; 32]),
            key: Zeroizing::new([0; 8]),
            block_state: Zeroizing::new([0; 2]),
            round_state: Zeroizing::new([0; 8]),
            tag: Zeroizing::new([0; 4]),
        })
    }
    fn expand_key_in_place(&mut self) {
        for (word, bytes) in self.key.iter_mut().zip(self.key_bytes.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        self.key_bytes.zeroize();
    }
    #[inline(always)]
    fn step(&mut self, index: usize) {
        let this = core::hint::black_box(self);
        this.round_state[0] = this.block_state[0].wrapping_add(this.key[index]);
        this.round_state[6] = 0;
        for row in 0..8 {
            this.round_state[1] = (this.round_state[0] >> (4 * row)) & 15;
            substitute_into(&mut this.round_state, row);
            this.round_state[6] |= this.round_state[3] << (4 * row);
        }
        this.round_state[7] = this.block_state[1] ^ this.round_state[6].rotate_left(11);
        this.block_state[1] = this.block_state[0];
        this.block_state[0] = this.round_state[7];
    }
    #[inline(always)]
    fn block(&mut self, input: &[u8], output: &mut [u8], decrypt: bool) {
        self.block_state[0] = u32::from_le_bytes(input[..4].try_into().expect("block half"));
        self.block_state[1] = u32::from_le_bytes(input[4..].try_into().expect("block half"));
        for step in 0..32 {
            let index = if decrypt {
                if step < 8 { step } else { 7 - (step % 8) }
            } else if step < 24 {
                step % 8
            } else {
                7 - (step % 8)
            };
            self.step(index);
        }
        for i in 0..4 {
            output[i] = (self.block_state[1] >> (8 * i)) as u8;
            output[i + 4] = (self.block_state[0] >> (8 * i)) as u8;
        }
        self.block_state.zeroize();
        self.round_state.zeroize();
    }
    #[inline(always)]
    fn mac(&mut self, iv: &[u8], cek: &[u8; 32]) {
        self.block_state[0] = u32::from_le_bytes(iv[..4].try_into().expect("IV half"));
        self.block_state[1] = u32::from_le_bytes(iv[4..].try_into().expect("IV half"));
        for block in cek.as_chunks::<8>().0 {
            self.block_state[0] ^= u32::from_le_bytes(block[..4].try_into().expect("block half"));
            self.block_state[1] ^= u32::from_le_bytes(block[4..].try_into().expect("block half"));
            for step in 0..16 {
                self.step(step % 8);
            }
        }
        for i in 0..4 {
            self.tag[i] = (self.block_state[0] >> (8 * i)) as u8;
        }
        self.block_state.zeroize();
        self.round_state.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn kdf_rfc7836_example_9() {
        let key = hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mut got = Zeroizing::new([0; 32]);
        kdf_into(&key, &hex::<8>("af21434145656378"), &mut got);
        assert_eq!(
            *got,
            hex::<32>("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")
        );
    }

    #[test]
    fn primary_sbox_all_nibbles() {
        // Independent printed rows, including K3 positions12/13 = c,9.
        let rows = [
            "c462a5b9e8d703f1",
            "68239a5c1e47bd0f",
            "b3582fade174c960",
            "c821d4f670a53e9b",
            "7f5a816d093eb42c",
            "5df692cab78143e0",
            "8e25691cf4b0da37",
            "17ed05834fa69cb2",
        ];
        for (row, expected) in rows.iter().enumerate() {
            for (nibble, byte) in expected.bytes().enumerate() {
                let want = (byte as char).to_digit(16).unwrap();
                let mut work = [0; 8];
                work[1] = nibble as u32;
                substitute_into(&mut work, row);
                assert_eq!(work[3], want);
            }
        }
    }

    #[test]
    fn rfc7836_example_11_cipher_and_mac() {
        let mut cipher = Gost28147::zeroed_owner();
        cipher.key_bytes.copy_from_slice(&hex::<32>(
            "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
        ));
        cipher.expand_key_in_place();
        let cek = hex::<32>("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        let external =
            hex::<32>("d15547f8ee85121bc87d4b1027d26027ecc071bba6e72f3fec6f620f56834c5a");
        let mut enc = [0; 32];
        let mut dec = [0; 32];
        for (input, output) in cek
            .as_chunks::<8>()
            .0
            .iter()
            .zip(enc.as_chunks_mut::<8>().0)
        {
            cipher.block(input, output, false);
        }
        for (input, output) in external
            .as_chunks::<8>()
            .0
            .iter()
            .zip(dec.as_chunks_mut::<8>().0)
        {
            cipher.block(input, output, true);
        }
        assert_eq!(enc, external);
        assert_eq!(dec, cek);
        cipher.mac(&hex::<8>("af21434145656378"), &cek);
        assert_eq!(*cipher.tag, hex::<4>("be33f052"));
    }

    #[inline(never)]
    fn move_cek_capsule(value: SecretCek) -> SecretCek {
        std::hint::black_box(value)
    }

    #[test]
    fn recovered_cek_owner_move_preserves_secret_storage_address() {
        let kek = hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let external = hex::<44>(concat!(
            "af21434145656378",
            "d15547f8ee85121bc87d4b1027d26027ecc071bba6e72f3fec6f620f56834c5a",
            "be33f052"
        ));
        let cek = unwrap_cek(WrapProfile::Rfc7836Tc26Z, &kek, &external).unwrap();
        let address = std::hint::black_box(cek.as_ptr());
        let moved = move_cek_capsule(cek);
        assert_eq!(
            moved.as_ptr(),
            address,
            "successful recovered-key moves must not copy plaintext key bytes"
        );
        assert_eq!(
            &*moved,
            &hex::<32>("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        );
        // Compare identity only; never inspect moved-from stack/freed memory.
    }
}
