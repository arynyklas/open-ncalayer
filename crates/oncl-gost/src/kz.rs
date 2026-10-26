//! GOST keys and signatures in the byte conventions of the Kazakhstan PKI (Kalkan / NCALayer).
//!
//! - The digest integer `e` is the digest bytes read as a **little-endian** number.
//! - A signature is `reverse(s_BE ‖ r_BE)` = `r_LE ‖ s_LE`, each half [`CurveId::coord_len`]
//!   bytes (64 or 128 bytes in total).
//! - A public key is `X_LE ‖ Y_LE`, each coordinate exactly [`CurveId::coord_len`] bytes, also
//!   when its top byte is zero.
//! - For [`CurveId::Pkigovkz2004A`] only, verification falls back to the standard RFC 4491
//!   layout `s_BE ‖ r_BE`, as Kalkan does ("gost big-endian block").

use crate::curves::CurveId;
use crate::hazmat;
use crypto_bigint::BoxedUint;
use std::fmt;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Error of a KZ GOST key or signature operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GostError {
    /// A private key or nonce is outside `[1, q − 1]`.
    #[error("GOST scalar is outside [1, q - 1]")]
    InvalidScalar,
    /// A public key is not a point on the curve.
    #[error("GOST public key is not a point on the curve")]
    InvalidPoint,
    /// A public key or signature has the wrong length for the curve.
    #[error("GOST public key or signature has the wrong length")]
    InvalidLength,
    /// The signature does not verify.
    #[error("GOST signature does not verify")]
    BadSignature,
}

/// GOST private key. The scalar is zeroized on drop.
#[derive(Clone)]
pub struct SigningKey {
    curve: CurveId,
    d: Zeroizing<BoxedUint>,
    public: VerifyingKey,
}

impl ZeroizeOnDrop for SigningKey {}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("curve", &self.curve)
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Private key from the big-endian scalar `d`. Leading zero bytes are allowed.
    ///
    /// # Errors
    ///
    /// [`GostError::InvalidScalar`] unless `1 ≤ d ≤ q − 1`.
    pub fn from_scalar_be(curve: CurveId, d_be: &[u8]) -> Result<SigningKey, GostError> {
        let d = scalar_be(curve, d_be)?;
        let (x, y) = hazmat::public_point(curve.params(), &d);
        Ok(SigningKey {
            curve,
            d,
            public: VerifyingKey { curve, x, y },
        })
    }

    /// New private key with `d` drawn uniformly from `[1, q − 1]` (rejection sampling from
    /// the operating system RNG).
    ///
    /// # Panics
    ///
    /// If the operating system RNG fails.
    pub fn generate(curve: CurveId) -> SigningKey {
        let d = random_scalar(curve);
        let (x, y) = hazmat::public_point(curve.params(), &d);
        SigningKey {
            curve,
            d,
            public: VerifyingKey { curve, x, y },
        }
    }

    /// The scalar `d`, big-endian, exactly [`CurveId::coord_len`] bytes; zeroized on drop.
    pub fn scalar_be(&self) -> Zeroizing<Vec<u8>> {
        let n = self.curve.coord_len();
        let bytes = Zeroizing::new(self.d.to_be_bytes());
        let (excess, d) = bytes.split_at(bytes.len().saturating_sub(n));
        debug_assert!(
            excess.iter().all(|&b| b == 0),
            "scalar wider than coord_len"
        );
        let mut out = Zeroizing::new(Vec::with_capacity(n));
        out.resize(n - d.len(), 0);
        out.extend_from_slice(d);
        out
    }

    /// Curve of this key.
    pub fn curve(&self) -> CurveId {
        self.curve
    }

    /// Public half of this key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.public
    }

    /// KZ-encoded signature (`r_LE ‖ s_LE`) of a precomputed digest, with a fresh nonce `k`
    /// drawn uniformly from `[1, q − 1]` by rejection sampling from the operating system RNG.
    ///
    /// # Panics
    ///
    /// If the operating system RNG fails.
    pub fn sign_digest(&self, digest: &[u8]) -> Vec<u8> {
        let e = digest_le(digest);
        loop {
            let k = random_scalar(self.curve);
            if let Some(sig) = self.sign(&e, &k) {
                return sig;
            }
        }
    }

    /// Like [`SigningKey::sign_digest`] with the caller's big-endian nonce `k`, for test
    /// vectors. `k` is used as is, never reduced.
    ///
    /// # Errors
    ///
    /// [`GostError::InvalidScalar`] unless `1 ≤ k ≤ q − 1`, or if this `k` yields `r = 0` or
    /// `s = 0`.
    pub fn sign_digest_with_k(&self, digest: &[u8], k_be: &[u8]) -> Result<Vec<u8>, GostError> {
        let k = scalar_be(self.curve, k_be)?;
        self.sign(&digest_le(digest), &k)
            .ok_or(GostError::InvalidScalar)
    }

    fn sign(&self, e: &BoxedUint, k: &BoxedUint) -> Option<Vec<u8>> {
        let (r, s) = hazmat::sign_with_k(self.curve.params(), &self.d, e, k)?;
        let n = self.curve.coord_len();
        let mut sig = le_fixed(&r, n);
        sig.extend(le_fixed(&s, n));
        Some(sig)
    }
}

/// GOST public key: a point on the curve other than the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    curve: CurveId,
    x: BoxedUint,
    y: BoxedUint,
}

impl VerifyingKey {
    /// Public key from its KZ encoding `X_LE ‖ Y_LE` (the contents of the OCTET STRING inside
    /// the SPKI `subjectPublicKey`).
    ///
    /// The curves have prime order, so any point on the curve is a valid key.
    ///
    /// # Errors
    ///
    /// [`GostError::InvalidLength`] unless `xy_le` is exactly `2 · coord_len` bytes;
    /// [`GostError::InvalidPoint`] if the point is not on the curve.
    pub fn from_kz_bytes(curve: CurveId, xy_le: &[u8]) -> Result<VerifyingKey, GostError> {
        let n = curve.coord_len();
        if xy_le.len() != 2 * n {
            return Err(GostError::InvalidLength);
        }
        let (x, y) = xy_le.split_at(n);
        let (x, y) = (uint_le(curve, x), uint_le(curve, y));
        if !hazmat::is_on_curve(curve.params(), &x, &y) {
            return Err(GostError::InvalidPoint);
        }
        Ok(VerifyingKey { curve, x, y })
    }

    /// Curve of this key.
    pub fn curve(&self) -> CurveId {
        self.curve
    }

    /// KZ encoding `X_LE ‖ Y_LE`, always `2 · coord_len` bytes.
    pub fn to_kz_bytes(&self) -> Vec<u8> {
        let n = self.curve.coord_len();
        let mut out = le_fixed(&self.x, n);
        out.extend(le_fixed(&self.y, n));
        out
    }

    /// Verifies a KZ-encoded signature (`r_LE ‖ s_LE`) over a precomputed digest. For
    /// [`CurveId::Pkigovkz2004A`] a standard `s_BE ‖ r_BE` signature is accepted as well.
    ///
    /// # Errors
    ///
    /// [`GostError::InvalidLength`] unless `sig` is exactly `2 · coord_len` bytes;
    /// [`GostError::BadSignature`] if it does not verify.
    pub fn verify_digest(&self, digest: &[u8], sig: &[u8]) -> Result<(), GostError> {
        let n = self.curve.coord_len();
        if sig.len() != 2 * n {
            return Err(GostError::InvalidLength);
        }
        let e = digest_le(digest);
        let (lo, hi) = sig.split_at(n);
        let check = |r: &BoxedUint, s: &BoxedUint| {
            hazmat::verify(self.curve.params(), &self.x, &self.y, &e, r, s)
        };
        if check(&uint_le(self.curve, lo), &uint_le(self.curve, hi)) {
            return Ok(());
        }
        if self.curve == CurveId::Pkigovkz2004A
            && check(&uint_be(self.curve, hi), &uint_be(self.curve, lo))
        {
            return Ok(());
        }
        Err(GostError::BadSignature)
    }
}

/// Bit precision of the curve's integers (that of `p`).
fn precision(curve: CurveId) -> u32 {
    curve.params().p.bits_precision()
}

/// Little-endian unsigned integer of at most `coord_len` bytes.
fn uint_le(curve: CurveId, bytes: &[u8]) -> BoxedUint {
    BoxedUint::from_le_slice(bytes, precision(curve)).expect("at most coord_len bytes")
}

/// Big-endian unsigned integer of at most `coord_len` bytes.
fn uint_be(curve: CurveId, bytes: &[u8]) -> BoxedUint {
    BoxedUint::from_be_slice(bytes, precision(curve)).expect("at most coord_len bytes")
}

/// The digest integer `e`: digest bytes read as little-endian.
fn digest_le(digest: &[u8]) -> BoxedUint {
    let bits = u32::try_from(digest.len().max(1) * 8).expect("digest shorter than 512 MiB");
    BoxedUint::from_le_slice(digest, bits).expect("precision covers the digest")
}

/// `x < 2^(8n)` as exactly `n` little-endian bytes.
fn le_fixed(x: &BoxedUint, n: usize) -> Vec<u8> {
    let bytes = x.to_le_bytes();
    let mut out = vec![0; n];
    let len = bytes.len().min(n);
    debug_assert!(
        bytes[len..].iter().all(|&b| b == 0),
        "value wider than n bytes"
    );
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Big-endian scalar in `[1, q − 1]`; any number of leading zero bytes is accepted.
fn scalar_be(curve: CurveId, bytes: &[u8]) -> Result<Zeroizing<BoxedUint>, GostError> {
    let (excess, value) = bytes.split_at(bytes.len().saturating_sub(curve.coord_len()));
    if excess.iter().any(|&b| b != 0) {
        return Err(GostError::InvalidScalar);
    }
    let x = Zeroizing::new(uint_be(curve, value));
    if !hazmat::is_valid_scalar(curve.params(), &x) {
        return Err(GostError::InvalidScalar);
    }
    Ok(x)
}

/// Nonce drawn uniformly from `[1, q − 1]`: `bits(q)` random bits, redrawn while `0` or `≥ q`.
///
/// # Panics
///
/// If the operating system RNG fails.
fn random_scalar(curve: CurveId) -> Zeroizing<BoxedUint> {
    let params = curve.params();
    let bits = params.q.bits_vartime();
    let len = bits.div_ceil(8);
    let mask = 0xff_u8 >> (8 * len - bits);
    let mut buf = Zeroizing::new(vec![0u8; len as usize]);
    loop {
        getrandom::fill(&mut buf).expect("operating system RNG failed");
        buf[0] &= mask;
        let k = Zeroizing::new(uint_be(curve, &buf));
        if hazmat::is_valid_scalar(params, &k) {
            return k;
        }
    }
}
