//! RFC 7836 VKO primitives on the existing cofactor-one TC26 512-A curve.
//! These names do not assert a KZ CMS/envelope or recipient-certificate profile.
//! Verified RFC errata 6197–6201 apply: validate peer, never hash the identity.

use crate::{CurveId, SigningKey, VerifyingKey};
use crypto_bigint::{BoxedUint, Limb};
use streebog::{Digest, Streebog256Secret, Streebog512Secret};
use zeroize::Zeroizing;

/// Explicit primitive identities, not interchangeable KZ signature algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgreementProfile {
    /// RFC 7836 §4.3.1, 512-A keys and Streebog256 output.
    Rfc7836Tc26_512AStreebog256,
    /// RFC 7836 §4.3.2, 512-A keys and Streebog512 output.
    Rfc7836Tc26_512AStreebog512,
}

/// Failure before producing usable key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgreementError {
    /// Either key uses a different curve than the selected primitive.
    #[error("GOST agreement curve mismatch")]
    CurveMismatch,
    /// UKM must explicitly encode a nonzero little-endian integer in 1–64 bytes.
    #[error("invalid GOST agreement UKM")]
    InvalidUkm,
    /// Invalid peer or an identity result; no hash is computed for that point.
    #[error("invalid GOST shared point")]
    InvalidSharedPoint,
}

/// Zeroizing fixed-width key material; no Debug, Clone or serialization.
/// A 512-bit result must not be silently truncated to a 256-bit export key.
pub struct Kek {
    bytes: Box<Zeroizing<[u8; 64]>>,
    len: usize,
}

impl Kek {
    /// Borrow the complete derived key, exactly 32 or 64 bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Derive a key with an explicit nonzero little-endian UKM.
///
/// The caller/protocol owns random generation and freshness. Empty UKM is not
/// an implicit default. This software primitive neither authorizes key use nor
/// interprets certificates: those responsibilities belong to the host/provider.
///
/// # Errors
/// Returns an error for mismatched curves, zero/empty/oversized UKM, an invalid
/// peer or an identity shared point (including nonzero UKM congruent to zero).
pub fn derive_kek(
    profile: AgreementProfile,
    private: &SigningKey,
    peer: &VerifyingKey,
    ukm_le: &[u8],
) -> Result<Kek, AgreementError> {
    if private.curve() != CurveId::Tc26_512A || peer.curve() != CurveId::Tc26_512A {
        return Err(AgreementError::CurveMismatch);
    }
    if ukm_le.is_empty() || ukm_le.len() > 64 || ukm_le.iter().all(|&byte| byte == 0) {
        return Err(AgreementError::InvalidUkm);
    }
    let curve = CurveId::Tc26_512A.params().curve();
    let (x, y) = peer.affine_coordinates();
    let point = curve
        .affine(x, y)
        .ok_or(AgreementError::InvalidSharedPoint)?;
    // Only zero/public state is materialized before secret scalar use.
    let mut result = Kek {
        bytes: Box::new(Zeroizing::new([0; 64])),
        len: match profile {
            AgreementProfile::Rfc7836Tc26_512AStreebog256 => 32,
            AgreementProfile::Rfc7836Tc26_512AStreebog512 => 64,
        },
    };
    let hash = SecretHashState::new(profile);
    let ukm = BoxedUint::from_le_slice(ukm_le, 512).map_err(|_| AgreementError::InvalidUkm)?;
    // This specific curve has h=1. Never extend this formula to h>1 by simply
    // reducing h*UKM*d modulo q; errata6198/6199 require integer cofactor use.
    let scalar = curve
        .fq
        .element(&ukm)
        .mul(&curve.fq.element(private.secret_scalar()))
        .retrieve();
    let shared = curve.mul(&point, &scalar);
    let (x, y) = curve
        .to_affine(&shared)
        .ok_or(AgreementError::InvalidSharedPoint)?;
    let mut encoded = Zeroizing::new([0u8; 128]);
    coordinate_le(&x, &mut encoded[..64]);
    coordinate_le(&y, &mut encoded[64..]);
    hash.finish(&encoded[..], &mut result.bytes[..result.len]);
    Ok(result)
}

// Avoid allocating/copy-exporting BoxedUint::to_le_bytes for secret coordinates.
fn coordinate_le(value: &BoxedUint, output: &mut [u8]) {
    for (i, byte) in output.iter_mut().enumerate() {
        *byte = (value.as_limbs()[i / Limb::BYTES].0 >> (8 * (i % Limb::BYTES))) as u8;
    }
}

enum SecretHashState {
    Bits256(Streebog256Secret),
    Bits512(Streebog512Secret),
}
impl SecretHashState {
    fn new(profile: AgreementProfile) -> Self {
        match profile {
            AgreementProfile::Rfc7836Tc26_512AStreebog256 => {
                Self::Bits256(Streebog256Secret::new())
            }
            AgreementProfile::Rfc7836Tc26_512AStreebog512 => {
                Self::Bits512(Streebog512Secret::new())
            }
        }
    }
    fn finish(self, input: &[u8], output: &mut [u8]) {
        match self {
            Self::Bits256(state) => hash_into(state, input, output),
            Self::Bits512(state) => hash_into(state, input, output),
        }
    }
}

fn hash_into<D: Digest>(mut state: D, input: &[u8], output: &mut [u8]) {
    Digest::update(&mut state, input);
    let destination: &mut streebog::digest::Output<D> =
        output.try_into().expect("profile digest output width");
    state.finalize_into(destination);
}

#[cfg(test)]
mod ownership_regressions {
    use super::*;

    #[inline(never)]
    fn move_capsule(value: Kek) -> Kek {
        std::hint::black_box(value)
    }

    #[test]
    fn derived_key_owner_move_preserves_secret_storage_address() {
        // Ownership regression, not another agreement oracle: exact RFC KEK
        // correctness is covered independently in tests/agreement.rs.
        let private = SigningKey::from_scalar_be(CurveId::Tc26_512A, &[2]).unwrap();
        let peer = SigningKey::from_scalar_be(CurveId::Tc26_512A, &[3]).unwrap();
        let kek = derive_kek(
            AgreementProfile::Rfc7836Tc26_512AStreebog256,
            &private,
            peer.verifying_key(),
            &[1],
        )
        .unwrap();
        let address = std::hint::black_box(kek.as_bytes().as_ptr());
        let payload = kek.as_bytes().to_vec();
        let moved = move_capsule(kek);
        assert_eq!(
            moved.as_bytes().as_ptr(),
            address,
            "a successful secret capsule move must move ownership, not key bytes"
        );
        assert_eq!(moved.as_bytes(), payload.as_slice());
        // No dereference of the old pointer or a freed/moved-from frame.
        // Actual compiler-created copies still require optimized-artifact review.
    }
}
