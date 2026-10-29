//! Byte handling the drivers share: PKCS#1 padding, byte orders, public keys from card
//! bytes.

use crate::error::TokenError;
use der::Encode;
use der::asn1::UintRef;
use oncl_gost::{CurveId, VerifyingKey};
use oncl_pki::key::{KeyAlg, PublicKey};

/// The PKCS#1 v1.5 type 1 block `00 01 FF…FF 00 DigestInfo` of `modulus_len` bytes.
///
/// # Errors
///
/// [`TokenError::Malformed`] if the modulus is too short for the `DigestInfo` and 8 bytes
/// of padding.
pub fn pkcs1_type1(digest_info: &[u8], modulus_len: usize) -> Result<Vec<u8>, TokenError> {
    if modulus_len < digest_info.len() + 11 {
        return Err(TokenError::Malformed(format!(
            "a modulus of {modulus_len} bytes for a DigestInfo of {}",
            digest_info.len()
        )));
    }
    let mut block = Vec::with_capacity(modulus_len);
    block.extend([0x00, 0x01]);
    block.resize(modulus_len - digest_info.len() - 1, 0xFF);
    block.push(0x00);
    block.extend(digest_info);
    Ok(block)
}

/// `bytes` in reverse order.
pub fn reversed(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

/// Each half of `bytes` reversed in place: `X_BE ‖ Y_BE` ↔ `X_LE ‖ Y_LE`, `r_BE ‖ s_BE` ↔
/// `r_LE ‖ s_LE`.
pub fn reverse_halves(bytes: &[u8]) -> Vec<u8> {
    let (a, b) = bytes.split_at(bytes.len() / 2);
    let mut out = reversed(a);
    out.extend(b.iter().rev());
    out
}

/// The curve of a GOST key type.
pub(crate) fn curve(alg: KeyAlg) -> Option<CurveId> {
    match alg {
        KeyAlg::Gost2004 => Some(CurveId::Pkigovkz2004A),
        KeyAlg::Gost2015_512 => Some(CurveId::Tc26_512A),
        KeyAlg::Rsa => None,
    }
}

/// GOST public key from its point `X_LE ‖ Y_LE`.
///
/// # Errors
///
/// [`TokenError::Malformed`] for an RSA `alg`, a wrong length or a point off the curve.
pub fn gost_public(alg: KeyAlg, xy_le: &[u8]) -> Result<PublicKey, TokenError> {
    let curve = curve(alg).ok_or_else(|| TokenError::Malformed("not a GOST key".to_owned()))?;
    VerifyingKey::from_kz_bytes(curve, xy_le)
        .map(PublicKey::Gost)
        .map_err(|e| TokenError::Malformed(format!("GOST public key: {e}")))
}

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    exponent: UintRef<'a>,
}

/// RSA public key from its big-endian modulus; the exponent is 65537 (cards do not give it).
///
/// # Errors
///
/// [`TokenError::Malformed`] for an empty modulus.
pub fn rsa_public(modulus_be: &[u8]) -> Result<PublicKey, TokenError> {
    let malformed = |e: der::Error| TokenError::Malformed(format!("RSA modulus: {e}"));
    if modulus_be.iter().all(|&b| b == 0) {
        return Err(TokenError::Malformed("an empty RSA modulus".to_owned()));
    }
    let key = RsaPublicKey {
        modulus: UintRef::new(modulus_be).map_err(malformed)?,
        exponent: UintRef::new(&[0x01, 0x00, 0x01]).map_err(malformed)?,
    };
    key.to_der().map(PublicKey::Rsa).map_err(malformed)
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs1_layout() {
        let block = pkcs1_type1(&[7; 51], 256).unwrap();
        assert_eq!(block.len(), 256);
        assert_eq!(block[..2], [0, 1]);
        assert!(block[2..204].iter().all(|&b| b == 0xFF));
        assert_eq!(block[204], 0);
        assert_eq!(block[205..], [7; 51]);
        assert!(pkcs1_type1(&[7; 51], 61).is_err());
    }

    #[test]
    fn orders() {
        assert_eq!(reversed(&[1, 2, 3]), [3, 2, 1]);
        assert_eq!(reverse_halves(&[1, 2, 3, 4]), [2, 1, 4, 3]);
        assert_eq!(hex(&[0xAB, 0x01]), "ab01");
    }

    #[test]
    fn rsa_public_is_canonical() {
        let PublicKey::Rsa(der) = rsa_public(&[0x00, 0x80, 0x01]).unwrap() else {
            unreachable!()
        };
        // SEQUENCE { INTEGER 0x008001, INTEGER 65537 }
        assert_eq!(
            der,
            [
                0x30, 0x0A, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01
            ]
        );
        assert!(rsa_public(&[0, 0]).is_err());
    }
}
