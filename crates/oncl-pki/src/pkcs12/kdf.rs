//! Key derivation for PKCS#12: the PKCS#12 KDF (RFC 7292 Appendix B) and PBKDF2.

use sha1::digest::block_api::BlockSizeUser;
use sha1::digest::{Digest, Output};
use zeroize::{Zeroize, Zeroizing};

/// Purpose byte `ID` of the PKCS#12 KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    Key = 1,
    Iv = 2,
    Mac = 3,
}

/// PKCS#12 KDF (RFC 7292 B.2) producing `len` bytes. `password` is already encoded
/// (BMPString with terminator, see [`bmp_password`]); an empty password contributes nothing.
pub(crate) fn pkcs12<D: Digest + BlockSizeUser>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    purpose: Purpose,
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let u = <D as Digest>::output_size();
    let v = D::block_size();
    // S and P: salt and password repeated to a multiple of v bytes; I = S ‖ P.
    let repeat = |src: &[u8], out: &mut Vec<u8>| {
        if !src.is_empty() {
            out.extend((0..v * src.len().div_ceil(v)).map(|i| src[i % src.len()]));
        }
    };
    let mut i = Zeroizing::new(Vec::new());
    repeat(salt, &mut i);
    repeat(password, &mut i);
    let diversifier = vec![purpose as u8; v];
    let mut b = Zeroizing::new(vec![0u8; v]);
    let mut a = Output::<D>::default();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    loop {
        D::new()
            .chain_update(&diversifier)
            .chain_update(&*i)
            .finalize_into(&mut a);
        for _ in 1..iterations {
            let mut h = D::new();
            h.update(&a);
            h.finalize_into(&mut a);
        }
        let take = (len - out.len()).min(u);
        out.extend_from_slice(&a[..take]);
        if out.len() == len {
            break;
        }
        // I_j = (I_j + B + 1) mod 2^(8v), B = A repeated to v bytes.
        for (k, byte) in b.iter_mut().enumerate() {
            *byte = a[k % u];
        }
        for block in i.chunks_mut(v) {
            let mut carry = 1u16;
            for k in (0..v).rev() {
                let sum = u16::from(block[k]) + u16::from(b[k]) + carry;
                block[k] = sum as u8;
                carry = sum >> 8;
            }
        }
    }
    a[..].zeroize();
    out
}

/// Key and 8-byte IV of a PKCS#12 PBE scheme.
pub(crate) struct KeyIv {
    pub key: Zeroizing<Vec<u8>>,
    pub iv: Zeroizing<Vec<u8>>,
}

/// [`KeyIv`] of the `pbeWithSHAAnd*` schemes: PKCS#12 KDF with SHA-1.
pub(crate) fn pkcs12_key_iv(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> KeyIv {
    KeyIv {
        key: pkcs12::<sha1::Sha1>(password, salt, iterations, Purpose::Key, key_len),
        iv: pkcs12::<sha1::Sha1>(password, salt, iterations, Purpose::Iv, 8),
    }
}

/// Password for the PKCS#12 KDF: UTF-16 big-endian with a `00 00` terminator, as BMPString.
/// An empty password becomes empty bytes (the BouncyCastle / Kalkan convention).
pub(crate) fn bmp_password(password: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(2 * password.len() + 2));
    if !password.is_empty() {
        out.extend(password.encode_utf16().flat_map(u16::to_be_bytes));
        out.extend([0, 0]);
    }
    out
}

/// PRF of PBKDF2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Prf {
    HmacSha1,
    HmacSha256,
}

/// PBKDF2 key of 32 bytes (AES-256) from the UTF-8 password bytes.
pub(crate) fn pbkdf2_aes256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    prf: Prf,
) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    match prf {
        Prf::HmacSha1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, &mut *key),
        Prf::HmacSha256 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, &mut *key);
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn bmp_password_encoding() {
        assert_eq!(*bmp_password(""), b"");
        assert_eq!(*bmp_password("ab"), hex!("0061 0062 0000"));
        assert_eq!(*bmp_password("Пя"), hex!("041f 044f 0000"));
    }

    /// The classic PKCS#12 KDF vectors ("smeg"/"queeg", SHA-1) from BouncyCastle's
    /// `PKCS12Test`.
    #[test]
    fn pkcs12_kdf_sha1_vectors() {
        let password = bmp_password("smeg");
        let salt = hex!("0a58cf64530d823f");
        assert_eq!(
            *pkcs12::<sha1::Sha1>(&password, &salt, 1, Purpose::Key, 24),
            hex!("8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3")
        );
        assert_eq!(
            *pkcs12::<sha1::Sha1>(&password, &salt, 1, Purpose::Iv, 8),
            hex!("79993dfe048d3b76")
        );
        let salt = hex!("3d83c0e4546ac140");
        assert_eq!(
            *pkcs12::<sha1::Sha1>(&password, &salt, 1, Purpose::Mac, 20),
            hex!("8d967d88f6caa9d714800ab3d48051d63f73a312")
        );
        let password = bmp_password("queeg");
        let salt = hex!("1682c0fc5b3f7ec5");
        assert_eq!(
            *pkcs12::<sha1::Sha1>(&password, &salt, 1000, Purpose::Key, 24),
            hex!("483dd6e919d7de2e8e648ba8f862f3fbfbdc2bcb2c02957f")
        );
    }
}
