//! BCrypt primitives available on Windows 7; no persisted NCrypt/vault objects.
use crate::{
    digest::DigestValue,
    key::{HashAlg, KeyError, SigAlg},
};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    pkcs8::DecodePrivateKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use std::{ffi::c_void, ptr};
use windows_sys::Win32::Security::Cryptography::*;
use zeroize::Zeroizing;

struct Algorithm(BCRYPT_ALG_HANDLE);
impl Drop for Algorithm {
    fn drop(&mut self) {
        unsafe {
            BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}
struct Key {
    handle: BCRYPT_KEY_HANDLE,
    _algorithm: Algorithm,
    size: usize,
}
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyKey(self.handle);
        }
    }
}
fn status(value: i32) -> Result<(), KeyError> {
    if value >= 0 {
        Ok(())
    } else {
        Err(KeyError::BackendFailure)
    }
}
fn header(
    out: &mut Vec<u8>,
    magic: u32,
    bits: usize,
    e: usize,
    n: usize,
    p: usize,
    q: usize,
) -> Result<(), KeyError> {
    for value in [
        magic,
        u32::try_from(bits).map_err(|_| KeyError::BackendFailure)?,
        u32::try_from(e).map_err(|_| KeyError::BackendFailure)?,
        u32::try_from(n).map_err(|_| KeyError::BackendFailure)?,
        u32::try_from(p).map_err(|_| KeyError::BackendFailure)?,
        u32::try_from(q).map_err(|_| KeyError::BackendFailure)?,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(())
}
fn import(blob: &[u8], private: bool, size: usize) -> Result<Key, KeyError> {
    let mut alg = ptr::null_mut();
    // SAFETY: valid out pointer and static UTF16 algorithm; RAII owns successful handles.
    unsafe {
        status(BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_RSA_ALGORITHM,
            ptr::null(),
            0,
        ))?;
    }
    let algorithm = Algorithm(alg);
    let mut handle = ptr::null_mut();
    unsafe {
        status(BCryptImportKeyPair(
            algorithm.0,
            ptr::null_mut(),
            if private {
                BCRYPT_RSAPRIVATE_BLOB
            } else {
                BCRYPT_RSAPUBLIC_BLOB
            },
            &mut handle,
            blob.as_ptr(),
            u32::try_from(blob.len()).map_err(|_| KeyError::BackendFailure)?,
            0,
        ))?;
    }
    Ok(Key {
        handle,
        _algorithm: algorithm,
        size,
    })
}
fn private(pkcs8: &[u8]) -> Result<Key, KeyError> {
    let mut blob = Zeroizing::new(Vec::new());
    let size;
    {
        // Decode only; never use rsa0.9 for a production private operation.
        let key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8)
            .map_err(|e| KeyError::Malformed(e.to_string()))?;
        if key.primes().len() != 2 {
            return Err(KeyError::UnsupportedAlgorithm);
        }
        let e = key.e().to_bytes_be();
        let n = key.n().to_bytes_be();
        let p = Zeroizing::new(key.primes()[0].to_bytes_be());
        let q = Zeroizing::new(key.primes()[1].to_bytes_be());
        size = n.len();
        header(
            &mut blob,
            BCRYPT_RSAPRIVATE_MAGIC,
            key.n().bits(),
            e.len(),
            n.len(),
            p.len(),
            q.len(),
        )?;
        blob.extend_from_slice(&e);
        blob.extend_from_slice(&n);
        blob.extend_from_slice(&p);
        blob.extend_from_slice(&q);
    } // parsed Rust private object dropped BEFORE native import
    import(&blob, true, size)
}
fn public(der: &[u8]) -> Result<Key, KeyError> {
    let key = rsa::RsaPublicKey::from_pkcs1_der(der).map_err(|_| KeyError::BadSignature)?;
    if !(2048..=8192).contains(&key.n().bits()) || key.e().bits() > 33 {
        return Err(KeyError::BadSignature);
    }
    let e = key.e().to_bytes_be();
    let n = key.n().to_bytes_be();
    let mut blob = Vec::with_capacity(24 + e.len() + n.len());
    header(
        &mut blob,
        BCRYPT_RSAPUBLIC_MAGIC,
        key.n().bits(),
        e.len(),
        n.len(),
        0,
        0,
    )?;
    blob.extend_from_slice(&e);
    blob.extend_from_slice(&n);
    import(&blob, false, n.len())
}
pub(super) fn validate(pkcs8: &[u8]) -> Result<(), KeyError> {
    private(pkcs8).map(|_| ())
}
pub(super) fn sign(pkcs8: &[u8], digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
    if digest.algorithm() != HashAlg::Sha256 {
        return Err(KeyError::UnsupportedAlgorithm);
    }
    let key = private(pkcs8)?;
    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
    };
    let mut out = vec![0; key.size];
    let mut len = 0;
    // SAFETY: live imported key and correctly sized input/output buffers; padding lives through call.
    unsafe {
        status(BCryptSignHash(
            key.handle,
            (&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast::<c_void>(),
            digest.as_bytes().as_ptr(),
            digest.as_bytes().len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut len,
            BCRYPT_PAD_PKCS1,
        ))?;
    }
    if len as usize != out.len() {
        return Err(KeyError::BackendFailure);
    }
    Ok(out)
}
pub(super) fn verify(
    der: &[u8],
    alg: SigAlg,
    digest: &DigestValue,
    signature: &[u8],
) -> Result<(), KeyError> {
    let hash = match alg {
        SigAlg::RsaSha256 => BCRYPT_SHA256_ALGORITHM,
        SigAlg::RsaSha1 => BCRYPT_SHA1_ALGORITHM,
        _ => return Err(KeyError::UnsupportedAlgorithm),
    };
    let key = public(der)?;
    if signature.len() != key.size {
        return Err(KeyError::BadSignature);
    }
    let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: hash };
    unsafe {
        status(BCryptVerifySignature(
            key.handle,
            (&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast::<c_void>(),
            digest.as_bytes().as_ptr(),
            digest.as_bytes().len() as u32,
            signature.as_ptr(),
            signature.len() as u32,
            BCRYPT_PAD_PKCS1,
        ))
        .map_err(|_| KeyError::BadSignature)
    }
}
pub(super) fn decrypt(
    pkcs8: &[u8],
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let key = private(pkcs8)?;
    if ciphertext.len() != key.size {
        return Err(KeyError::DecryptionFailed);
    }
    let label_len = u32::try_from(label.len()).map_err(|_| KeyError::DecryptionFailed)?;
    let padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: if label.is_empty() {
            ptr::null_mut()
        } else {
            label.as_ptr().cast_mut()
        },
        cbLabel: label_len,
    };
    let mut out = Zeroizing::new(vec![0; key.size]);
    let mut len = 0;
    unsafe {
        status(BCryptDecrypt(
            key.handle,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            (&padding as *const BCRYPT_OAEP_PADDING_INFO).cast::<c_void>(),
            ptr::null_mut(),
            0,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut len,
            BCRYPT_PAD_OAEP,
        ))
        .map_err(|_| KeyError::DecryptionFailed)?;
    }
    let len = usize::try_from(len).map_err(|_| KeyError::DecryptionFailed)?;
    if len > out.len() {
        return Err(KeyError::DecryptionFailed);
    }
    out[len..].fill(0);
    out.truncate(len);
    Ok(out)
}
