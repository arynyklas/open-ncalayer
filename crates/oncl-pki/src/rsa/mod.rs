//! Native RSA prehash/OAEP operations. Only encoded private material is retained;
//! a single transient native private handle exists for the duration of each call.
use crate::{
    digest::DigestValue,
    key::{KeyError, SigAlg},
};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use zeroize::Zeroizing;

#[cfg(unix)]
mod aws_lc;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use aws_lc as native;
#[cfg(windows)]
use windows as native;

pub(crate) fn public_der(pkcs8: &[u8]) -> Result<Vec<u8>, KeyError> {
    // Decoding only: rsa0.9 never performs a production private operation.
    let key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8)
        .map_err(|e| KeyError::Malformed(e.to_string()))?;
    if !(2048..=8192).contains(&key.n().bits()) || key.e().bits() > 33 {
        return Err(KeyError::UnsupportedAlgorithm);
    }
    key.to_public_key()
        .to_pkcs1_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|e| KeyError::Malformed(e.to_string()))
}
pub(crate) fn validate(pkcs8: &[u8]) -> Result<(), KeyError> {
    native::validate(pkcs8)
}
pub(crate) fn sign(pkcs8: &[u8], digest: &DigestValue) -> Result<Vec<u8>, KeyError> {
    native::sign(pkcs8, digest)
}
pub(crate) fn verify(
    public: &[u8],
    alg: SigAlg,
    digest: &DigestValue,
    sig: &[u8],
) -> Result<(), KeyError> {
    native::verify(public, alg, digest, sig)
}
pub(crate) fn decrypt(pkcs8: &[u8], ciphertext: &[u8], label: &[u8]) -> Result<Vec<u8>, KeyError> {
    let plaintext: Zeroizing<Vec<u8>> = native::decrypt(pkcs8, ciphertext, label)?;
    // Transfer the result without retaining an unzeroized scratch copy.
    let mut plaintext = plaintext;
    Ok(std::mem::take(&mut *plaintext))
}
