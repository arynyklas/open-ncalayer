use crate::{
    digest::DigestValue,
    key::{HashAlg, KeyError, SigAlg},
};
use aws_lc_rs::{digest, rsa, signature};
use zeroize::Zeroizing;

pub(super) fn validate(pkcs8: &[u8]) -> Result<(), KeyError> {
    rsa::KeyPair::from_pkcs8(pkcs8)
        .map(|_| ())
        .map_err(|e| KeyError::Malformed(e.to_string()))
}
fn imported(value: &DigestValue) -> Result<digest::Digest, KeyError> {
    let alg = match value.algorithm() {
        HashAlg::Sha256 => &digest::SHA256,
        HashAlg::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        _ => return Err(KeyError::UnsupportedAlgorithm),
    };
    digest::Digest::import_less_safe(value.as_bytes(), alg)
        .map_err(|_| KeyError::UnsupportedAlgorithm)
}
pub(super) fn sign(pkcs8: &[u8], value: &DigestValue) -> Result<Vec<u8>, KeyError> {
    if value.algorithm() != HashAlg::Sha256 {
        return Err(KeyError::UnsupportedAlgorithm);
    }
    let key = rsa::KeyPair::from_pkcs8(pkcs8).map_err(|_| KeyError::BackendFailure)?;
    let mut out = vec![0; key.public_modulus_len()];
    key.sign_digest(&signature::RSA_PKCS1_SHA256, &imported(value)?, &mut out)
        .map_err(|_| KeyError::BackendFailure)?;
    Ok(out)
}
pub(super) fn verify(
    public: &[u8],
    alg: SigAlg,
    value: &DigestValue,
    sig: &[u8],
) -> Result<(), KeyError> {
    let params = match alg {
        SigAlg::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        SigAlg::RsaSha1 => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        _ => return Err(KeyError::UnsupportedAlgorithm),
    };
    signature::UnparsedPublicKey::new(params, public)
        .verify_digest(&imported(value)?, sig)
        .map_err(|_| KeyError::BadSignature)
}
pub(super) fn decrypt(
    pkcs8: &[u8],
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let key = rsa::PrivateDecryptingKey::from_pkcs8(pkcs8).map_err(|_| KeyError::BackendFailure)?;
    let key = rsa::OaepPrivateDecryptingKey::new(key).map_err(|_| KeyError::BackendFailure)?;
    if ciphertext.len() != key.key_size_bytes() {
        return Err(KeyError::DecryptionFailed);
    }
    let mut out = Zeroizing::new(vec![0; key.min_output_size()]);
    let len = key
        .decrypt(
            &rsa::OAEP_SHA256_MGF1SHA256,
            ciphertext,
            &mut out,
            Some(label),
        )
        .map_err(|_| KeyError::DecryptionFailed)?
        .len();
    out[len..].fill(0);
    out.truncate(len);
    Ok(out)
}
