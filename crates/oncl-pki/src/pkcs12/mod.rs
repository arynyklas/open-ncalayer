//! PKCS#12 key stores (RFC 7292) with the reading rules of Kalkan (the NCALayer provider).
//!
//! - Key and certificate encryption: PKCS#12 PBE `pbeWithSHAAnd3-KeyTripleDES-CBC`,
//!   `pbeWithSHAAnd128BitRC2-CBC`, `pbewithSHAAnd40BitRC2-CBC` (PKCS#12 KDF, SHA-1), and
//!   PBES2 with PBKDF2 and AES-256-CBC. A PBKDF2 without a PRF uses **HMAC-SHA256** (Kalkan),
//!   not the RFC 8018 default HMAC-SHA1.
//! - MAC: HMAC with SHA-1 or SHA-256, chosen by the `MacData` digest OID.
//! - Passwords: BMPString with a `00 00` terminator for the PKCS#12 KDF (an empty password is
//!   empty bytes, retried as `00 00` when the MAC fails, as OpenSSL writes it); UTF-8 bytes
//!   for PBKDF2.

mod kdf;
mod read;
mod write;

pub use read::{Limits, Loaded, load, load_contents, load_within};
pub use write::{Pbe, WriteEntry, WriteOptions, write};

use crate::ber::BerError;
use crate::cert::Certificate;
use crate::key::PrivateKey;
use crate::oid;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockCipherDecrypt, BlockModeDecrypt, InnerIvInit, KeyInit, KeyIvInit};
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Choice, DecodeValue, Sequence};
use kdf::Prf;
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

/// Private key with its certificate, as stored under one alias.
#[derive(Clone, Debug)]
pub struct KeyEntry {
    /// `friendlyName`, else hex of `localKeyId`, else `"unmarked"`.
    pub alias: String,
    /// Private key.
    pub key: PrivateKey,
    /// Certificate of the key.
    pub cert: Certificate,
}

/// Private key as stored under one alias, with its certificate if the store has one.
#[derive(Clone, Debug)]
pub struct StoredKey {
    /// `friendlyName`, else hex of `localKeyId`, else `"unmarked"`.
    pub alias: String,
    /// Private key.
    pub key: PrivateKey,
    /// Certificate of the key, if any.
    pub cert: Option<Certificate>,
}

/// Everything [`load_contents`] reads from a key store.
#[derive(Clone, Debug)]
pub struct Contents {
    /// Keys sorted by alias.
    pub keys: Vec<StoredKey>,
    /// Certificates that pair with no key (e.g. CA certificates), in stored order.
    pub other_certs: Vec<Certificate>,
}

/// Error of a PKCS#12 operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Pkcs12Error {
    /// The MAC or the decryption fails with this password.
    #[error("wrong PKCS#12 password")]
    WrongPassword,
    /// The input is not a valid PKCS#12 key store.
    #[error("malformed PKCS#12: {0}")]
    Malformed(String),
    /// The key store uses an algorithm or structure that is not supported.
    #[error("unsupported PKCS#12 feature: {0}")]
    Unsupported(String),
}

impl From<der::Error> for Pkcs12Error {
    fn from(e: der::Error) -> Self {
        Pkcs12Error::Malformed(e.to_string())
    }
}

impl From<BerError> for Pkcs12Error {
    fn from(e: BerError) -> Self {
        Pkcs12Error::Malformed(e.to_string())
    }
}

// ASN.1 structures of RFC 7292 / RFC 5652 / RFC 8018. SET OF values (attributes) stay `Any`
// and are walked in stored order, so non-canonical SETs from other writers are accepted.

/// `PFX`.
#[derive(Sequence)]
pub(crate) struct Pfx {
    pub version: u8,
    pub auth_safe: ContentInfo,
    pub mac_data: Option<MacData>,
}

/// `ContentInfo` with an `[0] EXPLICIT` content.
#[derive(Sequence)]
pub(crate) struct ContentInfo {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub content: Option<Any>,
}

/// `MacData`.
#[derive(Sequence)]
pub(crate) struct MacData {
    pub mac: DigestInfo,
    pub mac_salt: OctetString,
    #[asn1(default = "default_iterations")]
    pub iterations: u32,
}

fn default_iterations() -> u32 {
    1
}

/// `DigestInfo`.
#[derive(Sequence)]
pub(crate) struct DigestInfo {
    pub algorithm: AlgorithmIdentifierOwned,
    pub digest: OctetString,
}

/// `SafeBag`; `bag_attributes` is the raw `SET OF Attribute`.
#[derive(Sequence)]
pub(crate) struct SafeBag {
    pub bag_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub bag_value: Any,
    pub bag_attributes: Option<Any>,
}

/// PKCS#12 `Attribute`; `values` is the raw `SET OF` value.
#[derive(Sequence)]
pub(crate) struct Attribute {
    pub oid: ObjectIdentifier,
    pub values: Any,
}

/// `CertBag`.
#[derive(Sequence)]
pub(crate) struct CertBag {
    pub cert_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub cert_value: OctetString,
}

/// `EncryptedPrivateKeyInfo`.
#[derive(Sequence)]
pub(crate) struct EncryptedPrivateKeyInfo {
    pub encryption_algorithm: AlgorithmIdentifierOwned,
    pub encrypted_data: OctetString,
}

/// `EncryptedData`.
#[derive(Sequence)]
pub(crate) struct EncryptedData {
    pub version: u8,
    pub encrypted_content_info: EncryptedContentInfo,
}

/// `EncryptedContentInfo`; `encrypted_content` is the raw `[0] IMPLICIT OCTET STRING`, which
/// BER writers may also encode constructed.
#[derive(Sequence)]
pub(crate) struct EncryptedContentInfo {
    pub content_type: ObjectIdentifier,
    pub content_encryption_algorithm: AlgorithmIdentifierOwned,
    pub encrypted_content: Option<Any>,
}

/// `pkcs-12PbeParams`.
#[derive(Sequence)]
pub(crate) struct Pkcs12PbeParams {
    pub salt: OctetString,
    pub iterations: u32,
}

/// `PBES2-params`.
#[derive(Sequence)]
pub(crate) struct Pbes2Params {
    pub key_derivation_func: AlgorithmIdentifierOwned,
    pub encryption_scheme: AlgorithmIdentifierOwned,
}

/// `PBKDF2-params` with a `specified` salt.
#[derive(Sequence)]
pub(crate) struct Pbkdf2Params {
    pub salt: OctetString,
    pub iteration_count: u32,
    pub key_length: Option<u32>,
    pub prf: Option<AlgorithmIdentifierOwned>,
}

/// The password in both encodings used by PKCS#12.
pub(crate) struct Passwords {
    /// For the PKCS#12 KDF (PBE and MAC).
    pub bmp: Zeroizing<Vec<u8>>,
    /// For PBKDF2.
    pub utf8: Zeroizing<Vec<u8>>,
}

impl Passwords {
    pub fn new(password: &str) -> Passwords {
        Passwords {
            bmp: kdf::bmp_password(password),
            utf8: Zeroizing::new(password.as_bytes().to_vec()),
        }
    }
}

/// Parameters of an `AlgorithmIdentifier`.
fn params<T: for<'a> Choice<'a> + for<'a> DecodeValue<'a, Error = der::Error>>(
    alg: &AlgorithmIdentifierOwned,
) -> Result<T, Pkcs12Error> {
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| Pkcs12Error::Malformed(format!("{} without parameters", alg.oid)))?;
    Ok(params.decode_as()?)
}

/// Largest iteration count accepted for the MAC KDF, PKCS#12 PBE and PBKDF2, as the JDK's
/// `PKCS12KeyStore` caps it. Real key stores use a few thousand; a hostile or corrupt count
/// near 2³² would keep the KDF busy for hours.
pub const MAX_ITERATIONS: u32 = 5_000_000;

/// `iterations` if it is in `1..=MAX_ITERATIONS`; checked before any KDF work.
fn check_iterations(iterations: u32) -> Result<u32, Pkcs12Error> {
    if iterations == 0 {
        return Err(Pkcs12Error::Malformed("iteration count 0".to_owned()));
    }
    if iterations > MAX_ITERATIONS {
        return Err(Pkcs12Error::Unsupported(format!(
            "iteration count {iterations} (at most {MAX_ITERATIONS})"
        )));
    }
    Ok(iterations)
}

/// Key and IV of a PKCS#12 PBE scheme from its parameters.
fn pbe_key_iv(
    password: &[u8],
    params: &Pkcs12PbeParams,
    key_len: usize,
) -> Result<kdf::KeyIv, Pkcs12Error> {
    let iterations = check_iterations(params.iterations)?;
    Ok(kdf::pkcs12_key_iv(
        password,
        params.salt.as_bytes(),
        iterations,
        key_len,
    ))
}

fn cbc_decrypt<C: BlockCipherDecrypt>(
    cipher: C,
    iv: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Pkcs12Error> {
    let mode = cbc::Decryptor::inner_iv_slice_init(cipher, iv)
        .map_err(|_| Pkcs12Error::Malformed("wrong IV length".to_owned()))?;
    mode.decrypt_padded_vec::<Pkcs7>(data)
        .map(Zeroizing::new)
        .map_err(|_| Pkcs12Error::WrongPassword)
}

/// PBES2 scheme: PRF, salt, iterations and IV.
pub(crate) struct Pbes2 {
    pub prf: Prf,
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub iv: Vec<u8>,
}

impl Pbes2 {
    fn parse(alg: &AlgorithmIdentifierOwned) -> Result<Pbes2, Pkcs12Error> {
        let p: Pbes2Params = params(alg)?;
        if p.key_derivation_func.oid != oid::PBKDF2 {
            return Err(Pkcs12Error::Unsupported(format!(
                "PBES2 key derivation {}",
                p.key_derivation_func.oid
            )));
        }
        if p.encryption_scheme.oid != oid::AES_256_CBC {
            return Err(Pkcs12Error::Unsupported(format!(
                "PBES2 encryption scheme {}",
                p.encryption_scheme.oid
            )));
        }
        let kdf: Pbkdf2Params = params(&p.key_derivation_func)?;
        if kdf.key_length.is_some_and(|l| l != 32) {
            return Err(Pkcs12Error::Unsupported(
                "PBKDF2 key length other than 32".to_owned(),
            ));
        }
        let prf = match kdf.prf.map(|a| a.oid) {
            None => Prf::HmacSha256, // Kalkan's default, not RFC 8018's HMAC-SHA1
            Some(oid::HMAC_SHA256) => Prf::HmacSha256,
            Some(oid::HMAC_SHA1) => Prf::HmacSha1,
            Some(other) => return Err(Pkcs12Error::Unsupported(format!("PBKDF2 PRF {other}"))),
        };
        let iv: OctetString = params(&p.encryption_scheme)?;
        Ok(Pbes2 {
            prf,
            salt: kdf.salt.as_bytes().to_vec(),
            iterations: check_iterations(kdf.iteration_count)?,
            iv: iv.as_bytes().to_vec(),
        })
    }

    fn key(&self, passwords: &Passwords) -> Zeroizing<[u8; 32]> {
        kdf::pbkdf2_aes256(&passwords.utf8, &self.salt, self.iterations, self.prf)
    }
}

/// Decrypts `data` encrypted with the password-based scheme `alg`.
pub(crate) fn decrypt(
    alg: &AlgorithmIdentifierOwned,
    passwords: &Passwords,
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Pkcs12Error> {
    let rc2 = |eff_bits: usize, key_len| -> Result<_, Pkcs12Error> {
        let k = pbe_key_iv(&passwords.bmp, &params(alg)?, key_len)?;
        cbc_decrypt(
            rc2::Rc2::new_with_eff_key_len(&k.key, eff_bits),
            &k.iv,
            data,
        )
    };
    match alg.oid {
        oid::PBE_SHA_3DES => {
            let k = pbe_key_iv(&passwords.bmp, &params(alg)?, 24)?;
            let cipher = des::TdesEde3::new_from_slice(&k.key).expect("24-byte 3DES key");
            cbc_decrypt(cipher, &k.iv, data)
        }
        oid::PBE_SHA_RC2_40 => rc2(40, 5),
        oid::PBE_SHA_RC2_128 => rc2(128, 16),
        oid::PBES2 => {
            let scheme = Pbes2::parse(alg)?;
            let key = scheme.key(passwords);
            let mode = cbc::Decryptor::<aes::Aes256>::new_from_slices(&*key, &scheme.iv)
                .map_err(|_| Pkcs12Error::Malformed("AES-256-CBC IV is not 16 bytes".to_owned()))?;
            mode.decrypt_padded_vec::<Pkcs7>(data)
                .map(Zeroizing::new)
                .map_err(|_| Pkcs12Error::WrongPassword)
        }
        other => Err(Pkcs12Error::Unsupported(format!("encryption {other}"))),
    }
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iteration_bounds() {
        assert!(matches!(
            check_iterations(0),
            Err(Pkcs12Error::Malformed(_))
        ));
        assert_eq!(check_iterations(1).ok(), Some(1));
        assert_eq!(check_iterations(2048).ok(), Some(2048));
        assert_eq!(check_iterations(MAX_ITERATIONS).ok(), Some(MAX_ITERATIONS));
        assert!(matches!(
            check_iterations(MAX_ITERATIONS + 1),
            Err(Pkcs12Error::Unsupported(_))
        ));
        assert!(matches!(
            check_iterations(u32::MAX),
            Err(Pkcs12Error::Unsupported(_))
        ));
    }
}
