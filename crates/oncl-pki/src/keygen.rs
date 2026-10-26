//! Keys for new key files, chosen as NCALayer chooses them: by the signature algorithm OID of
//! a certificate request (`params[].algorithm`).

use crate::key::{PrivateKey, PublicKey, SigAlg, key_id_bytes, spki_key_id_bytes};
use crate::keystore::KeystoreError;
use crate::oid;
use crate::pkcs12::hex;
use der::asn1::ObjectIdentifier;
use oncl_gost::{CurveId, SigningKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::rand_core::{self, CryptoRng, RngCore};

/// Modulus sizes of RSA keys for sha256WithRSA. The original passes the request's `length`
/// to the key pair generator; `ring`, which signs with the key, takes moduli of 2048 to 4096
/// bits whose primes are multiples of 512 bits, so these three.
const RSA_BITS: [u32; 3] = [2048, 3072, 4096];

/// The key (and signature algorithm) of a certificate request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySpec {
    /// GOST 34.10-2015-512 (`1.2.398.3.10.1.1.2.3.2`).
    Gost2015_512,
    /// GOST 34.310-2004 (`1.2.398.3.10.1.1.1.2`).
    Gost2004,
    /// RSA with sha256WithRSA (`1.2.840.113549.1.1.11`), modulus of 2048, 3072 or 4096
    /// bits.
    RsaSha256(u32),
    /// RSA of the given modulus size with sha1WithRSA (`1.2.840.113549.1.1.5`). Accepted
    /// as an algorithm (key files get the `RSA_` prefix), but refused for keys and requests
    /// with [`KeystoreError::UnknownAlgorithm`]: its request needs a SHA-1 signature, which
    /// OpenNCALayer never makes (the original generates such keys; the NCA no longer issues
    /// sha1WithRSA certificates).
    Rsa1Sha1(u32),
}

impl KeySpec {
    /// The spec of a request's `algorithm` OID and `length`. GOST keys have fixed sizes, so
    /// the length is ignored for them; for sha256WithRSA it is the modulus size.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::UnknownAlgorithm`] for any other OID, and for sha256WithRSA with a
    /// length other than 2048, 3072 or 4096.
    pub fn from_oid_len(oid: &str, len: u32) -> Result<KeySpec, KeystoreError> {
        let oid = ObjectIdentifier::new(oid).map_err(|_| KeystoreError::UnknownAlgorithm)?;
        match oid {
            oid::GOST_2015_512_SIGNATURE => Ok(KeySpec::Gost2015_512),
            oid::GOST_2004_SIGNATURE => Ok(KeySpec::Gost2004),
            oid::SHA256_WITH_RSA if RSA_BITS.contains(&len) => Ok(KeySpec::RsaSha256(len)),
            oid::SHA1_WITH_RSA => Ok(KeySpec::Rsa1Sha1(len)),
            _ => Err(KeystoreError::UnknownAlgorithm),
        }
    }

    /// Signature algorithm of the request (and of certificates issued on it).
    pub fn sig_alg(self) -> SigAlg {
        match self {
            KeySpec::Gost2015_512 => SigAlg::Gost2015_512,
            KeySpec::Gost2004 => SigAlg::Gost2004,
            KeySpec::RsaSha256(_) => SigAlg::RsaSha256,
            KeySpec::Rsa1Sha1(_) => SigAlg::RsaSha1,
        }
    }

    /// File name prefix of a key file with this key (Kalkan `KeyStoreUtil`).
    pub(crate) fn file_prefix(self) -> &'static str {
        match self {
            KeySpec::Gost2015_512 => "GOST512_",
            KeySpec::Gost2004 => "GOSTKNCA_",
            KeySpec::RsaSha256(_) => "RSA256_",
            KeySpec::Rsa1Sha1(_) => "RSA_",
        }
    }
}

/// A new private key of `spec`. GOST scalars are drawn uniformly from `[1, q − 1]` with the
/// operating system RNG; RSA keys come from `rsa` with the same RNG and are used through
/// their PKCS#8 (signing is `ring`).
///
/// # Errors
///
/// [`KeystoreError::UnknownAlgorithm`] for [`KeySpec::Rsa1Sha1`] (see there) and for an RSA
/// modulus size other than 2048, 3072 or 4096.
///
/// # Panics
///
/// If the operating system RNG fails.
pub fn generate(spec: KeySpec) -> Result<PrivateKey, KeystoreError> {
    match spec {
        KeySpec::Gost2015_512 => Ok(PrivateKey::Gost(SigningKey::generate(CurveId::Tc26_512A))),
        KeySpec::Gost2004 => Ok(PrivateKey::Gost(SigningKey::generate(
            CurveId::Pkigovkz2004A,
        ))),
        KeySpec::RsaSha256(bits) if RSA_BITS.contains(&bits) => {
            let key =
                rsa::RsaPrivateKey::new(&mut OsRng, bits as usize).expect("RSA key generation");
            let pkcs8 = key.to_pkcs8_der().expect("RSA PKCS#8 encodes");
            Ok(PrivateKey::from_pkcs8_der(pkcs8.as_bytes(), None)
                .expect("ring reads a generated RSA key of a supported size"))
        }
        KeySpec::RsaSha256(_) | KeySpec::Rsa1Sha1(_) => Err(KeystoreError::UnknownAlgorithm),
    }
}

/// Key identifier of `key`, lowercase hex: SHA-1 of the `subjectPublicKey` BIT STRING
/// contents. Kalkan names generated keys (alias, `friendlyName`) and their files by it, and
/// NCA certificates carry it as SubjectKeyIdentifier.
pub fn key_id(key: &PublicKey) -> String {
    hex(&key_id_bytes(&key.to_spki()))
}

/// The legacy Applet's key identifier of `key`, lowercase hex: SHA-1 of the whole DER
/// `SubjectPublicKeyInfo` (Kalkan's `KALKANUtils.getKeyIdFromPK`). The Applet's
/// `genKeyPairAndGetPKCS10` names its keys and files by it and puts it in the request as
/// SubjectKeyIdentifier.
pub fn applet_key_id(key: &PublicKey) -> String {
    hex(&spki_key_id_bytes(&key.to_spki()))
}

/// The operating system RNG for `rsa` (`rand_core` 0.6).
struct OsRng;

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("operating system RNG failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::fill(dest).map_err(rand_core::Error::new)
    }
}

impl CryptoRng for OsRng {}
