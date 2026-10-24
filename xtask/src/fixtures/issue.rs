//! Keys and certificates of the synthetic PKI. Every random value — GOST scalars and nonces,
//! RSA keys, serial numbers — is drawn from the caller's seeded [`ChaCha20Rng`], so the output
//! is a pure function of the seed and of the order of calls.

use der::asn1::{Any, BitString, ObjectIdentifier, OctetString, Uint};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Sequence};
use oncl_gost::{GostAlg, GostError, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha1::{Digest, Sha1};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

/// sha256WithRSAEncryption.
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// RSA modulus size of the synthetic keys.
const RSA_BITS: usize = 2048;

/// Key type of a synthetic key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyKind {
    /// GOST key; certificates it issues are signed with this algorithm.
    Gost(GostAlg),
    /// RSA-2048; certificates it issues are signed with sha256WithRSAEncryption.
    Rsa,
}

enum Secret {
    Gost { alg: GostAlg, key: SigningKey },
    Rsa(Box<RsaPrivateKey>),
}

/// A key pair with its encodings.
pub(super) struct Key {
    secret: Secret,
    /// DER `PrivateKeyInfo`.
    pub pkcs8_der: Vec<u8>,
    /// `SubjectPublicKeyInfo` for certificates of this key.
    pub spki: SubjectPublicKeyInfoOwned,
    /// SubjectKeyIdentifier: SHA-1 of the `subjectPublicKey` BIT STRING contents (RFC 5280
    /// §4.2.1.2, method 1).
    pub ski: Vec<u8>,
}

impl Key {
    /// Generates a key from `rng`.
    pub fn generate(kind: KeyKind, rng: &mut ChaCha20Rng) -> Key {
        let (secret, pkcs8_der, spki) = match kind {
            KeyKind::Gost(alg) => gost_key(alg, rng),
            KeyKind::Rsa => rsa_key(rng),
        };
        let bits = spki
            .subject_public_key
            .as_bytes()
            .expect("public key BIT STRING without unused bits");
        let ski = Sha1::digest(bits).to_vec();
        Key {
            secret,
            pkcs8_der,
            spki,
            ski,
        }
    }

    /// Certificate signature algorithm of this key as an issuer; the parameters are NULL.
    fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
        let oid = match &self.secret {
            Secret::Gost { alg, .. } => ObjectIdentifier::new_unwrap(alg.signature_oid()),
            Secret::Rsa(_) => SHA256_WITH_RSA,
        };
        AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        }
    }

    /// Deterministic signature of `message`: GOST with a nonce `k` from `rng` (redrawn while
    /// outside `[1, q − 1]` or yielding `r = 0` / `s = 0`), RSA PKCS#1 v1.5 with SHA-256.
    fn sign(&self, message: &[u8], rng: &mut ChaCha20Rng) -> Vec<u8> {
        match &self.secret {
            Secret::Gost { alg, key } => {
                let digest = alg.hash(message);
                let mut k = vec![0; key.curve().coord_len()];
                loop {
                    rng.fill_bytes(&mut k);
                    match key.sign_digest_with_k(&digest, &k) {
                        Ok(sig) => return sig,
                        Err(GostError::InvalidScalar) => continue,
                        Err(e) => panic!("GOST signing: {e}"),
                    }
                }
            }
            Secret::Rsa(key) => {
                let digest = sha2::Sha256::digest(message);
                key.sign(Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), &digest)
                    .expect("RSA PKCS#1 v1.5 signing with a 2048-bit key")
            }
        }
    }
}

/// GOST key: scalar `d` from `coord_len` bytes of `rng`, redrawn while outside `[1, q − 1]`.
/// PKCS#8 holds the forms the reader picks without a certificate: a DER INTEGER (`d`
/// big-endian) for GOST 2004, a DER OCTET STRING (`d` little-endian) for GOST 2015.
fn gost_key(alg: GostAlg, rng: &mut ChaCha20Rng) -> (Secret, Vec<u8>, SubjectPublicKeyInfoOwned) {
    let curve = alg.curve();
    let mut d = vec![0; curve.coord_len()];
    let key = loop {
        rng.fill_bytes(&mut d);
        match SigningKey::from_scalar_be(curve, &d) {
            Ok(key) => break key,
            Err(GostError::InvalidScalar) => continue,
            Err(e) => panic!("GOST key: {e}"),
        }
    };
    let params = vec![
        ObjectIdentifier::new_unwrap(curve.curve_oid()),
        ObjectIdentifier::new_unwrap(curve.digest_param_oid()),
    ];
    let algorithm = AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap(curve.key_oid()),
        parameters: Some(Any::from_der(&der(&params)).expect("DER parameters")),
    };
    let private_key = match alg {
        GostAlg::Gost34310_2004 => der(&Uint::new(&d).expect("scalar INTEGER")),
        GostAlg::Gost3410_2015_512 => {
            let d_le: Vec<u8> = d.iter().rev().copied().collect();
            der(&OctetString::new(d_le).expect("scalar OCTET STRING"))
        }
    };
    let info = pkcs8::PrivateKeyInfoOwned {
        algorithm: algorithm.clone(),
        private_key: OctetString::new(private_key).expect("privateKey OCTET STRING"),
        public_key: None,
    };
    let xy = OctetString::new(key.verifying_key().to_kz_bytes()).expect("public key octets");
    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key: BitString::from_bytes(&der(&xy)).expect("public key BIT STRING"),
    };
    (Secret::Gost { alg, key }, der(&info), spki)
}

/// RSA-2048 key from `rsa` 0.9; its encodings cross into the `der` 0.8 types as DER bytes.
fn rsa_key(rng: &mut ChaCha20Rng) -> (Secret, Vec<u8>, SubjectPublicKeyInfoOwned) {
    let key = RsaPrivateKey::new(rng, RSA_BITS).expect("RSA key generation");
    let pkcs8_der = key
        .to_pkcs8_der()
        .expect("RSA PKCS#8 encoding")
        .as_bytes()
        .to_vec();
    let spki_der = key
        .to_public_key()
        .to_public_key_der()
        .expect("RSA SPKI encoding");
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("RSA SPKI");
    (Secret::Rsa(Box::new(key)), pkcs8_der, spki)
}

/// `TBSCertificate` of RFC 5280, encoded from the `x509-cert` field types. `x509-cert` 0.3 keeps
/// its own `TbsCertificate` fields private and builds certificates only through `signature` 3
/// signers, which neither `oncl-gost` nor `rsa` 0.9 provide.
#[derive(Sequence)]
struct TbsCertificate {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    version: Version,
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    extensions: Vec<Extension>,
}

/// `Certificate` of RFC 5280.
#[derive(Sequence)]
struct SignedCertificate {
    tbs_certificate: TbsCertificate,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

/// Contents of a certificate other than its keys.
pub(super) struct CertSpec {
    pub subject: Name,
    pub validity: Validity,
    /// Serial number bytes (big-endian, unsigned).
    pub serial: Vec<u8>,
    /// Extensions other than SubjectKeyIdentifier and AuthorityKeyIdentifier.
    pub extensions: Vec<Extension>,
}

/// Issuer of a certificate: its name and key.
#[derive(Clone, Copy)]
pub(super) struct Issuer<'a> {
    pub name: &'a Name,
    pub key: &'a Key,
}

/// Issues a v3 certificate for `subject_key`, signed by `issuer` (self-signed when `None`).
/// The extensions are `spec.extensions`, then SubjectKeyIdentifier, then — unless
/// self-signed — AuthorityKeyIdentifier.
pub(super) fn issue(
    spec: CertSpec,
    subject_key: &Key,
    issuer: Option<Issuer<'_>>,
    rng: &mut ChaCha20Rng,
) -> Vec<u8> {
    let self_signed = issuer.is_none();
    let issuer = issuer.unwrap_or(Issuer {
        name: &spec.subject,
        key: subject_key,
    });
    let mut extensions = spec.extensions;
    extensions.push(extension(
        false,
        &SubjectKeyIdentifier(octets(&subject_key.ski)),
    ));
    if !self_signed {
        extensions.push(extension(
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(octets(&issuer.key.ski)),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
        ));
    }
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&spec.serial).expect("serial number"),
        signature: issuer.key.signature_algorithm(),
        issuer: issuer.name.clone(),
        validity: spec.validity,
        subject: spec.subject.clone(),
        subject_public_key_info: subject_key.spki.clone(),
        extensions,
    };
    let tbs_der = der(&tbs);
    let signature = issuer.key.sign(&tbs_der, rng);
    let cert_der = der(&SignedCertificate {
        signature_algorithm: issuer.key.signature_algorithm(),
        tbs_certificate: tbs,
        signature: BitString::from_bytes(&signature).expect("signature BIT STRING"),
    });
    // The signature only verifies if `x509-cert` re-encodes the TBS byte for byte.
    let parsed = Certificate::from_der(&cert_der).expect("issued certificate parses");
    assert_eq!(der(parsed.tbs_certificate()), tbs_der, "TBS re-encoding");
    cert_der
}

/// Extension with the DER of `value` as `extnValue`.
pub(super) fn extension<T: AssociatedOid + Encode>(critical: bool, value: &T) -> Extension {
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(der(value)).expect("extnValue"),
    }
}

fn octets(bytes: &[u8]) -> OctetString {
    OctetString::new(bytes).expect("OCTET STRING")
}

fn der(value: &impl Encode) -> Vec<u8> {
    value.to_der().expect("DER encoding")
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::key::{PrivateKey, PublicKey, SigAlg};
    use rand_chacha::rand_core::SeedableRng;

    /// The PKCS#8 forms are the ones the reader picks without a certificate, so a key read on
    /// its own signs for the certificate's public key.
    #[test]
    fn pkcs8_reads_without_certificate() {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let kinds = [
            (KeyKind::Gost(GostAlg::Gost34310_2004), SigAlg::Gost2004),
            (
                KeyKind::Gost(GostAlg::Gost3410_2015_512),
                SigAlg::Gost2015_512,
            ),
            (KeyKind::Rsa, SigAlg::RsaSha256),
        ];
        for (kind, alg) in kinds {
            let key = Key::generate(kind, &mut rng);
            let private = PrivateKey::from_pkcs8_der(&key.pkcs8_der, None).unwrap();
            let sig = private.sign(alg, b"message").unwrap();
            PublicKey::from_spki(&key.spki)
                .unwrap()
                .verify(alg, b"message", &sig)
                .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        }
    }
}
