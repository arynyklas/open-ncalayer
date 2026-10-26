//! PKCS#12 writer: the Kalkan profile, and its variants for test fixtures.

use super::kdf::{self, Prf, Purpose};
use super::{
    Attribute, CertBag, ContentInfo, DigestInfo, EncryptedContentInfo, EncryptedData,
    EncryptedPrivateKeyInfo, MAX_ITERATIONS, MacData, Passwords, Pbes2Params, Pbkdf2Params, Pfx,
    Pkcs12Error, Pkcs12PbeParams, SafeBag,
};
use crate::key::{PrivateKey, key_id_bytes, spki_key_id_bytes};
use crate::oid;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockCipherEncrypt, BlockModeEncrypt, InnerIvInit, KeyInit, KeyIvInit};
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode, EncodeValue, Tag, TagNumber, Tagged};
use hmac::{Hmac, Mac};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use zeroize::Zeroize;

/// Salt length of every scheme and of the MAC (Kalkan: 20 bytes).
const SALT_LEN: usize = 20;

/// Password-based encryption scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pbe {
    /// pbewithSHAAnd40BitRC2-CBC.
    Rc2_40,
    /// pbeWithSHAAnd3-KeyTripleDES-CBC.
    TripleDes,
    /// PBES2: PBKDF2 without a PRF field (read as HMAC-SHA256 by Kalkan) and AES-256-CBC.
    Pbes2Aes256NoPrf,
}

/// Encryption profile of [`write()`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteOptions {
    /// Scheme for the private keys.
    pub key: Pbe,
    /// Scheme for the certificate bag container.
    pub certs: Pbe,
    /// Iteration count of every KDF and of the MAC.
    pub iterations: u32,
}

impl Default for WriteOptions {
    /// The Kalkan profile: 3DES keys, RC2-40 certificates, 1024 iterations.
    fn default() -> Self {
        WriteOptions {
            key: Pbe::TripleDes,
            certs: Pbe::Rc2_40,
            iterations: 1024,
        }
    }
}

/// One key with its certificate, if it has one. The PKCS#8 bytes are zeroized on drop.
#[derive(Clone)]
pub struct WriteEntry {
    /// Written as `friendlyName` (Kalkan: hex of the key identifier).
    pub alias: String,
    /// DER `PrivateKeyInfo`.
    pub pkcs8_der: Vec<u8>,
    /// DER certificate of the key.
    pub cert_der: Option<Vec<u8>>,
}

impl Drop for WriteEntry {
    fn drop(&mut self) {
        self.pkcs8_der.zeroize();
    }
}

/// Writes a PKCS#12 key store as Kalkan does: one unencrypted `data` safe with a
/// `pkcs8ShroudedKeyBag` per entry; then, unless there are no certificates at all, one
/// `encryptedData` safe with the entries' certificates followed by `other_certs` (without
/// attributes); and an HMAC-SHA1 MAC. Key bags and their certificate bags carry
/// `friendlyName` = alias and `localKeyId` = the key identifier (SHA-1 of the
/// `subjectPublicKey` BIT STRING contents) of the certificate, or of the key itself when the
/// entry has no certificate (Kalkan writes the hex-decoded alias there: the same for the keys
/// its provider generates, and written so for the legacy Applet's keys, whose alias is
/// their SHA-1 of the whole `SubjectPublicKeyInfo`). Salts (20 bytes) and IVs come from `fill_random`, so the
/// output is a function of the inputs and of `fill_random`.
///
/// # Errors
///
/// [`Pkcs12Error::Malformed`] if a certificate is not DER or a keyless entry's key cannot
/// be read; [`Pkcs12Error::Unsupported`] for a keyless entry of another key type.
///
/// # Panics
///
/// If `opts.iterations` is not in `1..=`[`MAX_ITERATIONS`] (the reader refuses other
/// counts).
pub fn write(
    entries: &[WriteEntry],
    other_certs: &[Vec<u8>],
    password: &str,
    opts: &WriteOptions,
    fill_random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, Pkcs12Error> {
    assert!(
        (1..=MAX_ITERATIONS).contains(&opts.iterations),
        "PKCS#12 iteration count must be in 1..={MAX_ITERATIONS}"
    );
    let passwords = Passwords::new(password);
    let mut key_bags = Vec::with_capacity(entries.len());
    let mut cert_bags = Vec::with_capacity(entries.len() + other_certs.len());
    for entry in entries {
        let attributes = Some(bag_attributes(&entry.alias, &local_key_id(entry)?));
        let (algorithm, encrypted) = encrypt(
            opts.key,
            &passwords,
            opts.iterations,
            fill_random,
            &entry.pkcs8_der,
        );
        let shrouded = EncryptedPrivateKeyInfo {
            encryption_algorithm: algorithm,
            encrypted_data: octets(encrypted),
        };
        key_bags.push(SafeBag {
            bag_id: oid::PKCS8_SHROUDED_KEY_BAG,
            bag_value: any(&shrouded),
            bag_attributes: attributes.clone(),
        });
        if let Some(cert_der) = &entry.cert_der {
            cert_bags.push(cert_bag(cert_der, attributes));
        }
    }
    for cert_der in other_certs {
        Certificate::from_der(cert_der)?;
        cert_bags.push(cert_bag(cert_der, None));
    }

    let mut safes = vec![ContentInfo {
        content_type: oid::DATA,
        content: Some(any(&octets(der(&key_bags)))),
    }];
    if !cert_bags.is_empty() {
        let (algorithm, encrypted) = encrypt(
            opts.certs,
            &passwords,
            opts.iterations,
            fill_random,
            &der(&cert_bags),
        );
        let encrypted_content = Any::new(
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(0),
            },
            encrypted,
        )
        .expect("encrypted content length fits DER");
        safes.push(ContentInfo {
            content_type: oid::ENCRYPTED_DATA,
            content: Some(any(&EncryptedData {
                version: 0,
                encrypted_content_info: EncryptedContentInfo {
                    content_type: oid::DATA,
                    content_encryption_algorithm: algorithm,
                    encrypted_content: Some(encrypted_content),
                },
            })),
        });
    }
    let auth_safe = der(&safes);

    let mut mac_salt = vec![0u8; SALT_LEN];
    fill_random(&mut mac_salt);
    let mac_key =
        kdf::pkcs12::<sha1::Sha1>(&passwords.bmp, &mac_salt, opts.iterations, Purpose::Mac, 20);
    let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(&mac_key).expect("any HMAC key size");
    hmac.update(&auth_safe);
    let mac = hmac.finalize().into_bytes().to_vec();

    let pfx = Pfx {
        version: 3,
        auth_safe: ContentInfo {
            content_type: oid::DATA,
            content: Some(any(&octets(auth_safe))),
        },
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: algorithm_id(oid::SHA1, Some(Any::null())),
                digest: octets(mac),
            },
            mac_salt: octets(mac_salt),
            iterations: opts.iterations,
        }),
    };
    Ok(der(&pfx))
}

fn cert_bag(cert_der: &[u8], attributes: Option<Any>) -> SafeBag {
    let cert_bag = CertBag {
        cert_id: oid::X509_CERTIFICATE,
        cert_value: octets(cert_der.to_vec()),
    };
    SafeBag {
        bag_id: oid::CERT_BAG,
        bag_value: any(&cert_bag),
        bag_attributes: attributes,
    }
}

/// `localKeyId`: the key identifier of the certificate's public key; for an entry without
/// a certificate the hex-decoded alias when it is the legacy Applet's identifier of the key
/// (SHA-1 of the whole `SubjectPublicKeyInfo`), as Kalkan writes the alias there, else the
/// key's key identifier.
fn local_key_id(entry: &WriteEntry) -> Result<Vec<u8>, Pkcs12Error> {
    let spki = match &entry.cert_der {
        Some(cert_der) => {
            let cert = Certificate::from_der(cert_der)?;
            return Ok(key_id_bytes(cert.tbs_certificate().subject_public_key_info()).to_vec());
        }
        None => PrivateKey::from_pkcs8_der(&entry.pkcs8_der, None)
            .map_err(super::read::key_error)?
            .public_key()
            .to_spki(),
    };
    let applet_id = spki_key_id_bytes(&spki);
    if entry.alias == super::hex(&applet_id) {
        return Ok(applet_id.to_vec());
    }
    Ok(key_id_bytes(&spki).to_vec())
}

/// `SET OF Attribute` with `friendlyName` and `localKeyId`, in DER order.
fn bag_attributes(alias: &str, local_key_id: &[u8]) -> Any {
    let name: Vec<u8> = alias.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let values = |value: Any| Any::new(Tag::Set, der(&value)).expect("attribute value fits DER");
    let mut attrs = [
        Attribute {
            oid: oid::FRIENDLY_NAME,
            values: values(Any::new(Tag::BmpString, name).expect("alias fits DER")),
        },
        Attribute {
            oid: oid::LOCAL_KEY_ID,
            values: values(any(&octets(local_key_id.to_vec()))),
        },
    ]
    .map(|a| der(&a));
    attrs.sort();
    Any::new(Tag::Set, attrs.concat()).expect("attributes fit DER")
}

/// Encrypts `data`, drawing salt and IV from `fill_random`.
fn encrypt(
    pbe: Pbe,
    passwords: &Passwords,
    iterations: u32,
    fill_random: &mut dyn FnMut(&mut [u8]),
    data: &[u8],
) -> (AlgorithmIdentifierOwned, Vec<u8>) {
    let mut salt = vec![0u8; SALT_LEN];
    fill_random(&mut salt);
    match pbe {
        Pbe::TripleDes | Pbe::Rc2_40 => {
            let (oid, key_len) = match pbe {
                Pbe::TripleDes => (oid::PBE_SHA_3DES, 24),
                _ => (oid::PBE_SHA_RC2_40, 5),
            };
            let k = kdf::pkcs12_key_iv(&passwords.bmp, &salt, iterations, key_len);
            let encrypted = match pbe {
                Pbe::TripleDes => cbc_encrypt(
                    des::TdesEde3::new_from_slice(&k.key).expect("24-byte 3DES key"),
                    &k.iv,
                    data,
                ),
                _ => cbc_encrypt(rc2::Rc2::new_with_eff_key_len(&k.key, 40), &k.iv, data),
            };
            let params = Pkcs12PbeParams {
                salt: octets(salt),
                iterations,
            };
            (algorithm_id(oid, Some(any(&params))), encrypted)
        }
        Pbe::Pbes2Aes256NoPrf => {
            let mut iv = vec![0u8; 16];
            fill_random(&mut iv);
            let key = kdf::pbkdf2_aes256(&passwords.utf8, &salt, iterations, Prf::HmacSha256);
            let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(&*key, &iv)
                .expect("AES-256 key and IV sizes")
                .encrypt_padded_vec::<Pkcs7>(data);
            let params = Pbes2Params {
                key_derivation_func: algorithm_id(
                    oid::PBKDF2,
                    Some(any(&Pbkdf2Params {
                        salt: octets(salt),
                        iteration_count: iterations,
                        key_length: None,
                        prf: None,
                    })),
                ),
                encryption_scheme: algorithm_id(oid::AES_256_CBC, Some(any(&octets(iv)))),
            };
            (algorithm_id(oid::PBES2, Some(any(&params))), encrypted)
        }
    }
}

fn cbc_encrypt<C: BlockCipherEncrypt>(cipher: C, iv: &[u8], data: &[u8]) -> Vec<u8> {
    cbc::Encryptor::inner_iv_slice_init(cipher, iv)
        .expect("8-byte IV")
        .encrypt_padded_vec::<Pkcs7>(data)
}

fn algorithm_id(oid: ObjectIdentifier, parameters: Option<Any>) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid, parameters }
}

fn octets(bytes: Vec<u8>) -> OctetString {
    OctetString::new(bytes).expect("length fits DER")
}

fn any<T: Tagged + EncodeValue>(value: &T) -> Any {
    Any::encode_from(value).expect("value encodes as DER")
}

fn der(value: &impl Encode) -> Vec<u8> {
    value.to_der().expect("value encodes as DER")
}
