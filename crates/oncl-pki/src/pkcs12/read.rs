//! PKCS#12 reader.

use super::kdf::{self, Purpose};
use super::{
    Attribute, CertBag, ContentInfo, Contents, EncryptedData, EncryptedPrivateKeyInfo, KeyEntry,
    MacData, Passwords, Pfx, Pkcs12Error, SafeBag, StoredKey, check_iterations, decrypt, hex,
};
use crate::ber;
use crate::cert::{self, Certificate};
use crate::key::{KeyError, PrivateKey};
use crate::oid;
use der::asn1::{Any, OctetString};
use der::{Decode, Reader, SliceReader, Tag, TagNumber, Tagged};
use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

/// Attributes of a bag that link keys to certificates.
#[derive(Default)]
struct BagAttributes {
    friendly_name: Option<String>,
    local_key_id: Option<Vec<u8>>,
}

struct KeyBag {
    pkcs8: Zeroizing<Vec<u8>>,
    attrs: BagAttributes,
}

struct CertBagEntry {
    cert: Certificate,
    attrs: BagAttributes,
}

impl KeyBag {
    /// `friendlyName`, else hex of `localKeyId`, else `"unmarked"`.
    fn alias(&self) -> String {
        self.attrs
            .friendly_name
            .clone()
            .or_else(|| self.attrs.local_key_id.as_deref().map(hex))
            .unwrap_or_else(|| "unmarked".to_owned())
    }
}

/// Opens a PKCS#12 key store (DER or BER) and returns its key entries sorted by alias.
///
/// A key is paired with the certificate carrying the same `localKeyId`, else the same
/// `friendlyName`, else the first certificate whose public key the private key matches
/// (bags without linking attributes); keys matching no certificate are skipped. Bags other
/// than `keyBag`, `pkcs8ShroudedKeyBag` and X.509 `certBag` are ignored.
///
/// # Errors
///
/// [`Pkcs12Error::WrongPassword`] if the MAC or a decryption fails,
/// [`Pkcs12Error::Malformed`] for invalid structures or keys that do not match their
/// certificates, [`Pkcs12Error::Unsupported`] for unsupported algorithms.
pub fn load(pfx: &[u8], password: &str) -> Result<Vec<KeyEntry>, Pkcs12Error> {
    let (keys, certs) = bags(pfx, password, None)?;
    Ok(paired(keys, certs)?.entries)
}

/// How much of a key store [`load_within`] reads: more is refused before any key
/// derivation that the excess would cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most key bags (encrypted or not), counted across the store.
    pub key_bags: usize,
    /// The most encrypted safes (each opened with a key derivation).
    pub encrypted_safes: usize,
}

/// What [`load_within`] reads from a key store.
#[derive(Clone, Debug)]
pub struct Loaded {
    /// The key entries, as [`load`] returns them.
    pub entries: Vec<KeyEntry>,
    /// The certificates no key pairs with, in stored order.
    pub other_certs: Vec<Certificate>,
}

/// Opens a key store from an untrusted source (such as a page) like [`load`], in one pass
/// that also returns the certificates no key pairs with. A store with more encrypted safes
/// than `limits` allows is refused before the MAC or any decryption; one with more key bags,
/// as soon as they are counted: before the MAC for the bags in plain safes, and before any
/// key is decrypted for the rest.
///
/// # Errors
///
/// As [`load`]; [`Pkcs12Error::Unsupported`] for a store over `limits`.
pub fn load_within(pfx: &[u8], password: &str, limits: &Limits) -> Result<Loaded, Pkcs12Error> {
    let (keys, certs) = bags(pfx, password, Some(limits))?;
    paired(keys, certs)
}

/// The keys that pair with a certificate, sorted by alias, and the certificates no key
/// pairs with.
fn paired(keys: Vec<KeyBag>, certs: Vec<CertBagEntry>) -> Result<Loaded, Pkcs12Error> {
    let mut used = vec![false; certs.len()];
    let mut pairs = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some((private, cert)) = key_with_cert(&key, &certs)? {
            used[cert] = true;
            pairs.push((key.alias(), private, cert));
        }
    }
    let mut entries: Vec<KeyEntry> = pairs
        .into_iter()
        .map(|(alias, key, cert)| KeyEntry {
            alias,
            key,
            cert: certs[cert].cert.clone(),
        })
        .collect();
    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    let other_certs = certs
        .into_iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|(entry, _)| entry.cert)
        .collect();
    Ok(Loaded {
        entries,
        other_certs,
    })
}

/// Opens a PKCS#12 key store like [`load`], keeping every key. A key that no certificate
/// pairs with must carry a `localKeyId` (Kalkan writes the key identifier there): the key
/// is the PKCS#8 form whose key identifier it is. Certificates that pair with no key are
/// returned apart, in stored order.
///
/// # Errors
///
/// As [`load`]; also [`Pkcs12Error::Malformed`] / [`Pkcs12Error::Unsupported`] for a key
/// without a certificate that has no `localKeyId`, matches none, or cannot be read.
pub fn load_contents(pfx: &[u8], password: &str) -> Result<Contents, Pkcs12Error> {
    let (keys, certs) = bags(pfx, password, None)?;
    let mut paired = vec![false; certs.len()];
    let mut stored = Vec::with_capacity(keys.len());
    for key in keys {
        let (private, cert) = match key_with_cert(&key, &certs)? {
            Some((private, cert)) => {
                paired[cert] = true;
                (private, Some(certs[cert].cert.clone()))
            }
            None => {
                let id = key.attrs.local_key_id.as_deref().ok_or_else(|| {
                    Pkcs12Error::Malformed("key without certificate and localKeyId".into())
                })?;
                let private = PrivateKey::from_pkcs8_der_with_key_id(&key.pkcs8, id).map_err(
                    |e| match e {
                        KeyError::KeyMismatch => Pkcs12Error::Malformed(
                            "key without certificate does not match its localKeyId".into(),
                        ),
                        e => key_error(e),
                    },
                )?;
                (private, None)
            }
        };
        stored.push(StoredKey {
            alias: key.alias(),
            key: private,
            cert,
        });
    }
    stored.sort_by(|a, b| a.alias.cmp(&b.alias));
    let other_certs = certs
        .into_iter()
        .zip(paired)
        .filter(|(_, paired)| !paired)
        .map(|(entry, _)| entry.cert)
        .collect();
    Ok(Contents {
        keys: stored,
        other_certs,
    })
}

/// A safe of the authenticated safe: its bags, or still encrypted.
enum Safe<'a> {
    Bags(Vec<SafeBag>),
    Encrypted(&'a ContentInfo),
}

/// The number of key bags among `bags`.
fn key_bag_count(bags: &[SafeBag]) -> usize {
    bags.iter()
        .filter(|bag| matches!(bag.bag_id, oid::PKCS8_SHROUDED_KEY_BAG | oid::KEY_BAG))
        .count()
}

/// `Err` if `key_bags` are more than `limits` allows.
fn check_key_bags(key_bags: usize, limits: Option<&Limits>) -> Result<(), Pkcs12Error> {
    match limits {
        Some(limits) if key_bags > limits.key_bags => Err(Pkcs12Error::Unsupported(format!(
            "more than {} key bags",
            limits.key_bags
        ))),
        _ => Ok(()),
    }
}

/// The key and certificate bags of a key store, decrypted, in stored order; within
/// `limits`, if given, checked before the key derivations they bound.
fn bags(
    pfx: &[u8],
    password: &str,
    limits: Option<&Limits>,
) -> Result<(Vec<KeyBag>, Vec<CertBagEntry>), Pkcs12Error> {
    let der = ber::to_der(pfx)?;
    let pfx = Pfx::from_der(&der)?;
    let auth_safe = data_content(&pfx.auth_safe)?;
    let infos = Vec::<ContentInfo>::from_der(&ber::to_der(auth_safe.as_bytes())?)?;
    let mut safes = Vec::with_capacity(infos.len());
    for info in &infos {
        safes.push(match info.content_type {
            oid::DATA => Safe::Bags(safe_bags(data_content(info)?.as_bytes())?),
            oid::ENCRYPTED_DATA => Safe::Encrypted(info),
            other => {
                return Err(Pkcs12Error::Unsupported(format!(
                    "authenticated safe content type {other}"
                )));
            }
        });
    }
    if let Some(limits) = limits {
        let encrypted = safes
            .iter()
            .filter(|safe| matches!(safe, Safe::Encrypted(_)))
            .count();
        if encrypted > limits.encrypted_safes {
            return Err(Pkcs12Error::Unsupported(format!(
                "more than {} encrypted safes",
                limits.encrypted_safes
            )));
        }
    }
    let plain_key_bags = safes
        .iter()
        .map(|safe| match safe {
            Safe::Bags(bags) => key_bag_count(bags),
            Safe::Encrypted(_) => 0,
        })
        .sum();
    check_key_bags(plain_key_bags, limits)?;

    let mut passwords = Passwords::new(password);
    if let Some(mac) = &pfx.mac_data
        && !mac_matches(mac, &passwords.bmp, auth_safe.as_bytes())?
    {
        // OpenSSL encodes an empty password as a lone terminator; Kalkan retries with it.
        let double_zero = [0u8, 0];
        if password.is_empty() && mac_matches(mac, &double_zero, auth_safe.as_bytes())? {
            passwords.bmp = Zeroizing::new(double_zero.to_vec());
        } else {
            return Err(Pkcs12Error::WrongPassword);
        }
    }

    let mut opened = Vec::with_capacity(safes.len());
    for safe in safes {
        opened.push(match safe {
            Safe::Bags(bags) => bags,
            Safe::Encrypted(info) => {
                let data: EncryptedData = content(info)?.decode_as()?;
                let eci = &data.encrypted_content_info;
                let encrypted = encrypted_content(eci.encrypted_content.as_ref())?;
                let decrypted = decrypt(&eci.content_encryption_algorithm, &passwords, &encrypted)?;
                safe_bags(&decrypted)?
            }
        });
    }
    check_key_bags(opened.iter().map(|bags| key_bag_count(bags)).sum(), limits)?;

    let mut keys = Vec::new();
    let mut certs = Vec::new();
    for bag in opened.into_iter().flatten() {
        collect_bag(bag, &passwords, &mut keys, &mut certs)?;
    }
    Ok((keys, certs))
}

/// The bags of a safe's contents (DER or BER).
fn safe_bags(contents: &[u8]) -> Result<Vec<SafeBag>, Pkcs12Error> {
    let der = Zeroizing::new(ber::to_der(contents)?);
    Ok(Vec::<SafeBag>::from_der(&der)?)
}

fn content(info: &ContentInfo) -> Result<&Any, Pkcs12Error> {
    info.content
        .as_ref()
        .ok_or_else(|| Pkcs12Error::Malformed(format!("{} without content", info.content_type)))
}

/// Contents of an id-data `ContentInfo`.
fn data_content(info: &ContentInfo) -> Result<OctetString, Pkcs12Error> {
    if info.content_type != oid::DATA {
        return Err(Pkcs12Error::Unsupported(format!(
            "content type {} (only password integrity is supported)",
            info.content_type
        )));
    }
    Ok(content(info)?.decode_as()?)
}

/// Bytes of `[0] IMPLICIT OCTET STRING`, primitive or constructed from OCTET STRINGs.
fn encrypted_content(any: Option<&Any>) -> Result<Zeroizing<Vec<u8>>, Pkcs12Error> {
    let any = any.ok_or_else(|| Pkcs12Error::Malformed("encryptedData without content".into()))?;
    match any.tag() {
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        } => Ok(Zeroizing::new(any.value().to_vec())),
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(0),
        } => {
            let mut out = Zeroizing::new(Vec::new());
            for segment in decode_all::<OctetString>(any.value())? {
                out.extend_from_slice(segment.as_bytes());
            }
            Ok(out)
        }
        other => Err(Pkcs12Error::Malformed(format!(
            "encryptedContent has tag {other}"
        ))),
    }
}

/// Elements of a SET / SEQUENCE body, in stored order.
fn decode_all<T: for<'a> Decode<'a, Error = der::Error>>(body: &[u8]) -> der::Result<Vec<T>> {
    let mut reader = SliceReader::new(body)?;
    let mut out = Vec::new();
    while !reader.is_finished() {
        out.push(T::decode(&mut reader)?);
    }
    Ok(out)
}

fn mac_matches(mac: &MacData, password: &[u8], data: &[u8]) -> Result<bool, Pkcs12Error> {
    let salt = mac.mac_salt.as_bytes();
    let iterations = check_iterations(mac.iterations)?;
    let expected = mac.mac.digest.as_bytes();
    Ok(match mac.mac.algorithm.oid {
        oid::SHA1 => {
            let key = kdf::pkcs12::<sha1::Sha1>(password, salt, iterations, Purpose::Mac, 20);
            let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(&key).expect("any HMAC key size");
            hmac.update(data);
            hmac.verify_slice(expected).is_ok()
        }
        oid::SHA256 => {
            let key = kdf::pkcs12::<sha2::Sha256>(password, salt, iterations, Purpose::Mac, 32);
            let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&key).expect("any HMAC key size");
            hmac.update(data);
            hmac.verify_slice(expected).is_ok()
        }
        other => return Err(Pkcs12Error::Unsupported(format!("MAC digest {other}"))),
    })
}

fn collect_bag(
    bag: SafeBag,
    passwords: &Passwords,
    keys: &mut Vec<KeyBag>,
    certs: &mut Vec<CertBagEntry>,
) -> Result<(), Pkcs12Error> {
    let attrs = bag_attributes(bag.bag_attributes.as_ref())?;
    match bag.bag_id {
        oid::PKCS8_SHROUDED_KEY_BAG => {
            let info: EncryptedPrivateKeyInfo = bag.bag_value.decode_as()?;
            let pkcs8 = decrypt(
                &info.encryption_algorithm,
                passwords,
                info.encrypted_data.as_bytes(),
            )?;
            keys.push(KeyBag { pkcs8, attrs });
        }
        oid::KEY_BAG => {
            let pkcs8 = Zeroizing::new(der::Encode::to_der(&bag.bag_value)?);
            keys.push(KeyBag { pkcs8, attrs });
        }
        oid::CERT_BAG => {
            let cert_bag: CertBag = bag.bag_value.decode_as()?;
            if cert_bag.cert_id == oid::X509_CERTIFICATE {
                let cert = cert::parse(cert_bag.cert_value.as_bytes())
                    .map_err(|e| Pkcs12Error::Malformed(e.to_string()))?;
                certs.push(CertBagEntry { cert, attrs });
            }
        }
        _ => {}
    }
    Ok(())
}

fn bag_attributes(set: Option<&Any>) -> Result<BagAttributes, Pkcs12Error> {
    let mut attrs = BagAttributes::default();
    let Some(set) = set else {
        return Ok(attrs);
    };
    if set.tag() != Tag::Set {
        return Err(Pkcs12Error::Malformed(
            "bag attributes are not a SET".into(),
        ));
    }
    for attr in decode_all::<Attribute>(set.value())? {
        let Some(value) = decode_all::<Any>(attr.values.value())?.into_iter().next() else {
            continue;
        };
        match attr.oid {
            oid::FRIENDLY_NAME => attrs.friendly_name = Some(string_value(&value)?),
            oid::LOCAL_KEY_ID => {
                attrs.local_key_id = Some(value.decode_as::<OctetString>()?.as_bytes().to_vec());
            }
            _ => {}
        }
    }
    Ok(attrs)
}

/// `friendlyName` value: BMPString (UTF-16BE, as Java reads it) or UTF8String.
fn string_value(value: &Any) -> Result<String, Pkcs12Error> {
    match value.tag() {
        Tag::BmpString => {
            let (pairs, rest) = value.value().as_chunks::<2>();
            if !rest.is_empty() {
                return Err(Pkcs12Error::Malformed("odd-length BMPString".into()));
            }
            let units = pairs.iter().map(|&pair| u16::from_be_bytes(pair));
            Ok(char::decode_utf16(units)
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect())
        }
        Tag::Utf8String => Ok(value.decode_as::<String>()?),
        other => Err(Pkcs12Error::Malformed(format!(
            "friendlyName has tag {other}"
        ))),
    }
}

/// Private key of a key bag with the index of its certificate: the one linked by attributes
/// (which the key must match), else the first certificate the key matches. `None` if there
/// is none.
fn key_with_cert(
    key: &KeyBag,
    certs: &[CertBagEntry],
) -> Result<Option<(PrivateKey, usize)>, Pkcs12Error> {
    if let Some(cert) = linked_cert(&key.attrs, certs) {
        let private =
            PrivateKey::from_pkcs8_der(&key.pkcs8, Some(&certs[cert].cert)).map_err(key_error)?;
        return Ok(Some((private, cert)));
    }
    // Any error here means "not this certificate": another key, another key type, or a
    // certificate (e.g. of a CA) whose key type is not supported.
    Ok(certs.iter().enumerate().find_map(|(i, entry)| {
        PrivateKey::from_pkcs8_der(&key.pkcs8, Some(&entry.cert))
            .ok()
            .map(|private| (private, i))
    }))
}

pub(super) fn key_error(e: KeyError) -> Pkcs12Error {
    match e {
        KeyError::UnknownKeyAlgorithm(alg) => {
            Pkcs12Error::Unsupported(format!("key algorithm {alg}"))
        }
        e => Pkcs12Error::Malformed(e.to_string()),
    }
}

fn linked_cert(key: &BagAttributes, certs: &[CertBagEntry]) -> Option<usize> {
    let by_id = key.local_key_id.as_ref().and_then(|id| {
        certs
            .iter()
            .position(|c| c.attrs.local_key_id.as_ref() == Some(id))
    });
    let by_name = || {
        key.friendly_name.as_ref().and_then(|name| {
            certs
                .iter()
                .position(|c| c.attrs.friendly_name.as_ref() == Some(name))
        })
    };
    by_id.or_else(by_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{PublicKey, SigAlg};
    use der::Encode;
    use hex_literal::hex;
    use oncl_testkit::{fixture, read};

    fn any(value: &(impl Tagged + der::EncodeValue)) -> Any {
        Any::encode_from(value).unwrap()
    }

    fn octets(bytes: Vec<u8>) -> OctetString {
        OctetString::new(bytes).unwrap()
    }

    /// Unencrypted RSA `keyBag` with optional attributes.
    fn key_bag(attributes: Option<Any>) -> SafeBag {
        SafeBag {
            bag_id: oid::KEY_BAG,
            bag_value: Any::from_der(&read(fixture("openssl/rsa.pk8.der"))).unwrap(),
            bag_attributes: attributes,
        }
    }

    /// `certBag` without attributes.
    fn cert_bag(path: &str) -> SafeBag {
        SafeBag {
            bag_id: oid::CERT_BAG,
            bag_value: any(&CertBag {
                cert_id: oid::X509_CERTIFICATE,
                cert_value: octets(read(fixture(path))),
            }),
            bag_attributes: None,
        }
    }

    /// PFX without MAC holding one unencrypted `data` safe with `bags`.
    fn pfx(bags: Vec<SafeBag>) -> Vec<u8> {
        let safe = ContentInfo {
            content_type: oid::DATA,
            content: Some(any(&octets(bags.to_der().unwrap()))),
        };
        Pfx {
            version: 3,
            auth_safe: ContentInfo {
                content_type: oid::DATA,
                content: Some(any(&octets(vec![safe].to_der().unwrap()))),
            },
            mac_data: None,
        }
        .to_der()
        .unwrap()
    }

    fn assert_key_matches_cert(entry: &KeyEntry) {
        let public =
            PublicKey::from_spki(entry.cert.tbs_certificate().subject_public_key_info()).unwrap();
        let sig = entry.key.sign(SigAlg::RsaSha256, b"m").unwrap();
        assert_eq!(public.verify(SigAlg::RsaSha256, b"m", &sig), Ok(()));
    }

    #[test]
    fn attribute_less_bags_link_by_key_and_are_unmarked() {
        let rsa_cert = read(fixture("openssl/rsa.cer"));
        // A CA certificate of another key (GOST) comes first and must be skipped.
        let p12 = pfx(vec![
            cert_bag("nca/prod/ncagost22.der"),
            key_bag(None),
            cert_bag("openssl/rsa.cer"),
        ]);
        let entries = load(&p12, "any").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "unmarked");
        assert_eq!(entries[0].cert.to_der().unwrap(), rsa_cert);
        assert_key_matches_cert(&entries[0]);
    }

    #[test]
    fn key_with_unmatched_attributes_links_by_key() {
        // friendlyName on the key only: no certificate carries it.
        let name = Attribute {
            oid: oid::FRIENDLY_NAME,
            values: Any::new(
                Tag::Set,
                Any::new(Tag::BmpString, hex!("006b 0065 0079"))
                    .unwrap()
                    .to_der()
                    .unwrap(),
            )
            .unwrap(),
        };
        let attrs = Any::new(Tag::Set, name.to_der().unwrap()).unwrap();
        let p12 = pfx(vec![key_bag(Some(attrs)), cert_bag("openssl/rsa.cer")]);
        let entries = load(&p12, "").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "key");
        assert_key_matches_cert(&entries[0]);
    }

    #[test]
    fn key_matching_no_certificate_is_skipped() {
        let p12 = pfx(vec![key_bag(None), cert_bag("nca/prod/ncarsa22.der")]);
        assert!(load(&p12, "").unwrap().is_empty());
    }

    #[test]
    fn load_contents_keeps_keyless_keys_and_other_certificates() {
        let p12 = pfx(vec![
            cert_bag("nca/prod/ncarsa22.der"),
            key_bag(None),
            cert_bag("openssl/rsa.cer"),
            cert_bag("nca/prod/ncagost22.der"),
        ]);
        let contents = load_contents(&p12, "").unwrap();
        assert_eq!(contents.keys.len(), 1);
        assert_eq!(contents.keys[0].alias, "unmarked");
        assert_eq!(
            contents.keys[0].cert.as_ref().unwrap().to_der().unwrap(),
            read(fixture("openssl/rsa.cer"))
        );
        let others: Vec<Vec<u8>> = contents
            .other_certs
            .iter()
            .map(|c| c.to_der().unwrap())
            .collect();
        assert_eq!(
            others,
            [
                read(fixture("nca/prod/ncarsa22.der")),
                read(fixture("nca/prod/ncagost22.der"))
            ]
        );

        // Without its certificate the key is found by its localKeyId (the key identifier).
        let rsa = PrivateKey::from_pkcs8_der(&read(fixture("openssl/rsa.pk8.der")), None).unwrap();
        let id = crate::key::key_id_bytes(&rsa.public_key().to_spki());
        let p12 = pfx(vec![
            key_bag(Some(local_key_id(&id))),
            cert_bag("nca/prod/ncarsa22.der"),
        ]);
        let contents = load_contents(&p12, "").unwrap();
        assert_eq!(contents.keys.len(), 1);
        assert!(contents.keys[0].cert.is_none());
        assert_eq!(
            *contents.keys[0].key.to_pkcs8_der().unwrap(),
            read(fixture("openssl/rsa.pk8.der"))
        );
        assert_eq!(contents.other_certs.len(), 1);

        // Without a localKeyId, or with another one, a keyless key is not guessed.
        for attrs in [None, Some(local_key_id(&[0; 20]))] {
            let p12 = pfx(vec![key_bag(attrs), cert_bag("nca/prod/ncarsa22.der")]);
            assert!(matches!(
                load_contents(&p12, ""),
                Err(Pkcs12Error::Malformed(_))
            ));
        }
    }

    /// Bag attributes with `localKeyId` = `id`.
    fn local_key_id(id: &[u8]) -> Any {
        let attribute = Attribute {
            oid: oid::LOCAL_KEY_ID,
            values: Any::new(Tag::Set, octets(id.to_vec()).to_der().unwrap()).unwrap(),
        };
        Any::new(Tag::Set, attribute.to_der().unwrap()).unwrap()
    }

    #[test]
    fn openssl_empty_password_mac_needs_double_zero() {
        let der = oncl_testkit::read(oncl_testkit::fixture("openssl/rsa-empty.p12"));
        let pfx = Pfx::from_der(&der).unwrap();
        let data = data_content(&pfx.auth_safe).unwrap();
        let mac = pfx.mac_data.as_ref().unwrap();
        assert!(!mac_matches(mac, &[], data.as_bytes()).unwrap());
        assert!(mac_matches(mac, &[0, 0], data.as_bytes()).unwrap());
    }

    #[test]
    fn encrypted_content_primitive_or_constructed() {
        let primitive = Any::from_der(&hex!("8003 aabbcc")).unwrap();
        assert_eq!(
            *encrypted_content(Some(&primitive)).unwrap(),
            hex!("aabbcc")
        );
        let constructed = Any::from_der(&hex!("a007 0402aabb 0401cc")).unwrap();
        assert_eq!(
            *encrypted_content(Some(&constructed)).unwrap(),
            hex!("aabbcc")
        );
        let wrong = Any::from_der(&hex!("0403 aabbcc")).unwrap();
        assert!(encrypted_content(Some(&wrong)).is_err());
        assert!(encrypted_content(None).is_err());
    }

    #[test]
    fn friendly_name_is_utf16_be() {
        let bmp = Any::from_der(&hex!("1e08 0422 0435 0441 0442")).unwrap();
        assert_eq!(string_value(&bmp).unwrap(), "Тест");
        let utf8 = Any::from_der(&hex!("0c03 616263")).unwrap();
        assert_eq!(string_value(&utf8).unwrap(), "abc");
    }

    /// A MAC no password matches: refused only after its key derivation.
    fn bogus_mac() -> MacData {
        MacData {
            mac: super::super::DigestInfo {
                algorithm: spki::AlgorithmIdentifierOwned {
                    oid: oid::SHA1,
                    parameters: None,
                },
                digest: octets(vec![0; 20]),
            },
            mac_salt: octets(vec![1; 20]),
            iterations: 1,
        }
    }

    /// An encrypted safe that opens only through a key derivation.
    fn encrypted_safe() -> ContentInfo {
        let params = super::super::Pkcs12PbeParams {
            salt: octets(vec![2; 20]),
            iterations: 1,
        };
        ContentInfo {
            content_type: oid::ENCRYPTED_DATA,
            content: Some(any(&EncryptedData {
                version: 0,
                encrypted_content_info: super::super::EncryptedContentInfo {
                    content_type: oid::DATA,
                    content_encryption_algorithm: spki::AlgorithmIdentifierOwned {
                        oid: oid::PBE_SHA_3DES,
                        parameters: Some(any(&params)),
                    },
                    encrypted_content: Some(
                        Any::new(
                            Tag::ContextSpecific {
                                constructed: false,
                                number: TagNumber(0),
                            },
                            vec![0u8; 16],
                        )
                        .unwrap(),
                    ),
                },
            })),
        }
    }

    /// A PFX of `safes` with a MAC no password matches.
    fn pfx_of(safes: Vec<ContentInfo>) -> Vec<u8> {
        Pfx {
            version: 3,
            auth_safe: ContentInfo {
                content_type: oid::DATA,
                content: Some(any(&octets(safes.to_der().unwrap()))),
            },
            mac_data: Some(bogus_mac()),
        }
        .to_der()
        .unwrap()
    }

    fn plain_safe(bags: Vec<SafeBag>) -> ContentInfo {
        ContentInfo {
            content_type: oid::DATA,
            content: Some(any(&octets(bags.to_der().unwrap()))),
        }
    }

    const LIMITS: Limits = Limits {
        key_bags: 2,
        encrypted_safes: 1,
    };

    #[test]
    fn too_many_key_bags_are_refused_before_any_key_derivation() {
        let store = pfx_of(vec![plain_safe(key_bags(3))]);
        // Without limits the MAC is checked first, and fails.
        assert!(matches!(load(&store, "x"), Err(Pkcs12Error::WrongPassword)));
        let e = load_within(&store, "x", &LIMITS).unwrap_err();
        assert!(
            matches!(&e, Pkcs12Error::Unsupported(text) if text.contains("key bags")),
            "{e}"
        );
        // At the limit the store is read as usual.
        let store = pfx_of(vec![plain_safe(key_bags(2))]);
        assert_eq!(
            load_within(&store, "x", &LIMITS).unwrap_err(),
            Pkcs12Error::WrongPassword
        );
    }

    #[test]
    fn too_many_encrypted_safes_are_refused_before_any_key_derivation() {
        let store = pfx_of(vec![encrypted_safe(), encrypted_safe()]);
        assert!(matches!(load(&store, "x"), Err(Pkcs12Error::WrongPassword)));
        let e = load_within(&store, "x", &LIMITS).unwrap_err();
        assert!(
            matches!(&e, Pkcs12Error::Unsupported(text) if text.contains("encrypted")),
            "{e}"
        );
    }

    #[test]
    fn load_within_returns_entries_and_unpaired_certificates() {
        let p12 = pfx(vec![
            cert_bag("nca/prod/ncarsa22.der"),
            key_bag(None),
            cert_bag("openssl/rsa.cer"),
        ]);
        let loaded = load_within(&p12, "", &LIMITS).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_key_matches_cert(&loaded.entries[0]);
        assert_eq!(
            loaded.other_certs[0].to_der().unwrap(),
            read(fixture("nca/prod/ncarsa22.der"))
        );
        assert_eq!(loaded.other_certs.len(), 1);
        // A key no certificate pairs with is skipped, as `load` does.
        let p12 = pfx(vec![key_bag(None), cert_bag("nca/prod/ncarsa22.der")]);
        let loaded = load_within(&p12, "", &LIMITS).unwrap();
        assert!(loaded.entries.is_empty());
        assert_eq!(loaded.other_certs.len(), 1);
    }

    fn key_bags(count: usize) -> Vec<SafeBag> {
        (0..count).map(|_| key_bag(None)).collect()
    }
}
