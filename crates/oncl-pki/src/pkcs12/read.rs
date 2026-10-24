//! PKCS#12 reader.

use super::kdf::{self, Purpose};
use super::{
    Attribute, CertBag, ContentInfo, EncryptedData, EncryptedPrivateKeyInfo, KeyEntry, MacData,
    Passwords, Pfx, Pkcs12Error, SafeBag, check_iterations, decrypt, hex,
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

/// Opens a PKCS#12 key store (DER or BER) and returns its key entries sorted by alias.
///
/// A key is paired with the certificate carrying the same `localKeyId`, else the same
/// `friendlyName`; keys without a certificate are skipped. Bags other than `keyBag`,
/// `pkcs8ShroudedKeyBag` and X.509 `certBag` are ignored.
///
/// # Errors
///
/// [`Pkcs12Error::WrongPassword`] if the MAC or a decryption fails,
/// [`Pkcs12Error::Malformed`] for invalid structures or keys that do not match their
/// certificates, [`Pkcs12Error::Unsupported`] for unsupported algorithms.
pub fn load(pfx: &[u8], password: &str) -> Result<Vec<KeyEntry>, Pkcs12Error> {
    let der = ber::to_der(pfx)?;
    let pfx = Pfx::from_der(&der)?;
    let auth_safe = data_content(&pfx.auth_safe)?;
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

    let mut keys = Vec::new();
    let mut certs = Vec::new();
    let infos = Vec::<ContentInfo>::from_der(&ber::to_der(auth_safe.as_bytes())?)?;
    for info in &infos {
        let safe_contents = match info.content_type {
            oid::DATA => Zeroizing::new(data_content(info)?.as_bytes().to_vec()),
            oid::ENCRYPTED_DATA => {
                let data: EncryptedData = content(info)?.decode_as()?;
                let eci = &data.encrypted_content_info;
                let encrypted = encrypted_content(eci.encrypted_content.as_ref())?;
                decrypt(&eci.content_encryption_algorithm, &passwords, &encrypted)?
            }
            other => {
                return Err(Pkcs12Error::Unsupported(format!(
                    "authenticated safe content type {other}"
                )));
            }
        };
        let safe_contents = Zeroizing::new(ber::to_der(&safe_contents)?);
        for bag in Vec::<SafeBag>::from_der(&safe_contents)? {
            collect_bag(bag, &passwords, &mut keys, &mut certs)?;
        }
    }

    let mut entries = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(cert) = linked_cert(&key.attrs, &certs) else {
            continue;
        };
        let private = PrivateKey::from_pkcs8_der(&key.pkcs8, Some(cert)).map_err(|e| match e {
            KeyError::UnknownKeyAlgorithm(alg) => {
                Pkcs12Error::Unsupported(format!("key algorithm {alg}"))
            }
            e => Pkcs12Error::Malformed(e.to_string()),
        })?;
        let alias = key
            .attrs
            .friendly_name
            .clone()
            .or_else(|| key.attrs.local_key_id.as_deref().map(hex))
            .unwrap_or_else(|| "unmarked".to_owned());
        entries.push(KeyEntry {
            alias,
            key: private,
            cert: cert.clone(),
        });
    }
    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(entries)
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

fn linked_cert<'a>(key: &BagAttributes, certs: &'a [CertBagEntry]) -> Option<&'a Certificate> {
    let by_id = key.local_key_id.as_ref().and_then(|id| {
        certs
            .iter()
            .find(|c| c.attrs.local_key_id.as_ref() == Some(id))
    });
    let by_name = || {
        key.friendly_name.as_ref().and_then(|name| {
            certs
                .iter()
                .find(|c| c.attrs.friendly_name.as_ref() == Some(name))
        })
    };
    by_id.or_else(by_name).map(|c| &c.cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

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
}
