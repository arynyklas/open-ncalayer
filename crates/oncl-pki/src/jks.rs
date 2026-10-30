//! Java KeyStore (Sun JKS, Kalkan's `JKS`/`CaseExactJKS`) files, read-only, as Kalkan's
//! `JavaKeyStore` reads them.
//!
//! - Layout (big-endian): magic `FEEDFEED`, version 1 or 2, the entry count, the entries,
//!   then a SHA-1 digest of the password (UTF-16BE), the text `Mighty Aphrodite` and every
//!   byte before the digest. A digest that does not match means a wrong password.
//! - A private-key entry (tag 1): alias (Java modified UTF-8), date, a DER
//!   `EncryptedPrivateKeyInfo` protected with Sun's `KeyProtector`
//!   (1.3.6.1.4.1.42.2.17.1.1: 20-byte salt, the PKCS#8 key XORed with the chain
//!   `SHA-1(password ‖ previous block)` seeded by the salt, then `SHA-1(password ‖ key)`),
//!   then its certificate chain. Version 2 names each certificate's type (`X.509`).
//! - A trusted-certificate entry (tag 2): alias, date, a certificate.
//!
//! NCALayer opens a JKS with one password for the store and its keys. Kalkan's
//! `KeyProtector` turns every recovered key into an RSA key; GOST keys are read here too,
//! in the PKCS#8 forms [`PrivateKey::from_pkcs8_der`] accepts.

use crate::cert::{self, Certificate};
use crate::key::PrivateKey;
use crate::pkcs12::{EncryptedPrivateKeyInfo, KeyEntry};
use der::Decode;
use der::asn1::ObjectIdentifier;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// `FEEDFEED`.
const MAGIC: u32 = 0xFEED_FEED;
/// Sun's `KeyProtector` algorithm.
const KEY_PROTECTOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.42.2.17.1.1");
/// What the integrity digest hashes after the password.
const WHITENER: &[u8] = b"Mighty Aphrodite";
const DIGEST_LEN: usize = 20;
const PRIVATE_KEY_TAG: u32 = 1;
const TRUSTED_CERT_TAG: u32 = 2;

/// Error of reading a JKS file.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JksError {
    /// The integrity digest or a key's check does not match this password.
    #[error("wrong JKS password")]
    WrongPassword,
    /// The input is not a valid JKS file.
    #[error("malformed JKS: {0}")]
    Malformed(String),
    /// The file uses a certificate type or key protection that is not supported.
    #[error("unsupported JKS feature: {0}")]
    Unsupported(String),
}

/// Whether `data` starts like a JKS file (its magic number).
pub fn is_jks(data: &[u8]) -> bool {
    data.get(..4) == Some(&MAGIC.to_be_bytes()[..])
}

/// Opens a JKS file and returns its private keys that have a certificate (the first of the
/// chain), sorted by alias. Trusted-certificate entries and keys without a certificate are
/// skipped.
///
/// # Errors
///
/// [`JksError::Malformed`] for an invalid layout, certificate or key, or a key that does not
/// match its certificate; [`JksError::Unsupported`] for certificate types other than X.509
/// and key protections other than Sun's; [`JksError::WrongPassword`] if the integrity
/// digest or a key's check fails.
pub fn load(data: &[u8], password: &str) -> Result<Vec<KeyEntry>, JksError> {
    let mut r = Reader { data, pos: 0 };
    let magic = r.u32()?;
    let version = r.u32()?;
    if magic != MAGIC || !(version == 1 || version == 2) {
        return Err(JksError::Malformed("not a JKS file".to_owned()));
    }
    let count = r.u32()?;
    let mut keys = Vec::new();
    for _ in 0..count {
        match r.u32()? {
            PRIVATE_KEY_TAG => {
                let alias = r.utf()?;
                r.take(8)?; // date
                let protected = r.block()?;
                let certs = r.u32()?;
                let mut first = None;
                for _ in 0..certs {
                    let cert = r.cert(version)?;
                    first.get_or_insert(cert);
                }
                if let Some(cert) = first {
                    keys.push((alias, protected, cert));
                }
            }
            TRUSTED_CERT_TAG => {
                r.utf()?;
                r.take(8)?;
                r.cert(version)?;
            }
            tag => return Err(JksError::Malformed(format!("unknown entry tag {tag}"))),
        }
    }
    let signed = &data[..r.pos];
    let digest = r.take(DIGEST_LEN)?;
    let passwd = password_bytes(password);
    let computed = Sha1::new()
        .chain_update(&*passwd)
        .chain_update(WHITENER)
        .chain_update(signed)
        .finalize();
    if computed.as_slice() != digest {
        return Err(JksError::WrongPassword);
    }
    let mut entries = keys
        .into_iter()
        .map(|(alias, protected, cert)| {
            let pkcs8 = recover(protected, &passwd)?;
            let key = PrivateKey::from_pkcs8_der(&pkcs8, Some(&cert))
                .map_err(|e| JksError::Malformed(format!("key {alias}: {e}")))?;
            Ok(KeyEntry { alias, key, cert })
        })
        .collect::<Result<Vec<_>, JksError>>()?;
    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(entries)
}

/// An entry of a JKS file, read without its password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JksEntry {
    /// The alias.
    pub alias: String,
    /// What it holds.
    pub kind: JksEntryKind,
}

/// What a JKS entry holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JksEntryKind {
    /// A private key (not returned: it stays encrypted) with its certificate chain.
    PrivateKey {
        /// The chain, the key's certificate first.
        chain: Vec<Certificate>,
    },
    /// A trusted certificate.
    TrustedCert(Box<Certificate>),
}

/// The entries of a JKS file in file order, without a password: the protected key blocks
/// are skipped by their length and never returned, and the integrity digest is not checked.
///
/// # Errors
///
/// [`JksError::Malformed`] for an invalid layout or certificate (a truncated file
/// included); [`JksError::Unsupported`] for certificate types other than X.509.
pub fn entries(data: &[u8]) -> Result<Vec<JksEntry>, JksError> {
    let mut r = Reader { data, pos: 0 };
    let magic = r.u32()?;
    let version = r.u32()?;
    if magic != MAGIC || !(version == 1 || version == 2) {
        return Err(JksError::Malformed("not a JKS file".to_owned()));
    }
    let count = r.u32()?;
    let mut out = Vec::new();
    for _ in 0..count {
        match r.u32()? {
            PRIVATE_KEY_TAG => {
                let alias = r.utf()?;
                r.take(8)?;
                r.block()?;
                let certs = r.u32()?;
                let chain = (0..certs)
                    .map(|_| r.cert(version))
                    .collect::<Result<Vec<_>, _>>()?;
                out.push(JksEntry {
                    alias,
                    kind: JksEntryKind::PrivateKey { chain },
                });
            }
            TRUSTED_CERT_TAG => {
                let alias = r.utf()?;
                r.take(8)?;
                let cert = r.cert(version)?;
                out.push(JksEntry {
                    alias,
                    kind: JksEntryKind::TrustedCert(Box::new(cert)),
                });
            }
            tag => return Err(JksError::Malformed(format!("unknown entry tag {tag}"))),
        }
    }
    Ok(out)
}

/// The password as Java's key store code hashes it: each UTF-16 unit high byte first.
fn password_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.encode_utf16().flat_map(u16::to_be_bytes).collect())
}

/// The PKCS#8 key protected by Sun's `KeyProtector`.
fn recover(protected: &[u8], passwd: &[u8]) -> Result<Zeroizing<Vec<u8>>, JksError> {
    let info = EncryptedPrivateKeyInfo::from_der(protected)
        .map_err(|e| JksError::Malformed(format!("protected key: {e}")))?;
    if info.encryption_algorithm.oid != KEY_PROTECTOR {
        return Err(JksError::Unsupported(format!(
            "key protection {}",
            info.encryption_algorithm.oid
        )));
    }
    let data = info.encrypted_data.as_bytes();
    if data.len() < 2 * DIGEST_LEN {
        return Err(JksError::Malformed("protected key too short".to_owned()));
    }
    let (salt, rest) = data.split_at(DIGEST_LEN);
    let (encrypted, check) = rest.split_at(rest.len() - DIGEST_LEN);
    let mut plain = Zeroizing::new(Vec::with_capacity(encrypted.len()));
    let mut block = salt.to_vec();
    for chunk in encrypted.chunks(DIGEST_LEN) {
        block = Sha1::new()
            .chain_update(passwd)
            .chain_update(&block)
            .finalize()
            .to_vec();
        plain.extend(chunk.iter().zip(&block).map(|(c, k)| c ^ k));
    }
    let computed = Sha1::new()
        .chain_update(passwd)
        .chain_update(&*plain)
        .finalize();
    if computed.as_slice() != check {
        return Err(JksError::WrongPassword);
    }
    Ok(plain)
}

/// A cursor over the file; every read is bounded by what is left.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], JksError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| JksError::Malformed("truncated".to_owned()))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, JksError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, JksError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-prefixed (32-bit) block.
    fn block(&mut self) -> Result<&'a [u8], JksError> {
        let len = self.u32()?;
        self.take(usize::try_from(len).map_err(|_| JksError::Malformed("length".to_owned()))?)
    }

    /// Java's `DataInput.readUTF`.
    fn utf(&mut self) -> Result<String, JksError> {
        let len = self.u16()?;
        decode_modified_utf8(self.take(usize::from(len))?)
    }

    /// A certificate, after its type in version 2.
    fn cert(&mut self, version: u32) -> Result<Certificate, JksError> {
        if version == 2 {
            let kind = self.utf()?;
            if kind != "X.509" && kind != "X509" {
                return Err(JksError::Unsupported(format!("certificate type {kind}")));
            }
        }
        cert::parse(self.block()?).map_err(|e| JksError::Malformed(format!("certificate: {e}")))
    }
}

/// Java's modified UTF-8: UTF-8 of UTF-16 units, NUL as `C0 80`, surrogates encoded one by
/// one.
fn decode_modified_utf8(bytes: &[u8]) -> Result<String, JksError> {
    let bad = || JksError::Malformed("invalid modified UTF-8".to_owned());
    let cont = |b: Option<&u8>| match b {
        Some(&b) if b & 0xC0 == 0x80 => Ok(u16::from(b & 0x3F)),
        _ => Err(bad()),
    };
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let unit = match b {
            0x01..=0x7F => {
                i += 1;
                u16::from(b)
            }
            0xC0..=0xDF => {
                let unit = (u16::from(b & 0x1F) << 6) | cont(bytes.get(i + 1))?;
                i += 2;
                unit
            }
            0xE0..=0xEF => {
                let unit = (u16::from(b & 0x0F) << 12)
                    | (cont(bytes.get(i + 1))? << 6)
                    | cont(bytes.get(i + 2))?;
                i += 3;
                unit
            }
            _ => return Err(bad()),
        };
        units.push(unit);
    }
    String::from_utf16(&units).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_utf8() {
        assert_eq!(decode_modified_utf8(b"abc").unwrap(), "abc");
        assert_eq!(decode_modified_utf8(&[0xC0, 0x80]).unwrap(), "\0");
        assert_eq!(decode_modified_utf8("ключ".as_bytes()).unwrap(), "ключ");
        // U+1F600 as two encoded surrogates.
        let pair = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_modified_utf8(&pair).unwrap(), "\u{1F600}");
        // Plain UTF-8 of a supplementary character and raw NUL are not modified UTF-8.
        assert!(decode_modified_utf8("\u{1F600}".as_bytes()).is_err());
        assert!(decode_modified_utf8(&[0]).is_err());
        assert!(decode_modified_utf8(&[0xC3]).is_err());
    }

    #[test]
    fn password_is_utf16_big_endian() {
        assert_eq!(&*password_bytes("aЖ"), &[0, b'a', 0x04, 0x16]);
    }
}
