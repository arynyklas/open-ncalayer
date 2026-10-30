//! The trusted certificates of a Java KeyStore (JKS): the CA lists some original plugins
//! download. Only read, and only certificates: a private key entry is stepped over.

use sha1::{Digest, Sha1};

/// The magic number of a JKS.
const MAGIC: u32 = 0xfeed_feed;

/// What the integrity hash mixes in after the password.
const WHITENER: &[u8] = b"Mighty Aphrodite";

/// `KeyStore.load` of the JKS `jks` with `password`, then every `trustedCertEntry`'s
/// certificate (DER), in the store's order.
///
/// # Errors
///
/// Java's messages: `Invalid keystore format` for another magic number or version,
/// `Keystore was tampered with, or password was incorrect` when the SHA-1 integrity hash
/// over the password (UTF-16BE), `Mighty Aphrodite` and the store does not hold; an
/// `EOFException`'s empty message for a truncated store, and `Unrecognized keystore entry`
/// for an unknown entry tag.
pub fn jks_certs(jks: &[u8], password: &str) -> Result<Vec<Vec<u8>>, String> {
    let truncated = || String::new();
    let body_len = jks.len().checked_sub(20).ok_or_else(truncated)?;
    let mut reader = Reader {
        data: &jks[..body_len],
    };
    if reader.u32().ok_or_else(truncated)? != MAGIC {
        return Err("Invalid keystore format".to_owned());
    }
    let version = reader.u32().ok_or_else(truncated)?;
    if version != 1 && version != 2 {
        return Err("Invalid keystore format".to_owned());
    }
    let count = reader.u32().ok_or_else(truncated)?;
    let mut certs = Vec::new();
    for _ in 0..count {
        let tag = reader.u32().ok_or_else(truncated)?;
        // The alias (modified UTF-8) and the creation date.
        reader.utf().ok_or_else(truncated)?;
        reader.take(8).ok_or_else(truncated)?;
        match tag {
            // A private key: its encrypted key, then its chain.
            1 => {
                let len = reader.u32().ok_or_else(truncated)?;
                reader.take(len as usize).ok_or_else(truncated)?;
                let chain = reader.u32().ok_or_else(truncated)?;
                for _ in 0..chain {
                    reader.cert(version).ok_or_else(truncated)?;
                }
            }
            2 => certs.push(reader.cert(version).ok_or_else(truncated)?.to_vec()),
            _ => return Err("Unrecognized keystore entry".to_owned()),
        }
    }
    let mut sha = Sha1::new();
    for unit in password.encode_utf16() {
        sha.update(unit.to_be_bytes());
    }
    sha.update(WHITENER);
    sha.update(&jks[..body_len]);
    if sha.finalize().as_slice() != &jks[body_len..] {
        return Err("Keystore was tampered with, or password was incorrect".to_owned());
    }
    Ok(certs)
}

/// `DataInputStream` over the store.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() < n {
            return None;
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn utf(&mut self) -> Option<&'a [u8]> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().ok()?);
        self.take(usize::from(len))
    }

    /// A certificate: its type (version 2) and its encoding.
    fn cert(&mut self, version: u32) -> Option<&'a [u8]> {
        if version == 2 {
            self.utf()?;
        }
        let len = self.u32()?;
        self.take(len as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JKS of `entries`: `(tag, payload)`, the payload written after the alias and date.
    fn store(version: u32, entries: &[(u32, Vec<u8>)], password: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(MAGIC.to_be_bytes());
        out.extend(version.to_be_bytes());
        out.extend((entries.len() as u32).to_be_bytes());
        for (i, (tag, payload)) in entries.iter().enumerate() {
            let alias = format!("alias{i}");
            out.extend(tag.to_be_bytes());
            out.extend((alias.len() as u16).to_be_bytes());
            out.extend(alias.as_bytes());
            out.extend(0_u64.to_be_bytes());
            out.extend(payload);
        }
        let mut sha = Sha1::new();
        for unit in password.encode_utf16() {
            sha.update(unit.to_be_bytes());
        }
        sha.update(WHITENER);
        sha.update(&out);
        out.extend(sha.finalize());
        out
    }

    fn cert(version: u32, der: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if version == 2 {
            out.extend(5_u16.to_be_bytes());
            out.extend(b"X.509");
        }
        out.extend((der.len() as u32).to_be_bytes());
        out.extend(der);
        out
    }

    #[test]
    fn trusted_certificates_in_order() {
        for version in [1, 2] {
            let key = [
                &3_u32.to_be_bytes()[..],
                b"key",
                &1_u32.to_be_bytes(),
                &cert(version, b"chain"),
            ]
            .concat();
            let jks = store(
                version,
                &[
                    (2, cert(version, b"first")),
                    (1, key),
                    (2, cert(version, b"second")),
                ],
                "changeit",
            );
            assert_eq!(
                jks_certs(&jks, "changeit").unwrap(),
                [b"first".to_vec(), b"second".to_vec()]
            );
        }
    }

    #[test]
    fn integrity_and_format_errors() {
        let jks = store(2, &[(2, cert(2, b"ca"))], "changeit");
        assert_eq!(
            jks_certs(&jks, "other").unwrap_err(),
            "Keystore was tampered with, or password was incorrect"
        );
        let mut tampered = jks.clone();
        tampered[30] ^= 1;
        assert!(jks_certs(&tampered, "changeit").is_err());
        let mut magic = jks.clone();
        magic[0] = 0;
        assert_eq!(
            jks_certs(&magic, "changeit").unwrap_err(),
            "Invalid keystore format"
        );
        assert_eq!(jks_certs(&jks[..10], "changeit").unwrap_err(), "");
        let unknown = store(2, &[(7, Vec::new())], "changeit");
        assert_eq!(
            jks_certs(&unknown, "changeit").unwrap_err(),
            "Unrecognized keystore entry"
        );
    }
}
