//! Identifiers shared by the native messaging host manifest, the relay and the extension.

use sha2::{Digest, Sha256};

/// Name of the native messaging host.
pub const HOST_NAME: &str = "io.github.arynyklas.openncalayer";

/// Extension id in Firefox (`browser_specific_settings.gecko.id`).
pub const FIREFOX_EXTENSION_ID: &str = "openncalayer@arynyklas.github.io";

/// Public key of the Chromium extension (`key` of its manifest): base64 of the DER
/// `SubjectPublicKeyInfo` of an RSA-2048 key.
// Throwaway test key; the real one replaces it (and `CHROMIUM_EXTENSION_ID`) later.
pub const CHROMIUM_EXTENSION_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqNd7JGONbeHlhBYnkOXF1Y75qHD3mecgF72v7G37xpdyw08vruPkaNmMJu46zWCYYZfgsud7rKR2kCgO3gGypF4WUZ91oxHysCnM7whfiDF7xQ1df4L1bgkZ/ia9S08LqRxvkm+xE7h1C+ilyRnhRiiHhz+bfDQoYzJ6m5OkC14w3+utj1bBMhwswAM+JYq5IwEPlMawjzkALW4Po8vnboPEkAlC30smOutipbTo3QID//OvhsIzVuURb4xCGl4Dn2kSdDk5tEDmAZYkJfifUFMayIISRvH9XbKlE+fqDaEifvKfBsKta5zvwzZHESAwzc8UeK6Z3V/n6/1kOdp77QIDAQAB";

/// Chromium extension id derived from [`CHROMIUM_EXTENSION_KEY`] by [`chromium_extension_id`].
// Throwaway test key id, replaced later together with `CHROMIUM_EXTENSION_KEY`.
pub const CHROMIUM_EXTENSION_ID: &str = "pmhfibnacapcmnoabggpgmafjbkellac";

/// Chromium extension id of a public key: the first 16 bytes of SHA-256 of the DER
/// `SubjectPublicKeyInfo`, each nibble `n` written as the letter `'a' + n`.
pub fn chromium_extension_id(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    digest[..16]
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(b'a' + nibble))
        .collect()
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    /// An unrelated RSA-2048 SPKI (generated with `openssl genpkey`, base64 of the DER).
    const SPKI_FIXTURE: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0YKdGHpi2V2mTSeR3rlvVE0xxhUYKnDP9owge30pYiJNGeBm6HECCQiLzNw0mtaLZiG7JWwJZxC/z5E8taAossn6FVIVnvp4v/4f/1t+GFcCV439u2xomAmMkhHqPB35A+mqfxckyUrCzcL6TmQ3R3vrRsCq58R2tUo+UFLqDLEmkZ4Cxz9zqblC9rsDYavSu4XJwp9tjna3XG6frJ3x0nKwQPNcs+Hu0pixzOJ5ngIfgxwR+ongH3Li0aMjNtP7wzMMZiSmaFpjh8ouM1TSxXK3rpNVsrGpo5EdZGu9ll0zdklUsRDyOAnZ7j/AzTdORDtypMX1hDNiWzUCtJRrnwIDAQAB";

    /// Id of [`SPKI_FIXTURE`], computed independently in Python:
    /// `''.join(chr(97 + int(c, 16)) for c in hashlib.sha256(spki).hexdigest()[:32])`.
    const ID_FIXTURE: &str = "fbgdcpfpofkniamjiljgenpnloeiaemm";

    fn b64(text: &str) -> Vec<u8> {
        STANDARD.decode(text).expect("valid base64")
    }

    #[test]
    fn chromium_id_from_key() {
        assert_eq!(chromium_extension_id(&b64(SPKI_FIXTURE)), ID_FIXTURE);
        assert_eq!(
            chromium_extension_id(&b64(CHROMIUM_EXTENSION_KEY)),
            CHROMIUM_EXTENSION_ID
        );
    }

    #[test]
    fn chromium_id_shape() {
        let id = chromium_extension_id(b"");
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|c| (b'a'..=b'p').contains(&c)));
    }
}
