//! A user-supplied server certificate chain and key.

use der::asn1::{ObjectIdentifier, UintRef};
use der::{Decode, Encode, Sequence};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
use x509_cert::spki::SubjectPublicKeyInfoRef;
use zeroize::Zeroizing;

use crate::{TlsError, TlsInfo, TlsMaterial, TlsSource, TlsWarning};

const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA1_SIGNATURES: [ObjectIdentifier; 4] = [
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"), // sha1WithRSAEncryption
    ObjectIdentifier::new_unwrap("1.3.14.3.2.29"),        // sha1WithRSASignature (OIW)
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.1"),    // ecdsa-with-SHA1
    ObjectIdentifier::new_unwrap("1.2.840.10040.4.3"),    // dsa-with-sha1
];
const MIN_RSA_BITS: usize = 2048;
const MAX_VALIDITY_DAYS: i64 = 825;
const LOCALHOST_V4: [u8; 4] = [127, 0, 0, 1];

/// Checks a user's server certificate chain (leaf first, then intermediates) and its key.
///
/// The checks run in this order: IP `127.0.0.1` in subjectAltName, serverAuth EKU, key
/// strength (ECDSA P-256/P-384 or RSA ≥ 2048), no SHA-1 signature on the leaf or an
/// intermediate, not expired at `now`, the key matches the leaf. The chain is kept as given;
/// a leaf valid for more than 825 days only yields a warning.
pub fn import(
    chain_pem: &str,
    key_pem: &str,
    now: OffsetDateTime,
) -> Result<TlsMaterial, TlsError> {
    let ders = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Parse(format!("certificate chain: {e}")))?;
    let Some(leaf_der) = ders.first() else {
        return Err(TlsError::Parse("no certificate in the chain".to_owned()));
    };
    let certs = ders
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Parse(format!("certificate: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| TlsError::Parse(format!("private key: {e}")))?;
    let leaf = &certs[0];
    let tbs = leaf.tbs_certificate();

    let san = tbs
        .get_extension::<SubjectAltName>()
        .map_err(|e| TlsError::Parse(format!("subjectAltName: {e}")))?;
    let has_ip = san.is_some_and(|(_, san)| {
        san.0
            .iter()
            .any(|name| matches!(name, GeneralName::IpAddress(ip) if ip.as_bytes() == LOCALHOST_V4))
    });
    if !has_ip {
        return Err(TlsError::MissingIpSan);
    }

    let eku = tbs
        .get_extension::<ExtendedKeyUsage>()
        .map_err(|e| TlsError::Parse(format!("extendedKeyUsage: {e}")))?;
    if !eku.is_some_and(|(_, eku)| eku.0.contains(&ID_KP_SERVER_AUTH)) {
        return Err(TlsError::MissingServerAuth);
    }

    let spki_der = tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|e| TlsError::Parse(format!("subjectPublicKeyInfo: {e}")))?;
    check_key_strength(&spki_der)?;

    let sha1_signed = certs
        .iter()
        .enumerate()
        // A self-signed root at the end of the chain is trusted by itself, not by its signature.
        .filter(|(i, cert)| {
            *i == 0 || cert.tbs_certificate().issuer() != cert.tbs_certificate().subject()
        })
        .any(|(_, cert)| SHA1_SIGNATURES.contains(&cert.signature_algorithm().oid));
    if sha1_signed {
        return Err(TlsError::Sha1Signature);
    }

    let validity = tbs.validity();
    let not_before = to_time(&validity.not_before);
    let not_after = to_time(&validity.not_after);
    if now > not_after {
        return Err(TlsError::Expired);
    }

    let signer = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| TlsError::Parse(format!("private key: {e}")))?;
    match signer.public_key() {
        Some(public) if public.as_ref() == spki_der.as_slice() => {}
        _ => return Err(TlsError::KeyMismatch),
    }

    let mut warnings = Vec::new();
    if not_after - not_before > Duration::days(MAX_VALIDITY_DAYS) {
        warnings.push(TlsWarning::ValidityOver825Days);
    }
    let info = TlsInfo {
        source: TlsSource::Imported,
        ca_sha1: None,
        ca_sha256: None,
        leaf_sha256: crate::sha256_hex(leaf_der),
        leaf_not_after: crate::rfc3339(not_after).map_err(TlsError::Parse)?,
        created_at: crate::rfc3339(now).map_err(TlsError::Parse)?,
        generator: crate::generator(),
    };
    Ok(TlsMaterial {
        // Re-encoded from the parsed DER: same certificates in the same order, without any
        // other PEM blocks (such as a private key) that a combined file might carry.
        chain_pem: ders
            .iter()
            .map(|der| der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, der))
            .collect::<Result<String, _>>()
            .map_err(|e| TlsError::Parse(format!("certificate chain: {e}")))?,
        key_pem: Zeroizing::new(key_pem.to_owned()),
        ca_pem: None,
        ca_der: None,
        info,
        warnings,
    })
}

/// `RSAPublicKey` (RFC 8017, A.1.1).
#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    _public_exponent: UintRef<'a>,
}

/// Accepts ECDSA P-256/P-384 and RSA keys of at least 2048 bits; everything else is weak or
/// unsupported for the local server.
fn check_key_strength(spki_der: &[u8]) -> Result<(), TlsError> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| TlsError::Parse(format!("subjectPublicKeyInfo: {e}")))?;
    let strong = match spki.algorithm.oid {
        EC_PUBLIC_KEY => spki
            .algorithm
            .parameters
            .and_then(|params| params.decode_as::<ObjectIdentifier>().ok())
            .is_some_and(|curve| curve == SECP256R1 || curve == SECP384R1),
        RSA_ENCRYPTION => spki
            .subject_public_key
            .as_bytes()
            .and_then(|bytes| RsaPublicKey::from_der(bytes).ok())
            .is_some_and(|key| bit_len(key.modulus.as_bytes()) >= MIN_RSA_BITS),
        _ => false,
    };
    if strong {
        Ok(())
    } else {
        Err(TlsError::WeakKey)
    }
}

/// Bit length of a big-endian unsigned integer without leading zero octets.
fn bit_len(be: &[u8]) -> usize {
    match be.first() {
        Some(&first) => be.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    }
}

fn to_time(t: &x509_cert::time::Time) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + t.to_unix_duration()
}

#[cfg(test)]
mod tests {
    use der::asn1::{BitString, Null};
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

    use super::*;

    fn rsa_spki(modulus: &[u8]) -> Vec<u8> {
        let key = RsaPublicKey {
            modulus: UintRef::new(modulus).unwrap(),
            _public_exponent: UintRef::new(&[1, 0, 1]).unwrap(),
        }
        .to_der()
        .unwrap();
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: RSA_ENCRYPTION,
                parameters: Some(Null.into()),
            },
            subject_public_key: BitString::from_bytes(&key).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn rsa_key_strength() {
        let mut m2048 = vec![0x80; 256];
        assert_eq!(check_key_strength(&rsa_spki(&m2048)), Ok(()));
        m2048[0] = 0x7f; // 2047 bits
        assert_eq!(
            check_key_strength(&rsa_spki(&m2048)),
            Err(TlsError::WeakKey)
        );
        assert_eq!(
            check_key_strength(&rsa_spki(&[0xc0; 128])),
            Err(TlsError::WeakKey)
        );
        assert_eq!(check_key_strength(&rsa_spki(&[0xc0; 384])), Ok(()));
    }
}
