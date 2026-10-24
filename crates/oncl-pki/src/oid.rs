//! Object identifiers used by the PKI code.

use der::asn1::ObjectIdentifier as Oid;

// Public-key algorithms.
/// rsaEncryption.
pub const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
/// GOST 34.310-2004 public key (`CurveId::Pkigovkz2004A::key_oid`).
pub const GOST_2004_KEY: Oid = Oid::new_unwrap("1.2.398.3.10.1.1.1.1");
/// GOST 34.10-2015 512-bit public key (`CurveId::Tc26_512A::key_oid`).
pub const GOST_2015_512_KEY: Oid = Oid::new_unwrap("1.2.398.3.10.1.1.2.2");

// Signature algorithms.
/// GOST 34.311-95 with GOST 34.310-2004.
pub const GOST_2004_SIGNATURE: Oid = Oid::new_unwrap("1.2.398.3.10.1.1.1.2");
/// GOST 34.11-2015 (512) with GOST 34.10-2015 (512).
pub const GOST_2015_512_SIGNATURE: Oid = Oid::new_unwrap("1.2.398.3.10.1.1.2.3.2");
/// sha256WithRSAEncryption.
pub const SHA256_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
/// sha1WithRSAEncryption.
pub const SHA1_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.5");

// Digest algorithms.
/// GOST 34.311-95.
pub const GOST_34311: Oid = Oid::new_unwrap("1.2.398.3.10.1.3.1");
/// GOST 34.11-2015, 512 bits.
pub const STREEBOG_512: Oid = Oid::new_unwrap("1.2.398.3.10.1.3.3");
/// id-sha256.
pub const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
/// id-sha1.
pub const SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");

// PKCS#7 content types.
/// id-data.
pub const DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
/// id-encryptedData.
pub const ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");

// Subject name attributes.
/// commonName (CN).
pub const COMMON_NAME: Oid = Oid::new_unwrap("2.5.4.3");
/// serialNumber (SERIALNUMBER): `IIN…` in NCA certificates.
pub const SERIAL_NUMBER: Oid = Oid::new_unwrap("2.5.4.5");
/// organizationName (O).
pub const ORGANIZATION: Oid = Oid::new_unwrap("2.5.4.10");
/// organizationalUnitName (OU): `BIN…` in NCA certificates.
pub const ORGANIZATIONAL_UNIT: Oid = Oid::new_unwrap("2.5.4.11");

// Extended key usages.
/// id-kp-clientAuth.
pub const CLIENT_AUTH: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.2");

// PKCS#12 bags and attributes.
/// keyBag.
pub const KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.1");
/// pkcs8ShroudedKeyBag.
pub const PKCS8_SHROUDED_KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.2");
/// certBag.
pub const CERT_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.3");
/// x509Certificate (certBag type).
pub const X509_CERTIFICATE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.22.1");
/// friendlyName (BMPString).
pub const FRIENDLY_NAME: Oid = Oid::new_unwrap("1.2.840.113549.1.9.20");
/// localKeyId (OCTET STRING).
pub const LOCAL_KEY_ID: Oid = Oid::new_unwrap("1.2.840.113549.1.9.21");

// Password-based encryption.
/// pbeWithSHAAnd128BitRC2-CBC.
pub const PBE_SHA_RC2_128: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.5");
/// pbeWithSHAAnd3-KeyTripleDES-CBC.
pub const PBE_SHA_3DES: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.3");
/// pbewithSHAAnd40BitRC2-CBC.
pub const PBE_SHA_RC2_40: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.6");
/// id-PBES2.
pub const PBES2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.13");
/// id-PBKDF2.
pub const PBKDF2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.12");
/// id-hmacWithSHA1.
pub const HMAC_SHA1: Oid = Oid::new_unwrap("1.2.840.113549.2.7");
/// id-hmacWithSHA256.
pub const HMAC_SHA256: Oid = Oid::new_unwrap("1.2.840.113549.2.9");
/// id-aes256-CBC.
pub const AES_256_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.42");

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_gost::{CurveId, GostAlg};

    #[test]
    fn gost_oids_agree_with_oncl_gost() {
        assert_eq!(GOST_2004_KEY.to_string(), CurveId::Pkigovkz2004A.key_oid());
        assert_eq!(GOST_2015_512_KEY.to_string(), CurveId::Tc26_512A.key_oid());
        let pairs = [
            (GostAlg::Gost34310_2004, GOST_2004_SIGNATURE, GOST_34311),
            (
                GostAlg::Gost3410_2015_512,
                GOST_2015_512_SIGNATURE,
                STREEBOG_512,
            ),
        ];
        for (alg, signature, digest) in pairs {
            assert_eq!(signature.to_string(), alg.signature_oid());
            assert_eq!(digest.to_string(), alg.digest_oid());
        }
    }
}
