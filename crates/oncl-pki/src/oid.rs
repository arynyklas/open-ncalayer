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
/// GOST 34.11-2015, 256 bits.
pub const STREEBOG_256: Oid = Oid::new_unwrap("1.2.398.3.10.1.3.2");
/// id-sha256.
pub const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
/// id-sha384.
pub const SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
/// id-sha512.
pub const SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");
/// id-sha1.
pub const SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");

// PKCS#7 / CMS content types.
/// id-data.
pub const DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
/// id-signedData.
pub const SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
/// id-encryptedData.
pub const ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");
/// id-ct-TSTInfo (RFC 3161 time-stamp token content).
pub const TST_INFO: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.4");

// CMS attributes.
/// id-contentType.
pub const CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
/// id-messageDigest.
pub const MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
/// id-signingTime.
pub const SIGNING_TIME: Oid = Oid::new_unwrap("1.2.840.113549.1.9.5");
/// id-aa-signingCertificateV2 (RFC 5035).
pub const SIGNING_CERTIFICATE_V2: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// id-aa-timeStampToken (RFC 3161 unsigned attribute).
pub const TIME_STAMP_TOKEN: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.2.14");

// Subject name attributes.
/// commonName (CN).
pub const COMMON_NAME: Oid = Oid::new_unwrap("2.5.4.3");
/// serialNumber (SERIALNUMBER): `IIN…` in NCA certificates.
pub const SERIAL_NUMBER: Oid = Oid::new_unwrap("2.5.4.5");
/// countryName (C).
pub const COUNTRY: Oid = Oid::new_unwrap("2.5.4.6");
/// organizationName (O).
pub const ORGANIZATION: Oid = Oid::new_unwrap("2.5.4.10");
/// organizationalUnitName (OU): `BIN…` in NCA certificates.
pub const ORGANIZATIONAL_UNIT: Oid = Oid::new_unwrap("2.5.4.11");
/// telephoneNumber.
pub const TELEPHONE_NUMBER: Oid = Oid::new_unwrap("2.5.4.20");
/// dnQualifier.
pub const DN_QUALIFIER: Oid = Oid::new_unwrap("2.5.4.46");
/// emailAddress (PKCS#9, E).
pub const EMAIL_ADDRESS: Oid = Oid::new_unwrap("1.2.840.113549.1.9.1");
/// domainComponent (DC).
pub const DOMAIN_COMPONENT: Oid = Oid::new_unwrap("0.9.2342.19200300.100.1.25");
/// dateOfBirth (RFC 3739).
pub const DATE_OF_BIRTH: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.9.1");

// Extended key usages.
/// id-kp-serverAuth.
pub const SERVER_AUTH: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.1");
/// id-kp-clientAuth.
pub const CLIENT_AUTH: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.2");
/// id-kp-timeStamping.
pub const TIME_STAMPING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.8");
/// id-kp-OCSPSigning.
pub const OCSP_SIGNING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.9");

// Certificate extensions without an `x509-cert` type.
/// id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1).
pub const OCSP_NOCHECK: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1.5");
/// KeyStoreInfo (KNCA `keystore_branch`): the key storage a certificate request came from.
pub const KEYSTORE_INFO: Oid = Oid::new_unwrap("1.2.398.3.3.5");
/// KeyStoreInfo storage: a PKCS#12 file (Kalkan `Storage.PKCS12`).
pub const STORAGE_PKCS12: Oid = Oid::new_unwrap("1.2.398.3.3.5.1.1");
/// KeyStoreInfo storage: a JKS file (Kalkan `Storage.JKS`).
pub const STORAGE_JKS: Oid = Oid::new_unwrap("1.2.398.3.3.5.1.2");

// PKCS#9 / PKCS#10.
/// extensionRequest.
pub const EXTENSION_REQUEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.14");

// CRL extensions (RFC 5280 §5.2). `x509-cert` 0.3 gives `IssuingDistributionPoint` the
// OID of subjectInfoAccess, so both are spelled out here.
/// id-ce-deltaCRLIndicator.
pub const DELTA_CRL_INDICATOR: Oid = Oid::new_unwrap("2.5.29.27");
/// id-ce-issuingDistributionPoint.
pub const ISSUING_DISTRIBUTION_POINT: Oid = Oid::new_unwrap("2.5.29.28");

// OCSP (RFC 6960).
/// id-ad-ocsp: the OCSP access method of AuthorityInfoAccess.
pub const AD_OCSP: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1");
/// id-ad-caIssuers: the issuer certificates access method of AuthorityInfoAccess.
pub const AD_CA_ISSUERS: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.2");
/// id-ad-timeStamping: the TSA access method of SubjectInfoAccess and AuthorityInfoAccess.
pub const AD_TIME_STAMPING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.3");
/// id-pkix-ocsp-basic: the `BasicOCSPResponse` response type.
pub const OCSP_BASIC: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1.1");
/// id-pkix-ocsp-nonce: the nonce extension of an OCSP request and response.
pub const OCSP_NONCE: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.1.2");

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
