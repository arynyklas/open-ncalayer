//! Certificate details as NCALayer reads them: KZ subject attributes (IIN, BIN), serial,
//! validity, key usages and the signing algorithm.

use crate::key::SigAlg;
use crate::oid;
use der::Encode;
use der::asn1::{AnyRef, ObjectIdentifier};
use std::collections::BTreeSet;
use std::fmt::Write;
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};
use x509_cert::name::Name;

/// Key usage bits NCALayer looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyUsageBits {
    /// digitalSignature.
    pub digital_signature: bool,
    /// nonRepudiation (contentCommitment).
    pub non_repudiation: bool,
    /// keyEncipherment.
    pub key_encipherment: bool,
    /// keyAgreement.
    pub key_agreement: bool,
}

/// Certificate details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// First subject CN.
    pub subject_cn: Option<String>,
    /// First subject SERIALNUMBER with every `"IIN"` removed.
    pub iin: Option<String>,
    /// First subject OU with every `"BIN"` removed.
    pub bin: Option<String>,
    /// First subject O.
    pub organization: Option<String>,
    /// Lowercase hex of the serial's DER INTEGER content (Java `BigInteger.toByteArray()`):
    /// a serial with the top bit set keeps its leading `00`.
    pub serial_hex: String,
    /// Start of validity.
    pub not_before: OffsetDateTime,
    /// End of validity.
    pub not_after: OffsetDateTime,
    /// Extended key usage OIDs (empty without the extension).
    pub ext_key_usages: BTreeSet<String>,
    /// Key usage bits (all clear without the extension).
    pub key_usage: KeyUsageBits,
    /// OID of the certificate's own signature algorithm.
    pub signature_alg_oid: String,
    /// OID of the subject public key algorithm.
    pub spki_alg_oid: String,
}

/// The certificate signature algorithm is not one the signer supports.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown signature algorithm {0}")]
pub struct UnknownAlgorithm(pub String);

/// Reads the details of `cert`. A key usage or extended key usage extension that is
/// malformed or repeated counts as absent; a subject attribute that is not a
/// `DirectoryString` counts as absent.
pub fn cert_info(cert: &Certificate) -> CertInfo {
    let tbs = cert.tbs_certificate();
    let subject = tbs.subject();
    let key_usage = match tbs.get_extension::<KeyUsage>() {
        Ok(Some((_, ku))) => KeyUsageBits {
            digital_signature: ku.digital_signature(),
            non_repudiation: ku.non_repudiation(),
            key_encipherment: ku.key_encipherment(),
            key_agreement: ku.key_agreement(),
        },
        Ok(None) | Err(_) => KeyUsageBits::default(),
    };
    let ext_key_usages = match tbs.get_extension::<ExtendedKeyUsage>() {
        Ok(Some((_, eku))) => eku.0.iter().map(ToString::to_string).collect(),
        Ok(None) | Err(_) => BTreeSet::new(),
    };
    let validity = tbs.validity();
    CertInfo {
        subject_cn: first_attribute(subject, oid::COMMON_NAME),
        iin: first_attribute(subject, oid::SERIAL_NUMBER).map(|s| s.replace("IIN", "")),
        bin: first_attribute(subject, oid::ORGANIZATIONAL_UNIT).map(|s| s.replace("BIN", "")),
        organization: first_attribute(subject, oid::ORGANIZATION),
        serial_hex: serial_hex(cert),
        not_before: OffsetDateTime::UNIX_EPOCH + validity.not_before.to_unix_duration(),
        not_after: OffsetDateTime::UNIX_EPOCH + validity.not_after.to_unix_duration(),
        ext_key_usages,
        key_usage,
        signature_alg_oid: cert.signature_algorithm().oid.to_string(),
        spki_alg_oid: tbs.subject_public_key_info().algorithm.oid.to_string(),
    }
}

impl CertInfo {
    /// Extended key usages for key filtering: the certificate's own, plus clientAuth when it
    /// is in `requested` and the certificate predates the clientAuth EKU (the original's
    /// rule): a GOST 2015-512 certificate with keyAgreement, or a sha256WithRSA certificate
    /// with keyEncipherment or keyAgreement.
    pub fn effective_ekus(&self, requested: &BTreeSet<String>) -> BTreeSet<String> {
        let mut ekus = self.ext_key_usages.clone();
        let client_auth = oid::CLIENT_AUTH.to_string();
        let ku = &self.key_usage;
        let legacy_auth = match self.signing_alg() {
            Ok(SigAlg::Gost2015_512) => ku.key_agreement,
            Ok(SigAlg::RsaSha256) => ku.key_encipherment || ku.key_agreement,
            Ok(SigAlg::Gost2004 | SigAlg::RsaSha1) | Err(_) => false,
        };
        if legacy_auth && requested.contains(&client_auth) {
            ekus.insert(client_auth);
        }
        ekus
    }

    /// Algorithm to sign with: the certificate's own signature algorithm, as the original
    /// picks the CMS algorithm by `cert.getSigAlgOID()`.
    ///
    /// # Errors
    ///
    /// [`UnknownAlgorithm`] with the OID if it is not a supported signature algorithm.
    pub fn signing_alg(&self) -> Result<SigAlg, UnknownAlgorithm> {
        ObjectIdentifier::new(&self.signature_alg_oid)
            .ok()
            .and_then(|oid| SigAlg::from_signature_oid(&oid))
            .ok_or_else(|| UnknownAlgorithm(self.signature_alg_oid.clone()))
    }

    /// Whether `now` is strictly inside the validity period: `notBefore < now < notAfter`.
    pub fn is_within_validity(&self, now: OffsetDateTime) -> bool {
        self.not_before < now && now < self.not_after
    }
}

/// Value of the first attribute `oid` in `name`, if it is a `DirectoryString`.
fn first_attribute(name: &Name, oid: ObjectIdentifier) -> Option<String> {
    let atav = name.iter().find(|atav| atav.oid == oid)?;
    let value = DirectoryString::try_from(&atav.value).ok()?;
    Some(value.value().into_owned())
}

/// Lowercase hex of the serial's DER INTEGER content octets.
fn serial_hex(cert: &Certificate) -> String {
    let der = cert
        .tbs_certificate()
        .serial_number()
        .to_der()
        .expect("a decoded serial number re-encodes");
    let content = AnyRef::try_from(der.as_slice())
        .expect("a DER INTEGER parses as ANY")
        .value();
    let mut hex = String::with_capacity(content.len() * 2);
    for b in content {
        write!(hex, "{b:02x}").expect("writing to a String");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

    fn info(signature_alg_oid: &str, key_usage: KeyUsageBits) -> CertInfo {
        CertInfo {
            subject_cn: None,
            iin: None,
            bin: None,
            organization: None,
            serial_hex: "01".to_owned(),
            not_before: datetime!(2025-01-01 0:00 UTC),
            not_after: datetime!(2026-01-01 0:00 UTC),
            ext_key_usages: BTreeSet::new(),
            key_usage,
            signature_alg_oid: signature_alg_oid.to_owned(),
            spki_alg_oid: String::new(),
        }
    }

    fn adds_client_auth(signature_alg: SigAlg, key_usage: KeyUsageBits) -> bool {
        let requested = BTreeSet::from([CLIENT_AUTH.to_owned()]);
        info(&signature_alg.signature_oid().to_string(), key_usage)
            .effective_ekus(&requested)
            .contains(CLIENT_AUTH)
    }

    #[test]
    fn obsolete_auth_rule_matrix() {
        let ka = KeyUsageBits {
            key_agreement: true,
            ..KeyUsageBits::default()
        };
        let ke = KeyUsageBits {
            key_encipherment: true,
            ..KeyUsageBits::default()
        };
        let sign = KeyUsageBits {
            digital_signature: true,
            non_repudiation: true,
            ..KeyUsageBits::default()
        };
        assert!(adds_client_auth(SigAlg::Gost2015_512, ka.clone()));
        assert!(!adds_client_auth(SigAlg::Gost2015_512, ke.clone()));
        assert!(!adds_client_auth(SigAlg::Gost2015_512, sign.clone()));
        assert!(adds_client_auth(SigAlg::RsaSha256, ka.clone()));
        assert!(adds_client_auth(SigAlg::RsaSha256, ke.clone()));
        assert!(!adds_client_auth(SigAlg::RsaSha256, sign));
        assert!(!adds_client_auth(SigAlg::Gost2004, ka.clone()));
        assert!(!adds_client_auth(SigAlg::RsaSha1, ke));
        // Requested something else: nothing is added.
        let other = BTreeSet::from(["1.3.6.1.5.5.7.3.4".to_owned()]);
        let i = info(&oid::GOST_2015_512_SIGNATURE.to_string(), ka);
        assert!(i.effective_ekus(&other).is_empty());
    }

    #[test]
    fn unknown_signing_alg() {
        let i = info("1.2.840.10045.4.3.2", KeyUsageBits::default());
        assert_eq!(
            i.signing_alg(),
            Err(UnknownAlgorithm("1.2.840.10045.4.3.2".to_owned()))
        );
    }

    #[test]
    fn validity_bounds_are_exclusive() {
        let i = info("1.2.840.113549.1.1.11", KeyUsageBits::default());
        assert!(!i.is_within_validity(i.not_before));
        assert!(!i.is_within_validity(i.not_after));
        assert!(i.is_within_validity(datetime!(2025-06-01 0:00 UTC)));
        assert!(!i.is_within_validity(datetime!(2024-12-31 23:59:59 UTC)));
    }
}
