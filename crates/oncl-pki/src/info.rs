//! Certificate details as NCALayer reads them: KZ subject attributes (IIN, BIN), serial,
//! validity, key usages, the signing algorithm, Kalkan's certificate types
//! ([`kcert_types`]) and Kalkan's rendering of names ([`kalkan_dn`]).

use crate::key::SigAlg;
use crate::oid;
use der::Encode;
use der::asn1::{Any, AnyRef, ObjectIdentifier};
use der::{Tag, Tagged};
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
    /// Whether the certificate has the id-pkix-ocsp-nocheck extension.
    pub ocsp_no_check: bool,
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
        ocsp_no_check: tbs
            .extensions()
            .is_some_and(|exts| exts.iter().any(|e| e.extn_id == oid::OCSP_NOCHECK)),
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

/// Kalkan's `KNCACertificateType`: what a certificate is for. Ordered as Kalkan declares
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KncaCertType {
    /// `SIGNATURE`.
    Signature,
    /// `AUTHENTICATION`.
    Authentication,
    /// `SSL`.
    Ssl,
    /// `OCSP_RESPONSE_SIGNING`.
    OcspResponseSigning,
    /// `TSP_SIGNING`.
    TspSigning,
}

impl KncaCertType {
    /// Every type, in declaration order.
    pub const ALL: [KncaCertType; 5] = [
        KncaCertType::Signature,
        KncaCertType::Authentication,
        KncaCertType::Ssl,
        KncaCertType::OcspResponseSigning,
        KncaCertType::TspSigning,
    ];

    /// The Java constant name, e.g. `SIGNATURE`.
    pub fn name(self) -> &'static str {
        match self {
            KncaCertType::Signature => "SIGNATURE",
            KncaCertType::Authentication => "AUTHENTICATION",
            KncaCertType::Ssl => "SSL",
            KncaCertType::OcspResponseSigning => "OCSP_RESPONSE_SIGNING",
            KncaCertType::TspSigning => "TSP_SIGNING",
        }
    }

    /// The type named `name` exactly (Java's `valueOf`, case-sensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }
}

/// The certificate's types as Kalkan's `X509Util.getKNCACertificateType` classifies them:
///
/// - SIGNATURE: digitalSignature and nonRepudiation; such a certificate is AUTHENTICATION
///   too if it is GOST 2015-512 (dual-use keys), or sha256WithRSA with keyAgreement;
/// - AUTHENTICATION: digitalSignature, keyEncipherment and the clientAuth extended key usage;
/// - SSL: digitalSignature, keyEncipherment and serverAuth;
/// - OCSP_RESPONSE_SIGNING: id-pkix-ocsp-nocheck and OCSPSigning;
/// - TSP_SIGNING: timeStamping.
///
/// Empty where Kalkan raises `UNKNOWN_KNCA_CERTIFICATE_TYPE`.
pub fn kcert_types(info: &CertInfo) -> BTreeSet<KncaCertType> {
    let ku = &info.key_usage;
    let eku = |oid: ObjectIdentifier| info.ext_key_usages.contains(&oid.to_string());
    let sig_oid = info.signature_alg_oid.as_str();
    let mut types = BTreeSet::new();
    if ku.digital_signature && ku.non_repudiation {
        types.insert(KncaCertType::Signature);
        let dual_use = sig_oid == oid::GOST_2015_512_SIGNATURE.to_string()
            || (sig_oid == oid::SHA256_WITH_RSA.to_string() && ku.key_agreement);
        if dual_use {
            types.insert(KncaCertType::Authentication);
        }
    }
    if ku.digital_signature && ku.key_encipherment && eku(oid::CLIENT_AUTH) {
        types.insert(KncaCertType::Authentication);
    }
    if ku.digital_signature && ku.key_encipherment && eku(oid::SERVER_AUTH) {
        types.insert(KncaCertType::Ssl);
    }
    if info.ocsp_no_check && eku(oid::OCSP_SIGNING) {
        types.insert(KncaCertType::OcspResponseSigning);
    }
    if eku(oid::TIME_STAMPING) {
        types.insert(KncaCertType::TspSigning);
    }
    types
}

/// Value of the first CN of `name`, if it is a `DirectoryString`.
pub fn common_name(name: &Name) -> Option<String> {
    first_attribute(name, oid::COMMON_NAME)
}

/// `name` as Kalkan's `X509Util.getSubjectDN(cert).toString()` writes it (its BouncyCastle
/// `X509Name` with the default symbols, in certificate order): `CN=…,SURNAME=…,C=KZ`,
/// multi-valued RDNs joined by `+`, `,"\+=<>;` escaped with a backslash, unknown attribute
/// types as dotted OIDs, values that are not strings as `#` and the hex of their DER.
///
/// Kalkan builds the name through its own string form and parses it again, which trims
/// the values: a value loses its trailing whitespace, and the first value of a multi-valued
/// RDN its leading whitespace as well. That trimming is reproduced; the round trip's
/// failure on the `NameAtBirth` attribute (its symbol does not parse back) is not.
pub fn kalkan_dn(name: &Name) -> String {
    let mut out = String::new();
    for (i, rdn) in name.iter_rdn().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let multi_valued = rdn.iter().nth(1).is_some();
        for (j, atav) in rdn.iter().enumerate() {
            if j > 0 {
                out.push('+');
            }
            let value = name_value(&atav.value);
            let value = if j == 0 && multi_valued {
                value.trim_matches(java_whitespace)
            } else {
                value.trim_end_matches(java_whitespace)
            };
            match kalkan_symbol(&atav.oid) {
                Some(symbol) => out.push_str(symbol),
                None => out.push_str(&atav.oid.to_string()),
            }
            out.push('=');
            let (kept, rest) = match value.strip_prefix("\\#") {
                Some(rest) => ("\\#", rest),
                None => ("", value),
            };
            out.push_str(kept);
            for c in rest.chars() {
                if matches!(c, ',' | '"' | '\\' | '+' | '=' | '<' | '>' | ';') {
                    out.push('\\');
                }
                out.push(c);
            }
        }
    }
    out
}

/// Java's `String.trim` whitespace: every character up to U+0020.
fn java_whitespace(c: char) -> bool {
    c <= ' '
}

/// BouncyCastle's `X509Name.DefaultSymbols` as Kalkan fills it (`S` and `G` replace `ST`
/// and `GIVENNAME`, put later under the same OIDs).
fn kalkan_symbol(oid: &ObjectIdentifier) -> Option<&'static str> {
    const SYMBOLS: [(&str, &str); 32] = [
        ("2.5.4.6", "C"),
        ("2.5.4.10", "O"),
        ("2.5.4.12", "T"),
        ("2.5.4.11", "OU"),
        ("2.5.4.3", "CN"),
        ("2.5.4.7", "L"),
        ("2.5.4.8", "S"),
        ("2.5.4.5", "SERIALNUMBER"),
        ("1.2.840.113549.1.9.1", "E"),
        ("0.9.2342.19200300.100.1.25", "DC"),
        ("0.9.2342.19200300.100.1.1", "UID"),
        ("2.5.4.9", "STREET"),
        ("2.5.4.4", "SURNAME"),
        ("2.5.4.42", "G"),
        ("2.5.4.43", "INITIALS"),
        ("2.5.4.44", "GENERATION"),
        ("1.2.840.113549.1.9.8", "unstructuredAddress"),
        ("1.2.840.113549.1.9.2", "unstructuredName"),
        ("2.5.4.45", "UniqueIdentifier"),
        ("2.5.4.46", "DN"),
        ("2.5.4.65", "Pseudonym"),
        ("2.5.4.16", "PostalAddress"),
        ("1.3.36.8.3.14", "NameAtBirth"),
        ("1.3.6.1.5.5.7.9.4", "CountryOfCitizenship"),
        ("1.3.6.1.5.5.7.9.5", "CountryOfResidence"),
        ("1.3.6.1.5.5.7.9.3", "Gender"),
        ("1.3.6.1.5.5.7.9.2", "PlaceOfBirth"),
        ("1.3.6.1.5.5.7.9.1", "DateOfBirth"),
        ("2.5.4.17", "PostalCode"),
        ("2.5.4.15", "BusinessCategory"),
        ("2.5.4.20", "TelephoneNumber"),
        ("2.5.4.41", "Name"),
    ];
    let dotted = oid.to_string();
    SYMBOLS
        .iter()
        .find(|(o, _)| *o == dotted)
        .map(|(_, symbol)| *symbol)
}

/// An attribute value as BouncyCastle's `X509Name` holds it: the text of a string type
/// (a leading `#` escaped as `\#`), `\#` and the hex of the DER of a BIT STRING (its
/// `getString`), `#` and the hex of the DER of anything else (UniversalString included).
fn name_value(value: &Any) -> String {
    let bytes = value.value();
    let latin1 = || bytes.iter().map(|&b| char::from(b)).collect::<String>();
    let text = match value.tag() {
        Tag::Utf8String => String::from_utf8_lossy(bytes).into_owned(),
        Tag::BmpString => char::decode_utf16(
            bytes
                .chunks(2)
                .map(|p| u16::from_be_bytes([p[0], p.get(1).copied().unwrap_or(0)])),
        )
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect(),
        Tag::PrintableString
        | Tag::Ia5String
        | Tag::TeletexString
        | Tag::VisibleString
        | Tag::NumericString
        | Tag::GeneralString => latin1(),
        Tag::BitString => return format!("\\#{}", lower_hex(&der_of(value))),
        _ => return format!("#{}", lower_hex(&der_of(value))),
    };
    if text.starts_with('#') {
        format!("\\{text}")
    } else {
        text
    }
}

fn der_of(value: &Any) -> Vec<u8> {
    value
        .to_der()
        .expect("a decoded attribute value re-encodes")
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
    lower_hex(content)
}

/// Lowercase hex, as Kalkan's `Hex.encodeStr` writes it.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
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
            ocsp_no_check: false,
        }
    }

    fn ku(ds: bool, nr: bool, ke: bool, ka: bool) -> KeyUsageBits {
        KeyUsageBits {
            digital_signature: ds,
            non_repudiation: nr,
            key_encipherment: ke,
            key_agreement: ka,
        }
    }

    fn types(
        alg: SigAlg,
        key_usage: KeyUsageBits,
        ekus: &[ObjectIdentifier],
        nocheck: bool,
    ) -> Vec<KncaCertType> {
        let mut i = info(&alg.signature_oid().to_string(), key_usage);
        i.ext_key_usages = ekus.iter().map(ToString::to_string).collect();
        i.ocsp_no_check = nocheck;
        kcert_types(&i).into_iter().collect()
    }

    #[test]
    fn kalkan_certificate_types() {
        use KncaCertType::*;
        let sign = ku(true, true, false, false);
        // GOST 2015-512 signing keys are dual-use; RSA ones only with keyAgreement.
        assert_eq!(
            types(SigAlg::Gost2015_512, sign.clone(), &[], false),
            [Signature, Authentication]
        );
        assert_eq!(
            types(SigAlg::Gost2004, sign.clone(), &[], false),
            [Signature]
        );
        assert_eq!(
            types(SigAlg::RsaSha256, sign.clone(), &[], false),
            [Signature]
        );
        assert_eq!(
            types(SigAlg::RsaSha256, ku(true, true, false, true), &[], false),
            [Signature, Authentication]
        );
        // Authentication and SSL need keyEncipherment; keyAgreement does not count.
        let tls = ku(true, false, true, false);
        assert_eq!(
            types(SigAlg::RsaSha256, tls.clone(), &[oid::CLIENT_AUTH], false),
            [Authentication]
        );
        assert_eq!(
            types(SigAlg::RsaSha256, tls.clone(), &[oid::SERVER_AUTH], false),
            [Ssl]
        );
        let agreement = ku(true, false, false, true);
        assert!(types(SigAlg::Gost2015_512, agreement, &[oid::CLIENT_AUTH], false).is_empty());
        // OCSP responders need id-pkix-ocsp-nocheck; time-stamping only the EKU.
        let ds = ku(true, false, false, false);
        assert_eq!(
            types(SigAlg::Gost2015_512, ds.clone(), &[oid::OCSP_SIGNING], true),
            [OcspResponseSigning]
        );
        assert!(
            types(
                SigAlg::Gost2015_512,
                ds.clone(),
                &[oid::OCSP_SIGNING],
                false
            )
            .is_empty()
        );
        assert_eq!(
            types(
                SigAlg::Gost2015_512,
                KeyUsageBits::default(),
                &[oid::TIME_STAMPING],
                false
            ),
            [TspSigning]
        );
    }

    #[test]
    fn kalkan_certificate_type_names() {
        for t in KncaCertType::ALL {
            assert_eq!(KncaCertType::from_name(t.name()), Some(t));
        }
        assert_eq!(
            KncaCertType::from_name("OCSP_RESPONSE_SIGNING"),
            Some(KncaCertType::OcspResponseSigning)
        );
        for other in ["", "ALL", "signature", " SIGNATURE"] {
            assert_eq!(KncaCertType::from_name(other), None, "{other:?}");
        }
    }

    fn atav(oid: &str, tag: Tag, value: &[u8]) -> x509_cert::attr::AttributeTypeAndValue {
        x509_cert::attr::AttributeTypeAndValue {
            oid: ObjectIdentifier::new_unwrap(oid),
            value: Any::new(tag, value).unwrap(),
        }
    }

    fn name(rdns: Vec<Vec<x509_cert::attr::AttributeTypeAndValue>>) -> Name {
        let rdns: Vec<x509_cert::name::RelativeDistinguishedName> = rdns
            .into_iter()
            .map(|atavs| atavs.try_into().unwrap())
            .collect();
        let der = x509_cert::name::RdnSequence::from(rdns).to_der().unwrap();
        der::Decode::from_der(&der).unwrap()
    }

    #[test]
    fn kalkan_dn_symbols_order_and_escapes() {
        let utf8 = |oid, s: &str| vec![atav(oid, Tag::Utf8String, s.as_bytes())];
        let n = name(vec![
            utf8("2.5.4.3", "ТЕСТОВ ТЕСТ"),
            utf8("2.5.4.4", "ТЕСТОВ"),
            vec![atav("2.5.4.5", Tag::PrintableString, b"IIN123456789011")],
            vec![atav("2.5.4.6", Tag::PrintableString, b"KZ")],
            utf8("2.5.4.42", "ТЕСТОВИЧ"),
            utf8("2.5.4.8", "A,B"),
            vec![atav("1.2.840.113549.1.9.1", Tag::Ia5String, b"a@b.kz")],
            utf8("1.2.3.4", "x=\"y\"+<z>;\\"),
        ]);
        assert_eq!(
            kalkan_dn(&n),
            "CN=ТЕСТОВ ТЕСТ,SURNAME=ТЕСТОВ,SERIALNUMBER=IIN123456789011,C=KZ,G=ТЕСТОВИЧ,\
             S=A\\,B,E=a@b.kz,1.2.3.4=x\\=\\\"y\\\"\\+\\<z\\>\\;\\\\"
        );
    }

    #[test]
    fn kalkan_dn_value_forms() {
        // BMPString and TeletexString (bytes as Latin-1) are strings; a leading `#` is
        // escaped and kept unescaped further.
        let bmp: Vec<u8> = "Әлем".encode_utf16().flat_map(u16::to_be_bytes).collect();
        let n = name(vec![
            vec![atav("2.5.4.3", Tag::BmpString, &bmp)],
            vec![atav("2.5.4.10", Tag::TeletexString, &[0x41, 0xe9])],
            vec![atav("2.5.4.11", Tag::Utf8String, b"#1,2")],
        ]);
        assert_eq!(kalkan_dn(&n), "CN=Әлем,O=Aé,OU=\\#1\\,2");
        // Other types: `#` and the hex of their DER; a BIT STRING as `\#` and its hex.
        let n = name(vec![
            vec![atav("2.5.4.3", Tag::Integer, &[5])],
            vec![atav("2.5.4.45", Tag::BitString, &[0, 0xff])],
            vec![atav("2.5.4.10", Tag::OctetString, &[0x41])],
        ]);
        assert_eq!(
            kalkan_dn(&n),
            "CN=#020105,UniqueIdentifier=\\#030200ff,O=#040141"
        );
    }

    #[test]
    fn kalkan_dn_trims_as_its_string_round_trip_does() {
        let n = name(vec![
            vec![atav("2.5.4.3", Tag::Utf8String, b"  lead and trail \t")],
            vec![
                atav("2.5.4.3", Tag::Utf8String, b" first "),
                atav("2.5.4.10", Tag::Utf8String, b" second "),
            ],
        ]);
        let dn = kalkan_dn(&n);
        // A single value keeps its leading spaces; the multi-valued RDN's values are
        // ordered by DER (CN before O) and its first value is trimmed on both sides.
        assert_eq!(dn, "CN=  lead and trail,CN=first+O= second");
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
