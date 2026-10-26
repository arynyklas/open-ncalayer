//! PKCS#10 certificate requests as NCALayer's `generateCsr` builds them: the subject from the
//! page's `dn`, an `extensionRequest` with SubjectAltName (when there are names) and
//! KeyStoreInfo, signed with the request's own key, as PEM `CERTIFICATE REQUEST`; and as the
//! legacy Applet's `genKeyPairAndGetPKCS10` builds them, with SubjectKeyIdentifier instead of
//! KeyStoreInfo.

use crate::asn1util;
use crate::cert::Certificate;
use crate::key::{PrivateKey, SigAlg, key_id_bytes};
use crate::keygen::KeySpec;
use crate::keystore::KeystoreError;
use crate::oid;
use crate::pem;
use der::asn1::{
    Any, BitString, Ia5String, ObjectIdentifier, OctetString, PrintableStringRef, SequenceRef,
    SetOfVec, Utf8StringRef,
};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Sequence, SliceReader, Tag};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::cmp::Ordering;
use x509_cert::attr::{Attribute, AttributeTypeAndValue};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{SubjectAltName, SubjectKeyIdentifier};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq, Version};

/// The KeyStoreInfo extension (`1.2.398.3.3.5`) of a request and of the certificate issued
/// on it: the storage the key lives in and, for file storages, the directory of the key
/// file. `KeyStoreInfo ::= SEQUENCE { storage OID, path UTF8String OPTIONAL }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyStoreInfo {
    /// Storage OID (`oid::STORAGE_PKCS12` for PKCS#12 files).
    pub storage_oid: ObjectIdentifier,
    /// Directory of the key file; `None` for tokens.
    pub path: Option<String>,
}

impl KeyStoreInfo {
    /// DER of the extension value.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::InvalidRequest`] if the path is too long for DER.
    pub fn to_der(&self) -> Result<Vec<u8>, KeystoreError> {
        let path = self
            .path
            .as_deref()
            .map(Utf8StringRef::new)
            .transpose()
            .map_err(invalid)?;
        KeyStoreInfoAsn1 {
            storage: self.storage_oid,
            path,
        }
        .to_der()
        .map_err(invalid)
    }

    /// Reads an extension value as Kalkan does (`X509Util.getKeystoreOid` reads only the
    /// OID): the storage OID first; a valid UTF8String path after it is taken, anything else
    /// after it ignored.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::Malformed`] unless the value is a SEQUENCE starting with an OID.
    pub fn from_der(der: &[u8]) -> Result<KeyStoreInfo, KeystoreError> {
        let malformed = |e: der::Error| KeystoreError::Malformed(format!("KeyStoreInfo: {e}"));
        let info = <&SequenceRef>::from_der(der).map_err(malformed)?;
        let mut elements = SliceReader::new(info.as_bytes()).map_err(malformed)?;
        let storage_oid = ObjectIdentifier::decode(&mut elements).map_err(malformed)?;
        let path = Option::<Utf8StringRef<'_>>::decode(&mut elements)
            .ok()
            .flatten()
            .map(|path| path.as_str().to_owned());
        Ok(KeyStoreInfo { storage_oid, path })
    }

    /// The KeyStoreInfo extension of `cert`, if it has one.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::Malformed`] if the extension does not read (see
    /// [`KeyStoreInfo::from_der`]).
    pub fn of_certificate(cert: &Certificate) -> Result<Option<KeyStoreInfo>, KeystoreError> {
        cert.tbs_certificate()
            .extensions()
            .and_then(|exts| exts.iter().find(|e| e.extn_id == oid::KEYSTORE_INFO))
            .map(|ext| KeyStoreInfo::from_der(ext.extn_value.as_bytes()))
            .transpose()
    }
}

/// What a request says besides its key.
#[derive(Clone, Debug)]
pub struct CsrRequest<'a> {
    /// Subject attributes (`dn` of the page: `{OID: value}`), in any order.
    pub dn: &'a [(ObjectIdentifier, String)],
    /// dNSName alternative names (`subjectAltNames`).
    pub dns_names: &'a [String],
    /// rfc822Name alternative name (`email`); blank means none.
    pub email: Option<&'a str>,
    /// The KeyStoreInfo extension.
    pub keystore_info: KeyStoreInfo,
}

/// What a request of the legacy Applet's `genKeyPairAndGetPKCS10` (Kalkan applet
/// `KeyStoreUtil`) says besides its key.
#[derive(Clone, Debug)]
pub struct LegacyCsrRequest<'a> {
    /// Subject attributes, one RDN each, in this order.
    pub dn: &'a [(ObjectIdentifier, String)],
    /// dNSName alternative names; `None` for no SubjectAltName.
    pub dns_names: Option<&'a [String]>,
}

/// `KeyStoreInfo ::= SEQUENCE { storage OID, path UTF8String OPTIONAL }`.
#[derive(Sequence)]
struct KeyStoreInfoAsn1<'a> {
    storage: ObjectIdentifier,
    #[asn1(optional = "true")]
    path: Option<Utf8StringRef<'a>>,
}

/// Builds the request for `key` (of `spec`) as PEM `CERTIFICATE REQUEST` (lines of 64,
/// the platform line separator):
/// - the subject has one RDN per `dn` attribute, ordered as Kalkan's applet orders them (see
///   [`natural_order`]); values are encoded as Kalkan's default converter does: `#hex` is
///   DER, a leading `\` is dropped, emailAddress and domainComponent are IA5String,
///   dateOfBirth GeneralizedTime, countryName, serialNumber, dnQualifier and
///   telephoneNumber PrintableString, anything else UTF8String;
/// - `extensionRequest` holds SubjectAltName (the dNSNames, then the rfc822Name; only if
///   there is one) and KeyStoreInfo, both non-critical;
/// - the signature algorithm is `spec`'s with NULL parameters.
///
/// # Errors
///
/// [`KeystoreError::UnknownAlgorithm`] for sha1WithRSA (SHA-1 signatures are refused) or a
/// key of another type than `spec`; [`KeystoreError::InvalidRequest`] if a value does not
/// fit its string type.
///
/// # Panics
///
/// If the operating system RNG fails (GOST signatures).
pub fn build_csr(
    key: &PrivateKey,
    spec: KeySpec,
    req: &CsrRequest<'_>,
) -> Result<String, KeystoreError> {
    let alg = request_alg(key, spec)?;

    let mut names = Vec::new();
    for dns in req.dns_names {
        names.push(GeneralName::DnsName(ia5(dns)?));
    }
    if let Some(email) = req.email
        && !email.trim().is_empty()
    {
        names.push(GeneralName::Rfc822Name(ia5(email)?));
    }
    let mut extensions = Vec::with_capacity(2);
    if !names.is_empty() {
        extensions.push(extension(SubjectAltName::OID, &SubjectAltName(names)));
    }
    extensions.push(Extension {
        extn_id: oid::KEYSTORE_INFO,
        critical: false,
        extn_value: OctetString::new(req.keystore_info.to_der()?).map_err(invalid)?,
    });
    let mut sorted: Vec<&(ObjectIdentifier, String)> = req.dn.iter().collect();
    sorted.sort_by(|a, b| natural_order(&a.0.to_string(), &b.0.to_string()));
    let der = sign_request(
        key,
        alg,
        key.public_key().to_spki(),
        subject(sorted)?,
        extensions,
    )?;
    Ok(pem::encode("CERTIFICATE REQUEST", &der))
}

/// Builds the request of the legacy Applet's `genKeyPairAndGetPKCS10` for `key` (of
/// `spec`), as DER:
/// - the subject has one RDN per `dn` attribute, in the given order; values are encoded as
///   in [`build_csr`];
/// - `extensionRequest` holds SubjectKeyIdentifier (the key identifier, see
///   [`crate::keygen::key_id`]) and, with `dns_names`, SubjectAltName: each dNSName,
///   followed by an iPAddress for `127.0.0.1` (Kalkan's `getExtensionReqSet`); both
///   non-critical;
/// - the signature algorithm is `spec`'s with NULL parameters.
///
/// # Errors
///
/// As [`build_csr`].
///
/// # Panics
///
/// If the operating system RNG fails (GOST signatures).
pub fn build_legacy_csr(
    key: &PrivateKey,
    spec: KeySpec,
    req: &LegacyCsrRequest<'_>,
) -> Result<Vec<u8>, KeystoreError> {
    let alg = request_alg(key, spec)?;
    let public_key = key.public_key().to_spki();
    let ski = SubjectKeyIdentifier(OctetString::new(key_id_bytes(&public_key)).map_err(invalid)?);
    let mut extensions = vec![extension(SubjectKeyIdentifier::OID, &ski)];
    if let Some(dns_names) = req.dns_names {
        let mut names = Vec::with_capacity(dns_names.len());
        for dns in dns_names {
            names.push(GeneralName::DnsName(ia5(dns)?));
            if dns == "127.0.0.1" {
                names.push(GeneralName::IpAddress(
                    OctetString::new([127, 0, 0, 1]).map_err(invalid)?,
                ));
            }
        }
        extensions.push(extension(SubjectAltName::OID, &SubjectAltName(names)));
    }
    sign_request(key, alg, public_key, subject(req.dn.iter())?, extensions)
}

/// The signature algorithm of a request for `key` of `spec`.
fn request_alg(key: &PrivateKey, spec: KeySpec) -> Result<SigAlg, KeystoreError> {
    let alg = spec.sig_alg();
    if alg == SigAlg::RsaSha1 || alg.key_alg() != key.alg() {
        return Err(KeystoreError::UnknownAlgorithm);
    }
    Ok(alg)
}

/// DER of the request for `key` (whose SubjectPublicKeyInfo is `public_key`) with `subject`
/// and an `extensionRequest` of `extensions`, signed with `alg` (NULL parameters).
fn sign_request(
    key: &PrivateKey,
    alg: SigAlg,
    public_key: SubjectPublicKeyInfoOwned,
    subject: Name,
    extensions: Vec<Extension>,
) -> Result<Vec<u8>, KeystoreError> {
    let mut attributes = SetOfVec::new();
    attributes
        .insert(Attribute::try_from(ExtensionReq(extensions)).map_err(invalid)?)
        .expect("one attribute");

    let info = CertReqInfo {
        version: Version::V1,
        subject,
        public_key,
        attributes,
    };
    let signature = key
        .sign(alg, &info.to_der().map_err(invalid)?)
        .expect("the key signs with its own algorithm");
    let request = CertReq {
        info,
        algorithm: AlgorithmIdentifierOwned {
            oid: alg.signature_oid(),
            parameters: Some(Any::null()),
        },
        signature: BitString::from_bytes(&signature).expect("signature BIT STRING"),
    };
    request.to_der().map_err(invalid)
}

fn invalid(e: impl std::fmt::Display) -> KeystoreError {
    KeystoreError::InvalidRequest(e.to_string())
}

fn ia5(value: &str) -> Result<Ia5String, KeystoreError> {
    Ia5String::new(value).map_err(|e| invalid(format!("{value:?}: {e}")))
}

/// A non-critical extension with the DER of `value`.
fn extension(extn_id: ObjectIdentifier, value: &impl Encode) -> Extension {
    Extension {
        extn_id,
        critical: false,
        extn_value: OctetString::new(value.to_der().expect("extension value encodes"))
            .expect("extension value fits DER"),
    }
}

/// The subject: one single-valued RDN per attribute, in the given order.
fn subject<'a>(
    dn: impl IntoIterator<Item = &'a (ObjectIdentifier, String)>,
) -> Result<Name, KeystoreError> {
    let mut rdns = RdnSequence::default();
    for (oid, value) in dn {
        let atv = AttributeTypeAndValue {
            oid: *oid,
            value: name_value(oid, value)?,
        };
        rdns.push(RelativeDistinguishedName::try_from(vec![atv]).map_err(invalid)?);
    }
    Name::from_der(&rdns.to_der().map_err(invalid)?).map_err(invalid)
}

/// A subject attribute value as Kalkan's `X509DefaultEntryConverter` encodes it.
fn name_value(oid: &ObjectIdentifier, value: &str) -> Result<Any, KeystoreError> {
    let bad = |e: &dyn std::fmt::Display| invalid(format!("{oid} = {value:?}: {e}"));
    if let Some(hex) = value.strip_prefix('#') {
        let bytes = decode_hex(hex).ok_or_else(|| bad(&"not hex"))?;
        return Any::from_der(&bytes).map_err(|e| bad(&e));
    }
    let value = value.strip_prefix('\\').unwrap_or(value);
    match *oid {
        oid::EMAIL_ADDRESS | oid::DOMAIN_COMPONENT => {
            Any::encode_from(&ia5(value)?).map_err(|e| bad(&e))
        }
        oid::DATE_OF_BIRTH => {
            asn1util::generalized_time(value.as_bytes()).map_err(|e| bad(&e))?;
            Any::new(Tag::GeneralizedTime, value.as_bytes()).map_err(|e| bad(&e))
        }
        oid::COUNTRY | oid::SERIAL_NUMBER | oid::DN_QUALIFIER | oid::TELEPHONE_NUMBER => {
            PrintableStringRef::new(value)
                .and_then(|s| Any::encode_from(&s))
                .map_err(|e| bad(&e))
        }
        _ => Utf8StringRef::new(value)
            .and_then(|s| Any::encode_from(&s))
            .map_err(|e| bad(&e)),
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The order of Kalkan applet's `NaturalOrderComparator`, which sorts the `dn` OIDs. Its
/// number runs take `.` and `,` as digits, so an OID is one run: a longer OID sorts after a
/// shorter one and OIDs of one length by their first differing character, e.g.
/// `2.5.4.3 < 2.5.4.5 < 2.5.4.11 < 1.2.840.113549.1.9.1`. Spaces and zeros before a run
/// are skipped (the count of zeros breaks ties). For ASCII strings such as OIDs.
pub fn natural_order(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut ia, mut ib) = (0, 0);
    loop {
        let (mut zeros_a, mut zeros_b) = (0usize, 0usize);
        let mut ca = at(a, ia);
        while ca == b' ' || ca == b'0' {
            zeros_a = if ca == b'0' { zeros_a + 1 } else { 0 };
            ia += 1;
            ca = at(a, ia);
        }
        let mut cb = at(b, ib);
        while cb == b' ' || cb == b'0' {
            zeros_b = if cb == b'0' { zeros_b + 1 } else { 0 };
            ib += 1;
            cb = at(b, ib);
        }
        if ca.is_ascii_digit() && cb.is_ascii_digit() {
            let bias = compare_runs(&a[ia..], &b[ib..]);
            if bias != Ordering::Equal {
                return bias;
            }
        }
        if ca == 0 && cb == 0 {
            return zeros_a
                .cmp(&zeros_b)
                .then(a.len().cmp(&b.len()))
                .then(a.cmp(b));
        }
        match ca.cmp(&cb) {
            Ordering::Equal => {}
            unequal => return unequal,
        }
        ia += 1;
        ib += 1;
    }
}

/// Compares the leading runs of digits, `.` and `,`: the longer run is greater; runs of one
/// length compare by their first differing character.
fn compare_runs(a: &[u8], b: &[u8]) -> Ordering {
    let in_run = |c: u8| c.is_ascii_digit() || c == b'.' || c == b',';
    let mut bias = Ordering::Equal;
    for i in 0.. {
        let (ca, cb) = (at(a, i), at(b, i));
        match (in_run(ca), in_run(cb)) {
            (false, false) => return bias,
            (false, true) => return Ordering::Less,
            (true, false) => return Ordering::Greater,
            (true, true) if bias == Ordering::Equal => bias = ca.cmp(&cb),
            (true, true) => {}
        }
    }
    unreachable!("the runs end")
}

/// The character at `i`, `0` past the end (Java's `charAt` helper of the comparator).
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::PublicKey;

    fn subject_oids(der: &[u8]) -> Vec<String> {
        CertReq::from_der(der)
            .unwrap()
            .info
            .subject
            .iter_rdn()
            .map(|rdn| rdn.iter().next().unwrap().oid.to_string())
            .collect()
    }

    #[test]
    fn legacy_requests_keep_the_subject_order() {
        let key = crate::keygen::generate(KeySpec::Gost2004).unwrap();
        let dn = [
            (oid::COUNTRY, "KZ".to_owned()),
            (oid::COMMON_NAME, "A".to_owned()),
        ];
        let der = build_legacy_csr(
            &key,
            KeySpec::Gost2004,
            &LegacyCsrRequest {
                dn: &dn,
                dns_names: None,
            },
        )
        .unwrap();
        assert_eq!(subject_oids(&der), ["2.5.4.6", "2.5.4.3"]);
        let request = CertReq::from_der(&der).unwrap();
        let public = PublicKey::from_spki(&request.info.public_key).unwrap();
        public
            .verify(
                SigAlg::Gost2004,
                &request.info.to_der().unwrap(),
                request.signature.as_bytes().unwrap(),
            )
            .unwrap();
        // Another key's spec is refused, as in `build_csr`.
        assert_eq!(
            build_legacy_csr(
                &key,
                KeySpec::Gost2015_512,
                &LegacyCsrRequest {
                    dn: &dn,
                    dns_names: None
                }
            ),
            Err(KeystoreError::UnknownAlgorithm)
        );
    }

    #[test]
    fn natural_order_of_oids() {
        let mut oids = [
            "1.2.840.113549.1.9.1",
            "2.5.4.11",
            "2.5.4.3",
            "2.5.4.42",
            "2.5.4.5",
            "2.5.4.10",
            "2.5.4.4",
        ];
        oids.sort_by(|a, b| natural_order(a, b));
        assert_eq!(
            oids,
            [
                "2.5.4.3",
                "2.5.4.4",
                "2.5.4.5",
                "2.5.4.10",
                "2.5.4.11",
                "2.5.4.42",
                "1.2.840.113549.1.9.1"
            ]
        );
        assert_eq!(natural_order("2.5.4.3", "2.5.4.3"), Ordering::Equal);
    }

    #[test]
    fn natural_order_of_words_and_numbers() {
        assert_eq!(natural_order("a2", "a10"), Ordering::Less);
        assert_eq!(natural_order("x 1", "x1"), Ordering::Greater);
        assert_eq!(natural_order("007", "7"), Ordering::Greater);
        assert_eq!(natural_order("abc", "abd"), Ordering::Less);
    }

    #[test]
    fn hex_values() {
        assert_eq!(decode_hex("0c0161"), Some(vec![0x0c, 0x01, 0x61]));
        assert_eq!(decode_hex("0c0"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("é0"), None);
    }
}
