//! Helpers for tests of certificate validation: certificates issued on the fly.

use crate::cert::{self, Certificate};
use crate::key::{KeyAlg, SigAlg};
use crate::pkcs12::KeyEntry;
use der::asn1::{Any, BitString};
use der::{Encode, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::Version;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

/// Contents of a certificate to issue.
#[derive(Clone, Debug)]
pub struct TestCertSpec {
    /// Subject name.
    pub subject: Name,
    /// Subject public key.
    pub public_key: SubjectPublicKeyInfoOwned,
    /// Serial number: unsigned big-endian bytes.
    pub serial: Vec<u8>,
    /// Validity period.
    pub validity: Validity,
    /// Extensions, written as given (none adds an AuthorityKeyIdentifier).
    pub extensions: Vec<Extension>,
}

impl TestCertSpec {
    /// The subject, key, serial, validity and extensions of `cert`, to issue a variant of it.
    pub fn from_cert(cert: &Certificate) -> TestCertSpec {
        let tbs = cert.tbs_certificate();
        TestCertSpec {
            subject: tbs.subject().clone(),
            public_key: tbs.subject_public_key_info().clone(),
            serial: tbs.serial_number().as_bytes().to_vec(),
            validity: *tbs.validity(),
            extensions: tbs.extensions().cloned().unwrap_or_default(),
        }
    }
}

/// `TBSCertificate` of RFC 5280: `x509-cert` keeps its fields private.
#[derive(Sequence)]
struct TbsCertificate {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    version: Version,
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Vec<Extension>>,
}

/// `Certificate` of RFC 5280.
#[derive(Sequence)]
struct SignedCertificate {
    tbs_certificate: TbsCertificate,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

/// Issues a v3 certificate of `spec` signed by `issuer`: the issuer name is the subject of
/// `issuer.cert`, the algorithm follows the key (GOST 34.310-2004, GOST 34.10-2015-512 or
/// sha256WithRSA, with NULL parameters as the NCA writes them).
///
/// # Panics
///
/// If `spec` does not encode (e.g. an empty serial) or signing fails.
pub fn issue_cert(issuer: &KeyEntry, spec: TestCertSpec) -> Certificate {
    let alg = match issuer.key.alg() {
        KeyAlg::Gost2004 => SigAlg::Gost2004,
        KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
        KeyAlg::Rsa => SigAlg::RsaSha256,
    };
    let algorithm = AlgorithmIdentifierOwned {
        oid: alg.signature_oid(),
        parameters: Some(Any::null()),
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&spec.serial).expect("serial number"),
        signature: algorithm.clone(),
        issuer: issuer.cert.tbs_certificate().subject().clone(),
        validity: spec.validity,
        subject: spec.subject,
        subject_public_key_info: spec.public_key,
        extensions: (!spec.extensions.is_empty()).then_some(spec.extensions),
    };
    let tbs_der = tbs.to_der().expect("TBSCertificate encodes");
    let signature = issuer.key.sign(alg, &tbs_der).expect("issuer key signs");
    let der = SignedCertificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature).expect("signature BIT STRING"),
    }
    .to_der()
    .expect("Certificate encodes");
    let cert = cert::parse(&der).expect("issued certificate parses");
    assert_eq!(
        cert.tbs_certificate()
            .to_der()
            .expect("TBSCertificate encodes"),
        tbs_der,
        "TBSCertificate re-encodes byte for byte"
    );
    cert
}
