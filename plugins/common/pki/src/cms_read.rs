//! What a plugin reads from a CMS SignedData (DER): its content, signers and certificates.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use der::{Decode, Encode};
use x509_cert::Certificate;

/// A signer of a CMS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerView {
    /// The DER of the certificate among the CMS's certificates its identifier names.
    pub sid_cert: Option<Vec<u8>>,
    /// The signature value.
    pub signature: Vec<u8>,
    /// The DER of the signed attributes as signed (a SET OF), if any.
    pub signed_attrs: Option<Vec<u8>>,
    /// The DER of the unsigned attributes (a SET OF), if any.
    pub unsigned_attrs: Option<Vec<u8>>,
}

/// The SignedData of a ContentInfo.
fn signed_data(cms: &[u8]) -> Option<SignedData> {
    let info = ContentInfo::from_der(cms).ok()?;
    if info.content_type != ID_SIGNED_DATA {
        return None;
    }
    SignedData::from_der(&info.content.to_der().ok()?).ok()
}

/// The encapsulated content, `None` for a detached CMS or one that does not parse.
pub fn content(cms: &[u8]) -> Option<Vec<u8>> {
    let signed = signed_data(cms)?;
    signed
        .encap_content_info
        .econtent
        .map(|econtent| econtent.value().to_vec())
}

/// The DER of the certificates of the CMS, in its order.
pub fn certificates(cms: &[u8]) -> Vec<Vec<u8>> {
    let Some(signed) = signed_data(cms) else {
        return Vec::new();
    };
    signed
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => cert.to_der().ok(),
            _ => None,
        })
        .collect()
}

/// The signers, in the order of the CMS.
pub fn signers(cms: &[u8]) -> Vec<SignerView> {
    let Some(signed) = signed_data(cms) else {
        return Vec::new();
    };
    let certs: Vec<Certificate> = certificates(cms)
        .iter()
        .filter_map(|der| Certificate::from_der(der).ok())
        .collect();
    signed
        .signer_infos
        .0
        .iter()
        .map(|info| SignerView {
            sid_cert: certs
                .iter()
                .find(|cert| names(&info.sid, cert))
                .and_then(|cert| cert.to_der().ok()),
            signature: info.signature.as_bytes().to_vec(),
            signed_attrs: info.signed_attrs.as_ref().and_then(|a| a.to_der().ok()),
            unsigned_attrs: info.unsigned_attrs.as_ref().and_then(|a| a.to_der().ok()),
        })
        .collect()
}

/// Whether `sid` names `cert`: its issuer and serial number, or its subject key identifier.
fn names(sid: &SignerIdentifier, cert: &Certificate) -> bool {
    let tbs = cert.tbs_certificate();
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(id) => {
            id.issuer == *tbs.issuer() && id.serial_number == *tbs.serial_number()
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => tbs
            .get_extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, own)| own.0 == ski.0),
    }
}
