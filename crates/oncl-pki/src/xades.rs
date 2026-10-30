//! XAdES-BASELINE signatures (ETSI EN 319 132-1, XAdES 1.3.2) of a whole XML document, at
//! the levels plugins ask for:
//!
//! - **B**: an enveloped `ds:Signature` (as [`xmldsig::sign_enveloped`] makes it, with an
//!   `Id`) with `xades:QualifyingProperties` in a `ds:Object`; its `SignedProperties`
//!   (`SigningTime`, `SigningCertificateV2` with the SHA-256 of the signer's certificate)
//!   are signed by a second reference of the type `http://uri.etsi.org/01903#SignedProperties`;
//! - **T**: and an unsigned `SignatureTimeStamp` over the `ds:SignatureValue` element,
//!   canonicalized with Exclusive XML Canonicalization;
//! - **LT**: and `CertificateValues` (the signer's path: its issuer, that issuer's issuer
//!   and so on, taken from the certificates given) and `RevocationValues` (for the signer's
//!   certificate and each certificate of the path other than a self-signed root: an OCSP
//!   response from the responder of the certificate's AIA through [`ocsp::fetch`], or, for
//!   a certificate naming no responder, the CRLs of its distribution points through
//!   [`crl::fetch_for`]; a certificate with neither is an error).
//!
//! The signature and algorithm URIs follow the signer's certificate as Kalkan's do (GOST
//! 2015-512, GOST 2004, RSA-SHA256), unless the spec names them. Byte-for-byte equality
//! with other XAdES signers is not a goal; the structure is B-LT's, and the signature passes
//! [`xmldsig::verify`].

use crate::cert::{self, Certificate};
use crate::crl::{self, CrlError, CrlStatus};
use crate::http::{HttpTransport, NonceSpec, PkiMethod};
use crate::key::{HashAlg, PrivateKey};
use crate::ocsp::{self, CertStatus, OcspError};
use crate::tsp::{self, TsaSpec, TspError};
use crate::xmldsig::{self, C14n, QualifyingObject, XmlError, XmlSignSpec};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use sha2::{Digest, Sha256};
use std::time::Duration;
use time::OffsetDateTime;

/// The `DigestMethod` of `SigningCertificateV2`.
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Timeout of each OCSP request of [`XadesLevel::Lt`].
const OCSP_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout of each CRL download of [`XadesLevel::Lt`].
const CRL_TIMEOUT: Duration = Duration::from_secs(30);

/// How much a XAdES signature carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XadesLevel {
    /// The signed properties.
    B,
    /// And a signature time-stamp.
    T,
    /// And the certificates and OCSP responses to validate it later.
    Lt,
}

/// How to make a XAdES signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XadesSpec<'a> {
    /// The level.
    pub level: XadesLevel,
    /// The TSA of [`XadesLevel::T`] and [`XadesLevel::Lt`]; not used for
    /// [`XadesLevel::B`].
    pub tsa: Option<TsaSpec>,
    /// The certificates the signer's path is taken from, in any order: its issuers (the
    /// root may be among them), possibly a whole CA list. [`XadesLevel::Lt`] puts the path
    /// into `CertificateValues` and asks about each certificate on it; the others are not
    /// used.
    pub chain: Vec<Certificate>,
    /// The `SignatureMethod` URI; `None`: Kalkan's for the certificate's algorithm.
    pub signature_method: Option<&'a str>,
    /// The `DigestMethod` URI; `None`: the one paired with the signature method.
    pub digest_method: Option<&'a str>,
}

/// Why a XAdES signature is not made.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XadesError {
    /// The document cannot be signed so, or the spec is inconsistent.
    #[error(transparent)]
    Xml(#[from] XmlError),
    /// The time-stamp failed.
    #[error("time-stamp: {0}")]
    Tsp(#[from] TspError),
    /// No OCSP response about a certificate of the chain, from its responder at `url`
    /// (empty if the certificate names none).
    #[error("OCSP of {subject}: {error}")]
    Ocsp {
        /// The certificate's subject.
        subject: String,
        /// The responder's URL.
        url: String,
        /// What failed.
        error: OcspError,
    },
    /// A responder answered without a successful response (`OCSPResponseStatus`).
    #[error("OCSP of {subject}: response status {status}")]
    OcspRejected {
        /// The certificate's subject.
        subject: String,
        /// The responder's URL.
        url: String,
        /// The `OCSPResponseStatus`.
        status: u8,
    },
    /// A certificate of the chain is not good: revoked (in its OCSP response or CRL), or
    /// unknown to its responder.
    #[error("status of {subject}: {status:?}")]
    NotGood {
        /// The certificate's subject.
        subject: String,
        /// Its status.
        status: CertStatus,
    },
    /// The chain has no issuer of a certificate that is not self-signed.
    #[error("the chain has no issuer of {0}")]
    NoIssuer(String),
    /// No CRL of a certificate that names no OCSP responder, from its distribution point
    /// at `url` (empty if it names none: then it has no revocation data at all).
    #[error("CRL of {subject}: {error}")]
    Crl {
        /// The certificate's subject.
        subject: String,
        /// The first distribution point's URL.
        url: String,
        /// What failed.
        error: CrlError,
    },
}

/// Signs the whole of `xml` with `key` (certificate `cert`) as a XAdES-BASELINE signature
/// of `spec.level` made at `now`; time-stamps and OCSP requests go through `http`.
///
/// # Errors
///
/// [`XadesError::Xml`] as [`xmldsig::sign_spec`] fails, and for T or LT without a TSA;
/// [`XadesError::Tsp`]; for LT, [`XadesError::NoIssuer`], the OCSP and CRL failures
/// (including a certificate naming neither a responder nor a distribution point), and a
/// certificate that is not good.
pub fn sign(
    xml: &[u8],
    spec: &XadesSpec<'_>,
    key: &PrivateKey,
    cert: &Certificate,
    http: &dyn HttpTransport,
    now: OffsetDateTime,
) -> Result<Vec<u8>, XadesError> {
    let tsa = match (spec.level, &spec.tsa) {
        (XadesLevel::B, _) => None,
        (_, Some(tsa)) => Some(tsa),
        (_, None) => {
            return Err(
                XmlError::Constraint("a XAdES-T or -LT signature needs a TSA".to_owned()).into(),
            );
        }
    };
    let cert_der = cert
        .to_der()
        .map_err(|e| XmlError::Parse(format!("certificate: {e}")))?;
    let id = signature_id(xml, &cert_der, now);
    let properties_id = format!("{id}-SignedProperties");
    let utc = now.to_offset(time::UtcOffset::UTC);
    let signing_time = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    );
    let signed_properties = format!(
        "<xades:SignedProperties Id=\"{properties_id}\">\
         <xades:SignedSignatureProperties>\
         <xades:SigningTime>{signing_time}</xades:SigningTime>\
         <xades:SigningCertificateV2><xades:Cert><xades:CertDigest>\
         <ds:DigestMethod Algorithm=\"{SHA256_URI}\"/>\
         <ds:DigestValue>{}</ds:DigestValue>\
         </xades:CertDigest></xades:Cert></xades:SigningCertificateV2>\
         </xades:SignedSignatureProperties>\
         </xades:SignedProperties>",
        STANDARD.encode(Sha256::digest(&cert_der)),
    );
    let xml_spec = XmlSignSpec {
        signature_method: spec.signature_method,
        digest_method: spec.digest_method,
        signature_id: Some(&id),
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = xmldsig::sign_qualified(
        xml,
        &xml_spec,
        key,
        cert,
        QualifyingObject {
            signed_properties: &signed_properties,
            signed_properties_id: &properties_id,
        },
    )?;
    let Some(tsa) = tsa else {
        return Ok(signed);
    };

    let value = xmldsig::signature_value_c14n(&signed, &id)?;
    let stamp = tsp::request(tsa, &tsa.hash.digest(&value), http)?;
    let mut unsigned = format!(
        "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>\
         <xades:SignatureTimeStamp Id=\"{id}-SignatureTimeStamp\">\
         <ds:CanonicalizationMethod Algorithm=\"{}\"/>\
         <xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp>\
         </xades:SignatureTimeStamp>",
        C14n::Exclusive.uri(),
        STANDARD.encode(&stamp.token),
    );
    if spec.level == XadesLevel::Lt {
        let path = signer_path(cert, &spec.chain)?;
        let revocation = revocation_values(cert, &path, http, now)?;
        unsigned.push_str("<xades:CertificateValues>");
        for issuer in &path {
            let der = issuer
                .to_der()
                .map_err(|e| XmlError::Parse(format!("certificate: {e}")))?;
            unsigned.push_str(&format!(
                "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                STANDARD.encode(der)
            ));
        }
        unsigned.push_str("</xades:CertificateValues><xades:RevocationValues>");
        let lists = [
            ("CRLValues", "EncapsulatedCRLValue", &revocation.crls),
            ("OCSPValues", "EncapsulatedOCSPValue", &revocation.ocsp),
        ];
        for (list, value, items) in lists {
            if items.is_empty() {
                continue;
            }
            unsigned.push_str(&format!("<xades:{list}>"));
            for item in items {
                unsigned.push_str(&format!(
                    "<xades:{value}>{}</xades:{value}>",
                    STANDARD.encode(item)
                ));
            }
            unsigned.push_str(&format!("</xades:{list}>"));
        }
        unsigned.push_str("</xades:RevocationValues>");
    }
    unsigned.push_str("</xades:UnsignedSignatureProperties></xades:UnsignedProperties>");
    Ok(xmldsig::append_qualifying(&signed, &id, &unsigned)?)
}

/// An `Id` for the signature: of the document, the certificate and the time, so two
/// signatures of a document differ.
fn signature_id(xml: &[u8], cert_der: &[u8], now: OffsetDateTime) -> String {
    let mut hash = Sha256::new();
    hash.update(xml);
    hash.update(cert_der);
    hash.update(now.unix_timestamp_nanos().to_be_bytes());
    let digest = hash.finalize();
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("xades-{hex}")
}

/// Whether `cert` is self-signed: its issuer is its subject, and its own key verifies it.
fn self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate().issuer() == cert.tbs_certificate().subject()
        && cert::verify_signature(cert, cert).is_ok()
}

/// The signer's path through `cas`: its issuer, the issuer's issuer, and so on, up to a
/// self-signed certificate or a certificate whose issuer is not among `cas`. A certificate
/// is its issuer's when the issuer's key verifies it; one certificate never appears twice.
///
/// # Errors
///
/// [`XadesError::NoIssuer`] when no certificate of `cas` issued the signer's.
fn signer_path(signer: &Certificate, cas: &[Certificate]) -> Result<Vec<Certificate>, XadesError> {
    let issued = |cert: &Certificate, path: &[Certificate]| {
        cas.iter()
            .find(|ca| !path.contains(ca) && cert::verify_signature(cert, ca).is_ok())
            .cloned()
    };
    let first = issued(signer, &[])
        .ok_or_else(|| XadesError::NoIssuer(signer.tbs_certificate().subject().to_string()))?;
    let mut path = vec![first];
    while let Some(last) = path.last().filter(|last| !self_signed(last))
        && let Some(next) = issued(last, &path)
    {
        path.push(next);
    }
    Ok(path)
}

/// The revocation data of an LT signature, as `RevocationValues` carries it.
struct RevocationValues {
    /// The CRLs, as received.
    crls: Vec<Vec<u8>>,
    /// The `OCSPResponse`s, as received.
    ocsp: Vec<Vec<u8>>,
}

/// The revocation data of `signer` and each certificate of `chain` that is not self-signed,
/// in that order, each saying the certificate is good: an `OCSPResponse` from the
/// responder of the certificate's AIA, or, for a certificate naming no responder, the CRLs
/// of its distribution points ([`crl::fetch_for`]). A certificate naming neither has no
/// revocation data, which is an error, not a gap.
fn revocation_values(
    signer: &Certificate,
    chain: &[Certificate],
    http: &dyn HttpTransport,
    now: OffsetDateTime,
) -> Result<RevocationValues, XadesError> {
    let request = ocsp::RequestSpec {
        cert_id_hash: HashAlg::Sha1,
        nonce: NonceSpec::None,
        method: PkiMethod::Post { content_type: None },
        url: None,
        timeout: OCSP_TIMEOUT,
    };
    let mut values = RevocationValues {
        crls: Vec::new(),
        ocsp: Vec::new(),
    };
    for cert in std::iter::once(signer).chain(chain) {
        if self_signed(cert) {
            continue;
        }
        let subject = cert.tbs_certificate().subject().to_string();
        let issuer = chain
            .iter()
            .find(|candidate| cert::verify_signature(cert, candidate).is_ok())
            .ok_or_else(|| XadesError::NoIssuer(subject.clone()))?;
        let Some(url) = ocsp::ocsp_url(cert) else {
            // A CA naming no responder (as the NCA's intermediates): its CRL.
            let (crls, status) =
                crl::fetch_for(cert, issuer, http, CRL_TIMEOUT, now).map_err(|error| {
                    XadesError::Crl {
                        subject: subject.clone(),
                        url: crl::crl_urls(cert).into_iter().next().unwrap_or_default(),
                        error,
                    }
                })?;
            if let CrlStatus::Revoked { time, reason } = status {
                return Err(XadesError::NotGood {
                    subject,
                    status: CertStatus::Revoked { time, reason },
                });
            }
            values.crls.extend(crls);
            continue;
        };
        let fetched =
            ocsp::fetch(cert, issuer, &request, http, None).map_err(|error| XadesError::Ocsp {
                subject: subject.clone(),
                url: url.clone(),
                error,
            })?;
        if fetched.response_status != 0 {
            return Err(XadesError::OcspRejected {
                subject,
                url,
                status: fetched.response_status,
            });
        }
        match fetched.answer.map(|answer| answer.status) {
            Some(CertStatus::Good) => {}
            status => {
                return Err(XadesError::NotGood {
                    subject,
                    status: status.unwrap_or(CertStatus::Unknown),
                });
            }
        }
        values.ocsp.push(fetched.response);
    }
    Ok(values)
}
