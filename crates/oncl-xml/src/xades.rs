//! Source XAdES B/T/LT/LTA and explicit bounded legacy adapters.
//!
//! [`sign_source`] and [`sign_prepared`] implement EN 319 132-1 V1.2.1
//! baseline properties, actual shared F03/F04 proofs and non-distributed v1.4.1
//! archive coverage (§5.5.2.2). [`extend_source`] renews proof-only without a key.
//! Every present proof is checked; one SignatureTimeStamp and multiple archive
//! renewals are supported. Dynamic host services sample time after TSA replies;
//! fixed-as-of services retain explicit validation-time semantics.
//!
//! [`prepare_spec_source`] accepts bounded [`XadesSpec`] options through a
//! DigestSigner, prepares before key opening and emits complete B/T/LT baseline
//! properties using the same metadata/crypto and evidence kernels.
//!
//! [`sign`] remains the old bounded PrivateKey wire API: claimed SigningTime,
//! SigningCertificateV2 and optional timestamp/status elements, preserving its
//! historical certificate-derived default algorithm and XML layout. Its legacy
//! shape lacks mandatory DataObjectFormat: successful mathematical verification
//! alone must not report a complete EN baseline level. Use Source or the guarded
//! prepared adapter for new baseline generation.

use crate::{C14n, QualifyingObject, XmlError, XmlSignSpec};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use oncl_pki::cert::{self, Certificate};
use oncl_pki::crl::{self, CrlError, CrlStatus};
use oncl_pki::http::{HttpTransport, NonceSpec, PkiMethod};
use oncl_pki::key::{HashAlg, PrivateKey};
use oncl_pki::ocsp::{self, CertStatus, OcspError};
use oncl_pki::tsp::{self, TsaSpec, TspError};
use sha2::{Digest, Sha256};
use std::time::Duration;
use time::OffsetDateTime;
pub(crate) mod source;
pub use source::{
    XadesReport, XadesServices, XadesSourceSpec, extend_source, extend_staged, extend_transaction,
    prepare_source, sign_prepared, sign_source, sign_staged,
};

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
/// [`XadesError::Xml`] as [`crate::sign_spec`] fails, and for T or LT without a TSA;
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
    // Santuario's line breaks: XAdES is not Kalkan's `createXmlSignature`.
    let xml_spec = XmlSignSpec {
        signature_method: spec.signature_method,
        digest_method: spec.digest_method,
        signature_id: Some(&id),
        strip_whitespace: false,
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = crate::sign_qualified(
        xml,
        &xml_spec,
        key,
        cert,
        QualifyingObject {
            signed_properties: &signed_properties,
            signed_properties_id: &properties_id,
            data_reference_id: None,
        },
    )?;
    let Some(tsa) = tsa else {
        return Ok(signed);
    };

    let imprint = crate::signature_value_digest(&signed, &id, tsa.hash)?;
    let stamp = tsp::request(tsa, imprint.as_bytes(), http)?;
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
    Ok(crate::append_qualifying(&signed, &id, &unsigned)?)
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

/// Prepared bounded XadesSpec-compatible operation. Algorithms and public chain
/// options remain explicit; TSA authority belongs to the supplied host services.
/// Unlike the historical wire adapter, this generates the required baseline
/// DataObjectFormat and uses the shared strict evidence implementation.
pub struct PreparedXadesSpec<'a> {
    prepared: crate::PreparedLegacySign<'a>,
    id: String,
    context: String,
    level: oncl_pki::evidence::AdesLevel,
    signing_time: OffsetDateTime,
    chain: Vec<Certificate>,
    _metadata: oncl_pki::resource::ResourceReservation,
    _chain_metadata: oncl_pki::resource::ResourceReservation,
}
pub fn prepare_spec_source<'a>(
    input: oncl_pki::io::Source<'_>,
    spec: &XadesSpec<'a>,
    now: OffsetDateTime,
    services: &XadesServices<'_>,
    scope: &mut oncl_pki::resource::ResourceScope,
) -> Result<PreparedXadesSpec<'a>, crate::XmlSourceError> {
    use oncl_pki::{evidence::AdesLevel, resource::ProcessingError};
    let level = match spec.level {
        XadesLevel::B => AdesLevel::B,
        XadesLevel::T => AdesLevel::T,
        XadesLevel::Lt => AdesLevel::Lt,
    };
    if level > AdesLevel::B && spec.tsa.as_ref() != services.tsa {
        return Err(crate::XmlSourceError::Malformed(
            "XadesSpec TSA must equal explicit host configuration",
        ));
    }
    let profile = crate::XmlSignProfile::default();
    // B/T do not serialize the request's chain. Preserve that compatibility
    // contract instead of rejecting or copying ignored public material.
    let selected_chain = if level >= AdesLevel::Lt {
        spec.chain.as_slice()
    } else {
        &[]
    };
    // Inspect the actual material union without cloning/encoding it, before
    // intake or key opening. The later union uses these same certificate slices.
    services.preflight_with_certificates(level, &profile, selected_chain)?;
    let chain_bytes =
        selected_chain
            .iter()
            .try_fold(0u64, |n, cert| -> Result<u64, crate::XmlSourceError> {
                let len = u32::from(cert.encoded_len().map_err(|_| {
                    crate::XmlSourceError::Malformed("XadesSpec certificate DER length")
                })?);
                n.checked_add(u64::from(len))
                    .ok_or(ProcessingError::MetadataLimit.into())
            })?;
    let chain_metadata = scope.reserve_metadata(
        chain_bytes
            .checked_mul(4)
            .and_then(|n| {
                n.checked_add(
                    selected_chain.len() as u64 * std::mem::size_of::<Certificate>() as u64,
                )
            })
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let metadata = scope.reserve_metadata(profile.max_metadata_bytes as u64 * 8)?;
    // These are the XadesSpec's actual supported options, not a guessed ID selector.
    let xml = XmlSignSpec {
        signature_method: spec.signature_method,
        digest_method: spec.digest_method,
        signed_info_c14n: Some(C14n::Exclusive),
        transforms: Some(vec![
            crate::Transform::Enveloped,
            crate::Transform::C14n(C14n::Exclusive),
        ]),
        strip_whitespace: false,
        output: crate::XmlOutput::AsIs,
        ..XmlSignSpec::kalkan(None, None)
    };
    let prepared = crate::prepare_legacy_source(input, &xml, services.temporary, scope)?;
    let id = signature_id(prepared.bytes(), &[], now);
    let doc = crate::parse::parse_admitted(prepared.bytes(), false, Some(scope))?;
    for node in doc.descendants().filter(roxmltree::Node::is_element) {
        if crate::is_ds(node, "Signature") {
            return Err(crate::XmlSourceError::Malformed(
                "bounded XadesSpec Create cannot replace an existing signature",
            ));
        }
        if node.attribute("Id").is_some_and(|value| {
            value == id
                || value == format!("{id}-SignedProperties")
                || value == format!("{id}-Reference-0")
        }) {
            return Err(crate::XmlSourceError::Malformed(
                "bounded XAdES derived ID collision",
            ));
        }
    }
    let root = doc.root_element();
    let mut context = String::from("<context");
    for namespace in root.namespaces() {
        if namespace.name() == Some("xml") {
            continue;
        }
        let name = namespace
            .name()
            .map_or_else(|| "xmlns".to_owned(), |p| format!("xmlns:{p}"));
        context.push_str(&format!(
            " {name}=\"{}\"",
            crate::escape_attribute(namespace.uri())
        ));
    }
    for attribute in root
        .attributes()
        .filter(|a| a.namespace() == Some("http://www.w3.org/XML/1998/namespace"))
    {
        context.push_str(&format!(
            " xml:{}=\"{}\"",
            attribute.name(),
            crate::escape_attribute(attribute.value())
        ));
    }
    context.push_str(">\0");
    context.push('0');
    if context.len() > profile.max_metadata_bytes {
        return Err(ProcessingError::MetadataLimit.into());
    }
    drop(doc);
    Ok(PreparedXadesSpec {
        prepared,
        id,
        context,
        level,
        signing_time: now,
        chain: selected_chain.to_vec(),
        _metadata: metadata,
        _chain_metadata: chain_metadata,
    })
}
impl PreparedXadesSpec<'_> {
    pub fn sign_transaction(
        self,
        signer: &mut dyn oncl_pki::key::DigestSigner,
        services: &XadesServices<'_>,
        output: &mut oncl_pki::io::XmlSignatureOutput<'_>,
        scope: &mut oncl_pki::resource::ResourceScope,
        admit: &mut dyn FnMut(u64) -> Result<(), oncl_pki::resource::ProcessingError>,
    ) -> Result<XadesReport, crate::XmlSourceError> {
        use oncl_pki::{evidence::SignerEvidence, resource::ProcessingError, validation::Verdict};
        let spec = XadesSourceSpec {
            xml: crate::XmlSignProfile {
                signature_id: Some(&self.id),
                canonicalization: crate::C14nProfile::KalkanLegacy,
                strip_whitespace: false,
                ..Default::default()
            },
            level: self.level,
            signing_time: self.signing_time,
        };
        let (properties, properties_id, reference_id) =
            source::properties(&spec, signer.certificate())?;
        let mut signed = self.prepared.sign_bytes(
            signer,
            scope,
            Some((
                &self.id,
                QualifyingObject {
                    signed_properties: &properties,
                    signed_properties_id: &properties_id,
                    data_reference_id: Some(&reference_id),
                },
            )),
            Some(admit),
        )?;
        let (signature, digest, raw_value) = {
            let doc = crate::parse::parse_admitted(&signed.bytes, false, Some(scope))?;
            let signature = doc
                .descendants()
                .find(|n| crate::is_ds(*n, "Signature") && n.attribute("Id") == Some(&self.id))
                .ok_or(crate::XmlSourceError::Malformed("generated Signature"))?;
            let digest = crate::canonicalizer(C14n::Exclusive)
                .hash(
                    crate::ds_child(signature, "SignedInfo")?,
                    signer.algorithm().hash_alg(),
                )?
                .0;
            let encoded: String = crate::ds_child(signature, "SignatureValue")?
                .text()
                .unwrap_or_default()
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            let raw = STANDARD
                .decode(encoded)
                .map_err(|_| crate::XmlSourceError::Malformed("generated SignatureValue Base64"))?;
            (
                std::str::from_utf8(&signed.bytes[signature.range()])
                    .map_err(|_| crate::XmlSourceError::Malformed("generated Signature UTF8"))?
                    .to_owned(),
                digest,
                raw,
            )
        };
        let candidate_bytes = services.material.certificates.iter().try_fold(
            (services.material.certificates.len() + self.chain.len()) as u64
                * std::mem::size_of::<Certificate>() as u64,
            |n, cert| -> Result<u64, crate::XmlSourceError> {
                let len = u32::from(cert.encoded_len().map_err(|_| {
                    crate::XmlSourceError::Malformed("XAdES service certificate length")
                })?);
                n.checked_add(u64::from(len) * 4)
                    .ok_or(ProcessingError::MetadataLimit.into())
            },
        )?;
        let _candidate_metadata = scope.reserve_metadata(candidate_bytes)?;
        let mut certificates = services.material.certificates.to_vec();
        certificates.extend(self.chain);
        let effective = XadesServices {
            validation: services.validation,
            network: services.network,
            temporary: services.temporary,
            tsa: services.tsa,
            material: oncl_pki::cms::ades::ValidationMaterial {
                certificates: &certificates,
                ocsp: services.material.ocsp,
                crls: services.material.crls,
            },
            evidence_limits: services.evidence_limits,
            host_clock: services.host_clock,
        };
        let mut work = crate::REFERENCE_WORK as u64;
        let complete = source::complete_signature(
            &mut signed.canonical,
            &signature,
            &self.context,
            &SignerEvidence {
                certificate: signer.certificate(),
                algorithm: signer.algorithm(),
                signed_digest: digest,
                signature: &raw_value,
                claimed_time: Some(self.signing_time),
            },
            &spec,
            &effective,
            scope,
            &mut work,
        )?;
        if complete.len() > spec.xml.max_metadata_bytes {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let doc = crate::parse::parse_admitted(&signed.bytes, false, Some(scope))?;
        let range = doc
            .descendants()
            .find(|n| crate::is_ds(*n, "Signature") && n.attribute("Id") == Some(&self.id))
            .ok_or(crate::XmlSourceError::Malformed(
                "generated bounded Signature",
            ))?
            .range();
        drop(doc);
        output.append(&signed.bytes[..range.start])?;
        output.append(complete.as_bytes())?;
        output.append(&signed.bytes[range.end..])?;
        let profile = crate::XmlVerifyProfile {
            canonicalization: crate::C14nProfile::KalkanLegacy,
            required_level: Some(self.level),
            evidence_limits: Some(effective.bounded_limits(&spec.xml)?),
            ..Default::default()
        };
        let mut summary = signed.into_summary();
        drop(complete);
        drop(signature);
        drop(raw_value);
        drop(self.context);
        drop(self._metadata);
        let verification = effective.verify(output.source()?, &profile, scope)?;
        if verification.validation.verdict == Verdict::Invalid
            || (services.validation.policy == oncl_pki::validation::ValidationPolicy::StrictOnline
                && verification.validation.verdict != Verdict::Valid)
        {
            return Err(crate::XmlSourceError::Malformed(
                "final bounded XAdES validation failed",
            ));
        }
        summary.bytes_out = output.len();
        Ok(XadesReport {
            summary,
            verification,
        })
    }
}
