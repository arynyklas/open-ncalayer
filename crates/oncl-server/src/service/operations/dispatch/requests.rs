//! Typed SDK request construction from the wire DTO. One implementation shared by the
//! sequential `/v1/operations` dispatch and the closed `/v1/batch` route.
use super::*;

/// Borrowed wire fields that select the signing profile; never an authority.
pub(in crate::service::operations) struct SignSpec<'a> {
    pub profile: SignKind,
    pub mode: SignWriteMode,
    pub attached: bool,
    pub target: Option<&'a str>,
    pub parent: Option<&'a str>,
    pub signature_id: Option<&'a str>,
    pub soap: Option<SoapKind>,
    pub body_id: Option<&'a str>,
    pub element: Option<&'a str>,
    pub xpath_parent: Option<&'a str>,
    pub signature_method: Option<&'a str>,
    pub digest_method: Option<&'a str>,
}
pub(in crate::service::operations) fn sign_request<'a>(
    spec: &SignSpec<'a>,
    mut requests: Vec<KeyRequest<'a>>,
    detached: Option<Source<'a>>,
    material: ValidationMaterial<'a>,
    limits: EvidenceLimits,
    tsa: Option<&oncl_pki::tsp::TsaSpec>,
) -> Result<oncl_core::SignRequest<'a>, OperationError> {
    let profile = spec.profile;
    let level = ades_level(profile);
    if matches!(profile, SignKind::Wsse) {
        if requests.len() != 1 {
            return Err(ProcessingError::InvalidInput("WSSE signing takes one key").into());
        }
        let key = requests.remove(0);
        let mut wsse = oncl_xml::wsse::SourceWsseSignProfile::default();
        wsse.verification.soap = soap_version(spec.soap);
        if let Some(id) = spec.body_id {
            wsse.body_id = id.to_owned();
        }
        Ok(oncl_core::SignRequest::wsse(key, wsse))
    } else if matches!(profile, SignKind::XmlLegacy) {
        if requests.len() != 1 {
            return Err(ProcessingError::InvalidInput("XML signing takes one key").into());
        }
        let key = requests.remove(0);
        let mut xml = oncl_xml::XmlSignSpec::kalkan(spec.element, spec.xpath_parent);
        xml.signature_method = spec.signature_method;
        xml.digest_method = spec.digest_method;
        Ok(oncl_core::SignRequest::xml_legacy(key, xml))
    } else if matches!(profile, SignKind::XadesLegacyB | SignKind::XadesLegacyT) {
        if requests.len() != 1 {
            return Err(ProcessingError::InvalidInput("XML signing takes one key").into());
        }
        let key = requests.remove(0);
        let timestamped = matches!(profile, SignKind::XadesLegacyT);
        let xades = oncl_xml::xades::XadesSpec {
            level: if timestamped {
                oncl_xml::xades::XadesLevel::T
            } else {
                oncl_xml::xades::XadesLevel::B
            },
            tsa: if timestamped { tsa.cloned() } else { None },
            chain: material.certificates.to_vec(),
            signature_method: spec.signature_method,
            digest_method: spec.digest_method,
        };
        Ok(oncl_core::SignRequest::xades_legacy(key, xades))
    } else if is_xml(profile) {
        if spec.mode != SignWriteMode::Create || detached.is_some() || spec.attached {
            return Err(ProcessingError::InvalidInput("XML signing is enveloped create").into());
        }
        if requests.len() != 1 {
            return Err(ProcessingError::InvalidInput("XML signing takes one key").into());
        }
        let key = requests.remove(0);
        let xml = oncl_xml::XmlSignProfile {
            target: spec.target,
            parent: spec.parent,
            signature_id: spec.signature_id,
            ..oncl_xml::XmlSignProfile::default()
        };
        Ok(match level {
            None => oncl_core::SignRequest::xml(key, xml),
            Some(level) => oncl_core::SignRequest::xades(key, xml, level),
        })
    } else if is_pdf(profile) {
        if spec.mode != SignWriteMode::Create || detached.is_some() || spec.attached {
            return Err(ProcessingError::InvalidInput("PDF signing is incremental").into());
        }
        if requests.len() != 1 {
            return Err(ProcessingError::InvalidInput("PDF signing takes one key").into());
        }
        let key = requests.remove(0);
        let pdf = oncl_pdf::PdfSignProfile::default();
        Ok(match level {
            None => oncl_core::SignRequest::pdf(key, pdf),
            Some(level) => oncl_core::SignRequest::pades(key, pdf, level, material, limits),
        })
    } else {
        Ok(match (level, spec.mode) {
            (None, SignWriteMode::Create) => {
                if detached.is_some() {
                    return Err(
                        ProcessingError::InvalidInput("create takes no detached input").into(),
                    );
                }
                oncl_core::SignRequest::cms_create(requests, spec.attached)
            }
            (None, SignWriteMode::Add) => oncl_core::SignRequest::cms_add(requests, detached),
            (Some(level), SignWriteMode::Create) => {
                if detached.is_some() {
                    return Err(
                        ProcessingError::InvalidInput("create takes no detached input").into(),
                    );
                }
                oncl_core::SignRequest::cades_create(
                    requests,
                    spec.attached,
                    level,
                    material,
                    limits,
                )
            }
            (Some(level), SignWriteMode::Add) => {
                oncl_core::SignRequest::cades_add(requests, detached, level, material, limits)
            }
        })
    }
}
pub(in crate::service::operations) fn extend_request<'a>(
    profile: ExtendKind,
    detached: Option<Source<'a>>,
    material: ValidationMaterial<'a>,
    limits: EvidenceLimits,
) -> Result<oncl_core::ExtendRequest<'a>, OperationError> {
    let (level, format) = extend_level(profile);
    let mut request = match format {
        Format::Pdf | Format::Xml if detached.is_some() => {
            return Err(ProcessingError::InvalidInput("no detached input").into());
        }
        Format::Pdf => oncl_core::ExtendRequest::pdf(level, oncl_pdf::PdfLimits::default()),
        Format::Xml => oncl_core::ExtendRequest::xml(level),
        Format::Cms => oncl_core::ExtendRequest::cms(level),
    }
    .with_evidence_limits(limits)
    .with_material(material);
    if let Some(source) = detached {
        request = request.with_detached(source);
    }
    Ok(request)
}
