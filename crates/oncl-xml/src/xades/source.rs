//! XAdES baseline B/T/LT/LTA, EN 319 132-1 V1.2.1 non-distributed §5.5.2.2.
use crate::{
    C14n, XmlDocument, XmlSignProfile, XmlSignSummary, XmlSourceError, XmlVerification,
    XmlVerifyProfile, canonical_stream::Options,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use der::Encode;
use oncl_pki::{
    cert::Certificate,
    cms::ades::ValidationMaterial,
    digest::{DigestValue, HashState},
    evidence::*,
    http::deadline::DeadlineTransport,
    io::{Region, Source, StagedArtifact, TemporaryStore, XmlSignatureOutput},
    key::{DigestSigner, HashAlg},
    resource::{IO_CHUNK_BYTES, ProcessingError, ResourceScope},
    tsp::TsaSpec,
    validation::{NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
};
use std::io::Write;
type Result<T, E = XmlSourceError> = std::result::Result<T, E>;
#[path = "tsa_material.rs"]
mod tsa_material;
pub(crate) use tsa_material::{current_tsa_validation, hash_stage};
#[derive(Clone, Debug)]
pub struct XadesSourceSpec<'a> {
    pub xml: XmlSignProfile<'a>,
    pub level: AdesLevel,
    pub signing_time: time::OffsetDateTime,
}
pub struct XadesServices<'a> {
    pub validation: &'a ValidationContext<'a>,
    pub network: &'a NetworkPolicy,
    pub temporary: &'a TemporaryStore,
    pub tsa: Option<&'a TsaSpec>,
    pub material: ValidationMaterial<'a>,
    pub evidence_limits: Option<EvidenceLimits>,
}
#[derive(Debug)]
pub struct XadesReport {
    pub summary: XmlSignSummary,
    pub verification: XmlVerification,
}
fn invalid(s: &'static str) -> XmlSourceError {
    XmlSourceError::Malformed(s)
}
pub(crate) fn limits(profile: &XmlSignProfile<'_>) -> Result<EvidenceLimits> {
    effective_limits(
        profile.max_metadata_bytes,
        profile.max_work,
        profile.evidence_limits,
    )
}
fn properties(spec: &XadesSourceSpec<'_>, cert: &Certificate) -> Result<(String, String)> {
    let id = spec
        .xml
        .signature_id
        .ok_or_else(|| invalid("XAdES needs explicit unique signature Id"))?;
    let properties_id = format!("{id}-SignedProperties");
    let time = spec
        .signing_time
        .to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| invalid("SigningTime"))?;
    let digest = STANDARD.encode(HashAlg::Sha256.digest(&crate::cert_der(cert)?));
    Ok((
        format!(
            "<xades:SignedProperties Id=\"{}\"><xades:SignedSignatureProperties><xades:SigningTime>{time}</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>{digest}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties>",
            crate::escape_attribute(&properties_id)
        ),
        properties_id,
    ))
}
/// Write only after actual final indexed XML verification. No issuance
/// configuration is needed for B; later levels use only explicit host services.
pub fn sign_source(
    input: Source<'_>,
    spec: &XadesSourceSpec<'_>,
    signer: &mut dyn DigestSigner,
    services: &XadesServices<'_>,
    output: &mut dyn Write,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    let mut stage = services.temporary.stage(scope)?;
    let report = sign_staged(input, spec, signer, services, &mut stage, scope)?;
    stage.copy_to(output)?;
    Ok(report)
}
pub fn sign_staged(
    input: Source<'_>,
    spec: &XadesSourceSpec<'_>,
    signer: &mut dyn DigestSigner,
    services: &XadesServices<'_>,
    stage: &mut StagedArtifact,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    let mut transaction = XmlSignatureOutput::new(stage, scope)?;
    services.preflight(spec.level, &spec.xml)?;
    let mut prepared = prepare_source(input, spec, services.temporary, scope)?;
    prepared.verify_existing(services.validation, services.network, scope)?;
    let report = sign_prepared(
        prepared,
        spec.level,
        spec.signing_time,
        signer,
        services,
        &mut transaction,
        scope,
    )?;
    transaction.finish(scope)?;
    Ok(report)
}
pub fn prepare_source<'a>(
    input: Source<'_>,
    spec: &XadesSourceSpec<'a>,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
) -> Result<crate::PreparedXmlSign<'a>> {
    if spec.xml.signed_info_c14n != C14n::Exclusive || spec.xml.reference_c14n != C14n::Exclusive {
        return Err(XmlSourceError::Unsupported(
            "baseline generation requires Exclusive C14N",
        ));
    }
    let id = spec
        .xml
        .signature_id
        .ok_or_else(|| invalid("XAdES needs explicit unique signature Id"))?;
    let mut prepared = crate::prepare_source(input, &spec.xml, store, scope)?;
    prepared.check_id(&format!("{id}-SignedProperties"), scope)?;
    Ok(prepared)
}
pub fn sign_prepared(
    prepared: crate::PreparedXmlSign<'_>,
    level: AdesLevel,
    signing_time: time::OffsetDateTime,
    signer: &mut dyn DigestSigner,
    services: &XadesServices<'_>,
    transaction: &mut XmlSignatureOutput<'_>,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    let spec = XadesSourceSpec {
        xml: prepared.profile().clone(),
        level,
        signing_time,
    };
    services.preflight(level, &spec.xml)?;
    let (signed_properties, properties_id) = properties(&spec, signer.certificate())?;
    let summary = prepared.finish(
        signer,
        &mut crate::sign::StageWriter(transaction),
        scope,
        Some(crate::QualifyingObject {
            signed_properties: &signed_properties,
            signed_properties_id: &properties_id,
        }),
        Some((&spec, services)),
    )?;
    let profile = XmlVerifyProfile {
        xml: spec.xml.xml.clone(),
        canonicalization: spec.xml.canonicalization,
        allowed_signature_algorithms: spec.xml.allowed_signature_algorithms,
        max_metadata_bytes: spec.xml.max_metadata_bytes,
        max_work: spec.xml.max_work,
        required_level: Some(spec.level),
        evidence_limits: Some(services.bounded_limits(&spec.xml)?),
        ..Default::default()
    };
    let verification = crate::verify_source(
        transaction.source()?,
        &profile,
        services.temporary,
        services.validation,
        services.network,
        scope,
    )?;
    if verification.validation.verdict == Verdict::Invalid
        || (services.validation.policy == ValidationPolicy::StrictOnline
            && verification.validation.verdict != Verdict::Valid)
    {
        return Err(invalid("final XAdES validation failed"));
    }
    Ok(XadesReport {
        summary,
        verification,
    })
}
fn canonical(
    signature: &str,
    context: &str,
    name: &str,
    profile: &XmlSignProfile<'_>,
) -> Result<Vec<u8>> {
    let xml = crate::sign::wrap(context, signature)?;
    if xml.len() > profile.max_metadata_bytes {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let parsed = crate::parse::parse_signed(xml.as_bytes())?;
    let node = parsed
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == name
                && matches!(
                    n.tag_name().namespace(),
                    Some(crate::DSIG_NS | crate::XADES_NS)
                )
        })
        .ok_or_else(|| invalid("generated canonical component"))?;
    canonical_node(node, profile)
}
fn canonical_node(node: roxmltree::Node<'_, '_>, profile: &XmlSignProfile<'_>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut config = crate::canonicalizer(C14n::Exclusive);
    config.limit = profile.max_metadata_bytes;
    config.write_to_profile(node, &mut out, profile.canonicalization)?;
    Ok(out)
}
fn bind_value(
    bytes: &[u8],
    signer: &SignerEvidence<'_>,
    profile: &XmlSignProfile<'_>,
    services: &XadesServices<'_>,
    scope: &mut ResourceScope,
) -> Result<BoundSignatureRepresentation> {
    let xml = std::str::from_utf8(bytes).map_err(|_| invalid("canonical value UTF8"))?;
    let parsed = roxmltree::Document::parse(xml).map_err(|_| invalid("canonical value XML"))?;
    let projections = parsed
        .root_element()
        .children()
        .filter(roxmltree::Node::is_text)
        .map(|n| Region {
            offset: n.range().start as u64,
            len: n.range().len() as u64,
        })
        .collect::<Vec<_>>();
    let mut stage = services.temporary.stage_source(scope)?;
    stage.write_chunk(bytes)?;
    Ok(BoundSignatureRepresentation::from_base64_projection(
        stage,
        Region {
            offset: 0,
            len: bytes.len() as u64,
        },
        &projections,
        signer,
        &services.bounded_limits(profile)?,
        scope,
    )?)
}
pub(crate) fn read_token(
    bundle: &mut EvidenceBundle,
    id: EvidenceId,
    max: usize,
) -> Result<Vec<u8>> {
    let n = bundle
        .entry(id)
        .ok_or_else(|| invalid("timestamp owner"))?
        .region()
        .len;
    if n > max as u64 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let mut bytes = vec![0; n as usize];
    let mut at = 0;
    while at < bytes.len() {
        let end = (at + IO_CHUNK_BYTES).min(bytes.len());
        let n = bundle.read_entry(id, at as u64, &mut bytes[at..end])?;
        if n == 0 {
            return Err(invalid("timestamp token extent"));
        }
        at += n;
    }
    Ok(bytes)
}
pub(crate) fn stamp(id: &str, archive: bool, token: &[u8]) -> String {
    let name = if archive {
        "xades141:ArchiveTimeStamp xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\""
    } else {
        "xades:SignatureTimeStamp"
    };
    let close = if archive {
        "xades141:ArchiveTimeStamp"
    } else {
        "xades:SignatureTimeStamp"
    };
    format!(
        "<{name} xmlns:xades=\"{}\" xmlns:ds=\"{}\" Id=\"{}\"><ds:CanonicalizationMethod Algorithm=\"{}\"/><xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></{close}>",
        crate::XADES_NS,
        crate::DSIG_NS,
        crate::escape_attribute(id),
        C14n::Exclusive.uri(),
        STANDARD.encode(token)
    )
}
fn with_unsigned(signature: &str, unsigned: &str) -> Result<String> {
    let at = signature
        .find("</xades:QualifyingProperties>")
        .ok_or_else(|| invalid("generated qualifying properties"))?;
    Ok(format!(
        "{}<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{unsigned}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>{}",
        &signature[..at],
        &signature[at..]
    ))
}
fn hash(algorithm: HashAlg, bytes: &[u8]) -> DigestValue {
    let mut state = HashState::new(algorithm);
    state.update(bytes);
    state.finish()
}
pub(crate) fn acquire(
    leaf: &Certificate,
    services: &XadesServices<'_>,
    scope: &ResourceScope,
) -> Result<Vec<(EvidenceKind, Vec<u8>)>> {
    let _response_memory = scope.reserve_memory(oncl_pki::http::MAX_RESPONSE_LEN * 18)?;
    let _response_metadata = scope.reserve_metadata(oncl_pki::http::MAX_RESPONSE_LEN * 2)?;
    let candidates: Vec<_> = services
        .validation
        .intermediates
        .iter()
        .chain(services.material.certificates)
        .cloned()
        .collect();
    let path = oncl_pki::pkix::build_anchored_path(
        leaf,
        services.validation.anchors,
        &candidates,
        oncl_pki::pkix::validation_time(leaf, services.validation.now),
    )
    .map_err(|_| invalid("XAdES evidence issuer path"))?;
    let transport = DeadlineTransport::new(services.validation.http, services.network, scope);
    let mut values = Vec::new();
    let result = (|| {
        for cert in path
            .iter()
            .skip(1)
            .filter(|c| !services.validation.anchors.certs().contains(c))
        {
            values.push((EvidenceKind::Certificate, crate::cert_der(cert)?));
        }
        for pair in path.windows(2) {
            let cert = &pair[0];
            let issuer = &pair[1];
            if oncl_pki::ocsp::ocsp_url(cert).is_some() {
                let request = oncl_pki::ocsp::RequestSpec {
                    cert_id_hash: HashAlg::Sha1,
                    nonce: oncl_pki::http::NonceSpec::None,
                    method: oncl_pki::http::PkiMethod::Post { content_type: None },
                    url: None,
                    timeout: std::time::Duration::from_secs(10),
                };
                let fetched = oncl_pki::ocsp::fetch(cert, issuer, &request, &transport, None)
                    .map_err(|e| XmlSourceError::Acquisition(e.to_string()))?;
                if fetched.response_status != 0 {
                    return Err(invalid("XAdES OCSP unsuccessful"));
                }
                values.push((EvidenceKind::Ocsp, fetched.response));
            } else {
                let (crls, _) = oncl_pki::crl::fetch_for(
                    cert,
                    issuer,
                    &transport,
                    std::time::Duration::from_secs(30),
                    services.validation.now,
                )
                .map_err(|e| XmlSourceError::Acquisition(e.to_string()))?;
                values.extend(crls.into_iter().map(|bytes| (EvidenceKind::Crl, bytes)));
            }
        }
        Ok(values)
    })();
    transport.finish()?;
    result
}
pub(crate) fn material_xml(
    items: &[(EvidenceKind, Vec<u8>)],
    evidence: &mut EvidenceStore,
    entries: &mut Vec<(EvidenceId, EvidenceKind)>,
    profile: &XmlSignProfile<'_>,
) -> Result<String> {
    let total = items.iter().try_fold(0usize, |n, (_, bytes)| {
        n.checked_add(bytes.len())
            .ok_or(ProcessingError::MetadataLimit)
    })?;
    if total > profile.max_metadata_bytes {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let mut certs = String::new();
    let mut ocsp = String::new();
    let mut crls = String::new();
    // Group serialization and store intake identically; each raw DER entry has one projection.
    for kind in [
        EvidenceKind::Certificate,
        EvidenceKind::Crl,
        EvidenceKind::Ocsp,
    ] {
        for (k, bytes) in items.iter().filter(|(k, _)| *k == kind) {
            let id = evidence.collect(
                *k,
                Source::sequential(&mut bytes.as_slice(), Some(bytes.len() as u64)),
                EvidenceOrigin::Embedded {
                    label: "XAdES acquired validation material",
                },
            )?;
            entries.push((id, *k));
            let tag = match kind {
                EvidenceKind::Certificate => "EncapsulatedX509Certificate",
                EvidenceKind::Crl => "EncapsulatedCRLValue",
                EvidenceKind::Ocsp => "EncapsulatedOCSPValue",
                _ => unreachable!(),
            };
            let value = format!("<xades:{tag}>{}</xades:{tag}>", STANDARD.encode(bytes));
            match kind {
                EvidenceKind::Certificate => certs.push_str(&value),
                EvidenceKind::Crl => crls.push_str(&value),
                EvidenceKind::Ocsp => ocsp.push_str(&value),
                _ => unreachable!(),
            }
        }
    }
    let mut out = String::new();
    if !certs.is_empty() {
        out.push_str(&format!(
            "<xades:CertificateValues xmlns:xades=\"{}\">{certs}</xades:CertificateValues>",
            crate::XADES_NS
        ));
    }
    if !crls.is_empty() || !ocsp.is_empty() {
        out.push_str(&format!(
            "<xades:RevocationValues xmlns:xades=\"{}\">",
            crate::XADES_NS
        ));
        if !crls.is_empty() {
            out.push_str(&format!("<xades:CRLValues>{crls}</xades:CRLValues>"))
        }
        if !ocsp.is_empty() {
            out.push_str(&format!("<xades:OCSPValues>{ocsp}</xades:OCSPValues>"))
        }
        out.push_str("</xades:RevocationValues>");
    }
    Ok(out)
}
pub(crate) fn complete_signature(
    document: &mut XmlDocument,
    signature: &str,
    context: &str,
    target: Option<Region>,
    reference_method: C14n,
    signer: &SignerEvidence<'_>,
    spec: &XadesSourceSpec<'_>,
    services: &XadesServices<'_>,
    scope: &mut ResourceScope,
    work: &mut u64,
) -> Result<String> {
    if spec.level == AdesLevel::B {
        return Ok(signature.to_owned());
    }
    let tsa = services.tsa.ok_or_else(|| invalid("XAdES TSA absent"))?;
    let value = canonical(signature, context, "SignatureValue", &spec.xml)?;
    let bound = bind_value(&value, signer, &spec.xml, services, scope)?;
    let mut evidence = EvidenceStore::new(
        services.temporary.clone(),
        services.bounded_limits(&spec.xml)?,
        scope,
    )?;
    let token_id = evidence.request_timestamp(
        signer,
        &[CoveragePart::BoundSignature(&bound)],
        tsa,
        services.validation,
        services.network,
    )?;
    let mut bundle = evidence.finish();
    let token = read_token(&mut bundle, token_id, spec.xml.max_metadata_bytes)?;
    let signature_stamp_id = format!("{}-T", spec.xml.signature_id.unwrap_or_default());
    let mut unsigned = stamp(&signature_stamp_id, false, &token);
    let mut entries = vec![(token_id, EvidenceKind::Timestamp)];
    let mut signature_tsa = None;
    if spec.level >= AdesLevel::Lt {
        let (_, tsa_leaf) = oncl_pki::tsp::verify_token_imprint(&token, &hash(tsa.hash, &value))
            .map_err(EvidenceError::from)?;
        let mut tsa_items = acquire(&tsa_leaf, services, scope)?;
        for cert in services.material.certificates {
            tsa_items.push((EvidenceKind::Certificate, crate::cert_der(cert)?));
        }
        tsa_items.extend(
            services
                .material
                .crls
                .iter()
                .map(|b| (EvidenceKind::Crl, b.to_vec())),
        );
        tsa_items.extend(
            services
                .material
                .ocsp
                .iter()
                .map(|b| (EvidenceKind::Ocsp, b.to_vec())),
        );
        let signer_items = acquire(signer.certificate, services, scope)?;
        tsa_items.retain(|item| !signer_items.contains(item));
        let mut evidence = EvidenceStore::resume(bundle);
        let tsa_xml = material_xml(&tsa_items, &mut evidence, &mut entries, &spec.xml)?;
        if !tsa_xml.is_empty() {
            unsigned.push_str(&format!("<xades141:TimeStampValidationData xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" URI=\"#{}\">{tsa_xml}</xades141:TimeStampValidationData>",crate::escape_attribute(&signature_stamp_id)));
        }
        unsigned.push_str(&material_xml(
            &signer_items,
            &mut evidence,
            &mut entries,
            &spec.xml,
        )?);
        bundle = evidence.finish();
        signature_tsa = Some(tsa_leaf);
    }
    if spec.level == AdesLevel::Lta {
        let with_properties = with_unsigned(signature, &unsigned)?;
        let xml = crate::sign::wrap(context, &with_properties)?;
        if xml.len() > spec.xml.max_metadata_bytes {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let parsed = crate::parse::parse_signed(xml.as_bytes())?;
        let mut coverage = services.temporary.stage_source(scope)?;
        document.canonical_append(
            Options {
                target,
                method: reference_method,
                profile: spec.xml.canonicalization,
                prefixes: &[],
                excluded: &[],
                metadata_limit: None,
            },
            &mut coverage,
            scope,
            work,
        )?;
        coverage.write_chunk(&canonical(
            signature,
            context,
            "SignedProperties",
            &spec.xml,
        )?)?;
        let mut value_region = Region { offset: 0, len: 0 };
        for name in ["SignedInfo", "SignatureValue", "KeyInfo"] {
            let bytes = canonical(signature, context, name, &spec.xml)?;
            let at = coverage.len();
            coverage.write_chunk(&bytes)?;
            if name == "SignatureValue" {
                value_region = Region {
                    offset: at,
                    len: bytes.len() as u64,
                }
            }
        }
        let mut groups = Vec::new();
        let mut item = 0;
        let unsigned_node = parsed
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some(crate::XADES_NS)
                    && n.tag_name().name() == "UnsignedSignatureProperties"
            })
            .ok_or_else(|| invalid("generated unsigned properties"))?;
        for property in unsigned_node.children().filter(roxmltree::Node::is_element) {
            let bytes = canonical_node(property, &spec.xml)?;
            let at = coverage.len();
            let text =
                std::str::from_utf8(&bytes).map_err(|_| invalid("canonical property UTF8"))?;
            let node =
                roxmltree::Document::parse(text).map_err(|_| invalid("canonical property XML"))?;
            for leaf in node.descendants().filter(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some(crate::XADES_NS)
                    && n.tag_name().name().starts_with("Encapsulated")
            }) {
                let (id, _) = entries
                    .get(item)
                    .ok_or_else(|| invalid("generated evidence association"))?;
                let spans = leaf
                    .children()
                    .filter(roxmltree::Node::is_text)
                    .map(|n| Region {
                        offset: at + n.range().start as u64,
                        len: n.range().len() as u64,
                    })
                    .collect::<Vec<_>>();
                groups.push((*id, spans));
                item += 1;
            }
            coverage.write_chunk(&bytes)?;
        }
        if item != entries.len() {
            return Err(invalid("generated evidence projection count"));
        }
        let groups: Vec<_> = groups
            .iter()
            .map(|(id, spans)| (*id, spans.as_slice()))
            .collect();
        let archive_imprint = hash_stage(&mut coverage, tsa.hash, scope, work)?;
        let archive = BoundArchiveRepresentation::from_base64_projections(
            coverage,
            &bound,
            value_region,
            &groups,
            signer,
            &mut bundle,
            None,
            scope,
        )?;
        let mut evidence = EvidenceStore::resume(bundle);
        let archive_id = evidence.request_timestamp(
            signer,
            &[CoveragePart::BoundArchive(&archive)],
            tsa,
            services.validation,
            services.network,
        )?;
        bundle = evidence.finish();
        let token = read_token(&mut bundle, archive_id, spec.xml.max_metadata_bytes)?;
        let archive_stamp_id = format!("{}-A1", spec.xml.signature_id.unwrap_or_default());
        unsigned.push_str(&stamp(&archive_stamp_id, true, &token));
        let (_completed, tail) = current_tsa_validation(
            bundle,
            &token,
            &archive_imprint,
            &archive_stamp_id,
            &entries,
            &spec.xml,
            services,
            scope,
            work,
            signature_tsa.as_ref(),
        )?;
        unsigned.push_str(&tail);
    }
    let result = with_unsigned(signature, &unsigned)?;
    if result.len() > spec.xml.max_metadata_bytes {
        return Err(ProcessingError::MetadataLimit.into());
    }
    Ok(result)
}

pub fn extend_source(
    input: Source<'_>,
    level: AdesLevel,
    profile: &XmlVerifyProfile,
    services: &XadesServices<'_>,
    output: &mut dyn Write,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    let mut stage = services.temporary.stage(scope)?;
    let report = extend_staged(input, level, profile, services, &mut stage, scope)?;
    stage.copy_to(output)?;
    Ok(report)
}
pub fn extend_staged(
    input: Source<'_>,
    level: AdesLevel,
    profile: &XmlVerifyProfile,
    services: &XadesServices<'_>,
    output: &mut StagedArtifact,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    crate::references::ades::extend_staged(input, level, profile, services, output, scope)
}

/// Borrow the host's guarded output transaction; the host finishes only after
/// its own transport/control checks have also completed successfully.
pub fn extend_transaction(
    input: Source<'_>,
    level: AdesLevel,
    profile: &XmlVerifyProfile,
    services: &XadesServices<'_>,
    output: &mut XmlSignatureOutput<'_>,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    crate::references::ades::extend_transaction(input, level, profile, services, output, scope)
}

pub(crate) fn intersect_limits(a: EvidenceLimits, b: EvidenceLimits) -> EvidenceLimits {
    EvidenceLimits {
        max_items: a.max_items.min(b.max_items),
        max_bytes: a.max_bytes.min(b.max_bytes),
        max_item_bytes: a.max_item_bytes.min(b.max_item_bytes),
        max_chain_len: a.max_chain_len.min(b.max_chain_len),
        max_proofs: a.max_proofs.min(b.max_proofs),
        max_coverage_parts: a.max_coverage_parts.min(b.max_coverage_parts),
        max_coverage_bytes: a.max_coverage_bytes.min(b.max_coverage_bytes),
    }
}
pub(crate) fn effective_limits(
    metadata: usize,
    work: u64,
    configured: Option<EvidenceLimits>,
) -> Result<EvidenceLimits> {
    let defaults = EvidenceLimits {
        max_items: 24,
        max_bytes: 24 * metadata as u64,
        max_item_bytes: metadata as u64,
        max_chain_len: 16,
        max_proofs: 8,
        max_coverage_parts: 256,
        max_coverage_bytes: work,
    };
    let limits = configured.map_or(defaults, |c| intersect_limits(defaults, c));
    limits.validate()?;
    Ok(limits)
}
impl XadesServices<'_> {
    pub fn bounded_limits(&self, profile: &XmlSignProfile<'_>) -> Result<EvidenceLimits> {
        let limits = limits(profile)?;
        let limits = self
            .evidence_limits
            .map_or(limits, |c| intersect_limits(limits, c));
        limits.validate()?;
        Ok(limits)
    }
    pub fn preflight(&self, level: AdesLevel, profile: &XmlSignProfile<'_>) -> Result<()> {
        let limits = self.bounded_limits(profile)?;
        if level > AdesLevel::B {
            let tsa = self
                .tsa
                .ok_or_else(|| invalid("XAdES issuance TSA configuration absent"))?;
            validate_timestamp_configuration(tsa, self.validation.policy)?;
            let minimum = if level == AdesLevel::Lta { 2 } else { 1 };
            if limits.max_proofs < minimum || limits.max_items < minimum {
                return Err(EvidenceError::Limit.into());
            }
            let count = self
                .material
                .certificates
                .len()
                .checked_add(self.material.ocsp.len())
                .and_then(|n| n.checked_add(self.material.crls.len()))
                .ok_or(EvidenceError::Limit)?;
            if count > limits.max_items - minimum {
                return Err(EvidenceError::Limit.into());
            }
            let mut bytes = 0u64;
            for cert in self.material.certificates {
                let len = u32::from(
                    cert.encoded_len()
                        .map_err(|_| invalid("public certificate encoding"))?,
                ) as u64;
                if len > limits.max_item_bytes {
                    return Err(EvidenceError::Limit.into());
                }
                bytes = bytes.checked_add(len).ok_or(EvidenceError::Limit)?;
            }
            for item in self.material.ocsp.iter().chain(self.material.crls) {
                if item.len() as u64 > limits.max_item_bytes {
                    return Err(EvidenceError::Limit.into());
                }
                bytes = bytes
                    .checked_add(item.len() as u64)
                    .ok_or(EvidenceError::Limit)?;
            }
            if bytes > limits.max_bytes {
                return Err(EvidenceError::Limit.into());
            }
        }
        Ok(())
    }
}
