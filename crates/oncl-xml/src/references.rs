//! Source-bound XMLDSig verification. Only bounded signature metadata is parsed.
use crate::{
    C14n, C14nProfile, XmlDocument, XmlError, XmlEventKind, XmlLimits, canonical_stream::Options,
};
use oncl_pki::{
    cert,
    evidence::{
        AdesLevel, EvidenceError, EvidenceLimits, EvidenceStore, SignerEvidence, validate_evidence,
    },
    io::{Region, Source, TemporaryStore},
    resource::{ProcessingError, ResourceReservation, ResourceScope},
    validation::{FormatFailure, NetworkPolicy, ValidationContext, ValidationReport},
};
use roxmltree::Node;
type Result<T, E = XmlSourceError> = std::result::Result<T, E>;
#[path = "references/ades.rs"]
pub(crate) mod ades;
pub(crate) mod intake;
#[derive(Debug, thiserror::Error)]
pub enum XmlSourceError {
    #[error(transparent)]
    Processing(#[from] ProcessingError),
    #[error(transparent)]
    Xml(#[from] XmlError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error("signature algorithm denied by the host XML profile")]
    AlgorithmDenied,
    #[error("malformed XML signature: {0}")]
    Malformed(&'static str),
    #[error("unsupported XML signature: {0}")]
    Unsupported(&'static str),
    #[error("PKI evidence acquisition: {0}")]
    Acquisition(String),
}
/// Host-selected source verification limits, not embedded trust/policy flags.
/// Defaults: 16 signers, 1024 references across all signers/Manifests, 256 KiB
/// per metadata component, eight Manifest levels and 1 TiB of replay/canonical
/// octet work. Parser limits remain independent; combined quotas may reject
/// simultaneous maxima. Exclusive inclusive-prefix lists are capped at 128.
#[derive(Clone, Debug)]
pub struct XmlVerifyProfile {
    pub xml: XmlLimits,
    pub canonicalization: C14nProfile,
    pub allowed_signature_algorithms: &'static [oncl_pki::key::SigAlg],
    pub max_signers: usize,
    pub max_references: usize,
    pub max_metadata_bytes: usize,
    pub max_work: u64,
    pub max_manifest_depth: usize,
    /// Minimum requested AdES level; carried proofs are always checked too.
    pub required_level: Option<AdesLevel>,
    pub evidence_limits: Option<EvidenceLimits>,
}
impl Default for XmlVerifyProfile {
    fn default() -> Self {
        Self {
            xml: XmlLimits::default(),
            canonicalization: C14nProfile::Standard,
            allowed_signature_algorithms: &[
                oncl_pki::key::SigAlg::Gost2004,
                oncl_pki::key::SigAlg::Gost2015_512,
                oncl_pki::key::SigAlg::RsaSha256,
            ],
            max_signers: 16,
            max_references: 1024,
            max_metadata_bytes: 262144,
            max_work: 1 << 40,
            max_manifest_depth: 8,
            required_level: None,
            evidence_limits: None,
        }
    }
}
#[derive(Debug)]
pub struct XmlReferenceResult {
    pub target: Option<Region>,
    pub digest_matches: bool,
}
#[derive(Debug)]
pub struct XmlSignerResult {
    pub signature: Region,
    pub signed_info: Region,
    pub signature_value: Region,
    pub algorithm: oncl_pki::key::SigAlg,
    pub key_info: Option<Region>,
    /// Actual selected certificate-bearing element, not a global token search.
    pub certificate: Region,
    pub certificate_sha256: [u8; 32],
    pub level: Option<AdesLevel>,
    references: Vec<XmlReferenceResult>,
}
impl XmlSignerResult {
    pub fn references(&self) -> &[XmlReferenceResult] {
        &self.references
    }
}
/// Facts and scoped PKI report remain admitted for their complete lifetime.
#[derive(Debug)]
pub struct XmlVerification {
    pub validation: ValidationReport,
    pub facts: XmlVerificationFacts,
}
/// Inseparable coverage rows, original-operation memory and metadata admission.
/// ```compile_fail
/// fn detach(mut facts: oncl_xml::XmlVerificationFacts) {
///     let _unscoped = std::mem::take(&mut facts.signatures);
/// }
/// ```
pub struct XmlVerificationFacts {
    signatures: Vec<XmlSignerResult>,
    _metadata: ResourceReservation,
    pub(crate) wsse: Option<Box<crate::wsse::WsseCoverageFacts>>,
}
impl XmlVerification {
    pub fn signatures(&self) -> &[XmlSignerResult] {
        self.facts.signatures()
    }
    /// Minimum actually validated format level, never a timestamp-presence or
    /// failed/indeterminate-evidence promotion.
    pub fn minimum_level(&self) -> Option<AdesLevel> {
        if self.validation.verdict != oncl_pki::validation::Verdict::Valid {
            return None;
        }
        self.signatures()
            .iter()
            .try_fold(AdesLevel::Lta, |minimum, signer| {
                signer.level.map(|level| minimum.min(level))
            })
    }
}
impl XmlVerificationFacts {
    pub fn signatures(&self) -> &[XmlSignerResult] {
        &self.signatures
    }
    pub fn wsse(&self) -> Option<&crate::wsse::WsseCoverageFacts> {
        self.wsse.as_deref()
    }
    pub fn read_used_soap_body(
        &mut self,
        offset: u64,
        output: &mut [u8],
        scope: &ResourceScope,
    ) -> Result<usize> {
        self.wsse
            .as_mut()
            .ok_or_else(|| invalid("report has no SOAP Body binding"))?
            .read_used_body(offset, output, scope)
    }
}
impl std::fmt::Debug for XmlVerificationFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XmlVerificationFacts")
            .field("signatures", &self.signatures)
            .finish()
    }
}
pub(crate) type BoundMetadata = (Region, Vec<(String, String)>);
struct ExtraMetadata {
    bound: BoundMetadata,
    _metadata: ResourceReservation,
}
struct Metadata {
    signature: Region,
    info: Region,
    info_namespaces: Vec<(String, String)>,
    value: BoundMetadata,
    certificate: BoundMetadata,
    targets: Vec<Region>,
    proofs: Vec<(oncl_pki::evidence::ProofKind, ExtraMetadata)>,
    evidence: Vec<(oncl_pki::evidence::EvidenceKind, ExtraMetadata)>,
    key_info: Option<ExtraMetadata>,
    signed_properties: Option<ExtraMetadata>,
    unsigned: Vec<ExtraMetadata>,
    objects: Vec<Region>,
    qualifying: Option<Region>,
    unsigned_container: Option<Region>,
}
struct Pending {
    depth: usize,
    info: Option<BoundMetadata>,
    value: Option<BoundMetadata>,
    certificate: Option<BoundMetadata>,
    targets: Vec<Region>,
    proofs: Vec<(oncl_pki::evidence::ProofKind, ExtraMetadata)>,
    evidence: Vec<(oncl_pki::evidence::EvidenceKind, ExtraMetadata)>,
    key_info: Option<ExtraMetadata>,
    signed_properties: Option<ExtraMetadata>,
    unsigned: Vec<ExtraMetadata>,
    objects: Vec<Region>,
    qualifying: Option<Region>,
    unsigned_container: Option<Region>,
    key_info_seen: bool,
    x509_data_seen: bool,
}
fn invalid(message: &'static str) -> XmlSourceError {
    XmlSourceError::Malformed(message)
}
fn unique<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    if slot.is_some() {
        return Err(invalid("duplicate signature metadata"));
    }
    *slot = Some(value);
    Ok(())
}
fn extra(
    event: &crate::XmlEvent,
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<ExtraMetadata> {
    if event.region.len > profile.max_metadata_bytes as u64 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let bytes = event
        .namespaces()
        .map(|(p, u)| p.len() + u.len() + 96)
        .sum::<usize>() as u64
        + 256;
    let metadata = scope.reserve_metadata(bytes)?;
    Ok(ExtraMetadata {
        bound: (
            event.region,
            event
                .namespaces()
                .map(|(p, u)| (p.to_owned(), u.to_owned()))
                .collect(),
        ),
        _metadata: metadata,
    })
}
fn suffix(path: &[(u8, String)], expected: &[(u8, &str)]) -> bool {
    path.len() >= expected.len()
        && path[path.len() - expected.len()..]
            .iter()
            .zip(expected)
            .all(|((kind, name), (k, n))| kind == k && name == n)
}
fn scan(
    document: &mut XmlDocument,
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<Vec<Metadata>> {
    let signatures = scan_optional(document, profile, scope)?;
    if signatures.is_empty() {
        return Err(XmlError::NoSignature.into());
    }
    Ok(signatures)
}
fn scan_optional(
    document: &mut XmlDocument,
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<Vec<Metadata>> {
    use oncl_pki::evidence::EvidenceKind;
    let mut events = document.events();
    let mut signatures = Vec::with_capacity(profile.max_signers);
    let mut current: Option<Pending> = None;
    let mut path: Vec<(u8, String)> = Vec::with_capacity(profile.xml.max_depth);
    let mut proof_count = 0;
    let mut evidence_count = 0;
    while let Some(event) = events.next_event()? {
        scope.checkpoint()?;
        if !matches!(event.kind, XmlEventKind::Start | XmlEventKind::End) {
            continue;
        }
        let name = event
            .name
            .as_ref()
            .ok_or_else(|| invalid("missing XML name"))?;
        let ds = name.namespace() == Some(crate::DSIG_NS);
        let xades = name.namespace() == Some(crate::XADES_NS);
        let xades14 = name.namespace() == Some("http://uri.etsi.org/01903/v1.4.1#");
        let archive = xades14 && name.local() == "ArchiveTimeStamp";
        if matches!(
            name.namespace(),
            Some(
                "http://uri.etsi.org/01903/v1.2.2#"
                    | "http://uri.etsi.org/01903/v1.1.1#"
                    | "http://uri.etsi.org/01903#"
            )
        ) || (name.namespace() == Some("http://uri.etsi.org/01903/v1.4.1#")
            && !matches!(name.local(), "ArchiveTimeStamp" | "TimeStampValidationData"))
        {
            return Err(XmlSourceError::Unsupported("XAdES namespace/version"));
        }
        if event.kind == XmlEventKind::Start {
            if xades14 {
                let pending = current
                    .as_ref()
                    .ok_or_else(|| invalid("unbound XAdES 1.4.1 evidence"))?;
                if event.depth != pending.depth + 5
                    || !suffix(
                        &path,
                        &[
                            (1, "Object"),
                            (2, "QualifyingProperties"),
                            (2, "UnsignedProperties"),
                            (2, "UnsignedSignatureProperties"),
                        ],
                    )
                {
                    return Err(invalid(
                        "XAdES 1.4.1 evidence requires a direct unsigned-property location",
                    ));
                }
            }
            if ds && name.local() == "Signature" {
                if current.is_some() {
                    return Err(invalid("nested XML signature"));
                }
                if signatures.len() == profile.max_signers {
                    return Err(ProcessingError::MetadataLimit.into());
                }
                current = Some(Pending {
                    depth: event.depth,
                    info: None,
                    value: None,
                    certificate: None,
                    targets: Vec::new(),
                    proofs: Vec::new(),
                    evidence: Vec::new(),
                    key_info: None,
                    signed_properties: None,
                    unsigned: Vec::new(),
                    objects: Vec::new(),
                    qualifying: None,
                    unsigned_container: None,
                    key_info_seen: false,
                    x509_data_seen: false,
                });
            }
            if let Some(pending) = current.as_mut() {
                if ds && name.local() == "KeyInfo" && event.depth == pending.depth + 1 {
                    if pending.key_info_seen {
                        return Err(invalid("duplicate KeyInfo"));
                    }
                    pending.key_info_seen = true;
                }
                if ds
                    && name.local() == "X509Data"
                    && event.depth == pending.depth + 2
                    && path
                        .get(pending.depth + 1)
                        .is_some_and(|(kind, n)| *kind == 1 && n == "KeyInfo")
                {
                    if pending.x509_data_seen {
                        return Err(invalid("duplicate X509Data"));
                    }
                    pending.x509_data_seen = true;
                }
            }
            if xades && name.local() == "QualifyingProperties" {
                let pending = current
                    .as_mut()
                    .ok_or_else(|| invalid("unbound qualifying properties"))?;
                if event.depth != pending.depth + 2
                    || !suffix(&path, &[(1, "Signature"), (1, "Object")])
                    || !pending.targets.is_empty()
                {
                    return Err(invalid("qualifying properties location"));
                }
                let targets: Vec<_> = event
                    .attributes
                    .iter()
                    .filter(|a| a.name.namespace().is_none() && a.name.local() == "Target")
                    .collect();
                if targets.len() != 1 {
                    return Err(invalid("qualifying properties Target"));
                }
                pending.targets.push(targets[0].value);
            }
            if xades
                && (name.local().starts_with("ArchiveTimeStamp") && !archive
                    || (name.local().ends_with("TimeStamp")
                        && !matches!(name.local(), "SignatureTimeStamp" | "EncapsulatedTimeStamp")))
            {
                return Err(XmlSourceError::Unsupported("XAdES archive/proof coverage"));
            }
            path.push((
                if ds {
                    1
                } else if xades {
                    2
                } else if xades14 {
                    3
                } else {
                    0
                },
                name.local().to_owned(),
            ));
        } else {
            if let Some(pending) = current.as_mut() {
                if ds && event.depth == pending.depth + 1 {
                    match name.local() {
                        "SignedInfo" => unique(
                            &mut pending.info,
                            (
                                event.region,
                                event
                                    .namespaces()
                                    .map(|(p, u)| (p.to_owned(), u.to_owned()))
                                    .collect(),
                            ),
                        )?,
                        "SignatureValue" => unique(
                            &mut pending.value,
                            (
                                event.region,
                                event
                                    .namespaces()
                                    .map(|(p, u)| (p.to_owned(), u.to_owned()))
                                    .collect(),
                            ),
                        )?,
                        _ => {}
                    }
                }
                if ds
                    && name.local() == "X509Certificate"
                    && event.depth == pending.depth + 3
                    && path
                        .get(pending.depth + 1)
                        .is_some_and(|(kind, n)| *kind == 1 && n == "KeyInfo")
                    && path
                        .get(pending.depth + 2)
                        .is_some_and(|(kind, n)| *kind == 1 && n == "X509Data")
                {
                    unique(
                        &mut pending.certificate,
                        (
                            event.region,
                            event
                                .namespaces()
                                .map(|(p, u)| (p.to_owned(), u.to_owned()))
                                .collect(),
                        ),
                    )?;
                }
                if xades
                    && name.local() == "EncapsulatedTimeStamp"
                    && !suffix(
                        &path,
                        &[(2, "SignatureTimeStamp"), (2, "EncapsulatedTimeStamp")],
                    )
                    && !suffix(
                        &path,
                        &[(3, "ArchiveTimeStamp"), (2, "EncapsulatedTimeStamp")],
                    )
                {
                    return Err(invalid("unbound EncapsulatedTimeStamp"));
                }
                if (xades && name.local() == "SignatureTimeStamp") || archive {
                    if !suffix(
                        &path[..path.len().saturating_sub(1)],
                        &[
                            (1, "Object"),
                            (2, "QualifyingProperties"),
                            (2, "UnsignedProperties"),
                            (2, "UnsignedSignatureProperties"),
                        ],
                    ) {
                        return Err(invalid("signature timestamp location"));
                    }
                    if !archive
                        && pending
                            .proofs
                            .iter()
                            .any(|(kind, _)| *kind == oncl_pki::evidence::ProofKind::Signature)
                    {
                        return Err(XmlSourceError::Unsupported(
                            "multiple independent SignatureTimeStamp proofs",
                        ));
                    }
                    proof_count += 1;
                    if proof_count > 8 {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                    pending.proofs.push((
                        if archive {
                            oncl_pki::evidence::ProofKind::Archive
                        } else {
                            oncl_pki::evidence::ProofKind::Signature
                        },
                        extra(event, profile, scope)?,
                    ));
                }
                let kind = if xades {
                    match name.local() {
                        "EncapsulatedX509Certificate" => {
                            Some((EvidenceKind::Certificate, "CertificateValues"))
                        }
                        "EncapsulatedOCSPValue" => Some((EvidenceKind::Ocsp, "OCSPValues")),
                        "EncapsulatedCRLValue" => Some((EvidenceKind::Crl, "CRLValues")),
                        _ => None,
                    }
                } else {
                    None
                };
                if let Some((kind, parent)) = kind {
                    if !suffix(&path, &[(2, parent), (2, name.local())]) {
                        return Err(invalid("embedded evidence location"));
                    }
                    evidence_count += 1;
                    if evidence_count > 16 {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                    pending.evidence.push((kind, extra(event, profile, scope)?));
                }
                if ds && name.local() == "KeyInfo" && event.depth == pending.depth + 1 {
                    unique(&mut pending.key_info, extra(event, profile, scope)?)?;
                }
                if xades && name.local() == "QualifyingProperties" {
                    unique(&mut pending.qualifying, event.region)?;
                }
                if xades && name.local() == "UnsignedSignatureProperties" {
                    if !suffix(
                        &path,
                        &[
                            (1, "Object"),
                            (2, "QualifyingProperties"),
                            (2, "UnsignedProperties"),
                            (2, "UnsignedSignatureProperties"),
                        ],
                    ) {
                        return Err(invalid("unsigned signature properties location"));
                    }
                    unique(&mut pending.unsigned_container, event.region)?;
                }
                if xades && name.local() == "SignedProperties" {
                    if !suffix(
                        &path,
                        &[
                            (1, "Object"),
                            (2, "QualifyingProperties"),
                            (2, "SignedProperties"),
                        ],
                    ) {
                        return Err(invalid("signed properties location"));
                    }
                    unique(
                        &mut pending.signed_properties,
                        extra(event, profile, scope)?,
                    )?;
                }
                if suffix(
                    &path[..path.len().saturating_sub(1)],
                    &[
                        (1, "Object"),
                        (2, "QualifyingProperties"),
                        (2, "UnsignedProperties"),
                        (2, "UnsignedSignatureProperties"),
                    ],
                ) {
                    if pending.unsigned.len() == 64 {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                    pending.unsigned.push(extra(event, profile, scope)?);
                }
                if ds
                    && name.local() == "Object"
                    && event.depth == pending.depth + 1
                    && !pending.targets.iter().any(|r| {
                        r.offset >= event.region.offset
                            && r.offset < event.region.offset + event.region.len
                    })
                {
                    if pending.objects.len() == 64 {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                    pending.objects.push(event.region);
                }
                if ds && name.local() == "Signature" && event.depth == pending.depth {
                    let pending = current.take().expect("active signature");
                    let (info, info_namespaces) =
                        pending.info.ok_or_else(|| invalid("missing SignedInfo"))?;
                    signatures.push(Metadata {
                        signature: event.region,
                        info,
                        info_namespaces,
                        value: pending
                            .value
                            .ok_or_else(|| invalid("missing SignatureValue"))?,
                        certificate: pending
                            .certificate
                            .or_else(|| pending.key_info.as_ref().map(|key| key.bound.clone()))
                            .ok_or_else(|| invalid("missing certificate"))?,
                        targets: pending.targets,
                        proofs: pending.proofs,
                        evidence: pending.evidence,
                        key_info: pending.key_info,
                        signed_properties: pending.signed_properties,
                        unsigned: pending.unsigned,
                        objects: pending.objects,
                        qualifying: pending.qualifying,
                        unsigned_container: pending.unsigned_container,
                    });
                }
            } else if xades || xades14 {
                return Err(invalid("unbound XAdES evidence"));
            }
            path.pop().ok_or_else(|| invalid("signature path"))?;
        }
    }
    drop(events);
    for signature in &mut signatures {
        if let Some(key) = &signature.key_info {
            if let Some(certificate) = crate::wsse::certificate_binding(
                document,
                signature.signature,
                &key.bound,
                profile,
                scope,
            )? {
                signature.certificate = certificate;
            } else if signature.certificate.0 == key.bound.0 {
                return Err(invalid("missing certificate"));
            }
        }
    }
    Ok(signatures)
}
pub(crate) fn metadata(
    document: &mut XmlDocument,
    region: Region,
    namespaces: &[(String, String)],
    cap: usize,
) -> Result<String> {
    let count = usize::try_from(region.len).map_err(|_| ProcessingError::MetadataLimit)?;
    if count > cap {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let mut bytes = vec![0; count];
    let node = document.indexed_node(region);
    let mut at = 0;
    while at < count {
        let n = document.read_node(&node, at as u64, &mut bytes[at..])?;
        if n == 0 {
            return Err(invalid("short signature metadata"));
        }
        at += n;
    }
    let mut wrapped = String::from("<__oncl_metadata");
    for (prefix, uri) in namespaces {
        if prefix == "xml" {
            continue;
        }
        wrapped.push_str(" xmlns");
        if !prefix.is_empty() {
            wrapped.push(':');
            wrapped.push_str(prefix);
        }
        wrapped.push_str("=\"");
        wrapped.push_str(&crate::c14n::escape_attribute(uri));
        wrapped.push('"');
    }
    wrapped.push('>');
    wrapped.push_str(std::str::from_utf8(&bytes).map_err(|_| invalid("metadata UTF-8"))?);
    wrapped.push_str("</__oncl_metadata>");
    Ok(wrapped)
}
fn parse_guards(scope: &ResourceScope, bytes: usize) -> Result<ResourceReservation> {
    let bound = (bytes as u64)
        .checked_mul(64)
        .ok_or(ProcessingError::MetadataLimit)?;
    Ok(scope.reserve_metadata(bound)?)
}
fn base64(node: Node<'_, '_>) -> Result<Vec<u8>> {
    if node.children().any(|n| n.is_element()) {
        return Err(invalid("nested base64 signature metadata"));
    }
    crate::base64_content(node).map_err(|_| invalid("base64 signature metadata"))
}
pub(crate) fn attribute_value(
    document: &mut XmlDocument,
    span: Region,
    cap: usize,
) -> Result<String> {
    if span.len > cap as u64 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let region = Region {
        offset: span
            .offset
            .checked_sub(1)
            .ok_or_else(|| invalid("attribute quote"))?,
        len: span.len + 2,
    };
    let node = document.indexed_node(region);
    let mut bytes = vec![0; region.len as usize];
    let mut at = 0;
    while at < bytes.len() {
        let n = document.read_node(&node, at as u64, &mut bytes[at..])?;
        if n == 0 {
            return Err(invalid("attribute extent"));
        }
        at += n;
    }
    let xml = format!(
        "<r v={}/>",
        std::str::from_utf8(&bytes).map_err(|_| invalid("attribute UTF-8"))?
    );
    let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("attribute value"))?;
    Ok(parsed
        .root_element()
        .attribute("v")
        .ok_or_else(|| invalid("attribute value"))?
        .to_owned())
}
fn only_ds_children(node: Node<'_, '_>, allowed: &[&str]) -> Result<()> {
    for child in node.children() {
        if child.is_element()
            && (child.tag_name().namespace() != Some(crate::DSIG_NS)
                || !allowed.contains(&child.tag_name().name()))
        {
            return Err(invalid("unsupported XMLDSig structure/parameters"));
        }
        if child.is_text()
            && child
                .text()
                .unwrap_or("")
                .bytes()
                .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Err(invalid("non-whitespace XMLDSig structure content"));
        }
    }
    Ok(())
}
fn plain_algorithm<'a, 'i>(node: Node<'a, 'i>) -> Result<&'a str> {
    only_ds_children(node, &[])?;
    algorithm(node)
}
fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Node<'a, 'i>> {
    let mut matches = node.children().filter(|n| crate::is_ds(*n, name));
    let found = matches
        .next()
        .ok_or_else(|| invalid("missing XMLDSig child"))?;
    if matches.next().is_some() {
        return Err(invalid("duplicate XMLDSig child"));
    }
    Ok(found)
}
fn algorithm<'a, 'i>(node: Node<'a, 'i>) -> Result<&'a str> {
    node.attribute("Algorithm")
        .ok_or_else(|| invalid("missing algorithm"))
}
fn prefixes(node: Node<'_, '_>) -> Result<Vec<String>> {
    let children: Vec<_> = node.children().filter(Node::is_element).collect();
    if children.len() > 1 {
        return Err(invalid("duplicate inclusive namespace parameters"));
    }
    let Some(parameters) = children.first() else {
        return Ok(Vec::new());
    };
    if !C14n::from_uri(algorithm(node)?).is_some_and(C14n::is_exclusive) {
        return Err(invalid(
            "inclusive namespace parameters require exclusive C14N",
        ));
    }
    if parameters.tag_name().namespace() != Some(crate::EXC_C14N_NS)
        || parameters.tag_name().name() != "InclusiveNamespaces"
    {
        return Err(invalid("unsupported canonical parameters"));
    }
    only_ds_children(*parameters, &[])?;
    if parameters
        .attributes()
        .any(|a| a.namespace().is_some() || a.name() != "PrefixList")
    {
        return Err(invalid("unsupported inclusive namespace attributes"));
    }
    let list = parameters
        .attribute("PrefixList")
        .ok_or_else(|| invalid("missing inclusive PrefixList"))?;
    let mut prefixes = Vec::new();
    for prefix in list.split_ascii_whitespace() {
        if prefixes.len() == 128 || prefix.len() > 1024 {
            return Err(ProcessingError::MetadataLimit.into());
        }
        prefixes.push(if prefix == "#default" {
            String::new()
        } else {
            prefix.to_owned()
        });
    }
    prefixes.sort_unstable();
    prefixes.dedup();
    Ok(prefixes)
}
fn signature_xpath_filter(transform: Node<'_, '_>) -> Result<()> {
    let xpath = child(transform, "XPath")?;
    if transform.children().filter(Node::is_element).count() != 1
        || xpath.children().any(|n| n.is_element())
    {
        return Err(invalid("XPath transform parameters"));
    }
    let expression: String = xpath
        .children()
        .filter(Node::is_text)
        .filter_map(|n| n.text())
        .collect();
    let expression = expression.trim_matches([' ', '\t', '\r', '\n']);
    let name = expression
        .strip_prefix("not(ancestor-or-self::")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| XmlError::XPath("unsupported signature XPath filter".into()))?;
    let (prefix, local) = name
        .split_once(':')
        .ok_or_else(|| XmlError::XPath("signature XPath filter needs a bound prefix".into()))?;
    if local != "Signature" || xpath.lookup_namespace_uri(Some(prefix)) != Some(crate::DSIG_NS) {
        return Err(XmlError::XPath("signature XPath namespace/target".into()).into());
    }
    Ok(())
}
fn decode_id(uri: &str) -> Result<String> {
    let id = uri
        .strip_prefix('#')
        .ok_or_else(|| XmlError::UnsupportedAlgorithm("external reference URI".into()))?;
    if id.is_empty() {
        return Err(XmlError::UnsupportedAlgorithm("empty reference fragment".into()).into());
    }
    let mut bytes = Vec::with_capacity(id.len());
    let mut iter = id.bytes();
    while let Some(b) = iter.next() {
        if b == b'%' {
            let h = iter.next().ok_or_else(|| invalid("URI percent escape"))?;
            let l = iter.next().ok_or_else(|| invalid("URI percent escape"))?;
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            bytes.push(
                digit(h)
                    .and_then(|h| digit(l).map(|l| h * 16 + l))
                    .ok_or_else(|| invalid("URI percent escape"))?,
            );
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).map_err(|_| invalid("URI fragment UTF-8"))
}
struct ReferenceVerifier<'a> {
    document: &'a mut XmlDocument,
    profile: &'a XmlVerifyProfile,
    signatures: &'a [Metadata],
    signer_index: usize,
    scope: &'a mut ResourceScope,
    work: &'a mut u64,
    count: &'a mut usize,
    failures: &'a mut Vec<FormatFailure>,
    archive_references: Option<&'a mut oncl_pki::io::StagedArtifact>,
    results: &'a mut Vec<XmlReferenceResult>,
}
impl ReferenceVerifier<'_> {
    fn verify_all(
        &mut self,
        container: Node<'_, '_>,
        depth: usize,
        active: &mut Vec<Region>,
    ) -> Result<()> {
        let mut any = false;
        for reference in container.children().filter(Node::is_element) {
            if crate::is_ds(reference, "Reference") {
                any = true;
                self.verify_one(reference, depth, active)?;
            } else if crate::is_ds(container, "Manifest") {
                return Err(invalid("Manifest contains a non-Reference element"));
            }
        }
        if !any {
            return Err(invalid("reference container without References"));
        }
        Ok(())
    }
    fn verify_one(
        &mut self,
        reference: Node<'_, '_>,
        depth: usize,
        active: &mut Vec<Region>,
    ) -> Result<()> {
        self.scope.checkpoint()?;
        only_ds_children(reference, &["Transforms", "DigestMethod", "DigestValue"])?;
        *self.count = self
            .count
            .checked_add(1)
            .ok_or(ProcessingError::MetadataLimit)?;
        if *self.count > self.profile.max_references {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let uri = reference
            .attribute("URI")
            .ok_or_else(|| invalid("Reference without URI"))?;
        let (target, missing, drop_comments) = if uri.is_empty() {
            (None, false, true)
        } else {
            let fragment = decode_id(uri)?;
            if let Some(expression) = fragment
                .strip_prefix("xpointer(")
                .and_then(|s| s.strip_suffix(')'))
            {
                if expression == "/" {
                    (None, false, false)
                } else {
                    let node = if let Some(literal) = expression
                        .strip_prefix("id(")
                        .and_then(|s| s.strip_suffix(')'))
                    {
                        let quote = literal
                            .as_bytes()
                            .first()
                            .copied()
                            .ok_or_else(|| invalid("xpointer id"))?;
                        if !matches!(quote, b'\'' | b'"')
                            || literal.len() < 2
                            || literal.as_bytes().last() != Some(&quote)
                            || literal.as_bytes()[1..literal.len() - 1].contains(&quote)
                        {
                            return Err(invalid("xpointer id literal"));
                        }
                        let identity = &literal[1..literal.len() - 1];
                        if identity.is_empty()
                            || identity
                                .bytes()
                                .any(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                        {
                            return Err(XmlSourceError::Unsupported(
                                "empty or multi-ID XPointer id()",
                            ));
                        }
                        self.document.lookup_id(identity)?
                    } else {
                        *self.work = self
                            .work
                            .checked_sub(self.document.len())
                            .ok_or(ProcessingError::InvalidInput("reference work limit"))?;
                        let namespaces: Vec<_> = reference
                            .namespaces()
                            .map(|ns| (ns.name().unwrap_or(""), ns.uri()))
                            .collect();
                        self.document
                            .select_xpath_unique(expression, &namespaces, self.scope)?
                    };
                    let target = node.map(|n| self.document.node_region(&n)).transpose()?;
                    (target, target.is_none(), false)
                }
            } else {
                let target = self
                    .document
                    .lookup_id(&fragment)?
                    .map(|n| self.document.node_region(&n))
                    .transpose()?;
                (target, target.is_none(), true)
            }
        };
        let mut method = C14n::Inclusive;
        let mut inclusive = Vec::new();
        let mut enveloped = false;
        let mut canonical_seen = false;
        let mut xpath_filter = false;
        let transforms: Vec<_> = reference
            .children()
            .filter(|n| crate::is_ds(*n, "Transforms"))
            .collect();
        if transforms.len() > 1 {
            return Err(invalid("duplicate Transforms"));
        }
        if let Some(transforms) = transforms.first() {
            only_ds_children(*transforms, &["Transform"])?;
            if !transforms.children().any(|n| n.is_element()) {
                return Err(invalid("empty Transforms"));
            }
        }
        if let Some(transforms) = transforms.first() {
            for transform in transforms.children().filter(Node::is_element) {
                if !crate::is_ds(transform, "Transform") {
                    return Err(invalid("transform namespace"));
                }
                let uri = algorithm(transform)?;
                if uri == crate::ENVELOPED_SIGNATURE && !canonical_seen && !enveloped {
                    if transform.children().any(|n| n.is_element()) {
                        return Err(invalid("enveloped transform parameters"));
                    }
                    enveloped = true;
                } else if uri == "http://www.w3.org/TR/1999/REC-xpath-19991116"
                    && !canonical_seen
                    && !xpath_filter
                {
                    signature_xpath_filter(transform)?;
                    xpath_filter = true;
                } else if let Some(canonical) = C14n::from_uri(uri).filter(|_| !canonical_seen) {
                    method = canonical;
                    inclusive = prefixes(transform)?;
                    canonical_seen = true;
                } else {
                    return Err(XmlSourceError::Unsupported("reference transform URI/order"));
                }
            }
        }
        if drop_comments {
            method = if method.is_exclusive() {
                C14n::Exclusive
            } else {
                C14n::Inclusive
            };
        }
        let mut excluded = Vec::new();
        if xpath_filter {
            excluded.extend(self.signatures.iter().map(|s| s.signature));
        } else {
            if enveloped {
                excluded.push(self.signatures[self.signer_index].signature);
            }
            if self.profile.canonicalization == C14nProfile::KalkanLegacy {
                excluded.extend(
                    self.signatures[self.signer_index + 1..]
                        .iter()
                        .map(|s| s.signature),
                );
                if let Some(target) = target {
                    let end = target.end()?;
                    // The legacy document-order subtree filter never meets an
                    // omitted ancestor (notably an enveloped signing-time Object).
                    excluded.retain(|signature| {
                        signature.offset >= target.offset && signature.offset < end
                    });
                }
            }
        }
        let digest_uri = plain_algorithm(child(reference, "DigestMethod")?)?;
        let algorithm = crate::digest_method(digest_uri)
            .ok_or(XmlSourceError::Unsupported("reference digest URI"))?;
        let expected = base64(child(reference, "DigestValue")?)?;
        let matches = if missing {
            false
        } else {
            self.document
                .canonical_digest(
                    Options {
                        target,
                        method,
                        profile: self.profile.canonicalization,
                        prefixes: &inclusive,
                        excluded: &excluded,
                        metadata_limit: None,
                    },
                    algorithm.hash_alg(),
                    self.scope,
                    self.work,
                )?
                .as_bytes()
                == expected
        };
        if !matches {
            self.failures.push(if missing {
                FormatFailure::ReferenceTargetMissing
            } else {
                FormatFailure::ReferenceDigestMismatch
            });
        }
        self.results.push(XmlReferenceResult {
            target,
            digest_matches: matches,
        });
        if depth == 0
            && !missing
            && let Some(archive) = self.archive_references.as_deref_mut()
        {
            self.document.canonical_append(
                Options {
                    target,
                    method,
                    profile: self.profile.canonicalization,
                    prefixes: &inclusive,
                    excluded: &excluded,
                    metadata_limit: None,
                },
                archive,
                self.scope,
                self.work,
            )?;
        }
        if reference.attribute("Type") == Some("http://www.w3.org/2000/09/xmldsig#Manifest")
            && !missing
        {
            let target = target.ok_or_else(|| invalid("Manifest reference is not an element"))?;
            if depth >= self.profile.max_manifest_depth || active.contains(&target) {
                return Err(ProcessingError::InvalidInput("Manifest recursion/cycle limit").into());
            }
            *self.work = self
                .work
                .checked_sub(self.document.len())
                .ok_or(ProcessingError::InvalidInput("reference work limit"))?;
            let node = self.document.indexed_node(target);
            let namespaces = self.document.node_namespaces(&node, self.scope)?;
            let xml = metadata(
                self.document,
                target,
                &namespaces,
                self.profile.max_metadata_bytes,
            )?;
            let _parsed = parse_guards(self.scope, xml.len())?;
            let parsed =
                roxmltree::Document::parse(&xml).map_err(|_| invalid("Manifest metadata"))?;
            let manifest = parsed
                .root_element()
                .first_element_child()
                .ok_or_else(|| invalid("Manifest target"))?;
            if !crate::is_ds(manifest, "Manifest") {
                return Err(invalid("Manifest reference targets a different element"));
            }
            active.push(target);
            let result = self.verify_all(manifest, depth + 1, active);
            active.pop();
            result?;
        }
        Ok(())
    }
}
/// Verify all source-bound signatures using host-selected F03 trust/network policy.
/// The profile is selected by the host, never by an embedded trust declaration.
pub fn verify_source(
    input: Source<'_>,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    scope: &mut ResourceScope,
) -> Result<XmlVerification> {
    let mut document = XmlDocument::index_signed(input, profile, store, scope)?;
    verify_document(&mut document, profile, store, ctx, network, scope)
}
/// Dynamic hosts sample ONE current validation time only after all document
/// canonical/reference work. This callback is a trusted service, never wire data.
pub fn verify_source_with_clock(
    input: Source<'_>,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    clock: &(dyn Fn() -> time::OffsetDateTime + Send + Sync),
    scope: &mut ResourceScope,
) -> Result<XmlVerification> {
    let mut document = XmlDocument::index_signed(input, profile, store, scope)?;
    verify_document_timed(
        &mut document,
        profile,
        store,
        ctx,
        network,
        scope,
        Some(clock),
    )
}
struct PendingSigner {
    certificate: cert::Certificate,
    value: Vec<u8>,
    digest: oncl_pki::digest::DigestValue,
    algorithm: oncl_pki::key::SigAlg,
    info_xml: String,
    certificate_sha256: [u8; 32],
    references: Vec<XmlReferenceResult>,
    failures: Vec<FormatFailure>,
    archive_references: Option<oncl_pki::io::StagedArtifact>,
    _metadata: ResourceReservation,
}
pub(crate) fn verify_document(
    document: &mut XmlDocument,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    scope: &mut ResourceScope,
) -> Result<XmlVerification> {
    verify_document_timed(document, profile, store, ctx, network, scope, None)
}
pub(crate) fn verify_document_timed(
    document: &mut XmlDocument,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    scope: &mut ResourceScope,
    clock: Option<&(dyn Fn() -> time::OffsetDateTime + Send + Sync)>,
) -> Result<XmlVerification> {
    document.check_scope(scope)?;
    profile.xml.reservation()?;
    if profile.max_signers == 0
        || profile.max_signers > 64
        || profile.max_references == 0
        || profile.max_references > 4096
        || profile.max_metadata_bytes == 0
        || profile.max_metadata_bytes > 1048576
        || profile.max_work == 0
        || profile.max_manifest_depth > 16
    {
        return Err(ProcessingError::InvalidLimits.into());
    }
    let retained = (profile.max_signers as u64)
        * (3 * (profile.xml.max_namespace_bytes as u64 + profile.xml.max_namespaces as u64 * 96)
            + 4096)
        + (profile.max_references as u64) * 256
        + profile.xml.max_depth as u64 * (profile.xml.max_name_bytes as u64 + 128);
    let metadata_guard = scope.reserve_metadata(retained)?;
    let signatures = scan(document, profile, scope)?;
    let scratch =
        (profile.max_metadata_bytes as u64) * 10 + profile.xml.max_namespace_bytes as u64 * 4;
    let _scratch_metadata = scope.reserve_metadata(scratch)?;
    let mut work = profile.max_work;
    let mut count = 0usize;
    let mut pending = Vec::with_capacity(signatures.len());
    for (signer_index, signature) in signatures.iter().enumerate() {
        scope.checkpoint()?;
        let info_xml = metadata(
            document,
            signature.info,
            &signature.info_namespaces,
            profile.max_metadata_bytes,
        )?;
        let retained_size = (info_xml.len() as u64)
            .checked_add(signature.value.0.len)
            .and_then(|n| {
                signature
                    .certificate
                    .0
                    .len
                    .checked_mul(4)
                    .and_then(|c| n.checked_add(c))
            })
            .and_then(|n| n.checked_add(std::mem::size_of::<PendingSigner>() as u64))
            .ok_or(ProcessingError::MetadataLimit)?;
        let retained_metadata = scope.reserve_metadata(retained_size)?;
        let _info_parse = parse_guards(scope, info_xml.len())?;
        let info_doc =
            roxmltree::Document::parse(&info_xml).map_err(|_| invalid("SignedInfo metadata"))?;
        let info = info_doc
            .root_element()
            .first_element_child()
            .ok_or_else(|| invalid("SignedInfo metadata"))?;
        only_ds_children(
            info,
            &["CanonicalizationMethod", "SignatureMethod", "Reference"],
        )?;
        let canonical = child(info, "CanonicalizationMethod")?;
        let uri = algorithm(canonical)?;
        let method = C14n::from_uri(uri).ok_or(XmlSourceError::Unsupported(
            "SignedInfo canonicalization URI",
        ))?;
        let inclusive = prefixes(canonical)?;
        let signature_uri = plain_algorithm(child(info, "SignatureMethod")?)?;
        let signature_algorithm = crate::signature_method(signature_uri)
            .ok_or(XmlSourceError::Unsupported("signature method URI"))?;
        if !profile
            .allowed_signature_algorithms
            .contains(&signature_algorithm)
        {
            return Err(XmlSourceError::AlgorithmDenied);
        }
        let value_xml = metadata(
            document,
            signature.value.0,
            &signature.value.1,
            profile.max_metadata_bytes,
        )?;
        let _value_parse = parse_guards(scope, value_xml.len())?;
        let value_doc = roxmltree::Document::parse(&value_xml)
            .map_err(|_| invalid("SignatureValue metadata"))?;
        let value = base64(
            value_doc
                .root_element()
                .first_element_child()
                .ok_or_else(|| invalid("SignatureValue"))?,
        )?;
        let cert_xml = metadata(
            document,
            signature.certificate.0,
            &signature.certificate.1,
            profile.max_metadata_bytes,
        )?;
        let _cert_parse = parse_guards(scope, cert_xml.len())?;
        let cert_doc =
            roxmltree::Document::parse(&cert_xml).map_err(|_| invalid("certificate metadata"))?;
        let certificate_der = base64(
            cert_doc
                .root_element()
                .first_element_child()
                .ok_or_else(|| invalid("certificate"))?,
        )?;
        let certificate =
            cert::parse(&certificate_der).map_err(|_| invalid("signer certificate"))?;
        let mut certificate_hash = oncl_pki::digest::HashState::new(oncl_pki::key::HashAlg::Sha256);
        certificate_hash.update(&certificate_der);
        let mut certificate_sha256 = [0; 32];
        certificate_sha256.copy_from_slice(certificate_hash.finish().as_bytes());
        let digest = document.canonical_digest(
            Options {
                target: Some(signature.info),
                method,
                profile: profile.canonicalization,
                prefixes: &inclusive,
                excluded: &[],
                metadata_limit: Some(profile.max_metadata_bytes as u64),
            },
            signature_algorithm.hash_alg(),
            scope,
            &mut work,
        )?;
        for target in &signature.targets {
            let target = attribute_value(document, *target, profile.max_metadata_bytes)?;
            let node = document
                .lookup_id(&decode_id(&target)?)?
                .ok_or_else(|| invalid("qualifying properties target"))?;
            if document.node_region(&node)? != signature.signature {
                return Err(invalid("qualifying properties bound to another signature"));
            }
        }
        let mut references = Vec::new();
        let mut failures = Vec::new();
        let mut archive_references = if signature
            .proofs
            .iter()
            .any(|(kind, _)| *kind == oncl_pki::evidence::ProofKind::Archive)
        {
            Some(store.stage_source(scope)?)
        } else {
            None
        };
        ReferenceVerifier {
            document,
            profile,
            signatures: &signatures,
            signer_index,
            scope,
            work: &mut work,
            count: &mut count,
            failures: &mut failures,
            archive_references: archive_references.as_mut(),
            results: &mut references,
        }
        .verify_all(info, 0, &mut Vec::new())?;
        drop(info_doc);
        drop(_info_parse);
        pending.push(PendingSigner {
            certificate,
            value,
            digest,
            algorithm: signature_algorithm,
            info_xml,
            certificate_sha256,
            references,
            failures,
            archive_references,
            _metadata: retained_metadata,
        });
    }
    scope.checkpoint()?;
    // One host instant for the whole verification, sampled by the first signer's evidence check
    // AFTER that signer's document passes (see `ades::check_carried_evidence`), not before them.
    let final_context = ValidationContext { ..*ctx };
    let shared_now = std::cell::Cell::new(None);
    scope.checkpoint()?;
    let mut combined: Option<ValidationReport> = None;
    let mut records = Vec::with_capacity(signatures.len());
    for (signature, mut prepared) in signatures.iter().zip(pending) {
        let _info_parse = parse_guards(scope, prepared.info_xml.len())?;
        let parsed = roxmltree::Document::parse(&prepared.info_xml)
            .map_err(|_| invalid("prepared SignedInfo metadata"))?;
        let info = parsed
            .root_element()
            .first_element_child()
            .ok_or_else(|| invalid("prepared SignedInfo"))?;
        let signer = SignerEvidence {
            certificate: &prepared.certificate,
            algorithm: prepared.algorithm,
            signed_digest: prepared.digest,
            signature: &prepared.value,
            claimed_time: None,
        };
        let (mut checked, level) = ades::check_carried_evidence(
            document,
            signature,
            info,
            signer,
            profile,
            store,
            prepared.archive_references.as_mut(),
            &final_context,
            (clock, &shared_now),
            network,
            scope,
            &mut work,
        )?;
        for failure in prepared.failures {
            checked.invalidate_signer(0, failure, scope)?;
        }
        records.push(XmlSignerResult {
            signature: signature.signature,
            signed_info: signature.info,
            signature_value: signature.value.0,
            algorithm: prepared.algorithm,
            key_info: signature.key_info.as_ref().map(|key| key.bound.0),
            certificate: signature.certificate.0,
            certificate_sha256: prepared.certificate_sha256,
            level,
            references: prepared.references,
        });
        if let Some(report) = combined.as_mut() {
            if checked.verdict == oncl_pki::validation::Verdict::Invalid
                || report.verdict == oncl_pki::validation::Verdict::Valid
            {
                report.verdict = checked.verdict;
            }
            report.signers.append(checked.signers, scope)?;
        } else {
            combined = Some(checked);
        }
    }
    scope.checkpoint()?;
    Ok(XmlVerification {
        validation: combined.ok_or(XmlError::NoSignature)?,
        facts: XmlVerificationFacts {
            signatures: records,
            _metadata: metadata_guard,
            wsse: None,
        },
    })
}
