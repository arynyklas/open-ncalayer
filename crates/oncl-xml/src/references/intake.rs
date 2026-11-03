//! Signed-wire accounting is derived from the actual immutable XML grammar.
//! No signature/trust verdict, original spelling claim or generic free Source.
use super::*;
use oncl_pki::{
    digest::DigestValue,
    io::{FrozenReader, ProvisionalInput},
};
const X4: &str = "http://uri.etsi.org/01903/v1.4.1#";
// Three fixed declaration pseudo-attributes plus normal quoting/spacing fit far
// below one KiB. Oversized but parser-valid declarations remain DOCUMENT bytes.
const SERIALIZATION_PROLOG_CAP: u64 = 1024;

pub struct SignedXmlInput {
    input: ProvisionalInput,
}
pub struct SignedXmlReader<'a> {
    reader: FrozenReader<'a>,
}
impl SignedXmlInput {
    pub fn len(&self) -> u64 {
        self.input.len()
    }
    pub fn is_empty(&self) -> bool {
        self.input.is_empty()
    }
    pub fn wire_digest(&self) -> &DigestValue {
        self.input.wire_digest()
    }
    pub fn document_bytes(&self) -> u64 {
        self.input.document_bytes().expect("classified XML")
    }
    pub fn container_bytes(&self) -> u64 {
        self.input.container_bytes().expect("classified XML")
    }
    pub fn reader<'a>(&'a mut self, scope: &ResourceScope) -> Result<SignedXmlReader<'a>> {
        let length = self.len();
        Ok(SignedXmlReader {
            reader: self.input.reader(
                &[Region {
                    offset: 0,
                    len: length,
                }],
                scope,
            )?,
        })
    }
}
impl SignedXmlReader<'_> {
    pub fn source(&mut self) -> Source<'_> {
        self.reader.source()
    }
    pub fn finish(&mut self) -> Result<()> {
        self.reader.finish()?;
        Ok(())
    }
}
pub fn capture_signed_input(
    source: Source<'_>,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
) -> Result<SignedXmlInput> {
    let document = index_signed(source, profile, store, scope)?;
    Ok(SignedXmlInput {
        input: document.into_signed()?,
    })
}
fn validate_profile(profile: &XmlVerifyProfile) -> Result<()> {
    profile.xml.reservation()?;
    if profile.max_signers == 0
        || profile.max_signers > 64
        || profile.max_references == 0
        || profile.max_references > 4096
        || profile.max_metadata_bytes == 0
        || profile.max_metadata_bytes > 1048576
        || profile.max_work == 0
    {
        return Err(ProcessingError::InvalidLimits.into());
    }
    Ok(())
}
pub(crate) fn index_signed(
    source: Source<'_>,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
) -> Result<XmlDocument> {
    validate_profile(profile)?;
    // This metadata admission already counts as live RAM. Do not repeat the
    // predecessor's separate whole-bound RAM reservation in this new path.
    let index_metadata = scope.reserve_metadata(profile.xml.reservation()?)?;
    let per_signature = (profile.max_metadata_bytes as u64)
        .checked_mul(70)
        .and_then(|n| n.checked_add(profile.xml.max_name_bytes as u64 + 2))
        .ok_or(ProcessingError::ContainerLimit)?;
    let allowance = per_signature
        .checked_mul(profile.max_signers as u64)
        .and_then(|n| n.checked_add(SERIALIZATION_PROLOG_CAP + 3))
        .ok_or(ProcessingError::ContainerLimit)?;
    let pending = ProvisionalInput::capture(source, store, scope, allowance)?;
    let mut document =
        XmlDocument::index_provisional(pending, &profile.xml, store, scope, index_metadata)?;
    let framing = scope.reserve_metadata(
        (profile.max_metadata_bytes as u64)
            .checked_mul(10)
            .and_then(|n| {
                n.checked_add(
                    profile.xml.max_depth as u64 * 2048 + profile.max_signers as u64 * 8192,
                )
            })
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let signatures = scan_optional(&mut document, profile, scope)?;
    for signature in &signatures {
        metadata_shape(&mut document, signature, profile, scope)?;
    }
    let regions = geometry(&mut document, &signatures, profile, scope)?;
    document.classify_signed(&regions, scope)?;
    drop(framing);
    Ok(document)
}
fn metadata_shape(
    document: &mut XmlDocument,
    signature: &Metadata,
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<()> {
    if signature.info.len > profile.max_metadata_bytes as u64
        || signature.value.0.len > profile.max_metadata_bytes as u64
    {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let xml = metadata(
        document,
        signature.info,
        &signature.info_namespaces,
        profile.max_metadata_bytes,
    )?;
    let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("SignedInfo metadata"))?;
    let info = parsed
        .root_element()
        .first_element_child()
        .ok_or_else(|| invalid("SignedInfo"))?;
    only_ds_children(
        info,
        &["CanonicalizationMethod", "SignatureMethod", "Reference"],
    )?;
    let method = child(info, "CanonicalizationMethod")?;
    if C14n::from_uri(algorithm(method)?).is_none() {
        return Err(XmlSourceError::Unsupported(
            "SignedInfo canonicalization URI",
        ));
    }
    prefixes(method)?;
    let sig_algorithm = crate::signature_method(plain_algorithm(child(info, "SignatureMethod")?)?)
        .ok_or(XmlSourceError::Unsupported("signature algorithm URI"))?;
    if !profile
        .allowed_signature_algorithms
        .contains(&sig_algorithm)
    {
        return Err(XmlSourceError::AlgorithmDenied);
    }
    for reference in info.children().filter(|n| crate::is_ds(*n, "Reference")) {
        scope.checkpoint()?;
        only_ds_children(reference, &["Transforms", "DigestMethod", "DigestValue"])?;
        let uri = reference.attribute("URI").unwrap_or("");
        if !uri.is_empty() {
            decode_id(uri)?;
        }
        let hash = crate::digest_method(plain_algorithm(child(reference, "DigestMethod")?)?)
            .ok_or(XmlSourceError::Unsupported("reference digest URI"))?
            .hash_alg();
        let length = match hash {
            oncl_pki::key::HashAlg::Sha1 => 20,
            oncl_pki::key::HashAlg::Sha512 | oncl_pki::key::HashAlg::Streebog512 => 64,
            _ => 32,
        };
        if base64(child(reference, "DigestValue")?)?.len() != length {
            return Err(invalid("reference digest length"));
        }
        if let Some(transforms) = reference
            .children()
            .find(|n| crate::is_ds(*n, "Transforms"))
        {
            only_ds_children(transforms, &["Transform"])?;
            for transform in transforms.children().filter(Node::is_element) {
                let uri = algorithm(transform)?;
                if uri == crate::ENVELOPED_SIGNATURE {
                    if transform.children().any(|node| node.is_element()) {
                        return Err(XmlSourceError::Unsupported(
                            "enveloped transform parameters",
                        ));
                    }
                } else if uri == "http://www.w3.org/TR/1999/REC-xpath-19991116" {
                    signature_xpath_filter(transform)?;
                } else if C14n::from_uri(uri).is_some() {
                    prefixes(transform)?;
                } else {
                    return Err(XmlSourceError::Unsupported("reference transform URI"));
                }
            }
        }
    }
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrapper {
    None,
    Signature,
    Qualifying,
    Object,
    Unsigned,
    UnsignedSignature,
}
struct Frame {
    start: Region,
    qname_bytes: usize,
    signature: Option<usize>,
    is_signature: bool,
    wrapper: Wrapper,
    only_signatures: bool,
    direct_signatures: Vec<Region>,
    only_qualifying: bool,
    layout: Vec<Region>,
    attributes_allowed: bool,
}
struct Parent {
    start: Region,
    closing: Region,
    qname_bytes: usize,
    signatures: Vec<Region>,
}
fn contains(a: Region, b: Region) -> Result<bool> {
    Ok(b.offset >= a.offset && b.end()? <= a.end()?)
}
fn known_unsigned(namespace: Option<&str>, name: &str) -> bool {
    (namespace == Some(crate::XADES_NS)
        && matches!(
            name,
            "SignatureTimeStamp" | "CertificateValues" | "RevocationValues"
        ))
        || (namespace == Some(X4) && matches!(name, "ArchiveTimeStamp" | "TimeStampValidationData"))
}
fn normalize(mut regions: Vec<Region>) -> Result<Vec<Region>> {
    regions.sort_unstable_by_key(|r| r.offset);
    let mut merged: Vec<Region> = Vec::with_capacity(regions.len());
    for region in regions {
        if region.len == 0 {
            continue;
        }
        if let Some(previous) = merged.last_mut() {
            let end = previous.end()?;
            if region.offset < end {
                return Err(invalid("overlapping XML metadata geometry"));
            }
            if region.offset == end {
                previous.len = previous
                    .len
                    .checked_add(region.len)
                    .ok_or(ProcessingError::ContainerLimit)?;
                continue;
            }
        }
        merged.push(region);
    }
    Ok(merged)
}
fn covers(regions: &[Region], whole: Region) -> Result<bool> {
    let mut at = whole.offset;
    for region in regions {
        if region.end()? <= at {
            continue;
        }
        if region.offset > at {
            break;
        }
        at = region.end()?;
        if at >= whole.end()? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn whitespace(document: &mut XmlDocument, region: Region, scope: &ResourceScope) -> Result<bool> {
    let mut bytes = [0; 4096];
    let mut at = 0;
    while at < region.len {
        scope.checkpoint()?;
        let n = document.read_region(
            Region {
                offset: region.offset + at,
                len: region.len - at,
            },
            &mut bytes,
        )?;
        if n == 0 {
            return Err(invalid("layout extent"));
        }
        if bytes[..n]
            .iter()
            .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Ok(false);
        }
        at += n as u64;
    }
    Ok(true)
}
fn add_framing(
    regions: &mut Vec<Region>,
    totals: &mut [u64],
    signature: usize,
    region: Region,
    limit: usize,
) -> Result<()> {
    let total = totals[signature]
        .checked_add(region.len)
        .ok_or(ProcessingError::MetadataLimit)?;
    if total > limit as u64 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    totals[signature] = total;
    regions.push(region);
    Ok(())
}
fn geometry(
    document: &mut XmlDocument,
    signatures: &[Metadata],
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<Vec<Region>> {
    let mut regions = Vec::new();
    for signature in signatures {
        regions.extend([signature.info, signature.value.0]);
        if let Some(key) = &signature.key_info {
            regions.push(key.bound.0)
        }
        if let Some(properties) = &signature.signed_properties {
            regions.push(properties.bound.0)
        }
    }
    let whole = regions.clone();
    let mut frames: Vec<Frame> = Vec::with_capacity(profile.xml.max_depth);
    let mut parents = Vec::new();
    let mut layouts = Vec::new();
    let mut declarations = Vec::new();
    let mut totals = vec![0; signatures.len()];
    {
        let mut events = document.events();
        while let Some(event) = events.next_event()? {
            scope.checkpoint()?;
            if event.xml_declaration {
                declarations.push(event.region);
                continue;
            }
            if event.kind == XmlEventKind::Start {
                let name = event.name.as_ref().ok_or_else(|| invalid("element name"))?;
                let own = signatures
                    .iter()
                    .position(|s| s.signature.offset == event.region.offset);
                let signature = own.or_else(|| frames.last().and_then(|f| f.signature));
                if let Some(parent) = frames.last_mut() {
                    if let Some(own) = own {
                        parent.direct_signatures.push(signatures[own].signature);
                    } else {
                        parent.only_signatures = false;
                    }
                    if !signature
                        .and_then(|i| signatures[i].qualifying)
                        .is_some_and(|q| q.offset == event.region.offset)
                    {
                        parent.only_qualifying = false;
                    }
                }
                let wrapper = if own.is_some() {
                    Wrapper::Signature
                } else if let Some(index) = signature {
                    let current = &signatures[index];
                    if current
                        .qualifying
                        .is_some_and(|q| q.offset == event.region.offset)
                    {
                        Wrapper::Qualifying
                    } else if name.namespace() == Some(crate::XADES_NS)
                        && name.local() == "UnsignedProperties"
                        && frames
                            .last()
                            .is_some_and(|f| f.wrapper == Wrapper::Qualifying)
                    {
                        Wrapper::Unsigned
                    } else if current
                        .unsigned_container
                        .is_some_and(|r| r.offset == event.region.offset)
                    {
                        Wrapper::UnsignedSignature
                    } else if name.namespace() == Some(crate::DSIG_NS)
                        && name.local() == "Object"
                        && frames.last().is_some_and(|f| f.is_signature)
                    {
                        Wrapper::Object
                    } else {
                        Wrapper::None
                    }
                } else {
                    Wrapper::None
                };
                if frames.last().is_some_and(|f| f.is_signature)
                    && !(name.namespace() == Some(crate::DSIG_NS)
                        && matches!(
                            name.local(),
                            "SignedInfo" | "SignatureValue" | "KeyInfo" | "Object"
                        ))
                {
                    return Err(XmlSourceError::Unsupported("unknown Signature child"));
                }
                if let Some(index) = signature
                    && known_unsigned(name.namespace(), name.local())
                    && let Some(property) = signatures[index]
                        .unsigned
                        .iter()
                        .find(|m| m.bound.0.offset == event.region.offset)
                {
                    regions.push(property.bound.0);
                }
                let attributes_allowed = event.attributes.iter().all(|a| {
                    a.name.namespace() == Some("http://www.w3.org/XML/1998/namespace")
                        || a.name.namespace().is_none()
                            && match wrapper {
                                Wrapper::Signature => a.name.local() == "Id",
                                Wrapper::Qualifying => matches!(a.name.local(), "Id" | "Target"),
                                Wrapper::Unsigned | Wrapper::UnsignedSignature => {
                                    a.name.local() == "Id"
                                }
                                Wrapper::Object => {
                                    matches!(a.name.local(), "Id" | "MimeType" | "Encoding")
                                }
                                Wrapper::None => true,
                            }
                });
                frames.push(Frame {
                    start: event.region,
                    qname_bytes: name.qname.len(),
                    signature,
                    is_signature: own.is_some(),
                    wrapper,
                    only_signatures: true,
                    direct_signatures: Vec::new(),
                    only_qualifying: true,
                    layout: Vec::new(),
                    attributes_allowed,
                });
            } else if event.kind == XmlEventKind::End {
                let frame = frames.pop().ok_or_else(|| invalid("XML frame"))?;
                let mut wrapper = frame.wrapper;
                if wrapper == Wrapper::Object
                    && !frame
                        .signature
                        .and_then(|i| signatures[i].qualifying)
                        .is_some_and(|q| contains(event.region, q).unwrap_or(false))
                {
                    wrapper = Wrapper::None;
                }
                if wrapper != Wrapper::None {
                    if !frame.attributes_allowed {
                        return Err(XmlSourceError::Unsupported(
                            "unsupported signature wrapper attributes",
                        ));
                    }
                    let index = frame.signature.ok_or_else(|| invalid("wrapper signer"))?;
                    if !whole
                        .iter()
                        .any(|r| contains(*r, frame.start).unwrap_or(false))
                    {
                        add_framing(
                            &mut regions,
                            &mut totals,
                            index,
                            frame.start,
                            profile.max_metadata_bytes,
                        )?;
                        if let Some(closing) = event.closing_tag {
                            add_framing(
                                &mut regions,
                                &mut totals,
                                index,
                                closing,
                                profile.max_metadata_bytes,
                            )?;
                        }
                    }
                    if wrapper != Wrapper::Object || frame.only_qualifying {
                        for layout in frame.layout {
                            layouts.push((index, layout, wrapper == Wrapper::Object));
                        }
                    }
                }
                if frame.only_signatures
                    && !frame.direct_signatures.is_empty()
                    && let Some(closing) = event.closing_tag
                {
                    parents.push(Parent {
                        start: frame.start,
                        closing,
                        qname_bytes: frame.qname_bytes,
                        signatures: frame.direct_signatures,
                    });
                }
            } else if let Some(frame) = frames.last_mut() {
                frame.only_signatures = false;
                if event.kind == XmlEventKind::Text && frame.wrapper != Wrapper::None {
                    frame.layout.push(event.region);
                } else if frame.wrapper == Wrapper::Object {
                    frame.only_qualifying = false;
                }
            }
        }
    }
    for (index, region, object) in layouts {
        if region.len > profile.max_metadata_bytes as u64 {
            if object {
                continue;
            } else {
                return Err(ProcessingError::MetadataLimit.into());
            }
        }
        if whitespace(document, region, scope)? {
            add_framing(
                &mut regions,
                &mut totals,
                index,
                region,
                profile.max_metadata_bytes,
            )?;
        } else if !object {
            return Err(XmlSourceError::Unsupported(
                "non-layout text in signature metadata wrapper",
            ));
        }
    }
    let mut regions = normalize(regions)?;
    for parent in parents {
        if parent.closing.len != parent.qname_bytes as u64 + 3 {
            continue;
        }
        let mut at = parent.start.end()?;
        let mut valid = true;
        for signature in parent.signatures {
            if signature.offset != at || !covers(&regions, signature)? {
                valid = false;
                break;
            }
            at = signature.end()?;
        }
        if valid && at == parent.closing.offset {
            regions.push(Region {
                offset: parent.closing.offset,
                len: parent.closing.len - 1,
            });
        }
    }
    if !signatures.is_empty() {
        if let Some(bom) = document.bom_region() {
            regions.push(bom)
        }
        if declarations.len() > 1 {
            return Err(invalid("duplicate serialization declaration"));
        }
        for declaration in declarations {
            if declaration.len <= SERIALIZATION_PROLOG_CAP {
                regions.push(declaration)
            }
        }
    }
    normalize(regions)
}
