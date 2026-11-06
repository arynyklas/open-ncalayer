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
    document.classify_signed(&regions.entries, scope)?;
    drop(framing);
    Ok(document)
}
/// Key-independent check for an Add: inserting a new `ds:Signature` at `at` changes the
/// bytes of every reference of an existing signature that covers that offset (the whole
/// document, or an element around it) unless the reference drops all signatures (the
/// XPath filter) or, under `KalkanLegacy`, the new signature is later in document order
/// than the existing one (the legacy filter excludes later signatures). Such a
/// signature would fail verification, so the Add is refused BEFORE the key is used.
/// Manifest members are followed with the verifier's resolution and its depth, cycle,
/// count and work limits. No trust or algorithm decision is made here.
pub(crate) fn check_insertion_keeps_existing_references(
    document: &mut XmlDocument,
    at: u64,
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<()> {
    let signatures = scan_optional(document, profile, scope)?;
    let mut work = profile.max_work;
    let mut count = 0usize;
    for signature in &signatures {
        scope.checkpoint()?;
        let xml = metadata(
            document,
            signature.info,
            &signature.info_namespaces,
            profile.max_metadata_bytes,
        )?;
        let _parsed = parse_guards(scope, xml.len())?;
        let parsed =
            roxmltree::Document::parse(&xml).map_err(|_| invalid("SignedInfo metadata"))?;
        let info = parsed
            .root_element()
            .first_element_child()
            .ok_or_else(|| invalid("SignedInfo"))?;
        let later_is_excluded = profile.canonicalization == C14nProfile::KalkanLegacy
            && signature.signature.offset < at;
        let mut active = Vec::new();
        insertion_container(
            document,
            info,
            at,
            later_is_excluded,
            0,
            &mut active,
            &mut count,
            &mut work,
            profile,
            scope,
        )?;
    }
    Ok(())
}
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the verifier's explicit state"
)]
fn insertion_container(
    document: &mut XmlDocument,
    container: Node<'_, '_>,
    at: u64,
    later_is_excluded: bool,
    depth: usize,
    active: &mut Vec<Region>,
    count: &mut usize,
    work: &mut u64,
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<()> {
    for reference in container
        .children()
        .filter(|n| crate::is_ds(*n, "Reference"))
    {
        scope.checkpoint()?;
        *count += 1;
        if *count > profile.max_references {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let drops_signatures = later_is_excluded
            || reference
                .children()
                .filter(|n| crate::is_ds(*n, "Transforms"))
                .flat_map(|transforms| transforms.children().filter(Node::is_element))
                .any(|transform| {
                    algorithm(transform)
                        .is_ok_and(|uri| uri == "http://www.w3.org/TR/1999/REC-xpath-19991116")
                });
        let (target, missing, _) = resolve_reference_uri(document, reference, work, scope)?;
        if missing {
            continue;
        }
        let covers = match target {
            None => true,
            Some(region) => region.offset < at && at < region.end()?,
        };
        if covers && !drops_signatures {
            return Err(XmlSourceError::Unsupported(
                "Add would change the bytes an existing signature reference covers",
            ));
        }
        if reference.attribute("Type") == Some("http://www.w3.org/2000/09/xmldsig#Manifest") {
            let target = target.ok_or_else(|| invalid("Manifest reference is not an element"))?;
            if depth >= profile.max_manifest_depth || active.contains(&target) {
                return Err(ProcessingError::InvalidInput("Manifest recursion/cycle limit").into());
            }
            *work = work
                .checked_sub(document.len())
                .ok_or(ProcessingError::InvalidInput("reference work limit"))?;
            let node = document.indexed_node(target);
            let namespaces = document.node_namespaces(&node, scope)?;
            let xml = metadata(document, target, &namespaces, profile.max_metadata_bytes)?;
            let _parsed = parse_guards(scope, xml.len())?;
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
            let result = insertion_container(
                document,
                manifest,
                at,
                later_is_excluded,
                depth + 1,
                active,
                count,
                work,
                profile,
                scope,
            );
            active.pop();
            result?;
        }
    }
    Ok(())
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
    has_direct_signatures: bool,
    only_qualifying: bool,
    attributes_allowed: bool,
}
struct Parent {
    start: Region,
    closing: Region,
    qname_bytes: usize,
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
struct GeometryRegions {
    entries: Vec<Region>,
    metadata: oncl_pki::resource::ResourceReservation,
}
impl GeometryRegions {
    fn new(scope: &ResourceScope) -> Result<Self> {
        Ok(Self {
            entries: Vec::new(),
            metadata: scope.reserve_metadata(0)?,
        })
    }
    fn push(&mut self, region: Region) -> Result<()> {
        region.end()?;
        if region.len == 0 {
            return Ok(());
        }
        if let Some(last) = self.entries.last_mut()
            && last.end()? == region.offset
        {
            last.len = last
                .len
                .checked_add(region.len)
                .ok_or(ProcessingError::ContainerLimit)?;
            return Ok(());
        }
        if self.entries.len() == self.entries.capacity() {
            let capacity = self
                .entries
                .capacity()
                .max(4)
                .checked_mul(2)
                .ok_or(ProcessingError::MetadataLimit)?;
            let additional = (capacity - self.entries.capacity())
                .checked_mul(std::mem::size_of::<Region>())
                .ok_or(ProcessingError::MetadataLimit)?;
            // Metadata is live RAM. Admit before the actual Vec growth, retaining
            // its owner through sort/normalization and the classification copy.
            self.metadata.grow(additional as u64)?;
            self.entries
                .try_reserve_exact(capacity - self.entries.len())
                .map_err(|_| ProcessingError::MemoryLimit)?;
        }
        self.entries.push(region);
        Ok(())
    }
    fn normalize(&mut self) -> Result<()> {
        self.entries.sort_unstable_by_key(|r| r.offset);
        let mut retained = 0;
        for index in 0..self.entries.len() {
            let region = self.entries[index];
            if retained > 0 {
                let previous = &mut self.entries[retained - 1];
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
            self.entries[retained] = region;
            retained += 1;
        }
        self.entries.truncate(retained);
        Ok(())
    }
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
pub(crate) fn whitespace(
    document: &mut dyn oncl_pki::io::CapturedInput,
    region: Region,
    scope: &ResourceScope,
) -> Result<bool> {
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
    regions: &mut GeometryRegions,
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
    regions.push(region)?;
    Ok(())
}
fn geometry(
    document: &mut XmlDocument,
    signatures: &[Metadata],
    profile: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<GeometryRegions> {
    let mut regions = GeometryRegions::new(scope)?;
    for signature in signatures {
        regions.push(signature.info)?;
        regions.push(signature.value.0)?;
        if let Some(key) = &signature.key_info {
            regions.push(key.bound.0)?;
        }
        if let Some(properties) = &signature.signed_properties {
            regions.push(properties.bound.0)?;
        }
    }
    let mut frames: Vec<Frame> = Vec::with_capacity(profile.xml.max_depth);
    // Both arrays are bounded by already admitted depth/signer cardinality,
    // never by document nodes or text events.
    let mut parents = Vec::with_capacity(signatures.len());
    let mut declaration = None;
    let mut totals = vec![0; signatures.len()];
    let mut work = profile.max_work;
    {
        let mut events = document.events();
        while let Some(event) = events.next_event()? {
            scope.checkpoint()?;
            work = work.checked_sub(1).ok_or(ProcessingError::InvalidInput(
                "signed XML geometry work limit",
            ))?;
            if event.xml_declaration {
                if declaration.replace(event.region).is_some() {
                    return Err(invalid("duplicate serialization declaration"));
                }
                continue;
            }
            if event.kind == XmlEventKind::Start {
                let name = event.name.as_ref().ok_or_else(|| invalid("element name"))?;
                let own = signatures
                    .iter()
                    .position(|s| s.signature.offset == event.region.offset);
                let signature = own.or_else(|| frames.last().and_then(|f| f.signature));
                if let Some(parent) = frames.last_mut() {
                    if own.is_some() {
                        parent.has_direct_signatures = true;
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
                    regions.push(property.bound.0)?;
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
                    has_direct_signatures: false,
                    only_qualifying: true,
                    attributes_allowed,
                });
            } else if event.kind == XmlEventKind::End {
                let closing_tag = event.closing_tag;
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
                    if !signatures.iter().any(|signature| {
                        [
                            Some(signature.info),
                            Some(signature.value.0),
                            signature.key_info.as_ref().map(|key| key.bound.0),
                            signature
                                .signed_properties
                                .as_ref()
                                .map(|properties| properties.bound.0),
                        ]
                        .into_iter()
                        .flatten()
                        .any(|region| contains(region, frame.start).unwrap_or(false))
                    }) {
                        add_framing(
                            &mut regions,
                            &mut totals,
                            index,
                            frame.start,
                            profile.max_metadata_bytes,
                        )?;
                        if let Some(closing) = closing_tag {
                            add_framing(
                                &mut regions,
                                &mut totals,
                                index,
                                closing,
                                profile.max_metadata_bytes,
                            )?;
                        }
                    }
                    if wrapper == Wrapper::Object
                        && frame.only_qualifying
                        && let Some(qualifying) = signatures[index].qualifying
                        && let Some(closing) = closing_tag
                    {
                        // With no other direct child/comment/PI/CDATA, layout
                        // can only be the two contiguous spans around the known
                        // qualifying subtree. Application text is never free.
                        for region in [
                            Region {
                                offset: frame.start.end()?,
                                len: qualifying.offset - frame.start.end()?,
                            },
                            Region {
                                offset: qualifying.end()?,
                                len: closing.offset - qualifying.end()?,
                            },
                        ] {
                            if region.len <= profile.max_metadata_bytes as u64
                                && whitespace(events.reader.file, region, scope)?
                            {
                                add_framing(
                                    &mut regions,
                                    &mut totals,
                                    index,
                                    region,
                                    profile.max_metadata_bytes,
                                )?;
                            }
                        }
                    }
                }
                if frame.only_signatures
                    && frame.has_direct_signatures
                    && let Some(closing) = closing_tag
                {
                    parents.push(Parent {
                        start: frame.start,
                        closing,
                        qname_bytes: frame.qname_bytes,
                    });
                }
            } else if let Some(frame) = frames.last_mut() {
                frame.only_signatures = false;
                let kind = event.kind;
                let region = event.region;
                if kind == XmlEventKind::Text
                    && !matches!(frame.wrapper, Wrapper::None | Wrapper::Object)
                {
                    let index = frame.signature.ok_or_else(|| invalid("wrapper signer"))?;
                    // Bound bytes BEFORE retaining any per-event extent. Read
                    // whitespace now, not after an input-sized layout collection.
                    if region.len > profile.max_metadata_bytes as u64
                        || totals[index]
                            .checked_add(region.len)
                            .is_none_or(|n| n > profile.max_metadata_bytes as u64)
                    {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                    if !whitespace(events.reader.file, region, scope)? {
                        return Err(XmlSourceError::Unsupported(
                            "non-layout text in signature metadata wrapper",
                        ));
                    }
                    add_framing(
                        &mut regions,
                        &mut totals,
                        index,
                        region,
                        profile.max_metadata_bytes,
                    )?;
                } else if kind != XmlEventKind::Text && frame.wrapper == Wrapper::Object {
                    frame.only_qualifying = false;
                }
            }
        }
    }
    let (wsse, _wsse_admission) = crate::wsse::metadata_regions(document, profile, scope)?;
    for region in &wsse {
        regions.push(*region)?;
    }
    regions.normalize()?;
    for parent in parents {
        if wsse
            .iter()
            .any(|region| contains(*region, parent.closing).unwrap_or(false))
        {
            continue;
        }
        if parent.closing.len != parent.qname_bytes as u64 + 3 {
            continue;
        }
        let mut at = parent.start.end()?;
        let mut valid = true;
        for signature in signatures.iter().filter(|signature| {
            signature.signature.offset >= parent.start.end().unwrap_or(u64::MAX)
                && signature
                    .signature
                    .end()
                    .is_ok_and(|end| end <= parent.closing.offset)
        }) {
            if signature.signature.offset != at || !covers(&regions.entries, signature.signature)? {
                valid = false;
                break;
            }
            at = signature.signature.end()?;
        }
        if valid && at == parent.closing.offset {
            regions.push(Region {
                offset: parent.closing.offset,
                len: parent.closing.len - 1,
            })?;
        }
    }
    if !signatures.is_empty() {
        if let Some(bom) = document.bom_region() {
            regions.push(bom)?;
        }
        if let Some(declaration) = declaration
            && declaration.len <= SERIALIZATION_PROLOG_CAP
        {
            regions.push(declaration)?;
        }
    }
    regions.normalize()?;
    Ok(regions)
}

#[cfg(test)]
mod geometry_admission_tests {
    use super::*;
    use oncl_pki::resource::{OperationControl, Progress, ResourceLimits, SharedBudget};
    use std::sync::Arc;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> std::result::Result<(), ProcessingError> {
            Ok(())
        }
    }
    #[test]
    fn region_capacity_is_admitted_exactly_before_any_growth() {
        let bytes = 8 * std::mem::size_of::<Region>() as u64;
        for short in [false, true] {
            let limits = ResourceLimits {
                metadata_bytes: bytes,
                memory_bytes: bytes - u64::from(short),
                ..Default::default()
            };
            let scope = Arc::new(SharedBudget::new(limits.clone()).unwrap())
                .begin(limits, Arc::new(Control))
                .unwrap();
            let mut regions = GeometryRegions::new(&scope).unwrap();
            let first = regions.push(Region { offset: 0, len: 1 });
            if short {
                assert!(matches!(
                    first,
                    Err(XmlSourceError::Processing(
                        ProcessingError::MetadataLimit | ProcessingError::MemoryLimit
                    ))
                ));
                assert_eq!(
                    regions.entries.capacity(),
                    0,
                    "no allocation precedes admission"
                );
            } else {
                first.unwrap();
                for offset in [2, 4, 6, 8, 10, 12, 14] {
                    regions.push(Region { offset, len: 1 }).unwrap();
                }
                assert_eq!(regions.metadata.bytes(), bytes);
                assert_eq!(regions.entries.capacity(), 8);
                assert!(matches!(
                    regions.push(Region { offset: 16, len: 1 }),
                    Err(XmlSourceError::Processing(
                        ProcessingError::MetadataLimit | ProcessingError::MemoryLimit
                    ))
                ));
                assert_eq!(regions.entries.len(), 8);
                assert_eq!(regions.entries.capacity(), 8);
                assert_eq!(regions.metadata.bytes(), bytes);
            }
        }
    }
}
