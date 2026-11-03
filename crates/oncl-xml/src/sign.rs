//! Source signing keeps the document immutable and only materializes bounded metadata.
use crate::{
    Algorithms, DSIG_NS, QualifyingObject, SIGNED_PROPERTIES_TYPE, SigningTimeObject, SplicePoint,
    XADES_NS, XmlError, base64_lines, canonicalizer, escape_attribute, escape_text, parse,
};
use crate::{
    C14n, C14nProfile, XmlDocument, XmlEventKind, XmlLimits, XmlSourceError,
    canonical_stream::Options,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oncl_pki::key::PrivateKey;
use oncl_pki::{
    io::{Region, Source, TemporaryStore},
    key::{DigestSigner, SigAlg},
    resource::{IO_CHUNK_BYTES, ProcessingError, ResourceScope},
};
use roxmltree::Node;
use std::io::Write;
type Result<T, E = XmlSourceError> = std::result::Result<T, E>;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum XmlSignMode {
    #[default]
    Create,
    Add,
}
/// Host-selected identity targets; these are full unique XML IDs, not guessed filenames.
#[derive(Clone, Debug)]
pub struct XmlSignProfile<'a> {
    pub xml: XmlLimits,
    pub target: Option<&'a str>,
    pub parent: Option<&'a str>,
    pub mode: XmlSignMode,
    pub signature_id: Option<&'a str>,
    pub reference_c14n: C14n,
    pub signed_info_c14n: C14n,
    pub canonicalization: C14nProfile,
    pub enveloped: bool,
    pub allowed_signature_algorithms: &'static [SigAlg],
    pub max_metadata_bytes: usize,
    pub max_work: u64,
    pub output: crate::XmlOutput,
    pub strip_whitespace: bool,
    pub base64_line_breaks: Option<bool>,
    pub evidence_limits: Option<oncl_pki::evidence::EvidenceLimits>,
}
impl Default for XmlSignProfile<'_> {
    fn default() -> Self {
        Self {
            xml: XmlLimits::default(),
            target: None,
            parent: None,
            mode: XmlSignMode::Create,
            signature_id: None,
            reference_c14n: C14n::Exclusive,
            signed_info_c14n: C14n::Exclusive,
            canonicalization: C14nProfile::Standard,
            enveloped: true,
            allowed_signature_algorithms: &[
                SigAlg::RsaSha256,
                SigAlg::Gost2004,
                SigAlg::Gost2015_512,
            ],
            max_metadata_bytes: 262144,
            max_work: 1 << 40,
            output: crate::XmlOutput::AsIs,
            strip_whitespace: true,
            base64_line_breaks: None,
            evidence_limits: None,
        }
    }
}
#[derive(Debug)]
pub struct XmlSignSummary {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub algorithm: SigAlg,
}
/// An actual immutable source, indexed targets and unique insertion point.
/// Creation performs all key-independent structural checks before Core opens
/// a key. Fields, original scope and document storage cannot be detached.
pub struct PreparedXmlSign<'a> {
    document: XmlDocument,
    profile: XmlSignProfile<'a>,
    target: Option<Region>,
    place: Placement,
    has_signatures: bool,
    output_plan: OutputPlan,
    store: TemporaryStore,
    _memory: oncl_pki::resource::ResourceReservation,
    _metadata: oncl_pki::resource::ResourceReservation,
}
impl<'a> PreparedXmlSign<'a> {
    pub fn profile(&self) -> &XmlSignProfile<'a> {
        &self.profile
    }
    pub fn verify_existing(
        &mut self,
        validation: &oncl_pki::validation::ValidationContext<'_>,
        network: &oncl_pki::validation::NetworkPolicy,
        scope: &mut ResourceScope,
    ) -> Result<()> {
        self.document.check_scope(scope)?;
        if !self.has_signatures {
            return Ok(());
        }
        let profile = crate::XmlVerifyProfile {
            xml: self.profile.xml.clone(),
            canonicalization: self.profile.canonicalization,
            allowed_signature_algorithms: self.profile.allowed_signature_algorithms,
            max_metadata_bytes: self.profile.max_metadata_bytes,
            max_work: self.profile.max_work,
            evidence_limits: self.profile.evidence_limits,
            ..Default::default()
        };
        let report = crate::references::verify_document(
            &mut self.document,
            &profile,
            &self.store,
            validation,
            network,
            scope,
        )?;
        if report.validation.verdict == oncl_pki::validation::Verdict::Invalid
            || (validation.policy == oncl_pki::validation::ValidationPolicy::StrictOnline
                && report.validation.verdict != oncl_pki::validation::Verdict::Valid)
        {
            return Err(invalid(
                "existing XML signature/reference/proof validation failed",
            ));
        }
        Ok(())
    }
    pub(crate) fn check_id(&mut self, id: &str, scope: &ResourceScope) -> Result<()> {
        self.document.check_scope(scope)?;
        if id.is_empty()
            || id.len() > self.profile.xml.max_id_bytes
            || self.document.lookup_id(id)?.is_some()
        {
            return Err(invalid("signature metadata ID collision"));
        }
        Ok(())
    }
}
fn invalid(s: &'static str) -> XmlSourceError {
    XmlSourceError::Malformed(s)
}
fn contains(a: Region, b: Region) -> Result<bool> {
    Ok(b.offset >= a.offset && b.end()? <= a.end()?)
}
fn read(document: &mut XmlDocument, region: Region, max: usize) -> Result<Vec<u8>> {
    if region.len > max as u64 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let mut out = vec![0; region.len as usize];
    let mut at = 0;
    while at < out.len() {
        let n = document.read_region(
            Region {
                offset: region.offset + at as u64,
                len: region.len - at as u64,
            },
            &mut out[at..],
        )?;
        if n == 0 {
            return Err(invalid("short XML metadata"));
        }
        at += n;
    }
    Ok(out)
}
pub(crate) struct Placement {
    pub(crate) at: u64,
    pub(crate) skip: u64,
    pub(crate) open: &'static str,
    pub(crate) close: String,
    pub(crate) context: String,
}
pub(crate) fn placement(
    document: &mut XmlDocument,
    parent: Region,
    max: usize,
    scope: &ResourceScope,
) -> Result<Placement> {
    let mut starts = Vec::<Vec<(String, Region)>>::new();
    let mut attributes = None;
    let mut namespaces = Vec::new();
    let mut qname = String::new();
    {
        let mut events = document.events();
        while let Some(event) = events.next_event()? {
            scope.checkpoint()?;
            match event.kind {
                XmlEventKind::Start => {
                    starts.push(
                        event
                            .attributes
                            .iter()
                            .filter(|a| {
                                a.name.namespace() == Some("http://www.w3.org/XML/1998/namespace")
                            })
                            .map(|a| (a.name.qname.clone(), a.value))
                            .collect(),
                    );
                }
                XmlEventKind::End => {
                    if event.region == parent {
                        attributes = Some(starts.iter().flatten().cloned().collect::<Vec<_>>());
                        namespaces = event
                            .namespaces()
                            .map(|(p, u)| (p.to_owned(), u.to_owned()))
                            .collect();
                        qname = event
                            .name
                            .as_ref()
                            .ok_or_else(|| invalid("parent name"))?
                            .qname
                            .clone();
                        break;
                    }
                    starts.pop();
                }
                _ => {}
            }
        }
    }
    let attributes = attributes.ok_or_else(|| invalid("signature parent missing"))?;
    // Separate ancestor wrappers preserve both standard-nearest and explicitly legacy-outermost xml:* semantics.
    let mut context = String::from("<context");
    for (p, u) in namespaces {
        if p == "xml" {
            continue;
        }
        let name = if p.is_empty() {
            "xmlns".to_owned()
        } else {
            format!("xmlns:{p}")
        };
        context.push_str(&format!(" {name}=\"{}\"", crate::escape_attribute(&u)));
    }
    context.push('>');
    let mut depth = 0;
    for (name, region) in attributes {
        let raw = read(
            document,
            Region {
                offset: region
                    .offset
                    .checked_sub(1)
                    .ok_or_else(|| invalid("attribute extent"))?,
                len: region.len + 2,
            },
            max,
        )?;
        context.push_str("<context ");
        context.push_str(&name);
        context.push('=');
        context.push_str(std::str::from_utf8(&raw).map_err(|_| invalid("attribute UTF8"))?);
        context.push('>');
        depth += 1;
        if context.len() > max {
            return Err(ProcessingError::MetadataLimit.into());
        }
    }
    // Store closing context count in the wrapper itself via a marker-free suffix at use sites.
    let tail = read(
        document,
        Region {
            offset: parent
                .end()?
                .checked_sub(2)
                .ok_or_else(|| invalid("parent extent"))?,
            len: 2,
        },
        max,
    )?;
    let (at, skip, open, close) = if tail == b"/>" {
        (parent.end()? - 2, 2, ">", format!("</{qname}>"))
    } else {
        let n = parent.len.min(max as u64);
        let tail = read(
            document,
            Region {
                offset: parent.end()? - n,
                len: n,
            },
            max,
        )?;
        let start = tail
            .windows(2)
            .rposition(|w| w == b"</")
            .ok_or_else(|| invalid("parent end tag"))?;
        (parent.end()? - n + start as u64, 0, "", String::new())
    };
    context.push_str(&format!("\u{0}{depth}"));
    Ok(Placement {
        at,
        skip,
        open,
        close,
        context,
    })
}
pub(crate) fn wrap(context: &str, signature: &str) -> Result<String> {
    let (prefix, depth) = context
        .split_once('\0')
        .ok_or_else(|| invalid("metadata context"))?;
    let depth: usize = depth.parse().map_err(|_| invalid("metadata context"))?;
    Ok(format!(
        "{prefix}{signature}{}",
        "</context>".repeat(depth + 1)
    ))
}
fn root(document: &mut XmlDocument) -> Result<Region> {
    let mut events = document.events();
    while let Some(event) = events.next_event()? {
        if event.kind == XmlEventKind::End && event.depth == 0 {
            return Ok(event.region);
        }
    }
    Err(invalid("XML document element"))
}
/// Sign the actual source using the leaf/key algorithm selected by DigestSigner.
/// Reference hashing is internal work, and output is charged before each external write.
/// Existing signatures survive Add byte-for-byte. Whole-document references may be
/// invalidated by a later Add; use stable ID targets for independently preserved signatures.
pub(crate) trait SignatureOutput {
    fn write_chunk(&mut self, bytes: &[u8], scope: &ResourceScope) -> Result<()>;
}
struct ExternalWriter<'a>(&'a mut dyn Write);
impl SignatureOutput for ExternalWriter<'_> {
    fn write_chunk(&mut self, bytes: &[u8], scope: &ResourceScope) -> Result<()> {
        scope.account_output(bytes.len() as u64)?;
        self.0.write_all(bytes).map_err(ProcessingError::from)?;
        Ok(())
    }
}
pub(crate) struct StageWriter<'a, 'b>(pub &'a mut oncl_pki::io::XmlSignatureOutput<'b>);
impl SignatureOutput for StageWriter<'_, '_> {
    fn write_chunk(&mut self, bytes: &[u8], _: &ResourceScope) -> Result<()> {
        self.0.append(bytes)?;
        Ok(())
    }
}
pub fn sign_source(
    input: Source<'_>,
    profile: &XmlSignProfile<'_>,
    signer: &mut dyn DigestSigner,
    store: &TemporaryStore,
    output: &mut dyn Write,
    scope: &mut ResourceScope,
) -> Result<XmlSignSummary> {
    prepare_source(input, profile, store, scope)?.finish(
        signer,
        &mut ExternalWriter(output),
        scope,
        None,
        None,
    )
}
/// Finish a prepared document into an already protected OUTPUT transaction.
/// Hosts open keys only after preparation/verify_existing. Final validation is
/// always performed on actual assembled output before the host may finish it.
pub fn sign_prepared(
    prepared: PreparedXmlSign<'_>,
    signer: &mut dyn DigestSigner,
    validation: &oncl_pki::validation::ValidationContext<'_>,
    network: &oncl_pki::validation::NetworkPolicy,
    output: &mut oncl_pki::io::XmlSignatureOutput<'_>,
    scope: &mut ResourceScope,
) -> Result<crate::xades::XadesReport> {
    let profile = prepared.profile.clone();
    let store = prepared.store.clone();
    let summary = prepared.finish(signer, &mut StageWriter(output), scope, None, None)?;
    let verify = crate::XmlVerifyProfile {
        xml: profile.xml,
        canonicalization: profile.canonicalization,
        allowed_signature_algorithms: profile.allowed_signature_algorithms,
        max_metadata_bytes: profile.max_metadata_bytes,
        max_work: profile.max_work,
        evidence_limits: profile.evidence_limits,
        ..Default::default()
    };
    let verification = crate::verify_source(
        output.source()?,
        &verify,
        &store,
        validation,
        network,
        scope,
    )?;
    if verification.validation.verdict == oncl_pki::validation::Verdict::Invalid
        || (validation.policy == oncl_pki::validation::ValidationPolicy::StrictOnline
            && verification.validation.verdict != oncl_pki::validation::Verdict::Valid)
    {
        return Err(invalid(
            "final XML signature/reference/proof validation failed",
        ));
    }
    Ok(crate::xades::XadesReport {
        summary,
        verification,
    })
}
pub fn prepare_source<'a>(
    input: Source<'_>,
    profile: &XmlSignProfile<'a>,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
) -> Result<PreparedXmlSign<'a>> {
    if profile.max_metadata_bytes == 0
        || profile.max_metadata_bytes > 1048576
        || profile.max_work == 0
    {
        return Err(ProcessingError::InvalidLimits.into());
    }
    let memory = scope.reserve_memory(profile.max_metadata_bytes as u64 * 4)?;
    let metadata = scope.reserve_metadata(profile.max_metadata_bytes as u64)?;
    let mut document = XmlDocument::index(input, &profile.xml, store, scope)?;
    let mut signature_count = 0;
    {
        let mut events = document.events();
        while let Some(event) = events.next_event()? {
            if event.kind == XmlEventKind::Start
                && event.name.as_ref().is_some_and(|n| {
                    n.namespace() == Some(crate::DSIG_NS) && n.local() == "Signature"
                })
            {
                signature_count += 1;
            }
        }
    }
    if profile.mode == XmlSignMode::Create && signature_count != 0 {
        return Err(invalid("Create cannot replace existing XML signatures"));
    }
    if let Some(id) = profile.signature_id
        && (id.is_empty()
            || id.len() > profile.xml.max_id_bytes
            || document.lookup_id(id)?.is_some())
    {
        return Err(invalid("signature metadata ID collision"));
    }
    let target = profile
        .target
        .map(|id| document.lookup_id(id))
        .transpose()?
        .flatten();
    if profile.target.is_some() && target.is_none() {
        return Err(invalid("signature target ID missing"));
    }
    let target = target
        .as_ref()
        .map(|n| document.node_region(n))
        .transpose()?;
    let parent = match profile.parent {
        Some(id) => {
            let node = document
                .lookup_id(id)?
                .ok_or_else(|| invalid("signature parent ID missing"))?;
            document.node_region(&node)?
        }
        None => root(&mut document)?,
    };
    if !profile.enveloped && (target.is_none() || contains(target.unwrap(), parent)?) {
        return Err(invalid(
            "signature inside reference requires enveloped transform",
        ));
    }
    let place = placement(&mut document, parent, profile.max_metadata_bytes, scope)?;
    let output_plan = output_plan(&mut document, profile.output, scope)?;
    Ok(PreparedXmlSign {
        document,
        profile: profile.clone(),
        target,
        place,
        output_plan,
        has_signatures: signature_count != 0,
        store: store.clone(),
        _memory: memory,
        _metadata: metadata,
    })
}
impl PreparedXmlSign<'_> {
    pub(crate) fn finish(
        self,
        signer: &mut dyn DigestSigner,
        output: &mut dyn SignatureOutput,
        scope: &mut ResourceScope,
        qualifying: Option<crate::QualifyingObject<'_>>,
        ades: Option<(
            &crate::xades::XadesSourceSpec<'_>,
            &crate::xades::XadesServices<'_>,
        )>,
    ) -> Result<XmlSignSummary> {
        let Self {
            mut document,
            profile,
            target,
            place,
            output_plan,
            _memory,
            _metadata,
            ..
        } = self;
        document.check_scope(scope)?;
        let profile = &profile;
        let algorithm = signer.algorithm();
        if !profile.allowed_signature_algorithms.contains(&algorithm) {
            return Err(XmlSourceError::AlgorithmDenied);
        }
        let (signature_uri, digest_uri) =
            crate::signing_uris(algorithm).ok_or(XmlSourceError::AlgorithmDenied)?;
        let _working =
            scope.reserve_memory(profile.max_metadata_bytes as u64 * 12 + IO_CHUNK_BYTES as u64)?;
        let _working_metadata = scope.reserve_metadata(profile.max_metadata_bytes as u64 * 7)?;
        if let Some(q) = qualifying
            && document.lookup_id(q.signed_properties_id)?.is_some()
        {
            return Err(invalid("signed properties ID collision"));
        }
        let mut work = profile.max_work;
        // Same-document URI references omit comments even if a transform requests them.
        let method = if profile.reference_c14n.is_exclusive() {
            C14n::Exclusive
        } else {
            C14n::Inclusive
        };
        let digest = document.canonical_digest(
            Options {
                target,
                method,
                profile: profile.canonicalization,
                prefixes: &[],
                excluded: &[],
                metadata_limit: None,
            },
            algorithm.hash_alg(),
            scope,
            &mut work,
        )?;
        let uri = profile
            .target
            .map_or_else(String::new, |id| format!("#{}", percent_id(id)));
        let mut transforms = Vec::new();
        if profile.enveloped {
            transforms.push(crate::ENVELOPED_SIGNATURE)
        }
        transforms.push(profile.reference_c14n.uri());
        let template = crate::Template {
            algorithms: crate::Algorithms {
                signature: algorithm,
                signature_uri,
                digest: algorithm.hash_alg(),
                digest_uri,
            },
            method: profile.signed_info_c14n,
            uri: &uri,
            transforms: &transforms,
            digest: digest.as_bytes().to_vec(),
            cert: crate::cert_der(signer.certificate())?,
            id: profile.signature_id,
            object: qualifying.map(crate::ObjectTemplate::Qualifying),
            reference_c14n: profile.reference_c14n,
            separator: if profile.strip_whitespace { "" } else { "\n" },
            line_breaks: profile
                .base64_line_breaks
                .unwrap_or(!profile.strip_whitespace),
        };
        let metadata_hash = |rendered: &str,
                             id: Option<&str>,
                             method: C14n,
                             hash_algorithm: oncl_pki::key::HashAlg|
         -> Result<oncl_pki::digest::DigestValue> {
            let xml = wrap(&place.context, rendered)?;
            if xml.len() > profile.max_metadata_bytes {
                return Err(ProcessingError::MetadataLimit.into());
            }
            let doc = crate::parse::parse_signed(xml.as_bytes())?;
            let signature = doc
                .descendants()
                .find(|n| crate::is_ds(*n, "Signature"))
                .ok_or_else(|| invalid("generated signature"))?;
            let target = match id {
                Some(id) => signature
                    .descendants()
                    .find(|n| n.attribute("Id") == Some(id))
                    .ok_or_else(|| invalid("generated properties"))?,
                None => crate::ds_child(signature, "SignedInfo")?,
            };
            let mut canonical = Vec::new();
            let mut config = crate::canonicalizer(method);
            config.limit = profile.max_metadata_bytes;
            config.write_to_profile(target, &mut canonical, profile.canonicalization)?;
            let mut state = oncl_pki::digest::HashState::new(hash_algorithm);
            state.update(&canonical);
            Ok(state.finish())
        };
        let prepared = template.signed(metadata_hash, |digest| {
            scope.checkpoint()?;
            let value = signer.sign_digest(digest).map_err(crate::XmlError::Key)?;
            scope.checkpoint()?;
            Ok::<_, XmlSourceError>(value)
        })?;
        let signature = prepared.xml;
        let signature = if let Some((spec, services)) = ades {
            crate::xades::source::complete_signature(
                &mut document,
                &signature,
                &place.context,
                target,
                method,
                &oncl_pki::evidence::SignerEvidence {
                    certificate: signer.certificate(),
                    algorithm,
                    signed_digest: prepared.digest,
                    signature: &prepared.value,
                    claimed_time: Some(spec.signing_time),
                },
                spec,
                services,
                scope,
                &mut work,
            )?
        } else {
            signature
        };
        if signature.len() > profile.max_metadata_bytes {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let mut count = 0;
        let mut buffer = vec![0; IO_CHUNK_BYTES];
        if let Some(standalone_no) = output_plan.declaration {
            write(
                if standalone_no {
                    b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
                } else {
                    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                },
                output,
                scope,
                &mut count,
            )?;
        }
        copy(
            &mut document,
            Region {
                offset: output_plan.body.offset,
                len: place.at - output_plan.body.offset,
            },
            output,
            scope,
            &mut buffer,
            &mut count,
        )?;
        for bytes in [
            place.open.as_bytes(),
            signature.as_bytes(),
            place.close.as_bytes(),
        ] {
            write(bytes, output, scope, &mut count)?;
        }
        let offset = place.at + place.skip;
        let length = output_plan.body.end()? - offset;
        copy(
            &mut document,
            Region {
                offset,
                len: length,
            },
            output,
            scope,
            &mut buffer,
            &mut count,
        )?;
        scope.checkpoint()?;
        Ok(XmlSignSummary {
            bytes_in: document.len(),
            bytes_out: count,
            algorithm,
        })
    }
}

struct OutputPlan {
    body: Region,
    declaration: Option<bool>,
}
fn output_plan(
    document: &mut XmlDocument,
    form: crate::XmlOutput,
    scope: &ResourceScope,
) -> Result<OutputPlan> {
    let crate::XmlOutput::Serialize {
        declaration,
        standalone_no,
        trim,
    } = form
    else {
        return Ok(OutputPlan {
            body: Region {
                offset: 0,
                len: document.len(),
            },
            declaration: None,
        });
    };
    let _memory = scope.reserve_memory(IO_CHUNK_BYTES as u64)?;
    let mut buffer = vec![0; IO_CHUNK_BYTES];
    let n = document.read_region(
        Region {
            offset: 0,
            len: document.len(),
        },
        &mut buffer,
    )?;
    let mut start = if buffer[..n].starts_with(b"\xef\xbb\xbf") {
        3
    } else {
        0
    };
    if buffer[..n]
        .get(start..)
        .is_some_and(|s| s.starts_with(b"<?xml"))
    {
        let mut at = start as u64;
        let mut question = false;
        'declaration: loop {
            let n = document.read_region(
                Region {
                    offset: at,
                    len: document.len() - at,
                },
                &mut buffer,
            )?;
            if n == 0 {
                return Err(invalid("XML declaration extent"));
            }
            for (i, b) in buffer[..n].iter().copied().enumerate() {
                if question && b == b'>' {
                    start = usize::try_from(at + i as u64 + 1)
                        .map_err(|_| ProcessingError::InputLimit)?;
                    break 'declaration;
                }
                question = b == b'?';
            }
            at += n as u64;
        }
    }
    let mut start = start as u64;
    'leading: while start < document.len() {
        let n = document.read_region(
            Region {
                offset: start,
                len: document.len() - start,
            },
            &mut buffer,
        )?;
        if n == 0 {
            return Err(invalid("XML output extent"));
        }
        for (i, b) in buffer[..n].iter().copied().enumerate() {
            if !b.is_ascii_whitespace() {
                start += i as u64;
                break 'leading;
            }
        }
        start += n as u64;
    }
    let mut end = document.len();
    if trim {
        while end > start {
            let at = end.saturating_sub(IO_CHUNK_BYTES as u64).max(start);
            let n = document.read_region(
                Region {
                    offset: at,
                    len: end - at,
                },
                &mut buffer,
            )?;
            if let Some(i) = buffer[..n].iter().rposition(|b| *b > b' ') {
                end = at + i as u64 + 1;
                break;
            }
            end = at;
        }
    }
    Ok(OutputPlan {
        body: Region {
            offset: start,
            len: end - start,
        },
        declaration: declaration.then_some(standalone_no),
    })
}
fn percent_id(id: &str) -> String {
    let mut text = String::new();
    for b in id.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            text.push(b as char)
        } else {
            text.push_str(&format!("%{b:02X}"))
        }
    }
    text
}
fn write(
    bytes: &[u8],
    output: &mut dyn SignatureOutput,
    scope: &ResourceScope,
    count: &mut u64,
) -> Result<()> {
    for part in bytes.chunks(IO_CHUNK_BYTES) {
        scope.checkpoint()?;
        output.write_chunk(part, scope)?;
        *count = count
            .checked_add(part.len() as u64)
            .ok_or(ProcessingError::OutputLimit)?;
    }
    Ok(())
}
fn copy(
    document: &mut XmlDocument,
    mut region: Region,
    output: &mut dyn SignatureOutput,
    scope: &ResourceScope,
    buffer: &mut [u8],
    count: &mut u64,
) -> Result<()> {
    while region.len != 0 {
        let n = document.read_region(region, buffer)?;
        if n == 0 {
            return Err(invalid("short frozen XML"));
        }
        write(&buffer[..n], output, scope, count)?;
        region.offset += n as u64;
        region.len -= n as u64;
    }
    Ok(())
}
/// The `ds:Object` of a signature to write.
pub(super) enum ObjectTemplate<'t> {
    /// A signing-time object.
    SigningTime {
        object: SigningTimeObject<'t>,
        /// The signature's parent has a default namespace: `<timestamp>` resets it.
        reset_default_namespace: bool,
    },
    /// XAdES qualifying properties.
    Qualifying(QualifyingObject<'t>),
}

impl ObjectTemplate<'_> {
    /// The `Id`, `Type`, transforms and canonicalization of the second reference, if the
    /// object has one.
    fn reference<'s>(
        &'s self,
        template: &'s Template<'_>,
    ) -> Option<(&'s str, Option<&'static str>, Vec<&'s str>, C14n)> {
        match self {
            ObjectTemplate::SigningTime { object, .. } => object.target_ref.then(|| {
                (
                    object.property_id,
                    None,
                    template.transforms.to_vec(),
                    template.reference_c14n,
                )
            }),
            ObjectTemplate::Qualifying(q) => Some((
                q.signed_properties_id,
                Some(SIGNED_PROPERTIES_TYPE),
                vec![C14n::Exclusive.uri()],
                C14n::Exclusive,
            )),
        }
    }
}

/// The signature to write.
pub(super) struct Template<'t> {
    pub(super) algorithms: Algorithms<'t>,
    pub(super) method: C14n,
    pub(super) uri: &'t str,
    pub(super) transforms: &'t [&'t str],
    pub(super) digest: Vec<u8>,
    pub(super) cert: Vec<u8>,
    pub(super) id: Option<&'t str>,
    pub(super) object: Option<ObjectTemplate<'t>>,
    /// The canonicalization of the references.
    pub(super) reference_c14n: C14n,
    /// Between the elements: a line break, or nothing.
    pub(super) separator: &'static str,
    /// Base64 in lines.
    pub(super) line_breaks: bool,
}

impl Template<'_> {
    fn base64(&self, bytes: &[u8]) -> String {
        if self.line_breaks {
            base64_lines(bytes)
        } else {
            STANDARD.encode(bytes)
        }
    }

    fn reference(
        &self,
        s: &mut String,
        uri: &str,
        kind: Option<&str>,
        transforms: &[&str],
        digest: &[u8],
    ) {
        let n = self.separator;
        let kind = kind
            .map(|kind| format!(" Type=\"{}\"", escape_attribute(kind)))
            .unwrap_or_default();
        s.push_str(&format!(
            "<ds:Reference URI=\"{}\"{kind}>{n}<ds:Transforms>{n}",
            escape_attribute(uri)
        ));
        for transform in transforms {
            s.push_str(&format!("<ds:Transform Algorithm=\"{transform}\"/>{n}"));
        }
        s.push_str(&format!(
            "</ds:Transforms>{n}<ds:DigestMethod Algorithm=\"{}\"/>{n}\
             <ds:DigestValue>{}</ds:DigestValue>{n}</ds:Reference>{n}",
            escape_attribute(self.algorithms.digest_uri),
            self.base64(digest),
        ));
    }

    /// `ds:Signature` element; without `value` the `SignatureValue` is empty, without
    /// `object_digest` the signing-time object's reference has an empty digest.
    fn render(&self, value: Option<&[u8]>, object_digest: Option<&[u8]>) -> String {
        let n = self.separator;
        let id = self
            .id
            .map(|id| format!(" Id=\"{}\"", escape_attribute(id)))
            .unwrap_or_default();
        let mut s = format!(
            "<ds:Signature xmlns:ds=\"{DSIG_NS}\"{id}>{n}<ds:SignedInfo>{n}\
             <ds:CanonicalizationMethod Algorithm=\"{}\"/>{n}\
             <ds:SignatureMethod Algorithm=\"{}\"/>{n}",
            self.method.uri(),
            escape_attribute(self.algorithms.signature_uri),
        );
        self.reference(&mut s, self.uri, None, self.transforms, &self.digest);
        if let Some((id, kind, transforms, _)) =
            self.object.as_ref().and_then(|o| o.reference(self))
        {
            let uri = format!("#{id}");
            self.reference(
                &mut s,
                &uri,
                kind,
                &transforms,
                object_digest.unwrap_or_default(),
            );
        }
        s.push_str(&format!("</ds:SignedInfo>{n}<ds:SignatureValue>"));
        if let Some(value) = value {
            // Santuario puts a long value on lines of its own.
            let text = self.base64(value);
            if self.line_breaks && text.len() > 76 {
                s.push_str(&format!("\n{text}\n"));
            } else {
                s.push_str(&text);
            }
        }
        let cert = self.base64(&self.cert);
        let cert = if self.line_breaks {
            format!("\n{cert}\n")
        } else {
            cert
        };
        s.push_str(&format!(
            "</ds:SignatureValue>{n}<ds:KeyInfo>{n}<ds:X509Data>{n}<ds:X509Certificate>{cert}\
             </ds:X509Certificate>{n}</ds:X509Data>{n}</ds:KeyInfo>{n}"
        ));
        match &self.object {
            Some(ObjectTemplate::SigningTime {
                object,
                reset_default_namespace,
            }) => {
                let reset = if *reset_default_namespace {
                    " xmlns=\"\""
                } else {
                    ""
                };
                s.push_str(&format!(
                    "<ds:Object>{n}<ds:SignatureProperties>{n}\
                     <ds:SignatureProperty Id=\"{}\" Target=\"#{}\">{n}\
                     <timestamp{reset}>{}</timestamp>{n}</ds:SignatureProperty>{n}\
                     </ds:SignatureProperties>{n}</ds:Object>{n}",
                    escape_attribute(object.property_id),
                    escape_attribute(self.id.unwrap_or_default()),
                    escape_text(object.text),
                ));
            }
            Some(ObjectTemplate::Qualifying(q)) => s.push_str(&format!(
                "<ds:Object>{n}<xades:QualifyingProperties xmlns:xades=\"{XADES_NS}\" \
                 Target=\"#{}\">{n}{}{n}</xades:QualifyingProperties>{n}</ds:Object>{n}",
                escape_attribute(self.id.unwrap_or_default()),
                q.signed_properties,
            )),
            None => {}
        }
        s.push_str("</ds:Signature>");
        s
    }

    /// The signature spliced into `xml` at `point`, parsed: `f` on its element.
    fn in_place<T>(
        &self,
        xml: &[u8],
        point: &SplicePoint,
        rendered: &str,
        scope: Option<&ResourceScope>,
        f: impl FnOnce(Node<'_, '_>) -> Result<T, XmlError>,
    ) -> Result<T, XmlError> {
        let unsigned = point.splice(xml, rendered);
        let doc = parse::parse_admitted(&unsigned, true, scope)?;
        let signature = doc
            .descendants()
            .find(|n| n.is_element() && n.range().start == point.signature_offset())
            .expect("the inserted signature");
        f(signature)
    }

    /// Splices the signature into the parent at `point` as its last child, then fills in the
    /// signing-time object's digest over the object as canonicalized in place, and the value
    /// over the SignedInfo as canonicalized in place.
    pub(super) fn insert(
        &self,
        xml: &[u8],
        point: &SplicePoint,
        backend: &mut BoundedSigner<'_>,
        scope: Option<&ResourceScope>,
    ) -> Result<Vec<u8>, XmlError> {
        let signed = self.signed(
            |rendered, id, method, algorithm| {
                self.in_place(xml, point, rendered, scope, |signature| {
                    let target = match id {
                        Some(id) => signature
                            .descendants()
                            .find(|n| n.is_element() && n.attribute("Id") == Some(id))
                            .expect("the object's signed element"),
                        None => signature.first_element_child().expect("SignedInfo"),
                    };
                    Ok(canonicalizer(method).hash(target, algorithm)?.0)
                })
            },
            |digest| backend.sign_digest(self.algorithms.signature, digest),
        )?;
        Ok(point.splice(xml, &signed.xml))
    }
    /// One metadata/reference builder and private-use sequence for both input
    /// adapters. The bounded adapter supplies explicit Kalkan legacy hashes;
    /// Source supplies original-scope, standard canonical metadata hashes.
    fn signed<E>(
        &self,
        mut hash: impl FnMut(
            &str,
            Option<&str>,
            C14n,
            oncl_pki::key::HashAlg,
        ) -> Result<oncl_pki::digest::DigestValue, E>,
        mut sign: impl FnMut(&oncl_pki::digest::DigestValue) -> Result<Vec<u8>, E>,
    ) -> Result<PreparedSignature, E> {
        let object_digest = self
            .object
            .as_ref()
            .and_then(|o| o.reference(self))
            .map(|(id, _, _, method)| {
                hash(
                    &self.render(None, None),
                    Some(id),
                    method,
                    self.algorithms.digest,
                )
            })
            .transpose()?;
        let signed_digest = hash(
            &self.render(None, object_digest.as_ref().map(|d| d.as_bytes())),
            None,
            self.method,
            self.algorithms.signature.hash_alg(),
        )?;
        let value = sign(&signed_digest)?;
        Ok(PreparedSignature {
            xml: self.render(Some(&value), object_digest.as_ref().map(|d| d.as_bytes())),
            digest: signed_digest,
            value,
        })
    }
}

struct PreparedSignature {
    xml: String,
    digest: oncl_pki::digest::DigestValue,
    value: Vec<u8>,
}

/// Only the old PrivateKey convenience wrappers construct Legacy. Guarded
/// callers retain their actual Core signer/guard and original scope.
pub(super) enum BoundedSigner<'a> {
    Legacy {
        key: &'a PrivateKey,
        cert: &'a oncl_pki::cert::Certificate,
    },
    Guarded {
        signer: &'a mut dyn DigestSigner,
        scope: &'a ResourceScope,
    },
}
impl BoundedSigner<'_> {
    pub(super) fn certificate(&self) -> &oncl_pki::cert::Certificate {
        match self {
            Self::Legacy { cert, .. } => cert,
            Self::Guarded { signer, .. } => signer.certificate(),
        }
    }
    pub(super) fn algorithms<'a>(
        &self,
        spec: &crate::XmlSignSpec<'a>,
    ) -> Result<Algorithms<'a>, XmlError> {
        match self {
            Self::Legacy { key, cert } => Algorithms::of(spec, key, cert),
            Self::Guarded { signer, .. } => {
                let algorithms = Algorithms::of_capabilities(
                    spec,
                    signer.algorithm().key_alg(),
                    signer.certificate(),
                )?;
                if algorithms.signature != signer.algorithm() {
                    return Err(XmlError::Constraint(
                        "the legacy signature algorithm does not fit the actual signer".to_owned(),
                    ));
                }
                Ok(algorithms)
            }
        }
    }
    fn sign_digest(
        &mut self,
        algorithm: SigAlg,
        digest: &oncl_pki::digest::DigestValue,
    ) -> Result<Vec<u8>, XmlError> {
        match self {
            Self::Legacy { key, .. } => key.sign_digest(algorithm, digest).map_err(XmlError::Key),
            Self::Guarded { signer, scope } => {
                use oncl_pki::key::{AppliedState, KeyError, KeyExecutionError};
                scope.checkpoint().map_err(|e| {
                    XmlError::Key(KeyError::Execution(KeyExecutionError::processing(
                        &e,
                        AppliedState::NotApplied,
                    )))
                })?;
                let result = signer.sign_digest(digest);
                let applied = match &result {
                    Ok(_) => AppliedState::Applied,
                    Err(e) => e.applied_state(),
                };
                scope.checkpoint().map_err(|e| {
                    XmlError::Key(KeyError::Execution(KeyExecutionError::processing(
                        &e, applied,
                    )))
                })?;
                result.map_err(XmlError::Key)
            }
        }
    }
}

/// Exact bounded XmlSignSpec compatibility using the real DigestSigner. No
/// temporary-store default, separate quota, raw-key extraction or large DOM.
pub fn sign_spec_source(
    input: Source<'_>,
    spec: &crate::XmlSignSpec<'_>,
    signer: &mut dyn DigestSigner,
    store: &TemporaryStore,
    output: &mut dyn Write,
    scope: &mut ResourceScope,
) -> Result<XmlSignSummary> {
    let algorithm = signer.algorithm();
    input.is_snapshot_for(scope)?;
    if input
        .known_len()
        .is_some_and(|n| n > crate::MAX_INPUT as u64)
        && scope.limits().input_bytes >= crate::MAX_INPUT as u64
    {
        return Err(XmlError::TooLarge.into());
    }
    if let Some(transforms) = &spec.transforms {
        crate::check_transforms(transforms)?;
    }
    let mut frozen =
        oncl_pki::io::FrozenInput::capture_bounded(input, store, scope, crate::MAX_INPUT as u64)?;
    {
        let mut reader = frozen.reader(&[], scope)?;
        if !reader.source().is_snapshot_for(scope)? {
            return Err(ProcessingError::InvalidInput(
                "bounded legacy signing requires original input",
            )
            .into());
        }
    }
    let mut metadata = 0u64;
    for value in spec
        .namespaces
        .iter()
        .flat_map(|(p, u)| [*p, *u])
        .chain(spec.element)
        .chain(spec.parent)
        .chain(spec.other_prefix_uri)
        .chain(spec.signature_id)
        .chain(spec.signature_method)
        .chain(spec.digest_method)
        .chain(
            spec.signing_time_object
                .into_iter()
                .flat_map(|o| [o.property_id, o.text]),
        )
    {
        metadata = metadata
            .checked_add(value.len() as u64)
            .ok_or(ProcessingError::MetadataLimit)?;
    }
    let spec_metadata = scope.reserve_metadata(
        metadata
            .checked_mul(6)
            .and_then(|n| n.checked_add(8192))
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let _memory = scope.reserve_memory(
        frozen
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_add(262144))
            .ok_or(ProcessingError::MemoryLimit)?,
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(frozen.len() as usize)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    bytes.resize(frozen.len() as usize, 0);
    let mut at = 0;
    while at < bytes.len() {
        let n = frozen.read_region(
            Region {
                offset: at as u64,
                len: bytes.len() as u64 - at as u64,
            },
            &mut bytes[at..],
        )?;
        if n == 0 {
            return Err(invalid("bounded snapshot extent"));
        }
        at += n;
    }
    let signed = crate::sign_with_backend(
        &bytes,
        spec,
        &mut BoundedSigner::Guarded { signer, scope },
        None,
        Some(scope),
    )?;
    scope.checkpoint()?;
    let mut written = 0;
    write(&signed, &mut ExternalWriter(output), scope, &mut written)?;
    drop(spec_metadata);
    Ok(XmlSignSummary {
        bytes_in: frozen.len(),
        bytes_out: written,
        algorithm,
    })
}
