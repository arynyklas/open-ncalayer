//! WS-Security over the immutable streaming XML index and shared XMLDSig engine.
//! The SOAP consumer is the unique direct Body of the actual root Envelope.
//! Supported tokens: pinned NCANode full-X509v3 KeyIdentifier, or local X509v3
//! BinarySecurityToken/STR Reference. No network token, Java, XPath or new trust engine.
use crate::{
    C14n, C14nProfile, XmlDocument, XmlEventKind, XmlSignMode, XmlSignSummary, XmlSourceError,
    XmlVerification, XmlVerifyProfile,
    canonical_stream::Options,
    references::{BoundMetadata, attribute_value, metadata},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oncl_pki::{
    io::{Region, Source, StagedArtifact, TemporaryStore, XmlSignatureOutput},
    key::DigestSigner,
    resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope},
    validation::{NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
};
use std::io::Write;
type Result<T, E = XmlSourceError> = std::result::Result<T, E>;
pub const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
pub const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
pub const X509_V3: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
pub const BASE64_BINARY: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SoapVersion {
    #[default]
    Soap11,
    Soap12,
}
impl SoapVersion {
    pub fn namespace(self) -> &'static str {
        match self {
            Self::Soap11 => "http://schemas.xmlsoap.org/soap/envelope/",
            Self::Soap12 => "http://www.w3.org/2003/05/soap-envelope",
        }
    }
    fn role_attribute(self) -> &'static str {
        match self {
            Self::Soap11 => "actor",
            Self::Soap12 => "role",
        }
    }
    fn normalize_role(self, role: &str) -> &str {
        if self == Self::Soap12
            && role == "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"
        {
            ""
        } else {
            role
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenReference {
    /// Actual pinned NCANode compatibility form, not a subject-key-identifier.
    #[default]
    NcanodeX509KeyIdentifier,
    BinarySecurityToken,
}
#[derive(Clone, Debug)]
pub struct WsseTimestamp {
    pub id: String,
    pub created: time::OffsetDateTime,
    pub expires: time::OffsetDateTime,
}
#[derive(Clone, Copy, Debug)]
pub struct TimestampPolicy {
    pub required: bool,
    pub max_lifetime_seconds: u64,
}
impl Default for TimestampPolicy {
    fn default() -> Self {
        Self {
            required: false,
            max_lifetime_seconds: 300,
        }
    }
}
#[derive(Clone, Debug)]
pub struct WsseVerifyProfile {
    pub xml: XmlVerifyProfile,
    pub soap: SoapVersion,
    /// Trusted host processing recipient, not a routing or invocation grant.
    pub role: Option<String>,
    pub timestamp: TimestampPolicy,
    /// Full unique WSU identities of direct application header blocks.
    pub required_headers: Vec<String>,
}
impl Default for WsseVerifyProfile {
    fn default() -> Self {
        Self {
            xml: XmlVerifyProfile::default(),
            soap: SoapVersion::Soap11,
            role: None,
            timestamp: TimestampPolicy::default(),
            required_headers: Vec::new(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct SourceWsseSignProfile {
    pub verification: WsseVerifyProfile,
    pub mode: XmlSignMode,
    /// Used only if the actual direct Body has no ID. Existing WSU identity is retained.
    pub body_id: String,
    pub token_reference: TokenReference,
    pub token_id: String,
    pub timestamp: Option<WsseTimestamp>,
}
impl Default for SourceWsseSignProfile {
    fn default() -> Self {
        Self {
            verification: WsseVerifyProfile::default(),
            mode: XmlSignMode::Create,
            body_id: "oncl-body".into(),
            token_reference: TokenReference::NcanodeX509KeyIdentifier,
            token_id: "oncl-token".into(),
            timestamp: None,
        }
    }
}
impl WsseVerifyProfile {
    /// Admit bounded owned host profile data before a dispatcher clones it.
    pub fn preflight(&self, scope: &ResourceScope) -> Result<ResourceReservation> {
        profile(self)?;
        let bytes = self
            .required_headers
            .iter()
            .try_fold(256u64, |n, id| {
                n.checked_add(id.len() as u64 + std::mem::size_of::<String>() as u64)
            })
            .and_then(|n| n.checked_add(self.role.as_ref().map_or(0, |r| r.len() as u64)))
            .ok_or(ProcessingError::MetadataLimit)?;
        Ok(scope.reserve_metadata(bytes)?)
    }
}
impl SourceWsseSignProfile {
    pub fn preflight(&self, scope: &ResourceScope) -> Result<ResourceReservation> {
        let mut admission = self.verification.preflight(scope)?;
        if self.verification.xml.required_level.is_some() {
            return Err(XmlSourceError::Unsupported(
                "WSSE generation does not create EN baseline properties",
            ));
        }
        let references = 1usize
            .checked_add(self.verification.required_headers.len())
            .and_then(|n| n.checked_add(usize::from(self.timestamp.is_some())))
            .ok_or(ProcessingError::MetadataLimit)?;
        if references > self.verification.xml.max_references {
            return Err(ProcessingError::MetadataLimit.into());
        }
        bounded_id(&self.body_id, &self.verification.xml)?;
        bounded_id(&self.token_id, &self.verification.xml)?;
        if let Some(timestamp) = &self.timestamp {
            bounded_id(&timestamp.id, &self.verification.xml)?;
        }
        admission.grow(
            (self.body_id.len()
                + self.token_id.len()
                + self.timestamp.as_ref().map_or(0, |t| t.id.len())
                + 256) as u64,
        )?;
        minimum_generation_metadata(
            self,
            "",
            self.verification
                .required_headers
                .iter()
                .map(String::as_str)
                .chain(self.timestamp.iter().map(|timestamp| timestamp.id.as_str())),
            scope,
        )?;
        Ok(admission)
    }
}
fn token_metadata(profile: &SourceWsseSignProfile, certificate: &[u8]) -> (String, String) {
    let encoded = STANDARD.encode(certificate);
    match profile.token_reference {
        TokenReference::NcanodeX509KeyIdentifier => (
            String::new(),
            format!(
                "<wsse:SecurityTokenReference xmlns:wsse=\"{WSSE_NS}\"><wsse:KeyIdentifier EncodingType=\"{BASE64_BINARY}\" ValueType=\"{X509_V3}\">{encoded}</wsse:KeyIdentifier></wsse:SecurityTokenReference>"
            ),
        ),
        TokenReference::BinarySecurityToken => (
            format!(
                "<wsse:BinarySecurityToken xmlns:wsse=\"{WSSE_NS}\" xmlns:wsu=\"{WSU_NS}\" wsu:Id=\"{}\" EncodingType=\"{BASE64_BINARY}\" ValueType=\"{X509_V3}\">{encoded}</wsse:BinarySecurityToken>",
                crate::escape_attribute(&profile.token_id)
            ),
            format!(
                "<wsse:SecurityTokenReference xmlns:wsse=\"{WSSE_NS}\"><wsse:Reference URI=\"#{}\" ValueType=\"{X509_V3}\"/></wsse:SecurityTokenReference>",
                crate::escape_attribute(&profile.token_id)
            ),
        ),
    }
}
fn sizing_admission(
    profile: &SourceWsseSignProfile,
    body_id: &str,
    references: usize,
    scope: &ResourceScope,
) -> Result<ResourceReservation> {
    // Reference descriptors borrow IDs; attribute escaping is streamed by the
    // common emitter. Only the small token wrapper still has escaped temporaries:
    // at most 6 UTF-8 output bytes/input byte, String capacity and overlap included.
    let token_id = if profile.token_reference == TokenReference::BinarySecurityToken {
        profile.token_id.len() as u64
    } else {
        0
    };
    let bytes = (references as u64)
        .checked_mul(std::mem::size_of::<(&str, oncl_pki::digest::DigestValue)>() as u64)
        .and_then(|n| n.checked_add(16_384))
        .and_then(|n| {
            token_id
                .checked_mul(6 * 8)
                .and_then(|token| n.checked_add(token))
        })
        .and_then(|n| {
            (body_id.len() as u64)
                .checked_add(1)
                .and_then(|body| body.checked_mul(2))
                .and_then(|body| n.checked_add(body))
        })
        .ok_or(ProcessingError::MetadataLimit)?;
    Ok(scope.reserve_metadata(bytes)?)
}
fn minimum_generation_metadata<'a>(
    profile: &SourceWsseSignProfile,
    body_id: &str,
    ids: impl Iterator<Item = &'a str> + Clone,
    scope: &ResourceScope,
) -> Result<()> {
    let count = ids.clone().count();
    let _sizing = sizing_admission(profile, body_id, count, scope)?;
    // Layout-only lower bound from the SAME signature renderer, not a crypto
    // result or a stand-in certificate. Actual selected DER is checked later.
    let (token, key_info) = token_metadata(profile, &[]);
    let uri = format!("#{body_id}");
    let mut supported = false;
    for algorithm in profile.verification.xml.allowed_signature_algorithms {
        let Some((signature_uri, digest_uri)) = crate::signing_uris(*algorithm) else {
            continue;
        };
        supported = true;
        let digest = oncl_pki::digest::HashState::new(algorithm.hash_alg()).finish();
        let mut references = Vec::with_capacity(count);
        references.extend(ids.clone().map(|id| (id, digest)));
        let template = crate::sign::Template {
            algorithms: crate::Algorithms {
                signature: *algorithm,
                signature_uri,
                digest: algorithm.hash_alg(),
                digest_uri,
            },
            method: C14n::Exclusive,
            uri: &uri,
            transforms: &[C14n::Exclusive.uri()],
            digest: digest.as_bytes().to_vec(),
            cert: Vec::new(),
            id: None,
            object: None,
            reference_c14n: C14n::Exclusive,
            separator: "",
            line_breaks: false,
        };
        let Some(limit) = profile
            .verification
            .xml
            .max_metadata_bytes
            .checked_sub(token.len())
        else {
            continue;
        };
        match template.wsse_metadata_len(
            &crate::sign::WsseTemplate {
                key_info: &key_info,
                references: &references,
            },
            0,
            limit,
        ) {
            Ok(_) => return Ok(()),
            Err(ProcessingError::MetadataLimit) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if !supported {
        return Err(XmlSourceError::AlgorithmDenied);
    }
    Err(ProcessingError::MetadataLimit.into())
}
fn security_open(profile: &WsseVerifyProfile) -> String {
    let soap = profile.soap;
    let ns = soap.namespace();
    let role = profile
        .role
        .as_ref()
        .map(|role| {
            format!(
                " env:{}=\"{}\"",
                soap.role_attribute(),
                crate::escape_attribute(role)
            )
        })
        .unwrap_or_default();
    format!(
        "<wsse:Security xmlns:wsse=\"{WSSE_NS}\" xmlns:env=\"{ns}\" env:mustUnderstand=\"1\"{role}>"
    )
}
fn generation_framing(layout: &Layout, profile: &WsseVerifyProfile) -> Result<()> {
    let mut total = 0u64;
    let mut add = |length: u64| -> Result<()> {
        total = total
            .checked_add(length)
            .ok_or(ProcessingError::MetadataLimit)?;
        if length > profile.xml.max_metadata_bytes as u64
            || total > profile.xml.max_metadata_bytes as u64
        {
            return Err(ProcessingError::MetadataLimit.into());
        }
        Ok(())
    };
    let size = |element: &Element| -> Result<u64> {
        Ok(if let Some(closing) = element.closing {
            element
                .start
                .len
                .checked_add(closing.len)
                .ok_or(ProcessingError::MetadataLimit)?
        } else {
            element
                .start
                .len
                .checked_add(element.qname.len() as u64 + 2)
                .ok_or(ProcessingError::MetadataLimit)?
        })
    };
    let selected = recipient(layout, profile)?;
    for security in &layout.securities {
        if !security.signatures.is_empty()
            || selected.is_some_and(|s| s.element.whole == security.element.whole)
        {
            add(size(&security.element)?)?;
        }
    }
    if selected.is_none() {
        add(security_open(profile).len() as u64 + "</wsse:Security>".len() as u64)?;
    }
    if layout.header_only_security {
        if let Some(header) = &layout.header {
            add(size(header)?)?;
        } else {
            let name_len = layout
                .envelope
                .qname
                .rsplit_once(':')
                .map_or(6, |(prefix, _)| prefix.len() + 7);
            add((name_len as u64)
                .checked_mul(2)
                .and_then(|n| n.checked_add(5))
                .ok_or(ProcessingError::MetadataLimit)?)?;
        }
    }
    Ok(())
}
fn invalid(s: &'static str) -> XmlSourceError {
    XmlSourceError::Malformed(s)
}
fn bounded_id(id: &str, p: &XmlVerifyProfile) -> Result<()> {
    if id.is_empty()
        || id.len() > p.xml.max_id_bytes
        || id.bytes().any(|b| {
            b.is_ascii_whitespace() || matches!(b, b'#' | b'%' | b'(' | b')' | b'\'' | b'"')
        })
    {
        return Err(invalid(
            "WSSE identity must be an unambiguous bare-name fragment",
        ));
    }
    Ok(())
}
fn profile(p: &WsseVerifyProfile) -> Result<()> {
    p.xml.xml.reservation()?;
    if p.xml.canonicalization != C14nProfile::Standard
        || p.xml.max_signers == 0
        || p.xml.max_signers > 64
        || p.xml.max_references == 0
        || p.xml.max_references > 4096
        || p.xml.max_manifest_depth > 16
        || p.xml.max_metadata_bytes == 0
        || p.xml.max_metadata_bytes > 1048576
        || p.xml.max_work == 0
        || p.required_headers.len() > 128
        || p.timestamp.max_lifetime_seconds == 0
        || p.timestamp.max_lifetime_seconds > 86400
    {
        return Err(ProcessingError::InvalidLimits.into());
    }
    if let Some(limits) = &p.xml.evidence_limits {
        limits.validate()?;
    }
    if p.role
        .as_ref()
        .is_some_and(|r| r.is_empty() || r.len() > p.xml.xml.max_id_bytes || !r.contains(':'))
    {
        return Err(invalid("WSSE host role must be an absolute URI"));
    }
    if p.soap == SoapVersion::Soap12
        && p.role.as_deref() == Some("http://www.w3.org/2003/05/soap-envelope/role/none")
    {
        return Err(invalid("SOAP role/none cannot be a host processing target"));
    }
    for (i, id) in p.required_headers.iter().enumerate() {
        bounded_id(id, &p.xml)?;
        if p.required_headers[..i].contains(id) {
            return Err(invalid("duplicate required header identity"));
        }
    }
    Ok(())
}
struct Element {
    start: Region,
    whole: Region,
    closing: Option<Region>,
    qname: String,
}
struct HeaderPart {
    region: Region,
    id: Option<String>,
}
struct Security {
    element: Element,
    role_span: Option<Region>,
    role: String,
    must_span: Option<Region>,
    signatures: Vec<Region>,
    tokens: Vec<Region>,
    timestamps: Vec<Region>,
}
struct Layout {
    envelope: Element,
    header: Option<Element>,
    body: Element,
    body_id: Option<String>,
    body_prefix: String,
    body_metadata: Vec<Region>,
    securities: Vec<Security>,
    headers: Vec<HeaderPart>,
    header_only_security: bool,
    _metadata: ResourceReservation,
}
fn element_start(event: &crate::XmlEvent) -> Result<Element> {
    Ok(Element {
        start: event.region,
        whole: event.region,
        closing: None,
        qname: event
            .name
            .as_ref()
            .ok_or_else(|| invalid("SOAP element name"))?
            .qname
            .clone(),
    })
}
fn finish_element(element: &mut Element, event: &crate::XmlEvent) {
    element.whole = event.region;
    element.closing = event.closing_tag;
}
fn is_id(a: &crate::XmlAttribute) -> bool {
    (a.name.namespace().is_none() && matches!(a.name.local(), "Id" | "ID" | "id"))
        || a.name.namespace() == Some(WSU_NS) && a.name.local() == "Id"
        || a.name.namespace() == Some("http://www.w3.org/XML/1998/namespace")
            && a.name.local() == "id"
}
fn layout(
    document: &mut XmlDocument,
    p: &XmlVerifyProfile,
    expected: Option<SoapVersion>,
    scope: &ResourceScope,
) -> Result<Layout> {
    document.check_scope(scope)?;
    // All retained rows/names are admitted BEFORE input-dependent pushes.
    let admission = scope.reserve_metadata(
        p.max_signers as u64
            * (p.max_signers as u64 * 48
                + p.xml.max_name_bytes as u64
                + p.xml.max_id_bytes as u64
                + 256)
            + 256 * (p.xml.max_id_bytes as u64 + 64)
            + p.xml.max_name_bytes as u64 * 4
            + 1024,
    )?;
    let mut envelope = None;
    let mut header = None;
    let mut body = None;
    let mut soap = None;
    let mut body_id = None;
    let mut body_prefix = String::from("onclwsu");
    let mut body_metadata = Vec::with_capacity(2);
    let mut securities: Vec<Security> = Vec::with_capacity(p.max_signers);
    let mut headers = Vec::with_capacity(256);
    let mut header_only_security = true;
    let mut current_security = None;
    let mut body_ids = 0;
    let mut body_wsu = false;
    let mut work = p.max_work;
    {
        let mut events = document.events();
        while let Some(event) = events.next_event()? {
            scope.checkpoint()?;
            work = work
                .checked_sub(1)
                .ok_or(ProcessingError::InvalidInput("SOAP geometry work limit"))?;
            if event.kind == XmlEventKind::ProcessingInstruction && !event.xml_declaration {
                return Err(invalid("SOAP processing instruction"));
            }
            if event.kind == XmlEventKind::Start {
                let n = event
                    .name
                    .as_ref()
                    .ok_or_else(|| invalid("SOAP element name"))?;
                if event.depth == 0 {
                    let version = match n.namespace() {
                        Some("http://schemas.xmlsoap.org/soap/envelope/") => SoapVersion::Soap11,
                        Some("http://www.w3.org/2003/05/soap-envelope") => SoapVersion::Soap12,
                        _ => return Err(invalid("SOAP Envelope namespace")),
                    };
                    if n.local() != "Envelope" || expected.is_some_and(|v| v != version) {
                        return Err(invalid("actual root SOAP Envelope"));
                    }
                    soap = Some(version);
                    envelope = Some(element_start(event)?);
                } else if matches!(n.local(), "Envelope" | "Header" | "Body")
                    && matches!(
                        n.namespace(),
                        Some(
                            "http://schemas.xmlsoap.org/soap/envelope/"
                                | "http://www.w3.org/2003/05/soap-envelope"
                        )
                    )
                {
                    if event.depth != 1
                        || n.namespace()
                            != Some(soap.ok_or_else(|| invalid("SOAP root"))?.namespace())
                    {
                        return Err(invalid("nested, wrapped or wrong-namespace SOAP container"));
                    }
                    match n.local() {
                        "Header" if header.is_none() && body.is_none() => {
                            header = Some(element_start(event)?);
                            if !event.attributes.is_empty() || !event.lexical_attributes.is_empty()
                            {
                                header_only_security = false;
                            }
                        }
                        "Body" if body.is_none() => {
                            body = Some(element_start(event)?);
                            let id_attrs: Vec<_> =
                                event.attributes.iter().filter(|a| is_id(a)).collect();
                            body_ids = id_attrs.len();
                            body_wsu = id_attrs
                                .first()
                                .is_some_and(|a| a.name.namespace() == Some(WSU_NS));
                            if body_ids > 1 || body_ids == 1 && !body_wsu {
                                return Err(invalid(
                                    "Body requires exactly one WSU Id, without aliases",
                                ));
                            }
                            if let Some(attr) = id_attrs.first() {
                                body_prefix = attr
                                    .name
                                    .qname
                                    .split_once(':')
                                    .ok_or_else(|| invalid("qualified WSU Id"))?
                                    .0
                                    .to_owned();
                                for (name, region) in &event.lexical_attributes {
                                    if name == &attr.name.qname
                                        || name == &format!("xmlns:{body_prefix}")
                                    {
                                        if region.len > p.max_metadata_bytes as u64 {
                                            return Err(ProcessingError::MetadataLimit.into());
                                        }
                                        body_metadata.push(*region);
                                    }
                                }
                            } else {
                                let mut suffix = 0;
                                while event.namespaces().any(|(prefix, _)| prefix == body_prefix) {
                                    suffix += 1;
                                    body_prefix = format!("onclwsu{suffix}");
                                }
                            }
                        }
                        _ => return Err(invalid("SOAP Header/Body cardinality or order")),
                    }
                } else if event.depth == 1 {
                    return Err(invalid("unexpected direct SOAP Envelope child"));
                }
                if n.namespace() == Some(WSU_NS)
                    && n.local() == "Timestamp"
                    && !(current_security.is_some() && event.depth == 3)
                {
                    return Err(invalid(
                        "recognized Timestamp outside its Security recipient",
                    ));
                }
                if n.namespace() == Some(WSSE_NS)
                    && n.local() == "BinarySecurityToken"
                    && !(current_security.is_some() && event.depth == 3)
                {
                    return Err(invalid(
                        "BinarySecurityToken outside its Security recipient",
                    ));
                }
                if n.namespace() == Some(WSSE_NS) && n.local() == "Security" {
                    if event.depth != 2 || header.is_none() || body.is_some() {
                        return Err(invalid("Security must be a direct actual Header block"));
                    }
                    if securities.len() == p.max_signers {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                    let version = soap.ok_or_else(|| invalid("SOAP root"))?;
                    let mut role_span = None;
                    let mut must_span = None;
                    for a in &event.attributes {
                        if a.name.namespace() == Some(WSU_NS) && a.name.local() == "Id" {
                            continue;
                        }
                        if a.name.namespace() != Some(version.namespace()) {
                            return Err(XmlSourceError::Unsupported("Security attribute"));
                        }
                        match a.name.local() {
                            name if name == version.role_attribute() => role_span = Some(a.value),
                            "mustUnderstand" => must_span = Some(a.value),
                            _ => {
                                return Err(XmlSourceError::Unsupported(
                                    "Security processing attribute",
                                ));
                            }
                        }
                    }
                    current_security = Some(securities.len());
                    securities.push(Security {
                        element: element_start(event)?,
                        role_span,
                        role: String::new(),
                        must_span,
                        signatures: Vec::with_capacity(p.max_signers),
                        tokens: Vec::with_capacity(p.max_signers),
                        timestamps: Vec::with_capacity(1),
                    });
                } else if event.depth == 2 && header.is_some() && body.is_none() {
                    header_only_security = false;
                    if headers.len() == 256 {
                        return Err(ProcessingError::MetadataLimit.into());
                    }
                    if n.namespace().is_none() {
                        return Err(invalid(
                            "SOAP application header must be namespace-qualified",
                        ));
                    }
                    let ids: Vec<_> = event.attributes.iter().filter(|a| is_id(a)).collect();
                    if ids.len() > 1
                        || ids
                            .first()
                            .is_some_and(|a| a.name.namespace() != Some(WSU_NS))
                    {
                        return Err(invalid("header identity aliases"));
                    }
                    headers.push(HeaderPart {
                        region: event.region,
                        id: None,
                    });
                }
                if let Some(i) = current_security
                    && event.depth == 3
                {
                    let allowed = n.namespace() == Some(crate::DSIG_NS) && n.local() == "Signature"
                        || n.namespace() == Some(WSSE_NS) && n.local() == "BinarySecurityToken"
                        || n.namespace() == Some(WSU_NS) && n.local() == "Timestamp";
                    if !allowed {
                        return Err(XmlSourceError::Unsupported(
                            "recognized Security child/proof",
                        ));
                    }
                    if n.namespace() == Some(WSU_NS) && !securities[i].timestamps.is_empty() {
                        return Err(invalid("duplicate Timestamp"));
                    }
                }
            } else if event.kind == XmlEventKind::End {
                let n = event
                    .name
                    .as_ref()
                    .ok_or_else(|| invalid("SOAP element name"))?;
                if n.namespace() == Some(crate::DSIG_NS)
                    && n.local() == "Signature"
                    && !(current_security.is_some() && event.depth == 3)
                {
                    return Err(invalid("recognized Signature outside direct Security"));
                }
                if event.depth == 0 {
                    finish_element(
                        envelope.as_mut().ok_or_else(|| invalid("SOAP root"))?,
                        event,
                    );
                }
                if event.depth == 1 && n.local() == "Header" {
                    finish_element(
                        header.as_mut().ok_or_else(|| invalid("SOAP Header"))?,
                        event,
                    );
                }
                if event.depth == 1 && n.local() == "Body" {
                    finish_element(body.as_mut().ok_or_else(|| invalid("SOAP Body"))?, event);
                    if body_ids == 1 && body_wsu {
                        body_id = event.ids.first().cloned();
                    }
                }
                if let Some(i) = current_security {
                    if event.depth == 3 {
                        let list = match (n.namespace(), n.local()) {
                            (Some(crate::DSIG_NS), "Signature") => &mut securities[i].signatures,
                            (Some(WSSE_NS), "BinarySecurityToken") => &mut securities[i].tokens,
                            (Some(WSU_NS), "Timestamp") => &mut securities[i].timestamps,
                            _ => return Err(invalid("Security child")),
                        };
                        if list.len() == p.max_signers
                            || event.region.len > p.max_metadata_bytes as u64 * 70
                        {
                            return Err(ProcessingError::MetadataLimit.into());
                        }
                        if n.local() != "Signature"
                            && event.region.len > p.max_metadata_bytes as u64
                        {
                            return Err(ProcessingError::MetadataLimit.into());
                        }
                        list.push(event.region);
                    }
                    if event.depth == 2 && n.namespace() == Some(WSSE_NS) && n.local() == "Security"
                    {
                        finish_element(&mut securities[i].element, event);
                        current_security = None;
                    }
                } else if event.depth == 2
                    && let Some(part) = headers.last_mut()
                    && part.region.offset == event.region.offset
                {
                    part.region = event.region;
                    part.id = event.ids.first().cloned();
                }
            } else if event.kind == XmlEventKind::Text
                && (event.depth <= 1 || current_security.is_some() && event.depth == 3)
            {
                let region = event.region;
                if region.len > p.max_metadata_bytes as u64
                    || !crate::references::intake::whitespace(events.reader.file, region, scope)?
                {
                    return Err(invalid("non-layout SOAP/Security content"));
                }
            }
        }
    }
    let version = soap.ok_or_else(|| invalid("SOAP root"))?;
    for i in 0..securities.len() {
        if let Some(span) = securities[i].role_span {
            let role = attribute_value(document, span, p.xml.max_id_bytes)?;
            if role.is_empty() || !role.contains(':') {
                return Err(invalid("Security recipient URI"));
            }
            securities[i].role = version.normalize_role(&role).to_owned();
        }
        if let Some(span) = securities[i].must_span {
            let value = attribute_value(document, span, 5)?;
            if !matches!(value.as_str(), "0" | "1")
                && !(version == SoapVersion::Soap12 && matches!(value.as_str(), "true" | "false"))
            {
                return Err(invalid("SOAP mustUnderstand value"));
            }
        }
        if securities[..i].iter().any(|s| s.role == securities[i].role) {
            return Err(invalid("duplicate Security recipient"));
        }
    }
    Ok(Layout {
        envelope: envelope.ok_or_else(|| invalid("SOAP Envelope"))?,
        header,
        body: body.ok_or_else(|| invalid("missing direct SOAP Body"))?,
        body_id,
        body_prefix,
        body_metadata,
        securities,
        headers,
        header_only_security,
        _metadata: admission,
    })
}
fn recipient<'a>(l: &'a Layout, p: &WsseVerifyProfile) -> Result<Option<&'a Security>> {
    let role = p.soap.normalize_role(p.role.as_deref().unwrap_or(""));
    Ok(l.securities.iter().find(|s| s.role == role))
}
fn bound(
    document: &mut XmlDocument,
    region: Region,
    scope: &ResourceScope,
) -> Result<BoundMetadata> {
    let node = document.indexed_node(region);
    Ok((region, document.node_namespaces(&node, scope)?))
}
fn fragment(document: &mut XmlDocument, b: &BoundMetadata, cap: usize) -> Result<String> {
    metadata(document, b.0, &b.1, cap)
}
fn one_child<'a, 'i>(
    node: roxmltree::Node<'a, 'i>,
    ns: &str,
    name: &str,
) -> Result<roxmltree::Node<'a, 'i>> {
    let mut children = node.children().filter(roxmltree::Node::is_element);
    let child = children
        .next()
        .ok_or_else(|| invalid("missing WSSE token child"))?;
    if children.next().is_some()
        || child.tag_name().namespace() != Some(ns)
        || child.tag_name().name() != name
    {
        return Err(invalid("ambiguous WSSE token metadata"));
    }
    Ok(child)
}
fn attributes(node: roxmltree::Node<'_, '_>, names: &[&str], id: bool) -> Result<()> {
    if node.attributes().any(|a| {
        !(a.namespace().is_none() && names.contains(&a.name())
            || id && a.namespace() == Some(WSU_NS) && a.name() == "Id")
    }) {
        return Err(XmlSourceError::Unsupported("WSSE token attributes"));
    }
    Ok(())
}
fn token_shape(node: roxmltree::Node<'_, '_>) -> Result<()> {
    attributes(
        node,
        &["EncodingType", "ValueType"],
        node.tag_name().name() == "BinarySecurityToken",
    )?;
    if node.attribute("ValueType") != Some(X509_V3)
        || node.attribute("EncodingType") != Some(BASE64_BINARY)
        || node.children().any(|n| !n.is_text())
    {
        return Err(XmlSourceError::Unsupported(
            "X509v3 token type/encoding/content",
        ));
    }
    let certificate = crate::base64_content(node)?;
    oncl_pki::cert::parse(&certificate)
        .map_err(|_| invalid("X509v3 token is not a DER certificate"))?;
    Ok(())
}
/// Resolve ONLY the actual signature's direct STR. A different global/header token
/// can never supply its certificate, and mixed X509Data/STR has no fallback.
pub(crate) fn certificate_binding(
    document: &mut XmlDocument,
    signature: Region,
    key: &BoundMetadata,
    p: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<Option<BoundMetadata>> {
    let _admission = scope.reserve_metadata(
        key.0
            .len
            .checked_mul(64)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let xml = fragment(document, key, p.max_metadata_bytes)?;
    let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("KeyInfo metadata"))?;
    let info = parsed
        .root_element()
        .first_element_child()
        .ok_or_else(|| invalid("KeyInfo"))?;
    if !info
        .children()
        .any(|n| n.is_element() && n.tag_name().namespace() == Some(WSSE_NS))
    {
        return Ok(None);
    }
    attributes(info, &["Id"], false)?;
    let reference = one_child(info, WSSE_NS, "SecurityTokenReference")?;
    attributes(reference, &[], true)?;
    let child = reference
        .children()
        .find(roxmltree::Node::is_element)
        .ok_or_else(|| invalid("empty STR"))?;
    if child.tag_name().namespace() != Some(WSSE_NS)
        || reference
            .children()
            .filter(roxmltree::Node::is_element)
            .count()
            != 1
    {
        return Err(invalid("ambiguous STR"));
    }
    let l = layout(document, p, None, scope)?;
    let security = l
        .securities
        .iter()
        .find(|s| s.signatures.contains(&signature))
        .ok_or_else(|| invalid("STR Signature not directly in Security"))?;
    match child.tag_name().name() {
        "KeyIdentifier" => {
            token_shape(child)?;
            let offset = key.0.offset + (child.range().start - info.range().start) as u64;
            Ok(Some((
                Region {
                    offset,
                    len: child.range().len() as u64,
                },
                key.1.clone(),
            )))
        }
        "Reference" => {
            attributes(child, &["URI", "ValueType"], false)?;
            if child.children().any(|n| n.is_element())
                || child.attribute("ValueType").is_some_and(|v| v != X509_V3)
            {
                return Err(XmlSourceError::Unsupported("STR Reference type/parameters"));
            }
            let id = child
                .attribute("URI")
                .and_then(|s| s.strip_prefix('#'))
                .ok_or_else(|| invalid("local STR token URI required"))?;
            bounded_id(id, p)?;
            let node = document
                .lookup_id(id)?
                .ok_or_else(|| invalid("STR token missing"))?;
            let region = document.node_region(&node)?;
            if !security.tokens.contains(&region) {
                return Err(invalid(
                    "STR token must belong to the same Security recipient",
                ));
            }
            let b = bound(document, region, scope)?;
            let xml = fragment(document, &b, p.max_metadata_bytes)?;
            let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("BST metadata"))?;
            let token = parsed
                .root_element()
                .first_element_child()
                .ok_or_else(|| invalid("BST"))?;
            if token.tag_name().namespace() != Some(WSSE_NS)
                || token.tag_name().name() != "BinarySecurityToken"
                || token.attribute((WSU_NS, "Id")) != Some(id)
            {
                return Err(invalid("STR token identity/type"));
            }
            token_shape(token)?;
            Ok(Some(b))
        }
        _ => Err(XmlSourceError::Unsupported("STR token reference form")),
    }
}

pub struct WsseSignerCoverage {
    signature: Region,
    body: Region,
    security: Region,
    certificate: Region,
    role: String,
    body_digest_matches: bool,
    selected: bool,
    headers: Vec<Region>,
    timestamp: Option<Region>,
}
impl WsseSignerCoverage {
    pub fn signature_region(&self) -> Region {
        self.signature
    }
    pub fn body_region(&self) -> Region {
        self.body
    }
    pub fn security_region(&self) -> Region {
        self.security
    }
    pub fn certificate_region(&self) -> Region {
        self.certificate
    }
    /// Actual SOAP processing metadata, not a claim that the role attribute was signed.
    pub fn processing_role(&self) -> &str {
        &self.role
    }
    pub fn body_digest_matches(&self) -> bool {
        self.body_digest_matches
    }
    pub fn selected_recipient(&self) -> bool {
        self.selected
    }
    pub fn covered_headers(&self) -> &[Region] {
        &self.headers
    }
    pub fn covered_timestamp(&self) -> Option<Region> {
        self.timestamp
    }
}
pub struct WsseVerification {
    pub xml: XmlVerification,
}
impl WsseVerification {
    pub fn signers(&self) -> &[WsseSignerCoverage] {
        self.xml
            .facts
            .wsse
            .as_ref()
            .expect("WSSE-bound report")
            .signers()
    }
    pub fn coverage(&self) -> &WsseCoverageFacts {
        self.xml.facts.wsse.as_ref().expect("WSSE-bound report")
    }
}
pub struct WsseCoverageFacts {
    input: oncl_pki::io::ProvisionalInput,
    layout: Layout,
    signers: Vec<WsseSignerCoverage>,
    _metadata: ResourceReservation,
}
impl std::fmt::Debug for WsseCoverageFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsseCoverageFacts")
            .field("used_body", &self.layout.body.whole)
            .field("signers", &self.signers.len())
            .finish_non_exhaustive()
    }
}
impl WsseCoverageFacts {
    pub fn signers(&self) -> &[WsseSignerCoverage] {
        &self.signers
    }
    pub fn envelope_region(&self) -> Region {
        self.layout.envelope.whole
    }
    pub fn used_body_region(&self) -> Region {
        self.layout.body.whole
    }
    pub fn used_body_id(&self) -> &str {
        self.layout.body_id.as_deref().expect("verified WSU Body")
    }
    /// Borrowed immutable ORIGINAL-scope bytes; no owning body buffer or permit.
    pub fn read_used_body(
        &mut self,
        offset: u64,
        output: &mut [u8],
        scope: &ResourceScope,
    ) -> Result<usize> {
        drop(self.input.reader(&[], scope)?);
        if offset > self.layout.body.whole.len {
            return Err(invalid("Body read offset"));
        }
        Ok(self.input.read_region(
            Region {
                offset: self.layout.body.whole.offset + offset,
                len: self.layout.body.whole.len - offset,
            },
            output,
        )?)
    }
}
fn timestamp(
    document: &mut XmlDocument,
    region: Region,
    p: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<(String, time::OffsetDateTime, time::OffsetDateTime)> {
    let b = bound(document, region, scope)?;
    let xml = fragment(document, &b, p.max_metadata_bytes)?;
    let _parse = scope.reserve_metadata(xml.len() as u64 * 64)?;
    let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("Timestamp metadata"))?;
    let root = parsed
        .root_element()
        .first_element_child()
        .ok_or_else(|| invalid("Timestamp"))?;
    attributes(root, &[], true)?;
    let id = root
        .attribute((WSU_NS, "Id"))
        .ok_or_else(|| invalid("Timestamp WSU Id"))?;
    bounded_id(id, p)?;
    if root.children().any(|node| {
        !node.is_element()
            && (!node.is_text()
                || node
                    .text()
                    .unwrap_or("")
                    .bytes()
                    .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n')))
    }) {
        return Err(invalid("unsupported non-layout Timestamp framing"));
    }
    let mut children = root.children().filter(roxmltree::Node::is_element);
    let created = children.next().ok_or_else(|| invalid("missing Created"))?;
    let expires = children.next().ok_or_else(|| invalid("missing Expires"))?;
    if children.next().is_some()
        || created.tag_name().namespace() != Some(WSU_NS)
        || created.tag_name().name() != "Created"
        || expires.tag_name().namespace() != Some(WSU_NS)
        || expires.tag_name().name() != "Expires"
    {
        return Err(XmlSourceError::Unsupported(
            "Timestamp must contain exactly Created then Expires",
        ));
    }
    let parse_time = |node: roxmltree::Node<'_, '_>| -> Result<time::OffsetDateTime> {
        attributes(node, &[], false)?;
        let mut value = String::with_capacity(64);
        for child in node.children() {
            if !child.is_text() {
                return Err(invalid("unsupported mixed Timestamp value"));
            }
            let text = child.text().ok_or_else(|| invalid("Timestamp value"))?;
            if value.len().checked_add(text.len()).is_none_or(|n| n > 64) {
                return Err(invalid("Timestamp UTC lexical value"));
            }
            value.push_str(text);
        }
        if !value.ends_with('Z') {
            return Err(invalid("Timestamp UTC lexical value"));
        }
        time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)
            .map_err(|_| invalid("Timestamp date"))
    };
    Ok((id.to_owned(), parse_time(created)?, parse_time(expires)?))
}
fn validate_timestamp(
    created: time::OffsetDateTime,
    expires: time::OffsetDateTime,
    now: time::OffsetDateTime,
    p: TimestampPolicy,
) -> Result<()> {
    if expires <= created
        || expires - created > time::Duration::seconds(p.max_lifetime_seconds as i64)
        || created > now
        || expires <= now
    {
        return Err(invalid("Timestamp outside host time/lifetime policy"));
    }
    Ok(())
}
fn strict_references(
    document: &mut XmlDocument,
    signature: &crate::XmlSignerResult,
    p: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<()> {
    let key_region = signature
        .key_info
        .ok_or_else(|| invalid("WSSE requires direct KeyInfo/STR"))?;
    let key = bound(document, key_region, scope)?;
    let certificate = certificate_binding(document, signature.signature, &key, p, scope)?
        .ok_or_else(|| invalid("WSSE requires SecurityTokenReference, not plain X509Data"))?;
    if certificate.0 != signature.certificate {
        return Err(invalid("WSSE selected certificate association changed"));
    }
    let b = bound(document, signature.signed_info, scope)?;
    let xml = fragment(document, &b, p.max_metadata_bytes)?;
    let _parse = scope.reserve_metadata(xml.len() as u64 * 64)?;
    let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("WSSE SignedInfo"))?;
    let info = parsed
        .root_element()
        .first_element_child()
        .ok_or_else(|| invalid("WSSE SignedInfo"))?;
    for node in info.children().filter(roxmltree::Node::is_element) {
        if crate::is_ds(node, "CanonicalizationMethod")
            && (node.attribute("Algorithm") != Some(C14n::Exclusive.uri())
                || node.children().any(|n| n.is_element()))
        {
            return Err(XmlSourceError::Unsupported(
                "WSSE SignedInfo canonicalization",
            ));
        }
        if !crate::is_ds(node, "Reference") {
            continue;
        }
        let id = node
            .attribute("URI")
            .and_then(|s| s.strip_prefix('#'))
            .ok_or_else(|| invalid("WSSE requires direct bare-name References"))?;
        bounded_id(id, p)?;
        if node
            .attribute("Type")
            .is_some_and(|kind| kind != crate::SIGNED_PROPERTIES_TYPE)
        {
            return Err(XmlSourceError::Unsupported(
                "WSSE indirect/unsupported typed Reference",
            ));
        }
        let transforms = node
            .children()
            .find(|n| crate::is_ds(*n, "Transforms"))
            .ok_or_else(|| invalid("WSSE reference transform"))?;
        let transform = one_child(transforms, crate::DSIG_NS, "Transform")?;
        if transform.attribute("Algorithm") != Some(C14n::Exclusive.uri())
            || transform.children().any(|n| n.is_element())
        {
            return Err(XmlSourceError::Unsupported(
                "WSSE reference must cover complete element with exclusive C14N",
            ));
        }
    }
    Ok(())
}
fn verify_document(
    mut document: XmlDocument,
    p: &WsseVerifyProfile,
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    scope: &mut ResourceScope,
    clock: Option<&(dyn Fn() -> time::OffsetDateTime + Send + Sync)>,
) -> Result<WsseVerification> {
    profile(p)?;
    let l = layout(&mut document, &p.xml, Some(p.soap), scope)?;
    let (mut xml, signers, rows) =
        verify_bound(&mut document, (&l, p), store, ctx, network, scope, clock)?;
    xml.facts.wsse = Some(Box::new(WsseCoverageFacts {
        input: document.into_signed()?,
        layout: l,
        signers,
        _metadata: rows,
    }));
    Ok(WsseVerification { xml })
}
fn verify_bound(
    document: &mut XmlDocument,
    binding: (&Layout, &WsseVerifyProfile),
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    scope: &mut ResourceScope,
    clock: Option<&(dyn Fn() -> time::OffsetDateTime + Send + Sync)>,
) -> Result<(
    XmlVerification,
    Vec<WsseSignerCoverage>,
    ResourceReservation,
)> {
    let (l, p) = binding;
    let selected =
        recipient(l, p)?.ok_or_else(|| invalid("missing selected Security recipient"))?;
    if selected.signatures.is_empty() || l.body_id.is_none() {
        return Err(invalid("selected Security must sign actual WSU Body"));
    }
    let rows = scope.reserve_metadata(
        p.xml.max_signers as u64
            * (256 + p.xml.xml.max_id_bytes as u64 + l.headers.len() as u64 * 32)
            + std::mem::size_of::<WsseCoverageFacts>() as u64
            + 64,
    )?;
    let xml = crate::references::verify_document_timed(
        document, &p.xml, store, ctx, network, scope, clock,
    )?;
    let mut signers = Vec::with_capacity(xml.signatures().len());
    let mut selected_count = 0;
    for signer in xml.signatures() {
        let sec = l
            .securities
            .iter()
            .find(|s| s.signatures.contains(&signer.signature))
            .ok_or_else(|| invalid("signature outside actual Security"))?;
        strict_references(document, signer, &p.xml, scope)?;
        let is_selected = sec.element.whole == selected.element.whole;
        let mut body_refs = signer
            .references()
            .iter()
            .filter(|r| r.target == Some(l.body.whole));
        let body_ref = body_refs
            .next()
            .ok_or_else(|| invalid("Signature does not cover actual used Body"))?;
        if body_refs.next().is_some() {
            return Err(invalid("duplicate Body Reference"));
        }
        let mut headers = Vec::with_capacity(l.headers.len());
        for header in &l.headers {
            let mut covered = signer
                .references()
                .iter()
                .filter(|r| r.target == Some(header.region));
            if let Some(reference) = covered.next() {
                if covered.next().is_some() {
                    return Err(invalid("duplicate application header Reference"));
                }
                if reference.digest_matches {
                    headers.push(header.region);
                }
            }
        }
        if is_selected {
            for id in &p.required_headers {
                let region = l
                    .headers
                    .iter()
                    .find(|h| h.id.as_ref() == Some(id))
                    .ok_or_else(|| invalid("required direct header missing"))?
                    .region;
                if !headers.contains(&region) {
                    return Err(invalid("required header not covered by selected signer"));
                }
            }
        }
        if sec.timestamps.len() > 1
            || is_selected && p.timestamp.required && sec.timestamps.is_empty()
        {
            return Err(invalid("required/unique Timestamp"));
        }
        let mut covered_timestamp = None;
        if let Some(region) = sec.timestamps.first().copied() {
            let (_, created, expires) = timestamp(document, region, &p.xml, scope)?;
            let mut references = signer
                .references()
                .iter()
                .filter(|r| r.target == Some(region));
            let reference = references
                .next()
                .ok_or_else(|| invalid("present Timestamp must be signed"))?;
            if references.next().is_some() || !reference.digest_matches {
                return Err(invalid(
                    "present Timestamp must be signed by its Security signer",
                ));
            }
            let now = xml.validation.checked_at;
            validate_timestamp(created, expires, now, p.timestamp)?;
            covered_timestamp = Some(region);
        }
        if is_selected {
            selected_count += 1;
        }
        signers.push(WsseSignerCoverage {
            signature: signer.signature,
            body: l.body.whole,
            security: sec.element.whole,
            certificate: signer.certificate,
            role: sec.role.clone(),
            body_digest_matches: body_ref.digest_matches,
            selected: is_selected,
            headers,
            timestamp: covered_timestamp,
        });
    }
    if selected_count == 0 {
        return Err(invalid("no selected Security signer"));
    }
    Ok((xml, signers, rows))
}
pub fn verify_source(
    input: Source<'_>,
    p: &WsseVerifyProfile,
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    scope: &mut ResourceScope,
) -> Result<WsseVerification> {
    profile(p)?;
    let document = XmlDocument::index_signed(input, &p.xml, store, scope)?;
    verify_document(document, p, store, ctx, network, scope, None)
}
pub fn verify_source_with_clock(
    input: Source<'_>,
    p: &WsseVerifyProfile,
    store: &TemporaryStore,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    clock: &(dyn Fn() -> time::OffsetDateTime + Send + Sync),
    scope: &mut ResourceScope,
) -> Result<WsseVerification> {
    profile(p)?;
    let document = XmlDocument::index_signed(input, &p.xml, store, scope)?;
    verify_document(document, p, store, ctx, network, scope, Some(clock))
}

struct CanonicalPart {
    id: String,
    stage: StagedArtifact,
}
pub struct PreparedWsseSign<'a> {
    document: XmlDocument,
    layout: Layout,
    profile: &'a SourceWsseSignProfile,
    body_id: String,
    body: StagedArtifact,
    additional: Vec<CanonicalPart>,
    timestamp_xml: String,
    work: u64,
    store: TemporaryStore,
    existing: Option<XmlVerification>,
    _metadata: ResourceReservation,
    place: crate::sign::Placement,
}
fn canonical_options(region: Region) -> Options<'static> {
    Options {
        target: Some(region),
        method: C14n::Exclusive,
        profile: C14nProfile::Standard,
        prefixes: &[],
        excluded: &[],
        metadata_limit: None,
    }
}
fn metadata_canonical(xml: &str, p: &XmlVerifyProfile, scope: &ResourceScope) -> Result<Vec<u8>> {
    if xml.len() > p.max_metadata_bytes {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let _admission = scope.reserve_metadata(xml.len() as u64 * 64)?;
    let parsed = roxmltree::Document::parse(xml).map_err(|_| invalid("generated WSSE metadata"))?;
    let mut out = Vec::new();
    let mut c = crate::canonicalizer(C14n::Exclusive);
    c.limit = p.max_metadata_bytes;
    c.write_to_profile(parsed.root_element(), &mut out, C14nProfile::Standard)?;
    Ok(out)
}
pub fn prepare_source<'a>(
    input: Source<'_>,
    p: &'a SourceWsseSignProfile,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
) -> Result<PreparedWsseSign<'a>> {
    let _profile_admission = p.preflight(scope)?;
    let vp = &p.verification.xml;
    bounded_id(&p.body_id, vp)?;
    bounded_id(&p.token_id, vp)?;
    if !vp
        .allowed_signature_algorithms
        .iter()
        .any(|a| crate::signing_uris(*a).is_some())
    {
        return Err(XmlSourceError::AlgorithmDenied);
    }
    if p.verification.timestamp.required && p.timestamp.is_none() {
        return Err(invalid("signing requires explicit host Timestamp"));
    }
    let admission = scope.reserve_metadata(
        vp.max_metadata_bytes as u64
            + (p.verification.required_headers.len() as u64 + 2)
                * (vp.xml.max_id_bytes as u64 + 128),
    )?;
    let mut document = if p.mode == XmlSignMode::Add {
        XmlDocument::index_signed(input, vp, store, scope)?
    } else {
        XmlDocument::index(input, &vp.xml, store, scope)?
    };
    let l = layout(&mut document, vp, Some(p.verification.soap), scope)?;
    if p.mode == XmlSignMode::Create && l.securities.iter().any(|s| !s.signatures.is_empty()) {
        return Err(invalid("WSSE Create cannot replace signatures"));
    }
    if p.mode == XmlSignMode::Add && recipient(&l, &p.verification)?.is_none() {
        return Err(invalid("WSSE Add requires selected Security"));
    }
    if l.securities
        .iter()
        .map(|security| security.signatures.len())
        .sum::<usize>()
        .checked_add(1)
        .is_none_or(|n| n > vp.max_signers)
    {
        return Err(ProcessingError::MetadataLimit.into());
    }
    let parent = recipient(&l, &p.verification)?
        .map(|s| s.element.whole)
        .or_else(|| l.header.as_ref().map(|header| header.whole))
        .unwrap_or(l.envelope.whole);
    let place = crate::sign::placement(&mut document, parent, vp.max_metadata_bytes, scope)?;
    generation_framing(&l, &p.verification)?;
    let body_id = l.body_id.clone().unwrap_or_else(|| p.body_id.clone());
    bounded_id(&body_id, vp)?;
    if l.body_id.is_none() && document.lookup_id(&body_id)?.is_some() {
        return Err(invalid("new Body Id collision"));
    }
    if p.token_reference == TokenReference::BinarySecurityToken
        && document.lookup_id(&p.token_id)?.is_some()
    {
        return Err(invalid("new token Id collision"));
    }
    if recipient(&l, &p.verification)?.is_some_and(|s| !s.timestamps.is_empty())
        && p.timestamp.is_some()
    {
        return Err(invalid(
            "Timestamp already present; Add must preserve its signed claims",
        ));
    }
    let mut work = vp.max_work;
    let mut body = store.stage_source(scope)?;
    document.canonical_append_wsu_id(
        canonical_options(l.body.whole),
        &mut body,
        scope,
        &mut work,
        l.body_id
            .is_none()
            .then_some((l.body_prefix.as_str(), body_id.as_str())),
    )?;
    let mut additional = Vec::with_capacity(p.verification.required_headers.len() + 1);
    for id in &p.verification.required_headers {
        let target = l
            .headers
            .iter()
            .find(|h| h.id.as_ref() == Some(id))
            .ok_or_else(|| invalid("required direct signing header missing"))?
            .region;
        let mut stage = store.stage_source(scope)?;
        document.canonical_append(canonical_options(target), &mut stage, scope, &mut work)?;
        additional.push(CanonicalPart {
            id: id.clone(),
            stage,
        });
    }
    let timestamp_xml = if let Some(ts) = &p.timestamp {
        bounded_id(&ts.id, vp)?;
        if ts.id == body_id
            || p.token_reference == TokenReference::BinarySecurityToken && ts.id == p.token_id
            || document.lookup_id(&ts.id)?.is_some()
        {
            return Err(invalid("new Timestamp Id collision"));
        }
        if ts.expires <= ts.created
            || ts.expires - ts.created
                > time::Duration::seconds(p.verification.timestamp.max_lifetime_seconds as i64)
        {
            return Err(invalid("Timestamp lifetime"));
        }
        let format = time::format_description::well_known::Rfc3339;
        let created = ts
            .created
            .to_offset(time::UtcOffset::UTC)
            .format(&format)
            .map_err(|_| invalid("Timestamp created"))?;
        let expires = ts
            .expires
            .to_offset(time::UtcOffset::UTC)
            .format(&format)
            .map_err(|_| invalid("Timestamp expires"))?;
        let xml = format!(
            "<wsu:Timestamp xmlns:wsu=\"{WSU_NS}\" wsu:Id=\"{}\"><wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires></wsu:Timestamp>",
            crate::escape_attribute(&ts.id)
        );
        let canonical = metadata_canonical(&xml, vp, scope)?;
        let mut stage = store.stage_source(scope)?;
        stage.write_chunk(&canonical)?;
        additional.push(CanonicalPart {
            id: ts.id.clone(),
            stage,
        });
        xml
    } else if let Some(region) = recipient(&l, &p.verification)?
        .and_then(|s| s.timestamps.first())
        .copied()
    {
        let (id, _, _) = timestamp(&mut document, region, vp, scope)?;
        let mut stage = store.stage_source(scope)?;
        document.canonical_append(canonical_options(region), &mut stage, scope, &mut work)?;
        additional.push(CanonicalPart { id, stage });
        String::new()
    } else {
        String::new()
    };
    if additional
        .len()
        .checked_add(1)
        .is_none_or(|n| n > vp.max_references)
    {
        return Err(ProcessingError::MetadataLimit.into());
    }
    minimum_generation_metadata(
        p,
        &body_id,
        additional.iter().map(|part| part.id.as_str()),
        scope,
    )?;
    let hashing = additional
        .iter()
        .try_fold(body.len(), |n, part| n.checked_add(part.stage.len()))
        .ok_or(ProcessingError::InvalidInput(
            "WSSE reference work overflow",
        ))?;
    work.checked_sub(hashing)
        .ok_or(ProcessingError::InvalidInput(
            "WSSE reference hash work limit",
        ))?;
    if p.token_reference == TokenReference::BinarySecurityToken && p.token_id == body_id {
        return Err(invalid("token/Body identity collision"));
    }
    Ok(PreparedWsseSign {
        document,
        layout: l,
        profile: p,
        body_id,
        body,
        additional,
        timestamp_xml,
        work,
        store: store.clone(),
        existing: None,
        place,
        _metadata: admission,
    })
}
impl PreparedWsseSign<'_> {
    pub fn verify_existing(
        &mut self,
        validation: &ValidationContext<'_>,
        network: &NetworkPolicy,
        scope: &mut ResourceScope,
        clock: Option<&(dyn Fn() -> time::OffsetDateTime + Send + Sync)>,
    ) -> Result<()> {
        self.document.check_scope(scope)?;
        self.existing = None;
        let now = clock.map_or(validation.now, |clock| clock());
        if now < validation.now {
            return Err(invalid(
                "host clock moved backwards during WSSE preparation",
            ));
        }
        if let Some(timestamp) = &self.profile.timestamp {
            validate_timestamp(
                timestamp.created,
                timestamp.expires,
                now,
                self.profile.verification.timestamp,
            )?;
        }
        if self.profile.timestamp.is_none()
            && let Some(region) = recipient(&self.layout, &self.profile.verification)?
                .and_then(|security| security.timestamps.first())
                .copied()
        {
            let (_, created, expires) = timestamp(
                &mut self.document,
                region,
                &self.profile.verification.xml,
                scope,
            )?;
            validate_timestamp(created, expires, now, self.profile.verification.timestamp)?;
        }
        if self.profile.mode != XmlSignMode::Add {
            return Ok(());
        }
        let (report, _, _) = verify_bound(
            &mut self.document,
            (&self.layout, &self.profile.verification),
            &self.store,
            validation,
            network,
            scope,
            clock,
        )?;
        if report.validation.verdict == Verdict::Invalid
            || validation.policy == ValidationPolicy::StrictOnline
                && report.validation.verdict != Verdict::Valid
        {
            return Err(invalid(
                "existing WSSE signature/body/token validation failed",
            ));
        }
        let existing_references = report
            .signatures()
            .iter()
            .try_fold(0usize, |n, signer| n.checked_add(signer.references().len()))
            .ok_or(ProcessingError::MetadataLimit)?;
        if existing_references
            .checked_add(self.additional.len() + 1)
            .is_none_or(|n| n > self.profile.verification.xml.max_references)
        {
            return Err(ProcessingError::MetadataLimit.into());
        }
        self.existing = Some(report);
        Ok(())
    }
    fn finish(
        mut self,
        signer: &mut dyn DigestSigner,
        output: &mut dyn crate::sign::SignatureOutput,
        scope: &mut ResourceScope,
    ) -> Result<XmlSignSummary> {
        self.document.check_scope(scope)?;
        if self.profile.mode == XmlSignMode::Add && self.existing.is_none() {
            return Err(invalid(
                "Add requires actual scoped existing-signature validation",
            ));
        }
        let p = &self.profile.verification.xml;
        let algorithm = signer.algorithm();
        if !p.allowed_signature_algorithms.contains(&algorithm) {
            return Err(XmlSourceError::AlgorithmDenied);
        }
        let (signature_uri, digest_uri) =
            crate::signing_uris(algorithm).ok_or(XmlSourceError::AlgorithmDenied)?;
        let _memory = scope.reserve_memory(IO_CHUNK_BYTES as u64)?;
        let _metadata = scope.reserve_metadata(
            p.max_metadata_bytes as u64 * 7
                + self.additional.len() as u64 * (p.xml.max_id_bytes as u64 + 128) * 2,
        )?;
        let digest = crate::xades::source::hash_stage(
            &mut self.body,
            algorithm.hash_alg(),
            scope,
            &mut self.work,
        )?;
        let mut references = Vec::with_capacity(self.additional.len());
        for part in &mut self.additional {
            references.push((
                part.id.as_str(),
                crate::xades::source::hash_stage(
                    &mut part.stage,
                    algorithm.hash_alg(),
                    scope,
                    &mut self.work,
                )?,
            ));
        }
        let cert = crate::cert_der(signer.certificate())?;
        if cert.len() > p.max_metadata_bytes / 4 {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let (token, key_info) = token_metadata(self.profile, &cert);
        let security = recipient(&self.layout, &self.profile.verification)?;
        let place = self.place;
        let uri = format!("#{}", self.body_id);
        let template = crate::sign::Template {
            algorithms: crate::Algorithms {
                signature: algorithm,
                signature_uri,
                digest: algorithm.hash_alg(),
                digest_uri,
            },
            method: C14n::Exclusive,
            uri: &uri,
            transforms: &[C14n::Exclusive.uri()],
            digest: digest.as_bytes().to_vec(),
            // Actual DER is already in STR/BST, not the unused X509Data slot.
            cert: Vec::new(),
            id: None,
            object: None,
            reference_c14n: C14n::Exclusive,
            separator: "",
            line_breaks: false,
        };
        let signature_bound = match algorithm {
            oncl_pki::key::SigAlg::Gost2004 => 64,
            oncl_pki::key::SigAlg::Gost2015_512 => 128,
            oncl_pki::key::SigAlg::RsaSha256 => signer
                .certificate()
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| invalid("RSA public key encoding"))?
                .len(),
            oncl_pki::key::SigAlg::RsaSha1 => return Err(XmlSourceError::AlgorithmDenied),
        };
        let limit = p
            .max_metadata_bytes
            .checked_sub(token.len())
            .and_then(|n| n.checked_sub(self.timestamp_xml.len()))
            .ok_or(ProcessingError::MetadataLimit)?;
        template.wsse_metadata_len(
            &crate::sign::WsseTemplate {
                key_info: &key_info,
                references: &references,
            },
            signature_bound,
            limit,
        )?;
        let prepared = template.signed_with(
            |rendered, _, method, hash| {
                let xml = crate::sign::wrap(&place.context, rendered)?;
                if xml.len() > p.max_metadata_bytes {
                    return Err(ProcessingError::MetadataLimit.into());
                }
                let parsed = roxmltree::Document::parse(&xml)
                    .map_err(|_| invalid("WSSE generated signature"))?;
                let info = parsed
                    .descendants()
                    .find(|n| crate::is_ds(*n, "SignedInfo"))
                    .ok_or_else(|| invalid("generated SignedInfo"))?;
                let mut canonical = Vec::new();
                let mut writer = crate::canonicalizer(method);
                writer.limit = p.max_metadata_bytes;
                writer.write_to_profile(info, &mut canonical, C14nProfile::Standard)?;
                let mut state = oncl_pki::digest::HashState::new(hash);
                state.update(&canonical);
                Ok::<_, XmlSourceError>(state.finish())
            },
            |digest| {
                scope.checkpoint()?;
                let result = signer.sign_digest(digest).map_err(crate::XmlError::Key)?;
                scope.checkpoint()?;
                Ok::<_, XmlSourceError>(result)
            },
            Some(&crate::sign::WsseTemplate {
                key_info: &key_info,
                references: &references,
            }),
            None,
        )?;
        let content = format!("{token}{}{}", self.timestamp_xml, prepared.xml);
        if content.len() > p.max_metadata_bytes {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let mut insertions: Vec<(u64, u64, String)> = Vec::with_capacity(2);
        if security.is_some() {
            insertions.push((
                place.at,
                place.skip,
                format!("{}{content}{}", place.open, place.close),
            ));
        } else {
            let security = format!(
                "{}{content}</wsse:Security>",
                security_open(&self.profile.verification)
            );
            if self.layout.header.is_some() {
                insertions.push((
                    place.at,
                    place.skip,
                    format!("{}{security}{}", place.open, place.close),
                ));
            } else {
                let qname = self.layout.envelope.qname.rsplit_once(':').map_or_else(
                    || String::from("Header"),
                    |(prefix, _)| format!("{prefix}:Header"),
                );
                insertions.push((
                    self.layout.body.start.offset,
                    0,
                    format!("<{qname}>{security}</{qname}>"),
                ));
            }
        }
        if self.layout.body_id.is_none() {
            let mut end = [0; 2];
            self.document.read_region(
                Region {
                    offset: self.layout.body.start.end()? - 2,
                    len: 2,
                },
                &mut end,
            )?;
            let at = self.layout.body.start.end()? - if end == *b"/>" { 2 } else { 1 };
            let prefix = &self.layout.body_prefix;
            insertions.push((
                at,
                0,
                format!(
                    " xmlns:{prefix}=\"{WSU_NS}\" {prefix}:Id=\"{}\"",
                    crate::escape_attribute(&self.body_id)
                ),
            ));
        }
        insertions.sort_by_key(|row| row.0);
        let mut buffer = vec![0; IO_CHUNK_BYTES];
        let mut count = 0;
        let mut at = 0;
        for (offset, skip, xml) in insertions {
            crate::sign::copy(
                &mut self.document,
                Region {
                    offset: at,
                    len: offset
                        .checked_sub(at)
                        .ok_or_else(|| invalid("WSSE insertion order"))?,
                },
                output,
                scope,
                &mut buffer,
                &mut count,
            )?;
            crate::sign::write(xml.as_bytes(), output, scope, &mut count)?;
            at = offset + skip;
        }
        let len = self.document.len();
        crate::sign::copy(
            &mut self.document,
            Region {
                offset: at,
                len: len - at,
            },
            output,
            scope,
            &mut buffer,
            &mut count,
        )?;
        scope.checkpoint()?;
        Ok(XmlSignSummary {
            bytes_in: len,
            bytes_out: count,
            algorithm,
        })
    }
}
pub fn sign_source(
    input: Source<'_>,
    p: &SourceWsseSignProfile,
    signer: &mut dyn DigestSigner,
    store: &TemporaryStore,
    output: &mut dyn Write,
    scope: &mut ResourceScope,
) -> Result<XmlSignSummary> {
    struct External<'a>(&'a mut dyn Write);
    impl crate::sign::SignatureOutput for External<'_> {
        fn write_chunk(&mut self, bytes: &[u8], scope: &ResourceScope) -> Result<()> {
            scope.account_output(bytes.len() as u64)?;
            self.0.write_all(bytes).map_err(ProcessingError::from)?;
            Ok(())
        }
    }
    if p.mode == XmlSignMode::Add {
        return Err(XmlSourceError::Unsupported(
            "Add requires prepared existing-signature validation",
        ));
    }
    let prepared = prepare_source(input, p, store, scope)?;
    if p.timestamp.is_some()
        || recipient(&prepared.layout, &p.verification)?
            .is_some_and(|security| !security.timestamps.is_empty())
    {
        return Err(XmlSourceError::Unsupported(
            "Timestamp-bearing creation requires an explicit trusted validation context",
        ));
    }
    prepared.finish(signer, &mut External(output), scope)
}
pub fn sign_prepared(
    mut prepared: PreparedWsseSign<'_>,
    signer: &mut dyn DigestSigner,
    validation: &ValidationContext<'_>,
    network: &NetworkPolicy,
    clock: Option<&(dyn Fn() -> time::OffsetDateTime + Send + Sync)>,
    output: &mut XmlSignatureOutput<'_>,
    scope: &mut ResourceScope,
) -> Result<(XmlSignSummary, WsseVerification)> {
    prepared.verify_existing(validation, network, scope, clock)?;
    let _profile_admission = prepared.profile.verification.preflight(scope)?;
    let profile = prepared.profile.verification.clone();
    let store = prepared.store.clone();
    let summary = prepared.finish(signer, &mut crate::sign::StageWriter(output), scope)?;
    let checked = match clock {
        Some(clock) => verify_source_with_clock(
            output.source()?,
            &profile,
            &store,
            validation,
            network,
            clock,
            scope,
        )?,
        None => verify_source(
            output.source()?,
            &profile,
            &store,
            validation,
            network,
            scope,
        )?,
    };
    if checked.xml.validation.verdict == Verdict::Invalid
        || validation.policy == ValidationPolicy::StrictOnline
            && checked.xml.validation.verdict != Verdict::Valid
    {
        return Err(invalid("final WSSE validation failed"));
    }
    Ok((summary, checked))
}

/// Exact XML-owned security geometry, not an exemption for arbitrary Header data.
/// Existing signature/proof geometry is independently derived by the shared scanner.
fn framing_push(
    regions: &mut Vec<Region>,
    region: Region,
    total: &mut u64,
    cap: usize,
) -> Result<()> {
    let next = total
        .checked_add(region.len)
        .ok_or(ProcessingError::MetadataLimit)?;
    if region.len > cap as u64 || next > cap as u64 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    geometry_push(regions, region)?;
    *total = next;
    Ok(())
}
fn geometry_push(regions: &mut Vec<Region>, region: Region) -> Result<()> {
    if regions.len() == 4096 {
        return Err(ProcessingError::MetadataLimit.into());
    }
    regions.push(region);
    Ok(())
}
pub(crate) fn metadata_regions(
    document: &mut XmlDocument,
    p: &XmlVerifyProfile,
    scope: &ResourceScope,
) -> Result<(Vec<Region>, ResourceReservation)> {
    // Ordinary XML remains ordinary: don't impose SOAP grammar on other families.
    let has_security = {
        let mut events = document.events();
        let mut soap_root = false;
        let mut found = false;
        while let Some(event) = events.next_event()? {
            if event.kind != XmlEventKind::Start {
                continue;
            }
            let name = event.name.as_ref().ok_or_else(|| invalid("element name"))?;
            if event.depth == 0 {
                soap_root = name.local() == "Envelope"
                    && matches!(
                        name.namespace(),
                        Some(
                            "http://schemas.xmlsoap.org/soap/envelope/"
                                | "http://www.w3.org/2003/05/soap-envelope"
                        )
                    );
                if !soap_root {
                    break;
                }
            } else if event.depth == 1 && name.local() == "Body" {
                break;
            } else if soap_root
                && event.depth == 2
                && name.namespace() == Some(WSSE_NS)
                && name.local() == "Security"
            {
                found = true;
                break;
            }
        }
        found
    };
    let admission = scope.reserve_metadata(if has_security { 4096 * 32 } else { 0 })?;
    if !has_security {
        return Ok((Vec::new(), admission));
    }
    let l = layout(document, p, None, scope)?;
    let mut regions = Vec::with_capacity(4096);
    if !l.securities.iter().any(|s| !s.signatures.is_empty()) {
        return Ok((regions, admission));
    }
    regions.extend_from_slice(&l.body_metadata);
    let mut framing = 0;
    for security in &l.securities {
        if security.signatures.is_empty() {
            continue;
        }
        framing_push(
            &mut regions,
            security.element.start,
            &mut framing,
            p.max_metadata_bytes,
        )?;
        if let Some(closing) = security.element.closing {
            framing_push(&mut regions, closing, &mut framing, p.max_metadata_bytes)?;
        }
        for token in &security.tokens {
            let b = bound(document, *token, scope)?;
            let xml = fragment(document, &b, p.max_metadata_bytes)?;
            let _parse = scope.reserve_metadata(xml.len() as u64 * 64)?;
            let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("BST geometry"))?;
            token_shape(
                parsed
                    .root_element()
                    .first_element_child()
                    .ok_or_else(|| invalid("BST"))?,
            )?;
            geometry_push(&mut regions, *token)?;
        }
        for ts in &security.timestamps {
            timestamp(document, *ts, p, scope)?;
            geometry_push(&mut regions, *ts)?;
        }
    }
    if l.header_only_security
        && let Some(header) = &l.header
    {
        framing_push(
            &mut regions,
            header.start,
            &mut framing,
            p.max_metadata_bytes,
        )?;
        if let Some(closing) = header.closing {
            framing_push(&mut regions, closing, &mut framing, p.max_metadata_bytes)?;
        }
    }
    Ok((regions, admission))
}
