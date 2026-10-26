//! XML signatures (XMLDSig) in the shape Kalkan's `XMLUtil.createXmlSignature` produces, and
//! their verification.
//!
//! - [`sign_enveloped`] signs the whole document: a `ds:Signature` with one `Reference URI=""`
//!   (enveloped-signature, then Canonical XML with comments) becomes the last child of the
//!   document element; SignedInfo is canonicalized with Canonical XML 1.0.
//! - [`sign_element`] signs the element with an `Id` attribute selected by an XPath:
//!   `Reference URI="#<Id>"` with Canonical XML with comments only, SignedInfo canonicalized
//!   with Exclusive XML Canonicalization; the signature goes into the element selected by
//!   the parent XPath, else into the document element.
//!
//! The input bytes are kept: the signature is spliced in before the end tag of its parent
//! (an empty-element tag `<p/>` becomes `<p>…</p>`). The signature layout follows Kalkan's
//! (Apache Santuario's) serialization: a line break after every element and base64 in lines
//! of 76 characters ended by `&#13;`.
//!
//! Signing algorithms follow the signature algorithm of the signer's certificate; sha1RSA
//! certificates are refused. Same-document references (`URI=""`, `URI="#id"`) leave comments
//! out whatever the canonicalization method says, as XMLDSig requires and Santuario does.
//!
//! Input is untrusted: no DOCTYPE (so no entity expansion and nothing fetched), at most
//! [`MAX_INPUT`] bytes and [`MAX_DEPTH`] levels, bounded parse work for attributes and
//! namespace declarations, and at most [`REFERENCE_WORK`] bytes canonicalized by [`verify`].

mod c14n;
mod parse;
mod xpath;

pub use c14n::{C14n, NodeRef, canonicalize};
pub use parse::{MAX_DEPTH, MAX_INPUT};

use crate::cert::{self, Certificate};
use crate::key::{KeyError, PrivateKey, PublicKey, SigAlg};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use c14n::Canonicalizer;
use der::Encode;
use roxmltree::{Document, Node, NodeId};

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Bound on the references of a document times its size, the bytes [`verify`] may
/// canonicalize: a 64 MiB document may carry 16 references, a 1 MiB one 1024.
pub const REFERENCE_WORK: usize = 1 << 30;

/// `(SignatureMethod, DigestMethod)` URIs Kalkan writes for an algorithm.
fn signing_uris(alg: SigAlg) -> Option<(&'static str, &'static str)> {
    match alg {
        SigAlg::Gost2015_512 => Some((
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
            "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
        )),
        SigAlg::Gost2004 => Some((
            "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
            "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        )),
        SigAlg::RsaSha256 => Some((
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        )),
        SigAlg::RsaSha1 => None,
    }
}

/// Algorithm of a `SignatureMethod` URI; legacy RSA-SHA1 is accepted for verification.
fn signature_method(uri: &str) -> Option<SigAlg> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1" => Some(SigAlg::RsaSha1),
        _ => [SigAlg::Gost2015_512, SigAlg::Gost2004, SigAlg::RsaSha256]
            .into_iter()
            .find(|&alg| signing_uris(alg).is_some_and(|(sig, _)| sig == uri)),
    }
}

/// Algorithm whose hash a `DigestMethod` URI names.
fn digest_method(uri: &str) -> Option<SigAlg> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1"
        | "http://www.w3.org/2001/04/xmldsig-more#sha1" => Some(SigAlg::RsaSha1),
        _ => [SigAlg::Gost2015_512, SigAlg::Gost2004, SigAlg::RsaSha256]
            .into_iter()
            .find(|&alg| signing_uris(alg).is_some_and(|(_, digest)| digest == uri)),
    }
}

/// Error of an XML signature operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    /// The input is not well-formed UTF-8 XML, or a signature is malformed.
    #[error("malformed XML: {0}")]
    Parse(String),
    /// The input has a DOCTYPE declaration.
    #[error("DOCTYPE is not allowed in XML")]
    Doctype,
    /// The input is larger than [`MAX_INPUT`], or would take too much work: attributes or
    /// namespace declarations beyond the parse work bounds, or signature references whose
    /// count times the input size exceeds 1 GiB.
    #[error("XML input exceeds the processing limits")]
    TooLarge,
    /// Elements are nested deeper than [`MAX_DEPTH`].
    #[error("XML elements are nested deeper than 256 levels")]
    TooDeep,
    /// The XPath is outside the supported subset.
    #[error("{0}")]
    XPath(String),
    /// The element to sign or the signature parent breaks a signing rule (not found, no
    /// `Id`, signature inside the signed element): Kalkan's `CREATE_XML_SIGNATURE_CONSTRAINT`.
    #[error("{0}")]
    Constraint(String),
    /// An algorithm, transform or reference form is not supported.
    #[error("unsupported XML signature algorithm {0}")]
    UnsupportedAlgorithm(String),
    /// The document has no signature.
    #[error("the XML document has no signature")]
    NoSignature,
    /// A reference digest does not match.
    #[error("XML signature reference digest does not match")]
    BadDigest,
    /// The signature value does not verify.
    #[error("XML signature value does not verify")]
    BadSignature,
    /// The key cannot be used with the algorithm.
    #[error("key: {0}")]
    Key(KeyError),
}

/// One verified signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlSignatureInfo {
    /// Signer certificate from `KeyInfo`.
    pub cert: Certificate,
    /// Signature algorithm.
    pub sig_alg: SigAlg,
}

/// Signs the whole document (enveloped signature, appended to the document element).
///
/// # Errors
///
/// The parsing errors, [`XmlError::UnsupportedAlgorithm`] for a certificate signature
/// algorithm other than GOST 2015-512, GOST 2004 or sha256RSA, [`XmlError::Key`] if the key
/// does not fit that algorithm.
pub fn sign_enveloped(
    xml: &[u8],
    key: &PrivateKey,
    cert: &Certificate,
) -> Result<Vec<u8>, XmlError> {
    let alg = signing_alg(cert)?;
    let doc = parse::parse(xml)?;
    // The new signature is the only node the enveloped transform drops, so the digest is
    // that of the document as it is now; comments are out (`URI=""`).
    let digest = alg.digest(&canonicalizer(C14n::Inclusive).run(doc.root()));
    let template = Template {
        alg,
        method: C14n::Inclusive,
        uri: "",
        transforms: &[ENVELOPED_SIGNATURE, C14n::InclusiveWithComments.uri()],
        digest,
        cert: cert_der(cert)?,
    };
    template.insert(xml, doc.root_element(), key)
}

/// Signs the element selected by `tbs_xpath`, which must have an `Id` attribute; the
/// signature goes into the element selected by `parent_xpath`, else into the document
/// element. Both XPaths are in the supported subset: absolute paths of element names as
/// written in the document, each step optionally `[n]`, `//` for descendants
/// (`/root/body[2]`, `//data`).
///
/// # Errors
///
/// As [`sign_enveloped`], plus [`XmlError::XPath`] for an unsupported XPath and
/// [`XmlError::Constraint`] if an element is not found, the element to sign has no `Id`
/// (Kalkan refuses such elements too) or an `Id` used twice, or the signature would land
/// inside the signed element.
pub fn sign_element(
    xml: &[u8],
    tbs_xpath: &str,
    parent_xpath: Option<&str>,
    key: &PrivateKey,
    cert: &Certificate,
) -> Result<Vec<u8>, XmlError> {
    let alg = signing_alg(cert)?;
    let doc = parse::parse(xml)?;
    let tbs = xpath::select_first(&doc, tbs_xpath)?.ok_or_else(|| {
        XmlError::Constraint(format!("the element {tbs_xpath} to sign is not found"))
    })?;
    let parent = match parent_xpath {
        Some(expr) => xpath::select_first(&doc, expr)?.ok_or_else(|| {
            XmlError::Constraint(format!("the signature parent element {expr} is not found"))
        })?,
        None => doc.root_element(),
    };
    if parent.ancestors().any(|a| a == tbs) {
        return Err(XmlError::Constraint(
            "the signature cannot be placed inside the signed element".to_owned(),
        ));
    }
    let id = tbs
        .attribute("Id")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            XmlError::Constraint("the element to sign has no 'Id' attribute".to_owned())
        })?;
    if element_by_id(&doc, id).ok().flatten() != Some(tbs) {
        return Err(XmlError::Constraint(format!(
            "the Id {id:?} also belongs to another element"
        )));
    }
    let digest = alg.digest(&canonicalizer(C14n::Inclusive).run(tbs));
    let uri = format!("#{id}");
    let template = Template {
        alg,
        method: C14n::Exclusive,
        uri: &uri,
        transforms: &[C14n::InclusiveWithComments.uri()],
        digest,
        cert: cert_der(cert)?,
    };
    template.insert(xml, parent, key)
}

/// Verifies every signature of the document, from the last to the first, each against the
/// certificate in its own `KeyInfo`. Signatures are the `ds:Signature` elements not nested in
/// another one; a signature is checked as if the ones after it were removed, as NCANode does,
/// so signatures appended one after another all verify.
///
/// Returns the signatures in that order (last first).
///
/// # Errors
///
/// The parsing errors, [`XmlError::NoSignature`], [`XmlError::BadSignature`],
/// [`XmlError::BadDigest`], [`XmlError::UnsupportedAlgorithm`], [`XmlError::Key`] if the
/// certificate key does not fit the signature algorithm, [`XmlError::Parse`] for a malformed
/// signature, [`XmlError::TooLarge`] if the references would canonicalize more than
/// [`REFERENCE_WORK`] bytes.
pub fn verify(xml: &[u8]) -> Result<Vec<XmlSignatureInfo>, XmlError> {
    let doc = parse::parse(xml)?;
    let signatures: Vec<Node<'_, '_>> = doc
        .root_element()
        .descendants()
        .filter(|n| is_ds(*n, "Signature") && !n.ancestors().skip(1).any(|a| is_ds(a, "Signature")))
        .collect();
    if signatures.is_empty() {
        return Err(XmlError::NoSignature);
    }
    // Each reference may canonicalize the whole document: bound the total.
    let references: usize = signatures
        .iter()
        .filter_map(|s| ds_child(*s, "SignedInfo").ok())
        .map(|info| info.children().filter(|n| is_ds(*n, "Reference")).count())
        .sum();
    if references.saturating_mul(xml.len()) > REFERENCE_WORK {
        return Err(XmlError::TooLarge);
    }
    let ids: Vec<NodeId> = signatures.iter().map(Node::id).collect();
    (0..signatures.len())
        .rev()
        .map(|i| verify_signature(&doc, signatures[i], &ids[i + 1..]))
        .collect()
}

/// Algorithm for signing with `cert`.
fn signing_alg(cert: &Certificate) -> Result<SigAlg, XmlError> {
    let oid = cert.signature_algorithm().oid;
    SigAlg::from_signature_oid(&oid)
        .filter(|&alg| signing_uris(alg).is_some())
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(oid.to_string()))
}

fn cert_der(cert: &Certificate) -> Result<Vec<u8>, XmlError> {
    cert.to_der()
        .map_err(|e| XmlError::Parse(format!("signer certificate: {e}")))
}

/// Canonicalizer for signing: no comments, no subtree left out.
fn canonicalizer(method: C14n) -> Canonicalizer<'static> {
    Canonicalizer {
        exclusive: method.is_exclusive(),
        comments: false,
        inclusive_prefixes: &[],
        excluded: &[],
    }
}

/// The signature to write.
struct Template<'t> {
    alg: SigAlg,
    method: C14n,
    uri: &'t str,
    transforms: &'t [&'t str],
    digest: Vec<u8>,
    cert: Vec<u8>,
}

impl Template<'_> {
    /// `ds:Signature` element; without `value` the `SignatureValue` is empty.
    fn render(&self, value: Option<&[u8]>) -> String {
        let (signature_uri, digest_uri) = signing_uris(self.alg).expect("signing algorithm");
        let mut s = format!(
            "<ds:Signature xmlns:ds=\"{DSIG_NS}\">\n<ds:SignedInfo>\n\
             <ds:CanonicalizationMethod Algorithm=\"{}\"/>\n\
             <ds:SignatureMethod Algorithm=\"{signature_uri}\"/>\n\
             <ds:Reference URI=\"{}\">\n<ds:Transforms>\n",
            self.method.uri(),
            escape_attribute(self.uri),
        );
        for transform in self.transforms {
            s.push_str(&format!("<ds:Transform Algorithm=\"{transform}\"/>\n"));
        }
        s.push_str(&format!(
            "</ds:Transforms>\n<ds:DigestMethod Algorithm=\"{digest_uri}\"/>\n\
             <ds:DigestValue>{}</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n\
             <ds:SignatureValue>",
            base64_lines(&self.digest),
        ));
        if let Some(value) = value {
            // Santuario puts a long value on lines of its own.
            let text = base64_lines(value);
            if STANDARD.encode(value).len() > 76 {
                s.push_str(&format!("\n{text}\n"));
            } else {
                s.push_str(&text);
            }
        }
        s.push_str(&format!(
            "</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>\n{}\n\
             </ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature>",
            base64_lines(&self.cert),
        ));
        s
    }

    /// Splices the signature into `parent` (an element of the parse of `xml`) as its last
    /// child, then fills in the value over the SignedInfo as canonicalized in place.
    fn insert(
        &self,
        xml: &[u8],
        parent: Node<'_, '_>,
        key: &PrivateKey,
    ) -> Result<Vec<u8>, XmlError> {
        let range = parent.range();
        let (head, tail): (Vec<u8>, Vec<u8>) = if xml[..range.end].ends_with(b"/>") {
            let mut head = xml[..range.end - 2].to_vec();
            head.push(b'>');
            let mut tail = format!("</{}>", parse::element_qname(parent)).into_bytes();
            tail.extend_from_slice(&xml[range.end..]);
            (head, tail)
        } else {
            let end_tag = xml[range.clone()]
                .windows(2)
                .rposition(|w| w == b"</")
                .map(|p| range.start + p)
                .ok_or_else(|| XmlError::Parse("element without an end tag".to_owned()))?;
            (xml[..end_tag].to_vec(), xml[end_tag..].to_vec())
        };
        let splice =
            |signature: &str| [head.as_slice(), signature.as_bytes(), tail.as_slice()].concat();

        let unsigned = splice(&self.render(None));
        let doc = parse::parse_unbounded(&unsigned)?;
        let signature = doc
            .descendants()
            .find(|n| n.is_element() && n.range().start == head.len())
            .expect("the inserted signature");
        let signed_info = signature.first_element_child().expect("SignedInfo");
        let tbs = canonicalizer(self.method).run(signed_info);
        let value = key.sign(self.alg, &tbs).map_err(XmlError::Key)?;
        Ok(splice(&self.render(Some(&value))))
    }
}

fn verify_signature(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    later: &[NodeId],
) -> Result<XmlSignatureInfo, XmlError> {
    let signed_info = ds_child(signature, "SignedInfo")?;
    let method_element = ds_child(signed_info, "CanonicalizationMethod")?;
    let method_uri = algorithm(method_element)?;
    let method = C14n::from_uri(method_uri)
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(method_uri.to_owned()))?;
    let sig_uri = algorithm(ds_child(signed_info, "SignatureMethod")?)?;
    let alg = signature_method(sig_uri)
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(sig_uri.to_owned()))?;
    let value = base64_content(ds_child(signature, "SignatureValue")?)?;

    let certificate = ds_child(signature, "KeyInfo")?
        .children()
        .filter(|n| is_ds(*n, "X509Data"))
        .flat_map(|data| data.children().filter(|n| is_ds(*n, "X509Certificate")))
        .next()
        .ok_or_else(|| malformed("no KeyInfo/X509Data/X509Certificate"))?;
    let cert = cert::parse(&base64_content(certificate)?)
        .map_err(|e| XmlError::Parse(format!("signer certificate: {e}")))?;
    let public = PublicKey::from_spki(cert.tbs_certificate().subject_public_key_info())
        .map_err(XmlError::Key)?;

    let prefixes = inclusive_prefixes(method_element);
    let tbs = Canonicalizer {
        exclusive: method.is_exclusive(),
        comments: method.with_comments(),
        inclusive_prefixes: &prefixes,
        excluded: &[],
    }
    .run(signed_info);
    public.verify(alg, &tbs, &value).map_err(|e| match e {
        KeyError::BadSignature => XmlError::BadSignature,
        e => XmlError::Key(e),
    })?;

    let mut references = signed_info
        .children()
        .filter(|n| is_ds(*n, "Reference"))
        .peekable();
    if references.peek().is_none() {
        return Err(malformed("SignedInfo has no Reference"));
    }
    for reference in references {
        verify_reference(doc, signature, reference, later)?;
    }
    Ok(XmlSignatureInfo { cert, sig_alg: alg })
}

fn verify_reference(
    doc: &Document<'_>,
    signature: Node<'_, '_>,
    reference: Node<'_, '_>,
    later: &[NodeId],
) -> Result<(), XmlError> {
    let uri = reference
        .attribute("URI")
        .ok_or_else(|| XmlError::UnsupportedAlgorithm("Reference without URI".to_owned()))?;
    let target = match uri.strip_prefix('#') {
        None if uri.is_empty() => doc.root(),
        Some(id) if !id.starts_with("xpointer(") => element_by_id(doc, id)?
            .ok_or_else(|| malformed(&format!("no element with Id {id:?}")))?,
        _ => {
            return Err(XmlError::UnsupportedAlgorithm(format!(
                "Reference URI {uri:?}"
            )));
        }
    };

    let mut enveloped = false;
    let mut method = None;
    if let Ok(transforms) = ds_child(reference, "Transforms") {
        for transform in transforms.children().filter(|n| is_ds(*n, "Transform")) {
            let uri = algorithm(transform)?;
            match (method, C14n::from_uri(uri)) {
                (None, _) if uri == ENVELOPED_SIGNATURE => enveloped = true,
                (None, Some(m)) => method = Some((m, transform)),
                _ => return Err(XmlError::UnsupportedAlgorithm(uri.to_owned())),
            }
        }
    }
    let (method, prefixes) = match method {
        Some((m, transform)) => (m, inclusive_prefixes(transform)),
        None => (C14n::Inclusive, Vec::new()),
    };
    // In document order: the signature itself comes before the later ones.
    let excluded: Vec<NodeId> = enveloped
        .then_some(signature.id())
        .into_iter()
        .chain(later.iter().copied())
        .collect();
    let data = Canonicalizer {
        exclusive: method.is_exclusive(),
        // Same-document references drop comments.
        comments: false,
        inclusive_prefixes: &prefixes,
        excluded: &excluded,
    }
    .run(target);

    let digest_uri = algorithm(ds_child(reference, "DigestMethod")?)?;
    let digest_alg = digest_method(digest_uri)
        .ok_or_else(|| XmlError::UnsupportedAlgorithm(digest_uri.to_owned()))?;
    if digest_alg.digest(&data) != base64_content(ds_child(reference, "DigestValue")?)? {
        return Err(XmlError::BadDigest);
    }
    Ok(())
}

fn malformed(what: &str) -> XmlError {
    XmlError::Parse(format!("malformed XML signature: {what}"))
}

fn is_ds(node: Node<'_, '_>, local: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(DSIG_NS)
        && node.tag_name().name() == local
}

fn ds_child<'a, 'i>(node: Node<'a, 'i>, local: &str) -> Result<Node<'a, 'i>, XmlError> {
    node.children()
        .find(|n| is_ds(*n, local))
        .ok_or_else(|| malformed(&format!("no ds:{local}")))
}

fn algorithm<'a>(node: Node<'a, '_>) -> Result<&'a str, XmlError> {
    node.attribute("Algorithm")
        .ok_or_else(|| malformed(&format!("{} without Algorithm", node.tag_name().name())))
}

/// `InclusiveNamespaces PrefixList` of an exclusive canonicalization element, sorted;
/// `#default` becomes `""`.
fn inclusive_prefixes<'a>(method: Node<'a, '_>) -> Vec<&'a str> {
    let mut prefixes: Vec<&str> = method
        .children()
        .find(|n| {
            n.tag_name().namespace() == Some(EXC_C14N_NS)
                && n.tag_name().name() == "InclusiveNamespaces"
        })
        .and_then(|n| n.attribute("PrefixList"))
        .map(|list| {
            list.split_ascii_whitespace()
                .map(|p| if p == "#default" { "" } else { p })
                .collect()
        })
        .unwrap_or_default();
    prefixes.sort_unstable();
    prefixes.dedup();
    prefixes
}

/// The element whose `Id`, `ID` or `id` attribute is `id`; an `Id` on two elements is an
/// error (a signature wrapping attack, or an ambiguous reference).
fn element_by_id<'a, 'i>(
    doc: &'a Document<'i>,
    id: &str,
) -> Result<Option<Node<'a, 'i>>, XmlError> {
    let mut found = doc.descendants().filter(|n| {
        n.is_element()
            && ["Id", "ID", "id"]
                .iter()
                .any(|name| n.attribute(*name) == Some(id))
    });
    let first = found.next();
    if found.next().is_some() {
        return Err(malformed(&format!("Id {id:?} is not unique")));
    }
    Ok(first)
}

/// Base64 content of an element, XML whitespace ignored.
fn base64_content(node: Node<'_, '_>) -> Result<Vec<u8>, XmlError> {
    let text: Vec<u8> = node
        .descendants()
        .filter(Node::is_text)
        .flat_map(|t| t.text().unwrap_or("").bytes())
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    STANDARD
        .decode(text)
        .map_err(|e| malformed(&format!("bad base64 in {}: {e}", node.tag_name().name())))
}

/// Base64 in lines of 76 characters, each line break written as Santuario's serializer
/// writes the MIME `\r\n`: `&#13;` and a line feed.
fn base64_lines(bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("&#13;\n")
}

fn escape_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
}
