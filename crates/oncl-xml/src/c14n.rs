//! Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 of a whole document or of one
//! element's subtree, optionally leaving out some element subtrees.
//!
//! The data model is the parsed document without a DTD: attribute values are normalized as
//! CDATA, the only entities are the predefined ones, line ends are already `#xA`.

use super::XmlError;
use super::parse::{self, element_qname};
use crate::{
    C14nProfile,
    canonical_writer::{Attribute, CanonicalWriter},
};
use roxmltree::{Document, Node, NodeId, NodeType};

/// Canonicalization method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum C14n {
    /// Canonical XML 1.0, comments omitted.
    Inclusive,
    /// Canonical XML 1.0 with comments.
    InclusiveWithComments,
    /// Exclusive XML Canonicalization 1.0, comments omitted.
    Exclusive,
    /// Exclusive XML Canonicalization 1.0 with comments.
    ExclusiveWithComments,
}

impl C14n {
    const ALL: [C14n; 4] = [
        C14n::Inclusive,
        C14n::InclusiveWithComments,
        C14n::Exclusive,
        C14n::ExclusiveWithComments,
    ];

    /// Algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            C14n::Inclusive => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            C14n::InclusiveWithComments => {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
            }
            C14n::Exclusive => "http://www.w3.org/2001/10/xml-exc-c14n#",
            C14n::ExclusiveWithComments => "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        }
    }

    /// Method of an algorithm URI.
    pub fn from_uri(uri: &str) -> Option<C14n> {
        C14n::ALL.into_iter().find(|m| m.uri() == uri)
    }

    /// Whether comments are kept.
    pub const fn with_comments(self) -> bool {
        matches!(
            self,
            C14n::InclusiveWithComments | C14n::ExclusiveWithComments
        )
    }

    /// Whether this is exclusive canonicalization.
    pub const fn is_exclusive(self) -> bool {
        matches!(self, C14n::Exclusive | C14n::ExclusiveWithComments)
    }
}

/// An element of a document, identified by the byte offset of the `<` of its start tag in
/// the input (a UTF-8 BOM, if any, counts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeRef(usize);

impl NodeRef {
    /// The element whose start tag begins at byte `offset`.
    pub const fn element_at(offset: usize) -> NodeRef {
        NodeRef(offset)
    }

    /// Byte offset of the element's start tag.
    pub const fn offset(self) -> usize {
        self.0
    }

    fn resolve<'a, 'i>(self, doc: &'a Document<'i>) -> Result<Node<'a, 'i>, XmlError> {
        doc.descendants()
            .find(|n| n.is_element() && n.range().start == self.0)
            .ok_or_else(|| XmlError::Parse(format!("no element starts at byte {}", self.0)))
    }
}

/// Canonicalizes a whole document with `method`, leaving out the subtree of
/// `exclude_subtree` (as the enveloped-signature transform does with its signature).
///
/// # Errors
///
/// The parsing errors of this module, [`XmlError::Parse`] if `exclude_subtree` does not
/// point at an element, [`XmlError::TooLarge`] if the canonical form would exceed
/// [`MAX_CANONICAL`] bytes.
pub fn canonicalize(
    xml: &[u8],
    method: C14n,
    exclude_subtree: Option<NodeRef>,
) -> Result<Vec<u8>, XmlError> {
    let doc = parse::parse(xml)?;
    let excluded = match exclude_subtree {
        Some(node) => vec![node.resolve(&doc)?.id()],
        None => Vec::new(),
    };
    Canonicalizer {
        exclusive: method.is_exclusive(),
        comments: method.with_comments(),
        inclusive_prefixes: &[],
        excluded: &excluded,
        limit: MAX_CANONICAL,
    }
    .run(doc.root())
}

/// Largest canonical form produced, in bytes. Escaping and the namespace declarations
/// exclusive canonicalization repeats on every element using them can make the canonical
/// form much larger than its input.
pub const MAX_CANONICAL: usize = 2 * parse::MAX_INPUT;

/// One canonicalization.
pub(crate) struct Canonicalizer<'s> {
    /// Exclusive rather than inclusive namespace rendering.
    pub exclusive: bool,
    /// Whether comments are output.
    pub comments: bool,
    /// Exclusive only: the `InclusiveNamespaces PrefixList`, sorted, `""` for `#default`.
    pub inclusive_prefixes: &'s [&'s str],
    /// Elements left out with their subtrees, in document order.
    pub excluded: &'s [NodeId],
    /// Largest output, in bytes.
    pub limit: usize,
}

impl Canonicalizer<'_> {
    /// The bounded DOM is an input adapter for the same canonical writer used
    /// by indexed sources; it never implements a second namespace renderer.
    pub(crate) fn run(&self, node: Node<'_, '_>) -> Result<Vec<u8>, XmlError> {
        let mut bytes = Vec::new();
        self.write_to(node, &mut bytes)?;
        Ok(bytes)
    }
    pub(crate) fn hash(
        &self,
        node: Node<'_, '_>,
        algorithm: oncl_pki::key::HashAlg,
    ) -> Result<(oncl_pki::digest::DigestValue, usize), XmlError> {
        struct Sink(oncl_pki::digest::HashState);
        impl std::io::Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Sink(oncl_pki::digest::HashState::new(algorithm));
        let count = self.write_to(node, &mut sink)?;
        Ok((sink.0.finish(), count))
    }
    fn write_to(
        &self,
        node: Node<'_, '_>,
        sink: &mut dyn std::io::Write,
    ) -> Result<usize, XmlError> {
        self.write_to_profile(node, sink, C14nProfile::KalkanLegacy)
    }
    pub(crate) fn write_to_profile(
        &self,
        node: Node<'_, '_>,
        sink: &mut dyn std::io::Write,
        profile: C14nProfile,
    ) -> Result<usize, XmlError> {
        fn visit<'a, 'i: 'a>(
            config: &Canonicalizer<'_>,
            out: &mut CanonicalWriter<'_, &'a str>,
            node: Node<'a, 'i>,
            target: std::ops::Range<usize>,
            excluded: bool,
        ) -> Result<(), oncl_pki::resource::ProcessingError> {
            let excluded = excluded
                || (node.is_element()
                    && target.contains(&node.range().start)
                    && config
                        .excluded
                        .binary_search_by_key(&node.id().get(), |id| id.get())
                        .is_ok());
            let selected = !excluded && target.contains(&node.range().start);
            match node.node_type() {
                NodeType::Root => {
                    let mut after = false;
                    for child in node.children() {
                        let outside = matches!(child.node_type(), NodeType::Comment | NodeType::PI)
                            && selected
                            && target.contains(&child.range().start)
                            && (child.is_pi() || out.comments());
                        if outside && after {
                            out.put(b"\n")?;
                        }
                        visit(config, out, child, target.clone(), excluded)?;
                        if outside && !after {
                            out.put(b"\n")?;
                        }
                        if child.is_element() {
                            after = true;
                        }
                    }
                }
                NodeType::Element => {
                    if excluded || (!selected && !node.range().contains(&target.start)) {
                        return Ok(());
                    }
                    let src = node.document().input_text();
                    let attributes = node
                        .attributes()
                        .map(|a| Attribute {
                            namespace: a.namespace().unwrap_or("").to_owned(),
                            local: a.name().to_owned(),
                            qname: src[a.range_qname()].to_owned(),
                            value: a.value(),
                        })
                        .collect();
                    let apex = selected && !out.selected();
                    let declarations = if !apex && !config.exclusive {
                        parse::declared_prefixes(node)
                    } else {
                        Vec::new()
                    };
                    let mut namespaces: Vec<(String, String)> = if config.exclusive {
                        let mut visible = vec![(
                            parse::prefix(element_qname(node)).to_owned(),
                            node.tag_name().namespace().unwrap_or("").to_owned(),
                        )];
                        for a in node.attributes() {
                            let prefix = parse::prefix(&src[a.range_qname()]);
                            if !prefix.is_empty() && prefix != "xml" {
                                visible.push((
                                    prefix.to_owned(),
                                    a.namespace().unwrap_or("").to_owned(),
                                ));
                            }
                        }
                        for prefix in config.inclusive_prefixes {
                            if let Some(uri) =
                                node.lookup_namespace_uri((!prefix.is_empty()).then_some(*prefix))
                            {
                                visible.push(((*prefix).to_owned(), uri.to_owned()));
                            }
                        }
                        visible
                    } else if apex || !declarations.is_empty() {
                        node.namespaces()
                            .filter(|ns| apex || declarations.contains(&ns.name().unwrap_or("")))
                            .map(|ns| (ns.name().unwrap_or("").to_owned(), ns.uri().to_owned()))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    if parse::prefix(element_qname(node)).is_empty()
                        && !namespaces.iter().any(|(p, _)| p.is_empty())
                    {
                        namespaces.push((
                            String::new(),
                            node.tag_name().namespace().unwrap_or("").to_owned(),
                        ));
                    }
                    out.start(
                        element_qname(node).to_owned(),
                        namespaces,
                        attributes,
                        selected,
                        |value, out| out.escaped(value.as_bytes(), true),
                    )?;
                    for child in node.children() {
                        visit(config, out, child, target.clone(), excluded)?;
                    }
                    out.end()?;
                }
                NodeType::Text if out.selected() => {
                    out.escaped(node.text().unwrap_or("").as_bytes(), false)?
                }
                NodeType::Comment if selected && out.comments() => {
                    out.put(b"<!--")?;
                    let normalized = node
                        .text()
                        .unwrap_or("")
                        .replace("\r\n", "\n")
                        .replace('\r', "\n");
                    out.put(normalized.as_bytes())?;
                    out.put(b"-->")?;
                }
                NodeType::PI if selected => {
                    let pi = node.pi().expect("PI node");
                    out.put(b"<?")?;
                    out.put(pi.target.as_bytes())?;
                    if let Some(value) = pi.value {
                        out.put(b" ")?;
                        let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
                        out.put(normalized.as_bytes())?;
                    }
                    out.put(b"?>")?;
                }
                _ => {}
            }
            Ok(())
        }
        let method = match (self.exclusive, self.comments) {
            (false, false) => C14n::Inclusive,
            (false, true) => C14n::InclusiveWithComments,
            (true, false) => C14n::Exclusive,
            (true, true) => C14n::ExclusiveWithComments,
        };
        let prefixes: Vec<String> = self
            .inclusive_prefixes
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let mut writer =
            CanonicalWriter::new(sink, method, profile, &prefixes, self.limit as u64, None);
        let target = if node.is_root() {
            0..node.document().input_text().len().saturating_add(1)
        } else {
            node.range()
        };
        visit(self, &mut writer, node.document().root(), target, false)
            .map_err(|_| XmlError::TooLarge)?;
        usize::try_from(writer.written()).map_err(|_| XmlError::TooLarge)
    }
}

/// Replacement of a byte, if it is escaped.
type Escape = fn(u8) -> Option<&'static [u8]>;

fn text_escape(b: u8) -> Option<&'static [u8]> {
    match b {
        b'&' => Some(b"&amp;"),
        b'<' => Some(b"&lt;"),
        b'>' => Some(b"&gt;"),
        b'\r' => Some(b"&#xD;"),
        _ => None,
    }
}

fn attribute_escape(b: u8) -> Option<&'static [u8]> {
    match b {
        b'&' => Some(b"&amp;"),
        b'<' => Some(b"&lt;"),
        b'"' => Some(b"&quot;"),
        b'\t' => Some(b"&#x9;"),
        b'\n' => Some(b"&#xA;"),
        b'\r' => Some(b"&#xD;"),
        _ => None,
    }
}
/// Borrowed attribute escaping, using exactly the canonical writer's byte rules.
/// A formatting/counting sink never needs an escaped temporary String.
pub(crate) struct AttributeDisplay<'a>(pub &'a str);
impl std::fmt::Display for AttributeDisplay<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut start = 0;
        for (at, byte) in self.0.bytes().enumerate() {
            if let Some(replacement) = attribute_escape(byte) {
                out.write_str(&self.0[start..at])?;
                out.write_str(std::str::from_utf8(replacement).expect("XML escapes are ASCII"))?;
                start = at + 1;
            }
        }
        out.write_str(&self.0[start..])
    }
}

fn escaped_len(text: &str, escape: Escape) -> usize {
    text.bytes().map(|b| escape(b).map_or(1, <[u8]>::len)).sum()
}

fn push_escaped(out: &mut Vec<u8>, text: &str, escape: Escape) {
    for b in text.bytes() {
        match escape(b) {
            Some(replacement) => out.extend_from_slice(replacement),
            None => out.push(b),
        }
    }
}

/// An attribute value as Canonical XML writes it between double quotes; parsing it back
/// gives `value`.
pub(crate) fn escape_attribute(value: &str) -> String {
    let mut out = Vec::with_capacity(escaped_len(value, attribute_escape));
    push_escaped(&mut out, value, attribute_escape);
    String::from_utf8(out).expect("escaping keeps UTF-8")
}

/// Character data as Canonical XML writes it; parsing it back gives `text`.
pub(crate) fn escape_text(text: &str) -> String {
    let mut out = Vec::with_capacity(escaped_len(text, text_escape));
    push_escaped(&mut out, text, text_escape);
    String::from_utf8(out).expect("escaping keeps UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical form of the first element named `name` (an XPath-selected subtree, as in
    /// the examples of the Exclusive XML Canonicalization specification, section 2.2).
    fn subtree(xml: &str, name: &str, method: C14n) -> String {
        let doc = parse::parse(xml.as_bytes()).unwrap();
        let node = doc
            .descendants()
            .find(|n| n.is_element() && element_qname(*n) == name)
            .unwrap();
        let c = Canonicalizer {
            exclusive: method.is_exclusive(),
            comments: method.with_comments(),
            inclusive_prefixes: &[],
            excluded: &[],
            limit: MAX_CANONICAL,
        };
        String::from_utf8(c.run(node).unwrap()).unwrap()
    }

    #[test]
    fn exc_c14n_spec_example_elem1() {
        let xml = "<n0:pdu xmlns:n0=\"http://a.example\">\n   <n1:elem1 xmlns:n1=\"http://b.example\">\n       content\n   </n1:elem1>\n</n0:pdu>";
        assert_eq!(
            subtree(xml, "n1:elem1", C14n::Inclusive),
            "<n1:elem1 xmlns:n0=\"http://a.example\" xmlns:n1=\"http://b.example\">\n       content\n   </n1:elem1>"
        );
        assert_eq!(
            subtree(xml, "n1:elem1", C14n::Exclusive),
            "<n1:elem1 xmlns:n1=\"http://b.example\">\n       content\n   </n1:elem1>"
        );
    }

    #[test]
    fn exc_c14n_spec_example_elem2() {
        let first = "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\"><n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"/></n1:elem2></n0:local>";
        let second = "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\"><n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"/></n1:elem2></n2:pdu>";
        assert_eq!(
            subtree(first, "n1:elem2", C14n::Inclusive),
            "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" xml:lang=\"en\"><n3:stuff></n3:stuff></n1:elem2>"
        );
        assert_eq!(
            subtree(second, "n1:elem2", C14n::Inclusive),
            "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" xml:lang=\"en\" xml:space=\"retain\"><n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff></n1:elem2>"
        );
        let exclusive = "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\"><n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff></n1:elem2>";
        assert_eq!(subtree(first, "n1:elem2", C14n::Exclusive), exclusive);
        assert_eq!(subtree(second, "n1:elem2", C14n::Exclusive), exclusive);
    }

    #[test]
    fn exclusive_renders_empty_default_under_a_rendered_default() {
        let xml = "<a xmlns=\"urn:a\"><b xmlns=\"\"><c/></b></a>";
        assert_eq!(
            subtree(xml, "a", C14n::Exclusive),
            "<a xmlns=\"urn:a\"><b xmlns=\"\"><c></c></b></a>"
        );
        // At the apex no default namespace is in effect yet.
        assert_eq!(subtree(xml, "b", C14n::Exclusive), "<b><c></c></b>");
    }

    #[test]
    fn exclusive_inclusive_prefix_list() {
        let xml = "<r xmlns:p=\"urn:p\" xmlns:q=\"urn:q\"><e><f/><f xmlns:q=\"urn:q2\" xmlns:p=\"urn:p2\"/></e></r>";
        let doc = parse::parse(xml.as_bytes()).unwrap();
        let e = doc.descendants().find(|n| n.has_tag_name("e")).unwrap();
        let c = Canonicalizer {
            exclusive: true,
            comments: false,
            inclusive_prefixes: &["#unused", "q"],
            excluded: &[],
            limit: MAX_CANONICAL,
        };
        assert_eq!(
            c.run(e).unwrap(),
            b"<e xmlns:q=\"urn:q\"><f></f><f xmlns:q=\"urn:q2\"></f></e>"
        );
    }

    #[test]
    fn outermost_xml_attribute_of_omitted_ancestors_wins() {
        // Kalkan's Santuario, not the Canonical XML 1.0 text (which takes the nearest).
        let xml = "<r xml:lang=\"ru\" xml:space=\"preserve\"><m xml:lang=\"kk\"><e/><f xml:lang=\"en\"/></m></r>";
        assert_eq!(
            subtree(xml, "e", C14n::Inclusive),
            "<e xml:lang=\"ru\" xml:space=\"preserve\"></e>"
        );
        assert_eq!(
            subtree(xml, "f", C14n::Inclusive),
            "<f xml:lang=\"en\" xml:space=\"preserve\"></f>"
        );
        assert_eq!(subtree(xml, "e", C14n::Exclusive), "<e></e>");
    }

    #[test]
    fn output_is_capped() {
        // Exclusive canonicalization repeats a long namespace URI on every element using it.
        let uri = "u".repeat(1000);
        let xml = format!("<r xmlns:p=\"{uri}\">{}</r>", "<p:x/>".repeat(100));
        let doc = parse::parse(xml.as_bytes()).unwrap();
        let run = |limit| {
            Canonicalizer {
                exclusive: true,
                comments: false,
                inclusive_prefixes: &[],
                excluded: &[],
                limit,
            }
            .run(doc.root())
        };
        let full = run(MAX_CANONICAL).unwrap();
        assert!(full.len() > 100_000);
        assert_eq!(run(full.len()).unwrap(), full);
        assert_eq!(run(full.len() - 1), Err(XmlError::TooLarge));
        assert_eq!(run(50_000), Err(XmlError::TooLarge));
    }

    #[test]
    fn attribute_escape_round_trips() {
        assert_eq!(
            escape_attribute("a&<\"\t\n\r>'b"),
            "a&amp;&lt;&quot;&#x9;&#xA;&#xD;>'b"
        );
    }
}

#[cfg(test)]
#[test]
fn bounded_adapter_hashes_shared_writer_without_canonical_buffer() {
    let document = parse::parse(b"<r a='&quot;'>text&amp;</r>").unwrap();
    let canonicalizer = Canonicalizer {
        exclusive: false,
        comments: false,
        inclusive_prefixes: &[],
        excluded: &[],
        limit: MAX_CANONICAL,
    };
    let (digest, count) = canonicalizer
        .hash(document.root(), oncl_pki::key::HashAlg::Sha256)
        .unwrap();
    let expected = b"<r a=\"&quot;\">text&amp;</r>";
    assert_eq!(count, expected.len());
    assert_eq!(
        digest.as_bytes(),
        oncl_pki::key::HashAlg::Sha256.digest(expected)
    );
}

#[cfg(test)]
#[test]
fn bounded_root_element_subtree_omits_outside_pis_without_spurious_newlines() {
    let document = parse::parse(b"<r Id='x'/><?after value?><!--outside-->").unwrap();
    let canonicalizer = Canonicalizer {
        exclusive: false,
        comments: true,
        inclusive_prefixes: &[],
        excluded: &[],
        limit: MAX_CANONICAL,
    };
    assert_eq!(
        canonicalizer.run(document.root_element()).unwrap(),
        b"<r Id=\"x\"></r>"
    );
}
