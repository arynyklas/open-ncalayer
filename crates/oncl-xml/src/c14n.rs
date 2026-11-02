//! Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 of a whole document or of one
//! element's subtree, optionally leaving out some element subtrees.
//!
//! The data model is the parsed document without a DTD: attribute values are normalized as
//! CDATA, the only entities are the predefined ones, line ends are already `#xA`.

use super::XmlError;
use super::parse::{self, element_qname};
use roxmltree::{Document, Node, NodeId, NodeType};
use std::collections::{HashMap, HashSet};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

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

/// Output plus the namespace bindings in effect in it.
struct Output<'a> {
    bytes: Vec<u8>,
    limit: usize,
    /// URIs each prefix is bound to by the open output elements, innermost last.
    bindings: HashMap<&'a str, Vec<&'a str>>,
}

impl Output<'_> {
    /// URI the output binds `prefix` to (`""` for the default namespace when unbound).
    fn bound(&self, prefix: &str) -> &str {
        self.bindings
            .get(prefix)
            .and_then(|uris| uris.last())
            .copied()
            .unwrap_or("")
    }

    fn room(&self, len: usize) -> Result<(), XmlError> {
        if self.bytes.len().saturating_add(len) > self.limit {
            return Err(XmlError::TooLarge);
        }
        Ok(())
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), XmlError> {
        self.room(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn put_escaped(&mut self, text: &str, escape: Escape) -> Result<(), XmlError> {
        self.room(escaped_len(text, escape))?;
        push_escaped(&mut self.bytes, text, escape);
        Ok(())
    }

    /// Comment or processing instruction content: line ends normalized to `#xA` (the
    /// parser keeps them raw there).
    fn put_newlines_normalized(&mut self, text: &str) -> Result<(), XmlError> {
        self.room(text.len())?;
        let mut bytes = text.bytes().peekable();
        while let Some(b) = bytes.next() {
            if b == b'\r' {
                bytes.next_if_eq(&b'\n');
                self.bytes.push(b'\n');
            } else {
                self.bytes.push(b);
            }
        }
        Ok(())
    }
}

impl Canonicalizer<'_> {
    /// Canonical form of the document (`node` is the root) or of an element subtree.
    ///
    /// # Errors
    ///
    /// [`XmlError::TooLarge`] if the output would exceed the limit.
    pub(crate) fn run(&self, node: Node<'_, '_>) -> Result<Vec<u8>, XmlError> {
        let mut out = Output {
            bytes: Vec::new(),
            limit: self.limit,
            bindings: HashMap::new(),
        };
        if node.node_type() == NodeType::Root {
            self.document(&mut out, node)?;
        } else {
            self.element(&mut out, node, true)?;
        }
        Ok(out.bytes)
    }

    fn document<'a>(&self, out: &mut Output<'a>, root: Node<'a, '_>) -> Result<(), XmlError> {
        let mut after_element = false;
        for child in root.children() {
            match child.node_type() {
                NodeType::Element => {
                    self.element(out, child, false)?;
                    after_element = true;
                }
                NodeType::Comment | NodeType::PI => {
                    if !self.writes(child) {
                        continue;
                    }
                    if after_element {
                        out.put(b"\n")?;
                    }
                    self.leaf(out, child)?;
                    if !after_element {
                        out.put(b"\n")?;
                    }
                }
                NodeType::Root | NodeType::Text => {}
            }
        }
        Ok(())
    }

    /// Whether a comment or processing instruction is output.
    fn writes(&self, node: Node<'_, '_>) -> bool {
        node.is_pi() || (self.comments && node.is_comment())
    }

    /// Writes a comment (if comments are kept) or a processing instruction.
    fn leaf(&self, out: &mut Output<'_>, node: Node<'_, '_>) -> Result<(), XmlError> {
        if !self.writes(node) {
            return Ok(());
        }
        if let Some(pi) = node.pi() {
            out.put(b"<?")?;
            out.put(pi.target.as_bytes())?;
            if let Some(value) = pi.value {
                out.put(b" ")?;
                out.put_newlines_normalized(value)?;
            }
            out.put(b"?>")
        } else {
            out.put(b"<!--")?;
            out.put_newlines_normalized(node.text().unwrap_or(""))?;
            out.put(b"-->")
        }
    }

    fn element<'a, 'i: 'a>(
        &self,
        out: &mut Output<'a>,
        node: Node<'a, 'i>,
        apex: bool,
    ) -> Result<(), XmlError> {
        if self
            .excluded
            .binary_search_by_key(&node.id().get(), |id| id.get())
            .is_ok()
        {
            return Ok(());
        }
        let qname = element_qname(node);

        let mut declarations: Vec<(&'a str, &'a str)> = self
            .namespace_candidates(node, qname, apex)
            .into_iter()
            .filter(|&(prefix, uri)| out.bound(prefix) != uri)
            .collect();
        declarations.sort_unstable_by_key(|&(prefix, _)| prefix);
        declarations.dedup_by_key(|&mut (prefix, _)| prefix);

        let src = node.document().input_text();
        // (namespace URI, local name, qualified name, value)
        let mut attributes: Vec<(&'a str, &'a str, &'a str, &'a str)> = node
            .attributes()
            .map(|a| {
                let qname = &src[a.range_qname()];
                (a.namespace().unwrap_or(""), a.name(), qname, a.value())
            })
            .collect();
        if apex && !self.exclusive {
            // Canonical XML 1.0 carries the xml:* attributes of omitted ancestors over to the
            // apex. The apex's own ones win; among the ancestors Kalkan's Santuario keeps the
            // OUTERMOST value, where the specification says the nearest: `handleParent`
            // (Canonicalizer20010315) adds every ancestor's xml:* attributes to one
            // XmlAttrStack level, root first (`push(-1)` does not start a new level), and
            // `getXmlnsAttr` keeps the first of each name. We follow Kalkan.
            let mut seen: HashSet<&str> = attributes
                .iter()
                .filter(|(ns, ..)| *ns == XML_NS)
                .map(|&(_, local, ..)| local)
                .collect();
            let ancestors: Vec<Node<'a, 'i>> =
                node.ancestors().skip(1).filter(Node::is_element).collect();
            for ancestor in ancestors.iter().rev() {
                for a in ancestor.attributes() {
                    if a.namespace() == Some(XML_NS) && seen.insert(a.name()) {
                        let qname = &src[a.range_qname()];
                        attributes.push((XML_NS, a.name(), qname, a.value()));
                    }
                }
            }
        }
        attributes.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        out.put(b"<")?;
        out.put(qname.as_bytes())?;
        for (prefix, uri) in &declarations {
            out.put(b" xmlns")?;
            if !prefix.is_empty() {
                out.put(b":")?;
                out.put(prefix.as_bytes())?;
            }
            out.put(b"=\"")?;
            out.put_escaped(uri, attribute_escape)?;
            out.put(b"\"")?;
        }
        for (_, _, qname, value) in &attributes {
            out.put(b" ")?;
            out.put(qname.as_bytes())?;
            out.put(b"=\"")?;
            out.put_escaped(value, attribute_escape)?;
            out.put(b"\"")?;
        }
        out.put(b">")?;
        for &(prefix, uri) in &declarations {
            out.bindings.entry(prefix).or_default().push(uri);
        }

        for child in node.children() {
            match child.node_type() {
                NodeType::Element => self.element(out, child, false)?,
                NodeType::Text => out.put_escaped(child.text().unwrap_or(""), text_escape)?,
                NodeType::Comment | NodeType::PI => self.leaf(out, child)?,
                NodeType::Root => {}
            }
        }

        out.put(b"</")?;
        out.put(qname.as_bytes())?;
        out.put(b">")?;
        for (prefix, _) in &declarations {
            if let Some(uris) = out.bindings.get_mut(prefix) {
                uris.pop();
            }
        }
        Ok(())
    }

    /// Namespace nodes that may be rendered on `node`. Canonical XML: the namespaces in
    /// scope that may differ from the output's: all of them at the apex, below it only the
    /// ones the element declares (the others are its parent's, which the output already
    /// binds). Exclusive: the visibly utilized ones, plus those of the first kind in the
    /// `InclusiveNamespaces` list.
    fn namespace_candidates<'a, 'i: 'a>(
        &self,
        node: Node<'a, 'i>,
        qname: &'a str,
        apex: bool,
    ) -> Vec<(&'a str, &'a str)> {
        let mut declared = if apex {
            Vec::new()
        } else {
            parse::declared_prefixes(node)
        };
        declared.sort_unstable();
        let in_scope: Vec<(&'a str, &'a str)> = if apex || !declared.is_empty() {
            node.namespaces()
                .map(|ns| (ns.name().unwrap_or(""), ns.uri()))
                .filter(|(prefix, _)| apex || declared.binary_search(prefix).is_ok())
                .collect()
        } else {
            Vec::new()
        };
        if !self.exclusive {
            return in_scope;
        }
        let src = node.document().input_text();
        let mut candidates = vec![(
            parse::prefix(qname),
            node.tag_name().namespace().unwrap_or(""),
        )];
        for a in node.attributes() {
            let prefix = parse::prefix(&src[a.range_qname()]);
            if !prefix.is_empty() && prefix != "xml" {
                candidates.push((prefix, a.namespace().unwrap_or("")));
            }
        }
        candidates.extend(
            in_scope
                .into_iter()
                .filter(|(prefix, _)| self.inclusive_prefixes.binary_search(prefix).is_ok()),
        );
        candidates
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
