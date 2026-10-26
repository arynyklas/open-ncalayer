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
/// The parsing errors of this module, and [`XmlError::Parse`] if `exclude_subtree` does not
/// point at an element.
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
    Ok(Canonicalizer {
        exclusive: method.is_exclusive(),
        comments: method.with_comments(),
        inclusive_prefixes: &[],
        excluded: &excluded,
    }
    .run(doc.root()))
}

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
}

/// Output plus the namespace bindings in effect in it.
struct Output<'a> {
    bytes: Vec<u8>,
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
}

impl Canonicalizer<'_> {
    /// Canonical form of the document (`node` is the root) or of an element subtree.
    pub(crate) fn run(&self, node: Node<'_, '_>) -> Vec<u8> {
        let mut out = Output {
            bytes: Vec::new(),
            bindings: HashMap::new(),
        };
        if node.node_type() == NodeType::Root {
            self.document(&mut out, node);
        } else {
            self.element(&mut out, node, true);
        }
        out.bytes
    }

    fn document<'a>(&self, out: &mut Output<'a>, root: Node<'a, '_>) {
        let mut after_element = false;
        for child in root.children() {
            match child.node_type() {
                NodeType::Element => {
                    self.element(out, child, false);
                    after_element = true;
                }
                NodeType::Comment | NodeType::PI => {
                    let start = out.bytes.len();
                    if after_element {
                        out.bytes.push(b'\n');
                    }
                    if self.leaf(out, child) {
                        if !after_element {
                            out.bytes.push(b'\n');
                        }
                    } else {
                        out.bytes.truncate(start);
                    }
                }
                NodeType::Root | NodeType::Text => {}
            }
        }
    }

    /// Writes a comment (if comments are kept) or a processing instruction; `false` if
    /// nothing was written.
    fn leaf(&self, out: &mut Output<'_>, node: Node<'_, '_>) -> bool {
        match node.node_type() {
            NodeType::Comment if self.comments => {
                out.bytes.extend_from_slice(b"<!--");
                push_newlines_normalized(&mut out.bytes, node.text().unwrap_or(""));
                out.bytes.extend_from_slice(b"-->");
                true
            }
            NodeType::PI => {
                let pi = node.pi().expect("PI node");
                out.bytes.extend_from_slice(b"<?");
                out.bytes.extend_from_slice(pi.target.as_bytes());
                if let Some(value) = pi.value {
                    out.bytes.push(b' ');
                    push_newlines_normalized(&mut out.bytes, value);
                }
                out.bytes.extend_from_slice(b"?>");
                true
            }
            _ => false,
        }
    }

    fn element<'a, 'i: 'a>(&self, out: &mut Output<'a>, node: Node<'a, 'i>, apex: bool) {
        if self
            .excluded
            .binary_search_by_key(&node.id().get(), |id| id.get())
            .is_ok()
        {
            return;
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
            // apex, the nearest ancestor's value winning.
            let mut seen: HashSet<&str> = attributes
                .iter()
                .filter(|(ns, ..)| *ns == XML_NS)
                .map(|&(_, local, ..)| local)
                .collect();
            for ancestor in node.ancestors().skip(1).filter(Node::is_element) {
                for a in ancestor.attributes() {
                    if a.namespace() == Some(XML_NS) && seen.insert(a.name()) {
                        let qname = &src[a.range_qname()];
                        attributes.push((XML_NS, a.name(), qname, a.value()));
                    }
                }
            }
        }
        attributes.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

        let bytes = &mut out.bytes;
        bytes.push(b'<');
        bytes.extend_from_slice(qname.as_bytes());
        for (prefix, uri) in &declarations {
            bytes.extend_from_slice(b" xmlns");
            if !prefix.is_empty() {
                bytes.push(b':');
                bytes.extend_from_slice(prefix.as_bytes());
            }
            bytes.extend_from_slice(b"=\"");
            push_attribute_value(bytes, uri);
            bytes.push(b'"');
        }
        for (_, _, qname, value) in &attributes {
            bytes.push(b' ');
            bytes.extend_from_slice(qname.as_bytes());
            bytes.extend_from_slice(b"=\"");
            push_attribute_value(bytes, value);
            bytes.push(b'"');
        }
        bytes.push(b'>');
        for &(prefix, uri) in &declarations {
            out.bindings.entry(prefix).or_default().push(uri);
        }

        for child in node.children() {
            match child.node_type() {
                NodeType::Element => self.element(out, child, false),
                NodeType::Text => push_text(&mut out.bytes, child.text().unwrap_or("")),
                NodeType::Comment | NodeType::PI => {
                    self.leaf(out, child);
                }
                NodeType::Root => {}
            }
        }

        out.bytes.extend_from_slice(b"</");
        out.bytes.extend_from_slice(qname.as_bytes());
        out.bytes.push(b'>');
        for (prefix, _) in &declarations {
            if let Some(uris) = out.bindings.get_mut(prefix) {
                uris.pop();
            }
        }
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
        let declared = if apex {
            Vec::new()
        } else {
            parse::declared_prefixes(node)
        };
        let in_scope: Vec<(&'a str, &'a str)> = if apex || !declared.is_empty() {
            node.namespaces()
                .map(|ns| (ns.name().unwrap_or(""), ns.uri()))
                .filter(|(prefix, _)| apex || declared.contains(prefix))
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

fn push_newlines_normalized(out: &mut Vec<u8>, text: &str) {
    let mut chars = text.bytes().peekable();
    while let Some(b) = chars.next() {
        if b == b'\r' {
            chars.next_if_eq(&b'\n');
            out.push(b'\n');
        } else {
            out.push(b);
        }
    }
}

fn push_text(out: &mut Vec<u8>, text: &str) {
    for b in text.bytes() {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
}

fn push_attribute_value(out: &mut Vec<u8>, value: &str) {
    for b in value.bytes() {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\t' => out.extend_from_slice(b"&#x9;"),
            b'\n' => out.extend_from_slice(b"&#xA;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            _ => out.push(b),
        }
    }
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
        };
        String::from_utf8(c.run(node)).unwrap()
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
        };
        assert_eq!(
            c.run(e),
            b"<e xmlns:q=\"urn:q\"><f></f><f xmlns:q=\"urn:q2\"></f></e>"
        );
    }
}
