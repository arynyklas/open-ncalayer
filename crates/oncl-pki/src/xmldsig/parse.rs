//! Bounded, namespace-aware XML parsing: UTF-8 input of at most [`MAX_INPUT`] bytes, at most
//! [`MAX_DEPTH`] levels of element nesting, [`MAX_NODES`] nodes and [`MAX_ATTRIBUTES`]
//! attributes, and no DOCTYPE, so no entities beyond the predefined ones and nothing is ever
//! fetched.
//!
//! Everything that is not linear in the input is bounded by one scan before the tree is
//! built:
//! - the parser sizes its node and attribute arrays by the counts of `<` and `=` bytes;
//! - checking an element's attributes for duplicates is quadratic in their number;
//! - every element name and prefixed attribute name is resolved by a linear search of the
//!   namespaces in scope, and an element declaring a namespace gets its own copy of them
//!   (checked against its declarations), so namespace work is charged on every start tag.
//!
//! An attribute with a prefix and the local part `xmlns` (`a:xmlns`, `xml:xmlns`) is refused
//! as malformed: roxmltree would take it for a default namespace declaration (and copy every
//! namespace in scope into the element), where Kalkan's parser sees an ordinary attribute,
//! or an error for an undeclared prefix.

use super::XmlError;
use roxmltree::{Document, Node, ParsingOptions};

/// Largest accepted input, in bytes.
pub const MAX_INPUT: usize = 64 * 1024 * 1024;

/// Deepest accepted element nesting; the document element is level 1.
pub const MAX_DEPTH: usize = 256;

/// Most nodes (elements, text, comments, processing instructions) in a document; the input
/// may also hold at most this many `<` bytes.
pub const MAX_NODES: usize = 1 << 21;

/// Most `=` bytes in a document, which bounds its attributes.
pub const MAX_ATTRIBUTES: usize = 1 << 21;

/// Limits of one parse.
#[derive(Clone, Copy)]
struct Bounds {
    nodes: usize,
    attributes: usize,
    /// Bound on the sum over elements of the squared attribute count.
    attribute_work: usize,
    /// Bound on the namespace entries the parser looks at: on every start tag, (namespaces
    /// in scope) × (1 + prefixed attributes other than `xml:*` and declarations), plus
    /// (namespaces in scope)² / 2 on a declaring one (its copy checks each inherited
    /// namespace against the ones copied so far). About 1 ns each: 2²⁹ is half a second.
    namespace_work: usize,
    /// Bound on the namespace entries the parser copies: the namespaces in scope of every
    /// declaring element (2 bytes each).
    namespace_copies: usize,
}

const BOUNDS: Bounds = Bounds {
    nodes: MAX_NODES,
    attributes: MAX_ATTRIBUTES,
    attribute_work: 1 << 28,
    namespace_work: 1 << 29,
    namespace_copies: 1 << 24,
};

/// Bounds for a document this module produced from an accepted one by inserting a signature:
/// its few nodes and attributes, and its namespace work, which is at most that of the
/// signature's parent (declaring `ds`, the signature copies the parent's namespaces).
const SIGNED_BOUNDS: Bounds = Bounds {
    nodes: MAX_NODES + 256,
    attributes: MAX_ATTRIBUTES + 256,
    attribute_work: 2 * BOUNDS.attribute_work,
    namespace_work: 2 * BOUNDS.namespace_work,
    namespace_copies: 2 * BOUNDS.namespace_copies,
};

/// Parses untrusted input.
///
/// # Errors
///
/// [`XmlError::TooLarge`] for input over [`MAX_INPUT`], [`MAX_NODES`], [`MAX_ATTRIBUTES`] or
/// the parse work bounds, [`XmlError::TooDeep`], [`XmlError::Doctype`],
/// [`XmlError::NotWellFormed`] for a document that ends inside its root element, or
/// [`XmlError::Parse`] for other input that is not well-formed namespace-aware UTF-8 XML (an
/// attribute with a prefix and the local name `xmlns` included).
pub(crate) fn parse(xml: &[u8]) -> Result<Document<'_>, XmlError> {
    if xml.len() > MAX_INPUT {
        return Err(XmlError::TooLarge);
    }
    parse_with(xml, BOUNDS)
}

/// Parses a document this module produced from an input accepted by [`parse`] by inserting
/// one signature; it may exceed [`MAX_INPUT`] and the other bounds by the signature's share.
pub(crate) fn parse_signed(xml: &[u8]) -> Result<Document<'_>, XmlError> {
    parse_with(xml, SIGNED_BOUNDS)
}

fn parse_with(xml: &[u8], bounds: Bounds) -> Result<Document<'_>, XmlError> {
    let text = std::str::from_utf8(xml)
        .map_err(|e| XmlError::Parse(format!("the input is not UTF-8: {e}")))?;
    let count = |byte: u8| xml.iter().filter(|&&b| b == byte).count();
    if count(b'<') > bounds.nodes || count(b'=') > bounds.attributes {
        return Err(XmlError::TooLarge);
    }
    check_markup(xml, bounds)?;
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: u32::try_from(bounds.nodes).expect("node bound fits u32"),
        ..ParsingOptions::default()
    };
    Document::parse_with_options(text, options).map_err(|e| match e {
        roxmltree::Error::DtdDetected => XmlError::Doctype,
        roxmltree::Error::NodesLimitReached => XmlError::TooLarge,
        roxmltree::Error::UnclosedRootNode => sax_at_end(
            text,
            "XML document structures must start and end within the same entity.",
        ),
        e => XmlError::Parse(e.to_string()),
    })
}

/// [`XmlError::NotWellFormed`] with `message` at the end of `text`, where the JDK's parser
/// (Xerces) stops: lines broken by LF, CR or CRLF, columns counted in UTF-16 units from 1, a
/// byte order mark not counted.
fn sax_at_end(text: &str, message: &str) -> XmlError {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let (mut line, mut column) = (1usize, 1usize);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' | '\n' => {
                if c == '\r' {
                    chars.next_if_eq(&'\n');
                }
                line += 1;
                column = 1;
            }
            c => column += c.len_utf16(),
        }
    }
    XmlError::NotWellFormed(format!(
        "org.xml.sax.SAXParseException; lineNumber: {line}; columnNumber: {column}; {message}"
    ))
}

/// Rejects a DOCTYPE, nesting deeper than [`MAX_DEPTH`], prefixed `xmlns` attributes and
/// input over the work bounds in one linear scan, before the tree is built. Otherwise only
/// well-formed input matters here: anything malformed is reported by the parser afterwards.
fn check_markup(xml: &[u8], bounds: Bounds) -> Result<(), XmlError> {
    // Namespaces in scope (an upper bound) of each open element.
    let mut in_scope: Vec<usize> = Vec::new();
    let mut attribute_work = 0usize;
    let mut namespace_work = 0usize;
    let mut namespace_copies = 0usize;
    let mut at = 0;
    while let Some(lt) = xml[at..].iter().position(|&b| b == b'<') {
        let start = at + lt;
        let rest = &xml[start..];
        at = if rest.starts_with(b"<!--") {
            skip_past(xml, start + 4, b"-->")
        } else if rest.starts_with(b"<![CDATA[") {
            skip_past(xml, start + 9, b"]]>")
        } else if rest.starts_with(b"<!DOCTYPE") {
            return Err(XmlError::Doctype);
        } else if rest.starts_with(b"<?") {
            skip_past(xml, start + 2, b"?>")
        } else if rest.starts_with(b"</") {
            in_scope.pop();
            start + 2
        } else {
            if in_scope.len() == MAX_DEPTH {
                return Err(XmlError::TooDeep);
            }
            let (mut attributes, mut declarations, mut resolved) = (0usize, 0usize, 0usize);
            let mut reserved = None;
            let (end, empty) = scan_start_tag(xml, start + 1, |name| {
                attributes += 1;
                if namespace_prefix(name).is_some() {
                    declarations += 1;
                } else if name.ends_with(b":xmlns") {
                    reserved.get_or_insert(name);
                } else if name.contains(&b':') && !name.starts_with(b"xml:") {
                    // The parser looks up only these attributes' prefixes.
                    resolved += 1;
                }
            });
            if let Some(name) = reserved {
                return Err(XmlError::Parse(format!(
                    "the attribute {} has a prefix and the local name xmlns",
                    String::from_utf8_lossy(name)
                )));
            }
            let own = in_scope.last().copied().unwrap_or(0) + declarations;
            attribute_work = attribute_work.saturating_add(attributes.saturating_mul(attributes));
            namespace_work = namespace_work.saturating_add(own.saturating_mul(1 + resolved));
            if declarations > 0 {
                namespace_work = namespace_work.saturating_add(own.saturating_mul(own) / 2);
                namespace_copies = namespace_copies.saturating_add(own);
            }
            if attribute_work > bounds.attribute_work
                || namespace_work > bounds.namespace_work
                || namespace_copies > bounds.namespace_copies
            {
                return Err(XmlError::TooLarge);
            }
            if !empty {
                in_scope.push(own);
            }
            end
        };
    }
    Ok(())
}

/// Position after the first `needle` at or after `from`, or the end of the input.
fn skip_past(xml: &[u8], from: usize, needle: &[u8]) -> usize {
    xml[from.min(xml.len())..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map_or(xml.len(), |p| from + p + needle.len())
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Scans the start tag whose name begins at `from`, calling `on_attribute` with every
/// attribute name (namespace declarations included). Returns the position after its `>` and
/// whether it is an empty-element tag.
fn scan_start_tag<'x>(
    xml: &'x [u8],
    from: usize,
    mut on_attribute: impl FnMut(&'x [u8]),
) -> (usize, bool) {
    let name_end = |mut i: usize| {
        while i < xml.len() && !is_space(xml[i]) && !matches!(xml[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        i
    };
    let mut i = name_end(from);
    loop {
        while i < xml.len() && is_space(xml[i]) {
            i += 1;
        }
        match xml.get(i..) {
            None | Some([]) => return (xml.len(), false),
            Some([b'>', ..]) => return (i + 1, false),
            Some([b'/', b'>', ..]) => return (i + 2, true),
            Some([b'/' | b'=' | b'"' | b'\'', ..]) => i += 1,
            Some(_) => {
                let end = name_end(i);
                on_attribute(&xml[i..end]);
                i = end;
                while i < xml.len() && is_space(xml[i]) {
                    i += 1;
                }
                if xml.get(i) == Some(&b'=') {
                    i += 1;
                    while i < xml.len() && is_space(xml[i]) {
                        i += 1;
                    }
                    if let Some(&quote @ (b'"' | b'\'')) = xml.get(i) {
                        i = xml[i + 1..]
                            .iter()
                            .position(|&b| b == quote)
                            .map_or(xml.len(), |p| i + 1 + p + 1);
                    }
                }
            }
        }
    }
}

/// Prefix a namespace declaration attribute declares (`""` for the default namespace), as a
/// subslice of `name`, or `None` for another attribute.
fn namespace_prefix(name: &[u8]) -> Option<&[u8]> {
    match name.strip_prefix(b"xmlns") {
        Some([]) => Some(&name[5..]),
        Some([b':', ..]) => Some(&name[6..]),
        _ => None,
    }
}

/// Prefixes the start tag of `node` declares, `""` for the default namespace.
pub(crate) fn declared_prefixes<'i>(node: Node<'_, 'i>) -> Vec<&'i str> {
    let src = node.document().input_text();
    let mut prefixes = Vec::new();
    scan_start_tag(src.as_bytes(), node.range().start + 1, |name| {
        if let Some(prefix) = namespace_prefix(name) {
            // Attribute names end at ASCII delimiters, so the slice is on char boundaries.
            let start = prefix.as_ptr() as usize - src.as_ptr() as usize;
            prefixes.push(&src[start..start + prefix.len()]);
        }
    });
    prefixes
}

/// Qualified name of an element as written in its start tag.
pub(crate) fn element_qname<'i>(node: Node<'_, 'i>) -> &'i str {
    let tag = &node.document().input_text()[node.range().start + 1..];
    let end = tag
        .find([' ', '\t', '\r', '\n', '>', '/'])
        .unwrap_or(tag.len());
    &tag[..end]
}

/// Prefix of a qualified name, `""` for none.
pub(crate) fn prefix(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(p, _)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes(tag: &str) -> (Vec<String>, usize, bool) {
        let mut names = Vec::new();
        let (end, empty) = scan_start_tag(tag.as_bytes(), 1, |n| {
            names.push(String::from_utf8(n.to_vec()).unwrap());
        });
        (names, end, empty)
    }

    #[test]
    fn scans_start_tags() {
        let tag = "<p:e a='>' xmlns:q = \"u/>\"\txmlns=\"\" b=\"x\"/>tail";
        assert_eq!(
            attributes(tag),
            (
                vec!["a".into(), "xmlns:q".into(), "xmlns".into(), "b".into()],
                tag.len() - 4,
                true
            )
        );
        assert_eq!(attributes("<e>"), (vec![], 3, false));
        assert_eq!(attributes("<e x=\"1\" >"), (vec!["x".into()], 10, false));
    }

    #[test]
    fn declared_prefixes_come_from_the_start_tag() {
        let doc = parse(b"<a xmlns='urn:a' xmlns:p='urn:p' xmlnsx='1'><b xmlns=''/></a>").unwrap();
        let a = doc.root_element();
        assert_eq!(declared_prefixes(a), ["", "p"]);
        assert_eq!(declared_prefixes(a.first_element_child().unwrap()), [""]);
    }

    #[test]
    fn parse_work_is_bounded() {
        // One element with 20 000 attributes: 4·10⁸ duplicate checks.
        let attributes: String = (0..20_000).map(|i| format!(" a{i}=''")).collect();
        let xml = format!("<r{attributes}/>");
        assert_eq!(parse(xml.as_bytes()).err(), Some(XmlError::TooLarge));

        // 5 000 namespaces in scope copied into each of 20 000 elements.
        let declarations: String = (0..5_000).map(|i| format!(" xmlns:n{i}='u{i}'")).collect();
        let children = "<c xmlns:z='z'/>".repeat(20_000);
        let xml = format!("<r{declarations}>{children}</r>");
        assert_eq!(parse(xml.as_bytes()).err(), Some(XmlError::TooLarge));

        // Without the copies 20 000 children are fine, but every element name is still looked
        // up among the 5 000 namespaces: 200 000 children are too many.
        let xml = format!("<r{declarations}>{}</r>", "<c/>".repeat(20_000));
        assert!(parse(xml.as_bytes()).is_ok());
        let xml = format!("<r{declarations}>{}</r>", "<c/>".repeat(200_000));
        assert_eq!(parse(xml.as_bytes()).err(), Some(XmlError::TooLarge));

        // Unprefixed attributes are not looked up; prefixed ones are.
        let plain: String = (0..8).map(|i| format!(" a{i}=''")).collect();
        let xml = format!(
            "<r{declarations}>{}</r>",
            format!("<c{plain}/>").repeat(20_000)
        );
        assert!(parse(xml.as_bytes()).is_ok());
        let prefixed: String = (0..8).map(|i| format!(" n{i}:a=''")).collect();
        let xml = format!(
            "<r{declarations}>{}</r>",
            format!("<c{prefixed}/>").repeat(20_000)
        );
        assert_eq!(parse(xml.as_bytes()).err(), Some(XmlError::TooLarge));
        // Nor are `xml:*` attributes: that prefix is bound without a search.
        let xml_attributes: String = (0..8).map(|i| format!(" xml:a{i}=''")).collect();
        let xml = format!(
            "<r{declarations}>{}</r>",
            format!("<c{xml_attributes}/>").repeat(20_000)
        );
        assert!(parse(xml.as_bytes()).is_ok());
    }

    #[test]
    fn prefixed_xmlns_attributes_are_refused() {
        // roxmltree takes `p:xmlns` for a default namespace declaration and copies every
        // namespace in scope into the element: 15 ms per element under 5 000 namespaces.
        let declarations: String = (0..5_000).map(|i| format!(" xmlns:n{i}='u{i}'")).collect();
        for attribute in ["n1:xmlns", "a:xmlns", "xml:xmlns", ":xmlns"] {
            let children = format!("<c {attribute}='z'/>").repeat(20_000);
            let xml = format!("<r{declarations}>{children}</r>");
            let started = std::time::Instant::now();
            assert!(
                matches!(parse(xml.as_bytes()), Err(XmlError::Parse(m)) if m.contains(attribute)),
                "{attribute}"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "{attribute}"
            );
            assert!(matches!(
                parse(format!("<r {attribute}='z'/>").as_bytes()),
                Err(XmlError::Parse(_))
            ));
        }
        // Names that only look alike are ordinary attributes and declarations.
        let doc = "<r xmlns='urn:d' xmlns:a='urn:a' xmlnsx='1' a:xmlnsx='2' a:x-xmlns='3'><c xmlns=''/></r>";
        assert!(parse(doc.as_bytes()).is_ok());
    }

    #[test]
    fn nodes_and_attributes_are_capped() {
        let at_cap = format!("<r>{}</r>", "<a/>".repeat(MAX_NODES - 2));
        assert!(parse(at_cap.as_bytes()).is_ok());
        let over = format!("<r>{}</r>", "<a/>".repeat(MAX_NODES - 1));
        assert_eq!(parse(over.as_bytes()).err(), Some(XmlError::TooLarge));
        // Text nodes count too: below the `<` bound, over the node bound.
        let text = format!("<r>{}</r>", "<a/>x".repeat(MAX_NODES / 2 + 1));
        assert_eq!(parse(text.as_bytes()).err(), Some(XmlError::TooLarge));
        // A signature's share is allowed on re-parse.
        let signed = format!("<r>{}</r>", "<a/>".repeat(MAX_NODES + 10));
        assert!(parse_signed(signed.as_bytes()).is_ok());

        let equals = format!("<r>{}</r>", "=".repeat(MAX_ATTRIBUTES + 1));
        assert_eq!(parse(equals.as_bytes()).err(), Some(XmlError::TooLarge));
    }
}
