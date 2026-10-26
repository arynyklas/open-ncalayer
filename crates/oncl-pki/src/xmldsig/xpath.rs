//! The XPath subset of `signXml`: absolute location paths of element names, each step
//! optionally `[n]`, with `/` (child) or `//` (descendant) separators: `/root/body[2]`,
//! `//data`, `/a//b[1]`; at most [`MAX_STEPS`] steps.
//!
//! A name matches the qualified name as written in the document, prefix included. The one
//! exception follows Kalkan's namespace context (`XMLUtil.PkiNamespaceContext`): the prefix
//! `SOAP-ENV` stands for the SOAP 1.1 envelope namespace whatever prefix the document binds
//! to it, so `/SOAP-ENV:Envelope/SOAP-ENV:Body` selects `<soapenv:Body>`. (Kalkan maps every
//! other prefix to the XMLDSig namespace and an unprefixed name to no namespace; literal
//! matching selects whatever that would select when the document uses those prefixes.)

use super::XmlError;
use super::parse::element_qname;
use roxmltree::{Document, Node, NodeId};

/// Most steps in an expression: each costs up to a pass over the document.
pub(crate) const MAX_STEPS: usize = 32;

const SOAP_ENV_PREFIX: &str = "SOAP-ENV:";
const SOAP11_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Axis {
    Child,
    Descendant,
}

#[derive(Debug, PartialEq, Eq)]
struct Step<'e> {
    axis: Axis,
    name: &'e str,
    /// 1-based position among the parent's children of that name.
    position: Option<usize>,
}

fn unsupported(expr: &str) -> XmlError {
    XmlError::XPath(format!("unsupported XPath expression {expr:?}"))
}

fn parse(expr: &str) -> Result<Vec<Step<'_>>, XmlError> {
    let mut steps = Vec::new();
    let mut rest = expr;
    while !rest.is_empty() {
        let axis = if let Some(r) = rest.strip_prefix("//") {
            rest = r;
            Axis::Descendant
        } else if let Some(r) = rest.strip_prefix('/') {
            rest = r;
            Axis::Child
        } else {
            return Err(unsupported(expr));
        };
        let end = rest.find('/').unwrap_or(rest.len());
        let (step, tail) = rest.split_at(end);
        rest = tail;
        let (name, position) = match step.split_once('[') {
            None => (step, None),
            Some((name, predicate)) => {
                let digits = predicate
                    .strip_suffix(']')
                    .ok_or_else(|| unsupported(expr))?;
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(unsupported(expr));
                }
                let n: usize = digits.parse().map_err(|_| unsupported(expr))?;
                if n == 0 {
                    return Err(unsupported(expr));
                }
                (name, Some(n))
            }
        };
        if !is_qname(name) {
            return Err(unsupported(expr));
        }
        steps.push(Step {
            axis,
            name,
            position,
        });
    }
    if steps.is_empty() {
        return Err(unsupported(expr));
    }
    Ok(steps)
}

/// An XML name with at most one colon, neither first nor last.
fn is_qname(name: &str) -> bool {
    let start = |c: char| c.is_alphabetic() || c == '_';
    let rest = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '\u{B7}');
    let mut parts = name.split(':');
    let ok = |part: &str| {
        let mut chars = part.chars();
        chars.next().is_some_and(start) && chars.all(rest)
    };
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), None, None) => ok(local),
        (Some(prefix), Some(local), None) => ok(prefix) && ok(local),
        _ => false,
    }
}

fn name_matches(node: Node<'_, '_>, name: &str) -> bool {
    if !node.is_element() {
        return false;
    }
    match name.strip_prefix(SOAP_ENV_PREFIX) {
        Some(local) => {
            node.tag_name().namespace() == Some(SOAP11_ENVELOPE_NS)
                && node.tag_name().name() == local
        }
        None => element_qname(node) == name,
    }
}

/// Element children of `parent` matching `step`, in document order.
fn matching_children<'a, 'i>(
    parent: Node<'a, 'i>,
    step: &Step<'_>,
) -> impl Iterator<Item = Node<'a, 'i>> {
    let named = parent.children().filter(|c| name_matches(*c, step.name));
    let (skip, take) = match step.position {
        None => (0, usize::MAX),
        Some(n) => (n - 1, 1),
    };
    named.skip(skip).take(take)
}

/// Nodes of `context` (in document order) that are not inside an earlier one's subtree.
fn outermost<'a, 'i>(
    doc: &'a Document<'i>,
    context: &[NodeId],
) -> impl Iterator<Item = Node<'a, 'i>> {
    let mut searched_until = 0;
    context
        .iter()
        .map(|id| doc.get_node(*id).expect("node of this document"))
        .filter(move |node| {
            if node.range().start < searched_until {
                return false;
            }
            searched_until = node.range().end;
            true
        })
}

/// Nodes selected by `step` from `context`, in document order without duplicates.
fn apply<'i>(doc: &Document<'i>, context: &[NodeId], step: &Step<'_>) -> Vec<NodeId> {
    let mut next: Vec<NodeId> = Vec::new();
    match step.axis {
        Axis::Child => {
            for id in context {
                let node = doc.get_node(*id).expect("node of this document");
                next.extend(matching_children(node, step).map(|n| n.id()));
            }
        }
        // A context node inside a subtree already searched adds nothing.
        Axis::Descendant => {
            for node in outermost(doc, context) {
                for d in node.descendants().filter(|d| d.is_element() || d.is_root()) {
                    next.extend(matching_children(d, step).map(|n| n.id()));
                }
            }
        }
    }
    next.sort_unstable_by_key(|id| id.get());
    next.dedup();
    next
}

/// First node selected by the last `step` from `context`, in document order.
fn first<'a, 'i>(
    doc: &'a Document<'i>,
    context: &[NodeId],
    step: &Step<'_>,
) -> Option<Node<'a, 'i>> {
    match (step.axis, step.position) {
        // The outermost context nodes have disjoint subtrees in document order: the first
        // named descendant of the first one that has any is the answer.
        (Axis::Descendant, None) => outermost(doc, context).find_map(|node| {
            node.descendants()
                .skip(1)
                .find(|d| name_matches(*d, step.name))
        }),
        // Matches of nested context nodes interleave: take the earliest of each.
        (Axis::Child, _) => context
            .iter()
            .filter_map(|id| matching_children(doc.get_node(*id)?, step).next())
            .min_by_key(|n| n.id().get()),
        (Axis::Descendant, Some(_)) => {
            let first = apply(doc, context, step).into_iter().next()?;
            doc.get_node(first)
        }
    }
}

/// First element selected by `expr`, in document order. Each step costs at most one pass
/// over the document; intermediate node sets are kept as node ids.
///
/// # Errors
///
/// [`XmlError::XPath`] if `expr` is outside the supported subset or longer than
/// [`MAX_STEPS`] steps.
pub(crate) fn select_first<'a, 'i>(
    doc: &'a Document<'i>,
    expr: &str,
) -> Result<Option<Node<'a, 'i>>, XmlError> {
    let steps = parse(expr)?;
    if steps.len() > MAX_STEPS {
        return Err(XmlError::XPath(format!(
            "XPath expression {expr:?} has more than {MAX_STEPS} steps"
        )));
    }
    let (last, inner) = steps.split_last().expect("at least one step");
    let mut context = vec![doc.root().id()];
    for step in inner {
        context = apply(doc, &context, step);
        if context.is_empty() {
            return Ok(None);
        }
    }
    Ok(first(doc, &context, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_subset() {
        let steps = parse("/a/ds:b[2]//c").unwrap();
        assert_eq!(
            steps,
            [
                Step {
                    axis: Axis::Child,
                    name: "a",
                    position: None
                },
                Step {
                    axis: Axis::Child,
                    name: "ds:b",
                    position: Some(2)
                },
                Step {
                    axis: Axis::Descendant,
                    name: "c",
                    position: None
                },
            ]
        );
    }

    #[test]
    fn rejects_everything_else() {
        for expr in [
            "",
            "/",
            "a",
            "/a/",
            "/a[0]",
            "/a[x]",
            "/a[1",
            "/*",
            "/a/@id",
            "/a/text()",
            "/a[@Id='x']",
            "/a/..",
            "/a/.",
            "/a:b:c",
            "/a | /b",
            "//",
            "/a[1][2]",
        ] {
            assert!(
                matches!(parse(expr), Err(XmlError::XPath(_))),
                "{expr:?} accepted"
            );
        }
    }

    #[test]
    fn selects_in_document_order() {
        let xml = "<root><body><data i=\"1\"/></body><body><x><data i=\"2\"/></x></body><data i=\"3\"/></root>";
        let doc = parse_doc(xml);
        let doc = &doc;
        let attr = |expr: &str| {
            select_first(doc, expr)
                .unwrap()
                .map(|n| n.attribute("i").unwrap())
        };
        assert_eq!(attr("//data"), Some("1"));
        assert_eq!(attr("/root/body[2]//data"), Some("2"));
        assert_eq!(attr("/root/data"), Some("3"));
        assert_eq!(attr("//x/data[1]"), Some("2"));
        assert_eq!(attr("/root/body[3]//data"), None);
        assert_eq!(attr("/body"), None);
        assert!(select_first(doc, "//root").unwrap().is_some());
    }

    #[test]
    fn nested_context_nodes_give_the_earliest_match() {
        let xml = "<r><a i=\"1\"><x><a i=\"2\"><b i=\"in\"/><c i=\"c2\"/></a></x><b i=\"out\"/><c i=\"c1\"/></a></r>";
        let doc = parse_doc(xml);
        let doc = &doc;
        let attr = |expr: &str| {
            select_first(doc, expr)
                .unwrap()
                .map(|n| n.attribute("i").unwrap())
        };
        assert_eq!(attr("//a/b"), Some("in"));
        assert_eq!(attr("//a/b[1]"), Some("in"));
        assert_eq!(attr("//a//c"), Some("c2"));
        assert_eq!(attr("//a//c[1]"), Some("c2"));
        assert_eq!(attr("/r/a//a//b"), Some("in"));
    }

    #[test]
    fn soap_env_prefix_means_the_soap_namespace() {
        let xml = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body Id=\"b\"/></soapenv:Envelope>";
        let doc = parse_doc(xml);
        let id = |expr: &str| select_first(&doc, expr).unwrap().map(|n| n.attribute("Id"));
        assert_eq!(id("/SOAP-ENV:Envelope/SOAP-ENV:Body"), Some(Some("b")));
        assert_eq!(id("//SOAP-ENV:Body"), Some(Some("b")));
        assert_eq!(id("/soapenv:Envelope/soapenv:Body"), Some(Some("b")));
        let other = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"urn:not-soap\"/>";
        let doc = parse_doc(other);
        assert!(select_first(&doc, "/SOAP-ENV:Envelope").unwrap().is_none());
    }

    #[test]
    fn step_count_is_capped() {
        let doc = parse_doc("<a/>");
        let ok = "//a".repeat(MAX_STEPS);
        assert!(select_first(&doc, &ok).unwrap().is_none());
        let long = "//a".repeat(MAX_STEPS + 1);
        assert!(matches!(select_first(&doc, &long), Err(XmlError::XPath(_))));
    }

    fn parse_doc(xml: &str) -> Document<'_> {
        crate::xmldsig::parse::parse(xml.as_bytes()).unwrap()
    }
}
