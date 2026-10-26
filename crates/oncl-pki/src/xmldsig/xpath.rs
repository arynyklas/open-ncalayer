//! The XPath subset of `signXml`: absolute location paths of element names as written in the
//! document (with their namespace prefixes), each step optionally `[n]`, with `/` (child) or
//! `//` (descendant) separators: `/root/body[2]`, `//data`, `/a//b[1]`.

use super::XmlError;
use super::parse::{MAX_DEPTH, element_qname};
use roxmltree::{Document, Node};

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

/// Element children of `parent` named `step.name`, narrowed to `step.position`.
fn matching_children<'a, 'i>(parent: Node<'a, 'i>, step: &Step<'_>, out: &mut Vec<Node<'a, 'i>>) {
    let mut named = parent
        .children()
        .filter(|c| c.is_element() && element_qname(*c) == step.name);
    match step.position {
        None => out.extend(named),
        Some(n) => out.extend(named.nth(n - 1)),
    }
}

/// First element selected by `expr`, in document order. Each step costs at most one pass
/// over the document.
///
/// # Errors
///
/// [`XmlError::XPath`] if `expr` is outside the supported subset.
pub(crate) fn select_first<'a, 'i>(
    doc: &'a Document<'i>,
    expr: &str,
) -> Result<Option<Node<'a, 'i>>, XmlError> {
    let steps = parse(expr)?;
    // Every step goes at least one level down.
    if steps.len() > MAX_DEPTH {
        return Ok(None);
    }
    let mut context = vec![doc.root()];
    for step in &steps {
        let mut next = Vec::new();
        // Context nodes are in document order: one inside a subtree already searched is
        // skipped.
        let mut searched_until = 0;
        for node in &context {
            match step.axis {
                Axis::Child => matching_children(*node, step, &mut next),
                Axis::Descendant if node.range().start < searched_until => {}
                Axis::Descendant => {
                    searched_until = node.range().end;
                    for d in node.descendants().filter(|d| d.is_element() || d.is_root()) {
                        matching_children(d, step, &mut next);
                    }
                }
            }
        }
        next.sort_unstable_by_key(|n| n.id().get());
        next.dedup_by_key(|n| n.id());
        context = next;
    }
    Ok(context.into_iter().next())
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

    fn parse_doc(xml: &str) -> Document<'_> {
        crate::xmldsig::parse::parse(xml.as_bytes()).unwrap()
    }
}
