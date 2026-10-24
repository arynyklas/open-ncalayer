//! BER → DER normalization of the encoding shape.
//!
//! NCA containers and CMS made by the original NCALayer use BER: indefinite lengths
//! (`30 80 … 00 00`) and constructed OCTET STRINGs. [`to_der`] rewrites the *shape* only:
//!
//! - every indefinite length becomes a minimal definite length;
//! - every definite length is re-encoded in its minimal form;
//! - constructed universal OCTET STRINGs and BIT STRINGs are flattened into primitive ones.
//!
//! Contents are copied byte for byte and SET elements keep their order, so signatures over
//! the original bytes stay valid. Input that is already DER comes back unchanged.

use std::ops::Range;

/// Maximum nesting depth accepted, to bound recursion on hostile input.
const MAX_DEPTH: usize = 64;

const OCTET_STRING: u8 = 0x04;
const BIT_STRING: u8 = 0x03;
const CONSTRUCTED: u8 = 0x20;

/// Error of [`to_der`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BerError {
    /// The input ends inside an element.
    #[error("BER input is truncated at offset {offset}")]
    Truncated {
        /// Offset where more bytes were expected.
        offset: usize,
    },
    /// The input is not valid BER.
    #[error("invalid BER at offset {offset}: {reason}")]
    Invalid {
        /// Offset of the offending element or byte.
        offset: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// Bytes follow the single top-level element.
    #[error("trailing data after the BER element at offset {offset}")]
    TrailingData {
        /// Offset of the first trailing byte.
        offset: usize,
    },
    /// Elements are nested deeper than the supported limit.
    #[error("BER elements nested deeper than {MAX_DEPTH} levels")]
    TooDeep,
}

/// Normalizes one BER element into DER shape (see the [module docs](self)).
///
/// # Errors
///
/// [`BerError`] if the input is empty, truncated, malformed, nested too deep, or has bytes
/// after its single top-level element.
pub fn to_der(input: &[u8]) -> Result<Vec<u8>, BerError> {
    let mut parser = Parser { input, pos: 0 };
    let node = parser.element(0)?;
    if parser.pos != input.len() {
        return Err(BerError::TrailingData { offset: parser.pos });
    }
    let mut out = Vec::with_capacity(node.encoded_len());
    node.write(input, &mut out);
    debug_assert_eq!(out.len(), node.encoded_len());
    Ok(out)
}

/// Parsed element; byte ranges point into the input.
struct Node {
    /// Identifier octets as in the input (rewritten to primitive for flattened strings).
    tag: Range<usize>,
    body: Body,
    /// Length of the normalized contents.
    content_len: usize,
}

enum Body {
    Primitive(Range<usize>),
    Constructed(Vec<Node>),
    /// Flattened constructed OCTET STRING: the concatenated segments.
    Octets(Vec<Range<usize>>),
    /// Flattened constructed BIT STRING: segments without their unused-bits octets, and the
    /// unused-bit count of the last segment.
    Bits {
        segments: Vec<Range<usize>>,
        unused: u8,
    },
}

impl Node {
    fn encoded_len(&self) -> usize {
        let tag_len = match self.body {
            Body::Octets(_) | Body::Bits { .. } => 1,
            _ => self.tag.len(),
        };
        tag_len + length_len(self.content_len) + self.content_len
    }

    fn write(&self, input: &[u8], out: &mut Vec<u8>) {
        match &self.body {
            Body::Octets(_) => out.push(OCTET_STRING),
            Body::Bits { .. } => out.push(BIT_STRING),
            _ => out.extend_from_slice(&input[self.tag.clone()]),
        }
        write_length(self.content_len, out);
        match &self.body {
            Body::Primitive(range) => out.extend_from_slice(&input[range.clone()]),
            Body::Constructed(children) => children.iter().for_each(|c| c.write(input, out)),
            Body::Octets(segments) => {
                segments
                    .iter()
                    .for_each(|s| out.extend_from_slice(&input[s.clone()]));
            }
            Body::Bits { segments, unused } => {
                out.push(*unused);
                segments
                    .iter()
                    .for_each(|s| out.extend_from_slice(&input[s.clone()]));
            }
        }
    }
}

enum Length {
    Definite(usize),
    Indefinite,
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn byte(&mut self) -> Result<u8, BerError> {
        let b = *self
            .input
            .get(self.pos)
            .ok_or(BerError::Truncated { offset: self.pos })?;
        self.pos += 1;
        Ok(b)
    }

    fn at_end_of_contents(&self) -> bool {
        self.input[self.pos..].starts_with(&[0, 0])
    }

    fn element(&mut self, depth: usize) -> Result<Node, BerError> {
        if depth > MAX_DEPTH {
            return Err(BerError::TooDeep);
        }
        let start = self.pos;
        let first = self.byte()?;
        if first & 0x1f == 0x1f {
            // High tag number: base-128 continuation octets.
            while self.byte()? & 0x80 != 0 {}
        }
        let tag = start..self.pos;
        let length = self.length()?;
        if first & CONSTRUCTED == 0 {
            let Length::Definite(len) = length else {
                return Err(BerError::Invalid {
                    offset: start,
                    reason: "indefinite length on a primitive element",
                });
            };
            if first == 0 && len == 0 {
                return Err(BerError::Invalid {
                    offset: start,
                    reason: "unexpected end-of-contents",
                });
            }
            let range = self.take(len)?;
            return Ok(Node {
                tag,
                body: Body::Primitive(range),
                content_len: len,
            });
        }

        let mut children = Vec::new();
        match length {
            Length::Definite(len) => {
                let end = self.pos.checked_add(len).filter(|&e| e <= self.input.len());
                let end = end.ok_or(BerError::Truncated {
                    offset: self.input.len(),
                })?;
                while self.pos < end {
                    let child = self.element(depth + 1)?;
                    if self.pos > end {
                        return Err(BerError::Invalid {
                            offset: start,
                            reason: "child element overruns its parent",
                        });
                    }
                    children.push(child);
                }
            }
            Length::Indefinite => loop {
                if self.pos >= self.input.len() {
                    return Err(BerError::Truncated { offset: self.pos });
                }
                if self.at_end_of_contents() {
                    self.pos += 2;
                    break;
                }
                children.push(self.element(depth + 1)?);
            },
        }

        match first {
            0x24 => flatten_octets(self.input, start, tag, children),
            0x23 => flatten_bits(self.input, start, tag, children),
            _ => {
                let content_len = children.iter().map(Node::encoded_len).sum();
                Ok(Node {
                    tag,
                    body: Body::Constructed(children),
                    content_len,
                })
            }
        }
    }

    fn length(&mut self) -> Result<Length, BerError> {
        let offset = self.pos;
        let first = self.byte()?;
        match first {
            0..=0x7f => Ok(Length::Definite(usize::from(first))),
            0x80 => Ok(Length::Indefinite),
            0xff => Err(BerError::Invalid {
                offset,
                reason: "reserved length octet 0xff",
            }),
            _ => {
                let mut len: usize = 0;
                for _ in 0..first & 0x7f {
                    let b = self.byte()?;
                    len = len.checked_mul(256).map(|l| l | usize::from(b)).ok_or(
                        BerError::Invalid {
                            offset,
                            reason: "length does not fit in memory",
                        },
                    )?;
                }
                Ok(Length::Definite(len))
            }
        }
    }

    fn take(&mut self, len: usize) -> Result<Range<usize>, BerError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&e| e <= self.input.len())
            .ok_or(BerError::Truncated {
                offset: self.input.len(),
            })?;
        let range = self.pos..end;
        self.pos = end;
        Ok(range)
    }
}

fn flatten_octets(
    input: &[u8],
    start: usize,
    tag: Range<usize>,
    children: Vec<Node>,
) -> Result<Node, BerError> {
    let mut segments = Vec::with_capacity(children.len());
    for child in children {
        match child.body {
            Body::Primitive(range) if input[child.tag.clone()] == [OCTET_STRING] => {
                segments.push(range);
            }
            Body::Octets(inner) => segments.extend(inner),
            _ => {
                return Err(BerError::Invalid {
                    offset: start,
                    reason: "constructed OCTET STRING segment is not an OCTET STRING",
                });
            }
        }
    }
    Ok(octets_node(tag, segments))
}

fn octets_node(tag: Range<usize>, segments: Vec<Range<usize>>) -> Node {
    let content_len = segments.iter().map(Range::len).sum();
    Node {
        tag,
        body: Body::Octets(segments),
        content_len,
    }
}

fn flatten_bits(
    input: &[u8],
    start: usize,
    tag: Range<usize>,
    children: Vec<Node>,
) -> Result<Node, BerError> {
    let invalid = |reason| BerError::Invalid {
        offset: start,
        reason,
    };
    let mut segments = Vec::with_capacity(children.len());
    let mut unused = 0u8;
    for child in children {
        if unused != 0 {
            return Err(invalid(
                "unused bits in a BIT STRING segment other than the last",
            ));
        }
        match child.body {
            Body::Primitive(range)
                if child.tag.len() == 1 && input[child.tag.start] == BIT_STRING =>
            {
                let Some(&bits) = input.get(range.start).filter(|_| !range.is_empty()) else {
                    return Err(invalid("BIT STRING segment without the unused-bits octet"));
                };
                if bits > 7 || (bits != 0 && range.len() == 1) {
                    return Err(invalid("invalid unused-bit count in a BIT STRING segment"));
                }
                unused = bits;
                segments.push(range.start + 1..range.end);
            }
            Body::Bits {
                segments: inner,
                unused: bits,
            } => {
                unused = bits;
                segments.extend(inner);
            }
            _ => {
                return Err(invalid(
                    "constructed BIT STRING segment is not a BIT STRING",
                ));
            }
        }
    }
    let content_len = 1 + segments.iter().map(Range::len).sum::<usize>();
    Ok(Node {
        tag,
        body: Body::Bits { segments, unused },
        content_len,
    })
}

/// Length of the minimal DER length octets for `len`.
fn length_len(len: usize) -> usize {
    if len < 0x80 {
        1
    } else {
        1 + (usize::BITS - len.leading_zeros()).div_ceil(8) as usize
    }
}

fn write_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let n = length_len(len) - 1;
    out.push(0x80 | n as u8);
    out.extend_from_slice(&len.to_be_bytes()[size_of::<usize>() - n..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_octets_are_minimal() {
        for (len, expected) in [
            (0usize, &[0x00][..]),
            (0x7f, &[0x7f]),
            (0x80, &[0x81, 0x80]),
            (0xff, &[0x81, 0xff]),
            (0x100, &[0x82, 0x01, 0x00]),
            (0x01_0000, &[0x83, 0x01, 0x00, 0x00]),
        ] {
            let mut out = Vec::new();
            write_length(len, &mut out);
            assert_eq!(out, expected, "{len:#x}");
            assert_eq!(length_len(len), expected.len());
        }
    }
}
