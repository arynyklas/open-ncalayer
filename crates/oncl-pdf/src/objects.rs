use crate::{PdfError, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) enum Value {
    Int(u64),
    Name(Vec<u8>),
    Bytes(Vec<u8>, std::ops::Range<u64>),
    Array(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
    Ref(u32, u16),
    Other,
}
impl Value {
    pub fn int(&self) -> Result<u64> {
        if let Self::Int(n) = self {
            Ok(*n)
        } else {
            Err(PdfError::Malformed("expected nonnegative integer"))
        }
    }
    pub fn dict(&self) -> Result<&BTreeMap<Vec<u8>, Value>> {
        if let Self::Dict(n) = self {
            Ok(n)
        } else {
            Err(PdfError::Malformed("expected dictionary"))
        }
    }
    pub fn array(&self) -> Result<&[Value]> {
        if let Self::Array(n) = self {
            Ok(n)
        } else {
            Err(PdfError::Malformed("expected array"))
        }
    }
    pub fn name(&self, expected: &[u8]) -> bool {
        matches!(self, Self::Name(n) if n == expected)
    }
}
pub(crate) fn get<'a>(dict: &'a BTreeMap<Vec<u8>, Value>, key: &[u8]) -> Result<&'a Value> {
    dict.get(key)
        .ok_or(PdfError::Malformed("missing dictionary entry"))
}
pub(crate) fn white(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}
fn delimiter(b: u8) -> bool {
    white(b) || b"()<>[]{}/%".contains(&b)
}
pub(crate) struct Parser<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
    pub base: u64,
    pub nodes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
}
impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8], base: u64, max_nodes: usize, max_depth: usize) -> Self {
        Self {
            bytes,
            pos: 0,
            base,
            nodes: 0,
            max_nodes,
            max_depth,
        }
    }
    pub fn ws(&mut self) {
        loop {
            while self.pos < self.bytes.len() && white(self.bytes[self.pos]) {
                self.pos += 1;
            }
            if self.bytes.get(self.pos) == Some(&b'%') {
                while self.pos < self.bytes.len() && !b"\r\n".contains(&self.bytes[self.pos]) {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }
    pub fn word(&mut self) -> Result<&'a [u8]> {
        self.ws();
        let start = self.pos;
        while self.pos < self.bytes.len() && !delimiter(self.bytes[self.pos]) {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(PdfError::Malformed("expected PDF token"));
        }
        Ok(&self.bytes[start..self.pos])
    }
    pub fn integer(&mut self) -> Result<u64> {
        number(self.word()?)
    }
    pub fn expect(&mut self, word: &[u8]) -> Result<()> {
        if self.word()? == word {
            Ok(())
        } else {
            Err(PdfError::Malformed("unexpected PDF token"))
        }
    }
    pub fn value(&mut self, depth: usize) -> Result<Value> {
        self.nodes += 1;
        if depth > self.max_depth || self.nodes > self.max_nodes {
            return Err(PdfError::Limit("object complexity"));
        }
        self.ws();
        let start = self.pos;
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or(PdfError::Malformed("truncated object"))?;
        match b {
            b'<' if self.bytes.get(self.pos + 1) == Some(&b'<') => {
                self.pos += 2;
                let mut map = BTreeMap::new();
                loop {
                    self.ws();
                    if self.bytes.get(self.pos..self.pos + 2) == Some(b">>") {
                        self.pos += 2;
                        break;
                    }
                    let Value::Name(key) = self.value(depth + 1)? else {
                        return Err(PdfError::Malformed("dictionary key"));
                    };
                    let value = self.value(depth + 1)?;
                    if map.insert(key, value).is_some() {
                        return Err(PdfError::Malformed("duplicate dictionary key"));
                    }
                }
                Ok(Value::Dict(map))
            }
            b'[' => {
                self.pos += 1;
                let mut values = Vec::new();
                loop {
                    self.ws();
                    if self.bytes.get(self.pos) == Some(&b']') {
                        self.pos += 1;
                        break;
                    }
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            b'/' => {
                self.pos += 1;
                let mut name = Vec::new();
                while self.pos < self.bytes.len() && !delimiter(self.bytes[self.pos]) {
                    let b = self.bytes[self.pos];
                    self.pos += 1;
                    if b == b'#' {
                        let a = *self
                            .bytes
                            .get(self.pos)
                            .ok_or(PdfError::Malformed("name escape"))?;
                        let b = *self
                            .bytes
                            .get(self.pos + 1)
                            .ok_or(PdfError::Malformed("name escape"))?;
                        name.push(hex(a)? * 16 + hex(b)?);
                        self.pos += 2;
                    } else {
                        name.push(b);
                    }
                }
                Ok(Value::Name(name))
            }
            b'<' | b'(' => {
                let mut bytes = Vec::new();
                let consumed =
                    oncl_pki::io::decode_pdf_byte_string(&self.bytes[self.pos..], &mut bytes)?;
                self.pos += consumed;
                Ok(Value::Bytes(
                    bytes,
                    self.base + start as u64..self.base + self.pos as u64,
                ))
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                let token = self.word()?;
                let body = if matches!(token.first(), Some(b'+' | b'-')) {
                    &token[1..]
                } else {
                    token
                };
                if body.is_empty()
                    || body.iter().any(|b| !b.is_ascii_digit() && *b != b'.')
                    || body.iter().filter(|b| **b == b'.').count() > 1
                    || !body.iter().any(u8::is_ascii_digit)
                {
                    return Err(PdfError::Malformed("PDF number"));
                }
                if body.contains(&b'.') || token.first() == Some(&b'-') {
                    return Ok(Value::Other);
                }
                let n = number(body)?;
                let after = self.pos;
                let reference = (|| {
                    let generation = self.integer()?;
                    self.expect(b"R")?;
                    Ok::<_, PdfError>((
                        u32::try_from(n).map_err(|_| PdfError::Malformed("object id"))?,
                        u16::try_from(generation).map_err(|_| PdfError::Malformed("generation"))?,
                    ))
                })();
                if let Ok((id, generation)) = reference {
                    Ok(Value::Ref(id, generation))
                } else {
                    self.pos = after;
                    Ok(Value::Int(n))
                }
            }
            _ => match self.word()? {
                b"true" | b"false" | b"null" => Ok(Value::Other),
                _ => Err(PdfError::Unsupported("PDF scalar token")),
            },
        }
    }
}
pub(crate) fn number(bytes: &[u8]) -> Result<u64> {
    let bytes = bytes.strip_prefix(b"+").unwrap_or(bytes);
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(PdfError::Malformed("nonnegative integer required"));
    }
    bytes.iter().try_fold(0u64, |n, b| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))
            .ok_or(PdfError::Malformed("integer overflow"))
    })
}
fn hex(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(PdfError::Malformed("hex digit")),
    }
}
