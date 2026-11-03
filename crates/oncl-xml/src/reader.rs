//! Bounded lexical replay of a frozen UTF-8 XML source. Text is validated byte by
//! byte and represented by a Region, never accumulated in a String.
use crate::index::XmlLimits;
use oncl_pki::{
    io::{CapturedInput, Region},
    resource::{IO_CHUNK_BYTES, OperationControl, ProcessingError, Progress},
};
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

type Result<T, E = ProcessingError> = std::result::Result<T, E>;
pub(crate) fn invalid() -> ProcessingError {
    ProcessingError::InvalidInput("invalid indexed XML")
}
fn xml_character(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

/// Expanded names are lending event metadata, not retainable SDK-owned copies.
/// ```compile_fail
/// fn escape(mut document: oncl_xml::XmlDocument) -> oncl_xml::XmlName {
///     let retained_name = {
///         let mut events = document.events();
///         events.next_event().unwrap().unwrap().attributes[0].name.clone()
///     };
///     drop(document);
///     retained_name
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct XmlName {
    namespace: Option<String>,
    local: String,
    pub(crate) qname: String,
}
impl XmlName {
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
    pub fn local(&self) -> &str {
        &self.local
    }
    pub(crate) fn into_parts(self) -> (Option<String>, String, String) {
        (self.namespace, self.local, self.qname)
    }
    // Only the bounded active frame/event pair needs an owning copy. It stays
    // inside the reader and is covered by the document's existing reservation.
    fn copy_for_frame(&self) -> Self {
        Self {
            namespace: self.namespace.clone(),
            local: self.local.clone(),
            qname: self.qname.clone(),
        }
    }
}
/// Attribute values are validated lexical spans, excluding quotes. In
/// particular a multi-gigabyte ordinary value never becomes a String. Namespace
/// and ID normalization is performed internally; X03 can normalize other values
/// while consuming their bounded raw replay.
///
/// Attribute metadata cannot be cloned out of a lending event:
/// ```compile_fail
/// fn escape(mut document: oncl_xml::XmlDocument) -> oncl_xml::XmlAttribute {
///     let retained = {
///         let mut events = document.events();
///         events.next_event().unwrap().unwrap().attributes[0].clone()
///     };
///     drop(document);
///     retained
/// }
/// ```
#[derive(Debug)]
pub struct XmlAttribute {
    pub name: XmlName,
    pub(crate) value: Region,
    pub(crate) owner: Weak<()>,
}
impl XmlAttribute {
    /// Retain only the opaque lexical span, not the expanded name metadata.
    pub fn span(&self) -> XmlAttributeSpan {
        XmlAttributeSpan {
            value: self.value,
            owner: self.owner.clone(),
        }
    }
    pub fn value_region(&self) -> Region {
        self.value
    }
}
/// A cheap owner-bound raw value handle. It owns no QName/namespace strings and
/// retains no document buffers, admission or resource reservation.
#[derive(Debug)]
pub struct XmlAttributeSpan {
    pub(crate) value: Region,
    pub(crate) owner: Weak<()>,
}
impl XmlAttributeSpan {
    pub fn value_region(&self) -> Region {
        self.value
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlEventKind {
    Start,
    End,
    Text,
    Comment,
    Cdata,
    ProcessingInstruction,
}
/// Namespace contexts are supplied at Start/End element boundaries only;
/// consumers maintain that scope for Text/Comment/Cdata/PI events, whose
/// namespaces field is empty. End events carry the complete element region;
/// other events carry their lexical region.
///
/// Namespace storage cannot be cloned into retained SDK metadata:
/// ```compile_fail
/// fn escape(mut document: oncl_xml::XmlDocument) -> Vec<(String, String)> {
///     let retained_context = {
///         let mut events = document.events();
///         events.next_event().unwrap().unwrap().namespaces.clone()
///     };
///     drop(document);
///     retained_context
/// }
/// ```
#[derive(Debug)]
pub struct XmlEvent {
    pub kind: XmlEventKind,
    pub region: Region,
    pub depth: usize,
    pub name: Option<XmlName>,
    /// Actual lexical closing tag; None for a self-closing element's synthetic end.
    pub(crate) closing_tag: Option<Region>,
    pub(crate) xml_declaration: bool,
    pub attributes: Vec<XmlAttribute>,
    namespaces: Vec<(String, String)>,
    pub(crate) ids: Vec<String>,
}
impl XmlEvent {
    /// Current bindings at an element boundary, borrowed from this lending
    /// event. The iterator and returned strings cannot outlive the event.
    pub fn namespaces(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.namespaces
            .iter()
            .map(|(prefix, uri)| (prefix.as_str(), uri.as_str()))
    }
    pub(crate) fn take_namespaces(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.namespaces)
    }
}
struct Frame {
    qname: String,
    name: XmlName,
    start: u64,
    ids: Vec<String>,
    changes: Vec<(String, Option<String>)>,
}
pub(crate) struct Reader<'a> {
    pub(crate) file: &'a mut dyn CapturedInput,
    limits: &'a XmlLimits,
    buffer: Vec<u8>,
    at: usize,
    count: usize,
    position: u64,
    stack: Vec<Frame>,
    namespaces: BTreeMap<String, String>,
    root: bool,
    bom: bool,
    prolog_bom: Option<Region>,
    pending: Option<XmlEvent>,
    work: u64,
    finished: bool,
    owner: Weak<()>,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(
        file: &'a mut dyn CapturedInput,
        limits: &'a XmlLimits,
        owner: &Arc<()>,
    ) -> Self {
        Self {
            file,
            limits,
            buffer: vec![0; IO_CHUNK_BYTES],
            at: 0,
            count: 0,
            position: 0,
            stack: Vec::new(),
            namespaces: BTreeMap::new(),
            root: false,
            bom: false,
            prolog_bom: None,
            pending: None,
            work: 0,
            finished: false,
            owner: Arc::downgrade(owner),
        }
    }
    fn peek(&mut self) -> Result<Option<u8>> {
        if self.at == self.count {
            if self.position == self.file.len() {
                return Ok(None);
            }
            self.count = self.file.read_region(
                Region {
                    offset: self.position,
                    len: self.file.len() - self.position,
                },
                &mut self.buffer,
            )?;
            self.at = 0;
        }
        Ok(Some(self.buffer[self.at]))
    }
    fn byte(&mut self) -> Result<Option<u8>> {
        let b = self.peek()?;
        if b.is_some() {
            self.at += 1;
            self.position += 1;
        }
        Ok(b)
    }
    fn required(&mut self) -> Result<u8> {
        self.byte()?.ok_or_else(invalid)
    }
    fn expect(&mut self, bytes: &[u8]) -> Result<()> {
        for b in bytes {
            if self.required()? != *b {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn region(&self, start: u64) -> Region {
        Region {
            offset: start,
            len: self.position - start,
        }
    }
    fn event(&self, kind: XmlEventKind, start: u64) -> XmlEvent {
        XmlEvent {
            kind,
            region: self.region(start),
            closing_tag: None,
            xml_declaration: false,
            depth: self.stack.len(),
            name: None,
            attributes: Vec::new(),
            namespaces: Vec::new(),
            ids: Vec::new(),
        }
    }
    fn character(&mut self, first: u8) -> Result<char> {
        let n = if first < 128 {
            1
        } else if first & 0xe0 == 0xc0 {
            2
        } else if first & 0xf0 == 0xe0 {
            3
        } else if first & 0xf8 == 0xf0 {
            4
        } else {
            return Err(invalid());
        };
        let mut bytes = [0; 4];
        bytes[0] = first;
        for b in &mut bytes[1..n] {
            *b = self.required()?;
        }
        let c = std::str::from_utf8(&bytes[..n])
            .map_err(|_| invalid())?
            .chars()
            .next()
            .ok_or_else(invalid)?;
        if !xml_character(c) {
            return Err(invalid());
        }
        Ok(c)
    }
    fn entity(&mut self) -> Result<([u8; 37], usize)> {
        // Preserve the existing bounded lexical reference length without an
        // allocation or miniature DOM per reference. Include ';' for callers
        // retaining namespace declaration bytes.
        let mut bytes = [0; 37];
        let mut len = 0;
        loop {
            let b = self.required()?;
            if !b.is_ascii() || len == bytes.len() {
                return Err(invalid());
            }
            bytes[len] = b;
            len += 1;
            if b == b';' {
                break;
            }
        }
        let body = &bytes[..len - 1];
        if !matches!(body, b"amp" | b"lt" | b"gt" | b"apos" | b"quot") {
            let (digits, radix) = if let Some(digits) = body.strip_prefix(b"#x") {
                (digits, 16u32)
            } else if let Some(digits) = body.strip_prefix(b"#") {
                (digits, 10u32)
            } else {
                return Err(invalid());
            };
            if digits.is_empty() {
                return Err(invalid());
            }
            let mut value = 0u32;
            for b in digits {
                let digit = match b {
                    b'0'..=b'9' => (b - b'0') as u32,
                    b'a'..=b'f' if radix == 16 => (b - b'a' + 10) as u32,
                    b'A'..=b'F' if radix == 16 => (b - b'A' + 10) as u32,
                    _ => return Err(invalid()),
                };
                value = value
                    .checked_mul(radix)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or_else(invalid)?;
            }
            if !char::from_u32(value).is_some_and(xml_character) {
                return Err(invalid());
            }
        }
        Ok((bytes, len))
    }
    fn delimited(&mut self, delimiter: &[u8], comment: bool) -> Result<()> {
        let mut repeated = 0usize;
        loop {
            let b = self.required()?;
            self.character(b)?;
            if repeated >= 2 {
                if b == delimiter[2] {
                    return Ok(());
                }
                if comment {
                    return Err(invalid());
                }
            }
            repeated = if b == delimiter[0] {
                (repeated + 1).min(2)
            } else {
                0
            };
        }
    }
    fn start_tag(&mut self, first: u8) -> Result<(Vec<u8>, Vec<Region>)> {
        let mut raw = Vec::with_capacity(self.limits.max_markup_bytes);
        raw.extend_from_slice(&[b'<', first]);
        let mut spans = Vec::with_capacity(self.limits.max_attributes);
        // QName and attribute syntax remain bounded. Only ordinary value bytes
        // are elided from this one-tag parser input; their exact spans survive.
        while let Some(b) = self.peek()? {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>') {
                break;
            }
            raw.push(self.required()?);
            if raw.len() > self.limits.max_name_bytes + 1 {
                return Err(ProcessingError::MetadataLimit);
            }
        }
        let mut count = 0;
        loop {
            let mut spaced = false;
            while self
                .peek()?
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                self.required()?;
                spaced = true;
            }
            let b = self.required()?;
            if b == b'>' {
                raw.push(b);
                break;
            }
            if b == b'/' {
                self.expect(b">")?;
                raw.extend_from_slice(b"/>");
                break;
            }
            if !spaced {
                return Err(invalid());
            }
            count += 1;
            if count > self.limits.max_attributes {
                return Err(ProcessingError::MetadataLimit);
            }
            let mut name = vec![b];
            while let Some(b) = self.peek()? {
                if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'=') {
                    break;
                }
                name.push(self.required()?);
                if name.len() > self.limits.max_name_bytes {
                    return Err(ProcessingError::MetadataLimit);
                }
            }
            let name = std::str::from_utf8(&name).map_err(|_| invalid())?;
            if name.ends_with(":xmlns") {
                return Err(invalid());
            }
            let namespace = name == "xmlns" || name.starts_with("xmlns:");
            while self
                .peek()?
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                self.required()?;
            }
            self.expect(b"=")?;
            while self
                .peek()?
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                self.required()?;
            }
            let quote = self.required()?;
            if !matches!(quote, b'\'' | b'"') {
                return Err(invalid());
            }
            raw.push(b' ');
            raw.extend_from_slice(name.as_bytes());
            raw.push(b'=');
            raw.push(quote);
            let start = self.position;
            loop {
                let b = self.required()?;
                if b == quote {
                    break;
                }
                if b == b'<' {
                    return Err(invalid());
                }
                if b == b'&' {
                    let (entity, len) = self.entity()?;
                    if namespace {
                        raw.push(b'&');
                        raw.extend_from_slice(&entity[..len]);
                    }
                } else {
                    let c = self.character(b)?;
                    if namespace {
                        let mut encoded = [0; 4];
                        raw.extend_from_slice(c.encode_utf8(&mut encoded).as_bytes());
                    }
                }
                if raw.len() >= self.limits.max_markup_bytes {
                    return Err(ProcessingError::MetadataLimit);
                }
            }
            if !namespace {
                spans.push(Region {
                    offset: start,
                    len: self.position - start - 1,
                });
            }
            raw.push(quote);
            if raw.len() >= self.limits.max_markup_bytes {
                return Err(ProcessingError::MetadataLimit);
            }
        }
        Ok((raw, spans))
    }
    fn normalized_id(&mut self, span: Region) -> Result<String> {
        if span.len > self.limits.max_markup_bytes as u64 {
            return Err(ProcessingError::MetadataLimit);
        }
        let mut quote = [0];
        self.file.read_region(
            Region {
                offset: span.offset.checked_sub(1).ok_or_else(invalid)?,
                len: 1,
            },
            &mut quote,
        )?;
        let mut bytes = vec![0; span.len as usize];
        self.file.read_region(span, &mut bytes)?;
        let raw = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        let quote = quote[0] as char;
        let wrapped = format!("<r v={quote}{raw}{quote}/>");
        let doc = roxmltree::Document::parse(&wrapped).map_err(|_| invalid())?;
        Ok(doc
            .root_element()
            .attribute("v")
            .ok_or_else(invalid)?
            .to_owned())
    }
    fn markup(&mut self, start: u64, first: u8) -> Result<XmlEvent> {
        if first == b'!' {
            match self.required()? {
                b'-' => {
                    self.expect(b"-")?;
                    self.delimited(b"-->", true)?;
                    return Ok(self.event(XmlEventKind::Comment, start));
                }
                b'[' => {
                    if self.stack.is_empty() {
                        return Err(invalid());
                    }
                    self.expect(b"CDATA[")?;
                    self.delimited(b"]]>", false)?;
                    return Ok(self.event(XmlEventKind::Cdata, start));
                }
                _ => {
                    return Err(ProcessingError::InvalidInput(
                        "DTD and declarations are forbidden",
                    ));
                }
            }
        }
        let (raw, spans) = if first == b'?' || first == b'/' {
            let mut raw = Vec::with_capacity(self.limits.max_markup_bytes);
            raw.extend_from_slice(&[b'<', first]);
            loop {
                let b = self.required()?;
                if raw.len() == self.limits.max_markup_bytes {
                    return Err(ProcessingError::MetadataLimit);
                }
                raw.push(b);
                if b == b'>' && (first != b'?' || raw.get(raw.len() - 2) == Some(&b'?')) {
                    break;
                }
            }
            (raw, Vec::new())
        } else {
            self.start_tag(first)?
        };
        let raw = std::str::from_utf8(&raw).map_err(|_| invalid())?;
        if first == b'?' {
            let declaration = raw.starts_with("<?xml ")
                || raw.starts_with("<?xml\t")
                || raw.starts_with("<?xml\r")
                || raw.starts_with("<?xml\n");
            if declaration && start != 0 && !(self.bom && start == 3) {
                return Err(invalid());
            }
            let wrapped = if declaration {
                format!("{raw}<r/>")
            } else {
                format!("<r>{raw}</r>")
            };
            roxmltree::Document::parse(&wrapped).map_err(|_| invalid())?;
            if declaration {
                // roxmltree consumes &str and deliberately ignores the encoding
                // pseudo-attribute. Our frozen byte-source contract is UTF-8,
                // so do not let a conflicting declaration survive replay.
                let element = format!("<{}/>", &raw[2..raw.len() - 2]);
                let declaration = roxmltree::Document::parse(&element).map_err(|_| invalid())?;
                if declaration
                    .root_element()
                    .attribute("encoding")
                    .is_some_and(|encoding| !encoding.eq_ignore_ascii_case("UTF-8"))
                {
                    return Err(ProcessingError::InvalidInput("indexed XML requires UTF-8"));
                }
            }
            let mut event = self.event(XmlEventKind::ProcessingInstruction, start);
            event.xml_declaration = declaration;
            return Ok(event);
        }
        if first == b'/' {
            let name = raw[2..raw.len() - 1].trim_end_matches([' ', '\t', '\r', '\n']);
            let frame = self.stack.pop().ok_or_else(invalid)?;
            if frame.qname != name {
                return Err(invalid());
            }
            let mut event = self.event(XmlEventKind::End, frame.start);
            event.closing_tag = Some(self.region(start));
            event.name = Some(frame.name);
            event.ids = frame.ids;
            event.namespaces = self
                .namespaces
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (key, old) in frame.changes {
                if let Some(v) = old {
                    self.namespaces.insert(key, v);
                } else {
                    self.namespaces.remove(&key);
                }
            }
            return Ok(event);
        }
        if self.stack.len() >= self.limits.max_depth || (self.stack.is_empty() && self.root) {
            return Err(invalid());
        }
        let count = check_attributes(raw, self.limits)?;
        self.work = self
            .work
            .checked_add(
                ((count + 1) * (count + 1)
                    + (self.namespaces.len() + 1) * (count + self.namespaces.len() + 1))
                    as u64,
            )
            .ok_or_else(invalid)?;
        if self.work > self.limits.max_work {
            return Err(ProcessingError::MetadataLimit);
        }
        let mut wrapped = String::from("<__oncl");
        for (prefix, uri) in &self.namespaces {
            if prefix.is_empty() {
                wrapped.push_str(" xmlns=\"");
            } else {
                wrapped.push_str(" xmlns:");
                wrapped.push_str(prefix);
                wrapped.push_str("=\"");
            }
            escape(uri, &mut wrapped);
            wrapped.push('"');
        }
        wrapped.push('>');
        let empty = raw.ends_with("/>");
        if empty {
            wrapped.push_str(raw);
        } else {
            wrapped.push_str(&raw[..raw.len() - 1]);
            wrapped.push_str("/>");
        }
        wrapped.push_str("</__oncl>");
        let doc = roxmltree::Document::parse(&wrapped).map_err(|_| invalid())?;
        let node = doc
            .root_element()
            .first_element_child()
            .ok_or_else(invalid)?;
        let qname = raw[1..]
            .split([' ', '\t', '\r', '\n', '/', '>'])
            .next()
            .ok_or_else(invalid)?
            .to_owned();
        if qname.len() > self.limits.max_name_bytes {
            return Err(ProcessingError::MetadataLimit);
        }
        let name = XmlName {
            namespace: node
                .tag_name()
                .namespace()
                .filter(|ns| !ns.is_empty())
                .map(str::to_owned),
            local: node.tag_name().name().to_owned(),
            qname: qname.clone(),
        };
        let mut attributes = Vec::new();
        let mut ids = Vec::new();
        for (i, a) in node.attributes().enumerate() {
            if a.name().len() > self.limits.max_name_bytes || a.name() == "xmlns" {
                return Err(invalid());
            }
            if (a.namespace().is_none() && matches!(a.name(), "Id" | "ID" | "id"))
                || (a.namespace() == Some("http://www.w3.org/XML/1998/namespace")
                    && a.name() == "id")
                || (a.namespace()
                    == Some(
                        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                    )
                    && a.name() == "Id")
            {
                let value = self.normalized_id(*spans.get(i).ok_or_else(invalid)?)?;
                let value = if a.namespace() == Some("http://www.w3.org/XML/1998/namespace") {
                    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
                } else {
                    value
                };
                if value.len() > self.limits.max_id_bytes || value.is_empty() {
                    return Err(invalid());
                }
                ids.push(value);
            }
            attributes.push(XmlAttribute {
                name: XmlName {
                    namespace: a.namespace().filter(|ns| !ns.is_empty()).map(str::to_owned),
                    local: a.name().to_owned(),
                    qname: wrapped[a.range_qname()].to_owned(),
                },
                value: *spans.get(i).ok_or_else(invalid)?,
                owner: self.owner.clone(),
            });
        }
        if ids.iter().map(String::len).sum::<usize>() > self.limits.max_markup_bytes {
            return Err(ProcessingError::MetadataLimit);
        }
        let namespaces: Vec<_> = node
            .namespaces()
            .map(|ns| (ns.name().unwrap_or("").to_owned(), ns.uri().to_owned()))
            .collect();
        if namespaces.len() > self.limits.max_namespaces
            || namespaces
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > self.limits.max_namespace_bytes
        {
            return Err(ProcessingError::MetadataLimit);
        }
        let mut changes = Vec::new();
        for (key, value) in &namespaces {
            if self.namespaces.get(key) != Some(value) {
                changes.push((
                    key.clone(),
                    self.namespaces.insert(key.clone(), value.clone()),
                ));
            }
        }
        self.root = true;
        self.stack.push(Frame {
            qname,
            name: name.copy_for_frame(),
            start,
            ids,
            changes,
        });
        let mut event = self.event(XmlEventKind::Start, start);
        event.depth -= 1;
        event.name = Some(name);
        event.attributes = attributes;
        event.namespaces = namespaces;
        if empty {
            let frame = self.stack.pop().ok_or_else(invalid)?;
            let mut end = self.event(XmlEventKind::End, start);
            end.name = Some(frame.name);
            end.ids = frame.ids;
            end.namespaces = event.namespaces.clone();
            for (key, old) in frame.changes {
                if let Some(v) = old {
                    self.namespaces.insert(key, v);
                } else {
                    self.namespaces.remove(&key);
                }
            }
            self.pending = Some(end);
        }
        Ok(event)
    }
    pub(crate) fn next(&mut self) -> Result<Option<XmlEvent>> {
        if let Some(event) = self.pending.take() {
            return Ok(Some(event));
        }
        if self.finished {
            return Ok(None);
        }
        let start = self.position;
        let Some(b) = self.byte()? else {
            self.finished = true;
            if !self.root || !self.stack.is_empty() {
                return Err(invalid());
            }
            return Ok(None);
        };
        if b == b'<' {
            let first = self.required()?;
            return self.markup(start, first).map(Some);
        }
        if start == 0 && b == 0xef {
            self.expect(&[0xbb, 0xbf])?;
            self.bom = true;
            self.prolog_bom = Some(self.region(start));
            return self.next();
        }
        let mut current = b;
        let mut brackets = 0;
        loop {
            if current == b'&' {
                if self.stack.is_empty() {
                    return Err(invalid());
                }
                self.entity()?;
                brackets = 0;
            } else {
                let c = self.character(current)?;
                if self.stack.is_empty() && !matches!(c, ' ' | '\t' | '\r' | '\n') {
                    return Err(invalid());
                }
                if c == '>' && brackets >= 2 {
                    return Err(invalid());
                }
                brackets = if c == ']' { (brackets + 1).min(2) } else { 0 };
            }
            match self.peek()? {
                Some(b'<') | None => break,
                Some(_) => current = self.required()?,
            }
        }
        Ok(Some(self.event(XmlEventKind::Text, start)))
    }
    pub(crate) fn bom_region(&self) -> Option<Region> {
        self.prolog_bom
    }
}
// Bound parser's quadratic attribute checks before constructing the one-tag
// tree. '=' inside quoted data is data, not another attribute.
fn check_attributes(raw: &str, limits: &XmlLimits) -> Result<usize> {
    let b = raw.as_bytes();
    let space = |c| matches!(c, b' ' | b'\t' | b'\r' | b'\n');
    let mut at = 1;
    while at < b.len() && !space(b[at]) && !matches!(b[at], b'/' | b'>') {
        at += 1;
    }
    if at - 1 > limits.max_name_bytes {
        return Err(ProcessingError::MetadataLimit);
    }
    let mut count = 0;
    loop {
        let before = at;
        while at < b.len() && space(b[at]) {
            at += 1;
        }
        if at == b.len() || matches!(b[at], b'/' | b'>') {
            return Ok(count);
        }
        if before == at {
            return Err(invalid());
        }
        let start = at;
        while at < b.len() && !space(b[at]) && !matches!(b[at], b'=' | b'/' | b'>') {
            at += 1;
        }
        if at - start > limits.max_name_bytes {
            return Err(ProcessingError::MetadataLimit);
        }
        if raw[start..at].ends_with(":xmlns") {
            return Err(invalid());
        }
        while at < b.len() && space(b[at]) {
            at += 1;
        }
        if b.get(at) != Some(&b'=') {
            return Err(invalid());
        }
        at += 1;
        while at < b.len() && space(b[at]) {
            at += 1;
        }
        let quote = *b.get(at).ok_or_else(invalid)?;
        if !matches!(quote, b'\'' | b'"') {
            return Err(invalid());
        }
        at += 1;
        while at < b.len() && b[at] != quote {
            at += 1;
        }
        if at == b.len() {
            return Err(invalid());
        }
        at += 1;
        count += 1;
        if count > limits.max_attributes {
            return Err(ProcessingError::MetadataLimit);
        }
    }
}
fn escape(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            _ => out.push(c),
        }
    }
}
/// Lending replay cursor: metadata cannot accumulate or outlive the document.
/// The next token invalidates the preceding borrow, retaining one bounded event.
pub struct XmlEvents<'a> {
    pub(crate) reader: Reader<'a>,
    pub(crate) current: Option<XmlEvent>,
    pub(crate) control: Arc<dyn OperationControl>,
}
impl XmlEvents<'_> {
    pub fn next_event(&mut self) -> Result<Option<&XmlEvent>> {
        self.control.checkpoint(Progress::default())?;
        self.current = None;
        self.current = self.reader.next()?;
        Ok(self.current.as_ref())
    }
}
