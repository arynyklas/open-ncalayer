//! Just enough PDF to append pages to a document: its objects read through its
//! cross-reference sections (tables or streams, object streams included), new objects
//! written, and an incremental update that adds them and puts the new pages at the end of
//! the page tree. The document's own bytes stay as they are.

use flate2::read::ZlibDecoder;
use std::collections::BTreeMap;
use std::io::Read;

/// The largest stream the reader inflates.
const MAX_INFLATED: u64 = 64 << 20;

/// The most cross-reference sections the reader follows.
const MAX_SECTIONS: usize = 1024;

/// A PDF object.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Obj {
    Null,
    Bool(bool),
    Int(i64),
    /// A real number, as written.
    Real(String),
    /// A name, without the slash, its `#xx` escapes decoded.
    Name(Vec<u8>),
    /// A string's bytes.
    Str(Vec<u8>),
    Array(Vec<Obj>),
    Dict(Dict),
    Ref(u32, u16),
    Stream(Dict, Vec<u8>),
}

/// A dictionary, its entries in order.
pub(crate) type Dict = Vec<(Vec<u8>, Obj)>;

/// The value of `key` in `dict`.
pub(crate) fn get<'d>(dict: &'d Dict, key: &str) -> Option<&'d Obj> {
    dict.iter()
        .find(|(k, _)| k == key.as_bytes())
        .map(|(_, v)| v)
}

/// Sets `key` of `dict` to `value`, in its place or at the end.
pub(crate) fn set(dict: &mut Dict, key: &str, value: Obj) {
    match dict.iter_mut().find(|(k, _)| k == key.as_bytes()) {
        Some(entry) => entry.1 = value,
        None => dict.push((key.as_bytes().to_vec(), value)),
    }
}

/// A name object.
pub(crate) fn name(text: &str) -> Obj {
    Obj::Name(text.as_bytes().to_vec())
}

impl Obj {
    /// The object as PDF syntax.
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        match self {
            Obj::Null => out.extend(b"null"),
            Obj::Bool(b) => out.extend(if *b { &b"true"[..] } else { b"false" }),
            Obj::Int(i) => out.extend(i.to_string().as_bytes()),
            Obj::Real(r) => out.extend(r.as_bytes()),
            Obj::Name(n) => {
                out.push(b'/');
                for &b in n {
                    if b.is_ascii_graphic() && !b"()<>[]{}/%#".contains(&b) {
                        out.push(b);
                    } else {
                        out.extend(format!("#{b:02X}").as_bytes());
                    }
                }
            }
            Obj::Str(s) => {
                out.push(b'<');
                for b in s {
                    out.extend(format!("{b:02X}").as_bytes());
                }
                out.push(b'>');
            }
            Obj::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b' ');
                    }
                    item.write(out);
                }
                out.push(b']');
            }
            Obj::Dict(dict) => write_dict(dict, out),
            Obj::Ref(num, generation) => out.extend(format!("{num} {generation} R").as_bytes()),
            Obj::Stream(dict, data) => {
                let mut dict = dict.clone();
                set(&mut dict, "Length", Obj::Int(data.len() as i64));
                write_dict(&dict, out);
                out.extend(b"\nstream\n");
                out.extend(data);
                out.extend(b"\nendstream");
            }
        }
    }
}

fn write_dict(dict: &Dict, out: &mut Vec<u8>) {
    out.extend(b"<<");
    for (key, value) in dict {
        Obj::Name(key.clone()).write(out);
        out.push(b' ');
        value.write(out);
    }
    out.extend(b">>");
}

/// Why a document cannot be read or extended.
pub(crate) type Error = &'static str;

/// The lexer and parser of PDF objects.
struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

fn is_white(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_delimiter(b: u8) -> bool {
    b"()<>[]{}/%".contains(&b)
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8], pos: usize) -> Parser<'a> {
        Parser { data, pos }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn skip_space(&mut self) {
        while let Some(b) = self.peek() {
            if is_white(b) {
                self.pos += 1;
            } else if b == b'%' {
                while let Some(b) = self.peek() {
                    if b == b'\n' || b == b'\r' {
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    /// A run of regular characters.
    fn word(&mut self) -> &'a [u8] {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if is_white(b) || is_delimiter(b) {
                break;
            }
            self.pos += 1;
        }
        &self.data[start..self.pos]
    }

    fn keyword(&mut self, word: &[u8]) -> bool {
        self.skip_space();
        let save = self.pos;
        if self.word() == word {
            true
        } else {
            self.pos = save;
            false
        }
    }

    /// An unsigned integer, if the next word is one.
    fn uint(&mut self) -> Option<u64> {
        self.skip_space();
        let save = self.pos;
        let word = self.word();
        match std::str::from_utf8(word).ok().and_then(|w| w.parse().ok()) {
            Some(n) if !word.is_empty() && word.iter().all(u8::is_ascii_digit) => Some(n),
            _ => {
                self.pos = save;
                None
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Obj, Error> {
        if depth > 64 {
            return Err("nested too deep");
        }
        self.skip_space();
        let b = self.peek().ok_or("unexpected end")?;
        match b {
            b'/' => {
                self.pos += 1;
                let raw = self.word();
                Ok(Obj::Name(unescape_name(raw)))
            }
            b'(' => self.literal().map(Obj::Str),
            b'<' if self.data.get(self.pos + 1) == Some(&b'<') => {
                self.pos += 2;
                let dict = self.dict_body(depth)?;
                let save = self.pos;
                if self.keyword(b"stream") {
                    let data = self.stream_data(&dict)?;
                    return Ok(Obj::Stream(dict, data));
                }
                self.pos = save;
                Ok(Obj::Dict(dict))
            }
            b'<' => self.hex().map(Obj::Str),
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_space();
                    match self.peek() {
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Obj::Array(items));
                        }
                        None => return Err("unterminated array"),
                        _ => items.push(self.object(depth + 1)?),
                    }
                }
            }
            _ => {
                let save = self.pos;
                if let Some(num) = self.uint() {
                    let after = self.pos;
                    if let Some(generation) = self.uint()
                        && self.keyword(b"R")
                    {
                        return Ok(Obj::Ref(
                            u32::try_from(num).map_err(|_| "bad reference")?,
                            u16::try_from(generation).map_err(|_| "bad reference")?,
                        ));
                    }
                    self.pos = after;
                    return Ok(Obj::Int(i64::try_from(num).map_err(|_| "bad number")?));
                }
                self.pos = save;
                let word = self.word();
                match word {
                    b"null" => Ok(Obj::Null),
                    b"true" => Ok(Obj::Bool(true)),
                    b"false" => Ok(Obj::Bool(false)),
                    _ => {
                        let text = std::str::from_utf8(word).map_err(|_| "bad token")?;
                        if text.is_empty() {
                            return Err("bad token");
                        }
                        if let Ok(i) = text.parse::<i64>() {
                            Ok(Obj::Int(i))
                        } else if text.parse::<f64>().is_ok() || text.starts_with('.') {
                            Ok(Obj::Real(text.to_owned()))
                        } else {
                            Err("bad token")
                        }
                    }
                }
            }
        }
    }

    fn dict_body(&mut self, depth: usize) -> Result<Dict, Error> {
        let mut dict = Vec::new();
        loop {
            self.skip_space();
            match self.peek() {
                Some(b'>') if self.data.get(self.pos + 1) == Some(&b'>') => {
                    self.pos += 2;
                    return Ok(dict);
                }
                Some(b'/') => {
                    let Obj::Name(key) = self.object(depth + 1)? else {
                        unreachable!("a slash starts a name")
                    };
                    let value = self.object(depth + 1)?;
                    dict.push((key, value));
                }
                _ => return Err("bad dictionary"),
            }
        }
    }

    fn literal(&mut self) -> Result<Vec<u8>, Error> {
        self.pos += 1;
        let mut out = Vec::new();
        let mut nesting = 0;
        loop {
            let b = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match b {
                b'(' => {
                    nesting += 1;
                    out.push(b);
                }
                b')' if nesting == 0 => return Ok(out),
                b')' => {
                    nesting -= 1;
                    out.push(b);
                }
                b'\\' => {
                    let e = self.peek().ok_or("unterminated string")?;
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(0x0c),
                        b'0'..=b'7' => {
                            let mut value = u32::from(e - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(d - b'0');
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(value as u8);
                        }
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        other => out.push(other),
                    }
                }
                _ => out.push(b),
            }
        }
    }

    fn hex(&mut self) -> Result<Vec<u8>, Error> {
        self.pos += 1;
        let mut digits = Vec::new();
        loop {
            let b = self.peek().ok_or("unterminated hex string")?;
            self.pos += 1;
            match b {
                b'>' => break,
                b if b.is_ascii_hexdigit() => digits.push(hex_value(b)),
                b if is_white(b) => {}
                _ => return Err("bad hex string"),
            }
        }
        if digits.len() % 2 == 1 {
            digits.push(0);
        }
        Ok(digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect())
    }

    /// The data of a stream whose dictionary is `dict`, after `stream`; a `Length` that is
    /// a reference is not resolved here: the data then runs to `endstream`.
    fn stream_data(&mut self, dict: &Dict) -> Result<Vec<u8>, Error> {
        // `stream` is followed by CRLF or LF.
        if self.peek() == Some(b'\r') {
            self.pos += 1;
        }
        if self.peek() == Some(b'\n') {
            self.pos += 1;
        }
        let start = self.pos;
        let direct = match get(dict, "Length") {
            Some(Obj::Int(len)) => usize::try_from(*len).ok(),
            _ => None,
        };
        if let Some(len) = direct
            && let Some(end) = start.checked_add(len)
            && end <= self.data.len()
        {
            let mut after = Parser::new(self.data, end);
            if after.keyword(b"endstream") {
                self.pos = after.pos;
                return Ok(self.data[start..end].to_vec());
            }
        }
        // Else up to `endstream`, without the end of line before it.
        let at = find(&self.data[start..], b"endstream").ok_or("unterminated stream")?;
        let mut end = start + at;
        if end > start && self.data[end - 1] == b'\n' {
            end -= 1;
        }
        if end > start && self.data[end - 1] == b'\r' {
            end -= 1;
        }
        self.pos = start + at + b"endstream".len();
        Ok(self.data[start..end].to_vec())
    }
}

fn hex_value(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

fn unescape_name(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#'
            && i + 2 < raw.len()
            && raw[i + 1].is_ascii_hexdigit()
            && raw[i + 2].is_ascii_hexdigit()
        {
            out.push(hex_value(raw[i + 1]) << 4 | hex_value(raw[i + 2]));
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Where an object is.
#[derive(Debug, Clone, Copy)]
enum Entry {
    Free,
    At(usize),
    /// In this object stream.
    InStream(u32),
}

/// A document read through its cross-reference sections.
pub(crate) struct Document<'a> {
    data: &'a [u8],
    entries: BTreeMap<u32, (Entry, u16)>,
    /// The newest trailer (or cross-reference stream dictionary).
    pub(crate) trailer: Dict,
    /// Where the newest cross-reference section starts.
    pub(crate) startxref: usize,
    /// Whether the newest section is a stream.
    pub(crate) xref_stream: bool,
}

impl<'a> Document<'a> {
    /// Reads the cross-reference sections of `data`.
    pub(crate) fn read(data: &'a [u8]) -> Result<Document<'a>, Error> {
        if find(&data[..data.len().min(1024)], b"%PDF-").is_none() {
            return Err("not a PDF");
        }
        let tail_from = data.len().saturating_sub(4096);
        let at = rfind(&data[tail_from..], b"startxref").ok_or("no startxref")? + tail_from;
        let mut parser = Parser::new(data, at + b"startxref".len());
        let startxref = parser.uint().ok_or("bad startxref")? as usize;
        let mut doc = Document {
            data,
            entries: BTreeMap::new(),
            trailer: Vec::new(),
            startxref,
            xref_stream: false,
        };
        let mut next = Some(startxref);
        let mut seen = Vec::new();
        let mut first = true;
        while let Some(offset) = next {
            if seen.contains(&offset) || seen.len() >= MAX_SECTIONS {
                return Err("cross-reference loop");
            }
            seen.push(offset);
            let (trailer, is_stream) = doc.section(offset)?;
            if first {
                doc.trailer = trailer.clone();
                doc.xref_stream = is_stream;
                first = false;
            }
            // A hybrid file's table names a stream with the objects only it lists.
            if let Some(Obj::Int(stream)) = get(&trailer, "XRefStm") {
                let stream = usize::try_from(*stream).map_err(|_| "bad XRefStm")?;
                if !seen.contains(&stream) {
                    seen.push(stream);
                    doc.section(stream)?;
                }
            }
            next = match get(&trailer, "Prev") {
                Some(Obj::Int(prev)) => Some(usize::try_from(*prev).map_err(|_| "bad Prev")?),
                _ => None,
            };
        }
        if get(&doc.trailer, "Encrypt").is_some() {
            return Err("encrypted");
        }
        Ok(doc)
    }

    /// Reads the section at `offset` into the entries not read yet: its trailer, and whether
    /// it is a stream.
    fn section(&mut self, offset: usize) -> Result<(Dict, bool), Error> {
        let mut parser = Parser::new(self.data, offset);
        if parser.keyword(b"xref") {
            loop {
                let save = parser.pos;
                let (Some(start), Some(count)) = (parser.uint(), parser.uint()) else {
                    parser.pos = save;
                    break;
                };
                for i in 0..count {
                    let (Some(field), Some(generation)) = (parser.uint(), parser.uint()) else {
                        return Err("bad cross-reference entry");
                    };
                    parser.skip_space();
                    let kind = parser.word();
                    let num = u32::try_from(start + i).map_err(|_| "bad object number")?;
                    let generation = u16::try_from(generation).map_err(|_| "bad generation")?;
                    let entry = match kind {
                        b"n" => Entry::At(field as usize),
                        b"f" => Entry::Free,
                        _ => return Err("bad cross-reference entry"),
                    };
                    self.entries.entry(num).or_insert((entry, generation));
                }
            }
            if !parser.keyword(b"trailer") {
                return Err("no trailer");
            }
            let Obj::Dict(trailer) = parser.object(0)? else {
                return Err("bad trailer");
            };
            return Ok((trailer, false));
        }
        let (dict, data) = match self.indirect_at(offset)? {
            Obj::Stream(dict, data) => (dict, data),
            _ => return Err("bad cross-reference stream"),
        };
        let decoded = decode(&dict, &data, |obj| self.resolve_int(obj))?;
        let widths: Vec<usize> = match get(&dict, "W") {
            Some(Obj::Array(w)) if w.len() == 3 => w
                .iter()
                .map(|o| match o {
                    Obj::Int(i) if (0..=8).contains(i) => Ok(*i as usize),
                    _ => Err("bad W"),
                })
                .collect::<Result<_, _>>()?,
            _ => return Err("bad W"),
        };
        let size = match get(&dict, "Size") {
            Some(Obj::Int(size)) => *size,
            _ => return Err("bad Size"),
        };
        let index: Vec<i64> = match get(&dict, "Index") {
            Some(Obj::Array(index)) => index
                .iter()
                .map(|o| match o {
                    Obj::Int(i) => Ok(*i),
                    _ => Err("bad Index"),
                })
                .collect::<Result<_, _>>()?,
            _ => vec![0, size],
        };
        let row = widths.iter().sum::<usize>();
        if row == 0 {
            return Err("bad W");
        }
        let mut rows = decoded.chunks_exact(row);
        for pair in index.chunks(2) {
            let [start, count] = pair else {
                return Err("bad Index");
            };
            for i in 0..*count {
                let fields = rows.next().ok_or("short cross-reference stream")?;
                let (a, rest) = fields.split_at(widths[0]);
                let (b, c) = rest.split_at(widths[1]);
                let kind = if widths[0] == 0 { 1 } else { be(a) };
                let num = u32::try_from(start + i).map_err(|_| "bad object number")?;
                let entry = match kind {
                    0 => (Entry::Free, 0),
                    1 => (Entry::At(be(b) as usize), be(c) as u16),
                    2 => (Entry::InStream(be(b) as u32), 0),
                    _ => continue,
                };
                self.entries.entry(num).or_insert(entry);
            }
        }
        Ok((dict, true))
    }

    /// The indirect object `N G obj … endobj` at `offset`.
    fn indirect_at(&self, offset: usize) -> Result<Obj, Error> {
        let mut parser = Parser::new(self.data, offset);
        if parser.uint().is_none() || parser.uint().is_none() || !parser.keyword(b"obj") {
            return Err("bad object header");
        }
        let obj = parser.object(0)?;
        // A stream whose Length is a reference: read again with the length resolved.
        if let Obj::Stream(dict, _) = &obj
            && let Some(Obj::Ref(..)) = get(dict, "Length")
        {
            let len = self.resolve_int(get(dict, "Length").expect("checked"))?;
            let mut dict = dict.clone();
            set(&mut dict, "Length", Obj::Int(len));
            let mut again = Parser::new(self.data, offset);
            again.uint();
            again.uint();
            again.keyword(b"obj");
            again.skip_space();
            again.pos += 2;
            again.dict_body(0)?;
            again.keyword(b"stream");
            let data = again.stream_data(&dict)?;
            return Ok(Obj::Stream(dict, data));
        }
        Ok(obj)
    }

    fn resolve_int(&self, obj: &Obj) -> Result<i64, Error> {
        match self.resolve(obj)? {
            Obj::Int(i) => Ok(i),
            _ => Err("not an integer"),
        }
    }

    /// `obj`, or the object it refers to.
    pub(crate) fn resolve(&self, obj: &Obj) -> Result<Obj, Error> {
        match obj {
            Obj::Ref(num, _) => self.object(*num),
            other => Ok(other.clone()),
        }
    }

    /// The object `num`.
    pub(crate) fn object(&self, num: u32) -> Result<Obj, Error> {
        match self.entries.get(&num) {
            None | Some((Entry::Free, _)) => Ok(Obj::Null),
            Some((Entry::At(offset), _)) => self.indirect_at(*offset),
            Some((Entry::InStream(stream), _)) => {
                let Some((Entry::At(offset), _)) = self.entries.get(stream) else {
                    return Err("bad object stream");
                };
                let Obj::Stream(dict, data) = self.indirect_at(*offset)? else {
                    return Err("bad object stream");
                };
                let decoded = decode(&dict, &data, |obj| self.resolve_int(obj))?;
                let n = self.resolve_int(get(&dict, "N").ok_or("bad object stream")?)?;
                let first = self.resolve_int(get(&dict, "First").ok_or("bad object stream")?)?;
                let first = usize::try_from(first).map_err(|_| "bad object stream")?;
                let mut header = Parser::new(&decoded, 0);
                for _ in 0..n {
                    let (Some(obj_num), Some(at)) = (header.uint(), header.uint()) else {
                        return Err("bad object stream");
                    };
                    if obj_num == u64::from(num) {
                        let mut parser = Parser::new(&decoded, first + at as usize);
                        return parser.object(0);
                    }
                }
                Err("object not in its stream")
            }
        }
    }

    /// The generation of object `num`.
    pub(crate) fn generation(&self, num: u32) -> u16 {
        self.entries
            .get(&num)
            .map_or(0, |(_, generation)| *generation)
    }

    /// The trailer's `Size`: the first object number free for new objects.
    pub(crate) fn size(&self) -> Result<u32, Error> {
        let declared = match get(&self.trailer, "Size") {
            Some(Obj::Int(size)) => u32::try_from(*size).map_err(|_| "bad Size")?,
            _ => return Err("bad Size"),
        };
        let highest = self.entries.keys().next_back().map_or(0, |n| n + 1);
        Ok(declared.max(highest))
    }
}

/// A big-endian unsigned integer.
fn be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |n, b| n << 8 | u64::from(*b))
}

/// The data of a stream, its filters (none or FlateDecode, with PNG predictors) undone.
fn decode(
    dict: &Dict,
    data: &[u8],
    int: impl Fn(&Obj) -> Result<i64, Error>,
) -> Result<Vec<u8>, Error> {
    let filters: Vec<Vec<u8>> = match get(dict, "Filter") {
        None => Vec::new(),
        Some(Obj::Name(n)) => vec![n.clone()],
        Some(Obj::Array(items)) => items
            .iter()
            .map(|o| match o {
                Obj::Name(n) => Ok(n.clone()),
                _ => Err("bad Filter"),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("bad Filter"),
    };
    let mut out = data.to_vec();
    for filter in &filters {
        if filter != b"FlateDecode" {
            return Err("unsupported filter");
        }
        let mut inflated = Vec::new();
        ZlibDecoder::new(&out[..])
            .take(MAX_INFLATED)
            .read_to_end(&mut inflated)
            .map_err(|_| "bad compressed stream")?;
        out = inflated;
    }
    let params = match get(dict, "DecodeParms") {
        Some(Obj::Dict(params)) => Some(params.clone()),
        Some(Obj::Array(items)) => items.iter().find_map(|o| match o {
            Obj::Dict(params) => Some(params.clone()),
            _ => None,
        }),
        _ => None,
    };
    if let Some(params) = params {
        let predictor = get(&params, "Predictor").map_or(Ok(1), &int)?;
        if predictor >= 10 {
            let columns = get(&params, "Columns").map_or(Ok(1), &int)?;
            out = unpredict_png(&out, usize::try_from(columns).map_err(|_| "bad Columns")?)?;
        } else if predictor != 1 {
            return Err("unsupported predictor");
        }
    }
    Ok(out)
}

/// Undoes PNG row predictors of rows of `columns` bytes.
fn unpredict_png(data: &[u8], columns: usize) -> Result<Vec<u8>, Error> {
    if columns == 0 {
        return Err("bad Columns");
    }
    let mut out = Vec::with_capacity(data.len());
    let mut previous = vec![0u8; columns];
    for row in data.chunks(columns + 1) {
        if row.len() != columns + 1 {
            break;
        }
        let (kind, bytes) = (row[0], &row[1..]);
        let mut current = vec![0u8; columns];
        for i in 0..columns {
            let left = if i > 0 { current[i - 1] } else { 0 };
            let up = previous[i];
            let up_left = if i > 0 { previous[i - 1] } else { 0 };
            current[i] = match kind {
                0 => bytes[i],
                1 => bytes[i].wrapping_add(left),
                2 => bytes[i].wrapping_add(up),
                3 => bytes[i].wrapping_add(((u16::from(left) + u16::from(up)) / 2) as u8),
                4 => bytes[i].wrapping_add(paeth(left, up, up_left)),
                _ => return Err("bad predictor row"),
            };
        }
        out.extend(&current);
        previous = current;
    }
    Ok(out)
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = (
        (p - i16::from(a)).abs(),
        (p - i16::from(b)).abs(),
        (p - i16::from(c)).abs(),
    );
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// The new objects of an incremental update, numbered from the document's `Size`.
pub(crate) struct Update<'d, 'a> {
    doc: &'d Document<'a>,
    next: u32,
    objects: Vec<(u32, u16, Obj)>,
}

impl<'d, 'a> Update<'d, 'a> {
    pub(crate) fn new(doc: &'d Document<'a>) -> Result<Update<'d, 'a>, Error> {
        Ok(Update {
            doc,
            next: doc.size()?,
            objects: Vec::new(),
        })
    }

    /// The number the next new object gets.
    pub(crate) fn reserve(&mut self) -> u32 {
        let num = self.next;
        self.next += 1;
        num
    }

    /// Writes `obj` as the object `num` (new, or a new version of the document's own).
    pub(crate) fn put(&mut self, num: u32, obj: Obj) {
        let generation = if num < self.doc.size().unwrap_or(0) {
            self.doc.generation(num)
        } else {
            0
        };
        self.objects.push((num, generation, obj));
    }

    /// The document with the update appended: the objects, a cross-reference section of the
    /// newest section's kind and a trailer pointing back to it.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        let doc = self.doc;
        let mut out = doc.data.to_vec();
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        let mut offsets: Vec<(u32, u16, usize)> = Vec::new();
        for (num, generation, obj) in &self.objects {
            offsets.push((*num, *generation, out.len()));
            out.extend(format!("{num} {generation} obj\n").as_bytes());
            obj.write(&mut out);
            out.extend(b"\nendobj\n");
        }
        let mut trailer: Dict = Vec::new();
        for key in ["Root", "Info", "ID"] {
            if let Some(value) = get(&doc.trailer, key) {
                set(&mut trailer, key, value.clone());
            }
        }
        set(&mut trailer, "Prev", Obj::Int(doc.startxref as i64));
        let xref_at = out.len();
        if doc.xref_stream {
            let own = self.reserve();
            offsets.push((own, 0, xref_at));
            offsets.sort_by_key(|(num, ..)| *num);
            let mut index = Vec::new();
            let mut rows = Vec::new();
            for (num, generation, offset) in &offsets {
                index.push(Obj::Int(i64::from(*num)));
                index.push(Obj::Int(1));
                rows.push(1u8);
                rows.extend(&(*offset as u32).to_be_bytes());
                rows.extend(&generation.to_be_bytes());
            }
            set(&mut trailer, "Type", name("XRef"));
            set(&mut trailer, "Size", Obj::Int(i64::from(self.next)));
            set(&mut trailer, "Index", Obj::Array(index));
            set(
                &mut trailer,
                "W",
                Obj::Array(vec![Obj::Int(1), Obj::Int(4), Obj::Int(2)]),
            );
            out.extend(format!("{own} 0 obj\n").as_bytes());
            Obj::Stream(trailer, rows).write(&mut out);
            out.extend(b"\nendobj\n");
        } else {
            offsets.sort_by_key(|(num, ..)| *num);
            out.extend(b"xref\n");
            for (num, generation, offset) in &offsets {
                out.extend(format!("{num} 1\n{offset:010} {generation:05} n\r\n").as_bytes());
            }
            set(&mut trailer, "Size", Obj::Int(i64::from(self.next)));
            out.extend(b"trailer\n");
            Obj::Dict(trailer).write(&mut out);
            out.push(b'\n');
        }
        out.extend(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());
        out
    }
}
