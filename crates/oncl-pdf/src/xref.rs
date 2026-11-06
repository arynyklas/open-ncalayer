use crate::{
    PdfDocument, PdfError, Result,
    objects::{Parser, Value, get, white},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Entry {
    /// Free entry: next free object number and the generation to use if reused.
    Free {
        next: u64,
        generation: u32,
    },
    Direct(u64, u16),
    Compressed(u32, u32),
}
pub(crate) struct Revision {
    pub xref: u64,
    pub end: u64,
    pub eof_token_end: u64,
    pub entries: BTreeMap<u32, Entry>,
    pub root: Value,
    pub trailer: BTreeMap<Vec<u8>, Value>,
    _trailer_memory: oncl_pki::resource::ResourceReservation,
    _trailer_metadata: oncl_pki::resource::ResourceReservation,
}
pub(crate) struct Indirect {
    pub value: Value,
    pub stream: Option<Vec<u8>>,
    pub stream_region: Option<oncl_pki::io::Region>,
    pub end: u64,
}
type XrefSection = (BTreeMap<u32, Entry>, BTreeMap<Vec<u8>, Value>, u64);
impl PdfDocument<'_, '_> {
    pub(crate) fn parser<'a>(&self, bytes: &'a [u8], base: u64) -> Parser<'a> {
        Parser::new(bytes, base, self.limits.max_nodes, self.limits.max_depth)
    }
    pub(crate) fn window(&mut self, offset: u64) -> Result<Vec<u8>> {
        self.work = self
            .work
            .checked_add(self.limits.max_object_bytes as u64)
            .ok_or(PdfError::Limit("read work"))?;
        if self.work > self.limits.max_read_work {
            return Err(PdfError::Limit("read work"));
        }
        self.input
            .read_at(offset, self.limits.max_object_bytes, self.scope)
    }
    pub(crate) fn indirect(
        &mut self,
        offset: u64,
        expected: Option<(u32, u16)>,
        decode: bool,
    ) -> Result<Indirect> {
        let bytes = self.window(offset)?;
        let mut p = self.parser(&bytes, offset);
        let id = p.integer()?;
        let generation = p.integer()?;
        p.expect(b"obj")?;
        if let Some((want, gen_want)) = expected
            && (id != u64::from(want) || generation != u64::from(gen_want))
        {
            return Err(PdfError::Malformed("xref object identity"));
        }
        let value = p.value(0)?;
        p.ws();
        let mut stream = None;
        let mut stream_region = None;
        if p.bytes.get(p.pos..p.pos + 6) == Some(b"stream") {
            p.pos += 6;
            if p.bytes.get(p.pos) == Some(&b'\r') {
                p.pos += 1;
                if p.bytes.get(p.pos) == Some(&b'\n') {
                    p.pos += 1;
                }
            } else if p.bytes.get(p.pos) == Some(&b'\n') {
                p.pos += 1;
            } else {
                return Err(PdfError::Malformed("stream newline"));
            }
            if !decode {
                return Err(PdfError::Unsupported("stream in signature metadata graph"));
            }
            let dict = value.dict()?;
            let length = usize::try_from(get(dict, b"Length")?.int()?)
                .map_err(|_| PdfError::Limit("stream size"))?;
            let end = p
                .pos
                .checked_add(length)
                .ok_or(PdfError::Limit("stream size"))?;
            stream_region = Some(oncl_pki::io::Region {
                offset: offset + p.pos as u64,
                len: length as u64,
            });
            let encoded = p
                .bytes
                .get(p.pos..end)
                .ok_or(PdfError::Limit("encoded stream size"))?;
            let decoded = match dict.get(b"Filter".as_slice()) {
                None => {
                    self.decoded = self
                        .decoded
                        .checked_add(encoded.len() as u64)
                        .ok_or(PdfError::Limit("decode work"))?;
                    if encoded.len() > self.limits.max_decoded_bytes
                        || self.decoded > self.limits.max_decode_work
                    {
                        return Err(PdfError::Limit("decode work"));
                    }
                    encoded.to_vec()
                }
                Some(filter)
                    if filter.name(b"FlateDecode")
                        || matches!(filter,Value::Array(a) if a.len()==1 && a[0].name(b"FlateDecode")) =>
                {
                    let mut decoder = flate2::read::ZlibDecoder::new(encoded);
                    let mut decoded = Vec::new();
                    let mut chunk = [0; 8192];
                    loop {
                        self.scope.checkpoint()?;
                        let n = decoder.read(&mut chunk)?;
                        if n == 0 {
                            break;
                        }
                        self.decoded = self
                            .decoded
                            .checked_add(n as u64)
                            .ok_or(PdfError::Limit("decompression work"))?;
                        if self.decoded > self.limits.max_decode_work
                            || decoded
                                .len()
                                .checked_add(n)
                                .is_none_or(|n| n > self.limits.max_decoded_bytes)
                        {
                            return Err(PdfError::Limit("decompression work"));
                        }
                        decoded.extend_from_slice(&chunk[..n]);
                    }
                    if let Some(parameters) = dict.get(b"DecodeParms".as_slice()) {
                        self.decoded = self
                            .decoded
                            .checked_add(decoded.len() as u64)
                            .ok_or(PdfError::Limit("predictor work"))?;
                        if self.decoded > self.limits.max_decode_work {
                            return Err(PdfError::Limit("predictor work"));
                        }
                        predictor(&mut decoded, parameters)?;
                    }
                    decoded
                }
                _ => return Err(PdfError::Unsupported("stream filter")),
            };
            p.pos = end;
            p.expect(b"endstream")?;
            stream = Some(decoded);
        }
        p.expect(b"endobj")?;
        Ok(Indirect {
            value,
            stream,
            stream_region,
            end: offset + p.pos as u64,
        })
    }
    pub(crate) fn load_revisions(&mut self) -> Result<()> {
        let tail_size = self.input.extent.min(65536) as usize;
        let tail_offset = self.input.extent - tail_size as u64;
        let tail = self.input.read_at(tail_offset, tail_size, self.scope)?;
        let (mut offset, end, _) = tail_marker(&tail, tail_offset)?;
        if end != self.input.extent {
            return Err(PdfError::Malformed("trailing bytes after EOF"));
        }
        let mut seen = BTreeSet::new();
        loop {
            self.scope.checkpoint()?;
            if self.revisions.len() >= self.limits.max_revisions {
                return Err(PdfError::Limit("revision count"));
            }
            if offset >= self.input.extent || !seen.insert(offset) {
                return Err(PdfError::Malformed("xref cycle or offset"));
            }
            let (mut entries, dict, object_end) = self.xref_section(offset)?;
            if dict.contains_key(b"Encrypt".as_slice()) {
                return Err(PdfError::Unsupported("encrypted PDF"));
            }
            if let Some(hybrid) = dict.get(b"XRefStm".as_slice()) {
                let hybrid = hybrid.int()?;
                if !seen.insert(hybrid) {
                    return Err(PdfError::Malformed("hybrid xref cycle"));
                }
                let (extra, extra_dict, _) = self.xref_section(hybrid)?;
                if extra_dict.contains_key(b"Prev".as_slice()) {
                    return Err(PdfError::Unsupported("hybrid stream Prev"));
                }
                entries.extend(extra);
                if entries.len() > self.limits.max_objects {
                    return Err(PdfError::Limit("hybrid xref entries"));
                }
            }
            let marker = self.input.read_at(object_end, 4096, self.scope)?;
            let (declared, revision_end, eof_token_end) = head_marker(&marker, object_end)?;
            if declared != offset {
                return Err(PdfError::Malformed("revision startxref mismatch"));
            }
            let root = match dict.get(b"Root".as_slice()) {
                Some(value @ Value::Ref(_, _)) => value.clone(),
                Some(_) => return Err(PdfError::Malformed("trailer Root must be indirect")),
                None => Value::Other,
            };
            if entries
                .values()
                .any(|entry| matches!(entry,Entry::Direct(at,_) if *at>=revision_end))
            {
                return Err(PdfError::Malformed("xref entry outside its revision"));
            }
            // Retain only trailer metadata required by incremental updates;
            // admit each actual clone before its storage outlives this parser.
            let mut retained_bytes = 256u64;
            for key in [b"Size".as_slice(), b"Info".as_slice(), b"ID".as_slice()] {
                if let Some(value) = dict.get(key) {
                    retained_bytes = retained_bytes
                        .checked_add(value.retained_bytes()?)
                        .ok_or(PdfError::Limit("trailer metadata size"))?;
                }
            }
            let trailer_memory = self.scope.reserve_memory(retained_bytes)?;
            let trailer_metadata = self.scope.reserve_metadata(retained_bytes)?;
            let trailer = [b"Size".as_slice(), b"Info".as_slice(), b"ID".as_slice()]
                .into_iter()
                .filter_map(|key| dict.get(key).map(|value| (key.to_vec(), value.clone())))
                .collect();
            self.revisions.push(Revision {
                xref: offset,
                end: revision_end,
                eof_token_end,
                entries,
                root,
                trailer,
                _trailer_memory: trailer_memory,
                _trailer_metadata: trailer_metadata,
            });
            match dict.get(b"Prev".as_slice()) {
                Some(prev) => {
                    let prev = prev.int()?;
                    if prev >= offset {
                        return Err(PdfError::Malformed("forward Prev"));
                    }
                    offset = prev;
                }
                None => break,
            }
        }
        self.revisions.reverse();
        let mut inherited_root = None;
        for revision in &mut self.revisions {
            if matches!(revision.root, Value::Other) {
                revision.root = inherited_root
                    .clone()
                    .ok_or(PdfError::Malformed("missing root in oldest revision"))?;
            } else {
                inherited_root = Some(revision.root.clone());
            }
        }
        for pair in self.revisions.windows(2) {
            if pair[0].end > pair[1].xref {
                return Err(PdfError::Malformed("revision overlap"));
            }
        }
        if self
            .revisions
            .last()
            .is_none_or(|r| r.end != self.input.extent)
        {
            return Err(PdfError::Malformed("latest revision endpoint"));
        }
        Ok(())
    }
    fn xref_section(&mut self, offset: u64) -> Result<XrefSection> {
        let bytes = self.window(offset)?;
        let mut p = self.parser(&bytes, offset);
        let mut entries = BTreeMap::new();
        if p.word()? == b"xref" {
            loop {
                p.ws();
                if p.bytes.get(p.pos..p.pos + 7) == Some(b"trailer") {
                    p.pos += 7;
                    break;
                }
                let first = p.integer()?;
                let count = p.integer()?;
                if count > self.limits.max_objects as u64
                    || first.checked_add(count).is_none_or(|n| n > u32::MAX as u64)
                {
                    return Err(PdfError::Limit("xref entries"));
                }
                for id in first..first + count {
                    let offset = p.integer()?;
                    let generation = p.integer()?;
                    let kind = p.word()?;
                    let entry = match kind {
                        b"f" => Entry::Free {
                            next: offset,
                            generation: u32::try_from(generation)
                                .map_err(|_| PdfError::Malformed("generation"))?,
                        },
                        b"n" => Entry::Direct(
                            offset,
                            u16::try_from(generation)
                                .map_err(|_| PdfError::Malformed("generation"))?,
                        ),
                        _ => return Err(PdfError::Malformed("xref status")),
                    };
                    if entries.len() >= self.limits.max_objects
                        || entries.insert(id as u32, entry).is_some()
                    {
                        return Err(PdfError::Limit("xref entries"));
                    }
                }
            }
            let dict = p.value(0)?.dict()?.clone();
            let size = get(&dict, b"Size")?.int()?;
            if entries.keys().any(|id| u64::from(*id) >= size) {
                return Err(PdfError::Malformed("xref object id exceeds Size"));
            }
            Ok((entries, dict, offset + p.pos as u64))
        } else {
            let object = self.indirect(offset, None, true)?;
            let dict = object.value.dict()?.clone();
            if !get(&dict, b"Type")?.name(b"XRef") {
                return Err(PdfError::Malformed("xref stream type"));
            }
            let widths = get(&dict, b"W")?.array()?;
            if widths.len() != 3 {
                return Err(PdfError::Malformed("xref widths"));
            }
            let w = [widths[0].int()?, widths[1].int()?, widths[2].int()?];
            if w.iter().any(|n| *n > 8) || w.iter().sum::<u64>() == 0 {
                return Err(PdfError::Malformed("xref widths"));
            }
            let size = get(&dict, b"Size")?.int()?;
            let indices = match dict.get(b"Index".as_slice()) {
                Some(v) => v
                    .array()?
                    .iter()
                    .map(Value::int)
                    .collect::<Result<Vec<_>>>()?,
                None => vec![0, size],
            };
            if !indices.len().is_multiple_of(2) {
                return Err(PdfError::Malformed("xref indices"));
            }
            let stream = object
                .stream
                .ok_or(PdfError::Malformed("missing xref stream"))?;
            let mut pos = 0;
            for pair in indices.as_chunks::<2>().0 {
                let [first, count] = [pair[0], pair[1]];
                if count > self.limits.max_objects as u64
                    || first
                        .checked_add(count)
                        .is_none_or(|n| n > size || n > u32::MAX as u64)
                {
                    return Err(PdfError::Limit("xref entries"));
                }
                for id in first..first + count {
                    let mut field = [0u64; 3];
                    for (slot, width) in w.iter().enumerate() {
                        for _ in 0..*width {
                            field[slot] = field[slot]
                                .checked_mul(256)
                                .and_then(|n| {
                                    stream.get(pos).and_then(|b| n.checked_add(u64::from(*b)))
                                })
                                .ok_or(PdfError::Malformed("truncated xref stream"))?;
                            pos += 1;
                        }
                    }
                    if w[0] == 0 {
                        field[0] = 1;
                    }
                    let entry = match field[0] {
                        0 => Entry::Free {
                            next: field[1],
                            // ISO 32000-1 7.5.8.3 defaults an absent field (W[2] == 0)
                            // to 0, while the free-list head is 65535. Producers
                            // such as NCANode omit it, so that tolerated deviation
                            // is read as the head's 65535; with a real field the
                            // stored value is used unchanged.
                            generation: if w[2] == 0 {
                                65535
                            } else {
                                u32::try_from(field[2]).unwrap_or(u32::MAX)
                            },
                        },
                        1 => Entry::Direct(
                            field[1],
                            u16::try_from(field[2])
                                .map_err(|_| PdfError::Malformed("xref generation"))?,
                        ),
                        2 => Entry::Compressed(
                            u32::try_from(field[1])
                                .map_err(|_| PdfError::Malformed("object stream id"))?,
                            u32::try_from(field[2])
                                .map_err(|_| PdfError::Malformed("object stream index"))?,
                        ),
                        _ => return Err(PdfError::Unsupported("xref entry type")),
                    };
                    if entries.len() >= self.limits.max_objects
                        || entries.insert(id as u32, entry).is_some()
                    {
                        return Err(PdfError::Limit("xref entries"));
                    }
                }
            }
            if pos != stream.len() {
                return Err(PdfError::Malformed("xref stream trailing data"));
            }
            Ok((entries, dict, object.end))
        }
    }
    pub(crate) fn resolve(&mut self, revision: usize, value: &Value) -> Result<Value> {
        let Value::Ref(id, generation) = value else {
            return Ok(value.clone());
        };
        let entry = self.revisions[..=revision]
            .iter()
            .rev()
            .find_map(|r| r.entries.get(id))
            .copied()
            .ok_or(PdfError::Malformed("unresolved reference"))?;
        match entry {
            Entry::Free { .. } => Err(PdfError::Malformed("free object reference")),
            Entry::Direct(offset, gen_actual) => {
                if gen_actual != *generation || offset >= self.revisions[revision].end {
                    return Err(PdfError::Malformed("reference generation or revision"));
                }
                let object = self.indirect(offset, Some((*id, *generation)), false)?;
                if object.end > self.revisions[revision].end {
                    return Err(PdfError::Malformed("object crosses revision boundary"));
                }
                Ok(object.value)
            }
            Entry::Compressed(stream_id, index) => {
                if *generation != 0 || stream_id == *id {
                    return Err(PdfError::Malformed("compressed object reference"));
                }
                let entry = self.revisions[..=revision]
                    .iter()
                    .rev()
                    .find_map(|r| r.entries.get(&stream_id))
                    .copied()
                    .ok_or(PdfError::Malformed("missing object stream"))?;
                let Entry::Direct(offset, generation) = entry else {
                    return Err(PdfError::Malformed("nested object stream"));
                };
                if offset >= self.revisions[revision].end {
                    return Err(PdfError::Malformed("object stream revision"));
                }
                if !self
                    .object_stream_cache
                    .as_ref()
                    .is_some_and(|(r, id, _, _)| *r == revision && *id == stream_id)
                {
                    let object = self.indirect(offset, Some((stream_id, generation)), true)?;
                    if object.end > self.revisions[revision].end {
                        return Err(PdfError::Malformed(
                            "object stream crosses revision boundary",
                        ));
                    }
                    let bytes = object
                        .stream
                        .ok_or(PdfError::Malformed("object stream missing"))?;
                    self.object_stream_cache = Some((revision, stream_id, object.value, bytes));
                }
                let (_, _, value, bytes) = self
                    .object_stream_cache
                    .as_ref()
                    .ok_or(PdfError::Malformed("object stream cache"))?;
                let dict = value.dict()?;
                if !get(dict, b"Type")?.name(b"ObjStm") {
                    return Err(PdfError::Malformed("object stream type"));
                }
                let n = get(dict, b"N")?.int()?;
                let first = get(dict, b"First")?.int()?;
                if n > self.limits.max_objects as u64 || u64::from(index) >= n {
                    return Err(PdfError::Limit("object stream count"));
                }
                let first =
                    usize::try_from(first).map_err(|_| PdfError::Limit("object stream offset"))?;
                if first > bytes.len() {
                    return Err(PdfError::Malformed("object stream offset"));
                }
                let mut p = self.parser(&bytes[..first], 0);
                let mut ranges = Vec::new();
                for _ in 0..n {
                    ranges.push((p.integer()?, p.integer()?));
                }
                p.ws();
                if p.pos != first {
                    return Err(PdfError::Malformed("object stream header"));
                }
                let slot = index as usize;
                if ranges[slot].0 != u64::from(*id) {
                    return Err(PdfError::Malformed("object stream identity"));
                }
                let mut previous = 0;
                let mut ids = BTreeSet::new();
                for (i, (object_id, off)) in ranges.iter().enumerate() {
                    if (i > 0 && *off <= previous) || !ids.insert(*object_id) {
                        return Err(PdfError::Malformed("object stream ordering"));
                    }
                    previous = *off;
                }
                let start = first
                    .checked_add(
                        usize::try_from(ranges[slot].1)
                            .map_err(|_| PdfError::Limit("object stream offset"))?,
                    )
                    .ok_or(PdfError::Limit("object stream offset"))?;
                let end = if slot + 1 < ranges.len() {
                    first
                        .checked_add(
                            usize::try_from(ranges[slot + 1].1)
                                .map_err(|_| PdfError::Limit("object stream offset"))?,
                        )
                        .ok_or(PdfError::Limit("object stream offset"))?
                } else {
                    bytes.len()
                };
                let mut p = self.parser(
                    bytes
                        .get(start..end)
                        .ok_or(PdfError::Malformed("object stream slice"))?,
                    0,
                );
                let value = p.value(0)?;
                p.ws();
                if p.pos != p.bytes.len() {
                    return Err(PdfError::Malformed("compressed object trailing data"));
                }
                // Compressed signature dictionaries cannot provide a physical Contents gap.
                Ok(value)
            }
        }
    }
}
fn head_marker(bytes: &[u8], base: u64) -> Result<(u64, u64, u64)> {
    let mut p = Parser::new(bytes, base, 16, 4);
    p.expect(b"startxref")?;
    let offset = p.integer()?;
    while p.bytes.get(p.pos).is_some_and(|b| white(*b)) {
        p.pos += 1;
    }
    if p.bytes.get(p.pos..p.pos + 5) != Some(b"%%EOF") {
        return Err(PdfError::Malformed("revision EOF"));
    }
    p.pos += 5;
    let eof_token_end = base + p.pos as u64;
    if p.bytes
        .get(p.pos)
        .is_some_and(|b| !matches!(b, b'\r' | b'\n'))
    {
        return Err(PdfError::Malformed("revision EOF token boundary"));
    }
    // Include one PDF line ending. Other bytes belong to the next revision.
    if p.bytes.get(p.pos) == Some(&b'\r') {
        p.pos += 1;
        if p.bytes.get(p.pos) == Some(&b'\n') {
            p.pos += 1;
        }
    } else if p.bytes.get(p.pos) == Some(&b'\n') {
        p.pos += 1;
    }
    Ok((offset, base + p.pos as u64, eof_token_end))
}
fn tail_marker(bytes: &[u8], base: u64) -> Result<(u64, u64, u64)> {
    let start = bytes
        .windows(9)
        .rposition(|w| w == b"startxref")
        .ok_or(PdfError::Malformed("missing startxref"))?;
    head_marker(&bytes[start..], base + start as u64)
}

fn predictor(bytes: &mut Vec<u8>, parameters: &Value) -> Result<()> {
    let parameters = match parameters {
        Value::Array(values) if values.len() == 1 => &values[0],
        value => value,
    };
    let dict = parameters.dict()?;
    let algorithm = dict
        .get(b"Predictor".as_slice())
        .map(Value::int)
        .transpose()?
        .unwrap_or(1);
    if algorithm == 1 {
        return Ok(());
    }
    if !(10..=15).contains(&algorithm) {
        return Err(PdfError::Unsupported("Flate predictor"));
    }
    let columns = dict
        .get(b"Columns".as_slice())
        .map(Value::int)
        .transpose()?
        .unwrap_or(1);
    let colors = dict
        .get(b"Colors".as_slice())
        .map(Value::int)
        .transpose()?
        .unwrap_or(1);
    let bits = dict
        .get(b"BitsPerComponent".as_slice())
        .map(Value::int)
        .transpose()?
        .unwrap_or(8);
    if bits != 8 || columns == 0 || colors == 0 {
        return Err(PdfError::Unsupported("predictor component layout"));
    }
    let width = usize::try_from(
        columns
            .checked_mul(colors)
            .ok_or(PdfError::Limit("predictor row"))?,
    )
    .map_err(|_| PdfError::Limit("predictor row"))?;
    let stride = width
        .checked_add(1)
        .ok_or(PdfError::Limit("predictor row"))?;
    let bpp = usize::try_from(colors).map_err(|_| PdfError::Limit("predictor colors"))?;
    if !bytes.len().is_multiple_of(stride) {
        return Err(PdfError::Malformed("truncated predictor row"));
    }
    let rows = bytes.len() / stride;
    for row in 0..rows {
        let filter = bytes[row * stride];
        if filter > 4 {
            return Err(PdfError::Malformed("PNG predictor filter"));
        }
        for column in 0..width {
            let dest = row * width + column;
            let raw = bytes[row * stride + 1 + column];
            let left = if column >= bpp { bytes[dest - bpp] } else { 0 };
            let up = if row > 0 { bytes[dest - width] } else { 0 };
            let upper_left = if row > 0 && column >= bpp {
                bytes[dest - width - bpp]
            } else {
                0
            };
            let prediction = match filter {
                0 => 0,
                1 => left,
                2 => up,
                3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                4 => {
                    let p = i32::from(left) + i32::from(up) - i32::from(upper_left);
                    let a = (p - i32::from(left)).abs();
                    let b = (p - i32::from(up)).abs();
                    let c = (p - i32::from(upper_left)).abs();
                    if a <= b && a <= c {
                        left
                    } else if b <= c {
                        up
                    } else {
                        upper_left
                    }
                }
                _ => return Err(PdfError::Malformed("PNG predictor filter")),
            };
            bytes[dest] = raw.wrapping_add(prediction);
        }
    }
    bytes.truncate(rows * width);
    Ok(())
}
