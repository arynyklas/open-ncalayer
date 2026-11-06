use crate::{
    PdfDocument, PdfError, Result,
    objects::{Parser, Value, get, white},
    source::Input,
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
/// Cross-reference rows of one revision as a compact, sorted table (no per-object
/// heap node): runs of consecutive object numbers share one section header, so a
/// dense document costs `size_of::<Entry>()` (16) bytes per object plus 32 per run.
/// Every grown byte is charged to the operation's memory budget before it is
/// allocated (`push`), so the table never outgrows what the scope admitted.
pub(crate) struct Table {
    sections: Vec<Section>,
    rows: Vec<Entry>,
    reserved: Option<oncl_pki::resource::ResourceReservation>,
}
#[derive(Clone, Copy)]
struct Section {
    first: u32,
    count: u32,
    base: usize,
}
/// Bytes one row occupies (what the document charges per cross-reference entry).
pub(crate) const ROW_BYTES: u64 = size_of::<Entry>() as u64;
pub(crate) const SECTION_BYTES: u64 = 2 * size_of::<Section>() as u64;
/// Largest growth step of the row vector, in rows (1 MiB of rows).
pub(crate) const GROW_ROWS: usize = 65_536;
impl Table {
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
            rows: Vec::new(),
            reserved: None,
        }
    }
    fn charge(
        &mut self,
        scope: &oncl_pki::resource::ResourceScope,
        bytes: u64,
    ) -> std::result::Result<(), oncl_pki::resource::ProcessingError> {
        match &mut self.reserved {
            Some(reservation) => reservation.grow(bytes),
            None => {
                self.reserved = Some(scope.reserve_memory(bytes)?);
                Ok(())
            }
        }
    }
    /// Append `entry` for object `id`; ids extend the open run when consecutive.
    pub fn push(
        &mut self,
        scope: &oncl_pki::resource::ResourceScope,
        id: u32,
        entry: Entry,
    ) -> Result<()> {
        if self.rows.len() == self.rows.capacity() {
            let step = self.rows.len().clamp(1024, GROW_ROWS);
            self.charge(scope, step as u64 * ROW_BYTES)?;
            self.rows
                .try_reserve_exact(step)
                .map_err(|_| PdfError::Limit("xref entries"))?;
        }
        let extends = self
            .sections
            .last()
            .is_some_and(|s| u64::from(s.first) + u64::from(s.count) == u64::from(id));
        if extends {
            let last = self.sections.len() - 1;
            self.sections[last].count += 1;
        } else {
            self.charge(scope, SECTION_BYTES)?;
            self.sections
                .try_reserve(1)
                .map_err(|_| PdfError::Limit("xref entries"))?;
            self.sections.push(Section {
                first: id,
                count: 1,
                base: self.rows.len(),
            });
        }
        self.rows.push(entry);
        Ok(())
    }
    /// Sort the runs by object number; overlapping runs are a duplicate entry.
    pub fn finish(&mut self) -> Result<()> {
        self.sections.sort_unstable_by_key(|s| s.first);
        if self
            .sections
            .windows(2)
            .any(|w| u64::from(w[0].first) + u64::from(w[0].count) > u64::from(w[1].first))
        {
            return Err(PdfError::Limit("xref entries"));
        }
        Ok(())
    }
    pub fn get(&self, id: &u32) -> Option<&Entry> {
        let at = self
            .sections
            .partition_point(|s| s.first <= *id)
            .checked_sub(1)?;
        let s = self.sections[at];
        let k = (*id - s.first) as usize;
        (k < s.count as usize).then(|| &self.rows[s.base + k])
    }
    pub fn contains_key(&self, id: &u32) -> bool {
        self.get(id).is_some()
    }
    /// Highest object number listed.
    pub fn max_id(&self) -> Option<u32> {
        self.sections.last().map(|s| s.first + (s.count - 1))
    }
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }
    /// First object number and rows of the `index`-th run (ascending).
    pub fn section(&self, index: usize) -> (u32, &[Entry]) {
        let s = self.sections[index];
        (s.first, &self.rows[s.base..s.base + s.count as usize])
    }
    /// Ascending `(id, entry)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (u32, Entry)> + '_ {
        (0..self.sections.len()).flat_map(|i| {
            let (first, rows) = self.section(i);
            rows.iter()
                .enumerate()
                .map(move |(k, e)| (first + k as u32, *e))
        })
    }
    /// `extra` (a hybrid file's `XRefStm`) overrides `main` where both list an object.
    pub fn merged(
        main: &Self,
        extra: &Self,
        scope: &oncl_pki::resource::ResourceScope,
    ) -> Result<Self> {
        let mut out = Self::new();
        let (mut a, mut b) = (main.iter().peekable(), extra.iter().peekable());
        loop {
            let next = match (a.peek(), b.peek()) {
                (Some((x, _)), Some((y, _))) if x == y => {
                    a.next();
                    b.next()
                }
                (Some((x, _)), Some((y, _))) if x < y => a.next(),
                (Some(_), Some(_)) | (None, Some(_)) => b.next(),
                (Some(_), None) => a.next(),
                (None, None) => break,
            };
            if let Some((id, entry)) = next {
                out.push(scope, id, entry)?;
            }
        }
        out.finish()?;
        Ok(out)
    }
}
pub(crate) struct Revision {
    pub xref: u64,
    pub end: u64,
    pub eof_token_end: u64,
    pub entries: Table,
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
/// What `indirect` does with the stream of an object.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamMode {
    /// A stream is not part of this graph.
    Reject,
    /// Copy and (Flate) decode the body, bounded by `max_decoded_bytes`.
    Decode,
    /// Unfiltered evidence: record the extent only, never the bytes.
    Region,
}
type XrefSection = (Table, BTreeMap<Vec<u8>, Value>, u64);
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
        mode: StreamMode,
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
            stream_eol(&mut p)?;
            if matches!(mode, StreamMode::Reject) {
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
            if matches!(mode, StreamMode::Region) {
                // Validation evidence (a CRL can be tens of MB): only its extent is
                // recorded, never its bytes; the owner spools the region. The keyword
                // after the body is read from its own small window.
                if dict.contains_key(b"Filter".as_slice()) {
                    return Err(PdfError::Unsupported("filtered evidence stream"));
                }
                let body_start = offset
                    .checked_add(p.pos as u64)
                    .ok_or(PdfError::Limit("stream size"))?;
                let body_end = body_start
                    .checked_add(length as u64)
                    .filter(|end| *end <= self.input.extent)
                    .ok_or(PdfError::Malformed("stream beyond the source"))?;
                self.work = self
                    .work
                    .checked_add(64)
                    .ok_or(PdfError::Limit("read work"))?;
                let tail = self.input.read_at(body_end, 64, self.scope)?;
                let mut after = self.parser(&tail, body_end);
                after.expect(b"endstream")?;
                after.expect(b"endobj")?;
                return Ok(Indirect {
                    value,
                    stream: None,
                    stream_region,
                    end: body_end + after.pos as u64,
                });
            }
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
                entries = Table::merged(&entries, &extra, self.scope)?;
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
                .iter()
                .any(|(_, entry)| matches!(entry,Entry::Direct(at,_) if at>=revision_end))
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
        let head = self.input.read_at(offset, 16, self.scope)?;
        let mut probe = self.parser(&head, offset);
        if probe.word()? == b"xref" {
            self.classic_xref(offset + probe.pos as u64)
        } else {
            self.xref_stream(offset)
        }
    }
    /// Count one more cross-reference entry against the document-wide budget.
    fn count_xref_entry(&mut self) -> Result<()> {
        self.xref_entries = self
            .xref_entries
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_xref_entries as u64)
            .ok_or(PdfError::Limit("xref entries"))?;
        Ok(())
    }
    /// Entries still admitted by `max_xref_entries` across all revisions.
    fn xref_entries_left(&self) -> u64 {
        (self.limits.max_xref_entries as u64).saturating_sub(self.xref_entries)
    }
    /// A classic table is read in fixed chunks of the SOURCE, not through one
    /// object-sized window, so its size is bounded by `max_xref_entries` (charged per
    /// row), never by `max_object_bytes`.
    fn classic_xref(&mut self, start: u64) -> Result<XrefSection> {
        const CHUNK: usize = 65_536;
        // Refill below this much so ordinary entries never straddle a chunk.
        const NEED: usize = 64;
        // A unit (subsection header or entry) that does not start at the chunk start and
        // fails to parse, or whose last token reaches the chunk end (it may be cut there:
        // `12` of `123`), is re-read from a fresh chunk starting at it, so acceptance
        // never depends on where the 64 KiB boundaries fall. A unit starting at the
        // chunk start is final: it is accepted when it ends before the chunk does (with
        // all its blanks) and refused otherwise, in every alignment.
        macro_rules! tok {
            ($e:expr, $unit:expr, $p:ident, $chunk:ident, $at_end:ident) => {
                match $e {
                    Ok(v) if $at_end || $p.pos < $chunk.len() => v,
                    Ok(_) if $unit == 0 => {
                        return Err(PdfError::Malformed("xref entry longer than a chunk"));
                    }
                    Ok(_) => {
                        $p.pos = $unit;
                        break;
                    }
                    Err(error) => {
                        if !$at_end && $unit > 0 {
                            $p.pos = $unit;
                            break;
                        }
                        return Err(error);
                    }
                }
            };
        }
        let mut entries = Table::new();
        let mut pos = start;
        let (mut next_id, mut remaining) = (0u64, 0u64);
        let trailer_at = 'sections: loop {
            self.work = self
                .work
                .checked_add(CHUNK as u64)
                .filter(|w| *w <= self.limits.max_read_work)
                .ok_or(PdfError::Limit("read work"))?;
            let chunk = self.input.read_at(pos, CHUNK, self.scope)?;
            let at_end = pos + chunk.len() as u64 == self.input.extent;
            let mut p = self.parser(&chunk, pos);
            loop {
                let unit = p.pos;
                if !at_end && chunk.len() - p.pos < NEED {
                    break;
                }
                if remaining == 0 {
                    p.ws();
                    if !at_end && chunk.len() - p.pos < NEED {
                        break;
                    }
                    if chunk.get(p.pos..p.pos + 7) == Some(b"trailer") {
                        break 'sections pos + p.pos as u64 + 7;
                    }
                    let first = tok!(p.integer(), unit, p, chunk, at_end);
                    let count = tok!(p.integer(), unit, p, chunk, at_end);
                    if count > self.xref_entries_left()
                        || first.checked_add(count).is_none_or(|n| n > u32::MAX as u64)
                    {
                        return Err(PdfError::Limit("xref entries"));
                    }
                    // An entry is at least `n n f` and a blank: a count the rest of the
                    // source cannot hold is a lie, refused before any row is read.
                    if count.saturating_mul(5) > self.input.extent - (pos + p.pos as u64) {
                        return Err(PdfError::Malformed("xref section beyond the source"));
                    }
                    (next_id, remaining) = (first, count);
                    continue;
                }
                let offset = tok!(p.integer(), unit, p, chunk, at_end);
                let generation = tok!(p.integer(), unit, p, chunk, at_end);
                let entry = match tok!(p.word(), unit, p, chunk, at_end) {
                    b"f" => Entry::Free {
                        next: offset,
                        generation: u32::try_from(generation)
                            .map_err(|_| PdfError::Malformed("generation"))?,
                    },
                    b"n" => Entry::Direct(
                        offset,
                        u16::try_from(generation).map_err(|_| PdfError::Malformed("generation"))?,
                    ),
                    _ => return Err(PdfError::Malformed("xref status")),
                };
                self.count_xref_entry()?;
                entries.push(self.scope, next_id as u32, entry)?;
                next_id += 1;
                remaining -= 1;
            }
            if p.pos == 0 {
                return Err(PdfError::Malformed("xref table"));
            }
            pos += p.pos as u64;
        };
        let bytes = self.window(trailer_at)?;
        let mut p = self.parser(&bytes, trailer_at);
        let dict = p.value(0)?.dict()?.clone();
        let size = get(&dict, b"Size")?.int()?;
        entries.finish()?;
        if entries.max_id().is_some_and(|id| u64::from(id) >= size) {
            return Err(PdfError::Malformed("xref object id exceeds Size"));
        }
        Ok((entries, dict, trailer_at + p.pos as u64))
    }
    /// A cross-reference stream is decoded incrementally (inflate, PNG predictor)
    /// straight from the source into table rows: the decoded table is never held, and
    /// the decoded size is bounded by `max_xref_entries` rows, not `max_decoded_bytes`.
    fn xref_stream(&mut self, offset: u64) -> Result<XrefSection> {
        let bytes = self.window(offset)?;
        let mut p = self.parser(&bytes, offset);
        p.integer()?;
        p.integer()?;
        p.expect(b"obj")?;
        let value = p.value(0)?;
        let dict = value.dict()?.clone();
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
        let row_bytes = w.iter().sum::<u64>() as usize;
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
        let mut declared = 0u64;
        for pair in indices.as_chunks::<2>().0 {
            let [first, count] = [pair[0], pair[1]];
            declared = declared
                .checked_add(count)
                .filter(|n| *n <= self.xref_entries_left())
                .ok_or(PdfError::Limit("xref entries"))?;
            if first
                .checked_add(count)
                .is_none_or(|n| n > size || n > u32::MAX as u64)
            {
                return Err(PdfError::Limit("xref entries"));
            }
        }
        p.ws();
        if p.bytes.get(p.pos..p.pos + 6) != Some(b"stream") {
            return Err(PdfError::Malformed("missing xref stream"));
        }
        p.pos += 6;
        stream_eol(&mut p)?;
        let length = get(&dict, b"Length")?.int()?;
        let body_start = offset + p.pos as u64;
        let body_end = body_start
            .checked_add(length)
            .filter(|end| *end <= self.input.extent)
            .ok_or(PdfError::Malformed("stream beyond the source"))?;
        let flate = match dict.get(b"Filter".as_slice()) {
            None => false,
            Some(filter)
                if filter.name(b"FlateDecode")
                    || matches!(filter, Value::Array(a) if a.len() == 1 && a[0].name(b"FlateDecode")) =>
            {
                true
            }
            _ => return Err(PdfError::Unsupported("stream filter")),
        };
        let layout = match (flate, dict.get(b"DecodeParms".as_slice())) {
            (true, Some(parameters)) => predictor_layout(parameters, self.limits.max_object_bytes)?,
            _ => None,
        };
        self.work = self
            .work
            .checked_add(64)
            .ok_or(PdfError::Limit("read work"))?;
        let tail = self.input.read_at(body_end, 64, self.scope)?;
        let mut after = self.parser(&tail, body_end);
        after.expect(b"endstream")?;
        after.expect(b"endobj")?;
        let end = body_end + after.pos as u64;
        let failure = std::cell::RefCell::new(None);
        let mut source = SourceRead {
            input: &mut self.input,
            scope: self.scope,
            pos: body_start,
            end: body_end,
            work: &mut self.work,
            max_work: self.limits.max_read_work,
            failure: &failure,
        };
        let mut inflate;
        let inner: &mut dyn Read = if flate {
            inflate = flate2::read::ZlibDecoder::new(&mut source);
            &mut inflate
        } else {
            &mut source
        };
        let mut rows = RowReader {
            inner,
            layout,
            prev: Vec::new(),
            raw: Vec::new(),
            pending: Vec::new(),
            at: 0,
            budget: self.limits.max_decode_work.saturating_sub(self.decoded),
            used: 0,
        };
        let mut entries = Table::new();
        let mut field_bytes = [0u8; 24];
        let outcome = (|| -> Result<()> {
            for pair in indices.as_chunks::<2>().0 {
                let [first, count] = [pair[0], pair[1]];
                for id in first..first + count {
                    rows.take(&mut field_bytes[..row_bytes])?;
                    let mut field = [0u64; 3];
                    let mut at = 0;
                    for (slot, width) in w.iter().enumerate() {
                        for _ in 0..*width {
                            field[slot] = field[slot] * 256 + u64::from(field_bytes[at]);
                            at += 1;
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
                    entries.push(self.scope, id as u32, entry)?;
                }
            }
            rows.finish()
        })();
        let used = rows.used;
        drop(rows);
        if let Some(error) = failure.take() {
            return Err(error);
        }
        outcome?;
        self.decoded = self.decoded.saturating_add(used);
        // The rows were admitted up front (`declared`): count them now.
        self.xref_entries = self.xref_entries.saturating_add(declared);
        entries.finish()?;
        Ok((entries, dict, end))
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
                let object = self.indirect(offset, Some((*id, *generation)), StreamMode::Reject)?;
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
                    let object =
                        self.indirect(offset, Some((stream_id, generation)), StreamMode::Decode)?;
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

/// The PNG predictor row geometry of a `DecodeParms`, `None` for "no predictor".
/// `cap` bounds one decoded row (`Columns * Colors`) before anything is allocated.
struct Layout {
    width: usize,
    bpp: usize,
}
fn predictor_layout(parameters: &Value, cap: usize) -> Result<Option<Layout>> {
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
        return Ok(None);
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
    if width >= cap {
        return Err(PdfError::Limit("predictor row"));
    }
    let bpp = usize::try_from(colors).map_err(|_| PdfError::Limit("predictor colors"))?;
    Ok(Some(Layout { width, bpp }))
}
/// PNG filter prediction of one byte (`filter` 0..=4).
fn prediction(filter: u8, left: u8, up: u8, upper_left: u8) -> Result<u8> {
    Ok(match filter {
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
    })
}
fn predictor(bytes: &mut Vec<u8>, parameters: &Value) -> Result<()> {
    let Some(Layout { width, bpp }) = predictor_layout(parameters, usize::MAX)? else {
        return Ok(());
    };
    let stride = width
        .checked_add(1)
        .ok_or(PdfError::Limit("predictor row"))?;
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
            bytes[dest] = raw.wrapping_add(prediction(filter, left, up, upper_left)?);
        }
    }
    bytes.truncate(rows * width);
    Ok(())
}
/// The end of line after the `stream` keyword (CRLF or LF; a bare CR is not one).
fn stream_eol(p: &mut Parser<'_>) -> Result<()> {
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
    Ok(())
}
/// A bounded window of the source as `Read`; a typed failure (cancel, deadline, work
/// limit) is parked in `failure` because `io::Error` cannot carry it.
struct SourceRead<'x, 'a> {
    input: &'x mut Input<'a>,
    scope: &'x oncl_pki::resource::ResourceScope,
    pos: u64,
    end: u64,
    work: &'x mut u64,
    max_work: u64,
    failure: &'x std::cell::RefCell<Option<PdfError>>,
}
impl Read for SourceRead<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (self.end - self.pos).min(buf.len() as u64).min(65_536) as usize;
        if n == 0 {
            return Ok(0);
        }
        let fail = |this: &Self, error: PdfError| {
            *this.failure.borrow_mut() = Some(error);
            std::io::Error::other("PDF source read failed")
        };
        *self.work = match self.work.checked_add(n as u64) {
            Some(work) if work <= self.max_work => work,
            _ => return Err(fail(self, PdfError::Limit("read work"))),
        };
        match self.input.read_at(self.pos, n, self.scope) {
            Ok(bytes) => {
                buf[..bytes.len()].copy_from_slice(&bytes);
                self.pos += bytes.len() as u64;
                Ok(bytes.len())
            }
            Err(error) => Err(fail(self, error)),
        }
    }
}
/// Decoded bytes of a stream, un-predicted row by row, handed out on demand.
/// Everything inflated is charged to `budget` (`max_decode_work`).
struct RowReader<'r> {
    inner: &'r mut dyn Read,
    layout: Option<Layout>,
    prev: Vec<u8>,
    raw: Vec<u8>,
    pending: Vec<u8>,
    at: usize,
    budget: u64,
    used: u64,
}
impl RowReader<'_> {
    fn charge(&mut self, n: usize) -> Result<()> {
        self.used = self.used.saturating_add(n as u64);
        if self.used > self.budget {
            return Err(PdfError::Limit("decompression work"));
        }
        Ok(())
    }
    /// Append the next decoded bytes to `pending`; `false` at a clean end.
    fn fill(&mut self) -> Result<bool> {
        if self.at == self.pending.len() {
            self.pending.clear();
            self.at = 0;
        }
        let Some(Layout { width, bpp }) = self.layout else {
            let mut chunk = [0u8; 4096];
            let n = self.inner.read(&mut chunk)?;
            self.charge(n)?;
            self.pending.extend_from_slice(&chunk[..n]);
            return Ok(n > 0);
        };
        let stride = width + 1;
        self.raw.resize(stride, 0);
        self.prev.resize(width, 0);
        let mut filled = 0;
        while filled < stride {
            let n = self.inner.read(&mut self.raw[filled..])?;
            if n == 0 {
                return if filled == 0 {
                    Ok(false)
                } else {
                    Err(PdfError::Malformed("truncated predictor row"))
                };
            }
            filled += n;
        }
        self.charge(stride)?;
        let filter = self.raw[0];
        let start = self.pending.len();
        self.pending.resize(start + width, 0);
        for column in 0..width {
            let left = if column >= bpp {
                self.pending[start + column - bpp]
            } else {
                0
            };
            let up = self.prev[column];
            let upper_left = if column >= bpp {
                self.prev[column - bpp]
            } else {
                0
            };
            self.pending[start + column] =
                self.raw[1 + column].wrapping_add(prediction(filter, left, up, upper_left)?);
        }
        self.prev.copy_from_slice(&self.pending[start..]);
        Ok(true)
    }
    fn take(&mut self, out: &mut [u8]) -> Result<()> {
        while self.pending.len() - self.at < out.len() {
            if !self.fill()? {
                return Err(PdfError::Malformed("truncated xref stream"));
            }
        }
        out.copy_from_slice(&self.pending[self.at..self.at + out.len()]);
        self.at += out.len();
        Ok(())
    }
    /// Nothing may follow the declared rows.
    fn finish(&mut self) -> Result<()> {
        if self.at != self.pending.len() || self.fill()? {
            return Err(PdfError::Malformed("xref stream trailing data"));
        }
        Ok(())
    }
}
