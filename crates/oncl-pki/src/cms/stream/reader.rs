use super::StreamError;
use crate::cms::CmsError;
use crate::io::Source;
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope};
use std::io::Read;

pub(super) fn malformed(reason: &str) -> StreamError {
    CmsError::Malformed(reason.to_owned()).into()
}

/// Storage and capacity reservations are deliberately inseparable.
pub(crate) struct Metadata {
    bytes: Vec<u8>,
    memory: ResourceReservation,
    metadata: ResourceReservation,
}
impl Metadata {
    pub(crate) fn new(scope: &ResourceScope) -> Result<Self, ProcessingError> {
        Ok(Self {
            bytes: Vec::new(),
            memory: scope.reserve_memory(0)?,
            metadata: scope.reserve_metadata(0)?,
        })
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), ProcessingError> {
        let len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(ProcessingError::MetadataLimit)?;
        if len > self.bytes.capacity() {
            let capacity = len.max(self.bytes.capacity().saturating_mul(2)).max(32);
            let previous = self.bytes.capacity() as u64;
            // A realloc may hold old and new blocks simultaneously. Reserve
            // that transient peak, not just the final capacity delta.
            self.memory.grow(capacity as u64)?;
            self.metadata.grow(capacity as u64)?;
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| ProcessingError::MemoryLimit)?;
            self.memory.shrink(previous)?;
            self.metadata.shrink(previous)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn append_tlv(&mut self, tag: u8, bytes: &[u8]) -> Result<(), ProcessingError> {
        self.append(&[tag])?;
        let (length, count) = encoded_length(bytes.len() as u64);
        self.append(&length[..count])?;
        self.append(bytes)
    }
    pub(super) fn normalize(self, scope: &ResourceScope) -> Result<Self, StreamError> {
        // The existing normalizer builds a tree (including Vec capacities).
        // Its input is ONLY this bounded metadata TLV, never eContent.
        let bytes = (self.bytes.len() as u64)
            .checked_mul(128)
            .and_then(|n| n.checked_add(1024))
            .ok_or(ProcessingError::MemoryLimit)?;
        let mut memory = scope.reserve_memory(bytes)?;
        let metadata = scope.reserve_metadata(self.bytes.len() as u64)?;
        scope.checkpoint()?;
        let normalized = crate::ber::to_der(&self.bytes).map_err(CmsError::from)?;
        scope.checkpoint()?;
        memory.shrink(bytes - normalized.capacity() as u64)?;
        Ok(Self {
            bytes: normalized,
            memory,
            metadata,
        })
    }
}

pub(super) fn encoded_length(len: u64) -> ([u8; 9], usize) {
    let mut result = [0; 9];
    if len < 128 {
        result[0] = len as u8;
        return (result, 1);
    }
    let bytes = len.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    let count = 8 - first;
    result[0] = 0x80 | count as u8;
    result[1..=count].copy_from_slice(&bytes[first..]);
    (result, count + 1)
}

#[derive(Clone, Copy)]
pub(super) struct Header {
    pub tag: u8,
    pub value_offset: u64,
    pub len: Option<u64>,
    encoded: [u8; 20],
    encoded_len: usize,
}
impl Header {
    pub(super) fn start(self) -> u64 {
        self.value_offset - self.encoded_len as u64
    }
}
#[derive(Clone, Copy)]
struct Frame {
    end: Option<u64>,
    ended: bool,
}
const MAX_DEPTH: usize = 64;

pub(super) struct Reader<'a, 's> {
    source: Source<'a>,
    pub scope: &'s mut ResourceScope,
    buffer: Vec<u8>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
    start: usize,
    available: usize,
    pub offset: u64,
    frames: [Frame; MAX_DEPTH],
    depth: usize,
    replay: bool,
}
impl<'a, 's> Reader<'a, 's> {
    pub fn new(source: Source<'a>, scope: &'s mut ResourceScope) -> Result<Self, StreamError> {
        Self::new_mode(source, scope, false)
    }
    pub(super) fn new_replay(
        source: Source<'a>,
        scope: &'s mut ResourceScope,
    ) -> Result<Self, StreamError> {
        Self::new_mode(source, scope, true)
    }
    fn new_mode(
        source: Source<'a>,
        scope: &'s mut ResourceScope,
        replay: bool,
    ) -> Result<Self, StreamError> {
        scope.checkpoint()?;
        scope.check_input()?;
        if !replay
            && source
                .known_len()
                .is_some_and(|len| len > scope.input_remaining())
        {
            return Err(ProcessingError::InputLimit.into());
        }
        let metadata = scope.reserve_metadata(std::mem::size_of::<Self>() as u64)?;
        // Bounded recursive metadata/content walks retain at most MAX_DEPTH
        // frames. Include their stack allowance, not just the heap I/O buffer.
        let fixed = (std::mem::size_of::<Self>() + MAX_DEPTH * 1024) as u64;
        let capacity = scope
            .available_memory()
            .saturating_sub(fixed)
            .min(IO_CHUNK_BYTES as u64) as usize;
        if capacity == 0 {
            return Err(ProcessingError::MemoryLimit.into());
        }
        let memory = scope.reserve_memory(capacity as u64 + fixed)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| ProcessingError::MemoryLimit)?;
        buffer.resize(capacity, 0);
        Ok(Self {
            source,
            replay,
            scope,
            buffer,
            _memory: memory,
            _metadata: metadata,
            start: 0,
            available: 0,
            offset: 0,
            frames: [Frame {
                end: None,
                ended: false,
            }; MAX_DEPTH],
            depth: 0,
        })
    }
    fn fill(&mut self) -> Result<bool, StreamError> {
        if self.start != self.available {
            return Ok(true);
        }
        loop {
            self.scope.checkpoint()?;
            let request = if self.replay {
                self.buffer.len()
            } else {
                self.scope.input_request(self.buffer.len())?
            };
            let n = match self.source.read(&mut self.buffer[..request]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.map_err(ProcessingError::from)?,
            };
            if n > request {
                return Err(malformed("reader exceeded supplied buffer"));
            }
            if !self.replay {
                self.scope.consumed_input(n as u64)?;
            }
            self.scope.checkpoint()?;
            self.start = 0;
            self.available = n;
            return Ok(n != 0);
        }
    }
    fn byte(&mut self) -> Result<u8, StreamError> {
        if self.depth != 0
            && self.frames[..self.depth]
                .iter()
                .any(|f| f.end.is_some_and(|end| self.offset >= end))
        {
            return Err(malformed("header exceeds enclosing value"));
        }
        if !self.fill()? {
            return Err(malformed("truncated CMS header"));
        }
        let value = self.buffer[self.start];
        self.start += 1;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| malformed("CMS offset overflows u64"))?;
        self.scope.account_container(1)?;
        self.scope.account_framing(1)?;
        Ok(value)
    }
    pub fn next(&mut self) -> Result<Option<Header>, StreamError> {
        self.scope.checkpoint()?;
        if self.depth != 0 {
            let frame = self.frames[self.depth - 1];
            if frame.ended || frame.end == Some(self.offset) {
                return Ok(None);
            }
        }
        let mut encoded = [0; 20];
        let tag = self.byte()?;
        encoded[0] = tag;
        let mut count = 1;
        if tag & 0x1f == 0x1f {
            let mut number = 0u64;
            loop {
                if count >= 11 {
                    return Err(malformed("tag number exceeds u64"));
                }
                let byte = self.byte()?;
                if count == 1 && byte & 0x7f == 0 {
                    return Err(malformed("nonminimal tag number"));
                }
                number = number
                    .checked_mul(128)
                    .and_then(|n| n.checked_add(u64::from(byte & 0x7f)))
                    .ok_or_else(|| malformed("tag number overflows u64"))?;
                encoded[count] = byte;
                count += 1;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            if number < 31 {
                return Err(malformed("nonminimal high tag number"));
            }
        }
        let first = self.byte()?;
        encoded[count] = first;
        count += 1;
        let len = if first == 0x80 {
            None
        } else if first & 0x80 == 0 {
            Some(u64::from(first))
        } else {
            let octets = (first & 0x7f) as usize;
            if octets > 8 {
                return Err(malformed("length exceeds u64"));
            }
            let mut value = 0u64;
            for _ in 0..octets {
                let byte = self.byte()?;
                encoded[count] = byte;
                count += 1;
                value = (value << 8) | u64::from(byte);
            }
            Some(value)
        };
        if tag == 0 {
            if len != Some(0)
                || count != 2
                || self.depth == 0
                || self.frames[self.depth - 1].end.is_some()
            {
                return Err(malformed("unexpected or malformed end-of-contents"));
            }
            self.frames[self.depth - 1].ended = true;
            return Ok(None);
        }
        if len.is_none() && tag & 0x20 == 0 {
            return Err(malformed("indefinite primitive value"));
        }
        if let Some(len) = len {
            let end = self
                .offset
                .checked_add(len)
                .ok_or_else(|| malformed("CMS value end overflows u64"))?;
            if self.frames[..self.depth]
                .iter()
                .any(|frame| frame.end.is_some_and(|parent| end > parent))
            {
                return Err(malformed("value exceeds enclosing length"));
            }
            // A declared value must fit the total wire allowance, including
            // already buffered but not yet parsed bytes. Do not narrow to usize.
            if end > self.scope.limits().input_bytes {
                return Err(ProcessingError::InputLimit.into());
            }
        }
        Ok(Some(Header {
            tag,
            value_offset: self.offset,
            len,
            encoded,
            encoded_len: count,
        }))
    }
    pub fn required(&mut self, tag: u8) -> Result<Header, StreamError> {
        let header = self.next()?.ok_or_else(|| malformed("missing CMS field"))?;
        if header.tag != tag {
            return Err(malformed("unexpected CMS field tag"));
        }
        Ok(header)
    }
    pub fn enter(&mut self, header: Header) -> Result<(), StreamError> {
        if header.tag & 0x20 == 0 {
            return Err(malformed("constructed value required"));
        }
        if self.depth == MAX_DEPTH {
            return Err(malformed("CMS nesting depth exceeded"));
        }
        self.frames[self.depth] = Frame {
            end: header.len.map(|len| header.value_offset + len),
            ended: false,
        };
        self.depth += 1;
        Ok(())
    }
    pub fn leave(&mut self) -> Result<(), StreamError> {
        if self.depth == 0 || self.next()?.is_some() {
            return Err(malformed("unexpected extra CMS field"));
        }
        self.depth -= 1;
        Ok(())
    }
    pub fn payload(
        &mut self,
        len: u64,
        content: bool,
        mut consume: impl FnMut(&[u8], &ResourceScope) -> Result<(), StreamError>,
    ) -> Result<(), StreamError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| malformed("CMS payload overflows u64"))?;
        if self.frames[..self.depth]
            .iter()
            .any(|frame| frame.end.is_some_and(|parent| end > parent))
        {
            return Err(malformed("payload exceeds parent"));
        }
        let mut remaining = len;
        while remaining != 0 {
            self.scope.checkpoint()?;
            if !self.fill()? {
                return Err(malformed("truncated CMS payload"));
            }
            let count = remaining.min((self.available - self.start) as u64) as usize;
            if !content {
                self.scope.account_container(count as u64)?;
            }
            consume(&self.buffer[self.start..self.start + count], self.scope)?;
            self.start += count;
            self.offset += count as u64;
            remaining -= count as u64;
            self.scope.checkpoint()?;
        }
        Ok(())
    }
    fn capture(&mut self, header: Header, result: &mut Metadata) -> Result<(), StreamError> {
        result.append(&header.encoded[..header.encoded_len])?;
        if header.tag & 0x20 == 0 {
            self.payload(
                header
                    .len
                    .ok_or_else(|| malformed("indefinite metadata primitive"))?,
                false,
                |bytes, _| {
                    result.append(bytes)?;
                    Ok(())
                },
            )?;
        } else {
            self.enter(header)?;
            while let Some(child) = self.next()? {
                self.capture(child, result)?;
            }
            self.leave()?;
            if header.len.is_none() {
                result.append(&[0, 0])?;
            }
        }
        Ok(())
    }
    pub fn metadata(&mut self, header: Header) -> Result<Metadata, StreamError> {
        let mut value = Metadata::new(self.scope)?;
        self.capture(header, &mut value)?;
        value.normalize(self.scope)
    }
    pub fn finish(&mut self) -> Result<(), StreamError> {
        if self.depth != 0 {
            return Err(malformed("unclosed CMS value"));
        }
        if self.fill()? {
            return Err(malformed("trailing CMS data"));
        }
        self.scope.checkpoint()?;
        Ok(())
    }
}

impl Reader<'_, '_> {
    pub fn raw_content(
        &mut self,
        mut consume: impl FnMut(&[u8]) -> Result<(), StreamError>,
    ) -> Result<(), StreamError> {
        while self.fill()? {
            self.scope.checkpoint()?;
            consume(&self.buffer[self.start..self.available])?;
            self.offset = self
                .offset
                .checked_add((self.available - self.start) as u64)
                .ok_or_else(|| malformed("content length overflows u64"))?;
            self.start = self.available;
            self.scope.checkpoint()?;
        }
        Ok(())
    }
}
