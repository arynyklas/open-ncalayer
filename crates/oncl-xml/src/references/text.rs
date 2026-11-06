//! The text of one base64 evidence leaf, streamed from its source extents.
use super::*;
use oncl_pki::resource::IO_CHUNK_BYTES;
use std::io;

/// Decoded text (entity references resolved, CDATA content verbatim) of the text extents
/// of one `Encapsulated*` leaf, read piecewise through a single fixed buffer: the encoded
/// text of a multi-megabyte CRL is never materialised. It is the `Read` the base64
/// evidence collector decodes, so the decoded bytes are charged to the evidence quotas
/// as they appear.
pub(super) struct EvidenceText<'a> {
    document: &'a mut XmlDocument,
    spans: &'a [Span],
    index: usize,
    taken: u64,
    raw: Vec<u8>,
    raw_len: usize,
    raw_pos: usize,
    raw_cdata: bool,
    reference: [u8; 37],
    reference_len: usize,
    in_reference: bool,
    carry: [u8; 4],
    carry_len: usize,
    carry_pos: usize,
    /// A failure of the source or of the quota accounting, kept for the caller.
    pub(super) error: Option<ProcessingError>,
    /// The text itself is malformed (an unknown or unterminated reference).
    pub(super) invalid: bool,
    _memory: ResourceReservation,
}
impl<'a> EvidenceText<'a> {
    pub(super) fn new(
        document: &'a mut XmlDocument,
        spans: &'a [Span],
        scope: &ResourceScope,
    ) -> Result<Self> {
        let memory = scope.reserve_memory(IO_CHUNK_BYTES as u64 + 256)?;
        Ok(Self {
            document,
            spans,
            index: 0,
            taken: 0,
            raw: vec![0; IO_CHUNK_BYTES],
            raw_len: 0,
            raw_pos: 0,
            raw_cdata: false,
            reference: [0; 37],
            reference_len: 0,
            in_reference: false,
            carry: [0; 4],
            carry_len: 0,
            carry_pos: 0,
            error: None,
            invalid: false,
            _memory: memory,
        })
    }
    fn malformed(&mut self) -> io::Error {
        self.invalid = true;
        io::Error::new(io::ErrorKind::InvalidData, "malformed evidence text")
    }
    /// Refill the raw window from the next extent; false at the end of the text.
    fn fill(&mut self) -> io::Result<bool> {
        loop {
            let Some(span) = self.spans.get(self.index) else {
                return if self.in_reference {
                    Err(self.malformed())
                } else {
                    Ok(false)
                };
            };
            if self.taken == span.region.len {
                if self.in_reference {
                    return Err(self.malformed());
                }
                self.index += 1;
                self.taken = 0;
                continue;
            }
            let region = Region {
                offset: span.region.offset + self.taken,
                len: span.region.len - self.taken,
            };
            let cdata = span.cdata;
            let n = match self.document.read_region(region, &mut self.raw) {
                Ok(0) => {
                    self.error = Some(ProcessingError::InvalidInput("short evidence text"));
                    return Err(io::Error::other("short evidence text"));
                }
                Ok(n) => n,
                Err(error) => {
                    self.error = Some(error);
                    return Err(io::Error::other("evidence text source"));
                }
            };
            self.raw_len = n;
            self.raw_pos = 0;
            self.raw_cdata = cdata;
            self.taken += n as u64;
            return Ok(true);
        }
    }
}
impl io::Read for EvidenceText<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < out.len() {
            if self.carry_pos < self.carry_len {
                out[written] = self.carry[self.carry_pos];
                self.carry_pos += 1;
                written += 1;
                continue;
            }
            if self.raw_pos == self.raw_len && !self.fill()? {
                break;
            }
            let byte = self.raw[self.raw_pos];
            self.raw_pos += 1;
            if self.in_reference {
                if byte == b';' {
                    let c = crate::canonical_stream::entity(&self.reference[..self.reference_len])
                        .map_err(|_| self.malformed())?;
                    self.carry_len = c.encode_utf8(&mut self.carry).len();
                    self.carry_pos = 0;
                    self.reference_len = 0;
                    self.in_reference = false;
                } else {
                    if self.reference_len == self.reference.len() {
                        return Err(self.malformed());
                    }
                    self.reference[self.reference_len] = byte;
                    self.reference_len += 1;
                }
                continue;
            }
            if byte == b'&' && !self.raw_cdata {
                self.in_reference = true;
                continue;
            }
            out[written] = byte;
            written += 1;
        }
        Ok(written)
    }
}
