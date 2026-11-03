use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::stream::Stream;

use crate::{constants, FramingObserver};

pub(crate) struct StreamBuffer<'r> {
    pub(crate) eof: bool,
    pub(crate) buf: BytesMut,
    pub(crate) stream: Pin<Box<dyn Stream<Item = Result<Bytes, crate::Error>> + Send + 'r>>,
    pub(crate) whole_stream_size_limit: u64,
    pub(crate) stream_size_counter: u64,
    framing_observer: Option<std::sync::Arc<dyn FramingObserver>>,
    // A prefix of buf already proven/charged as framing, even before a split
    // terminator arrives. Advancing it never refunds the host's cumulative count.
    framing_credited: usize,
}

impl<'r> StreamBuffer<'r> {
    pub fn new<S>(
        stream: S,
        whole_stream_size_limit: u64,
        framing_observer: Option<std::sync::Arc<dyn FramingObserver>>,
    ) -> Self
    where
        S: Stream<Item = Result<Bytes, crate::Error>> + Send + 'r,
    {
        StreamBuffer {
            eof: false,
            buf: BytesMut::new(),
            stream: Box::pin(stream),
            whole_stream_size_limit,
            stream_size_counter: 0,
            framing_observer,
            framing_credited: 0,
        }
    }

    pub fn poll_stream(&mut self, cx: &mut Context<'_>) -> Result<(), crate::Error> {
        if self.eof {
            return Ok(());
        }

        loop {
            match self.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    self.stream_size_counter = self.stream_size_counter.checked_add(data.len() as u64).ok_or(
                        crate::Error::StreamSizeExceeded {
                            limit: self.whole_stream_size_limit,
                        },
                    )?;

                    if self.stream_size_counter > self.whole_stream_size_limit {
                        return Err(crate::Error::StreamSizeExceeded {
                            limit: self.whole_stream_size_limit,
                        });
                    }

                    self.buf.extend_from_slice(&data)
                }
                Poll::Ready(Some(Err(err))) => return Err(err),
                Poll::Ready(None) => {
                    self.eof = true;
                    return Ok(());
                }
                Poll::Pending => return Ok(()),
            }
        }
    }

    pub(crate) fn credit_framing(&mut self, prefix: usize) -> crate::Result<()> {
        if prefix > self.buf.len() {
            return Err(crate::Error::IncompleteStream);
        }
        if let Some(observer) = &self.framing_observer {
            if prefix > self.framing_credited {
                let newly_proven = prefix - self.framing_credited;
                self.framing_credited = prefix;
                observer
                    .observe(newly_proven as u64)
                    .map_err(crate::Error::StreamReadFailed)?;
            }
        }
        Ok(())
    }
    fn advance_framing(&mut self, size: usize) -> crate::Result<()> {
        self.credit_framing(size)?;
        self.buf.advance(size);
        self.framing_credited = self.framing_credited.saturating_sub(size);
        Ok(())
    }

    pub fn read_exact(&mut self, size: usize) -> crate::Result<Option<Bytes>> {
        self.credit_framing(size.min(self.buf.len()))?;
        if size <= self.buf.len() {
            let bytes = self.buf.split_to(size).freeze();
            self.framing_credited = self.framing_credited.saturating_sub(size);
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    pub fn peek_exact(&mut self, size: usize) -> Option<&[u8]> {
        self.buf.get(..size)
    }

    pub fn read_until(&mut self, pattern: &[u8]) -> crate::Result<Option<Bytes>> {
        let end = memchr::memmem::find(&self.buf, pattern).map(|idx| idx + pattern.len());
        self.credit_framing(end.unwrap_or(self.buf.len()))?;
        match end {
            Some(size) => self.read_exact(size),
            None => Ok(None),
        }
    }

    pub fn read_to(&mut self, pattern: &[u8]) -> crate::Result<Option<Bytes>> {
        let end = memchr::memmem::find(&self.buf, pattern);
        let proven = end.unwrap_or_else(|| self.buf.len().saturating_sub(pattern.len().saturating_sub(1)));
        self.credit_framing(proven)?;
        match end {
            Some(size) => self.read_exact(size),
            None => Ok(None),
        }
    }

    pub fn advance_past_transport_padding(&mut self) -> crate::Result<bool> {
        match self.buf.iter().position(|b| *b != b' ' && *b != b'\t') {
            Some(pos) => {
                self.advance_framing(pos)?;
                Ok(true)
            }
            None => {
                let size = self.buf.len();
                self.advance_framing(size)?;
                Ok(false)
            }
        }
    }

    pub fn read_field_data(
        &mut self,
        boundary: &str,
        field_name: Option<&str>,
    ) -> crate::Result<Option<(bool, Bytes)>> {
        trace!("finding next field: {:?}", field_name);
        if self.buf.is_empty() && self.eof {
            trace!("empty buffer && EOF");
            return Err(crate::Error::IncompleteFieldData {
                field_name: field_name.map(|s| s.to_owned()),
            });
        } else if self.buf.is_empty() {
            return Ok(None);
        }

        let boundary_deriv = format!("{}{}{}", constants::CRLF, constants::BOUNDARY_EXT, boundary);
        let b_len = boundary_deriv.len();

        match memchr::memmem::find(&self.buf, boundary_deriv.as_bytes()) {
            Some(idx) => {
                trace!("new field found at {}", idx);
                let bytes = self.buf.split_to(idx).freeze();

                // discard \r\n.
                self.advance_framing(constants::CRLF.len())?;

                Ok(Some((true, bytes)))
            }
            None if self.eof => {
                trace!("no new field found: EOF. terminating");
                Err(crate::Error::IncompleteFieldData {
                    field_name: field_name.map(|s| s.to_owned()),
                })
            }
            None => {
                let buf_len = self.buf.len();
                let rem_boundary_part_max_len = b_len - 1;
                let rem_boundary_part_idx = if buf_len >= rem_boundary_part_max_len {
                    buf_len - rem_boundary_part_max_len
                } else {
                    0
                };

                trace!("no new field found, not EOF, checking close");
                let bytes = &self.buf[rem_boundary_part_idx..];
                match memchr::memmem::rfind(bytes, constants::CR.as_bytes()) {
                    Some(rel_idx) => {
                        let idx = rel_idx + rem_boundary_part_idx;

                        match memchr::memmem::find(boundary_deriv.as_bytes(), &self.buf[idx..]) {
                            Some(_) => {
                                let bytes = self.buf.split_to(idx).freeze();

                                match bytes.is_empty() {
                                    true => Ok(None),
                                    false => Ok(Some((false, bytes))),
                                }
                            }
                            None => Ok(Some((false, self.read_full_buf()))),
                        }
                    }
                    None => Ok(Some((false, self.read_full_buf()))),
                }
            }
        }
    }

    pub fn read_full_buf(&mut self) -> Bytes {
        self.buf.split_to(self.buf.len()).freeze()
    }
}

impl fmt::Debug for StreamBuffer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamBuffer").finish()
    }
}
