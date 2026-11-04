//! Bounded `multipart/form-data` writer: a `Read` that yields the metadata field, every
//! secret part (memory only) and then every document part in declaration order.
//!
//! Document bodies are streamed from their readers (files, stdin) straight into the caller's
//! buffer: nothing is collected, framing is O(1), and a source that does not deliver exactly
//! its declared length is an error, never a silently shorter or longer upload. The writer
//! records how many bytes were handed to the transport and whether the *whole* body was
//! handed over: only then can the service have started the private operation.
use super::{Source, Stop};
use std::io::{self, Read};
use zeroize::Zeroizing;

enum Piece {
    /// Framing or memory-only bytes (metadata JSON, secrets, small documents).
    Bytes(Zeroizing<Vec<u8>>, usize),
    /// A streamed document with its declared length, if known.
    Stream {
        reader: Box<dyn Read + Send>,
        declared: Option<u64>,
        produced: u64,
    },
}

/// Why the body stopped before its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UploadFailure {
    Stop(Stop),
    /// A document source failed or did not deliver its declared length.
    Source,
}

pub(super) struct Upload<'a> {
    pieces: Vec<Piece>,
    /// Indexes of the pieces whose bytes are document payload (not framing, not secrets).
    document_pieces: Vec<usize>,
    index: usize,
    control: &'a (dyn Fn() -> Result<(), Stop> + 'a),
    handed: u64,
    documents: u64,
    total: Option<u64>,
    complete: bool,
    failure: Option<UploadFailure>,
}

const BOUNDARY_BYTES: usize = 24;

pub(super) fn boundary() -> io::Result<String> {
    let mut random = [0u8; BOUNDARY_BYTES];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let mut text = String::from("oncl-");
    for byte in random {
        text.push_str(&format!("{byte:02x}"));
    }
    Ok(text)
}

fn disposition(boundary: &str, name: &str, content_type: Option<&str>) -> Vec<u8> {
    let mut head = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n");
    if let Some(content_type) = content_type {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

fn add(pieces: &mut Vec<Piece>, total: &mut Option<u64>, piece: Piece) {
    *total = match (&piece, *total) {
        (Piece::Bytes(bytes, _), Some(n)) => Some(n + bytes.len() as u64),
        (
            Piece::Stream {
                declared: Some(len),
                ..
            },
            Some(n),
        ) => Some(n + len),
        _ => None,
    };
    pieces.push(piece);
}

impl<'a> Upload<'a> {
    /// `parts` are in wire order (secrets first, as declared by the metadata); the flag says
    /// whether the part is a document (counted in [`Upload::documents`]) or a secret.
    pub(super) fn new(
        boundary: &str,
        metadata: &[u8],
        parts: Vec<(String, bool, Source)>,
        control: &'a (dyn Fn() -> Result<(), Stop> + 'a),
    ) -> Self {
        let mut pieces = Vec::with_capacity(parts.len() * 3 + 2);
        let mut document_pieces = Vec::new();
        let mut total = Some(0u64);
        // The metadata field and its framing: plain JSON, never a secret.
        let mut first = disposition(boundary, "metadata", None);
        first.extend_from_slice(metadata);
        first.extend_from_slice(b"\r\n");
        add(
            &mut pieces,
            &mut total,
            Piece::Bytes(Zeroizing::new(first), 0),
        );
        for (name, document, source) in parts {
            // Header, payload and CRLF are separate pieces so a secret is never copied into
            // a framing buffer.
            let header = disposition(boundary, &name, Some("application/octet-stream"));
            add(
                &mut pieces,
                &mut total,
                Piece::Bytes(Zeroizing::new(header), 0),
            );
            if document {
                document_pieces.push(pieces.len());
            }
            let payload = match source {
                Source::Memory(bytes) => Piece::Bytes(bytes, 0),
                Source::Stream { reader, length } => Piece::Stream {
                    reader,
                    declared: length,
                    produced: 0,
                },
            };
            add(&mut pieces, &mut total, payload);
            add(
                &mut pieces,
                &mut total,
                Piece::Bytes(Zeroizing::new(b"\r\n".to_vec()), 0),
            );
        }
        let closing = format!("--{boundary}--\r\n").into_bytes();
        add(
            &mut pieces,
            &mut total,
            Piece::Bytes(Zeroizing::new(closing), 0),
        );
        Self {
            pieces,
            document_pieces,
            index: 0,
            control,
            handed: 0,
            documents: 0,
            total,
            complete: false,
            failure: None,
        }
    }

    /// The exact request body length when every document length is known.
    pub(super) fn length(&self) -> Option<u64> {
        self.total
    }
    /// True once the last byte of the body was handed to the transport.
    pub(super) fn complete(&self) -> bool {
        self.complete
    }
    pub(super) fn failure(&self) -> Option<UploadFailure> {
        self.failure
    }
    /// Document payload bytes handed to the transport (never framing or secrets).
    pub(super) fn documents(&self) -> u64 {
        self.documents
    }
    #[cfg(test)]
    pub(super) fn handed(&self) -> u64 {
        self.handed
    }

    fn fail(&mut self, failure: UploadFailure, error: io::Error) -> io::Error {
        self.failure.get_or_insert(failure);
        error
    }
}

impl Read for Upload<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(failure) = self.failure {
            return Err(io::Error::other(match failure {
                UploadFailure::Stop(_) => "request body aborted",
                UploadFailure::Source => "request source failed",
            }));
        }
        if let Err(stop) = (self.control)() {
            return Err(self.fail(
                UploadFailure::Stop(stop),
                io::Error::new(io::ErrorKind::Interrupted, "request body aborted"),
            ));
        }
        loop {
            let counted = self.document_pieces.binary_search(&self.index).is_ok();
            let Some(piece) = self.pieces.get_mut(self.index) else {
                self.complete = true;
                return Ok(0);
            };
            match piece {
                Piece::Bytes(bytes, at) => {
                    let remaining = &bytes[*at..];
                    if remaining.is_empty() {
                        self.index += 1;
                        continue;
                    }
                    let count = remaining.len().min(out.len());
                    out[..count].copy_from_slice(&remaining[..count]);
                    *at += count;
                    self.handed += count as u64;
                    if counted {
                        self.documents += count as u64;
                    }
                    if self.total == Some(self.handed) {
                        self.complete = true;
                    }
                    return Ok(count);
                }
                Piece::Stream {
                    reader,
                    declared,
                    produced,
                } => {
                    let wanted = match declared {
                        Some(len) => {
                            let left = *len - *produced;
                            if left == 0 {
                                // The source must be exhausted exactly at its declared
                                // length: a grown file is not silently truncated.
                                let mut probe = [0u8; 1];
                                loop {
                                    match reader.read(&mut probe) {
                                        Ok(0) => break,
                                        Ok(_) => {
                                            return Err(self.fail(
                                                UploadFailure::Source,
                                                io::Error::other("source grew while sending"),
                                            ));
                                        }
                                        Err(error)
                                            if error.kind() == io::ErrorKind::Interrupted => {}
                                        Err(error) => {
                                            return Err(self.fail(UploadFailure::Source, error));
                                        }
                                    }
                                }
                                self.index += 1;
                                continue;
                            }
                            out.len().min(usize::try_from(left).unwrap_or(usize::MAX))
                        }
                        None => out.len(),
                    };
                    match reader.read(&mut out[..wanted]) {
                        Ok(0) => {
                            if declared.is_some() {
                                return Err(self.fail(
                                    UploadFailure::Source,
                                    io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "source ended before its declared length",
                                    ),
                                ));
                            }
                            self.index += 1;
                            continue;
                        }
                        Ok(count) => {
                            *produced += count as u64;
                            self.handed += count as u64;
                            self.documents += count as u64;
                            return Ok(count);
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(self.fail(UploadFailure::Source, error)),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(upload: &mut Upload<'_>) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 7];
        loop {
            match upload.read(&mut chunk)? {
                0 => return Ok(out),
                n => out.extend_from_slice(&chunk[..n]),
            }
        }
    }
    fn control() -> Result<(), Stop> {
        Ok(())
    }

    #[test]
    fn frames_metadata_secrets_then_documents_and_reports_the_exact_length() {
        let parts = vec![
            (
                "pw".to_owned(),
                false,
                Source::Memory(Zeroizing::new(b"secret".to_vec())),
            ),
            (
                "doc".to_owned(),
                true,
                Source::Stream {
                    reader: Box::new(io::Cursor::new(b"abc".to_vec())),
                    length: Some(3),
                },
            ),
        ];
        let mut upload = Upload::new("B", b"{}", parts, &control);
        let declared = upload.length().unwrap();
        let body = read_all(&mut upload).unwrap();
        assert_eq!(body.len() as u64, declared);
        assert!(upload.complete());
        // Only the document counts as document bytes: not framing, not the secret.
        assert_eq!(upload.documents(), 3);
        let text = String::from_utf8(body).unwrap();
        let metadata = text.find("name=\"metadata\"").unwrap();
        let secret = text.find("name=\"pw\"").unwrap();
        let document = text.find("name=\"doc\"").unwrap();
        assert!(metadata < secret && secret < document);
        assert!(text.ends_with("\r\n--B--\r\n"));
        assert!(text.contains("\r\n\r\nabc\r\n--B"));
    }

    #[test]
    fn small_memory_documents_are_counted_as_documents() {
        let parts = vec![(
            "doc".to_owned(),
            true,
            Source::Memory(Zeroizing::new(b"hello".to_vec())),
        )];
        let mut upload = Upload::new("B", b"{}", parts, &control);
        read_all(&mut upload).unwrap();
        assert_eq!(upload.documents(), 5);
    }

    #[test]
    fn unknown_length_has_no_declared_length() {
        let parts = vec![(
            "doc".to_owned(),
            true,
            Source::Stream {
                reader: Box::new(io::Cursor::new(b"abcdef".to_vec())),
                length: None,
            },
        )];
        let mut upload = Upload::new("B", b"{}", parts, &control);
        assert_eq!(upload.length(), None);
        let body = read_all(&mut upload).unwrap();
        assert!(String::from_utf8(body).unwrap().contains("abcdef"));
        assert!(upload.complete());
    }

    #[test]
    fn a_source_shorter_or_longer_than_declared_is_never_sent_as_if_complete() {
        for (bytes, declared) in [(b"ab".to_vec(), 3u64), (b"abcd".to_vec(), 3u64)] {
            let parts = vec![(
                "doc".to_owned(),
                true,
                Source::Stream {
                    reader: Box::new(io::Cursor::new(bytes)),
                    length: Some(declared),
                },
            )];
            let mut upload = Upload::new("B", b"{}", parts, &control);
            assert!(read_all(&mut upload).is_err());
            assert!(!upload.complete());
            assert_eq!(upload.failure(), Some(UploadFailure::Source));
            // The failure is sticky: no later read can resume the body.
            assert!(upload.read(&mut [0u8; 8]).is_err());
        }
    }

    #[test]
    fn control_stop_aborts_before_the_body_is_complete() {
        let stop = || Err(Stop::Cancelled);
        let parts = vec![(
            "doc".to_owned(),
            true,
            Source::Stream {
                reader: Box::new(io::Cursor::new(vec![1u8; 100])),
                length: Some(100),
            },
        )];
        let mut upload = Upload::new("B", b"{}", parts, &stop);
        assert!(upload.read(&mut [0u8; 16]).is_err());
        assert!(!upload.complete());
        assert_eq!(upload.handed(), 0);
        assert_eq!(upload.failure(), Some(UploadFailure::Stop(Stop::Cancelled)));
    }
}
