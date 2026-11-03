//! Bounded admission around multer's boundary/header parser. This adapter does
//! not interpret multipart framing. The host validates a parsed field's role
//! before enabling data, and charges its transport buffers separately.
use axum::body::Bytes;
use futures_util::Stream;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

const FEED_BYTES: usize = 4096;
const HEADER_CREDIT: usize = 8192;
const MAX_PARTS: usize = 128;

#[derive(Default)]
struct Admission {
    header_credit: Option<usize>,
}
struct Feeder<S> {
    input: Pin<Box<S>>,
    pending: Bytes,
    yield_poll: bool,
    remaining: u64,
    admission: Arc<Mutex<Admission>>,
}
impl<S, E> Stream for Feeder<S>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Item = Result<Bytes, io::Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // multer::StreamBuffer::poll_stream drains all Ready chunks into one
        // BytesMut. A bounded chunk without this cooperative barrier is NOT a
        // memory bound, even for a perfectly valid document.
        if this.yield_poll {
            this.yield_poll = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if this.pending.is_empty() {
            match this.input.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(bytes))) => this.pending = bytes,
                Poll::Ready(Some(Err(_))) => {
                    return Poll::Ready(Some(Err(io::Error::other("multipart transport failed"))));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
        let count = FEED_BYTES.min(this.pending.len());
        let mut state = this
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if this.remaining < count as u64 {
            return Poll::Ready(Some(Err(io::Error::other("multipart framing limit"))));
        }
        if let Some(credit) = state.header_credit.as_mut() {
            if *credit < count {
                return Poll::Ready(Some(Err(io::Error::other("multipart header limit"))));
            }
            *credit -= count;
        }
        this.remaining -= count as u64;
        this.yield_poll = true;
        // This retains the original input allocation. A host must admit that
        // allocation (not just count this slice); only one input frame is held.
        Poll::Ready(Some(Ok(this.pending.split_to(count))))
    }
}

pub struct BoundedMultipart<'a> {
    parser: multer::Multipart<'a>,
    admission: Arc<Mutex<Admission>>,
    parts: usize,
    allowed: Vec<String>,
    part_limit: usize,
    installed: bool,
}
impl<'a> BoundedMultipart<'a> {
    pub fn new<S, E>(
        input: S,
        boundary: &str,
        framing_bytes: u64,
        allowed: &[&str],
    ) -> io::Result<Self>
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'a,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'a,
    {
        if boundary.is_empty()
            || boundary.len() > 70
            || !boundary
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=?".contains(&b))
            || framing_bytes == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid multipart boundary or limit",
            ));
        }
        let admission = Arc::new(Mutex::new(Admission {
            header_credit: Some(HEADER_CREDIT),
        }));
        let feeder = Feeder {
            input: Box::pin(input),
            pending: Bytes::new(),
            yield_poll: false,
            remaining: framing_bytes,
            admission: admission.clone(),
        };
        let constraints = multer::Constraints::new()
            .size_limit(multer::SizeLimit::new().whole_stream(framing_bytes));
        Ok(Self {
            parser: multer::Multipart::with_constraints(feeder, boundary, constraints),
            admission,
            parts: 0,
            allowed: allowed.iter().map(|s| (*s).to_owned()).collect(),
            part_limit: MAX_PARTS,
            installed: false,
        })
    }
    /// Header/preamble admission is restored before polling the actual parser.
    /// At most one previous data-feed chunk plus the <=74-byte boundary suffix
    /// can already be buffered, in addition to the new 8192-byte header credit.
    /// A dropped/partially consumed previous field never bypasses this bound.
    pub async fn next_field(&mut self) -> Result<Option<multer::Field<'a>>, multer::Error> {
        self.admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .header_credit = Some(HEADER_CREDIT);
        let field = self.parser.next_field().await?;
        if let Some(field) = &field {
            if self.parts >= self.part_limit
                || !field
                    .name()
                    .is_some_and(|name| self.allowed.iter().any(|s| s == name))
            {
                return Err(multer::Error::IncompleteStream);
            }
            self.parts += 1;
        }
        Ok(field)
    }
    /// Install the already host-validated metadata schema, exactly once after
    /// the initial metadata field. No later field may change role/cardinality.
    pub fn install_fields(&mut self, allowed: &[&str], part_count: usize) -> io::Result<()> {
        if self.installed || self.parts != 1 || part_count != allowed.len() || part_count > 2048 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid multipart field schema",
            ));
        }
        self.allowed = allowed.iter().map(|s| (*s).to_owned()).collect();
        self.part_limit = part_count + 1;
        self.installed = true;
        Ok(())
    }
    /// Call ONLY after checking the returned field name against the immutable
    /// host-validated metadata role. A filename or Content-Type is not a role.
    pub fn admit_data(&mut self) {
        self.admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .header_credit = None;
    }
}
