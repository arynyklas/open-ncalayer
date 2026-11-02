//! Seekable, bounded PDF signature inspection. Never renders or executes PDF actions.
mod byte_range;
mod objects;
mod source;
mod verify;
mod xref;
pub use byte_range::ByteRange;
use oncl_pki::{
    io::Source,
    resource::{ProcessingError, ResourceReservation, ResourceScope},
};
pub use verify::{
    PdfRevisionFacts, PdfSignature, PdfSignatureFacts, PdfVerification, ScopedPdfRows,
    verify_source,
};

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("malformed PDF: {0}")]
    Malformed(&'static str),
    #[error("unsupported PDF: {0}")]
    Unsupported(&'static str),
    #[error("PDF limit exceeded: {0}")]
    Limit(&'static str),
    #[error(transparent)]
    Processing(#[from] ProcessingError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Cms(#[from] oncl_pki::cms::stream::StreamError),
}
pub type Result<T, E = PdfError> = std::result::Result<T, E>;
#[derive(Debug, Clone)]
pub struct PdfLimits {
    pub max_object_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_objects: usize,
    pub max_revisions: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_signatures: usize,
    pub max_read_work: u64,
    pub max_decode_work: u64,
}
impl Default for PdfLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: 1_048_576,
            max_decoded_bytes: 4_194_304,
            max_objects: 4096,
            max_revisions: 16,
            max_nodes: 16_384,
            max_depth: 64,
            max_signatures: 64,
            max_read_work: 1_073_741_824,
            max_decode_work: 268_435_456,
        }
    }
}
/// Owns only bounded cross-reference metadata, not page content or a document DOM.
/// Source extent is measured from its current logical start, ignoring length hints.
pub struct PdfDocument<'a, 's> {
    pub(crate) input: source::Input<'a>,
    pub(crate) scope: &'s mut ResourceScope,
    pub(crate) limits: PdfLimits,
    pub(crate) revisions: Vec<xref::Revision>,
    pub(crate) work: u64,
    pub(crate) decoded: u64,
    // One-entry cache: bounded by max_decoded_bytes, invalidated by revision.
    pub(crate) object_stream_cache: Option<(usize, u32, objects::Value, Vec<u8>)>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl<'a, 's> PdfDocument<'a, 's> {
    pub fn open(
        source: Source<'a>,
        limits: &PdfLimits,
        scope: &'s mut ResourceScope,
    ) -> Result<Self> {
        if limits.max_object_bytes < 32
            || limits.max_decoded_bytes == 0
            || limits.max_objects == 0
            || limits.max_revisions == 0
            || limits.max_depth == 0
            || limits.max_depth > 128
            || limits.max_signatures == 0
        {
            return Err(PdfError::Limit("invalid reader limits"));
        }
        // Admission covers transient window/parser trees and all xref revisions;
        // there is intentionally no unbounded object cache.
        let metadata = (limits.max_objects as u64)
            .checked_mul(limits.max_revisions as u64)
            .and_then(|n| n.checked_mul(96))
            .and_then(|n| n.checked_add((limits.max_object_bytes as u64).checked_mul(32)?))
            .ok_or(ProcessingError::MetadataLimit)?;
        let memory = metadata
            .checked_add(
                (limits.max_decoded_bytes as u64)
                    .checked_mul(4)
                    .ok_or(ProcessingError::MemoryLimit)?,
            )
            .and_then(|n| n.checked_add((limits.max_object_bytes as u64).checked_mul(96)?))
            .ok_or(ProcessingError::MemoryLimit)?;
        let metadata_reservation = scope.reserve_metadata(metadata)?;
        let memory_reservation = scope.reserve_memory(memory)?;
        let input = source::Input::new(source, scope)?;
        let mut doc = Self {
            input,
            scope,
            limits: limits.clone(),
            revisions: Vec::new(),
            work: 0,
            decoded: 0,
            object_stream_cache: None,
            _memory: memory_reservation,
            _metadata: metadata_reservation,
        };
        let header = doc.input.read_at(0, 8, doc.scope)?;
        if !header.starts_with(b"%PDF-1.") && !header.starts_with(b"%PDF-2.") {
            return Err(PdfError::Unsupported("PDF header"));
        }
        doc.load_revisions()?;
        Ok(doc)
    }
    pub fn extent(&self) -> u64 {
        self.input.extent
    }
    pub fn revision_count(&self) -> usize {
        self.revisions.len()
    }
    pub fn revision_ends(&self) -> impl Iterator<Item = u64> + '_ {
        self.revisions.iter().map(|r| r.end)
    }
}
