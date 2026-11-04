//! Bounded PDF signature inspection and incremental signing; never renders or executes actions.
pub mod ades;
mod byte_range;
mod objects;
mod sign;
mod source;
mod verify;
mod xref;
pub use byte_range::ByteRange;
use oncl_pki::{
    io::Source,
    resource::{ProcessingError, ResourceReservation, ResourceScope},
};
pub use sign::{PdfOperationReport, PdfSignProfile, sign_source};
pub use verify::{
    PdfEndpointScope, PdfRevisionFacts, PdfSignature, PdfSignatureFacts, PdfVerification,
    ScopedPdfRows, verify_source,
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
    #[error(transparent)]
    Ades(#[from] oncl_pki::cms::ades::AdesError),
}
/// Memory/metadata the PDF layer reserves, computed in ONE place. The reader,
/// the update plan and the signer reserve through these functions, and hosts call
/// [`budget::plan_memory`] to refuse a predictable need before any private key use.
pub mod budget {
    use super::PdfLimits;
    use oncl_pki::resource::ProcessingError;
    /// `(metadata, memory)` reserved by one document reader.
    pub fn reader(limits: &PdfLimits) -> Result<(u64, u64), ProcessingError> {
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
        Ok((metadata, memory))
    }
    /// Memory reserved by the PAdES update plan itself (before its nested reader).
    pub fn plan_reservation(limits: &PdfLimits) -> Result<u64, ProcessingError> {
        (limits.max_object_bytes as u64)
            .checked_mul(128)
            .ok_or(ProcessingError::MemoryLimit)
    }
    /// Memory reserved by the incremental signer.
    pub fn sign_reservation(limits: &PdfLimits) -> Result<u64, ProcessingError> {
        (limits.max_object_bytes as u64)
            .checked_mul(32)
            .ok_or(ProcessingError::MemoryLimit)
    }
    /// Memory reserved by the signature-verification view of an update.
    pub fn verify_reservation(limits: &PdfLimits) -> Result<u64, ProcessingError> {
        (limits.max_signatures as u64)
            .checked_mul(2048)
            .and_then(|n| n.checked_add(limits.max_objects as u64 * 256))
            .ok_or(ProcessingError::MetadataLimit)
    }
    /// Peak memory per evidence/trust byte of a PAdES update (see [`plan_memory`]).
    pub const EVIDENCE_MEMORY_FACTOR: u64 = 64;
    /// Inputs known BEFORE key use that size the update's reservations.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PlanInputs {
        /// Sum of the existing signatures' `/Contents` bytes (`update_plan` reserves 4x).
        pub prior_contents_sum: u64,
        /// Largest single `/Contents` (decoded with a 128x working reservation).
        pub prior_contents_max: u64,
        /// Request-supplied evidence DER bytes (certificates, OCSP, CRLs; `append_dss` 4x).
        pub evidence_bytes: u64,
        /// Operator trust set DER bytes (anchors + intermediates; `append_dss` 4x).
        pub trust_bytes: u64,
    }
    /// Existing DSS/VRI retention and xref trailer retention are bounded by one
    /// object's limit each (3x for the VRI copy, 1x for the trailer).
    fn retained_bound(limits: &PdfLimits) -> Result<u64, ProcessingError> {
        (limits.max_object_bytes as u64)
            .checked_mul(4)
            .ok_or(ProcessingError::MemoryLimit)
    }
    /// Upper bound of the memory a PAdES update (LT/LTA sign or extend) holds, from
    /// the same reservation formulas the reader, update plan, DSS append and signer
    /// use: the plan, its nested reader, the signer, the verify view, the largest status transfer, the existing
    /// signatures (4x contents + 128x working for the largest), the new evidence and
    /// trust set (4x) and the retained-object bound.
    pub fn plan_memory(limits: &PdfLimits, inputs: &PlanInputs) -> Result<u64, ProcessingError> {
        let mut total = plan_reservation(limits)?;
        for term in [
            reader(limits)?.1,
            sign_reservation(limits)?,
            verify_reservation(limits)?,
            retained_bound(limits)?,
            // Revocation status fetched while the update is held reserves its
            // maximum CRL size (the largest transfer buffer of the status path).
            oncl_pki::crl::MAX_CRL_LEN,
            inputs
                .prior_contents_sum
                .checked_mul(4)
                .ok_or(ProcessingError::MemoryLimit)?,
            inputs
                .prior_contents_max
                .checked_mul(128)
                .ok_or(ProcessingError::MemoryLimit)?,
            // New evidence/trust bytes are held in several derived forms at once
            // (`append_dss` 4x, parsed validation material, the embedded copies). The
            // coefficient is the measured peak per evidence byte (about 54x for several
            // MiB of CRLs on this build) rounded up; the sweep tests guard it.
            inputs
                .evidence_bytes
                .checked_add(inputs.trust_bytes)
                .and_then(|n| n.checked_mul(EVIDENCE_MEMORY_FACTOR))
                .ok_or(ProcessingError::MemoryLimit)?,
        ] {
            total = total
                .checked_add(term)
                .ok_or(ProcessingError::MemoryLimit)?;
        }
        Ok(total)
    }
    /// Metadata reserved by the incremental signer's node table.
    pub fn sign_metadata(limits: &PdfLimits) -> Result<u64, ProcessingError> {
        (limits.max_nodes as u64)
            .checked_mul(512)
            .and_then(|n| n.checked_add((limits.max_object_bytes as u64).checked_mul(8)?))
            .ok_or(ProcessingError::MetadataLimit)
    }
    /// Metadata reserved by the update plan itself (before its nested reader).
    pub fn plan_metadata_reservation(limits: &PdfLimits) -> Result<u64, ProcessingError> {
        (limits.max_object_bytes as u64)
            .checked_mul(16)
            .ok_or(ProcessingError::MetadataLimit)
    }
    /// Peak METADATA of a PAdES update. The plan phase (plan + nested reader + verify
    /// view) and the signing phase (signer + its reader) do not overlap, so the peak is
    /// the larger phase, plus the existing-signature and new-evidence/trust accounting
    /// (`append_dss` 4x, per-signature 4x + 16x working for the largest).
    pub fn plan_metadata(limits: &PdfLimits, inputs: &PlanInputs) -> Result<u64, ProcessingError> {
        let plan_phase = plan_metadata_reservation(limits)?
            .checked_add(reader(limits)?.0)
            .and_then(|n| n.checked_add(verify_reservation(limits).ok()?))
            .ok_or(ProcessingError::MetadataLimit)?;
        let sign_phase = sign_metadata(limits)?
            .checked_add(reader(limits)?.0)
            .ok_or(ProcessingError::MetadataLimit)?;
        let extras = [
            inputs.prior_contents_sum.checked_mul(4),
            inputs.prior_contents_max.checked_mul(16),
            inputs
                .evidence_bytes
                .checked_add(inputs.trust_bytes)
                .and_then(|n| n.checked_mul(4)),
        ]
        .into_iter()
        .try_fold(0u64, |sum, term| sum.checked_add(term?))
        .ok_or(ProcessingError::MetadataLimit)?;
        plan_phase
            .max(sign_phase)
            .checked_add(extras)
            .ok_or(ProcessingError::MetadataLimit)
    }
    /// What the existing signatures of a document cost the update, read from the
    /// document itself before any key is applied.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PriorSignatures {
        /// Number of distinct existing signatures (a new one must still fit
        /// `PdfLimits::max_signatures`: `count + 1 <= max_signatures`).
        pub count: u64,
        /// Sum of their `/Contents` lengths.
        pub contents_sum: u64,
        /// The largest single `/Contents` length.
        pub contents_max: u64,
    }
    /// Read [`PriorSignatures`] from `source`. An unreadable/malformed PDF is an error
    /// the caller must surface (a predictable refusal), never a zero default.
    pub fn prior_signature_contents(
        source: oncl_pki::io::Source<'_>,
        limits: &PdfLimits,
        scope: &mut oncl_pki::resource::ResourceScope,
    ) -> Result<PriorSignatures, crate::PdfError> {
        crate::ades::prior_signature_contents(source, limits, scope)
    }
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
        let (metadata, memory) = budget::reader(limits)?;
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
