//! Reversible signature projection, not a format/schema/canonicalization oracle.
use super::{EvidenceError, EvidenceLimits, SignerEvidence, lock_staged};
use crate::{
    digest::{DigestValue, HashState},
    io::{Region, StagedArtifact},
    key::HashAlg,
    resource::{IO_CHUNK_BYTES, ResourceReservation, ResourceScope},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::Mutex;
type Result<T, E = EvidenceError> = std::result::Result<T, E>;
/// A sealed source-role representation whose admitted Base64 text projections
/// strictly decode to the current raw signature. Whole representation bytes,
/// including layout/comments, are timestamped. This proves no format semantics;
/// a format adapter must derive the representation/projections from its source.
/// No mutable artifact, owning buffer, scope clone or permit can escape.
/// ```compile_fail
/// fn detach(value: oncl_pki::evidence::BoundSignatureRepresentation) {
///     let _raw_artifact = value.artifact;
/// }
/// ```
pub struct BoundSignatureRepresentation {
    pub(super) artifact: Mutex<StagedArtifact>,
    pub(super) region: Region,
    signature_len: u64,
    signature_hash: DigestValue,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl BoundSignatureRepresentation {
    /// Consume an immutable source-role artifact. Projections are ordered,
    /// non-overlapping text spans in its fixed whole extent, at most 4096.
    /// Only XML whitespace and canonical `&#xD;` whitespace references may occur
    /// between strict Base64 characters; padding/trailing bits are checked.
    /// Representation and decoded signature are each bounded to 16 MiB and by
    /// the host evidence limits before I/O/allocation.
    pub fn from_base64_projection(
        mut artifact: StagedArtifact,
        region: Region,
        projections: &[Region],
        signer: &SignerEvidence<'_>,
        limits: &EvidenceLimits,
        scope: &ResourceScope,
    ) -> Result<Self> {
        limits.validate()?;
        artifact.check_source_binding(scope)?;
        if region.offset != 0
            || region.len != artifact.len()
            || region.len == 0
            || region.len > 16 * 1024 * 1024
            || region.len > limits.max_item_bytes
            || region.len > limits.max_coverage_bytes
            || signer.signature.is_empty()
            || signer.signature.len() as u64 > limits.max_item_bytes
            || signer.signature.len() > 16 * 1024 * 1024
            || projections.is_empty()
            || projections.len() > 4096
            || projections.len() > limits.max_coverage_parts
        {
            return Err(EvidenceError::Limit);
        }
        let mut previous = region.offset;
        for projection in projections {
            if projection.len == 0
                || projection.offset < previous
                || projection.end()? > region.end()?
            {
                return Err(EvidenceError::InvalidBinding);
            }
            previous = projection.end()?;
        }
        let owner_bytes = std::mem::size_of::<Self>() as u64;
        let memory = scope.reserve_memory(owner_bytes)?;
        let metadata = scope.reserve_metadata(owner_bytes)?;
        let _working = scope.reserve_memory(IO_CHUNK_BYTES as u64)?;
        let mut buffer = vec![0; IO_CHUNK_BYTES];
        let mut quartet = [0; 4];
        let mut used = 0;
        let mut reference = [0; 6];
        let mut reference_used = 0;
        let mut in_reference = false;
        let mut decoded = 0usize;
        let mut padded = false;
        for projection in projections {
            let mut remaining = *projection;
            while remaining.len != 0 {
                scope.checkpoint()?;
                let n = artifact.read_region(remaining, &mut buffer)?;
                if n == 0 {
                    return Err(EvidenceError::InvalidBinding);
                }
                for &b in &buffer[..n] {
                    if in_reference {
                        if reference_used == reference.len() {
                            return Err(EvidenceError::InvalidBinding);
                        }
                        reference[reference_used] = b;
                        reference_used += 1;
                        if b == b';' {
                            if &reference[..reference_used] != b"&#xD;" {
                                return Err(EvidenceError::InvalidBinding);
                            }
                            in_reference = false;
                            reference_used = 0;
                        }
                        continue;
                    }
                    if b == b'&' {
                        in_reference = true;
                        reference[0] = b'&';
                        reference_used = 1;
                        continue;
                    }
                    if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                        continue;
                    }
                    if padded {
                        return Err(EvidenceError::InvalidBinding);
                    }
                    quartet[used] = b;
                    used += 1;
                    if used == 4 {
                        let mut bytes = [0; 3];
                        let count = STANDARD
                            .decode_slice(quartet, &mut bytes)
                            .map_err(|_| EvidenceError::InvalidBinding)?;
                        let end = decoded.checked_add(count).ok_or(EvidenceError::Limit)?;
                        if signer.signature.get(decoded..end) != Some(&bytes[..count]) {
                            return Err(EvidenceError::InvalidBinding);
                        }
                        decoded = end;
                        padded = quartet.contains(&b'=');
                        used = 0;
                    }
                }
                remaining.offset = remaining
                    .offset
                    .checked_add(n as u64)
                    .ok_or(EvidenceError::Limit)?;
                remaining.len -= n as u64;
                scope.checkpoint()?;
            }
            // An XML character reference cannot cross a text-node projection.
            if in_reference {
                return Err(EvidenceError::InvalidBinding);
            }
        }
        if used != 0 || decoded != signer.signature.len() {
            return Err(EvidenceError::InvalidBinding);
        }
        let mut hash = HashState::new(HashAlg::Sha256);
        hash.update(signer.signature);
        scope.checkpoint()?;
        Ok(Self {
            artifact: Mutex::new(artifact),
            region,
            signature_len: decoded as u64,
            signature_hash: hash.finish(),
            _memory: memory,
            _metadata: metadata,
        })
    }
    pub(super) fn check(&self, signer: &SignerEvidence<'_>, scope: &ResourceScope) -> Result<()> {
        scope.checkpoint()?;
        let artifact = lock_staged(&self.artifact)?;
        artifact.check_source_binding(scope)?;
        if artifact.len() != self.region.len || signer.signature.len() as u64 != self.signature_len
        {
            return Err(EvidenceError::InvalidBinding);
        }
        let mut hash = HashState::new(HashAlg::Sha256);
        hash.update(signer.signature);
        if hash.finish() != self.signature_hash {
            return Err(EvidenceError::InvalidBinding);
        }
        scope.checkpoint()?;
        Ok(())
    }
}
