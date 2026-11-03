//! Closed reversible archive inclusion proof, not an XML/schema/format oracle.
use super::{
    BoundSignatureRepresentation, EvidenceBundle, EvidenceError, EvidenceId, EvidenceKind,
    SignerEvidence, lock_staged,
};
use crate::{
    digest::{DigestValue, HashState},
    io::{Region, StagedArtifact},
    key::HashAlg,
    resource::{IO_CHUNK_BYTES, ResourceReservation, ResourceScope},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::Mutex;
type Result<T, E = EvidenceError> = std::result::Result<T, E>;
/// Immutable actual coverage, bound to the CURRENT complete SignatureValue and
/// every prior evidence entry. The format adapter must independently derive all
/// canonical components, ordering, structural associations and proof cutoffs.
/// No format-validity, signature-success or trusted-time fact is minted here.
pub struct BoundArchiveRepresentation {
    pub(super) artifact: Mutex<StagedArtifact>,
    pub(super) region: Region,
    owner: u64,
    prior: usize,
    signature_len: u64,
    signature_hash: DigestValue,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl BoundArchiveRepresentation {
    /// Each evidence entry must occur exactly once among the groups, and every
    /// group's text projections must strictly decode to that store's actual DER.
    /// `before=None` binds all entries for issuance; verification must bind the
    /// prefix before the current token. The validator rechecks that exact cutoff.
    pub fn from_base64_projections(
        mut artifact: StagedArtifact,
        signature: &BoundSignatureRepresentation,
        signature_region: Region,
        groups: &[(EvidenceId, &[Region])],
        signer: &SignerEvidence<'_>,
        bundle: &mut EvidenceBundle,
        before: Option<EvidenceId>,
        scope: &ResourceScope,
    ) -> Result<Self> {
        bundle.checkpoint()?;
        artifact.check_source_binding(scope)?;
        signature.check(signer, scope)?;
        if !bundle.scope.same_operation(scope) {
            return Err(EvidenceError::InvalidBinding);
        }
        let prior = match before {
            Some(id) => {
                if bundle.checked_entry(id)?.kind != EvidenceKind::Timestamp {
                    return Err(EvidenceError::InvalidBinding);
                }
                id.index
            }
            None => bundle.entries.len(),
        };
        let length = artifact.len();
        if length == 0
            || length > bundle.limits.max_coverage_bytes
            || groups.len() != prior
            || groups.len() > bundle.limits.max_coverage_parts
            || signature_region.len != signature.region.len
            || signature_region.end()? > length
        {
            return Err(EvidenceError::InvalidBinding);
        }
        let mut projections = 0usize;
        let mut work = signature_region.len;
        for (position, (id, spans)) in groups.iter().enumerate() {
            if id.owner != bundle.owner
                || id.index >= prior
                || groups[..position].iter().any(|(old, _)| old == id)
                || spans.is_empty()
            {
                return Err(EvidenceError::InvalidBinding);
            }
            let entry = bundle.checked_entry(*id)?;
            work = work
                .checked_add(entry.region.len)
                .ok_or(EvidenceError::Limit)?;
            let mut end = 0;
            for span in *spans {
                projections = projections.checked_add(1).ok_or(EvidenceError::Limit)?;
                if projections > bundle.limits.max_coverage_parts {
                    return Err(EvidenceError::Limit);
                }
                if span.len == 0
                    || span.offset < end
                    || span.end()? > length
                    || overlap(*span, signature_region)?
                {
                    return Err(EvidenceError::InvalidBinding);
                }
                for (_, other) in &groups[..position] {
                    for earlier in *other {
                        if overlap(*span, *earlier)? {
                            return Err(EvidenceError::InvalidBinding);
                        }
                    }
                }
                end = span.end()?;
                work = work.checked_add(span.len).ok_or(EvidenceError::Limit)?;
            }
        }
        if projections > bundle.limits.max_coverage_parts || work > bundle.limits.max_coverage_bytes
        {
            return Err(EvidenceError::Limit);
        }
        let memory = scope.reserve_memory(std::mem::size_of::<Self>() as u64)?;
        let metadata = scope.reserve_metadata(std::mem::size_of::<Self>() as u64)?;
        let _working = scope.reserve_memory(3 * IO_CHUNK_BYTES as u64)?;
        let mut input = vec![0; IO_CHUNK_BYTES];
        let mut expected = vec![0; IO_CHUNK_BYTES];
        let mut decoded = Vec::with_capacity(IO_CHUNK_BYTES);
        let mut original = lock_staged(&signature.artifact)?;
        let mut at = 0;
        while at < signature_region.len {
            bundle.checkpoint()?;
            scope.checkpoint()?;
            let n = artifact.read_region(
                Region {
                    offset: signature_region.offset + at,
                    len: signature_region.len - at,
                },
                &mut input,
            )?;
            let m = original.read_region(
                Region {
                    offset: at,
                    len: signature_region.len - at,
                },
                &mut expected[..n],
            )?;
            if n == 0 || m != n || input[..n] != expected[..n] {
                return Err(EvidenceError::InvalidBinding);
            }
            at += n as u64;
        }
        drop(original);
        for (id, spans) in groups {
            let expected_region = bundle.checked_entry(*id)?.region;
            let mut matched = 0u64;
            let mut quartet = [0; 4];
            let mut used = 0;
            let mut padded = false;
            let mut reference = 0usize;
            for span in *spans {
                let mut remaining = *span;
                while remaining.len != 0 {
                    bundle.checkpoint()?;
                    scope.checkpoint()?;
                    let n = artifact.read_region(remaining, &mut input)?;
                    if n == 0 {
                        return Err(EvidenceError::InvalidBinding);
                    }
                    for &b in &input[..n] {
                        if reference != 0 {
                            let entity = b"&#xD;";
                            if entity.get(reference) != Some(&b) {
                                return Err(EvidenceError::InvalidBinding);
                            }
                            reference += 1;
                            if reference == entity.len() {
                                reference = 0;
                            }
                            continue;
                        }
                        if b == b'&' {
                            reference = 1;
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
                            let mut raw = [0; 3];
                            let n = STANDARD
                                .decode_slice(quartet, &mut raw)
                                .map_err(|_| EvidenceError::InvalidBinding)?;
                            decoded.extend_from_slice(&raw[..n]);
                            padded = quartet.contains(&b'=');
                            used = 0;
                        }
                        if decoded.len() >= IO_CHUNK_BYTES - 3 {
                            compare(
                                &mut bundle.staged,
                                expected_region,
                                &mut matched,
                                &mut decoded,
                                &mut expected,
                            )?;
                        }
                    }
                    remaining.offset += n as u64;
                    remaining.len -= n as u64;
                }
                if reference != 0 {
                    return Err(EvidenceError::InvalidBinding);
                }
            }
            compare(
                &mut bundle.staged,
                expected_region,
                &mut matched,
                &mut decoded,
                &mut expected,
            )?;
            if used != 0 || matched != expected_region.len {
                return Err(EvidenceError::InvalidBinding);
            }
        }
        bundle.checkpoint()?;
        scope.checkpoint()?;
        let mut hash = HashState::new(HashAlg::Sha256);
        hash.update(signer.signature);
        Ok(Self {
            artifact: Mutex::new(artifact),
            region: Region {
                offset: 0,
                len: length,
            },
            owner: bundle.owner,
            prior,
            signature_len: signer.signature.len() as u64,
            signature_hash: hash.finish(),
            _memory: memory,
            _metadata: metadata,
        })
    }
    pub(super) fn check(
        &self,
        signer: &SignerEvidence<'_>,
        bundle: &EvidenceBundle,
        scope: &ResourceScope,
        before: Option<EvidenceId>,
    ) -> Result<()> {
        bundle.checkpoint()?;
        scope.checkpoint()?;
        let artifact = lock_staged(&self.artifact)?;
        artifact.check_source_binding(scope)?;
        if artifact.len() != self.region.len {
            return Err(EvidenceError::InvalidBinding);
        }
        if !bundle.scope.same_operation(scope)
            || self.owner != bundle.owner
            || signer.signature.len() as u64 != self.signature_len
            || self.prior > bundle.entries.len()
            || before.is_some_and(|id| id.owner != self.owner || id.index != self.prior)
        {
            return Err(EvidenceError::InvalidBinding);
        }
        let mut hash = HashState::new(HashAlg::Sha256);
        hash.update(signer.signature);
        if hash.finish() != self.signature_hash {
            return Err(EvidenceError::InvalidBinding);
        }
        Ok(())
    }
    pub(super) fn check_issuance(
        &self,
        signer: &SignerEvidence<'_>,
        bundle: &EvidenceBundle,
    ) -> Result<()> {
        self.check(signer, bundle, &bundle.scope, None)?;
        if self.prior != bundle.entries.len() {
            return Err(EvidenceError::InvalidBinding);
        }
        Ok(())
    }
}
fn overlap(a: Region, b: Region) -> Result<bool> {
    Ok(a.offset < b.end()? && b.offset < a.end()?)
}
fn compare(
    stage: &mut StagedArtifact,
    region: Region,
    matched: &mut u64,
    decoded: &mut Vec<u8>,
    expected: &mut [u8],
) -> Result<()> {
    if decoded.is_empty() {
        return Ok(());
    }
    if decoded.len() as u64 > region.len.saturating_sub(*matched) {
        return Err(EvidenceError::InvalidBinding);
    }
    let n = stage.read_region(
        Region {
            offset: region.offset + *matched,
            len: decoded.len() as u64,
        },
        &mut expected[..decoded.len()],
    )?;
    if n != decoded.len() || decoded[..] != expected[..n] {
        return Err(EvidenceError::InvalidBinding);
    }
    *matched += n as u64;
    decoded.clear();
    Ok(())
}
