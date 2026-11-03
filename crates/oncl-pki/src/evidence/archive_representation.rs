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
    _metadata: ResourceReservation,
}
impl BoundArchiveRepresentation {
    /// Each evidence entry must occur exactly once among the groups, and every
    /// group's text projections must strictly decode to that store's actual DER.
    /// `before=None` binds all entries for issuance; verification must bind the
    /// prefix before the current token. The validator rechecks that exact cutoff.
    #[allow(
        clippy::too_many_arguments,
        reason = "Explicit original-scope signature, evidence owner and cutoff bindings"
    )]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evidence::{EvidenceLimits, EvidenceStore},
        key::SigAlg,
        resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
    };
    use std::sync::Arc;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> std::result::Result<(), ProcessingError> {
            Ok(())
        }
    }
    #[test]
    fn one_metadata_header_and_three_real_buffers_fit_exact_headroom() {
        let fixture = oncl_testkit::synthetic("user-rsa-sign");
        let key = crate::pkcs12::load(&oncl_testkit::read(fixture.path), &fixture.password)
            .unwrap()
            .remove(0);
        let data = b"actual public document for archive admission";
        let signature = key.key.sign(SigAlg::RsaSha256, data).unwrap();
        let mut state = HashState::new(HashAlg::Sha256);
        state.update(data);
        let signer = SignerEvidence {
            certificate: &key.cert,
            algorithm: SigAlg::RsaSha256,
            signed_digest: state.finish(),
            signature: &signature,
            claimed_time: None,
        };
        for short in [false, true] {
            let limits = ResourceLimits::default();
            let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
            let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let store = crate::io::TemporaryStore::new(dir.path()).unwrap();
            let evidence_limits = EvidenceLimits {
                max_items: 4,
                max_bytes: 1 << 20,
                max_item_bytes: 1 << 20,
                max_chain_len: 4,
                max_proofs: 2,
                max_coverage_parts: 16,
                max_coverage_bytes: 1 << 20,
            };
            let bytes = format!("<v>{}</v>", STANDARD.encode(&signature)).into_bytes();
            let mut value_stage = store.stage_source(&mut scope).unwrap();
            value_stage.write_chunk(&bytes).unwrap();
            let bound = BoundSignatureRepresentation::from_base64_projection(
                value_stage,
                Region {
                    offset: 0,
                    len: bytes.len() as u64,
                },
                &[Region {
                    offset: 3,
                    len: bytes.len() as u64 - 7,
                }],
                &signer,
                &evidence_limits,
                &scope,
            )
            .unwrap();
            let mut bundle = EvidenceStore::new(store.clone(), evidence_limits, &mut scope)
                .unwrap()
                .finish();
            let mut archive = store.stage_source(&mut scope).unwrap();
            archive.write_chunk(&bytes).unwrap();
            let required = std::mem::size_of::<BoundArchiveRepresentation>() as u64
                + 3 * IO_CHUNK_BYTES as u64;
            let _ballast = scope
                .reserve_memory(scope.available_memory() - required + u64::from(short))
                .unwrap();
            let result = BoundArchiveRepresentation::from_base64_projections(
                archive,
                &bound,
                Region {
                    offset: 0,
                    len: bytes.len() as u64,
                },
                &[],
                &signer,
                &mut bundle,
                None,
                &scope,
            );
            if short {
                assert!(matches!(
                    result,
                    Err(EvidenceError::Processing(ProcessingError::MemoryLimit))
                ));
            } else {
                let _bound =
                    result.expect("one metadata header plus all three actual buffers must fit");
                assert_eq!(scope.available_memory(), 3 * IO_CHUNK_BYTES as u64);
            }
        }
    }
}
