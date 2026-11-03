//! Inclusion-bound PAdES facts, not an independent PDF structural validator.
//! The format adapter must validate xrefs, field associations and permitted changes.
use super::*;
use crate::evidence::{
    EvidenceBundle, PreparedEvidence, lock_snapshot, validate_snapshot_evidence,
};
use crate::io::{DerivedInput, PdfSnapshot, PdfSnapshotCoverage, SnapshotEncoding};
use std::sync::Mutex;

/// A closed decoding of actual evidence stream bytes in the same snapshot.
/// No host trust, digest, or claimed proof time can be supplied by this record.
pub struct SnapshotMaterial<'a> {
    pub value: &'a DerivedInput,
    pub kind: EvidenceKind,
}
/// Exact immutable RFC3161 ByteRanges, excluding only the physical Contents token.
pub struct SnapshotDocumentTimestamp<'a> {
    pub token: &'a DerivedInput,
    pub regions: [Region; 2],
}
pub(super) struct PdfContext<'a, 's> {
    snapshot: &'a Mutex<PdfSnapshot<'s>>,
    metadata: &'a DerivedInput,
    material: &'a [SnapshotMaterial<'a>],
    documents: &'a [SnapshotDocumentTimestamp<'a>],
}
fn contains(ranges: &[Region], value: Region) -> bool {
    value.end().is_ok_and(|end| {
        ranges
            .iter()
            .any(|r| r.offset <= value.offset && r.end().is_ok_and(|r_end| end <= r_end))
    })
}
impl PdfContext<'_, '_> {
    pub(super) fn collect_tokens(
        &self,
        store: &mut EvidenceStore,
    ) -> Result<Vec<EvidenceId>, AdesError> {
        self.documents
            .iter()
            .map(|doc| {
                collect(
                    store,
                    EvidenceKind::Timestamp,
                    crate::io::padded_der_sequence(doc.token.as_bytes())?,
                )
            })
            .collect()
    }
    pub(super) fn achieved(&self, signature_timestamp: bool) -> AdesLevel {
        let time = signature_timestamp
            || self
                .documents
                .iter()
                .any(|doc| contains(&doc.regions, self.metadata.region()));
        let material = self
            .material
            .iter()
            .any(|m| matches!(m.kind, EvidenceKind::Ocsp | EvidenceKind::Crl));
        let archive = material
            && self.documents.iter().enumerate().any(|(index, doc)| {
                (signature_timestamp
                    || self.documents[..index]
                        .iter()
                        .any(|prior| contains(&prior.regions, self.metadata.region())))
                    && contains(&doc.regions, self.metadata.region())
                    && self
                        .material
                        .iter()
                        .all(|m| contains(&doc.regions, m.value.region()))
            });
        if archive {
            AdesLevel::Lta
        } else if time && material {
            AdesLevel::Lt
        } else if time {
            AdesLevel::T
        } else {
            AdesLevel::B
        }
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Same C03 SignerInfo and F04 validator with closed snapshot inclusion"
    )]
    pub(super) fn validate(
        &self,
        signer: &SignerEvidence<'_>,
        bundle: &mut EvidenceBundle,
        signatures: &[&(ObjectIdentifier, &[u8], EvidenceId)],
        documents: &[EvidenceId],
        level: AdesLevel,
        services: &AdesServices<'_>,
        scope: &ResourceScope,
        prepared: &PreparedEvidence,
    ) -> Result<ValidationReport, AdesError> {
        if signatures.len() > 1 || documents.len() != self.documents.len() {
            return Err(invalid("duplicate or missing PAdES proof"));
        }
        if level >= AdesLevel::Lt
            && !self
                .material
                .iter()
                .any(|m| matches!(m.kind, EvidenceKind::Ocsp | EvidenceKind::Crl))
        {
            return Err(invalid("PAdES LT requires carried DSS status material"));
        }
        let bytes = ((self.documents.len() + self.material.len() + 4) as u64)
            .checked_mul(1024)
            .ok_or(ProcessingError::MetadataLimit)?;
        let _memory = scope.reserve_memory(bytes)?;
        let _metadata = scope.reserve_metadata(bytes)?;
        let applicable: Vec<_> = self
            .documents
            .iter()
            .enumerate()
            .filter(|(_, doc)| contains(&doc.regions, self.metadata.region()))
            .collect();
        let coverage: Vec<_> = applicable
            .iter()
            .map(|(_, doc)| {
                [
                    CoveragePart::Snapshot {
                        input: self.snapshot,
                        region: doc.regions[0],
                    },
                    CoveragePart::Snapshot {
                        input: self.snapshot,
                        region: doc.regions[1],
                    },
                ]
            })
            .collect();
        let signature_coverage = [CoveragePart::Signature];
        let mut proofs = Vec::new();
        if let Some((_, _, id)) = signatures.first() {
            proofs.push(TimestampBinding {
                token: *id,
                kind: ProofKind::Signature,
                coverage: &signature_coverage,
            });
        }
        for ((index, _), coverage) in applicable.iter().zip(&coverage) {
            proofs.push(TimestampBinding {
                token: documents[*index],
                kind: ProofKind::Document,
                coverage,
            });
        }
        let graph = SnapshotProofGraph {
            context: self,
            documents,
            signature: signatures.first().map(|(_, _, id)| *id),
        };
        Ok(validate_snapshot_evidence(
            signer,
            bundle,
            &proofs,
            level,
            services.validation,
            services.network,
            scope,
            prepared,
            &graph,
        )?)
    }
}
/// Deliberately private construction: only real C03 decoded signer evidence can
/// reach this graph. There is no public trusted-bool or ProofTime constructor.
pub(crate) struct SnapshotProofGraph<'a, 's> {
    context: &'a PdfContext<'a, 's>,
    documents: &'a [EvidenceId],
    signature: Option<EvidenceId>,
}
impl SnapshotProofGraph<'_, '_> {
    pub(crate) fn check(
        &self,
        proofs: &[TimestampBinding<'_>],
        scope: &ResourceScope,
    ) -> Result<(), EvidenceError> {
        let input = lock_snapshot(self.context.snapshot)?;
        input.binds(self.context.metadata, scope)?;
        if self.context.metadata.encoding() != SnapshotEncoding::PdfByteString {
            return Err(EvidenceError::InvalidBinding);
        }
        for material in self.context.material {
            input.binds(material.value, scope)?;
            if material.value.encoding() != SnapshotEncoding::Identity
                || !matches!(
                    material.kind,
                    EvidenceKind::Certificate | EvidenceKind::Ocsp | EvidenceKind::Crl
                )
            {
                return Err(EvidenceError::InvalidBinding);
            }
        }
        let mut prior_end = 0;
        for doc in self.context.documents {
            input.binds(doc.token, scope)?;
            let gap = doc.token.region();
            if doc.token.encoding() != SnapshotEncoding::PdfByteString
                || doc.regions[0].offset != 0
                || doc.regions[0].len != gap.offset
                || doc.regions[1].offset != gap.end()?
                || doc.regions[1].end()? > input.len()
                || doc.regions[1].len == 0
                || gap.offset <= prior_end
            {
                return Err(EvidenceError::InvalidBinding);
            }
            // All prior proofs are physically committed, not just their digests.
            for prior in self
                .context
                .documents
                .iter()
                .take_while(|prior| prior.token.region().offset < gap.offset)
            {
                if !contains(&doc.regions, prior.token.region()) {
                    return Err(EvidenceError::InvalidBinding);
                }
            }
            prior_end = doc.regions[1].end()?;
        }
        let mut index = 0;
        if let Some(signature) = self.signature {
            let first = proofs.first().ok_or(EvidenceError::InvalidBinding)?;
            if first.token != signature
                || first.kind != ProofKind::Signature
                || !matches!(first.coverage, [CoveragePart::Signature])
            {
                return Err(EvidenceError::InvalidBinding);
            }
            index += 1;
        }
        for (number, doc) in self
            .context
            .documents
            .iter()
            .enumerate()
            .filter(|(_, doc)| contains(&doc.regions, self.context.metadata.region()))
        {
            let proof = proofs.get(index).ok_or(EvidenceError::InvalidBinding)?;
            if proof.token != self.documents[number] || proof.kind != ProofKind::Document {
                return Err(EvidenceError::InvalidBinding);
            }
            for (part, region) in proof.coverage.iter().zip(doc.regions) {
                if !matches!(part, CoveragePart::Snapshot { input, region: actual } if std::ptr::eq(*input, self.context.snapshot as &dyn PdfSnapshotCoverage) && *actual == region)
                {
                    return Err(EvidenceError::InvalidBinding);
                }
            }
            if proof.coverage.len() != 2 {
                return Err(EvidenceError::InvalidBinding);
            }
            index += 1;
        }
        if index != proofs.len() {
            return Err(EvidenceError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn is_archive(&self, token: EvidenceId) -> bool {
        self.documents
            .iter()
            .position(|id| *id == token)
            .is_some_and(|index| {
                let doc = &self.context.documents[index];
                let prior = self.signature.is_some()
                    || self.context.documents[..index]
                        .iter()
                        .any(|prior| contains(&prior.regions, self.context.metadata.region()));
                prior
                    && self
                        .context
                        .material
                        .iter()
                        .any(|m| matches!(m.kind, EvidenceKind::Ocsp | EvidenceKind::Crl))
                    && self
                        .context
                        .material
                        .iter()
                        .all(|m| contains(&doc.regions, m.value.region()))
            })
    }
}

/// Verify actual CMS detached regions plus inclusion-bound document timestamps.
/// This reports crypto/evidence facts only: the PDF caller remains responsible
/// for physical dictionary/field/xref association and allowed revision changes.
#[allow(
    clippy::too_many_arguments,
    reason = "Closed snapshot and actual format-derived material"
)]
pub fn verify_snapshot_pades(
    required: AdesLevel,
    metadata: &DerivedInput,
    snapshot: &Mutex<PdfSnapshot<'_>>,
    regions: &[Region],
    material: &[SnapshotMaterial<'_>],
    documents: &[SnapshotDocumentTimestamp<'_>],
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
) -> Result<AdesReport, AdesError> {
    services.limits.validate()?;
    if material.len() > services.limits.max_items || documents.len() > services.limits.max_proofs {
        return Err(EvidenceError::Limit.into());
    }
    let bytes = material
        .iter()
        .map(|item| item.value.as_bytes())
        .chain(documents.iter().map(|item| item.token.as_bytes()))
        .try_fold(metadata.as_bytes().len() as u64, |sum, value| {
            sum.checked_add(value.len() as u64)
                .ok_or(ProcessingError::MetadataLimit)
        })?;
    let _memory =
        scope.reserve_memory(bytes.checked_mul(128).ok_or(ProcessingError::MemoryLimit)?)?;
    let _metadata = scope.reserve_metadata(
        bytes
            .checked_mul(16)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let mut operation = scope.shared_view();
    let mut input = lock_snapshot(snapshot)?;
    input.binds(metadata, scope)?;
    if metadata.encoding() != SnapshotEncoding::PdfByteString {
        return Err(invalid("PAdES requires closed PDF string decoding"));
    }
    let encoded = crate::io::padded_der_sequence(metadata.as_bytes())?;
    let mut cms = services.temporary.stage_source(&mut operation)?;
    cms.write_chunk(encoded)?;
    let mut reader = input.reader(regions, scope)?;
    let frozen = freeze_stage_extra(cms, Some(reader.source()), true, scope, allowed);
    reader.finish()?;
    drop(reader);
    let mut frozen = frozen?;
    if !frozen.parsed.inspection.detached {
        return Err(invalid("PAdES requires detached CMS"));
    }
    let mut certs = Vec::new();
    let mut ocsp = Vec::new();
    let mut crls = Vec::new();
    for item in material {
        input.binds(item.value, scope)?;
        if item.value.encoding() != SnapshotEncoding::Identity {
            return Err(invalid("DSS requires closed raw stream decoding"));
        }
        match item.kind {
            EvidenceKind::Certificate => certs.push(Certificate::from_der(item.value.as_bytes())?),
            EvidenceKind::Ocsp => ocsp.push(item.value.as_bytes()),
            EvidenceKind::Crl => crls.push(item.value.as_bytes()),
            EvidenceKind::Timestamp => return Err(invalid("timestamp is not DSS status material")),
        }
    }
    // Host material may assist B/T validation, but never becomes carried LT data.
    if material.is_empty() {
        certs.extend_from_slice(services.material.certificates);
        ocsp.extend_from_slice(services.material.ocsp);
        crls.extend_from_slice(services.material.crls);
    }
    let carried = AdesServices {
        material: ValidationMaterial {
            certificates: &certs,
            ocsp: &ocsp,
            crls: &crls,
        },
        ..*services
    };
    add_material(&mut frozen, &carried, scope)?;
    drop(input);
    let context = PdfContext {
        snapshot,
        metadata,
        material,
        documents,
    };
    verify_frozen_impl(required, &frozen, &carried, allowed, scope, Some(&context))
}

/// Add only the standard CMS signature-time-stamp attribute. This internal
/// function receives the closed PDF output signer's completed CMS, never input.
pub(crate) fn stamp_contents(
    encoded: &[u8],
    services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<ScopedToken, AdesError> {
    let _working = scope.reserve_memory(
        (encoded.len() as u64)
            .checked_mul(128)
            .ok_or(ProcessingError::MemoryLimit)?,
    )?;
    let _decode = scope.reserve_metadata(
        (encoded.len() as u64)
            .checked_mul(16)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let normalized = ber::to_der(encoded)?;
    let ci = ContentInfo::from_der(&normalized)?;
    let mut data: SignedData<'_> = ci.content.decode_as()?;
    let mut signers = Metadata::new(scope)?;
    for encoded in data.signer_infos.tlvs()? {
        let raw = RawSigner::new(encoded)?;
        let info = SignerInfo::from_der(encoded)?;
        let token = request_imprint(&hash(info.signature.as_bytes()), services, scope)?;
        signers.append(&raw.encode(&[attribute(SIGNATURE_TIMESTAMP, &token.bytes)?]))?;
    }
    data.signer_infos = RawSet(signers.as_bytes());
    let content = SignedContentInfo { signed_data: &data };
    let len: u32 = content.encoded_len()?.into();
    let memory = scope.reserve_memory(u64::from(len))?;
    let metadata = scope.reserve_metadata(u64::from(len))?;
    Ok(ScopedToken {
        bytes: content.to_der()?,
        _memory: memory,
        _metadata: metadata,
    })
}
