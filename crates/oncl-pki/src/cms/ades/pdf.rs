//! Inclusion-bound PAdES facts, not an independent PDF structural validator.
//! The format adapter must validate xrefs, field associations and permitted changes.
use super::*;
use crate::evidence::{
    EvidenceBundle, PreparedEvidence, lock_snapshot, validate_snapshot_evidence,
};
use crate::io::{DerivedInput, PdfSnapshot, PdfSnapshotCoverage, SnapshotEncoding};
use std::sync::{Mutex, OnceLock};

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
    checked_at: &'a OnceLock<OffsetDateTime>,
    host_clock: Option<&'a (dyn Fn() -> OffsetDateTime + Send + Sync)>,
}
fn contains(ranges: &[Region], value: Region) -> bool {
    value.end().is_ok_and(|end| {
        ranges
            .iter()
            .any(|r| r.offset <= value.offset && r.end().is_ok_and(|r_end| end <= r_end))
    })
}
impl PdfContext<'_, '_> {
    pub(super) fn validation_context<'a>(
        &self,
        services: &'a AdesServices<'_>,
    ) -> Result<ValidationContext<'a>, AdesError> {
        // Called only after every source hash and the shared evidence decode.
        let now = *self.checked_at.get_or_init(|| {
            self.host_clock
                .map_or(services.validation.now, |clock| clock())
        });
        if self.host_clock.is_some() && now < services.validation.now {
            return Err(tsp::TspError::ClockSkew.into());
        }
        Ok(ValidationContext {
            now,
            ..*services.validation
        })
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
        let current = self.validation_context(services)?;
        Ok(validate_snapshot_evidence(
            signer,
            bundle,
            &proofs,
            level,
            &current,
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
                // Sealed coverage has exactly this snapshot owner. Compare its
                // data address, not trait-object vtables: codegen may duplicate
                // vtables for the same concrete type in different units.
                if !matches!(part, CoveragePart::Snapshot { input, region: actual } if std::ptr::addr_eq(*input, self.context.snapshot as &dyn PdfSnapshotCoverage) && *actual == region)
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

/// One source CMS and its actual immutable detached PDF ranges.
pub struct SnapshotSignature<'a> {
    pub metadata: &'a DerivedInput,
    pub regions: [Region; 2],
}

/// Scoped per-source reports. Moving a report transfers its existing scoped
/// owners; dropping the collection or iterator cannot detach a yielded report.
pub struct SnapshotPadesReports {
    reports: Vec<AdesReport>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
pub struct SnapshotPadesIntoIter {
    reports: std::vec::IntoIter<AdesReport>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl IntoIterator for SnapshotPadesReports {
    type Item = AdesReport;
    type IntoIter = SnapshotPadesIntoIter;
    fn into_iter(self) -> Self::IntoIter {
        SnapshotPadesIntoIter {
            reports: self.reports.into_iter(),
            _memory: self._memory,
            _metadata: self._metadata,
        }
    }
}
impl Iterator for SnapshotPadesIntoIter {
    type Item = AdesReport;
    fn next(&mut self) -> Option<Self::Item> {
        self.reports.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.reports.size_hint()
    }
}
impl ExactSizeIterator for SnapshotPadesIntoIter {}

pub(super) struct SharedEvidence<'a> {
    pub(super) bundle: EvidenceBundle,
    pub(super) prepared: Option<PreparedEvidence>,
    tokens: Vec<(&'a [u8], EvidenceId)>,
    pub(super) documents: Vec<EvidenceId>,
    pub(super) required_certificates: Vec<EvidenceId>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl SharedEvidence<'_> {
    pub(super) fn token_id(&self, value: &[u8]) -> Result<EvidenceId, AdesError> {
        self.tokens
            .iter()
            .find(|(bytes, _)| *bytes == value)
            .map(|(_, id)| *id)
            .ok_or_else(|| invalid("timestamp absent from shared immutable evidence"))
    }
}

fn collect_unique<'a>(
    store: &mut EvidenceStore,
    entries: &mut Vec<(EvidenceKind, &'a [u8], EvidenceId)>,
    kind: EvidenceKind,
    bytes: &'a [u8],
    maximum: usize,
) -> Result<EvidenceId, AdesError> {
    if let Some((_, _, id)) = entries
        .iter()
        .find(|(existing_kind, value, _)| *existing_kind == kind && *value == bytes)
    {
        return Ok(*id);
    }
    if entries.len() >= maximum {
        return Err(EvidenceError::Limit.into());
    }
    let id = store.collect(
        kind,
        Source::sequential(&mut Cursor::new(bytes), Some(bytes.len() as u64)),
        EvidenceOrigin::Embedded {
            label: "PAdES immutable snapshot evidence",
        },
    )?;
    entries.push((kind, bytes, id));
    Ok(id)
}

fn common_evidence<'a>(
    frozen: &'a [Frozen],
    material: &'a [SnapshotMaterial<'a>],
    documents: &'a [SnapshotDocumentTimestamp<'a>],
    services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<SharedEvidence<'a>, AdesError> {
    let headers = (services.limits.max_items as u64)
        .checked_mul(256)
        .ok_or(ProcessingError::MetadataLimit)?;
    let memory = scope.reserve_memory(headers)?;
    let metadata = scope.reserve_metadata(headers)?;
    let mut raw_tokens = Vec::new();
    for source in frozen {
        for encoded in raw_set(source.signers.as_bytes())? {
            for (oid, _, value) in RawSigner::new(encoded)?.unsigned_values()? {
                if (oid == SIGNATURE_TIMESTAMP || oid == ARCHIVE_TIMESTAMP)
                    && !raw_tokens.contains(&value)
                {
                    if raw_tokens.len() >= services.limits.max_items {
                        return Err(EvidenceError::Limit.into());
                    }
                    raw_tokens.push(value);
                }
            }
        }
    }
    for document in documents {
        let token = crate::io::padded_der_sequence(document.token.as_bytes())?;
        if !raw_tokens.contains(&token) {
            if raw_tokens.len() >= services.limits.max_items {
                return Err(EvidenceError::Limit.into());
            }
            raw_tokens.push(token);
        }
    }
    // Normalize each real token once so its certificate SET can be borrowed.
    // F04's shared prepared store then decodes certificate/TSTInfo/signature
    // math once; per-signer graphs still recheck inclusion, imprint and policy.
    let mut normalized = Vec::with_capacity(raw_tokens.len());
    for token in &raw_tokens {
        let mut value = Metadata::new(scope)?;
        value.append(&ber::to_der(token)?)?;
        normalized.push(value);
    }
    let mut host_certificates = Metadata::new(scope)?;
    if material.is_empty() {
        for certificate in services.material.certificates {
            host_certificates.append(&certificate.to_der()?)?;
        }
    }
    let mut operation = scope.shared_view();
    let mut store =
        EvidenceStore::new(services.temporary.clone(), services.limits, &mut operation)?;
    let mut entries = Vec::new();
    let maximum = services.limits.max_items;
    for source in frozen {
        for certificate in raw_set(source.certificates.as_bytes())? {
            collect_unique(
                &mut store,
                &mut entries,
                EvidenceKind::Certificate,
                certificate,
                maximum,
            )?;
        }
        for status in ber::raw_children(source.status.as_bytes())? {
            let (kind, bytes, _, _) = revocation_parts(status)?;
            collect_unique(&mut store, &mut entries, kind, bytes, maximum)?;
        }
    }
    let mut required_certificates = Vec::new();
    for item in material {
        let id = collect_unique(
            &mut store,
            &mut entries,
            item.kind,
            item.value.as_bytes(),
            maximum,
        )?;
        if item.kind == EvidenceKind::Certificate {
            required_certificates.push(id);
        }
    }
    if material.is_empty() {
        for certificate in raw_set(host_certificates.as_bytes())? {
            collect_unique(
                &mut store,
                &mut entries,
                EvidenceKind::Certificate,
                certificate,
                maximum,
            )?;
        }
        for response in services.material.ocsp {
            collect_unique(
                &mut store,
                &mut entries,
                EvidenceKind::Ocsp,
                response,
                maximum,
            )?;
        }
        for crl in services.material.crls {
            collect_unique(&mut store, &mut entries, EvidenceKind::Crl, crl, maximum)?;
        }
    }
    for token in &normalized {
        let content = ContentInfo::from_der(token.as_bytes())?;
        let data: SignedData<'_> = content.content.decode_as()?;
        if let Some(certificates) = data.certificates {
            for certificate in certificates.tlvs()? {
                if certificate.first() == Some(&0x30) {
                    collect_unique(
                        &mut store,
                        &mut entries,
                        EvidenceKind::Certificate,
                        certificate,
                        maximum,
                    )?;
                }
            }
        }
    }
    let mut tokens = Vec::with_capacity(raw_tokens.len());
    for token in raw_tokens {
        let id = collect_unique(
            &mut store,
            &mut entries,
            EvidenceKind::Timestamp,
            token,
            maximum,
        )?;
        tokens.push((token, id));
    }
    let documents = documents
        .iter()
        .map(|document| {
            let bytes = crate::io::padded_der_sequence(document.token.as_bytes())?;
            tokens
                .iter()
                .find(|(value, _)| *value == bytes)
                .map(|(_, id)| *id)
                .ok_or_else(|| invalid("missing shared document timestamp"))
        })
        .collect::<Result<_, _>>()?;
    Ok(SharedEvidence {
        bundle: store.finish(),
        prepared: None,
        tokens,
        documents,
        required_certificates,
        _memory: memory,
        _metadata: metadata,
    })
}

/// Verify an entire operation's source CMS signatures against one immutable
/// snapshot and one common evidence owner/prepared decode. These are crypto and
/// evidence facts; PDF structural/permission validation remains the caller's job.
#[allow(
    clippy::too_many_arguments,
    reason = "One operation batch with closed source and common evidence bindings"
)]
pub fn verify_snapshot_pades(
    required: AdesLevel,
    signatures: &[SnapshotSignature<'_>],
    snapshot: &Mutex<PdfSnapshot<'_>>,
    material: &[SnapshotMaterial<'_>],
    documents: &[SnapshotDocumentTimestamp<'_>],
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
) -> Result<SnapshotPadesReports, AdesError> {
    services.limits.validate()?;
    if signatures.is_empty() {
        return Err(invalid("empty PAdES source signature batch"));
    }
    if material.len() > services.limits.max_items || documents.len() > services.limits.max_proofs {
        return Err(EvidenceError::Limit.into());
    }
    let mut bytes = signatures
        .iter()
        .map(|source| source.metadata.as_bytes())
        .chain(material.iter().map(|item| item.value.as_bytes()))
        .chain(documents.iter().map(|item| item.token.as_bytes()))
        .try_fold(0u64, |sum, value| {
            sum.checked_add(value.len() as u64)
                .ok_or(ProcessingError::MetadataLimit)
        })?;
    if material.is_empty() {
        for certificate in services.material.certificates {
            let length: u32 = certificate.encoded_len()?.into();
            bytes = bytes
                .checked_add(u64::from(length))
                .ok_or(ProcessingError::MetadataLimit)?;
        }
        for status in services.material.ocsp.iter().chain(services.material.crls) {
            bytes = bytes
                .checked_add(status.len() as u64)
                .ok_or(ProcessingError::MetadataLimit)?;
        }
    }
    let _working =
        scope.reserve_memory(bytes.checked_mul(128).ok_or(ProcessingError::MemoryLimit)?)?;
    let _decode = scope.reserve_metadata(
        bytes
            .checked_mul(16)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let headers = (signatures.len() as u64)
        .checked_mul((std::mem::size_of::<Frozen>() + std::mem::size_of::<AdesReport>()) as u64 * 2)
        .ok_or(ProcessingError::MetadataLimit)?;
    let memory = scope.reserve_memory(headers)?;
    let metadata = scope.reserve_metadata(headers)?;
    let mut input = lock_snapshot(snapshot)?;
    for source in signatures {
        input.binds(source.metadata, scope)?;
        if source.metadata.encoding() != SnapshotEncoding::PdfByteString {
            return Err(invalid("PAdES requires closed PDF string decoding"));
        }
    }
    for item in material {
        input.binds(item.value, scope)?;
        if item.value.encoding() != SnapshotEncoding::Identity
            || !matches!(
                item.kind,
                EvidenceKind::Certificate | EvidenceKind::Ocsp | EvidenceKind::Crl
            )
        {
            return Err(invalid(
                "DSS requires closed raw validation stream decoding",
            ));
        }
    }
    for document in documents {
        input.binds(document.token, scope)?;
        if document.token.encoding() != SnapshotEncoding::PdfByteString {
            return Err(invalid(
                "document timestamp requires closed PDF string decoding",
            ));
        }
    }
    let mut frozen = Vec::with_capacity(signatures.len());
    for source in signatures {
        let encoded = crate::io::padded_der_sequence(source.metadata.as_bytes())?;
        let mut operation = scope.shared_view();
        let mut cms = services.temporary.stage_source(&mut operation)?;
        cms.write_chunk(encoded)?;
        let mut reader = input.reader(&source.regions, scope)?;
        let value = freeze_stage_extra(cms, Some(reader.source()), true, scope, allowed);
        reader.finish()?;
        drop(reader);
        let value = value?;
        if !value.parsed.inspection.detached {
            return Err(invalid("PAdES requires detached CMS"));
        }
        frozen.push(value);
    }
    drop(input);
    let mut common = common_evidence(&frozen, material, documents, services, scope)?;
    let checked_at = OnceLock::new();
    // Keep the existing CMS validator's static context construction from sampling
    // once per source; PdfContext samples only after its lazy common preparation.
    let as_of = AdesServices {
        validation: services.validation,
        host_clock: None,
        network: services.network,
        temporary: services.temporary,
        limits: services.limits,
        tsa: services.tsa,
        material: ValidationMaterial {
            certificates: services.material.certificates,
            ocsp: services.material.ocsp,
            crls: services.material.crls,
        },
    };
    let mut reports = Vec::with_capacity(signatures.len());
    for (source, frozen) in signatures.iter().zip(&frozen) {
        let context = PdfContext {
            snapshot,
            metadata: source.metadata,
            material,
            documents,
            checked_at: &checked_at,
            host_clock: services.host_clock,
        };
        reports.push(verify_frozen_impl(
            required,
            frozen,
            &as_of,
            allowed,
            scope,
            Some(&context),
            Some(&mut common),
        )?);
    }
    Ok(SnapshotPadesReports {
        reports,
        _memory: memory,
        _metadata: metadata,
    })
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
