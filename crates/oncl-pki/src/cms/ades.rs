//! CAdES baseline signatures (ETSI EN 319 122-1 V1.3.1).
//!
//! Archive timestamps use archiveTimestampV3 and ATSHashIndexV3, not the
//! deprecated RFC 5126 archiveTimestampV2. Document bytes remain in the original
//! source-role temporary artifact; only bounded format metadata is decoded.
#[path = "ades/pdf.rs"]
pub(crate) mod pdf;
use super::reader::{Metadata, Reader, malformed};
use super::sign::{Output, StageReader, copy_region, metadata_region, size, snapshot, sum};
use super::{ALGORITHMS, CmsSignRequest, CmsSignServices, Parsed, StreamError, parse_with};
use crate::ber;
use crate::cert::Certificate;
use crate::cms::asn1::{Attribute, ContentInfo, RawSet, SignedContentInfo, SignedData, SignerInfo};
use crate::cms::report::PreparedCms;
use crate::cms::verify::{ContentDigests, Signer};
use crate::digest::{DigestValue, HashState};
use crate::evidence::{
    AdesLevel, ArchiveSelection, CoverageEncoding, CoveragePart, EvidenceError, EvidenceId,
    EvidenceKind, EvidenceLimits, EvidenceOrigin, EvidenceStore, ProofKind, SignerEvidence,
    TimestampBinding, prepare_evidence, validate_prepared_evidence,
};
use crate::http::deadline::{DeadlineTransport, NetworkPolicy};
use crate::io::{Region, Source, StagedArtifact, TemporaryStore};
use crate::key::{AppliedState, DigestSigner, HashAlg, SigAlg};
use crate::resource::{ProcessingError, ResourceReservation, ResourceScope};
use crate::tsp::{self, TsaSpec};
use crate::validation::{ValidationContext, ValidationReason, ValidationReport, Verdict};
use der::asn1::{AnyRef, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence};
pub use pdf::{
    SnapshotDocumentTimestamp, SnapshotMaterial, SnapshotPadesIntoIter, SnapshotPadesReports,
    SnapshotSignature, verify_snapshot_pades,
};
use std::io::{self, Cursor, Read, Write};
use time::OffsetDateTime;

const SIGNATURE_TIMESTAMP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
const ARCHIVE_TIMESTAMP: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");
const HASH_INDEX: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.19122.1.5");
const OCSP_RESPONSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.16.2");

#[derive(Debug, thiserror::Error)]
pub enum AdesError {
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Cms(#[from] crate::cms::CmsError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error(transparent)]
    Timestamp(#[from] tsp::TspError),
    #[error(transparent)]
    Processing(#[from] ProcessingError),
    #[error("{source} (key application: {applied:?})")]
    AfterKeyUse {
        source: Box<AdesError>,
        applied: AppliedState,
    },
    #[error("CAdES timestamp acquisition is not configured")]
    MissingConfiguration,
}
impl From<der::Error> for AdesError {
    fn from(value: der::Error) -> Self {
        Self::Cms(value.into())
    }
}
fn fatal(error: &AdesError) -> bool {
    match error {
        AdesError::Processing(_)
        | AdesError::Evidence(EvidenceError::Processing(_) | EvidenceError::Limit) => true,
        AdesError::Stream(StreamError::Processing(_) | StreamError::MissingTemporaryStore) => true,
        AdesError::AfterKeyUse { source, .. } => fatal(source),
        AdesError::Cms(crate::cms::CmsError::Key(_)) => true,
        _ => false,
    }
}
impl From<ber::BerError> for AdesError {
    fn from(value: ber::BerError) -> Self {
        Self::Cms(value.into())
    }
}
fn invalid(message: &'static str) -> AdesError {
    malformed(message).into()
}

/// Public DER validation material collected by the trusted host. Nothing here
/// grants trust: every path, status, freshness and signature is checked again.
/// OCSP entries are complete RFC 6960 OCSPResponse values (not BasicOCSPResponse).
pub struct ValidationMaterial<'a> {
    pub certificates: &'a [Certificate],
    pub ocsp: &'a [&'a [u8]],
    pub crls: &'a [&'a [u8]],
}
pub struct AdesServices<'a> {
    pub validation: &'a ValidationContext<'a>,
    pub network: &'a NetworkPolicy,
    pub temporary: &'a TemporaryStore,
    pub limits: EvidenceLimits,
    pub tsa: Option<&'a TsaSpec>,
    pub material: ValidationMaterial<'a>,
    /// Trusted host service; None preserves explicit-as-of validation.
    pub host_clock: Option<&'a (dyn Fn() -> time::OffsetDateTime + Send + Sync)>,
}
impl AdesServices<'_> {
    fn validation_context(&self) -> ValidationContext<'_> {
        ValidationContext {
            now: self.host_clock.map_or(self.validation.now, |clock| clock()),
            ..*self.validation
        }
    }
}
/// A level is exposed only after all signers' required proofs actually validate.
/// All owning reports and their original admissions remain inseparable.
pub struct AdesReport {
    pub verdict: Verdict,
    level: Option<AdesLevel>,
    reports: Vec<ValidationReport>,
    bytes_in: u64,
    bytes_out: u64,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl AdesReport {
    pub fn level(&self) -> Option<AdesLevel> {
        self.level
    }
    pub fn reports(&self) -> &[ValidationReport] {
        &self.reports
    }
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in
    }
    pub fn bytes_out(&self) -> u64 {
        self.bytes_out
    }
    pub fn into_validation(
        self,
        scope: &ResourceScope,
    ) -> Result<ValidationReport, ProcessingError> {
        let mut reports = self.reports.into_iter();
        let mut report = reports
            .next()
            .ok_or(ProcessingError::InvalidInput("empty CAdES report"))?;
        for next in reports {
            if next.policy != report.policy || next.checked_at != report.checked_at {
                return Err(ProcessingError::InvalidInput(
                    "CAdES report context mismatch",
                ));
            }
            report.signers.append(next.signers, scope)?;
        }
        report.verdict = self.verdict;
        Ok(report)
    }
}
impl std::fmt::Debug for AdesReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdesReport")
            .field("verdict", &self.verdict)
            .field("level", &self.level)
            .field("reports", &self.reports)
            .finish()
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let (length, count) = super::reader::encoded_length(value.len() as u64);
    let mut result = Vec::with_capacity(1 + count + value.len());
    result.push(tag);
    result.extend_from_slice(&length[..count]);
    result.extend_from_slice(value);
    result
}
fn attribute(oid: ObjectIdentifier, value: &[u8]) -> Result<Vec<u8>, AdesError> {
    Ok(Attribute {
        attr_type: oid,
        attr_values: RawSet(value),
    }
    .to_der()?)
}
fn hash(bytes: &[u8]) -> DigestValue {
    let mut state = HashState::new(HashAlg::Sha256);
    state.update(bytes);
    state.finish()
}
fn digest_pair(first: &[u8], second: &[u8]) -> DigestValue {
    let mut state = HashState::new(HashAlg::Sha256);
    state.update(first);
    state.update(second);
    state.finish()
}
#[derive(Sequence)]
struct HashIndex<'a> {
    algorithm: spki::AlgorithmIdentifierRef<'a>,
    certificates: Vec<OctetString>,
    crls: Vec<OctetString>,
    unsigned: Vec<OctetString>,
}
impl HashIndex<'_> {
    fn check(&self) -> Result<(), AdesError> {
        if self.algorithm.oid != HashAlg::Sha256.oid()
            || self.algorithm.parameters.is_some_and(|p| p != AnyRef::NULL)
            || self
                .certificates
                .iter()
                .chain(&self.crls)
                .chain(&self.unsigned)
                .any(|v| v.as_bytes().len() != 32)
        {
            return Err(invalid("CAdES SHA-256 archive profile/hash index mismatch"));
        }
        Ok(())
    }
}
struct RawSigner<'a> {
    fields: Vec<&'a [u8]>,
    attrs: Vec<&'a [u8]>,
}
impl<'a> RawSigner<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, AdesError> {
        let fields = ber::raw_children(encoded)?;
        if fields.len() < 6 || fields.len() > 7 || fields[3].first() != Some(&0xa0) {
            return Err(invalid("CAdES requires signed attributes"));
        }
        let attrs = if fields.len() == 7 {
            ber::raw_children(fields[6])?
        } else {
            Vec::new()
        };
        Ok(Self { fields, attrs })
    }
    #[allow(
        clippy::type_complexity,
        reason = "Borrowed standard OID, encoded OID and value without allocating owning wrappers"
    )]
    fn unsigned_values(&self) -> Result<Vec<(ObjectIdentifier, &'a [u8], &'a [u8])>, AdesError> {
        let mut values = Vec::new();
        for attr in &self.attrs {
            let fields = ber::raw_children(attr)?;
            if fields.len() != 2 {
                return Err(invalid("malformed CAdES unsigned attribute"));
            }
            let oid = ObjectIdentifier::from_der(fields[0])?;
            // Deprecated validation-value/reference attributes are not the current
            // baseline profile. Never silently relabel them B-LT/B-LTA.
            if [
                "1.2.840.113549.1.9.16.2.21",
                "1.2.840.113549.1.9.16.2.22",
                "1.2.840.113549.1.9.16.2.23",
                "1.2.840.113549.1.9.16.2.24",
                "1.2.840.113549.1.9.16.2.48",
            ]
            .iter()
            .any(|old| oid.to_string() == *old)
            {
                return Err(invalid(
                    "deprecated CAdES validation profile is not baseline v3",
                ));
            }
            let entries = ber::raw_children(fields[1])?;
            if entries.is_empty()
                || ((oid == SIGNATURE_TIMESTAMP || oid == ARCHIVE_TIMESTAMP) && entries.len() != 1)
            {
                return Err(invalid("invalid CAdES unsigned attribute cardinality"));
            }
            for value in entries {
                values.push((oid, fields[0], value));
            }
        }
        Ok(values)
    }
    fn encode(&self, added: &[Vec<u8>]) -> Vec<u8> {
        let prefix: Vec<u8> = self.fields[..6]
            .iter()
            .flat_map(|field| field.iter().copied())
            .collect();
        let unsigned: Vec<u8> = self
            .attrs
            .iter()
            .flat_map(|attr| attr.iter().copied())
            .chain(added.iter().flat_map(|attr| attr.iter().copied()))
            .collect();
        let mut body = prefix;
        if !unsigned.is_empty() {
            body.extend_from_slice(&tlv(0xa1, &unsigned));
        }
        tlv(0x30, &body)
    }
}

struct Frozen {
    source: StagedArtifact,
    parsed: Parsed,
    certificates: Metadata,
    status: Metadata,
    signers: Metadata,
    content_type: Metadata,
    values: [Option<DigestValue>; 4],
}
/// Only this module can construct an Add admission: it retains the exact
/// frozen bytes, calculated digests and completed scoped CAdES proof report.
pub(super) struct PreparedAdd {
    frozen: Frozen,
    proof: AdesReport,
}
impl PreparedAdd {
    pub(super) fn into_parts(
        self,
    ) -> (
        StagedArtifact,
        Parsed,
        [Option<DigestValue>; 4],
        Option<AdesReport>,
    ) {
        (
            self.frozen.source,
            self.frozen.parsed,
            self.frozen.values,
            Some(self.proof),
        )
    }
}
fn freeze(
    input: Source<'_>,
    detached: Option<Source<'_>>,
    services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<Frozen, AdesError> {
    freeze_extra(input, detached, services, scope, &[SigAlg::RsaSha256])
}
fn freeze_extra(
    input: Source<'_>,
    detached: Option<Source<'_>>,
    services: &AdesServices<'_>,
    scope: &ResourceScope,
    extra: &[SigAlg],
) -> Result<Frozen, AdesError> {
    services.limits.validate()?;
    let mut operation = scope.retain();
    let source = snapshot(input, Some(services.temporary), &mut operation)?;
    freeze_stage_extra(source, detached, false, scope, extra)
}
fn freeze_stage(
    source: StagedArtifact,
    detached: Option<Source<'_>>,
    replay_detached: bool,
    _services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<Frozen, AdesError> {
    freeze_stage_extra(
        source,
        detached,
        replay_detached,
        scope,
        &[SigAlg::RsaSha256],
    )
}
fn freeze_stage_extra(
    mut source: StagedArtifact,
    detached: Option<Source<'_>>,
    replay_detached: bool,
    scope: &ResourceScope,
    extra: &[SigAlg],
) -> Result<Frozen, AdesError> {
    let mut operation = scope.retain();
    let length = source.len();
    let mut reader = StageReader {
        stage: &mut source,
        position: 0,
        error: None,
    };
    let parsed = parse_with(
        Source::sequential(&mut reader, Some(length)),
        &mut operation,
        true,
        None,
        extra,
        true,
        // The CRLs stay in the frozen source and `Frozen::status`: a second resident
        // copy inside the parsed metadata would only be charged and never read.
        false,
    );
    if let Some(error) = reader.error.take() {
        return Err(error.into());
    }
    let mut parsed = parsed?;
    if !parsed.inspection.detached && detached.is_some() {
        return Err(invalid("attached CAdES does not accept detached content"));
    }
    let mut present = !parsed.inspection.detached;
    if let Some(detached) = detached {
        let mut reader = if replay_detached {
            Reader::new_replay(detached, &mut operation)?
        } else {
            Reader::new(detached, &mut operation)?
        };
        reader.raw_content(|bytes| {
            parsed.digests.update(bytes);
            Ok(())
        })?;
        present = true;
    }
    if !present {
        return Err(invalid("detached CAdES requires actual content"));
    }
    let values = parsed.digests.finish(present);
    let certificates = match parsed.layout.certificates {
        Some(region) => metadata_region(&mut source, region, scope)?,
        None => return Err(invalid("CAdES requires embedded signer certificates")),
    };
    let status = match parsed.layout.status {
        Some(region) => metadata_region(&mut source, region, scope)?,
        None => {
            let mut value = Metadata::new(scope)?;
            value.append(&[0xa1, 0])?;
            value
        }
    };
    let signers = metadata_region(&mut source, parsed.layout.signers, scope)?;
    let content_type = metadata_region(&mut source, parsed.layout.content_type, scope)?;
    Ok(Frozen {
        source,
        parsed,
        certificates,
        status,
        signers,
        content_type,
        values,
    })
}
fn raw_set(bytes: &[u8]) -> Result<Vec<&[u8]>, AdesError> {
    Ok(ber::raw_elements(bytes)?)
}
struct Record<'a> {
    id: EvidenceId,
    wire: &'a [u8],
    prefix: &'a [u8],
    suffix: &'a [u8],
}
fn collect(
    store: &mut EvidenceStore,
    kind: EvidenceKind,
    value: &[u8],
) -> Result<EvidenceId, AdesError> {
    Ok(store.collect(
        kind,
        Source::sequential(&mut Cursor::new(value), Some(value.len() as u64)),
        EvidenceOrigin::Embedded {
            label: "CAdES standard SignedData evidence",
        },
    )?)
}
fn store_common<'a>(
    store: &mut EvidenceStore,
    certificates: &'a [&'a [u8]],
    statuses: &'a [&'a [u8]],
) -> Result<(Vec<Record<'a>>, Vec<Record<'a>>), AdesError> {
    let mut certs = Vec::with_capacity(certificates.len());
    let mut revocation = Vec::with_capacity(statuses.len());
    for bytes in certificates {
        certs.push(Record {
            id: collect(store, EvidenceKind::Certificate, bytes)?,
            wire: bytes,
            prefix: &[],
            suffix: &[],
        });
    }
    for bytes in statuses {
        let (kind, payload, prefix, suffix) = revocation_parts(bytes)?;
        revocation.push(Record {
            id: collect(store, kind, payload)?,
            wire: bytes,
            prefix,
            suffix,
        });
    }
    Ok((certs, revocation))
}
type RevocationParts<'a> = (EvidenceKind, &'a [u8], &'a [u8], &'a [u8]);
fn revocation_parts(bytes: &[u8]) -> Result<RevocationParts<'_>, AdesError> {
    Ok(match bytes.first() {
        Some(0x30) => (EvidenceKind::Crl, bytes, &[][..], &[][..]),
        Some(0xa1) => {
            let fields = ber::raw_children(bytes)?;
            if fields.len() != 2 || ObjectIdentifier::from_der(fields[0])? != OCSP_RESPONSE {
                return Err(invalid("unsupported CAdES other revocation format"));
            }
            let start = fields[1].as_ptr() as usize - bytes.as_ptr() as usize;
            (
                EvidenceKind::Ocsp,
                fields[1],
                &bytes[..start],
                &bytes[start + fields[1].len()..],
            )
        }
        _ => return Err(invalid("unsupported CAdES revocation choice")),
    })
}
#[allow(
    clippy::type_complexity,
    reason = "Borrowed standard unsigned attribute OID/value and owned evidence ID"
)]
fn signer_tokens<'a>(
    signers: &[&'a [u8]],
    mut collect_token: impl FnMut(&'a [u8]) -> Result<EvidenceId, AdesError>,
) -> Result<Vec<Vec<(ObjectIdentifier, &'a [u8], EvidenceId)>>, AdesError> {
    signers
        .iter()
        .map(|encoded| {
            let raw = RawSigner::new(encoded)?;
            raw.unsigned_values()?
                .into_iter()
                .filter(|(oid, _, _)| *oid == SIGNATURE_TIMESTAMP || *oid == ARCHIVE_TIMESTAMP)
                .map(|(oid, _, value)| Ok((oid, value, collect_token(value)?)))
                .collect()
        })
        .collect()
}
fn index_from_token(token: &[u8]) -> Result<Vec<u8>, AdesError> {
    let content = ber::raw_children(token)?;
    if content.len() != 2 || ObjectIdentifier::from_der(content[0])? != crate::oid::SIGNED_DATA {
        return Err(invalid("archive token content type"));
    }
    let explicit = ber::raw_children(content[1])?;
    if explicit.len() != 1 {
        return Err(invalid("archive token explicit content"));
    }
    let data = ber::raw_children(explicit[0])?;
    let infos = ber::raw_children(
        data.last()
            .ok_or_else(|| invalid("archive token has no signerInfos"))?,
    )?;
    if infos.len() != 1 {
        return Err(invalid("archive token requires exactly one signer"));
    }
    let signer = RawSigner::new(infos[0])?;
    let mut found = None;
    for (oid, _, value) in signer.unsigned_values()? {
        if oid == HASH_INDEX {
            if found.is_some() {
                return Err(invalid("duplicate ATSHashIndexV3"));
            }
            // Hash-index DER is normative. Do not normalize an altered unsigned
            // hash index into the bytes originally protected by the TSA.
            let index = HashIndex::from_der(value)?;
            index.check()?;
            if index.to_der()? != value {
                return Err(invalid("ATSHashIndexV3 must be DER"));
            }
            found = Some(value.to_vec());
        }
    }
    found.ok_or_else(|| invalid("archive token has no ATSHashIndexV3"))
}
fn token_with_index(token: &[u8], index: &[u8]) -> Result<Vec<u8>, AdesError> {
    let normalized = ber::to_der(token)?;
    let ci = ContentInfo::from_der(&normalized)?;
    let mut data: SignedData<'_> = ci.content.decode_as()?;
    let infos = data.signer_infos.tlvs()?;
    if infos.len() != 1 {
        return Err(invalid("archive TSA token requires one signer"));
    }
    let signer = RawSigner::new(infos[0])?;
    if signer
        .unsigned_values()?
        .iter()
        .any(|(oid, _, _)| *oid == HASH_INDEX)
    {
        return Err(invalid("TSA supplied an unrelated hash index"));
    }
    let encoded = signer.encode(&[attribute(HASH_INDEX, index)?]);
    data.signer_infos = RawSet(&encoded);
    Ok(SignedContentInfo { signed_data: &data }.to_der()?)
}

/// Create or co-sign through the accepted DigestSigner path. Baseline signing
/// adds the mandatory signing-time without changing legacy CMS defaults.
struct Tee<'a, 'b> {
    input: Source<'a>,
    stage: &'b mut StagedArtifact,
    fatal: Option<ProcessingError>,
}
impl Read for Tee<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.input.read(output)?;
        if let Err(error) = self.stage.write_chunk(&output[..count]) {
            self.fatal = Some(error);
            return Err(io::Error::other("detached content staging failed"));
        }
        Ok(count)
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "Explicit C02 inputs, target level and independent borrowed reader/issuance services"
)]
pub fn sign(
    request: &CmsSignRequest,
    level: AdesLevel,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    cms: &CmsSignServices<'_>,
    services: Option<&AdesServices<'_>>,
    output: &mut dyn Write,
    scope: &ResourceScope,
) -> Result<super::SignSummary, AdesError> {
    sign_impl(
        request,
        level,
        input,
        detached,
        signers,
        cms,
        services,
        &mut Output::Writer(output),
        scope,
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "Same explicit contract as the writer entry point"
)]
pub fn sign_staged(
    request: &CmsSignRequest,
    level: AdesLevel,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    cms: &CmsSignServices<'_>,
    services: Option<&AdesServices<'_>>,
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<super::SignSummary, AdesError> {
    output.check_sign_output(scope)?;
    let result = sign_impl(
        request,
        level,
        input,
        detached,
        signers,
        cms,
        services,
        &mut Output::Staged(output),
        scope,
    );
    if result.is_err() {
        output.fail_sign_output();
    }
    result
}
#[allow(
    clippy::too_many_arguments,
    reason = "Single implementation for writer and admitted staged output"
)]
fn sign_impl(
    request: &CmsSignRequest,
    level: AdesLevel,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    cms: &CmsSignServices<'_>,
    services: Option<&AdesServices<'_>>,
    output: &mut Output<'_>,
    scope: &ResourceScope,
) -> Result<super::SignSummary, AdesError> {
    let before = scope.progress();
    let at = services.map_or_else(OffsetDateTime::now_utc, |services| services.validation.now);
    let request = request.with_default_signing_time(at);
    if level > AdesLevel::B {
        let services = services.ok_or(AdesError::MissingConfiguration)?;
        services.limits.validate()?;
        let tsa = services.tsa.ok_or(AdesError::MissingConfiguration)?;
        if tsa.hash != HashAlg::Sha256 || !tsa.require_tsa_eku {
            return Err(invalid("CAdES acquisition requires SHA-256 and TSA EKU"));
        }
    }
    let temporary = services
        .map(|services| services.temporary)
        .or(cms.temporary)
        .ok_or(StreamError::MissingTemporaryStore)?;
    let mut operation = scope.retain();
    let mut signed = temporary.stage_source(&mut operation)?;
    let needs_detached = request.attachment() == Some(false) || detached.is_some();
    let mut retained = if needs_detached {
        Some(temporary.stage_source(&mut operation)?)
    } else {
        None
    };
    let mut summary = if request.attachment().is_none() {
        let services = services.ok_or(AdesError::MissingConfiguration)?;
        let mut needed = [SigAlg::RsaSha256; 4];
        let mut needed_len = 1;
        for signer in signers.iter() {
            let algorithm = signer.algorithm();
            if !needed[..needed_len].contains(&algorithm) {
                if needed_len == needed.len() {
                    return Err(invalid("unsupported Add signature algorithm"));
                }
                needed[needed_len] = algorithm;
                needed_len += 1;
            }
        }
        let frozen = if let Some(detached) = detached {
            let length = detached.known_len();
            let mut tee = Tee {
                input: detached,
                stage: retained.as_mut().expect("detached source admitted"),
                fatal: None,
            };
            let result = freeze_extra(
                input,
                Some(Source::sequential(&mut tee, length)),
                services,
                scope,
                &needed[..needed_len],
            );
            if let Some(error) = tee.fatal.take() {
                return Err(error.into());
            }
            result?
        } else {
            freeze_extra(input, None, services, scope, &needed[..needed_len])?
        };
        let proof = verify_frozen(
            AdesLevel::B,
            &frozen,
            services,
            request.allowed_algorithms(),
            scope,
        )?;
        if proof.verdict != Verdict::Valid {
            return Err(invalid(
                "all original CAdES signatures and proofs must validate before Add",
            ));
        }
        super::sign::sign_prepared_staged(
            &request,
            PreparedAdd { frozen, proof },
            signers,
            cms,
            &mut signed,
            scope,
        )?
    } else if request.attachment() == Some(false) {
        let length = input.known_len();
        let mut tee = Tee {
            input,
            stage: retained.as_mut().expect("detached source admitted"),
            fatal: None,
        };
        let result = super::sign::sign_internal(
            &request,
            Source::sequential(&mut tee, length),
            detached,
            signers,
            cms,
            &mut signed,
            scope,
        );
        if let Some(error) = tee.fatal.take() {
            return Err(error.into());
        }
        result?
    } else if let Some(detached) = detached {
        let length = detached.known_len();
        let mut tee = Tee {
            input: detached,
            stage: retained.as_mut().expect("detached source admitted"),
            fatal: None,
        };
        let result = super::sign::sign_internal(
            &request,
            input,
            Some(Source::sequential(&mut tee, length)),
            signers,
            cms,
            &mut signed,
            scope,
        );
        if let Some(error) = tee.fatal.take() {
            return Err(error.into());
        }
        result?
    } else {
        super::sign::sign_internal(&request, input, None, signers, cms, &mut signed, scope)?
    };
    let result = (|| {
        if level == AdesLevel::B {
            return publish(signed, output, scope);
        }
        let services = services.expect("services checked before private operation");
        let report = if let Some(mut retained) = retained {
            let length = retained.len();
            let mut reader = StageReader {
                stage: &mut retained,
                position: 0,
                error: None,
            };
            let result = freeze_stage(
                signed,
                Some(Source::sequential(&mut reader, Some(length))),
                true,
                services,
                scope,
            );
            if let Some(error) = reader.error.take() {
                return Err(error.into());
            }
            extend_frozen(
                level,
                result?,
                services,
                request.allowed_algorithms(),
                output,
                scope,
            )?
        } else {
            extend_frozen(
                level,
                freeze_stage(signed, None, false, services, scope)?,
                services,
                request.allowed_algorithms(),
                output,
                scope,
            )?
        };
        Ok(report.bytes_out)
    })();
    summary.bytes_out = result.map_err(|source| AdesError::AfterKeyUse {
        source: Box::new(source),
        applied: summary.applied,
    })?;
    summary.bytes_in = scope.progress().bytes_in - before.bytes_in;
    Ok(summary)
}

/// Verify the original signature and every standard proof. Required is a host
/// minimum, never a claimed achieved level. Unknown profiles are not Valid.
pub fn verify(
    required: AdesLevel,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
) -> Result<AdesReport, AdesError> {
    let before = scope.progress();
    let frozen = freeze(input, detached, services, scope)?;
    let mut report = verify_frozen(required, &frozen, services, allowed, scope)?;
    report.bytes_in = scope.progress().bytes_in - before.bytes_in;
    Ok(report)
}

fn verify_frozen(
    required: AdesLevel,
    frozen: &Frozen,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
) -> Result<AdesReport, AdesError> {
    verify_frozen_impl(required, frozen, services, allowed, scope, None, None)
}
#[allow(
    clippy::too_many_arguments,
    reason = "One scoped C03 validator with an optional private shared PDF evidence owner"
)]
fn verify_frozen_impl(
    required: AdesLevel,
    frozen: &Frozen,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
    pdf: Option<&pdf::PdfContext<'_, '_>>,
    shared: Option<&mut pdf::SharedEvidence<'_>>,
) -> Result<AdesReport, AdesError> {
    scope.checkpoint()?;
    // Bulk CRLs are borrowed and scanned, never decoded: only the rest amplifies.
    let encoded_size = frozen.parsed.metadata.decoded_bytes();
    let _working = scope.reserve_memory(
        encoded_size
            .checked_mul(128)
            .ok_or(ProcessingError::MemoryLimit)?,
    )?;
    let _metadata = scope.reserve_metadata(
        encoded_size
            .checked_mul(16)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let certificates = raw_set(frozen.certificates.as_bytes())?;
    let statuses = ber::raw_children(frozen.status.as_bytes())?;
    let signer_bytes = raw_set(frozen.signers.as_bytes())?;
    let report_bytes = signer_bytes
        .len()
        .checked_mul(std::mem::size_of::<ValidationReport>())
        .ok_or(ProcessingError::MemoryLimit)? as u64;
    let memory = scope.reserve_memory(report_bytes)?;
    let metadata = scope.reserve_metadata(report_bytes)?;
    let mut local_bundle;
    let mut local_prepared = None;
    let local_documents = [];
    let (
        bundle,
        prepared_evidence,
        cert_records,
        status_records,
        token_ids,
        document_ids,
        required_certificates,
    ) = if let Some(common) = shared {
        let token_ids = signer_tokens(&signer_bytes, |value| common.token_id(value))?;
        (
            &mut common.bundle,
            &mut common.prepared,
            Vec::new(),
            Vec::new(),
            token_ids,
            common.documents.as_slice(),
            common.required_certificates.as_slice(),
        )
    } else {
        let mut operation = scope.retain();
        let mut store =
            EvidenceStore::new(services.temporary.clone(), services.limits, &mut operation)?;
        let (cert_records, status_records) = store_common(&mut store, &certificates, &statuses)?;
        let token_ids = signer_tokens(&signer_bytes, |value| {
            collect(&mut store, EvidenceKind::Timestamp, value)
        })?;
        local_bundle = store.finish();
        (
            &mut local_bundle,
            &mut local_prepared,
            cert_records,
            status_records,
            token_ids,
            local_documents.as_slice(),
            [].as_slice(),
        )
    };
    let prepared = PreparedCms::from_digests(frozen.parsed.metadata.as_bytes(), frozen.values);
    let data = prepared.signed_data()?;
    let other_revocations = data
        .crls
        .map(|values| values.tlvs())
        .transpose()?
        .is_some_and(|values| values.iter().any(|choice| choice.first() == Some(&0xa1)));
    if other_revocations && data.version != 5 {
        return Err(invalid(
            "RFC5940 other revocation information requires SignedData version 5",
        ));
    }
    let certs = crate::cms::verify::certificates(&data)?;
    let digests = ContentDigests::from_values(frozen.values);
    let normalized_infos = data.signer_infos.tlvs()?;
    let mut reports = Vec::with_capacity(signer_bytes.len());
    let mut minimum = AdesLevel::Lta;
    // Data/source digests and issuance precede one shared final policy instant.
    let mut final_context = services.validation_context();
    for (index, encoded) in signer_bytes.iter().enumerate() {
        scope.checkpoint()?;
        let raw = RawSigner::new(encoded)?;
        let signer = Signer {
            index,
            info: SignerInfo::from_der(normalized_infos[index])?,
            content_type: data.encap_content_info.e_content_type,
            digests: &digests,
        };
        let algorithm = signer.algorithm()?;
        if !allowed.contains(&algorithm) || algorithm == SigAlg::RsaSha1 {
            return Err(invalid("CAdES signer algorithm not authorized"));
        }
        let slot = ALGORITHMS
            .iter()
            .position(|candidate| *candidate == algorithm)
            .ok_or_else(|| invalid("unknown CAdES digest"))?;
        if !frozen.parsed.digests.declared[slot] {
            return Err(invalid("CAdES digest absent from digestAlgorithms"));
        }
        let (certificate, certificate_der) = signer
            .find_cert(&certs, |_| true)?
            .ok_or(crate::cms::CmsError::CertNotFound(index))?;
        let attrs = signer.signed_attrs()?;
        let seen = signer.check_signed_attrs(attrs, algorithm, Some(certificate_der), false)?;
        let source_problem = if seen.digest_matches != Some(true) {
            Some(crate::cms::Problem::DigestMismatch)
        } else if seen.ess_matches == Some(false) {
            Some(crate::cms::Problem::EssCertIdMismatch)
        } else if data.encap_content_info.e_content_type != crate::oid::DATA
            || (pdf.is_none() && seen.signing_time.is_none())
            || (pdf.is_some() && seen.signing_time.is_some())
            || seen.ess_matches.is_none()
        {
            Some(crate::cms::Problem::Malformed)
        } else {
            None
        };
        let signed = attrs.to_der()?;
        let mut state = HashState::new(algorithm.hash_alg());
        state.update(&signed);
        let evidence = SignerEvidence {
            certificate,
            algorithm,
            signed_digest: state.finish(),
            signature: signer.info.signature.as_bytes(),
            claimed_time: seen.signing_time,
        };
        let values = raw.unsigned_values()?;
        let signatures: Vec<_> = token_ids[index]
            .iter()
            .filter(|(oid, _, _)| *oid == SIGNATURE_TIMESTAMP)
            .collect();
        let achieved = if let Some(pdf) = pdf {
            pdf.achieved(!signatures.is_empty())
        } else if token_ids[index]
            .iter()
            .any(|(oid, _, _)| *oid == ARCHIVE_TIMESTAMP)
        {
            AdesLevel::Lta
        } else if !signatures.is_empty() && !statuses.is_empty() {
            AdesLevel::Lt
        } else if !signatures.is_empty() {
            AdesLevel::T
        } else {
            AdesLevel::B
        };
        let level = required.max(achieved);
        minimum = minimum.min(level);
        let signature_coverage = [CoveragePart::Signature];
        if prepared_evidence.is_none() {
            *prepared_evidence = Some(prepare_evidence(&evidence, bundle, &final_context, scope)?);
        }
        if let Some(pdf) = pdf {
            final_context = pdf.validation_context(services)?;
        }
        if required_certificates.iter().any(|id| {
            !prepared_evidence
                .as_ref()
                .expect("prepared above")
                .has_certificate(*id)
        }) {
            return Err(invalid("DSS contains a malformed certificate"));
        }
        let checked = (|| -> Result<ValidationReport, AdesError> {
            if let Some(pdf) = pdf {
                if token_ids[index]
                    .iter()
                    .any(|(oid, _, _)| *oid == ARCHIVE_TIMESTAMP)
                {
                    return Err(invalid(
                        "CMS archive timestamps are not PDF document timestamps",
                    ));
                }
                return pdf.validate(
                    &evidence,
                    bundle,
                    &signatures,
                    document_ids,
                    level,
                    services,
                    scope,
                    prepared_evidence.as_ref().expect("prepared above"),
                );
            }
            if signatures.len() > 1 {
                return Err(invalid("duplicate signature timestamp"));
            }
            let archive_oid = ARCHIVE_TIMESTAMP.to_der()?;
            let mut archives = Vec::new();
            for (oid, token, id) in &token_ids[index] {
                if *oid == ARCHIVE_TIMESTAMP {
                    let bytes = index_from_token(token)?;
                    let hash_index = HashIndex::from_der(&bytes)?;
                    let predecessor_count = token_ids[index]
                        .iter()
                        .filter(|(oid, value, _)| {
                            *oid == ARCHIVE_TIMESTAMP
                                && hash_index.unsigned.iter().any(|hash| {
                                    hash.as_bytes() == digest_pair(&archive_oid, value).as_bytes()
                                })
                        })
                        .count();
                    archives.push((predecessor_count, *token, *id, bytes));
                }
            }
            archives.sort_by_key(|(count, _, _, _)| *count);
            if archives
                .iter()
                .enumerate()
                .any(|(index, (count, _, _, _))| index != *count)
            {
                return Err(invalid("archive proof chain omits, branches or cycles"));
            }
            let mut nested: Vec<[CoveragePart<'_>; 3]> = Vec::new();
            let mut coverages: Vec<Vec<CoveragePart<'_>>> = Vec::new();
            let mut selected: Vec<Vec<EvidenceId>> = Vec::new();
            for (_, _, _, index_bytes) in &archives {
                let hash_index = HashIndex::from_der(index_bytes)?;
                hash_index.check()?;
                let mut protected = Vec::new();
                let mut leaves = Vec::new();
                // Each selected index entry is matched to the actual standard root
                // choice or same-signer unsigned value, not to a wire skip list.
                for (hashes, records) in [
                    (&hash_index.certificates, &cert_records),
                    (&hash_index.crls, &status_records),
                ] {
                    let mut used = Vec::new();
                    for entry in hashes {
                        let matches: Vec<_> = records
                            .iter()
                            .enumerate()
                            .filter(|(_, record)| hash(record.wire).as_bytes() == entry.as_bytes())
                            .collect();
                        if matches.len() != 1 || used.contains(&matches[0].0) {
                            return Err(invalid(
                                "archive index has missing or duplicate root evidence",
                            ));
                        }
                        used.push(matches[0].0);
                        let record = matches[0].1;
                        protected.push(record.id);
                        leaves.push([
                            CoveragePart::Bytes(record.prefix),
                            CoveragePart::Evidence {
                                id: record.id,
                                encoding: CoverageEncoding::Raw,
                            },
                            CoveragePart::Bytes(record.suffix),
                        ]);
                    }
                }
                let mut used = Vec::new();
                for entry in &hash_index.unsigned {
                    let matches: Vec<_> = values
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, oid, value))| {
                            digest_pair(oid, value).as_bytes() == entry.as_bytes()
                        })
                        .collect();
                    if matches.len() != 1 || used.contains(&matches[0].0) {
                        return Err(invalid(
                            "archive index has missing or duplicate unsigned value",
                        ));
                    }
                    used.push(matches[0].0);
                    let (oid, oid_bytes, value) = *matches[0].1;
                    if oid == SIGNATURE_TIMESTAMP || oid == ARCHIVE_TIMESTAMP {
                        let id = token_ids[index]
                            .iter()
                            .find(|(kind, bytes, _)| *kind == oid && *bytes == value)
                            .ok_or_else(|| invalid("unbound archive predecessor"))?
                            .2;
                        protected.push(id);
                        leaves.push([
                            CoveragePart::Bytes(oid_bytes),
                            CoveragePart::Evidence {
                                id,
                                encoding: CoverageEncoding::Raw,
                            },
                            CoveragePart::Bytes(&[]),
                        ]);
                    } else {
                        leaves.push([
                            CoveragePart::Bytes(oid_bytes),
                            CoveragePart::Bytes(value),
                            CoveragePart::Bytes(&[]),
                        ]);
                    }
                }
                // Reconstruct exact DER ATSHashIndexV3 around streaming hash leaves.
                // Comparing its output to the parsed index is intrinsic to imprint
                // verification; no trusted precomputed digest enters F04.
                nested.extend(leaves);
                selected.push(protected);
            }
            // Build graphs only after the owning vectors have reached final size.
            let mut leaf_offset = 0;
            for (_, _, _, index_bytes) in &archives {
                let fields = ber::raw_children(encoded)?;
                let signature_field = fields[5];
                let signature_header_len = signature_field
                    .len()
                    .checked_sub(evidence.signature.len())
                    .ok_or_else(|| invalid("nonprimitive CAdES signature field"))?;
                if signature_field.first() != Some(&4) {
                    return Err(invalid("CAdES signature must be primitive OCTET STRING"));
                }
                let mut coverage = Vec::new();
                let index_fields = ber::raw_children(index_bytes)?;
                coverage.extend(fields[..5].iter().map(|bytes| CoveragePart::Bytes(bytes)));
                coverage.push(CoveragePart::Bytes(
                    &signature_field[..signature_header_len],
                ));
                coverage.push(CoveragePart::Signature);
                coverage.push(CoveragePart::Bytes(
                    &index_bytes
                        [..index_bytes.len() - AnyRef::from_der(index_bytes)?.value().len()],
                ));
                coverage.push(CoveragePart::Bytes(index_fields[0]));
                for field in &index_fields[1..] {
                    coverage.push(CoveragePart::Bytes(
                        &field[..field.len() - AnyRef::from_der(field)?.value().len()],
                    ));
                    for hash_value in ber::raw_children(field)? {
                        coverage.push(CoveragePart::Bytes(
                            &hash_value
                                [..hash_value.len() - AnyRef::from_der(hash_value)?.value().len()],
                        ));
                        coverage.push(CoveragePart::Hashed {
                            algorithm: HashAlg::Sha256,
                            parts: &nested[leaf_offset],
                        });
                        leaf_offset += 1;
                    }
                }
                coverages.push(coverage);
            }
            // Prefix the actual content type and independently streamed document
            // digest to the signer fields + reconstructed hash index.
            let document_hash = frozen.values[2]
                .as_ref()
                .ok_or_else(|| invalid("archive document hash missing"))?;
            for coverage in &mut coverages {
                coverage.insert(0, CoveragePart::Bytes(document_hash.as_bytes()));
                coverage.insert(0, CoveragePart::Bytes(frozen.content_type.as_bytes()));
            }
            let mut proofs = Vec::with_capacity(1 + archives.len());
            if let Some((_, _, id)) = signatures.first() {
                proofs.push(TimestampBinding {
                    token: *id,
                    kind: ProofKind::Signature,
                    coverage: &signature_coverage,
                });
            }
            for ((_, _, id, _), coverage) in archives.iter().zip(&coverages) {
                proofs.push(TimestampBinding {
                    token: *id,
                    kind: ProofKind::Archive,
                    coverage,
                });
            }
            let selections: Vec<_> = archives
                .iter()
                .zip(&selected)
                .map(|((_, _, token, _), protected)| ArchiveSelection {
                    token: *token,
                    protected,
                    algorithm: HashAlg::Sha256,
                })
                .collect();
            Ok(validate_prepared_evidence(
                &evidence,
                bundle,
                &proofs,
                level,
                &final_context,
                services.network,
                scope,
                (!archives.is_empty()).then_some(selections.as_slice()),
                prepared_evidence.as_ref().expect("prepared above"),
            )?)
        })();
        let mut report = match checked {
            Ok(report) => report,
            Err(error) if fatal(&error) => return Err(error),
            Err(_) => {
                let proofs = signatures
                    .first()
                    .map(|(_, _, token)| TimestampBinding {
                        token: *token,
                        kind: ProofKind::Signature,
                        coverage: &signature_coverage,
                    })
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut report = validate_prepared_evidence(
                    &evidence,
                    bundle,
                    &proofs,
                    if proofs.is_empty() {
                        AdesLevel::B
                    } else {
                        AdesLevel::T
                    },
                    &final_context,
                    services.network,
                    scope,
                    None,
                    prepared_evidence.as_ref().expect("prepared above"),
                )?;
                report
                    .signers
                    .cades_failure(0, ValidationReason::Timestamp, scope)?;
                report.verdict = Verdict::Invalid;
                report
            }
        };
        if let Some(problem) = source_problem {
            report
                .signers
                .cades_failure(0, ValidationReason::Signature(problem), scope)?;
            report.verdict = Verdict::Invalid;
        }
        report.signers.cades_level(0, level);
        reports.push(report);
    }
    let verdict = if reports
        .iter()
        .any(|report| report.verdict == Verdict::Invalid)
    {
        Verdict::Invalid
    } else if reports
        .iter()
        .any(|report| report.verdict == Verdict::Indeterminate)
    {
        Verdict::Indeterminate
    } else {
        Verdict::Valid
    };
    Ok(AdesReport {
        verdict,
        level: (verdict == Verdict::Valid).then_some(minimum),
        reports,
        bytes_in: 0,
        bytes_out: 0,
        _memory: memory,
        _metadata: metadata,
    })
}

pub(crate) struct ScopedToken {
    pub(crate) bytes: Vec<u8>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
pub(crate) fn request_imprint(
    imprint: &DigestValue,
    services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<ScopedToken, AdesError> {
    let spec = services.tsa.ok_or(AdesError::MissingConfiguration)?;
    if spec.hash != HashAlg::Sha256 || !spec.require_tsa_eku {
        return Err(invalid(
            "CAdES TSA profile requires SHA-256 and timestamp EKU",
        ));
    }
    // The established RFC3161 decoder returns owned response/token/certificate
    // values. Admit their bounded maximum plus parser/re-encoding scratch before
    // the network callback can allocate, and retain it through metadata adoption.
    let memory = scope.reserve_memory(crate::http::MAX_RESPONSE_LEN * 64)?;
    let metadata = scope.reserve_metadata(crate::http::MAX_RESPONSE_LEN * 16)?;
    let http = DeadlineTransport::new(services.validation.http, services.network, scope);
    let result = if let Some(clock) = services.host_clock {
        crate::tsp::request_with_clock_scoped(spec, imprint.as_bytes(), &http, clock).and_then(
            |(reply, checked_at)| {
                if reply.reply.tst.gen_time > checked_at {
                    Err(crate::tsp::TspError::ClockSkew)
                } else {
                    Ok(reply)
                }
            },
        )
    } else {
        crate::tsp::request_at_scoped(spec, imprint.as_bytes(), &http, services.validation.now)
    };
    http.finish()?;
    let reply = result?;
    Ok(ScopedToken {
        bytes: reply.reply.token.clone(),
        _memory: memory,
        _metadata: metadata,
    })
}

/// Extend without a private-key operation. Original signed fields and signature
/// octets are copied, never re-signed. An invalid original/proof is never repaired
/// by adding a newer archive token. Publication occurs only after final validation.
pub fn extend(
    level: AdesLevel,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    output: &mut dyn Write,
    scope: &ResourceScope,
) -> Result<AdesReport, AdesError> {
    let before = scope.progress();
    let frozen = freeze(input, detached, services, scope)?;
    let mut report = extend_frozen(
        level,
        frozen,
        services,
        allowed,
        &mut Output::Writer(output),
        scope,
    )?;
    report.bytes_in = scope.progress().bytes_in - before.bytes_in;
    Ok(report)
}
pub fn extend_staged(
    level: AdesLevel,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<AdesReport, AdesError> {
    output.check_sign_output(scope)?;
    let before = scope.progress();
    let result = (|| {
        let frozen = freeze(input, detached, services, scope)?;
        let mut report = extend_frozen(
            level,
            frozen,
            services,
            allowed,
            &mut Output::Staged(output),
            scope,
        )?;
        report.bytes_in = scope.progress().bytes_in - before.bytes_in;
        Ok(report)
    })();
    if result.is_err() {
        output.fail_sign_output();
    }
    result
}
fn extend_frozen(
    level: AdesLevel,
    mut frozen: Frozen,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    output: &mut Output<'_>,
    scope: &ResourceScope,
) -> Result<AdesReport, AdesError> {
    let material_bytes = services
        .material
        .certificates
        .iter()
        .try_fold(0u64, |sum, cert| -> Result<u64, AdesError> {
            Ok(sum
                .checked_add(u32::from(cert.encoded_len()?) as u64)
                .ok_or(ProcessingError::MetadataLimit)?)
        })?
        .checked_add(
            services
                .material
                .ocsp
                .iter()
                .chain(services.material.crls)
                .try_fold(0u64, |sum, bytes| {
                    sum.checked_add(bytes.len() as u64)
                        .ok_or(ProcessingError::MetadataLimit)
                })?,
        )
        .ok_or(ProcessingError::MetadataLimit)?;
    let _working = scope.reserve_memory(
        material_bytes
            .checked_add(frozen.parsed.metadata.decoded_bytes())
            .and_then(|bytes| bytes.checked_mul(128))
            .ok_or(ProcessingError::MemoryLimit)?,
    )?;
    let _metadata = scope.reserve_metadata(
        material_bytes
            .checked_mul(16)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let has_archive = raw_set(frozen.signers.as_bytes())?.iter().try_fold(
        false,
        |found, encoded| -> Result<bool, AdesError> {
            Ok(found
                || RawSigner::new(encoded)?
                    .unsigned_values()?
                    .iter()
                    .any(|(oid, _, _)| *oid == ARCHIVE_TIMESTAMP))
        },
    )?;
    if !has_archive {
        add_material(&mut frozen, services, scope)?;
    }
    let original = verify_frozen(AdesLevel::B, &frozen, services, allowed, scope)?;
    if original.verdict != Verdict::Valid {
        return Err(invalid(
            "all original CAdES signatures and proofs must validate before extension",
        ));
    }
    drop(original);
    let old_signers = raw_set(frozen.signers.as_bytes())?;
    let mut updated = Metadata::new(scope)?;
    for encoded in old_signers {
        let raw = RawSigner::new(encoded)?;
        let values = raw.unsigned_values()?;
        let token = if level >= AdesLevel::T
            && !values.iter().any(|(oid, _, _)| *oid == SIGNATURE_TIMESTAMP)
        {
            let normalized = ber::to_der(encoded)?;
            let signer = SignerInfo::from_der(&normalized)?;
            Some(request_imprint(
                &hash(signer.signature.as_bytes()),
                services,
                scope,
            )?)
        } else {
            None
        };
        let added = token
            .as_ref()
            .map(|token| attribute(SIGNATURE_TIMESTAMP, &token.bytes))
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        updated.append(&raw.encode(&added))?;
    }
    frozen.signers = updated;
    if level >= AdesLevel::Lt {
        add_material(&mut frozen, services, scope)?;
    }
    if level >= AdesLevel::Lta {
        let certs = raw_set(frozen.certificates.as_bytes())?;
        let statuses = ber::raw_children(frozen.status.as_bytes())?;
        let document = frozen.values[2]
            .as_ref()
            .ok_or_else(|| invalid("missing archive document hash"))?;
        let mut updated = Metadata::new(scope)?;
        for encoded in raw_set(frozen.signers.as_bytes())? {
            let raw = RawSigner::new(encoded)?;
            let values = raw.unsigned_values()?;
            let index = HashIndex {
                algorithm: spki::AlgorithmIdentifierRef {
                    oid: HashAlg::Sha256.oid(),
                    parameters: Some(AnyRef::NULL),
                },
                certificates: certs
                    .iter()
                    .map(|bytes| OctetString::new(hash(bytes).as_bytes()).map_err(AdesError::from))
                    .collect::<Result<_, _>>()?,
                crls: statuses
                    .iter()
                    .map(|bytes| OctetString::new(hash(bytes).as_bytes()).map_err(AdesError::from))
                    .collect::<Result<_, _>>()?,
                unsigned: values
                    .iter()
                    .map(|(_, oid, value)| {
                        OctetString::new(digest_pair(oid, value).as_bytes())
                            .map_err(AdesError::from)
                    })
                    .collect::<Result<_, _>>()?,
            }
            .to_der()?;
            let mut imprint = HashState::new(HashAlg::Sha256);
            imprint.update(frozen.content_type.as_bytes());
            imprint.update(document.as_bytes());
            for field in &raw.fields[..6] {
                imprint.update(field);
            }
            imprint.update(&index);
            let granted = request_imprint(&imprint.finish(), services, scope)?;
            let token = token_with_index(&granted.bytes, &index)?;
            updated.append(&raw.encode(&[attribute(ARCHIVE_TIMESTAMP, &token)?]))?;
        }
        frozen.signers = updated;
    }
    // Rebuild a bounded metadata-only PreparedCms for final content/ESS checks.
    let old = PreparedCms::from_digests(frozen.parsed.metadata.as_bytes(), frozen.values);
    let mut data = old.signed_data()?;
    data.certificates = Some(RawSet(frozen.certificates.as_bytes()));
    let status_any = AnyRef::from_der(frozen.status.as_bytes())?;
    data.crls = (!status_any.value().is_empty()).then(|| RawSet(status_any.value()));
    data.signer_infos = RawSet(frozen.signers.as_bytes());
    if ber::raw_children(frozen.status.as_bytes())?
        .iter()
        .any(|choice| choice.first() == Some(&0xa1))
    {
        data.version = 5;
    }
    let encoded = SignedContentInfo { signed_data: &data }.to_der()?;
    let normalized = ber::to_der(&encoded)?;
    let mut metadata = Metadata::new(scope)?;
    metadata.append(&normalized)?;
    frozen.parsed.metadata = metadata;
    let mut report = verify_frozen(level, &frozen, services, allowed, scope)?;
    if report.verdict != Verdict::Valid {
        return Err(invalid(
            "extended CAdES did not validate at requested level",
        ));
    }
    let mut operation = scope.retain();
    let mut staged = services.temporary.stage_source(&mut operation)?;
    write_frozen(&mut frozen, &mut Output::Staged(&mut staged), scope)?;
    report.bytes_out = publish(staged, output, scope)?;
    Ok(report)
}
fn publish(
    mut staged: StagedArtifact,
    output: &mut Output<'_>,
    scope: &ResourceScope,
) -> Result<u64, AdesError> {
    let len = staged.len();
    copy_region(&mut staged, Region { offset: 0, len }, output, scope)?;
    output.finish(scope)?;
    Ok(len)
}

fn add_material(
    frozen: &mut Frozen,
    services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<(), AdesError> {
    let mut certificates = raw_set(frozen.certificates.as_bytes())?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    for certificate in services.material.certificates {
        let encoded = certificate.to_der()?;
        if !certificates.contains(&encoded) {
            certificates.push(encoded);
        }
    }
    for encoded in raw_set(frozen.signers.as_bytes())? {
        for (oid, _, token) in RawSigner::new(encoded)?.unsigned_values()? {
            if oid == SIGNATURE_TIMESTAMP || oid == ARCHIVE_TIMESTAMP {
                let normalized = ber::to_der(token)?;
                let ci = ContentInfo::from_der(&normalized)?;
                let data: SignedData<'_> = ci.content.decode_as()?;
                if let Some(values) = data.certificates {
                    for encoded in values.tlvs()? {
                        if encoded.first() == Some(&0x30)
                            && !certificates.iter().any(|cert| cert == encoded)
                        {
                            certificates.push(encoded.to_vec());
                        }
                    }
                }
            }
        }
    }
    let mut encoded_certificates = Metadata::new(scope)?;
    for certificate in certificates {
        encoded_certificates.append(&certificate)?;
    }
    frozen.certificates = encoded_certificates;
    let mut statuses = ber::raw_children(frozen.status.as_bytes())?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    for crl in services.material.crls {
        if !statuses.iter().any(|value| value == crl) {
            statuses.push(crl.to_vec());
        }
    }
    for ocsp in services.material.ocsp {
        let mut body = OCSP_RESPONSE.to_der()?;
        body.extend_from_slice(ocsp);
        let choice = tlv(0xa1, &body);
        if !statuses.contains(&choice) {
            statuses.push(choice);
        }
    }
    let mut body = Metadata::new(scope)?;
    for status in statuses {
        body.append(&status)?;
    }
    let mut statuses = Metadata::new(scope)?;
    statuses.append_tlv(0xa1, body.as_bytes())?;
    frozen.status = statuses;
    Ok(())
}

fn write_frozen(
    frozen: &mut Frozen,
    output: &mut Output<'_>,
    scope: &ResourceScope,
) -> Result<(), AdesError> {
    let mut version = metadata_region(&mut frozen.source, frozen.parsed.layout.version, scope)?;
    if ber::raw_children(frozen.status.as_bytes())?
        .iter()
        .any(|choice| choice.first() == Some(&0xa1))
    {
        version = Metadata::new(scope)?;
        version.append(&5u8.to_der()?)?;
    }
    let algorithms = metadata_region(&mut frozen.source, frozen.parsed.layout.algorithms, scope)?;
    let status = AnyRef::from_der(frozen.status.as_bytes())?;
    let status_len = if status.value().is_empty() {
        0
    } else {
        frozen.status.as_bytes().len() as u64
    };
    let flags = frozen.parsed.layout.indefinite;
    let body_len = sum(&[
        version.as_bytes().len() as u64,
        size(algorithms.as_bytes().len() as u64, false)?,
        frozen.parsed.layout.encap.len,
        size(frozen.certificates.as_bytes().len() as u64, false)?,
        status_len,
        size(frozen.signers.as_bytes().len() as u64, false)?,
    ])?;
    let signed_len = size(body_len, flags[2])?;
    let explicit_len = size(signed_len, flags[1])?;
    let oid = crate::oid::SIGNED_DATA.to_der()?;
    let root_len = sum(&[oid.len() as u64, explicit_len])?;
    scope.account_container(
        size(root_len, flags[0])?
            .checked_sub(frozen.parsed.inspection.content_len)
            .ok_or(ProcessingError::ContainerLimit)?,
    )?;
    output.header(0x30, root_len, flags[0], scope)?;
    output.write(&oid, scope)?;
    output.header(0xa0, signed_len, flags[1], scope)?;
    output.header(0x30, body_len, flags[2], scope)?;
    output.write(version.as_bytes(), scope)?;
    output.header(0x31, algorithms.as_bytes().len() as u64, false, scope)?;
    output.write(algorithms.as_bytes(), scope)?;
    copy_region(
        &mut frozen.source,
        frozen.parsed.layout.encap,
        output,
        scope,
    )?;
    output.header(
        0xa0,
        frozen.certificates.as_bytes().len() as u64,
        false,
        scope,
    )?;
    output.write(frozen.certificates.as_bytes(), scope)?;
    if status_len != 0 {
        output.write(frozen.status.as_bytes(), scope)?;
    }
    output.header(0x31, frozen.signers.as_bytes().len() as u64, false, scope)?;
    output.write(frozen.signers.as_bytes(), scope)?;
    output.end(flags[2], scope)?;
    output.end(flags[1], scope)?;
    output.end(flags[0], scope)?;
    output.finish(scope)?;
    Ok(())
}
