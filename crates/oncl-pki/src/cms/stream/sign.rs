//! Streaming private operations. Content is never retained in a heap container.
use super::{
    ALGORITHMS, StreamError,
    reader::{Metadata, Reader, encoded_length, malformed},
};
use crate::{
    cms::{AttrSpec, CmsError, asn1::RawSet, report::PreparedCms},
    digest::{DigestValue, HashState},
    io::{Region, Source, StagedArtifact, TemporaryStore},
    key::{AppliedState, DigestSigner, SigAlg},
    resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope},
};
use der::{Decode, Encode, EncodeValue, Tagged};
use std::io::{self, Read, Write};

/// Only implemented CMS operations; Add preserves existing attachment/encoding.
#[derive(Clone, Copy, Debug)]
pub struct CmsSignRequest {
    attached: Option<bool>,
    allowed: &'static [SigAlg],
    signing_time: Option<time::OffsetDateTime>,
}
impl CmsSignRequest {
    pub const fn create(attached: bool) -> Self {
        Self {
            attached: Some(attached),
            allowed: &ALGORITHMS,
            signing_time: None,
        }
    }
    pub const fn add() -> Self {
        Self {
            attached: None,
            allowed: &ALGORITHMS,
            signing_time: None,
        }
    }
    /// Trusted host policy for existing signatures; creation still rejects SHA-1.
    pub const fn with_allowed_algorithms(mut self, allowed: &'static [SigAlg]) -> Self {
        self.allowed = allowed;
        self
    }
    pub fn with_signing_time(mut self, at: time::OffsetDateTime) -> Self {
        self.signing_time = Some(at);
        self
    }
    pub(super) fn attachment(&self) -> Option<bool> {
        self.attached
    }
    pub(super) fn with_default_signing_time(mut self, at: time::OffsetDateTime) -> Self {
        self.signing_time.get_or_insert(at);
        self
    }
    pub(super) fn allowed_algorithms(&self) -> &'static [SigAlg] {
        self.allowed
    }
}
/// Borrowed trusted-host dependencies for CMS signing. These are not wire
/// settings, document readers, secrets, or a second operation/resource context.
pub struct CmsSignServices<'a> {
    pub(super) validation: Option<&'a crate::validation::ValidationContext<'a>>,
    pub(super) temporary: Option<&'a TemporaryStore>,
}
impl<'a> CmsSignServices<'a> {
    pub const fn new(
        validation: Option<&'a crate::validation::ValidationContext<'a>>,
        temporary: Option<&'a TemporaryStore>,
    ) -> Self {
        Self {
            validation,
            temporary,
        }
    }
    pub fn validation(&self) -> Option<&crate::validation::ValidationContext<'_>> {
        self.validation
    }
    pub fn temporary(&self) -> Option<&TemporaryStore> {
        self.temporary
    }
}

/// Owned completion facts retain their exact original resource admission.
pub struct SignSummary {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub signer_count: usize,
    pub applied: AppliedState,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl std::fmt::Debug for SignSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignSummary")
            .field("bytes_in", &self.bytes_in)
            .field("bytes_out", &self.bytes_out)
            .field("signer_count", &self.signer_count)
            .field("applied", &self.applied)
            .finish_non_exhaustive()
    }
}
fn applied(error: StreamError, state: AppliedState) -> StreamError {
    if state == AppliedState::NotApplied {
        error
    } else {
        StreamError::AfterKeyUse {
            source: Box::new(error),
            applied: state,
        }
    }
}
pub(super) enum Output<'a> {
    Writer(&'a mut dyn Write),
    Staged(&'a mut StagedArtifact),
    Internal(&'a mut dyn Write, u64),
}
impl Output<'_> {
    pub(super) fn write(
        &mut self,
        mut bytes: &[u8],
        scope: &ResourceScope,
    ) -> Result<(), StreamError> {
        match self {
            Self::Staged(stage) => {
                stage.write_chunk(bytes)?;
            }
            Self::Internal(writer, _) => {
                scope.checkpoint()?;
                writer.write_all(bytes).map_err(ProcessingError::from)?;
            }
            Self::Writer(writer) => {
                scope.account_output(bytes.len() as u64)?;
                while !bytes.is_empty() {
                    scope.checkpoint()?;
                    let n = match writer.write(&bytes[..bytes.len().min(IO_CHUNK_BYTES)]) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        result => result.map_err(ProcessingError::from)?,
                    };
                    if n == 0 || n > bytes.len().min(IO_CHUNK_BYTES) {
                        return Err(ProcessingError::Io(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "sign output made invalid progress",
                        ))
                        .into());
                    }
                    bytes = &bytes[n..];
                    scope.checkpoint()?;
                }
            }
        }
        scope.checkpoint()?;
        Ok(())
    }
    pub(super) fn header(
        &mut self,
        tag: u8,
        len: u64,
        indefinite: bool,
        scope: &ResourceScope,
    ) -> Result<(), StreamError> {
        scope.account_framing(if indefinite {
            2
        } else {
            1 + encoded_length(len).1 as u64
        })?;
        self.write(&[tag], scope)?;
        if indefinite {
            self.write(&[0x80], scope)
        } else {
            let (bytes, n) = encoded_length(len);
            self.write(&bytes[..n], scope)
        }
    }
    pub(super) fn end(
        &mut self,
        indefinite: bool,
        scope: &ResourceScope,
    ) -> Result<(), StreamError> {
        if indefinite {
            scope.account_framing(2)?;
            self.write(&[0, 0], scope)?;
        }
        Ok(())
    }
    pub(super) fn finish(&mut self, scope: &ResourceScope) -> Result<(), StreamError> {
        scope.checkpoint()?;
        if let Self::Writer(w) = self {
            w.flush().map_err(ProcessingError::from)?;
        }
        scope.checkpoint()?;
        Ok(())
    }
}
pub(super) fn size(len: u64, indefinite: bool) -> Result<u64, StreamError> {
    len.checked_add(if indefinite {
        4
    } else {
        1 + encoded_length(len).1 as u64
    })
    .ok_or_else(|| malformed("CMS output length overflow"))
}
pub(super) fn sum(values: &[u64]) -> Result<u64, StreamError> {
    values.iter().try_fold(0u64, |n, v| {
        n.checked_add(*v)
            .ok_or_else(|| malformed("CMS output length overflow"))
    })
}

// Shared with final emission, including BER framing for ordinary CMS Add.
fn cms_lengths(fields: &[u64; 6], oid_len: u64, flags: [bool; 3]) -> Result<[u64; 4], StreamError> {
    let body = sum(fields)?;
    let signed = size(body, flags[2])?;
    let explicit = size(signed, flags[1])?;
    let root = sum(&[oid_len, explicit])?;
    Ok([body, signed, root, size(root, flags[0])?])
}

pub(super) struct StageReader<'a> {
    pub(super) stage: &'a mut StagedArtifact,
    pub(super) position: u64,
    pub(super) error: Option<ProcessingError>,
}
impl Read for StageReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let n = match self.stage.read_region(
            Region {
                offset: self.position,
                len: self.stage.len() - self.position,
            },
            output,
        ) {
            Ok(n) => n,
            Err(error) => {
                self.error = Some(error);
                return Err(io::Error::other("source snapshot replay failed"));
            }
        };
        self.position += n as u64;
        Ok(n)
    }
}
pub(super) fn copy_region(
    stage: &mut StagedArtifact,
    region: Region,
    output: &mut Output<'_>,
    scope: &ResourceScope,
) -> Result<(), StreamError> {
    let capacity = scope.available_memory().min(IO_CHUNK_BYTES as u64) as usize;
    if capacity == 0 {
        return Err(ProcessingError::MemoryLimit.into());
    }
    let _memory = scope.reserve_memory(capacity as u64)?;
    let mut buffer = vec![0; capacity];
    let mut at = 0;
    while at < region.len {
        scope.checkpoint()?;
        let n = stage.read_region(
            Region {
                offset: region.offset + at,
                len: region.len - at,
            },
            &mut buffer,
        )?;
        if n == 0 {
            return Err(malformed("short source snapshot"));
        }
        output.write(&buffer[..n], scope)?;
        at += n as u64;
    }
    Ok(())
}
pub(super) fn snapshot(
    input: Source<'_>,
    store: Option<&TemporaryStore>,
    scope: &mut ResourceScope,
) -> Result<StagedArtifact, StreamError> {
    let mut stage = store
        .ok_or(StreamError::MissingTemporaryStore)?
        .stage_source(scope)?;
    Reader::new(input, scope)?.raw_content(|bytes| {
        stage.write_chunk(bytes)?;
        Ok(())
    })?;
    Ok(stage)
}
pub(super) fn metadata_region(
    stage: &mut StagedArtifact,
    region: Region,
    scope: &ResourceScope,
) -> Result<Metadata, StreamError> {
    let mut result = Metadata::new(scope)?;
    result.reserve_total(region.len)?;
    let mut at = 0;
    let mut buffer = [0; 4096];
    let _memory = scope.reserve_memory(buffer.len() as u64)?;
    while at < region.len {
        let n = stage.read_region(
            Region {
                offset: region.offset + at,
                len: region.len - at,
            },
            &mut buffer,
        )?;
        if n == 0 {
            return Err(malformed("short metadata snapshot"));
        }
        result.append(&buffer[..n])?;
        at += n as u64;
    }
    Ok(result)
}
fn admission(
    signers: &[&mut dyn DigestSigner],
    scope: &ResourceScope,
) -> Result<(ResourceReservation, ResourceReservation), StreamError> {
    if signers.is_empty() || signers.len() > 64 {
        return Err(malformed("signer count must be 1..=64"));
    }
    let mut bytes = 16384u64
        .checked_mul(signers.len() as u64)
        .ok_or(ProcessingError::MetadataLimit)?;
    for signer in signers {
        if signer.algorithm() == SigAlg::RsaSha1 {
            return Err(CmsError::Key(crate::key::KeyError::UnsupportedAlgorithm).into());
        }
        let len: u32 = signer.certificate().encoded_len()?.into();
        bytes = bytes
            .checked_add(u64::from(len) * 32)
            .ok_or(ProcessingError::MetadataLimit)?;
    }
    Ok((scope.reserve_memory(bytes)?, scope.reserve_metadata(bytes)?))
}
fn summary(
    scope: &ResourceScope,
    before: crate::resource::Progress,
    count: usize,
    memory: ResourceReservation,
    metadata: ResourceReservation,
) -> SignSummary {
    let after = scope.progress();
    SignSummary {
        bytes_in: after.bytes_in - before.bytes_in,
        bytes_out: after.bytes_out - before.bytes_out,
        signer_count: count,
        applied: AppliedState::Applied,
        _memory: memory,
        _metadata: metadata,
    }
}
/// Write a new DER CMS or add to a verified CMS. Arbitrary writers may retain a
/// prefix on failure. For an SDK artifact use sign_staged, not a writer adapter.
pub fn sign(
    request: &CmsSignRequest,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    services: &CmsSignServices<'_>,
    output: &mut dyn Write,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    sign_impl(
        request,
        Some(input),
        detached,
        signers,
        services,
        &mut Output::Writer(output),
        scope,
        None,
    )
}
pub fn sign_staged(
    request: &CmsSignRequest,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    services: &CmsSignServices<'_>,
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    output.check_sign_output(scope)?;
    let result = sign_impl(
        request,
        Some(input),
        detached,
        signers,
        services,
        &mut Output::Staged(output),
        scope,
        None,
    );
    if result.is_err() {
        output.fail_sign_output();
    }
    result
}
pub(super) fn sign_prepared_staged(
    request: &CmsSignRequest,
    prepared: super::ades::PreparedAdd,
    signers: &mut [&mut dyn DigestSigner],
    services: &CmsSignServices<'_>,
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    output.check_internal_output(scope)?;
    let result = sign_impl(
        request,
        None,
        None,
        signers,
        services,
        &mut Output::Staged(output),
        scope,
        Some(prepared),
    );
    if result.is_err() {
        output.fail_sign_output();
    }
    result
}
pub(super) fn sign_internal(
    request: &CmsSignRequest,
    input: Source<'_>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    services: &CmsSignServices<'_>,
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    output.check_internal_output(scope)?;
    let result = sign_impl(
        request,
        Some(input),
        detached,
        signers,
        services,
        &mut Output::Staged(output),
        scope,
        None,
    );
    if result.is_err() {
        output.fail_sign_output();
    }
    result
}
#[allow(
    clippy::too_many_arguments,
    reason = "One C02 engine, with private ownership-bearing C03 Add admission"
)]
fn sign_impl(
    request: &CmsSignRequest,
    input: Option<Source<'_>>,
    detached: Option<Source<'_>>,
    signers: &mut [&mut dyn DigestSigner],
    services: &CmsSignServices<'_>,
    output: &mut Output<'_>,
    scope: &ResourceScope,
    prepared: Option<super::ades::PreparedAdd>,
) -> Result<SignSummary, StreamError> {
    let validation = services.validation;
    let temp = services.temporary;
    let before = scope.progress();
    let (_working, _metadata) = admission(signers, scope)?;
    let result_memory = scope.reserve_memory(std::mem::size_of::<SignSummary>() as u64)?;
    let result_metadata = scope.reserve_metadata(std::mem::size_of::<SignSummary>() as u64)?;
    let mut operation = scope.retain();
    let mut content: Option<StagedArtifact> = None;
    let mut old_metadata = None;
    let mut old_layout = None;
    let content_type;
    let values;
    let mut content_len = 0u64;
    let attached;
    let _proof;
    if let Some(mode) = request.attached {
        _proof = None;
        let input = input.ok_or_else(|| malformed("Create requires content input"))?;
        let mut states: [Option<HashState>; 4] = std::array::from_fn(|index| {
            signers
                .iter()
                .any(|s| s.algorithm() == ALGORITHMS[index])
                .then(|| HashState::new(ALGORITHMS[index].hash_alg()))
        });
        if detached.is_some() {
            return Err(malformed("Create does not accept detached auxiliary input"));
        }
        attached = mode;
        content_type = crate::oid::DATA;
        if attached {
            content = Some(
                temp.ok_or(StreamError::MissingTemporaryStore)?
                    .stage_source(&mut operation)?,
            );
        }
        Reader::new(input, &mut operation)?.raw_content(|bytes| {
            for state in states.iter_mut().flatten() {
                state.update(bytes);
            }
            content_len = content_len
                .checked_add(bytes.len() as u64)
                .ok_or(ProcessingError::InputLimit)?;
            if let Some(stage) = &mut content {
                stage.write_chunk(bytes)?;
            }
            Ok(())
        })?;
        values = states.map(|state| state.map(HashState::finish));
    } else {
        let (existing, parsed, digests, proof) = if let Some(prepared) = prepared {
            prepared.into_parts()
        } else {
            let validation =
                validation.ok_or_else(|| malformed("Add requires host validation services"))?;
            let input = input.ok_or_else(|| malformed("Add requires CMS input"))?;
            let mut existing = snapshot(input, temp, &mut operation)?;
            let length = existing.len();
            let mut reader = StageReader {
                stage: &mut existing,
                position: 0,
                error: None,
            };
            let needed: Vec<_> = signers.iter().map(|s| s.algorithm()).collect();
            let parsed = super::parse_with(
                Source::sequential(&mut reader, Some(length)),
                &mut operation,
                true,
                None,
                &needed,
                true,
                true,
            );
            if let Some(error) = reader.error.take() {
                return Err(error.into());
            }
            let mut parsed = parsed?;
            if !parsed.inspection.detached && detached.is_some() {
                return Err(malformed("attached Add does not accept detached data"));
            }
            let (report, digests) = super::verify::verify_parsed(
                &mut parsed,
                detached,
                validation,
                request.allowed,
                &mut operation,
            )?;
            if report.verdict != crate::validation::Verdict::Valid {
                return Err(malformed(
                    "all existing signatures must validate before Add",
                ));
            }
            (existing, parsed, digests, None)
        };
        _proof = proof;
        let prepared = PreparedCms::from_digests(parsed.metadata.as_bytes(), digests);
        content_type = prepared.signed_data()?.encap_content_info.e_content_type;
        attached = !parsed.inspection.detached;
        content_len = parsed.inspection.content_len;
        values = digests;
        old_layout = Some(parsed.layout);
        old_metadata = Some(parsed.metadata);
        content = Some(existing);
    }
    // Raw old TLVs are preserved for output; normalized metadata is used only
    // for identity/association checks. Admit index/temporary capacities first.
    let _old_working = if let Some(metadata) = &old_metadata {
        Some(
            scope.reserve_memory(
                (metadata.as_bytes().len() as u64)
                    .checked_mul(32)
                    .ok_or(ProcessingError::MemoryLimit)?,
            )?,
        )
    } else {
        None
    };
    let mut known_algorithms = [false; 4];
    let mut known_certificates = Vec::new();
    if let Some(metadata) = &old_metadata {
        let prepared = PreparedCms::from_digests(metadata.as_bytes(), values);
        let signed_data = prepared.signed_data()?;
        for encoded in signed_data.digest_algorithms.tlvs()? {
            let algorithm = spki::AlgorithmIdentifierRef::from_der(encoded)?;
            for (slot, candidate) in ALGORITHMS.iter().enumerate() {
                if candidate.digest_oid() == algorithm.oid {
                    known_algorithms[slot] = true;
                }
            }
        }
        if let Some(certs) = signed_data.certificates {
            known_certificates = certs.tlvs()?;
        }
    }
    let mut algorithms = Metadata::new(scope)?;
    let mut certificates = Metadata::new(scope)?;
    let mut signer_infos = Metadata::new(scope)?;
    if let (Some(layout), Some(stage)) = (old_layout, content.as_mut()) {
        algorithms = metadata_region(stage, layout.algorithms, scope)?;
        if let Some(region) = layout.certificates {
            certificates = metadata_region(stage, region, scope)?;
        }
        signer_infos = metadata_region(stage, layout.signers, scope)?;
    }
    // Complete all metadata admission/algorithm checks before the first application.
    let mut certs = Vec::with_capacity(signers.len());
    for signer in signers.iter() {
        certs.push(signer.certificate().to_der()?);
    }
    preflight_certificate_union(old_metadata.as_ref(), signers, &certs, scope)?;
    for (index, signer) in signers.iter().enumerate() {
        let alg = signer.algorithm();
        let slot = ALGORITHMS
            .iter()
            .position(|a| *a == alg)
            .ok_or_else(|| malformed("unsupported signing algorithm"))?;
        if values[slot].is_none() {
            return Err(malformed("missing actual detached content digest"));
        }
        if !known_algorithms[slot] {
            algorithms.append(
                &spki::AlgorithmIdentifierRef {
                    oid: alg.digest_oid(),
                    parameters: Some(der::asn1::AnyRef::NULL),
                }
                .to_der()?,
            )?;
            known_algorithms[slot] = true;
        }
        if !known_certificates.contains(&certs[index].as_slice())
            && !certs[..index].iter().any(|cert| cert == &certs[index])
        {
            certificates.append(&certs[index])?;
        }
    }
    drop(known_certificates);
    let mut applied_state = AppliedState::NotApplied;
    let execution = (|| {
        for (index, signer) in signers.iter_mut().enumerate() {
            scope.checkpoint()?;
            let alg = signer.algorithm();
            let slot = ALGORITHMS
                .iter()
                .position(|a| *a == alg)
                .ok_or_else(|| malformed("unsupported signing algorithm"))?;
            let digest =
                values[slot].ok_or_else(|| malformed("missing actual detached content digest"))?;
            let spec = AttrSpec {
                content_type: true,
                message_digest: true,
                signing_certificate_v2: true,
                signing_time: request
                    .signing_time
                    .map(|at| (at, crate::cms::TimeForm::Auto)),
                extra: Vec::new(),
            };
            let attrs = crate::cms::sign::signed_attributes(
                &spec,
                &content_type,
                digest.as_bytes(),
                &certs[index],
            )?
            .ok_or_else(|| malformed("signed attributes required"))?;
            let signed = RawSet(&attrs).to_der()?;
            let mut hash = HashState::new(alg.hash_alg());
            hash.update(&signed);
            let prepared =
                crate::cms::sign::PreparedSignerInfo::new(signer.certificate(), alg, Some(&attrs))?;
            if let Output::Internal(_, capacity) = output {
                // PDF has one detached fresh SignerInfo. Size the SAME borrowed
                // ASN.1 value that will be emitted, substituting only the
                // supported backend's known fixed signature length.
                let info = prepared.value(&[])?;
                let value_len: u32 = info.value_len()?.into();
                let empty_signature_len: u32 = info.signature.encoded_len()?.into();
                let fixed = u64::from(value_len)
                    .checked_sub(u64::from(empty_signature_len))
                    .ok_or_else(|| malformed("invalid signer-info size"))?;
                let signer_len = size(
                    sum(&[
                        fixed,
                        size(
                            crate::key::signature_width(signer.certificate(), alg)
                                .map_err(crate::cms::CmsError::Key)?,
                            false,
                        )?,
                    ])?,
                    false,
                )?;
                let type_len: u32 = content_type.encoded_len()?.into();
                let version_len: u32 = 1u8.encoded_len()?.into();
                let oid_len: u32 = crate::oid::SIGNED_DATA.encoded_len()?.into();
                let total = cms_lengths(
                    &[
                        u64::from(version_len),
                        size(algorithms.as_bytes().len() as u64, false)?,
                        size(u64::from(type_len), false)?,
                        size(certificates.as_bytes().len() as u64, false)?,
                        0,
                        size(signer_len, false)?,
                    ],
                    u64::from(oid_len),
                    [false; 3],
                )?[3];
                if total > *capacity {
                    return Err(malformed(
                        "CMS exceeds reserved PDF signature space before private use",
                    ));
                }
            }
            let signature = match signer.sign_digest(&hash.finish()) {
                Ok(value) => {
                    applied_state = applied_state.combine(AppliedState::Applied);
                    value
                }
                Err(error) => {
                    applied_state = applied_state.combine(error.applied_state());
                    return Err(CmsError::Key(error).into());
                }
            };
            scope.checkpoint()?;
            signer_infos.append(&prepared.value(&signature)?.to_der()?)?;
        }
        algorithms = sorted_set(algorithms, scope, old_layout.is_some())?;
        certificates = sorted_set(certificates, scope, old_layout.is_some())?;
        signer_infos = sorted_set(signer_infos, scope, old_layout.is_some())?;
        let oid = crate::oid::SIGNED_DATA.to_der()?;
        let version = if let (Some(layout), Some(stage)) = (old_layout, content.as_mut()) {
            metadata_region(stage, layout.version, scope)?
        } else {
            let mut v = Metadata::new(scope)?;
            v.append(&1u8.to_der()?)?;
            v
        };
        let type_der = content_type.to_der()?;
        let encap_body = sum(&[
            type_der.len() as u64,
            if attached {
                size(size(content_len, false)?, false)?
            } else {
                0
            },
        ])?;
        let encap_len = if let Some(layout) = old_layout {
            layout.encap.len
        } else {
            size(encap_body, false)?
        };
        let status_len = old_layout.and_then(|l| l.status).map_or(0, |r| r.len);
        let flags = old_layout.map_or([false; 3], |l| l.indefinite);
        let [body_len, signed_len, root_len, total_len] = cms_lengths(
            &[
                version.as_bytes().len() as u64,
                size(algorithms.as_bytes().len() as u64, false)?,
                encap_len,
                size(certificates.as_bytes().len() as u64, false)?,
                status_len,
                size(signer_infos.as_bytes().len() as u64, false)?,
            ],
            oid.len() as u64,
            flags,
        )?;
        // Only bytes actually embedded in the output are excluded from its
        // container overhead. Detached document intake is not output payload.
        let encapsulated_payload = if attached { content_len } else { 0 };
        scope.account_container(
            total_len
                .checked_sub(encapsulated_payload)
                .ok_or_else(|| malformed("invalid content/output length"))?,
        )?;
        output.header(0x30, root_len, flags[0], scope)?;
        output.write(&oid, scope)?;
        output.header(0xa0, signed_len, flags[1], scope)?;
        output.header(0x30, body_len, flags[2], scope)?;
        output.write(version.as_bytes(), scope)?;
        output.header(0x31, algorithms.as_bytes().len() as u64, false, scope)?;
        output.write(algorithms.as_bytes(), scope)?;
        if let (Some(layout), Some(stage)) = (old_layout, content.as_mut()) {
            copy_region(stage, layout.encap, output, scope)?;
        } else {
            output.header(0x30, encap_body, false, scope)?;
            output.write(&type_der, scope)?;
            if attached {
                output.header(0xa0, size(content_len, false)?, false, scope)?;
                output.header(4, content_len, false, scope)?;
                if let Some(stage) = content.as_mut() {
                    copy_region(
                        stage,
                        Region {
                            offset: 0,
                            len: content_len,
                        },
                        output,
                        scope,
                    )?;
                }
            }
        }
        output.header(0xa0, certificates.as_bytes().len() as u64, false, scope)?;
        output.write(certificates.as_bytes(), scope)?;
        if let (Some(region), Some(stage)) = (old_layout.and_then(|l| l.status), content.as_mut()) {
            copy_region(stage, region, output, scope)?;
        }
        output.header(0x31, signer_infos.as_bytes().len() as u64, false, scope)?;
        output.write(signer_infos.as_bytes(), scope)?;
        output.end(flags[2], scope)?;
        output.end(flags[1], scope)?;
        output.end(flags[0], scope)?;
        output.finish(scope)?;
        Ok(())
    })();
    // Keep normalized old metadata admitted until every borrowed verification fact is gone.
    drop(old_metadata);
    execution.map_err(|error| applied(error, applied_state))?;
    Ok(summary(
        scope,
        before,
        signers.len(),
        result_memory,
        result_metadata,
    ))
}

/// Internal, closed output-role replay: only PDF assembly can mint its source.
pub(crate) fn sign_pdf_contents(
    input: Source<'_>,
    signer: &mut dyn DigestSigner,
    services: &CmsSignServices<'_>,
    output: &mut dyn Write,
    capacity: usize,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    sign_impl(
        &CmsSignRequest::create(false),
        Some(input),
        None,
        &mut [signer],
        services,
        &mut Output::Internal(output, capacity as u64),
        scope,
        None,
    )
}
/// Raw document signing hashes the source once and applies the prehash backend.
pub fn sign_raw(
    input: Source<'_>,
    signer: &mut dyn DigestSigner,
    output: &mut dyn Write,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    raw_impl(input, None, signer, &mut Output::Writer(output), scope)
}
pub fn sign_raw_staged(
    input: Source<'_>,
    signer: &mut dyn DigestSigner,
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    output.check_sign_output(scope)?;
    let result = raw_impl(input, None, signer, &mut Output::Staged(output), scope);
    if result.is_err() {
        output.fail_sign_output();
    }
    result
}
/// Explicitly supplied digest. The source must be empty; authorization belongs
/// to the host's DigestSigner (Core requires SignDigest and allow_prehashed).
pub fn sign_raw_digest(
    input: Source<'_>,
    digest: &DigestValue,
    signer: &mut dyn DigestSigner,
    output: &mut dyn Write,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    raw_impl(
        input,
        Some(digest),
        signer,
        &mut Output::Writer(output),
        scope,
    )
}
pub fn sign_raw_digest_staged(
    input: Source<'_>,
    digest: &DigestValue,
    signer: &mut dyn DigestSigner,
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    output.check_sign_output(scope)?;
    let result = raw_impl(
        input,
        Some(digest),
        signer,
        &mut Output::Staged(output),
        scope,
    );
    if result.is_err() {
        output.fail_sign_output();
    }
    result
}
fn raw_impl(
    input: Source<'_>,
    provided: Option<&DigestValue>,
    signer: &mut dyn DigestSigner,
    output: &mut Output<'_>,
    scope: &ResourceScope,
) -> Result<SignSummary, StreamError> {
    let before = scope.progress();
    let (_working, _metadata) = admission(&[&mut *signer], scope)?;
    let memory = scope.reserve_memory(std::mem::size_of::<SignSummary>() as u64)?;
    let metadata = scope.reserve_metadata(std::mem::size_of::<SignSummary>() as u64)?;
    let alg = signer.algorithm();
    if provided.is_some_and(|d| d.algorithm() != alg.hash_alg()) {
        return Err(CmsError::Key(crate::key::KeyError::UnsupportedAlgorithm).into());
    }
    let mut hash = provided.is_none().then(|| HashState::new(alg.hash_alg()));
    let mut operation = scope.retain();
    Reader::new(input, &mut operation)?.raw_content(|bytes| {
        if provided.is_some() && !bytes.is_empty() {
            return Err(malformed(
                "provided digest mode requires empty document source",
            ));
        }
        if let Some(hash) = &mut hash {
            hash.update(bytes);
        }
        Ok(())
    })?;
    let computed = hash.map(HashState::finish);
    let digest = provided
        .or(computed.as_ref())
        .ok_or_else(|| malformed("missing raw digest"))?;
    let signature = signer.sign_digest(digest).map_err(CmsError::Key)?;
    let result = (|| {
        scope.checkpoint()?;
        output.write(&signature, scope)?;
        output.finish(scope)
    })();
    result.map_err(|error| applied(error, AppliedState::Applied))?;
    Ok(summary(scope, before, 1, memory, metadata))
}

fn sorted_set(
    input: Metadata,
    scope: &ResourceScope,
    preserve_ber: bool,
) -> Result<Metadata, StreamError> {
    let mut entries = match RawSet(input.as_bytes()).tlvs() {
        Ok(entries) => entries,
        Err(_) if preserve_ber => return Ok(input), // validated original BER TLVs remain byte-exact
        Err(error) => return Err(error.into()),
    };
    entries.sort_unstable();
    let mut result = Metadata::new(scope)?;
    for entry in entries {
        result.append(entry)?;
    }
    Ok(result)
}

fn same_issuer_serial(left: &crate::cert::Certificate, right: &crate::cert::Certificate) -> bool {
    let left = left.tbs_certificate();
    let right = right.tbs_certificate();
    left.issuer() == right.issuer()
        && left.serial_number().as_bytes() == right.serial_number().as_bytes()
}

fn matches_ski(certificate: &crate::cert::Certificate, id: &[u8]) -> bool {
    matches!(
        certificate.tbs_certificate().get_extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>(),
        Ok(Some((_, ski))) if ski.0.as_bytes() == id
    )
}

/// The legacy verifier resolves the first certificate named by a SID. Do not
/// change that association by admitting a conflicting certificate or sorting
/// an ambiguous union. Exact certificate reuse is harmless and stays allowed.
fn preflight_certificate_union(
    old: Option<&Metadata>,
    incoming: &[&mut dyn DigestSigner],
    encoded: &[Vec<u8>],
    scope: &ResourceScope,
) -> Result<(), StreamError> {
    let _decoded = old
        .map(|metadata| -> Result<_, ProcessingError> {
            let encoded_len = metadata.as_bytes().len() as u64;
            let memory = encoded_len
                .checked_mul(128)
                .ok_or(ProcessingError::MemoryLimit)?;
            let metadata = encoded_len
                .checked_mul(16)
                .ok_or(ProcessingError::MetadataLimit)?;
            Ok((
                scope.reserve_memory(memory)?,
                scope.reserve_metadata(metadata)?,
            ))
        })
        .transpose()?;
    let prepared = old.map(|metadata| PreparedCms::from_digests(metadata.as_bytes(), [None; 4]));
    let signed_data = prepared
        .as_ref()
        .map(PreparedCms::signed_data)
        .transpose()?;
    let existing = signed_data
        .as_ref()
        .map(crate::cms::verify::certificates)
        .transpose()?
        .unwrap_or_default();
    for (index, (certificate, der)) in existing.iter().enumerate() {
        scope.checkpoint()?;
        for (previous, previous_der) in &existing[..index] {
            scope.checkpoint()?;
            if der != previous_der && same_issuer_serial(certificate, previous) {
                return Err(malformed(
                    "conflicting CMS issuer-and-serial certificate identifiers",
                ));
            }
        }
    }
    for (index, signer) in incoming.iter().enumerate() {
        scope.checkpoint()?;
        for (certificate, der) in &existing {
            scope.checkpoint()?;
            if encoded[index].as_slice() != *der
                && same_issuer_serial(signer.certificate(), certificate)
            {
                return Err(malformed(
                    "conflicting CMS issuer-and-serial certificate identifiers",
                ));
            }
        }
        for (previous, earlier) in incoming[..index].iter().enumerate() {
            scope.checkpoint()?;
            if encoded[index] != encoded[previous]
                && same_issuer_serial(signer.certificate(), earlier.certificate())
            {
                return Err(malformed(
                    "conflicting CMS issuer-and-serial certificate identifiers",
                ));
            }
        }
    }
    if let Some(signed_data) = signed_data {
        for encoded_signer in signed_data.signer_infos.tlvs()? {
            scope.checkpoint()?;
            let signer = crate::cms::asn1::SignerInfo::from_der(encoded_signer)?;
            if signer.sid.tag()
                != (der::Tag::ContextSpecific {
                    constructed: false,
                    number: der::TagNumber(0),
                })
            {
                continue;
            }
            let id = signer.sid.value();
            let mut chosen = None;
            for (certificate, der) in &existing {
                scope.checkpoint()?;
                if matches_ski(certificate, id) {
                    if chosen.is_some_and(|previous| previous != *der) {
                        return Err(malformed(
                            "ambiguous existing CMS subject-key-identifier association",
                        ));
                    }
                    chosen = Some(*der);
                }
            }
            let chosen = chosen
                .ok_or_else(|| malformed("existing CMS SKI signer certificate is missing"))?;
            for (index, candidate) in incoming.iter().enumerate() {
                scope.checkpoint()?;
                if encoded[index].as_slice() != chosen && matches_ski(candidate.certificate(), id) {
                    return Err(malformed(
                        "conflicting CMS subject-key-identifier certificate association",
                    ));
                }
            }
        }
    }
    Ok(())
}
