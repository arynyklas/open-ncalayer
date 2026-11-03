//! Forward-only CMS SignedData processing with bounded metadata and u64 lengths.
//!
//! Source begins at its reader's current position. Inspection is structural and
//! extraction is unverified; arbitrary sinks may retain a partial prefix on any
//! error. Only verify performs signature, host trust and status validation.
//! Total input counts wire bytes plus detached bytes; container counts exclude
//! primitive eContent payload, and framing independently bounds TLV work.
#[path = "../ades.rs"]
pub mod ades;
mod reader;
mod sign;
mod verify;
pub use sign::{
    CmsSignRequest, CmsSignServices, SignSummary, sign, sign_raw, sign_raw_digest,
    sign_raw_digest_staged, sign_raw_staged, sign_staged,
};

use crate::cms::CmsError;
use crate::digest::{DigestValue, HashState};
use crate::io::{Region, Source};
use crate::key::SigAlg;
use crate::resource::{ProcessingError, ResourceScope};
use der::asn1::ObjectIdentifier;
use der::{Decode, Reader as _, SliceReader};
use reader::{Metadata, Reader, malformed};
use std::io::Write;

pub use verify::verify;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error(transparent)]
    Cms(#[from] CmsError),
    #[error("host temporary store is required for this source")]
    MissingTemporaryStore,
    #[error("{source} (key application: {applied:?})")]
    AfterKeyUse {
        source: Box<StreamError>,
        applied: crate::key::AppliedState,
    },
    #[error(transparent)]
    Processing(#[from] ProcessingError),
}
impl From<der::Error> for StreamError {
    fn from(error: der::Error) -> Self {
        Self::Cms(error.into())
    }
}

/// Structural facts only; no signature/trust assertion or retained content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub detached: bool,
    pub content_len: u64,
    pub signer_count: usize,
    /// Source-start-relative primitive value; None for constructed/detached.
    pub content_region: Option<Region>,
}
/// Unverified extraction. This intentionally has no validation verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtractedContent {
    pub bytes_written: u64,
}

pub fn inspect(input: Source<'_>, scope: &mut ResourceScope) -> Result<Inspection, StreamError> {
    Ok(parse(input, scope, false, None)?.inspection)
}
pub fn extract(
    input: Source<'_>,
    output: &mut dyn Write,
    scope: &mut ResourceScope,
) -> Result<ExtractedContent, StreamError> {
    let parsed = parse(input, scope, false, Some(output))?;
    if parsed.inspection.detached {
        return Err(CmsError::NoEncapsulatedData.into());
    }
    Ok(ExtractedContent {
        bytes_written: parsed.inspection.content_len,
    })
}

pub(super) const ALGORITHMS: [SigAlg; 4] = [
    SigAlg::Gost2004,
    SigAlg::Gost2015_512,
    SigAlg::RsaSha256,
    SigAlg::RsaSha1,
];
pub(super) struct Digests {
    pub declared: [bool; 4],
    states: [Option<HashState>; 4],
    _memory: crate::resource::ResourceReservation,
    _metadata: crate::resource::ResourceReservation,
}
impl Digests {
    fn new(
        algorithms: &[u8],
        hashing: bool,
        extra: &[SigAlg],
        scope: &ResourceScope,
    ) -> Result<Self, StreamError> {
        let memory = scope.reserve_memory(std::mem::size_of::<Self>() as u64)?;
        let metadata = scope.reserve_metadata(std::mem::size_of::<Self>() as u64)?;
        let any = der::asn1::AnyRef::from_der(algorithms)?;
        let mut reader = SliceReader::new(any.value())?;
        let mut declared = [false; 4];
        while !reader.is_finished() {
            let algorithm = spki::AlgorithmIdentifierRef::from_der(reader.tlv_bytes()?)?;
            for (index, sig) in ALGORITHMS.iter().enumerate() {
                if algorithm.oid == sig.digest_oid() {
                    declared[index] = true;
                }
            }
        }
        let states = std::array::from_fn(|index| {
            (hashing && (declared[index] || extra.contains(&ALGORITHMS[index])))
                .then(|| HashState::new(ALGORITHMS[index].hash_alg()))
        });
        Ok(Self {
            declared,
            states,
            _memory: memory,
            _metadata: metadata,
        })
    }
    fn update(&mut self, bytes: &[u8]) {
        for state in self.states.iter_mut().flatten() {
            state.update(bytes);
        }
    }
    pub fn finish(&mut self, present: bool) -> [Option<DigestValue>; 4] {
        std::array::from_fn(|index| {
            let state = self.states[index].take();
            if present {
                state.map(HashState::finish)
            } else {
                None
            }
        })
    }
}
pub(super) struct Parsed {
    pub metadata: Metadata,
    pub digests: Digests,
    pub inspection: Inspection,
    pub layout: Layout,
}

#[derive(Clone, Copy)]
pub(super) struct Layout {
    pub indefinite: [bool; 3],
    pub version: Region,
    pub algorithms: Region,
    pub encap: Region,
    pub content_type: Region,
    pub certificates: Option<Region>,
    pub status: Option<Region>,
    pub signers: Region,
}
fn span(start: u64, end: u64) -> Region {
    Region {
        offset: start,
        len: end - start,
    }
}

fn read_content(
    reader: &mut Reader<'_, '_>,
    header: reader::Header,
    digests: &mut Digests,
    output: &mut Option<&mut dyn Write>,
    length: &mut u64,
) -> Result<(), StreamError> {
    match header.tag {
        4 => {
            let len = header
                .len
                .ok_or_else(|| malformed("indefinite content primitive"))?;
            *length = length
                .checked_add(len)
                .ok_or_else(|| malformed("content length overflows u64"))?;
            reader.payload(len, true, |bytes, scope| {
                digests.update(bytes);
                if let Some(sink) = output.as_deref_mut() {
                    scope.account_output(bytes.len() as u64)?;
                    let mut remaining = bytes;
                    while !remaining.is_empty() {
                        scope.checkpoint()?;
                        let count = match sink.write(remaining) {
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            result => result.map_err(ProcessingError::from)?,
                        };
                        if count == 0 || count > remaining.len() {
                            return Err(ProcessingError::Io(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "CMS content sink made no progress",
                            ))
                            .into());
                        }
                        remaining = &remaining[count..];
                        scope.checkpoint()?;
                    }
                }
                Ok(())
            })?;
        }
        0x24 => {
            reader.enter(header)?;
            while let Some(child) = reader.next()? {
                read_content(reader, child, digests, output, length)?;
            }
            reader.leave()?;
        }
        _ => return Err(malformed("constructed eContent contains non-OCTET value")),
    }
    Ok(())
}

pub(super) fn parse(
    input: Source<'_>,
    scope: &mut ResourceScope,
    hashing: bool,
    output: Option<&mut dyn Write>,
) -> Result<Parsed, StreamError> {
    parse_with(input, scope, hashing, output, &[], false)
}
pub(super) fn parse_with(
    input: Source<'_>,
    scope: &mut ResourceScope,
    hashing: bool,
    mut output: Option<&mut dyn Write>,
    extra: &[SigAlg],
    replay: bool,
) -> Result<Parsed, StreamError> {
    let mut reader = if replay {
        Reader::new_replay(input, scope)?
    } else {
        Reader::new(input, scope)?
    };
    let root = reader.required(0x30)?;
    reader.enter(root)?;
    let oid_header = reader.required(6)?;
    let signed_oid = reader.metadata(oid_header)?;
    if ObjectIdentifier::from_der(signed_oid.as_bytes())? != crate::oid::SIGNED_DATA {
        return Err(malformed("CMS content is not SignedData"));
    }
    let explicit = reader.required(0xa0)?;
    reader.enter(explicit)?;
    let signed = reader.required(0x30)?;
    reader.enter(signed)?;
    let indefinite = [
        root.len.is_none(),
        explicit.len.is_none(),
        signed.len.is_none(),
    ];
    let mut body = Metadata::new(reader.scope)?;
    let version_header = reader.required(2)?;
    let version_start = version_header.start();
    let version = reader.metadata(version_header)?;
    let _version = u8::from_der(version.as_bytes())?;
    let version_region = span(version_start, reader.offset);
    body.append(version.as_bytes())?;
    drop(version);
    let algorithms_header = reader.required(0x31)?;
    let algorithms = reader.metadata(algorithms_header)?;
    let algorithms_region = span(
        algorithms_header.value_offset,
        reader.offset - u64::from(algorithms_header.len.is_none()) * 2,
    );
    let mut digests = Digests::new(algorithms.as_bytes(), hashing, extra, reader.scope)?;
    body.append(algorithms.as_bytes())?;
    drop(algorithms);
    let encap_start = reader.offset;
    let encap = reader.required(0x30)?;
    reader.enter(encap)?;
    let content_type_header = reader.required(6)?;
    let content_type = reader.metadata(content_type_header)?;
    let content_type_region = span(content_type_header.start(), reader.offset);
    let _content_type: ObjectIdentifier = ObjectIdentifier::from_der(content_type.as_bytes())?;
    // A bounded metadata-only EncapsulatedContentInfo, with no eContent bytes.
    body.append_tlv(0x30, content_type.as_bytes())?;
    drop(content_type);
    let mut inspection = Inspection {
        detached: true,
        content_len: 0,
        signer_count: 0,
        content_region: None,
    };
    if let Some(explicit) = reader.next()? {
        if explicit.tag != 0xa0 {
            return Err(malformed("unexpected encapsulated content field"));
        }
        inspection.detached = false;
        reader.enter(explicit)?;
        let content = reader
            .next()?
            .ok_or_else(|| malformed("missing eContent OCTET STRING"))?;
        if content.tag == 4 {
            inspection.content_region = Some(Region {
                offset: content.value_offset,
                len: content
                    .len
                    .ok_or_else(|| malformed("indefinite primitive eContent"))?,
            });
        }
        read_content(
            &mut reader,
            content,
            &mut digests,
            &mut output,
            &mut inspection.content_len,
        )?;
        reader.leave()?;
    }
    reader.leave()?;
    let encap_region = span(encap_start, reader.offset);
    let mut certificates_region = None;
    let mut status_region = None;
    let mut field = reader
        .next()?
        .ok_or_else(|| malformed("missing signerInfos"))?;
    if field.tag == 0xa0 {
        let certificates = reader.metadata(field)?;
        certificates_region = Some(span(
            field.value_offset,
            reader.offset - u64::from(field.len.is_none()) * 2,
        ));
        body.append(certificates.as_bytes())?;
        field = reader
            .next()?
            .ok_or_else(|| malformed("missing signerInfos after certificates"))?;
    }
    if field.tag == 0xa1 {
        let status = reader.metadata(field)?;
        status_region = Some(span(field.start(), reader.offset));
        body.append(status.as_bytes())?;
        field = reader
            .next()?
            .ok_or_else(|| malformed("missing signerInfos after revocation info"))?;
    }
    if field.tag != 0x31 {
        return Err(malformed("missing signerInfos SET"));
    }
    let signers = reader.metadata(field)?;
    let signers_region = span(
        field.value_offset,
        reader.offset - u64::from(field.len.is_none()) * 2,
    );
    let any = der::asn1::AnyRef::from_der(signers.as_bytes())?;
    let mut signer_reader = SliceReader::new(any.value())?;
    while !signer_reader.is_finished() {
        let _ = crate::cms::asn1::SignerInfo::from_der(signer_reader.tlv_bytes()?)?;
        inspection.signer_count = inspection
            .signer_count
            .checked_add(1)
            .ok_or_else(|| malformed("signer count overflows usize"))?;
    }
    if inspection.signer_count == 0 {
        return Err(malformed("no signers"));
    }
    body.append(signers.as_bytes())?;
    drop(signers);
    reader.leave()?;
    reader.leave()?;
    reader.leave()?;
    reader.finish()?;
    let mut signed_data = Metadata::new(reader.scope)?;
    signed_data.append_tlv(0x30, body.as_bytes())?;
    drop(body);
    let mut explicit = Metadata::new(reader.scope)?;
    explicit.append_tlv(0xa0, signed_data.as_bytes())?;
    drop(signed_data);
    let mut ci = Metadata::new(reader.scope)?;
    ci.append(signed_oid.as_bytes())?;
    ci.append(explicit.as_bytes())?;
    drop(signed_oid);
    drop(explicit);
    let mut metadata = Metadata::new(reader.scope)?;
    metadata.append_tlv(0x30, ci.as_bytes())?;
    Ok(Parsed {
        metadata,
        digests,
        inspection,
        layout: Layout {
            indefinite,
            version: version_region,
            algorithms: algorithms_region,
            encap: encap_region,
            content_type: content_type_region,
            certificates: certificates_region,
            status: status_region,
            signers: signers_region,
        },
    })
}
