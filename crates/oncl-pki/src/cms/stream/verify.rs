use super::reader::{Reader, malformed};
use super::{ALGORITHMS, StreamError, parse};
use crate::cms::asn1::SignerInfo;
use crate::cms::report::PreparedCms;
use crate::cms::verify::{ContentDigests, Signer};
use crate::io::Source;
use crate::key::SigAlg;
use crate::resource::{ProcessingError, ResourceScope};
use crate::validation::{ValidationContext, ValidationError, ValidationReport};
use der::{Decode, Encode, Reader as _, SliceReader};

/// Verify all signers and apply the same F03 trust, status, TSA and time policy
/// as bounded validation. Unknown status is never a complete Valid verdict.
pub fn verify(
    input: Source<'_>,
    detached: Option<Source<'_>>,
    validation: &ValidationContext<'_>,
    allowed_signature_algorithms: &[SigAlg],
    scope: &mut ResourceScope,
) -> Result<ValidationReport, StreamError> {
    let mut parsed = parse(input, scope, true, None)?;
    Ok(verify_parsed(
        &mut parsed,
        detached,
        validation,
        allowed_signature_algorithms,
        scope,
    )?
    .0)
}

pub(super) fn verify_parsed(
    parsed: &mut super::Parsed,
    detached: Option<Source<'_>>,
    validation: &ValidationContext<'_>,
    allowed_signature_algorithms: &[SigAlg],
    scope: &mut ResourceScope,
) -> Result<(ValidationReport, [Option<crate::digest::DigestValue>; 4]), StreamError> {
    scope.checkpoint()?;
    // Charge decoded certificate/attribute trees, candidate clones, crypto
    // scratch and ephemeral Judge reports before the existing code allocates.
    // Content was excluded from this representation by the streaming reader.
    let mut encoded_bytes = parsed.metadata.as_bytes().len() as u64;
    for certificate in validation.intermediates {
        let length: u32 = certificate.encoded_len()?.into();
        encoded_bytes = encoded_bytes
            .checked_add(u64::from(length))
            .ok_or(ProcessingError::MemoryLimit)?;
    }
    let _working = scope.reserve_memory(
        encoded_bytes
            .checked_mul(128)
            .ok_or(ProcessingError::MemoryLimit)?,
    )?;
    let _metadata = scope.reserve_metadata(
        encoded_bytes
            .checked_mul(16)
            .ok_or(ProcessingError::MetadataLimit)?,
    )?;
    let empty = ContentDigests::new(None);
    let preliminary = PreparedCms::from_digests(parsed.metadata.as_bytes(), [None; 4]);
    let signed_data = preliminary.signed_data()?;
    let mut reader = SliceReader::new(signed_data.signer_infos.0)?;
    let mut index = 0usize;
    while !reader.is_finished() {
        scope.checkpoint()?;
        let signer = Signer {
            index,
            info: SignerInfo::from_der(reader.tlv_bytes()?)?,
            content_type: signed_data.encap_content_info.e_content_type,
            digests: &empty,
        };
        let algorithm = signer.algorithm()?;
        if !allowed_signature_algorithms.contains(&algorithm) {
            return Err(crate::cms::CmsError::UnknownAlgorithm(format!(
                "signature algorithm {algorithm:?} is not authorized"
            ))
            .into());
        }
        let slot = ALGORITHMS
            .iter()
            .position(|candidate| *candidate == algorithm)
            .ok_or_else(|| malformed("unknown signer digest slot"))?;
        if !parsed.digests.declared[slot] {
            return Err(malformed("signer digest is absent from digestAlgorithms"));
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| malformed("signer index overflows usize"))?;
    }
    let mut present = !parsed.inspection.detached;
    if parsed.inspection.detached
        && let Some(detached) = detached
    {
        let mut reader = Reader::new(detached, scope)?;
        reader.raw_content(|bytes| {
            parsed.digests.update(bytes);
            Ok(())
        })?;
        present = true;
    }
    let values = parsed.digests.finish(present);
    let prepared = PreparedCms::from_digests(parsed.metadata.as_bytes(), values);
    scope.checkpoint()?;
    let report = crate::validation::validate_prepared_cms(&prepared, validation, scope).map_err(
        |error| match error {
            ValidationError::Cms(error) => StreamError::Cms(error),
            ValidationError::Processing(error) => StreamError::Processing(error),
        },
    )?;
    scope.checkpoint()?;
    Ok((report, values))
}
