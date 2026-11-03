//! Noncyclic current-TSA data; a later archive covers this complete TSVD.
use super::*;
pub(crate) fn hash_stage(
    stage: &mut StagedArtifact,
    algorithm: HashAlg,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<DigestValue> {
    *work = work
        .checked_sub(stage.len())
        .ok_or(ProcessingError::InvalidInput("archive imprint replay work"))?;
    let _memory = scope.reserve_memory(IO_CHUNK_BYTES as u64)?;
    let mut bytes = vec![0; IO_CHUNK_BYTES];
    let mut at = 0;
    let mut state = HashState::new(algorithm);
    while at < stage.len() {
        scope.checkpoint()?;
        let n = stage.read_region(
            Region {
                offset: at,
                len: stage.len() - at,
            },
            &mut bytes,
        )?;
        if n == 0 {
            return Err(invalid("archive imprint extent"));
        }
        state.update(&bytes[..n]);
        at += n as u64;
    }
    scope.checkpoint()?;
    Ok(state.finish())
}
fn novel_material(
    bundle: &mut EvidenceBundle,
    entries: &[(EvidenceId, EvidenceKind)],
    items: Vec<(EvidenceKind, Vec<u8>)>,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<Vec<(EvidenceKind, Vec<u8>)>> {
    let _memory = scope.reserve_memory(8192)?;
    let mut buffer = [0; 8192];
    let mut out = Vec::new();
    for item in items {
        if out.contains(&item) {
            continue;
        }
        let mut duplicate = false;
        for (id, _) in entries.iter().filter(|(_, kind)| *kind == item.0) {
            if !bundle
                .entry(*id)
                .is_some_and(|e| e.region().len == item.1.len() as u64)
            {
                continue;
            }
            *work = work
                .checked_sub(item.1.len() as u64)
                .ok_or(ProcessingError::InvalidInput("evidence comparison work"))?;
            let mut at = 0;
            let mut matches = true;
            while at < item.1.len() {
                let end = (at + buffer.len()).min(item.1.len());
                let n = bundle.read_entry(*id, at as u64, &mut buffer[..end - at])?;
                if n == 0 {
                    return Err(invalid("evidence comparison extent"));
                }
                if buffer[..n] != item.1[at..at + n] {
                    matches = false;
                    break;
                }
                at += n;
            }
            if matches {
                duplicate = true;
                break;
            }
        }
        if !duplicate {
            out.push(item)
        }
    }
    Ok(out)
}
#[allow(
    clippy::too_many_arguments,
    reason = "Current TSA-only tail is bound to the actual token, prior evidence, owner and unchanged host policy"
)]
pub(crate) fn current_tsa_validation(
    mut bundle: EvidenceBundle,
    token: &[u8],
    imprint: &DigestValue,
    stamp_id: &str,
    prior: &[(EvidenceId, EvidenceKind)],
    profile: &XmlSignProfile<'_>,
    services: &XadesServices<'_>,
    scope: &mut ResourceScope,
    work: &mut u64,
    known_tsa: Option<&Certificate>,
) -> Result<(EvidenceBundle, String)> {
    let (_, leaf) =
        oncl_pki::tsp::verify_token_imprint(token, imprint).map_err(EvidenceError::from)?;
    // This identity comparison only avoids redundant acquisition. The shared
    // final validator still requires actual fresh embedded status for every proof.
    if known_tsa == Some(&leaf) {
        return Ok((bundle, String::new()));
    }
    let items = novel_material(
        &mut bundle,
        prior,
        acquire(&leaf, services, scope)?,
        scope,
        work,
    )?;
    let mut store = EvidenceStore::resume(bundle);
    let mut entries = Vec::new();
    let material = material_xml(&items, &mut store, &mut entries, profile)?;
    let xml = if material.is_empty() {
        String::new()
    } else {
        format!(
            "<xades141:TimeStampValidationData xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" URI=\"#{}\">{material}</xades141:TimeStampValidationData>",
            crate::escape_attribute(stamp_id)
        )
    };
    Ok((store.finish(), xml))
}
