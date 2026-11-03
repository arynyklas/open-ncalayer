//! Proof-only augmentation. No key/provider/guard parameter or private use exists.
use super::*;
use crate::xades::source::{self, XadesReport, XadesServices};
use oncl_pki::{
    io::{StagedArtifact, XmlSignatureOutput},
    key::HashAlg,
    validation::{CheckStatus, ValidationPolicy, Verdict},
};
fn leaf_bytes(document: &mut XmlDocument, bound: &BoundMetadata, max: usize) -> Result<Vec<u8>> {
    let xml = metadata(document, bound.0, &bound.1, max)?;
    let parsed =
        roxmltree::Document::parse(&xml).map_err(|_| invalid("signature public metadata"))?;
    base64(
        parsed
            .root_element()
            .first_element_child()
            .ok_or_else(|| invalid("signature public metadata"))?,
    )
}
fn unique_id(document: &mut XmlDocument, signature: Region, suffix: &str) -> Result<String> {
    for n in 0..64 {
        let id = format!("oncl-{}-{suffix}-{n}", signature.offset);
        if document.lookup_id(&id)?.is_none() {
            return Ok(id);
        }
    }
    Err(invalid("augmentation ID collisions"))
}
fn evidence_limits(profile: &XmlVerifyProfile) -> Result<EvidenceLimits> {
    source::effective_limits(
        profile.max_metadata_bytes,
        profile.max_work,
        profile.evidence_limits,
    )
}
fn novel(
    bundle: &mut EvidenceBundle,
    rows: &[EvidenceRow],
    items: Vec<(EvidenceKind, Vec<u8>)>,
    max: usize,
) -> Result<Vec<(EvidenceKind, Vec<u8>)>> {
    let mut out = Vec::new();
    for item in items {
        if out.contains(&item) {
            continue;
        }
        let mut duplicate = false;
        for row in rows.iter().filter(|r| r.kind == item.0) {
            if bundle
                .entry(row.id)
                .is_some_and(|e| e.region().len == item.1.len() as u64)
                && source::read_token(bundle, row.id, max)? == item.1
            {
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
fn copy_original(
    document: &mut XmlDocument,
    mut region: Region,
    output: &mut XmlSignatureOutput<'_>,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<()> {
    *work = work
        .checked_sub(region.len)
        .ok_or(ProcessingError::InvalidInput("XML extension replay work"))?;
    let _memory = scope.reserve_memory(oncl_pki::resource::IO_CHUNK_BYTES as u64)?;
    let mut buffer = vec![0; oncl_pki::resource::IO_CHUNK_BYTES];
    while region.len != 0 {
        scope.checkpoint()?;
        let n = document.read_region(region, &mut buffer)?;
        if n == 0 {
            return Err(invalid("original XML extent"));
        }
        output.append(&buffer[..n])?;
        region.offset += n as u64;
        region.len -= n as u64;
    }
    Ok(())
}
pub(crate) fn extend_staged(
    input: Source<'_>,
    level: AdesLevel,
    profile: &XmlVerifyProfile,
    services: &XadesServices<'_>,
    stage: &mut StagedArtifact,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    let mut output = XmlSignatureOutput::new(stage, scope)?;
    let report = extend_transaction(input, level, profile, services, &mut output, scope)?;
    output.finish(scope)?;
    Ok(report)
}
pub(crate) fn extend_transaction(
    input: Source<'_>,
    level: AdesLevel,
    profile: &XmlVerifyProfile,
    services: &XadesServices<'_>,
    output: &mut XmlSignatureOutput<'_>,
    scope: &mut ResourceScope,
) -> Result<XadesReport> {
    let mut profile = profile.clone();
    let caller = evidence_limits(&profile)?;
    profile.evidence_limits = Some(
        services
            .evidence_limits
            .map_or(caller, |host| source::intersect_limits(caller, host)),
    );
    let profile = &profile;
    if level > AdesLevel::B
        && let Some(tsa) = services.tsa
    {
        validate_timestamp_configuration(tsa, services.validation.policy)?;
    }
    let mut frozen = crate::capture_signed_input(input, profile, services.temporary, scope)?;
    let extent = frozen.len();
    let mut initial_profile = profile.clone();
    initial_profile.required_level = None;
    let levels;
    let refresh;
    {
        let mut reader = frozen.reader(scope)?;
        let initial = services.verify(reader.source(), &initial_profile, scope)?;
        reader.finish()?;
        refresh = initial
            .validation
            .signers
            .iter()
            .map(|signer| {
                signer.timestamp == CheckStatus::Unavailable
                    || signer.revocation == CheckStatus::Unavailable
            })
            .collect::<Vec<_>>();
        let refreshable = level >= AdesLevel::Lt
            && initial.validation.signers.iter().all(|signer| {
                signer.signature == CheckStatus::Passed
                    && signer.chain != CheckStatus::Failed
                    && signer.key_usage != CheckStatus::Failed
                    && signer.timestamp != CheckStatus::Failed
                    && (signer.revocation != CheckStatus::Failed
                        || signer.timestamp == CheckStatus::Unavailable)
                    && (signer.validity != CheckStatus::Failed
                        || signer.timestamp == CheckStatus::Unavailable)
            });
        if initial.validation.verdict != Verdict::Valid && !refreshable {
            return Err(invalid(
                "cannot extend a failed signature, binding, trust path or present proof",
            ));
        }
        levels = initial
            .signatures()
            .iter()
            .map(|s| {
                s.level
                    .ok_or_else(|| invalid("extension requires signed XAdES baseline properties"))
            })
            .collect::<Result<Vec<_>>>()?;
    }
    let algorithm;
    {
        let count = levels.len() as u64;
        let _memory = scope.reserve_memory(count * profile.max_metadata_bytes as u64 * 23)?;
        let _metadata = scope.reserve_metadata(
            count
                * (profile.max_metadata_bytes as u64
                    + profile.xml.max_namespace_bytes as u64 * 4
                    + 8192),
        )?;
        let mut reader = frozen.reader(scope)?;
        let mut document =
            XmlDocument::index_signed(reader.source(), profile, services.temporary, scope)?;
        reader.finish()?;
        let signatures = scan(&mut document, profile, scope)?;
        if signatures.len() != levels.len() {
            return Err(invalid("immutable signer count changed"));
        }
        let mut insertions = Vec::new();
        let mut work = profile.max_work;
        let mut first_algorithm = None;
        for (index, signature) in signatures.iter().enumerate() {
            let info_xml = metadata(
                &mut document,
                signature.info,
                &signature.info_namespaces,
                profile.max_metadata_bytes,
            )?;
            let info_doc =
                roxmltree::Document::parse(&info_xml).map_err(|_| invalid("SignedInfo"))?;
            let info = info_doc
                .root_element()
                .first_element_child()
                .ok_or_else(|| invalid("SignedInfo"))?;
            let algorithm =
                crate::signature_method(plain_algorithm(child(info, "SignatureMethod")?)?)
                    .ok_or(XmlSourceError::Unsupported("signature algorithm"))?;
            first_algorithm.get_or_insert(algorithm);
            if levels[index] >= level && level != AdesLevel::Lta && !refresh[index] {
                continue;
            }
            if level > AdesLevel::B && services.tsa.is_none() {
                return Err(invalid("XAdES extension TSA configuration absent"));
            }
            let certificate = cert::parse(&leaf_bytes(
                &mut document,
                &signature.certificate,
                profile.max_metadata_bytes,
            )?)
            .map_err(|_| invalid("signer certificate"))?;
            let value = leaf_bytes(&mut document, &signature.value, profile.max_metadata_bytes)?;
            let method_node = child(info, "CanonicalizationMethod")?;
            let method = C14n::from_uri(super::super::algorithm(method_node)?)
                .ok_or(XmlSourceError::Unsupported("SignedInfo canonicalization"))?;
            let inclusive = prefixes(method_node)?;
            let digest = document.canonical_digest(
                Options {
                    target: Some(signature.info),
                    method,
                    profile: profile.canonicalization,
                    prefixes: &inclusive,
                    excluded: &[],
                    metadata_limit: Some(profile.max_metadata_bytes as u64),
                },
                algorithm.hash_alg(),
                scope,
                &mut work,
            )?;
            let signer = SignerEvidence {
                certificate: &certificate,
                algorithm,
                signed_digest: digest,
                signature: &value,
                claimed_time: None,
            };
            let (artifact, projections) = document.canonical_proof(
                Options {
                    target: Some(signature.value.0),
                    method: C14n::Exclusive,
                    profile: profile.canonicalization,
                    prefixes: &[],
                    excluded: &[],
                    metadata_limit: Some(profile.max_metadata_bytes as u64),
                },
                services.temporary,
                scope,
                &mut work,
            )?;
            let canonical_region = Region {
                offset: 0,
                len: artifact.len(),
            };
            let bound = BoundSignatureRepresentation::from_base64_projection(
                artifact,
                canonical_region,
                &projections,
                &signer,
                &evidence_limits(profile)?,
                scope,
            )?;
            let (mut bundle, rows, carried) = collect_carried(
                &mut document,
                signature,
                profile,
                services.temporary,
                scope,
                evidence_limits(profile)?,
            )?;
            let parent = signature
                .unsigned_container
                .or(signature.qualifying)
                .ok_or_else(|| invalid("qualifying properties placement"))?;
            let point =
                crate::sign::placement(&mut document, parent, profile.max_metadata_bytes, scope)?;
            let mut additions = String::new();
            let mut new_entries = Vec::new();
            let mut issued_token = None;
            let mut stamp_id = None;
            let mut signature_tsa = None;
            if levels[index] < AdesLevel::T {
                let tsa = services
                    .tsa
                    .ok_or_else(|| invalid("signature timestamp TSA absent"))?;
                let mut evidence = EvidenceStore::resume(bundle);
                let id = services.request_timestamp(
                    &mut evidence,
                    &signer,
                    &[CoveragePart::BoundSignature(&bound)],
                    tsa,
                )?;
                bundle = evidence.finish();
                let token = source::read_token(&mut bundle, id, profile.max_metadata_bytes)?;
                let id_text = unique_id(&mut document, signature.signature, "T")?;
                additions.push_str(&source::stamp(&id_text, false, &token));
                stamp_id = Some(id_text);
                new_entries.push((id, EvidenceKind::Timestamp));
                issued_token = Some((token, tsa.hash, C14n::Exclusive, Vec::new()));
            }
            if level >= AdesLevel::Lt {
                let (token, hash_algorithm, method, prefixes) = if let Some(issued) = issued_token {
                    issued
                } else {
                    let (_, _, meta, method, prefixes) = carried
                        .iter()
                        .find(|(_, kind, _, _, _)| *kind == ProofKind::Signature)
                        .ok_or_else(|| invalid("signature timestamp missing"))?;
                    let (token, _, _) = proof_metadata(&mut document, meta, profile)?;
                    let tst = oncl_pki::tsp::verify_token(&token).map_err(EvidenceError::from)?;
                    let hash = HashAlg::from_oid(&tst.imprint_alg)
                        .ok_or(XmlSourceError::Unsupported("timestamp hash"))?;
                    let xml = metadata(
                        &mut document,
                        meta.bound.0,
                        &meta.bound.1,
                        profile.max_metadata_bytes,
                    )?;
                    let parsed = roxmltree::Document::parse(&xml)
                        .map_err(|_| invalid("timestamp identity"))?;
                    stamp_id = parsed
                        .root_element()
                        .first_element_child()
                        .and_then(|n| n.attribute("Id"))
                        .map(str::to_owned);
                    (token, hash, *method, prefixes.clone())
                };
                let imprint = document.canonical_digest(
                    Options {
                        target: Some(signature.value.0),
                        method,
                        profile: profile.canonicalization,
                        prefixes: &prefixes,
                        excluded: &[],
                        metadata_limit: Some(profile.max_metadata_bytes as u64),
                    },
                    hash_algorithm,
                    scope,
                    &mut work,
                )?;
                let (_, tsa_leaf) = oncl_pki::tsp::verify_token_imprint(&token, &imprint)
                    .map_err(EvidenceError::from)?;
                let needs_material = levels[index] < AdesLevel::Lt
                    || refresh[index]
                    || !services.material.certificates.is_empty()
                    || !services.material.ocsp.is_empty()
                    || !services.material.crls.is_empty();
                if needs_material {
                    let signer_items = novel(
                        &mut bundle,
                        &rows,
                        source::acquire(&certificate, services, scope)?,
                        profile.max_metadata_bytes,
                    )?;
                    let mut tsa_items = source::acquire(&tsa_leaf, services, scope)?;
                    for cert in services.material.certificates {
                        tsa_items.push((EvidenceKind::Certificate, crate::cert_der(cert)?));
                    }
                    tsa_items.extend(
                        services
                            .material
                            .crls
                            .iter()
                            .map(|b| (EvidenceKind::Crl, b.to_vec())),
                    );
                    tsa_items.extend(
                        services
                            .material
                            .ocsp
                            .iter()
                            .map(|b| (EvidenceKind::Ocsp, b.to_vec())),
                    );
                    tsa_items.retain(|item| !signer_items.contains(item));
                    let tsa_items =
                        novel(&mut bundle, &rows, tsa_items, profile.max_metadata_bytes)?;
                    let sign_profile = crate::XmlSignProfile {
                        xml: profile.xml.clone(),
                        max_metadata_bytes: profile.max_metadata_bytes,
                        max_work: profile.max_work,
                        canonicalization: profile.canonicalization,
                        ..Default::default()
                    };
                    let mut evidence = EvidenceStore::resume(bundle);
                    let tsa_xml = source::material_xml(
                        &tsa_items,
                        &mut evidence,
                        &mut new_entries,
                        &sign_profile,
                    )?;
                    if !tsa_xml.is_empty() {
                        let id = stamp_id.as_deref().ok_or(XmlSourceError::Unsupported(
                            "validation-data extension requires timestamp Id",
                        ))?;
                        additions.push_str(&format!("<xades141:TimeStampValidationData xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" URI=\"#{}\">{tsa_xml}</xades141:TimeStampValidationData>",crate::escape_attribute(id)));
                    }
                    additions.push_str(&source::material_xml(
                        &signer_items,
                        &mut evidence,
                        &mut new_entries,
                        &sign_profile,
                    )?);
                    bundle = evidence.finish();
                }
                signature_tsa = Some(tsa_leaf);
            }
            if level == AdesLevel::Lta {
                let mut references = services.temporary.stage_source(scope)?;
                let mut failures = Vec::new();
                let mut results = Vec::new();
                let mut count = 0;
                ReferenceVerifier {
                    document: &mut document,
                    profile,
                    signatures: &signatures,
                    signer_index: index,
                    scope,
                    work: &mut work,
                    count: &mut count,
                    failures: &mut failures,
                    archive_references: Some(&mut references),
                    results: &mut results,
                }
                .verify_all(info, 0, &mut Vec::new())?;
                if !failures.is_empty() {
                    return Err(invalid("reference changed before extension"));
                }
                let tsa = services.tsa.ok_or_else(|| invalid("archive TSA absent"))?;
                let mut prior_values = Vec::with_capacity(carried.len());
                for (_, _, _, method, prefixes) in &carried {
                    let (stage, spans) = document.canonical_proof(
                        Options {
                            target: Some(signature.value.0),
                            method: *method,
                            profile: profile.canonicalization,
                            prefixes,
                            excluded: &[],
                            metadata_limit: Some(profile.max_metadata_bytes as u64),
                        },
                        services.temporary,
                        scope,
                        &mut work,
                    )?;
                    let region = Region {
                        offset: 0,
                        len: stage.len(),
                    };
                    prior_values.push(BoundSignatureRepresentation::from_base64_projection(
                        stage,
                        region,
                        &spans,
                        &signer,
                        &evidence_limits(profile)?,
                        scope,
                    )?);
                }
                let mut prior_archives = Vec::with_capacity(carried.len());
                for (i, (token, kind, meta, method, prefixes)) in carried.iter().enumerate() {
                    prior_archives.push(if *kind == ProofKind::Archive {
                        Some(
                            archive_representation(
                                &mut document,
                                signature,
                                &mut references,
                                &rows,
                                meta.bound.0,
                                *method,
                                prefixes,
                                &prior_values[i],
                                &signer,
                                &mut bundle,
                                Some(*token),
                                profile,
                                services.temporary,
                                scope,
                                &mut work,
                                None,
                                None,
                            )?
                            .0,
                        )
                    } else {
                        None
                    });
                }
                let mut prior_coverages = carried
                    .iter()
                    .enumerate()
                    .map(|(i, (_, kind, _, _, _))| {
                        if *kind == ProofKind::Archive {
                            [CoveragePart::BoundArchive(
                                prior_archives[i]
                                    .as_ref()
                                    .expect("reconstructed prior archive"),
                            )]
                        } else {
                            [CoveragePart::BoundSignature(&prior_values[i])]
                        }
                    })
                    .collect::<Vec<_>>();
                let added_time = new_entries
                    .iter()
                    .filter(|(_, kind)| *kind == EvidenceKind::Timestamp)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>();
                for _ in &added_time {
                    prior_coverages.push([CoveragePart::BoundSignature(&bound)]);
                }
                let mut old_proofs = carried
                    .iter()
                    .enumerate()
                    .map(|(i, (token, kind, _, _, _))| TimestampBinding {
                        token: *token,
                        kind: *kind,
                        coverage: &prior_coverages[i],
                    })
                    .collect::<Vec<_>>();
                for (i, token) in added_time.iter().enumerate() {
                    old_proofs.push(TimestampBinding {
                        token: *token,
                        kind: ProofKind::Signature,
                        coverage: &prior_coverages[carried.len() + i],
                    });
                }
                let (archive, imprint) = archive_representation(
                    &mut document,
                    signature,
                    &mut references,
                    &rows,
                    Region {
                        offset: u64::MAX,
                        len: 0,
                    },
                    C14n::Exclusive,
                    &[],
                    &bound,
                    &signer,
                    &mut bundle,
                    None,
                    profile,
                    services.temporary,
                    scope,
                    &mut work,
                    if additions.is_empty() {
                        None
                    } else {
                        Some((&additions, &point.context, &new_entries))
                    },
                    Some(tsa.hash),
                )?;
                let mut evidence = EvidenceStore::resume(bundle);
                let id = evidence.request_archive_timestamp_for_extension(
                    &signer,
                    &old_proofs,
                    &archive,
                    tsa,
                    services.validation,
                    services.network,
                    services.host_clock,
                )?;
                bundle = evidence.finish();
                let token = source::read_token(&mut bundle, id, profile.max_metadata_bytes)?;
                let id_text = unique_id(&mut document, signature.signature, "A")?;
                additions.push_str(&source::stamp(&id_text, true, &token));
                let prior = rows
                    .iter()
                    .map(|r| (r.id, r.kind))
                    .chain(new_entries.iter().copied())
                    .collect::<Vec<_>>();
                let sign_profile = crate::XmlSignProfile {
                    xml: profile.xml.clone(),
                    max_metadata_bytes: profile.max_metadata_bytes,
                    max_work: profile.max_work,
                    canonicalization: profile.canonicalization,
                    ..Default::default()
                };
                let (_bundle, tail) = source::current_tsa_validation(
                    bundle,
                    &token,
                    &imprint.ok_or_else(|| invalid("archive imprint absent"))?,
                    &id_text,
                    &prior,
                    &sign_profile,
                    services,
                    scope,
                    &mut work,
                    signature_tsa.as_ref(),
                )?;
                additions.push_str(&tail);
            }
            if additions.len() > profile.max_metadata_bytes {
                return Err(ProcessingError::MetadataLimit.into());
            }
            if signature.unsigned_container.is_none() {
                additions = format!(
                    "<xades:UnsignedProperties xmlns:xades=\"{}\"><xades:UnsignedSignatureProperties>{additions}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>",
                    crate::XADES_NS
                );
            }
            insertions.push((point, additions));
        }
        algorithm = first_algorithm.ok_or_else(|| invalid("no source signer"))?;
        insertions.sort_by_key(|(point, _)| point.at);
        let mut offset = 0;
        for (point, additions) in insertions {
            if point.at < offset {
                return Err(invalid("overlapping XML extension slots"));
            }
            copy_original(
                &mut document,
                Region {
                    offset,
                    len: point.at - offset,
                },
                output,
                scope,
                &mut work,
            )?;
            output.append(point.open.as_bytes())?;
            output.append(additions.as_bytes())?;
            output.append(point.close.as_bytes())?;
            offset = point.at + point.skip;
        }
        copy_original(
            &mut document,
            Region {
                offset,
                len: extent - offset,
            },
            output,
            scope,
            &mut work,
        )?;
    }
    let mut final_profile = profile.clone();
    final_profile.required_level = Some(level);
    let verification = services.verify(output.source()?, &final_profile, scope)?;
    if verification.validation.verdict == Verdict::Invalid
        || (services.validation.policy == ValidationPolicy::StrictOnline
            && verification.validation.verdict != Verdict::Valid)
    {
        return Err(invalid("final extended XAdES validation failed"));
    }
    let bytes_out = output.len();
    Ok(XadesReport {
        summary: crate::XmlSignSummary {
            bytes_in: extent,
            bytes_out,
            algorithm,
        },
        verification,
    })
}
