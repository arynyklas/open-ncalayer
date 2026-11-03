//! ETSI EN 319 132-1 V1.2.1 §5.3 and §5.5.2.2 actual source coverage.
use super::*;
use oncl_pki::evidence::*;
#[path = "extension.rs"]
mod extension;
pub(crate) use extension::{extend_staged, extend_transaction};
struct EvidenceRow {
    source: Region,
    id: EvidenceId,
    kind: EvidenceKind,
}
fn proof_metadata(
    document: &mut XmlDocument,
    proof: &ExtraMetadata,
    profile: &XmlVerifyProfile,
) -> Result<(Vec<u8>, C14n, Vec<String>)> {
    let xml = metadata(
        document,
        proof.bound.0,
        &proof.bound.1,
        profile.max_metadata_bytes,
    )?;
    let parsed = roxmltree::Document::parse(&xml).map_err(|_| invalid("timestamp XML"))?;
    let timestamp = parsed
        .root_element()
        .first_element_child()
        .ok_or_else(|| invalid("timestamp"))?;
    let methods: Vec<_> = timestamp
        .children()
        .filter(|n| crate::is_ds(*n, "CanonicalizationMethod"))
        .collect();
    if methods.len() > 1 {
        return Err(invalid("timestamp canonicalization method"));
    }
    let (method, prefixes) = if let Some(method) = methods.first() {
        (
            C14n::from_uri(algorithm(*method)?).ok_or(XmlSourceError::Unsupported(
                "timestamp canonicalization URI",
            ))?,
            prefixes(*method)?,
        )
    } else {
        (C14n::Inclusive, Vec::new())
    };
    let values: Vec<_> = timestamp
        .children()
        .filter(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(crate::XADES_NS)
                && n.tag_name().name() == "EncapsulatedTimeStamp"
        })
        .collect();
    if values.len() != 1
        || timestamp
            .children()
            .filter(Node::is_element)
            .any(|n| !crate::is_ds(n, "CanonicalizationMethod") && n != values[0])
    {
        return Err(XmlSourceError::Unsupported(
            "timestamp include/transform or token cardinality",
        ));
    }
    Ok((base64(values[0])?, method, prefixes))
}
fn xchild<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Node<'a, 'i>> {
    let mut nodes = node.children().filter(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some(crate::XADES_NS)
            && n.tag_name().name() == name
    });
    let node = nodes
        .next()
        .ok_or_else(|| invalid("baseline signed property missing"))?;
    if nodes.next().is_some() {
        return Err(invalid("baseline signed property duplicate"));
    }
    Ok(node)
}
#[allow(
    clippy::too_many_arguments,
    reason = "Original document, signer, proof sources and host validation remain explicit"
)]
pub(super) fn check_carried_evidence(
    document: &mut XmlDocument,
    signature: &Metadata,
    info: Node<'_, '_>,
    mut signer: SignerEvidence<'_>,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    reference_stream: Option<&mut oncl_pki::io::StagedArtifact>,
    ctx: &ValidationContext<'_>,
    network: &NetworkPolicy,
    scope: &mut ResourceScope,
    work: &mut u64,
) -> Result<(ValidationReport, Option<AdesLevel>)> {
    validate_unsigned_layout(document, signature, profile)?;
    let mut level = signature.signed_properties.as_ref().map(|_| AdesLevel::B);
    if let Some(properties) = &signature.signed_properties {
        let xml = metadata(
            document,
            properties.bound.0,
            &properties.bound.1,
            profile.max_metadata_bytes,
        )?;
        let parsed =
            roxmltree::Document::parse(&xml).map_err(|_| invalid("SignedProperties XML"))?;
        let properties_node = parsed
            .root_element()
            .first_element_child()
            .ok_or_else(|| invalid("SignedProperties"))?;
        let id = properties_node
            .attribute("Id")
            .ok_or_else(|| invalid("SignedProperties ID"))?;
        let mut refs = info.children().filter(|n| {
            crate::is_ds(*n, "Reference")
                && n.attribute("Type") == Some(crate::SIGNED_PROPERTIES_TYPE)
        });
        let reference = refs
            .next()
            .ok_or_else(|| invalid("unsigned SignedProperties"))?;
        if refs.next().is_some() || decode_id(reference.attribute("URI").unwrap_or(""))? != id {
            return Err(invalid("SignedProperties reference binding"));
        }
        let signed = xchild(properties_node, "SignedSignatureProperties")?;
        signer.claimed_time = Some(
            time::OffsetDateTime::parse(
                xchild(signed, "SigningTime")?
                    .text()
                    .ok_or_else(|| invalid("SigningTime text"))?,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| invalid("SigningTime"))?,
        );
        let cert = xchild(xchild(signed, "SigningCertificateV2")?, "Cert")?;
        let digest = xchild(cert, "CertDigest")?;
        if plain_algorithm(child(digest, "DigestMethod")?)?
            != "http://www.w3.org/2001/04/xmlenc#sha256"
        {
            return Err(XmlSourceError::Unsupported("SigningCertificateV2 digest"));
        }
        if base64(child(digest, "DigestValue")?)?
            != oncl_pki::key::HashAlg::Sha256.digest(&crate::cert_der(signer.certificate)?)
        {
            return Err(invalid("SigningCertificateV2 leaf binding"));
        }
        if !baseline_data_formats(properties_node, info, scope)? {
            if profile.required_level.is_some() {
                return Err(invalid(
                    "required baseline DataObjectFormat/reference binding absent",
                ));
            }
            // Old bounded wire remains verifiable as XML+evidence, not falsely
            // reported as a complete EN319132-1 baseline signature.
            level = None;
        }
    } else if profile.required_level.is_some() {
        return Err(invalid("requested XAdES baseline properties absent"));
    }
    let limits = crate::xades::source::effective_limits(
        profile.max_metadata_bytes,
        profile.max_work,
        profile.evidence_limits,
    )?;
    let (mut bundle, rows, carried) =
        collect_carried(document, signature, profile, store, scope, limits)?;
    let mut bound_values = Vec::new();
    for (_, _, _, method, prefixes) in &carried {
        let (artifact, projections) = document.canonical_proof(
            Options {
                target: Some(signature.value.0),
                method: *method,
                profile: profile.canonicalization,
                prefixes,
                excluded: &[],
                metadata_limit: Some(profile.max_metadata_bytes as u64),
            },
            store,
            scope,
            work,
        )?;
        let region = Region {
            offset: 0,
            len: artifact.len(),
        };
        bound_values.push(BoundSignatureRepresentation::from_base64_projection(
            artifact,
            region,
            &projections,
            &signer,
            &limits,
            scope,
        )?);
    }
    let mut archives = Vec::new();
    let mut reference_stream = reference_stream;
    for (index, (id, kind, meta, method, prefixes)) in carried.iter().enumerate() {
        if *kind == ProofKind::Archive {
            let references = reference_stream
                .as_deref_mut()
                .ok_or_else(|| invalid("archive reference coverage"))?;
            archives.push(Some(
                archive_representation(
                    document,
                    signature,
                    references,
                    &rows,
                    meta.bound.0,
                    *method,
                    prefixes,
                    &bound_values[index],
                    &signer,
                    &mut bundle,
                    Some(*id),
                    profile,
                    store,
                    scope,
                    work,
                    None,
                    None,
                )?
                .0,
            ));
        } else {
            archives.push(None);
        }
    }
    let coverages: Vec<_> = carried
        .iter()
        .enumerate()
        .map(|(i, (_, kind, _, _, _))| {
            if *kind == ProofKind::Archive {
                [CoveragePart::BoundArchive(
                    archives[i].as_ref().expect("archive built"),
                )]
            } else {
                [CoveragePart::BoundSignature(&bound_values[i])]
            }
        })
        .collect();
    let proofs: Vec<_> = carried
        .iter()
        .zip(&coverages)
        .map(|((token, kind, _, _, _), coverage)| TimestampBinding {
            token: *token,
            kind: *kind,
            coverage,
        })
        .collect();
    let evidence_level = if proofs.iter().any(|proof| proof.kind == ProofKind::Archive) {
        AdesLevel::Lta
    } else if !proofs.is_empty()
        && signature
            .evidence
            .iter()
            .any(|(kind, _)| matches!(kind, EvidenceKind::Ocsp | EvidenceKind::Crl))
    {
        AdesLevel::Lt
    } else if !proofs.is_empty() {
        AdesLevel::T
    } else {
        AdesLevel::B
    };
    level = level.map(|_| evidence_level);
    let required = profile
        .required_level
        .unwrap_or(AdesLevel::B)
        .max(evidence_level);
    let report = validate_evidence(&signer, &mut bundle, &proofs, required, ctx, network, scope)?;
    Ok((report, level))
}
fn copy_stage(
    source: &mut oncl_pki::io::StagedArtifact,
    target: &mut oncl_pki::io::StagedArtifact,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<()> {
    *work = work
        .checked_sub(source.len())
        .ok_or(ProcessingError::InvalidInput("archive replay work"))?;
    let _memory = scope.reserve_memory(oncl_pki::resource::IO_CHUNK_BYTES as u64)?;
    let mut bytes = vec![0; oncl_pki::resource::IO_CHUNK_BYTES];
    let mut region = Region {
        offset: 0,
        len: source.len(),
    };
    while region.len != 0 {
        scope.checkpoint()?;
        let n = source.read_region(region, &mut bytes)?;
        if n == 0 {
            return Err(invalid("short canonical stage"));
        }
        target.write_chunk(&bytes[..n])?;
        region.offset += n as u64;
        region.len -= n as u64;
    }
    Ok(())
}
type AdditionalUnsigned<'a> = (&'a str, &'a str, &'a [(EvidenceId, EvidenceKind)]);
#[allow(
    clippy::too_many_arguments,
    reason = "Normative archive order is derived from original signer, cutoff, existing evidence and optional actual additions"
)]
fn archive_representation(
    document: &mut XmlDocument,
    signature: &Metadata,
    references: &mut oncl_pki::io::StagedArtifact,
    rows: &[EvidenceRow],
    cutoff: Region,
    method: C14n,
    prefixes: &[String],
    value: &BoundSignatureRepresentation,
    signer: &SignerEvidence<'_>,
    bundle: &mut EvidenceBundle,
    token: Option<EvidenceId>,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
    work: &mut u64,
    additional: Option<AdditionalUnsigned<'_>>,
    issuance_hash: Option<oncl_pki::key::HashAlg>,
) -> Result<(
    BoundArchiveRepresentation,
    Option<oncl_pki::digest::DigestValue>,
)> {
    let mut archive = store.stage_source(scope)?;
    copy_stage(references, &mut archive, scope, work)?;
    // EN 319 132-1 V1.2.1 §5.5.2.2 steps 3,4,5,6, in EXACT order.
    let mut value_region = Region { offset: 0, len: 0 };
    for component in [
        Some(signature.info),
        Some(signature.value.0),
        signature.key_info.as_ref().map(|m| m.bound.0),
    ]
    .into_iter()
    .flatten()
    {
        let at = archive.len();
        document.canonical_append(
            Options {
                target: Some(component),
                method,
                profile: profile.canonicalization,
                prefixes,
                excluded: &[],
                metadata_limit: None,
            },
            &mut archive,
            scope,
            work,
        )?;
        if component == signature.value.0 {
            value_region = Region {
                offset: at,
                len: archive.len() - at,
            };
        }
    }
    let mut groups = Vec::new();
    for property in signature
        .unsigned
        .iter()
        .filter(|p| p.bound.0.offset < cutoff.offset)
    {
        let (mut canonical, _) = document.canonical_proof(
            Options {
                target: Some(property.bound.0),
                method,
                profile: profile.canonicalization,
                prefixes,
                excluded: &[],
                metadata_limit: Some(profile.max_metadata_bytes as u64),
            },
            store,
            scope,
            work,
        )?;
        let at = archive.len();
        let mut bytes = vec![0; canonical.len() as usize];
        // read_region deliberately caps one read to the common I/O chunk.
        let mut offset = 0;
        while offset < bytes.len() {
            let n = canonical.read_region(
                Region {
                    offset: offset as u64,
                    len: bytes.len() as u64 - offset as u64,
                },
                &mut bytes[offset..],
            )?;
            if n == 0 {
                return Err(invalid("canonical property extent"));
            }
            offset += n;
        }
        let xml = std::str::from_utf8(&bytes).map_err(|_| invalid("canonical property UTF8"))?;
        let parsed =
            roxmltree::Document::parse(xml).map_err(|_| invalid("canonical property XML"))?;
        let ids: Vec<_> = rows
            .iter()
            .filter(|row| {
                row.source.offset >= property.bound.0.offset
                    && row
                        .source
                        .end()
                        .is_ok_and(|end| end <= property.bound.0.offset + property.bound.0.len)
            })
            .collect();
        let mut index = 0;
        for element in parsed.descendants().filter(Node::is_element) {
            let kind = match (element.tag_name().namespace(), element.tag_name().name()) {
                (Some(crate::XADES_NS), "EncapsulatedTimeStamp") => Some(EvidenceKind::Timestamp),
                (Some(crate::XADES_NS), "EncapsulatedX509Certificate") => {
                    Some(EvidenceKind::Certificate)
                }
                (Some(crate::XADES_NS), "EncapsulatedOCSPValue") => Some(EvidenceKind::Ocsp),
                (Some(crate::XADES_NS), "EncapsulatedCRLValue") => Some(EvidenceKind::Crl),
                _ => None,
            };
            if let Some(kind) = kind {
                let row = ids
                    .get(index)
                    .ok_or_else(|| invalid("archive evidence association"))?;
                if row.kind != kind {
                    return Err(invalid("archive evidence kind/order"));
                }
                let spans = element
                    .children()
                    .filter(Node::is_text)
                    .map(|n| Region {
                        offset: at + n.range().start as u64,
                        len: n.range().len() as u64,
                    })
                    .collect::<Vec<_>>();
                groups.push((row.id, spans));
                index += 1;
            }
        }
        if index != ids.len() {
            return Err(invalid("archive omitted prior evidence"));
        }
        copy_stage(&mut canonical, &mut archive, scope, work)?;
    }
    if let Some((properties, context, ids)) = additional {
        let xml = crate::sign::wrap(context, properties)?;
        if xml.len() > profile.max_metadata_bytes {
            return Err(ProcessingError::MetadataLimit.into());
        }
        let parsed = crate::parse::parse_signed(xml.as_bytes())?;
        let parent = parsed
            .descendants()
            .find(|n| {
                n.is_element()
                    && n.children().any(|c| {
                        c.is_element()
                            && c.tag_name().namespace().is_some_and(|ns| {
                                matches!(ns, crate::XADES_NS | "http://uri.etsi.org/01903/v1.4.1#")
                            })
                    })
            })
            .ok_or_else(|| invalid("extension property context"))?;
        let mut index = 0;
        for property in parent.children().filter(Node::is_element) {
            let mut bytes = Vec::new();
            let mut config = crate::canonicalizer(method);
            config.limit = profile.max_metadata_bytes;
            config.write_to_profile(property, &mut bytes, profile.canonicalization)?;
            let at = archive.len();
            let parsed = roxmltree::Document::parse(
                std::str::from_utf8(&bytes).map_err(|_| invalid("extension canonical UTF8"))?,
            )
            .map_err(|_| invalid("extension canonical XML"))?;
            for leaf in parsed.descendants().filter(|n| {
                n.is_element()
                    && n.tag_name().namespace() == Some(crate::XADES_NS)
                    && n.tag_name().name().starts_with("Encapsulated")
            }) {
                let (id, _) = ids
                    .get(index)
                    .ok_or_else(|| invalid("extension evidence association"))?;
                groups.push((
                    *id,
                    leaf.children()
                        .filter(Node::is_text)
                        .map(|n| Region {
                            offset: at + n.range().start as u64,
                            len: n.range().len() as u64,
                        })
                        .collect(),
                ));
                index += 1;
            }
            archive.write_chunk(&bytes)?;
        }
        if index != ids.len() {
            return Err(invalid("extension evidence omission"));
        }
    }
    for object in &signature.objects {
        document.canonical_append(
            Options {
                target: Some(*object),
                method,
                profile: profile.canonicalization,
                prefixes,
                excluded: &[],
                metadata_limit: None,
            },
            &mut archive,
            scope,
            work,
        )?;
    }
    let groups: Vec<_> = groups
        .iter()
        .map(|(id, spans)| (*id, spans.as_slice()))
        .collect();
    let imprint = issuance_hash
        .map(|algorithm| crate::xades::source::hash_stage(&mut archive, algorithm, scope, work))
        .transpose()?;
    Ok((
        BoundArchiveRepresentation::from_base64_projections(
            archive,
            value,
            value_region,
            &groups,
            signer,
            bundle,
            token,
            scope,
        )?,
        imprint,
    ))
}

type CarriedProof<'a> = (EvidenceId, ProofKind, &'a ExtraMetadata, C14n, Vec<String>);
fn collect_carried<'a>(
    document: &mut XmlDocument,
    signature: &'a Metadata,
    profile: &XmlVerifyProfile,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
    limits: EvidenceLimits,
) -> Result<(EvidenceBundle, Vec<EvidenceRow>, Vec<CarriedProof<'a>>)> {
    let mut evidence = EvidenceStore::new(store.clone(), limits, scope)?;
    let mut intake: Vec<_> = signature
        .evidence
        .iter()
        .map(|(kind, meta)| (meta.bound.0.offset, *kind, meta, None))
        .collect();
    intake.extend(signature.proofs.iter().map(|(kind, meta)| {
        (
            meta.bound.0.offset,
            EvidenceKind::Timestamp,
            meta,
            Some(*kind),
        )
    }));
    intake.sort_by_key(|row| row.0);
    let mut rows = Vec::new();
    let mut carried = Vec::new();
    for (_, kind, meta, proof_kind) in intake {
        let (bytes, canonical) = if let Some(proof_kind) = proof_kind {
            let (bytes, method, prefixes) = proof_metadata(document, meta, profile)?;
            (bytes, Some((proof_kind, method, prefixes)))
        } else {
            let xml = metadata(
                document,
                meta.bound.0,
                &meta.bound.1,
                profile.max_metadata_bytes,
            )?;
            let parsed =
                roxmltree::Document::parse(&xml).map_err(|_| invalid("embedded evidence XML"))?;
            (
                base64(
                    parsed
                        .root_element()
                        .first_element_child()
                        .ok_or_else(|| invalid("embedded evidence"))?,
                )?,
                None,
            )
        };
        let id = evidence.collect(
            kind,
            Source::sequential(&mut bytes.as_slice(), Some(bytes.len() as u64)),
            EvidenceOrigin::Embedded {
                label: "XML carried evidence",
            },
        )?;
        rows.push(EvidenceRow {
            source: meta.bound.0,
            id,
            kind,
        });
        if let Some((kind, method, prefixes)) = canonical {
            carried.push((id, kind, meta, method, prefixes));
        }
    }
    Ok((evidence.finish(), rows, carried))
}

fn validate_unsigned_layout(
    document: &mut XmlDocument,
    signature: &Metadata,
    profile: &XmlVerifyProfile,
) -> Result<()> {
    let mut proofs = Vec::new();
    for (kind, meta) in &signature.proofs {
        let xml = metadata(
            document,
            meta.bound.0,
            &meta.bound.1,
            profile.max_metadata_bytes,
        )?;
        let parsed =
            roxmltree::Document::parse(&xml).map_err(|_| invalid("timestamp identity XML"))?;
        let node = parsed
            .root_element()
            .first_element_child()
            .ok_or_else(|| invalid("timestamp identity"))?;
        proofs.push((*kind, meta.bound.0, node.attribute("Id").map(str::to_owned)));
    }
    let last_archive = proofs
        .iter()
        .rfind(|(kind, _, _)| *kind == ProofKind::Archive);
    let mut after_archive = 0;
    for property in &signature.unsigned {
        let xml = metadata(
            document,
            property.bound.0,
            &property.bound.1,
            profile.max_metadata_bytes,
        )?;
        let parsed =
            roxmltree::Document::parse(&xml).map_err(|_| invalid("unsigned property XML"))?;
        let node = parsed
            .root_element()
            .first_element_child()
            .ok_or_else(|| invalid("unsigned property"))?;
        let tsvd = node.tag_name().namespace() == Some("http://uri.etsi.org/01903/v1.4.1#")
            && node.tag_name().name() == "TimeStampValidationData";
        if tsvd {
            if node.children().filter(Node::is_element).any(|n| {
                n.tag_name().namespace() != Some(crate::XADES_NS)
                    || !matches!(
                        n.tag_name().name(),
                        "CertificateValues" | "RevocationValues"
                    )
            }) {
                return Err(invalid("timestamp validation-data children"));
            }
            if let Some(uri) = node.attribute("URI") {
                let id = decode_id(uri)?;
                if !proofs
                    .iter()
                    .any(|(_, _, candidate)| candidate.as_deref() == Some(&id))
                {
                    return Err(invalid("timestamp validation-data URI association"));
                }
            } else if !signature
                .unsigned
                .iter()
                .take_while(|p| p.bound.0 != property.bound.0)
                .last()
                .is_some_and(|p| proofs.iter().any(|(_, region, _)| *region == p.bound.0))
            {
                return Err(invalid("implicit timestamp validation-data association"));
            }
        }
        if let Some((_, archive, id)) = last_archive
            && property.bound.0.offset > archive.offset
        {
            after_archive += 1;
            if after_archive != 1 || !tsvd {
                return Err(invalid(
                    "unsupported unsigned property after current archive",
                ));
            }
            let expected = id
                .as_deref()
                .ok_or_else(|| invalid("current archive needs Id for trailing TSVD"))?;
            if node.attribute("URI").map(decode_id).transpose()?.as_deref() != Some(expected) {
                return Err(invalid("current archive TSVD URI mismatch"));
            }
        }
    }
    Ok(())
}

/// EN319132-1 V1.2.1 6.3k: one signed format descriptor for each current
/// SignedInfo data Reference, never for the SignedProperties Reference.
fn baseline_data_formats(
    properties: Node<'_, '_>,
    info: Node<'_, '_>,
    scope: &ResourceScope,
) -> Result<bool> {
    let mut containers = properties.children().filter(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some(crate::XADES_NS)
            && n.tag_name().name() == "SignedDataObjectProperties"
    });
    let Some(container) = containers.next() else {
        return Ok(false);
    };
    if containers.next().is_some() {
        return Err(invalid("duplicate SignedDataObjectProperties"));
    }
    let mut references = std::collections::HashMap::new();
    let mut missing_id = false;
    for reference in info.children().filter(|n| {
        crate::is_ds(*n, "Reference") && n.attribute("Type") != Some(crate::SIGNED_PROPERTIES_TYPE)
    }) {
        scope.checkpoint()?;
        match reference.attribute("Id").filter(|id| !id.is_empty()) {
            Some(id) => {
                if references.insert(id, false).is_some() {
                    return Err(invalid("duplicate data Reference Id"));
                }
            }
            None => missing_id = true,
        }
    }
    let mut count = 0;
    for format in container.children().filter(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some(crate::XADES_NS)
            && n.tag_name().name() == "DataObjectFormat"
    }) {
        scope.checkpoint()?;
        let id = decode_id(
            format
                .attribute("ObjectReference")
                .ok_or_else(|| invalid("DataObjectFormat ObjectReference missing"))?,
        )?;
        let seen = references
            .get_mut(id.as_str())
            .ok_or_else(|| invalid("DataObjectFormat points outside current data References"))?;
        if *seen {
            return Err(invalid("duplicate DataObjectFormat for data Reference"));
        }
        *seen = true;
        let mime = xchild(format, "MimeType")?;
        if mime.children().any(|n| n.is_element())
            || mime.text().is_none_or(|text| text.trim().is_empty())
        {
            return Err(invalid("DataObjectFormat MimeType missing or malformed"));
        }
        count += 1;
    }
    Ok(!missing_id && count == references.len() && references.values().all(|seen| *seen))
}

#[cfg(test)]
mod data_object_format_tests {
    use super::*;
    use oncl_pki::resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget,
    };
    use std::sync::Arc;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> std::result::Result<(), ProcessingError> {
            Ok(())
        }
    }
    fn check(references: &str, formats: &str) -> Result<bool> {
        let limits = ResourceLimits::default();
        let scope =
            Arc::new(SharedBudget::new(limits.clone())?).begin(limits, Arc::new(Control))?;
        let xml = format!(
            "<r xmlns:ds='{}' xmlns:x='{}'><ds:SignedInfo>{references}<ds:Reference Type='{}' URI='#properties'/></ds:SignedInfo><x:SignedProperties><x:SignedDataObjectProperties>{formats}</x:SignedDataObjectProperties></x:SignedProperties></r>",
            crate::DSIG_NS,
            crate::XADES_NS,
            crate::SIGNED_PROPERTIES_TYPE
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        baseline_data_formats(
            doc.descendants()
                .find(|n| n.tag_name().name() == "SignedProperties")
                .unwrap(),
            doc.descendants()
                .find(|n| crate::is_ds(*n, "SignedInfo"))
                .unwrap(),
            &scope,
        )
    }
    #[test]
    fn every_data_reference_has_one_own_descriptor_and_signed_properties_are_exempt() {
        let references =
            "<ds:Reference Id='data' URI='#p'/><ds:Reference Id='object' URI='#other-object'/>";
        let data = "<x:DataObjectFormat ObjectReference='#data'><x:MimeType>application/xml</x:MimeType></x:DataObjectFormat>";
        let object = "<x:DataObjectFormat ObjectReference='#object'><x:MimeType>application/octet-stream</x:MimeType></x:DataObjectFormat>";
        assert!(check(references, &format!("{data}{object}")).unwrap());
        assert!(!check(references, data).unwrap());
        assert!(check(references, &format!("{data}{data}{object}")).is_err());
        for bad in [
            "#p",
            "#foreign",
            "#properties",
            "https://example.test/#data",
        ] {
            assert!(
                check(
                    references,
                    &format!("{}{}", data.replace("#data", bad), object)
                )
                .is_err()
            );
        }
        assert!(check("<ds:Reference Id='data'/><ds:Reference Id='data'/>", data).is_err());
        assert!(!check("<ds:Reference/>", "").unwrap());
        assert!(
            check(
                references,
                &format!(
                    "{}{}",
                    data.replace("<x:MimeType>application/xml</x:MimeType>", ""),
                    object
                )
            )
            .is_err()
        );
        assert!(
            check(
                references,
                &format!("{}{}", data.replace("application/xml", " "), object)
            )
            .is_err()
        );
        assert!(
            check(
                references,
                &format!(
                    "{}{}",
                    data.replace("x:MimeType", "foreign:MimeType").replace(
                        "<x:DataObjectFormat ",
                        "<x:DataObjectFormat xmlns:foreign='urn:foreign' "
                    ),
                    object
                )
            )
            .is_err()
        );
    }
}
