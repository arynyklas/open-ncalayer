//! PAdES baseline evidence and immutable incremental augmentation.
//!
//! ETSI EN 319 142-1 V1.2.1 (2024-01), 5.4.2/5.4.3 and 6.3 table 1,
//! requirements n), q), r)-y). A document timestamp may provide initial PoE;
//! LTA additionally needs a later seal covering DSS and every prior proof.
//! https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
use crate::{
    PdfDocument, PdfError, PdfLimits, PdfSignProfile, PdfSignature, PdfVerification, Result,
    ScopedPdfRows,
    objects::{Value, get, white},
    verify::Candidate,
    xref::{Entry, StreamMode},
};
use der::Encode;
use oncl_pki::{
    cms::ades::{
        self, AdesServices, SnapshotDocumentTimestamp, SnapshotMaterial, SnapshotSignature,
    },
    digest::HashState,
    evidence::{AdesLevel, EvidenceKind},
    io::{
        DerivedInput, FrozenInput, PdfSignatureOutput, PdfSnapshot, Region, SnapshotEncoding,
        Source, StagedArtifact,
    },
    key::{DigestSigner, HashAlg, SigAlg},
    resource::{IO_CHUNK_BYTES, ProcessingError, ResourceScope},
    validation::Verdict,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

pub struct PadesReport {
    pub verdict: Verdict,
    level: Option<AdesLevel>,
    /// Level each signature ACHIEVED on its own (what its proofs support, possibly above
    /// what a request asked for), in `signatures()` order.
    signature_levels: Vec<Option<AdesLevel>>,
    verification: PdfVerification,
}
impl PadesReport {
    /// The minimum ACHIEVED level over all signatures, only when every signature validated.
    /// It is a floor over every signature, not the level an operation requested.
    pub fn level(&self) -> Option<AdesLevel> {
        self.level
    }
    /// The level each signature ACHIEVED, parallel to [`Self::signatures`]: what its own
    /// proofs (signature timestamp, covering document timestamps, DSS) support, never
    /// lowered to a request and never raised without validated evidence. A signature
    /// appended at level `L` therefore reports `>= L`: it can report more when the file
    /// already holds covering DSS evidence (e.g. a new T signature in an LTA file reports
    /// LT). `None` for a signature that did not validate.
    pub fn signature_levels(&self) -> &[Option<AdesLevel>] {
        &self.signature_levels
    }
    pub fn signatures(&self) -> &[PdfSignature] {
        &self.verification.signatures
    }
    pub fn into_verification(self) -> PdfVerification {
        self.verification
    }
}
impl std::fmt::Debug for PadesReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PadesReport")
            .field("verdict", &self.verdict)
            .field("level", &self.level)
            .field("signature_levels", &self.signature_levels)
            .field("verification", &self.verification)
            .finish()
    }
}
struct Material {
    kind: EvidenceKind,
    region: Region,
    reference: (u32, u16),
}
struct Dss {
    material: Vec<Material>,
    objects: BTreeSet<(u32, u16)>,
    vri: BTreeMap<Vec<u8>, Value>,
    normalized_vri: BTreeMap<Vec<u8>, Value>,
    _vri_memory: Option<oncl_pki::resource::ResourceReservation>,
    _vri_metadata: Option<oncl_pki::resource::ResourceReservation>,
}
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Name(a), Value::Name(b))
        | (Value::Scalar(a), Value::Scalar(b))
        | (Value::Bytes(a, _), Value::Bytes(b, _)) => a == b,
        (Value::Ref(a, ag), Value::Ref(b, bg)) => a == b && ag == bg,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
        }
        (Value::Dict(a), Value::Dict(b)) => {
            a.len() == b.len() && a.iter().all(|(k, a)| b.get(k).is_some_and(|b| same(a, b)))
        }
        _ => false,
    }
}
fn except(a: &BTreeMap<Vec<u8>, Value>, b: &BTreeMap<Vec<u8>, Value>, ignored: &[&[u8]]) -> bool {
    a.iter()
        .filter(|(k, _)| !ignored.contains(&k.as_slice()))
        .all(|(k, a)| b.get(k).is_some_and(|b| same(a, b)))
        && b.keys()
            .filter(|k| !ignored.contains(&k.as_slice()))
            .all(|k| a.contains_key(k))
}
fn direct(doc: &PdfDocument<'_, '_>, revision: usize, value: &Value) -> Result<(u32, u16, u64)> {
    let Value::Ref(id, generation) = value else {
        return Err(PdfError::Unsupported(
            "DSS and augmentation nodes must be indirect",
        ));
    };
    match doc.revisions[..=revision]
        .iter()
        .rev()
        .find_map(|r| r.entries.get(id))
    {
        Some(Entry::Direct(offset, actual)) if actual == generation => {
            Ok((*id, *generation, *offset))
        }
        _ => Err(PdfError::Unsupported(
            "compressed or missing augmentation object",
        )),
    }
}
fn node(
    doc: &mut PdfDocument<'_, '_>,
    revision: usize,
    value: &Value,
    objects: &mut BTreeSet<(u32, u16)>,
) -> Result<Value> {
    if let Value::Ref(id, generation) = value {
        if objects.len() >= doc.limits.max_objects {
            return Err(PdfError::Limit("DSS graph"));
        }
        objects.insert((*id, *generation));
    }
    doc.resolve(revision, value)
}
fn dss(
    doc: &mut PdfDocument<'_, '_>,
    revision: usize,
    keys: &BTreeMap<Vec<u8>, usize>,
) -> Result<Dss> {
    let root = doc.revisions[revision].root.clone();
    let catalog = doc.resolve(revision, &root)?;
    let mut result = Dss {
        material: Vec::new(),
        objects: BTreeSet::new(),
        vri: BTreeMap::new(),
        normalized_vri: BTreeMap::new(),
        _vri_memory: None,
        _vri_metadata: None,
    };
    let Some(value) = catalog.dict()?.get(b"DSS".as_slice()) else {
        return Ok(result);
    };
    let value = node(doc, revision, value, &mut result.objects)?;
    let dict = value.dict()?;
    if dict
        .get(b"Type".as_slice())
        .is_some_and(|v| !v.name(b"DSS"))
        || dict.keys().any(|k| {
            ![b"Type".as_slice(), b"Certs", b"OCSPs", b"CRLs", b"VRI"].contains(&k.as_slice())
        })
    {
        return Err(PdfError::Malformed("DSS validation-only dictionary"));
    }
    let mut references = BTreeMap::new();
    for (name, kind) in [
        (b"Certs".as_slice(), EvidenceKind::Certificate),
        (b"OCSPs", EvidenceKind::Ocsp),
        (b"CRLs", EvidenceKind::Crl),
    ] {
        if let Some(array) = dict.get(name) {
            let array = node(doc, revision, array, &mut result.objects)?;
            for reference in array.array()? {
                let (id, generation, offset) = direct(doc, revision, reference)?;
                if result.material.len() >= doc.limits.max_objects {
                    return Err(PdfError::Limit("DSS evidence count"));
                }
                if references.insert((id, generation), kind).is_some() {
                    return Err(PdfError::Malformed("DSS duplicate or aliased material"));
                }
                result.objects.insert((id, generation));
                let object = doc.indirect(offset, Some((id, generation)), StreamMode::Region)?;
                if object.end > doc.revisions[revision].end
                    || object
                        .value
                        .dict()?
                        .keys()
                        .any(|k| ![b"Length".as_slice(), b"Type"].contains(&k.as_slice()))
                {
                    return Err(PdfError::Unsupported(
                        "DSS filtered or non-validation stream",
                    ));
                }
                let region = object
                    .stream_region
                    .ok_or(PdfError::Malformed("DSS evidence must be a stream"))?;
                result.material.push(Material {
                    kind,
                    region,
                    reference: (id, generation),
                });
            }
        }
    }
    if let Some(vri) = dict.get(b"VRI".as_slice()) {
        let vri = node(doc, revision, vri, &mut result.objects)?;
        let retained = vri
            .retained_bytes()?
            .checked_mul(3)
            .ok_or(ProcessingError::MetadataLimit)?;
        result._vri_memory = Some(doc.scope.reserve_memory(retained)?);
        result._vri_metadata = Some(doc.scope.reserve_metadata(retained)?);
        result.vri = vri.dict()?.clone();
        for (key, value) in vri.dict()? {
            if !keys
                .get(key)
                .is_some_and(|signed_revision| *signed_revision < revision)
            {
                return Err(PdfError::Malformed(
                    "VRI must identify a signature from an earlier revision",
                ));
            }
            let value = node(doc, revision, value, &mut result.objects)?;
            let extra = value
                .retained_bytes()?
                .checked_mul(2)
                .ok_or(ProcessingError::MetadataLimit)?;
            result
                ._vri_memory
                .as_mut()
                .expect("VRI admission")
                .grow(extra)?;
            result
                ._vri_metadata
                .as_mut()
                .expect("VRI admission")
                .grow(extra)?;
            result.normalized_vri.insert(key.clone(), value.clone());
            let vri = value.dict()?;
            if vri.get(b"Type".as_slice()).is_some_and(|v| !v.name(b"VRI"))
                || vri.keys().any(|k| {
                    ![b"Type".as_slice(), b"Cert", b"OCSP", b"CRL"].contains(&k.as_slice())
                })
            {
                return Err(PdfError::Unsupported(
                    "VRI time claims or non-validation fields",
                ));
            }
            for (name, kind) in [
                (b"Cert".as_slice(), EvidenceKind::Certificate),
                (b"OCSP", EvidenceKind::Ocsp),
                (b"CRL", EvidenceKind::Crl),
            ] {
                if let Some(array) = vri.get(name) {
                    let array = node(doc, revision, array, &mut result.objects)?;
                    if array.array()?.is_empty() {
                        return Err(PdfError::Malformed("empty VRI array"));
                    }
                    for reference in array.array()? {
                        let (id, generation, _) = direct(doc, revision, reference)?;
                        if references.get(&(id, generation)) != Some(&kind) {
                            return Err(PdfError::Malformed("VRI material absent from DSS"));
                        }
                    }
                }
            }
        }
    }
    Ok(result)
}
fn signing_keys(
    doc: &mut PdfDocument<'_, '_>,
    candidates: &[(usize, Candidate)],
) -> Result<BTreeMap<Vec<u8>, usize>> {
    let mut keys = BTreeMap::new();
    for (revision, candidate) in candidates {
        doc.work = doc
            .work
            .checked_add(candidate.contents.len)
            .ok_or(PdfError::Limit("signature metadata work"))?;
        if doc.work > doc.limits.max_read_work {
            return Err(PdfError::Limit("signature metadata work"));
        }
        let token = doc.input.read_at(
            candidate.contents.offset,
            candidate.contents.len as usize,
            doc.scope,
        )?;
        let value = doc.parser(&token, candidate.contents.offset).value(0)?;
        let Value::Bytes(bytes, _) = value else {
            return Err(PdfError::Malformed("physical signature Contents"));
        };
        let mut hash = HashState::new(HashAlg::Sha1);
        hash.update(&bytes);
        let mut key = Vec::with_capacity(40);
        for byte in hash.finish().as_bytes() {
            key.push(b"0123456789ABCDEF"[(byte >> 4) as usize]);
            key.push(b"0123456789ABCDEF"[(byte & 15) as usize]);
        }
        if keys.insert(key, *revision).is_some() {
            return Err(PdfError::Malformed("ambiguous VRI identifier"));
        }
    }
    Ok(keys)
}
fn fields(
    doc: &mut PdfDocument<'_, '_>,
    revision: usize,
    catalog: &Value,
) -> Result<(Value, Vec<Value>)> {
    match catalog.dict()?.get(b"AcroForm".as_slice()) {
        Some(form) => {
            let form = doc.resolve(revision, form)?;
            let array = doc.resolve(revision, get(form.dict()?, b"Fields")?)?;
            Ok((form, array.array()?.to_vec()))
        }
        None => Ok((Value::Dict(BTreeMap::new()), Vec::new())),
    }
}
fn white_gap(doc: &mut PdfDocument<'_, '_>, mut start: u64, end: u64) -> Result<()> {
    if start > end {
        return Err(PdfError::Malformed("overlapping augmentation objects"));
    }
    while start < end {
        let bytes = doc.input.read_at(
            start,
            (end - start).min(IO_CHUNK_BYTES as u64) as usize,
            doc.scope,
        )?;
        if bytes.is_empty() || bytes.iter().any(|b| !white(*b)) {
            return Err(PdfError::Unsupported(
                "unindexed bytes in incremental validation update",
            ));
        }
        start += bytes.len() as u64;
    }
    Ok(())
}
/// Strict, explicit validation-only/signature-append grammar. No page, content,
/// permission, existing-field or unrelated catalog/object change is allowed.
fn permitted(
    doc: &mut PdfDocument<'_, '_>,
    revision: usize,
    old: &Dss,
    current: &Dss,
) -> Result<()> {
    let prior = revision - 1;
    if old.normalized_vri.iter().any(|(key, value)| {
        !current
            .normalized_vri
            .get(key)
            .is_some_and(|new| same(value, new))
    }) {
        return Err(PdfError::Unsupported(
            "existing VRI entry changed or removed",
        ));
    }
    if !same(&doc.revisions[prior].root, &doc.revisions[revision].root) {
        return Err(PdfError::Unsupported("incremental root substitution"));
    }
    match (
        doc.revisions[prior].trailer.get(b"Info".as_slice()),
        doc.revisions[revision].trailer.get(b"Info".as_slice()),
    ) {
        (Some(a), Some(b)) if same(a, b) => {}
        (None, None) => {}
        _ => return Err(PdfError::Unsupported("incremental trailer metadata change")),
    }
    // ISO 32000-1 14.4: ID[0] is the permanent original identifier and MUST
    // stay; ID[1] identifies the latest revision and legitimately changes.
    match (
        doc.revisions[prior].trailer.get(b"ID".as_slice()),
        doc.revisions[revision].trailer.get(b"ID".as_slice()),
    ) {
        (None, None) => {}
        (Some(Value::Array(a)), Some(Value::Array(b)))
            if a.len() == 2
                && b.len() == 2
                && matches!(&a[1], Value::Bytes(..))
                && matches!(&b[1], Value::Bytes(..))
                && matches!(&a[0], Value::Bytes(..))
                && same(&a[0], &b[0]) => {}
        _ => return Err(PdfError::Unsupported("incremental trailer metadata change")),
    }
    let root = doc.revisions[revision].root.clone();
    let before = doc.resolve(prior, &root)?;
    let after = doc.resolve(revision, &root)?;
    if before.dict()?.contains_key(b"Perms".as_slice())
        || after.dict()?.contains_key(b"Perms".as_slice())
    {
        return Err(PdfError::Unsupported("certification signature permissions"));
    }
    if !except(before.dict()?, after.dict()?, &[b"DSS", b"AcroForm"]) {
        return Err(PdfError::Unsupported("non-validation catalog change"));
    }
    let mut allowed = current.objects.clone();
    let mut prior_roles = old.objects.clone();
    if let Value::Ref(id, generation) = root {
        prior_roles.insert((id, generation));
    }
    if let Some(Value::Ref(id, generation)) = before.dict()?.get(b"AcroForm".as_slice()) {
        prior_roles.insert((*id, *generation));
    }
    if let Value::Ref(id, generation) = root {
        allowed.insert((id, generation));
    }
    let (old_form, old_fields) = fields(doc, prior, &before)?;
    let (new_form, new_fields) = fields(doc, revision, &after)?;
    if !except(
        old_form.dict()?,
        new_form.dict()?,
        &[b"Fields", b"SigFlags"],
    ) || new_fields.len() < old_fields.len()
        || !old_fields.iter().zip(&new_fields).all(|(a, b)| same(a, b))
    {
        return Err(PdfError::Unsupported("existing form or field change"));
    }
    if let Some(Value::Ref(id, generation)) = after.dict()?.get(b"AcroForm".as_slice()) {
        allowed.insert((*id, *generation));
    }
    for field in new_fields.iter().skip(old_fields.len()) {
        let (id, generation, _) = direct(doc, revision, field)?;
        allowed.insert((id, generation));
        let value = doc.resolve(revision, field)?;
        let field = value.dict()?;
        if !get(field, b"FT")?.name(b"Sig")
            || field
                .keys()
                .any(|k| ![b"FT".as_slice(), b"T", b"V"].contains(&k.as_slice()))
        {
            return Err(PdfError::Unsupported("non-signature new field"));
        }
        let value = get(field, b"V")?;
        let (id, generation, offset) = direct(doc, revision, value)?;
        if offset < doc.revisions[prior].end {
            return Err(PdfError::Unsupported("old signature field alias"));
        }
        allowed.insert((id, generation));
    }
    for material in &old.material {
        if !current.material.iter().any(|m| {
            m.reference == material.reference
                && m.kind == material.kind
                && m.region == material.region
        }) {
            return Err(PdfError::Unsupported(
                "old DSS material removed or replaced",
            ));
        }
    }
    let start = doc.revisions[prior].end;
    let xref = doc.revisions[revision].xref;
    let mut spans = Vec::new();
    for section in 0..doc.revisions[revision].entries.section_count() {
        for row in 0..doc.revisions[revision].entries.section(section).1.len() {
            let (first, rows) = doc.revisions[revision].entries.section(section);
            let (id, entry) = (first + row as u32, rows[row]);
            match entry {
                Entry::Direct(offset, generation) if offset == xref => {
                    if doc.revisions[..revision]
                        .iter()
                        .any(|r| r.entries.contains_key(&id))
                    {
                        return Err(PdfError::Unsupported(
                            "xref object aliases an existing object",
                        ));
                    }
                    let object =
                        doc.indirect(offset, Some((id, generation)), StreamMode::Decode)?;
                    if !get(object.value.dict()?, b"Type")?.name(b"XRef") {
                        return Err(PdfError::Malformed("incremental xref object identity"));
                    }
                }
                Entry::Direct(offset, generation) => {
                    let previous = doc.revisions[..revision]
                        .iter()
                        .rev()
                        .find_map(|r| r.entries.get(&id));
                    if matches!(previous, Some(Entry::Direct(old,old_gen)) if *old==offset && *old_gen==generation)
                    {
                        continue;
                    }
                    if previous.is_some() && !prior_roles.contains(&(id, generation)) {
                        return Err(PdfError::Unsupported(
                            "validation metadata aliases existing source object",
                        ));
                    }
                    if offset < start || !allowed.contains(&(id, generation)) {
                        return Err(PdfError::Unsupported(
                            "non-validation incremental object change",
                        ));
                    }
                    if old.material.iter().any(|m| m.reference.0 == id) {
                        return Err(PdfError::Unsupported("old evidence object redefinition"));
                    }
                    let object = doc.indirect(
                        offset,
                        Some((id, generation)),
                        if current
                            .material
                            .iter()
                            .any(|m| m.reference == (id, generation))
                        {
                            StreamMode::Region
                        } else {
                            StreamMode::Reject
                        },
                    )?;
                    spans.push((offset, object.end));
                }
                // Object 0 is the mandatory head of the free list (ISO 32000-1
                // 7.5.4); every revision's xref re-lists it. Only that entry,
                // and only when it was already free, is not an object change.
                Entry::Free { next, generation }
                    if id == 0
                        && generation == 65535
                        && free_head_unchanged(doc, revision, next) => {}
                _ => {
                    return Err(PdfError::Unsupported(
                        "free or compressed augmentation entry",
                    ));
                }
            }
        }
    }
    spans.sort_unstable();
    let mut at = start;
    for (offset, end) in spans {
        white_gap(doc, at, offset)?;
        at = end;
    }
    white_gap(doc, at, xref)
}
/// Object 0 may be re-listed only as the free-list head: it was never in use,
/// and its next-free link ends the list (0) or names another free entry.
fn free_head_unchanged(doc: &PdfDocument<'_, '_>, revision: usize, next: u64) -> bool {
    let latest = |id: u64| {
        doc.revisions[..=revision]
            .iter()
            .rev()
            .find_map(|r| r.entries.get(&u32::try_from(id).ok()?))
    };
    doc.revisions[..revision].iter().all(|r| {
        !matches!(
            r.entries.get(&0),
            Some(Entry::Direct(..) | Entry::Compressed(..))
        )
    }) && (next == 0 || matches!(latest(next), Some(Entry::Free { .. })))
}
struct Parsed {
    candidates: Vec<(usize, Candidate)>,
    material: Vec<Material>,
    keys: BTreeMap<Vec<u8>, usize>,
    vri: BTreeMap<Vec<u8>, Value>,
    _vri_memory: Option<oncl_pki::resource::ResourceReservation>,
    _vri_metadata: Option<oncl_pki::resource::ResourceReservation>,
}
pub(crate) fn prior_signature_contents(
    source: oncl_pki::io::Source<'_>,
    limits: &PdfLimits,
    scope: &mut ResourceScope,
) -> Result<crate::budget::PriorSignatures> {
    let mut doc = PdfDocument::open(source, limits, scope)?;
    let mut seen = BTreeSet::new();
    let (mut sum, mut largest) = (0u64, 0u64);
    for revision in 0..doc.revisions.len() {
        for candidate in doc.signature_candidates(revision, &seen, true)? {
            if seen.insert(candidate.range.values()) {
                sum = sum
                    .checked_add(candidate.contents.len)
                    .ok_or(ProcessingError::MetadataLimit)?;
                largest = largest.max(candidate.contents.len);
            }
            if seen.len() > limits.max_signatures {
                return Err(PdfError::Limit("signature count"));
            }
        }
    }
    Ok(crate::budget::PriorSignatures {
        count: seen.len() as u64,
        contents_sum: sum,
        contents_max: largest,
        xref_entries: doc.xref_entries,
    })
}
fn parse(
    snapshot: &mut PdfSnapshot<'_>,
    limits: &PdfLimits,
    scope: &mut ResourceScope,
) -> Result<Parsed> {
    let extent = snapshot.len();
    let mut reader = snapshot.reader(
        &[Region {
            offset: 0,
            len: extent,
        }],
        scope,
    )?;
    let result = (|| {
        let mut doc = PdfDocument::open(reader.source(), limits, scope)?;
        let mut seen = BTreeSet::new();
        let mut candidates = Vec::new();
        for revision in 0..doc.revisions.len() {
            for candidate in doc.signature_candidates(revision, &seen, true)? {
                if candidate.permission_transform {
                    return Err(PdfError::Unsupported("signature permission transform"));
                }
                if seen.insert(candidate.range.values()) {
                    candidates.push((revision, candidate));
                }
                if candidates.len() > limits.max_signatures {
                    return Err(PdfError::Limit("signature count"));
                }
            }
        }
        if !candidates.iter().any(|(_, c)| !c.document_timestamp) {
            return Err(PdfError::Unsupported("no PAdES document signature"));
        }
        let keys = signing_keys(&mut doc, &candidates)?;
        let first = candidates
            .iter()
            .find(|(_, c)| !c.document_timestamp)
            .map(|(r, _)| *r)
            .unwrap();
        let mut previous = dss(&mut doc, first, &keys)?;
        for revision in first + 1..doc.revisions.len() {
            let current = dss(&mut doc, revision, &keys)?;
            permitted(&mut doc, revision, &previous, &current)?;
            previous = current;
        }
        Ok(Parsed {
            candidates,
            material: previous.material,
            keys,
            vri: previous.vri,
            _vri_memory: previous._vri_memory,
            _vri_metadata: previous._vri_metadata,
        })
    })();
    reader.finish()?;
    result
}
pub fn verify(
    required: AdesLevel,
    input: Source<'_>,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &mut ResourceScope,
) -> Result<PadesReport> {
    let mut frozen = crate::verify::capture_signed(input, services.temporary, limits, scope)?;
    verify_view(
        required,
        PdfSnapshot::input(&mut frozen, scope)?,
        limits,
        services,
        allowed,
        scope,
    )
}
fn verify_view(
    required: AdesLevel,
    mut view: PdfSnapshot<'_>,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &mut ResourceScope,
) -> Result<PadesReport> {
    let bytes = crate::budget::verify_reservation(limits)?;
    let memory = scope.reserve_memory(bytes)?;
    let metadata = scope.reserve_metadata(bytes)?;
    let parsed = parse(&mut view, limits, scope)?;
    let mut decoded = Vec::new();
    for (_, candidate) in &parsed.candidates {
        decoded.push(view.derive_region(
            candidate.contents,
            scope,
            SnapshotEncoding::PdfByteString,
        )?);
    }
    let mut material = Vec::new();
    for item in &parsed.material {
        material.push(view.derive_region(item.region, scope, SnapshotEncoding::Identity)?);
    }
    let material: Vec<_> = parsed
        .material
        .iter()
        .zip(&material)
        .map(|(item, value)| SnapshotMaterial {
            value,
            kind: item.kind,
        })
        .collect();
    let documents: Vec<_> = parsed
        .candidates
        .iter()
        .zip(&decoded)
        .filter(|((_, c), _)| c.document_timestamp)
        .map(|((_, c), token)| SnapshotDocumentTimestamp {
            token,
            regions: regions(c),
        })
        .collect();
    let extent = view.len();
    let snapshot = Mutex::new(view);
    let mut signatures = Vec::new();
    let mut signature_levels = Vec::new();
    let mut minimum = AdesLevel::Lta;
    let sources: Vec<_> = parsed
        .candidates
        .iter()
        .zip(&decoded)
        .filter(|((_, candidate), _)| !candidate.document_timestamp)
        .map(|((_, candidate), metadata)| SnapshotSignature {
            metadata,
            regions: regions(candidate),
        })
        .collect();
    let reports = ades::verify_snapshot_pades(
        required, &sources, &snapshot, &material, &documents, services, allowed, scope,
    )?
    .into_iter();
    if reports.len() != sources.len() {
        return Err(PdfError::Malformed("PAdES source report count"));
    }
    for (((revision, candidate), _), report) in parsed
        .candidates
        .iter()
        .zip(&decoded)
        .filter(|((_, candidate), _)| !candidate.document_timestamp)
        .zip(reports)
    {
        if let Some(level) = report.level() {
            minimum = minimum.min(level);
        }
        signature_levels.push(report.level());
        signatures.push(PdfSignature {
            byte_range: candidate.range,
            revision: *revision,
            revision_end: candidate.range.signed_end(),
            parser_revision_end: candidate.parser_revision_end,
            endpoint_scope: candidate.endpoint_scope,
            later_changes: candidate.range.signed_end() < extent,
            validation: report.into_validation(scope)?,
        });
    }
    let verdict = if signatures
        .iter()
        .any(|s| s.validation.verdict == Verdict::Invalid)
    {
        Verdict::Invalid
    } else if signatures
        .iter()
        .all(|s| s.validation.verdict == Verdict::Valid)
    {
        Verdict::Valid
    } else {
        Verdict::Indeterminate
    };
    Ok(PadesReport {
        verdict,
        level: (verdict == Verdict::Valid).then_some(minimum),
        signature_levels,
        verification: PdfVerification {
            verdict,
            extent,
            signatures: ScopedPdfRows {
                values: signatures,
                _memory: memory,
                _metadata: metadata,
            },
        },
    })
}
fn regions(candidate: &Candidate) -> [Region; 2] {
    let [offset, len, second, last] = candidate.range.values();
    [
        Region { offset, len },
        Region {
            offset: second,
            len: last,
        },
    ]
}

pub(crate) fn verify_frozen(
    required: AdesLevel,
    input: &mut FrozenInput,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &mut ResourceScope,
) -> Result<PadesReport> {
    verify_view(
        required,
        PdfSnapshot::input(input, scope)?,
        limits,
        services,
        allowed,
        scope,
    )
}
fn verify_output(
    required: AdesLevel,
    output: &mut StagedArtifact,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
) -> Result<PadesReport> {
    let mut operation = scope.shared_view();
    PdfSignatureOutput::with_snapshot(output, scope, |view| {
        let report = verify_view(required, view, limits, services, allowed, &mut operation)?;
        if report.verdict != Verdict::Valid {
            return Err(PdfError::Unsupported(
                "final PAdES evidence did not validate",
            ));
        }
        Ok(report)
    })
}
/// Final check after appending ONE new signature to a possibly already signed PDF:
/// every signature must validate at its own achieved level (a present signature is never
/// upgraded or ignored), and the signature this operation appended must itself reach
/// `required`. That signature is identified by its ByteRange: it is the one whose signed
/// extent ends exactly at `appended_end`, the output length when the operation finished
/// writing it (before any evidence augmentation). Earlier signatures are not demanded to
/// reach `required`.
fn verify_new_signature(
    required: AdesLevel,
    appended_end: u64,
    output: &mut StagedArtifact,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
) -> Result<PadesReport> {
    let report = verify_output(AdesLevel::B, output, limits, services, allowed, scope)?;
    let mut appended = report
        .signatures()
        .iter()
        .zip(report.signature_levels())
        .filter(|(signature, _)| signature.byte_range.signed_end() == appended_end)
        .map(|(_, level)| *level);
    let (Some(achieved), None) = (appended.next(), appended.next()) else {
        return Err(PdfError::Malformed("appended signature identity"));
    };
    if achieved.is_none_or(|level| level < required) {
        return Err(PdfError::Unsupported(
            "new PAdES signature did not reach the requested level",
        ));
    }
    Ok(report)
}
fn acquisition(level: AdesLevel, services: &AdesServices<'_>) -> Result<()> {
    services.limits.validate().map_err(ades::AdesError::from)?;
    if level >= AdesLevel::T {
        let tsa = services.tsa.ok_or(ades::AdesError::MissingConfiguration)?;
        if tsa.hash != HashAlg::Sha256 || !tsa.require_tsa_eku {
            return Err(PdfError::Unsupported(
                "PAdES TSA requires SHA-256 and timestamp EKU",
            ));
        }
    }
    if level >= AdesLevel::Lt
        && services.material.ocsp.is_empty()
        && services.material.crls.is_empty()
    {
        return Err(PdfError::Unsupported(
            "PAdES extension requires acquired status material",
        ));
    }
    Ok(())
}
/// One ordinary document-signing operation. Later evidence acquisition never
/// requests a second local user signature; post-use failures retain Applied.
pub fn sign(
    level: AdesLevel,
    input: Source<'_>,
    profile: &PdfSignProfile,
    signer: &mut dyn DigestSigner,
    services: &AdesServices<'_>,
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<crate::PdfOperationReport> {
    PdfSignatureOutput::check_output(output, scope)?;
    if let Err(error) = acquisition(level, services) {
        // Own a poisoning transaction even on known pre-private configuration failure.
        drop(PdfSignatureOutput::new(output, scope)?);
        return Err(error);
    }
    let before = scope.progress();
    let mut report = crate::sign::sign_pades_source(
        level.min(AdesLevel::T),
        input,
        profile,
        signer,
        services,
        output,
        scope,
    )?;
    let appended_end = output.len();
    let result = (|| {
        verify_new_signature(
            level.min(AdesLevel::T),
            appended_end,
            output,
            &profile.limits,
            services,
            profile.allowed,
            scope,
        )?;
        if level >= AdesLevel::Lt {
            augment(
                level,
                output,
                &profile.limits,
                services,
                profile.allowed,
                scope,
            )?;
        }
        if level >= AdesLevel::Lt {
            // The evidence steps above cover every signature, so all must reach it.
            verify_output(
                level,
                output,
                &profile.limits,
                services,
                profile.allowed,
                scope,
            )?;
        } else {
            verify_new_signature(
                level,
                appended_end,
                output,
                &profile.limits,
                services,
                profile.allowed,
                scope,
            )?;
        }
        Ok::<_, PdfError>(())
    })();
    if let Err(error) = result {
        let _ = PdfSignatureOutput::abort_output(output, scope);
        let source = match error {
            PdfError::Ades(error) => error,
            PdfError::Processing(error) => error.into(),
            other => ades::AdesError::Stream(oncl_pki::cms::stream::StreamError::Cms(
                oncl_pki::cms::CmsError::Malformed(other.to_string()),
            )),
        };
        return Err(ades::AdesError::AfterKeyUse {
            source: Box::new(source),
            applied: report.applied,
        }
        .into());
    }
    report.bytes_in = scope.progress().bytes_in - before.bytes_in;
    report.bytes_out = output.len();
    Ok(report)
}
/// Evidence-only augmentation: no local key, guard, password or private lease.
pub fn extend(
    level: AdesLevel,
    input: Source<'_>,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<PadesReport> {
    let mut transaction = PdfSignatureOutput::new(output, scope)?;
    let mut operation = scope.shared_view();
    let mut frozen =
        crate::verify::capture_signed(input, services.temporary, limits, &mut operation)?;
    let old = verify_frozen(
        AdesLevel::B,
        &mut frozen,
        limits,
        services,
        allowed,
        &mut operation,
    )?;
    if old.verdict != Verdict::Valid {
        return Err(PdfError::Unsupported(
            "all original PAdES signatures and proofs must validate before Extend",
        ));
    }
    let achieved = old
        .level()
        .ok_or(PdfError::Unsupported("no verified PAdES level"))?;
    if level > achieved || level == AdesLevel::Lta {
        acquisition(level, services)?;
    }
    let _memory = scope.reserve_memory(IO_CHUNK_BYTES as u64)?;
    let mut buffer = vec![0; IO_CHUNK_BYTES];
    let mut at = 0;
    while at < frozen.len() {
        scope.checkpoint()?;
        let n = frozen.read_region(
            Region {
                offset: at,
                len: frozen.len() - at,
            },
            &mut buffer,
        )?;
        if n == 0 {
            return Err(PdfError::Malformed("truncated immutable PDF"));
        }
        transaction.append(&buffer[..n])?;
        at += n as u64;
    }
    transaction.finish_validation_update(scope)?;
    let result = (|| {
        if level > achieved || level == AdesLevel::Lta {
            augment(level, output, limits, services, allowed, scope)?;
        }
        verify_output(level, output, limits, services, allowed, scope)
    })();
    if result.is_err() {
        let _ = PdfSignatureOutput::abort_output(output, scope);
    }
    result
}
struct UpdatePlan {
    plan: crate::sign::Plan,
    parsed: Parsed,
    material: Vec<DerivedInput>,
    certificates: Vec<Vec<u8>>,
    _memory: oncl_pki::resource::ResourceReservation,
    _metadata: oncl_pki::resource::ResourceReservation,
    _certificate_memory: oncl_pki::resource::ResourceReservation,
    _certificate_metadata: oncl_pki::resource::ResourceReservation,
}
fn update_plan(
    output: &mut StagedArtifact,
    limits: &PdfLimits,
    scope: &ResourceScope,
) -> Result<UpdatePlan> {
    let memory = scope.reserve_memory(crate::budget::plan_reservation(limits)?)?;
    let metadata = scope.reserve_metadata(crate::budget::plan_metadata_reservation(limits)?)?;
    let mut operation = scope.shared_view();
    PdfSignatureOutput::with_snapshot(output, scope, |mut view| {
        let parsed = parse(&mut view, limits, &mut operation)?;
        let certificate_bytes = parsed
            .candidates
            .iter()
            .try_fold(0u64, |sum, (_, candidate)| {
                sum.checked_add(candidate.contents.len)
                    .ok_or(ProcessingError::MetadataLimit)
            })?
            .checked_mul(4)
            .ok_or(ProcessingError::MetadataLimit)?;
        let certificate_memory = scope.reserve_memory(certificate_bytes)?;
        let certificate_metadata = scope.reserve_metadata(certificate_bytes)?;
        let mut material = Vec::new();
        for item in &parsed.material {
            material.push(view.derive_region(item.region, scope, SnapshotEncoding::Identity)?);
        }
        let mut certificates = Vec::new();
        for (_, candidate) in &parsed.candidates {
            let cms =
                view.derive_region(candidate.contents, scope, SnapshotEncoding::PdfByteString)?;
            let der = oncl_pki::io::padded_der_sequence(cms.as_bytes())?;
            let _working = scope.reserve_memory(
                (der.len() as u64)
                    .checked_mul(128)
                    .ok_or(ProcessingError::MemoryLimit)?,
            )?;
            let _decode = scope.reserve_metadata(
                (der.len() as u64)
                    .checked_mul(16)
                    .ok_or(ProcessingError::MetadataLimit)?,
            )?;
            for cert in oncl_pki::cms::certificates(der).map_err(ades::AdesError::from)? {
                let der = cert
                    .to_der()
                    .map_err(oncl_pki::cms::CmsError::from)
                    .map_err(ades::AdesError::from)?;
                if !certificates.contains(&der) {
                    if certificates.len() >= limits.max_objects {
                        return Err(PdfError::Limit("validation certificate count"));
                    }
                    certificates.push(der);
                }
            }
        }
        let length = view.len();
        let mut reader = view.reader(
            &[Region {
                offset: 0,
                len: length,
            }],
            scope,
        )?;
        let result = (|| {
            let mut doc = PdfDocument::open(reader.source(), limits, &mut operation)?;
            let revision = doc.revision_count() - 1;
            let root = doc.revisions[revision].root.clone();
            let catalog = doc.resolve(revision, &root)?;
            let mut plan = crate::sign::plan(&mut doc, true)?;
            plan.catalog = catalog;
            Ok::<_, PdfError>(plan)
        })();
        reader.finish()?;
        Ok(UpdatePlan {
            plan: result?,
            parsed,
            material,
            certificates,
            _memory: memory,
            _metadata: metadata,
            _certificate_memory: certificate_memory,
            _certificate_metadata: certificate_metadata,
        })
    })
}
fn close_xref(
    output: &mut PdfSignatureOutput<'_>,
    plan: &crate::sign::Plan,
    next: u32,
    mut offsets: BTreeMap<(u32, u16), u64>,
    limits: &PdfLimits,
) -> Result<()> {
    let xref = output.len();
    offsets.insert((next, 0), xref);
    let mut index = String::new();
    let mut rows = Vec::new();
    for ((id, generation), offset) in offsets {
        index.push_str(&format!("{id} 1 "));
        rows.extend_from_slice(&crate::sign::xref_entry(offset, generation));
    }
    let size = next
        .checked_add(1)
        .ok_or(PdfError::Limit("object identifiers"))?;
    output.append(format!("{next} 0 obj\n<< /Type /XRef /Size {size} /Root {} {} R /Prev {} /W [1 8 2] /Index [{index}] /Length {} ",plan.root.0,plan.root.1,plan.previous,rows.len()).as_bytes())?;
    let mut extras = Vec::new();
    for (key, value) in &plan.extras {
        crate::sign::name(key, &mut extras);
        extras.push(b' ');
        crate::sign::encode(value, &mut extras)?;
        extras.push(b' ');
    }
    if extras
        .len()
        .checked_add(rows.len())
        .and_then(|n| n.checked_add(index.len() + 256))
        .is_none_or(|n| n > limits.max_object_bytes)
    {
        return Err(PdfError::Limit("incremental xref metadata"));
    }
    output.append(&extras)?;
    output.append(b">>\nstream\n")?;
    output.append(&rows)?;
    output.append(format!("\nendstream\nendobj\nstartxref\n{xref}\n%%EOF\n").as_bytes())?;
    Ok(())
}
fn add_material(
    bytes: &[u8],
    kind: EvidenceKind,
    old: &UpdatePlan,
    new: &mut Vec<(EvidenceKind, Vec<u8>)>,
    scope: &ResourceScope,
) -> Result<()> {
    if old
        .parsed
        .material
        .iter()
        .zip(&old.material)
        .any(|(item, value)| item.kind == kind && value.as_bytes() == bytes)
        || new.iter().any(|(k, b)| *k == kind && b == bytes)
    {
        return Ok(());
    }
    scope.checkpoint()?;
    new.push((kind, bytes.to_vec()));
    Ok(())
}
fn append_dss(
    output: &mut StagedArtifact,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<()> {
    let mut update = update_plan(output, limits, scope)?;
    let size = services
        .material
        .certificates
        .iter()
        .chain(services.validation.anchors.certs())
        .chain(services.validation.intermediates)
        .try_fold(0u64, |sum, cert| {
            let n: u32 = cert
                .encoded_len()
                .map_err(oncl_pki::cms::CmsError::from)
                .map_err(ades::AdesError::from)?
                .into();
            sum.checked_add(u64::from(n))
                .ok_or(PdfError::Processing(ProcessingError::MetadataLimit))
        })?
        .checked_add(
            services
                .material
                .ocsp
                .iter()
                .chain(services.material.crls)
                .try_fold(0u64, |sum, b| {
                    sum.checked_add(b.len() as u64)
                        .ok_or(ProcessingError::MetadataLimit)
                })?,
        )
        .ok_or(ProcessingError::MetadataLimit)?;
    let _memory = scope.reserve_memory(size.checked_mul(4).ok_or(ProcessingError::MemoryLimit)?)?;
    let _metadata =
        scope.reserve_metadata(size.checked_mul(2).ok_or(ProcessingError::MetadataLimit)?)?;
    let mut new = Vec::new();
    for der in &update.certificates {
        add_material(der, EvidenceKind::Certificate, &update, &mut new, scope)?;
    }
    for cert in services
        .material
        .certificates
        .iter()
        .chain(services.validation.anchors.certs())
        .chain(services.validation.intermediates)
    {
        let der = cert
            .to_der()
            .map_err(oncl_pki::cms::CmsError::from)
            .map_err(ades::AdesError::from)?;
        add_material(&der, EvidenceKind::Certificate, &update, &mut new, scope)?;
    }
    for bytes in services.material.ocsp {
        add_material(bytes, EvidenceKind::Ocsp, &update, &mut new, scope)?;
    }
    for bytes in services.material.crls {
        add_material(bytes, EvidenceKind::Crl, &update, &mut new, scope)?;
    }
    if update
        .parsed
        .material
        .len()
        .checked_add(new.len())
        .is_none_or(|n| n > services.limits.max_items)
    {
        return Err(PdfError::Limit("DSS evidence count"));
    }
    let mut transaction = PdfSignatureOutput::resume_checked(output, scope)?;
    transaction.append(b"\n")?;
    let mut next = update.plan.next;
    let mut offsets = BTreeMap::new();
    let mut certs = Vec::new();
    let mut ocsp = Vec::new();
    let mut crls = Vec::new();
    for item in &update.parsed.material {
        let refs = match item.kind {
            EvidenceKind::Certificate => &mut certs,
            EvidenceKind::Ocsp => &mut ocsp,
            EvidenceKind::Crl => &mut crls,
            _ => unreachable!(),
        };
        refs.push(Value::Ref(item.reference.0, item.reference.1));
    }
    for (kind, bytes) in new {
        if bytes.len() + 128 > limits.max_object_bytes
            || bytes.len() as u64 > services.limits.max_item_bytes
        {
            return Err(PdfError::Limit("DSS evidence stream"));
        }
        let id = next;
        next = next
            .checked_add(1)
            .ok_or(PdfError::Limit("object identifiers"))?;
        offsets.insert((id, 0), transaction.len());
        transaction
            .append(format!("{id} 0 obj\n<< /Length {} >>\nstream\n", bytes.len()).as_bytes())?;
        transaction.append(&bytes)?;
        transaction.append(b"\nendstream\nendobj\n")?;
        let refs = match kind {
            EvidenceKind::Certificate => &mut certs,
            EvidenceKind::Ocsp => &mut ocsp,
            EvidenceKind::Crl => &mut crls,
            _ => unreachable!(),
        };
        refs.push(Value::Ref(id, 0));
    }
    let mut vri_value = BTreeMap::new();
    for (key, refs) in [
        (b"Cert".as_slice(), &certs),
        (b"OCSP", &ocsp),
        (b"CRL", &crls),
    ] {
        if !refs.is_empty() {
            vri_value.insert(key.to_vec(), Value::Array(refs.clone()));
        }
    }
    let mut entries = std::mem::take(&mut update.parsed.vri);
    for key in update.parsed.keys.keys() {
        entries
            .entry(key.clone())
            .or_insert_with(|| Value::Dict(vri_value.clone()));
    }
    let vri = Value::Dict(entries);
    let vri_id = next;
    next = next
        .checked_add(1)
        .ok_or(PdfError::Limit("object identifiers"))?;
    offsets.insert(
        (vri_id, 0),
        crate::sign::object(&mut transaction, vri_id, 0, &vri, limits.max_object_bytes)?,
    );
    let mut dss = BTreeMap::from([
        (b"Type".to_vec(), Value::Name(b"DSS".to_vec())),
        (b"VRI".to_vec(), Value::Ref(vri_id, 0)),
    ]);
    for (key, refs) in [
        (b"Certs".as_slice(), certs),
        (b"OCSPs", ocsp),
        (b"CRLs", crls),
    ] {
        if !refs.is_empty() {
            dss.insert(key.to_vec(), Value::Array(refs));
        }
    }
    let dss_id = next;
    next = next
        .checked_add(1)
        .ok_or(PdfError::Limit("object identifiers"))?;
    offsets.insert(
        (dss_id, 0),
        crate::sign::object(
            &mut transaction,
            dss_id,
            0,
            &Value::Dict(dss),
            limits.max_object_bytes,
        )?,
    );
    if let Value::Dict(catalog) = &mut update.plan.catalog {
        catalog.insert(b"DSS".to_vec(), Value::Ref(dss_id, 0));
    }
    offsets.insert(
        update.plan.root,
        crate::sign::object(
            &mut transaction,
            update.plan.root.0,
            update.plan.root.1,
            &update.plan.catalog,
            limits.max_object_bytes,
        )?,
    );
    close_xref(&mut transaction, &update.plan, next, offsets, limits)?;
    transaction.finish_validation_update(scope)?;
    Ok(())
}
fn append_timestamp(
    output: &mut StagedArtifact,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    scope: &ResourceScope,
) -> Result<()> {
    let mut update = update_plan(output, limits, scope)?;
    let form = update.plan.next;
    let field = form
        .checked_add(1)
        .ok_or(PdfError::Limit("object identifiers"))?;
    let signature = form
        .checked_add(2)
        .ok_or(PdfError::Limit("object identifiers"))?;
    let xref = form
        .checked_add(3)
        .ok_or(PdfError::Limit("object identifiers"))?;
    if let Value::Dict(catalog) = &mut update.plan.catalog {
        catalog.insert(b"AcroForm".to_vec(), Value::Ref(form, 0));
    }
    if let Value::Dict(dict) = &mut update.plan.form
        && let Some(Value::Array(fields)) = dict.get_mut(b"Fields".as_slice())
    {
        fields.push(Value::Ref(field, 0));
    }
    let mut transaction = PdfSignatureOutput::resume_checked(output, scope)?;
    transaction.append(b"\n")?;
    let mut offsets = BTreeMap::new();
    offsets.insert(
        update.plan.root,
        crate::sign::object(
            &mut transaction,
            update.plan.root.0,
            update.plan.root.1,
            &update.plan.catalog,
            limits.max_object_bytes,
        )?,
    );
    offsets.insert(
        (form, 0),
        crate::sign::object(
            &mut transaction,
            form,
            0,
            &update.plan.form,
            limits.max_object_bytes,
        )?,
    );
    let value = Value::Dict(BTreeMap::from([
        (b"FT".to_vec(), Value::Name(b"Sig".to_vec())),
        (
            b"T".to_vec(),
            Value::Bytes(format!("ONCLTimestamp{signature}").into_bytes(), 0..0),
        ),
        (b"V".to_vec(), Value::Ref(signature, 0)),
    ]));
    offsets.insert(
        (field, 0),
        crate::sign::object(&mut transaction, field, 0, &value, limits.max_object_bytes)?,
    );
    offsets.insert((signature, 0), transaction.len());
    transaction.append(format!("{signature} 0 obj\n<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161").as_bytes())?;
    let reservation = PdfSignProfile::default().reserved_cms_bytes();
    if reservation
        .checked_mul(2)
        .and_then(|n| n.checked_add(512))
        .is_none_or(|n| n > limits.max_object_bytes)
    {
        return Err(PdfError::Limit("timestamp reservation"));
    }
    transaction.reserve_contents(reservation)?;
    transaction.append(b" >>\nendobj\n")?;
    close_xref(&mut transaction, &update.plan, xref, offsets, limits)?;
    transaction.finish_document_timestamp(services, scope)?;
    Ok(())
}
fn augment(
    level: AdesLevel,
    output: &mut StagedArtifact,
    limits: &PdfLimits,
    services: &AdesServices<'_>,
    allowed: &[SigAlg],
    scope: &ResourceScope,
) -> Result<()> {
    let old = verify_output(AdesLevel::B, output, limits, services, allowed, scope)?;
    let achieved = old
        .level()
        .ok_or(PdfError::Unsupported("no verified PAdES level"))?;
    if achieved < AdesLevel::T && level >= AdesLevel::T {
        append_timestamp(output, limits, services, scope)?;
        verify_output(AdesLevel::T, output, limits, services, allowed, scope)?;
    }
    if level >= AdesLevel::Lt {
        append_dss(output, limits, services, scope)?;
        verify_output(AdesLevel::Lt, output, limits, services, allowed, scope)?;
    }
    if level == AdesLevel::Lta {
        append_timestamp(output, limits, services, scope)?;
    }
    Ok(())
}
