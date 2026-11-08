//! Incremental, invisible detached CMS signatures. Original bytes are immutable.
use crate::{
    PdfDocument, PdfError, PdfLimits, Result,
    objects::{Value, get},
};
use oncl_pki::{
    cms::stream::{CmsSignServices, SignSummary},
    io::{PdfSignatureOutput, Region, Source, StagedArtifact},
    key::DigestSigner,
    resource::{IO_CHUNK_BYTES, ResourceScope},
    validation::Verdict,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct PdfSignProfile {
    pub limits: PdfLimits,
    reserved_cms_bytes: usize,
    pub(crate) allowed: &'static [oncl_pki::key::SigAlg],
}
impl Default for PdfSignProfile {
    fn default() -> Self {
        Self {
            limits: PdfLimits::default(),
            reserved_cms_bytes: 16384,
            allowed: &[
                oncl_pki::key::SigAlg::RsaSha256,
                oncl_pki::key::SigAlg::RsaSha1,
                oncl_pki::key::SigAlg::Gost2004,
                oncl_pki::key::SigAlg::Gost2015_512,
            ],
        }
    }
}
impl PdfSignProfile {
    pub fn new(reserved_cms_bytes: usize) -> Result<Self> {
        if reserved_cms_bytes == 0
            || reserved_cms_bytes > 16 * 1024 * 1024
            || reserved_cms_bytes.checked_mul(2).is_none()
        {
            return Err(PdfError::Limit("invalid CMS reservation"));
        }
        Ok(Self {
            reserved_cms_bytes,
            ..Self::default()
        })
    }
    pub fn reserved_cms_bytes(&self) -> usize {
        self.reserved_cms_bytes
    }
    pub fn with_allowed_algorithms(mut self, allowed: &'static [oncl_pki::key::SigAlg]) -> Self {
        self.allowed = allowed;
        self
    }
}
pub type PdfOperationReport = SignSummary;
pub(crate) struct Plan {
    pub(crate) root: (u32, u16),
    pub(crate) catalog: Value,
    pub(crate) form: Value,
    pub(crate) next: u32,
    pub(crate) previous: u64,
    pub(crate) extras: BTreeMap<Vec<u8>, Value>,
    pub(crate) signed: bool,
}
pub(crate) fn plan(doc: &mut PdfDocument<'_, '_>, pades: bool) -> Result<Plan> {
    let revision = doc.revisions.len() - 1;
    if doc.revisions.len() >= doc.limits.max_revisions {
        return Err(PdfError::Limit("revision count"));
    }
    let root = doc.revisions[revision].root.clone();
    let Value::Ref(id, generation) = root else {
        return Err(PdfError::Malformed("root reference"));
    };
    let mut catalog = doc.resolve(revision, &root)?;
    let dictionary = catalog.dict()?;
    if !get(dictionary, b"Type")?.name(b"Catalog") {
        return Err(PdfError::Malformed("catalog type"));
    }
    if dictionary.contains_key(b"Perms".as_slice()) {
        return Err(PdfError::Unsupported("certification signature permissions"));
    }
    let mut form = match dictionary.get(b"AcroForm".as_slice()) {
        Some(v) => doc.resolve(revision, v)?,
        None => Value::Dict(BTreeMap::new()),
    };
    if form.dict()?.contains_key(b"XFA".as_slice()) {
        return Err(PdfError::Unsupported("XFA form"));
    }
    let fields = match form.dict()?.get(b"Fields".as_slice()) {
        Some(v) => doc.resolve(revision, v)?,
        None => Value::Array(Vec::new()),
    };
    fields.array()?;
    if fields.array()?.len() >= doc.limits.max_objects {
        return Err(PdfError::Limit("field count"));
    }
    let flags = form
        .dict()?
        .get(b"SigFlags".as_slice())
        .map(Value::int)
        .transpose()?
        .unwrap_or(0)
        | 3;
    if let Value::Dict(d) = &mut form {
        d.insert(b"Fields".to_vec(), fields);
        d.insert(b"SigFlags".to_vec(), Value::Int(flags));
    }
    let header = doc.input.read_at(0, 8, doc.scope)?;
    let version = if header == b"%PDF-2.0" {
        b"2.0".to_vec()
    } else {
        match catalog.dict()?.get(b"Version".as_slice()) {
            Some(Value::Name(v)) if matches!(v.as_slice(), b"1.5" | b"1.6" | b"1.7" | b"2.0") => {
                v.clone()
            }
            None => b"1.7".to_vec(),
            Some(Value::Name(v))
                if matches!(v.as_slice(), b"1.0" | b"1.1" | b"1.2" | b"1.3" | b"1.4") =>
            {
                b"1.7".to_vec()
            }
            _ => return Err(PdfError::Unsupported("catalog version")),
        }
    };
    if let Value::Dict(d) = &mut catalog {
        d.insert(b"Version".to_vec(), Value::Name(version));
    }
    let mut next = 0u64;
    let mut extras = BTreeMap::new();
    for r in &doc.revisions {
        next = next.max(get(&r.trailer, b"Size")?.int()?);
        for k in [b"Info".as_slice(), b"ID".as_slice()] {
            if let Some(v) = r.trailer.get(k) {
                extras.insert(k.to_vec(), v.clone());
            }
        }
        if let Some(highest) = r.entries.max_id() {
            next = next.max(u64::from(highest) + 1);
        }
    }
    let next = u32::try_from(next).map_err(|_| PdfError::Limit("object identifiers"))?;
    next.checked_add(4)
        .ok_or(PdfError::Limit("object identifiers"))?;
    let field_name = format!("ONCLSignature{}", next + 2).into_bytes();
    for field in get(form.dict()?, b"Fields")?.array()? {
        let field = doc.resolve(revision, field)?;
        if let Some(name) = field.dict()?.get(b"T".as_slice()) {
            let name = doc.resolve(revision, name)?;
            if matches!(name,Value::Bytes(bytes,_) if bytes==field_name) {
                return Err(PdfError::Unsupported("new signature field name collision"));
            }
        }
    }
    let previous = doc.revisions[revision].xref;
    let signed = doc.has_signatures_mode(pades)?;
    Ok(Plan {
        root: (id, generation),
        catalog,
        form,
        next,
        previous,
        extras,
        signed,
    })
}
pub(crate) fn name(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for b in bytes {
        out.push(b'#');
        out.push(b"0123456789ABCDEF"[(b >> 4) as usize]);
        out.push(b"0123456789ABCDEF"[(b & 15) as usize]);
    }
}
pub(crate) fn encode(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Ref(n, g) => out.extend_from_slice(format!("{n} {g} R").as_bytes()),
        Value::Name(n) => name(n, out),
        Value::Bytes(bytes, _) => {
            out.push(b'<');
            for b in bytes {
                out.push(b"0123456789ABCDEF"[(b >> 4) as usize]);
                out.push(b"0123456789ABCDEF"[(b & 15) as usize]);
            }
            out.push(b'>');
        }
        Value::Scalar(bytes) => out.extend_from_slice(bytes),
        Value::Array(values) => {
            out.push(b'[');
            for value in values {
                encode(value, out)?;
                out.push(b' ');
            }
            out.push(b']');
        }
        Value::Dict(values) => {
            out.extend_from_slice(b"<<");
            for (k, v) in values {
                name(k, out);
                out.push(b' ');
                encode(v, out)?;
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
        }
        Value::Other => return Err(PdfError::Unsupported("unrepresentable PDF object")),
    }
    Ok(())
}
pub(crate) fn object(
    output: &mut PdfSignatureOutput<'_>,
    id: u32,
    generation: u16,
    value: &Value,
    limit: usize,
) -> Result<u64> {
    let mut bytes = Vec::new();
    encode(value, &mut bytes)?;
    if bytes.len() > limit {
        return Err(PdfError::Limit("updated object size"));
    }
    let offset = output.len();
    output.append(format!("{id} {generation} obj\n").as_bytes())?;
    output.append(&bytes)?;
    output.append(b"\nendobj\n")?;
    Ok(offset)
}
/// Adds one signature to an existing PDF; no input source is mutated. Existing
/// signatures must all validate, with latest-revision coverage, before any use.
/// Failure leaves the OUTPUT stage poisoned and therefore unpublishable.
pub fn sign_source(
    input: Source<'_>,
    profile: &PdfSignProfile,
    signer: &mut dyn DigestSigner,
    services: &CmsSignServices<'_>,
    staged_output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<PdfOperationReport> {
    sign_impl(input, profile, signer, services, staged_output, scope, None)
}
pub(crate) fn sign_pades_source(
    level: oncl_pki::evidence::AdesLevel,
    input: Source<'_>,
    profile: &PdfSignProfile,
    signer: &mut dyn DigestSigner,
    services: &oncl_pki::cms::ades::AdesServices<'_>,
    staged_output: &mut StagedArtifact,
    scope: &ResourceScope,
) -> Result<PdfOperationReport> {
    let cms = CmsSignServices::new(Some(services.validation), Some(services.temporary));
    sign_impl(
        input,
        profile,
        signer,
        &cms,
        staged_output,
        scope,
        Some((level, services)),
    )
}
fn sign_impl(
    input: Source<'_>,
    profile: &PdfSignProfile,
    signer: &mut dyn DigestSigner,
    services: &CmsSignServices<'_>,
    staged_output: &mut StagedArtifact,
    scope: &ResourceScope,
    pades: Option<(
        oncl_pki::evidence::AdesLevel,
        &oncl_pki::cms::ades::AdesServices<'_>,
    )>,
) -> Result<PdfOperationReport> {
    // This precheck and poisoning borrow precede intake and private key use.
    let mut output = PdfSignatureOutput::new(staged_output, scope)?;
    if !profile.allowed.contains(&signer.algorithm()) {
        return Err(PdfError::Unsupported("signer algorithm disallowed"));
    }
    if profile
        .reserved_cms_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(512))
        .is_none_or(|n| n > profile.limits.max_object_bytes)
    {
        return Err(PdfError::Limit(
            "CMS reservation exceeds signature object reader limit",
        ));
    }
    let before = scope.progress();
    let mut operation = scope.shared_view();
    let size = crate::budget::sign_reservation(&profile.limits)?;
    let metadata = crate::budget::sign_metadata(&profile.limits)?;
    let _memory = scope.reserve_memory(size)?;
    let _metadata = scope.reserve_metadata(metadata)?;
    let store = services
        .temporary()
        .ok_or(oncl_pki::cms::stream::StreamError::MissingTemporaryStore)?;
    let mut snapshot =
        crate::verify::capture_signed(input, store, &profile.limits, &mut operation)?;
    let length = snapshot.len();
    let mut reader = snapshot.reader(
        &[Region {
            offset: 0,
            len: length,
        }],
        scope,
    )?;
    let result = (|| {
        let mut doc = PdfDocument::open(reader.source(), &profile.limits, &mut operation)?;
        plan(&mut doc, pades.is_some())
    })();
    reader.finish()?;
    drop(reader);
    let mut plan = result?;
    if plan.signed {
        let validation = services.validation().ok_or(PdfError::Unsupported(
            "Add requires host validation services",
        ))?;
        let verdict = if let Some((_, ades)) = pades {
            crate::ades::verify_frozen(
                oncl_pki::evidence::AdesLevel::B,
                &mut snapshot,
                &profile.limits,
                ades,
                profile.allowed,
                &mut operation,
            )?
            .verdict
        } else {
            crate::verify::verify_snapshot(
                &mut snapshot,
                &profile.limits,
                validation,
                profile.allowed,
                &mut operation,
            )?
            .verdict
        };
        if verdict != Verdict::Valid {
            return Err(PdfError::Unsupported(
                "all existing signatures and latest revision must validate before Add",
            ));
        }
    }
    // Admission includes temporary serialized catalog/form and hex expansion;
    // the document itself is copied only chunkwise, never into a heap DOM.
    let _chunk = scope.reserve_memory(IO_CHUNK_BYTES as u64)?;
    let mut buffer = vec![0; IO_CHUNK_BYTES];
    let mut position = 0;
    while position < length {
        scope.checkpoint()?;
        let n = snapshot.read_region(
            Region {
                offset: position,
                len: length - position,
            },
            &mut buffer,
        )?;
        if n == 0 {
            return Err(PdfError::Malformed("snapshot truncated"));
        }
        output.append(&buffer[..n])?;
        position += n as u64;
    }
    output.append(b"\n")?;
    let form_id = plan.next;
    let field_id = form_id + 1;
    let signature_id = form_id + 2;
    let xref_id = form_id + 3;
    let size = xref_id
        .checked_add(1)
        .ok_or(PdfError::Limit("object identifiers"))?;
    if let Value::Dict(d) = &mut plan.catalog {
        d.insert(b"AcroForm".to_vec(), Value::Ref(form_id, 0));
    }
    if let Value::Dict(d) = &mut plan.form
        && let Some(Value::Array(fields)) = d.get_mut(b"Fields".as_slice())
    {
        fields.push(Value::Ref(field_id, 0));
    }
    let mut offsets = BTreeMap::new();
    offsets.insert(
        plan.root,
        object(
            &mut output,
            plan.root.0,
            plan.root.1,
            &plan.catalog,
            profile.limits.max_object_bytes,
        )?,
    );
    offsets.insert(
        (form_id, 0),
        object(
            &mut output,
            form_id,
            0,
            &plan.form,
            profile.limits.max_object_bytes,
        )?,
    );
    let field = Value::Dict(BTreeMap::from([
        (b"FT".to_vec(), Value::Name(b"Sig".to_vec())),
        (
            b"T".to_vec(),
            Value::Bytes(format!("ONCLSignature{signature_id}").into_bytes(), 0..0),
        ),
        (b"V".to_vec(), Value::Ref(signature_id, 0)),
    ]));
    offsets.insert(
        (field_id, 0),
        object(
            &mut output,
            field_id,
            0,
            &field,
            profile.limits.max_object_bytes,
        )?,
    );
    offsets.insert((signature_id, 0), output.len());
    if let Some((_, services)) = pades {
        let at = services.validation.now;
        output.append(format!("{signature_id} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M (D:{:04}{:02}{:02}{:02}{:02}{:02}Z)", at.year(), u8::from(at.month()), at.day(), at.hour(), at.minute(), at.second()).as_bytes())?;
    } else {
        output.append(format!("{signature_id} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached").as_bytes())?;
    }
    output.reserve_contents(profile.reserved_cms_bytes)?;
    output.append(b" >>\nendobj\n")?;
    // Always use an 8-byte xref offset field: valid past ten decimal digits.
    let xref = output.len();
    offsets.insert((xref_id, 0), xref);
    let mut index = String::new();
    let mut rows = Vec::new();
    for ((id, generation), offset) in offsets {
        index.push_str(&format!("{id} 1 "));
        rows.extend_from_slice(&xref_entry(offset, generation));
    }
    output.append(format!("{xref_id} 0 obj\n<< /Type /XRef /Size {size} /Root {} {} R /Prev {} /W [1 8 2] /Index [{index}] /Length {} ",plan.root.0,plan.root.1,plan.previous,rows.len()).as_bytes())?;
    let mut extras = Vec::new();
    for (key, value) in plan.extras {
        name(&key, &mut extras);
        extras.push(b' ');
        encode(&value, &mut extras)?;
        extras.push(b' ');
    }
    if (output.len() - xref)
        .checked_add(extras.len() as u64)
        .and_then(|n| n.checked_add(rows.len() as u64))
        .and_then(|n| n.checked_add(64))
        .is_none_or(|n| n > profile.limits.max_object_bytes as u64)
    {
        return Err(PdfError::Limit("incremental xref object size"));
    }
    output.append(&extras)?;
    output.append(b">>\nstream\n")?;
    output.append(&rows)?;
    output.append(format!("\nendstream\nendobj\nstartxref\n{xref}\n%%EOF\n").as_bytes())?;
    let mut report = match pades {
        Some((level, ades)) if level >= oncl_pki::evidence::AdesLevel::T => {
            output.finish_pades(signer, services, ades, scope)?
        }
        _ => output.finish(signer, services, scope)?,
    };
    report.bytes_in = scope.progress().bytes_in - before.bytes_in;
    Ok(report)
}

pub(crate) fn xref_entry(offset: u64, generation: u16) -> [u8; 11] {
    let mut row = [0; 11];
    row[0] = 1;
    row[1..9].copy_from_slice(&offset.to_be_bytes());
    row[9..].copy_from_slice(&generation.to_be_bytes());
    row
}

#[cfg(test)]
mod tests {
    #[test]
    // Offsets beyond ten decimal digits (about 9.3 GiB) are beyond the 1 GiB document
    // guarantee; u64 offset arithmetic still has to be correct.
    fn xref_stream_offsets_beyond_ten_decimal_digits_are_u64() {
        // Arithmetic-only boundary; not a 1-GiB document/RSS claim (10_737_418_240 is just an offset above ten decimal digits).
        for offset in [(1u64 << 32) + 17, 10_737_418_240, u64::MAX] {
            let row = super::xref_entry(offset, 65534);
            assert_eq!(row[0], 1);
            assert_eq!(u64::from_be_bytes(row[1..9].try_into().unwrap()), offset);
            assert_eq!(u16::from_be_bytes(row[9..11].try_into().unwrap()), 65534);
        }
    }
}
