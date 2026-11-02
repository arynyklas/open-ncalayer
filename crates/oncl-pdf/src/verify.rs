use crate::{
    ByteRange, PdfDocument, PdfError, PdfLimits, Result,
    objects::{Value, get},
};
use oncl_pki::{
    io::Source,
    key::SigAlg,
    resource::{ResourceReservation, ResourceScope},
    validation::{ValidationContext, ValidationReport, Verdict},
};
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct PdfSignature {
    pub byte_range: ByteRange,
    pub revision: usize,
    pub revision_end: u64,
    pub later_changes: bool,
    pub validation: ValidationReport,
}
/// Each signer retains its full F03 report for the protected revision. Overall
/// Valid additionally requires a signature covering the latest revision;
/// an unsigned later revision cannot inherit an earlier revision's Valid.
pub struct PdfVerification {
    pub verdict: Verdict,
    pub extent: u64,
    pub signatures: ScopedPdfRows<PdfSignature>,
}
impl std::fmt::Debug for PdfVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdfVerification")
            .field("verdict", &self.verdict)
            .field("extent", &self.extent)
            .field("signatures", &self.signatures)
            .finish()
    }
}
/// Owning immutable rows; storage cannot be separated from its operation guards.
pub struct ScopedPdfRows<T> {
    values: Vec<T>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl<T> std::ops::Deref for ScopedPdfRows<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl<T: std::fmt::Debug> std::fmt::Debug for ScopedPdfRows<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.values.fmt(f)
    }
}

#[derive(Debug)]
pub struct PdfSignatureFacts {
    pub byte_range: ByteRange,
    pub revision: usize,
    pub revision_end: u64,
    pub later_changes: bool,
    /// Index range into the aggregate validation report's scoped signers.
    pub signers: std::ops::Range<usize>,
}
pub struct PdfRevisionFacts {
    pub extent: u64,
    pub signatures: ScopedPdfRows<PdfSignatureFacts>,
}
impl std::fmt::Debug for PdfRevisionFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdfRevisionFacts")
            .field("extent", &self.extent)
            .field("signatures", &self.signatures)
            .finish()
    }
}
impl PdfVerification {
    /// Consume the per-signature reports without detaching their reservations.
    pub fn into_aggregate(
        self,
        scope: &ResourceScope,
    ) -> Result<(ValidationReport, PdfRevisionFacts)> {
        let ScopedPdfRows {
            values,
            _memory,
            _metadata,
        } = self.signatures;
        let mut reports = values.into_iter();
        let first = reports
            .next()
            .ok_or(PdfError::Malformed("empty signature report"))?;
        let mut facts = Vec::new();
        let mut aggregate = first.validation;
        facts.push(PdfSignatureFacts {
            byte_range: first.byte_range,
            revision: first.revision,
            revision_end: first.revision_end,
            later_changes: first.later_changes,
            signers: 0..aggregate.signers.len(),
        });
        for report in reports {
            let start = aggregate.signers.len();
            aggregate.signers.append(report.validation.signers, scope)?;
            facts.push(PdfSignatureFacts {
                byte_range: report.byte_range,
                revision: report.revision,
                revision_end: report.revision_end,
                later_changes: report.later_changes,
                signers: start..aggregate.signers.len(),
            });
        }
        aggregate.verdict = self.verdict;
        Ok((
            aggregate,
            PdfRevisionFacts {
                extent: self.extent,
                signatures: ScopedPdfRows {
                    values: facts,
                    _memory,
                    _metadata,
                },
            },
        ))
    }
}
struct Candidate {
    range: ByteRange,
    contents: oncl_pki::io::Region,
}
impl PdfDocument<'_, '_> {
    fn signature_candidates(
        &mut self,
        revision: usize,
        known: &BTreeSet<[u64; 4]>,
    ) -> Result<Vec<Candidate>> {
        let root = self.revisions[revision].root.clone();
        let catalog = self.resolve(revision, &root)?;
        let dict = catalog.dict()?;
        if !get(dict, b"Type")?.name(b"Catalog") {
            return Err(PdfError::Malformed("catalog type"));
        }
        let Some(form) = dict.get(b"AcroForm".as_slice()) else {
            return Ok(Vec::new());
        };
        let form = self.resolve(revision, form)?;
        let fields = get(form.dict()?, b"Fields")?.clone();
        let fields = self.resolve(revision, &fields)?;
        let mut stack: Vec<(Value, bool, usize)> = fields
            .array()?
            .iter()
            .cloned()
            .map(|v| (v, false, 0))
            .collect();
        let mut seen = BTreeSet::new();
        let mut visited = 0;
        let mut result = Vec::new();
        while let Some((field, inherited_sig, depth)) = stack.pop() {
            self.scope.checkpoint()?;
            visited += 1;
            if visited > self.limits.max_objects || depth > self.limits.max_depth {
                return Err(PdfError::Limit("field traversal"));
            }
            if let Value::Ref(id, generation) = field
                && !seen.insert((id, generation))
            {
                return Err(PdfError::Malformed("field cycle or alias"));
            }
            let field = self.resolve(revision, &field)?;
            let field = field.dict()?;
            let sig = field
                .get(b"FT".as_slice())
                .map_or(inherited_sig, |v| v.name(b"Sig"));
            if let Some(kids) = field.get(b"Kids".as_slice()) {
                let kids = self.resolve(revision, kids)?;
                for kid in kids.array()? {
                    if stack.len() >= self.limits.max_objects {
                        return Err(PdfError::Limit("field breadth"));
                    }
                    stack.push((kid.clone(), sig, depth + 1));
                }
            }
            if !sig {
                continue;
            }
            let Some(value) = field.get(b"V".as_slice()) else {
                continue;
            };
            let signature = self.resolve(revision, value)?;
            let dict = signature.dict()?;
            if dict
                .get(b"Type".as_slice())
                .is_some_and(|v| !v.name(b"Sig"))
            {
                return Err(PdfError::Malformed("signature dictionary type"));
            }
            let subfilter = get(dict, b"SubFilter")?;
            if !subfilter.name(b"adbe.pkcs7.detached") && !subfilter.name(b"ETSI.CAdES.detached") {
                return Err(PdfError::Unsupported("signature SubFilter"));
            }
            let numbers = get(dict, b"ByteRange")?.array()?;
            if numbers.len() != 4 {
                return Err(PdfError::Unsupported("ByteRange region count"));
            }
            let range = ByteRange::new(
                [
                    numbers[0].int()?,
                    numbers[1].int()?,
                    numbers[2].int()?,
                    numbers[3].int()?,
                ],
                self.input.extent,
            )?;
            let Value::Bytes(contents, span) = get(dict, b"Contents")? else {
                return Err(PdfError::Malformed("Contents string"));
            };
            if range.gap() != *span {
                return Err(PdfError::Malformed(
                    "ByteRange must exclude exactly Contents token",
                ));
            }
            // The signature must be reachable in the revision it actually protects.
            // Historical copies in later revisions are not new signatures.
            if range.signed_end() != self.revisions[revision].end {
                if known.contains(&range.values()) {
                    continue;
                }
                return Err(PdfError::Malformed(
                    "signature not reachable in protected revision",
                ));
            }
            let token = self.input.read_at(
                span.start,
                usize::try_from(span.end - span.start)
                    .map_err(|_| PdfError::Limit("Contents token"))?,
                self.scope,
            )?;
            let mut p = self.parser(&token, span.start);
            let physical = p.value(0)?;
            if !matches!(&physical,Value::Bytes(actual,actual_span) if actual==contents&&actual_span==span)
            {
                return Err(PdfError::Malformed("nonphysical Contents token"));
            }
            canonical_cms(contents)?;
            if result.len() >= self.limits.max_signatures {
                return Err(PdfError::Limit("signature count"));
            }
            result.push(Candidate {
                range,
                contents: oncl_pki::io::Region {
                    offset: span.start,
                    len: span.end - span.start,
                },
            });
        }
        Ok(result)
    }
}
fn canonical_cms(contents: &[u8]) -> Result<&[u8]> {
    if contents.first() != Some(&0x30) {
        return Err(PdfError::Malformed("Contents CMS sequence"));
    }
    let first = *contents.get(1).ok_or(PdfError::Malformed("CMS length"))?;
    let (header, length) = if first < 128 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > 8 || contents.get(2) == Some(&0) {
            return Err(PdfError::Malformed("CMS DER length"));
        }
        let mut n = 0usize;
        for b in contents
            .get(2..2 + count)
            .ok_or(PdfError::Malformed("CMS length"))?
        {
            n = n
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*b)))
                .ok_or(PdfError::Limit("CMS length"))?;
        }
        if n < 128 {
            return Err(PdfError::Malformed("noncanonical CMS length"));
        }
        (2 + count, n)
    };
    let end = header
        .checked_add(length)
        .ok_or(PdfError::Limit("CMS length"))?;
    let cms = contents
        .get(..end)
        .ok_or(PdfError::Malformed("truncated CMS"))?;
    if contents[end..].iter().any(|b| *b != 0) {
        return Err(PdfError::Malformed("nonzero Contents padding"));
    }
    Ok(cms)
}
pub fn verify_source(
    input: Source<'_>,
    limits: &PdfLimits,
    store: &oncl_pki::io::TemporaryStore,
    validation: &ValidationContext<'_>,
    allowed: &[SigAlg],
    scope: &mut ResourceScope,
) -> Result<PdfVerification> {
    use oncl_pki::io::{FrozenInput, Region};
    let report_bytes = (limits.max_signatures.max(4) as u64)
        .checked_mul(1024)
        .ok_or(oncl_pki::resource::ProcessingError::MetadataLimit)?;
    let memory = scope.reserve_memory(report_bytes)?;
    let metadata = scope.reserve_metadata(report_bytes)?;
    let mut snapshot = FrozenInput::capture(input, store, scope)?;
    let extent = snapshot.len();
    let mut reader = snapshot.reader(
        &[Region {
            offset: 0,
            len: extent,
        }],
        scope,
    )?;
    let candidates = (|| {
        let mut doc = PdfDocument::open(reader.source(), limits, scope)?;
        let mut candidates = Vec::new();
        let mut seen = BTreeSet::new();
        for revision in 0..doc.revisions.len() {
            for candidate in doc.signature_candidates(revision, &seen)? {
                if !seen.insert(candidate.range.values()) {
                    continue;
                }
                if candidates.len() >= limits.max_signatures {
                    return Err(PdfError::Limit("signature count"));
                }
                candidates.push((revision, candidate));
            }
        }
        Ok(candidates)
    })();
    reader.finish()?;
    drop(reader);
    let mut signatures = Vec::new();
    for (revision, candidate) in candidates? {
        let scratch = candidate
            .contents
            .len
            .checked_mul(2)
            .ok_or(oncl_pki::resource::ProcessingError::MemoryLimit)?;
        let _decode_memory = scope.reserve_memory(scratch)?;
        let _decode_metadata = scope.reserve_metadata(scratch)?;
        let decoded = snapshot.derive_region(candidate.contents, scope, |encoded, output| {
            let mut parser = crate::objects::Parser::new(
                encoded,
                candidate.contents.offset,
                limits.max_nodes,
                limits.max_depth,
            );
            let Value::Bytes(bytes, _) = parser.value(0).map_err(|_| {
                oncl_pki::resource::ProcessingError::InvalidInput("Contents decoding")
            })?
            else {
                return Err(oncl_pki::resource::ProcessingError::InvalidInput(
                    "Contents string",
                ));
            };
            let cms = canonical_cms(&bytes).map_err(|_| {
                oncl_pki::resource::ProcessingError::InvalidInput("Contents DER padding")
            })?;
            output.write_all(cms)?;
            Ok(())
        })?;
        let [offset, len, second, last] = candidate.range.values();
        let report = oncl_pki::cms::stream::verify_snapshot_detached(
            &decoded,
            &mut snapshot,
            &[
                Region { offset, len },
                Region {
                    offset: second,
                    len: last,
                },
            ],
            validation,
            allowed,
            scope,
        )?;
        signatures.push(PdfSignature {
            byte_range: candidate.range,
            revision,
            revision_end: candidate.range.signed_end(),
            later_changes: candidate.range.signed_end() < extent,
            validation: report,
        });
    }
    if signatures.is_empty() {
        return Err(PdfError::Unsupported(
            "no supported revision-bound signature",
        ));
    }
    let verdict = if signatures
        .iter()
        .any(|s| s.validation.verdict == Verdict::Invalid)
    {
        Verdict::Invalid
    } else if signatures
        .iter()
        .all(|s| s.validation.verdict == Verdict::Valid)
        && signatures
            .iter()
            .any(|signature| signature.revision_end == extent)
    {
        Verdict::Valid
    } else {
        Verdict::Indeterminate
    };
    Ok(PdfVerification {
        verdict,
        extent,
        signatures: ScopedPdfRows {
            values: signatures,
            _memory: memory,
            _metadata: metadata,
        },
    })
}
