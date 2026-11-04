use crate::{
    C14n, C14nProfile, XmlLimits,
    canonical_writer::{Attribute, CanonicalWriter},
    reader::{Reader, XmlEventKind},
};
use oncl_pki::{
    io::{CapturedInput, Region},
    resource::{IO_CHUNK_BYTES, ProcessingError, ResourceScope},
};
use std::{io::Write, sync::Arc};
type Result<T, E = ProcessingError> = std::result::Result<T, E>;
struct Output<'a> {
    sink: &'a mut dyn Write,
    scope: &'a ResourceScope,
    error: Option<ProcessingError>,
}
impl Write for Output<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Err(error) = self
            .scope
            .checkpoint()
            .and_then(|_| self.scope.account_output(bytes.len() as u64))
        {
            self.error = Some(error);
            return Err(std::io::Error::other("canonical output quota/control"));
        }
        self.sink.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}
pub(crate) struct Options<'a> {
    pub target: Option<Region>,
    pub method: C14n,
    pub profile: C14nProfile,
    pub prefixes: &'a [String],
    pub excluded: &'a [Region],
    pub metadata_limit: Option<u64>,
}
struct RenderOutput<'a> {
    sink: &'a mut dyn Write,
    projections: Option<&'a mut Vec<Region>>,
    wsu_id: Option<(&'a str, &'a str)>,
}
pub(crate) fn run(
    source: &mut dyn CapturedInput,
    limits: &XmlLimits,
    owner: &Arc<()>,
    options: Options<'_>,
    sink: &mut dyn Write,
    scope: &mut ResourceScope,
) -> Result<()> {
    let mut output = Output {
        sink,
        scope,
        error: None,
    };
    let mut work = limits.max_work;
    let result = render(
        source,
        limits,
        owner,
        options,
        RenderOutput {
            sink: &mut output,
            projections: None,
            wsu_id: None,
        },
        scope,
        &mut work,
    );
    match output.error {
        Some(error) => Err(error),
        None => result,
    }
}
pub(crate) fn hash(
    source: &mut dyn CapturedInput,
    limits: &XmlLimits,
    owner: &Arc<()>,
    options: Options<'_>,
    algorithm: oncl_pki::key::HashAlg,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<oncl_pki::digest::DigestValue> {
    struct Sink {
        state: oncl_pki::digest::HashState,
        remaining: Option<u64>,
        error: Option<ProcessingError>,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if let Some(remaining) = &mut self.remaining {
                let Some(next) = remaining.checked_sub(bytes.len() as u64) else {
                    self.error = Some(ProcessingError::MetadataLimit);
                    return Err(std::io::Error::other("canonical metadata limit"));
                };
                *remaining = next;
            }
            self.state.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink {
        state: oncl_pki::digest::HashState::new(algorithm),
        remaining: options.metadata_limit,
        error: None,
    };
    let result = render(
        source,
        limits,
        owner,
        options,
        RenderOutput {
            sink: &mut sink,
            projections: None,
            wsu_id: None,
        },
        scope,
        work,
    );
    if let Some(error) = sink.error {
        return Err(error);
    }
    result?;
    Ok(sink.state.finish())
}
pub(crate) fn append(
    source: &mut dyn CapturedInput,
    limits: &XmlLimits,
    owner: &Arc<()>,
    options: Options<'_>,
    artifact: &mut oncl_pki::io::StagedArtifact,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<()> {
    append_with_wsu_id(
        source,
        limits,
        owner,
        (options, None),
        artifact,
        scope,
        work,
    )
}
pub(crate) fn append_with_wsu_id(
    source: &mut dyn CapturedInput,
    limits: &XmlLimits,
    owner: &Arc<()>,
    options: (Options<'_>, Option<(&str, &str)>),
    artifact: &mut oncl_pki::io::StagedArtifact,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<()> {
    let (options, wsu_id) = options;
    struct Sink<'a> {
        stage: &'a mut oncl_pki::io::StagedArtifact,
        error: Option<ProcessingError>,
    }
    impl Write for Sink<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if let Err(error) = self.stage.write_chunk(bytes) {
                self.error = Some(error);
                return Err(std::io::Error::other("canonical source stage"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink {
        stage: artifact,
        error: None,
    };
    let result = render(
        source,
        limits,
        owner,
        options,
        RenderOutput {
            sink: &mut sink,
            projections: None,
            wsu_id,
        },
        scope,
        work,
    );
    sink.error.map_or(result, Err)
}
pub(crate) fn stage(
    source: &mut dyn CapturedInput,
    limits: &XmlLimits,
    owner: &Arc<()>,
    options: Options<'_>,
    store: &oncl_pki::io::TemporaryStore,
    scope: &mut ResourceScope,
    work: &mut u64,
) -> Result<(oncl_pki::io::StagedArtifact, Vec<Region>)> {
    struct Sink<'a> {
        artifact: &'a mut oncl_pki::io::StagedArtifact,
        remaining: u64,
        error: Option<ProcessingError>,
    }
    impl Write for Sink<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let Some(remaining) = self.remaining.checked_sub(bytes.len() as u64) else {
                self.error = Some(ProcessingError::MetadataLimit);
                return Err(std::io::Error::other("canonical proof metadata limit"));
            };
            self.remaining = remaining;
            if let Err(error) = self.artifact.write_chunk(bytes) {
                self.error = Some(error);
                return Err(std::io::Error::other("canonical proof staging"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let remaining = options
        .metadata_limit
        .ok_or(ProcessingError::InvalidLimits)?;
    let mut artifact = store.stage_source(scope)?;
    let mut sink = Sink {
        artifact: &mut artifact,
        remaining,
        error: None,
    };
    let mut projections = Vec::new();
    let result = render(
        source,
        limits,
        owner,
        options,
        RenderOutput {
            sink: &mut sink,
            projections: Some(&mut projections),
            wsu_id: None,
        },
        scope,
        work,
    );
    if let Some(error) = sink.error {
        return Err(error);
    }
    result?;
    Ok((artifact, projections))
}
// Validated lexical references are at most 37 bytes; decoding never grows a span.
fn entity(bytes: &[u8]) -> Result<char> {
    Ok(match bytes {
        b"amp" => '&',
        b"lt" => '<',
        b"gt" => '>',
        b"quot" => '"',
        b"apos" => '\'',
        _ => {
            let value =
                std::str::from_utf8(bytes).map_err(|_| ProcessingError::InvalidInput("entity"))?;
            let (digits, radix) = if let Some(v) = value.strip_prefix("#x") {
                (v, 16)
            } else {
                (
                    value
                        .strip_prefix('#')
                        .ok_or(ProcessingError::InvalidInput("entity"))?,
                    10,
                )
            };
            char::from_u32(
                u32::from_str_radix(digits, radix)
                    .map_err(|_| ProcessingError::InvalidInput("entity"))?,
            )
            .ok_or(ProcessingError::InvalidInput("entity"))?
        }
    })
}
struct Decoder {
    input: Vec<u8>,
    normalized: Vec<u8>,
}
impl Decoder {
    fn new() -> Self {
        Self {
            input: vec![0; IO_CHUNK_BYTES],
            normalized: Vec::with_capacity(IO_CHUNK_BYTES),
        }
    }
    fn write<V: Clone>(
        &mut self,
        source: &mut dyn CapturedInput,
        region: Region,
        out: &mut CanonicalWriter<'_, V>,
        attribute: bool,
        entities: bool,
        escape: bool,
    ) -> Result<()> {
        let mut at = 0;
        let mut reference = [0; 37];
        let mut reference_len = 0;
        let mut in_reference = false;
        let mut cr = false;
        self.normalized.clear();
        while at < region.len {
            let n = source.read_region(
                Region {
                    offset: region.offset + at,
                    len: region.len - at,
                },
                &mut self.input,
            )?;
            if n == 0 {
                return Err(ProcessingError::InvalidInput("short canonical span"));
            }
            at += n as u64;
            for &b in &self.input[..n] {
                if in_reference {
                    if b == b';' {
                        let c = entity(&reference[..reference_len])?;
                        let mut encoded = [0; 4];
                        self.normalized
                            .extend_from_slice(c.encode_utf8(&mut encoded).as_bytes());
                        reference_len = 0;
                        in_reference = false;
                    } else {
                        if reference_len == reference.len() {
                            return Err(ProcessingError::InvalidInput("entity"));
                        }
                        reference[reference_len] = b;
                        reference_len += 1;
                        continue;
                    }
                } else {
                    if cr {
                        cr = false;
                        if b == b'\n' {
                            continue;
                        }
                    }
                    if entities && b == b'&' {
                        in_reference = true;
                        continue;
                    }
                    let b = if b == b'\r' {
                        cr = true;
                        if attribute { b' ' } else { b'\n' }
                    } else if attribute && matches!(b, b'\n' | b'\t') {
                        b' '
                    } else {
                        b
                    };
                    self.normalized.push(b);
                }
                if self.normalized.len() >= IO_CHUNK_BYTES - 4 {
                    if escape {
                        out.escaped(&self.normalized, attribute)?;
                    } else {
                        out.put(&self.normalized)?;
                    }
                    self.normalized.clear();
                }
            }
        }
        if in_reference {
            return Err(ProcessingError::InvalidInput("unterminated entity"));
        }
        if escape {
            out.escaped(&self.normalized, attribute)
        } else {
            out.put(&self.normalized)
        }
    }
}
#[derive(Clone)]
enum AttributeValue {
    Source(Region),
    Literal(String),
}
fn render(
    source: &mut dyn CapturedInput,
    limits: &XmlLimits,
    owner: &Arc<()>,
    options: Options<'_>,
    output: RenderOutput<'_>,
    scope: &ResourceScope,
    work: &mut u64,
) -> Result<()> {
    let RenderOutput {
        sink,
        mut projections,
        wsu_id,
    } = output;
    let Options {
        target,
        method,
        profile,
        prefixes,
        excluded,
        ..
    } = options;
    *work = work
        .checked_sub(source.len())
        .ok_or(ProcessingError::InvalidInput("canonical work limit"))?;
    // Authenticate scope without exporting a permit or cloned scope.
    drop(source.reader(&[], scope)?);
    let _memory = scope.reserve_memory(2 * IO_CHUNK_BYTES as u64)?;
    let _metadata = scope.reserve_metadata(512 * 1024)?;
    let mut out = CanonicalWriter::<AttributeValue>::new(
        sink,
        method,
        profile,
        prefixes,
        (*work).min(limits.max_work),
        Some(scope),
    );
    let mut reader = Reader::new(source, limits, owner);
    let mut decoder = Decoder::new();
    let mut after_root = false;
    while let Some(mut event) = reader.next()? {
        scope.checkpoint()?;
        match event.kind {
            XmlEventKind::Start => {
                let selected = target.is_none_or(|r| {
                    event.region.offset >= r.offset && event.region.offset < r.offset + r.len
                }) && !excluded.iter().any(|r| {
                    event.region.offset >= r.offset && event.region.offset < r.offset + r.len
                });
                let mut namespaces = event.take_namespaces();
                let name = event
                    .name
                    .take()
                    .ok_or(ProcessingError::InvalidInput("element"))?
                    .qname;
                let mut attrs: Vec<_> = std::mem::take(&mut event.attributes)
                    .into_iter()
                    .map(|a| {
                        let (namespace, local, qname) = a.name.into_parts();
                        Attribute {
                            namespace: namespace.unwrap_or_default(),
                            local,
                            qname,
                            value: AttributeValue::Source(a.value),
                        }
                    })
                    .collect();
                if let Some((prefix, id)) = wsu_id
                    && target.is_some_and(|r| event.region.offset == r.offset)
                {
                    namespaces.retain(|(p, _)| p != prefix);
                    namespaces.push((prefix.to_owned(), crate::wsse::WSU_NS.to_owned()));
                    attrs.push(Attribute {
                        namespace: crate::wsse::WSU_NS.to_owned(),
                        local: "Id".to_owned(),
                        qname: format!("{prefix}:Id"),
                        value: AttributeValue::Literal(id.to_owned()),
                    });
                }
                out.start(
                    name,
                    namespaces,
                    attrs,
                    selected,
                    |value, out| match value {
                        AttributeValue::Source(r) => {
                            decoder.write(reader.file, *r, out, true, true, true)
                        }
                        AttributeValue::Literal(value) => out.escaped(value.as_bytes(), true),
                    },
                )?;
            }
            XmlEventKind::End => {
                out.end()?;
                if event.depth == 0 {
                    after_root = true;
                }
            }
            XmlEventKind::Text | XmlEventKind::Cdata if out.selected() => {
                let before = out.written();
                let cdata = event.kind == XmlEventKind::Cdata;
                let region = if cdata {
                    Region {
                        offset: event.region.offset + 9,
                        len: event.region.len - 12,
                    }
                } else {
                    event.region
                };
                decoder.write(reader.file, region, &mut out, false, !cdata, true)?;
                let len = out.written() - before;
                if len != 0
                    && let Some(projections) = projections.as_deref_mut()
                {
                    if projections.len() == 256 {
                        return Err(ProcessingError::MetadataLimit);
                    }
                    projections.push(Region {
                        offset: before,
                        len,
                    });
                }
            }
            XmlEventKind::Comment | XmlEventKind::ProcessingInstruction => {
                let whole = target.is_none();
                if !out.selected() && !(whole && event.depth == 0) {
                    continue;
                }
                let comment = event.kind == XmlEventKind::Comment;
                if comment && !out.comments() {
                    continue;
                }
                // XML declarations are not processing instruction nodes.
                if !comment {
                    let mut prefix = [0; 6];
                    let n = reader.file.read_region(
                        Region {
                            offset: event.region.offset,
                            len: event.region.len.min(6),
                        },
                        &mut prefix,
                    )?;
                    if n >= 6
                        && &prefix[..5] == b"<?xml"
                        && matches!(prefix[5], b' ' | b'\t' | b'\r' | b'\n')
                    {
                        continue;
                    }
                }
                let outside = whole && event.depth == 0;
                if outside && after_root {
                    out.put(b"\n")?;
                }
                if comment {
                    out.put(b"<!--")?;
                    decoder.write(
                        reader.file,
                        Region {
                            offset: event.region.offset + 4,
                            len: event.region.len - 7,
                        },
                        &mut out,
                        false,
                        false,
                        false,
                    )?;
                } else {
                    if event.region.len > limits.max_markup_bytes as u64 {
                        return Err(ProcessingError::MetadataLimit);
                    }
                    let mut bytes = vec![0; event.region.len as usize];
                    reader.file.read_region(event.region, &mut bytes)?;
                    let body = &bytes[2..bytes.len() - 2];
                    let name_end = body
                        .iter()
                        .position(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                        .unwrap_or(body.len());
                    out.put(b"<?")?;
                    out.put(&body[..name_end])?;
                    let value_start = body[name_end..]
                        .iter()
                        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                        .map(|n| n + name_end);
                    if let Some(start) = value_start {
                        out.put(b" ")?;
                        decoder.write(
                            reader.file,
                            Region {
                                offset: event.region.offset + 2 + start as u64,
                                len: (body.len() - start) as u64,
                            },
                            &mut out,
                            false,
                            false,
                            false,
                        )?;
                    }
                }
                out.put(if comment { b"-->" } else { b"?>" })?;
                if outside && !after_root {
                    out.put(b"\n")?;
                }
            }
            _ => {}
        }
    }
    *work = out.remaining();
    Ok(())
}
