//! Source-role, quota-bound XML token and ID indexes. No node cardinality cap.
//! ID runs form a bounded (at most 64 levels) on-disk merge index; hash collisions
//! are ordered and checked using the complete normalized identity, not a digest.
use crate::reader::{Reader, XmlEventKind, XmlEvents, invalid};
use oncl_pki::{
    io::{
        CapturedInput, FrozenInput, FrozenReader, ProvisionalInput, Region, Source, StagedArtifact,
        TemporaryStore,
    },
    resource::{
        IO_CHUNK_BYTES, OperationControl, ProcessingError, Progress, ResourceReservation,
        ResourceScope,
    },
};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    sync::{Arc, Weak},
};
type Result<T, E = ProcessingError> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct XmlLimits {
    pub max_depth: usize,
    pub max_markup_bytes: usize,
    pub max_attributes: usize,
    pub max_name_bytes: usize,
    pub max_namespaces: usize,
    pub max_namespace_bytes: usize,
    pub max_id_bytes: usize,
    /// Checked sum of attribute/namespace comparison work, independent of nodes.
    pub max_work: u64,
}
impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_depth: 256,
            max_markup_bytes: 32768,
            max_attributes: 128,
            max_name_bytes: 1024,
            max_namespaces: 128,
            max_namespace_bytes: 65536,
            max_id_bytes: 1024,
            max_work: 1u64 << 40,
        }
    }
}
impl XmlLimits {
    pub(crate) fn reservation(&self) -> Result<u64> {
        // Explicit implementation bounds keep arithmetic and parser allocation
        // estimates finite even if a hostile host supplies absurd settings.
        if self.max_depth == 0
            || self.max_depth > 256
            || self.max_markup_bytes < 16
            || self.max_markup_bytes > 65536
            || self.max_attributes > 128
            || self.max_name_bytes > 1024
            || self.max_namespaces > 128
            || self.max_namespace_bytes > 65536
            || self.max_id_bytes == 0
            || self.max_id_bytes > 1024
            || self.max_work == 0
        {
            return Err(ProcessingError::InvalidLimits);
        }
        // Frame payload includes normalized IDs (one markup budget), expanded
        // element namespace (one), new declaration keys (one), and displaced
        // namespace key/value pairs (one complete namespace budget). Fixed
        // overhead also covers live parser/event scratch, sort batch and runs.
        Ok(12 * 1024 * 1024
            + self.max_depth as u64
                * (self.max_markup_bytes as u64 * 3 + self.max_namespace_bytes as u64 + 8192))
    }
}
/// Unforgeable document identity plus stable u64 lexical region. Not a permit
/// or raw spool handle; a dropped/foreign document cannot use this handle.
pub struct XmlNode {
    owner: Weak<()>,
    region: Region,
}
pub struct XmlDocument {
    source: XmlInput,
    tokens: StagedArtifact,
    keys: StagedArtifact,
    runs: Vec<Option<StagedArtifact>>,
    limits: XmlLimits,
    owner: Arc<()>,
    control: Arc<dyn OperationControl>,
    prolog_bom: Option<Region>,
    _metadata: ResourceReservation,
}
enum XmlInput {
    Original(FrozenInput),
    Signed(ProvisionalInput),
}
impl XmlInput {
    fn readable(&mut self) -> &mut dyn CapturedInput {
        match self {
            Self::Original(input) => input,
            Self::Signed(input) => input,
        }
    }
    fn len(&self) -> u64 {
        match self {
            Self::Original(input) => input.len(),
            Self::Signed(input) => input.len(),
        }
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_region(&mut self, region: Region, output: &mut [u8]) -> Result<usize> {
        self.readable().read_region(region, output)
    }
    fn reader<'a>(
        &'a mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<FrozenReader<'a>> {
        self.readable().reader(regions, scope)
    }
}
struct Buffered {
    file: StagedArtifact,
    bytes: Vec<u8>,
}
impl Buffered {
    fn new(file: StagedArtifact) -> Self {
        Self {
            file,
            bytes: Vec::with_capacity(IO_CHUNK_BYTES),
        }
    }
    fn append(&mut self, data: &[u8]) -> Result<()> {
        for part in data.chunks(IO_CHUNK_BYTES) {
            if self.bytes.len() + part.len() > IO_CHUNK_BYTES {
                self.flush()?;
            }
            self.bytes.extend_from_slice(part);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        self.file.write_chunk(&self.bytes)?;
        self.bytes.clear();
        Ok(())
    }
    fn finish(mut self) -> Result<StagedArtifact> {
        self.flush()?;
        Ok(self.file)
    }
}
#[derive(Clone)]
struct Entry {
    hash: [u8; 32],
    key: Region,
    node: Region,
}
impl Entry {
    fn encode(&self) -> [u8; 64] {
        let mut b = [0; 64];
        b[..32].copy_from_slice(&self.hash);
        for (i, v) in [
            self.key.offset,
            self.key.len,
            self.node.offset,
            self.node.len,
        ]
        .iter()
        .enumerate()
        {
            b[32 + i * 8..40 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
    fn read(file: &mut StagedArtifact, index: u64) -> Result<Self> {
        let mut b = [0; 64];
        file.read_region(
            Region {
                offset: index.checked_mul(64).ok_or_else(invalid)?,
                len: 64,
            },
            &mut b,
        )?;
        let n = |i| u64::from_le_bytes(b[i..i + 8].try_into().expect("fixed record"));
        Ok(Self {
            hash: b[..32].try_into().expect("fixed digest"),
            key: Region {
                offset: n(32),
                len: n(40),
            },
            node: Region {
                offset: n(48),
                len: n(56),
            },
        })
    }
}
fn key(file: &mut StagedArtifact, region: Region) -> Result<Vec<u8>> {
    if region.len > 1024 {
        return Err(invalid());
    }
    let mut bytes = vec![0; region.len as usize];
    file.read_region(region, &mut bytes)?;
    Ok(bytes)
}
fn compare(a: &Entry, b: &Entry, keys: &mut StagedArtifact) -> Result<Ordering> {
    let order = a.hash.cmp(&b.hash);
    if order != Ordering::Equal {
        return Ok(order);
    }
    Ok(key(keys, a.key)?.cmp(&key(keys, b.key)?))
}
fn merge(
    mut a: StagedArtifact,
    mut b: StagedArtifact,
    keys: &mut StagedArtifact,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
) -> Result<StagedArtifact> {
    let mut out = Buffered::new(store.stage_source(scope)?);
    let (mut ai, mut bi) = (0, 0);
    let (an, bn) = (a.len() / 64, b.len() / 64);
    let mut ae = if an > 0 {
        Some(Entry::read(&mut a, 0)?)
    } else {
        None
    };
    let mut be = if bn > 0 {
        Some(Entry::read(&mut b, 0)?)
    } else {
        None
    };
    while ae.is_some() || be.is_some() {
        let take_a = match (&ae, &be) {
            (Some(x), Some(y)) => match compare(x, y, keys)? {
                Ordering::Equal => return Err(ProcessingError::InvalidInput("duplicate XML ID")),
                Ordering::Less => true,
                Ordering::Greater => false,
            },
            (Some(_), None) => true,
            _ => false,
        };
        if take_a {
            out.append(&ae.as_ref().ok_or_else(invalid)?.encode())?;
            ai += 1;
            ae = if ai < an {
                Some(Entry::read(&mut a, ai)?)
            } else {
                None
            };
        } else {
            out.append(&be.as_ref().ok_or_else(invalid)?.encode())?;
            bi += 1;
            be = if bi < bn {
                Some(Entry::read(&mut b, bi)?)
            } else {
                None
            };
        }
    }
    out.finish()
}
fn flush_batch(
    batch: &mut Vec<(Entry, String)>,
    runs: &mut Vec<Option<StagedArtifact>>,
    keys: &mut StagedArtifact,
    store: &TemporaryStore,
    scope: &mut ResourceScope,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    batch.sort_unstable_by(|(a, ak), (b, bk)| a.hash.cmp(&b.hash).then_with(|| ak.cmp(bk)));
    if batch.windows(2).any(|p| p[0].1 == p[1].1) {
        return Err(ProcessingError::InvalidInput("duplicate XML ID"));
    }
    let mut out = Buffered::new(store.stage_source(scope)?);
    for (entry, _) in batch.drain(..) {
        out.append(&entry.encode())?;
    }
    let mut run = out.finish()?;
    let mut level = 0;
    loop {
        if level == runs.len() {
            runs.push(Some(run));
            break;
        }
        if let Some(old) = runs[level].take() {
            run = merge(old, run, keys, store, scope)?;
            level += 1;
        } else {
            runs[level] = Some(run);
            break;
        }
        if level == 64 {
            return Err(ProcessingError::TempLimit);
        }
    }
    Ok(())
}
impl XmlDocument {
    /// Freeze a known or unknown length source using the caller's explicit
    /// owner-only store and original operation quota/control/Deadline. Authentic
    /// same-operation snapshots replay without charging the input quota twice.
    /// No temp service is conjured from a filename or a limits structure.
    pub fn index(
        source: Source<'_>,
        limits: &XmlLimits,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
    ) -> Result<Self> {
        let bound = limits.reservation()?;
        let metadata = scope.reserve_metadata(bound)?;
        let frozen = FrozenInput::capture(source, store, scope)?;
        Self::build(XmlInput::Original(frozen), limits, store, scope, metadata)
    }
    fn build(
        mut frozen: XmlInput,
        limits: &XmlLimits,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
        metadata: ResourceReservation,
    ) -> Result<Self> {
        let mut tokens = Buffered::new(store.stage_source(scope)?);
        let mut keys = store.stage_source(scope)?;
        let mut runs = Vec::with_capacity(64);
        let mut batch = Vec::with_capacity(1024);
        let owner = Arc::new(());
        let mut reader = Reader::new(frozen.readable(), limits, &owner);
        while let Some(event) = reader.next()? {
            scope.checkpoint()?;
            let mut record = [0; 24];
            record[..8].copy_from_slice(&event.region.offset.to_le_bytes());
            record[8..16].copy_from_slice(&event.region.len.to_le_bytes());
            record[16] = event.kind as u8;
            record[17..19].copy_from_slice(&(event.depth as u16).to_le_bytes());
            tokens.append(&record)?;
            if event.kind == XmlEventKind::End {
                for id in event.ids {
                    let key_region = Region {
                        offset: keys.len(),
                        len: id.len() as u64,
                    };
                    keys.write_chunk(id.as_bytes())?;
                    let entry = Entry {
                        hash: Sha256::digest(id.as_bytes()).into(),
                        key: key_region,
                        node: event.region,
                    };
                    batch.push((entry, id));
                    if batch.len() == 1024 {
                        flush_batch(&mut batch, &mut runs, &mut keys, store, scope)?;
                    }
                }
            }
        }
        let prolog_bom = reader.bom_region();
        flush_batch(&mut batch, &mut runs, &mut keys, store, scope)?;
        // Runs are individually duplicate-free; fold all levels before exposing
        // the index to catch duplicates that straddle unequal final run sizes.
        let mut final_run = None;
        for run in &mut runs {
            if let Some(next) = run.take() {
                final_run = Some(if let Some(old) = final_run {
                    merge(old, next, &mut keys, store, scope)?
                } else {
                    next
                });
            }
        }
        runs.clear();
        runs.push(final_run);
        scope.checkpoint()?;
        Ok(Self {
            source: frozen,
            tokens: tokens.finish()?,
            keys,
            runs,
            limits: limits.clone(),
            owner,
            control: scope.operation_control(),
            prolog_bom,
            _metadata: metadata,
        })
    }
    pub(crate) fn index_provisional(
        source: ProvisionalInput,
        limits: &XmlLimits,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
        metadata: ResourceReservation,
    ) -> Result<Self> {
        Self::build(XmlInput::Signed(source), limits, store, scope, metadata)
    }
    pub(crate) fn index_signed(
        source: Source<'_>,
        profile: &crate::XmlVerifyProfile,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
    ) -> std::result::Result<Self, crate::XmlSourceError> {
        crate::references::intake::index_signed(source, profile, store, scope)
    }
    pub(crate) fn bom_region(&self) -> Option<Region> {
        self.prolog_bom
    }
    pub(crate) fn classify_signed(
        &mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<()> {
        match &mut self.source {
            XmlInput::Signed(input) => input.classify(regions, scope),
            XmlInput::Original(_) => Err(ProcessingError::InvalidInput(
                "not a provisional XML source",
            )),
        }
    }
    pub(crate) fn into_signed(self) -> Result<ProvisionalInput> {
        match self.source {
            XmlInput::Signed(input) if input.is_classified() => Ok(input),
            _ => Err(ProcessingError::InvalidInput(
                "unclassified XML cannot escape",
            )),
        }
    }
    pub fn len(&self) -> u64 {
        self.source.len()
    }
    pub fn is_empty(&self) -> bool {
        self.source.is_empty()
    }
    pub fn token_count(&self) -> u64 {
        self.tokens.len() / 24
    }
    pub fn token_region(&mut self, index: u64) -> Result<Region> {
        if index >= self.token_count() {
            return Err(invalid());
        }
        let mut b = [0; 24];
        self.tokens.read_region(
            Region {
                offset: index.checked_mul(24).ok_or_else(invalid)?,
                len: 24,
            },
            &mut b,
        )?;
        Ok(Region {
            offset: u64::from_le_bytes(b[..8].try_into().expect("fixed record")),
            len: u64::from_le_bytes(b[8..16].try_into().expect("fixed record")),
        })
    }
    pub fn lookup_id(&mut self, id: &str) -> Result<Option<XmlNode>> {
        self.control.checkpoint(Progress::default())?;
        if id.len() > self.limits.max_id_bytes {
            return Err(invalid());
        }
        let hash: [u8; 32] = Sha256::digest(id.as_bytes()).into();
        for run in self.runs.iter_mut().flatten() {
            let (mut lo, mut hi) = (0, run.len() / 64);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let entry = Entry::read(run, mid)?;
                let order = entry.hash.cmp(&hash);
                let order = if order == Ordering::Equal {
                    key(&mut self.keys, entry.key)?
                        .as_slice()
                        .cmp(id.as_bytes())
                } else {
                    order
                };
                match order {
                    Ordering::Less => lo = mid + 1,
                    Ordering::Greater => hi = mid,
                    Ordering::Equal => {
                        return Ok(Some(XmlNode {
                            owner: Arc::downgrade(&self.owner),
                            region: entry.node,
                        }));
                    }
                }
            }
        }
        Ok(None)
    }
    pub fn node_region(&self, node: &XmlNode) -> Result<Region> {
        if !Weak::ptr_eq(&node.owner, &Arc::downgrade(&self.owner))
            || node.owner.upgrade().is_none()
        {
            return Err(ProcessingError::InvalidInput("foreign or stale XML node"));
        }
        Ok(node.region)
    }
    /// Bounded replay relative to a checked owner-bound node (not arbitrary file
    /// access). Large node content remains streamed through caller buffers.
    pub fn read_node(&mut self, node: &XmlNode, offset: u64, output: &mut [u8]) -> Result<usize> {
        let region = self.node_region(node)?;
        if offset > region.len {
            return Err(invalid());
        }
        self.source.read_region(
            Region {
                offset: region.offset.checked_add(offset).ok_or_else(invalid)?,
                len: region.len - offset,
            },
            output,
        )
    }
    /// Replay validated raw attribute bytes, without quotes or implicit XML
    /// normalization. Spans remain bound to this document; X03 owns c14n.
    pub fn read_attribute(
        &mut self,
        attribute: &crate::reader::XmlAttributeSpan,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize> {
        if !Weak::ptr_eq(&attribute.owner, &Arc::downgrade(&self.owner))
            || attribute.owner.upgrade().is_none()
        {
            return Err(ProcessingError::InvalidInput(
                "foreign or stale XML attribute",
            ));
        }
        let region = attribute.value;
        if offset > region.len {
            return Err(invalid());
        }
        self.source.read_region(
            Region {
                offset: region.offset.checked_add(offset).ok_or_else(invalid)?,
                len: region.len - offset,
            },
            output,
        )
    }
    pub(crate) fn read_region(&mut self, region: Region, output: &mut [u8]) -> Result<usize> {
        self.source.read_region(region, output)
    }
    pub(crate) fn indexed_node(&self, region: Region) -> XmlNode {
        XmlNode {
            owner: Arc::downgrade(&self.owner),
            region,
        }
    }
    pub(crate) fn canonical_digest(
        &mut self,
        options: crate::canonical_stream::Options<'_>,
        algorithm: oncl_pki::key::HashAlg,
        scope: &ResourceScope,
        work: &mut u64,
    ) -> Result<oncl_pki::digest::DigestValue> {
        crate::canonical_stream::hash(
            self.source.readable(),
            &self.limits,
            &self.owner,
            options,
            algorithm,
            scope,
            work,
        )
    }
    pub(crate) fn canonical_append(
        &mut self,
        options: crate::canonical_stream::Options<'_>,
        artifact: &mut StagedArtifact,
        scope: &ResourceScope,
        work: &mut u64,
    ) -> Result<()> {
        crate::canonical_stream::append(
            self.source.readable(),
            &self.limits,
            &self.owner,
            options,
            artifact,
            scope,
            work,
        )
    }
    pub(crate) fn canonical_proof(
        &mut self,
        options: crate::canonical_stream::Options<'_>,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
        work: &mut u64,
    ) -> Result<(StagedArtifact, Vec<Region>)> {
        crate::canonical_stream::stage(
            self.source.readable(),
            &self.limits,
            &self.owner,
            options,
            store,
            scope,
            work,
        )
    }
    pub(crate) fn canonical_append_wsu_id(
        &mut self,
        options: crate::canonical_stream::Options<'_>,
        artifact: &mut StagedArtifact,
        scope: &ResourceScope,
        work: &mut u64,
        id: Option<(&str, &str)>,
    ) -> Result<()> {
        crate::canonical_stream::append_with_wsu_id(
            self.source.readable(),
            &self.limits,
            &self.owner,
            (options, id),
            artifact,
            scope,
            work,
        )
    }
    pub(crate) fn check_scope(&mut self, scope: &ResourceScope) -> Result<()> {
        drop(self.source.reader(&[], scope)?);
        Ok(())
    }
    pub(crate) fn node_namespaces(
        &mut self,
        node: &XmlNode,
        scope: &ResourceScope,
    ) -> Result<Vec<(String, String)>> {
        self.check_scope(scope)?;
        let region = self.node_region(node)?;
        let mut reader = Reader::new(self.source.readable(), &self.limits, &self.owner);
        while let Some(mut event) = reader.next()? {
            scope.checkpoint()?;
            if event.kind == XmlEventKind::End && event.region == region {
                return Ok(event.take_namespaces());
            }
        }
        Err(invalid())
    }
    /// Select the first real indexed element using the existing bounded
    /// absolute child/descendant XPath subset (at most 32 steps).
    pub fn select_xpath(
        &mut self,
        expression: &str,
        namespaces: &[(&str, &str)],
        scope: &mut ResourceScope,
    ) -> Result<Option<XmlNode>, crate::XmlSourceError> {
        crate::xpath::select_indexed(self, expression, namespaces, scope)
    }
    pub(crate) fn select_xpath_unique(
        &mut self,
        expression: &str,
        namespaces: &[(&str, &str)],
        scope: &ResourceScope,
    ) -> Result<Option<XmlNode>, crate::XmlSourceError> {
        crate::xpath::select_indexed_unique(self, expression, namespaces, scope)
    }
    /// Stream canonical UTF-8 bytes to an external output under the original
    /// operation's output quota. `None` selects the document including outer PIs.
    pub fn canonicalize(
        &mut self,
        node: Option<&XmlNode>,
        method: crate::C14n,
        profile: crate::C14nProfile,
        output: &mut dyn std::io::Write,
        scope: &mut ResourceScope,
    ) -> Result<()> {
        let target = node.map(|n| self.node_region(n)).transpose()?;
        crate::canonical_stream::run(
            self.source.readable(),
            &self.limits,
            &self.owner,
            crate::canonical_stream::Options {
                target,
                method,
                profile,
                prefixes: &[],
                excluded: &[],
                metadata_limit: None,
            },
            output,
            scope,
        )
    }
    pub fn events(&mut self) -> XmlEvents<'_> {
        XmlEvents {
            reader: Reader::new(self.source.readable(), &self.limits, &self.owner),
            current: None,
            control: self.control.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::resource::ResourceLimits;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<()> {
            Ok(())
        }
    }
    #[test]
    fn colliding_digest_records_compare_complete_identity() {
        let parent = tempfile::tempdir().unwrap();
        let store = TemporaryStore::new(parent.path()).unwrap();
        let limits = ResourceLimits::default();
        let budget = Arc::new(oncl_pki::resource::SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let mut keys = store.stage_source(&mut scope).unwrap();
        keys.write_chunk(b"alphabeta").unwrap();
        let a = Entry {
            hash: [7; 32],
            key: Region { offset: 0, len: 5 },
            node: Region {
                offset: 10,
                len: 20,
            },
        };
        let b = Entry {
            hash: [7; 32],
            key: Region { offset: 5, len: 4 },
            node: Region {
                offset: 30,
                len: 20,
            },
        };
        let mut left = store.stage_source(&mut scope).unwrap();
        left.write_chunk(&a.encode()).unwrap();
        let mut right = store.stage_source(&mut scope).unwrap();
        right.write_chunk(&b.encode()).unwrap();
        let mut merged = merge(left, right, &mut keys, &store, &mut scope).unwrap();
        assert_eq!(merged.len(), 128);
        assert_eq!(
            key(&mut keys, Entry::read(&mut merged, 0).unwrap().key).unwrap(),
            b"alpha"
        );
        assert_eq!(
            key(&mut keys, Entry::read(&mut merged, 1).unwrap().key).unwrap(),
            b"beta"
        );
        let mut duplicate = store.stage_source(&mut scope).unwrap();
        duplicate.write_chunk(&a.encode()).unwrap();
        assert!(matches!(
            merge(merged, duplicate, &mut keys, &store, &mut scope),
            Err(ProcessingError::InvalidInput("duplicate XML ID"))
        ));
    }
}
