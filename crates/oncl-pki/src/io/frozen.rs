//! Immutable source-role snapshots. No constructor accepts a pre-populated stage.
use super::{Region, Source, StagedArtifact, TemporaryStore};
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::Arc,
};

pub struct FrozenInput {
    stage: StagedArtifact,
    identity: Arc<()>,
}
pub struct FrozenReader<'a> {
    input: &'a mut FrozenInput,
    regions: Vec<Region>,
    position: u64,
    length: u64,
    error: Option<ProcessingError>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
pub struct DerivedInput {
    bytes: Vec<u8>,
    parent: Arc<()>,
    scope: ResourceScope,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl FrozenInput {
    /// Capture exactly the actual source bytes from its logical current start.
    /// The only persistent storage is the host's explicit source-role store.
    pub fn capture(
        mut source: Source<'_>,
        store: &TemporaryStore,
        scope: &mut ResourceScope,
    ) -> Result<Self, ProcessingError> {
        scope.checkpoint()?;
        if let Some(reader) = source.as_seekable() {
            let start = reader.stream_position()?;
            let end = reader.seek(SeekFrom::End(0))?;
            reader.seek(SeekFrom::Start(start))?;
            let size = end
                .checked_sub(start)
                .ok_or(ProcessingError::InvalidInput("source extent"))?;
            if size > scope.input_remaining() {
                return Err(ProcessingError::InputLimit);
            }
        }
        let _memory = scope.reserve_memory(IO_CHUNK_BYTES as u64)?;
        let mut buffer = vec![0; IO_CHUNK_BYTES];
        let mut stage = store.stage_source(scope)?;
        loop {
            scope.checkpoint()?;
            let request = scope.input_request(buffer.len())?;
            let count = match source.read(&mut buffer[..request]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count > request {
                return Err(ProcessingError::InvalidInput("reader exceeded buffer"));
            }
            scope.consumed_input(count as u64)?;
            scope.checkpoint()?;
            if count == 0 {
                break;
            }
            stage.write_chunk(&buffer[..count])?;
        }
        Ok(Self {
            stage,
            identity: Arc::new(()),
        })
    }
    pub fn len(&self) -> u64 {
        self.stage.len()
    }
    pub fn is_empty(&self) -> bool {
        self.stage.is_empty()
    }
    fn check(&self, scope: &ResourceScope) -> Result<(), ProcessingError> {
        scope.checkpoint()?;
        if !self.stage.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "snapshot belongs to another operation",
            ));
        }
        Ok(())
    }
    pub fn reader<'a>(
        &'a mut self,
        regions: &[Region],
        scope: &ResourceScope,
    ) -> Result<FrozenReader<'a>, ProcessingError> {
        self.check(scope)?;
        let mut length = 0u64;
        for region in regions {
            if region.end()? > self.len() {
                return Err(ProcessingError::InvalidInput(
                    "snapshot region exceeds extent",
                ));
            }
            length = length
                .checked_add(region.len)
                .ok_or(ProcessingError::InputLimit)?;
        }
        let bytes = (regions.len() as u64)
            .checked_mul(std::mem::size_of::<Region>() as u64)
            .and_then(|n| n.checked_add(std::mem::size_of::<FrozenReader<'_>>() as u64))
            .ok_or(ProcessingError::MetadataLimit)?;
        let metadata = scope.reserve_metadata(bytes)?;
        let memory = scope.reserve_memory(bytes)?;
        Ok(FrozenReader {
            input: self,
            regions: regions.to_vec(),
            position: 0,
            length,
            error: None,
            _memory: memory,
            _metadata: metadata,
        })
    }
    /// Decode bounded format metadata from an actual immutable encoded region.
    /// Both buffers are admitted first. The decoder can never emit more bytes
    /// than the encoded region; the result exposes no unscoped owned buffer.
    pub fn derive_region(
        &mut self,
        region: Region,
        scope: &ResourceScope,
        decode: impl FnOnce(&[u8], &mut dyn Write) -> Result<(), ProcessingError>,
    ) -> Result<DerivedInput, ProcessingError> {
        self.check(scope)?;
        if region.end()? > self.len() {
            return Err(ProcessingError::InvalidInput(
                "derived region exceeds snapshot",
            ));
        }
        // Charge the entire encoded container region before decoding; decoded
        // output is bounded by this admission, including reserved padding.
        scope.account_container(region.len)?;
        let length = usize::try_from(region.len).map_err(|_| ProcessingError::MetadataLimit)?;
        let memory = scope.reserve_memory(
            region
                .len
                .checked_mul(2)
                .ok_or(ProcessingError::MemoryLimit)?,
        )?;
        let metadata = scope.reserve_metadata(
            region
                .len
                .checked_mul(2)
                .ok_or(ProcessingError::MetadataLimit)?,
        )?;
        let mut encoded = vec![0; length];
        let mut at = 0;
        while at < length {
            let n = self.stage.read_region(
                Region {
                    offset: region.offset + at as u64,
                    len: region.len - at as u64,
                },
                &mut encoded[at..],
            )?;
            if n == 0 {
                return Err(ProcessingError::InvalidInput("short snapshot region"));
            }
            at += n;
        }
        struct Bounded {
            bytes: Vec<u8>,
            limit: usize,
        }
        impl Write for Bounded {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self
                    .bytes
                    .len()
                    .checked_add(bytes.len())
                    .is_none_or(|n| n > self.limit)
                {
                    return Err(io::Error::other("derived metadata exceeds encoded region"));
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut output = Bounded {
            bytes: Vec::with_capacity(length),
            limit: length,
        };
        decode(&encoded, &mut output)?;
        scope.checkpoint()?;
        Ok(DerivedInput {
            bytes: output.bytes,
            parent: self.identity.clone(),
            scope: self.stage.scope.retain(),
            _memory: memory,
            _metadata: metadata,
        })
    }
    pub(crate) fn binds(
        &self,
        derived: &DerivedInput,
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        self.check(scope)?;
        if !Arc::ptr_eq(&self.identity, &derived.parent) || !derived.scope.same_operation(scope) {
            return Err(ProcessingError::InvalidInput(
                "derived metadata belongs to another snapshot",
            ));
        }
        Ok(())
    }
}
impl DerivedInput {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl FrozenReader<'_> {
    pub fn source(&mut self) -> Source<'_> {
        let length = self.length;
        let admitted = self.input.stage.scope.retain();
        Source {
            reader: super::Reader::Seekable(self),
            len: Some(length),
            admitted: Some(admitted),
        }
    }
    pub fn finish(&mut self) -> Result<(), ProcessingError> {
        if let Some(error) = self.error.take() {
            Err(error)
        } else {
            self.input.stage.scope.checkpoint()
        }
    }
}
impl Read for FrozenReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::Error::other("snapshot reader failed"));
        }
        if self.position >= self.length {
            return Ok(0);
        }
        let mut start = 0;
        let mut chosen = None;
        for region in &self.regions {
            if self.position < start + region.len {
                chosen = Some(Region {
                    offset: region.offset + self.position - start,
                    len: start + region.len - self.position,
                });
                break;
            }
            start += region.len;
        }
        let region = chosen.ok_or_else(|| io::Error::other("snapshot region position"))?;
        match self.input.stage.read_region(region, out) {
            Ok(n) => {
                self.position += n as u64;
                Ok(n)
            }
            Err(error) => {
                self.error = Some(error);
                Err(io::Error::other("snapshot replay failed"))
            }
        }
    }
}
impl Seek for FrozenReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.length.checked_add_signed(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
        }
        .ok_or_else(|| io::Error::other("snapshot seek overflow"))?;
        self.position = position;
        Ok(position)
    }
}
