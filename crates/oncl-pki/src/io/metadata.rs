//! Bounded memory-only intake for certificates, tokens and secret containers.
use super::Source;
use crate::resource::{ProcessingError, ResourceReservation, ResourceScope};
use std::io::{self, Read};
use zeroize::Zeroizing;
/// Immutable charged bytes. No owning buffer or independent reservation escapes.
pub struct MetadataInput {
    bytes: Zeroizing<Vec<u8>>,
    _memory: ResourceReservation,
    _metadata: ResourceReservation,
}
impl MetadataInput {
    pub fn read(
        mut source: Source<'_>,
        scope: &mut ResourceScope,
        maximum: u64,
    ) -> Result<Self, ProcessingError> {
        let replay = source.is_snapshot_for(scope)?;
        scope.checkpoint()?;
        scope.check_input()?;
        let maximum = maximum.min(scope.limits().container_bytes);
        if source.known_len().is_some_and(|len| len > maximum) {
            return Err(ProcessingError::ContainerLimit);
        }
        if !replay
            && source
                .known_len()
                .is_some_and(|len| len > scope.input_remaining())
        {
            return Err(ProcessingError::InputLimit);
        }
        let mut memory = scope.reserve_memory(0)?;
        let mut metadata = scope.reserve_metadata(0)?;
        let _chunk = scope.reserve_memory(4096)?;
        let mut bytes = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new([0u8; 4096]);
        loop {
            scope.checkpoint()?;
            let remaining = maximum.saturating_sub(bytes.len() as u64);
            let mut request = chunk
                .len()
                .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
            if !replay {
                request = request.min(scope.input_request(request)?);
            }
            let count = match source.read(&mut chunk[..request]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    source.finish_snapshot()?;
                    scope.checkpoint()?;
                    return Err(error.into());
                }
                Ok(count) => count,
            };
            if count > request {
                return Err(ProcessingError::InvalidInput("reader exceeded buffer"));
            }
            if !replay {
                scope.consumed_input(count as u64)?;
            }
            scope.checkpoint()?;
            scope.account_container(count as u64)?;
            if count == 0 {
                source.finish_snapshot()?;
                break;
            }
            if count as u64 > remaining {
                return Err(ProcessingError::ContainerLimit);
            }
            // Account both the old and new allocation while reallocating.
            let old = bytes.capacity() as u64;
            let target = bytes
                .len()
                .checked_add(count)
                .ok_or(ProcessingError::MemoryLimit)?;
            memory.grow(target as u64)?;
            metadata.grow((target as u64).saturating_sub(metadata.bytes()))?;
            bytes
                .try_reserve_exact(count)
                .map_err(|_| ProcessingError::MemoryLimit)?;
            memory.shrink(old)?;
            bytes.extend_from_slice(&chunk[..count]);
        }
        Ok(Self {
            bytes,
            _memory: memory,
            _metadata: metadata,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
