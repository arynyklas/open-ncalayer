//! Bounded memory-only intake for certificates, tokens and secret containers.
//! Replacements admit old plus new live capacity and wipe the old owner before
//! deallocation. Known hints and bounded geometric growth avoid per-chunk moves.
use super::Source;
use crate::resource::{ProcessingError, ResourceReservation, ResourceScope};
use std::io::{self, Read};
use zeroize::{Zeroize, Zeroizing};
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
        let maximum_capacity =
            usize::try_from(maximum).map_err(|_| ProcessingError::MemoryLimit)?;
        let initial_capacity = source
            .known_len()
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ProcessingError::MemoryLimit)?;
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
            let required = bytes
                .len()
                .checked_add(count)
                .ok_or(ProcessingError::MemoryLimit)?;
            if required > bytes.capacity() {
                let old_capacity = bytes.capacity();
                let capacity = if old_capacity == 0 {
                    initial_capacity.unwrap_or(chunk.len()).max(required)
                } else {
                    old_capacity.saturating_mul(2).max(required)
                }
                .min(maximum_capacity);
                // Both owners are live during replacement. Never ask Vec to
                // reallocate an allocation that already contains secret bytes.
                memory.grow(capacity as u64)?;
                metadata.grow(capacity as u64)?;
                let mut replacement = Zeroizing::new(Vec::new());
                replacement
                    .try_reserve_exact(capacity)
                    .map_err(|_| ProcessingError::MemoryLimit)?;
                // Global Vec allocation uses the requested layout. Fail closed
                // before copying secrets if an allocator ever over-reserves it.
                if replacement.capacity() != capacity {
                    return Err(ProcessingError::MemoryLimit);
                }
                replacement.extend_from_slice(&bytes);
                bytes.zeroize();
                bytes = replacement; // the retired owner was wiped before free
                memory.shrink(old_capacity as u64)?;
                metadata.shrink(old_capacity as u64)?;
            }
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
