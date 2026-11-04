//! Intake for the SDK's explicitly bounded borrowed-byte APIs, not CMS streaming.
use oncl_core::{OperationContext, OperationError};
use oncl_pki::{
    io::Source,
    resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation},
};
use std::io::{self, Read};

/// Metadata bytes charged per encoded byte of a host-supplied certificate, before
/// it is parsed. Measured retained heap of `oncl_pki::cert::parse` over the 11
/// real NCA production, 10 real NCA test and 5 synthetic certificates is at most
/// 4.9x the DER length (tests/config_budget.rs asserts < 8x). The charge is
/// deliberately wider than that so an adversarial certificate of many tiny
/// elements, which expands more per byte, still cannot exceed the admitted
/// budget; it still admits 1024 real roots under the default 64 MiB metadata.
pub const CERTIFICATE_METADATA_FACTOR: u64 = 16;
pub struct Bytes {
    bytes: Vec<u8>,
    _memory: ResourceReservation,
}
impl Bytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub fn read(
    mut input: Source<'_>,
    maximum: usize,
    ctx: &mut OperationContext,
) -> Result<Bytes, OperationError> {
    ctx.resources().checkpoint()?;
    if input.known_len().is_some_and(|len| len > maximum as u64) {
        return Err(ProcessingError::InputLimit.into());
    }
    let limit =
        maximum.min(usize::try_from(ctx.resources().input_remaining()).unwrap_or(usize::MAX));
    let probe = limit.checked_add(1).ok_or(ProcessingError::MemoryLimit)?;
    let initial = input
        .known_len()
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| n.checked_add(1))
        .unwrap_or(IO_CHUNK_BYTES)
        .min(probe)
        .max(1);
    let mut memory = ctx.resources().reserve_memory(initial as u64)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(initial)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    bytes.resize(initial, 0);
    let mut count = 0usize;
    let intake = (|| {
        loop {
            ctx.resources().checkpoint()?;
            if count == bytes.len() {
                let capacity = bytes.len().checked_mul(2).unwrap_or(probe).min(probe);
                if capacity == bytes.len() {
                    return Err(ProcessingError::InputLimit.into());
                }
                // Old and replacement capacity coexist through the actual allocation.
                let replacement = ctx.resources().reserve_memory(capacity as u64)?;
                bytes
                    .try_reserve_exact(capacity - count)
                    .map_err(|_| ProcessingError::MemoryLimit)?;
                bytes.resize(capacity, 0);
                memory = replacement;
            }
            let read = input.read(&mut bytes[count..]);
            let n = match read {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result.map_err(ProcessingError::from)?,
            };
            count = count.checked_add(n).ok_or(ProcessingError::InputLimit)?;
            if count > limit {
                return Err(ProcessingError::InputLimit.into());
            }
            ctx.resources().checkpoint()?;
            if n == 0 {
                break;
            }
        }
        Ok::<(), OperationError>(())
    })();
    if let Err(error) = intake {
        // Failed intake never reaches Core's borrowed admission. Retain actual
        // consumed N+1 bytes before reporting cancellation/resource/I/O failure.
        ctx.resources().account_input(count as u64)?;
        return Err(error);
    }
    bytes.truncate(count);
    // On success Core accounts these immutable borrowed bytes exactly once.
    Ok(Bytes {
        bytes,
        _memory: memory,
    })
}
