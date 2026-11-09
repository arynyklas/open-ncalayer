//! Fixed-size digests and streaming RustCrypto hash states. No document buffering.
use crate::io::Source;
use crate::key::HashAlg;
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceReservation, ResourceScope};
use sha2::Digest;
use std::io::Read;

/// A digest with its algorithm; unused buffer bytes are always zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigestValue {
    algorithm: HashAlg,
    bytes: [u8; 64],
    len: u8,
}
impl DigestValue {
    /// Import a complete digest with an explicit algorithm tag.
    pub fn from_bytes(algorithm: HashAlg, bytes: &[u8]) -> Result<Self, crate::key::KeyError> {
        let len = match algorithm {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 | HashAlg::Gost34311 | HashAlg::Streebog256 => 32,
            HashAlg::Sha512 | HashAlg::Streebog512 => 64,
        };
        if bytes.len() != len {
            return Err(crate::key::KeyError::Malformed(
                "incorrect digest length".into(),
            ));
        }
        Ok(Self::from_hash(algorithm, bytes))
    }
    pub fn algorithm(&self) -> HashAlg {
        self.algorithm
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    fn from_hash(algorithm: HashAlg, digest: &[u8]) -> Self {
        let mut bytes = [0; 64];
        bytes[..digest.len()].copy_from_slice(digest);
        Self {
            algorithm,
            bytes,
            len: digest.len() as u8,
        }
    }
}

/// Concrete, non-allocating incremental states, using the same D-TEST GOST
/// parameters as the existing Kazakhstan PKI one-shot implementation.
pub enum HashState {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Gost34311(gost94::Gost94Test),
    Streebog256(streebog::Streebog256),
    Streebog512(streebog::Streebog512),
}
impl HashState {
    pub fn new(algorithm: HashAlg) -> Self {
        match algorithm {
            HashAlg::Sha1 => Self::Sha1(sha1::Sha1::new()),
            HashAlg::Sha256 => Self::Sha256(sha2::Sha256::new()),
            HashAlg::Sha512 => Self::Sha512(sha2::Sha512::new()),
            HashAlg::Gost34311 => Self::Gost34311(gost94::Gost94Test::new()),
            HashAlg::Streebog256 => Self::Streebog256(streebog::Streebog256::new()),
            HashAlg::Streebog512 => Self::Streebog512(streebog::Streebog512::new()),
        }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(state) => state.update(bytes),
            Self::Sha256(state) => state.update(bytes),
            Self::Sha512(state) => state.update(bytes),
            Self::Gost34311(state) => state.update(bytes),
            Self::Streebog256(state) => state.update(bytes),
            Self::Streebog512(state) => state.update(bytes),
        }
    }
    pub fn finish(self) -> DigestValue {
        match self {
            Self::Sha1(state) => DigestValue::from_hash(HashAlg::Sha1, &state.finalize()),
            Self::Sha256(state) => DigestValue::from_hash(HashAlg::Sha256, &state.finalize()),
            Self::Sha512(state) => DigestValue::from_hash(HashAlg::Sha512, &state.finalize()),
            Self::Gost34311(state) => DigestValue::from_hash(HashAlg::Gost34311, &state.finalize()),
            Self::Streebog256(state) => {
                DigestValue::from_hash(HashAlg::Streebog256, &state.finalize())
            }
            Self::Streebog512(state) => {
                DigestValue::from_hash(HashAlg::Streebog512, &state.finalize())
            }
        }
    }
}

/// Hash from the current reader position to EOF. Known lengths are admission
/// hints, not a way to bypass actual byte accounting. At the input limit one
/// extra byte is probed to distinguish exact EOF from an oversized stream.
/// Every read is at most 256 KiB; cancellation/deadline is checked before and
/// after I/O, before hashing, and before returning a result.
/// Authentic frozen views must belong to this exact operation; their bounded
/// bytes are replay, not fresh intake. They retain the original control/deadline
/// and typed one-shot snapshot read errors. Ordinary Sources keep N+1 accounting.
pub fn hash_source(
    mut source: Source<'_>,
    algorithm: HashAlg,
    scope: &mut ResourceScope,
) -> Result<DigestValue, ProcessingError> {
    let replay = source.is_snapshot_for(scope)?;
    let replay_limit = if replay {
        source
            .known_len()
            .ok_or(ProcessingError::InvalidInput("snapshot extent absent"))?
            .min(scope.limits().input_bytes)
    } else {
        0
    };
    scope.checkpoint()?;
    scope.check_input()?;
    if !replay
        && source
            .known_len()
            .is_some_and(|len| len > scope.input_remaining())
    {
        return Err(ProcessingError::InputLimit);
    }
    let _metadata = scope.reserve_metadata(std::mem::size_of::<HashState>() as u64)?;
    // Small memory budgets can still hash, without claiming that an unaccounted
    // stack-sized document buffer is free. The state itself is metadata-accounted.
    let capacity = scope.available_memory().min(IO_CHUNK_BYTES as u64) as usize;
    if capacity == 0 {
        return Err(ProcessingError::MemoryLimit);
    }
    let _memory = scope.reserve_memory(capacity as u64)?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(capacity)
        .map_err(|_| ProcessingError::MemoryLimit)?;
    buffer.resize(capacity, 0);
    let mut state = HashState::new(algorithm);
    let mut replayed = 0u64;
    loop {
        scope.checkpoint()?;
        let request = if replay {
            capacity
        } else {
            scope.input_request(capacity)?
        };
        let n = match source.read(&mut buffer[..request]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                source.finish_snapshot()?;
                scope.checkpoint()?;
                return Err(error.into());
            }
            Ok(count) => count,
        };
        if n > request {
            return Err(ProcessingError::InvalidInput(
                "reader exceeded its supplied buffer",
            ));
        }
        if replay {
            replayed = replayed
                .checked_add(n as u64)
                .ok_or(ProcessingError::InputLimit)?;
            if replayed > replay_limit {
                return Err(ProcessingError::InputLimit);
            }
        } else {
            scope.consumed_input(n as u64)?;
        }
        scope.checkpoint()?;
        if n == 0 {
            break;
        }
        state.update(&buffer[..n]);
    }
    source.finish_snapshot()?;
    scope.checkpoint()?;
    let digest = state.finish();
    scope.checkpoint()?;
    Ok(digest)
}

/// [`hash_source`] for a host that is handed the bytes instead of reading them, so that it can
/// wait for the client without holding a thread. The accounting is the one of `hash_source`
/// for an ordinary source: every byte is charged to `input_bytes` before it is hashed, with
/// the same N+1 probe at the limit (`InputLimit` for the byte that passes it) and the same
/// control/deadline checks. The hash state is metadata-accounted; the caller owns (and
/// accounts) the buffer the pieces come from.
pub struct HashStream {
    state: HashState,
    _metadata: ResourceReservation,
}
impl HashStream {
    pub fn new(algorithm: HashAlg, scope: &ResourceScope) -> Result<Self, ProcessingError> {
        scope.checkpoint()?;
        scope.check_input()?;
        let metadata = scope.reserve_metadata(std::mem::size_of::<HashState>() as u64)?;
        Ok(Self {
            state: HashState::new(algorithm),
            _metadata: metadata,
        })
    }
    /// Hashes `bytes` after charging them to the operation.
    pub fn update(
        &mut self,
        mut bytes: &[u8],
        scope: &ResourceScope,
    ) -> Result<(), ProcessingError> {
        while !bytes.is_empty() {
            scope.checkpoint()?;
            let request = scope.input_request(bytes.len())?;
            if request == 0 || request > bytes.len() {
                return Err(ProcessingError::InvalidInput(
                    "reader exceeded its supplied buffer",
                ));
            }
            scope.consumed_input(request as u64)?;
            scope.checkpoint()?;
            self.state.update(&bytes[..request]);
            bytes = &bytes[request..];
        }
        Ok(())
    }
    pub fn finish(self, scope: &ResourceScope) -> Result<DigestValue, ProcessingError> {
        scope.checkpoint()?;
        let digest = self.state.finish();
        scope.checkpoint()?;
        Ok(digest)
    }
}
