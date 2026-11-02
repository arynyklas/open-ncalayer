//! Fixed-size digests and streaming RustCrypto hash states. No document buffering.
use crate::io::Source;
use crate::key::HashAlg;
use crate::resource::{IO_CHUNK_BYTES, ProcessingError, ResourceScope};
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
pub fn hash_source(
    mut source: Source<'_>,
    algorithm: HashAlg,
    scope: &mut ResourceScope,
) -> Result<DigestValue, ProcessingError> {
    scope.checkpoint()?;
    scope.check_input()?;
    if source
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
    loop {
        scope.checkpoint()?;
        let request = scope.input_request(capacity)?;
        let n = match source.read(&mut buffer[..request]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n > request {
            return Err(ProcessingError::InvalidInput(
                "reader exceeded its supplied buffer",
            ));
        }
        scope.consumed_input(n as u64)?;
        scope.checkpoint()?;
        if n == 0 {
            break;
        }
        state.update(&buffer[..n]);
    }
    scope.checkpoint()?;
    let digest = state.finish();
    scope.checkpoint()?;
    Ok(digest)
}
