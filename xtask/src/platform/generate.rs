//! The independent reference generator of the platform proof.
//!
//! Everything a case expects is derived here, by construction, and never by calling
//! `oncl-xml`, `oncl-pdf` or `oncl-pki` parsers or canonicalizers: the XML records are
//! written in a deliberately non-canonical lexical form while their canonical form is
//! produced by a second, independent code path from the same logical values, and every
//! digest comes from `sha2` over bytes this module itself wrote. The generator is checked
//! against third-party tools on small instances (lxml for XML canonicalization, pyHanko for
//! the PDF structure) by `platform-proof` BEFORE any large file is made.

pub mod pdf;
pub mod xml;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
};

/// Buffer of the generator's file writer (large sequential writes).
const WRITE_BUFFER: usize = 4 << 20;

/// xoshiro256++ seeded through splitmix64: deterministic, fast, and not a security
/// primitive (the bytes are test content).
#[derive(Clone)]
pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut z = seed;
        let mut next = || {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^ (x >> 31)
        };
        Self {
            s: [next(), next(), next(), next()],
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform-ish value below `bound` (modulo bias is irrelevant for test content).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        let mut chunks = out.chunks_exact_mut(8);
        for chunk in &mut chunks {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let rest = chunks.into_remainder();
        if !rest.is_empty() {
            let word = self.next_u64().to_le_bytes();
            rest.copy_from_slice(&word[..rest.len()]);
        }
    }
}

/// A file writer that tracks the position and hashes everything written.
pub struct HashingFile {
    inner: BufWriter<File>,
    position: u64,
    sha256: Sha256,
    sha512: Option<Sha512>,
}

impl HashingFile {
    pub fn create(path: &Path, with_sha512: bool) -> io::Result<Self> {
        Ok(Self {
            inner: BufWriter::with_capacity(WRITE_BUFFER, File::create(path)?),
            position: 0,
            sha256: Sha256::new(),
            sha512: with_sha512.then(Sha512::new),
        })
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    /// SHA-256 of everything written so far (does not disturb the running hash).
    pub fn prefix_sha256(&self) -> String {
        hex(&self.sha256.clone().finalize())
    }

    pub fn finish(mut self) -> io::Result<FileDigests> {
        self.inner.flush()?;
        self.inner.get_ref().sync_all()?;
        Ok(FileDigests {
            len: self.position,
            sha256: hex(&self.sha256.finalize()),
            sha512: self.sha512.map(|h| hex(&h.finalize())),
        })
    }
}

impl Write for HashingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)?;
        self.sha256.update(buf);
        if let Some(h) = &mut self.sha512 {
            h.update(buf);
        }
        self.position = self
            .position
            .checked_add(buf.len() as u64)
            .ok_or_else(|| io::Error::other("position overflow"))?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileDigests {
    pub len: u64,
    pub sha256: String,
    pub sha512: Option<String>,
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A canonical-form accumulator: SHA-256 of the canonical octets plus their count.
#[derive(Clone, Default)]
pub struct CanonHash {
    sha256: Sha256,
    len: u64,
}

impl CanonHash {
    pub fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        self.len += bytes.len() as u64;
    }

    pub fn finish(self) -> (String, u64) {
        (hex(&self.sha256.finalize()), self.len)
    }
}

/// Real byte stream: framed pseudo-random content with a visible structure (magic,
/// frame counter, length, payload, checksum), never zero or constant fill.
pub mod blob {
    use super::*;

    const MAGIC: &[u8; 8] = b"ONCLBLOB";
    const FRAME_PAYLOAD: usize = 1 << 20;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct BlobFacts {
        pub frames: u64,
    }

    /// Writes exactly `total` bytes. Returns the facts and the file digests.
    pub fn generate(path: &Path, total: u64, seed: u64) -> io::Result<(BlobFacts, FileDigests)> {
        let mut file = HashingFile::create(path, true)?;
        let mut rng = Rng::new(seed);
        let mut payload = vec![0u8; FRAME_PAYLOAD];
        let mut frames = 0u64;
        let overhead = (MAGIC.len() + 8 + 4 + 4) as u64;
        while file.position() < total {
            let remaining = total - file.position();
            if remaining <= overhead {
                // Fewer bytes left than one frame: end with random trailer bytes.
                let mut tail = vec![0u8; remaining as usize];
                rng.fill(&mut tail);
                file.write_all(&tail)?;
                break;
            }
            let take = (remaining - overhead).min(FRAME_PAYLOAD as u64) as usize;
            rng.fill(&mut payload[..take]);
            let checksum = payload[..take]
                .chunks(8)
                .fold(0u32, |a, c| a.rotate_left(5) ^ u32::from(c[0]) ^ c.len() as u32);
            file.write_all(MAGIC)?;
            file.write_all(&frames.to_be_bytes())?;
            file.write_all(&(take as u32).to_be_bytes())?;
            file.write_all(&payload[..take])?;
            file.write_all(&checksum.to_be_bytes())?;
            frames += 1;
        }
        let digests = file.finish()?;
        Ok((BlobFacts { frames }, digests))
    }
}
