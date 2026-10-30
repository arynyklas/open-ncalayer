//! The `.onclp` package: a zip of exactly two files at its root, `plugin.toml`
//! ([`Manifest`]) and `plugin.wasm` (a WebAssembly module). Sizes are those of the unpacked
//! data as read, never those the zip headers claim.

use crate::{Manifest, PackageError};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use zip::ZipArchive;
use zip::write::SimpleFileOptions;

/// The extension of a package file.
pub const PACKAGE_EXT: &str = "onclp";
/// The largest package file: 32 MiB.
pub const MAX_PACKAGE: u64 = 32 << 20;
/// The largest `plugin.wasm`, unpacked: 16 MiB.
pub const MAX_WASM: u64 = 16 << 20;
/// The largest `plugin.toml`, unpacked: 64 KiB.
pub const MAX_MANIFEST: u64 = 64 << 10;

const MANIFEST_FILE: &str = "plugin.toml";
const WASM_FILE: &str = "plugin.wasm";
/// `\0asm` and version 1: how a core WebAssembly module starts.
const WASM_HEADER: &[u8] = b"\0asm\x01\0\0\0";

/// A checked package.
#[derive(Clone)]
pub struct Package {
    /// `plugin.toml`, checked.
    pub manifest: Manifest,
    /// `plugin.wasm`: a module of WebAssembly version 1, not yet validated.
    pub wasm: Vec<u8>,
    /// sha256 of the whole package file, as the update index gives it.
    pub sha256: [u8; 32],
}

impl fmt::Debug for Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sha256: String = self.sha256.iter().map(|b| format!("{b:02x}")).collect();
        f.debug_struct("Package")
            .field("manifest", &self.manifest)
            .field("wasm", &format_args!("{} bytes", self.wasm.len()))
            .field("sha256", &sha256)
            .finish()
    }
}

impl Package {
    /// Reads and checks a package from the bytes of its file.
    pub fn read(bytes: &[u8]) -> Result<Package, PackageError> {
        if bytes.len() as u64 > MAX_PACKAGE {
            return Err(PackageError::TooLarge);
        }
        let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| PackageError::NotZip)?;
        let (manifest_index, wasm_index) = find_entries(&mut archive)?;

        let manifest = read_entry(&mut archive, manifest_index, MAX_MANIFEST)?;
        let manifest = String::from_utf8(manifest)
            .map_err(|_| PackageError::Manifest(format!("{MANIFEST_FILE} is not UTF-8")))?;
        let manifest = Manifest::from_toml(&manifest)?;

        let wasm = read_entry(&mut archive, wasm_index, MAX_WASM)?;
        if !wasm.starts_with(WASM_HEADER) {
            return Err(PackageError::Entries(format!(
                "{WASM_FILE} is not a WebAssembly module of version 1"
            )));
        }
        Ok(Package {
            manifest,
            wasm,
            sha256: Sha256::digest(bytes).into(),
        })
    }

    /// Reads and checks a package file.
    pub fn read_file(path: &Path) -> Result<Package, PackageError> {
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_PACKAGE {
            return Err(PackageError::TooLarge);
        }
        // The file may grow after the size was looked at.
        let mut bytes = Vec::new();
        file.take(MAX_PACKAGE + 1).read_to_end(&mut bytes)?;
        Package::read(&bytes)
    }
}

/// The package of `manifest` (the bytes of `plugin.toml`) and `wasm`, the same bytes for the
/// same input: both deflated, with a fixed time and mode. Not checked: [`Package::read`]
/// the result.
///
/// # Errors
///
/// The zip writer failed.
pub fn archive(manifest: &[u8], wasm: &[u8]) -> zip::result::ZipResult<Vec<u8>> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);
    for (name, body) in [(MANIFEST_FILE, manifest), (WASM_FILE, wasm)] {
        zip.start_file(name, options)?;
        zip.write_all(body)?;
    }
    Ok(zip.finish()?.into_inner())
}

/// The indexes of `plugin.toml` and `plugin.wasm`, if they are the only entries: no other
/// names, directories, symbolic links, encrypted or repeated entries.
fn find_entries(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<(usize, usize), PackageError> {
    let bad = PackageError::Entries;
    if archive.has_duplicate_names() {
        return Err(bad("an entry is repeated".to_owned()));
    }
    let (mut manifest, mut wasm) = (None, None);
    for i in 0..archive.len() {
        let entry = archive.by_index_raw(i).map_err(|_| PackageError::NotZip)?;
        let name = String::from_utf8_lossy(entry.name_raw()).into_owned();
        let slot = match entry.name_raw() {
            _ if entry.is_dir() => return Err(bad(format!("{name:?} is a directory"))),
            b"plugin.toml" => &mut manifest,
            b"plugin.wasm" => &mut wasm,
            _ => {
                return Err(bad(format!(
                    "{name:?} is not {MANIFEST_FILE} or {WASM_FILE}"
                )));
            }
        };
        if entry.is_symlink() {
            return Err(bad(format!("{name:?} is a symbolic link")));
        }
        if entry.encrypted() {
            return Err(bad(format!("{name:?} is encrypted")));
        }
        if slot.replace(i).is_some() {
            return Err(bad(format!("{name:?} is repeated")));
        }
    }
    match (manifest, wasm) {
        (Some(manifest), Some(wasm)) => Ok((manifest, wasm)),
        (None, _) => Err(bad(format!("{MANIFEST_FILE} is missing"))),
        (_, None) => Err(bad(format!("{WASM_FILE} is missing"))),
    }
}

/// The unpacked data of entry `index`, at most `limit` bytes.
fn read_entry(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    index: usize,
    limit: u64,
) -> Result<Vec<u8>, PackageError> {
    let entry = archive.by_index(index).map_err(|_| PackageError::NotZip)?;
    // The declared size only refuses early; what is read is counted below.
    if entry.size() > limit {
        return Err(PackageError::TooLarge);
    }
    read_limited(entry, limit)
}

/// All of `reader`, refused once it yields more than `limit` bytes; at most `limit + 1`
/// bytes are read. A read error is corrupt zip data.
fn read_limited(reader: impl Read, limit: u64) -> Result<Vec<u8>, PackageError> {
    let mut data = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| PackageError::NotZip)?;
    if data.len() as u64 > limit {
        return Err(PackageError::TooLarge);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// A reader of endless zeros that counts what it yields.
    struct Zeros(u64);

    impl Read for Zeros {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(0);
            self.0 += buf.len() as u64;
            Ok(buf.len())
        }
    }

    #[test]
    fn read_limited_counts_what_is_read() {
        let mut zeros = Zeros(0);
        assert!(matches!(
            read_limited(&mut zeros, 1000),
            Err(PackageError::TooLarge)
        ));
        assert_eq!(zeros.0, 1001, "stops one byte past the limit");
        assert_eq!(read_limited(&[7u8; 1000][..], 1000).unwrap(), [7u8; 1000]);
        assert!(matches!(
            read_limited(&[7u8; 1001][..], 1000),
            Err(PackageError::TooLarge)
        ));
    }
}
