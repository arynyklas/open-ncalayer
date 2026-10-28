//! [`contents_sha256`]: the sum of the files in a Velopack package (a zip archive), the same
//! for every archive of the same files whatever their order, compression or zip metadata.
//! Velopack rebuilds a full package from the installed one and a delta as a new archive, so
//! the rebuilt file is checked by its contents, not by the sha256 of the published one.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::Digest;

use crate::{Sha256, UpdateError};

/// The sum of the entries of the zip archive at `path`: over the entries sorted by name,
/// each name's length (8 bytes, little-endian), the name and the sha256 of its
/// uncompressed data, after the number of entries. Only the names and the data count, as
/// they are what Velopack installs from a package.
///
/// # Errors
///
/// [`UpdateError::PackageContents`] if the file is not a zip archive, an entry cannot be
/// read or a name is there twice (extractors differ on which one they take);
/// [`UpdateError::Io`] if the file cannot be opened.
pub fn contents_sha256(path: &Path) -> Result<Sha256, UpdateError> {
    let bad = |e: zip::result::ZipError| UpdateError::PackageContents(e.to_string());
    let mut archive = zip::ZipArchive::new(File::open(path)?).map_err(bad)?;
    let mut entries = BTreeMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(bad)?;
        let name = entry.name().map_err(bad)?.into_owned();
        let mut hasher = sha2::Sha256::new();
        loop {
            let n = entry
                .read(&mut buf)
                .map_err(|e| UpdateError::PackageContents(format!("{name}: {e}")))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let sum: [u8; 32] = hasher.finalize().into();
        if entries.insert(name.clone(), sum).is_some() {
            return Err(UpdateError::PackageContents(format!(
                "{name} is in the package twice"
            )));
        }
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update((entries.len() as u64).to_le_bytes());
    for (name, sum) in &entries {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(sum);
    }
    Ok(Sha256(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn archive(path: &Path, entries: &[(&str, &[u8])], method: zip::CompressionMethod) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, data) in entries {
            zip.start_file(
                *name,
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn the_same_files_have_the_same_sum_in_any_archive() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.nupkg");
        let b = dir.path().join("b.nupkg");
        archive(
            &a,
            &[("lib/app/x.exe", b"program"), ("app.nuspec", b"<package/>")],
            zip::CompressionMethod::Deflated,
        );
        archive(
            &b,
            &[("app.nuspec", b"<package/>"), ("lib/app/x.exe", b"program")],
            zip::CompressionMethod::Stored,
        );
        assert_ne!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert_eq!(contents_sha256(&a).unwrap(), contents_sha256(&b).unwrap());

        // Another byte, another name, a file more: another sum.
        for other in [
            &[
                ("lib/app/x.exe", &b"programm"[..]),
                ("app.nuspec", b"<package/>"),
            ][..],
            &[("lib/app/y.exe", b"program"), ("app.nuspec", b"<package/>")],
            &[
                ("lib/app/x.exe", b"program"),
                ("app.nuspec", b"<package/>"),
                ("lib/app/z", b""),
            ],
        ] {
            archive(&b, other, zip::CompressionMethod::Deflated);
            assert_ne!(contents_sha256(&a).unwrap(), contents_sha256(&b).unwrap());
        }
    }

    #[test]
    fn not_a_package_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.nupkg");
        std::fs::write(&path, b"not a zip archive").unwrap();
        assert!(matches!(
            contents_sha256(&path),
            Err(UpdateError::PackageContents(_))
        ));
        assert!(matches!(
            contents_sha256(&dir.path().join("missing")),
            Err(UpdateError::Io(_))
        ));
    }
}
