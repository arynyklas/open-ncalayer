//! The published installer as it is: one stream from its URL into a file, hashed while it
//! streams, then looked at as a program.
//!
//! Nothing else gives the manifest an installer hash: not the release API (its digest is an
//! expected value to compare against), not the build that made the file, not a probe report
//! (a claim to compare against). A hash of bytes other than the published ones, or of bytes
//! that are not the installer entry of this version and flavor, ends the run.

use std::fmt;
use std::path::Path;

use anyhow::Context;
use object::pe::IMAGE_DIRECTORY_ENTRY_SECURITY;
use object::read::pe::{PeFile32, PeFile64};
use oncl_update::Version;
use oncl_winget_setup::payload::{self, Arch as PayloadArch};

use super::Arch;
use crate::upstream::http::{Fetcher, RequestCtx};

/// The most a published installer may have: the entry carries one `Setup.exe` and is far
/// smaller; a larger body is a mistake or an attack, not an installer.
pub const INSTALLER_MAX: u64 = 512 << 20;

/// What one download gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Downloaded {
    /// Bytes received.
    pub size: u64,
    /// SHA-256 of them, lowercase hex.
    pub sha256: String,
}

/// Where the bytes of a published asset come from.
pub trait AssetFetch {
    /// Streams `url` into `dest` once, at most `limit` bytes, and reports what arrived.
    ///
    /// # Errors
    ///
    /// The transfer fails, or the body is larger than `limit`.
    fn fetch(&self, url: &str, limit: u64, dest: &Path) -> anyhow::Result<Downloaded>;
}

/// The real thing: HTTPS to public addresses only, redirects followed with every hop checked.
#[derive(Debug, Default)]
pub struct Https {
    fetcher: Option<Fetcher>,
}

impl Https {
    /// A downloader that reaches the Internet.
    pub fn new() -> Https {
        Https::default()
    }

    /// A downloader with a configured client (tests reach a local mock through it).
    pub fn with(fetcher: Fetcher) -> Https {
        Https {
            fetcher: Some(fetcher),
        }
    }
}

impl AssetFetch for Https {
    fn fetch(&self, url: &str, limit: u64, dest: &Path) -> anyhow::Result<Downloaded> {
        let fetcher = self.fetcher.clone().unwrap_or_default();
        let done = fetcher
            .download(url, limit, &RequestCtx::default(), dest)
            .with_context(|| format!("downloading {url}"))?;
        Ok(Downloaded {
            size: done.size,
            sha256: done.sha256,
        })
    }
}

/// Why downloaded bytes are not an acceptable installer asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetError {
    /// The release API reports another size than the bytes that arrived.
    SizeMismatch {
        /// The asset.
        name: String,
        /// The API.
        api: u64,
        /// The stream.
        actual: u64,
    },
    /// The release API's digest is another than the hash of the bytes that arrived.
    DigestMismatch {
        /// The asset.
        name: String,
        /// The API.
        api: String,
        /// The stream.
        actual: String,
    },
    /// The bytes are not the WinGet installer entry of this version and architecture.
    NotTheInstaller {
        /// The asset.
        name: String,
        /// Why.
        why: String,
    },
    /// The installer carries no Authenticode signature (no certificate table).
    NotSigned(String),
}

impl fmt::Display for AssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetError::SizeMismatch { name, api, actual } => write!(
                f,
                "{name}: the release says {api} bytes, the download is {actual} bytes"
            ),
            AssetError::DigestMismatch { name, api, actual } => write!(
                f,
                "{name}: the release's digest sha256:{api} is not the hash {actual} of the downloaded bytes"
            ),
            AssetError::NotTheInstaller { name, why } => write!(
                f,
                "{name} is not the WinGet installer of this version and flavor: {why}"
            ),
            AssetError::NotSigned(name) => write!(
                f,
                "{name} has no Authenticode signature: only a signed final file gets a manifest"
            ),
        }
    }
}

impl std::error::Error for AssetError {}

fn certificate_table(pe: &[u8]) -> Option<bool> {
    let present = |directory: Option<&object::pe::ImageDataDirectory>| {
        directory.is_some_and(|d| {
            let (offset, size) = d.address_range();
            offset != 0 && size != 0 && u64::from(offset) + u64::from(size) <= pe.len() as u64
        })
    };
    if let Ok(file) = PeFile64::parse(pe) {
        return Some(present(
            file.data_directories().get(IMAGE_DIRECTORY_ENTRY_SECURITY),
        ));
    }
    PeFile32::parse(pe)
        .ok()
        .map(|file| present(file.data_directories().get(IMAGE_DIRECTORY_ENTRY_SECURITY)))
}

/// Checks the downloaded file `path` against what the release says and what an installer entry
/// must be: sizes and digests agree; it is a PE of `arch` carrying the unchanged `Setup.exe`
/// of `version` and `arch` ([`payload::read`]); and a certificate table is present.
///
/// # Errors
///
/// An [`AssetError`], wrapped.
pub fn inspect(
    name: &str,
    path: &Path,
    downloaded: &Downloaded,
    api_size: u64,
    api_sha256: Option<&str>,
    arch: Arch,
    version: &Version,
) -> anyhow::Result<()> {
    if downloaded.size != api_size {
        return Err(AssetError::SizeMismatch {
            name: name.to_owned(),
            api: api_size,
            actual: downloaded.size,
        }
        .into());
    }
    if let Some(api) = api_sha256
        && api != downloaded.sha256
    {
        return Err(AssetError::DigestMismatch {
            name: name.to_owned(),
            api: api.to_owned(),
            actual: downloaded.sha256.clone(),
        }
        .into());
    }
    let not_installer = |why: String| AssetError::NotTheInstaller {
        name: name.to_owned(),
        why,
    };
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let want = match arch {
        Arch::X64 => PayloadArch::X64,
        Arch::X86 => PayloadArch::X86,
    };
    if PayloadArch::of_image(&bytes) != Some(want) {
        return Err(not_installer(format!("it is not a PE image of {arch}")).into());
    }
    let embedded = payload::read(&bytes)
        .map_err(|e| not_installer(format!("it carries no valid Setup payload ({e})")))?;
    if embedded.arch != want || embedded.version != *version {
        return Err(not_installer(format!(
            "its payload is {} of version {}",
            embedded.arch, embedded.version
        ))
        .into());
    }
    if certificate_table(&bytes) != Some(true) {
        return Err(AssetError::NotSigned(name.to_owned()).into());
    }
    Ok(())
}
