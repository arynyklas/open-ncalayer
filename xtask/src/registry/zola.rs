//! Zola, the site generator: a build tool, not a dependency. One pinned version for CI,
//! Pages and local builds, downloaded from its GitHub release into
//! `target/tools/zola-v<version>/`, the archive checked against the pinned sha256 before it
//! is unpacked and the binary's `--version` after.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

use crate::fetch::{download, verify_sha256};

/// The pinned Zola.
pub const ZOLA_VERSION: &str = "0.23.6";

/// A release archive of Zola for one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZolaAsset {
    /// The Rust target triple.
    pub target: &'static str,
    /// The asset's file name.
    pub name: &'static str,
    /// Its sha256, lowercase hex.
    pub sha256: &'static str,
}

/// The archives of [`ZOLA_VERSION`], hashes from the release's asset digests, checked by
/// downloading.
pub const ZOLA_ASSETS: [ZolaAsset; 4] = [
    ZolaAsset {
        target: "x86_64-unknown-linux-gnu",
        name: "zola-v0.23.6-x86_64-unknown-linux-gnu.tar.gz",
        sha256: "8f5132b3522412d04e395e0b25f6d68613ad272a873e54a2b3ebf664873024a4",
    },
    ZolaAsset {
        target: "x86_64-pc-windows-msvc",
        name: "zola-v0.23.6-x86_64-pc-windows-msvc.zip",
        sha256: "79179284f816febc281adbedb27189806cf22f83e8be4d0fca6835fbeeb09587",
    },
    ZolaAsset {
        target: "x86_64-apple-darwin",
        name: "zola-v0.23.6-x86_64-apple-darwin.tar.gz",
        sha256: "79a4d0ab51a4d863c068e6e594c6fce36f0aa17429a414ea63066f5910d14460",
    },
    ZolaAsset {
        target: "aarch64-apple-darwin",
        name: "zola-v0.23.6-aarch64-apple-darwin.tar.gz",
        sha256: "cbffbd29b3f59c3f52633507c8cb945a7a02d8b1399b43b235f5932912297aa3",
    },
];

/// The archive for a host, by `std::env::consts::{OS, ARCH}`.
pub fn asset_for(os: &str, arch: &str) -> Option<&'static ZolaAsset> {
    let target = match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        _ => return None,
    };
    ZOLA_ASSETS.iter().find(|asset| asset.target == target)
}

/// The pinned Zola under `root/target/tools`, downloaded and checked if missing.
///
/// # Errors
///
/// No archive for this host, a failed download, a sha256 mismatch, a failed unpacking or a
/// binary of another version.
pub fn ensure(root: &Path) -> anyhow::Result<PathBuf> {
    let dir = root.join(format!("target/tools/zola-v{ZOLA_VERSION}"));
    let exe = dir.join(format!("zola{}", std::env::consts::EXE_SUFFIX));
    if !exe.is_file() {
        let asset = asset_for(std::env::consts::OS, std::env::consts::ARCH).with_context(|| {
            format!(
                "no Zola {ZOLA_VERSION} archive for {} {}: pass --zola",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
        let url = format!(
            "https://github.com/getzola/zola/releases/download/v{ZOLA_VERSION}/{}",
            asset.name
        );
        println!("downloading {url}");
        let bytes = download(&url)?;
        verify_sha256(&bytes, asset.sha256).with_context(|| url.clone())?;
        let unpacked = dir.with_extension("partial");
        if unpacked.exists() {
            fs::remove_dir_all(&unpacked)
                .with_context(|| format!("removing {}", unpacked.display()))?;
        }
        fs::create_dir_all(&unpacked)
            .with_context(|| format!("creating {}", unpacked.display()))?;
        let archive = unpacked.join(asset.name);
        fs::write(&archive, &bytes).with_context(|| format!("writing {}", archive.display()))?;
        if asset.name.ends_with(".zip") {
            let file = fs::File::open(&archive)?;
            zip::ZipArchive::new(file)
                .and_then(|mut zip| zip.extract(&unpacked))
                .with_context(|| format!("unpacking {}", archive.display()))?;
        } else {
            let status = Command::new("tar")
                .arg("-xzf")
                .arg(asset.name)
                .current_dir(&unpacked)
                .status()
                .context("running tar")?;
            if !status.success() {
                bail!("tar -xzf {} failed with {status}", archive.display());
            }
        }
        fs::remove_file(&archive)?;
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        }
        fs::rename(&unpacked, &dir)
            .with_context(|| format!("renaming {} to {}", unpacked.display(), dir.display()))?;
    }
    check_version(&exe)?;
    Ok(exe)
}

/// `zola --version` is the pinned one.
fn check_version(zola: &Path) -> anyhow::Result<()> {
    let output = Command::new(zola)
        .arg("--version")
        .output()
        .with_context(|| format!("running {}", zola.display()))?;
    let printed = String::from_utf8_lossy(&output.stdout);
    let expected = format!("zola {ZOLA_VERSION}");
    if !output.status.success() || printed.trim() != expected {
        bail!(
            "{} --version printed {:?}, not {expected:?}",
            zola.display(),
            printed.trim()
        );
    }
    Ok(())
}

/// `zola --root <src> build --output-dir <public>`, `public` removed first.
///
/// # Errors
///
/// Zola is not the pinned version, or the build fails.
pub fn build(zola: &Path, src: &Path, public: &Path) -> anyhow::Result<()> {
    check_version(zola)?;
    if public.exists() {
        fs::remove_dir_all(public).with_context(|| format!("removing {}", public.display()))?;
    }
    let status = Command::new(zola)
        .arg("--root")
        .arg(src)
        .arg("build")
        .arg("--output-dir")
        .arg(public)
        .status()
        .with_context(|| format!("running {}", zola.display()))?;
    if !status.success() {
        bail!("zola build failed with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_for_known_hosts() {
        let target = |os, arch| asset_for(os, arch).map(|a| a.target);
        assert_eq!(target("linux", "x86_64"), Some("x86_64-unknown-linux-gnu"));
        assert_eq!(target("windows", "x86_64"), Some("x86_64-pc-windows-msvc"));
        assert_eq!(target("macos", "x86_64"), Some("x86_64-apple-darwin"));
        assert_eq!(target("macos", "aarch64"), Some("aarch64-apple-darwin"));
        assert_eq!(target("linux", "aarch64"), None);
    }

    #[test]
    fn pins_are_hex64_and_named_by_version() {
        for asset in ZOLA_ASSETS {
            assert_eq!(asset.sha256.len(), 64, "{}", asset.name);
            assert!(
                asset
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{}",
                asset.name
            );
            assert!(
                asset
                    .name
                    .starts_with(&format!("zola-v{ZOLA_VERSION}-{}.", asset.target)),
                "{}",
                asset.name
            );
        }
    }
}
