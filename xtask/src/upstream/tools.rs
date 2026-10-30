//! `cargo xtask upstream tools`: the external unpackers, pinned. innounp (Windows only) is
//! downloaded from a fixed commit of its repository and checked against SHA-256 values
//! recorded here; 7-Zip comes from the runner image.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;

use super::http::{Fetcher, RequestCtx};
use crate::fetch::verify_sha256;

/// innounp 2.71.2 (`innounp-2/bin/innounp-2.zip` of InnoUnpacker-Windows-GUI at a fixed
/// commit).
pub const INNOUNP_URL: &str = "https://raw.githubusercontent.com/jrathlev/InnoUnpacker-Windows-GUI/032d64c782efc6b36766d8f9c3b1b2f042144a58/innounp-2/bin/innounp-2.zip";
/// SHA-256 of that zip.
pub const INNOUNP_ZIP_SHA256: &str =
    "10fce27b6344b7674d5625cc34afca1c88c12183d957c6d93e401097fa2556cd";
/// SHA-256 of `innounp.exe` inside it.
pub const INNOUNP_EXE_SHA256: &str =
    "aecc0d7b1a2669711cd86d50061bb68911faa832ca3c69d4b1d2deb735cb1fcd";
/// Largest zip accepted.
const INNOUNP_ZIP_MAX: u64 = 16 << 20;

/// Downloads innounp from `url` into `out`, checks both hashes and returns the program's
/// path. Nothing is left behind on a mismatch.
///
/// # Errors
///
/// Download, hash or zip errors.
pub fn fetch_innounp(
    fetcher: &Fetcher,
    url: &str,
    zip_sha256: &str,
    exe_sha256: &str,
    out: &Path,
) -> anyhow::Result<PathBuf> {
    let zip_bytes = fetcher
        .get(url, INNOUNP_ZIP_MAX, &RequestCtx::default())
        .map_err(|e| anyhow::anyhow!("innounp: {e}"))?
        .body;
    verify_sha256(&zip_bytes, zip_sha256).context("innounp zip")?;
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("innounp zip")?;
    let mut exe = Vec::new();
    archive
        .by_name("innounp.exe")
        .context("innounp.exe in the zip")?
        .take(INNOUNP_ZIP_MAX)
        .read_to_end(&mut exe)?;
    verify_sha256(&exe, exe_sha256).context("innounp.exe")?;
    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;
    let path = out.join("innounp.exe");
    std::fs::write(&path, exe).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// 7-Zip: `ONCL_7Z`, else the default Windows install, else `7z` on the `PATH`.
pub fn find_7z() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ONCL_7Z").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    if cfg!(windows) {
        let default = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
        if default.is_file() {
            return Some(default);
        }
    }
    let name = if cfg!(windows) { "7z.exe" } else { "7z" };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// The first line of `7z i` with a version (`7-Zip 24.09 …`), for `run.json`.
pub fn sevenzip_version(exe: &Path) -> Option<String> {
    let out = std::process::Command::new(exe).arg("i").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("7-Zip"))
        .map(|l| l.chars().take(80).collect())
}

/// The oldest 7-Zip used: 25.01 refuses, by default, symbolic links that point out of the
/// output directory (CVE-2025-55188); older versions would write through them.
pub const SEVENZIP_MIN: (u32, u32) = (25, 1);

/// Whether the version line of `7z i` names 7-Zip [`SEVENZIP_MIN`] or newer.
pub fn sevenzip_supported(version_line: &str) -> bool {
    if !version_line.starts_with("7-Zip") {
        return false;
    }
    version_line
        .split_whitespace()
        .find_map(|word| {
            let (major, minor) = word.split_once('.')?;
            Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?))
        })
        .is_some_and(|v| v >= SEVENZIP_MIN)
}

/// The `ONCL_7Z=…` line for 7-Zip found at a path with its version line, or `None` with a
/// warning when it is missing or older than [`SEVENZIP_MIN`]: MSI and DMG distributions are
/// then recorded as skipped, not a failure.
pub fn sevenzip_env_line(found: Option<(PathBuf, Option<String>)>) -> Option<String> {
    match found {
        Some((exe, Some(version))) if sevenzip_supported(&version) => {
            Some(format!("ONCL_7Z={}", exe.display()))
        }
        Some((_, version)) => {
            eprintln!(
                "warning: 7-Zip {} is older than 25.01: MSI and DMG distributions will be skipped",
                version.as_deref().unwrap_or("of unknown version")
            );
            None
        }
        None => {
            eprintln!("warning: 7-Zip not found: MSI and DMG distributions will be skipped");
            None
        }
    }
}

/// `cargo xtask upstream tools --out <dir>`: prints `ONCL_INNOUNP=…` (Windows) and
/// `ONCL_7Z=…` for `$GITHUB_ENV`.
///
/// # Errors
///
/// innounp cannot be fetched or checked.
pub fn tools(out: &Path) -> anyhow::Result<()> {
    if cfg!(windows) {
        let exe = fetch_innounp(
            &Fetcher::new(),
            INNOUNP_URL,
            INNOUNP_ZIP_SHA256,
            INNOUNP_EXE_SHA256,
            out,
        )?;
        println!("ONCL_INNOUNP={}", exe.display());
    }
    let found = find_7z().map(|exe| {
        let version = sevenzip_version(&exe);
        (exe, version)
    });
    if let Some(line) = sevenzip_env_line(found) {
        println!("{line}");
    }
    Ok(())
}
