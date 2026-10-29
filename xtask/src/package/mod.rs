//! The installers and update packages of a release (`cargo xtask package …`, roadmap D12,
//! P8): the one place the release workflow and CI build them. Velopack's `vpk pack` (the
//! pinned version, `VPK_VERSION` of the workflows) makes the update packages and what it can
//! of the installers; the rest is here:
//!
//! - [`windows`]: `Setup.exe` per flavor with the RID that makes it refuse an older Windows
//!   or another architecture, the Windows 7 payload and installer through the import gate;
//! - [`macos`]: the universal `.app` as `.zip` and as a `.pkg` of our own (hosts x86_64 and
//!   arm64, a postinstall that integrates the app for the console user, as that user);
//! - [`linux`]: the AppDir built in a glibc 2.28 container, checked against that glibc and
//!   started there, then the AppImage;
//! - [`aur`]: `PKGBUILD` and `.SRCINFO` of `openncalayer-bin`.
//!
//! Every published file is named `openncalayer-<version>-<flavor>…` (the update packages keep
//! Velopack's names, which the update index refers to).

pub mod aur;
pub mod linux;
pub mod macos;
pub mod windows;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use oncl_update::Version;

use crate::index::{delta_package_name, full_package_name};

/// Velopack's package id: the install directory on Windows, the bundle name on macOS.
pub const PACK_ID: &str = "OpenNCALayer";
const PACK_TITLE: &str = "OpenNCALayer";
const PACK_AUTHORS: &str = "OpenNCALayer contributors";
/// The documents shipped next to the programs.
const DOCS: [&str; 4] = ["README.md", "README.en.md", "LICENSE", "NOTICE"];
/// The tray icon, also the icon of the installers and the AppImage: 32×32 RGBA PNG.
const ICON: &str = "crates/oncl-ui/assets/tray-ok.png";

/// The `vpk` to run: `$VPK`, otherwise `vpk` on the `PATH`.
fn vpk_program() -> OsString {
    std::env::var_os("VPK").unwrap_or_else(|| OsString::from("vpk"))
}

/// `vpk pack` of `pack_dir` (whose main program is `main_exe`) for `channel` and `runtime`
/// into `packages`, with `extra` options. Velopack's own signing options come from its
/// `VPK_*` environment, set by the workflow when the secrets exist.
fn vpk_pack(
    pack_dir: &Path,
    main_exe: &str,
    version: &Version,
    channel: &str,
    runtime: &str,
    packages: &Path,
    extra: &[OsString],
) -> anyhow::Result<()> {
    let mut command = Command::new(vpk_program());
    command
        .args(["--skip-updates", "pack", "--packId", PACK_ID])
        .arg("--packVersion")
        .arg(version.to_string())
        .args(["--packTitle", PACK_TITLE, "--packAuthors", PACK_AUTHORS])
        .arg("--packDir")
        .arg(pack_dir)
        .args([
            "--mainExe",
            main_exe,
            "--channel",
            channel,
            "--runtime",
            runtime,
        ])
        .arg("--outputDir")
        .arg(packages)
        .args(extra);
    run(&mut command)
}

/// Runs `command`, failing on a nonzero exit.
fn run(command: &mut Command) -> anyhow::Result<()> {
    let shown = format!("{command:?}");
    let status = command
        .status()
        .with_context(|| format!("starting {shown}"))?;
    if !status.success() {
        bail!("{shown} failed: {status}");
    }
    Ok(())
}

/// Copies the documents of the workspace `root` into `dir`.
fn copy_docs(root: &Path, dir: &Path) -> anyhow::Result<()> {
    for doc in DOCS {
        copy(&root.join(doc), &dir.join(doc))?;
    }
    Ok(())
}

/// Copies `from` to `to`, creating `to`'s directory.
fn copy(from: &Path, to: &Path) -> anyhow::Result<()> {
    if let Some(dir) = to.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    fs::copy(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    Ok(())
}

/// A fresh directory for a step's files under `<root>/target/package/`.
fn scratch(root: &Path, prefix: &str) -> anyhow::Result<tempfile::TempDir> {
    let base = root.join("target").join("package");
    fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&base)
        .with_context(|| format!("creating a directory in {}", base.display()))
}

/// Copies the update packages of `version` for `flavor` from Velopack's output `packages`
/// into `dist`: the full package and Velopack's feed `releases.<flavor>.json` (both
/// required), the delta and `RELEASES-<flavor>` if made. Returns the copies.
fn collect_velopack(
    packages: &Path,
    dist: &Path,
    version: &Version,
    flavor: &str,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut copied = Vec::new();
    for (name, required) in [
        (full_package_name(version, flavor), true),
        (format!("releases.{flavor}.json"), true),
        (delta_package_name(version, flavor), false),
        (format!("RELEASES-{flavor}"), false),
    ] {
        let from = packages.join(&name);
        if !from.exists() {
            if required {
                bail!("vpk made no {}", from.display());
            }
            continue;
        }
        let to = dist.join(&name);
        copy(&from, &to)?;
        copied.push(to);
    }
    Ok(copied)
}

/// Copies `from` into `dist` as `name`, returning the copy.
fn publish(from: &Path, dist: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let to = dist.join(name);
    copy(from, &to)?;
    Ok(to)
}

/// The text of the file `name` inside the zip archive `archive` (a `.nupkg`).
fn zip_text(archive: &Path, name: impl Fn(&str) -> bool) -> anyhow::Result<String> {
    use std::io::Read as _;
    let file = fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut zip =
        zip::ZipArchive::new(file).with_context(|| format!("reading {}", archive.display()))?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if name(&entry.name()?) {
            let mut text = String::new();
            entry.read_to_string(&mut text)?;
            return Ok(text);
        }
    }
    bail!("{} has no such file", archive.display())
}

/// The value of the element `<tag>` of the nuspec `xml`, if it has one.
fn nuspec_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuspec_values_are_read() {
        let xml = "<metadata>\n<channel>win7-x64</channel>\n<osMinVersion>7</osMinVersion>\n\
                   <machineArchitecture> x64 </machineArchitecture></metadata>";
        assert_eq!(nuspec_value(xml, "osMinVersion"), Some("7"));
        assert_eq!(nuspec_value(xml, "machineArchitecture"), Some("x64"));
        assert_eq!(nuspec_value(xml, "rid"), None);
    }
}
