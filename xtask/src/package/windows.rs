//! The Windows installers: per flavor, `vpk pack` makes the update packages and `Setup.exe`,
//! a per-user installer into `%LOCALAPPDATA%\OpenNCALayer` (roadmap D12). Its RID sets
//! what the installer accepts before it writes anything: `win10-*` refuses Windows 7 and
//! 8, `win7-*` asks for Windows 7 SP1, and an x64 package refuses an x86 system. The
//! installer runs the daemon's hooks (`openncalayer::lifecycle`).
//!
//! A Windows 7 flavor ships its app-local DLLs, and both its payload (our programs, the
//! DLLs, Velopack's `Squirrel.exe` and stub) and `Setup.exe` itself pass the import gate.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::Version;

use super::{
    PACK_ID, collect_velopack, copy, copy_docs, nuspec_value, publish, scratch, vpk_pack, zip_text,
};
use crate::imports;
use crate::index::full_package_name;
use crate::win7;

/// A Windows flavor of the update index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsFlavor {
    /// The flavor (Velopack's channel): `win-x64`, `win7-x86`, ….
    pub name: &'static str,
    /// The RID given to vpk: the oldest Windows and the architecture `Setup.exe` accepts.
    pub runtime: &'static str,
    /// `osMinVersion` the RID writes into the package.
    pub os_min_version: &'static str,
    /// `machineArchitecture` the RID writes into the package.
    pub architecture: &'static str,
    /// A Windows 7 build: app-local DLLs, import gate.
    pub win7: bool,
}

/// The Windows flavors.
pub const FLAVORS: [WindowsFlavor; 4] = [
    WindowsFlavor {
        name: "win-x64",
        runtime: "win10-x64",
        os_min_version: "10",
        architecture: "x64",
        win7: false,
    },
    WindowsFlavor {
        name: "win-x86",
        runtime: "win10-x86",
        os_min_version: "10",
        architecture: "x86",
        win7: false,
    },
    WindowsFlavor {
        name: "win7-x64",
        runtime: "win7-x64",
        os_min_version: "7",
        architecture: "x64",
        win7: true,
    },
    WindowsFlavor {
        name: "win7-x86",
        runtime: "win7-x86",
        os_min_version: "7",
        architecture: "x86",
        win7: true,
    },
];

/// The Windows flavor `name`.
///
/// # Errors
///
/// `name` is not one.
pub fn flavor(name: &str) -> anyhow::Result<WindowsFlavor> {
    FLAVORS
        .into_iter()
        .find(|f| f.name == name)
        .with_context(|| format!("{name:?} is not a Windows flavor"))
}

/// The published installer: `openncalayer-<version>-<flavor>-setup.exe`.
pub fn setup_name(version: &Version, flavor: &WindowsFlavor) -> String {
    format!("openncalayer-{version}-{}-setup.exe", flavor.name)
}

/// The executables of the package next to the daemon.
const PROGRAMS: [&str; 2] = ["openncalayer.exe", "nmhost.exe"];

/// Packs the programs in `bin` (built for `flavor`, with the app-local DLLs of a Windows 7
/// flavor) as `version` into Velopack's output `packages` (where the previous full package
/// for the delta already is), checks the result, and copies what is published into `dist`:
/// the update packages and [`setup_name`]. Returns the published files.
///
/// # Errors
///
/// A file is missing, vpk fails, the package's OS or architecture is not the flavor's, or a
/// Windows 7 payload or installer fails the import gate.
pub fn package(
    root: &Path,
    flavor: &WindowsFlavor,
    bin: &Path,
    version: &Version,
    packages: &Path,
    dist: &Path,
) -> anyhow::Result<Vec<PathBuf>> {
    let work = scratch(root, &format!("{}-", flavor.name))?;
    let pack = work.path().join("pack");
    let files: Vec<&str> = if flavor.win7 {
        win7::FILES.iter().map(|(_, name)| *name).collect()
    } else {
        PROGRAMS.to_vec()
    };
    for file in files {
        copy(&bin.join(file), &pack.join(file))?;
    }
    copy_docs(root, &pack)?;
    let icon = work.path().join("openncalayer.ico");
    let png = fs::read(root.join(super::ICON)).context("reading the icon")?;
    fs::write(&icon, ico_from_png(&png)?).context("writing the icon")?;

    fs::create_dir_all(packages).with_context(|| format!("creating {}", packages.display()))?;
    let extra: Vec<OsString> = vec![
        "--icon".into(),
        icon.into_os_string(),
        // The portable zip is not published.
        "--noPortable".into(),
        // The daemon starts at login through our autostart: a Start menu entry, no desktop
        // shortcut.
        "--shortcuts".into(),
        "StartMenuRoot".into(),
    ];
    vpk_pack(
        &pack,
        PROGRAMS[0],
        version,
        flavor.name,
        flavor.runtime,
        packages,
        &extra,
    )?;

    let full = packages.join(full_package_name(version, flavor.name));
    let nuspec = zip_text(&full, |name| {
        name.ends_with(".nuspec") && !name.contains('/')
    })?;
    check_manifest(&nuspec, flavor)?;
    let setup = packages.join(format!("{PACK_ID}-{}-Setup.exe", flavor.name));
    if !setup.is_file() {
        bail!("vpk made no {}", setup.display());
    }
    if flavor.win7 {
        gate(&full, &setup, &work.path().join("payload"))?;
    }

    fs::create_dir_all(dist).with_context(|| format!("creating {}", dist.display()))?;
    let mut published = collect_velopack(packages, dist, version, flavor.name)?;
    published.push(publish(&setup, dist, &setup_name(version, flavor))?);
    Ok(published)
}

/// Checks that the nuspec of a package says what `Setup.exe` checks before installing: the
/// flavor's channel, its oldest Windows and its architecture, and our program.
///
/// # Errors
///
/// A value differs or is missing.
pub fn check_manifest(nuspec: &str, flavor: &WindowsFlavor) -> anyhow::Result<()> {
    for (tag, expected) in [
        ("channel", flavor.name),
        ("os", "win"),
        ("osMinVersion", flavor.os_min_version),
        ("machineArchitecture", flavor.architecture),
        ("mainExe", PROGRAMS[0]),
    ] {
        let found = nuspec_value(nuspec, tag);
        if found != Some(expected) {
            bail!(
                "the {} package says <{tag}>{}</{tag}>, not {expected}",
                flavor.name,
                found.unwrap_or("(none)")
            );
        }
    }
    Ok(())
}

/// The import gate of a Windows 7 package: the executables of its payload (from the full
/// package `full`, unpacked into `dir`) with the app-local DLLs beside them, and the
/// installer `setup` on its own.
fn gate(full: &Path, setup: &Path, dir: &Path) -> anyhow::Result<()> {
    let file = fs::File::open(full).with_context(|| format!("opening {}", full.display()))?;
    let mut zip =
        zip::ZipArchive::new(file).with_context(|| format!("reading {}", full.display()))?;
    let mut exes = Vec::new();
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let Some(name) = entry.name()?.strip_prefix("lib/app/").map(str::to_owned) else {
            continue;
        };
        if name.is_empty() || name.contains('/') {
            continue;
        }
        let path = dir.join(&name);
        let mut out =
            fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        std::io::copy(&mut entry, &mut out)?;
        if name.to_ascii_lowercase().ends_with(".exe") {
            exes.push(path);
        }
    }
    let required = win7::FILES
        .iter()
        .map(|(_, name)| *name)
        .chain(["Squirrel.exe"]);
    for required in required {
        if !dir.join(required).is_file() {
            bail!("{required} is not in {}", full.display());
        }
    }
    exes.sort();
    let found = imports::check_imports(&exes)? + imports::check_imports_alone(setup)?;
    if found > 0 {
        bail!("{found} violations of the Windows 7 import gate in the package or its installer");
    }
    Ok(())
}

/// A one-image `.ico` of the 32×32 RGBA `png` (a PNG entry, Windows Vista and later).
///
/// # Errors
///
/// `png` is not a 32×32 RGBA PNG: the directory entry says so.
pub fn ico_from_png(png: &[u8]) -> anyhow::Result<Vec<u8>> {
    // IHDR right after the signature: width, height (big-endian), bit depth 8, colour type 6.
    let ihdr = png.get(12..26).context("the icon is not a PNG")?;
    if &png[..8] != b"\x89PNG\r\n\x1a\n" || &ihdr[..4] != b"IHDR" {
        bail!("the icon is not a PNG");
    }
    if ihdr[4..14] != [0, 0, 0, 32, 0, 0, 0, 32, 8, 6] {
        bail!("the icon is not a 32x32 RGBA PNG: the .ico entry says it is");
    }
    let size = u32::try_from(png.len()).context("the icon is too large")?;
    let mut ico = Vec::with_capacity(22 + png.len());
    // ICONDIR: reserved, type 1 (icon), one image.
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    // ICONDIRENTRY: 32×32, no palette, reserved, 1 plane, 32 bpp, size, offset 22.
    ico.extend_from_slice(&[32, 32, 0, 0, 1, 0, 32, 0]);
    ico.extend_from_slice(&size.to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());
    ico.extend_from_slice(png);
    Ok(ico)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavors_refuse_older_windows_and_other_architectures() {
        let win = flavor("win-x86").unwrap();
        assert_eq!((win.runtime, win.os_min_version), ("win10-x86", "10"));
        let win7 = flavor("win7-x64").unwrap();
        assert_eq!((win7.runtime, win7.architecture), ("win7-x64", "x64"));
        assert!(win7.win7 && !win.win7);
        assert!(flavor("osx").is_err());
        let version = Version::parse("0.2.0-beta.1").unwrap();
        assert_eq!(
            setup_name(&version, &win7),
            "openncalayer-0.2.0-beta.1-win7-x64-setup.exe"
        );
    }

    /// The nuspec vpk 1.3.39 writes for `--runtime win7-x64 --channel win7-x64`.
    const WIN7_NUSPEC: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
        <package xmlns=\"http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd\">\n\
        <metadata>\n<id>OpenNCALayer</id>\n<version>0.1.0-alpha.2</version>\n\
        <channel>win7-x64</channel>\n<mainExe>openncalayer.exe</mainExe>\n<os>win</os>\n\
        <rid>win-x64</rid>\n<shortcutLocations>StartMenuRoot</shortcutLocations>\n\
        <osMinVersion>7</osMinVersion>\n<machineArchitecture>x64</machineArchitecture>\n\
        </metadata>\n</package>";

    #[test]
    fn the_manifest_must_hold_the_flavors_limits() {
        let win7 = flavor("win7-x64").unwrap();
        check_manifest(WIN7_NUSPEC, &win7).unwrap();
        // The same package as a Windows 10 flavor would install on Windows 7.
        let err = check_manifest(
            &WIN7_NUSPEC.replace("win7-x64", "win-x64"),
            &flavor("win-x64").unwrap(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("osMinVersion"), "{err}");
        let err = check_manifest(
            &WIN7_NUSPEC.replace("<machineArchitecture>x64", "<machineArchitecture>x86"),
            &win7,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("machineArchitecture"), "{err}");
        let no_arch = WIN7_NUSPEC.replace("<machineArchitecture>x64</machineArchitecture>", "");
        assert!(check_manifest(&no_arch, &win7).is_err());
    }

    #[test]
    fn the_icon_is_one_png_entry() {
        let root = oncl_testkit::workspace_root();
        let png = fs::read(root.join(crate::package::ICON)).unwrap();
        let ico = ico_from_png(&png).unwrap();
        assert_eq!(&ico[..6], &[0, 0, 1, 0, 1, 0]);
        assert_eq!(&ico[6..10], &[32, 32, 0, 0]);
        assert_eq!(
            u32::from_le_bytes(ico[14..18].try_into().unwrap()) as usize,
            png.len()
        );
        assert_eq!(u32::from_le_bytes(ico[18..22].try_into().unwrap()), 22);
        assert_eq!(&ico[22..], &png[..]);
        // Another size would contradict the entry.
        let mut wide = png.clone();
        wide[19] = 64;
        assert!(ico_from_png(&wide).is_err());
        assert!(ico_from_png(b"GIF89a").is_err());
    }
}
