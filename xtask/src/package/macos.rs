//! The macOS packages: one universal `.app` (x86_64 and arm64 joined by `lipo`) for every
//! Mac, the flavor `osx`. `vpk pack` makes the update packages and the `.app` (signed and
//! notarized when the workflow sets Velopack's `VPK_*` signing variables); it is published
//! as a `.zip` and in a `.pkg` of our own: Velopack's `.pkg` would ask Rosetta on Intel-less
//! hosts, and its postinstall runs as root without integrating anything.
//!
//! The `.pkg` ([`distribution`], [`POSTINSTALL`]) installs into `/Applications`, or into
//! `~/Applications` with "Install for me only", on x86_64 and arm64 hosts. Its postinstall
//! integrates the app for the user at the console, as that user
//! (`openncalayer integration install`: the browsers' relay, our LaunchAgent, the original's
//! autostart; never certificates), then starts it. Other users of the Mac get the same at the
//! app's first start.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use oncl_update::Version;

use super::{PACK_ID, collect_velopack, copy, copy_docs, publish, run, scratch, vpk_pack};
use crate::index::full_package_name;

/// The flavor of every Mac.
const FLAVOR: &str = "osx";
/// vpk 1.3.39 takes no runtime for both architectures (`--runtime osx` is refused):
/// `osx-arm64` only labels the package; the binaries stay universal ([`check_universal`]).
const RUNTIME: &str = "osx-arm64";
/// The installer package's identifier.
pub const PKG_ID: &str = "io.github.arynyklas.openncalayer";
/// The programs of the bundle.
const PROGRAMS: [&str; 2] = ["openncalayer", "nmhost"];

/// The published archive: `openncalayer-<version>-osx.zip`.
pub fn zip_name(version: &Version) -> String {
    format!("openncalayer-{version}-{FLAVOR}.zip")
}

/// The published installer: `openncalayer-<version>-osx.pkg`.
pub fn pkg_name(version: &Version) -> String {
    format!("openncalayer-{version}-{FLAVOR}.pkg")
}

/// How the `.pkg` is signed and notarized; all optional.
#[derive(Clone, Debug, Default)]
pub struct PkgSigning {
    /// A "Developer ID Installer" identity: `productbuild --sign`.
    pub identity: Option<String>,
    /// The keychain holding it.
    pub keychain: Option<PathBuf>,
    /// A `notarytool` keychain profile: the `.pkg` is notarized and stapled.
    pub notary_profile: Option<String>,
}

/// Packs the universal programs in `bin` as `version` into Velopack's output `packages`,
/// builds the `.pkg` from the `.app` vpk made, checks both, and copies what is published
/// into `dist`: the update packages, [`zip_name`] and [`pkg_name`]. Returns them. macOS
/// only (`ditto`, `pkgbuild`, `productbuild`, `pkgutil`).
///
/// # Errors
///
/// A program is not universal, a tool fails, or the result is not as described.
pub fn package(
    root: &Path,
    bin: &Path,
    version: &Version,
    packages: &Path,
    dist: &Path,
    signing: &PkgSigning,
) -> anyhow::Result<Vec<PathBuf>> {
    let work = scratch(root, "osx-")?;
    let pack = work.path().join("pack");
    for program in PROGRAMS {
        let path = bin.join(program);
        check_universal(&path)?;
        copy(&path, &pack.join(program))?;
    }
    copy_docs(root, &pack)?;
    fs::create_dir_all(packages).with_context(|| format!("creating {}", packages.display()))?;
    // vpk takes only an .icns icon on macOS, and there is none yet.
    let extra: Vec<OsString> = vec!["--noInst".into()];
    vpk_pack(
        &pack,
        PROGRAMS[0],
        version,
        FLAVOR,
        RUNTIME,
        packages,
        &extra,
    )?;

    // The update package carries both slices.
    let full = packages.join(full_package_name(version, FLAVOR));
    check_package_universal(&full, &work.path().join("nupkg"))?;

    // The .app as vpk made it (and signed it, if asked), from its portable zip.
    let portable = packages.join(format!("{PACK_ID}-{FLAVOR}-Portable.zip"));
    let payload = work.path().join("payload");
    fs::create_dir_all(&payload)?;
    run(Command::new("ditto")
        .args(["-x", "-k"])
        .arg(&portable)
        .arg(&payload))?;
    let app = payload.join(format!("{PACK_ID}.app"));
    for program in PROGRAMS {
        check_universal(&app.join("Contents").join("MacOS").join(program))?;
    }

    let pkg = build_pkg(&payload, version, &work.path().join("pkg"), signing)?;
    fs::create_dir_all(dist).with_context(|| format!("creating {}", dist.display()))?;
    let mut published = collect_velopack(packages, dist, version, FLAVOR)?;
    published.push(publish(&portable, dist, &zip_name(version))?);
    published.push(publish(&pkg, dist, &pkg_name(version))?);
    Ok(published)
}

/// Builds the `.pkg` of the `.app` in `payload` in `work`, signs and notarizes it as
/// `signing` says, and checks its distribution; returns it.
fn build_pkg(
    payload: &Path,
    version: &Version,
    work: &Path,
    signing: &PkgSigning,
) -> anyhow::Result<PathBuf> {
    let scripts = work.join("scripts");
    let components = work.join("components");
    fs::create_dir_all(&scripts)?;
    fs::create_dir_all(&components)?;
    let postinstall = scripts.join("postinstall");
    fs::write(&postinstall, POSTINSTALL)?;
    make_executable(&postinstall)?;
    let plist = work.join("component.plist");
    fs::write(&plist, component_plist())?;
    let distribution_file = work.join("distribution.xml");
    fs::write(&distribution_file, distribution(version))?;

    run(Command::new("pkgbuild")
        .arg("--root")
        .arg(payload)
        .arg("--component-plist")
        .arg(&plist)
        .arg("--scripts")
        .arg(&scripts)
        .args(["--identifier", PKG_ID, "--version"])
        .arg(version.to_string())
        .args(["--install-location", "/Applications"])
        .arg(components.join(COMPONENT)))?;

    let pkg = work.join(pkg_name(version));
    let mut productbuild = Command::new("productbuild");
    productbuild
        .arg("--distribution")
        .arg(&distribution_file)
        .arg("--package-path")
        .arg(&components);
    if let Some(identity) = &signing.identity {
        productbuild.args(["--sign", identity]);
        if let Some(keychain) = &signing.keychain {
            productbuild.arg("--keychain").arg(keychain);
        }
    } else {
        println!("the .pkg is not signed: no installer identity");
    }
    run(productbuild.arg(&pkg))?;

    if let Some(profile) = &signing.notary_profile {
        let mut notarize = Command::new("xcrun");
        notarize.args(["notarytool", "submit"]).arg(&pkg).args([
            "--keychain-profile",
            profile,
            "--wait",
        ]);
        if let Some(keychain) = &signing.keychain {
            notarize.arg("--keychain").arg(keychain);
        }
        run(&mut notarize)?;
        run(Command::new("xcrun").args(["stapler", "staple"]).arg(&pkg))?;
    }

    // What Installer reads: the distribution as built.
    let expanded = work.join("expanded");
    run(Command::new("pkgutil")
        .arg("--expand")
        .arg(&pkg)
        .arg(&expanded))?;
    let built = fs::read_to_string(expanded.join("Distribution"))
        .context("reading the Distribution of the built .pkg")?;
    check_distribution(&built)?;
    Ok(pkg)
}

/// The component package inside the product package.
const COMPONENT: &str = "OpenNCALayer-app.pkg";

/// The distribution of the `.pkg`: both host architectures (an Intel Mac opens it, an
/// Apple silicon Mac does not ask for Rosetta), the system or the user's home, one hidden
/// choice with the app.
pub fn distribution(version: &Version) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>OpenNCALayer</title>
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="true" enable_localSystem="true"/>
    <choices-outline>
        <line choice="default">
            <line choice="{PKG_ID}"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="{PKG_ID}" visible="false">
        <pkg-ref id="{PKG_ID}"/>
    </choice>
    <pkg-ref id="{PKG_ID}" version="{version}" onConclusion="none">{COMPONENT}</pkg-ref>
</installer-gui-script>
"#
    )
}

/// Checks that the distribution `xml` lets both architectures install and has our
/// component.
///
/// # Errors
///
/// It does not.
pub fn check_distribution(xml: &str) -> anyhow::Result<()> {
    let hosts = xml
        .split("hostArchitectures=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .context("the distribution has no hostArchitectures")?;
    let hosts: Vec<&str> = hosts.split(',').map(str::trim).collect();
    for arch in ["x86_64", "arm64"] {
        if !hosts.contains(&arch) {
            bail!("the distribution does not let {arch} hosts install: {hosts:?}");
        }
    }
    if !xml.contains(COMPONENT) {
        bail!("the distribution does not install {COMPONENT}");
    }
    Ok(())
}

/// The component property list: the app is installed where the package says, never
/// relocated to another copy found on disk.
pub fn component_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>BundleHasStrictIdentifier</key>
        <true/>
        <key>BundleIsRelocatable</key>
        <false/>
        <key>BundleIsVersionChecked</key>
        <false/>
        <key>BundleOverwriteAction</key>
        <string>upgrade</string>
        <key>RootRelativeBundlePath</key>
        <string>{PACK_ID}.app</string>
    </dict>
</array>
</plist>
"#
    )
}

/// The `.pkg`'s postinstall. Installer runs it after copying the app, as root for
/// `/Applications` and as the user for "Install for me only"; `$2` is the directory the app
/// went into. It never writes into a user's home as root: the integration runs as the user
/// at the console (`launchctl asuser` + `sudo -u`), in their session. Without one (a remote
/// or managed installation) every user gets it at the app's first start. A failed
/// integration fails the installation, after the app is started (it finishes the
/// integration at its start).
pub const POSTINSTALL: &str = r#"#!/bin/sh
# OpenNCALayer: integrate the app for the user at the console, as that user, and start it.
app="$2/OpenNCALayer.app"
exe="$app/Contents/MacOS/openncalayer"
if [ ! -x "$exe" ]; then
    echo "OpenNCALayer: $exe is missing" >&2
    exit 1
fi
if [ "$(/usr/bin/id -u)" -eq 0 ]; then
    user="$(/usr/bin/stat -f %Su /dev/console)"
    case "$user" in
        "" | root | loginwindow | _mbsetupuser)
            echo "OpenNCALayer: nobody is logged in at the console; the app integrates itself at its first start"
            exit 0
            ;;
    esac
    uid="$(/usr/bin/id -u "$user")" || exit 1
    as_user() {
        /bin/launchctl asuser "$uid" /usr/bin/sudo -u "$user" -H "$@"
    }
else
    as_user() {
        "$@"
    }
fi
# Packages an older version downloaded (Velopack keeps them in the user's caches) must not be
# applied over this one.
as_user /bin/sh -c 'exec /bin/rm -rf "$HOME/Library/Caches/velopack/OpenNCALayer"'
status=0
as_user "$exe" integration install || status=$?
as_user /usr/bin/open "$app" || true
exit "$status"
"#;

#[cfg(unix)]
fn make_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("making {} executable", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// `CPU_TYPE_X86_64` of a Mach-O header.
const CPU_X86_64: u32 = 0x0100_0007;
/// `CPU_TYPE_ARM64` of a Mach-O header.
const CPU_ARM64: u32 = 0x0100_000c;

/// The architectures of the Mach-O file `bytes`: the slices of a universal (fat) binary, or
/// the one of a thin binary; unknown CPU types are left out.
///
/// # Errors
///
/// `bytes` is not a Mach-O file.
pub fn mach_o_archs(bytes: &[u8]) -> anyhow::Result<Vec<&'static str>> {
    let word = |at: usize, big: bool| -> anyhow::Result<u32> {
        let b: [u8; 4] = bytes
            .get(at..at + 4)
            .context("the Mach-O file is cut short")?
            .try_into()?;
        Ok(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    let name = |cpu: u32| match cpu {
        CPU_X86_64 => Some("x86_64"),
        CPU_ARM64 => Some("arm64"),
        _ => None,
    };
    match word(0, true)? {
        // FAT_MAGIC, FAT_MAGIC_64: big-endian headers of 20 or 32 bytes per slice.
        magic @ (0xcafe_babe | 0xcafe_babf) => {
            let count = word(4, true)? as usize;
            if count > 16 {
                bail!("{count} slices: not a universal binary");
            }
            let size = if magic == 0xcafe_babe { 20 } else { 32 };
            (0..count)
                .map(|i| word(8 + i * size, true))
                .filter_map(|cpu| cpu.map(name).transpose())
                .collect()
        }
        // MH_MAGIC_64 as written by a little-endian CPU.
        0xcffa_edfe => Ok(name(word(4, false)?).into_iter().collect()),
        other => bail!("not a Mach-O file (magic {other:#010x})"),
    }
}

/// Checks that the program at `path` is universal: x86_64 and arm64.
///
/// # Errors
///
/// It is not, or cannot be read.
pub fn check_universal(path: &Path) -> anyhow::Result<()> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let archs = mach_o_archs(&bytes).with_context(|| path.display().to_string())?;
    println!("{}: {}", path.display(), archs.join(" "));
    for arch in ["x86_64", "arm64"] {
        if !archs.contains(&arch) {
            bail!("{} is not universal: {}", path.display(), archs.join(" "));
        }
    }
    Ok(())
}

/// Checks every program of the update package `full` (unpacked into `dir`) is universal.
fn check_package_universal(full: &Path, dir: &Path) -> anyhow::Result<()> {
    let file = fs::File::open(full).with_context(|| format!("opening {}", full.display()))?;
    let mut zip =
        zip::ZipArchive::new(file).with_context(|| format!("reading {}", full.display()))?;
    fs::create_dir_all(dir)?;
    let mut found = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let Some(name) = entry.name()?.rsplit('/').next().map(str::to_owned) else {
            continue;
        };
        if !PROGRAMS.contains(&name.as_str()) {
            continue;
        }
        let path = dir.join(&name);
        let mut out = fs::File::create(&path)?;
        std::io::copy(&mut entry, &mut out)?;
        check_universal(&path)?;
        found.push(name);
    }
    for program in PROGRAMS {
        if !found.iter().any(|f| f == program) {
            bail!("{program} is not in {}", full.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fat(slices: &[u32]) -> Vec<u8> {
        let mut bytes = vec![0xca, 0xfe, 0xba, 0xbe];
        bytes.extend_from_slice(&(slices.len() as u32).to_be_bytes());
        for cpu in slices {
            bytes.extend_from_slice(&cpu.to_be_bytes());
            bytes.extend_from_slice(&[0; 16]);
        }
        bytes
    }

    #[test]
    fn universal_binaries_are_told_from_thin_ones() {
        assert_eq!(
            mach_o_archs(&fat(&[CPU_X86_64, CPU_ARM64])).unwrap(),
            ["x86_64", "arm64"]
        );
        // lipo's order does not matter, an unknown slice is left out.
        assert_eq!(
            mach_o_archs(&fat(&[CPU_ARM64, 7, CPU_X86_64])).unwrap(),
            ["arm64", "x86_64"]
        );
        let mut thin = vec![0xcf, 0xfa, 0xed, 0xfe];
        thin.extend_from_slice(&CPU_ARM64.to_le_bytes());
        assert_eq!(mach_o_archs(&thin).unwrap(), ["arm64"]);
        assert!(mach_o_archs(b"\x7fELF\x02\x01\x01").is_err());
        assert!(mach_o_archs(&fat(&[CPU_X86_64])[..10]).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openncalayer");
        fs::write(&path, fat(&[CPU_ARM64])).unwrap();
        let err = check_universal(&path).unwrap_err().to_string();
        assert!(err.contains("not universal"), "{err}");
        fs::write(&path, fat(&[CPU_ARM64, CPU_X86_64])).unwrap();
        check_universal(&path).unwrap();
    }

    #[test]
    fn the_pkg_installs_on_both_architectures() {
        let version = Version::parse("0.2.0-beta.1").unwrap();
        let xml = distribution(&version);
        check_distribution(&xml).unwrap();
        assert!(xml.contains(r#"version="0.2.0-beta.1""#), "{xml}");
        assert!(xml.contains(r#"enable_currentUserHome="true""#), "{xml}");
        // productbuild --synthesize writes no hostArchitectures: refused.
        let synthesized = xml.replace(r#" hostArchitectures="x86_64,arm64""#, "");
        assert!(check_distribution(&synthesized).is_err());
        let arm_only = xml.replace("x86_64,arm64", "arm64");
        let err = check_distribution(&arm_only).unwrap_err().to_string();
        assert!(err.contains("x86_64"), "{err}");
        assert_eq!(pkg_name(&version), "openncalayer-0.2.0-beta.1-osx.pkg");
        assert_eq!(zip_name(&version), "openncalayer-0.2.0-beta.1-osx.zip");
        assert!(component_plist().contains("<string>OpenNCALayer.app</string>"));
    }

    #[test]
    fn the_postinstall_integrates_as_the_console_user_only() {
        // Never as root in a user's home: every command for the user goes through as_user.
        for line in POSTINSTALL.lines().map(str::trim) {
            if line.contains("integration install")
                || line.contains("/usr/bin/open")
                || line.contains("$HOME")
            {
                assert!(line.starts_with("as_user "), "{line}");
            }
        }
        assert!(
            POSTINSTALL.contains("/bin/launchctl asuser \"$uid\" /usr/bin/sudo -u \"$user\" -H")
        );
        assert!(POSTINSTALL.contains("stat -f %Su /dev/console"));
        // No certificate or trust tool anywhere.
        for tool in ["security", "certutil", "trust"] {
            assert!(!POSTINSTALL.contains(&format!("{tool} ")), "{tool}");
        }
        assert!(POSTINSTALL.starts_with("#!/bin/sh\n"));
        // Nothing in a world-writable directory: root would follow a user's symlink there.
        assert!(!POSTINSTALL.contains("/tmp"));
    }

    /// The postinstall runs under `sh` with what Installer passes; as a user it integrates
    /// with the user's own commands (stubbed here) and exits with their status.
    #[cfg(unix)]
    #[test]
    fn the_postinstall_runs_as_the_installing_user() {
        if unsafe { libc::geteuid() } == 0 {
            // Root would take the console-user branch, which needs macOS' tools.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let macos = dir.path().join("OpenNCALayer.app/Contents/MacOS");
        fs::create_dir_all(&macos).unwrap();
        let log = dir.path().join("log");
        let exe = macos.join("openncalayer");
        fs::write(
            &exe,
            format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 3\n", log.display()),
        )
        .unwrap();
        make_executable(&exe).unwrap();
        let script = dir.path().join("postinstall");
        // `open` (macOS', `openvt` on some Linux) becomes a command that records what it
        // would start.
        let opened = dir.path().join("opened");
        let sandboxed = POSTINSTALL.replace(
            "/usr/bin/open",
            &format!("/bin/sh -c 'echo \"$0\" > {}'", opened.display()),
        );
        fs::write(&script, sandboxed).unwrap();
        let home = dir.path().join("home");
        let cache = home.join("Library/Caches/velopack/OpenNCALayer");
        fs::create_dir_all(&cache).unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg(&script)
            .arg("pkg")
            .arg(dir.path())
            .env("HOME", &home)
            .status()
            .unwrap();
        // The integration's failure is the installation's, after the app is started.
        assert_eq!(status.code(), Some(3));
        assert_eq!(fs::read_to_string(&log).unwrap(), "integration install\n");
        assert_eq!(
            fs::read_to_string(&opened).unwrap().trim(),
            dir.path().join("OpenNCALayer.app").to_str().unwrap()
        );
        // Velopack's leftovers of an older version are gone.
        assert!(!cache.exists());
    }
}
