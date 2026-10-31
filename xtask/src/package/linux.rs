//! The Linux packages: the programs are built in a glibc 2.28 container ([`IMAGE`],
//! `xtask/assets/linux/build-appdir.sh`) with the pinned toolchain, not on a newer host, so
//! they start on every distribution with glibc 2.28 or newer (Debian 10, RHEL 8, Ubuntu
//! 18.10). The container also lays out the AppDir ([`appdir`]): the programs, the
//! libraries a desktop may lack ([`BUNDLED`], found through the daemon's `RUNPATH`, so what
//! the daemon starts does not inherit them), `AppRun`, the desktop entry and the icon; every
//! ELF file is checked against the glibc floor and the libraries a host provides
//! ([`HOST_LIBS`]), and `AppRun --version` must start there. On the host, `vpk pack` makes
//! the AppImage and the update packages from that AppDir ([`package`]); the AppImage is
//! unpacked and checked again, Velopack's `UpdateNix` included, and started in the
//! container.
//!
//! The release archive `openncalayer-<version>-x86_64-unknown-linux-gnu.tar.gz` (and so the
//! AUR package) carries the same container-built programs.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use object::elf;
use object::read::elf::{Dyn as _, ElfFile64};
use oncl_update::Version;

use super::{collect_velopack, copy, publish, run, scratch, vpk_pack};

/// The flavor, also Velopack's channel and runtime.
const FLAVOR: &str = "linux-x64";
/// The container the Linux programs are built and checked in: manylinux_2_28 (AlmaLinux 8,
/// glibc 2.28), pinned by digest.
pub const IMAGE: &str = "quay.io/pypa/manylinux_2_28_x86_64@sha256:e0adf18521ad35192df733a6c62d35df7801957d24e0470238aacecfab2188a3";
/// The newest glibc symbol version a program may need.
pub const GLIBC_FLOOR: (u32, u32) = (2, 28);
/// The container script, relative to the workspace.
const BUILD_SCRIPT: &str = "xtask/assets/linux/build-appdir.sh";
/// Where the container puts the programs and the AppDir, relative to the workspace.
pub const OUT_DIR: &str = "target/linux-x64";
/// The AppDir's name: vpk takes a directory ending in `.AppDir` as it is.
pub const APPDIR: &str = "OpenNCALayer.AppDir";
/// The programs.
const PROGRAMS: [&str; 2] = ["openncalayer", "nmhost"];

/// Libraries in the AppImage: the windows need libxkbcommon and its X11 part, which a
/// desktop may lack (Debian and Ubuntu do not install `libxkbcommon-x11-0` with X), and the
/// latter needs `libxcb-xkb`. winit loads them at run time.
pub const BUNDLED: [&str; 3] = [
    "libxkbcommon.so.0",
    "libxkbcommon-x11.so.0",
    "libxcb-xkb.so.1",
];

/// Libraries every desktop distribution has, as the AppImage exclude list says; the host's
/// copies must be used (glibc, the graphics and font stacks, D-Bus).
pub const HOST_LIBS: [&str; 24] = [
    "ld-linux-x86-64.so.2",
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
    "libutil.so.1",
    "libresolv.so.2",
    "libgcc_s.so.1",
    "libstdc++.so.6",
    "libz.so.1",
    "libexpat.so.1",
    "libuuid.so.1",
    "libfontconfig.so.1",
    "libfreetype.so.6",
    "libdbus-1.so.3",
    "libX11.so.6",
    "libxcb.so.1",
    "libXau.so.6",
    "libXdmcp.so.6",
    "libGL.so.1",
    "libEGL.so.1",
    "libwayland-client.so.0",
    "libwayland-cursor.so.0",
];

/// The directories the container's libraries are in.
const LIB_DIRS: [&str; 4] = [
    "/usr/lib64",
    "/lib64",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu",
];

/// The published AppImage: `openncalayer-<version>-linux-x64.AppImage`.
pub fn appimage_name(version: &Version) -> String {
    format!("openncalayer-{version}-{FLAVOR}.AppImage")
}

/// What an ELF file needs from the system.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ElfNeeds {
    /// `DT_NEEDED`.
    pub needed: Vec<String>,
    /// The `GLIBC_*` symbol versions it needs, unparsed.
    pub glibc: BTreeSet<String>,
}

impl ElfNeeds {
    /// The newest `GLIBC_<major>.<minor>[.<patch>]` version needed, as (major, minor).
    pub fn newest_glibc(&self) -> Option<(u32, u32)> {
        self.glibc.iter().filter_map(|v| glibc_version(v)).max()
    }

    /// The `GLIBC_*` versions that are not numbered (`GLIBC_PRIVATE`): never portable.
    pub fn private_glibc(&self) -> Vec<&str> {
        self.glibc
            .iter()
            .filter(|v| glibc_version(v).is_none())
            .map(String::as_str)
            .collect()
    }
}

/// `GLIBC_2.28` → (2, 28); `None` for anything else.
fn glibc_version(name: &str) -> Option<(u32, u32)> {
    let mut parts = name.strip_prefix("GLIBC_")?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// What the 64-bit ELF file `bytes` needs.
///
/// # Errors
///
/// It is not a 64-bit ELF file, or its dynamic section or version needs are malformed.
pub fn elf_needs(bytes: &[u8]) -> anyhow::Result<ElfNeeds> {
    let file = ElfFile64::<object::Endianness>::parse(bytes).context("not a 64-bit ELF file")?;
    let endian = file.endian();
    let sections = file.elf_section_table();
    let mut needs = ElfNeeds::default();
    if let Some((dynamic, link)) = sections.dynamic(endian, bytes)? {
        let strings = sections.strings(endian, bytes, link)?;
        for entry in dynamic {
            if entry.tag(endian) == elf::DT_NEEDED {
                let name = entry.string(endian, strings)?;
                needs
                    .needed
                    .push(String::from_utf8_lossy(name).into_owned());
            }
        }
    }
    if let Some((mut verneed, link)) = sections.gnu_verneed(endian, bytes)? {
        let strings = sections.strings(endian, bytes, link)?;
        while let Some((_, mut aux)) = verneed.next()? {
            while let Some(vernaux) = aux.next()? {
                let name = strings
                    .get(vernaux.vna_name.get(endian))
                    .map_err(|()| anyhow::anyhow!("invalid version name"))?;
                let name = String::from_utf8_lossy(name);
                if name.starts_with("GLIBC_") {
                    needs.glibc.insert(name.into_owned());
                }
            }
        }
    }
    Ok(needs)
}

/// Checks the ELF file `path` against the glibc floor and, if `allowed` is given, that every
/// library it needs is one of them; prints what it needs.
///
/// # Errors
///
/// It needs a newer or a private glibc, or another library, or cannot be read.
pub fn check_elf(path: &Path, allowed: Option<&BTreeSet<&str>>) -> anyhow::Result<ElfNeeds> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let needs = elf_needs(&bytes).with_context(|| path.display().to_string())?;
    let newest = needs.newest_glibc();
    println!(
        "{}: glibc {}, needs {}",
        path.display(),
        newest.map_or_else(|| "none".to_owned(), |(a, b)| format!("{a}.{b}")),
        if needs.needed.is_empty() {
            "nothing".to_owned()
        } else {
            needs.needed.join(" ")
        }
    );
    if let Some(newest) = newest
        && newest > GLIBC_FLOOR
    {
        bail!(
            "{} needs glibc {}.{}, newer than {}.{}",
            path.display(),
            newest.0,
            newest.1,
            GLIBC_FLOOR.0,
            GLIBC_FLOOR.1
        );
    }
    let private = needs.private_glibc();
    if !private.is_empty() {
        bail!("{} needs {}", path.display(), private.join(", "));
    }
    if let Some(allowed) = allowed {
        let foreign: Vec<&str> = needs
            .needed
            .iter()
            .map(String::as_str)
            .filter(|lib| !allowed.contains(lib))
            .collect();
        if !foreign.is_empty() {
            bail!(
                "{} needs {}, neither bundled nor provided by every host",
                path.display(),
                foreign.join(", ")
            );
        }
    }
    Ok(needs)
}

/// Whether `path` is an ELF file.
fn is_elf(path: &Path) -> bool {
    fs::read(path).is_ok_and(|bytes| bytes.starts_with(b"\x7fELF"))
}

/// The files in `dir` (not recursing), sorted; none if it does not exist.
fn files_in(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if path.is_file() {
                    files.push(path);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    }
    files.sort();
    Ok(files)
}

/// Checks every ELF file in `usr/bin` and `usr/lib` of the AppDir `dir`: the glibc floor,
/// and the libraries they need are bundled or on every host.
///
/// # Errors
///
/// A file fails [`check_elf`].
pub fn check_appdir(dir: &Path) -> anyhow::Result<()> {
    let allowed: BTreeSet<&str> = HOST_LIBS.iter().chain(&BUNDLED).copied().collect();
    let mut checked = 0;
    for sub in ["usr/bin", "usr/lib"] {
        for file in files_in(&dir.join(sub))? {
            if is_elf(&file) {
                check_elf(&file, Some(&allowed))?;
                checked += 1;
            }
        }
    }
    if checked == 0 {
        bail!("{} has no ELF file", dir.display());
    }
    Ok(())
}

/// The AppImage's entry point: the daemon, which finds the bundled libraries itself.
pub const APPRUN: &str = r#"#!/bin/sh
# OpenNCALayer's AppImage: the daemon finds the bundled libraries through its RUNPATH
# ($ORIGIN/../lib), so the programs it starts do not inherit them.
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/openncalayer" "$@"
"#;

/// The AppImage's desktop entry.
pub fn desktop_entry(version: &Version) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=OpenNCALayer\n\
         Comment=NCALayer-compatible signing service\n\
         Exec=openncalayer\n\
         Icon=openncalayer\n\
         Terminal=false\n\
         Categories=Utility;\n\
         X-AppImage-Version={version}\n"
    )
}

/// Lays out the AppDir `out` (replaced if it exists) with the programs in `bin` built in the
/// container, the [`BUNDLED`] libraries of the container, `AppRun`, the desktop entry, the
/// icon and the documents of the workspace `root`; checks it ([`check_appdir`], every
/// library resolvable with `ldd`) and starts `AppRun --version`. Linux only, in the
/// container ([`IMAGE`]): `patchelf` and `ldd` are needed.
///
/// # Errors
///
/// A file is missing, a tool fails, a check fails, or `AppRun` does not print the version.
pub fn appdir(root: &Path, bin: &Path, version: &Version, out: &Path) -> anyhow::Result<()> {
    if out.exists() {
        fs::remove_dir_all(out).with_context(|| format!("removing {}", out.display()))?;
    }
    let usr_bin = out.join("usr/bin");
    let usr_lib = out.join("usr/lib");
    for program in PROGRAMS {
        copy(&bin.join(program), &usr_bin.join(program))?;
        set_mode(&usr_bin.join(program), 0o755)?;
    }
    for lib in BUNDLED {
        let found = LIB_DIRS
            .iter()
            .map(|dir| Path::new(dir).join(lib))
            .find(|path| path.exists())
            .with_context(|| format!("{lib} is not in {}", LIB_DIRS.join(", ")))?;
        let real = fs::canonicalize(&found)?;
        println!("bundling {} as {lib}", real.display());
        copy(&real, &usr_lib.join(lib))?;
        set_mode(&usr_lib.join(lib), 0o644)?;
        run(Command::new("patchelf")
            .args(["--set-rpath", "$ORIGIN"])
            .arg(usr_lib.join(lib)))?;
    }
    run(Command::new("patchelf")
        .args(["--set-rpath", "$ORIGIN/../lib"])
        .arg(usr_bin.join("openncalayer")))?;

    let apprun = out.join("AppRun");
    fs::write(&apprun, APPRUN)?;
    set_mode(&apprun, 0o755)?;
    fs::write(out.join("openncalayer.desktop"), desktop_entry(version))?;
    let icon = root.join(super::ICON);
    copy(&icon, &out.join("openncalayer.png"))?;
    copy(&icon, &out.join(".DirIcon"))?;
    copy(
        &icon,
        &out.join("usr/share/icons/hicolor/32x32/apps/openncalayer.png"),
    )?;
    super::copy_docs(root, &out.join("usr/share/doc/openncalayer"))?;

    check_appdir(out)?;
    for file in files_in(&usr_bin)?.into_iter().chain(files_in(&usr_lib)?) {
        let output = Command::new("ldd")
            .arg(&file)
            .output()
            .with_context(|| format!("running ldd {}", file.display()))?;
        let text = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || text.contains("not found") {
            bail!("ldd {}:\n{text}", file.display());
        }
    }
    let printed = version_of(&mut Command::new(&apprun))?;
    check_version(&printed, version)?;
    println!("{}: {printed}", apprun.display());
    Ok(())
}

/// What `command --version` prints.
fn version_of(command: &mut Command) -> anyhow::Result<String> {
    let shown = format!("{command:?}");
    let output = command
        .arg("--version")
        .output()
        .with_context(|| format!("starting {shown}"))?;
    if !output.status.success() {
        bail!(
            "{shown} --version failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Checks that `printed` is `openncalayer <version>`.
fn check_version(printed: &str, version: &Version) -> anyhow::Result<()> {
    let expected = format!("openncalayer {version}");
    if printed != expected {
        bail!("the AppImage printed {printed:?}, not {expected:?}");
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> anyhow::Result<()> {
    Ok(())
}

/// Builds the programs and the AppDir of `version` in the container ([`IMAGE`]) with the
/// workspace `root` mounted, into [`OUT_DIR`]: `openncalayer`, `nmhost` and [`APPDIR`]. The
/// built-in modules (those of `ONCL_BUILTINS_DIR`, else built first on the host) are
/// embedded from their mounted folder. With `cache_volume` (a Docker volume) the toolchain
/// and cargo's files persist there between runs; otherwise under `target/glibc228/` of the
/// workspace. Needs Docker.
///
/// # Errors
///
/// Docker or the build fails.
pub fn build_in_container(
    root: &Path,
    version: &Version,
    cache_volume: Option<&str>,
) -> anyhow::Result<PathBuf> {
    let builtins = crate::builtins::prepare(root)?;
    let mut docker = Command::new("docker");
    docker
        .args(["run", "--rm"])
        .arg("-v")
        .arg(mount(root, "/src"))
        .arg("-v")
        .arg(mount(&builtins, "/builtins"))
        .args(["-w", "/src", "-e"])
        .arg(format!("ONCL_VERSION={version}"))
        .args(["-e", "ONCL_BUILTINS_DIR=/builtins"]);
    if let Some(volume) = cache_volume {
        docker
            .arg("-v")
            .arg(format!("{volume}:/cache"))
            .args(["-e", "ONCL_BUILD_CACHE=/cache"]);
    }
    #[cfg(unix)]
    {
        // SAFETY: getuid and getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        docker.args([
            "-e",
            &format!("HOST_UID={uid}"),
            "-e",
            &format!("HOST_GID={gid}"),
        ]);
    }
    docker.args([IMAGE, "bash", &format!("/src/{BUILD_SCRIPT}")]);
    run(&mut docker)?;
    let out = root.join(OUT_DIR);
    for program in PROGRAMS {
        if !out.join(program).is_file() {
            bail!("the container built no {}", out.join(program).display());
        }
    }
    Ok(out.join(APPDIR))
}

/// `-v` of `host` at `container`.
fn mount(host: &Path, container: &str) -> OsString {
    let mut arg = std::path::absolute(host)
        .unwrap_or_else(|_| host.to_owned())
        .into_os_string();
    arg.push(":");
    arg.push(container);
    arg
}

/// Packs the AppDir `appdir` as `version` into Velopack's output `packages`, unpacks the
/// AppImage it made and checks every ELF file in it (Velopack's `UpdateNix` too), starts its
/// `AppRun --version` in the container, and copies what is published into `dist`: the update
/// packages and [`appimage_name`]. Returns them. Linux only, with Docker.
///
/// # Errors
///
/// vpk fails, or the AppImage fails a check.
pub fn package(
    root: &Path,
    appdir: &Path,
    version: &Version,
    packages: &Path,
    dist: &Path,
) -> anyhow::Result<Vec<PathBuf>> {
    if appdir.extension().and_then(|e| e.to_str()) != Some("AppDir") {
        bail!("{} does not end in .AppDir", appdir.display());
    }
    fs::create_dir_all(packages).with_context(|| format!("creating {}", packages.display()))?;
    vpk_pack(appdir, PROGRAMS[0], version, FLAVOR, FLAVOR, packages, &[])?;
    let appimage =
        std::path::absolute(packages.join(format!("{}-{FLAVOR}.AppImage", super::PACK_ID)))?;
    if !appimage.is_file() {
        bail!("vpk made no {}", appimage.display());
    }

    let work = scratch(root, "linux-")?;
    run(Command::new(&appimage)
        .arg("--appimage-extract")
        .current_dir(work.path()))?;
    let extracted = work.path().join("squashfs-root");
    check_appdir(&extracted)?;
    let mut docker = Command::new("docker");
    docker
        .args(["run", "--rm", "-v"])
        .arg(mount(&extracted, "/app"))
        .args([IMAGE, "/app/AppRun"]);
    let printed = version_of(&mut docker)?;
    check_version(&printed, version)?;
    println!(
        "{} in the glibc 2.28 container: {printed}",
        appimage.display()
    );

    fs::create_dir_all(dist).with_context(|| format!("creating {}", dist.display()))?;
    let mut published = collect_velopack(packages, dist, version, FLAVOR)?;
    published.push(publish(&appimage, dist, &appimage_name(version))?);
    Ok(published)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_versions_are_compared_as_numbers() {
        let needs = ElfNeeds {
            needed: vec!["libc.so.6".to_owned()],
            glibc: ["GLIBC_2.2.5", "GLIBC_2.17", "GLIBC_2.28", "GLIBC_2.3"]
                .map(str::to_owned)
                .into(),
        };
        assert_eq!(needs.newest_glibc(), Some((2, 28)));
        assert!(needs.private_glibc().is_empty());
        let private = ElfNeeds {
            glibc: ["GLIBC_PRIVATE".to_owned()].into(),
            ..ElfNeeds::default()
        };
        assert_eq!(private.private_glibc(), ["GLIBC_PRIVATE"]);
        assert_eq!(glibc_version("GLIBC_2.34"), Some((2, 34)));
        assert!(glibc_version("GLIBC_2.34") > Some(GLIBC_FLOOR));
        assert_eq!(glibc_version("GLIBCXX_3.4"), None);
    }

    /// A minimal little-endian ELF64 file: a dynamic section needing `libs` and a
    /// version-needs section with `versions` of libc.so.6, as a linker writes them.
    fn elf(libs: &[&str], versions: &[&str]) -> Vec<u8> {
        fn pad8(out: &mut Vec<u8>) {
            out.resize(out.len().next_multiple_of(8), 0);
        }
        let mut dynstr = vec![0u8];
        let mut add = |s: &str| {
            let at = dynstr.len() as u32;
            dynstr.extend_from_slice(s.as_bytes());
            dynstr.push(0);
            at
        };
        let lib_names: Vec<u32> = libs.iter().map(|l| add(l)).collect();
        let libc = add("libc.so.6");
        let version_names: Vec<u32> = versions.iter().map(|v| add(v)).collect();
        let shstrtab = b"\0.dynstr\0.dynamic\0.gnu.version_r\0.shstrtab\0";

        let mut out = vec![0u8; 64];
        let dynstr_at = out.len();
        out.extend_from_slice(&dynstr);
        pad8(&mut out);
        let dynamic_at = out.len();
        for name in &lib_names {
            out.extend_from_slice(&1i64.to_le_bytes());
            out.extend_from_slice(&u64::from(*name).to_le_bytes());
        }
        out.extend_from_slice(&[0; 16]);
        let dynamic_len = out.len() - dynamic_at;
        let verneed_at = out.len();
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(versions.len() as u16).to_le_bytes());
        out.extend_from_slice(&libc.to_le_bytes());
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        for (i, name) in version_names.iter().enumerate() {
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&(2 + i as u16).to_le_bytes());
            out.extend_from_slice(&name.to_le_bytes());
            let next: u32 = if i + 1 < version_names.len() { 16 } else { 0 };
            out.extend_from_slice(&next.to_le_bytes());
        }
        let verneed_len = out.len() - verneed_at;
        let shstrtab_at = out.len();
        out.extend_from_slice(shstrtab);
        pad8(&mut out);
        let shoff = out.len();
        // name, type, offset, size, link, info, align, entsize
        type Section = (u32, u32, usize, usize, u32, u32, u64, u64);
        let sections: [Section; 5] = [
            (0, 0, 0, 0, 0, 0, 0, 0),
            (1, 3, dynstr_at, dynstr.len(), 0, 0, 1, 0),
            (9, 6, dynamic_at, dynamic_len, 1, 0, 8, 16),
            (18, 0x6fff_fffe, verneed_at, verneed_len, 1, 1, 8, 0),
            (33, 3, shstrtab_at, shstrtab.len(), 0, 0, 1, 0),
        ];
        for (name, kind, offset, size, link, info, align, entsize) in sections {
            out.extend_from_slice(&name.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&(offset as u64).to_le_bytes());
            out.extend_from_slice(&(size as u64).to_le_bytes());
            out.extend_from_slice(&link.to_le_bytes());
            out.extend_from_slice(&info.to_le_bytes());
            out.extend_from_slice(&align.to_le_bytes());
            out.extend_from_slice(&entsize.to_le_bytes());
        }
        let header = &mut out[..64];
        header[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
        header[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        header[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        header[20..24].copy_from_slice(&1u32.to_le_bytes());
        header[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        header[52..54].copy_from_slice(&64u16.to_le_bytes());
        header[54..56].copy_from_slice(&56u16.to_le_bytes());
        header[58..60].copy_from_slice(&64u16.to_le_bytes());
        header[60..62].copy_from_slice(&5u16.to_le_bytes());
        header[62..64].copy_from_slice(&4u16.to_le_bytes());
        out
    }

    #[test]
    fn an_elf_file_is_held_to_the_floor_and_the_host_libraries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openncalayer");
        let allowed: BTreeSet<&str> = HOST_LIBS.iter().chain(&BUNDLED).copied().collect();

        fs::write(
            &path,
            elf(
                &["libc.so.6", "libfontconfig.so.1"],
                &["GLIBC_2.17", "GLIBC_2.28"],
            ),
        )
        .unwrap();
        let needs = check_elf(&path, Some(&allowed)).unwrap();
        assert_eq!(needs.needed, ["libc.so.6", "libfontconfig.so.1"]);
        assert_eq!(needs.newest_glibc(), Some((2, 28)));

        fs::write(&path, elf(&["libc.so.6"], &["GLIBC_2.34"])).unwrap();
        let err = check_elf(&path, Some(&allowed)).unwrap_err().to_string();
        assert!(err.contains("needs glibc 2.34"), "{err}");

        fs::write(&path, elf(&["libgtk-3.so.0"], &["GLIBC_2.17"])).unwrap();
        let err = check_elf(&path, Some(&allowed)).unwrap_err().to_string();
        assert!(err.contains("libgtk-3.so.0"), "{err}");
        // Without a list, only the floor counts.
        check_elf(&path, None).unwrap();

        assert!(elf_needs(b"MZ").is_err());
    }

    #[test]
    fn the_appimage_starts_the_daemon_and_names_its_version() {
        assert!(APPRUN.starts_with("#!/bin/sh\n"));
        assert!(APPRUN.contains("exec \"$HERE/usr/bin/openncalayer\" \"$@\""));
        // The libraries go through RUNPATH, never the environment of what the daemon starts.
        assert!(!APPRUN.contains("export LD_LIBRARY_PATH"));
        let version = Version::parse("0.2.0").unwrap();
        assert!(desktop_entry(&version).contains("X-AppImage-Version=0.2.0\n"));
        assert_eq!(
            appimage_name(&version),
            "openncalayer-0.2.0-linux-x64.AppImage"
        );
        check_version("openncalayer 0.2.0", &version).unwrap();
        assert!(check_version("openncalayer 0.1.9", &version).is_err());
        let overlap: Vec<_> = BUNDLED.iter().filter(|l| HOST_LIBS.contains(l)).collect();
        assert!(overlap.is_empty(), "{overlap:?}");
    }
}
