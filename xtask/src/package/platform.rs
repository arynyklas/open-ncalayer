//! The standalone SDK programs as packages of their own (`cargo xtask package platform`):
//! `oncl` (the command line) and `oncl-server` (the HTTP service), one archive each per
//! flavor, named `<program>-<version>-<flavor>.zip` (Windows) or `.tar.gz`. They are plain
//! archives of a program and its documents: no installer, no Velopack, no autostart, and
//! nothing of the desktop application (`openncalayer`, `nmhost`), whose installers and
//! update packages stay with [`super::windows`], [`super::macos`] and [`super::linux`].
//!
//! Every archive holds the program, `README.md`, the licence texts of the third-party code
//! that program is built from on that flavor's targets (so AWS-LC appears for a Unix
//! archive and not for a Windows one), the user documentation and, for the server, the
//! example configuration (the HTTP API disabled) and, on Linux, the Dockerfile and the
//! systemd unit. It holds no key, certificate, token, password or test file, which
//! [`check_layout`] enforces on the finished archive, not on the staging directory.
//!
//! Before an archive is made the programs pass the import gates of their flavor (the static
//! CRT on Windows 10 and 11, the Windows 7 deny-list, glibc 2.28 on Linux, both slices on
//! macOS). After it, on a host that can run them, [`super::platform_smoke`] unpacks the
//! archives and starts the unpacked programs: hash, verify, a disabled server without a
//! listener, a signature through the server enabled on loopback, a clean shutdown.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use oncl_update::Version;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use super::{copy, linux, macos, publish, run, scratch, windows};
use crate::{imports, licenses};

/// The operating system of a flavor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
    Macos,
}

/// A flavor of the standalone packages. The names are those of the desktop flavors
/// (`oncl_update::Flavor`), so one matrix builds both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flavor {
    pub name: &'static str,
    pub os: Os,
    /// The rustc targets of its programs: the third-party code of all of them is licensed.
    pub targets: &'static [&'static str],
    /// Windows 7 SP1: built with `-Zbuild-std` and checked against the Windows 7 deny-list.
    pub win7: bool,
}

/// The flavors.
pub const FLAVORS: [Flavor; 6] = [
    Flavor {
        name: "win-x64",
        os: Os::Windows,
        targets: &["x86_64-pc-windows-msvc"],
        win7: false,
    },
    Flavor {
        name: "win-x86",
        os: Os::Windows,
        targets: &["i686-pc-windows-msvc"],
        win7: false,
    },
    Flavor {
        name: "win7-x64",
        os: Os::Windows,
        targets: &["x86_64-win7-windows-msvc"],
        win7: true,
    },
    Flavor {
        name: "win7-x86",
        os: Os::Windows,
        targets: &["i686-win7-windows-msvc"],
        win7: true,
    },
    Flavor {
        name: "linux-x64",
        os: Os::Linux,
        targets: &["x86_64-unknown-linux-gnu"],
        win7: false,
    },
    Flavor {
        name: "osx",
        os: Os::Macos,
        targets: &["x86_64-apple-darwin", "aarch64-apple-darwin"],
        win7: false,
    },
];

/// The flavor `name`.
///
/// # Errors
///
/// `name` is not one.
pub fn flavor(name: &str) -> anyhow::Result<Flavor> {
    FLAVORS
        .into_iter()
        .find(|flavor| flavor.name == name)
        .with_context(|| {
            let names: Vec<&str> = FLAVORS.iter().map(|flavor| flavor.name).collect();
            format!("{name:?} is not a flavor ({})", names.join(", "))
        })
}

/// A program of the standalone SDK, shipped as a package of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Product {
    /// The command line.
    Cli,
    /// The HTTP service.
    Server,
}

impl Product {
    pub const ALL: [Product; 2] = [Product::Cli, Product::Server];

    /// The program's and the package's name.
    pub fn name(self) -> &'static str {
        match self {
            Product::Cli => "oncl",
            Product::Server => "oncl-server",
        }
    }

    /// The cargo package that builds it.
    pub fn cargo_package(self) -> &'static str {
        match self {
            Product::Cli => "oncl-cli",
            Product::Server => "oncl-server",
        }
    }

    /// The program's file name on `os`.
    pub fn exe(self, os: Os) -> String {
        match os {
            Os::Windows => format!("{}.exe", self.name()),
            Os::Linux | Os::Macos => self.name().to_owned(),
        }
    }
}

/// The programs of both packages: the cargo target and the name it ships under, for a build
/// of `os` (cargo's file names).
pub fn files(os: Os) -> [(&'static str, String); 2] {
    [
        ("oncl", Product::Cli.exe(os)),
        ("oncl-server", Product::Server.exe(os)),
    ]
}

/// The name of the top directory of an archive.
pub fn dir_name(product: Product, version: &Version, flavor: &Flavor) -> String {
    format!("{}-{version}-{}", product.name(), flavor.name)
}

/// The published archive: `<program>-<version>-<flavor>.zip` on Windows, `.tar.gz`
/// elsewhere.
pub fn archive_name(product: Product, version: &Version, flavor: &Flavor) -> String {
    let extension = match flavor.os {
        Os::Windows => "zip",
        Os::Linux | Os::Macos => "tar.gz",
    };
    format!("{}.{extension}", dir_name(product, version, flavor))
}

/// The libraries a Linux program may need: the ones every glibc system has.
const LINUX_HOST_LIBS: [&str; 7] = [
    "ld-linux-x86-64.so.2",
    "libc.so.6",
    "libm.so.6",
    "libgcc_s.so.1",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
];

/// The files of an archive, relative to its top directory, for `product` on `flavor`:
/// exactly these and no others.
pub fn expected_files(product: Product, flavor: &Flavor) -> BTreeSet<String> {
    let mut files: BTreeSet<String> = [
        product.exe(flavor.os),
        "README.md".to_owned(),
        "LICENSE".to_owned(),
        "NOTICE".to_owned(),
        "THIRD-PARTY.txt".to_owned(),
    ]
    .into();
    match product {
        Product::Cli => {
            files.insert("docs/cli.md".to_owned());
        }
        Product::Server => {
            files.insert("server.example.toml".to_owned());
            files.insert("docs/server.md".to_owned());
            files.insert("docs/http-api.md".to_owned());
            if flavor.os == Os::Linux {
                files.insert("deploy/Dockerfile".to_owned());
                files.insert("deploy/openncalayer-server.service".to_owned());
            }
        }
    }
    files
}

/// Where the example configuration and the operations files are, relative to the workspace.
const DEPLOY: &str = "deploy/server";

/// The documents of a package: the source in the workspace and the name in the archive.
fn documents(product: Product) -> &'static [(&'static str, &'static str)] {
    match product {
        Product::Cli => &[("docs/user/cli.md", "docs/cli.md")],
        Product::Server => &[
            ("docs/user/server.md", "docs/server.md"),
            ("docs/user/http-api.md", "docs/http-api.md"),
        ],
    }
}

/// Fails unless `version` is the version the programs were built with: the workspace's, the
/// one `oncl --version` prints, the desktop's.
fn check_version(version: &Version) -> anyhow::Result<()> {
    let built = env!("CARGO_PKG_VERSION");
    if version.to_string() != built {
        bail!("the version {version} is not the workspace's {built}: the programs would say so");
    }
    Ok(())
}

/// The import gate of `flavor` on both programs of `bin`.
///
/// # Errors
///
/// A program is missing or does not pass.
pub fn gate(flavor: &Flavor, bin: &Path) -> anyhow::Result<()> {
    let exes: Vec<PathBuf> = files(flavor.os)
        .into_iter()
        .map(|(_, file)| bin.join(file))
        .collect();
    for exe in &exes {
        if !exe.is_file() {
            bail!("{} is not built", exe.display());
        }
    }
    match flavor.os {
        Os::Windows => {
            // Both: no Visual C++ redistributable (a clean Windows 10/11 has none), and for
            // Windows 7 no import missing there. No app-local DLL is shipped, so each
            // program is checked alone, as the relay is.
            windows::no_redistributable(exes.iter().cloned())?;
            if flavor.win7 {
                let mut found = 0;
                for exe in &exes {
                    found += imports::check_imports_alone(exe)?;
                }
                if found > 0 {
                    bail!("{found} violations of the Windows 7 import gate");
                }
            }
        }
        Os::Linux => {
            let allowed: BTreeSet<&str> = LINUX_HOST_LIBS.into();
            for exe in &exes {
                linux::check_elf(exe, Some(&allowed))?;
            }
        }
        Os::Macos => {
            for exe in &exes {
                macos::check_universal(exe)?;
            }
        }
    }
    Ok(())
}

/// Builds the Windows 7 programs of `arch` into `<out>/<arch>/` (the pinned nightly with
/// `-Zbuild-std` and the static CRT, as [`crate::win7`] does for the desktop), and returns
/// the directory.
///
/// # Errors
///
/// The build fails.
pub fn build_win7(
    root: &Path,
    arch: crate::win7::Arch,
    out: &Path,
    target_dir: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    let out = std::path::absolute(out).with_context(|| format!("{}", out.display()))?;
    let target_dir = target_dir
        .map(|dir| std::path::absolute(dir).with_context(|| format!("{}", dir.display())))
        .transpose()?;
    let packages = [
        Product::Cli.cargo_package(),
        Product::Server.cargo_package(),
    ];
    let files = files(Os::Windows);
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(target, file)| (*target, file.as_str()))
        .collect();
    // No built-in modules: the standalone programs embed none.
    crate::win7::build_packages(
        root,
        arch,
        &out,
        target_dir.as_deref(),
        None,
        &packages,
        &files,
    )
}

/// The script that builds the programs in the glibc 2.28 container, relative to the
/// workspace.
const LINUX_BUILD_SCRIPT: &str = "xtask/assets/linux/build-platform.sh";

/// Builds `oncl` and `oncl-server` in the glibc 2.28 container ([`linux::IMAGE`]) with the
/// workspace `root` mounted, into `<root>/target/platform/linux-x64/`, which it returns. With
/// `dist` (a path in the workspace) the container also runs [`package`] on them, smoke
/// included. Needs Docker.
///
/// # Errors
///
/// Docker or the build fails.
pub fn build_linux(
    root: &Path,
    version: &Version,
    cache_volume: Option<&str>,
    dist: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    let mut docker = Command::new("docker");
    docker
        .args(["run", "--rm", "-v"])
        .arg(linux::mount(root, "/src"))
        .args(["-w", "/src", "-e"])
        .arg(format!("ONCL_VERSION={version}"));
    if let Some(volume) = cache_volume {
        docker
            .arg("-v")
            .arg(format!("{volume}:/cache"))
            .args(["-e", "ONCL_BUILD_CACHE=/cache"]);
    }
    if let Some(dist) = dist {
        let dist = dist
            .strip_prefix(root)
            .with_context(|| format!("{} is not inside the workspace", dist.display()))?;
        let dist = dist.to_string_lossy().replace('\\', "/");
        docker.args(["-e", &format!("ONCL_PLATFORM_DIST=/src/{dist}")]);
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
    docker.args([linux::IMAGE, "bash", &format!("/src/{LINUX_BUILD_SCRIPT}")]);
    run(&mut docker)?;
    let out = root.join("target").join("platform").join("linux-x64");
    for (_, file) in files(Os::Linux) {
        if !out.join(&file).is_file() {
            bail!("the container built no {}", out.join(file).display());
        }
    }
    Ok(out)
}

/// Makes the archives of `version` for `flavor` from the programs in `bin`, gates them,
/// copies them into `dist` and returns them. With `smoke` (and a host that can run
/// `flavor`) the published archives are unpacked and started
/// ([`super::platform_smoke::run`]).
///
/// # Errors
///
/// A program is missing or fails its gate, a licence cannot be collected, an archive does
/// not have exactly the expected files, or the smoke fails.
pub fn package(
    root: &Path,
    flavor: &Flavor,
    bin: &Path,
    version: &Version,
    dist: &Path,
    smoke: bool,
) -> anyhow::Result<Vec<PathBuf>> {
    check_version(version)?;
    gate(flavor, bin)?;
    fs::create_dir_all(dist).with_context(|| format!("creating {}", dist.display()))?;
    let work = scratch(root, "platform-")?;
    let mut published = Vec::new();
    for product in Product::ALL {
        let name = dir_name(product, version, flavor);
        let stage = work.path().join(&name);
        stage_product(root, product, flavor, bin, version, &stage)?;
        let archive = work.path().join(archive_name(product, version, flavor));
        pack(&stage, &name, &archive, flavor.os)?;
        check_entries(&entries(&archive, flavor.os)?, product, version, flavor)
            .with_context(|| format!("the archive {}", archive.display()))?;
        published.push(publish(
            &archive,
            dist,
            &archive_name(product, version, flavor),
        )?);
    }
    if smoke {
        let outcome = super::platform_smoke::run(root, flavor, version, &published, work.path());
        if outcome.is_err() && std::env::var_os("ONCL_KEEP_SMOKE_FILES").is_some() {
            // The unpacked packages and the smoke's directories, for finding out why it failed.
            eprintln!("kept {}", work.keep().display());
        }
        outcome?;
    }
    Ok(published)
}

/// The behaviour smoke alone, on the archives of `version` for `flavor` that [`package`] left
/// in `dist`: they are unpacked into a fresh directory and the unpacked programs started
/// ([`super::platform_smoke::run`]).
///
/// # Errors
///
/// An archive is missing, or the smoke fails.
pub fn smoke(root: &Path, flavor: &Flavor, version: &Version, dist: &Path) -> anyhow::Result<()> {
    let archives: Vec<PathBuf> = Product::ALL
        .into_iter()
        .map(|product| dist.join(archive_name(product, version, flavor)))
        .collect();
    for archive in &archives {
        if !archive.is_file() {
            bail!("{} does not exist", archive.display());
        }
    }
    let work = scratch(root, "platform-smoke-")?;
    let outcome = super::platform_smoke::run(root, flavor, version, &archives, work.path());
    if outcome.is_err() && std::env::var_os("ONCL_KEEP_SMOKE_FILES").is_some() {
        eprintln!("kept {}", work.keep().display());
    }
    outcome
}

/// Lays out the package of `product` in `stage`.
fn stage_product(
    root: &Path,
    product: Product,
    flavor: &Flavor,
    bin: &Path,
    version: &Version,
    stage: &Path,
) -> anyhow::Result<()> {
    let exe = product.exe(flavor.os);
    copy(&bin.join(&exe), &stage.join(&exe))?;
    make_executable(&stage.join(&exe))?;
    for doc in ["LICENSE", "NOTICE"] {
        copy(&root.join(doc), &stage.join(doc))?;
    }
    for (from, to) in documents(product) {
        copy(&root.join(from), &stage.join(to))?;
    }
    let licences = licenses::generate_for(
        root,
        &[product.cargo_package()],
        flavor.targets,
        &format!(
            "{} {version} ({}): third-party software\n\
             ==========================================\n\
             \n\
             The program {} of OpenNCALayer includes the crates listed below. Each line names a\n\
             crate, its version, its licence as an SPDX expression (\"A OR B\" is a choice\n\
             between licences), its repository and the numbers of its licence texts, which\n\
             follow the list. It is the code of this flavor's targets: a crate that only another\n\
             platform needs is not in it.\n\
             \n\
             Generated by `cargo xtask package platform`; do not edit.\n\
             \n",
            product.name(),
            flavor.name,
            product.name()
        ),
    )?;
    fs::write(stage.join("THIRD-PARTY.txt"), licences).context("writing THIRD-PARTY.txt")?;
    let template = fs::read_to_string(
        root.join("xtask/assets/platform")
            .join(format!("README-{}.md", product.name())),
    )
    .context("reading the README template")?;
    let deploy_rows = if product == Product::Server && flavor.os == Os::Linux {
        "| `deploy/openncalayer-server.service` | hardened systemd unit (not enabled by copying it) |\n\
         | `deploy/Dockerfile` | container image built from this archive (non-root) |\n"
    } else {
        ""
    };
    let windows_provisioning = if product == Product::Server && flavor.os == Os::Windows {
        "## Windows: putting files in place\n\n\
         The server only reads files that its own private-file API created (a protected ACL with\n\
         one entry); `icacls` and `Set-Acl` cannot make them. Use the program:\n\n\
         ```bat\n\
         oncl-server install-file --directory %ProgramData%\\oncl-operator --name server.toml --input server.toml\n\
         oncl-server install-file --directory %ProgramData%\\oncl-operator --name corporate.p12 --input corporate.p12\n\
         oncl-server token-create --directory %ProgramData%\\oncl-operator --name accounting.token\n\
         oncl-server serve --config %ProgramData%\\oncl-operator\\server.toml --enable-api\n\
         ```\n\n\
         Paths in `server.toml` are Windows paths (use `'%ProgramData%\\oncl-operator\\audit'` literal strings).\n\
         Delete the plain source files afterwards. The Linux sections of the documentation\n\
         (systemd, container) do not apply.\n\n"
    } else {
        ""
    };
    let readme = template
        .replace("{{VERSION}}", &version.to_string())
        .replace("{{FLAVOR}}", flavor.name)
        .replace("{{EXE}}", &exe)
        .replace("{{DEPLOY_ROWS}}", deploy_rows)
        .replace("{{WINDOWS_PROVISIONING}}", windows_provisioning);
    fs::write(stage.join("README.md"), readme).context("writing README.md")?;
    if product == Product::Server {
        copy(
            &root.join(DEPLOY).join("server.example.toml"),
            &stage.join("server.example.toml"),
        )?;
        if flavor.os == Os::Linux {
            for file in ["Dockerfile", "openncalayer-server.service"] {
                copy(
                    &root.join(DEPLOY).join(file),
                    &stage.join("deploy").join(file),
                )?;
            }
        }
    }
    Ok(())
}

/// Makes `path` executable (Unix).
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

/// The files under `dir`, relative and with `/`, sorted.
fn walk(dir: &Path) -> anyhow::Result<Vec<String>> {
    fn visit(base: &Path, dir: &Path, out: &mut Vec<String>) -> anyhow::Result<()> {
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                visit(base, &path, out)?;
            } else {
                let relative = path
                    .strip_prefix(base)?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(relative);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(dir, dir, &mut files)?;
    files.sort();
    Ok(files)
}

/// Archives `stage` as `<top>/…` into `archive`: a zip for Windows, else a `tar.gz` made by
/// the host's `tar`.
fn pack(stage: &Path, top: &str, archive: &Path, os: Os) -> anyhow::Result<()> {
    match os {
        Os::Windows => {
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .last_modified_time(DateTime::default());
            let mut zip = ZipWriter::new(
                fs::File::create(archive)
                    .with_context(|| format!("creating {}", archive.display()))?,
            );
            for file in walk(stage)? {
                let mode = if file.ends_with(".exe") { 0o755 } else { 0o644 };
                zip.start_file(format!("{top}/{file}"), options.unix_permissions(mode))?;
                zip.write_all(&fs::read(stage.join(&file))?)?;
            }
            zip.finish()?.sync_all()?;
            Ok(())
        }
        Os::Linux | Os::Macos => write_tar_gz(stage, top, archive),
    }
}

/// A deterministic `.tar.gz` of `stage` under `top/`: sorted names, mode 0755 for
/// directories and programs and 0644 for other files whatever the staging file system says
/// (a Windows bind mount reports 0777), owner root, time 0, no links, no extended headers.
fn write_tar_gz(stage: &Path, top: &str, archive: &Path) -> anyhow::Result<()> {
    let mut tar: Vec<u8> = Vec::new();
    let files = walk(stage)?;
    let mut directories = BTreeSet::from([String::new()]);
    for file in &files {
        let mut parts: Vec<&str> = file.split('/').collect();
        parts.pop();
        for end in 1..=parts.len() {
            directories.insert(parts[..end].join("/"));
        }
    }
    let mut entries: Vec<(String, bool)> = directories
        .into_iter()
        .map(|d| {
            (
                if d.is_empty() {
                    format!("{top}/")
                } else {
                    format!("{top}/{d}/")
                },
                true,
            )
        })
        .chain(files.iter().map(|f| (format!("{top}/{f}"), false)))
        .collect();
    entries.sort();
    for (name, directory) in entries {
        let relative = name
            .strip_prefix(&format!("{top}/"))
            .unwrap_or("")
            .trim_end_matches('/');
        let body = if directory {
            Vec::new()
        } else {
            fs::read(stage.join(relative))?
        };
        let mode = if directory || is_program(relative) {
            0o755
        } else {
            0o644
        };
        tar.extend(tar_header(&name, mode, body.len(), directory)?);
        tar.extend(&body);
        tar.extend(std::iter::repeat_n(0_u8, (512 - body.len() % 512) % 512));
    }
    tar.extend([0_u8; 1024]);
    let file =
        fs::File::create(archive).with_context(|| format!("creating {}", archive.display()))?;
    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    gz.write_all(&tar)?;
    gz.finish()?.sync_all()?;
    Ok(())
}

/// The programs of a package: the files shipped executable.
fn is_program(relative: &str) -> bool {
    matches!(relative, "oncl" | "oncl-server")
}

/// A ustar header (names up to 100 bytes).
fn tar_header(name: &str, mode: u32, size: usize, directory: bool) -> anyhow::Result<[u8; 512]> {
    ensure_name(name)?;
    let mut header = [0_u8; 512];
    let mut put =
        |at: usize, text: &str| header[at..at + text.len()].copy_from_slice(text.as_bytes());
    put(0, name);
    put(100, &format!("{mode:07o}\0"));
    put(108, "0000000\0");
    put(116, "0000000\0");
    put(124, &format!("{size:011o}\0"));
    put(136, "00000000000\0");
    put(148, "        ");
    put(156, if directory { "5" } else { "0" });
    put(257, "ustar\0");
    put(263, "00");
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    Ok(header)
}

fn ensure_name(name: &str) -> anyhow::Result<()> {
    if name.len() > 100 || !name.is_ascii() {
        bail!("{name} does not fit a ustar header");
    }
    Ok(())
}

/// What an archive entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Other,
}

/// One entry of an archive: name, permission bits (if the format has them) and kind.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub mode: Option<u32>,
    pub kind: Kind,
}

/// The entries of a `.tar.gz`, read with our own parser (type flag and mode bytes).
fn read_tar_gz(archive: &Path) -> anyhow::Result<Vec<Entry>> {
    use std::io::Read as _;
    let file = fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(file).read_to_end(&mut tar)?;
    parse_tar(&tar)
}

/// The entries of an uncompressed ustar stream; an unreadable mode or size is an error.
fn parse_tar(tar: &[u8]) -> anyhow::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at + 512 <= tar.len() && tar[at..at + 512].iter().any(|b| *b != 0) {
        let header = &tar[at..at + 512];
        let text = |from: usize, to: usize| {
            String::from_utf8_lossy(&header[from..to])
                .trim_end_matches('\0')
                .trim()
                .to_owned()
        };
        let mut name = text(0, 100);
        let prefix = text(345, 500);
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let mode = Some(
            u32::from_str_radix(&text(100, 108), 8)
                .with_context(|| format!("the mode field of {name}"))?,
        );
        let size = usize::from_str_radix(&text(124, 136), 8).context("a tar size")?;
        let kind = match header[156] {
            b'0' | 0 => Kind::File,
            b'5' => Kind::Directory,
            _ => Kind::Other,
        };
        entries.push(Entry { name, mode, kind });
        at += 512 + size.div_ceil(512) * 512;
    }
    Ok(entries)
}

/// The files an archive holds (directories are not listed).
fn list(archive: &Path, os: Os) -> anyhow::Result<Vec<String>> {
    match os {
        Os::Windows => {
            let file = fs::File::open(archive)
                .with_context(|| format!("opening {}", archive.display()))?;
            let mut zip =
                ZipArchive::new(file).with_context(|| format!("reading {}", archive.display()))?;
            let mut names = Vec::new();
            for i in 0..zip.len() {
                let entry = zip.by_index(i)?;
                if !entry.is_dir() {
                    names.push(entry.name()?.into_owned());
                }
            }
            Ok(names)
        }
        Os::Linux | Os::Macos => {
            let output = Command::new("tar")
                .arg("-tzf")
                .arg(archive)
                .output()
                .context("running tar")?;
            if !output.status.success() {
                bail!(
                    "tar -tzf {}: {}\n{}",
                    archive.display(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(String::from_utf8(output.stdout)
                .context("tar listed a non-UTF-8 name")?
                .lines()
                .filter(|line| !line.ends_with('/'))
                .map(str::to_owned)
                .collect())
        }
    }
}

/// Unpacks `archive` into `dest` and returns the archive's top directory.
///
/// # Errors
///
/// The archive cannot be read or has an entry outside its top directory.
pub fn unpack(archive: &Path, os: Os, dest: &Path) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let names = list(archive, os)?;
    let top = names
        .first()
        .and_then(|name| name.split('/').next())
        .context("an empty archive")?
        .to_owned();
    if names
        .iter()
        .any(|name| name.split('/').next() != Some(top.as_str()))
    {
        bail!("{} has files outside {top}/", archive.display());
    }
    match os {
        Os::Windows => {
            let file = fs::File::open(archive)
                .with_context(|| format!("opening {}", archive.display()))?;
            ZipArchive::new(file)?.extract(dest)?;
        }
        Os::Linux | Os::Macos => {
            run(Command::new("tar")
                .arg("-xzf")
                .arg(archive)
                .arg("-C")
                .arg(dest))?;
        }
    }
    Ok(dest.join(top))
}

/// Extensions and names no package may contain: key material, certificates, tokens and
/// secrets a user would be harmed by finding in a download.
const FORBIDDEN_EXTENSIONS: [&str; 14] = [
    "p12", "pfx", "jks", "key", "pem", "crt", "cer", "der", "p7s", "token", "password", "pw",
    "secret", "keystore",
];

/// Checks the file list of an archive of `product` for `flavor`: one top directory named
/// after the package, exactly [`expected_files`], and no key material, certificate,
/// token, secret, test fixture or user directory by name.
///
/// # Errors
///
/// The list differs.
pub fn check_layout(
    names: &[String],
    product: Product,
    version: &Version,
    flavor: &Flavor,
) -> anyhow::Result<()> {
    let top = dir_name(product, version, flavor);
    let mut relative = BTreeSet::new();
    for name in names {
        let Some(rest) = name.strip_prefix(&format!("{top}/")) else {
            bail!("{name} is not under {top}/");
        };
        if rest.split('/').any(|part| part.is_empty() || part == "..") {
            bail!("{name} is not a plain relative path");
        }
        let lower = rest.to_ascii_lowercase();
        let extension = lower.rsplit_once('.').map(|(_, extension)| extension);
        if extension.is_some_and(|extension| FORBIDDEN_EXTENSIONS.contains(&extension))
            || [
                "fixtures",
                "synthetic",
                "org-93",
                ".ssh",
                "appdata",
                "home/",
            ]
            .iter()
            .any(|part| lower.contains(part))
        {
            bail!("{name}: key material, a secret or a test or user file in a package");
        }
        relative.insert(rest.to_owned());
    }
    let expected = expected_files(product, flavor);
    if relative != expected {
        let extra: Vec<&String> = relative.difference(&expected).collect();
        let missing: Vec<&String> = expected.difference(&relative).collect();
        bail!("unexpected files {extra:?}, missing files {missing:?}");
    }
    Ok(())
}

/// The entries of `archive` with modes and kinds.
fn entries(archive: &Path, os: Os) -> anyhow::Result<Vec<Entry>> {
    match os {
        Os::Windows => parse_zip_directory(&fs::read(archive)?),
        Os::Linux | Os::Macos => read_tar_gz(archive),
    }
}

/// The central directory of a zip: name and Unix mode (external attributes) of each entry.
fn parse_zip_directory(bytes: &[u8]) -> anyhow::Result<Vec<Entry>> {
    let le32 = |at: usize| -> anyhow::Result<u32> {
        let raw = bytes.get(at..at + 4).context("a cut zip")?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    };
    let le16 = |at: usize| -> anyhow::Result<usize> {
        let raw = bytes.get(at..at + 2).context("a cut zip")?;
        Ok(usize::from(u16::from_le_bytes([raw[0], raw[1]])))
    };
    let end = bytes
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .context("no end of central directory")?;
    let count = le16(end + 10)?;
    let mut at = usize::try_from(le32(end + 16)?)?;
    let mut found = Vec::new();
    for _ in 0..count {
        anyhow::ensure!(le32(at)? == 0x0201_4b50, "a bad central directory entry");
        let attributes = le32(at + 38)?;
        let (name_length, extra, comment) = (le16(at + 28)?, le16(at + 30)?, le16(at + 32)?);
        let name = String::from_utf8(
            bytes
                .get(at + 46..at + 46 + name_length)
                .context("a cut zip")?
                .to_vec(),
        )?;
        let mode = attributes >> 16;
        let kind = match mode & 0o170_000 {
            0o120_000 => Kind::Other,
            0o040_000 => Kind::Directory,
            _ if name.ends_with('/') => Kind::Directory,
            _ => Kind::File,
        };
        found.push(Entry {
            name,
            mode: Some(mode & 0o7777),
            kind,
        });
        at += 46 + name_length + extra + comment;
    }
    Ok(found)
}

/// [`check_layout`] on the files, and: only regular files and directories (no symlink, hard
/// link or device), no setuid/setgid/sticky bit, nothing group- or world-writable, programs
/// 0755 and other files 0644 (where the format records modes).
///
/// # Errors
///
/// An entry is of another kind or has another mode, or the layout differs.
pub fn check_entries(
    entries: &[Entry],
    product: Product,
    version: &Version,
    flavor: &Flavor,
) -> anyhow::Result<()> {
    let top = dir_name(product, version, flavor);
    for entry in entries {
        if entry.kind == Kind::Other {
            bail!("{}: not a regular file or directory", entry.name);
        }
        let Some(mode) = entry.mode else { continue };
        let relative = entry.name.strip_prefix(&format!("{top}/")).unwrap_or("");
        let expected = if entry.kind == Kind::Directory
            || is_program(relative)
            || relative.ends_with(".exe")
        {
            0o755
        } else {
            0o644
        };
        if mode & 0o7022 != 0 || mode != expected {
            bail!("{}: mode {mode:o}, expected {expected:o}", entry.name);
        }
    }
    let names: Vec<String> = entries
        .iter()
        .filter(|e| e.kind == Kind::File)
        .map(|e| e.name.clone())
        .collect();
    check_layout(&names, product, version, flavor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version() -> Version {
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
    }

    fn listed(product: Product, flavor: &Flavor) -> Vec<String> {
        let top = dir_name(product, &version(), flavor);
        expected_files(product, flavor)
            .into_iter()
            .map(|file| format!("{top}/{file}"))
            .collect()
    }

    #[test]
    fn flavors_match_the_desktop_flavors() {
        for flavor in FLAVORS {
            assert!(
                oncl_update::Flavor::ALL
                    .iter()
                    .any(|desktop| desktop.as_str() == flavor.name),
                "{} is not a desktop flavor",
                flavor.name
            );
        }
        assert!(flavor("win-arm64").is_err());
    }

    #[test]
    fn the_two_programs_are_packages_of_their_own() {
        for flavor in FLAVORS {
            let cli = archive_name(Product::Cli, &version(), &flavor);
            let server = archive_name(Product::Server, &version(), &flavor);
            assert_ne!(cli, server);
            assert!(!cli.starts_with("openncalayer"), "{cli}");
            assert!(!server.starts_with("openncalayer"), "{server}");
            let cli_files = expected_files(Product::Cli, &flavor);
            let server_files = expected_files(Product::Server, &flavor);
            assert!(!cli_files.contains(&Product::Server.exe(flavor.os)));
            assert!(!server_files.contains(&Product::Cli.exe(flavor.os)));
        }
    }

    #[test]
    fn the_expected_layout_passes() {
        for flavor in FLAVORS {
            for product in Product::ALL {
                check_layout(&listed(product, &flavor), product, &version(), &flavor).unwrap();
            }
        }
    }

    #[test]
    fn a_secret_or_a_fixture_in_an_archive_is_refused() {
        let flavor = flavor("linux-x64").unwrap();
        for extra in [
            "client.token",
            "signer.p12",
            "tls/server.key",
            "root.cer",
            "fixtures/synthetic/user-rsa-sign.p12",
            "operator/server.toml",
        ] {
            let mut names = listed(Product::Server, &flavor);
            names.push(format!(
                "{}/{extra}",
                dir_name(Product::Server, &version(), &flavor)
            ));
            let error = check_layout(&names, Product::Server, &version(), &flavor)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(extra) || error.contains("unexpected files"),
                "{extra}: {error}"
            );
        }
    }

    #[test]
    fn a_missing_or_foreign_file_is_refused() {
        let flavor = flavor("win-x64").unwrap();
        let mut names = listed(Product::Cli, &flavor);
        names.retain(|name| !name.ends_with("THIRD-PARTY.txt"));
        assert!(check_layout(&names, Product::Cli, &version(), &flavor).is_err());
        let mut names = listed(Product::Cli, &flavor);
        names.push("elsewhere/oncl.exe".to_owned());
        assert!(check_layout(&names, Product::Cli, &version(), &flavor).is_err());
    }

    #[test]
    fn a_tarball_has_fixed_modes_and_only_plain_entries() {
        let flavor = flavor("linux-x64").unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let top = dir_name(Product::Server, &version(), &flavor);
        let stage = temporary.path().join(&top);
        for file in expected_files(Product::Server, &flavor) {
            let path = stage.join(&file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"x").unwrap();
        }
        let archive = temporary.path().join("a.tar.gz");
        write_tar_gz(&stage, &top, &archive).unwrap();
        let again = temporary.path().join("b.tar.gz");
        write_tar_gz(&stage, &top, &again).unwrap();
        assert_eq!(fs::read(&archive).unwrap(), fs::read(&again).unwrap());
        let found = read_tar_gz(&archive).unwrap();
        check_entries(&found, Product::Server, &version(), &flavor).unwrap();
        let program = found
            .iter()
            .find(|e| e.name.ends_with("/oncl-server"))
            .unwrap();
        assert_eq!(program.mode, Some(0o755));
        for bad in [Some(0o777), Some(0o4755), Some(0o664)] {
            let mut changed = found.clone();
            changed
                .iter_mut()
                .find(|e| e.name.ends_with("README.md"))
                .unwrap()
                .mode = bad;
            assert!(check_entries(&changed, Product::Server, &version(), &flavor).is_err());
        }
        let mut link = found.clone();
        link.iter_mut()
            .find(|e| e.name.ends_with("NOTICE"))
            .unwrap()
            .kind = Kind::Other;
        assert!(check_entries(&link, Product::Server, &version(), &flavor).is_err());
    }

    #[test]
    fn an_unreadable_tar_mode_is_an_error() {
        let mut tar = tar_header("t/x", 0o644, 0, false).unwrap().to_vec();
        tar.extend([0_u8; 1024]);
        assert!(parse_tar(&tar).is_ok());
        tar[100..107].copy_from_slice(b"zzzzzzz");
        assert!(parse_tar(&tar).is_err());
    }

    #[test]
    fn a_zip_records_fixed_modes_and_mutations_are_refused() {
        let flavor = flavor("win-x64").unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let top = dir_name(Product::Cli, &version(), &flavor);
        let stage = temporary.path().join(&top);
        for file in expected_files(Product::Cli, &flavor) {
            let path = stage.join(&file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"x").unwrap();
        }
        let archive = temporary.path().join("a.zip");
        pack(&stage, &top, &archive, Os::Windows).unwrap();
        let found = parse_zip_directory(&fs::read(&archive).unwrap()).unwrap();
        check_entries(&found, Product::Cli, &version(), &flavor).unwrap();
        assert_eq!(
            found
                .iter()
                .find(|e| e.name.ends_with("oncl.exe"))
                .unwrap()
                .mode,
            Some(0o755)
        );
        for bad in [Some(0o664), Some(0o777), Some(0o4755)] {
            let mut changed = found.clone();
            changed
                .iter_mut()
                .find(|e| e.name.ends_with("NOTICE"))
                .unwrap()
                .mode = bad;
            assert!(check_entries(&changed, Product::Cli, &version(), &flavor).is_err());
        }
        let mut link = found.clone();
        link[0].kind = Kind::Other;
        assert!(check_entries(&link, Product::Cli, &version(), &flavor).is_err());
    }

    #[test]
    fn only_linux_server_archives_carry_the_service_files() {
        for flavor in FLAVORS {
            let files = expected_files(Product::Server, &flavor);
            assert_eq!(
                files.contains("deploy/openncalayer-server.service"),
                flavor.os == Os::Linux,
                "{}",
                flavor.name
            );
        }
    }

    #[test]
    fn a_version_that_is_not_the_workspace_one_is_refused() {
        check_version(&version()).unwrap();
        assert!(check_version(&Version::parse("9.9.9").unwrap()).is_err());
    }
}
