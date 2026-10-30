//! Unpacking of the original's files without running any of them. ZIP and JAR files, the
//! `.sh` installer (a script with a ZIP payload) and the Go dropper (a gzip stream of the real
//! installer) are read by our code; Inno Setup installers go to innounp, Windows Installer
//! and disk images to 7-Zip. The output of the tools goes to a log file; only their exit code
//! is reported.

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::artifact::Format;
use super::meta::{DistMeta, LiteMeta, ShMeta};
use super::sha256_hex;

/// Limits of unpacking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Bytes of all files.
    pub total_bytes: u64,
    /// Number of files.
    pub files: u64,
    /// Depth of archives inside archives.
    pub depth: u32,
    /// Bytes of one file.
    pub entry_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            total_bytes: 4 << 30,
            files: 200_000,
            depth: 4,
            entry_bytes: 512 << 20,
        }
    }
}

/// Why unpacking failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnpackError {
    /// A limit of [`Limits`] (its field name).
    Limit(&'static str),
    /// A tool exited with an error.
    Tool {
        /// The tool.
        name: &'static str,
        /// Its exit code.
        code: Option<i32>,
    },
    /// A tool ran too long.
    Timeout(&'static str),
    /// The file is not what its format says.
    Malformed(String),
    /// I/O.
    Io(String),
}

impl fmt::Display for UnpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnpackError::Limit(l) => write!(f, "limit {l} exceeded"),
            UnpackError::Tool { name, code } => write!(f, "{name} exited with {code:?}"),
            UnpackError::Timeout(name) => write!(f, "{name} timed out"),
            UnpackError::Malformed(e) => write!(f, "malformed: {e}"),
            UnpackError::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl std::error::Error for UnpackError {}

pub(crate) fn io(e: std::io::Error) -> UnpackError {
    UnpackError::Io(e.kind().to_string())
}

/// An external unpacker.
pub trait Extractor {
    /// Its name (`innounp`, `7z`).
    fn name(&self) -> &'static str;
    /// Extracts `archive` into `out`.
    ///
    /// # Errors
    ///
    /// [`UnpackError`].
    fn extract(&self, archive: &Path, out: &Path) -> Result<(), UnpackError>;
}

/// How long a tool may run.
pub const TOOL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// innounp: `-x -m -a -y -d<out> <archive>` (extract with the script, all copies, no
/// questions).
pub fn innounp_args(archive: &Path, out: &Path) -> Vec<OsString> {
    let mut d = OsString::from("-d");
    d.push(out);
    vec![
        "-x".into(),
        "-m".into(),
        "-a".into(),
        "-y".into(),
        d,
        archive.into(),
    ]
}

/// 7-Zip: `x -y -bd -bso0 -bsp0 -o<out> <archive>` (no progress, no output). 7-Zip 25.01
/// and newer refuse links that point out of `out` by default; older versions are not used
/// ([`super::tools::sevenzip_supported`]).
pub fn sevenzip_args(archive: &Path, out: &Path) -> Vec<OsString> {
    let mut o = OsString::from("-o");
    o.push(out);
    vec![
        "x".into(),
        "-y".into(),
        "-bd".into(),
        "-bso0".into(),
        "-bsp0".into(),
        o,
        archive.into(),
    ]
}

/// innounp at `exe`.
#[derive(Clone, Debug)]
pub struct Innounp {
    /// The program.
    pub exe: PathBuf,
}

impl Extractor for Innounp {
    fn name(&self) -> &'static str {
        "innounp"
    }

    fn extract(&self, archive: &Path, out: &Path) -> Result<(), UnpackError> {
        run_tool(
            self.name(),
            &self.exe,
            &innounp_args(archive, out),
            out,
            TOOL_TIMEOUT,
        )
    }
}

/// 7-Zip at `exe`.
#[derive(Clone, Debug)]
pub struct SevenZip {
    /// The program.
    pub exe: PathBuf,
}

impl Extractor for SevenZip {
    fn name(&self) -> &'static str {
        "7z"
    }

    fn extract(&self, archive: &Path, out: &Path) -> Result<(), UnpackError> {
        run_tool(
            self.name(),
            &self.exe,
            &sevenzip_args(archive, out),
            out,
            TOOL_TIMEOUT,
        )
    }
}

/// Runs `exe args` with its output in `<out>.log` (beside `out`), killed after `timeout`.
///
/// # Errors
///
/// [`UnpackError::Timeout`], [`UnpackError::Tool`] for a non-zero exit, I/O errors.
pub fn run_tool(
    name: &'static str,
    exe: &Path,
    args: &[OsString],
    out: &Path,
    timeout: Duration,
) -> Result<(), UnpackError> {
    std::fs::create_dir_all(out).map_err(io)?;
    let log_path = out.with_extension("log");
    let log = File::create(&log_path).map_err(io)?;
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(io)?)
        .stderr(log)
        .spawn()
        .map_err(io)?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(io)? {
            println!("unpack: {name} exit {}", status.code().unwrap_or(-1));
            return if status.success() {
                Ok(())
            } else {
                Err(UnpackError::Tool {
                    name,
                    code: status.code(),
                })
            };
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(UnpackError::Timeout(name));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The external tools available.
#[derive(Default)]
pub struct Tools {
    /// innounp.
    pub innounp: Option<Box<dyn Extractor>>,
    /// 7-Zip.
    pub sevenzip: Option<Box<dyn Extractor>>,
}

impl fmt::Debug for Tools {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tools")
            .field("innounp", &self.innounp.as_ref().map(|t| t.name()))
            .field("sevenzip", &self.sevenzip.as_ref().map(|t| t.name()))
            .finish()
    }
}

impl Tools {
    /// `ONCL_INNOUNP` and `ONCL_7Z` (as `cargo xtask upstream tools` prints them).
    pub fn from_env() -> Tools {
        let path = |var: &str| {
            std::env::var_os(var)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Tools {
            innounp: path("ONCL_INNOUNP")
                .map(|exe| Box::new(Innounp { exe }) as Box<dyn Extractor>),
            sevenzip: path("ONCL_7Z").map(|exe| Box::new(SevenZip { exe }) as Box<dyn Extractor>),
        }
    }
}

/// Where the files of an unpacked artifact are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeRoot {
    /// A directory an external tool wrote.
    Dir(PathBuf),
    /// A ZIP read in place (possibly with data before it).
    Archive(PathBuf),
}

/// An unpacked artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    /// Its files.
    pub root: TreeRoot,
    /// What was learnt while unpacking.
    pub meta: DistMeta,
}

/// The outcome of unpacking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unpacked {
    /// Unpacked.
    Tree(Box<Tree>),
    /// Not unpacked, and why (a fact, not a failure).
    Skipped {
        /// Why.
        reason: String,
    },
}

/// Unpacks `artifact` of `format` under `work`.
///
/// # Errors
///
/// [`UnpackError`].
pub fn unpack(
    artifact: &Path,
    format: Format,
    work: &Path,
    tools: &Tools,
    limits: &Limits,
) -> Result<Unpacked, UnpackError> {
    std::fs::create_dir_all(work).map_err(io)?;
    let tree = |root, meta| Ok(Unpacked::Tree(Box::new(Tree { root, meta })));
    match format {
        Format::Jar | Format::Zip => {
            tree(TreeRoot::Archive(artifact.to_owned()), DistMeta::default())
        }
        Format::Sh => {
            let (offset, header_sha256) = sh_payload(artifact)?;
            tree(
                TreeRoot::Archive(artifact.to_owned()),
                DistMeta {
                    sh: Some(ShMeta {
                        payload_offset: offset,
                        header_sha256,
                    }),
                    ..DistMeta::default()
                },
            )
        }
        Format::GoDropper => {
            let embedded = work.join("lite-embedded.exe");
            let (go_version, sha256) = go_dropper(artifact, &embedded, limits)?;
            tree(
                TreeRoot::Archive(embedded),
                DistMeta {
                    lite: Some(LiteMeta {
                        go_version,
                        embedded_exe_sha256: sha256,
                    }),
                    ..DistMeta::default()
                },
            )
        }
        Format::InnoExe => match &tools.innounp {
            None => Ok(skipped("no innounp")),
            Some(tool) => {
                let out = work.join("inno");
                tool.extract(artifact, &out)?;
                tree(TreeRoot::Dir(out), DistMeta::default())
            }
        },
        Format::Msi | Format::Dmg => match &tools.sevenzip {
            None => Ok(skipped("no 7z")),
            Some(tool) => {
                let out = work.join(if format == Format::Msi { "msi" } else { "dmg" });
                tool.extract(artifact, &out)?;
                if format == Format::Msi {
                    extract_cabinets(tool.as_ref(), &out, limits, 1)?;
                }
                tree(TreeRoot::Dir(out), DistMeta::default())
            }
        },
        other => Ok(skipped(&format!("format {other}"))),
    }
}

fn skipped(reason: &str) -> Unpacked {
    Unpacked::Skipped {
        reason: reason.to_owned(),
    }
}

/// Every `*.cab` under `dir` extracted with `tool` into `<cab>.d/`, recursively.
fn extract_cabinets(
    tool: &dyn Extractor,
    dir: &Path,
    limits: &Limits,
    depth: u32,
) -> Result<(), UnpackError> {
    if depth > limits.depth {
        return Err(UnpackError::Limit("depth"));
    }
    let cabs: Vec<PathBuf> = walk(dir, limits)?
        .into_iter()
        .map(|(_, path)| path)
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("cab")))
        .collect();
    for cab in cabs {
        let out = cab.with_extension("cab.d");
        tool.extract(&cab, &out)?;
        extract_cabinets(tool, &out, limits, depth + 1)?;
    }
    Ok(())
}

/// The regular files under `root` as `(relative path with '/', path)`, sorted; symbolic
/// links, reparse points and anything outside `root` are skipped. Counts against
/// `limits.files`.
///
/// # Errors
///
/// [`UnpackError::Limit`] or I/O errors.
pub fn walk(root: &Path, limits: &Limits) -> Result<Vec<(String, PathBuf)>, UnpackError> {
    let root = root.canonicalize().map_err(io)?;
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(io)? {
            let entry = entry.map_err(io)?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(io)?;
            if meta.file_type().is_symlink() || is_reparse_point(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let Ok(rel) = path.strip_prefix(&root) else {
                    continue;
                };
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, path));
                if out.len() as u64 > limits.files {
                    return Err(UnpackError::Limit("files"));
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(windows)]
fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &std::fs::Metadata) -> bool {
    false
}

/// The payload of a `.sh` installer: where its ZIP starts and the SHA-256 of the script
/// before it.
///
/// # Errors
///
/// [`UnpackError::Malformed`] without a ZIP.
pub fn sh_payload(path: &Path) -> Result<(u64, String), UnpackError> {
    let archive = zip::ZipArchive::new(BufReader::new(File::open(path).map_err(io)?))
        .map_err(|e| UnpackError::Malformed(format!("no ZIP payload: {e}")))?;
    let offset = archive.offset();
    let mut header =
        vec![0; usize::try_from(offset).map_err(|_| UnpackError::Limit("entry_bytes"))?];
    File::open(path)
        .map_err(io)?
        .read_exact(&mut header)
        .map_err(io)?;
    Ok((offset, sha256_hex(&header)))
}

/// The program inside a Go dropper: the first gzip stream that inflates (within
/// `limits.entry_bytes`) to a PE, written to `out`. Returns the Go version string and the
/// SHA-256 of the program.
///
/// # Errors
///
/// [`UnpackError::Malformed`] without such a stream, [`UnpackError::Limit`].
pub fn go_dropper(
    path: &Path,
    out: &Path,
    limits: &Limits,
) -> Result<(Option<String>, String), UnpackError> {
    let len = std::fs::metadata(path).map_err(io)?.len();
    if len > limits.entry_bytes.saturating_mul(2) {
        return Err(UnpackError::Limit("entry_bytes"));
    }
    let bytes = std::fs::read(path).map_err(io)?;
    let go_version = find(&bytes, b"go1.").map(|at| {
        bytes[at..]
            .iter()
            .take_while(|b| b.is_ascii_graphic())
            .take(64)
            .map(|&b| char::from(b))
            .collect::<String>()
    });
    let mut from = 0;
    while let Some(at) = find(&bytes[from..], &[0x1f, 0x8b, 0x08]).map(|i| i + from) {
        from = at + 1;
        let mut inflated = Vec::new();
        let decoder = flate2::read::GzDecoder::new(&bytes[at..]);
        let read = decoder
            .take(limits.entry_bytes + 1)
            .read_to_end(&mut inflated);
        if read.is_err() || !inflated.starts_with(b"MZ") {
            continue;
        }
        if inflated.len() as u64 > limits.entry_bytes {
            return Err(UnpackError::Limit("entry_bytes"));
        }
        std::fs::write(out, &inflated).map_err(io)?;
        return Ok((go_version, sha256_hex(&inflated)));
    }
    Err(UnpackError::Malformed(
        "no gzip stream of a program".to_owned(),
    ))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
