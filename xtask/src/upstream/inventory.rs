//! The inventory of an unpacked artifact: every file with its size, SHA-256 and kind,
//! archives inside archives listed as `outer.jar!/inner/path`, and a Java runtime folded into
//! one summary. ZIP entries are read in memory, never written to disk, so their names cannot
//! reach outside the work directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, Read, Seek};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::hex;
use super::unpack::{Limits, Tree, TreeRoot, UnpackError, io, walk};

/// Files kept in memory for the facts (an embedded manifest, an installer script, a
/// `Info.plist`): at most this large.
const BLOB_MAX: u64 = 4 << 20;

/// The inventory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// By path (`/`-separated, relative; inside an archive `outer.jar!/inner/path`).
    pub files: BTreeMap<String, FileEntry>,
    /// The Java runtime, if there is one.
    pub jre: Option<JreFacts>,
    /// Bytes of the JARs, by path (memory only, for the bytecode facts).
    pub nested: BTreeMap<String, Vec<u8>>,
    /// Bytes of embedded manifests, installer scripts and property lists, by path.
    pub blobs: BTreeMap<String, Vec<u8>>,
}

/// A file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Size.
    pub size: u64,
    /// SHA-256.
    pub sha256: String,
    /// Kind.
    pub kind: FileKind,
}

/// The kind of a file, by its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// A JAR.
    Jar,
    /// Another ZIP.
    Zip,
    /// A Java class.
    Class,
    /// A JKS keystore.
    Keystore,
    /// A DER certificate.
    Cert,
    /// A native program or library (PE, ELF, Mach-O).
    Native,
    /// An NCALayer manifest (`ncalayer.der`).
    Manifest,
    /// Anything else.
    Other,
}

/// A Java runtime folded into one entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JreFacts {
    /// `JAVA_VERSION` of `release`.
    pub java_version: Option<String>,
    /// `IMPLEMENTOR`.
    pub implementor: Option<String>,
    /// `OS_ARCH`.
    pub os_arch: Option<String>,
    /// Its files.
    pub files: u64,
    /// SHA-256 of the sorted lines `path\0sha256\n`.
    pub tree_sha256: String,
}

/// The kind of a file named `name` starting with `head`.
pub fn file_kind(name: &str, head: &[u8]) -> FileKind {
    let lower = name.to_ascii_lowercase();
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return if lower.ends_with(".jar") {
            FileKind::Jar
        } else {
            FileKind::Zip
        };
    }
    if head.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) && lower.ends_with(".class") {
        return FileKind::Class;
    }
    if head.starts_with(&[0xfe, 0xed, 0xfe, 0xed]) {
        return FileKind::Keystore;
    }
    if head.starts_with(b"MZ")
        || head.starts_with(b"\x7fELF")
        || [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
        ]
        .iter()
        .any(|m| head.starts_with(m))
    {
        return FileKind::Native;
    }
    if head.first() == Some(&0x30) {
        if lower.rsplit('/').next() == Some("ncalayer.der") {
            return FileKind::Manifest;
        }
        if oncl_pki::cert::parse(head).is_ok() {
            return FileKind::Cert;
        }
    }
    FileKind::Other
}

fn wants_blob(name: &str) -> bool {
    let base = name
        .rsplit(['/', '!'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "ncalayer.der" | "install_script.iss" | "info.plist" | "tzdb.dat"
    )
}

/// A path inside an archive, `/`-separated, without empty, `.` and `..` parts.
pub fn normalize(name: &str) -> String {
    name.replace('\\', "/")
        .split('/')
        .filter(|p| !p.is_empty() && *p != "." && *p != "..")
        .collect::<Vec<_>>()
        .join("/")
}

struct Counter<'a> {
    limits: &'a Limits,
    files: u64,
    bytes: u64,
}

impl Counter<'_> {
    fn add(&mut self, size: u64) -> Result<(), UnpackError> {
        self.files += 1;
        self.bytes += size;
        if self.files > self.limits.files {
            return Err(UnpackError::Limit("files"));
        }
        if self.bytes > self.limits.total_bytes {
            return Err(UnpackError::Limit("total_bytes"));
        }
        Ok(())
    }
}

/// Collected files before the runtime is folded.
#[derive(Default)]
struct Collect {
    files: BTreeMap<String, FileEntry>,
    nested: BTreeMap<String, Vec<u8>>,
    blobs: BTreeMap<String, Vec<u8>>,
    /// `release` contents by path.
    releases: BTreeMap<String, Vec<u8>>,
    /// Directories of Java runtimes (their archives are not opened).
    jre_dirs: Vec<String>,
}

/// The directories (with a final `/`, or `""`) holding `release` and `bin/java[.exe]`.
fn jre_dirs<S: AsRef<str>>(prefix: &str, names: impl Iterator<Item = S>) -> Vec<String> {
    let names: BTreeSet<String> = names.map(|n| normalize(n.as_ref())).collect();
    names
        .iter()
        .filter_map(|n| {
            let dir = n.strip_suffix("release")?;
            if !(dir.is_empty() || dir.ends_with('/')) {
                return None;
            }
            (names.contains(&format!("{dir}bin/java"))
                || names.contains(&format!("{dir}bin/java.exe")))
            .then(|| format!("{prefix}{dir}"))
        })
        .collect()
}

/// The inventory of `tree`.
///
/// # Errors
///
/// [`UnpackError`]: a limit, a malformed archive, I/O.
pub fn inventory(tree: &Tree, limits: &Limits) -> Result<Inventory, UnpackError> {
    let mut counter = Counter {
        limits,
        files: 0,
        bytes: 0,
    };
    let mut c = Collect::default();
    match &tree.root {
        TreeRoot::Archive(path) => {
            let file = BufReader::new(File::open(path).map_err(io)?);
            read_zip(file, "", 0, limits, &mut counter, &mut c)?;
        }
        TreeRoot::Dir(dir) => {
            let listed = walk(dir, limits)?;
            c.jre_dirs = jre_dirs("", listed.iter().map(|(rel, _)| rel.as_str()));
            for (rel, path) in listed {
                let mut file = File::open(&path).map_err(io)?;
                let size = file.metadata().map_err(io)?.len();
                if size > limits.entry_bytes {
                    return Err(UnpackError::Limit("entry_bytes"));
                }
                counter.add(size)?;
                let mut head = [0u8; 4096];
                let n = read_head(&mut file, &mut head)?;
                let kind = file_kind(&rel, &head[..n]);
                let keep = matches!(kind, FileKind::Jar | FileKind::Zip)
                    || wants_blob(&rel)
                    || rel.ends_with("/release")
                    || rel == "release";
                if keep {
                    let bytes = std::fs::read(&path).map_err(io)?;
                    add_entry(&rel, bytes, 0, limits, &mut counter, &mut c)?;
                } else {
                    let sha256 = hash_file(&path)?;
                    c.files.insert(rel, FileEntry { size, sha256, kind });
                }
            }
        }
    }
    Ok(fold_jre(c))
}

fn read_head(file: &mut File, buf: &mut [u8]) -> Result<usize, UnpackError> {
    let mut n = 0;
    while n < buf.len() {
        let got = file.read(&mut buf[n..]).map_err(io)?;
        if got == 0 {
            break;
        }
        n += got;
    }
    file.rewind().map_err(io)?;
    Ok(n)
}

fn hash_file(path: &std::path::Path) -> Result<String, UnpackError> {
    let mut file = File::open(path).map_err(io)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = file.read(&mut buf).map_err(io)?;
        if n == 0 {
            return Ok(hex(&hasher.finalize()));
        }
        hasher.update(&buf[..n]);
    }
}

/// The entries of a ZIP at `prefix` (`""` or `outer.jar!/`), archives inside at `depth + 1`.
fn read_zip<R: Read + Seek>(
    reader: R,
    prefix: &str,
    depth: u32,
    limits: &Limits,
    counter: &mut Counter<'_>,
    c: &mut Collect,
) -> Result<(), UnpackError> {
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| UnpackError::Malformed(format!("ZIP {prefix}: {e}")))?;
    let dirs = jre_dirs(prefix, archive.file_names().filter_map(Result::ok));
    c.jre_dirs.extend(dirs);
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UnpackError::Malformed(format!("ZIP entry: {e}")))?;
        if entry.is_dir() || entry.is_symlink() {
            continue;
        }
        let name = normalize(
            &entry
                .name()
                .map_err(|e| UnpackError::Malformed(format!("ZIP entry name: {e}")))?,
        );
        if name.is_empty() {
            continue;
        }
        let mut bytes = Vec::new();
        (&mut entry)
            .take(limits.entry_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| UnpackError::Malformed(format!("ZIP entry {name}: {}", e.kind())))?;
        if bytes.len() as u64 > limits.entry_bytes {
            return Err(UnpackError::Limit("entry_bytes"));
        }
        counter.add(bytes.len() as u64)?;
        add_entry(&format!("{prefix}{name}"), bytes, depth, limits, counter, c)?;
    }
    Ok(())
}

/// Records a file whose bytes are in memory; recurses into archives.
fn add_entry(
    path: &str,
    bytes: Vec<u8>,
    depth: u32,
    limits: &Limits,
    counter: &mut Counter<'_>,
    c: &mut Collect,
) -> Result<(), UnpackError> {
    let in_jre = c.jre_dirs.iter().any(|d| path.starts_with(d.as_str()));
    let kind = file_kind(path, &bytes[..bytes.len().min(4096)]);
    let size = bytes.len() as u64;
    c.files.insert(
        path.to_owned(),
        FileEntry {
            size,
            sha256: super::sha256_hex(&bytes),
            kind,
        },
    );
    if path.rsplit('/').next() == Some("release") {
        c.releases.insert(path.to_owned(), bytes.clone());
    }
    if wants_blob(path) && size <= BLOB_MAX {
        c.blobs.insert(path.to_owned(), bytes.clone());
    }
    if matches!(kind, FileKind::Jar | FileKind::Zip) && !in_jre {
        if depth + 1 > limits.depth {
            return Err(UnpackError::Limit("depth"));
        }
        // An archive that does not open is listed, not unpacked.
        let nested_prefix = format!("{path}!/");
        match read_zip(
            std::io::Cursor::new(&bytes),
            &nested_prefix,
            depth + 1,
            limits,
            counter,
            c,
        ) {
            Ok(()) | Err(UnpackError::Malformed(_)) => {}
            Err(e) => return Err(e),
        }
        if kind == FileKind::Jar {
            c.nested.insert(path.to_owned(), bytes);
        }
    }
    Ok(())
}

/// Folds every directory holding `release` and `bin/java[.exe]` into [`JreFacts`].
fn fold_jre(c: Collect) -> Inventory {
    let mut jre_roots: Vec<String> = c
        .jre_dirs
        .iter()
        .filter(|d| c.releases.contains_key(&format!("{d}release")))
        .cloned()
        .collect();
    jre_roots.sort();
    jre_roots.dedup();
    let mut files = c.files;
    let mut jre = None;
    if let Some(root) = jre_roots.first() {
        let inside: BTreeSet<String> = files
            .keys()
            .filter(|p| p.starts_with(root.as_str()))
            .cloned()
            .collect();
        let mut hasher = Sha256::new();
        for path in &inside {
            let rel = &path[root.len()..];
            hasher.update(rel.as_bytes());
            hasher.update(b"\0");
            hasher.update(files[path].sha256.as_bytes());
            hasher.update(b"\n");
        }
        let release = String::from_utf8_lossy(&c.releases[&format!("{root}release")]).into_owned();
        let value = |key: &str| {
            release.lines().find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim().trim_matches('"').to_owned())
            })
        };
        jre = Some(JreFacts {
            java_version: value("JAVA_VERSION"),
            implementor: value("IMPLEMENTOR"),
            os_arch: value("OS_ARCH"),
            files: inside.len() as u64,
            tree_sha256: hex(&hasher.finalize()),
        });
        files.retain(|p, _| !p.starts_with(root.as_str()));
    }
    let keep = |p: &String| files.contains_key(p);
    Inventory {
        nested: c.nested.into_iter().filter(|(p, _)| keep(p)).collect(),
        blobs: c.blobs.into_iter().filter(|(p, _)| keep(p)).collect(),
        files,
        jre,
    }
}
