//! `cargo xtask licenses`: the licences of the third-party crates in OpenNCALayer's
//! programs, for the About window ([`OUTPUT`], embedded into `oncl-ui`).
//!
//! The crates are those `cargo tree` resolves for the normal dependencies of `openncalayer`
//! and `oncl-nmhost` on every platform we ship ([`TARGETS`]); build dependencies and
//! procedural macros are not part of the programs. Their licence texts come from the
//! packages in the local cargo registry (`cargo metadata --offline`), without network
//! access, or from the patched copy of a crates.io package under [`VENDOR`]; `cargo fetch
//! --locked` unpacks the packages of every platform ([`PackagesMissing`] otherwise):
//!
//! - the package's `license-file` and its files named `LICENSE*`, `LICENCE*`, `COPYING*`,
//!   `NOTICE*`, `UNLICENSE*` or `COPYRIGHT*`;
//! - the files of a REUSE `LICENSES/` directory named after a licence `deny.toml` accepts;
//! - for a package with none of these, the standard texts in [`STANDARD_TEXTS`] of the
//!   licences its SPDX expression names.
//!
//! A template copyright line (`Copyright (c) <year> <copyright holders>`) names the
//! package's authors from `Cargo.toml`, or its repository. Identical texts (up to white
//! space) are written once, the packages' own files before the standard texts. The output
//! is the same on every host; `--check` compares it with the committed file.

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use serde_json::Value;

/// The generated file, relative to the workspace root.
pub const OUTPUT: &str = "crates/oncl-ui/assets/THIRD-PARTY.txt";

/// Standard licence texts (`<SPDX id>.txt`), relative to the workspace root.
pub const STANDARD_TEXTS: &str = "xtask/licenses";

/// Patched copies of crates.io packages (`[patch.crates-io]`), relative to the workspace root.
pub const VENDOR: &str = "vendor";

/// The packages of the programs we ship.
const PROGRAMS: [&str; 2] = ["openncalayer", "oncl-nmhost"];

/// The platforms we ship for.
pub const TARGETS: [&str; 7] = [
    "x86_64-pc-windows-msvc",
    "x86_64-win7-windows-msvc",
    "i686-win7-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];

/// Marks the start of the crate list in [`OUTPUT`].
pub const CRATES_HEADER: &str = "[crates]";

/// A third-party package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// `authors` of `Cargo.toml`.
    pub authors: Vec<String>,
    /// The SPDX expression of `Cargo.toml`.
    pub license: Option<String>,
    /// `license-file` of `Cargo.toml`, relative to `dir`.
    pub license_file: Option<String>,
    pub repository: Option<String>,
    /// The unpacked package.
    pub dir: PathBuf,
}

/// Some package is not in the local cargo registry: `cargo fetch --locked` unpacks them.
#[derive(Debug)]
pub struct PackagesMissing {
    /// What cargo said.
    pub detail: String,
}

impl std::fmt::Display for PackagesMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "packages are missing from the local cargo registry: run `cargo fetch --locked` \
             ({})",
            self.detail
        )
    }
}

impl std::error::Error for PackagesMissing {}

/// Writes [`OUTPUT`] under `root`.
///
/// # Errors
///
/// See [`generate`]; the file cannot be written.
pub fn write(root: &Path) -> anyhow::Result<PathBuf> {
    let text = generate(root)?;
    let path = root.join(OUTPUT);
    fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Whether [`OUTPUT`] under `root` is what [`generate`] gives.
///
/// # Errors
///
/// See [`generate`].
pub fn check(root: &Path) -> anyhow::Result<bool> {
    let expected = generate(root)?;
    Ok(fs::read(root.join(OUTPUT)).ok().as_deref() == Some(expected.as_bytes()))
}

/// The licence file of the workspace at `root`.
///
/// # Errors
///
/// [`PackagesMissing`]; `cargo tree` or `cargo metadata` fails otherwise, a licence file
/// cannot be read, `deny.toml` or a standard text is missing, or a package has no licence
/// text at all.
pub fn generate(root: &Path) -> anyhow::Result<String> {
    let shipped = shipped_crates(root)?;
    let mut packages = registry_packages(root)?;
    let crates = shipped
        .into_iter()
        .map(|(name, version)| {
            packages
                .remove(&(name.clone(), version.clone()))
                .with_context(|| format!("{name} {version} is not a crates.io package"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let accepted = accepted_licenses(root)?;
    let standard = standard_texts(&root.join(STANDARD_TEXTS))?;
    render(&crates, &accepted, &standard)
}

/// `(name, version)` of the third-party crates of [`PROGRAMS`] on [`TARGETS`], sorted.
fn shipped_crates(root: &Path) -> anyhow::Result<BTreeSet<(String, String)>> {
    let mut args = vec![
        "tree",
        "--locked",
        "--offline",
        "--edges",
        "normal,no-proc-macro",
    ];
    for program in PROGRAMS {
        args.extend(["--package", program]);
    }
    for target in TARGETS {
        args.extend(["--target", target]);
    }
    args.extend(["--prefix", "none", "--format", "{p}"]);
    let out = cargo(root, &args)?;
    let members = workspace_members(root)?;
    let mut crates = BTreeSet::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let mut words = line.split_whitespace();
        let (Some(name), Some(version)) = (words.next(), words.next()) else {
            bail!("unexpected `cargo tree` line {line:?}");
        };
        let version = version
            .strip_prefix('v')
            .with_context(|| format!("unexpected `cargo tree` line {line:?}"))?;
        if !members.contains(name) {
            crates.insert((name.to_owned(), version.to_owned()));
        }
    }
    Ok(crates)
}

/// The names of the workspace's packages.
fn workspace_members(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let metadata = metadata(root, &["--no-deps"])?;
    Ok(packages_of(&metadata)
        .filter_map(|p| p["name"].as_str().map(str::to_owned))
        .collect())
}

/// The crates.io packages of the lock file, from the local cargo registry or, if patched, from
/// [`VENDOR`].
fn registry_packages(root: &Path) -> anyhow::Result<HashMap<(String, String), Package>> {
    let metadata = metadata(root, &[])?;
    let vendor = root.join(VENDOR);
    let text = |p: &Value, key: &str| p[key].as_str().map(str::to_owned);
    let mut packages = HashMap::new();
    for p in packages_of(&metadata) {
        let registry = p["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("registry+"));
        let vendored = text(p, "manifest_path").is_some_and(|m| Path::new(&m).starts_with(&vendor));
        if !registry && !vendored {
            continue;
        }
        let (Some(name), Some(version), Some(manifest)) = (
            text(p, "name"),
            text(p, "version"),
            text(p, "manifest_path"),
        ) else {
            bail!("`cargo metadata`: a package without name, version or manifest_path");
        };
        let dir = Path::new(&manifest)
            .parent()
            .with_context(|| format!("{manifest}: no directory"))?
            .to_path_buf();
        packages.insert(
            (name.clone(), version.clone()),
            Package {
                name,
                version,
                authors: p["authors"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|a| a.as_str().map(str::to_owned))
                    .collect(),
                license: text(p, "license"),
                license_file: text(p, "license_file"),
                repository: text(p, "repository"),
                dir,
            },
        );
    }
    Ok(packages)
}

fn packages_of(metadata: &Value) -> impl Iterator<Item = &Value> {
    metadata["packages"].as_array().into_iter().flatten()
}

fn metadata(root: &Path, extra: &[&str]) -> anyhow::Result<Value> {
    let mut args = vec!["metadata", "--format-version", "1", "--locked", "--offline"];
    args.extend(extra);
    let out = cargo(root, &args)?;
    serde_json::from_str(&out).context("parsing `cargo metadata`")
}

/// The standard output of `cargo <args>` in `root`.
///
/// # Errors
///
/// [`PackagesMissing`] if offline cargo lacks a package; otherwise cargo's error.
fn cargo(root: &Path, args: &[&str]) -> anyhow::Result<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let out = Command::new(cargo)
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| format!("running cargo {}", args[0]))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if needs_download(&stderr) {
            return Err(PackagesMissing { detail: stderr }.into());
        }
        bail!("cargo {} failed: {stderr}", args[0]);
    }
    String::from_utf8(out.stdout).with_context(|| format!("cargo {}: not UTF-8", args[0]))
}

/// Whether offline cargo failed for want of a package (`attempting to make an HTTP request,
/// but --offline was specified`, `no matching package … offline mode`).
fn needs_download(stderr: &str) -> bool {
    stderr.contains("--offline") || stderr.contains("offline mode")
}

/// The licences `deny.toml` accepts (`[licenses] allow`).
fn accepted_licenses(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let path = root.join("deny.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let deny: toml::Table = toml::from_str(&text).with_context(|| path.display().to_string())?;
    let allow = deny
        .get("licenses")
        .and_then(|l| l.get("allow"))
        .and_then(toml::Value::as_array)
        .with_context(|| format!("{}: no [licenses] allow", path.display()))?;
    Ok(allow
        .iter()
        .filter_map(toml::Value::as_str)
        .map(str::to_owned)
        .collect())
}

/// The standard texts in `dir`: SPDX id (the file stem of `<id>.txt`) → text.
fn standard_texts(dir: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let mut texts = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "txt")
            && let Some(id) = path.file_stem().and_then(|s| s.to_str())
        {
            let text = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            texts.push((id.to_owned(), normalize(&text)));
        }
    }
    texts.sort();
    Ok(texts)
}

/// The licence files of `p`, sorted by name: see the module documentation.
fn license_files(p: &Package, accepted: &BTreeSet<String>) -> anyhow::Result<Vec<PathBuf>> {
    const PREFIXES: [&str; 6] = [
        "LICENSE",
        "LICENCE",
        "COPYING",
        "NOTICE",
        "UNLICENSE",
        "COPYRIGHT",
    ];
    let mut files = BTreeSet::new();
    if let Some(file) = &p.license_file {
        files.insert(p.dir.join(file));
    }
    for entry in fs::read_dir(&p.dir).with_context(|| format!("reading {}", p.dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_uppercase();
        if PREFIXES.iter().any(|prefix| name.starts_with(prefix)) && entry.file_type()?.is_file() {
            files.insert(entry.path());
        }
    }
    let reuse = p.dir.join("LICENSES");
    if reuse.is_dir() {
        for entry in fs::read_dir(&reuse).with_context(|| format!("reading {}", reuse.display()))? {
            let path = entry?.path();
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if accepted.contains(id) && path.is_file() {
                files.insert(path);
            }
        }
    }
    Ok(files.into_iter().collect())
}

/// The licence ids of an SPDX expression, without operators and exceptions.
pub fn license_ids(expression: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut exception = false;
    for token in expression
        .split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '/'))
        .filter(|t| !t.is_empty())
    {
        match token {
            "OR" | "AND" => {}
            "WITH" => exception = true,
            _ if exception => exception = false,
            id => ids.push(id.to_owned()),
        }
    }
    ids
}

/// `text` with LF line ends, without trailing white space, control characters other than
/// tabs, a byte order mark, or blank lines at either end; invalid UTF-8 replaced.
fn normalize(text: &[u8]) -> String {
    let text = String::from_utf8_lossy(text);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            line.chars()
                .filter(|&c| c == '\t' || !c.is_control())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect();
    let start = lines
        .iter()
        .position(|l| !l.is_empty())
        .unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|l| !l.is_empty())
        .map_or(start, |i| i + 1);
    lines[start..end].join("\n")
}

/// The same text for the purpose of writing it once.
fn dedup_key(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The template copyright line of the MIT and zlib texts.
const TEMPLATE_COPYRIGHT: &str = "Copyright (c) <year> <copyright holders>";

/// `text` with its template copyright line naming `p`'s authors from `Cargo.toml`, or, if
/// it has none, its repository.
fn with_holders(text: &str, p: &Package) -> String {
    if !text.contains(TEMPLATE_COPYRIGHT) {
        return text.to_owned();
    }
    let holders = if p.authors.is_empty() {
        format!(
            "the {} authors (see {})",
            p.name,
            p.repository.as_deref().unwrap_or("crates.io")
        )
    } else {
        p.authors.join(", ")
    };
    text.replace(TEMPLATE_COPYRIGHT, &format!("Copyright (c) {holders}"))
}

/// The licence file of `crates` (sorted by name and version): the list of crates, each
/// with the numbers of its texts, then the texts: the packages' own files first, then the
/// standard texts of packages without any, so that a text shared by both is titled after
/// a file. `accepted` filters REUSE `LICENSES/` files; `standard` are the texts for
/// packages without any.
///
/// # Errors
///
/// A licence file cannot be read; a package has neither an expression nor a file, or no
/// licence file and no standard text of its licences.
pub fn render(
    crates: &[Package],
    accepted: &BTreeSet<String>,
    standard: &[(String, String)],
) -> anyhow::Result<String> {
    // (title, text) in the order of first use; dedup key → number.
    let mut texts: Vec<(String, String)> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut add = |title: String, text: String| -> usize {
        *seen.entry(dedup_key(&text)).or_insert_with(|| {
            texts.push((title, text));
            texts.len()
        })
    };
    let mut refs: Vec<Vec<usize>> = Vec::with_capacity(crates.len());
    for p in crates {
        let mut own = Vec::new();
        for file in license_files(p, accepted)? {
            let text = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let text = normalize(&text);
            if text.is_empty() {
                continue;
            }
            let file_name = file
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            own.push(add(
                format!("{file_name} of {} {}", p.name, p.version),
                with_holders(&text, p),
            ));
        }
        refs.push(own);
    }
    let mut list = String::new();
    for (p, refs) in crates.iter().zip(&mut refs) {
        let Some(license) = p
            .license
            .as_deref()
            .or(p.license_file.as_deref().map(|_| ""))
        else {
            bail!("{} {}: no licence in Cargo.toml", p.name, p.version);
        };
        if refs.is_empty() {
            for id in license_ids(license) {
                if let Some((_, template)) = standard.iter().find(|(s, _)| *s == id) {
                    let text = with_holders(template, p);
                    let title = if text == *template {
                        format!("{id}, standard text (for crates without a licence file)")
                    } else {
                        format!(
                            "{id}, standard text for {} {} (it ships no licence file)",
                            p.name, p.version
                        )
                    };
                    refs.push(add(title, text));
                }
            }
        }
        if refs.is_empty() {
            bail!(
                "{} {}: no licence file and no standard text in {STANDARD_TEXTS} of {license:?}",
                p.name,
                p.version
            );
        }
        refs.sort_unstable();
        refs.dedup();
        let refs: Vec<String> = refs.iter().map(ToString::to_string).collect();
        let license = if license.is_empty() {
            "see the licence file"
        } else {
            license
        };
        let repository = p.repository.as_deref().unwrap_or("-");
        writeln!(
            list,
            "{} {} | {license} | {repository} | {}",
            p.name,
            p.version,
            refs.join(", ")
        )?;
    }

    let mut out = String::new();
    out.push_str(
        "OpenNCALayer: third-party software\n\
         ==================================\n\
         \n\
         The programs of OpenNCALayer (openncalayer and nmhost) for Windows, Linux and macOS\n\
         include the crates listed below. Each line names a crate, its version, its licence\n\
         as an SPDX expression (\"A OR B\" is a choice between licences), its repository and\n\
         the numbers of its licence texts, which follow the list. Slint is used under\n\
         LicenseRef-Slint-Royalty-free-2.0.\n\
         \n\
         Generated by `cargo xtask licenses`; do not edit.\n\
         \n",
    );
    out.push_str(CRATES_HEADER);
    out.push('\n');
    out.push_str(&list);
    for (i, (title, text)) in texts.iter().enumerate() {
        write!(out, "\n[text {}] {title}\n\n{text}\n", i + 1)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(dir: &Path, name: &str, license: Option<&str>) -> Package {
        let dir = dir.join(name);
        fs::create_dir_all(&dir).unwrap();
        Package {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            authors: Vec::new(),
            license: license.map(str::to_owned),
            license_file: None,
            repository: Some(format!("https://example.test/{name}")),
            dir,
        }
    }

    fn accepted() -> BTreeSet<String> {
        ["MIT", "Apache-2.0"].map(str::to_owned).into()
    }

    #[test]
    fn spdx_ids_without_operators_and_exceptions() {
        assert_eq!(license_ids("MIT OR Apache-2.0"), ["MIT", "Apache-2.0"]);
        assert_eq!(license_ids("MIT/Apache-2.0"), ["MIT", "Apache-2.0"]);
        assert_eq!(
            license_ids("(Apache-2.0 WITH LLVM-exception) OR MIT AND Zlib"),
            ["Apache-2.0", "MIT", "Zlib"]
        );
    }

    #[test]
    fn texts_are_normalized() {
        assert_eq!(
            normalize(b"\xef\xbb\xbf\r\n\r\nMIT \x0c\r\n\r\n\tpermission\t\r\n\r\n"),
            "MIT\n\n\tpermission"
        );
        assert_eq!(normalize(b"bad \xff byte"), "bad \u{fffd} byte");
    }

    #[test]
    fn identical_texts_are_written_once() {
        let dir = tempfile::tempdir().unwrap();
        let a = package(dir.path(), "a", Some("MIT OR Apache-2.0"));
        fs::write(a.dir.join("LICENSE-MIT"), "MIT text\r\nline two\r\n").unwrap();
        fs::write(a.dir.join("LICENSE-APACHE"), "Apache text").unwrap();
        fs::write(a.dir.join("README.md"), "not a licence").unwrap();
        let b = package(dir.path(), "b", Some("MIT"));
        fs::write(b.dir.join("license.txt"), "MIT  text\nline   two\n").unwrap();
        let out = render(&[a, b], &accepted(), &[]).unwrap();
        assert!(
            out.contains(
                "[crates]\n\
                 a 1.0.0 | MIT OR Apache-2.0 | https://example.test/a | 1, 2\n\
                 b 1.0.0 | MIT | https://example.test/b | 2\n"
            ),
            "{out}"
        );
        assert!(out.contains("\n[text 1] LICENSE-APACHE of a 1.0.0\n\nApache text\n"));
        assert!(out.contains("\n[text 2] LICENSE-MIT of a 1.0.0\n\nMIT text\nline two\n"));
        assert!(!out.contains("[text 3]"));
        assert!(!out.contains('\r'));
    }

    #[test]
    fn reuse_directory_keeps_accepted_licences_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = package(dir.path(), "slintish", Some("GPL-3.0-only OR MIT"));
        fs::create_dir(p.dir.join("LICENSES")).unwrap();
        fs::write(p.dir.join("LICENSES").join("GPL-3.0-only.txt"), "GPL").unwrap();
        fs::write(p.dir.join("LICENSES").join("MIT.txt"), "MIT").unwrap();
        let out = render(&[p], &accepted(), &[]).unwrap();
        assert!(
            out.contains("[text 1] MIT.txt of slintish 1.0.0\n\nMIT\n"),
            "{out}"
        );
        assert!(!out.contains("GPL\n"));
    }

    #[test]
    fn packages_without_files_get_standard_texts() {
        let dir = tempfile::tempdir().unwrap();
        let p = package(dir.path(), "bare", Some("Zlib OR Apache-2.0 OR MIT"));
        let standard = [
            ("Apache-2.0".to_owned(), "Apache".to_owned()),
            ("MIT".to_owned(), "MIT".to_owned()),
        ];
        let out = render(std::slice::from_ref(&p), &accepted(), &standard).unwrap();
        assert!(out.contains(
            "bare 1.0.0 | Zlib OR Apache-2.0 OR MIT | https://example.test/bare | 1, 2\n"
        ));
        assert!(out.contains("[text 1] Apache-2.0, standard text"));
        assert!(out.contains("[text 2] MIT, standard text"));

        let e = render(&[p], &accepted(), &[]).unwrap_err().to_string();
        assert!(e.contains("bare 1.0.0: no licence file"), "{e}");
        let unlicensed = package(dir.path(), "none", None);
        assert!(render(&[unlicensed], &accepted(), &[]).is_err());
    }

    /// A crate's own file titles a text it shares with a standard text, whichever crate
    /// comes first in the list.
    #[test]
    fn own_files_come_before_standard_texts() {
        let dir = tempfile::tempdir().unwrap();
        let bare = package(dir.path(), "a-bare", Some("Apache-2.0"));
        let shipped = package(dir.path(), "b-shipped", Some("Apache-2.0"));
        fs::write(shipped.dir.join("LICENSE-APACHE"), "Apache\n").unwrap();
        let standard = [("Apache-2.0".to_owned(), "Apache".to_owned())];
        let out = render(&[bare, shipped], &accepted(), &standard).unwrap();
        assert!(out.contains("a-bare 1.0.0 | Apache-2.0 | https://example.test/a-bare | 1\n"));
        assert!(
            out.contains("[text 1] LICENSE-APACHE of b-shipped 1.0.0\n"),
            "{out}"
        );
        assert!(!out.contains("[text 2]"));
    }

    /// The MIT and zlib templates name the crate's authors, or its repository.
    #[test]
    fn template_copyright_lines_name_the_holders() {
        let dir = tempfile::tempdir().unwrap();
        let mut authored = package(dir.path(), "authored", Some("MIT"));
        authored.authors = vec!["Ann <ann@example.test>".to_owned(), "Bob".to_owned()];
        let anonymous = package(dir.path(), "anonymous", Some("MIT"));
        let reuse = package(dir.path(), "reuse", Some("MIT"));
        fs::create_dir(reuse.dir.join("LICENSES")).unwrap();
        let template = format!("MIT License\n\n{TEMPLATE_COPYRIGHT}\n\nPermission");
        fs::write(reuse.dir.join("LICENSES").join("MIT.txt"), &template).unwrap();
        let standard = [("MIT".to_owned(), template)];
        let out = render(&[anonymous, authored, reuse], &accepted(), &standard).unwrap();
        assert!(!out.contains("<year>"), "{out}");
        assert!(out.contains("\nCopyright (c) Ann <ann@example.test>, Bob\n"));
        assert!(out.contains(
            "\nCopyright (c) the anonymous authors (see https://example.test/anonymous)\n"
        ));
        assert!(
            out.contains("\nCopyright (c) the reuse authors (see https://example.test/reuse)\n")
        );
        assert!(out.contains("MIT, standard text for authored 1.0.0 (it ships no licence file)"));
    }

    #[test]
    fn missing_packages_are_told_from_other_failures() {
        assert!(needs_download(
            "error: failed to download `objc2 v0.6.5`\n\nCaused by:\n  attempting to make an \
             HTTP request, but --offline was specified"
        ));
        assert!(needs_download(
            "error: no matching package named `serde_json` found\nnote: offline mode (via \
             `--offline`) can sometimes cause surprising resolution failures"
        ));
        assert!(!needs_download(
            "error: the lock file needs to be updated but --locked was passed"
        ));
    }
}
