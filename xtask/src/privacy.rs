//! `cargo xtask privacy`: what must never reach the public repository (roadmap D17).
//!
//! Structure checks, always:
//! - no transcript files (`*.jsonl`, `*.jsonl.zst` outside `target/`, except
//!   [`TRANSCRIPT_FILE_EXCEPTIONS`]);
//! - no text with a transcript header;
//! - no paths with a drive letter, except the test literals listed per file in
//!   [`MACHINE_PATH_EXCEPTIONS`];
//! - no certificate (DER, or base64 in text) issued by an NCA test CA: the subject names of
//!   the certificates in [`TEST_CA_DIR`]. Those CA certificates themselves may appear, and
//!   the files of [`TEST_CA_EXCEPTIONS`] as they are.
//!
//! With a denylist (a private file), every line that matches one of its entries. A finding
//! names the place and the line, never the entry or the text that matched.
//!
//! What is checked: the tracked files of the work tree (`git ls-files`) and, with a range
//! `<base>..<head>`, also what each commit of it adds (against its first parent): the lines
//! a text file gains (line numbers are those of the file version the commit makes), a binary
//! file when it is new or changed, and the commit's message. A line that was already there,
//! moved or not, is not checked again.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use der::{Decode, Encode};
use regex::{Regex, RegexSet};
use sha1::{Digest, Sha1};
use x509_cert::Certificate;

/// The NCA test CA certificates, from the workspace root: every certificate issued by one of
/// these subjects is rejected.
pub const TEST_CA_DIR: &str = "fixtures/nca/test";

/// Paths with a drive letter that tests use as literals, per file: `(file, drive, what may
/// follow "<drive>:")`, as written in the file (a doubled backslash stays doubled). Anything
/// else after a drive letter in these files, and any drive letter elsewhere, is a finding.
pub const MACHINE_PATH_EXCEPTIONS: &[(&str, char, &[&str])] = &[
    ("docs/user/compatibility.md", 'C', &[r"\…"]),
    (
        "crates/oncl-basics/src/page_file.rs",
        'C',
        &[r"\…", r"\k.p12", r"\x"],
    ),
    ("crates/oncl-basics/tests/sign.rs", 'C', &["/keys/"]),
    (
        "crates/oncl-builtin-tests/tests/basics_sign.rs",
        'C',
        &["/keys/"],
    ),
    (
        "crates/oncl-builtin-tests/tests/commonutils.rs",
        'C',
        &["/x"],
    ),
    (
        "crates/oncl-builtin-tests/tests/differential.rs",
        'C',
        &["/keys/"],
    ),
    (
        "crates/oncl-builtins-build/src/lib.rs",
        'C',
        &[r"\\Users\\u\\.cargo", "/Users/u/.cargo"],
    ),
    ("crates/oncl-commonutils/tests/commonutils.rs", 'C', &["/x"]),
    (
        "crates/oncl-desktop/src/autostart.rs",
        'C',
        &[
            r"\oncl\",
            r"\Open & Co <1>\",
            r"\\a\nb",
            r"\Program Files\OpenNCALayer\",
            r"\OpenNCALayer\",
        ],
    ),
    (
        "crates/oncl-desktop/src/lnk.rs",
        'C',
        &[r"\Program Files\NCALayer\", r"\Users\Әлия\", r"\NCALayer\"],
    ),
    (
        "crates/oncl-desktop/src/original.rs",
        'C',
        &[
            r"\Program Files\NCALayer\",
            r"\Open\",
            r"\Other\",
            r"\NCALayer\",
        ],
    ),
    (
        "crates/oncl-desktop/src/port_owner.rs",
        'C',
        &[r"\Program Files\NCALayer\", r"\OpenNCALayer\"],
    ),
    (
        "crates/oncl-flows/src/page_file.rs",
        'C',
        &[r"\…", r"\k.p12", r"\x"],
    ),
    (
        "crates/oncl-ipc/src/endpoint.rs",
        'C',
        &[r"\`", r"\Data", r"\\Data", "/Data/"],
    ),
    (
        "crates/oncl-ipc/src/windows.rs",
        'C',
        &[r"\Data\OpenNCALayer", r"\\Data\\OpenNCALayer"],
    ),
    ("crates/oncl-pki/tests/csr.rs", 'C', &[r"\\Users\\Тест\\"]),
    ("crates/oncl-pki/tests/keystore.rs", 'C', &[r"\\keys"]),
    (
        "crates/oncl-plugin/tests/package.rs",
        'C',
        &["/plugin.wasm"],
    ),
    (
        "crates/oncl-plugin/tests/runtime.rs",
        'C',
        &[r"\\k.p12", r"\\keys"],
    ),
    (
        "crates/oncl-port-tests/tests/clones.rs",
        'C',
        &[r#"\\""#, r"\\no\\such.cms", "/a.cms", r"\\a\\b.pdf"],
    ),
    (
        "crates/oncl-port-tests/tests/heavy.rs",
        'C',
        &["/data.txt", "/answer.json"],
    ),
    (
        "crates/oncl-port-tests/tests/invoker.rs",
        'Z',
        &[r"\\no\\such.p12"],
    ),
    (
        "crates/oncl-port-tests/tests/medium.rs",
        'C',
        &[r"\\ignored.p12"],
    ),
    (
        "crates/oncl-tls/src/mkcert.rs",
        'C',
        &[r"\Users\a\AppData\Local"],
    ),
    (
        "crates/oncl-tls/tests/tls.rs",
        'C',
        &[r"\Users\tester\AppData\Roaming\OpenNCALayer\"],
    ),
    (
        "crates/oncl-ui/src/settings_view.rs",
        'C',
        &[r"\\keys\\a.p12", r"\Program Files\NCALayer\"],
    ),
    (
        "crates/oncl-ui/src/stop_original.rs",
        'C',
        &[r"\Program Files\NCALayer\"],
    ),
    (
        "crates/openncalayer/src/lifecycle/tests.rs",
        'C',
        &["/keys/a.p12"],
    ),
    ("crates/openncalayer/src/nm.rs", 'C', &[r"\elsewhere.json"]),
    (
        "crates/openncalayer/src/notices.rs",
        'C',
        &[r"\Program Files\NCALayer\"],
    ),
    (
        "crates/openncalayer/src/wss.rs",
        'C',
        &[r"\Program Files\NCALayer\"],
    ),
    ("vendor/velopack/src/misc.rs", 'C', &[r"\\Windows\\"]),
    (
        "vendor/velopack/src/process_win.rs",
        'C',
        &[r"\\Program Files\\app.exe"],
    ),
    (
        "xtask/src/upstream/tools.rs",
        'C',
        &[r"\Program Files\7-Zip\"],
    ),
];

/// git's own test for binary content: a NUL among the first bytes.
const BINARY_PROBE: usize = 8000;

/// Shortest base64 run that is decoded to look for certificates (a CA name alone is longer).
const MIN_BASE64_RUN: usize = 64;

/// Tracked files named like transcripts that are not ones; their text is still checked.
pub const TRANSCRIPT_FILE_EXCEPTIONS: &[&str] = &[
    // The list of releases in the format of the `gh api` step of `pages.yml`.
    "fixtures/registry/releases.jsonl",
];

/// Files that may carry an NCA test CA name outside a CA certificate: `(file, SHA-256 of the
/// content)`, so a changed file is checked again.
pub const TEST_CA_EXCEPTIONS: &[(&str, &str)] = &[
    // A public answer of the NCA test OCSP responder: its responder certificate is issued
    // by a test CA (fixtures/README.md).
    (
        "fixtures/nca-ocsp/individual_valid_2015.resp.der",
        "55cb91a64587aa8da182e0b0f2aadf2e349ca949e31d0afc1f51a43625ada26a",
    ),
];

/// What a finding breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// `*.jsonl` or `*.jsonl.zst` outside `target/`.
    TranscriptFile,
    /// A transcript header in the text.
    TranscriptText,
    /// A path with a drive letter that no exception allows.
    MachinePath,
    /// A certificate (or another structure) with the name of an NCA test CA.
    TestNcaCertificate,
    /// A line that matches a denylist entry.
    Denylist,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Rule::TranscriptFile => "transcript file (*.jsonl, *.jsonl.zst outside target/)",
            Rule::TranscriptText => "transcript header",
            Rule::MachinePath => "path with a drive letter",
            Rule::TestNcaCertificate => "certificate issued by an NCA test CA",
            Rule::Denylist => "denylist entry",
        })
    }
}

/// Where a finding is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {
    /// A tracked file of the work tree.
    File(String),
    /// A file version that a commit of the range adds, other than the work tree's.
    Blob {
        /// Its path in the commit that added it.
        path: String,
        /// The blob id.
        id: String,
    },
    /// The message of a commit of the range.
    Commit(String),
}

/// Length of the object ids in findings.
const SHORT_ID: usize = 12;

fn short(id: &str) -> &str {
    &id[..id.len().min(SHORT_ID)]
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Place::File(path) => f.write_str(path),
            Place::Blob { path, id } => write!(f, "{path}@{}", short(id)),
            Place::Commit(id) => write!(f, "commit {}", short(id)),
        }
    }
}

/// One finding: `place:line: rule`; the line is 1-based, absent for a path or binary content.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub place: Place,
    pub line: Option<usize>,
    pub rule: Rule,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}: {}", self.place, self.rule),
            None => write!(f, "{}: {}", self.place, self.rule),
        }
    }
}

/// A private list of what must not be published: one entry per line, a case-insensitive
/// substring or `re:<regex>`; surrounding whitespace is dropped, empty lines and lines
/// starting with `#` are skipped. Errors name the line of the list, never its text.
pub struct Denylist {
    set: RegexSet,
}

impl Denylist {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut patterns = Vec::new();
        for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
            let entry = line.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            let pattern = match entry.strip_prefix("re:") {
                Some(re) => re.to_owned(),
                None => format!("(?i){}", regex::escape(entry)),
            };
            // The parser's error quotes the pattern: never print it.
            if Regex::new(&pattern).is_err() {
                bail!(
                    "denylist line {}: not a valid regular expression",
                    index + 1
                );
            }
            patterns.push(pattern);
        }
        ensure!(!patterns.is_empty(), "the denylist has no entries");
        let set = RegexSet::new(&patterns).map_err(|_| anyhow!("the denylist is too large"))?;
        Ok(Denylist { set })
    }

    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let text =
            String::from_utf8(bytes).map_err(|_| anyhow!("{} is not UTF-8", path.display()))?;
        Self::parse(&text)
    }

    fn matches(&self, text: &str) -> bool {
        self.set.is_match(text)
    }
}

/// The subject names of the NCA test CAs, and the CA certificates themselves (which carry
/// those names and may appear).
pub struct TestCas {
    certs: Vec<Vec<u8>>,
    names: Vec<KnownName>,
}

struct KnownName {
    finder: regex::bytes::Regex,
    /// Where the name sits inside the CA certificates: `(certificate, offset)`.
    inside: Vec<(usize, usize)>,
}

impl TestCas {
    /// Every certificate file in `dir`.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let mut files: Vec<_> = fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()?;
        files.sort();
        let mut certs = Vec::new();
        let mut subjects: Vec<Vec<u8>> = Vec::new();
        for file in files.iter().filter(|f| f.is_file()) {
            let der = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            let cert = Certificate::from_der(&der)
                .with_context(|| format!("{} is not a DER certificate", file.display()))?;
            let subject = cert.tbs_certificate().subject().to_der()?;
            ensure!(
                find_all(&der, &subject).next().is_some(),
                "the subject of {} does not re-encode byte for byte",
                file.display()
            );
            if !subjects.contains(&subject) {
                subjects.push(subject);
            }
            certs.push(der);
        }
        ensure!(!certs.is_empty(), "no certificates in {}", dir.display());
        let names = subjects
            .iter()
            .map(|subject| {
                let mut pattern = String::from("(?-u)");
                for byte in subject {
                    pattern.push_str(&format!(r"\x{byte:02X}"));
                }
                let inside = certs
                    .iter()
                    .enumerate()
                    .flat_map(|(i, cert)| find_all(cert, subject).map(move |at| (i, at)))
                    .collect();
                Ok(KnownName {
                    finder: regex::bytes::Regex::new(&pattern)?,
                    inside,
                })
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(TestCas { certs, names })
    }

    /// Offsets in `bytes` of a test CA name outside a copy of a CA certificate.
    fn hits(&self, bytes: &[u8]) -> Vec<usize> {
        let mut hits = Vec::new();
        for name in &self.names {
            for found in name.finder.find_iter(bytes) {
                let at = found.start();
                let in_ca_cert = name.inside.iter().any(|&(cert, offset)| {
                    at >= offset && bytes[at - offset..].starts_with(&self.certs[cert])
                });
                if !in_ca_cert {
                    hits.push(at);
                }
            }
        }
        hits
    }
}

/// Offsets of `needle` in `haystack`.
fn find_all<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(move |(_, window)| *window == needle)
        .map(|(at, _)| at)
}

/// What [`check`] looks at besides the structure.
#[derive(Default)]
pub struct Options<'a> {
    /// `<base>..<head>`: also what these commits add (the lines a text file gains, new or
    /// changed binary files) and their messages.
    pub range: Option<&'a str>,
    /// The private list.
    pub denylist: Option<&'a Denylist>,
}

/// Every finding in the git work tree `root`, sorted, without repeats.
pub fn check(root: &Path, cas: &TestCas, options: &Options) -> anyhow::Result<Vec<Finding>> {
    let scanner = Scanner::new(cas, options.denylist);
    let mut findings = Vec::new();
    let mut work_tree_blobs = HashMap::new();
    for path in nul_separated(&git(root, &["ls-files", "-z"])?) {
        let place = Place::File(path.clone());
        scanner.check_path(&place, &path, &mut findings);
        let file = root.join(&path);
        let Ok(meta) = fs::symlink_metadata(&file) else {
            continue; // deleted in the work tree, not yet in the index
        };
        if !meta.is_file() {
            continue; // a symbolic link or a submodule
        }
        let bytes = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
        scanner.check_content(&place, Some(&path), &bytes, &mut findings);
        work_tree_blobs.insert(path, blob_id(&bytes));
    }
    if let Some(range) = options.range {
        let (base, head) = range
            .split_once("..")
            .filter(|(base, head)| !base.is_empty() && !head.is_empty() && !head.starts_with('.'))
            .ok_or_else(|| anyhow!("--range wants <base>..<head>, not {range:?}"))?;
        let range = format!("{base}..{head}");
        let empty_tree = empty_tree(root)?;
        let commits = git(root, &["rev-list", "--parents", &range, "--"])?;
        for entry in commits.lines() {
            let mut ids = entry.split_whitespace();
            let Some(commit) = ids.next() else { continue };
            // Against the first parent; a root commit adds everything.
            let parent = ids.next().unwrap_or(&empty_tree);
            for add in commit_adds(root, parent, commit)? {
                if work_tree_blobs.get(&add.path) == Some(&add.id) {
                    continue; // the work tree's version: checked above
                }
                let place = Place::Blob {
                    path: add.path.clone(),
                    id: add.id.clone(),
                };
                if add.new_path {
                    scanner.check_path(&place, &add.path, &mut findings);
                }
                match &add.hunks {
                    Some(hunks) => scanner.check_added(&place, &add.path, hunks, &mut findings),
                    None => {
                        let bytes = git_bytes(root, &["cat-file", "blob", &add.id])?;
                        scanner.check_content(&place, Some(&add.path), &bytes, &mut findings);
                    }
                }
            }
        }
        let log = git(root, &["log", "-z", "--format=%H%n%B", &range, "--"])?;
        for entry in nul_separated(&log) {
            let (id, message) = entry.split_once('\n').unwrap_or((&entry, ""));
            let place = Place::Commit(id.to_owned());
            // Line 1 is the subject.
            scanner.check_content(&place, None, message.as_bytes(), &mut findings);
        }
    }
    findings.sort();
    findings.dedup();
    Ok(findings)
}

/// The id git gives `bytes` as a blob.
fn blob_id(bytes: &[u8]) -> String {
    let mut hash = Sha1::new();
    hash.update(format!("blob {}\0", bytes.len()));
    hash.update(bytes);
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn git(root: &Path, args: &[&str]) -> anyhow::Result<String> {
    String::from_utf8(git_bytes(root, args)?)
        .map_err(|_| anyhow!("git {}: not UTF-8", args.join(" ")))
}

fn git_bytes(root: &Path, args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    ensure!(
        out.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(out.stdout)
}

fn nul_separated(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.strip_prefix('\n').unwrap_or(s).to_owned())
}

/// The id of the empty tree in the repository's hash format.
fn empty_tree(root: &Path) -> anyhow::Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["hash-object", "-t", "tree", "--stdin"])
        .stdin(Stdio::null())
        .output()
        .context("running git hash-object")?;
    ensure!(out.status.success(), "git hash-object failed");
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Consecutive lines a commit adds to a text file.
#[derive(Clone)]
struct Hunk {
    /// The 1-based number of the first line in the file version the commit makes.
    first: usize,
    lines: Vec<Vec<u8>>,
}

/// What a commit adds to one file: the version it makes and, of a text file, its added
/// lines.
struct FileAdd {
    path: String,
    /// The blob id of the version.
    id: String,
    /// The path did not exist in the parent.
    new_path: bool,
    /// The added lines of a text file; `None`: binary, checked whole.
    hunks: Option<Vec<Hunk>>,
}

fn is_zero_id(id: &str) -> bool {
    id.bytes().all(|b| b == b'0')
}

/// The files that `commit` adds or changes against `parent` (a commit or tree): the new
/// blobs and, for text, the lines of the `-U0` patch that start with `+`. Deleted files,
/// mode-only changes and submodules add no content.
fn commit_adds(root: &Path, parent: &str, commit: &str) -> anyhow::Result<Vec<FileAdd>> {
    let diff = |extra: &[&str]| {
        let mut args = vec![
            "-c",
            "core.quotePath=false",
            "diff",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--full-index",
            "--no-abbrev",
        ];
        args.extend_from_slice(extra);
        args.extend([parent, commit, "--"]);
        git_bytes(root, &args)
    };
    // `:<mode> <mode> <id> <id> <status>`, then the path.
    let raw = diff(&["--raw", "-z"])?;
    let mut tokens = raw.split(|&b| b == 0).filter(|t| !t.is_empty());
    let mut files: Vec<(String, String, bool)> = Vec::new();
    while let Some(meta) = tokens.next() {
        let path = tokens
            .next()
            .ok_or_else(|| anyhow!("git diff --raw: a path is missing"))?;
        let meta = String::from_utf8_lossy(meta);
        let fields: Vec<&str> = meta.trim_start_matches(':').split_whitespace().collect();
        let [_, mode, old, new, status] = fields[..] else {
            bail!("git diff --raw: unexpected entry {meta:?}");
        };
        if mode == "160000" || status.starts_with('D') || is_zero_id(new) || old == new {
            continue;
        }
        files.push((
            String::from_utf8_lossy(path).into_owned(),
            new.to_owned(),
            status.starts_with('A'),
        ));
    }
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let sections = patch_sections(&diff(&["-U0"])?);
    Ok(files
        .into_iter()
        .map(|(path, id, new_path)| {
            let section = sections.get(&id);
            // A listed exception is matched on the whole content.
            let whole = TEST_CA_EXCEPTIONS.iter().any(|(file, _)| *file == path);
            let hunks = match section {
                Some((true, _)) => None,
                _ if whole => None,
                Some((false, hunks)) => Some(hunks.clone()),
                None => Some(Vec::new()),
            };
            FileAdd {
                path,
                id,
                new_path,
                hunks,
            }
        })
        .collect())
}

/// One file's part of a patch.
#[derive(Default)]
struct Section {
    binary: bool,
    /// The added lines with their numbers in the new version.
    added: Vec<(usize, Vec<u8>)>,
    /// The removed lines, counted: a line that is only moved is removed and added.
    removed: HashMap<Vec<u8>, usize>,
}

impl Section {
    /// The added lines that are not one of the removed (each removed line cancels one added
    /// line of the same text), as runs of consecutive lines.
    fn into_hunks(mut self) -> Vec<Hunk> {
        let mut hunks: Vec<Hunk> = Vec::new();
        for (number, line) in self.added {
            if let Some(count) = self.removed.get_mut(&line)
                && *count > 0
            {
                *count -= 1;
                continue;
            }
            match hunks.last_mut() {
                Some(hunk) if hunk.first + hunk.lines.len() == number => hunk.lines.push(line),
                _ => hunks.push(Hunk {
                    first: number,
                    lines: vec![line],
                }),
            }
        }
        hunks
    }
}

/// The sections of a `git diff -U0 --full-index` patch, by the blob id they make:
/// `(binary, added lines)`.
fn patch_sections(patch: &[u8]) -> HashMap<String, (bool, Vec<Hunk>)> {
    let mut sections = HashMap::new();
    let mut current: Option<(String, Section)> = None;
    let mut in_hunk = false;
    let mut next = 0usize;
    let mut flush = |current: &mut Option<(String, Section)>| {
        if let Some((id, section)) = current.take() {
            let binary = section.binary;
            sections
                .entry(id)
                .or_insert_with(|| (binary, section.into_hunks()));
        }
    };
    for line in patch.split(|&b| b == b'\n') {
        // Lines of a hunk start with `+`, `-`, a space or `\`: the others are headers.
        if line.starts_with(b"diff --git ") {
            flush(&mut current);
            in_hunk = false;
        } else if let Some(rest) = line.strip_prefix(b"index ") {
            let ids = String::from_utf8_lossy(rest);
            let new = ids.split(' ').next().and_then(|ids| ids.split_once(".."));
            if let Some((_, new)) = new {
                current = Some((new.to_owned(), Section::default()));
            }
        } else if line.starts_with(b"Binary files ") || line.starts_with(b"GIT binary patch") {
            if let Some((_, section)) = current.as_mut() {
                section.binary = true;
            }
        } else if let Some(rest) = line.strip_prefix(b"@@ ") {
            // `-<start>[,<count>] +<start>[,<count>] @@`
            let text = String::from_utf8_lossy(rest);
            next = text
                .split(' ')
                .find_map(|part| part.strip_prefix('+'))
                .and_then(|range| range.split(',').next())
                .and_then(|start| start.parse().ok())
                .unwrap_or(0);
            in_hunk = true;
        } else if in_hunk && let Some((_, section)) = current.as_mut() {
            if let Some(added) = line.strip_prefix(b"+") {
                section.added.push((next, added.to_vec()));
                next += 1;
            } else if let Some(removed) = line.strip_prefix(b"-") {
                *section.removed.entry(removed.to_vec()).or_default() += 1;
            }
        }
    }
    flush(&mut current);
    sections
}

/// The compiled rules.
struct Scanner<'a> {
    cas: &'a TestCas,
    denylist: Option<&'a Denylist>,
    machine_path: Regex,
    recorded_at: Regex,
    probe_tool: Regex,
    server_entry: Regex,
    base64: GeneralPurpose,
}

impl<'a> Scanner<'a> {
    fn new(cas: &'a TestCas, denylist: Option<&'a Denylist>) -> Self {
        // A quote may be escaped: a transcript line inside a string literal.
        let q = r#"\\?""#;
        let regex = |pattern: &str| Regex::new(pattern).expect("a valid built-in pattern");
        Scanner {
            cas,
            denylist,
            // The drive letter is group 1; a letter, digit or `_` before it makes it a word.
            machine_path: regex(r"(?:^|[^A-Za-z0-9_])([A-Z]):[\\/]"),
            recorded_at: regex(&format!(r"{q}recorded_at{q}\s*:")),
            probe_tool: regex(&format!(
                r"{q}tool{q}\s*:\s*\{{\s*{q}name{q}\s*:\s*{q}oncl-probe{q}"
            )),
            server_entry: regex(&format!(r"{q}dir{q}\s*:\s*{q}s2c{q}")),
            base64: GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                GeneralPurposeConfig::new()
                    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
                    .with_decode_allow_trailing_bits(true),
            ),
        }
    }

    fn check_path(&self, place: &Place, path: &str, out: &mut Vec<Finding>) {
        let transcript = path.ends_with(".jsonl") || path.ends_with(".jsonl.zst");
        if transcript && !path.starts_with("target/") && !TRANSCRIPT_FILE_EXCEPTIONS.contains(&path)
        {
            out.push(finding(place, None, Rule::TranscriptFile));
        }
        if self.denylist.is_some_and(|d| d.matches(path)) {
            out.push(finding(place, None, Rule::Denylist));
        }
    }

    /// `path` picks the machine path exceptions; a commit message has none.
    fn check_content(
        &self,
        place: &Place,
        path: Option<&str>,
        bytes: &[u8],
        out: &mut Vec<Finding>,
    ) {
        let binary = bytes[..bytes.len().min(BINARY_PROBE)].contains(&0);
        let line_at = |offset: usize| (!binary).then(|| line_of(bytes, offset));
        let ca_excepted = path.is_some_and(|path| {
            TEST_CA_EXCEPTIONS
                .iter()
                .any(|&(file, sha256)| file == path && crate::upstream::sha256_hex(bytes) == sha256)
        });
        if !ca_excepted {
            for at in self.cas.hits(bytes) {
                out.push(finding(place, line_at(at), Rule::TestNcaCertificate));
            }
        }
        let text = String::from_utf8_lossy(bytes);
        if binary {
            if self.denylist.is_some_and(|d| d.matches(&text)) {
                out.push(finding(place, None, Rule::Denylist));
            }
            return;
        }
        if self.probe_tool.is_match(&text) || self.server_entry.is_match(&text) {
            for found in self.recorded_at.find_iter(&text) {
                let line = line_of(text.as_bytes(), found.start());
                out.push(finding(place, Some(line), Rule::TranscriptText));
            }
        }
        let allowed = path.and_then(|path| {
            MACHINE_PATH_EXCEPTIONS
                .iter()
                .find(|(file, _, _)| *file == path)
                .map(|&(_, drive, after)| (drive, after))
        });
        for found in self.machine_path.captures_iter(&text) {
            let drive = found.get(1).expect("group 1");
            let rest = &text[drive.end() + 1..];
            let excepted = allowed.is_some_and(|(allowed_drive, after)| {
                drive.as_str().starts_with(allowed_drive)
                    && after.iter().any(|prefix| rest.starts_with(prefix))
            });
            if !excepted {
                let line = line_of(text.as_bytes(), drive.start());
                out.push(finding(place, Some(line), Rule::MachinePath));
            }
        }
        for line in self.base64_certificate_lines(&text) {
            out.push(finding(place, Some(line), Rule::TestNcaCertificate));
        }
        if let Some(denylist) = self.denylist {
            for (index, line) in text.lines().enumerate() {
                if denylist.matches(line) {
                    out.push(finding(place, Some(index + 1), Rule::Denylist));
                }
            }
        }
    }

    /// The lines `hunks` add to the text file `path` (line numbers as in the file version).
    /// They are read as one text, the hunks apart, so that a rule that spans lines (a base64
    /// body) sees what the commit wrote and no more.
    fn check_added(&self, place: &Place, path: &str, hunks: &[Hunk], out: &mut Vec<Finding>) {
        let mut text = Vec::new();
        // The line of the file for each line of `text`; none for a separator.
        let mut numbers: Vec<Option<usize>> = Vec::new();
        for (index, hunk) in hunks.iter().enumerate() {
            if index > 0 {
                text.extend_from_slice(b"-\n");
                numbers.push(None);
            }
            for (offset, line) in hunk.lines.iter().enumerate() {
                text.extend_from_slice(line);
                text.push(b'\n');
                numbers.push(Some(hunk.first + offset));
            }
        }
        let mut found = Vec::new();
        self.check_content(place, Some(path), &text, &mut found);
        for f in found {
            match f.line {
                Some(line) => {
                    if let Some(&Some(real)) = numbers.get(line - 1) {
                        out.push(Finding {
                            line: Some(real),
                            ..f
                        });
                    }
                }
                None => out.push(f),
            }
        }
    }

    /// Lines where base64 in `text` decodes to a test CA name outside a CA certificate.
    /// Whitespace, quotes and backslash escapes are dropped first, so a base64 body split
    /// over lines or string literals reads as one run; up to three stray characters before
    /// it shift the alignment, so each run is decoded from four starting offsets.
    fn base64_certificate_lines(&self, text: &str) -> Vec<usize> {
        let mut lines = Vec::new();
        for (run, run_lines) in base64_runs(text) {
            for skip in 0..4.min(run.len()) {
                let mut chars = &run[skip..];
                if chars.len() % 4 == 1 {
                    chars = &chars[..chars.len() - 1];
                }
                let Ok(decoded) = self.base64.decode(chars) else {
                    continue;
                };
                for at in self.cas.hits(&decoded) {
                    lines.push(run_lines[skip + at / 3 * 4]);
                }
            }
        }
        lines
    }
}

fn finding(place: &Place, line: Option<usize>, rule: Rule) -> Finding {
    Finding {
        place: place.clone(),
        line,
        rule,
    }
}

/// 1-based line of `offset`.
fn line_of(bytes: &[u8], offset: usize) -> usize {
    bytes[..offset].iter().filter(|&&b| b == b'\n').count() + 1
}

/// Runs of base64 characters at least [`MIN_BASE64_RUN`] long, with the line of each
/// character, `=` padding dropped. Whitespace, `"`, `'` and `\` (with the letter of a `\n`,
/// `\r` or `\t` escape) do not end a run; any other character does.
fn base64_runs(text: &str) -> Vec<(Vec<u8>, Vec<usize>)> {
    let mut runs = Vec::new();
    let mut run = Vec::new();
    let mut run_lines = Vec::new();
    let mut line = 1;
    let mut bytes = text.bytes().peekable();
    let mut end = |run: &mut Vec<u8>, run_lines: &mut Vec<usize>| {
        if run.len() >= MIN_BASE64_RUN {
            runs.push((std::mem::take(run), std::mem::take(run_lines)));
        } else {
            run.clear();
            run_lines.clear();
        }
    };
    while let Some(byte) = bytes.next() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                run.push(byte);
                run_lines.push(line);
            }
            b'\n' => line += 1,
            b' ' | b'\t' | b'\r' | b'"' | b'\'' => {}
            b'\\' => {
                if matches!(bytes.peek(), Some(b'n' | b'r' | b't')) {
                    bytes.next();
                }
            }
            b'=' => {
                end(&mut run, &mut run_lines);
                while bytes.peek() == Some(&b'=') {
                    bytes.next();
                }
            }
            _ => end(&mut run, &mut run_lines),
        }
    }
    end(&mut run, &mut run_lines);
    runs
}
