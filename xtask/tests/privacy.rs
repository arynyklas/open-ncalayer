//! `cargo xtask privacy` on throwaway git repositories, and on this one.
//!
//! What the check rejects is built at run time (`key("…")`, `drive(…)`, a changed CA
//! certificate): written out literally, it would be a finding in this file.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use xtask::privacy::{self, Denylist, Finding, Options, Place, Rule, TestCas};

fn workspace() -> PathBuf {
    oncl_testkit::workspace_root()
}

fn cas() -> TestCas {
    TestCas::load(&workspace().join(privacy::TEST_CA_DIR)).unwrap()
}

/// A git repository in a temporary directory.
struct Repo {
    dir: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let repo = Repo {
            dir: tempfile::tempdir().unwrap(),
        };
        repo.git(&["init", "-q"]);
        repo
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        let file = self.root().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }

    fn remove(&self, path: &str) {
        fs::remove_file(self.root().join(path)).unwrap();
    }

    /// Commits everything; returns the commit id.
    fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["rev-parse", "HEAD"]).trim().to_owned()
    }

    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.root())
            .args([
                "-c",
                "core.autocrlf=false",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn check(&self, options: &Options) -> Vec<Finding> {
        privacy::check(self.root(), &cas(), options).unwrap()
    }
}

/// `(place, line, rule)` of each finding, the place as printed.
fn summary(findings: &[Finding]) -> Vec<(String, Option<usize>, Rule)> {
    findings
        .iter()
        .map(|f| (f.place.to_string(), f.line, f.rule))
        .collect()
}

fn file(path: &str, line: Option<usize>, rule: Rule) -> (String, Option<usize>, Rule) {
    (path.to_owned(), line, rule)
}

/// A JSON key or string value: `"name"`.
fn key(name: &str) -> String {
    format!("\"{name}\"")
}

/// `<letter>:` followed by `rest`.
fn drive(letter: char, rest: &str) -> String {
    format!("{letter}:{rest}")
}

/// The header line of a recording of the lab's recorder.
fn transcript_header() -> String {
    format!(
        "{{{}: {}, {}: {}, {}: {{{}: {}, {}: {}}}}}",
        key("schema"),
        1,
        key("recorded_at"),
        key("2026-10-31T00:00:00Z"),
        key("tool"),
        key("name"),
        key(&["oncl", "probe"].join("-")),
        key("version"),
        key("0.2.0"),
    )
}

/// An entry of a recording: a frame from the server.
fn transcript_entry() -> String {
    format!(
        "{{{}: 5, {}: {}, {}: {}}}",
        key("t_ms"),
        key("dir"),
        key("s2c"),
        key("kind"),
        key("text"),
    )
}

/// A test CA certificate with its last signature byte changed: what a certificate issued
/// by that CA looks like to the check (the issuer name, outside a known CA certificate).
fn issued_by_test_ca() -> Vec<u8> {
    let mut der = fs::read(workspace().join("fixtures/nca/test/ncagosttest2018.der")).unwrap();
    *der.last_mut().unwrap() ^= 0xff;
    der
}

fn pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

#[test]
fn privacy_rejects_transcript_file() {
    let repo = Repo::new();
    repo.write(
        "recordings/win11/heartbeat.jsonl.zst",
        [0x28, 0xb5, 0x2f, 0xfd],
    );
    repo.write("notes/frames.jsonl", "{}\n");
    repo.write("target/cache/frames.jsonl", "{}\n");
    repo.write("README.md", "nothing here\n");
    repo.commit("init");

    assert_eq!(
        summary(&repo.check(&Options::default())),
        [
            file("notes/frames.jsonl", None, Rule::TranscriptFile),
            file(
                "recordings/win11/heartbeat.jsonl.zst",
                None,
                Rule::TranscriptFile
            ),
        ]
    );
}

#[test]
fn privacy_rejects_transcript_text() {
    let repo = Repo::new();
    repo.write(
        "docs/observed.md",
        format!("# Observed\n\n{}\n", transcript_header()),
    );
    // A recording pasted into a string literal: escaped quotes.
    let escaped = format!("{}\n{}", transcript_header(), transcript_entry()).replace('"', "\\\"");
    repo.write(
        "src/lib.rs",
        format!("// expected\nconst FRAMES: &str = \"{escaped}\";\n"),
    );
    // The key alone is not a header.
    repo.write(
        "src/other.rs",
        format!("let at = json[{}];\n", key("recorded_at")),
    );
    repo.write("data/entries.json", format!("[{}]\n", transcript_entry()));
    repo.commit("init");

    assert_eq!(
        summary(&repo.check(&Options::default())),
        [
            file("docs/observed.md", Some(3), Rule::TranscriptText),
            file("src/lib.rs", Some(2), Rule::TranscriptText),
        ]
    );
}

#[test]
fn privacy_rejects_machine_path() {
    let repo = Repo::new();
    repo.write(
        "docs/setup.md",
        format!(
            "Build:\n\nrun it from {} first\n",
            drive('Q', r"\builds\project")
        ),
    );
    repo.write(
        "src/main.rs",
        format!(
            "fn main() {{\n    let p = \"{}\";\n}}\n",
            drive('D', "/data/file")
        ),
    );
    // Not paths: a word before the colon, a URL, a drive without a separator.
    repo.write(
        "src/fine.rs",
        format!(
            "// {} https://example.invalid/ {} {}\n",
            drive('M', r"\x").replace("M:", "HKLM:"),
            drive('C', ""),
            drive('a', "/lowercase"),
        ),
    );
    // An excepted file: its listed literal passes, another path does not.
    repo.write(
        "crates/oncl-pki/tests/keystore.rs",
        format!(
            "let a = \"{}\";\nlet b = \"{}\";\n",
            drive('C', r"\\keys"),
            drive('C', r"\\Users\\someone"),
        ),
    );
    let base = repo.commit("init");
    repo.commit(&format!("fix: the path {}", drive('Q', "/build")));

    assert_eq!(
        summary(&repo.check(&Options::default())),
        [
            file(
                "crates/oncl-pki/tests/keystore.rs",
                Some(2),
                Rule::MachinePath
            ),
            file("docs/setup.md", Some(3), Rule::MachinePath),
            file("src/main.rs", Some(2), Rule::MachinePath),
        ]
    );
    let range = format!("{base}..HEAD");
    let findings = repo.check(&Options {
        range: Some(&range),
        denylist: None,
    });
    let commits: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.place, Place::Commit(_)))
        .map(|f| (f.line, f.rule))
        .collect();
    assert_eq!(commits, [(Some(1), Rule::MachinePath)]);
}

#[test]
fn privacy_rejects_test_nca_certificate() {
    let repo = Repo::new();
    let der = issued_by_test_ca();
    repo.write("keys/leaf.der", &der);
    repo.write("keys/leaf.pem", format!("# a leaf\n{}", pem(&der)));
    repo.write(
        "src/answer.json",
        format!(
            "{{\n  {}: {}\n}}\n",
            key("cert"),
            key(&STANDARD.encode(&der))
        ),
    );
    repo.commit("init");

    // A changed CA certificate carries two test CA names: its issuer's and its own.
    let findings = summary(&repo.check(&Options::default()));
    let mut places: Vec<_> = findings.iter().map(|(p, _, r)| (p.as_str(), *r)).collect();
    places.dedup();
    assert_eq!(
        places,
        [
            ("keys/leaf.der", Rule::TestNcaCertificate),
            ("keys/leaf.pem", Rule::TestNcaCertificate),
            ("src/answer.json", Rule::TestNcaCertificate),
        ],
        "{findings:?}"
    );
    let lines = |path: &str| -> Vec<Option<usize>> {
        findings
            .iter()
            .filter(|(p, _, _)| p == path)
            .map(|(_, line, _)| *line)
            .collect()
    };
    assert_eq!(
        lines("src/answer.json"),
        [Some(2)],
        "the line of the base64"
    );
    assert!(
        lines("keys/leaf.pem").iter().all(|l| l.unwrap() >= 3),
        "lines of the PEM body: {findings:?}"
    );
}

#[test]
fn privacy_accepts_synthetic_and_public_fixtures() {
    let repo = Repo::new();
    let fixtures = workspace().join("fixtures");
    let mut certificates = 0;
    for dir in [
        "synthetic",
        "nca/prod",
        "nca/test",
        "openssl",
        "ocsp",
        "jks",
    ] {
        for entry in fs::read_dir(fixtures.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap();
            let bytes = fs::read(&path).unwrap();
            let target = format!("fixtures/{dir}/{name}");
            if name.ends_with(".der") || name.ends_with(".cer") {
                // The certificates in text too, as PEM and inside JSON.
                repo.write(&format!("{target}.pem"), pem(&bytes));
                repo.write(
                    &format!("{target}.json"),
                    format!("{{{}: {}}}\n", key("cert"), key(&STANDARD.encode(&bytes))),
                );
                certificates += 1;
            }
            repo.write(&target, bytes);
        }
    }
    assert!(certificates >= 16, "{certificates}");
    repo.commit("fixtures");

    assert_eq!(summary(&repo.check(&Options::default())), []);
}

#[test]
fn privacy_denylist_hits_files_and_commit_messages() {
    let denylist =
        Denylist::parse("# private names\n\nsecrethost.example\nre:\\bnode-\\d{4}\\b\n").unwrap();
    let repo = Repo::new();
    repo.write("README.md", "nothing here\n");
    let base = repo.commit("init");
    repo.write(
        "docs/lab.md",
        "# Lab\n\nconnect to SecretHost.Example first\n",
    );
    repo.write("notes/node-4242.txt", "plain\n");
    repo.write("old.txt", "one\nsecrethost.example\n");
    repo.commit("docs: lab notes");
    repo.remove("old.txt");
    repo.commit("chore: drop the notes\n\nwere about node-1234");

    let options = Options {
        range: None,
        denylist: Some(&denylist),
    };
    assert_eq!(
        summary(&repo.check(&options)),
        [
            file("docs/lab.md", Some(3), Rule::Denylist),
            file("notes/node-4242.txt", None, Rule::Denylist),
        ]
    );

    let range = format!("{base}..HEAD");
    let findings = repo.check(&Options {
        range: Some(&range),
        denylist: Some(&denylist),
    });
    let mut kinds: Vec<_> = findings
        .iter()
        .map(|f| match &f.place {
            Place::File(path) => format!("file {path}:{:?}", f.line),
            Place::Blob { path, .. } => format!("blob {path}:{:?}", f.line),
            Place::Commit(_) => format!("commit:{:?}", f.line),
        })
        .collect();
    kinds.sort();
    assert_eq!(
        kinds,
        [
            "blob old.txt:Some(2)",
            "commit:Some(3)",
            "file docs/lab.md:Some(3)",
            "file notes/node-4242.txt:None",
        ]
    );
}

#[test]
fn privacy_denylist_output_hides_the_pattern() {
    // In the findings: the place and the line only.
    let denylist = Denylist::parse("Hidden-Name\nre:nodeq-\\d+\n").unwrap();
    let repo = Repo::new();
    repo.write("a.md", "a hidden-name here\nand nodeq-17 there\n");
    let base = repo.commit("init");
    repo.commit("feat: about hidden-name");
    let range = format!("{base}..HEAD");
    let printed: Vec<String> = repo
        .check(&Options {
            range: Some(&range),
            denylist: Some(&denylist),
        })
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(printed.len(), 3, "{printed:?}");
    for line in &printed {
        let lower = line.to_lowercase();
        assert!(
            !lower.contains("hidden") && !lower.contains("nodeq"),
            "{line}"
        );
    }

    // A broken entry: the line of the list, not its text.
    let err = Denylist::parse("fine\nre:(unclosed-secretword\n")
        .err()
        .unwrap();
    let message = format!("{err:#}");
    assert!(message.contains("line 2"), "{message}");
    assert!(!message.contains("secretword"), "{message}");

    // The command, on this repository: an entry that matches a known line of Cargo.toml.
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("denylist.txt");
    fs::write(&list, "re:^\\[workspace\\.package\\]$\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("privacy")
        .arg("--denylist")
        .arg(&list)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stdout}{stderr}");
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("Cargo.toml:") && l.ends_with(": denylist entry")),
        "{stdout}"
    );
    for text in [&stdout, &stderr] {
        assert!(!text.contains("workspace.package"), "{text}");
        assert!(!text.contains("workspace\\.package"), "{text}");
    }

    let broken = dir.path().join("broken.txt");
    fs::write(&broken, "re:(unclosed-secretword\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("privacy")
        .arg("--denylist")
        .arg(&broken)
        .output()
        .unwrap();
    assert!(!out.status.success());
    for text in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(text);
        assert!(!text.contains("secretword"), "{text}");
    }
}

#[test]
fn privacy_passes_on_this_repository() {
    let findings = privacy::check(&workspace(), &cas(), &Options::default()).unwrap();
    let printed: Vec<String> = findings.iter().map(ToString::to_string).collect();
    assert!(printed.is_empty(), "{}", printed.join("\n"));
}
