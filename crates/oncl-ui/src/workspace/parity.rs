//! Parity of what the workspace makes and says with tools that do not share its code: the
//! `oncl` command line (the same SDK, another front end, in another process, over HTTP), OpenSSL
//! (CMS/CAdES), pyHanko (PAdES, with revocation required from the document's own DSS) and the
//! repository's XML-DSig oracle (lxml canonicalization and `cryptography` RSA). The same
//! synthetic inputs are signed through the workspace's operations, with the user's confirmation,
//! and then verified by every tool; an altered copy must be refused by every tool the original
//! was accepted by.
//!
//! These tests need things a plain `cargo test` does not have, so they are ignored by default:
//!
//! ```text
//! cargo build -p oncl-cli
//! set ONCL_PYHANKO_PYTHON=<python with pyhanko, lxml, cryptography>
//! cargo test -p oncl-ui --lib parity -- --ignored --test-threads=1
//! ```
//!
//! The command line binary is `ONCL_BIN`, or `oncl[.exe]` of the build directory named by
//! `CARGO_TARGET_DIR` (default: the workspace's `target`); OpenSSL is `ONCL_OPENSSL`, `openssl`
//! on the path, or Git for Windows'. A tool that is missing FAILS the test; nothing is skipped
//! silently.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use der::Encode;
use oncl_pki::validation::Verdict;

use super::{
    Destination, Document, ExtendFormat, Level, SignFormat, SignOptions, SignSpec, ToolSpec,
    VerifyFormat, VerifyOptions, run_tool,
};
use crate::reports::controller::{BatchView, Detail, Outcome};
use crate::signing::runner::Outcome as SignOutcome;
use crate::signing::testing::*;
use crate::workspace::JobControl;

const NOW_TEXT: &str = "1793620800";

fn oncl() -> PathBuf {
    if let Ok(explicit) = std::env::var("ONCL_BIN") {
        return PathBuf::from(explicit);
    }
    let target = std::env::var("CARGO_TARGET_DIR").map_or_else(
        |_| oncl_testkit::workspace_root().join("target"),
        PathBuf::from,
    );
    let name = if cfg!(windows) { "oncl.exe" } else { "oncl" };
    let path = target.join("debug").join(name);
    assert!(
        path.exists(),
        "the oncl binary is missing at {}: run `cargo build -p oncl-cli` or set ONCL_BIN",
        path.display()
    );
    path
}

fn openssl() -> String {
    let mut candidates = Vec::new();
    if let Ok(explicit) = std::env::var("ONCL_OPENSSL") {
        candidates.push(explicit);
    }
    candidates.push("openssl".to_owned());
    for var in ["ProgramFiles", "ProgramW6432"] {
        if let Some(base) = std::env::var_os(var) {
            candidates.push(
                Path::new(&base)
                    .join("Git/usr/bin/openssl.exe")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    candidates
        .into_iter()
        .find(|c| {
            Command::new(c)
                .arg("version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .expect("OpenSSL is required: set ONCL_OPENSSL or put openssl on the path")
}

fn python() -> String {
    let python = std::env::var("ONCL_PYHANKO_PYTHON").unwrap_or_default();
    assert!(
        !python.is_empty() && Path::new(&python).exists(),
        "ONCL_PYHANKO_PYTHON must name a python with pyhanko, lxml and cryptography (got {python:?})"
    );
    python
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// The world, its services on a socket, and the root as a file the other tools can read.
struct Lab {
    w: World,
    _services: Loopback,
    root: PathBuf,
}

fn lab() -> Lab {
    let (w, services) = served_world();
    let root = w.dir.path().join("root.cer");
    std::fs::write(&root, w.root.to_der().unwrap()).unwrap();
    Lab {
        w,
        _services: services,
        root,
    }
}

impl Lab {
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.w.dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Signs `input` through the workspace's operation, the user confirming what was frozen.
    fn sign(&self, spec: &SignSpec, input: &Path) -> BatchView {
        let (engine, guard) = engine(&self.w);
        let outcome = sign_confirmed(
            &engine,
            &guard,
            &self.w,
            std::slice::from_ref(&input.to_owned()),
            spec,
            &Destination::Beside,
        );
        let SignOutcome::Done(view) = outcome else {
            panic!("{spec:?}: {outcome:?}");
        };
        assert_eq!(guard.applications(), 1, "{spec:?}");
        view
    }

    /// What the workspace's own verify tool says of `document`.
    fn workspace_verify(&self, format: VerifyFormat, document: &Document) -> BatchView {
        let (engine, _) = engine(&self.w);
        run_tool(
            &engine,
            &ToolSpec::Verify(format, VerifyOptions::default()),
            std::slice::from_ref(document),
            &Destination::Beside,
            NOW,
            &std::sync::Arc::new(JobControl::default()),
        )
        .unwrap()
    }

    /// What `oncl verify` says: the exit code (0 valid, 2 invalid) and its JSON report.
    fn cli_verify(
        &self,
        profile: &str,
        input: &Path,
        detached: Option<&Path>,
    ) -> (Option<i32>, serde_json::Value) {
        let mut command = Command::new(oncl());
        command.args(["verify", "--profile", profile, "--input", text(input)]);
        if let Some(detached) = detached {
            command.args(["--detached", text(detached)]);
        }
        command.args([
            "--json",
            "--root",
            text(&self.root),
            "--pki-endpoint",
            &self.w.origin,
            "--as-of",
            NOW_TEXT,
        ]);
        let output = command.output().unwrap();
        let report = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
        (output.status.code(), report)
    }

    fn openssl_cms(&self, signature: &Path, content: &Path) -> bool {
        let openssl = openssl();
        let root_pem = self.w.dir.path().join("root.pem");
        let converted = Command::new(&openssl)
            .args([
                "x509",
                "-inform",
                "DER",
                "-in",
                text(&self.root),
                "-out",
                text(&root_pem),
            ])
            .output()
            .unwrap();
        assert!(converted.status.success());
        Command::new(&openssl)
            .args([
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                text(signature),
                "-content",
                text(content),
                "-CAfile",
                text(&root_pem),
                "-purpose",
                "any",
                "-no_check_time",
                "-out",
            ])
            .arg(self.w.dir.path().join("openssl.out"))
            .output()
            .unwrap()
            .status
            .success()
    }

    fn pyhanko(&self, pdf: &Path) -> (bool, serde_json::Value) {
        let script = self.w.dir.path().join("pyhanko_oracle.py");
        std::fs::write(
            &script,
            include_str!("../../../oncl-cli/tests/support/pyhanko_oracle.py"),
        )
        .unwrap();
        let out: Output = Command::new(python())
            .args([text(&script), text(pdf), text(&self.root), "1793620920"])
            .output()
            .unwrap();
        let json = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
        eprintln!("PYHANKO {}", String::from_utf8_lossy(&out.stdout).trim());
        (out.status.success(), json)
    }

    fn xml_oracle(&self, signed: &Path) -> (bool, String) {
        let script = self.w.dir.path().join("xmldsig_oracle.py");
        std::fs::write(
            &script,
            include_str!("../../../oncl-cli/tests/support/xmldsig_oracle.py"),
        )
        .unwrap();
        let leaf = self.w.dir.path().join("oracle-leaf.der");
        std::fs::write(&leaf, self.w.leaf.cert.to_der().unwrap()).unwrap();
        let out = Command::new(python())
            .args([text(&script), text(signed), text(&leaf)])
            .output()
            .unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn evidence(&self, format: SignFormat) -> SignOptions {
        let needs = matches!(
            format,
            SignFormat::Cades(Level::Lt | Level::Lta) | SignFormat::Pades(Level::Lt | Level::Lta)
        );
        SignOptions {
            evidence: if needs {
                evidence_files(&self.w)
            } else {
                super::Evidence::default()
            },
            ..SignOptions::default()
        }
    }
}

fn verdict_of(view: &BatchView) -> Verdict {
    match &view.items[0].outcome {
        Outcome::Completed(Detail::Verified(v)) => v.verdict,
        other => panic!("not a verification: {other:?}"),
    }
}

fn level_of(view: &BatchView) -> Option<oncl_pki::evidence::AdesLevel> {
    match &view.items[0].outcome {
        Outcome::Completed(Detail::Verified(v)) => v.level,
        other => panic!("not a verification: {other:?}"),
    }
}

fn cli_says(report: &serde_json::Value) -> (String, Option<String>) {
    (
        report["verdict"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase(),
        report["ades_level"].as_str().map(str::to_ascii_lowercase),
    )
}

/// CMS and CAdES B/T/LT/LTA: the workspace's signature, verified by the workspace, by `oncl
/// verify` over HTTP and by OpenSSL, all Valid at the same level; the same signature over an
/// altered document is refused by all of them.
#[test]
#[ignore = "parity: needs the oncl binary and OpenSSL (see the module docs)"]
fn cms_and_cades_signatures_agree_with_the_command_line_and_openssl() {
    let lab = lab();
    let content = lab.write("doc.bin", b"the document of the parity run");
    let altered = lab.write("altered.bin", b"the document of the parity RUN");
    let cases = [
        (SignFormat::Cms, "cms", VerifyFormat::Cms, None),
        (
            SignFormat::Cades(Level::B),
            "cades-b",
            VerifyFormat::Cades(Level::B),
            Some("b"),
        ),
        (
            SignFormat::Cades(Level::T),
            "cades-t",
            VerifyFormat::Cades(Level::T),
            Some("t"),
        ),
        (
            SignFormat::Cades(Level::Lt),
            "cades-lt",
            VerifyFormat::Cades(Level::Lt),
            Some("lt"),
        ),
        (
            SignFormat::Cades(Level::Lta),
            "cades-lta",
            VerifyFormat::Cades(Level::Lta),
            Some("lta"),
        ),
    ];
    for (format, profile, verify_format, level) in cases {
        let _ = std::fs::remove_file(lab.w.dir.path().join("doc.bin.p7s"));
        lab.sign(
            &SignSpec {
                format,
                options: lab.evidence(format),
            },
            &content,
        );
        let signature = lab.w.dir.path().join("doc.bin.p7s");
        let ours = lab.workspace_verify(
            verify_format,
            &Document {
                path: signature.clone(),
                second: Some(content.clone()),
            },
        );
        assert_eq!(verdict_of(&ours), Verdict::Valid, "{profile}: workspace");
        let (code, report) = lab.cli_verify(profile, &signature, Some(&content));
        assert_eq!(code, Some(0), "{profile}: oncl verify: {report}");
        let (verdict, cli_level) = cli_says(&report);
        assert_eq!(verdict, "valid", "{profile}");
        assert_eq!(
            cli_level.as_deref(),
            level,
            "{profile}: the level oncl verified"
        );
        assert_eq!(
            level_of(&ours)
                .map(|l| format!("{l:?}").to_ascii_lowercase())
                .as_deref(),
            level,
            "{profile}: the level the workspace verified"
        );
        assert!(
            lab.openssl_cms(&signature, &content),
            "{profile}: OpenSSL accepts"
        );
        // The altered document: refused by all.
        let tampered = lab.workspace_verify(
            verify_format,
            &Document {
                path: signature.clone(),
                second: Some(altered.clone()),
            },
        );
        assert_eq!(
            verdict_of(&tampered),
            Verdict::Invalid,
            "{profile}: workspace refuses"
        );
        let (code, report) = lab.cli_verify(profile, &signature, Some(&altered));
        assert_eq!(code, Some(2), "{profile}: oncl verify refuses: {report}");
        assert!(
            !lab.openssl_cms(&signature, &altered),
            "{profile}: OpenSSL refuses"
        );
    }
}

/// PAdES B/T/LT/LTA: the workspace's PDF, verified by the workspace and by `oncl verify`, Valid
/// at the same level; LT and LTA also by pyHanko with revocation REQUIRED from the document's
/// own DSS; a byte flipped inside the signed revision is refused by all three.
#[test]
#[ignore = "parity: needs the oncl binary and pyHanko (see the module docs)"]
fn pades_signatures_agree_with_the_command_line_and_pyhanko() {
    let lab = lab();
    let source = oncl_testkit::workspace_root()
        .join("crates/oncl-pdf/tests/fixtures/external-multipage.pdf");
    let pdf = lab.w.dir.path().join("doc.pdf");
    std::fs::copy(source, &pdf).unwrap();
    let cases = [
        (
            SignFormat::Pades(Level::B),
            "pades-b",
            VerifyFormat::Pades(Level::B),
            "b",
            false,
        ),
        (
            SignFormat::Pades(Level::T),
            "pades-t",
            VerifyFormat::Pades(Level::T),
            "t",
            false,
        ),
        (
            SignFormat::Pades(Level::Lt),
            "pades-lt",
            VerifyFormat::Pades(Level::Lt),
            "lt",
            true,
        ),
        (
            SignFormat::Pades(Level::Lta),
            "pades-lta",
            VerifyFormat::Pades(Level::Lta),
            "lta",
            true,
        ),
    ];
    for (format, profile, verify_format, level, pyhanko) in cases {
        let signed = lab.w.dir.path().join("doc.signed.pdf");
        let _ = std::fs::remove_file(&signed);
        lab.sign(
            &SignSpec {
                format,
                options: lab.evidence(format),
            },
            &pdf,
        );
        let document = Document {
            path: signed.clone(),
            second: None,
        };
        let ours = lab.workspace_verify(verify_format, &document);
        assert_eq!(verdict_of(&ours), Verdict::Valid, "{profile}: workspace");
        let (code, report) = lab.cli_verify(profile, &signed, None);
        assert_eq!(code, Some(0), "{profile}: oncl verify: {report}");
        let (verdict, cli_level) = cli_says(&report);
        assert_eq!(
            (verdict.as_str(), cli_level.as_deref()),
            ("valid", Some(level)),
            "{profile}"
        );
        let mut bytes = std::fs::read(&signed).unwrap();
        bytes[300] ^= 0x01; // inside the original, signed revision
        let tampered = lab.write("tampered.pdf", &bytes);
        let refused = lab.workspace_verify(
            verify_format,
            &Document {
                path: tampered.clone(),
                second: None,
            },
        );
        assert!(
            !matches!(
                &refused.items[0].outcome,
                Outcome::Completed(Detail::Verified(v)) if v.verdict == Verdict::Valid
            ),
            "{profile}: the workspace refuses the altered PDF: {:?}",
            refused.items[0]
        );
        let (code, _) = lab.cli_verify(profile, &tampered, None);
        assert_ne!(
            code,
            Some(0),
            "{profile}: oncl verify refuses the altered PDF"
        );
        if pyhanko {
            let (ok, json) = lab.pyhanko(&signed);
            assert!(ok, "{profile}: pyHanko accepts: {json}");
            assert!(
                json["signatures"].as_u64().unwrap_or(0) >= 1,
                "{profile}: {json}"
            );
            if level == "lta" {
                assert!(
                    json["doc_timestamps"].as_u64().unwrap_or(0) >= 1,
                    "{profile}: {json}"
                );
            }
            assert!(
                !lab.pyhanko(&tampered).0,
                "{profile}: pyHanko refuses the altered PDF"
            );
        }
    }
}

/// XML-DSig and XAdES: the workspace's signed XML verified by the workspace and by `oncl verify`;
/// the plain XML-DSig also by the independent lxml/cryptography oracle, which re-derives every
/// reference digest and the SignedInfo signature; an edited document is refused by all.
#[test]
#[ignore = "parity: needs the oncl binary and python with lxml and cryptography (see the module docs)"]
fn xml_signatures_agree_with_the_command_line_and_the_xml_oracle() {
    let lab = lab();
    let xml = lab.write("x.xml", b"<r><p Id='p'>protected</p><s Id='s'/></r>");
    let ids = SignOptions {
        target: "p".into(),
        parent: "s".into(),
        signature_id: "sig".into(),
        ..SignOptions::default()
    };
    for (format, profile, verify_format, oracle) in [
        (SignFormat::Xml, "xml", VerifyFormat::Xml, true),
        (
            SignFormat::Xades(Level::B),
            "xades-b",
            VerifyFormat::Xades(Level::B),
            false,
        ),
        (
            SignFormat::Xades(Level::T),
            "xades-t",
            VerifyFormat::Xades(Level::T),
            false,
        ),
        (
            SignFormat::Xades(Level::Lt),
            "xades-lt",
            VerifyFormat::Xades(Level::Lt),
            false,
        ),
        (
            SignFormat::Xades(Level::Lta),
            "xades-lta",
            VerifyFormat::Xades(Level::Lta),
            false,
        ),
    ] {
        let signed = lab.w.dir.path().join("x.signed.xml");
        let _ = std::fs::remove_file(&signed);
        lab.sign(
            &SignSpec {
                format,
                options: ids.clone(),
            },
            &xml,
        );
        let ours = lab.workspace_verify(
            verify_format,
            &Document {
                path: signed.clone(),
                second: None,
            },
        );
        assert_eq!(verdict_of(&ours), Verdict::Valid, "{profile}: workspace");
        let (code, report) = lab.cli_verify(profile, &signed, None);
        assert_eq!(code, Some(0), "{profile}: oncl verify: {report}");
        assert_eq!(cli_says(&report).0, "valid", "{profile}");
        let edited = std::fs::read_to_string(&signed)
            .unwrap()
            .replace("protected", "changed!!");
        let edited_path = lab.write("edited.xml", edited.as_bytes());
        let refused = lab.workspace_verify(
            verify_format,
            &Document {
                path: edited_path.clone(),
                second: None,
            },
        );
        assert_eq!(
            verdict_of(&refused),
            Verdict::Invalid,
            "{profile}: workspace refuses"
        );
        assert_eq!(
            lab.cli_verify(profile, &edited_path, None).0,
            Some(2),
            "{profile}"
        );
        if oracle {
            let (ok, proof) = lab.xml_oracle(&signed);
            assert!(
                ok,
                "{profile}: the XML oracle rejects the workspace's signature: {proof}"
            );
            assert!(
                !lab.xml_oracle(&edited_path).0,
                "{profile}: the oracle refuses the edit"
            );
        }
    }
}

/// WS-Security: the workspace's signed SOAP message verified by the workspace and `oncl verify`.
#[test]
#[ignore = "parity: needs the oncl binary (see the module docs)"]
fn wsse_signatures_agree_with_the_command_line() {
    let lab = lab();
    let soap = lab.write(
        "s.xml",
        b"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Header/><soapenv:Body><a>hi</a></soapenv:Body></soapenv:Envelope>",
    );
    lab.sign(
        &SignSpec {
            format: SignFormat::Wsse,
            options: SignOptions::default(),
        },
        &soap,
    );
    let signed = lab.w.dir.path().join("s.signed.xml");
    let ours = lab.workspace_verify(
        VerifyFormat::Wsse,
        &Document {
            path: signed.clone(),
            second: None,
        },
    );
    assert_eq!(verdict_of(&ours), Verdict::Valid);
    let (code, report) = lab.cli_verify("wsse", &signed, None);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(cli_says(&report).0, "valid");
}

/// Extension: a CAdES-B the workspace extends to T, LT and LTA is verified by `oncl verify` and
/// OpenSSL at each level.
#[test]
#[ignore = "parity: needs the oncl binary and OpenSSL (see the module docs)"]
fn extended_cades_agrees_with_the_command_line_and_openssl() {
    let lab = lab();
    let content = lab.write("doc.bin", b"extend me");
    lab.sign(
        &SignSpec {
            format: SignFormat::Cades(Level::B),
            options: SignOptions::default(),
        },
        &content,
    );
    let mut current = lab.w.dir.path().join("doc.bin.p7s");
    for (level, profile, name) in [
        (Level::T, "cades-t", "t"),
        (Level::Lt, "cades-lt", "lt"),
        (Level::Lta, "cades-lta", "lta"),
    ] {
        let evidence = if matches!(level, Level::T) {
            super::Evidence::default()
        } else {
            evidence_files(&lab.w)
        };
        let (engine, _) = engine(&lab.w);
        let report = run_tool(
            &engine,
            &ToolSpec::Extend(ExtendFormat::Cms(level), evidence),
            &[Document {
                path: current.clone(),
                second: Some(content.clone()),
            }],
            &Destination::Beside,
            NOW,
            &std::sync::Arc::new(JobControl::default()),
        )
        .unwrap();
        current = report.items[0].output.clone().expect("the extended file");
        let (code, json) = lab.cli_verify(profile, &current, Some(&content));
        assert_eq!(code, Some(0), "{profile}: {json}");
        assert_eq!(
            cli_says(&json),
            ("valid".to_owned(), Some(name.to_owned())),
            "{profile}"
        );
        assert!(
            lab.openssl_cms(&current, &content),
            "{profile}: OpenSSL accepts"
        );
    }
}
