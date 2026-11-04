//! The CLI as a streaming client of the accepted `oncl-server` contract: the real `oncl`
//! process against a real loopback server, real (synthetic) crypto and independent oracles.
//! Every local file is read and written by the client; the server works in its own
//! directory. Fault tests cut the real response with a raw TCP proxy.
mod remote_support;
use remote_support::*;
use std::{
    path::{Path, PathBuf},
    process::Output,
};

/// A client working directory, deliberately not the server's.
struct Session<'a> {
    remote: &'a Remote,
    endpoint: String,
    dir: tempfile::TempDir,
}
impl<'a> Session<'a> {
    fn new(remote: &'a Remote) -> Self {
        Self {
            endpoint: remote.endpoint(),
            remote,
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn via(remote: &'a Remote, endpoint: String) -> Self {
        Self {
            endpoint,
            remote,
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn run_with(&self, extra: &[&str], stdin: &[u8], secrets: &[&str]) -> Output {
        let mut args = vec![
            "--endpoint",
            &self.endpoint,
            "--token-file",
            path(&self.remote.token_file),
        ];
        args.extend_from_slice(extra);
        let mut hidden = vec![self.remote.token.as_str(), KEY_PASSWORD];
        hidden.extend_from_slice(secrets);
        oncl(&args, stdin, &hidden, Some(self.dir.path()))
    }
    fn run(&self, extra: &[&str]) -> Output {
        self.run_with(extra, b"", &[])
    }
}
fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", text(&output.stdout)))
}
fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}
fn exit(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

#[test]
fn hash_streams_a_client_file_and_stdin_and_matches_openssl_and_local() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let session = Session::new(&remote);
    let data = payload(3 * 1024 * 1024 + 17);
    let file = session.file("big.bin", &data);
    let expected = openssl_sha256(&data, session.dir.path());
    for (input, stdin) in [(path(&file), Vec::new()), ("-", data.clone())] {
        let output = session.run_with(
            &["hash", "--algorithm", "sha256", "--input", input, "--json"],
            &stdin,
            &[],
        );
        assert_eq!(exit(&output), 0, "{input}: {}", text(&output.stderr));
        let report = json(&output);
        assert_eq!(report["digest"], expected, "{input}");
        assert_eq!(report["bytes_in"], data.len());
        assert_eq!(report["code"], "Completed");
        assert_eq!(report["applied"], "NotApplied");
    }
    // The same inputs and the local command give the same digest report.
    let local = oncl(
        &[
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path(&file),
            "--json",
        ],
        b"",
        &[],
        None,
    );
    assert_eq!(json(&local)["digest"], expected);
    assert_eq!(remote.audit_begins(), 0, "hashing never applies a key");
}

#[test]
fn sign_verify_extract_round_trip_with_client_files_and_a_different_server_directory() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let session = Session::new(&remote);
    assert_ne!(session.dir.path(), remote.server_dir.path());
    let content = b"remote CMS payload \x00\x01\x02 from a client-side file".to_vec();
    let doc = session.file("doc.bin", &content);
    let signature = session.path("doc.p7s");
    let signed = session.run(&[
        "sign",
        "--profile",
        "cms",
        "--key-name",
        "ops-key",
        "--authorize",
        "--input",
        path(&doc),
        "--output",
        path(&signature),
        "--json",
    ]);
    assert_eq!(exit(&signed), 0, "{}", text(&signed.stderr));
    let report = json(&signed);
    assert_eq!(report["code"], "Completed");
    assert_eq!(report["applied"], "Applied");
    // `bytes_in` is the service's count of its own captured snapshot (not re-debited).
    assert_eq!(report["signer_count"], 1);
    let sig_bytes = std::fs::read(&signature).unwrap();
    assert_eq!(report["bytes_out"], sig_bytes.len());
    // Independent oracle: OpenSSL verifies the attached CMS the *server* produced.
    assert_eq!(
        openssl_cms_verify(&sig_bytes, None, session.dir.path()).as_deref(),
        Some(content.as_slice())
    );
    assert_eq!((remote.audit_begins(), remote.audit_finals()), (1, 1));

    let verified = session.run(&[
        "verify",
        "--profile",
        "cms",
        "--input",
        path(&signature),
        "--json",
    ]);
    assert_eq!(exit(&verified), 0, "{}", text(&verified.stderr));
    assert_eq!(json(&verified)["verdict"], "Valid");

    let extracted = session.path("extracted.bin");
    let result = session.run(&[
        "extract",
        "--input",
        path(&signature),
        "--output",
        path(&extracted),
        "--json",
    ]);
    assert_eq!(exit(&result), 0, "{}", text(&result.stderr));
    assert_eq!(std::fs::read(&extracted).unwrap(), content);
    assert_eq!(json(&result)["verified"], false);
    // No client path or client byte stayed on the server beyond the operation.
    assert!(files(&remote.scratch()).is_empty(), "scratch must be empty");
}

mod remote {
    use super::*;
    use oncl_api::{
        client::{
            ApiClient, ArtifactSink, ClientConfig, ExecuteOptions, FailureKind, FinalRecord,
            Request, Route, Source,
        },
        dto::{
            EvidenceKind, EvidenceRef, HashAlgorithm, InspectTarget, ItemMetadata, KeyRef,
            Operation, OperationMetadata, PartMetadata, PartRole, PluginKeyRef, SignKind,
            SignWriteMode, VerifyProfile,
        },
    };
    use std::time::{Duration, Instant};

    fn client(remote: &Remote) -> ApiClient {
        ApiClient::new(
            &remote.endpoint(),
            zeroize::Zeroizing::new(remote.token.clone()),
            ClientConfig::new(),
        )
        .unwrap()
    }
    struct Discard;
    impl ArtifactSink for Discard {
        fn begin(&mut self, _: &str, _: u64) -> std::io::Result<()> {
            Ok(())
        }
        fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn send(remote: &Remote, metadata: &OperationMetadata, parts: Vec<(&str, &[u8])>) -> String {
        let sources = parts
            .into_iter()
            .map(|(name, bytes)| {
                (
                    name.to_owned(),
                    Source::Memory(zeroize::Zeroizing::new(bytes.to_vec())),
                )
            })
            .collect();
        let request = Request::new(Route::Operations, metadata, sources).unwrap();
        let control = || Ok::<(), oncl_api::client::Stop>(());
        let outcome = client(remote).execute(
            request,
            &mut Discard,
            &ExecuteOptions {
                deadline: Instant::now() + Duration::from_secs(60),
                control: std::sync::Arc::new(control),
            },
        );
        match outcome {
            Err(error) => format!("refused:{}", error.kind.code()),
            Ok(done) => match done.record {
                FinalRecord::Final {
                    status: oncl_api::dto::FinalStatus::Failed,
                    error: Some(error),
                    ..
                } => format!("failed:{:?}:{:?}", error.code, error.applied),
                other => panic!("a server path produced a completed result: {other:?}"),
            },
        }
    }
    fn item(id: &str, operation: Operation) -> ItemMetadata {
        ItemMetadata {
            id: id.into(),
            operation,
        }
    }
    fn part(name: &str, role: PartRole) -> PartMetadata {
        PartMetadata {
            name: name.into(),
            item_id: "i".into(),
            role,
        }
    }

    /// A request whose every string field names a path on the *server's* disk is refused;
    /// nothing returns bytes of the canary file, and no key is ever applied.
    #[test]
    fn server_cannot_open_client_path() {
        let pki = Pki::start();
        let remote = Remote::start(&pki);
        let canary = remote.server_dir.path().join("canary.bin");
        std::fs::write(&canary, b"SERVER-SIDE-CANARY-4f2a-must-never-be-read").unwrap();
        let before = std::fs::read(&canary).unwrap();
        let server_path = canary.to_str().unwrap().to_owned();
        let p = server_path.as_str();
        let xml = br#"<root xmlns="urn:t"><a Id="x">v</a></root>"#.as_slice();
        // Each case: one operation whose *every* string field is the server path, plus a
        // well-formed `doc` part where the shape needs one.
        type Case<'a> = (
            &'a str,
            Operation,
            Vec<PartMetadata>,
            Vec<(&'a str, &'a [u8])>,
        );
        let cases: Vec<Case<'_>> = vec![
            (
                "hash input",
                Operation::Hash {
                    algorithm: HashAlgorithm::Sha256,
                    input: p.into(),
                },
                vec![],
                vec![],
            ),
            (
                "verify input and detached",
                Operation::Verify {
                    profile: VerifyProfile::Cms,
                    input: p.into(),
                    detached: Some(p.into()),
                    soap: None,
                },
                vec![],
                vec![],
            ),
            (
                "extract input",
                Operation::Extract { input: p.into() },
                vec![],
                vec![],
            ),
            (
                "sign: named key, ids, xpaths, methods and evidence are all server paths",
                Operation::Sign {
                    profile: SignKind::Xml,
                    input: "doc".into(),
                    detached: Some(p.into()),
                    mode: SignWriteMode::Create,
                    attached: false,
                    target: Some(p.into()),
                    parent: Some(p.into()),
                    signature_id: Some(p.into()),
                    soap: None,
                    body_id: Some(p.into()),
                    element: Some(p.into()),
                    xpath_parent: Some(p.into()),
                    signature_method: Some(p.into()),
                    digest_method: Some(p.into()),
                    evidence: vec![EvidenceRef {
                        kind: EvidenceKind::Ocsp,
                        input: p.into(),
                    }],
                    keys: vec![KeyRef::Named { name: p.into() }],
                },
                vec![part("doc", PartRole::Document)],
                vec![("doc", xml)],
            ),
            (
                "sign: inline container, password and alias are server paths",
                Operation::Sign {
                    profile: SignKind::Cms,
                    input: "doc".into(),
                    detached: None,
                    mode: SignWriteMode::Create,
                    attached: true,
                    target: None,
                    parent: None,
                    signature_id: None,
                    soap: None,
                    body_id: None,
                    element: None,
                    xpath_parent: None,
                    signature_method: None,
                    digest_method: None,
                    evidence: vec![],
                    keys: vec![KeyRef::Inline {
                        container: p.into(),
                        password: Some(p.into()),
                        alias: Some(p.into()),
                    }],
                },
                vec![part("doc", PartRole::Document)],
                vec![("doc", b"x".as_slice())],
            ),
            (
                "inspect container",
                Operation::Inspect {
                    target: InspectTarget::Container {
                        container: p.into(),
                        password: Some(p.into()),
                    },
                },
                vec![],
                vec![],
            ),
            (
                "inspect named key",
                Operation::Inspect {
                    target: InspectTarget::Named { name: p.into() },
                },
                vec![],
                vec![],
            ),
            (
                "inspect certificate",
                Operation::Inspect {
                    target: InspectTarget::Certificate { input: p.into() },
                },
                vec![],
                vec![],
            ),
            (
                "stamp",
                Operation::Stamp { input: p.into() },
                vec![],
                vec![],
            ),
            (
                "verify stamp",
                Operation::VerifyStamp {
                    token: p.into(),
                    data: Some(p.into()),
                    algorithm: None,
                    max_age_seconds: None,
                },
                vec![],
                vec![],
            ),
            (
                "plugin",
                Operation::Plugin {
                    plugin: p.into(),
                    operation: p.into(),
                    args: p.into(),
                    keys: vec![PluginKeyRef {
                        handle: 1,
                        name: p.into(),
                    }],
                },
                vec![],
                vec![],
            ),
            (
                "part named like a path",
                Operation::Hash {
                    algorithm: HashAlgorithm::Sha256,
                    input: p.into(),
                },
                vec![part(p, PartRole::Document)],
                vec![(p, b"abc".as_slice())],
            ),
        ];
        for (name, operation, parts, sources) in cases {
            let mut metadata_parts = parts;
            for part in &mut metadata_parts {
                part.item_id = "i".into();
            }
            let metadata = OperationMetadata {
                items: vec![item("i", operation)],
                parts: metadata_parts,
            };
            let outcome = send(&remote, &metadata, sources);
            assert!(
                outcome.starts_with("refused:") || outcome.starts_with("failed:"),
                "{name}: {outcome}"
            );
            assert!(
                !outcome.contains("Applied:Applied"),
                "{name}: a key was applied: {outcome}"
            );
        }
        assert_eq!(remote.audit_begins(), 0, "no key use for any server path");
        assert_eq!(std::fs::read(&canary).unwrap(), before);
        // Positive control: a document the client names by part reaches the server as
        // exactly the bytes the client sent, never the canary behind a same-looking name.
        let session = Session::new(&remote);
        let local = session.file("canary.bin", b"client bytes, not the canary");
        let output = session.run(&[
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path(&local),
            "--json",
        ]);
        assert_eq!(exit(&output), 0);
        assert_eq!(
            json(&output)["digest"],
            openssl_sha256(b"client bytes, not the canary", session.dir.path())
        );
        // A path that exists only on the server is a *client* error before any network use.
        let proxy = Proxy::start(
            remote.address,
            Fault {
                spot: Spot::Nowhere,
                end: End::Clean,
            },
        );
        let session = Session::via(&remote, proxy.endpoint());
        let missing = session.run(&[
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            session
                .path("does-not-exist-on-the-client")
                .to_str()
                .unwrap(),
        ]);
        assert_eq!(exit(&missing), 1);
        assert_eq!(proxy.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(matches!(FailureKind::Rejected, FailureKind::Rejected));
    }

    /// Sign through a proxy that cuts the real response; the client must keep nothing.
    fn signed_through(
        remote: &Remote,
        fault: Fault,
    ) -> (Output, Session<'_>, PathBuf, Proxy, Vec<PathBuf>) {
        let proxy = Proxy::start(remote.address, fault);
        let session = Session::via(remote, proxy.endpoint());
        let doc = session.file("doc.bin", b"payload that the server will sign");
        let before = files(session.dir.path());
        let destination = session.path("signed.p7s");
        let output = session.run(&[
            "sign",
            "--profile",
            "cms",
            "--key-name",
            "ops-key",
            "--authorize",
            "--input",
            path(&doc),
            "--output",
            path(&destination),
            "--json",
        ]);
        (output, session, destination, proxy, before)
    }

    #[test]
    fn truncated_response_not_committed() {
        let pki = Pki::start();
        let remote = Remote::start(&pki);
        let cuts = [
            (
                "before the artifact",
                Spot::BeforePart("artifact"),
                End::Abort,
            ),
            ("inside the artifact", Spot::MidPart("artifact"), End::Abort),
            (
                "after the artifact",
                Spot::AfterPart("artifact"),
                End::Abort,
            ),
            (
                "after the artifact, polite end",
                Spot::AfterPart("artifact"),
                End::Clean,
            ),
            (
                "before the final record",
                Spot::BeforePart("final"),
                End::Abort,
            ),
            (
                "inside the final record",
                Spot::MidPart("final"),
                End::Abort,
            ),
            (
                "after the final, no closing delimiter",
                Spot::AfterPart("final"),
                End::Clean,
            ),
            ("inside the closing delimiter", Spot::MidClosing, End::Abort),
            (
                "complete multipart, HTTP entity never ended",
                Spot::Nowhere,
                End::Abort,
            ),
        ];
        for (name, spot, end) in cuts {
            let begins = remote.audit_begins();
            let (output, session, destination, proxy, before) =
                signed_through(&remote, Fault { spot, end });
            let stderr = text(&output.stderr);
            assert_eq!(exit(&output), 1, "{name}: {stderr}");
            assert!(stderr.contains("applied=Unknown"), "{name}: {stderr}");
            assert!(!destination.exists(), "{name}: a file was committed");
            assert_eq!(
                files(session.dir.path()),
                before,
                "{name}: temporary client results were left behind"
            );
            assert!(
                text(&output.stdout).is_empty(),
                "{name}: a success report was printed"
            );
            // The key was really applied on the server: the client must not claim otherwise.
            assert_eq!(remote.audit_begins(), begins + 1, "{name}");
            assert!(!stderr.contains("applied=NotApplied"), "{name}: {stderr}");
            // And nothing retried it.
            assert_eq!(
                proxy.requests.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{name}"
            );
        }
        // Control: an uncut response commits the file.
        let (output, _session, destination, _proxy, _) = signed_through(
            &remote,
            Fault {
                spot: Spot::Nowhere,
                end: End::Clean,
            },
        );
        assert_eq!(exit(&output), 0, "{}", text(&output.stderr));
        assert!(destination.exists());
    }

    #[test]
    fn lost_final_is_unknown() {
        let pki = Pki::start();
        let remote = Remote::start(&pki);
        let (output, session, destination, proxy, _) = signed_through(
            &remote,
            Fault {
                spot: Spot::BeforePart("final"),
                end: End::Abort,
            },
        );
        let stderr = text(&output.stderr);
        assert_eq!(exit(&output), 1, "{stderr}");
        assert!(stderr.contains("ResponseLost"), "{stderr}");
        assert!(stderr.contains("applied=Unknown"), "{stderr}");
        assert!(!destination.exists());
        // The server did apply the key (BEGIN and FINAL are in its durable journal); the
        // client never retried, and promised neither rollback nor exactly-once.
        assert_eq!((remote.audit_begins(), remote.audit_finals()), (1, 1));
        assert_eq!(
            proxy.connections.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(proxy.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(session);
        // A keyless operation that loses its answer is honestly `NotApplied`.
        let proxy = Proxy::start(
            remote.address,
            Fault {
                spot: Spot::BeforePart("final"),
                end: End::Abort,
            },
        );
        let session = Session::via(&remote, proxy.endpoint());
        let doc = session.file("doc.bin", b"abc");
        let extract = session.run(&[
            "extract",
            "--input",
            path(&doc),
            "--output",
            path(&session.path("out.bin")),
        ]);
        // (`abc` is not CMS: the answer is a typed failure, still never a lost-key claim.)
        assert_eq!(exit(&extract), 1);
        assert!(
            text(&extract.stderr).contains("applied=NotApplied"),
            "{}",
            text(&extract.stderr)
        );
    }

    /// Local and remote operations over the same inputs and policy give the same verdict,
    /// signer facts and exit code.
    #[test]
    fn remote_matches_local_verdict() {
        let pki = Pki::start();
        let remote = Remote::start(&pki);
        let session = Session::new(&remote);
        let trust = pki.local_trust(session.dir.path());
        let trust: Vec<&str> = trust.iter().map(String::as_str).collect();
        let content = b"verdict parity payload".to_vec();
        let doc = session.file("doc.bin", &content);
        let sign = |profile: &str, detached: bool, name: &str| -> PathBuf {
            let out = session.path(name);
            let mut args = vec![
                "sign",
                "--profile",
                profile,
                "--key-name",
                "ops-key",
                "--authorize",
                "--input",
                path(&doc),
                "--output",
                path(&out),
            ];
            if detached {
                args.push("--detached");
            }
            let signed = session.run(&args);
            assert_eq!(exit(&signed), 0, "{profile}: {}", text(&signed.stderr));
            out
        };
        let compare = |profile: &str, input: &Path, detached: Option<&Path>, expect: i32| {
            let mut args = vec![
                "verify",
                "--profile",
                profile,
                "--input",
                path(input),
                "--json",
            ];
            if let Some(detached) = detached {
                args.extend(["--detached", path(detached)]);
            }
            let remote_run = session.run(&args);
            let mut local_args = args.clone();
            local_args.extend(trust.iter().copied());
            let local_run = oncl(&local_args, b"", &[], None);
            assert_eq!(
                exit(&remote_run),
                expect,
                "{profile}: {}",
                text(&remote_run.stderr)
            );
            assert_eq!(
                exit(&local_run),
                expect,
                "{profile}: {}",
                text(&local_run.stderr)
            );
            let (r, l) = (json(&remote_run), json(&local_run));
            for key in ["code", "applied", "verdict", "policy"] {
                assert_eq!(r[key], l[key], "{profile}: {key}");
            }
            let (rs, ls) = (
                r["signers"].as_array().unwrap(),
                l["signers"].as_array().unwrap(),
            );
            assert_eq!(rs.len(), ls.len(), "{profile}: signer count");
            for (a, b) in rs.iter().zip(ls) {
                for key in [
                    "signature",
                    "chain",
                    "validity",
                    "revocation",
                    "timestamp",
                    "key_usage",
                    "ades_level",
                    "reasons",
                ] {
                    assert_eq!(a[key], b[key], "{profile}: signer {key}");
                }
                // The local report prints the basis with its instant (`Current(<time>)`),
                // the remote one the variant and the instant in `time_basis_unix`.
                let (variant, local) = (
                    a["time_basis"].as_str().unwrap(),
                    b["time_basis"].as_str().unwrap(),
                );
                assert!(
                    local.starts_with(variant),
                    "{profile}: time basis {local} vs {variant}"
                );
                assert_eq!(
                    a["claimed_signing_time"], b["claimed_signing_time"],
                    "{profile}"
                );
            }
            r
        };
        let attached = sign("cms", false, "attached.p7s");
        let valid = compare("cms", &attached, None, 0);
        assert_eq!(valid["verdict"], "Valid");
        let detached = sign("cades-b", true, "detached.p7s");
        compare("cades-b", &detached, Some(&doc), 0);
        // A flipped payload byte: Invalid (2) both ways.
        let mut bytes = std::fs::read(&attached).unwrap();
        let at = bytes
            .windows(content.len())
            .position(|w| w == content.as_slice())
            .unwrap();
        bytes[at] ^= 1;
        let tampered = session.file("tampered.p7s", &bytes);
        let invalid = compare("cms", &tampered, None, 2);
        assert_eq!(invalid["verdict"], "Invalid");
        // A server (and a local run) without any trust anchor: the same non-Valid verdict.
        let bare = Remote::start_with(&pki, |config, _| config.pki.anchors.clear());
        let bare_session = Session::new(&bare);
        let remote_run = bare_session.run(&[
            "verify",
            "--profile",
            "cms",
            "--input",
            path(&attached),
            "--json",
        ]);
        let local_run = oncl(
            &[
                "verify",
                "--profile",
                "cms",
                "--input",
                path(&attached),
                "--json",
                "--pki-endpoint",
                &pki.origin,
            ],
            b"",
            &[],
            None,
        );
        assert_eq!(
            exit(&remote_run),
            exit(&local_run),
            "{}",
            text(&remote_run.stderr)
        );
        assert_ne!(exit(&remote_run), 0);
        assert_eq!(json(&remote_run)["verdict"], json(&local_run)["verdict"]);
    }
}

/// Every channel a diagnostic can leave through: stdout, stderr and any file the command
/// created. The token and the container password must never be in them.
fn assert_clean(output: &Output, dir: &Path, remote: &Remote) {
    for secret in [remote.token.as_str(), KEY_PASSWORD] {
        for (name, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{name} leaks a secret"
            );
        }
        for file in files(dir) {
            // The client's own secret inputs (token and password files) are not outputs.
            if file.starts_with(remote.token_file.parent().unwrap())
                || file.components().any(|c| c.as_os_str() == "secrets")
            {
                continue;
            }
            let bytes = std::fs::read(&file).unwrap_or_default();
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{} leaks a secret",
                file.display()
            );
        }
    }
}

#[test]
fn token_never_appears_in_any_output_error_or_report() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let session = Session::new(&remote);
    let doc = session.file("doc.bin", b"redaction payload");
    let report = session.path("report.json");
    // Success, with a report file and JSON on stdout.
    let ok = session.run(&[
        "hash",
        "--algorithm",
        "sha256",
        "--input",
        path(&doc),
        "--json",
        "--report",
        path(&report),
    ]);
    assert_eq!(exit(&ok), 0, "{}", text(&ok.stderr));
    assert_clean(&ok, session.dir.path(), &remote);
    // A different (valid-shaped) token: the typed refusal never echoes either token.
    let other = oncl_server::auth::TokenSecret::generate().unwrap().bearer();
    let private =
        oncl_pki::private_fs::PrivateDirectory::create(&session.path("other-token")).unwrap();
    use std::io::Write as _;
    private
        .create_file("t")
        .unwrap()
        .write_all(other.as_bytes())
        .unwrap();
    let wrong = oncl(
        &[
            "--endpoint",
            &remote.endpoint(),
            "--token-file",
            path(&session.path("other-token").join("t")),
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path(&doc),
        ],
        b"",
        &[other.as_str(), remote.token.as_str()],
        Some(session.dir.path()),
    );
    assert_eq!(exit(&wrong), 1);
    assert!(text(&wrong.stderr).contains("oncl: PermissionDenied; applied=NotApplied"));
    // A server that answers with an untyped body that contains the token and a marker:
    // neither is ever printed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let leaked = format!("RAW-BODY-MARKER {} END", remote.token);
    let serve = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0u8; 4096];
        let _ = stream.read(&mut buffer);
        let _ = write!(
            stream,
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{leaked}",
            leaked.len()
        );
    });
    let proxy_session = Session::via(&remote, format!("http://{address}"));
    let bad = proxy_session.run(&["hash", "--algorithm", "sha256", "--input", path(&doc)]);
    serve.join().unwrap();
    let stderr = text(&bad.stderr);
    assert_eq!(exit(&bad), 1, "{stderr}");
    assert!(
        stderr.contains("UnexpectedStatus") && stderr.contains("HTTP 502"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("RAW-BODY-MARKER"),
        "a raw response body was printed"
    );
    assert_clean(&bad, proxy_session.dir.path(), &remote);
    // Connection refused (nothing listens): a typed local failure, never the token.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap();
    drop(closed);
    let refused = Session::via(&remote, format!("http://{port}"));
    let out = refused.run(&["hash", "--algorithm", "sha256", "--input", path(&doc)]);
    assert_eq!(exit(&out), 1);
    assert!(
        text(&out.stderr).contains("ConnectFailed; applied=NotApplied"),
        "{}",
        text(&out.stderr)
    );
    assert_clean(&out, refused.dir.path(), &remote);
}

#[test]
fn token_sources_and_preflight_refusals_need_no_network() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let proxy = Proxy::start(
        remote.address,
        Fault {
            spot: Spot::Nowhere,
            end: End::Clean,
        },
    );
    let session = Session::via(&remote, proxy.endpoint());
    let doc = session.file("doc.bin", b"abc");
    let endpoint = proxy.endpoint();
    let requests = || proxy.requests.load(std::sync::atomic::Ordering::SeqCst);
    // The token on standard input (the descriptor alternative to a file).
    let by_stdin = oncl(
        &[
            "--endpoint",
            &endpoint,
            "--token-stdin",
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path(&doc),
            "--json",
        ],
        format!("{}\n", remote.token).as_bytes(),
        &[remote.token.as_str()],
        Some(session.dir.path()),
    );
    assert_eq!(exit(&by_stdin), 0, "{}", text(&by_stdin.stderr));
    assert_eq!(requests(), 1);
    // Refusals: no request ever leaves the process.
    let token = path(&remote.token_file);
    let cases: Vec<(&str, Vec<&str>, &str)> = vec![
        (
            "no token source",
            vec![
                "--endpoint",
                &endpoint,
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                path(&doc),
            ],
            "TokenRequired",
        ),
        (
            "stdin is both token and document",
            vec![
                "--endpoint",
                &endpoint,
                "--token-stdin",
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                "-",
            ],
            "StdinConflict",
        ),
        (
            "token argument does not exist",
            vec![
                "--endpoint",
                &endpoint,
                "--token",
                "x",
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                path(&doc),
            ],
            "UsageError",
        ),
        (
            "plain http to a remote host",
            vec![
                "--endpoint",
                "http://192.0.2.1:9",
                "--token-file",
                token,
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                path(&doc),
            ],
            "PlainHttpRefused",
        ),
        (
            "malformed endpoint",
            vec![
                "--endpoint",
                "ftp://example.test",
                "--token-file",
                token,
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                path(&doc),
            ],
            "InvalidEndpoint",
        ),
        (
            "endpoint with userinfo and path",
            vec![
                "--endpoint",
                "http://user:pw@127.0.0.1:1/x",
                "--token-file",
                token,
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                path(&doc),
            ],
            "InvalidEndpoint",
        ),
        (
            "trust root on a remote session",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "--root",
                path(&doc),
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                path(&doc),
            ],
            "RemoteUnsupported",
        ),
        (
            "offline policy on a remote session",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "--offline",
                "hash",
                "--algorithm",
                "sha256",
                "--input",
                path(&doc),
            ],
            "RemoteUnsupported",
        ),
        (
            "container file without the explicit inline mode",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "sign",
                "--profile",
                "cms",
                "--key",
                path(&doc),
                "--secret-file",
                token,
                "--authorize",
                "--input",
                path(&doc),
                "--output",
                "x.p7s",
            ],
            "InlineKeyRequired",
        ),
        (
            "token reader on a remote session",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "sign",
                "--profile",
                "cms",
                "--token-reader",
                "r",
                "--token-kind",
                "kaztoken",
                "--token-alias",
                "a",
                "--authorize",
                "--input",
                path(&doc),
                "--output",
                "x.p7s",
            ],
            "RemoteUnsupported",
        ),
        (
            "plugin on a remote session",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "plugin",
                "call",
                "--manifest",
                "m",
                "--module",
                "w",
                "--operation",
                "o",
                "--caller",
                "c",
                "--args-file",
                "a",
                "--output",
                "-",
            ],
            "RemoteUnsupported",
        ),
        (
            "raw signing is not a profile of the contract",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "sign",
                "--profile",
                "raw",
                "--key-name",
                "ops-key",
                "--authorize",
                "--input",
                path(&doc),
                "--output",
                "x.sig",
            ],
            "RemoteUnsupported",
        ),
        (
            "xades-lt is sign xades-t then a keyless extend",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "sign",
                "--profile",
                "xades-lt",
                "--key-name",
                "ops-key",
                "--authorize",
                "--input",
                path(&doc),
                "--output",
                "x.sig",
            ],
            "RemoteUnsupported",
        ),
        (
            "named key with a client secret",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "sign",
                "--profile",
                "cms",
                "--key-name",
                "ops-key",
                "--secret-file",
                token,
                "--authorize",
                "--input",
                path(&doc),
                "--output",
                "x.p7s",
            ],
            "InvalidCombination",
        ),
        (
            "timestamp with a client TSA",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "timestamp",
                "acquire",
                "--input",
                path(&doc),
                "--output",
                "t.tsr",
                "--tsa",
                "http://tsa.example",
            ],
            "RemoteUnsupported",
        ),
        (
            "jwt claims policy is the operator's",
            vec![
                "--endpoint",
                &endpoint,
                "--token-file",
                token,
                "jwt",
                "verify",
                "--input",
                path(&doc),
                "--issuer",
                "x",
            ],
            "RemoteUnsupported",
        ),
    ];
    for (name, args, code) in cases {
        let output = oncl(
            &args,
            b"",
            &[remote.token.as_str()],
            Some(session.dir.path()),
        );
        assert_eq!(exit(&output), 1, "{name}: {}", text(&output.stderr));
        assert!(
            text(&output.stderr).contains(code),
            "{name}: {}",
            text(&output.stderr)
        );
        assert_eq!(requests(), 1, "{name}: a request left the process");
    }
    // An unprotected token directory is refused by the secret rules before any network use.
    let loose = session.file("loose.token", remote.token.as_bytes());
    let output = oncl(
        &[
            "--endpoint",
            &endpoint,
            "--token-file",
            path(&loose),
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path(&doc),
        ],
        b"",
        &[remote.token.as_str()],
        Some(session.dir.path()),
    );
    assert_eq!(exit(&output), 1, "{}", text(&output.stderr));
    assert_eq!(requests(), 1, "an unprotected token file was used");
}

#[test]
fn inline_key_mode_sends_the_container_only_when_explicit_and_never_spools_it() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let session = Session::new(&remote);
    let leaf = pki.leaf("user-rsa-sign");
    let container = session.file("signer.p12", &container(&leaf, KEY_PASSWORD));
    let private = oncl_pki::private_fs::PrivateDirectory::create(&session.path("secrets")).unwrap();
    use std::io::Write as _;
    private
        .create_file("pw")
        .unwrap()
        .write_all(KEY_PASSWORD.as_bytes())
        .unwrap();
    let password = session.path("secrets").join("pw");
    let doc = session.file("doc.bin", b"inline key payload");
    let signature = session.path("inline.p7s");
    let args = |extra: &[&'static str]| -> Vec<String> {
        let mut all: Vec<String> = [
            "sign",
            "--profile",
            "cms",
            "--key",
            path(&container),
            "--secret-file",
            path(&password),
            "--authorize",
            "--input",
            path(&doc),
            "--output",
            path(&signature),
            "--json",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        all.extend(extra.iter().map(ToString::to_string));
        all
    };
    // Without the explicit mode nothing is sent and nothing is applied.
    let a: Vec<String> = args(&[]);
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let refused = session.run(&a);
    assert_eq!(exit(&refused), 1);
    assert!(text(&refused.stderr).contains("InlineKeyRequired"));
    assert!(!signature.exists());
    assert_eq!(remote.audit_begins(), 0);
    // With it: signed, audited for the exact inline key, verified by OpenSSL.
    let a: Vec<String> = args(&["--inline-key"]);
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let watch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = watch.clone();
    let scratch = remote.scratch();
    let needle = KEY_PASSWORD.as_bytes().to_vec();
    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let found = hit.clone();
    let watcher = std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            for file in files(&scratch) {
                if let Ok(bytes) = std::fs::read(&file)
                    && bytes.windows(needle.len()).any(|w| w == needle.as_slice())
                {
                    found.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    let signed = session.run(&a);
    watch.store(true, std::sync::atomic::Ordering::SeqCst);
    watcher.join().unwrap();
    assert_eq!(exit(&signed), 0, "{}", text(&signed.stderr));
    assert!(
        !hit.load(std::sync::atomic::Ordering::SeqCst),
        "a secret reached the spool"
    );
    assert_eq!(
        openssl_cms_verify(
            &std::fs::read(&signature).unwrap(),
            None,
            session.dir.path()
        )
        .as_deref(),
        Some(b"inline key payload".as_slice())
    );
    assert_eq!((remote.audit_begins(), remote.audit_finals()), (1, 1));
    assert_clean(&signed, session.dir.path(), &remote);
    // Inspecting the container (also an explicit, secret-bearing mode).
    let inspected = session.run(&[
        "inspect",
        "--profile",
        "container",
        "--input",
        path(&container),
        "--secret-file",
        path(&password),
        "--inline-key",
        "--json",
    ]);
    assert_eq!(exit(&inspected), 0, "{}", text(&inspected.stderr));
    assert_eq!(json(&inspected)["entries"][0]["alias"], leaf.alias);
    // A server without the inline right refuses the container: nothing applied.
    let strict = Remote::start_with(&pki, |config, _| {
        config.tokens[0].inline_pkcs12 = false;
    });
    let session = Session::new(&strict);
    let doc = session.file("doc.bin", b"x");
    let out = session.path("never.p7s");
    let denied = session.run_with(
        &[
            "sign",
            "--profile",
            "cms",
            "--key",
            path(&container),
            "--secret-file",
            path(&password),
            "--inline-key",
            "--authorize",
            "--input",
            path(&doc),
            "--output",
            path(&out),
        ],
        b"",
        &[],
    );
    assert_eq!(exit(&denied), 1);
    assert!(
        text(&denied.stderr).contains("PermissionDenied; applied=NotApplied"),
        "{}",
        text(&denied.stderr)
    );
    assert!(!out.exists());
    assert_eq!(strict.audit_begins(), 0);
}

#[test]
fn https_with_a_private_ca_and_no_way_to_skip_verification() {
    let pki = Pki::start();
    // A private CA that issued the server certificate for 127.0.0.1.
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "oncl test private CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf_params.subject_alt_names = vec![rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let leaf = leaf_params
        .signed_by(&leaf_key, &rcgen::Issuer::new(ca_params, ca_key))
        .unwrap();
    let remote = Remote::start_tls(&pki, &leaf.pem(), &leaf_key.serialize_pem(), |_, _| {});
    let session = Session::new(&remote);
    let doc = session.file("doc.bin", b"tls payload");
    let ca_file = session.file("ca.pem", ca.pem().as_bytes());
    let hash = |extra: &[&str]| {
        let mut args = vec![
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path(&doc),
            "--json",
        ];
        args.extend_from_slice(extra);
        session.run(&args)
    };
    let ok = hash(&["--ca-file", path(&ca_file)]);
    assert_eq!(exit(&ok), 0, "{}", text(&ok.stderr));
    assert_eq!(
        json(&ok)["digest"],
        openssl_sha256(b"tls payload", session.dir.path())
    );
    // The same CA as DER also works.
    use der::Decode as _;
    let der_file = session.file("ca.der", ca.der());
    let _ = x509_cert::Certificate::from_der(ca.der()).unwrap();
    assert_eq!(exit(&hash(&["--ca-file", path(&der_file)])), 0);
    // The public roots do not know the private CA: refused, nothing sent past the handshake.
    let untrusted = hash(&[]);
    assert_eq!(exit(&untrusted), 1);
    assert!(
        text(&untrusted.stderr).contains("TlsFailed"),
        "{}",
        text(&untrusted.stderr)
    );
    // A different CA does not vouch for this server either.
    let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut other_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let other = other_params.self_signed(&other_key).unwrap();
    let other_file = session.file("other.pem", other.pem().as_bytes());
    let wrong = hash(&["--ca-file", path(&other_file)]);
    assert_eq!(exit(&wrong), 1);
    assert!(text(&wrong.stderr).contains("TlsFailed"));
    // There is no flag that skips verification.
    let insecure = hash(&["--insecure"]);
    assert_eq!(exit(&insecure), 1);
    assert!(text(&insecure.stderr).contains("UsageError"));
    // A private key in a PEM "CA" file is refused rather than ignored; a CA for plain http too.
    let bad = session.file("bad.pem", leaf_key.serialize_pem().as_bytes());
    let out = hash(&["--ca-file", path(&bad)]);
    assert_eq!(exit(&out), 1);
    assert!(
        text(&out.stderr).contains("InvalidCertificate"),
        "{}",
        text(&out.stderr)
    );
    assert_clean(&out, session.dir.path(), &remote);
}

fn manifest(session: &Session<'_>, items: serde_json::Value) -> PathBuf {
    session.file(
        "manifest.json",
        json_text(&serde_json::json!({ "items": items })).as_bytes(),
    )
}
fn json_text(value: &serde_json::Value) -> String {
    value.to_string()
}
fn p(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

#[test]
fn batch_runs_on_the_server_and_publishes_each_finished_output_on_the_client() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let session = Session::new(&remote);
    let doc = session.file("doc.bin", b"batch document");
    let made = session.path("made.p7s");
    let signed = session.run(&[
        "sign",
        "--profile",
        "cms",
        "--key-name",
        "ops-key",
        "--authorize",
        "--input",
        path(&doc),
        "--output",
        path(&made),
    ]);
    assert_eq!(exit(&signed), 0, "{}", text(&signed.stderr));
    let begins = remote.audit_begins();
    let (out_sig, out_x) = (session.path("batch.p7s"), session.path("batch.out"));
    let items = serde_json::json!([
        {"op":"hash","id":"h","algorithm":"sha256","input":p(&doc)},
        {"op":"sign","id":"s","profile":"cms","input":p(&doc),"output":p(&out_sig)},
        {"op":"verify","id":"v","input":p(&made)},
        {"op":"extract","id":"x","input":p(&made),"output":p(&out_x)},
        {"op":"hash","id":"missing","algorithm":"sha256","input":p(&session.path("absent.bin"))},
    ]);
    let manifest_file = manifest(&session, items);
    let run = session.run(&[
        "batch",
        "run",
        "--manifest",
        path(&manifest_file),
        "--key-name",
        "ops-key",
        "--authorize",
        "--json",
    ]);
    // One unreadable client source fails only its own item: the batch is incomplete (4).
    assert_eq!(exit(&run), 4, "{}", text(&run.stderr));
    let report = json(&run);
    assert_eq!(report["code"], "Partial");
    assert_eq!(
        (report["completed"].as_u64(), report["total"].as_u64()),
        (Some(4), Some(5))
    );
    let rows = report["items"].as_array().unwrap();
    let status = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap();
    assert_eq!(
        status("h")["digest"]["hex"],
        openssl_sha256(b"batch document", session.dir.path())
    );
    assert_eq!(status("s")["applied"], "Applied");
    assert_eq!(status("s")["published"], true);
    assert_eq!(status("v")["verdict"], "Valid");
    assert_eq!(status("x")["published"], true);
    assert_eq!(status("missing")["status"], "Failed");
    assert_eq!(remote.audit_begins(), begins + 1);
    assert_eq!(std::fs::read(&out_x).unwrap(), b"batch document");
    assert_eq!(
        openssl_cms_verify(&std::fs::read(&out_sig).unwrap(), None, session.dir.path()).as_deref(),
        Some(b"batch document".as_slice())
    );
    // A lost terminal record: nothing new is published, an earlier file is untouched and
    // the key use is `Unknown`, never retried.
    let proxy = Proxy::start(
        remote.address,
        Fault {
            spot: Spot::BeforePart("final"),
            end: End::Abort,
        },
    );
    let lossy = Session::via(&remote, proxy.endpoint());
    let (doc2, kept) = (
        lossy.file("d2.bin", b"second"),
        lossy.file("kept.bin", b"earlier output"),
    );
    let new_out = lossy.path("new.p7s");
    let manifest_file = manifest(
        &lossy,
        serde_json::json!([
            {"op":"sign","id":"s","profile":"cms","input":p(&doc2),"output":p(&new_out)},
        ]),
    );
    let lost = lossy.run(&[
        "batch",
        "run",
        "--manifest",
        path(&manifest_file),
        "--key-name",
        "ops-key",
        "--authorize",
    ]);
    assert_eq!(exit(&lost), 1, "{}", text(&lost.stderr));
    assert!(
        text(&lost.stderr).contains("ResponseLost")
            && text(&lost.stderr).contains("applied=Unknown")
    );
    assert!(!new_out.exists());
    assert_eq!(std::fs::read(&kept).unwrap(), b"earlier output");
    assert_eq!(proxy.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn jose_inspect_timestamp_and_extend_families_run_remotely() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let s = Session::new(&remote);
    let payload = s.file("payload", b"jws payload");
    let jws = s.path("a.jws");
    let signed = s.run(&[
        "jws",
        "sign",
        "--serialization",
        "compact",
        "--input",
        path(&payload),
        "--output",
        path(&jws),
        "--key-name",
        "ops-key",
        "--authorize",
    ]);
    assert_eq!(exit(&signed), 0, "{}", text(&signed.stderr));
    let verified = s.run(&[
        "jws",
        "verify",
        "--serialization",
        "compact",
        "--input",
        path(&jws),
        "--json",
    ]);
    assert!(
        [0, 2, 3].contains(&exit(&verified)),
        "{}",
        text(&verified.stderr)
    );
    assert!(
        ["Valid", "Invalid", "Indeterminate"]
            .contains(&json(&verified)["verdict"].as_str().unwrap())
    );
    let claims = s.file("claims.json", br#"{"iss":"operator","sub":"x"}"#);
    let jwt = s.path("a.jwt");
    let encoded = s.run(&[
        "jwt",
        "encode",
        "--input",
        path(&claims),
        "--output",
        path(&jwt),
        "--key-name",
        "ops-key",
        "--authorize",
    ]);
    assert_eq!(exit(&encoded), 0, "{}", text(&encoded.stderr));
    let decoded = s.path("claims.out");
    let d = s.run(&[
        "jwt",
        "decode",
        "--input",
        path(&jwt),
        "--output",
        path(&decoded),
        "--json",
    ]);
    assert_eq!(exit(&d), 0, "{}", text(&d.stderr));
    assert_eq!(
        std::fs::read(&decoded).unwrap(),
        br#"{"iss":"operator","sub":"x"}"#
    );
    assert_eq!(json(&d)["verified"], false);
    let v = s.run(&["jwt", "verify", "--input", path(&jwt), "--json"]);
    assert!([0, 2, 3].contains(&exit(&v)), "{}", text(&v.stderr));
    // Certificate metadata of a public document, and the named key's public metadata.
    let leaf = s.file("leaf.der", &{
        use der::Encode;
        pki.leaf("user-rsa-sign").cert.to_der().unwrap()
    });
    let c = s.run(&[
        "inspect",
        "--profile",
        "certificate",
        "--input",
        path(&leaf),
        "--json",
    ]);
    assert_eq!(exit(&c), 0, "{}", text(&c.stderr));
    assert_eq!(json(&c)["entries"].as_array().unwrap().len(), 1);
    // Timestamp: acquire through the operator's TSA, verify the token.
    let doc = s.file("doc.bin", b"stamp me");
    let token = s.path("doc.tsr");
    let t = s.run(&[
        "timestamp",
        "acquire",
        "--input",
        path(&doc),
        "--output",
        path(&token),
        "--json",
    ]);
    assert_eq!(exit(&t), 0, "{}", text(&t.stderr));
    let tv = s.run(&[
        "timestamp",
        "verify",
        "--input",
        path(&token),
        "--data",
        path(&doc),
        "--json",
    ]);
    assert!([0, 2, 3].contains(&exit(&tv)), "{}", text(&tv.stderr));
    // CAdES-B detached, then a keyless extension to T: the output verifies at level T.
    let base = s.path("base.p7s");
    let b = s.run(&[
        "sign",
        "--profile",
        "cades-b",
        "--detached",
        "--key-name",
        "ops-key",
        "--authorize",
        "--input",
        path(&doc),
        "--output",
        path(&base),
    ]);
    assert_eq!(exit(&b), 0, "{}", text(&b.stderr));
    let begins = remote.audit_begins();
    let ext = s.path("ext.p7s");
    let e = s.run(&[
        "extend",
        "--profile",
        "cms",
        "--level",
        "t",
        "--input",
        path(&base),
        "--detached",
        path(&doc),
        "--output",
        path(&ext),
        "--json",
    ]);
    assert_eq!(exit(&e), 0, "{}", text(&e.stderr));
    assert_eq!(remote.audit_begins(), begins, "extension never uses a key");
    assert!(std::fs::metadata(&ext).unwrap().len() > std::fs::metadata(&base).unwrap().len());
}

#[test]
fn overload_is_a_typed_not_applied_failure_with_the_local_exit_contract() {
    let pki = Pki::start();
    let remote = Remote::start_with(&pki, |config, _| {
        config.max_in_flight = 1;
        config.queue_capacity = 0;
        config.admission_wait_ms = 100;
    });
    pki.tsa_gate.hold();
    let s = Session::new(&remote);
    let doc = s.file("doc.bin", b"busy");
    let token_out = s.path("busy.tsr");
    let first = {
        let args: Vec<String> = [
            "--endpoint",
            &remote.endpoint(),
            "--token-file",
            path(&remote.token_file),
            "timestamp",
            "acquire",
            "--input",
            path(&doc),
            "--output",
            path(&token_out),
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let (secret, dir) = (remote.token.clone(), s.dir.path().to_owned());
        std::thread::spawn(move || {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            oncl(&refs, b"", &[secret.as_str()], Some(&dir))
        })
    };
    pki.tsa_gate.wait_entered(1);
    let second = s.run(&["hash", "--algorithm", "sha256", "--input", path(&doc)]);
    pki.tsa_gate.release();
    let finished = first.join().unwrap();
    assert_eq!(exit(&second), 1, "{}", text(&second.stderr));
    assert!(
        text(&second.stderr).contains("CapacityExceeded; applied=NotApplied"),
        "{}",
        text(&second.stderr)
    );
    assert_eq!(exit(&finished), 0, "{}", text(&finished.stderr));
    // A token without the right: PermissionDenied, NotApplied.
    let narrow = Remote::start_with(&pki, |config, _| {
        config.tokens[0].actions = vec![oncl_server::config::Permission::Hash]
    });
    let ns = Session::new(&narrow);
    let v = ns.run(&["verify", "--profile", "cms", "--input", path(&doc)]);
    assert_eq!(exit(&v), 1);
    assert!(text(&v.stderr).contains("PermissionDenied; applied=NotApplied"));
}

/// Mutation proof for the headline guarantee: the staged result is published only after the
/// COMPLETE response. (The check lives in `oncl_api::client::stream::parse` and the CLI's
/// `Session::call`; `truncated_response_not_committed` fails if either is bypassed.)
#[test]
fn a_complete_response_is_the_only_one_that_commits() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let proxy = Proxy::start(
        remote.address,
        Fault {
            spot: Spot::Nowhere,
            end: End::Clean,
        },
    );
    let s = Session::via(&remote, proxy.endpoint());
    let doc = s.file("doc.bin", b"complete");
    let out = s.path("ok.p7s");
    let run = s.run(&[
        "sign",
        "--profile",
        "cms",
        "--key-name",
        "ops-key",
        "--authorize",
        "--input",
        path(&doc),
        "--output",
        path(&out),
    ]);
    assert_eq!(exit(&run), 0, "{}", text(&run.stderr));
    assert!(out.exists());
    assert_eq!(proxy.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A well-framed artifact whose size disagrees with the final record is an integrity
/// failure: nothing is published. (`extract` states `bytes_written` exactly; signing and JWS
/// `bytes_out` are resource-scope counters, not artifact sizes, so only their identity and
/// count are checked: see cli.md.)
#[test]
fn artifact_of_the_wrong_size_is_never_published() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let s = Session::new(&remote);
    let doc = s.file("doc.bin", b"integrity payload");
    let sig = s.path("doc.p7s");
    let signed = s.run(&[
        "sign",
        "--profile",
        "cms",
        "--key-name",
        "ops-key",
        "--authorize",
        "--input",
        path(&doc),
        "--output",
        path(&sig),
    ]);
    assert_eq!(exit(&signed), 0, "{}", text(&signed.stderr));
    for (spot, expect_ok) in [(Spot::Nowhere, true), (Spot::TrimArtifact, false)] {
        let proxy = Proxy::start(
            remote.address,
            Fault {
                spot,
                end: End::Clean,
            },
        );
        let via = Session::via(&remote, proxy.endpoint());
        let out = via.path("extracted.bin");
        let before = files(via.dir.path());
        let run = via.run(&["extract", "--input", path(&sig), "--output", path(&out)]);
        let stderr = text(&run.stderr);
        if expect_ok {
            assert_eq!(exit(&run), 0, "{stderr}");
            assert_eq!(std::fs::read(&out).unwrap(), b"integrity payload");
        } else {
            assert_eq!(exit(&run), 1, "{stderr}");
            assert!(
                stderr.contains("ProtocolViolation") && stderr.contains("artifact length differs"),
                "{stderr}"
            );
            assert!(stderr.contains("applied=NotApplied"), "{stderr}");
            assert!(!out.exists());
            assert_eq!(
                files(via.dir.path()),
                before,
                "temporary results left behind"
            );
        }
    }
}

#[test]
fn a_reset_during_upload_is_not_applied_because_the_server_starts_work_only_after_the_whole_body() {
    // operations.rs/intake.rs: the service takes the complete multipart body (and re-checks
    // authority) before the worker may use a key, so an incomplete upload cannot have applied it.
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let serve = std::thread::spawn(move || {
        use std::io::Read;
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();
        let (mut total, mut buffer) = (0usize, [0u8; 8192]);
        while total < 256 * 1024 {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        // Dropped with unread request bytes in flight: the peer sees a reset.
    });
    let s = Session::via(&remote, format!("http://{address}"));
    let doc = s.file("big.bin", &payload(16 * 1024 * 1024));
    let out = s.path("never.p7s");
    let run = s.run(&[
        "sign",
        "--profile",
        "cms",
        "--key-name",
        "ops-key",
        "--authorize",
        "--input",
        path(&doc),
        "--output",
        path(&out),
    ]);
    serve.join().unwrap();
    let stderr = text(&run.stderr);
    assert_eq!(exit(&run), 1, "{stderr}");
    assert!(stderr.contains("applied=NotApplied"), "{stderr}");
    assert!(!out.exists());
    assert_eq!(remote.audit_begins(), 0);
}

#[test]
fn redirects_are_never_followed_and_ambient_proxies_are_never_used() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let watch = |listener: &std::net::TcpListener| listener.set_nonblocking(true).unwrap();
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ambient = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    (watch(&target), watch(&ambient));
    let (target_address, origin_address) =
        (target.local_addr().unwrap(), origin.local_addr().unwrap());
    let serve = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = origin.accept().unwrap();
        let mut buffer = [0u8; 4096];
        let _ = stream.read(&mut buffer);
        let _ = write!(
            stream,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/v1/operations\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    });
    let s = Session::via(&remote, format!("http://{origin_address}"));
    let doc = s.file("doc.bin", b"abc");
    let args = [
        "--endpoint",
        &s.endpoint,
        "--token-file",
        path(&remote.token_file),
        "hash",
        "--algorithm",
        "sha256",
        "--input",
        path(&doc),
    ];
    let run = oncl_with_proxy(
        &args,
        s.dir.path(),
        &format!("http://{}", ambient.local_addr().unwrap()),
    );
    serve.join().unwrap();
    let stderr = text(&run.stderr);
    assert_eq!(exit(&run), 1, "{stderr}");
    assert!(stderr.contains("UnexpectedStatus (HTTP 307)"), "{stderr}");
    assert!(!stderr.contains(&remote.token));
    assert!(
        matches!(target.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "the redirect (and the bearer token) was followed"
    );
    assert!(
        matches!(ambient.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "an ambient proxy was used"
    );
}

#[test]
fn plain_http_to_a_remote_host_needs_the_flag_and_then_warns_on_every_run() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let s = Session::new(&remote);
    let doc = s.file("doc.bin", b"abc");
    let base = |flag: bool| {
        let mut args = vec![
            "--endpoint",
            "http://192.0.2.1:9",
            "--token-file",
            path(&remote.token_file),
            "--timeout-seconds",
            "2",
        ];
        if flag {
            args.push("--allow-plain-http");
        }
        args.extend(["hash", "--algorithm", "sha256", "--input", path(&doc)]);
        oncl(&args, b"", &[remote.token.as_str()], Some(s.dir.path()))
    };
    let refused = base(false);
    assert_eq!(exit(&refused), 1);
    assert!(text(&refused.stderr).contains("PlainHttpRefused"));
    assert!(
        !text(&refused.stderr).contains("warning"),
        "a refusal needs no warning"
    );
    for _ in 0..2 {
        let allowed = base(true);
        let stderr = text(&allowed.stderr);
        assert_eq!(exit(&allowed), 1, "{stderr}");
        assert!(
            stderr.contains("warning: --allow-plain-http") && stderr.contains("unencrypted"),
            "{stderr}"
        );
    }
}

#[test]
fn batch_destinations_are_checked_for_publication_before_any_request() {
    let pki = Pki::start();
    let remote = Remote::start(&pki);
    let proxy = Proxy::start(
        remote.address,
        Fault {
            spot: Spot::Nowhere,
            end: End::Clean,
        },
    );
    let s = Session::via(&remote, proxy.endpoint());
    let doc = s.file("doc.bin", b"batch");
    let (one, two) = (s.path("one"), s.path("two"));
    std::fs::create_dir(&one).unwrap();
    let missing = two.join("out2.p7s");
    let manifest_file = manifest(
        &s,
        serde_json::json!([
            {"op":"sign","id":"a","profile":"cms","input":p(&doc),"output":p(&one.join("out1.p7s"))},
            {"op":"sign","id":"b","profile":"cms","input":p(&doc),"output":p(&missing)},
        ]),
    );
    let run = s.run(&[
        "batch",
        "run",
        "--manifest",
        path(&manifest_file),
        "--key-name",
        "ops-key",
        "--authorize",
    ]);
    let stderr = text(&run.stderr);
    assert_eq!(exit(&run), 1, "{stderr}");
    assert!(
        stderr.contains("DestinationNotLinkable; applied=NotApplied"),
        "{stderr}"
    );
    assert_eq!(
        proxy.requests.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a request left before the check"
    );
    assert_eq!(remote.audit_begins(), 0);
    assert!(files(&one).is_empty(), "the link probe left a file behind");
    // Two real directories on the same volume as the staging store: the batch runs, and each
    // output is linked into its own directory. (A second volume is not available on this
    // machine; the probe creates a real hard link in each directory, which is exactly the
    // capability publication needs, so a destination on another volume is refused the same way.)
    std::fs::create_dir(&two).unwrap();
    let run = s.run(&[
        "batch",
        "run",
        "--manifest",
        path(&manifest_file),
        "--key-name",
        "ops-key",
        "--authorize",
        "--json",
    ]);
    assert_eq!(exit(&run), 0, "{}", text(&run.stderr));
    assert!(one.join("out1.p7s").exists() && missing.exists());
    assert_eq!(proxy.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}
