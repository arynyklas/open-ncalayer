//! The configuration shipped in the `oncl-server` package (`deploy/server/server.example.toml`)
//! is what an operator copies first: it must load with the real loader, leave the HTTP API
//! disabled and hold no secret, and its commented samples must stay valid configuration
//! (the loader denies unknown fields, so a renamed option breaks a sample, not a deployment).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use oncl_pki::private_fs::PrivateDirectory;
use oncl_server::config::{Exposure, ServerConfig};

fn example() -> String {
    let path: PathBuf = oncl_testkit::workspace_root().join("deploy/server/server.example.toml");
    String::from_utf8(oncl_testkit::read(path)).expect("the example is UTF-8")
}

/// The example as a private `server.toml`, the only place the loader reads one from.
fn private_copy(directory: &std::path::Path, text: &str) -> PathBuf {
    let operator = directory.join("operator");
    PrivateDirectory::create(&operator)
        .unwrap()
        .create_file("server.toml")
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    operator.join("server.toml")
}

#[test]
fn the_example_loads_disabled_on_loopback_without_secrets() {
    let temporary = tempfile::tempdir().unwrap();
    let path = private_copy(temporary.path(), &example());
    let config = ServerConfig::read(&path).expect("the shipped example is valid configuration");
    assert!(!config.enabled, "the example must not enable the API");
    assert!(config.bind.ip().is_loopback());
    assert!(matches!(config.exposure, Exposure::Loopback));
    assert!(config.tokens.is_empty(), "no token, not even a verifier");
    assert!(config.keys.is_empty(), "no key binding");
    assert!(config.plugins.is_empty());
    assert!(!config.inline_pkcs12);
    assert!(!config.telemetry.enabled);
}

#[test]
fn serving_the_example_opens_no_listener() {
    let temporary = tempfile::tempdir().unwrap();
    let audit = temporary.path().join("audit");
    let scratch = temporary.path().join("scratch");
    // The example, with its state directories somewhere harmless to look at afterwards.
    let text = example()
        .replace(
            "\"/var/lib/oncl-server/audit\"",
            &format!("'{}'", audit.display()),
        )
        .replace(
            "\"/var/lib/oncl-server/scratch\"",
            &format!("'{}'", scratch.display()),
        );
    assert!(text.contains(&audit.display().to_string()));
    let path = private_copy(temporary.path(), &text);
    // The control pipe stays open: a listening service would wait for it and not exit.
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl-server"))
        .args(["serve", "--shutdown-stdin", "--config"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the disabled service kept running"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let output = child.wait_with_output().unwrap();
    assert!(status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("disabled: no listener"), "{stdout}");
    assert!(!stdout.contains("listening"), "{stdout}");
    // Disabled means untouched: no journal, no scratch directory.
    assert!(!audit.exists() && !scratch.exists());
}

/// The commented-out samples: runs of `# ` lines that are TOML, split at bare `#` lines.
fn samples(text: &str) -> Vec<String> {
    let mut samples = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let flush = |current: &mut Vec<String>, samples: &mut Vec<String>| {
        if !current.is_empty() {
            samples.push(current.join("\n"));
            current.clear();
        }
    };
    for line in text.lines() {
        match line.strip_prefix("# ") {
            Some(rest) if is_toml_line(rest) => current.push(rest.to_owned()),
            _ => flush(&mut current, &mut samples),
        }
    }
    flush(&mut current, &mut samples);
    samples
}

fn is_toml_line(line: &str) -> bool {
    line.starts_with('[')
        || line.split_once(" = ").is_some_and(|(key, _)| {
            !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_')
        })
}

#[test]
fn every_commented_sample_is_valid_configuration() {
    let samples = samples(&example());
    // tokens, keys, pki + endpoints, tls, trusted proxy, telemetry
    assert!(samples.len() >= 7, "found only {} samples", samples.len());
    for sample in &samples {
        toml::from_str::<ServerConfig>(sample)
            .unwrap_or_else(|e| panic!("the sample\n{sample}\nis not valid: {e}"));
    }
}
