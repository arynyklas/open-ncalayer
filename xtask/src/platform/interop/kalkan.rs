//! The Kalkan oracle: the real Kalkan JCE provider (and its XMLDSig configuration for Apache
//! Santuario) as an independent GOST R 34.10-2004 / 34.10-2015 verifier of signatures made by
//! `oncl` and by NCANode (docs/dev/platform-interop.md).
//!
//! It is LOCAL-ONLY. The Kalkan jars carry no licence text and the NCA asked for them to be
//! removed from public repositories, so they are never committed, never copied into the
//! repository or into an image: the operator's copies (those of an installed NCALayer) are
//! named by environment variables, and the descriptor in `coverage.toml` pins their sha256.
//! Without them, or with different bytes, every row that needs the oracle is `BLOCKED` with
//! exactly what is missing. The verifier itself is `xtask/assets/platform-interop/
//! KalkanOracle.java`, compiled by the JDK's source launcher at run time.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::Value;

use super::OracleDescriptor;
use super::tools::{self, Out, sha256_file};

/// The Java source of the verifier (single file, run with the source launcher).
pub const SOURCE: &str = include_str!("../../../assets/platform-interop/KalkanOracle.java");

/// File name the source must have (the public class is `KalkanOracle`).
pub const SOURCE_FILE: &str = "KalkanOracle.java";

/// Environment variable naming the Java launcher (default: `java` on the path).
pub const JAVA_ENV: &str = "ONCL_KALKAN_JAVA";

/// The oldest Java the verifier needs (switch expressions, pattern `instanceof`, the source
/// launcher).
const MIN_JAVA: u32 = 17;

/// A pinned file of an oracle that is supplied by the operator, never by the repository.
#[derive(Debug, Deserialize)]
pub struct Artifact {
    /// The environment variable that names the file.
    pub env: String,
    /// What it is, for the message of a missing or different file.
    pub name: String,
    /// Hex sha256 of the exact bytes.
    pub sha256: String,
}

/// A usable Kalkan oracle: the Java launcher and the verified classpath.
#[derive(Debug, Clone)]
pub struct Kalkan {
    pub java: PathBuf,
    pub classpath: OsString,
}

impl Kalkan {
    /// Finds and checks everything the oracle needs; `Err` is the exact reason it cannot
    /// serve (what the `BLOCKED` row says).
    pub fn discover(descriptor: &OracleDescriptor) -> Result<Kalkan, String> {
        let classpath = locate_jars(descriptor, |name| std::env::var_os(name))?;
        let java = std::env::var_os(JAVA_ENV).map_or_else(|| PathBuf::from("java"), PathBuf::from);
        check_java(&java)?;
        Ok(Kalkan { java, classpath })
    }
}

/// The classpath of the descriptor's jars, each looked up through `env` and compared with
/// its pinned sha256.
pub fn locate_jars(
    descriptor: &OracleDescriptor,
    env: impl Fn(&str) -> Option<OsString>,
) -> Result<OsString, String> {
    if descriptor.artifact.is_empty() {
        return Err(format!(
            "the descriptor of {} pins no artifact",
            descriptor.id
        ));
    }
    let mut paths = Vec::new();
    for artifact in &descriptor.artifact {
        let Some(path) = env(&artifact.env).filter(|p| !p.is_empty()) else {
            return Err(format!(
                "{} is not set: the Kalkan oracle is local-only (the jar has no licence text and \
                 is never committed or redistributed); point it at the {} of an installed \
                 NCALayer (sha256 {})",
                artifact.env, artifact.name, artifact.sha256
            ));
        };
        let path = PathBuf::from(path);
        if !path.is_file() {
            return Err(format!(
                "{}={} is not a file ({})",
                artifact.env,
                path.display(),
                artifact.name
            ));
        }
        let found = sha256_file(&path).map_err(|e| format!("{}: {e:#}", path.display()))?;
        if !found.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(format!(
                "{}={} has sha256 {found}, the descriptor pins {} for the {}",
                artifact.env,
                path.display(),
                artifact.sha256,
                artifact.name
            ));
        }
        paths.push(path);
    }
    std::env::join_paths(paths).map_err(|e| format!("the classpath cannot be built: {e}"))
}

/// The major version in the output of `java -version` (`openjdk version "17.0.20.1" ...`,
/// `java version "1.8.0_x"`).
pub fn java_major(version_output: &str) -> Option<u32> {
    let quoted = version_output.split('"').nth(1)?;
    let mut parts = quoted.split(['.', '_', '-', '+']);
    let first: u32 = parts.next()?.parse().ok()?;
    if first == 1 {
        parts.next()?.parse().ok()
    } else {
        Some(first)
    }
}

fn check_java(java: &Path) -> Result<(), String> {
    let unusable = |why: String| {
        format!(
            "{} cannot run the Kalkan oracle: {why} (a JDK {MIN_JAVA}+ with the jdk.compiler \
             module; set {JAVA_ENV} to its `java`)",
            java.display()
        )
    };
    let mut version = std::process::Command::new(java);
    version.arg("-version");
    let out = tools::exec(&mut version, b"", std::time::Duration::from_secs(30))
        .map_err(|e| unusable(format!("{e:#}")))?;
    let text = format!("{}{}", out.stdout_text(), out.stderr);
    let major = java_major(&text).ok_or_else(|| {
        unusable(format!(
            "`java -version` is not understood: {}",
            out.brief()
        ))
    })?;
    if major < MIN_JAVA {
        return Err(unusable(format!("it is Java {major}")));
    }
    let mut modules = std::process::Command::new(java);
    modules.arg("--list-modules");
    let out = tools::exec(&mut modules, b"", std::time::Duration::from_secs(30))
        .map_err(|e| unusable(format!("{e:#}")))?;
    if !out.stdout_text().contains("jdk.compiler") {
        return Err(unusable("it has no jdk.compiler module".to_owned()));
    }
    Ok(())
}

/// The verifier's answer: one JSON object on stdout. `{"error": ...}` (exit 2) means the
/// oracle itself failed (never a verdict about a signature); otherwise `ok` is the verdict.
pub fn parse_answer(out: &Out) -> anyhow::Result<Value> {
    let text = out.stdout_text();
    let answer: Value = serde_json::from_str(text.trim()).with_context(|| {
        format!(
            "the Kalkan oracle printed no JSON answer: {}",
            out.brief().chars().take(600).collect::<String>()
        )
    })?;
    if let Some(error) = answer.get("error") {
        bail!("the Kalkan oracle could not run: {error}");
    }
    if out.code != Some(0) {
        bail!(
            "the Kalkan oracle exited {:?} with an answer: {answer}",
            out.code
        );
    }
    if !answer["ok"].is_boolean() {
        bail!("the Kalkan oracle's answer has no verdict `ok`: {answer}");
    }
    Ok(answer)
}

/// `ok` of a parsed answer.
pub fn verdict(answer: &Value) -> bool {
    answer["ok"] == true
}

/// One word for a `wsse` answer, for the grade: `verified/Body` for a signature that holds,
/// else `rejected/` and what failed (`signature-value`, `digest`).
pub fn wsse_summary(answer: &Value) -> String {
    let signatures = answer["signatures"].as_array().cloned().unwrap_or_default();
    if verdict(answer) {
        let mut nodes: Vec<String> = signatures
            .iter()
            .flat_map(|s| s["references"].as_array().cloned().unwrap_or_default())
            .map(|r| r["node"].as_str().unwrap_or("?").to_owned())
            .collect();
        nodes.dedup();
        return format!("verified/{}", nodes.join("+"));
    }
    let value_failed = signatures.iter().any(|s| s["signature_value_ok"] != true);
    let digest_failed = signatures.iter().any(|s| {
        s["references"]
            .as_array()
            .is_none_or(|r| r.is_empty() || r.iter().any(|r| r["digest_ok"] != true))
    });
    let mut failed = Vec::new();
    if value_failed {
        failed.push("signature-value");
    }
    if digest_failed {
        failed.push("digest");
    }
    if failed.is_empty() {
        failed.push("no-signature");
    }
    format!("rejected/{}", failed.join("+"))
}

/// How a row judged by this oracle is named in the report.
pub const LABEL: &str = "kalkan (local-only, not reproducible in CI)";
