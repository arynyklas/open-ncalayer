//! The product under test: the `oncl` binary, run as a process with the matrix's trust
//! configuration. Nothing of the SDK is linked into the checks: a verdict is what the
//! shipped program prints and exits with.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::Value;

use super::tools::{Out, exec};
use super::world::{Signer, World};

/// The exit codes of `oncl` (docs/user/cli.md).
pub const VALID: i32 = 0;
pub const INVALID: i32 = 2;
pub const INDETERMINATE: i32 = 3;

pub struct Oncl {
    pub bin: PathBuf,
}

/// A finished `oncl verify`: its exit code and the JSON report on stdout.
pub struct Verified {
    pub out: Out,
    pub report: Value,
}

impl Verified {
    pub fn code(&self) -> Option<i32> {
        self.out.code
    }

    pub fn verdict(&self) -> &str {
        self.report["verdict"].as_str().unwrap_or("?")
    }

    pub fn signers(&self) -> &[Value] {
        self.report["signers"].as_array().map_or(&[], Vec::as_slice)
    }

    /// The state of one per-signer check (`signature`, `chain`, `validity`, `revocation`,
    /// `timestamp`, `key_usage`) of signer `index`.
    pub fn check(&self, index: usize, name: &str) -> &str {
        self.signers()
            .get(index)
            .and_then(|s| s[name].as_str())
            .unwrap_or("?")
    }

    /// The reasons of signer `index`: a debug-formatted list such as
    /// `[CertificateValidity, UntrustedChain]`.
    pub fn reasons(&self, index: usize) -> &str {
        self.signers()
            .get(index)
            .and_then(|s| s["reasons"].as_str())
            .unwrap_or("?")
    }

    /// One line for the report.
    pub fn summary(&self) -> String {
        let signers: Vec<String> = (0..self.signers().len())
            .map(|i| {
                format!(
                    "sig={} chain={} validity={} rev={} ts={}",
                    self.check(i, "signature"),
                    self.check(i, "chain"),
                    self.check(i, "validity"),
                    self.check(i, "revocation"),
                    self.check(i, "timestamp"),
                )
            })
            .collect();
        format!(
            "exit {:?} verdict={} [{}]",
            self.code(),
            self.verdict(),
            signers.join(" | ")
        )
    }
}

impl Oncl {
    pub fn new(bin: PathBuf) -> Self {
        Self { bin }
    }

    /// Runs `oncl <args>` as given.
    pub fn run<S: AsRef<str>>(&self, args: &[S]) -> anyhow::Result<Out> {
        let mut command = Command::new(&self.bin);
        command
            .args(args.iter().map(AsRef::as_ref))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY");
        exec(&mut command, b"", Duration::from_secs(3600))
    }

    /// `oncl --json verify` with the matrix's trust; extra arguments follow.
    pub fn verify<S: AsRef<str>>(
        &self,
        world: &World,
        profile: &str,
        input: &Path,
        extra: &[S],
    ) -> anyhow::Result<Verified> {
        let mut args: Vec<String> = vec!["--json".into()];
        args.extend(world.trust_args());
        args.extend(["verify".into(), "--profile".into(), profile.into()]);
        args.extend(["--input".into(), path_str(input)?.into()]);
        args.extend(extra.iter().map(|s| s.as_ref().to_owned()));
        let out = self.run(&args)?;
        let report = serde_json::from_slice(&out.stdout).with_context(|| {
            format!(
                "oncl verify --profile {profile} of a {}-byte input printed no JSON report: {}",
                std::fs::metadata(input).map_or(0, |m| m.len()),
                out.brief()
            )
        })?;
        Ok(Verified { out, report })
    }

    /// `oncl sign` of `input` with `signer` into `output`; trust options and `extra`
    /// follow. Fails unless it exits 0.
    pub fn sign<S: AsRef<str>>(
        &self,
        world: &World,
        profile: &str,
        signer: &Signer,
        input: &Path,
        output: &Path,
        extra: &[S],
    ) -> anyhow::Result<Out> {
        let out = self.sign_raw(world, profile, signer, input, output, extra)?;
        if !out.ok() {
            bail!("oncl sign --profile {profile} failed: {}", out.brief());
        }
        Ok(out)
    }

    /// Like [`Oncl::sign`] but returns the outcome whatever the exit code.
    pub fn sign_raw<S: AsRef<str>>(
        &self,
        world: &World,
        profile: &str,
        signer: &Signer,
        input: &Path,
        output: &Path,
        extra: &[S],
    ) -> anyhow::Result<Out> {
        let mut args: Vec<String> = world.trust_args();
        args.extend(["sign".into(), "--profile".into(), profile.into()]);
        args.extend(["--input".into(), path_str(input)?.into()]);
        args.extend(["--output".into(), path_str(output)?.into()]);
        args.extend(["--key".into(), path_str(&signer.p12)?.into()]);
        args.extend(["--secret-file".into(), path_str(&world.secret)?.into()]);
        args.push("--authorize".into());
        args.extend(extra.iter().map(|s| s.as_ref().to_owned()));
        self.run(&args)
    }

    /// `oncl --version`.
    pub fn version(&self) -> anyhow::Result<String> {
        Ok(self.run(&["--version"])?.stdout_text().trim().to_owned())
    }
}

pub fn path_str(path: &Path) -> anyhow::Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not UTF-8", path.display()))
}
