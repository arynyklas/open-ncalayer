//! One operation on one surface, run as a measured process, and its normalized outcome.

use super::env::{Env, HttpServer, ServerSettings};
use crate::platform::measure::{Feed, Measured, RunOptions, Running, parse_result_line};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Target {
    Sdk,
    Cli,
    Http,
}

impl Target {
    pub fn name(self) -> &'static str {
        match self {
            Target::Sdk => "sdk",
            Target::Cli => "cli",
            Target::Http => "http",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Cms,
    Cades(Level),
    Xml,
    Xades(Level),
    Wsse,
    Pdf,
    Pades(Level),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    B,
    T,
    Lt,
    Lta,
}

impl Level {
    pub fn text(self) -> &'static str {
        match self {
            Level::B => "b",
            Level::T => "t",
            Level::Lt => "lt",
            Level::Lta => "lta",
        }
    }
}

impl Profile {
    /// The CLI `--profile` value and the SDK probe family name.
    pub fn family(self) -> (&'static str, Option<Level>) {
        match self {
            Profile::Cms => ("cms", None),
            Profile::Cades(l) => ("cades", Some(l)),
            Profile::Xml => ("xml", None),
            Profile::Xades(l) => ("xades", Some(l)),
            Profile::Wsse => ("wsse", None),
            Profile::Pdf => ("pdf", None),
            Profile::Pades(l) => ("pades", Some(l)),
        }
    }

    pub fn cli_name(self) -> String {
        match self.family() {
            (f, Some(l)) => format!("{f}-{}", l.text()),
            (f, None) => f.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Op {
    Hash(&'static str),
    Sign(Profile),
    Verify(Profile),
    Extract,
    /// `cms`, `xml` or `pdf` extension to a level.
    Extend(&'static str, Level),
}

#[derive(Clone, Debug)]
pub enum Input {
    /// A file, with its length known (seekable).
    File(PathBuf),
    /// A file streamed through stdin / a chunked upload: no length is ever declared.
    Unknown(PathBuf),
    /// `len` bytes of one repeated byte through stdin.
    Pattern { byte: u8, len: u64 },
}

#[derive(Clone, Debug, Default)]
pub enum Cancel {
    #[default]
    No,
    /// SDK: the probe's control cancels after this many bytes.
    SdkAfterBytes(u64),
    /// CLI / HTTP client: CTRL_BREAK once the surface's scratch holds this many bytes.
    WhenScratchBytes(u64),
}

#[derive(Clone, Debug)]
pub struct Spec {
    pub op: Op,
    pub input: Input,
    pub detached: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub gost_key: bool,
    pub target_id: Option<String>,
    pub attached: bool,
    pub output_limit: Option<u64>,
    pub input_limit: Option<u64>,
    pub cancel: Cancel,
    /// Scratch directory the operation's temporary store is in (overrides the case default).
    pub temp_limit: Option<u64>,
    pub timeout_seconds: Option<u64>,
    pub with_evidence: bool,
}

impl Spec {
    pub fn new(op: Op, input: Input) -> Self {
        Self {
            op,
            input,
            detached: None,
            output: None,
            gost_key: false,
            target_id: None,
            attached: false,
            output_limit: None,
            input_limit: None,
            cancel: Cancel::No,
            temp_limit: None,
            timeout_seconds: None,
            with_evidence: false,
        }
    }

    pub fn output(mut self, path: impl Into<PathBuf>) -> Self {
        self.output = Some(path.into());
        self
    }

    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.detached = Some(path.into());
        self
    }

    pub fn target(mut self, id: &str) -> Self {
        self.target_id = Some(id.to_owned());
        self
    }

    pub fn gost(mut self) -> Self {
        self.gost_key = true;
        self
    }

    pub fn attached(mut self) -> Self {
        self.attached = true;
        self
    }
}

/// What an operation did, whatever the surface.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Outcome {
    pub exit: Option<i32>,
    pub completed: bool,
    pub code: Option<String>,
    pub applied: Option<String>,
    pub verdict: Option<String>,
    pub signature_checks: Vec<String>,
    pub digest: Option<String>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub bytes_written: Option<u64>,
    pub key_begins: Option<u64>,
    pub key_applied: Option<u64>,
    pub reference_lens: Vec<u64>,
    pub stderr_line: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcRecord {
    pub role: String,
    pub command: String,
    pub exit: Option<i32>,
    pub wall_seconds: f64,
    pub peak_working_set: u64,
    pub peak_private: u64,
    pub criterion_bytes: u64,
    pub sampled_max: u64,
    pub temp_peak_bytes: Option<u64>,
    pub temp_final_bytes: Option<u64>,
    pub temp_final_files: Option<u64>,
    pub timed_out: bool,
    pub interrupted: bool,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub surface: &'static str,
    pub title: String,
    pub status: &'static str,
    pub seconds: f64,
    pub processes: Vec<ProcRecord>,
    pub checks: Vec<Check>,
    pub evidence: Map<String, Value>,
    pub max_criterion_bytes: u64,
}

fn tail(bytes: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    if text.len() <= max {
        text.to_owned()
    } else {
        let mut start = text.len() - max;
        while !text.is_char_boundary(start) {
            start += 1;
        }
        format!("…{}", &text[start..])
    }
}

/// A case in progress: its surface, its processes, its checks and its evidence.
pub struct Case<'e> {
    pub env: &'e Env,
    pub target: Target,
    pub id: String,
    pub title: String,
    started: Instant,
    pub procs: Vec<ProcRecord>,
    pub checks: Vec<Check>,
    pub evidence: Map<String, Value>,
    pub work: PathBuf,
    pub scratch: PathBuf,
    pub server: Option<HttpServer>,
    pub server_settings: ServerSettings,
    pub blocked: Option<String>,
    /// For HTTP cases: how many BEGIN records the audit journal must hold.
    pub expect_begins: Option<u64>,
}

impl<'e> Case<'e> {
    pub fn new(env: &'e Env, target: Target, id: &str, title: &str) -> anyhow::Result<Self> {
        let key = format!("{}-{id}", target.name());
        let work = env.work_dir.join(&key);
        let scratch = env.scratch_root.join(&key);
        for dir in [&work, &scratch] {
            if dir.exists() {
                std::fs::remove_dir_all(dir)?;
            }
            std::fs::create_dir_all(dir)?;
        }
        Ok(Self {
            env,
            target,
            id: id.to_owned(),
            title: title.to_owned(),
            started: Instant::now(),
            procs: Vec::new(),
            checks: Vec::new(),
            evidence: Map::new(),
            work,
            scratch,
            server: None,
            server_settings: ServerSettings::control(&env.args, env.timeout_seconds),
            blocked: None,
            expect_begins: None,
        })
    }

    pub fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        let detail = detail.into();
        eprintln!(
            "[platform-proof]   {} {}/{}: {name}{}",
            if ok { "ok  " } else { "FAIL" },
            self.target.name(),
            self.id,
            if detail.is_empty() {
                String::new()
            } else {
                format!(" ({detail})")
            }
        );
        self.checks.push(Check {
            name: name.to_owned(),
            ok,
            detail,
        });
    }

    pub fn note(&mut self, key: &str, value: Value) {
        self.evidence.insert(key.to_owned(), value);
    }

    pub fn record(&mut self, role: &str, command: &str, m: &Measured) {
        eprintln!(
            "[platform-proof]   process {role}: exit {:?}, {:.1}s, peak working set {} MiB, peak private {} MiB{}",
            m.exit,
            m.wall.as_secs_f64(),
            m.peaks.peak_working_set >> 20,
            m.peaks.peak_private >> 20,
            m.temp
                .as_ref()
                .map(|t| format!(", temp peak {} MiB", t.peak_bytes >> 20))
                .unwrap_or_default()
        );
        self.procs.push(ProcRecord {
            role: role.to_owned(),
            command: command.to_owned(),
            exit: m.exit,
            wall_seconds: m.wall.as_secs_f64(),
            peak_working_set: m.peaks.peak_working_set,
            peak_private: m.peaks.peak_private,
            criterion_bytes: m.peaks.criterion(),
            sampled_max: m.peaks.sampled_max,
            temp_peak_bytes: m.temp.as_ref().map(|t| t.peak_bytes),
            temp_final_bytes: m.temp.as_ref().map(|t| t.final_bytes),
            temp_final_files: m.temp.as_ref().map(|t| t.final_files),
            timed_out: m.timed_out,
            interrupted: m.interrupted,
            stdout_tail: tail(&m.stdout, 1200),
            stderr_tail: tail(&m.stderr, 1200),
        });
    }

    /// Fails the case unless the scratch holds no file (cleanup after the operation).
    pub fn check_scratch_clean(&mut self, label: &str) {
        let (bytes, files) = crate::platform::measure::tree_usage(&self.scratch);
        self.check(
            label,
            files == 0,
            format!("{files} files, {bytes} bytes left in the scratch"),
        );
    }

    pub fn finish(mut self) -> CaseResult {
        if let Some(mut server) = self.server.take() {
            match server.stop() {
                Ok(measured) => {
                    self.record("oncl-server", "oncl-server serve", &measured);
                    let out = String::from_utf8_lossy(&measured.stdout).into_owned();
                    self.check(
                        "server stopped gracefully",
                        measured.exit == Some(0) && out.contains("stopped"),
                        out.trim().to_owned(),
                    );
                }
                Err(e) => self.check("server stopped gracefully", false, e.to_string()),
            }
            match server.audit_counts() {
                Ok(c) => {
                    self.note("audit", json!(c));
                    self.check(
                        "the durable audit journal has a FINAL for every BEGIN",
                        c.begin == c.finals,
                        format!("{c:?}"),
                    );
                    if let Some(expected) = self.expect_begins {
                        self.check(
                            "the durable audit journal shows the expected number of key uses",
                            c.begin == expected,
                            format!("{c:?}, expected {expected} BEGIN"),
                        );
                    }
                }
                Err(e) => self.check("audit journal readable", false, e.to_string()),
            }
            let (bytes, files) = crate::platform::measure::tree_usage(&server.scratch);
            self.check(
                "server scratch is empty after the server stopped",
                files == 0,
                format!("{files} files, {bytes} bytes"),
            );
        }
        let max_rss = self.env.args.max_rss_bytes;
        let max = self
            .procs
            .iter()
            .map(|p| p.criterion_bytes)
            .max()
            .unwrap_or(0);
        let over: Vec<_> = self
            .procs
            .iter()
            .filter(|p| p.criterion_bytes > max_rss)
            .map(|p| format!("{} {} MiB", p.role, p.criterion_bytes >> 20))
            .collect();
        if !over.is_empty() {
            self.check(
                "every process stays within --max-rss-bytes",
                false,
                over.join(", "),
            );
        }
        let status = if let Some(reason) = &self.blocked {
            self.evidence.insert("blocked".into(), json!(reason));
            "BLOCKED"
        } else if self.checks.iter().all(|c| c.ok) {
            "PASS"
        } else {
            "FAIL"
        };
        CaseResult {
            id: self.id,
            surface: self.target.name(),
            title: self.title,
            status,
            seconds: self.started.elapsed().as_secs_f64(),
            processes: self.procs,
            checks: self.checks,
            evidence: self.evidence,
            max_criterion_bytes: max,
        }
    }

    pub fn ensure_server(&mut self) -> anyhow::Result<()> {
        if self.server.is_none() {
            let base = self.work.join("server");
            std::fs::create_dir_all(&base)?;
            let server = HttpServer::start(self.env, &base, &self.server_settings)?;
            // The HTTP case's scratch is the server's own spool directory.
            self.scratch = server.scratch.clone();
            self.server = Some(server);
        }
        Ok(())
    }

    /// Runs one operation and returns its normalized outcome; every process is recorded.
    pub fn op(&mut self, spec: &Spec) -> anyhow::Result<Outcome> {
        let env = self.env;
        let (mut command, role, redacted) = match self.target {
            Target::Sdk => sdk_command(env, spec, &self.scratch),
            Target::Cli => cli_command(env, spec, &self.scratch, None),
            Target::Http => {
                self.ensure_server()?;
                let server = self.server.as_ref().unwrap();
                cli_command(
                    env,
                    spec,
                    &self.scratch,
                    Some((&server.endpoint(), &server.token_file)),
                )
            }
        };
        command.env_remove("ONCL_PY_TOOLS");
        let feed = match &spec.input {
            Input::File(_) => Feed::None,
            Input::Unknown(path) if self.target == Target::Sdk => {
                let _ = path;
                Feed::None
            }
            Input::Unknown(path) => Feed::File(path.clone()),
            Input::Pattern { byte, len } => Feed::Pattern {
                byte: *byte,
                len: *len,
            },
        };
        let watch = Some(self.scratch.clone());
        let interrupt_when: Option<Box<dyn FnMut() -> bool + Send>> =
            match (&spec.cancel, self.target) {
                (Cancel::WhenScratchBytes(bytes), Target::Cli | Target::Http) => {
                    let dir = self.scratch.clone();
                    let bytes = *bytes;
                    Some(Box::new(move || {
                        crate::platform::measure::tree_usage(&dir).0 >= bytes
                    }))
                }
                _ => None,
            };
        let measured = Running::spawn(
            command,
            RunOptions {
                timeout: Duration::from_secs(
                    spec.timeout_seconds.unwrap_or(env.timeout_seconds) + 600,
                ),
                feed,
                watch,
                interrupt_when,
                stdin_piped: false,
            },
        )?
        .wait()?;
        self.record(&role, &redacted, &measured);
        let outcome = parse_outcome(self.target, &measured, spec);
        let name = format!("{}-{}", self.target.name(), self.id);
        let log = env.log_dir.join(format!("{name}-{}.log", self.procs.len()));
        let _ = std::fs::write(
            log,
            format!(
                "{redacted}\nexit={:?}\n--- stdout\n{}\n--- stderr\n{}\n",
                measured.exit,
                String::from_utf8_lossy(&measured.stdout),
                String::from_utf8_lossy(&measured.stderr)
            ),
        );
        Ok(outcome)
    }
}

fn level_flag(spec: &Spec) -> Option<&'static str> {
    match &spec.op {
        Op::Sign(p) | Op::Verify(p) => p.family().1.map(Level::text),
        Op::Extend(_, l) => Some(l.text()),
        _ => None,
    }
}

fn sdk_command(env: &Env, spec: &Spec, scratch: &Path) -> (Command, String, String) {
    let mut c = Command::new(&env.bins.probe);
    c.arg("large");
    let name = match &spec.op {
        Op::Hash(_) => "hash".to_owned(),
        Op::Extract => "extract".to_owned(),
        Op::Extend(..) => "extend".to_owned(),
        Op::Sign(p) => format!("{}-sign", p.family().0),
        Op::Verify(p) => format!("{}-verify", p.family().0),
    };
    c.arg(&name);
    match &spec.input {
        Input::File(p) => {
            c.arg("--input").arg(p);
        }
        Input::Unknown(p) => {
            c.arg("--input").arg(p).arg("--unknown-length");
        }
        Input::Pattern { .. } => {
            c.args(["--input", "-"]);
        }
    }
    if let Op::Hash(alg) = &spec.op {
        c.args([
            "--algorithm",
            if *alg == "gost" { "streebog512" } else { alg },
        ]);
    }
    if let Some(l) = level_flag(spec) {
        c.args(["--level", l]);
    }
    if let Op::Extend(format, _) = &spec.op {
        c.args(["--target", format]);
    }
    if let Some(t) = &spec.target_id {
        c.args(["--target", t]);
    }
    if let Some(d) = &spec.detached {
        c.arg("--detached").arg(d);
    }
    if let Some(o) = &spec.output {
        c.arg("--output").arg(o);
    }
    if spec.attached {
        c.arg("--attached");
    }
    if spec.gost_key {
        c.args(["--key", "gost"]);
    }
    if let Some(n) = spec.input_limit {
        c.args(["--input-limit", &n.to_string()]);
    }
    if let Some(n) = spec.output_limit {
        c.args(["--output-limit", &n.to_string()]);
    }
    if let Some(n) = spec.temp_limit {
        c.args(["--temp-limit", &n.to_string()]);
    }
    if let Cancel::SdkAfterBytes(n) = spec.cancel {
        c.args(["--cancel-after-bytes", &n.to_string()]);
    }
    c.args([
        "--timeout-seconds",
        &spec
            .timeout_seconds
            .unwrap_or(env.timeout_seconds)
            .to_string(),
    ]);
    c.arg("--pki")
        .arg(&env.pki.dir)
        .arg("--scratch")
        .arg(scratch);
    (c, "sdk_probe".into(), format!("sdk_probe large {name}"))
}

fn cli_command(
    env: &Env,
    spec: &Spec,
    scratch: &Path,
    remote: Option<(&str, &Path)>,
) -> (Command, String, String) {
    let mut c = Command::new(&env.bins.oncl);
    c.arg("--json");
    let timeout = spec.timeout_seconds.unwrap_or(env.timeout_seconds);
    c.args(["--timeout-seconds", &timeout.to_string()]);
    let mut label = String::from("oncl");
    if let Some((endpoint, token)) = remote {
        c.args(["--endpoint", endpoint])
            .arg("--token-file")
            .arg(token);
        label.push_str(" --endpoint");
    } else {
        c.arg("--root").arg(env.pki.dir.join("root.cer"));
        c.args(["--pki-endpoint", &env.pki.meta.origin]);
        c.arg("--temporary-directory").arg(scratch);
        if matches!(spec.op, Op::Extend(..))
            || matches!(&spec.op, Op::Sign(p) if level_of(*p) > Some(Level::B))
        {
            c.args([
                "--tsa-url",
                &env.pki.meta.tsa_url,
                "--tsa-policy",
                &env.pki.meta.tsa_policy,
            ]);
        }
    }
    if matches!(spec.op, Op::Extend(..)) || spec.with_evidence {
        let dir = &env.pki.dir;
        let leaf = if spec.gost_key {
            "leaf-gost.ocsp"
        } else {
            "leaf-rsa.ocsp"
        };
        c.arg("--evidence-certificate").arg(dir.join("root.cer"));
        c.arg("--evidence-certificate").arg(dir.join("tsa.der"));
        c.arg("--evidence-ocsp").arg(dir.join(leaf));
        c.arg("--evidence-ocsp").arg(dir.join("tsa.ocsp"));
    }
    if let Some(n) = spec.output_limit {
        c.args(["--output-limit", &n.to_string()]);
    }
    let input = match &spec.input {
        Input::File(p) => p.clone().into_os_string(),
        Input::Unknown(_) | Input::Pattern { .. } => OsString::from("-"),
    };
    match &spec.op {
        Op::Hash(alg) => {
            let alg = match *alg {
                "gost" => "gost2015-512",
                other => other,
            };
            c.args(["hash", "--algorithm", alg])
                .arg("--input")
                .arg(&input);
        }
        Op::Extract => {
            c.arg("extract").arg("--input").arg(&input);
            c.arg("--output")
                .arg(spec.output.clone().unwrap_or_default());
        }
        Op::Verify(p) => {
            c.args(["verify", "--profile", &p.cli_name()])
                .arg("--input")
                .arg(&input);
            if let Some(d) = &spec.detached {
                c.arg("--detached").arg(d);
            }
        }
        Op::Extend(format, level) => {
            c.args(["extend", "--profile", format, "--level", level.text()]);
            c.arg("--input").arg(&input);
            c.arg("--output")
                .arg(spec.output.clone().unwrap_or_default());
            if let Some(d) = &spec.detached {
                c.arg("--detached").arg(d);
            }
        }
        Op::Sign(p) => {
            c.args(["sign", "--profile", &p.cli_name()])
                .arg("--input")
                .arg(&input);
            c.arg("--output")
                .arg(spec.output.clone().unwrap_or_default());
            if matches!(p, Profile::Cms | Profile::Cades(_)) && !spec.attached {
                c.arg("--detached");
            }
            if let Some(t) = &spec.target_id {
                c.args(["--target-id", t]);
            }
            if matches!(p, Profile::Xades(_)) {
                // XAdES needs an explicit signature Id
                c.args(["--signature-id", "oncl-proof-signature"]);
            }
            let name = if spec.gost_key { "gost" } else { "rsa" };
            if remote.is_some() {
                c.args(["--key-name", name]);
            } else {
                c.arg("--key").arg(env.pki.dir.join(format!("{name}.p12")));
                c.arg("--secret-file").arg(&env.secret_file);
            }
            c.arg("--authorize");
        }
    }
    (c, "oncl".into(), label)
}

fn level_of(p: Profile) -> Option<Level> {
    p.family().1.map(|l| match l {
        Level::B => Level::B,
        other => other,
    })
}

impl PartialOrd for Level {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let rank = |l: &Level| match l {
            Level::B => 0,
            Level::T => 1,
            Level::Lt => 2,
            Level::Lta => 3,
        };
        rank(self).partial_cmp(&rank(other))
    }
}

fn parse_outcome(target: Target, m: &Measured, spec: &Spec) -> Outcome {
    let stdout = m.stdout_text();
    let stderr = m.stderr_text();
    let mut o = Outcome {
        exit: m.exit,
        ..Outcome::default()
    };
    if target == Target::Sdk {
        if let Some(j) = parse_result_line(&stdout, "ONCL-PROOF-RESULT ") {
            o.completed = j["ok"].as_bool().unwrap_or(false);
            o.code = j["error"]["code"].as_str().map(str::to_owned);
            o.applied = j["applied"]
                .as_str()
                .or_else(|| j["error"]["applied"].as_str())
                .map(str::to_owned);
            o.verdict = j["verdict"].as_str().map(str::to_owned);
            if let Some(signers) = j["signers"].as_array() {
                o.signature_checks = signers
                    .iter()
                    .map(|s| s["signature"].as_str().unwrap_or("?").to_owned())
                    .collect();
            }
            o.digest = j["digest"].as_str().map(str::to_owned);
            o.bytes_in = j["bytes_in"].as_u64();
            o.bytes_out = j["bytes_out"].as_u64();
            o.bytes_written = j["bytes_written"].as_u64();
            o.key_begins = j["key_begins"].as_u64();
            o.key_applied = j["key_applied"].as_u64();
            if let Some(refs) = j["xml_references"].as_array() {
                o.reference_lens = refs
                    .iter()
                    .filter_map(|r| r["target_len"].as_u64())
                    .collect();
            }
        }
        return o;
    }
    let json = stdout
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<Value>(l).ok());
    let diag = stderr
        .lines()
        .rev()
        .find(|l| l.starts_with("oncl: "))
        .unwrap_or("");
    o.stderr_line = diag.to_owned();
    if let Some(rest) = diag.strip_prefix("oncl: ") {
        let (code, applied) = rest.split_once("; applied=").unwrap_or((rest, ""));
        o.code = Some(code.to_owned());
        if !applied.is_empty() {
            o.applied = Some(applied.to_owned());
        }
    }
    let verify = matches!(spec.op, Op::Verify(_));
    o.completed = if verify {
        matches!(m.exit, Some(0 | 2 | 3)) && json.is_some()
    } else {
        m.exit == Some(0) && json.is_some()
    };
    if let Some(j) = json {
        if o.completed {
            o.code = j["code"].as_str().map(str::to_owned).or(o.code);
            o.applied = j["applied"].as_str().map(str::to_owned).or(o.applied);
        }
        o.verdict = j["verdict"].as_str().map(str::to_owned);
        if let Some(signers) = j["signers"].as_array() {
            o.signature_checks = signers
                .iter()
                .map(|s| s["signature"].as_str().unwrap_or("?").to_owned())
                .collect();
        }
        o.digest = j["digest"].as_str().map(str::to_owned);
        o.bytes_in = j["bytes_in"].as_u64();
        o.bytes_out = j["bytes_out"].as_u64();
        o.bytes_written = j["bytes_written"].as_u64();
    }
    o
}

/// `true` when `outcome` is the typed refusal `code` with the key never applied.
pub fn refused(outcome: &Outcome, code: &str) -> bool {
    !outcome.completed
        && outcome.code.as_deref().is_some_and(|c| c.contains(code))
        && outcome.applied.as_deref().is_none_or(|a| a == "NotApplied")
}
