//! The stand of one run: binaries, the loopback PKI process, private directories, the
//! per-case `oncl-server` process and its audit journal.

use super::{Manifest, ProofArgs};
use crate::platform::measure::{self, Measured, RunOptions, Running};
use anyhow::{Context, bail};
use oncl_pki::private_fs::PrivateDirectory;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

pub struct Bins {
    pub probe: PathBuf,
    pub oncl: PathBuf,
    pub server: PathBuf,
}

impl Bins {
    /// Builds (unless `skip`) and locates the three programs under test, in release mode.
    pub fn prepare(root: &Path, skip: bool) -> anyhow::Result<Self> {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"));
        if !skip {
            for args in [
                &["build", "--release", "-p", "oncl-cli", "-p", "oncl-server"][..],
                &[
                    "build",
                    "--release",
                    "-p",
                    "oncl-core",
                    "--example",
                    "sdk_probe",
                    "--features",
                    "full",
                ][..],
            ] {
                let status = Command::new(std::env::var_os("CARGO").unwrap_or("cargo".into()))
                    .args(args)
                    .current_dir(root)
                    .status()
                    .context("cargo build")?;
                if !status.success() {
                    bail!("cargo {} failed", args.join(" "));
                }
            }
        }
        let exe = |name: &str| format!("{name}{}", std::env::consts::EXE_SUFFIX);
        let bins = Self {
            probe: target.join("release/examples").join(exe("sdk_probe")),
            oncl: target.join("release").join(exe("oncl")),
            server: target.join("release").join(exe("oncl-server")),
        };
        for p in [&bins.probe, &bins.oncl, &bins.server] {
            if !p.is_file() {
                bail!("BLOCKED: {} is missing (build with the release profile)", p.display());
            }
        }
        Ok(bins)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkiMeta {
    pub origin: String,
    pub tsa_url: String,
    pub tsa_policy: String,
    pub password: String,
}

/// The loopback certification authority (`sdk_probe pki-serve`), alive for the whole run.
pub struct PkiServer {
    child: Child,
    pub dir: PathBuf,
    pub meta: PkiMeta,
}

impl PkiServer {
    pub fn start(probe: &Path, dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut child = Command::new(probe)
            .args(["pki-serve", "--out"])
            .arg(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("starting the loopback PKI")?;
        let mut lines = BufReader::new(child.stdout.take().context("pki stdout")?).lines();
        loop {
            match lines.next() {
                Some(Ok(line)) if line == "ready" => break,
                Some(Ok(_)) => continue,
                _ => bail!("the loopback PKI ended before it was ready"),
            }
        }
        // keep draining so the PKI never blocks on a full pipe
        std::thread::spawn(move || for _ in lines {});
        let meta: PkiMeta = serde_json::from_slice(&std::fs::read(dir.join("pki.json"))?)?;
        Ok(Self {
            child,
            dir: dir.to_owned(),
            meta,
        })
    }
}

impl Drop for PkiServer {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Env {
    pub args: ProofArgs,
    pub root: PathBuf,
    pub out: PathBuf,
    pub data_dir: PathBuf,
    pub work_dir: PathBuf,
    pub scratch_root: PathBuf,
    pub log_dir: PathBuf,
    pub python: PathBuf,
    pub oracle: PathBuf,
    pub py_tools: Option<PathBuf>,
    pub bins: Bins,
    pub pki: PkiServer,
    pub secret_file: PathBuf,
    pub manifest: Manifest,
    /// Host operation deadline of every surface for the full-size cases.
    pub timeout_seconds: u64,
}

impl Env {
    pub fn doc(&self, name: &str) -> anyhow::Result<&super::DataSet> {
        self.manifest.set(name)
    }

    /// Runs the Python oracle with the tool path of the environment.
    pub fn oracle(&self, args: &[&std::ffi::OsStr]) -> anyhow::Result<serde_json::Value> {
        let mut command = Command::new(&self.python);
        command.arg(&self.oracle).args(args);
        if let Some(tools) = &self.py_tools {
            command.env("ONCL_PY_TOOLS", tools);
        }
        let output = command.output().context("running the Python oracle")?;
        let text = String::from_utf8_lossy(&output.stdout);
        let value = text
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok());
        match (output.status.success(), value) {
            (true, Some(v)) => Ok(v),
            (_, Some(v)) => bail!("oracle refused: {v}"),
            (_, None) => bail!(
                "oracle failed ({}): {} {}",
                output.status,
                text,
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }
}

/// One `oncl-server` process with its own operator directory, scratch and audit journal.
pub struct HttpServer {
    pub running: Option<Running>,
    pub address: String,
    pub operator: PathBuf,
    pub token_file: PathBuf,
    pub scratch: PathBuf,
    pub audit: PathBuf,
    pub config_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ServerSettings {
    pub max_in_flight: u64,
    pub blocking_workers: usize,
    pub queue_capacity: usize,
    pub admission_wait_ms: u64,
    pub operation_timeout_ms: u64,
    pub memory_per_operation: u64,
    pub total_memory: u64,
    pub temp_per_operation: u64,
    pub total_temp: u64,
    pub input_bytes: u64,
    pub tsa: bool,
    pub max_connections: u32,
    pub telemetry_endpoint: Option<String>,
    /// Keys are the two software cards of `token_host` (this alias) instead of file keys.
    pub token_alias: Option<String>,
}

impl ServerSettings {
    /// The example configuration's budgets (`deploy/server/server.example.toml`), with the
    /// deadline and the temporary quota of the control profile.
    pub fn control(env_args: &ProofArgs, timeout_seconds: u64) -> Self {
        Self {
            max_in_flight: 2,
            blocking_workers: 2,
            queue_capacity: 2,
            admission_wait_ms: 10_000,
            operation_timeout_ms: timeout_seconds * 1000,
            memory_per_operation: 268_435_456,
            total_memory: 536_870_912,
            temp_per_operation: env_args.scratch_bytes,
            total_temp: env_args.scratch_bytes,
            input_bytes: 10_737_418_240,
            tsa: true,
            max_connections: 32,
            telemetry_endpoint: None,
            token_alias: None,
        }
    }
}

fn toml_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\\', "/"))
}

impl HttpServer {
    pub fn start(
        env: &Env,
        base: &Path,
        settings: &ServerSettings,
    ) -> anyhow::Result<Self> {
        let operator = base.join("operator");
        let dir = PrivateDirectory::create(&operator).context("operator directory")?;
        let output = Command::new(&env.bins.server)
            .args(["token-create", "--directory"])
            .arg(&operator)
            .args(["--name", "token"])
            .output()
            .context("token-create")?;
        if !output.status.success() {
            bail!("token-create refused: {}", String::from_utf8_lossy(&output.stderr));
        }
        let stdout = String::from_utf8(output.stdout)?;
        let verifier = stdout
            .trim()
            .strip_prefix("verifier=")
            .context("token-create output")?
            .to_owned();
        for name in ["rsa.p12", "gost.p12"] {
            let bytes = std::fs::read(env.pki.dir.join(name))?;
            dir.create_file(name)?.write_all(&bytes)?;
        }
        dir.create_file("key.password")?
            .write_all(env.pki.meta.password.as_bytes())?;
        let audit = base.join("audit");
        let scratch = base.join("scratch");
        let origin = &env.pki.meta.origin;
        let addr = origin.trim_start_matches("http://");
        let mut config = format!(
            "enabled = true\nbind = '127.0.0.1:0'\naudit_directory = {}\nscratch_directory = {}\n\
             max_in_flight = {}\nblocking_workers = {}\nqueue_capacity = {}\nadmission_wait_ms = {}\n\
             operation_timeout_ms = {}\nmax_connections = {}\ninput_bytes = {}\nmemory_per_operation = {}\n\
             total_memory = {}\ntemp_per_operation = {}\ntotal_temp = {}\n",
            toml_path(&audit),
            toml_path(&scratch),
            settings.max_in_flight,
            settings.blocking_workers,
            settings.queue_capacity,
            settings.admission_wait_ms,
            settings.operation_timeout_ms,
            settings.max_connections,
            settings.input_bytes,
            settings.memory_per_operation,
            settings.total_memory,
            settings.temp_per_operation,
            settings.total_temp,
        );
        config.push_str(&format!(
            "\n[[tokens]]\nid = 'proof-client'\nverifier = '{verifier}'\nactions = ['hash', 'verify', 'extract', 'sign', 'extend']\nkeys = [{}]\n",
            if settings.token_alias.is_some() { "'card-a', 'card-b'" } else { "'rsa', 'gost'" }
        ));
        if let Some(alias) = &settings.token_alias {
            dir.create_file("pin")?.write_all(crate::platform::token_host::PIN.as_bytes())?;
            for (name, reader) in [("card-a", "reader-a"), ("card-b", "reader-b")] {
                config.push_str(&format!(
                    "\n[[keys]]\nsource = 'token'\nname = '{name}'\nreader = '{reader}'\nkind = 'kaztoken'\nalias = {}\nsecret = {{ directory = {}, name = 'pin' }}\n",
                    serde_json::to_string(alias)?,
                    toml_path(&operator),
                ));
            }
        } else {
            for name in ["rsa", "gost"] {
                config.push_str(&format!(
                    "\n[[keys]]\nsource = 'file'\nname = '{name}'\npath = {}\nsecret = {{ directory = {}, name = 'key.password' }}\n",
                    toml_path(&operator.join(format!("{name}.p12"))),
                    toml_path(&operator),
                ));
            }
        }
        config.push_str(&format!(
            "\n[pki]\nanchors = [{}]\n\n[[pki.endpoints]]\norigin = '{origin}'\naddresses = ['{addr}']\n",
            toml_path(&env.pki.dir.join("root.cer")),
        ));
        if settings.tsa {
            config.push_str(&format!(
                "\n[pki.tsa]\nurl = '{}'\npolicy = '{}'\ntimeout_ms = 60000\nskew_ms = 300000\n",
                env.pki.meta.tsa_url, env.pki.meta.tsa_policy
            ));
        }
        if let Some(endpoint) = &settings.telemetry_endpoint {
            config.push_str(&format!(
                "\n[telemetry]\nenabled = true\nendpoint = '{endpoint}'\nexport_interval_ms = 200\ntraces = false\n"
            ));
        }
        dir.create_file("server.toml")?.write_all(config.as_bytes())?;
        let config_path = operator.join("server.toml");
        let mut command = if settings.token_alias.is_some() {
            // the service library with a counting software card: see `token_host`
            let mut c = Command::new(std::env::current_exe().context("current executable")?);
            c.arg("platform-token-host")
                .arg("--config")
                .arg(&config_path)
                .arg("--pki")
                .arg(&env.pki.dir)
                .arg("--report")
                .arg(base.join("token-overlap.json"));
            c
        } else {
            let mut c = Command::new(&env.bins.server);
            c.args(["serve", "--config"]).arg(&config_path).arg("--shutdown-stdin");
            c
        };
        command.env_remove("ONCL_PY_TOOLS");
        let mut running = Running::spawn(
            command,
            RunOptions {
                stdin_piped: true,
                watch: None,
                ..RunOptions::default()
            },
        )?;
        let line = running.wait_for_line("listening ", Duration::from_secs(60))?;
        let mut address = line
            .trim()
            .strip_prefix("listening ")
            .context("listening line")?
            .to_owned();
        if address.starts_with("0.0.0.0") {
            address = address.replacen("0.0.0.0", "127.0.0.1", 1);
        }
        Ok(Self {
            running: Some(running),
            address,
            token_file: operator.join("token"),
            operator,
            scratch,
            audit,
            config_path,
        })
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Graceful stop: one newline on the control pipe. Returns the measured process.
    pub fn stop(&mut self) -> anyhow::Result<Measured> {
        let mut running = self.running.take().context("server already stopped")?;
        running.write_stdin(b"\n")?;
        running.close_stdin();
        running.wait()
    }

    /// `(BEGIN count, FINAL count, FINAL applied count, FINAL unknown count)` from the
    /// durable journal of a STOPPED server.
    pub fn audit_counts(&self) -> anyhow::Result<AuditCounts> {
        use oncl_server::audit::{AuditConfig, DurableAuditGuard, RecordKind};
        let config = oncl_server::config::ServerConfig::read(&self.config_path)
            .map_err(|e| anyhow::anyhow!("reading the server configuration: {e}"))?;
        let audit = AuditConfig::new(
            config.audit_directory,
            config.audit_segment_bytes,
            config.audit_quota_bytes,
            32,
            config.max_in_flight as usize,
        )?;
        let journal = DurableAuditGuard::open(audit)?;
        journal.recover()?;
        let mut counts = AuditCounts::default();
        for record in journal.records()? {
            match record.kind {
                RecordKind::Begin => counts.begin += 1,
                RecordKind::Final => {
                    counts.finals += 1;
                    match format!("{:?}", record.applied).as_str() {
                        "Applied" => counts.applied += 1,
                        "Unknown" => counts.unknown += 1,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        Ok(counts)
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        if let Some(mut running) = self.running.take() {
            let _ = running.write_stdin(b"\n");
            running.close_stdin();
            let _ = running.wait();
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditCounts {
    pub begin: u64,
    pub finals: u64,
    pub applied: u64,
    pub unknown: u64,
}

/// The CLI's owner-only secret file holding the key password, in a private directory.
pub fn make_secret(dir: &Path, password: &str) -> anyhow::Result<PathBuf> {
    let private = PrivateDirectory::create(dir).context("secret directory")?;
    private
        .create_file("key.secret")?
        .write_all(password.as_bytes())?;
    Ok(dir.join("key.secret"))
}

pub fn free_space_note(path: &Path) -> String {
    measure::storage_of(path)
        .map(|s| format!("{} free of {}", s.free_bytes, s.total_bytes))
        .unwrap_or_default()
}
