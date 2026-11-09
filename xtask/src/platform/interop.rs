//! `cargo xtask platform-interop`: the independent interop matrix of the platform
//! (docs/dev/platform-interop.md).
//!
//! The product under test is the `oncl` binary. Every row of `fixtures/platform/coverage.toml`
//! names the NCANode OpenAPI capability it covers, the real cases that exercise it, the
//! oracle (OpenSSL, pyHanko, lxml + cryptography, the pinned NCANode/Kalkan image) that
//! judges the artifact and the grade it must get. A case produces an artifact with one side
//! and has the other judge it; counterexamples alter signed data and must be rejected by the
//! oracle and by us. A row passes only when its observed grade is exactly the expected one;
//! a row whose prerequisite is absent is `BLOCKED` with that prerequisite, never replaced.
//! The Kalkan provider (`kalkan`, a Java verifier over the operator's own jars) is a
//! local-only oracle: see `kalkan.rs`; without its jars its rows are `BLOCKED`.
//!
//! The grades keep the certificate verdict apart from the cryptographic one: the synthetic
//! and NCANode test certificates do not chain to a root valid in NCANode's world, so a good
//! signature is graded `crypto-ok` (the oracle verified the signature value and digests; the
//! trust grade is not `Valid` by design), a counterexample `crypto-failure`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

#[path = "interop/cases.rs"]
mod cases;
#[path = "interop/kalkan.rs"]
pub mod kalkan;
#[path = "interop/oncl.rs"]
pub mod oncl;
#[path = "interop/tools.rs"]
pub mod tools;
#[path = "interop/world.rs"]
pub mod world;

use crate::ncanode::{Ncanode, container::Container};
use oncl::Oncl;
use tools::{Tools, sha256_file};
use world::World;

/// The committed matrix: capabilities, cases, oracle descriptors, expected grades.
pub const COVERAGE: &str = include_str!("../../../fixtures/platform/coverage.toml");

/// The oracle script run with the pyHanko environment's Python.
const ORACLE_PY: &str = include_str!("../../assets/platform-interop/oracle.py");

/// `coverage.toml`.
#[derive(Debug, Deserialize)]
pub struct Coverage {
    pub schema: u32,
    pub pins: Pins,
    pub oracle: Vec<OracleDescriptor>,
    pub capability: Vec<Capability>,
    #[serde(default)]
    pub excluded: Vec<Excluded>,
    #[serde(default)]
    pub case: Vec<CaseRow>,
    /// Capabilities whose cases are not written yet: they keep the matrix `INCOMPLETE`
    /// (never PASS) and the pending-capabilities test red until each has real rows.
    #[serde(default)]
    pub pending: Vec<Pending>,
    /// Production defects the matrix exposed: not adopted as desired behaviour; the rows
    /// that name one FAIL until it is fixed.
    #[serde(default)]
    pub defect: Vec<Defect>,
}

#[derive(Debug, Deserialize)]
pub struct Pending {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub routes: Vec<String>,
    /// What is missing: cases, an oracle, or a prerequisite.
    pub missing: String,
}

#[derive(Debug, Deserialize)]
pub struct Defect {
    pub id: String,
    pub title: String,
    /// The exact command or sequence that reproduces it.
    pub reproduction: String,
    pub observed: String,
    pub expected: String,
}

#[derive(Debug, Deserialize)]
pub struct Pins {
    pub ncanode_commit: String,
    pub ncanode_image: String,
    pub openapi_sha256: String,
    /// The routes of the pinned OpenAPI.
    pub openapi_routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OracleDescriptor {
    pub id: String,
    pub tool: String,
    /// The exact version (a pinned third-party library or image), or the required prefix
    /// of a system tool's version.
    pub version: String,
    /// `exact` or `prefix`.
    pub match_version: String,
    /// Commit or digest of the artifact, where one pins it.
    #[serde(default)]
    pub pin: String,
    pub role: String,
    /// A file the oracle needs that the operator supplies and that is never committed
    /// (a licence-restricted jar): the environment variable that names it and its sha256.
    #[serde(default)]
    pub artifact: Vec<kalkan::Artifact>,
    /// The oracle cannot run in CI (its software is not redistributable): the report marks
    /// every row it judges.
    #[serde(default)]
    pub local_only: bool,
}

#[derive(Debug, Deserialize)]
pub struct Capability {
    pub id: String,
    pub title: String,
    /// The OpenAPI routes the capability stands for (empty for our additional ones).
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Excluded {
    pub id: String,
    pub title: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct CaseRow {
    pub id: String,
    pub capability: String,
    pub profile: String,
    pub oracles: Vec<String>,
    /// What the case does, in one sentence.
    pub what: String,
    /// The grade the case must observe.
    pub expected: String,
    /// The production defect (an id of `[[defect]]`) this row is known to fail on.
    #[serde(default)]
    pub defect: Option<String>,
    /// For a defect row: the observed (buggy) grade, or for an error the text of its
    /// message, as a substring. `expected` is always the DESIRED outcome.
    #[serde(default)]
    pub defect_observed: Option<String>,
}

impl Coverage {
    pub fn load() -> anyhow::Result<Coverage> {
        let coverage: Coverage =
            toml::from_str(COVERAGE).context("fixtures/platform/coverage.toml does not parse")?;
        ensure!(coverage.schema == 1, "unknown coverage.toml schema");
        Ok(coverage)
    }

    pub fn row(&self, id: &str) -> Option<&CaseRow> {
        self.case.iter().find(|c| c.id == id)
    }

    pub fn descriptor(&self, id: &str) -> Option<&OracleDescriptor> {
        self.oracle.iter().find(|o| o.id == id)
    }
}

/// Everything a case may need.
pub struct Ctx {
    pub oncl: Oncl,
    pub world: World,
    pub tools: Tools,
    /// A fresh directory (on the world's filesystem) for the running case.
    pub dir: PathBuf,
    pub oracle_py: PathBuf,
    nc: NodeState,
    /// Directory of the large artifacts and their size.
    pub scratch: PathBuf,
    pub large_bytes: u64,
    pub coverage: std::sync::Arc<Coverage>,
    kalkan: std::cell::OnceCell<Result<kalkan::Kalkan, String>>,
}

enum NodeState {
    Idle,
    Up(Box<(Container, Ncanode)>),
    Down(String),
}

/// A prerequisite of the case is absent: the row is `BLOCKED`, not failed.
#[derive(Debug)]
pub struct Blocked(pub String);

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Blocked {}

pub fn blocked<T>(reason: impl Into<String>) -> anyhow::Result<T> {
    Err(Blocked(reason.into()).into())
}

/// What a case observed.
#[derive(Debug, Default)]
pub struct Observed {
    pub grade: String,
    /// What `oncl` said, in one line.
    pub ours: String,
    /// What the oracle said, in one line.
    pub oracle: String,
    pub detail: String,
}

pub type CaseFn = Box<dyn Fn(&mut Ctx) -> anyhow::Result<Observed>>;

pub struct Case {
    pub id: String,
    pub run: CaseFn,
}

impl Case {
    pub fn new(
        id: impl Into<String>,
        run: impl Fn(&mut Ctx) -> anyhow::Result<Observed> + 'static,
    ) -> Case {
        Case {
            id: id.into(),
            run: Box::new(run),
        }
    }
}

/// Every runnable case, by id.
pub fn catalog() -> Vec<Case> {
    cases::all()
}

impl Ctx {
    /// The running NCANode, started on first use. A start that fails blocks the case.
    pub(crate) fn ncanode(&mut self) -> anyhow::Result<&Ncanode> {
        if matches!(self.nc, NodeState::Idle) {
            self.nc = if self.tools.docker_version.is_none() {
                NodeState::Down(
                    "Docker is not available: NCANode runs from its pinned image in Docker \
                     (Linux, `service docker start`)"
                        .to_owned(),
                )
            } else if !cfg!(target_os = "linux") {
                NodeState::Down(
                    "the NCANode oracle runs in Linux only (the pinned image, Docker)".to_owned(),
                )
            } else {
                match crate::ncanode::launch() {
                    Ok(pair) => NodeState::Up(Box::new(pair)),
                    Err(e) => NodeState::Down(format!("NCANode did not start: {e:#}")),
                }
            };
        }
        match &self.nc {
            NodeState::Up(pair) => Ok(&pair.1),
            NodeState::Down(reason) => blocked(reason.clone()),
            NodeState::Idle => unreachable!("started above"),
        }
    }

    /// Runs the oracle script with the pyHanko environment's Python.
    pub fn py<S: AsRef<str>>(&self, args: &[S]) -> anyhow::Result<tools::Out> {
        let Some(python) = &self.tools.python else {
            return blocked(
                self.tools
                    .python_missing
                    .clone()
                    .unwrap_or_else(|| "no Python oracle environment".to_owned()),
            );
        };
        let mut command = std::process::Command::new(python);
        command.arg(&self.oracle_py);
        command.args(args.iter().map(AsRef::as_ref));
        tools::exec(&mut command, b"", tools::SHORT)
    }

    /// The oracle script's JSON answer (its `ok` flag is the caller's business).
    pub fn py_json<S: AsRef<str>>(&self, args: &[S]) -> anyhow::Result<Value> {
        let out = self.py(args)?;
        serde_json::from_slice(&out.stdout)
            .with_context(|| format!("the oracle script printed no JSON: {}", out.brief()))
    }

    /// The Kalkan oracle, found and checked on first use (its jars come from the operator's
    /// environment and are never part of the repository): why it cannot serve, or itself.
    pub fn kalkan_state(&self) -> &Result<kalkan::Kalkan, String> {
        self.kalkan
            .get_or_init(|| match self.coverage.descriptor("kalkan") {
                Some(descriptor) => kalkan::Kalkan::discover(descriptor),
                None => Err("coverage.toml has no descriptor of the Kalkan oracle".to_owned()),
            })
    }

    /// Runs the Kalkan verifier (`KalkanOracle.java`, compiled by the JDK's source launcher)
    /// with `args` (`raw|jws|wsse ...`). Blocks the case when the oracle is not available.
    pub fn java<S: AsRef<str>>(&self, args: &[S]) -> anyhow::Result<tools::Out> {
        let kalkan = match self.kalkan_state() {
            Ok(kalkan) => kalkan,
            Err(reason) => return blocked(reason.clone()),
        };
        let source = self.world.dir.path().join(kalkan::SOURCE_FILE);
        if !source.is_file() {
            std::fs::write(&source, kalkan::SOURCE)
                .with_context(|| source.display().to_string())?;
        }
        let mut command = std::process::Command::new(&kalkan.java);
        command.arg("-cp").arg(&kalkan.classpath).arg(&source);
        command.args(args.iter().map(AsRef::as_ref));
        tools::exec(&mut command, b"", tools::SHORT)
    }

    /// The Kalkan verifier's answer (`ok` is the verdict); an oracle that could not run is an
    /// error, never a verdict.
    pub fn java_json<S: AsRef<str>>(&self, args: &[S]) -> anyhow::Result<Value> {
        kalkan::parse_answer(&self.java(args)?)
    }

    pub fn openssl<S: AsRef<std::ffi::OsStr>>(&self, args: &[S]) -> anyhow::Result<tools::Out> {
        let mut command = std::process::Command::new(&self.tools.openssl);
        command.args(args);
        tools::exec(&mut command, b"", tools::SHORT)
    }

    /// POSTs JSON to NCANode and returns the HTTP status and the JSON answer (an error
    /// status is data here: the oracle's refusal is an observation).
    pub fn nc_post(&mut self, path: &str, body: &Value) -> anyhow::Result<(u16, Value)> {
        // NCANode's timestamp requests go to the NCA's TSA over the network: a failure
        // there is transient, the same request is repeated (not a verdict about a row).
        for attempt in 0..3 {
            let (status, value) = match self.nc_post_once(path, body) {
                Ok(pair) => pair,
                Err(e) if attempt < 2 && format!("{e:#}").contains("timeout") => {
                    // A wedged NCANode answers nothing to everything after it: start a
                    // fresh container (the cache volume keeps its downloads) and repeat.
                    self.nc = NodeState::Idle;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let transient = status == 500
                && value["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("TSP request failure"));
            if !transient || attempt == 2 {
                return Ok((status, value));
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
        unreachable!("the loop returns on its last attempt")
    }

    fn nc_post_once(&mut self, path: &str, body: &Value) -> anyhow::Result<(u16, Value)> {
        let node = self.ncanode()?;
        let mut response = node
            .agent
            .post(format!("{}{path}", node.base))
            .header("content-type", "application/json")
            .send(body.to_string())
            .with_context(|| format!("POST {path}"))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(64 << 20)
            .read_to_string()
            .with_context(|| format!("reading the answer to POST {path}"))?;
        let value = serde_json::from_str(&text)
            .unwrap_or_else(|_| json!({ "unparsed": text.chars().take(500).collect::<String>() }));
        Ok((status, value))
    }

    /// A path inside the case directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
        let path = self.file(name);
        std::fs::write(&path, bytes).with_context(|| path.display().to_string())?;
        Ok(path)
    }

    pub fn read(&self, name: &str) -> anyhow::Result<Vec<u8>> {
        let path = self.file(name);
        std::fs::read(&path).with_context(|| path.display().to_string())
    }
}

/// One row of the result.
#[derive(Debug)]
pub struct Row {
    pub id: String,
    pub capability: String,
    pub profile: String,
    pub oracles: Vec<String>,
    pub expected: String,
    pub status: Status,
    pub defect: Option<String>,
    pub grade: String,
    pub ours: String,
    pub oracle: String,
    pub detail: String,
    pub seconds: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Blocked,
    /// A row with a defect marker that still shows the documented defect.
    Defect,
    /// A row with a defect marker that now gives its desired grade: remove the marker.
    Fixed,
    /// A row with a defect marker that fails differently from the documented defect.
    Changed,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Blocked => "BLOCKED",
            Status::Defect => "DEFECT",
            Status::Fixed => "FIXED",
            Status::Changed => "CHANGED",
        }
    }
}

/// The options of `platform-interop`.
pub struct Options {
    pub out: PathBuf,
    /// The `oncl` to test; default: built from this workspace.
    pub oncl: Option<PathBuf>,
    /// Run only the cases whose id starts with one of these (a partial run never PASSes).
    pub filter: Vec<String>,
    /// List the cases and exit.
    pub list: bool,
    /// Start the loopback PKI, write its paths to `<out>/world.env`, and keep serving until
    /// stdin closes: to reproduce a row by hand with `oncl`.
    pub hold_world: bool,
    /// Where the large artifacts are generated (default: `ONCL_INTEROP_SCRATCH`, else a
    /// directory under the temporary directory): a volume with room for a few of them.
    pub scratch: Option<PathBuf>,
    /// The size of the large artifacts in bytes.
    pub large_bytes: u64,
}

/// Runs the matrix and writes `<out>/report.json` and `<out>/report.md`.
///
/// # Errors
///
/// If the matrix cannot be set up, any row FAILs, or (with no failure) a row is BLOCKED.
pub fn run(root: &Path, options: &Options) -> anyhow::Result<()> {
    let coverage = std::sync::Arc::new(Coverage::load()?);
    let catalog = catalog();
    ensure!(
        options.list || cfg!(target_os = "linux"),
        "platform-interop runs in Linux only (the NCANode oracle is a Docker image, the \
         other oracles and the large-artifact checks assume POSIX files); run it in a Linux \
         environment such as WSL: a Windows run is not an interop run"
    );
    if options.list {
        for row in &coverage.case {
            println!("{}\t{}\t{}", row.id, row.capability, row.expected);
        }
        return Ok(());
    }
    check_coverage(
        &coverage,
        &catalog,
        options.filter.is_empty() && !options.hold_world,
    )?;
    let tools = Tools::discover()?;
    let out = if options.out.is_absolute() {
        options.out.clone()
    } else {
        root.join(&options.out)
    };
    std::fs::create_dir_all(&out).with_context(|| out.display().to_string())?;
    let oncl_bin = match &options.oncl {
        Some(path) => path.clone(),
        None => build_oncl(root)?,
    };
    let oncl = Oncl::new(oncl_bin);
    let oncl_version = oncl.version()?;
    let oncl_sha = sha256_file(&oncl.bin)?;

    let run_dir = scratch_base()?;
    let base = run_dir.path().to_path_buf();
    let world = World::start(
        &base,
        tools
            .container_host
            .unwrap_or(std::net::Ipv4Addr::LOCALHOST),
    )?;
    let scratch = match &options.scratch {
        Some(dir) => dir.clone(),
        None => std::env::var_os("ONCL_INTEROP_SCRATCH")
            .map_or_else(|| base.join("large"), PathBuf::from),
    };
    std::fs::create_dir_all(&scratch).with_context(|| scratch.display().to_string())?;
    let oracle_py = world.dir.path().join("oracle.py");
    std::fs::write(&oracle_py, ORACLE_PY)?;
    if options.hold_world {
        return hold_world(&world, &out, &oncl);
    }
    // Public validation material is evidence, not a key export. Preserve it so artifacts
    // remain independently checkable after the ephemeral world has been removed.
    let public = out.join("public-pki");
    std::fs::create_dir_all(&public)?;
    for source in [&world.root, &world.tsa_cert, &world.responder_cert]
        .into_iter()
        .chain(world.signers.iter().map(|s| &s.cert_der))
    {
        let name = source.file_name().context("public certificate filename")?;
        std::fs::copy(source, public.join(name))?;
    }
    let fixture_digests = fixture_digests()?;
    let openapi = check_openapi(&coverage)?;

    let mut ctx = Ctx {
        oncl,
        world,
        tools,
        dir: PathBuf::new(),
        oracle_py,
        nc: NodeState::Idle,
        scratch,
        large_bytes: options.large_bytes,
        coverage: coverage.clone(),
        kalkan: std::cell::OnceCell::new(),
    };
    let oracle_versions = oracle_versions(&ctx, &coverage);

    let mut rows = Vec::new();
    let partial = !options.filter.is_empty();
    for case in &catalog {
        let row = coverage
            .row(&case.id)
            .with_context(|| format!("case {} has no row in coverage.toml", case.id))?;
        if partial
            && !options
                .filter
                .iter()
                .any(|f| case.id.starts_with(f.as_str()))
        {
            continue;
        }
        rows.push(run_case(&mut ctx, &out, case, row, &oracle_versions));
        let last = rows.last().expect("just pushed");
        println!(
            "{:<8} {:<44} {:<30} {}",
            last.status.label(),
            last.id,
            last.grade,
            last.detail.lines().next().unwrap_or_default()
        );
    }

    let mut missing = Vec::new();
    if !partial {
        for row in &coverage.case {
            if !catalog.iter().any(|c| c.id == row.id) {
                missing.push(row.id.clone());
            }
        }
    }
    let report = report_json(
        &coverage,
        &ctx,
        &rows,
        partial,
        &oncl_version,
        &oncl_sha,
        &fixture_digests,
        &openapi,
        &oracle_versions,
    );
    std::fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    std::fs::write(out.join("report.md"), report_md(&coverage, &rows, &report))?;
    let count = |status| rows.iter().filter(|r| r.status == status).count();
    let (pass, fail, blocked) = (
        count(Status::Pass),
        count(Status::Fail),
        count(Status::Blocked),
    );
    let (defect, fixed, changed) = (
        count(Status::Defect),
        count(Status::Fixed),
        count(Status::Changed),
    );
    println!(
        "{} rows: {pass} PASS, {fail} FAIL, {defect} DEFECT (known), {fixed} FIXED, {changed} CHANGED, {blocked} BLOCKED; report: {}",
        rows.len(),
        out.join("report.md").display()
    );
    ensure!(missing.is_empty(), "rows without a case: {missing:?}");
    ensure!(fail == 0, "{fail} rows FAILED");
    ensure!(
        fixed == 0,
        "{fixed} defect rows are FIXED: remove their markers (see the report)"
    );
    ensure!(
        changed == 0,
        "{changed} defect rows fail differently from the documented defect"
    );
    ensure!(defect == 0, "{defect} rows show known production defects");
    ensure!(
        blocked == 0,
        "{blocked} rows are BLOCKED (see the report for each prerequisite)"
    );
    ensure!(
        !partial,
        "a filtered run is not a verdict: the matrix did not run in full"
    );
    ensure!(
        coverage.pending.is_empty(),
        "the matrix is INCOMPLETE: capabilities without cases: {}",
        coverage
            .pending
            .iter()
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

/// Writes `world.env` (shell variables for the paths of the loopback PKI) and serves until
/// stdin closes.
fn hold_world(world: &World, out: &Path, oncl: &Oncl) -> anyhow::Result<()> {
    let mut env = String::new();
    let _ = writeln!(env, "ONCL={}", oncl.bin.display());
    let _ = writeln!(env, "ROOT={}", world.root.display());
    let _ = writeln!(env, "ORIGIN={}", world.origin);
    let _ = writeln!(env, "AS_OF={}", world::NOW);
    let _ = writeln!(env, "SECRET={}", world.secret.display());
    let _ = writeln!(env, "PASSWORD={}", world::PASSWORD);
    for signer in &world.signers {
        let label = signer.profile.label().to_uppercase();
        let _ = writeln!(env, "{label}_P12={}", signer.p12.display());
        let _ = writeln!(env, "{label}_CERT={}", signer.cert_der.display());
    }
    let _ = writeln!(env, "TSA_URL={}", world.tsa_url());
    std::fs::write(out.join("world.env"), env)?;
    println!(
        "the loopback PKI is up; paths in {}",
        out.join("world.env").display()
    );
    let mut sink = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink)?;
    Ok(())
}

fn run_case(
    ctx: &mut Ctx,
    out: &Path,
    case: &Case,
    row: &CaseRow,
    _versions: &BTreeMap<String, String>,
) -> Row {
    let start = Instant::now();
    let dir = ctx.world.dir.path().join("cases").join(&case.id);
    let _ = std::fs::remove_dir_all(&dir);
    let prepared = std::fs::create_dir_all(&dir);
    ctx.dir = dir.clone();
    let result = match prepared {
        Ok(()) => oracle_gate(ctx, row).and_then(|()| (case.run)(ctx)),
        Err(e) => Err(e.into()),
    };
    let seconds = start.elapsed().as_secs_f64();
    let mut result_row = Row {
        id: case.id.clone(),
        capability: row.capability.clone(),
        profile: row.profile.clone(),
        oracles: row.oracles.clone(),
        expected: row.expected.clone(),
        status: Status::Fail,
        defect: row.defect.clone(),
        grade: String::new(),
        ours: String::new(),
        oracle: String::new(),
        detail: String::new(),
        seconds,
    };
    match result {
        Ok(observed) => {
            result_row.ours = observed.ours;
            result_row.oracle = observed.oracle;
            result_row.detail = observed.detail;
            let matches = observed.grade == row.expected;
            match (&row.defect, matches) {
                (None, true) => result_row.status = Status::Pass,
                (None, false) => {
                    result_row.detail = format!(
                        "observed grade `{}` differs from the expected `{}`; {}",
                        observed.grade, row.expected, result_row.detail
                    );
                }
                (Some(defect), true) => {
                    result_row.status = Status::Fixed;
                    result_row.detail = format!(
                        "defect {defect} is FIXED: the row gives its desired grade; remove the marker"
                    );
                }
                (Some(defect), false) => {
                    result_row.status = defect_status(row, &observed.grade, &result_row.detail);
                    result_row.detail = format!(
                        "defect {defect}: observed `{}`, desired `{}`; {}",
                        observed.grade, row.expected, result_row.detail
                    );
                }
            }
            result_row.grade = observed.grade;
        }
        Err(e) => match e.downcast_ref::<Blocked>() {
            Some(Blocked(reason)) => {
                result_row.status = Status::Blocked;
                result_row.grade = "blocked".to_owned();
                result_row.detail = reason.clone();
            }
            None => {
                result_row.grade = "error".to_owned();
                result_row.detail = format!("{e:#}");
                if let Some(defect) = &row.defect {
                    result_row.status = defect_status(row, "error", &result_row.detail);
                    result_row.detail = format!("defect {defect}: {}", result_row.detail);
                }
            }
        },
    }
    keep_artifacts(&dir, &out.join("artifacts").join(&case.id));
    result_row
}

/// `Defect` if the row still shows the documented defect, else `Changed`.
fn defect_status(row: &CaseRow, grade: &str, detail: &str) -> Status {
    match row.defect_observed.as_deref() {
        Some(known) if grade.contains(known) || (grade == "error" && detail.contains(known)) => {
            Status::Defect
        }
        _ => Status::Changed,
    }
}

/// A case whose oracle is not the pinned one cannot judge: BLOCKED with the mismatch.
fn oracle_gate(ctx: &Ctx, row: &CaseRow) -> anyhow::Result<()> {
    for id in &row.oracles {
        let descriptor = ctx
            .coverage
            .descriptor(id)
            .with_context(|| format!("oracle {id} has no descriptor"))?;
        if let Some(reason) = oracle_problem(ctx, descriptor) {
            return blocked(reason);
        }
    }
    Ok(())
}

/// Why `descriptor`'s tool cannot serve as the oracle here, if it cannot.
fn oracle_problem(ctx: &Ctx, descriptor: &OracleDescriptor) -> Option<String> {
    if matches!(
        descriptor.id.as_str(),
        "pyhanko" | "lxml" | "cryptography" | "asn1crypto"
    ) && ctx.tools.python.is_none()
    {
        return ctx.tools.python_missing.clone();
    }
    if descriptor.id == "kalkan" {
        return ctx.kalkan_state().as_ref().err().cloned();
    }
    let found = oracle_version(ctx, &descriptor.id)?;
    let ok = match descriptor.match_version.as_str() {
        "exact" => found == descriptor.version,
        _ => found.starts_with(&descriptor.version),
    };
    (!ok).then(|| {
        format!(
            "{} is {found}, the descriptor pins {} ({})",
            descriptor.tool, descriptor.version, descriptor.match_version
        )
    })
}

/// The version of an oracle as found at run time; `None` for an oracle that is checked
/// where it is used (NCANode: by its image digest).
fn oracle_version(ctx: &Ctx, id: &str) -> Option<String> {
    match id {
        "openssl" => Some(
            ctx.tools
                .openssl_version
                .split_whitespace()
                .nth(1)
                .unwrap_or("?")
                .to_owned(),
        ),
        "pyhanko" => ctx
            .tools
            .python
            .as_ref()
            .map(|_| ctx.tools.python_package("pyHanko")),
        "lxml" => ctx
            .tools
            .python
            .as_ref()
            .map(|_| ctx.tools.python_package("lxml")),
        "cryptography" => ctx
            .tools
            .python
            .as_ref()
            .map(|_| ctx.tools.python_package("cryptography")),
        "asn1crypto" => ctx
            .tools
            .python
            .as_ref()
            .map(|_| ctx.tools.python_package("asn1crypto")),
        _ => None,
    }
}

fn oracle_versions(ctx: &Ctx, coverage: &Coverage) -> BTreeMap<String, String> {
    coverage
        .oracle
        .iter()
        .map(|o| {
            let found = match o.id.as_str() {
                "ncanode" => format!("{} ({})", o.version, o.pin),
                "kalkan" => match ctx.kalkan_state() {
                    Ok(_) => format!(
                        "{} (local-only, not reproducible in CI; {})",
                        o.version, o.pin
                    ),
                    Err(reason) => format!("unavailable: {reason}"),
                },
                _ => oracle_version(ctx, &o.id).unwrap_or_else(|| "unavailable".to_owned()),
            };
            (o.id.clone(), found)
        })
        .collect()
}

/// Copies a case's artifacts (not keys, containers or secrets) into the output.
fn keep_artifacts(dir: &Path, destination: &Path) {
    let _ = std::fs::remove_dir_all(destination);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let _ = std::fs::create_dir_all(destination);
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let lowered = name.to_string_lossy().to_lowercase();
        if !path.is_file() || lowered.ends_with(".p12") || lowered.ends_with(".secret") {
            continue;
        }
        if entry.metadata().is_ok_and(|m| m.len() > 64 << 20) {
            continue;
        }
        let _ = std::fs::copy(&path, destination.join(&name));
    }
}

/// Cross-checks the committed matrix against the case catalog: every capability has a case,
/// every case a row, every route a capability, every oracle a descriptor.
pub fn check_coverage(coverage: &Coverage, catalog: &[Case], complete: bool) -> anyhow::Result<()> {
    let mut problems = Vec::new();
    let ids: Vec<&str> = catalog.iter().map(|c| c.id.as_str()).collect();
    let mut seen = std::collections::BTreeSet::new();
    for id in &ids {
        if !seen.insert(*id) {
            problems.push(format!("case {id} is registered twice"));
        }
        if coverage.row(id).is_none() {
            problems.push(format!("case {id} has no row in coverage.toml"));
        }
    }
    for row in &coverage.case {
        if complete && !ids.contains(&row.id.as_str()) {
            problems.push(format!("row {} has no case", row.id));
        }
        if !coverage.capability.iter().any(|c| c.id == row.capability) {
            problems.push(format!(
                "row {} names unknown capability {}",
                row.id, row.capability
            ));
        }
        if row.oracles.is_empty() {
            problems.push(format!("row {} names no oracle", row.id));
        }
        for oracle in &row.oracles {
            if coverage.descriptor(oracle).is_none() {
                problems.push(format!("row {} names unknown oracle {oracle}", row.id));
            }
        }
        if row.expected.trim().is_empty() {
            problems.push(format!("row {} has no expected grade", row.id));
        }
    }
    for capability in coverage.capability.iter().filter(|_| complete) {
        if !coverage.case.iter().any(|c| c.capability == capability.id) {
            problems.push(format!("capability {} has no case", capability.id));
        }
    }
    let mut routes: Vec<&str> = coverage
        .capability
        .iter()
        .flat_map(|c| c.routes.iter().map(String::as_str))
        .chain(
            coverage
                .pending
                .iter()
                .flat_map(|c| c.routes.iter().map(String::as_str)),
        )
        .collect();
    routes.sort_unstable();
    let mut pinned: Vec<&str> = coverage
        .pins
        .openapi_routes
        .iter()
        .map(String::as_str)
        .collect();
    pinned.sort_unstable();
    for route in pinned.iter().filter(|_| complete) {
        if !routes.contains(route) {
            problems.push(format!("OpenAPI route {route} is in no capability"));
        }
    }
    for route in &routes {
        if !pinned.contains(route) {
            problems.push(format!(
                "capability route {route} is not in the pinned OpenAPI"
            ));
        }
    }
    for row in &coverage.case {
        if let Some(defect) = &row.defect
            && !coverage.defect.iter().any(|d| &d.id == defect)
        {
            problems.push(format!("row {} names unknown defect {defect}", row.id));
        }
    }
    for defect in &coverage.defect {
        if !coverage
            .case
            .iter()
            .any(|c| c.defect.as_deref() == Some(defect.id.as_str()))
        {
            problems.push(format!("defect {} is named by no row", defect.id));
        }
    }
    for excluded in &coverage.excluded {
        if excluded.reason.trim().len() < 20 {
            problems.push(format!("exclusion {} has no real reason", excluded.id));
        }
        if coverage.capability.iter().any(|c| c.id == excluded.id) {
            problems.push(format!("{} is both covered and excluded", excluded.id));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        bail!(
            "coverage.toml is inconsistent:\n  {}",
            problems.join("\n  ")
        )
    }
}

/// The pinned OpenAPI, fetched by `cargo xtask fetch-fixtures`: its digest and routes must
/// be the pinned ones. Returns the facts for the report.
pub fn check_openapi(coverage: &Coverage) -> anyhow::Result<Value> {
    let path = crate::fetch::ncanode_dir().join("openapi.yml");
    ensure!(
        path.is_file(),
        "{} is missing: run `cargo xtask fetch-fixtures`",
        path.display()
    );
    let digest = sha256_file(&path)?;
    ensure!(
        digest == coverage.pins.openapi_sha256,
        "the fetched openapi.yml has sha256 {digest}, coverage.toml pins {}",
        coverage.pins.openapi_sha256
    );
    let routes = openapi_routes(&std::fs::read_to_string(&path)?);
    let mut pinned = coverage.pins.openapi_routes.clone();
    pinned.sort();
    ensure!(
        routes == pinned,
        "the routes of openapi.yml {routes:?} differ from the pinned {pinned:?}"
    );
    Ok(json!({ "file": "openapi.yml", "sha256": digest, "routes": routes }))
}

/// The paths of an OpenAPI YAML document written the way NCANode's is: two-space indented
/// keys under a top-level `paths:`.
pub fn openapi_routes(yaml: &str) -> Vec<String> {
    let mut routes = Vec::new();
    let mut in_paths = false;
    for line in yaml.lines() {
        if !line.starts_with(' ') {
            in_paths = line.trim_end() == "paths:";
            continue;
        }
        if in_paths
            && let Some(route) = line
                .strip_prefix("  /")
                .and_then(|rest| rest.strip_suffix(':'))
        {
            routes.push(format!("/{route}"));
        }
    }
    routes.sort();
    routes
}

fn fixture_digests() -> anyhow::Result<BTreeMap<String, String>> {
    let mut digests = BTreeMap::new();
    let dir = crate::fetch::ncanode_dir();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("{} (run `cargo xtask fetch-fixtures`)", dir.display()))?
    {
        let path = entry?.path();
        if path.is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            // The keys and certificates of NCA test CAs are fetched, never published: only
            // their digests go into the report.
            digests.insert(name.to_owned(), sha256_file(&path)?);
        }
    }
    Ok(digests)
}

/// A fresh directory for this run, so concurrent runs never share files.
fn scratch_base() -> anyhow::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("oncl-platform-interop-")
        .tempdir()
        .context("creating the run directory")
}

/// Builds `oncl` from this workspace (debug profile; `--oncl` takes a release binary).
fn build_oncl(root: &Path) -> anyhow::Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = std::process::Command::new(&cargo)
        .args(["build", "-p", "oncl-cli", "--message-format", "short"])
        .current_dir(root)
        .status()
        .context("running cargo")?;
    ensure!(status.success(), "building oncl failed");
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let exe = if cfg!(windows) { "oncl.exe" } else { "oncl" };
    let path = target.join("debug").join(exe);
    ensure!(path.is_file(), "{} was not built", path.display());
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
fn report_json(
    coverage: &Coverage,
    ctx: &Ctx,
    rows: &[Row],
    partial: bool,
    oncl_version: &str,
    oncl_sha: &str,
    fixtures: &BTreeMap<String, String>,
    openapi: &Value,
    oracle_versions: &BTreeMap<String, String>,
) -> Value {
    let count = |status| rows.iter().filter(|r| r.status == status).count();
    let overall = if partial {
        "PARTIAL"
    } else if count(Status::Fail) == 0
        && count(Status::Blocked) == 0
        && !coverage.pending.is_empty()
    {
        "INCOMPLETE"
    } else if count(Status::Fail) + count(Status::Changed) + count(Status::Fixed) > 0 {
        "FAIL"
    } else if count(Status::Defect) > 0 {
        "FAIL-KNOWN-DEFECTS"
    } else if count(Status::Blocked) > 0 {
        "BLOCKED"
    } else {
        "PASS"
    };
    json!({
        "overall": overall,
        "oncl": { "version": oncl_version, "sha256": oncl_sha },
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "pins": {
            "ncanode_commit": coverage.pins.ncanode_commit,
            "ncanode_image": coverage.pins.ncanode_image,
        },
        "openapi": openapi,
        "fixtures_sha256": fixtures,
        "tools": {
            "openssl": ctx.tools.openssl_version,
            "docker": ctx.tools.docker_version,
            "python": ctx.tools.python_versions.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>(),
            "python_missing": ctx.tools.python_missing,
            "oracles": oracle_versions,
        },
        "defects": coverage.defect.iter().map(|d| json!({"id": d.id, "title": d.title, "reproduction": d.reproduction, "observed": d.observed, "expected": d.expected})).collect::<Vec<_>>(),
        "pending": coverage.pending.iter().map(|p| json!({"id": p.id, "title": p.title, "missing": p.missing})).collect::<Vec<_>>(),
        "excluded": coverage.excluded.iter().map(|e| json!({"id": e.id, "title": e.title, "reason": e.reason})).collect::<Vec<_>>(),
        "rows": rows.iter().map(|r| json!({
            "id": r.id,
            "capability": r.capability,
            "profile": r.profile,
            "oracles": oracle_labels(coverage, &r.oracles),
            "expected": r.expected,
            "status": r.status.label(),
            "defect": r.defect,
            "grade": r.grade,
            "ours": r.ours,
            "oracle": r.oracle,
            "detail": r.detail,
            "seconds": (r.seconds * 10.0).round() / 10.0,
        })).collect::<Vec<_>>(),
    })
}

fn report_md(coverage: &Coverage, rows: &[Row], report: &Value) -> String {
    let mut text = String::new();
    let _ = writeln!(
        text,
        "# platform-interop: {}\n",
        report["overall"].as_str().unwrap_or("?")
    );
    let _ = writeln!(
        text,
        "- oncl: {} (sha256 {})",
        report["oncl"]["version"].as_str().unwrap_or("?"),
        report["oncl"]["sha256"].as_str().unwrap_or("?")
    );
    let _ = writeln!(
        text,
        "- NCANode: {} (commit {})",
        coverage.pins.ncanode_image, coverage.pins.ncanode_commit
    );
    let _ = writeln!(text, "- OpenAPI sha256: {}", coverage.pins.openapi_sha256);
    let _ = writeln!(text, "- tools: {}\n", report["tools"]);
    let _ = writeln!(
        text,
        "| row | capability | profile | oracle | expected | status | grade |\n|---|---|---|---|---|---|---|"
    );
    for row in rows {
        let _ = writeln!(
            text,
            "| {} | {} | {} | {} | {} | {} | {} |",
            row.id,
            row.capability,
            row.profile,
            oracle_labels(coverage, &row.oracles).join("+"),
            row.expected,
            row.status.label(),
            row.grade
        );
    }
    let _ = writeln!(text, "\n## Details\n");
    for row in rows {
        let _ = writeln!(
            text,
            "### {} ({})\n\n- ours: {}\n- oracle: {}\n- {}\n",
            row.id,
            row.status.label(),
            row.ours,
            row.oracle,
            row.detail.replace('\n', "\n  ")
        );
    }
    let _ = writeln!(text, "## Pending (no cases yet)\n");
    for pending in &coverage.pending {
        let _ = writeln!(
            text,
            "- **{}** ({}): {}",
            pending.id, pending.title, pending.missing
        );
    }
    let _ = writeln!(text, "\n## Production defects\n");
    for defect in &coverage.defect {
        let _ = writeln!(
            text,
            "### {}: {}\n\n- reproduction: {}\n- observed: {}\n- expected: {}\n",
            defect.id, defect.title, defect.reproduction, defect.observed, defect.expected
        );
    }
    let _ = writeln!(text, "## Excluded\n");
    for excluded in &coverage.excluded {
        let _ = writeln!(
            text,
            "- **{}** ({}): {}",
            excluded.id, excluded.title, excluded.reason
        );
    }
    text
}

/// The oracle ids of a row, a local-only one marked as such (a row judged by it cannot be
/// reproduced in CI).
pub fn oracle_labels(coverage: &Coverage, ids: &[String]) -> Vec<String> {
    ids.iter()
        .map(|id| match coverage.descriptor(id) {
            Some(descriptor) if descriptor.local_only => {
                format!("{id} (local-only, not reproducible in CI)")
            }
            _ => id.clone(),
        })
        .collect()
}
