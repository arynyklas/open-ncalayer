//! The matrix of the platform proof: data, reference validation, cases, report.

pub mod barrier;
mod cases;
mod clients;
mod env;
mod exec;
pub mod http_raw;
pub mod otlp;
mod overload;
mod profile;

use super::{
    ProofArgs, Surface,
    generate::{
        self, FileDigests,
        blob::BlobFacts,
        pdf::{PdfFacts, PdfProfile},
        xml::{XmlFacts, XmlKind},
    },
    measure,
};
use anyhow::{Context, bail};
use env::{Bins, Env, PkiServer};
use exec::{CaseResult, Profile, Target};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

/// The Python oracle written next to the data (independent of every production parser).
pub const ORACLE_PY: &str = include_str!("../../assets/platform-proof/oracle.py");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Facts {
    Blob(BlobFacts),
    Xml(XmlFacts),
    Pdf(PdfFacts),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataSet {
    pub name: String,
    pub path: PathBuf,
    pub digests: FileDigests,
    pub facts: Facts,
    pub generate_seconds: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub document_bytes: u64,
    pub sets: Vec<DataSet>,
}

impl Manifest {
    pub fn set(&self, name: &str) -> anyhow::Result<&DataSet> {
        self.sets
            .iter()
            .find(|s| s.name == name)
            .with_context(|| format!("no data set {name}"))
    }
}

/// Seeds are fixed: two runs of the same size produce byte-identical documents.
const SEED: u64 = 0x4F4E_434C_5052_4F46;

fn timed<T>(f: impl FnOnce() -> std::io::Result<T>) -> anyhow::Result<(T, f64)> {
    let start = Instant::now();
    let value = f()?;
    Ok((value, start.elapsed().as_secs_f64()))
}

/// Generates every document of the proof of `bytes` bytes each into `dir`.
pub fn generate_all(dir: &Path, bytes: u64, log: &mut dyn FnMut(&str)) -> anyhow::Result<Manifest> {
    std::fs::create_dir_all(dir)?;
    let mut sets = Vec::new();
    let path = dir.join("blob.bin");
    log(&format!("generating {} ({bytes} bytes)", path.display()));
    let ((facts, digests), seconds) = timed(|| generate::blob::generate(&path, bytes, SEED))?;
    sets.push(DataSet {
        name: "blob".into(),
        path,
        digests,
        facts: Facts::Blob(facts),
        generate_seconds: seconds,
    });
    for (name, kind) in [
        ("xml-archive", XmlKind::Archive),
        ("xml-soap", XmlKind::Soap),
    ] {
        let path = dir.join(format!("{name}.xml"));
        log(&format!("generating {} ({bytes} bytes)", path.display()));
        let ((facts, digests), seconds) =
            timed(|| generate::xml::generate(&path, bytes, SEED ^ 1, kind))?;
        sets.push(DataSet {
            name: name.into(),
            path,
            digests,
            facts: Facts::Xml(facts),
            generate_seconds: seconds,
        });
    }
    for (name, profile) in [
        ("pdf-dense", PdfProfile::Dense),
        ("pdf-compact", PdfProfile::Compact),
    ] {
        let path = dir.join(format!("{name}.pdf"));
        log(&format!("generating {} ({bytes} bytes)", path.display()));
        let ((facts, digests), seconds) =
            timed(|| generate::pdf::generate(&path, bytes, SEED ^ 2, profile))?;
        sets.push(DataSet {
            name: name.into(),
            path,
            digests,
            facts: Facts::Pdf(facts),
            generate_seconds: seconds,
        });
    }
    let manifest = Manifest {
        document_bytes: bytes,
        sets,
    };
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

/// Resolves the Python of the oracle environment.
pub fn python(args: &ProofArgs) -> anyhow::Result<PathBuf> {
    if let Some(p) = &args.python {
        return Ok(p.clone());
    }
    if let Ok(p) = std::env::var("ONCL_PYHANKO_PYTHON") {
        return Ok(p.into());
    }
    bail!(
        "the oracle needs Python with lxml, cryptography, asn1crypto and pyHanko: set ONCL_PYHANKO_PYTHON or pass --python"
    );
}

/// Runs one oracle command and returns its JSON verdict (fails on a non-zero exit).
pub fn oracle(
    python: &Path,
    script: &Path,
    tools: Option<&Path>,
    args: &[&std::ffi::OsStr],
) -> anyhow::Result<serde_json::Value> {
    let mut command = Command::new(python);
    command.arg(script).args(args);
    if let Some(tools) = tools {
        command.env("ONCL_PY_TOOLS", tools);
    }
    let output = command.output().context("running the Python oracle")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok());
    if !output.status.success() {
        bail!(
            "oracle {:?} failed ({}): {} {}",
            args.first(),
            output.status,
            text,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    value.with_context(|| format!("oracle printed no JSON: {text}"))
}

/// Validates the generator against third-party tools on small instances: lxml for the XML
/// canonical digests, pyHanko (and qpdf/pypdf/pdfminer when `ONCL_PY_TOOLS` names them) for
/// the PDF structure. Returns the evidence for the report.
pub fn validate_reference(
    python: &Path,
    tools: Option<&Path>,
    dir: &Path,
    log: &mut dyn FnMut(&str),
) -> anyhow::Result<serde_json::Value> {
    std::fs::create_dir_all(dir)?;
    let script = dir.join("oracle.py");
    std::fs::write(&script, ORACLE_PY)?;
    let small = generate_all(&dir.join("small"), 3 * 1024 * 1024, log)?;
    let mut evidence = serde_json::Map::new();
    for set in &small.sets {
        let manifest = dir.join("small").join("manifest.json");
        let command = match &set.facts {
            Facts::Xml(_) => "xml-check",
            Facts::Pdf(_) => "pdf-check",
            Facts::Blob(_) => "blob-check",
        };
        let result = oracle(
            python,
            &script,
            tools,
            &[
                command.as_ref(),
                set.path.as_os_str(),
                manifest.as_os_str(),
                set.name.as_ref(),
            ],
        )
        .with_context(|| format!("reference validation of {}", set.name))?;
        log(&format!("reference check {}: {result}", set.name));
        evidence.insert(set.name.clone(), result);
    }
    Ok(serde_json::Value::Object(evidence))
}

fn sha256_of(path: &Path) -> String {
    cases::sha256_file(path).map(|(h, _)| h).unwrap_or_default()
}

struct Case {
    id: &'static str,
    /// Which surfaces run it.
    surfaces: &'static [Target],
    run: fn(&Env, Target) -> anyhow::Result<CaseResult>,
}

const ALL: &[Target] = &[Target::Sdk, Target::Cli, Target::Http];
const NOT_CLI: &[Target] = &[Target::Sdk, Target::Http];

fn plan() -> Vec<Case> {
    use cases::*;
    // Longest first: with `--jobs` the pool finishes sooner.
    vec![
        Case {
            id: "xades-levels",
            surfaces: ALL,
            run: xades_levels,
        },
        Case {
            id: "xml-far-reference",
            surfaces: ALL,
            run: xml_far,
        },
        Case {
            id: "xml-whole-document",
            surfaces: ALL,
            run: xml_whole,
        },
        Case {
            id: "wsse-body",
            surfaces: ALL,
            run: wsse,
        },
        Case {
            id: "xml-far-gost2015",
            surfaces: ALL,
            run: xml_gost,
        },
        Case {
            id: "xml-unknown-length",
            surfaces: ALL,
            run: xml_unknown_length,
        },
        Case {
            id: "xml-cancel",
            surfaces: ALL,
            run: xml_cancel,
        },
        Case {
            id: "xml-temp-quota",
            surfaces: NOT_CLI,
            run: xml_temp_limit,
        },
        Case {
            id: "pades-levels",
            surfaces: ALL,
            run: pades_levels,
        },
        Case {
            id: "pdf-dense-sign",
            surfaces: ALL,
            run: |e, t| {
                pdf_case(
                    e,
                    t,
                    "pdf-dense",
                    Profile::Pdf,
                    "pdf-dense-sign",
                    "PDF signature of a many-object, three-revision full-size document",
                )
            },
        },
        Case {
            id: "pdf-compact-sign",
            surfaces: ALL,
            run: |e, t| {
                pdf_case(
                    e,
                    t,
                    "pdf-compact",
                    Profile::Pdf,
                    "pdf-compact-sign",
                    "PDF signature of a large-page, three-revision full-size document",
                )
            },
        },
        Case {
            id: "pades-b-compact",
            surfaces: ALL,
            run: |e, t| {
                pdf_case(
                    e,
                    t,
                    "pdf-compact",
                    Profile::Pades(exec::Level::B),
                    "pades-b-compact",
                    "PAdES-B signature of the large-page full-size document",
                )
            },
        },
        Case {
            id: "cades-levels",
            surfaces: ALL,
            run: cades_levels,
        },
        Case {
            id: "cms-detached",
            surfaces: ALL,
            run: cms_detached,
        },
        Case {
            id: "cms-attached",
            surfaces: ALL,
            run: cms_attached,
        },
        Case {
            id: "cms-gost2015",
            surfaces: ALL,
            run: cms_gost,
        },
        Case {
            id: "cms-sign-limit-plus-one",
            surfaces: ALL,
            run: cms_limit,
        },
        Case {
            id: "cms-attached-output-limit",
            surfaces: &[Target::Sdk, Target::Cli],
            run: cms_output_limit,
        },
        Case {
            id: "hash-u64-boundaries",
            surfaces: ALL,
            run: hash_boundaries,
        },
        Case {
            id: "hash-limit-plus-one",
            surfaces: ALL,
            run: hash_limit,
        },
        Case {
            id: "hash-sha256-blob",
            surfaces: ALL,
            run: hash_basic,
        },
        Case {
            id: "hash-streebog512-blob",
            surfaces: ALL,
            run: hash_gost,
        },
        Case {
            id: "hash-unknown-length",
            surfaces: ALL,
            run: hash_unknown_length,
        },
        Case {
            id: "overload-profile",
            surfaces: &[Target::Http],
            run: profile::run,
        },
        Case {
            id: "overload-token-apdu",
            surfaces: &[Target::Http],
            run: overload::run_token,
        },
        Case {
            id: "overload-slot-release",
            surfaces: &[Target::Http],
            run: overload::run_slot_release,
        },
        Case {
            id: "http-progress-frame-rate",
            surfaces: &[Target::Http],
            run: overload::run_progress_rate,
        },
    ]
}

fn write_report(out: &Path, report: &Value) -> anyhow::Result<()> {
    let tmp = out.join("report.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(report)?)?;
    std::fs::rename(tmp, out.join("report.json"))?;
    Ok(())
}

pub fn run(args: ProofArgs) -> anyhow::Result<()> {
    let started = Instant::now();
    let out = std::path::absolute(&args.out)?;
    std::fs::create_dir_all(&out)?;
    let log_dir = out.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    let progress = std::sync::Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out.join("progress.log"))?,
    );
    let logf = |line: &str| {
        use std::io::Write;
        eprintln!("[platform-proof] {line}");
        let _ = writeln!(progress.lock().unwrap(), "{line}");
    };
    let mut log = |line: &str| logf(line);

    // ---- the stand: drives, scratch preflight ---------------------------------------
    let scratch_root = args.scratch_dir.clone().map_or_else(
        || out.join("scratch"),
        |p| std::path::absolute(&p).unwrap_or(p),
    );
    std::fs::create_dir_all(&scratch_root)?;
    let data_needed = args.document_bytes.saturating_mul(7);
    let out_storage =
        measure::preflight_storage(&out, args.scratch_bytes.saturating_add(data_needed))?;
    let scratch_storage = measure::preflight_storage(&scratch_root, args.scratch_bytes)?;
    let machine = measure::machine(&out_storage);
    log(&format!(
        "stand: {} / {} / {} logical CPUs / {} GiB RAM; data on {} ({}, {}, {} GiB free); {}",
        machine.os,
        machine.cpu,
        machine.logical_cpus,
        machine.physical_memory_bytes >> 30,
        out_storage.path,
        out_storage.filesystem,
        out_storage.kind,
        out_storage.free_bytes >> 30,
        machine.drive_media
    ));

    // ---- the independent reference generator is checked first -------------------------
    let python = python(&args)?;
    let tools = std::env::var_os("ONCL_PY_TOOLS").map(PathBuf::from);
    let reference =
        validate_reference(&python, tools.as_deref(), &out.join("reference"), &mut log)?;
    std::fs::write(
        out.join("reference-validation.json"),
        serde_json::to_vec_pretty(&reference)?,
    )?;

    // ---- data -------------------------------------------------------------------------
    let data_dir = out.join("data");
    let manifest = match (
        args.reuse_data,
        std::fs::read(data_dir.join("manifest.json")),
    ) {
        (true, Ok(bytes)) => {
            let m: Manifest = serde_json::from_slice(&bytes)?;
            if m.document_bytes != args.document_bytes || m.sets.iter().any(|s| !s.path.is_file()) {
                bail!(
                    "--reuse-data: the data of {} does not match --document-bytes",
                    data_dir.display()
                );
            }
            m
        }
        _ => generate_all(&data_dir, args.document_bytes, &mut log)?,
    };
    if args.generate_only {
        return Ok(());
    }

    // ---- programs, PKI, private directories ------------------------------------------
    let root = oncl_testkit::workspace_root();
    let bins = Bins::prepare(&root, args.skip_build)?;
    let pki = PkiServer::start(&bins.probe, &out.join("pki"))?;
    let secret_file = env::make_secret(&out.join("secret"), &pki.meta.password)?;
    let work_dir = out.join("work");
    std::fs::create_dir_all(&work_dir)?;
    let oracle_path = out.join("reference").join("oracle.py");
    let env = Env {
        args: args.clone(),
        root,
        data_dir,
        work_dir,
        scratch_root,
        log_dir,
        python,
        oracle: oracle_path,
        py_tools: tools,
        bins,
        pki,
        secret_file,
        manifest,
        timeout_seconds: 12 * 3600,
    };

    let programs: Vec<Value> = [("sdk_probe", &env.bins.probe), ("oncl", &env.bins.oncl), ("oncl-server", &env.bins.server)]
        .iter()
        .map(|(n, p)| json!({"name": n, "path": p.display().to_string(), "sha256": sha256_of(p), "bytes": std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)}))
        .collect();
    let artifacts: Vec<Value> = env
        .manifest
        .sets
        .iter()
        .map(|s| json!({"name": s.name, "bytes": s.digests.len, "sha256": s.digests.sha256, "sha512": s.digests.sha512, "generate_seconds": s.generate_seconds, "facts": s.facts}))
        .collect();
    let toolchain = Command::new("rustc")
        .arg("-V")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&env.root)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();

    let results: Vec<Value> = if args.resume {
        std::fs::read(out.join("report.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|r| r["cases"].as_array().cloned())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let report = json!({
        "command": {
            "document_bytes": args.document_bytes,
            "max_rss_bytes": args.max_rss_bytes,
            "scratch_bytes": args.scratch_bytes,
            "surface": format!("{:?}", args.surface),
        },
        "environment": {"machine": machine, "data_storage": out_storage, "scratch_storage": scratch_storage, "rustc": toolchain, "git_head": revision, "programs": programs},
        "reference_validation": reference,
        "artifacts": artifacts,
        "cases": results.clone(),
        "status": "RUNNING",
    });
    write_report(&out, &report)?;

    let wanted = |t: Target| {
        args.surface.includes(match t {
            Target::Sdk => Surface::Sdk,
            Target::Cli => Surface::Cli,
            Target::Http => Surface::Http,
        })
    };
    let cases = plan();
    let jobs: Vec<(Target, &Case)> = cases
        .iter()
        .filter(|c| args.only.is_empty() || args.only.iter().any(|o| c.id.contains(o.as_str())))
        .filter(|c| c.id != "http-progress-frame-rate" || args.only.iter().any(|o| o == c.id))
        .flat_map(|c| c.surfaces.iter().map(move |t| (*t, c)))
        .filter(|(t, _)| wanted(*t))
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let shared = std::sync::Mutex::new((results, report));
    std::thread::scope(|scope| {
        for _ in 0..args.jobs.max(1) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Some(&(target, case)) = jobs.get(index) else {
                        break;
                    };
                    let same = |r: &Value| r["surface"] == target.name() && r["id"] == case.id;
                    if args.resume
                        && shared.lock().unwrap().0.iter().any(|r| {
                            same(r)
                                && matches!(r["status"].as_str(), Some("PASS" | "FAIL" | "BLOCKED"))
                        })
                    {
                        logf(&format!(
                            "=== {} / {}: terminal result in the previous run, kept",
                            target.name(),
                            case.id
                        ));
                        continue;
                    }
                    logf(&format!("=== {} / {}", target.name(), case.id));
                    let began = Instant::now();
                    let result = match (case.run)(&env, target) {
                        Ok(r) => r,
                        Err(e) => CaseResult {
                            id: case.id.to_owned(),
                            surface: target.name(),
                            title: String::new(),
                            status: "FAIL",
                            seconds: began.elapsed().as_secs_f64(),
                            processes: vec![],
                            checks: vec![exec::Check {
                                name: "the case could be set up".into(),
                                ok: false,
                                detail: format!("{e:#}"),
                            }],
                            evidence: Default::default(),
                            max_criterion_bytes: 0,
                        },
                    };
                    logf(&format!(
                        "=== {} / {}: {} in {:.1}s, max peak {} MiB",
                        target.name(),
                        case.id,
                        result.status,
                        result.seconds,
                        result.max_criterion_bytes >> 20
                    ));
                    let mut guard = shared.lock().unwrap();
                    let (results, report) = &mut *guard;
                    results.retain(|r| !same(r));
                    if let Ok(v) = serde_json::to_value(&result) {
                        results.push(v);
                    }
                    report["cases"] = Value::Array(results.clone());
                    report["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
                    let _ = write_report(&out, report);
                }
            });
        }
    });
    let (results, mut report) = shared.into_inner().unwrap();
    let count = |s: &str| results.iter().filter(|r| r["status"] == s).count();
    let (failed, blocked, passed) = (count("FAIL"), count("BLOCKED"), count("PASS"));
    let status = if results.is_empty() || failed > 0 {
        "FAIL"
    } else if blocked > 0 {
        "BLOCKED"
    } else {
        "PASS"
    };
    report["status"] = json!(status);
    report["summary"] = json!({
        "passed": passed,
        "failed": failed,
        "blocked": blocked,
        "max_process_criterion_bytes": results.iter().filter_map(|r| r["max_criterion_bytes"].as_u64()).max().unwrap_or(0),
        "criterion": args.max_rss_bytes,
    });
    report["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
    write_report(&out, &report)?;
    log(&format!(
        "{status}: {passed} passed, {failed} failed, {blocked} blocked; report {}",
        out.join("report.json").display()
    ));
    if !args.keep_data {
        let _ = std::fs::remove_dir_all(env.work_dir.join("shared"));
    }
    if status != "PASS" {
        bail!("platform-proof {status}");
    }
    Ok(())
}
