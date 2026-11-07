//! `sdk_probe large <operation> ...`: ONE real SDK operation on a file of any size, run in
//! its own process so `cargo xtask platform-proof` can take the operating system's peak
//! memory of exactly this operation. It uses only the public `oncl-core` API, the default
//! `ResourceLimits` (apart from the host's deadline and the explicit probes below) and a
//! file key under strict validation against the loopback PKI of `sdk_probe pki-serve`.
//! The last line of stdout is `ONCL-PROOF-RESULT {json}`; the exit status is 0 whenever the
//! operation ran to a typed outcome (success, refusal or verdict) and 2 for a probe failure.
use super::*;
use oncl_core::{
    CadesConfiguration, ExtendRequest, OperationError, SignRequest, ValidationServices,
    VerifyRequest,
    keys::{
        AppliedState, KeyId, KeyRequest, KeySelector, KeySources, KeyUseEvent, KeyUseGuard,
        KeyUseOutcome, KeyUseReceipt,
    },
};
use oncl_pki::{
    cms::ades::ValidationMaterial,
    evidence::{AdesLevel, EvidenceLimits},
    http::{ProxySetting, UreqTransport},
    io::TemporaryStore,
    pkix::CaSet,
    validation::NetworkPolicy,
};
use serde_json::{Map, Value, json};
use std::{
    error::Error,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

type Res<T> = Result<T, Box<dyn Error>>;

#[derive(Default)]
struct Opts {
    operation: String,
    input: Option<String>,
    detached: Option<String>,
    output: Option<PathBuf>,
    pki: Option<PathBuf>,
    scratch: Option<PathBuf>,
    key: String,
    target: Option<String>,
    level: Option<String>,
    attached: bool,
    unknown_length: bool,
    input_limit: Option<u64>,
    output_limit: Option<u64>,
    temp_limit: Option<u64>,
    cancel_after_bytes: Option<u64>,
    timeout_seconds: u64,
    algorithm: Option<String>,
}

fn parse(args: Vec<String>) -> Res<Opts> {
    let mut o = Opts {
        key: "rsa".into(),
        timeout_seconds: 6 * 3600,
        ..Opts::default()
    };
    let mut it = args.into_iter();
    o.operation = it.next().ok_or("missing operation")?;
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--input" => o.input = Some(value()?),
            "--detached" => o.detached = Some(value()?),
            "--output" => o.output = Some(value()?.into()),
            "--pki" => o.pki = Some(value()?.into()),
            "--scratch" => o.scratch = Some(value()?.into()),
            "--key" => o.key = value()?,
            "--target" => o.target = Some(value()?),
            "--level" => o.level = Some(value()?),
            "--attached" => o.attached = true,
            "--unknown-length" => o.unknown_length = true,
            "--input-limit" => o.input_limit = Some(value()?.parse()?),
            "--output-limit" => o.output_limit = Some(value()?.parse()?),
            "--temp-limit" => o.temp_limit = Some(value()?.parse()?),
            "--cancel-after-bytes" => o.cancel_after_bytes = Some(value()?.parse()?),
            "--timeout-seconds" => o.timeout_seconds = value()?.parse()?,
            "--algorithm" => o.algorithm = Some(value()?),
            other => return Err(format!("unsupported argument {other}").into()),
        }
    }
    Ok(o)
}

struct ProofControl {
    cancel_after_bytes: Option<u64>,
    checkpoints: AtomicU64,
}
impl OperationControl for ProofControl {
    fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError> {
        self.checkpoints.fetch_add(1, Ordering::Relaxed);
        if let Some(limit) = self.cancel_after_bytes
            && (progress.bytes_in >= limit || progress.bytes_out >= limit)
        {
            return Err(ProcessingError::Cancelled);
        }
        Ok(())
    }
}

/// The host's key-use authority: counts every before-use and records every finish.
struct Authority {
    key: KeyId,
    begins: AtomicU64,
    applied: AtomicU64,
    unknown: AtomicU64,
}
impl KeyUseGuard for Authority {
    fn before_use(&self, event: &KeyUseEvent) -> Result<KeyUseReceipt, OperationError> {
        if event.action != Action::Sign || event.key_id != self.key {
            return Err(OperationError::PermissionDenied);
        }
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(KeyUseReceipt::new(event.clone()))
    }
    fn finish(&self, _: KeyUseReceipt, outcome: KeyUseOutcome) -> Result<(), OperationError> {
        match outcome.applied {
            AppliedState::Applied => {
                self.applied.fetch_add(1, Ordering::SeqCst);
            }
            AppliedState::Unknown => {
                self.unknown.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        Ok(())
    }
}

struct PkiFiles {
    origin: String,
    password: String,
    alias: String,
    key_path: PathBuf,
    root: oncl_pki::cert::Certificate,
    tsa_url: String,
    tsa_policy: String,
    dir: PathBuf,
}

fn load_pki(opts: &Opts) -> Res<PkiFiles> {
    let dir = opts.pki.clone().ok_or("--pki is required")?;
    let meta: Value = serde_json::from_slice(&std::fs::read(dir.join("pki.json"))?)?;
    let text = |k: &str| -> Res<String> {
        Ok(meta[k]
            .as_str()
            .ok_or_else(|| format!("pki.json: {k}"))?
            .to_owned())
    };
    let (file, alias) = match opts.key.as_str() {
        "rsa" => ("rsa.p12", text("alias_rsa")?),
        "gost" => ("gost.p12", text("alias_gost")?),
        other => return Err(format!("unknown key {other}").into()),
    };
    Ok(PkiFiles {
        origin: text("origin")?,
        password: text("password")?,
        alias,
        key_path: dir.join(file),
        root: oncl_pki::cert::parse(&std::fs::read(dir.join("root.cer"))?)?,
        tsa_url: text("tsa_url")?,
        tsa_policy: text("tsa_policy")?,
        dir,
    })
}

fn validation(pki: &PkiFiles) -> Res<ValidationServices> {
    Ok(ValidationServices::new(
        CaSet::new(vec![pki.root.clone()]),
        vec![],
        Arc::new(UreqTransport::with_proxy(ProxySetting::None)),
        NetworkPolicy::only_endpoints([pki.origin.as_str()])?,
        Arc::new(time::OffsetDateTime::now_utc),
    ))
}

fn level(text: &str) -> Res<AdesLevel> {
    Ok(match text {
        "b" => AdesLevel::B,
        "t" => AdesLevel::T,
        "lt" => AdesLevel::Lt,
        "lta" => AdesLevel::Lta,
        other => return Err(format!("unknown level {other}").into()),
    })
}

fn evidence_limits() -> EvidenceLimits {
    EvidenceLimits {
        max_items: 256,
        max_bytes: 16 * 1024 * 1024,
        max_item_bytes: 1024 * 1024,
        max_crl_bytes: 32 * 1024 * 1024,
        max_crl_item_bytes: 32 * 1024 * 1024,
        max_total_bytes: 48 * 1024 * 1024,
        max_chain_len: 16,
        max_proofs: 16,
        max_coverage_parts: 65536,
        // a host's evidence budget covering a whole 10 GiB document (the archive time-stamp
        // of an LTA level covers every document byte)
        max_coverage_bytes: 12 * 1024 * 1024 * 1024,
    }
}

enum Input {
    File(std::fs::File, u64),
    Stdin(io::Stdin),
}
impl Input {
    fn open(path: &str) -> Res<Self> {
        if path == "-" {
            return Ok(Self::Stdin(io::stdin()));
        }
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self::File(file, len))
    }
}

macro_rules! source {
    ($input:expr, $unknown:expr, $stdin:ident) => {
        match $input {
            Input::File(file, len) => {
                if $unknown {
                    Source::sequential(file, None)
                } else {
                    Source::seekable(file, Some(*len))
                }
            }
            Input::Stdin(stdin) => {
                $stdin = stdin.lock();
                Source::sequential(&mut $stdin, None)
            }
        }
    };
}

fn report_error(error: &OperationError) -> Value {
    json!({
        "code": format!("{:?}", error.code()),
        "applied": format!("{:?}", error.applied_state()),
        "message": error.to_string(),
    })
}

fn cell(label: &str, status: impl std::fmt::Debug) -> (String, Value) {
    (label.to_owned(), Value::String(format!("{status:?}")))
}

pub(super) fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    let opts = parse(args)?;
    let started = Instant::now();
    let mut out = Map::new();
    out.insert("operation".into(), opts.operation.clone().into());
    let result = execute(&opts, &mut out);
    out.insert("seconds".into(), started.elapsed().as_secs_f64().into());
    match result {
        Ok(()) => {
            out.insert("ok".into(), true.into());
        }
        Err(error) => match error.downcast::<OperationError>() {
            Ok(error) => {
                out.insert("ok".into(), false.into());
                out.insert("error".into(), report_error(&error));
            }
            Err(other) => {
                println!("probe failure: {other}");
                std::process::exit(2);
            }
        },
    }
    println!("ONCL-PROOF-RESULT {}", Value::Object(out));
    Ok(())
}

fn execute(opts: &Opts, out: &mut Map<String, Value>) -> Res<()> {
    let input_path = opts.input.clone().ok_or("--input is required")?;
    let mut limits = ResourceLimits {
        operation_timeout: Duration::from_secs(opts.timeout_seconds),
        ..ResourceLimits::default()
    };
    if let Some(v) = opts.input_limit {
        limits.input_bytes = v;
    }
    if let Some(v) = opts.output_limit {
        limits.output_bytes = v;
    }
    if let Some(v) = opts.temp_limit {
        limits.temp_bytes = v;
    }
    let scratch = opts.scratch.clone().ok_or("--scratch is required")?;
    std::fs::create_dir_all(&scratch)?;
    let store = TemporaryStore::new(&scratch)?;
    let control = Arc::new(ProofControl {
        cancel_after_bytes: opts.cancel_after_bytes,
        checkpoints: AtomicU64::new(0),
    });
    let op = opts.operation.as_str();
    let mut services = EngineServices::hash_only(limits).with_temporary_store(store.clone());
    let mut authority = None;
    let mut pki_files = None;
    let mut selector = None;
    if op != "hash" && op != "extract" {
        let pki = load_pki(opts)?;
        services = services.with_validation(validation(&pki)?);
        if op.contains("sign") {
            let key = KeySelector::file(&pki.key_path, Some(pki.alias.clone()))?;
            let guard = Arc::new(Authority {
                key: key.key_id(),
                begins: AtomicU64::new(0),
                applied: AtomicU64::new(0),
                unknown: AtomicU64::new(0),
            });
            services = services.with_keys(Arc::new(KeySources::new()), guard.clone());
            authority = Some(guard);
            selector = Some(key);
        }
        if matches!(opts.level.as_deref(), Some("t" | "lt" | "lta"))
            || op == "extend"
            || op == "xades-sign"
        {
            let mut tsa = oncl_pki::tsp::TsaSpec {
                url: pki.tsa_url.clone(),
                method: oncl_pki::http::PkiMethod::Post { content_type: None },
                hash: oncl_pki::key::HashAlg::Sha256,
                policy: Some(pki.tsa_policy.parse()?),
                nonce: oncl_pki::http::NonceSpec::Random(16),
                cert_req: true,
                retries: 0,
                timeout: Duration::from_secs(60),
                check_skew: Some(Duration::from_secs(300)),
                require_tsa_eku: true,
            };
            tsa.timeout = Duration::from_secs(60);
            services = services.with_cades(CadesConfiguration::new(evidence_limits(), tsa));
        }
        pki_files = Some(pki);
    }
    let engine = Engine::new(services)?;
    let mut input = Input::open(&input_path)?;
    let mut stdin_lock;
    let policy = OperationPolicy::strict_online();
    let action = match op {
        "hash" => Action::Hash,
        "extract" => Action::Extract,
        o if o.contains("verify") => Action::Verify,
        "extend" => Action::Extend,
        _ => Action::Sign,
    };
    let mut grant = ExecutionGrant::new([action]);
    if let Some(selector) = &selector {
        grant = grant.with_keys([selector.key_id()]);
    }
    let mut ctx = engine.begin(grant, policy, control.clone())?;
    let stage_out = |ctx: &mut oncl_core::OperationContext| store.stage(ctx.resources());
    let key = |selector: &KeySelector, pki: &PkiFiles| {
        // The password is borrowed from this stack frame for the request only.
        let _ = pki;
        selector.clone()
    };
    let _ = key;
    match op {
        "hash" => {
            let algorithm = match opts.algorithm.as_deref() {
                Some("sha256") | None => oncl_pki::key::HashAlg::Sha256,
                Some("sha512") => oncl_pki::key::HashAlg::Sha512,
                Some("streebog512") => oncl_pki::key::HashAlg::Streebog512,
                Some(other) => return Err(format!("unsupported algorithm {other}").into()),
            };
            let source = source!(&mut input, opts.unknown_length, stdin_lock);
            let report = engine.hash(algorithm, source, &mut ctx)?;
            out.insert("digest".into(), hex(report.digest.as_bytes()).into());
            out.insert("bytes_in".into(), report.bytes_in.into());
        }
        "extract" => {
            let source = source!(&mut input, opts.unknown_length, stdin_lock);
            let mut stage = stage_out(&mut ctx)?;
            let report = engine.extract_staged(source, &mut stage, &mut ctx)?;
            out.insert("bytes_written".into(), report.bytes_written.into());
            commit(stage, opts)?;
        }
        o if o.contains("verify") => {
            let request = verify_request(opts)?;
            let mut detached_input = opts.detached.as_deref().map(Input::open).transpose()?;
            let mut detached_lock;
            let detached = if let Some(input) = detached_input.as_mut() {
                Some(source!(input, false, detached_lock))
            } else {
                None
            };
            let source = source!(&mut input, opts.unknown_length, stdin_lock);
            let report = engine.verify(&request, source, detached, &mut ctx)?;
            out.insert("verdict".into(), format!("{:?}", report.verdict).into());
            out.insert("policy".into(), format!("{:?}", report.policy).into());
            let signers: Vec<Value> = report
                .signers
                .iter()
                .map(|s| {
                    Value::Object(Map::from_iter([
                        cell("signature", s.signature),
                        cell("chain", s.chain),
                        cell("validity", s.validity),
                        cell("revocation", s.revocation),
                        cell("timestamp", s.timestamp),
                    ]))
                })
                .collect();
            out.insert("signers".into(), signers.into());
            if let Some(xml) = &report.xml {
                let mut references = Vec::new();
                for signature in xml.signatures() {
                    for reference in signature.references() {
                        references.push(json!({
                            "target_len": reference.target.map(|t| t.len),
                        }));
                    }
                }
                out.insert("xml_references".into(), references.into());
            }
            if let Some(pdf) = &report.pdf {
                let mut text = format!("{pdf:?}");
                text.truncate(4000);
                out.insert("pdf_facts".into(), text.into());
            }
        }
        "extend" => {
            let lvl = level(opts.level.as_deref().ok_or("--level")?)?;
            let pki = pki_files.as_ref().ok_or("pki")?;
            let certificates = vec![
                pki.root.clone(),
                oncl_pki::cert::parse(&std::fs::read(pki.dir.join("tsa.der"))?)?,
            ];
            let leaf = std::fs::read(pki.dir.join(if opts.key == "gost" {
                "leaf-gost.ocsp"
            } else {
                "leaf-rsa.ocsp"
            }))?;
            let tsa_ocsp = std::fs::read(pki.dir.join("tsa.ocsp"))?;
            let ocsp = [leaf.as_slice(), tsa_ocsp.as_slice()];
            let material = ValidationMaterial {
                certificates: &certificates,
                ocsp: &ocsp,
                crls: &[],
            };
            let format = opts.target.as_deref().unwrap_or("cms");
            let request = match format {
                "cms" => ExtendRequest::cms(lvl),
                "pdf" => ExtendRequest::pdf(lvl, oncl_pdf::PdfLimits::default()),
                "xml" => ExtendRequest::xml(lvl),
                other => return Err(format!("unknown extend format {other}").into()),
            }
            .with_material(material)
            .with_evidence_limits(evidence_limits());
            let mut detached_input = opts.detached.as_deref().map(Input::open).transpose()?;
            let mut detached_lock;
            let request = match &mut detached_input {
                Some(input) => request.with_detached(source!(input, false, detached_lock)),
                None => request,
            };
            let source = source!(&mut input, opts.unknown_length, stdin_lock);
            let mut stage = stage_out(&mut ctx)?;
            let report = engine.extend_staged(&request, source, &mut stage, &mut ctx)?;
            out.insert("bytes_in".into(), report.bytes_in.into());
            out.insert("bytes_out".into(), report.bytes_out.into());
            out.insert("signers".into(), report.signer_count().into());
            commit(stage, opts)?;
        }
        _ => {
            let pki = pki_files.as_ref().ok_or("pki")?;
            let selector = selector.as_ref().ok_or("key selector")?;
            let key = || KeyRequest::new(selector, Some(pki.password.as_str()));
            let lvl = opts.level.as_deref().map(level).transpose()?;
            let ades = |l: AdesLevel| {
                let _ = l;
            };
            let _ = ades;
            let certificates = vec![pki.root.clone()];
            let ocsp: [&[u8]; 0] = [];
            let material = || ValidationMaterial {
                certificates: &certificates,
                ocsp: &ocsp,
                crls: &[],
            };
            let request = match op {
                "cms-sign" => SignRequest::cms_create(vec![key()], opts.attached),
                "cades-sign" => SignRequest::cades_create(
                    vec![key()],
                    opts.attached,
                    lvl.ok_or("--level")?,
                    material(),
                    evidence_limits(),
                ),
                "xml-sign" => SignRequest::xml(
                    key(),
                    oncl_xml::XmlSignProfile {
                        target: opts.target.as_deref(),
                        evidence_limits: Some(evidence_limits()),
                        ..oncl_xml::XmlSignProfile::default()
                    },
                ),
                "xades-sign" => SignRequest::xades(
                    key(),
                    oncl_xml::XmlSignProfile {
                        target: opts.target.as_deref(),
                        signature_id: Some("oncl-proof-signature"),
                        evidence_limits: Some(evidence_limits()),
                        ..oncl_xml::XmlSignProfile::default()
                    },
                    lvl.ok_or("--level")?,
                ),
                "wsse-sign" => {
                    SignRequest::wsse(key(), oncl_xml::wsse::SourceWsseSignProfile::default())
                }
                "pdf-sign" => SignRequest::pdf(key(), oncl_pdf::PdfSignProfile::default()),
                "pades-sign" => SignRequest::pades(
                    key(),
                    oncl_pdf::PdfSignProfile::default(),
                    lvl.ok_or("--level")?,
                    material(),
                    evidence_limits(),
                ),
                other => return Err(format!("unknown operation {other}").into()),
            };
            let source = source!(&mut input, opts.unknown_length, stdin_lock);
            let mut stage = stage_out(&mut ctx)?;
            let sign = engine.sign_staged(request, source, &mut stage, &mut ctx);
            if let Some(guard) = &authority {
                out.insert(
                    "key_begins".into(),
                    guard.begins.load(Ordering::SeqCst).into(),
                );
                out.insert(
                    "key_applied".into(),
                    guard.applied.load(Ordering::SeqCst).into(),
                );
                out.insert(
                    "key_unknown".into(),
                    guard.unknown.load(Ordering::SeqCst).into(),
                );
            }
            let report = sign?;
            out.insert("bytes_in".into(), report.bytes_in.into());
            out.insert("bytes_out".into(), report.bytes_out.into());
            out.insert("applied".into(), format!("{:?}", report.applied).into());
            out.insert("signers".into(), report.signer_count().into());
            drop(report);
            commit(stage, opts)?;
        }
    }
    out.insert(
        "checkpoints".into(),
        control.checkpoints.load(Ordering::Relaxed).into(),
    );
    Ok(())
}

fn commit(stage: oncl_pki::io::StagedArtifact, opts: &Opts) -> Res<()> {
    let path = opts.output.as_deref().ok_or("--output is required")?;
    stage.commit(path)?;
    Ok(())
}

fn verify_request(opts: &Opts) -> Res<VerifyRequest> {
    let lvl = opts.level.as_deref().map(level).transpose()?;
    Ok(match opts.operation.as_str() {
        "cms-verify" => VerifyRequest::cms(),
        "cades-verify" => VerifyRequest::cades(lvl.ok_or("--level")?, evidence_limits()),
        "xml-verify" => VerifyRequest::xml(),
        "xades-verify" => VerifyRequest::xades(lvl.ok_or("--level")?),
        "wsse-verify" => VerifyRequest::wsse(oncl_xml::wsse::WsseVerifyProfile::default()),
        "pdf-verify" => VerifyRequest::pdf(),
        "pades-verify" => VerifyRequest::pades(lvl.ok_or("--level")?, evidence_limits()),
        other => return Err(format!("unknown verify operation {other}").into()),
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[allow(dead_code)]
fn unused(_: &Path, _: &mut dyn Read) {}
