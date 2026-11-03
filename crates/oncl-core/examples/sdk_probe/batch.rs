//! B01 actual file/CMS/progress/cancel exercise; synthetic trust only.
use crate::plugin_crypto as fixture;
use oncl_core::{
    Action, ExecutionGrant, OperationPolicy, SignRequest, VerifyRequest,
    batch::*,
    keys::{AppliedState, KeyRequest},
};
use oncl_pki::{
    io::{Source, TemporaryStore},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits},
};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
const DATA: &[u8] = b"B01 exact confirmed public source\n";
#[derive(Default)]
struct Control(AtomicBool);
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
struct FileSink {
    path: PathBuf,
    file: Option<File>,
}
impl FileSink {
    fn new(path: PathBuf) -> Self {
        Self { path, file: None }
    }
}
impl Write for FileSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(File::create_new(&self.path)?);
        }
        self.file.as_mut().unwrap().write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.flush()?;
        }
        Ok(())
    }
}
struct Unavailable(PathBuf);
impl Read for Unavailable {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        File::open(&self.0)?.read(bytes)
    }
}
fn openssl(out: &Path, name: &str, success: bool) -> Result<(), Box<dyn std::error::Error>> {
    let result = std::process::Command::new("openssl")
        .args([
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-noverify",
            "-in",
        ])
        .arg(out.join(name))
        .arg("-out")
        .arg(out.join(format!("{name}.verified")))
        .output()?;
    std::fs::write(
        out.join(format!("{name}.openssl.stdout.txt")),
        &result.stdout,
    )?;
    std::fs::write(
        out.join(format!("{name}.openssl.stderr.txt")),
        &result.stderr,
    )?;
    std::fs::write(
        out.join(format!("{name}.openssl.exit.txt")),
        format!("{}\n", result.status.code().unwrap_or(-1)),
    )?;
    if result.status.success() != success {
        return Err(format!("OpenSSL unexpected result for {name}: {}", result.status).into());
    }
    if success && std::fs::read(out.join(format!("{name}.verified")))? != DATA {
        return Err("independent verified output differs from confirmed source".into());
    }
    Ok(())
}
pub(super) fn run(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join("source.bin"), DATA)?;
    let scratch = tempfile::tempdir()?;
    let guard = Arc::new(fixture::Guard::default());
    let provider = Arc::new(fixture::Provider::default());
    let engine = fixture::engine(
        TemporaryStore::new(scratch.path())?,
        guard.clone(),
        provider.clone(),
        ResourceLimits::default(),
    );
    let key = fixture::selector("user-rsa-sign");
    let grant = ExecutionGrant::new([Action::Sign, Action::Verify]).with_keys([key.key_id()]);
    {
        let mut ctx = engine.begin(
            grant.clone(),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )?;
        let mut source = File::open(out.join("source.bin"))?;
        let mut reference = File::create_new(out.join("reference.cms"))?;
        engine.sign(
            SignRequest::cms_create(vec![KeyRequest::new(&key, Some(fixture::PASSWORD))], true),
            Source::seekable(&mut source, None),
            &mut reference,
            &mut ctx,
        )?;
    }
    let mut log = String::from(
        "case=B01\nprofile=synthetic RSA CMS; no NCA trust/platform/large-file claim\n",
    );
    {
        let mut ctx = engine.begin(
            grant.clone(),
            OperationPolicy::strict_online(),
            Arc::new(Control::default()),
        )?;
        let mut first = File::open(out.join("source.bin"))?;
        let mut verify = File::open(out.join("reference.cms"))?;
        let mut bad = Unavailable(out.join("absent-source.bin"));
        let mut last = File::open(out.join("source.bin"))?;
        let mut first_out = FileSink::new(out.join("full-first.cms"));
        let mut bad_out = FileSink::new(out.join("bad-never-created.cms"));
        let mut last_out = FileSink::new(out.join("full-last.cms"));
        let plan = engine.capture_batch(
            [
                BatchItem::new(
                    "first-sign",
                    BatchOperation::Sign {
                        request: SignRequest::cms_create(
                            vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                            true,
                        ),
                        input: Source::seekable(&mut first, None),
                        output: &mut first_out,
                    },
                ),
                BatchItem::new(
                    "verify",
                    BatchOperation::Verify {
                        request: VerifyRequest::cms(),
                        input: Source::seekable(&mut verify, None),
                        detached: None,
                    },
                ),
                BatchItem::new(
                    "bad-source",
                    BatchOperation::Sign {
                        request: SignRequest::cms_create(
                            vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                            true,
                        ),
                        input: Source::sequential(&mut bad, None),
                        output: &mut bad_out,
                    },
                ),
                BatchItem::new(
                    "last-sign",
                    BatchOperation::Sign {
                        request: SignRequest::cms_create(
                            vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                            true,
                        ),
                        input: Source::seekable(&mut last, None),
                        output: &mut last_out,
                    },
                ),
            ],
            &mut ctx,
        )?;
        // Trusted fixture host confirms this exact captured plan; run never approves.
        for item in plan.items() {
            log.push_str(&format!(
                "confirmed id={} action={:?} source_count={} key_count={}\n",
                item.id,
                item.action,
                item.sources.len(),
                item.keys.len()
            ));
        }
        let authority = plan.authorize(&ctx)?;
        let summary = engine.run_batch(plan, authority, &mut ctx, |event| if let BatchEvent::ItemFinished { result, attempted, completed, total, progress } = event { log.push_str(&format!("full id={} applied={:?} attempted={attempted} completed={completed} total={total} bytes_in={} bytes_out={}\n", result.id(), result.applied_state(), progress.bytes_in, progress.bytes_out)); })?;
        if summary.attempted != 4 || summary.completed != 3 || summary.stop.is_some() {
            return Err("mixed batch totals differ".into());
        }
        if !matches!(summary.results()[1].outcome(), BatchOutcome::Completed(BatchReport::Verify(r)) if r.verdict == oncl_pki::validation::Verdict::Valid)
        {
            return Err("reference CMS not genuinely valid".into());
        }
        if !matches!(summary.results()[2].outcome(), BatchOutcome::Failed(e) if e.code() == oncl_core::ErrorCode::Io && e.applied_state() == AppliedState::NotApplied)
        {
            return Err("bad source did not retain a local failure".into());
        }
        if guard.applied.load(Ordering::SeqCst) != 3 || provider.opens.load(Ordering::SeqCst) != 2 {
            return Err(
                "mixed private/key-open counts differ (including one reference fixture use)".into(),
            );
        }
    }
    {
        let control = Arc::new(Control::default());
        let mut ctx = engine.begin(grant, OperationPolicy::strict_online(), control.clone())?;
        let mut first = File::open(out.join("source.bin"))?;
        let mut verify = File::open(out.join("reference.cms"))?;
        let mut last = File::open(out.join("source.bin"))?;
        let mut first_out = FileSink::new(out.join("cancel-first.cms"));
        let mut last_out = FileSink::new(out.join("cancel-not-run.cms"));
        let plan = engine.capture_batch(
            [
                BatchItem::new(
                    "first-sign",
                    BatchOperation::Sign {
                        request: SignRequest::cms_create(
                            vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                            true,
                        ),
                        input: Source::seekable(&mut first, None),
                        output: &mut first_out,
                    },
                ),
                BatchItem::new(
                    "verify-not-run",
                    BatchOperation::Verify {
                        request: VerifyRequest::cms(),
                        input: Source::seekable(&mut verify, None),
                        detached: None,
                    },
                ),
                BatchItem::new(
                    "sign-not-run",
                    BatchOperation::Sign {
                        request: SignRequest::cms_create(
                            vec![KeyRequest::new(&key, Some(fixture::PASSWORD))],
                            true,
                        ),
                        input: Source::seekable(&mut last, None),
                        output: &mut last_out,
                    },
                ),
            ],
            &mut ctx,
        )?;
        let authority = plan.authorize(&ctx)?;
        let summary = engine.run_batch(plan, authority, &mut ctx, |event| if let BatchEvent::ItemFinished { result, attempted, completed, total, .. } = event { log.push_str(&format!("cancel id={} applied={:?} attempted={attempted} completed={completed} total={total}\n", result.id(), result.applied_state())); if completed == 1 { control.0.store(true, Ordering::SeqCst); } })?;
        if summary.attempted != 1
            || summary.completed != 1
            || summary.stop.as_ref().map(BatchStop::code) != Some(oncl_core::ErrorCode::Cancelled)
        {
            return Err("cancellation totals/cause differ".into());
        }
        if !summary.results()[1..].iter().all(|r| {
            matches!(r.outcome(), BatchOutcome::NotRun)
                && r.applied_state() == AppliedState::NotApplied
        }) {
            return Err("unexecuted item reported as executed".into());
        }
        if guard.applied.load(Ordering::SeqCst) != 4 || provider.opens.load(Ordering::SeqCst) != 3 {
            return Err("cancel private/context separation counts differ (including reference fixture context)".into());
        }
    }
    if out.join("cancel-not-run.cms").exists() || out.join("bad-never-created.cms").exists() {
        return Err("unexecuted output unexpectedly exists".into());
    }
    for name in [
        "full-first.cms",
        "full-last.cms",
        "cancel-first.cms",
        "reference.cms",
    ] {
        openssl(out, name, true)?;
    }
    let mut altered = std::fs::read(out.join("full-first.cms"))?;
    let position = altered
        .windows(DATA.len())
        .position(|window| window == DATA)
        .ok_or("attached content absent")?;
    altered[position] ^= 1;
    std::fs::write(out.join("altered.cms"), altered)?;
    openssl(out, "altered.cms", false)?;
    log.push_str("fixture_reference_private_use=1 fixture_reference_key_open=1\nfull_completed=3 full_attempted=4 full_private_use=2\ncancel_completed=1 cancel_attempted=1 cancel_private_use=1\nbatch_key_opens=2 batch_contexts=2\nnot_run_outputs=absent\nopenssl=4 positive + altered negative\n");
    std::fs::write(out.join("summary.txt"), log)?;
    println!(
        "case=B01 mixed=3/4 cancel=1/3 private=2+1 leases=1/context openssl=4-positive+1-negative not-run-outputs=absent out={}",
        out.display()
    );
    Ok(())
}
