//! The overload profile: waves of stalled, uploading, CPU-bound and refused requests against the
//! REAL `oncl-server` configured with deliberately small shared budgets. The single-operation
//! RSS bound of the other cases says nothing about a busy server; this case records what the
//! server admitted and refused, its peak running/queued operations as the server itself exports
//! them (OTLP gauges), its shared temporary peak, the honesty of every answer (typed refusals,
//! never a hang or a 500) and its responsiveness.
//!
//! The outcome never depends on how the clients' threads happen to be scheduled. Since the
//! upload phase (docs/user/server.md, «Загрузки»), a body is received under one of `max_uploads`
//! upload slots, and only the whole body takes a `max_in_flight` slot and a worker; so the
//! profile is a sequence of WAVES, each started when the SERVER has reached the state the
//! previous wave was to produce (see [`super::barrier`]): the stalled uploads are PARKED (they
//! hold their slot until the harness lets go), the properties are observed against that parked
//! state, and no wave puts more clients in the upload phase than `max_uploads` can hold at once,
//! except the one probe that is meant to be refused. Which answer every client gets is then
//! fixed by the plan ([`Plan`]), not by a race.
//!
//! 1. *Five stalled uploads* (one slot short of `max_uploads = 6`, more than `max_in_flight` and
//!    `blocking_workers`): the server exports no pinned worker, a small request completes and a
//!    CPU-bound signature completes and verifies.
//! 2. *Every upload slot taken*: a CPU-bound signature already admitted completes; a further
//!    upload is refused `503 CapacityExceeded`/`NotApplied` before its body, after about
//!    `admission_wait_ms`; `/health` is answered throughout.
//! 3. *Disconnects*: the slots and spools of all six are free again (six new stalled uploads
//!    park at once).
//! 4. *A storm*: a 1 GiB upload and a disconnecting upload in progress, four CPU-bound
//!    signatures and three small requests next to them.
//! 5. *The idle rule* (a second server, `upload_idle_timeout_ms` short): stalled uploads are
//!    ended by the server with `504 DeadlineExceeded`/`NotApplied`, never held beyond the
//!    operation deadline, and their slots are free again.

use super::{
    DataSet, Facts,
    barrier::{all_hold, wait_until},
    clients::{
        self, BARRIER, Client, Ctx, Plan, Registry, ReleaseOnDrop, small, small_digest, stalling,
        upload,
    },
    env::{Env, ServerSettings},
    exec::{Case, CaseResult, Target},
    http_raw::{self, Probe, Source, Upload},
    otlp::Collector,
    overload::{
        GIB, MIB, hash_metadata, pattern_digest, pattern_digest_abc, percentile, sign_metadata,
    },
};
use crate::platform::{generate, measure::tree_usage};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// The profile server's upload slots (explicit, so that the counts below are exact).
const MAX_UPLOADS: usize = 6;
/// Stalled uploads of the first wave: one slot short of `MAX_UPLOADS`, and more than either
/// `max_in_flight` or `blocking_workers` of the profile server.
const FIRST_WAVE: usize = MAX_UPLOADS - 1;

/// Stops a server the case is done with, with the checks `Case::finish` makes for the last one.
fn retire_server(case: &mut Case<'_>, label: &str) -> anyhow::Result<()> {
    let mut server = case
        .server
        .take()
        .ok_or_else(|| anyhow::anyhow!("no server to stop"))?;
    let measured = server.stop()?;
    case.record(
        &format!("oncl-server ({label})"),
        "oncl-server serve",
        &measured,
    );
    let out = String::from_utf8_lossy(&measured.stdout).into_owned();
    case.check(
        &format!("{label}: server stopped gracefully"),
        measured.exit == Some(0) && out.contains("stopped"),
        out.trim().to_owned(),
    );
    match server.audit_counts() {
        Ok(c) => case.check(
            &format!("{label}: the durable audit journal has a FINAL for every BEGIN"),
            c.begin == c.finals,
            format!("{c:?}"),
        ),
        Err(e) => case.check(
            &format!("{label}: audit journal readable"),
            false,
            e.to_string(),
        ),
    }
    let (bytes, files) = tree_usage(&server.scratch);
    case.check(
        &format!("{label}: server scratch is empty after the server stopped"),
        files == 0,
        format!("{files} files, {bytes} bytes"),
    );
    // keep this server's operator directory and audit journal as evidence and free the name
    // for the next server of the case
    std::fs::rename(
        case.work.join("server"),
        case.work
            .join(format!("server-{}", label.replace(' ', "-"))),
    )?;
    Ok(())
}

pub fn run(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let mut case = Case::new(
        env,
        target,
        "overload-profile",
        "waves of stalled, uploading, CPU-bound and refused requests against the real oncl-server with small shared budgets, each wave started on observed server state",
    )?;
    if let Err(e) = body(&mut case) {
        case.check(
            "the overload case ran to completion",
            false,
            format!("{e:#}"),
        );
    }
    Ok(case.finish())
}

fn read_token(case: &Case<'_>) -> anyhow::Result<(String, String, std::path::PathBuf)> {
    let server = case.server.as_ref().unwrap();
    Ok((
        server.address.clone(),
        std::fs::read_to_string(&server.token_file)?
            .trim()
            .to_owned(),
        server.scratch.clone(),
    ))
}

fn body(case: &mut Case<'_>) -> anyhow::Result<()> {
    let env = case.env;
    let big = env.manifest.document_bytes.min(GIB);
    // small enough that four concurrent signatures finish well inside the deadline even when
    // the machine is busy with other cases of the same run
    let cpu_bytes = env.manifest.document_bytes.min(8 * MIB);
    let timeout_ms = 240_000u64;
    let admission_wait_ms = 4000u64;

    // the CPU-bound document, with its independent expectations
    let cpu_path = case.work.join("overload-cpu.xml");
    let (facts, digests) = generate::xml::generate(
        &cpu_path,
        cpu_bytes.max(64 * 1024),
        0x0A11,
        generate::xml::XmlKind::Archive,
    )?;
    let manifest_path = case.work.join("overload-manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&json!({"document_bytes": cpu_bytes, "sets": [DataSet {
            name: "overload-xml".into(),
            path: cpu_path.clone(),
            digests: digests.clone(),
            facts: Facts::Xml(facts),
            generate_seconds: 0.0,
        }]}))?,
    )?;
    let cpu = |name: String| Client {
        name,
        plan: Plan::Completes,
        upload: upload(sign_metadata(), Source::File(cpu_path.clone())),
        expected_digest: None,
        cpu: true,
    };

    let collector = Collector::start()?;
    // `max_uploads` is explicit: the exact slot counts below are the test, not a default that
    // follows `total_temp / (input_bytes + container_bytes)` (here 12 GiB / 2 GiB = 6).
    // `blocking_workers >= max_in_flight` (the documented default shape): an admitted
    // operation never waits for a worker, so how long a CPU-bound signature takes cannot turn
    // into a refusal. The idle timeout and the operation deadline are far beyond the run: only
    // the harness ends a stall here (the server's own rule is wave 5).
    let settings = ServerSettings {
        max_in_flight: 4,
        blocking_workers: 4,
        queue_capacity: 2,
        admission_wait_ms,
        operation_timeout_ms: timeout_ms,
        memory_per_operation: 268_435_456,
        // four concurrent signatures draw on the shared memory and metadata budgets (see
        // `metadata_bytes` below): room for all of them, so the budget cannot decide which of
        // them completes
        total_memory: GIB,
        temp_per_operation: 2 * GIB,
        total_temp: 12 * GIB,
        input_bytes: 1_073_741_824,
        tsa: false,
        max_connections: 64,
        telemetry_endpoint: Some(collector.url.clone()),
        token_alias: None,
        max_uploads: Some(MAX_UPLOADS),
        upload_idle_timeout_ms: Some(600_000),
        metadata_bytes: Some(512 * MIB),
    };
    case.server_settings = settings.clone();
    case.note(
        "server_settings",
        json!({
            "max_in_flight": settings.max_in_flight,
            "blocking_workers": settings.blocking_workers,
            "queue_capacity": settings.queue_capacity,
            "max_uploads": MAX_UPLOADS,
            "admission_wait_ms": settings.admission_wait_ms,
            "upload_idle_timeout_ms": settings.upload_idle_timeout_ms,
            "operation_timeout_ms": settings.operation_timeout_ms,
            "memory_per_operation": settings.memory_per_operation,
            "total_memory": settings.total_memory,
            "temp_per_operation": settings.temp_per_operation,
            "total_temp": settings.total_temp,
            "max_connections": settings.max_connections,
        }),
    );
    case.ensure_server()?;
    let (address, token, scratch) = read_token(case)?;

    let upload_digest = pattern_digest(0x6B, big);
    let ctx = Ctx::new(&address, &token);
    let stop = Arc::new(AtomicBool::new(false));
    let temp_peak = Arc::new(AtomicU64::new(0));
    let file_peak = Arc::new(AtomicU64::new(0));
    let beats = Mutex::new(Vec::<(u16, f64)>::new());
    let registry = Registry::default();
    let mut waves: Vec<Value> = Vec::new();

    let began = Instant::now();
    let wave_result: anyhow::Result<()> = thread::scope(|s| {
        // whatever happens below, every stalled client is let go and the helpers stop
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let _stop = StopOnDrop(stop.clone());
        let _release = ReleaseOnDrop(&registry);

        let (st, tp, fp, sp) = (
            stop.clone(),
            temp_peak.clone(),
            file_peak.clone(),
            scratch.clone(),
        );
        s.spawn(move || {
            while !st.load(Ordering::Relaxed) {
                let (bytes, files) = tree_usage(&sp);
                tp.fetch_max(bytes, Ordering::Relaxed);
                fp.fetch_max(files, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(100));
            }
        });
        let st = stop.clone();
        let (a2, t2) = (address.clone(), token.clone());
        let beats = &beats;
        s.spawn(move || {
            while !st.load(Ordering::Relaxed) {
                let (status, took) = http_raw::get(&a2, &t2, "/health");
                beats.lock().unwrap().push((status, took.as_secs_f64()));
                thread::sleep(Duration::from_millis(150));
            }
        });

        let ctx = &ctx;
        let spawn_client = |client: Client, probe: Arc<Probe>| {
            s.spawn(move || {
                ctx.run(client, &probe);
            });
        };
        // a stalled client, registered so that it is let go however this closure ends
        let stall = |name: String| -> Arc<Probe> {
            let probe = registry.probe();
            spawn_client(
                Client {
                    name,
                    plan: Plan::ClientEnds,
                    upload: stalling(big),
                    expected_digest: None,
                    cpu: false,
                },
                probe.clone(),
            );
            probe
        };
        let spools = || tree_usage(&scratch);
        // every one of `probes` holds an upload slot with its bytes written, and the scratch
        // holds `total` spools of what the server received
        let park = |label: &str, probes: &[Arc<Probe>], total: u64| -> anyhow::Result<(u64, u64)> {
            clients::park(label, probes, &scratch, total)
        };
        // fresh gauges: executor running, executor queued, requests in flight
        let gauges = |after: f64| -> Option<(f64, f64, f64)> {
            Some((
                collector.second_after("oncl.executor.running", after)?,
                collector.second_after("oncl.executor.queued", after)?,
                collector.second_after("oncl.requests.in_flight", after)?,
            ))
        };
        let settle = |label: &str, after: f64| -> anyhow::Result<(f64, f64, f64)> {
            wait_until(&format!("{label}: exported gauges"), BARRIER, || {
                gauges(after)
            })
        };
        // the slots and spools of let-go clients are free again
        let drained = |label: &str, probes: &[Arc<Probe>]| -> anyhow::Result<(f64, f64, f64)> {
            for probe in probes {
                probe.release();
            }
            wait_until(
                &format!("{label}: every disconnected client's spool to be deleted"),
                BARRIER,
                || (spools().1 == 0).then_some(()),
            )?;
            // "no request in flight" holds from here on (nothing is started meanwhile): any
            // export received after this point shows it, or a later one will
            let at = collector.elapsed();
            wait_until(
                &format!("{label}: the server to see every connection closed"),
                BARRIER,
                || {
                    let g = (
                        collector.latest_after("oncl.executor.running", at)?,
                        collector.latest_after("oncl.executor.queued", at)?,
                        collector.latest_after("oncl.requests.in_flight", at)?,
                    );
                    (g.2 == 0.0).then_some(g)
                },
            )
        };

        // ------------------------------------------------ wave 1: one slot short of full
        let wave1: Vec<Arc<Probe>> = (0..FIRST_WAVE)
            .map(|i| stall(format!("stall-a{i}")))
            .collect();
        let parked = park("wave 1", &wave1, FIRST_WAVE as u64);
        case.check(
            &format!("wave 1: {FIRST_WAVE} uploads stalled mid-body (more than max_in_flight {} and blocking_workers {}) each hold an upload slot and their spool", settings.max_in_flight, settings.blocking_workers),
            parked.is_ok(),
            match &parked {
                Ok((bytes, files)) => format!("{files} spools, {bytes} bytes"),
                Err(e) => format!("{e:#}"),
            },
        );
        parked?;
        let at = collector.elapsed();
        let (running, queued, in_flight) = settle("wave 1", at)?;
        waves.push(json!({"wave": 1, "stalled": FIRST_WAVE, "executor_running": running, "executor_queued": queued, "requests_in_flight": in_flight}));
        case.check(
            "wave 1: the stalled uploads pin no native worker and queue nothing (exported gauges after all were parked)",
            running == 0.0 && queued == 0.0,
            format!("running {running}, queued {queued}, requests in flight {in_flight}"),
        );
        // (a) the property the product promises: nothing but upload slots is held
        let began_small = Instant::now();
        let reply = ctx.run(
            Client {
                name: "small-1".into(),
                ..small()
            },
            &Probe::default(),
        );
        let digest = small_digest(&reply);
        case.check(
            &format!("(a) while {FIRST_WAVE} uploads are stalled a small request is admitted and completes with the right digest"),
            reply.status == 200 && digest.as_deref() == Some(pattern_digest_abc().as_str()),
            format!("status {}, {:.2}s, digest {digest:?}", reply.status, began_small.elapsed().as_secs_f64()),
        );
        let began_cpu = Instant::now();
        let reply = ctx.run(cpu("cpu-under-stall".into()), &Probe::default());
        let completed =
            http_raw::multipart_final(&reply).is_some_and(|(f, _)| f["status"] == "completed");
        case.check(
            &format!("(a) while {FIRST_WAVE} uploads are stalled a CPU-bound signature is admitted and completes"),
            reply.status == 200 && completed,
            format!("status {}, completed {completed}, {:.2}s", reply.status, began_cpu.elapsed().as_secs_f64()),
        );
        let still = wave1.iter().all(|p| p.answered().is_none());
        case.check(
            "wave 1: the stalled uploads were still stalled while that work completed (no answer, no close)",
            still,
            format!("{} of {FIRST_WAVE} unanswered", wave1.iter().filter(|p| p.answered().is_none()).count()),
        );

        // ------------------------------------------------ wave 2: every upload slot taken
        let c0_probe = Arc::new(Probe::default());
        spawn_client(cpu("cpu-running".into()), c0_probe.clone());
        let admitted = wait_until(
            "wave 2: the CPU-bound signature to be admitted (answer head received)",
            BARRIER,
            || c0_probe.answered().map(|_| ()),
        );
        case.check(
            "wave 2: a CPU-bound signature is admitted (its answer began) before the last upload slot is taken",
            admitted.is_ok(),
            match &admitted {
                Ok(()) => "answer head received".to_owned(),
                Err(e) => format!("{e:#}"),
            },
        );
        admitted?;
        let last = stall("stall-a-last".into());
        let wave2: Vec<Arc<Probe>> = wave1.iter().cloned().chain([last]).collect();
        let parked = park("wave 2", &wave2[FIRST_WAVE..], MAX_UPLOADS as u64);
        case.check(
            &format!(
                "wave 2: the sixth stalled upload takes the last of the {MAX_UPLOADS} upload slots"
            ),
            parked.is_ok(),
            match &parked {
                Ok((bytes, files)) => format!("{files} spools, {bytes} bytes"),
                Err(e) => format!("{e:#}"),
            },
        );
        parked?;
        let beats_before = beats.lock().unwrap().len();
        let refused = ctx.run(
            Client {
                name: "refused-probe".into(),
                plan: Plan::Refused,
                ..small()
            },
            &Probe::default(),
        );
        let beats_after = beats.lock().unwrap().len();
        let code = refused
            .json()
            .and_then(|j| j["code"].as_str().map(str::to_owned));
        let applied = refused
            .json()
            .and_then(|j| j["applied"].as_str().map(str::to_owned));
        let waited = refused.elapsed.as_secs_f64();
        case.check(
            "(b) with every upload slot taken by a stalled upload a further upload is refused 503 CapacityExceeded NotApplied before its body, after about admission_wait_ms",
            refused.status == 503
                && code.as_deref() == Some("CapacityExceeded")
                && applied.as_deref() == Some("NotApplied")
                && refused.refused_before_body
                && refused.sent_document_bytes == 0
                && waited >= admission_wait_ms as f64 / 1000.0 * 0.9
                && waited < admission_wait_ms as f64 / 1000.0 + 30.0,
            format!("status {}, code {code:?}, applied {applied:?}, before body {}, {} document bytes sent, refused after {waited:.2}s of {}s", refused.status, refused.refused_before_body, refused.sent_document_bytes, admission_wait_ms as f64 / 1000.0),
        );
        let window: Vec<(u16, f64)> = beats.lock().unwrap()[beats_before..beats_after].to_vec();
        let (probe_status, probe_took) = http_raw::get(&address, &token, "/health");
        case.check(
            "(b) /health is answered 200 throughout, with every upload slot taken",
            probe_status == 200
                && !window.is_empty()
                && window.iter().all(|(s, took)| *s == 200 && *took < 5.0),
            format!("{} heartbeats during the refusal, all 200: {}, one more answer {probe_status} in {probe_took:?}", window.len(), window.iter().all(|(s, _)| *s == 200)),
        );
        let running = wait_until(
            "wave 2: the admitted CPU-bound signature to end",
            BARRIER,
            || ctx.has_ended("cpu-running").then_some(()),
        );
        let reply = ctx.reply_of("cpu-running").unwrap_or_default();
        let completed =
            http_raw::multipart_final(&reply).is_some_and(|(f, _)| f["status"] == "completed");
        case.check(
            "(b) the operation admitted before the last slot was taken is unaffected: it completes",
            running.is_ok() && reply.status == 200 && completed,
            format!("status {}, completed {completed}", reply.status),
        );
        waves.push(json!({"wave": 2, "refused_after_s": waited, "heartbeats_during_refusal": window.len()}));

        // ------------------------------------------------ wave 3: disconnects free the slots
        let drain = drained("wave 3", &wave2);
        case.check(
            "(c) when the stalled clients disconnect, every spool is deleted and the server sees no request in flight",
            drain.is_ok(),
            match &drain {
                Ok((running, queued, in_flight)) => format!("running {running}, queued {queued}, in flight {in_flight}"),
                Err(e) => format!("{e:#}"),
            },
        );
        drain?;
        let wave3: Vec<Arc<Probe>> = (0..MAX_UPLOADS)
            .map(|i| stall(format!("stall-b{i}")))
            .collect();
        let parked = park("wave 3", &wave3, MAX_UPLOADS as u64);
        case.check(
            &format!("(c) all {MAX_UPLOADS} upload slots are free again: {MAX_UPLOADS} new stalled uploads each take one at once"),
            parked.is_ok(),
            match &parked {
                Ok((bytes, files)) => format!("{files} spools, {bytes} bytes"),
                Err(e) => format!("{e:#}"),
            },
        );
        parked?;
        let drain = drained("wave 3 (again)", &wave3);
        case.check(
            "(c) and they free every slot and spool again when they disconnect",
            drain.is_ok(),
            match &drain {
                Ok((_, _, in_flight)) => format!("{in_flight} requests in flight"),
                Err(e) => format!("{e:#}"),
            },
        );
        drain?;

        // ------------------------------------------------ wave 4: the storm
        let uploading = Arc::new(Probe::default());
        spawn_client(
            Client {
                name: "upload-0".into(),
                plan: Plan::Completes,
                upload: Upload {
                    chunked: true,
                    bytes_per_second: Some(128 * MIB),
                    ..upload(
                        hash_metadata(),
                        Source::Pattern {
                            byte: 0x6B,
                            len: big,
                        },
                    )
                },
                expected_digest: Some(upload_digest.clone()),
                cpu: false,
            },
            uploading.clone(),
        );
        let disconnecting = Arc::new(Probe::default());
        spawn_client(
            Client {
                name: "disconnect-0".into(),
                plan: Plan::ClientEnds,
                upload: Upload {
                    chunked: true,
                    bytes_per_second: Some(128 * MIB),
                    abort_after: Some(big.min(64 * MIB)),
                    ..upload(
                        hash_metadata(),
                        Source::Pattern {
                            byte: 0x6B,
                            len: big,
                        },
                    )
                },
                expected_digest: None,
                cpu: false,
            },
            disconnecting.clone(),
        );
        let target = big.min(256 * MIB);
        let started = wait_until(
            "wave 4: the big upload to be in progress (100 Continue and its first bytes written) next to the disconnecting one",
            BARRIER,
            || {
                (uploading.continued()
                    && disconnecting.continued()
                    && uploading.document_sent() >= target)
                    .then_some(())
            },
        );
        case.check(
            "wave 4: a large upload is in progress under its upload slot when the CPU-bound wave starts",
            started.is_ok(),
            match &started {
                Ok(()) => format!("{} document bytes written", uploading.document_sent()),
                Err(e) => format!("{e:#}"),
            },
        );
        started?;
        for i in 0..4 {
            spawn_client(cpu(format!("cpu-{i}")), Arc::new(Probe::default()));
        }
        wait_until(
            "wave 4: the four CPU-bound signatures to end",
            BARRIER + Duration::from_secs(150),
            || {
                (0..4)
                    .all(|i| ctx.has_ended(&format!("cpu-{i}")))
                    .then_some(())
            },
        )?;
        for i in 0..3 {
            spawn_client(
                Client {
                    name: format!("late-{i}"),
                    ..small()
                },
                Arc::new(Probe::default()),
            );
        }
        wait_until(
            "wave 4: the small requests, the large upload and the disconnect to end",
            BARRIER + Duration::from_secs(150),
            || {
                (0..3)
                    .all(|i| ctx.has_ended(&format!("late-{i}")))
                    .then_some(())
                    .filter(|_| ctx.has_ended("upload-0") && ctx.has_ended("disconnect-0"))
            },
        )?;
        Ok(())
    });
    let storm_seconds = began.elapsed().as_secs_f64();
    case.note("storm_seconds", json!(storm_seconds));
    case.note("waves", Value::Array(waves));
    stop.store(true, Ordering::Relaxed);
    wave_result?;
    let _ = timeout_ms;
    judge(
        case,
        &ctx,
        &collector,
        &settings,
        &scratch,
        &address,
        &token,
        &temp_peak,
        &file_peak,
        &beats,
        &manifest_path,
        admission_wait_ms,
    )?;
    retire_server(case, "profile server")?;
    idle_rule(case, big)
}

/// The answers of every client against the plan, the independent check of a result, and the
/// server's own account of the whole run.
#[allow(clippy::too_many_arguments)]
fn judge(
    case: &mut Case<'_>,
    ctx: &Ctx<'_>,
    collector: &Collector,
    settings: &ServerSettings,
    scratch: &Path,
    address: &str,
    token: &str,
    temp_peak: &AtomicU64,
    file_peak: &AtomicU64,
    beats: &Mutex<Vec<(u16, f64)>>,
    manifest_path: &Path,
    admission_wait_ms: u64,
) -> anyhow::Result<()> {
    let env = case.env;
    let outcomes = std::mem::take(&mut *ctx.outcomes.lock().unwrap());
    let launched = ctx.launched.load(Ordering::SeqCst);
    case.check(
        "every client got an end (answer or close), none hung",
        outcomes.len() as u64 == launched,
        format!("{} of {launched}", outcomes.len()),
    );

    let mut rows = Vec::new();
    let mut unexpected = Vec::new();
    let mut completed_cpu = Vec::new();
    for o in &outcomes {
        let json = o.reply.json();
        let code = json
            .as_ref()
            .and_then(|j| j["code"].as_str())
            .map(str::to_owned);
        let applied = json
            .as_ref()
            .and_then(|j| j["applied"].as_str())
            .map(str::to_owned);
        let streamed = http_raw::multipart_final(&o.reply);
        let final_completed = match &streamed {
            Some((f, _)) => f["status"] == "completed",
            None => json.as_ref().is_some_and(|j| j["status"] == "completed"),
        };
        let digest_ok = o.expected_digest.as_ref().is_none_or(|expected| {
            json.as_ref()
                .and_then(|j| j["results"][0]["result"]["digest"].as_str())
                == Some(expected.as_str())
        });
        let verdict = match (o.plan, o.reply.status) {
            (Plan::Completes, 200) if final_completed && digest_ok => "completed",
            (Plan::Refused, 503)
                if code.as_deref() == Some("CapacityExceeded")
                    && applied.as_deref() == Some("NotApplied") =>
            {
                "refused: CapacityExceeded"
            }
            (Plan::ServerEnds, 504)
                if code.as_deref() == Some("DeadlineExceeded")
                    && applied.as_deref() == Some("NotApplied") =>
            {
                "ended by the server: DeadlineExceeded"
            }
            (Plan::ClientEnds, 0) if o.reply.transport_error.is_some() => "client disconnected",
            _ => {
                unexpected.push(format!(
                    "{} ({:?}) answered {} code {:?} applied {:?} completed={final_completed} digest_ok={digest_ok} transport {:?}",
                    o.name, o.plan, o.reply.status, code, applied, o.reply.transport_error
                ));
                "UNEXPECTED"
            }
        };
        if o.cpu
            && verdict == "completed"
            && let Some((_, artifact)) = streamed
        {
            completed_cpu.push(artifact);
        }
        rows.push(json!({
            "client": o.name, "plan": format!("{:?}", o.plan), "status": o.reply.status, "code": code, "applied": applied,
            "verdict": verdict, "started_s": o.started, "ended_s": o.ended, "seconds": o.reply.elapsed.as_secs_f64(),
            "sent_document_bytes": o.reply.sent_document_bytes, "refused_before_body": o.reply.refused_before_body,
            "transport_error": o.reply.transport_error,
        }));
    }
    rows.sort_by(|a, b| {
        a["ended_s"]
            .as_f64()
            .partial_cmp(&b["ended_s"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    case.note("clients_detail", Value::Array(rows.clone()));
    case.check(
        "every answer is the one the plan says: a completed result, a typed honest refusal (no 500, no untyped close, a key never applied on a refusal) or the client's own close",
        unexpected.is_empty(),
        unexpected.join("; "),
    );
    let count = |v: &str| {
        rows.iter()
            .filter(|r| r["verdict"].as_str().is_some_and(|x| x.starts_with(v)))
            .count()
    };
    case.note(
        "answers",
        json!({"completed": count("completed"), "refused": count("refused"), "disconnected": count("client")}),
    );
    case.check(
        "overload produced honest refusals (the budgets bound the work)",
        count("refused") > 0,
        format!("{} refusals", count("refused")),
    );
    case.check(
        "work that was admitted completed",
        count("completed") > 0 && !rows.iter().any(|r| r["verdict"] == "UNEXPECTED"),
        format!("{} completed", count("completed")),
    );
    let cpu_total = outcomes.iter().filter(|o| o.cpu).count();
    case.check(
        "every CPU-bound signature completed under load",
        completed_cpu.len() == cpu_total && cpu_total > 0,
        format!("{} of {cpu_total}", completed_cpu.len()),
    );

    // independent result check
    if let Some(artifact) = completed_cpu.first() {
        let signed = case.work.join("overload-signed.xml");
        std::fs::write(&signed, artifact)?;
        match env.oracle(&[
            "xml-signature".as_ref(),
            signed.as_os_str(),
            manifest_path.as_os_str(),
            "overload-xml".as_ref(),
            "archive-end".as_ref(),
            "rsa".as_ref(),
        ]) {
            Ok(v) => case.check(
                "a signature produced under load is correct (independent oracle)",
                v["ok"] == true,
                v.to_string(),
            ),
            Err(e) => case.check(
                "a signature produced under load is correct (independent oracle)",
                false,
                format!("{e:#}"),
            ),
        }
    } else {
        case.check(
            "a CPU-bound signature completed under load",
            false,
            "none completed",
        );
    }

    // the server's own account
    let started = Instant::now();
    loop {
        let (_, files) = tree_usage(scratch);
        if files == 0 || started.elapsed() > Duration::from_secs(180) {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    let (bytes, files) = tree_usage(scratch);
    case.check(
        "the shared scratch is empty once the storm is over",
        files == 0,
        format!(
            "{files} files, {bytes} bytes after {:.0}s",
            started.elapsed().as_secs_f64()
        ),
    );
    thread::sleep(Duration::from_millis(1500)); // one more export interval
    let running = collector.peak("oncl.executor.running");
    let queued = collector.peak("oncl.executor.queued");
    let in_flight = collector.peak("oncl.requests.in_flight");
    case.note(
        "server_reported_peaks",
        json!({"executor_running": running, "executor_queued": queued, "requests_in_flight": in_flight,
               "executor_rejected_total": collector.last("oncl.executor.rejected"), "exports": collector.samples().len()}),
    );
    case.check(
        "the server exported its concurrency gauges",
        running.is_some() && queued.is_some() && in_flight.is_some(),
        format!("{} samples", collector.samples().len()),
    );
    case.check(
        "peak running native operations never exceeded blocking_workers (and the signatures did run)",
        running.is_some_and(|r| r >= 1.0 && r <= settings.blocking_workers as f64),
        format!("{running:?} of {}", settings.blocking_workers),
    );
    case.check(
        "peak queued operations never exceeded queue_capacity",
        queued.is_some_and(|q| q <= settings.queue_capacity as f64),
        format!("{queued:?} of {}", settings.queue_capacity),
    );
    case.check(
        "the server saw every stalled upload as a request in flight (at least the six of the full wave)",
        in_flight.is_some_and(|n| n >= MAX_UPLOADS as f64),
        format!("peak {in_flight:?}"),
    );
    let peak_temp = temp_peak.load(Ordering::Relaxed);
    case.note("shared_temp", json!({"peak_bytes": peak_temp, "peak_files": file_peak.load(Ordering::Relaxed), "configured_total_temp": settings.total_temp}));
    case.check(
        "the shared temporary peak stayed within total_temp",
        peak_temp <= settings.total_temp,
        format!("{peak_temp} of {}", settings.total_temp),
    );
    let beats = beats.lock().unwrap().clone();
    let mut latencies: Vec<f64> = beats.iter().map(|(_, t)| *t).collect();
    latencies.sort_by(f64::total_cmp);
    let bad: Vec<_> = beats.iter().filter(|(s, _)| *s != 200).collect();
    case.note("responsiveness", json!({"health_requests": beats.len(), "non_200": bad.len(), "p50_s": percentile(&latencies, 0.5), "p99_s": percentile(&latencies, 0.99), "max_s": latencies.last()}));
    case.check(
        "/health stayed answerable under load (every answer 200, none slower than 5 s)",
        !beats.is_empty() && bad.is_empty() && latencies.last().is_some_and(|m| *m < 5.0),
        format!(
            "{} requests, max {:.3}s, {} not 200",
            beats.len(),
            latencies.last().copied().unwrap_or(0.0),
            bad.len()
        ),
    );
    let _ = admission_wait_ms;
    // a fresh request after the storm is served normally
    let fresh = http_raw::send(
        address,
        token,
        &Upload {
            expect_continue: false,
            ..upload(hash_metadata(), Source::Bytes(b"abc".to_vec()))
        },
    );
    let digest = small_digest(&fresh);
    case.check(
        "a request after the storm completes with the right digest",
        fresh.status == 200 && digest.as_deref() == Some(pattern_digest_abc().as_str()),
        format!("status {}, digest {digest:?}", fresh.status),
    );
    Ok(())
}

/// Wave 5: the server's own rule for a stalled upload, on a server whose idle timeout is short.
fn idle_rule(case: &mut Case<'_>, big: u64) -> anyhow::Result<()> {
    const UPLOADS: usize = 2;
    let idle_ms = 3000u64;
    let timeout_ms = 60_000u64;
    case.server_settings = ServerSettings {
        max_in_flight: 2,
        blocking_workers: 2,
        queue_capacity: 2,
        admission_wait_ms: 3000,
        operation_timeout_ms: timeout_ms,
        memory_per_operation: 268_435_456,
        total_memory: 536_870_912,
        temp_per_operation: 2 * GIB,
        total_temp: 4 * GIB,
        input_bytes: 1_073_741_824,
        tsa: false,
        max_connections: 64,
        telemetry_endpoint: None,
        token_alias: None,
        max_uploads: Some(UPLOADS),
        upload_idle_timeout_ms: Some(idle_ms),
        metadata_bytes: None,
    };
    case.note(
        "idle_rule_server",
        json!({"max_uploads": UPLOADS, "upload_idle_timeout_ms": idle_ms, "operation_timeout_ms": timeout_ms, "admission_wait_ms": 3000}),
    );
    case.ensure_server()?;
    let (address, token, scratch) = read_token(case)?;
    let ctx = Ctx::new(&address, &token);
    let registry = Registry::default();
    let result: anyhow::Result<()> = thread::scope(|s| {
        let _release = ReleaseOnDrop(&registry);
        let ctx = &ctx;
        let stall = |name: String, plan: Plan| -> Arc<Probe> {
            let probe = registry.probe();
            let p = probe.clone();
            s.spawn(move || {
                ctx.run(
                    Client {
                        name,
                        plan,
                        upload: stalling(big),
                        expected_digest: None,
                        cpu: false,
                    },
                    &p,
                );
            });
            probe
        };
        let park = |probes: &[Arc<Probe>]| {
            wait_until(
                "every stalled upload to see 100 Continue and write its bytes",
                BARRIER,
                || {
                    let flags: Vec<bool> = probes
                        .iter()
                        .map(|p| p.continued() && p.stalled())
                        .collect();
                    all_hold(&flags).then_some(())
                },
            )
        };
        let first: Vec<Arc<Probe>> = (0..UPLOADS)
            .map(|i| stall(format!("idle-a{i}"), Plan::ServerEnds))
            .collect();
        let parked = park(&first);
        case.check(
            &format!("idle rule: {UPLOADS} uploads stall mid-body (every upload slot)"),
            parked.is_ok(),
            match &parked {
                Ok(()) => "parked".to_owned(),
                Err(e) => format!("{e:#}"),
            },
        );
        parked?;
        let ended = wait_until(
            "the server to end both stalled uploads by its own rule",
            BARRIER,
            || (ctx.has_ended("idle-a0") && ctx.has_ended("idle-a1")).then_some(()),
        );
        case.check(
            "idle rule: the server ended the stalled uploads by itself (the harness did not let go)",
            ended.is_ok() && first.iter().all(|p| p.answered().is_some()),
            match &ended {
                Ok(()) => "both answered".to_owned(),
                Err(e) => format!("{e:#}"),
            },
        );
        ended?;
        // a stalled upload is ended by the idle rule, never held beyond the operation deadline
        let mut detail = Vec::new();
        let mut within = true;
        for name in ["idle-a0", "idle-a1"] {
            let reply = ctx.reply_of(name).unwrap_or_default();
            let code = reply
                .json()
                .and_then(|j| j["code"].as_str().map(str::to_owned));
            let applied = reply
                .json()
                .and_then(|j| j["applied"].as_str().map(str::to_owned));
            let seconds = reply.elapsed.as_secs_f64();
            within &= reply.status == 504
                && code.as_deref() == Some("DeadlineExceeded")
                && applied.as_deref() == Some("NotApplied")
                && seconds >= idle_ms as f64 / 1000.0 * 0.9
                && seconds < timeout_ms as f64 / 1000.0;
            detail.push(format!(
                "{name}: {} {code:?} {applied:?} in {seconds:.1}s",
                reply.status
            ));
        }
        case.check(
            &format!("a stalled upload is ended by the idle rule (504 DeadlineExceeded, NotApplied) after about the idle timeout ({}s), never held to the operation deadline ({}s)", idle_ms / 1000, timeout_ms / 1000),
            within,
            detail.join(", "),
        );
        wait_until("the ended uploads' spools to be deleted", BARRIER, || {
            (tree_usage(&scratch).1 == 0).then_some(())
        })?;
        let again: Vec<Arc<Probe>> = (0..UPLOADS)
            .map(|i| stall(format!("idle-b{i}"), Plan::ClientEnds))
            .collect();
        let parked = park(&again);
        case.check(
            &format!("(c) after the idle rule ended them all {UPLOADS} upload slots are free: {UPLOADS} new stalled uploads take them at once"),
            parked.is_ok(),
            match &parked {
                Ok(()) => "parked".to_owned(),
                Err(e) => format!("{e:#}"),
            },
        );
        parked?;
        for probe in &again {
            probe.release();
        }
        wait_until(
            "the disconnected uploads' spools to be deleted",
            BARRIER,
            || (tree_usage(&scratch).1 == 0).then_some(()),
        )?;
        let follow = ctx.run(
            Client {
                name: "idle-follow-up".into(),
                ..small()
            },
            &Probe::default(),
        );
        let digest = small_digest(&follow);
        case.check(
            "a request after the idle rule's ends completes with the right digest",
            follow.status == 200 && digest.as_deref() == Some(pattern_digest_abc().as_str()),
            format!("status {}, digest {digest:?}", follow.status),
        );
        Ok(())
    });
    result?;
    let outcomes = ctx.outcomes.lock().unwrap();
    case.note(
        "idle_rule_clients",
        Value::Array(
            outcomes
                .iter()
                .map(|o| json!({"client": o.name, "status": o.reply.status, "started_s": o.started, "ended_s": o.ended, "transport_error": o.reply.transport_error}))
                .collect(),
        ),
    );
    Ok(())
}
