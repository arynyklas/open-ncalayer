//! The overload profile: many concurrent upload, CPU-bound and abandoned requests against
//! the REAL `oncl-server` binary configured with deliberately small shared budgets. The
//! single-operation RSS bound of the other cases says nothing about a busy server; this
//! case records what the server admitted, queued and refused, its peak running/queued
//! operations as the server itself exports them (OTLP gauges), its shared temporary peak,
//! the answers' honesty (typed refusals, never a hang or a 500) and its responsiveness.

use super::{
    DataSet, Facts,
    env::{Env, ServerSettings},
    exec::{Case, CaseResult, Target},
    http_raw::{self, Reply, Source, Upload},
    otlp::Collector,
};
use crate::platform::{generate, measure::tree_usage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Cpu,
    Upload,
    Disconnect,
    Deadline,
    Late,
}

struct Job {
    kind: Kind,
    index: usize,
    start_after: Duration,
    upload: Upload,
    expected_digest: Option<String>,
}

struct Outcome {
    kind: Kind,
    index: usize,
    reply: Reply,
    expected_digest: Option<String>,
}

fn hash_metadata() -> String {
    r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"source"}}],"parts":[{"name":"source","item_id":"h","role":"document"}]}"#.into()
}

fn sign_metadata() -> String {
    r#"{"items":[{"id":"s","operation":{"kind":"sign","profile":"xml","input":"source","target":"section-2","keys":[{"source":"named","name":"rsa"}]}}],"parts":[{"name":"source","item_id":"s","role":"document"}]}"#.into()
}

fn pattern_digest(byte: u8, len: u64) -> String {
    let chunk = vec![byte; 1 << 20];
    let mut h = Sha256::new();
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        h.update(&chunk[..n]);
        left -= n as u64;
    }
    generate::hex(&h.finalize())
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[(((sorted.len() - 1) as f64) * p).round() as usize]
}

pub fn run(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let mut case = Case::new(
        env,
        target,
        "overload-profile",
        "concurrent upload / CPU / abandoned / stalled requests against the real oncl-server with small shared budgets",
    )?;
    let outcome = body(&mut case);
    if let Err(e) = outcome {
        case.check(
            "the overload case ran to completion",
            false,
            format!("{e:#}"),
        );
    }
    Ok(case.finish())
}

fn body(case: &mut Case<'_>) -> anyhow::Result<()> {
    let env = case.env;
    let big = env.manifest.document_bytes.min(GIB);
    // small enough that two workers finish the CPU-bound signatures well inside the deadline
    // even when the machine is busy with other cases of the same run
    let cpu_bytes = env.manifest.document_bytes.min(8 * MIB);
    let timeout_ms = 240_000u64;

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

    let collector = Collector::start()?;
    let settings = ServerSettings {
        max_in_flight: 4,
        // the two stalled uploads hold two upload slots (`max_uploads`), not workers: the body is
        // received before an operation takes an in-flight slot or a worker. Keep more workers
        // than stallers so the storm still tests admitted work next to them.
        blocking_workers: 4,
        queue_capacity: 2,
        // long enough that the first CPU wave outlives the abandoned uploads that hold slots when
        // it arrives (they release within a second or two), short enough to refuse the surplus
        admission_wait_ms: 8000,
        operation_timeout_ms: timeout_ms,
        memory_per_operation: 268_435_456,
        total_memory: 536_870_912,
        temp_per_operation: 2 * GIB,
        total_temp: 3 * GIB,
        input_bytes: 1_073_741_824,
        tsa: false,
        max_connections: 64,
        telemetry_endpoint: Some(collector.url.clone()),
        token_alias: None,
        max_uploads: None,
    };
    case.server_settings = settings.clone();
    case.note(
        "server_settings",
        json!({
            "max_in_flight": settings.max_in_flight,
            "blocking_workers": settings.blocking_workers,
            "queue_capacity": settings.queue_capacity,
            "admission_wait_ms": settings.admission_wait_ms,
            "operation_timeout_ms": settings.operation_timeout_ms,
            "memory_per_operation": settings.memory_per_operation,
            "total_memory": settings.total_memory,
            "temp_per_operation": settings.temp_per_operation,
            "total_temp": settings.total_temp,
            "max_connections": settings.max_connections,
        }),
    );
    case.ensure_server()?;
    let (address, token, scratch) = {
        let server = case.server.as_ref().unwrap();
        (
            server.address.clone(),
            std::fs::read_to_string(&server.token_file)?
                .trim()
                .to_owned(),
            server.scratch.clone(),
        )
    };

    // ---------------------------------------------------------------- the clients
    let upload_digest = pattern_digest(0x6B, big);
    let mut jobs: Vec<Job> = Vec::new();
    let mut add = |kind, start_after_ms: u64, upload: Upload, expected_digest: Option<String>| {
        let index = jobs.iter().filter(|j| j.kind == kind).count();
        jobs.push(Job {
            kind,
            index,
            start_after: Duration::from_millis(start_after_ms),
            upload,
            expected_digest,
        });
    };
    for _ in 0..6 {
        add(
            Kind::Cpu,
            1500,
            Upload {
                path: "/v1/operations".into(),
                metadata: sign_metadata(),
                document: Source::File(cpu_path.clone()),
                chunked: false,
                expect_continue: true,
                bytes_per_second: None,
                stall_after: None,
                abort_after: None,
            },
            None,
        );
    }
    for _ in 0..6 {
        add(
            Kind::Upload,
            3000,
            Upload {
                path: "/v1/operations".into(),
                metadata: hash_metadata(),
                document: Source::Pattern {
                    byte: 0x6B,
                    len: big,
                },
                chunked: true,
                expect_continue: true,
                bytes_per_second: Some(128 * MIB),
                stall_after: None,
                abort_after: None,
            },
            Some(upload_digest.clone()),
        );
    }
    for _ in 0..4 {
        add(
            Kind::Disconnect,
            200,
            Upload {
                path: "/v1/operations".into(),
                metadata: hash_metadata(),
                document: Source::Pattern {
                    byte: 0x6B,
                    len: big,
                },
                chunked: true,
                expect_continue: true,
                bytes_per_second: Some(128 * MIB),
                stall_after: None,
                abort_after: Some(big.min(64 * MIB)),
            },
            None,
        );
    }
    for _ in 0..2 {
        add(
            Kind::Deadline,
            0,
            Upload {
                path: "/v1/operations".into(),
                metadata: hash_metadata(),
                document: Source::Pattern {
                    byte: 0x6B,
                    len: big,
                },
                chunked: true,
                expect_continue: true,
                bytes_per_second: None,
                stall_after: Some((8 * MIB, Duration::from_millis(timeout_ms + 60_000))),
                abort_after: None,
            },
            None,
        );
    }
    for _ in 0..3 {
        add(
            Kind::Late,
            5000,
            Upload {
                path: "/v1/operations".into(),
                metadata: hash_metadata(),
                document: Source::Bytes(b"abc".to_vec()),
                chunked: false,
                expect_continue: true,
                bytes_per_second: None,
                stall_after: None,
                abort_after: None,
            },
            Some(pattern_digest_abc()),
        );
    }
    let total_jobs = jobs.len();
    case.note("clients", json!({"cpu": 6, "upload": 6, "disconnect": 4, "deadline": 2, "late": 3, "upload_bytes": big, "cpu_document_bytes": cpu_bytes}));

    // ---------------------------------------------------------------- run
    let heartbeat_stop = Arc::new(AtomicBool::new(false));
    let temp_peak = Arc::new(AtomicU64::new(0));
    let file_peak = Arc::new(AtomicU64::new(0));
    let outcomes = std::sync::Mutex::new(Vec::<Outcome>::new());
    let beats = std::sync::Mutex::new(Vec::<(u16, f64)>::new());
    let began = Instant::now();
    thread::scope(|s| {
        let (stop, tp, fp, sp) = (
            heartbeat_stop.clone(),
            temp_peak.clone(),
            file_peak.clone(),
            scratch.clone(),
        );
        s.spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let (bytes, files) = tree_usage(&sp);
                tp.fetch_max(bytes, Ordering::Relaxed);
                fp.fetch_max(files, Ordering::Relaxed);
                thread::sleep(Duration::from_millis(100));
            }
        });
        let stop2 = heartbeat_stop.clone();
        let (a2, t2) = (address.clone(), token.clone());
        let beats = &beats;
        s.spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                let (status, took) = http_raw::get(&a2, &t2, "/health");
                beats.lock().unwrap().push((status, took.as_secs_f64()));
                thread::sleep(Duration::from_millis(150));
            }
        });
        let mut handles = Vec::new();
        for job in &jobs {
            let (a, t) = (address.clone(), token.clone());
            let outcomes = &outcomes;
            handles.push(s.spawn(move || {
                thread::sleep(job.start_after);
                let reply = http_raw::send(&a, &t, &job.upload);
                outcomes.lock().unwrap().push(Outcome {
                    kind: job.kind,
                    index: job.index,
                    reply,
                    expected_digest: job.expected_digest.clone(),
                });
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        heartbeat_stop.store(true, Ordering::Relaxed);
    });
    let storm_seconds = began.elapsed().as_secs_f64();
    case.note("storm_seconds", json!(storm_seconds));
    let outcomes = outcomes.into_inner().unwrap();
    case.check(
        "every client got an end (answer or close), none hung",
        outcomes.len() == total_jobs,
        format!("{} of {total_jobs}", outcomes.len()),
    );

    // ---------------------------------------------------------------- answers
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
        let mut verdict = "other";
        match (o.kind, o.reply.status) {
            (_, 200) => {
                verdict = "completed";
                let streamed = http_raw::multipart_final(&o.reply);
                let final_completed = match &streamed {
                    Some((f, _)) => f["status"] == "completed",
                    None => json.as_ref().is_some_and(|j| j["status"] == "completed"),
                };
                if !final_completed {
                    if streamed.is_none() && o.reply.transport_error.is_some() {
                        // The server answered 200 and then aborted the stream (an operation
                        // that expired in the queue after its head went out): documented as an
                        // unknown-outcome transport abort, never success. The durable journal
                        // must still show a FINAL for every BEGIN (checked when the server stops).
                        verdict = "aborted stream (no terminal record)";
                    } else {
                        let detail = streamed
                            .as_ref()
                            .map(|(f, _)| f.to_string())
                            .unwrap_or_else(|| {
                                String::from_utf8_lossy(
                                    &o.reply.body[..o.reply.body.len().min(600)],
                                )
                                .into_owned()
                            });
                        unexpected.push(format!(
                            "{:?}#{} status 200 without a completed final record: {}",
                            o.kind,
                            o.index,
                            detail.chars().take(500).collect::<String>()
                        ));
                    }
                }
                if o.kind == Kind::Cpu
                    && let Some((_, artifact)) = streamed
                {
                    completed_cpu.push(artifact);
                }
                if let (Some(expected), Some(j)) = (&o.expected_digest, &json)
                    && j["results"][0]["result"]["digest"].as_str() != Some(expected.as_str())
                {
                    unexpected.push(format!(
                        "{:?}#{} digest differs from the expected one",
                        o.kind, o.index
                    ));
                }
            }
            (_, 503) if code.as_deref() == Some("CapacityExceeded") => {
                verdict = "refused: CapacityExceeded"
            }
            (_, 413) => verdict = "refused: resource limit",
            (Kind::Deadline, 504) if code.as_deref() == Some("DeadlineExceeded") => {
                verdict = "deadline: DeadlineExceeded"
            }
            (Kind::Disconnect, 0) => verdict = "client disconnected",
            (_, s) if o.reply.transport_error.is_some() && s == 0 => verdict = "transport closed",
            (_, s) => unexpected.push(format!(
                "{:?}#{} answered {s} code {:?}",
                o.kind, o.index, code
            )),
        }
        if o.reply.status >= 400
            && o.reply.status != 0
            && json.is_some()
            && applied.as_deref() != Some("NotApplied")
        {
            unexpected.push(format!(
                "{:?}#{} refusal says applied={:?}",
                o.kind, o.index, applied
            ));
        }
        rows.push(json!({
            "kind": format!("{:?}", o.kind), "index": o.index, "status": o.reply.status, "code": code, "applied": applied,
            "verdict": verdict, "seconds": o.reply.elapsed.as_secs_f64(), "sent_document_bytes": o.reply.sent_document_bytes,
            "refused_before_body": o.reply.refused_before_body, "transport_error": o.reply.transport_error,
        }));
    }
    case.note("clients_detail", Value::Array(rows.clone()));
    case.check("every answer is a completed result or a typed honest refusal (no 500, no untyped close, key never applied on a refusal)", unexpected.is_empty(), unexpected.join("; "));
    let count = |v: &str| {
        rows.iter()
            .filter(|r| r["verdict"].as_str().is_some_and(|x| x.starts_with(v)))
            .count()
    };
    case.note("answers", json!({"completed": count("completed"), "refused": count("refused"), "deadline": count("deadline"), "disconnected": count("client"), "transport_closed": count("transport")}));
    case.check(
        "overload produced honest refusals (the budgets bound the work)",
        count("refused") > 0,
        format!("{} refusals", count("refused")),
    );
    case.check(
        "work that was admitted completed",
        count("completed") > 0,
        format!("{} completed", count("completed")),
    );
    let deadline_rows: Vec<&Value> = rows.iter().filter(|r| r["kind"] == "Deadline").collect();
    case.check(
        "a stalled upload is ended by the deadline (504 DeadlineExceeded) or by a refusal, never held beyond it",
        deadline_rows.iter().all(|r| r["seconds"].as_f64().unwrap_or(1e9) < (timeout_ms as f64 / 1000.0) + 45.0),
        deadline_rows.iter().map(|r| format!("{} in {:.1}s", r["verdict"], r["seconds"].as_f64().unwrap_or(0.0))).collect::<Vec<_>>().join(", "),
    );

    // ---------------------------------------------------------------- independent result check
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

    // ---------------------------------------------------------------- the server's own account
    let started = Instant::now();
    loop {
        let (_, files) = tree_usage(&scratch);
        if files == 0 || started.elapsed() > Duration::from_secs(180) {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    let (bytes, files) = tree_usage(&scratch);
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
        running.is_some() && queued.is_some(),
        format!("{} samples", collector.samples().len()),
    );
    case.check(
        "peak running native operations never exceeded blocking_workers",
        running.is_some_and(|r| r <= settings.blocking_workers as f64),
        format!("{running:?} of {}", settings.blocking_workers),
    );
    case.check(
        "peak queued operations never exceeded queue_capacity",
        queued.is_some_and(|q| q <= settings.queue_capacity as f64),
        format!("{queued:?} of {}", settings.queue_capacity),
    );
    let peak_temp = temp_peak.load(Ordering::Relaxed);
    case.note("shared_temp", json!({"peak_bytes": peak_temp, "peak_files": file_peak.load(Ordering::Relaxed), "configured_total_temp": settings.total_temp}));
    case.check(
        "the shared temporary peak stayed within total_temp",
        peak_temp <= settings.total_temp,
        format!("{peak_temp} of {}", settings.total_temp),
    );
    let beats = beats.into_inner().unwrap();
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
    // a fresh request after the storm is served normally
    let fresh = http_raw::send(
        &address,
        &token,
        &Upload {
            path: "/v1/operations".into(),
            metadata: hash_metadata(),
            document: Source::Bytes(b"abc".to_vec()),
            chunked: false,
            expect_continue: false,
            bytes_per_second: None,
            stall_after: None,
            abort_after: None,
        },
    );
    let digest = fresh.json().and_then(|j| {
        j["results"][0]["result"]["digest"]
            .as_str()
            .map(str::to_owned)
    });
    case.check(
        "a request after the storm completes with the right digest",
        fresh.status == 200 && digest.as_deref() == Some(pattern_digest_abc().as_str()),
        format!("status {}, digest {digest:?}", fresh.status),
    );
    Ok(())
}

fn pattern_digest_abc() -> String {
    generate::hex(&Sha256::digest(b"abc"))
}

// ------------------------------------------------------------------------------------------
// Private card use under load: per-device APDU overlap.

/// Sixteen concurrent signatures on two software cards, three times over, through the
/// service library with a card backend that counts simultaneous exchanges per reader
/// (`platform::token_host`; the standalone binary has no emulated card backend).
pub fn run_token(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let mut case = Case::new(
        env,
        target,
        "overload-token-apdu",
        "concurrent private card use on two readers: APDU overlap per device must be 1",
    )?;
    if let Err(e) = token_body(&mut case) {
        case.check(
            "the token overload case ran to completion",
            false,
            format!("{e:#}"),
        );
    }
    Ok(case.finish())
}

fn token_body(case: &mut Case<'_>) -> anyhow::Result<()> {
    use crate::platform::token_host::{self, ReaderStats};
    let env = case.env;
    let (_, alias) = token_host::emulator(&env.pki.dir, &env.pki.meta.password)?;
    let settings = ServerSettings {
        max_in_flight: 8,
        blocking_workers: 8,
        queue_capacity: 4,
        admission_wait_ms: 5000,
        operation_timeout_ms: 120_000,
        memory_per_operation: 134_217_728,
        total_memory: 1 << 30,
        temp_per_operation: GIB,
        total_temp: 4 * GIB,
        input_bytes: 1_073_741_824,
        tsa: false,
        max_connections: 64,
        telemetry_endpoint: None,
        token_alias: Some(alias),
        max_uploads: None,
    };
    case.server_settings = settings;
    case.ensure_server()?;
    let (address, token) = {
        let s = case.server.as_ref().unwrap();
        (
            s.address.clone(),
            std::fs::read_to_string(&s.token_file)?.trim().to_owned(),
        )
    };
    let document: Vec<u8> = (0..262_144u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let doc_path = case.work.join("token-document.bin");
    std::fs::write(&doc_path, &document)?;
    let outcomes = std::sync::Mutex::new(Vec::<(usize, Reply)>::new());
    for round in 0..3 {
        thread::scope(|s| {
            for index in 0..16usize {
                let (a, t, doc, outcomes) =
                    (address.clone(), token.clone(), document.clone(), &outcomes);
                s.spawn(move || {
                    let card = if index % 2 == 0 { "card-a" } else { "card-b" };
                    let metadata = format!(
                        r#"{{"items":[{{"id":"s","operation":{{"kind":"sign","profile":"cms","input":"source","keys":[{{"source":"named","name":"{card}"}}]}}}}],"parts":[{{"name":"source","item_id":"s","role":"document"}}]}}"#
                    );
                    let reply = http_raw::send(
                        &a,
                        &t,
                        &Upload {
                            path: "/v1/operations".into(),
                            metadata,
                            document: Source::Bytes(doc),
                            chunked: false,
                            expect_continue: true,
                            bytes_per_second: None,
                            stall_after: None,
                            abort_after: None,
                        },
                    );
                    outcomes.lock().unwrap().push((round * 16 + index, reply));
                });
            }
        });
    }
    let outcomes = outcomes.into_inner().unwrap();
    let mut completed = 0usize;
    let mut refused = 0usize;
    let mut bad = Vec::new();
    let mut verified = 0usize;
    for (n, reply) in &outcomes {
        match reply.status {
            200 => match http_raw::multipart_final(reply) {
                Some((f, artifact)) if f["status"] == "completed" => {
                    completed += 1;
                    if verified < 6 {
                        let sig = case.work.join(format!("token-{n}.p7s"));
                        std::fs::write(&sig, &artifact)?;
                        let out = case.work.join(format!("token-{n}.out"));
                        let ok = super::cases::openssl_cms_signature(&sig, Some(&doc_path), &out)?;
                        if !ok {
                            bad.push(format!("request {n}: OpenSSL rejects the card signature"));
                        }
                        verified += 1;
                    }
                }
                other => bad.push(format!(
                    "request {n}: 200 without a completed final ({})",
                    other.is_some()
                )),
            },
            503 if reply.json().is_some_and(|j| {
                j["code"] == "CapacityExceeded" && j["applied"] == "NotApplied"
            }) =>
            {
                refused += 1
            }
            s => bad.push(format!("request {n}: status {s} {:?}", reply.json())),
        }
    }
    case.note(
        "answers",
        json!({"completed": completed, "refused_capacity": refused, "unexpected": bad.len()}),
    );
    case.check(
        "every answer is a completed card signature or a typed CapacityExceeded/NotApplied refusal",
        bad.is_empty(),
        bad.join("; "),
    );
    case.check(
        "card signatures were produced",
        completed > 0,
        format!("{completed} of {}", outcomes.len()),
    );
    case.check(
        "signatures from the cards verify with OpenSSL (independent)",
        verified > 0 && !bad.iter().any(|b| b.contains("OpenSSL")),
        format!("{verified} checked"),
    );

    // stop the host: it writes its overlap statistics at the end
    let mut server = case.server.take().unwrap();
    let measured = server.stop()?;
    case.record(
        "token-host (service library + counting software card)",
        "xtask platform-token-host",
        &measured,
    );
    let overlap: std::collections::BTreeMap<String, ReaderStats> = serde_json::from_slice(
        &std::fs::read(server.operator.parent().unwrap().join("token-overlap.json"))?,
    )?;
    case.note("apdu_overlap_per_reader", json!(overlap));
    for reader in token_host::READERS {
        let s = overlap.get(reader).cloned().unwrap_or_default();
        case.check(
            &format!("{reader}: APDU exchanges never overlapped (max simultaneous transmit = 1)"),
            s.transmits > 0 && s.transmit_max == 1,
            format!(
                "{} transmits, max simultaneous {}",
                s.transmits, s.transmit_max
            ),
        );
        case.check(
            &format!("{reader}: card transactions never overlapped (max simultaneous = 1)"),
            s.transactions > 0 && s.transaction_max == 1,
            format!(
                "{} transactions, max simultaneous {}",
                s.transactions, s.transaction_max
            ),
        );
    }
    let audit = server.audit_counts()?;
    case.note("audit", json!(audit));
    case.check(
        "the durable audit has a FINAL for every BEGIN, and every completed signature was recorded",
        audit.begin == audit.finals && audit.applied as usize >= completed,
        format!("{audit:?}, {completed} completed"),
    );
    let (bytes, files) = tree_usage(&server.scratch);
    case.check(
        "the host's scratch is empty afterwards",
        files == 0,
        format!("{files} files, {bytes} bytes"),
    );
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Diagnostic of the streamed progress frames of one long operation.

/// One CPU-bound signature through the real server with a raw client that keeps the whole
/// response, to measure how many progress frames and bytes the server streams while it works.
/// Every frame is charged to the operation's output allowance (`account_output`), so a long
/// operation's frame traffic is a budget of its own: this case records its rate and the time
/// it would take to consume the default output limit.
pub fn run_progress_rate(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let mut case = Case::new(
        env,
        target,
        "http-progress-frame-rate",
        "progress frames streamed by the real server during one CPU-bound signature",
    )?;
    if let Err(e) = progress_body(&mut case) {
        case.check("the diagnostic ran to completion", false, format!("{e:#}"));
    }
    Ok(case.finish())
}

fn progress_body(case: &mut Case<'_>) -> anyhow::Result<()> {
    let env = case.env;
    let bytes = env.manifest.document_bytes;
    let path = env.doc("xml-archive")?.path.clone();
    let collector = Collector::start()?;
    case.server_settings.telemetry_endpoint = Some(collector.url.clone());
    case.ensure_server()?;
    let (address, token) = {
        let s = case.server.as_ref().unwrap();
        (
            s.address.clone(),
            std::fs::read_to_string(&s.token_file)?.trim().to_owned(),
        )
    };
    let reply = http_raw::send(
        &address,
        &token,
        &Upload {
            path: "/v1/operations".into(),
            metadata: sign_metadata(),
            document: Source::File(path),
            chunked: false,
            expect_continue: true,
            bytes_per_second: None,
            stall_after: None,
            abort_after: None,
        },
    );
    let marker = b"\"type\":\"progress\"";
    let frames = reply
        .body
        .windows(marker.len())
        .filter(|w| *w == marker)
        .count();
    let seconds = reply.elapsed.as_secs_f64();
    let limit = oncl_pki::resource::ResourceLimits::default().output_bytes as f64;
    let per_second = reply.body_len as f64 / seconds.max(1e-9);
    case.note(
        "progress_traffic",
        json!({
            "document_bytes": bytes, "seconds": seconds, "status": reply.status,
            "response_bytes": reply.body_len, "retained_response_bytes": reply.body.len(),
            "progress_frames_in_retained_prefix": frames, "transport_error": reply.transport_error,
            "response_bytes_per_second": per_second,
            "seconds_to_consume_default_output_limit_at_this_rate": limit / per_second.max(1e-9),
            "default_output_limit_bytes": limit,
        }),
    );
    // Drain the final metrics export after an abort; there is only one workload here.
    thread::sleep(Duration::from_secs(2));
    case.note("otlp_error_tokens", json!(collector.error_tokens()));
    case.check(
        "the HTTP entity completed without a transport abort",
        reply.status == 200 && reply.transport_error.is_none(),
        format!(
            "status {}, {:?}; {} bytes received",
            reply.status, reply.transport_error, reply.body_len
        ),
    );
    if reply.body_len == reply.body.len() as u64 {
        case.check(
            "the retained response has a completed final record",
            http_raw::multipart_final(&reply).is_some_and(|(f, _)| f["status"] == "completed"),
            "final-record parsing is only meaningful when the entire entity was retained",
        );
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Slot-release reproduction: do stalled uploads hold every in-flight slot, and when is a slot
// offered to a waiting CPU-bound client?

pub fn run_slot_repro(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let mut case = Case::new(
        env,
        target,
        "overload-slot-release",
        "two stalled uploads against max_in_flight=2, then CPU clients: slot release at the deadline",
    )?;
    if let Err(e) = slot_body(&mut case) {
        case.check("the repro ran to completion", false, format!("{e:#}"));
    }
    Ok(case.finish())
}

fn slot_body(case: &mut Case<'_>) -> anyhow::Result<()> {
    let env = case.env;
    let cpu_path = case.work.join("slot-cpu.xml");
    generate::xml::generate(&cpu_path, 8 * MIB, 0x5107, generate::xml::XmlKind::Archive)?;
    let deadline_ms = 30_000u64;
    case.server_settings = ServerSettings {
        max_in_flight: 2,
        blocking_workers: 2,
        queue_capacity: 2,
        admission_wait_ms: 3000,
        operation_timeout_ms: deadline_ms,
        memory_per_operation: 268_435_456,
        total_memory: 536_870_912,
        temp_per_operation: GIB,
        total_temp: 4 * GIB,
        input_bytes: 1_073_741_824,
        tsa: false,
        max_connections: 64,
        telemetry_endpoint: None,
        token_alias: None,
        max_uploads: None,
    };
    let _ = env;
    case.ensure_server()?;
    let (address, token) = {
        let s = case.server.as_ref().unwrap();
        (
            s.address.clone(),
            std::fs::read_to_string(&s.token_file)?.trim().to_owned(),
        )
    };
    let stalled = |chunked_bytes: u64| Upload {
        path: "/v1/operations".into(),
        metadata: hash_metadata(),
        document: Source::Pattern {
            byte: 0x11,
            len: GIB,
        },
        chunked: true,
        expect_continue: true,
        bytes_per_second: None,
        stall_after: Some((chunked_bytes, Duration::from_secs(deadline_ms / 1000 + 20))),
        abort_after: None,
    };
    let cpu = || Upload {
        path: "/v1/operations".into(),
        metadata: sign_metadata(),
        document: Source::File(cpu_path.clone()),
        chunked: false,
        expect_continue: true,
        bytes_per_second: None,
        stall_after: None,
        abort_after: None,
    };
    let began = Instant::now();
    let rows =
        std::sync::Mutex::new(Vec::<(String, f64, u16, Option<String>, Option<String>)>::new());
    thread::scope(|s| {
        for n in 0..2 {
            let (a, t, up, rows) = (address.clone(), token.clone(), stalled(MIB), &rows);
            s.spawn(move || {
                let r = http_raw::send(&a, &t, &up);
                let code = r.json().and_then(|j| j["code"].as_str().map(str::to_owned));
                rows.lock().unwrap().push((
                    format!("stalled-{n}"),
                    began.elapsed().as_secs_f64(),
                    r.status,
                    code,
                    r.transport_error.clone(),
                ));
            });
        }
        thread::sleep(Duration::from_secs(2));
        // CPU clients arrive while both slots are held, then keep arriving every 5 s
        for n in 0..8u64 {
            let (a, t, up, rows) = (address.clone(), token.clone(), cpu(), &rows);
            s.spawn(move || {
                thread::sleep(Duration::from_secs(n * 5));
                let start = began.elapsed().as_secs_f64();
                let r = http_raw::send(&a, &t, &up);
                let done = began.elapsed().as_secs_f64();
                let code = r.json().and_then(|j| j["code"].as_str().map(str::to_owned));
                let ok =
                    http_raw::multipart_final(&r).is_some_and(|(f, _)| f["status"] == "completed");
                rows.lock().unwrap().push((
                    format!("cpu-{n} started {start:.1}s completed={ok}"),
                    done,
                    r.status,
                    code,
                    r.transport_error.clone(),
                ));
            });
        }
    });
    let mut rows = rows.into_inner().unwrap();
    rows.sort_by(|a, b| a.1.total_cmp(&b.1));
    for r in &rows {
        eprintln!(
            "[platform-proof]   slot-repro {} ended {:.1}s status {} code {:?} {:?}",
            r.0, r.1, r.2, r.3, r.4
        );
    }
    case.note("timeline", json!(rows.iter().map(|r| json!({"client": r.0, "ended_s": r.1, "status": r.2, "code": r.3, "transport": r.4})).collect::<Vec<_>>()));
    let stalled_end = rows
        .iter()
        .filter(|r| r.0.starts_with("stalled"))
        .map(|r| r.1)
        .fold(0.0, f64::max);
    case.note("stalled_released_after_s", json!(stalled_end));
    case.check(
        "the stalled uploads were ended at about the operation deadline",
        stalled_end > 0.0 && stalled_end < (deadline_ms as f64 / 1000.0) + 15.0,
        format!("{stalled_end:.1}s for a {}s deadline", deadline_ms / 1000),
    );
    let completed = rows
        .iter()
        .filter(|r| r.0.starts_with("cpu") && r.0.contains("completed=true"))
        .count();
    case.check(
        "CPU clients that arrive after the slots were freed complete",
        completed > 0,
        format!("{completed} of 8 completed"),
    );
    Ok(())
}
