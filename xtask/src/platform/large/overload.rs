//! The other cases of the overload family (the profile itself is `profile`): private card use
//! under load, the streamed progress frames of one long operation, and the release of the
//! upload slots of stalled uploads; and the helpers they share with the profile.

use super::{
    barrier::wait_until,
    clients::{
        BARRIER, Client, Ctx, Plan, Registry, ReleaseOnDrop, park, spools_gone, stalling, upload,
    },
    env::{Env, ServerSettings},
    exec::{Case, CaseResult, Target},
    http_raw::{self, Probe, Reply, Source, Upload},
    otlp::Collector,
};
use crate::platform::{generate, measure::tree_usage};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{sync::Arc, thread, time::Duration};

pub(super) const GIB: u64 = 1 << 30;
pub(super) const MIB: u64 = 1 << 20;

pub(super) fn hash_metadata() -> String {
    r#"{"items":[{"id":"h","operation":{"kind":"hash","algorithm":"sha256","input":"source"}}],"parts":[{"name":"source","item_id":"h","role":"document"}]}"#.into()
}

pub(super) fn sign_metadata() -> String {
    r#"{"items":[{"id":"s","operation":{"kind":"sign","profile":"xml","input":"source","target":"section-2","keys":[{"source":"named","name":"rsa"}]}}],"parts":[{"name":"source","item_id":"s","role":"document"}]}"#.into()
}

pub(super) fn pattern_digest(byte: u8, len: u64) -> String {
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

pub(super) fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[(((sorted.len() - 1) as f64) * p).round() as usize]
}

pub(super) fn pattern_digest_abc() -> String {
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
        total_temp: 16 * GIB,
        input_bytes: 1_073_741_824,
        tsa: false,
        max_connections: 64,
        telemetry_endpoint: None,
        token_alias: Some(alias),
        // the 16 clients' bodies are 256 KiB each: all of them may be in the upload phase at
        // once; 8 slots need 8 x (input_bytes + container_bytes) = 16 GiB of total_temp
        max_uploads: Some(8),
        upload_idle_timeout_ms: None,
        metadata_bytes: None,
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
// Upload slots of stalled uploads with `max_in_flight` as small as the stallers' number, and
// their release by the operation deadline.

/// Two uploads stall mid-body against `max_in_flight = 2` and `blocking_workers = 2`: the
/// stalls hold upload slots and nothing else, so CPU-bound signatures complete next to them
/// (before the upload phase every staller held one of the two in-flight slots and a worker).
/// Then two stalls that only the operation deadline ends (the idle rule is longer than the
/// deadline): the server ends them with `504 DeadlineExceeded`, their slots and spools are
/// free, and the work that follows is served.
pub fn run_slot_release(env: &Env, target: Target) -> anyhow::Result<CaseResult> {
    let mut case = Case::new(
        env,
        target,
        "overload-slot-release",
        "stalled uploads against max_in_flight=2: they hold upload slots only (CPU work completes next to them), and the operation deadline releases them",
    )?;
    if let Err(e) = slot_body(&mut case) {
        case.check("the case ran to completion", false, format!("{e:#}"));
    }
    Ok(case.finish())
}

fn slot_body(case: &mut Case<'_>) -> anyhow::Result<()> {
    let cpu_path = case.work.join("slot-cpu.xml");
    generate::xml::generate(&cpu_path, 8 * MIB, 0x5107, generate::xml::XmlKind::Archive)?;
    let deadline_ms = 20_000u64;
    const UPLOADS: usize = 4;
    case.server_settings = ServerSettings {
        max_in_flight: 2,
        blocking_workers: 2,
        queue_capacity: 2,
        admission_wait_ms: 3000,
        operation_timeout_ms: deadline_ms,
        memory_per_operation: 268_435_456,
        total_memory: GIB,
        temp_per_operation: GIB,
        // UPLOADS x (input_bytes + container_bytes)
        total_temp: UPLOADS as u64 * 2 * GIB,
        input_bytes: 1_073_741_824,
        tsa: false,
        max_connections: 64,
        telemetry_endpoint: None,
        token_alias: None,
        max_uploads: Some(UPLOADS),
        // beyond the operation deadline: only the deadline ends a stall in this case
        upload_idle_timeout_ms: Some(120_000),
        // two concurrent signatures: room for both in the shared budgets
        metadata_bytes: Some(256 * MIB),
    };
    case.ensure_server()?;
    let (address, token, scratch) = {
        let s = case.server.as_ref().unwrap();
        (
            s.address.clone(),
            std::fs::read_to_string(&s.token_file)?.trim().to_owned(),
            s.scratch.clone(),
        )
    };
    let ctx = Ctx::new(&address, &token);
    let registry = Registry::default();
    let cpu = |name: &str| Client {
        name: name.into(),
        plan: Plan::Completes,
        upload: upload(sign_metadata(), Source::File(cpu_path.clone())),
        expected_digest: None,
        cpu: true,
    };
    let completed = |reply: &Reply| {
        reply.status == 200
            && http_raw::multipart_final(reply).is_some_and(|(f, _)| f["status"] == "completed")
    };
    thread::scope(|s| -> anyhow::Result<()> {
        let _release = ReleaseOnDrop(&registry);
        let ctx = &ctx;
        let spawn = |client: Client, probe: Arc<Probe>| {
            s.spawn(move || {
                ctx.run(client, &probe);
            });
        };
        let stall = |name: String, plan: Plan| -> Arc<Probe> {
            let probe = registry.probe();
            spawn(
                Client {
                    name,
                    plan,
                    upload: stalling(GIB),
                    expected_digest: None,
                    cpu: false,
                },
                probe.clone(),
            );
            probe
        };
        let parked_check =
            |case: &mut Case<'_>, what: &str, parked: &anyhow::Result<(u64, u64)>| {
                case.check(
                    what,
                    parked.is_ok(),
                    match parked {
                        Ok((bytes, files)) => format!("{files} spools, {bytes} bytes"),
                        Err(e) => format!("{e:#}"),
                    },
                );
            };

        // ---- the stalls hold upload slots only: CPU-bound work completes next to them
        let first: Vec<Arc<Probe>> = (0..2)
            .map(|i| stall(format!("stall-a{i}"), Plan::ClientEnds))
            .collect();
        let parked = park("stalls", &first, &scratch, 2);
        parked_check(
            case,
            "two uploads (as many as max_in_flight) stall mid-body, each holding its upload slot and spool",
            &parked,
        );
        parked?;
        for i in 0..2 {
            spawn(cpu(&format!("cpu-{i}")), registry.probe());
        }
        wait_until("the two CPU-bound signatures to end", BARRIER, || {
            (ctx.has_ended("cpu-0") && ctx.has_ended("cpu-1")).then_some(())
        })?;
        let done: Vec<bool> = (0..2)
            .map(|i| completed(&ctx.reply_of(&format!("cpu-{i}")).unwrap_or_default()))
            .collect();
        case.check(
            "while both stalls hold, two CPU-bound signatures are admitted and complete (the stalls hold no in-flight slot and no worker)",
            done.iter().all(|d| *d),
            format!("completed: {done:?}"),
        );
        case.check(
            "the stalls were still stalled when that work completed (no answer, no close)",
            first.iter().all(|p| p.answered().is_none()),
            format!(
                "{} of 2 unanswered",
                first.iter().filter(|p| p.answered().is_none()).count()
            ),
        );
        for probe in &first {
            probe.release();
        }
        spools_gone("disconnected stalls", &scratch)?;

        // ---- only the operation deadline ends these
        let second: Vec<Arc<Probe>> = (0..2)
            .map(|i| stall(format!("stall-b{i}"), Plan::ServerEnds))
            .collect();
        let parked = park("deadline stalls", &second, &scratch, 2);
        parked_check(case, "two more uploads stall mid-body", &parked);
        parked?;
        wait_until(
            "the server to end both stalls",
            BARRIER + Duration::from_millis(deadline_ms),
            || (ctx.has_ended("stall-b0") && ctx.has_ended("stall-b1")).then_some(()),
        )?;
        let mut within = true;
        let mut detail = Vec::new();
        for name in ["stall-b0", "stall-b1"] {
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
                && seconds >= deadline_ms as f64 / 1000.0 * 0.9
                && seconds < deadline_ms as f64 / 1000.0 + 15.0;
            detail.push(format!(
                "{name}: {} {code:?} {applied:?} after {seconds:.1}s",
                reply.status
            ));
        }
        case.check(
            &format!("the stalled uploads were ended by the server at about the operation deadline ({}s): 504 DeadlineExceeded, NotApplied", deadline_ms / 1000),
            within,
            detail.join(", "),
        );
        spools_gone("deadline-ended stalls", &scratch)?;

        // ---- their slots are free: all of them again, and the work after them is served
        let third: Vec<Arc<Probe>> = (0..UPLOADS)
            .map(|i| stall(format!("stall-c{i}"), Plan::ClientEnds))
            .collect();
        let parked = park("after the deadline", &third, &scratch, UPLOADS as u64);
        parked_check(
            case,
            &format!(
                "after the deadline ended them all {UPLOADS} upload slots are free: {UPLOADS} new stalled uploads take one each at once"
            ),
            &parked,
        );
        parked?;
        for probe in &third {
            probe.release();
        }
        spools_gone("released stalls", &scratch)?;
        let reply = ctx.run(cpu("cpu-after"), &Probe::default());
        case.check(
            "a CPU-bound signature after the stalls completes",
            completed(&reply),
            format!("status {}", reply.status),
        );
        Ok(())
    })?;
    // `Case::finish` checks the graceful stop, the audit journal (a FINAL for every BEGIN) and
    // the empty scratch of the server
    Ok(())
}
