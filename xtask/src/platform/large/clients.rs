//! The clients of the overload cases: one request each, with a PLAN of how it must end, run
//! through the raw-socket helper with a [`Probe`] the orchestrating thread can read, and the
//! registry that lets go of every stalled one however the orchestration ends.

use super::{
    barrier::{all_hold, spools_hold, wait_until},
    http_raw::{self, Probe, Reply, Source, Upload},
    overload::{hash_metadata, pattern_digest_abc},
};
use crate::platform::measure::tree_usage;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Document bytes a stalled upload writes before it stops.
pub(super) const STALL_BYTES: u64 = 8 * (1 << 20);

/// What the plan says a client's end must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// `200` with a completed final record (and the expected digest, when there is one).
    Completes,
    /// `503 CapacityExceeded`, `NotApplied`.
    Refused,
    /// The client closed the connection itself.
    ClientEnds,
    /// `504 DeadlineExceeded`, `NotApplied`: the server ended the stall.
    ServerEnds,
}

pub(super) struct Client {
    pub name: String,
    pub plan: Plan,
    pub upload: Upload,
    pub expected_digest: Option<String>,
    pub cpu: bool,
}

pub(super) struct Outcome {
    pub name: String,
    pub plan: Plan,
    pub reply: Reply,
    pub expected_digest: Option<String>,
    pub cpu: bool,
    pub started: f64,
    pub ended: f64,
}

/// The clients' side of one run: where to connect and how every client ended.
pub(super) struct Ctx<'a> {
    pub address: &'a str,
    pub token: &'a str,
    pub began: Instant,
    pub outcomes: Mutex<Vec<Outcome>>,
    pub launched: AtomicU64,
}

impl<'a> Ctx<'a> {
    pub fn new(address: &'a str, token: &'a str) -> Self {
        Self {
            address,
            token,
            began: Instant::now(),
            outcomes: Mutex::new(Vec::new()),
            launched: AtomicU64::new(0),
        }
    }

    /// Runs `client` to its end on this thread and records how it ended.
    pub fn run(&self, client: Client, probe: &Probe) -> Reply {
        self.launched.fetch_add(1, Ordering::SeqCst);
        let started = self.began.elapsed().as_secs_f64();
        let reply = http_raw::send_probed(self.address, self.token, &client.upload, probe);
        let ended = self.began.elapsed().as_secs_f64();
        self.outcomes.lock().unwrap().push(Outcome {
            name: client.name,
            plan: client.plan,
            reply: reply.clone(),
            expected_digest: client.expected_digest,
            cpu: client.cpu,
            started,
            ended,
        });
        reply
    }

    pub fn has_ended(&self, name: &str) -> bool {
        self.outcomes.lock().unwrap().iter().any(|o| o.name == name)
    }

    pub fn reply_of(&self, name: &str) -> Option<Reply> {
        self.outcomes
            .lock()
            .unwrap()
            .iter()
            .find(|o| o.name == name)
            .map(|o| o.reply.clone())
    }
}

/// Every stalled client's probe, so that all of them can be let go at once.
#[derive(Default)]
pub(super) struct Registry(Mutex<Vec<Arc<Probe>>>);

impl Registry {
    /// A new probe, remembered for [`Registry::release_all`].
    pub fn probe(&self) -> Arc<Probe> {
        let probe = Arc::new(Probe::default());
        self.0.lock().unwrap().push(probe.clone());
        probe
    }

    pub fn release_all(&self) {
        for probe in self.0.lock().unwrap().iter() {
            probe.release();
        }
    }
}

/// Lets go of every stalled client when dropped, so that a failure of the orchestration cannot
/// leave a thread waiting for a stall nobody will end.
pub(super) struct ReleaseOnDrop<'a>(pub &'a Registry);

impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        self.0.release_all();
    }
}

pub(super) fn upload(metadata: String, document: Source) -> Upload {
    Upload {
        path: "/v1/operations".into(),
        metadata,
        document,
        chunked: false,
        expect_continue: true,
        bytes_per_second: None,
        stall_after: None,
        abort_after: None,
    }
}

/// A hash upload that writes `STALL_BYTES` and then stops, until the harness disconnects it or
/// the server ends it.
pub(super) fn stalling(big: u64) -> Upload {
    Upload {
        chunked: true,
        stall_after: Some((STALL_BYTES, Duration::from_secs(900))),
        ..upload(
            hash_metadata(),
            Source::Pattern {
                byte: 0x6B,
                len: big,
            },
        )
    }
}

/// A three-byte hash request that must complete.
pub(super) fn small() -> Client {
    Client {
        name: String::new(),
        plan: Plan::Completes,
        upload: upload(hash_metadata(), Source::Bytes(b"abc".to_vec())),
        expected_digest: Some(pattern_digest_abc()),
        cpu: false,
    }
}

/// The digest of the three-byte request, from the `200` JSON of a hash operation.
pub(super) fn small_digest(reply: &Reply) -> Option<String> {
    reply.json().and_then(|j| {
        j["results"][0]["result"]["digest"]
            .as_str()
            .map(str::to_owned)
    })
}

/// How long a barrier waits for the server before it counts as a failure.
pub(super) const BARRIER: Duration = Duration::from_secs(90);

/// Waits until every one of `probes` has seen `100 Continue` (it holds an upload slot) and has
/// written its `STALL_BYTES`, and the scratch directory holds `total` spools of what the SERVER
/// received. Returns the scratch usage `(bytes, files)` then.
pub(super) fn park(
    label: &str,
    probes: &[Arc<Probe>],
    scratch: &std::path::Path,
    total: u64,
) -> anyhow::Result<(u64, u64)> {
    wait_until(
        &format!("{label}: every client to see 100 Continue and write its {STALL_BYTES} bytes"),
        BARRIER,
        || {
            let flags: Vec<bool> = probes
                .iter()
                .map(|p| p.continued() && p.stalled())
                .collect();
            all_hold(&flags).then_some(())
        },
    )?;
    wait_until(
        &format!("{label}: {total} spools of {STALL_BYTES} bytes in the scratch directory"),
        BARRIER,
        || {
            let (bytes, files) = tree_usage(scratch);
            spools_hold(files, bytes, total, STALL_BYTES).then_some((bytes, files))
        },
    )
}

/// Waits until the scratch directory holds no file: every spool of a client that ended is gone.
pub(super) fn spools_gone(label: &str, scratch: &std::path::Path) -> anyhow::Result<()> {
    wait_until(
        &format!("{label}: the spools in the scratch directory to be deleted"),
        BARRIER,
        || (tree_usage(scratch).1 == 0).then_some(()),
    )
}
