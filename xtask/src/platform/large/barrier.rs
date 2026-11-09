//! State barriers of the overload cases. A wave of clients starts only when the SERVER has
//! reached the state the previous wave was meant to produce, and what the harness reads is
//! either something the server did to the client (`100 Continue`, an answer, a close: see
//! [`super::http_raw::Probe`]), something it did to the disk (its spool files in the scratch
//! directory) or something it exported (its OTLP gauges, read through
//! [`super::otlp::second_sample_after`]). No barrier is a sleep that hopes the server has caught
//! up: each is a predicate that is polled until it holds or until a generous time-out turns
//! into an error that names what never happened. The time-out is the failure path, never the
//! way a barrier is passed.

use std::time::{Duration, Instant};

/// How often a barrier looks again.
const POLL: Duration = Duration::from_millis(20);

/// Polls `check` until it returns `Some`, at most `timeout`. The error names `what`.
pub fn wait_until<T>(
    what: &str,
    timeout: Duration,
    mut check: impl FnMut() -> Option<T>,
) -> anyhow::Result<T> {
    let began = Instant::now();
    loop {
        if let Some(value) = check() {
            return Ok(value);
        }
        if began.elapsed() >= timeout {
            anyhow::bail!(
                "timed out after {:.1}s waiting for {what}",
                began.elapsed().as_secs_f64()
            );
        }
        std::thread::sleep(POLL);
    }
}

/// Whether the scratch directory shows `parked` stalled uploads that each wrote `per_spool`
/// document bytes: at least `parked` spool files, and the bytes of them. A spool holds only
/// what the multipart parser has handed over, so the bytes are what the SERVER received, which a
/// client that merely wrote into its socket cannot know. A little less than the whole is
/// accepted (the parser withholds a few trailing bytes that could begin a boundary).
pub fn spools_hold(files: u64, bytes: u64, parked: u64, per_spool: u64) -> bool {
    files >= parked && bytes >= parked * (per_spool - per_spool / 16)
}

/// Whether every flag is set. An empty list is NOT a state: a barrier that waits for nobody
/// would pass vacuously.
pub fn all_hold(flags: &[bool]) -> bool {
    !flags.is_empty() && flags.iter().all(|f| *f)
}
