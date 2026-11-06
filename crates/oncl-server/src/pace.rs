//! Upload progress governance: a request body that stops (or crawls) must not keep an
//! admission slot, a worker and its spool until the whole operation deadline.
//!
//! Two rules apply to every wait for the next body frame. Only the time the *server*
//! spends waiting for the client counts, never the time spent hashing, spooling or
//! queueing, so server-side back-pressure is never charged to a client.
//!
//! * **Idle:** one wait for the next frame is capped at `idle`; no byte within that time
//!   ends the request.
//! * **Minimum rate:** a client that sends one byte just before each idle expiry would
//!   still hold the slot for the whole operation deadline. Every `idle` of accumulated
//!   waiting is therefore a window in which at least `min_rate * window` bytes must have
//!   arrived. `min_rate = 0` switches this rule off (idle only).
//!
//! The operation deadline stays the only bound on a long, healthy transfer. Both rules end
//! the request with `DeadlineExceeded` (HTTP 504, `NotApplied`): the same code as the
//! operation deadline, since the client gets no new case to handle.
use axum::body::{Body, Bytes};
use http_body_util::BodyExt;
use hyper::body::Frame;
use oncl_pki::resource::{Deadline, ProcessingError};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub(crate) struct PaceConfig {
    pub idle: Duration,
    pub min_rate: u64,
}

#[derive(Debug)]
pub(crate) struct UploadPace {
    config: PaceConfig,
    /// Time spent waiting for the client in the current window.
    waited: Duration,
    /// Bytes received in the current window.
    received: u64,
}

impl UploadPace {
    pub(crate) fn new(config: PaceConfig) -> Self {
        Self {
            config,
            waited: Duration::ZERO,
            received: 0,
        }
    }
    /// Account one finished wait that delivered `bytes` (0 for trailers / end of body).
    fn arrived(&mut self, waited: Duration, bytes: u64) -> Result<(), ProcessingError> {
        self.waited = self.waited.saturating_add(waited);
        self.received = self.received.saturating_add(bytes);
        if self.config.min_rate == 0 || self.waited < self.config.idle {
            return Ok(());
        }
        let required = u128::from(self.config.min_rate) * self.waited.as_millis() / 1000;
        let enough = u128::from(self.received) >= required;
        self.waited = Duration::ZERO;
        self.received = 0;
        if enough {
            Ok(())
        } else {
            Err(ProcessingError::DeadlineExceeded)
        }
    }
    /// Next frame of `body`, or `DeadlineExceeded` when the operation deadline, the idle
    /// timeout or the minimum rate ends the wait. `Ok(None)` is the end of the body.
    pub(crate) async fn frame(
        &mut self,
        body: &mut Body,
        deadline: Deadline,
    ) -> Result<Option<Result<Frame<Bytes>, axum::Error>>, ProcessingError> {
        let limit = self.config.idle.min(deadline.remaining());
        let began = Instant::now();
        let frame = tokio::time::timeout(limit, body.frame())
            .await
            .map_err(|_| ProcessingError::DeadlineExceeded)?;
        let bytes = frame
            .as_ref()
            .and_then(|f| f.as_ref().ok())
            .and_then(Frame::data_ref)
            .map_or(0, |data| data.len() as u64);
        self.arrived(began.elapsed(), bytes)?;
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);
    fn pace(idle: u64, min_rate: u64) -> UploadPace {
        UploadPace::new(PaceConfig {
            idle: Duration::from_secs(idle),
            min_rate,
        })
    }

    #[test]
    fn a_window_below_the_minimum_rate_is_refused_and_a_healthy_one_resets() {
        let mut p = pace(10, 1000);
        // 4 s + 4 s: still inside the window, nothing is judged yet.
        assert!(p.arrived(4 * SECOND, 10).is_ok());
        assert!(p.arrived(4 * SECOND, 10).is_ok());
        // The window closes at 10 s of waiting with 21 bytes against 10 000 required.
        assert!(matches!(
            p.arrived(2 * SECOND, 1),
            Err(ProcessingError::DeadlineExceeded)
        ));
        // A window with exactly the required bytes passes and starts a fresh one.
        let mut p = pace(10, 1000);
        assert!(p.arrived(10 * SECOND, 10_000).is_ok());
        assert!(p.arrived(10 * SECOND, 9_999).is_err());
    }

    #[test]
    fn bytes_are_charged_to_the_window_they_arrive_in_not_to_the_server_time_between_reads() {
        // A fast client the server reads slowly: every wait is ~0, so the window never
        // fills and nothing is judged, however much wall time the server spent hashing.
        let mut p = pace(10, 1000);
        for _ in 0..1000 {
            assert!(p.arrived(Duration::from_millis(1), 32_768).is_ok());
        }
    }

    #[test]
    fn rate_zero_is_idle_only() {
        let mut p = pace(10, 0);
        for _ in 0..100 {
            assert!(p.arrived(9 * SECOND, 1).is_ok());
        }
    }
}
