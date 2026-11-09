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
        self.frame_after(body, deadline, || async { Ok(()) }).await
    }
    /// As [`Self::frame`], for a server that gathers what it receives before it writes it.
    /// When no frame is ready the server has to wait for the client: `flush` runs first, and
    /// the idle timer and the pace window only run while the body is being waited for, so the
    /// work of `flush` is never charged to the client. A frame that is ready costs no wait
    /// and runs nothing. The consumer gathers bytes only between two calls (it is the task
    /// that polls this wait), so nothing can be gathered while the wait runs.
    pub(crate) async fn frame_after<Flush: Future<Output = Result<(), ProcessingError>>>(
        &mut self,
        body: &mut Body,
        deadline: Deadline,
        flush: impl FnOnce() -> Flush,
    ) -> Result<Option<Result<Frame<Bytes>, axum::Error>>, ProcessingError> {
        let mut next = std::pin::pin!(body.frame());
        // One poll with the task's own waker: when it is not ready, the very same future is
        // what the wait below goes on with.
        let first = std::future::poll_fn(|cx| std::task::Poll::Ready(next.as_mut().poll(cx))).await;
        if let std::task::Poll::Ready(ready) = first {
            self.arrived(Duration::ZERO, Self::data_len(&ready))?;
            return Ok(ready);
        }
        flush().await?;
        let limit = self.config.idle.min(deadline.remaining());
        let began = Instant::now();
        let frame = tokio::time::timeout(limit, next.as_mut())
            .await
            .map_err(|_| ProcessingError::DeadlineExceeded)?;
        self.arrived(began.elapsed(), Self::data_len(&frame))?;
        Ok(frame)
    }
    fn data_len(frame: &Option<Result<Frame<Bytes>, axum::Error>>) -> u64 {
        frame
            .as_ref()
            .and_then(|f| f.as_ref().ok())
            .and_then(Frame::data_ref)
            .map_or(0, |data| data.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

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

    #[tokio::test]
    async fn a_slow_consumer_is_never_charged() {
        let mut p = UploadPace::new(PaceConfig {
            idle: Duration::from_millis(200),
            min_rate: 200_000_000,
        });
        let mut body = Body::from_stream(futures_util::stream::iter(
            (0..40).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![0u8; 16 * 1024]))),
        ));
        let deadline = Deadline::after(Duration::from_secs(60)).unwrap();
        let mut frames = 0;
        while p
            .frame(&mut body, deadline)
            .await
            .expect("server time must not be charged to the client")
            .is_some()
        {
            frames += 1;
            // Slower than the idle timeout: the consumer, not the client, is slow.
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        assert_eq!(frames, 40);
    }

    /// The work done before a wait for the client (writing what is buffered) is not part of
    /// the wait: the idle timer starts after it. The frame arrives 20 ms after the first
    /// poll; the work takes 400 ms against an idle timeout of 200 ms.
    #[tokio::test]
    async fn work_before_the_wait_is_not_charged_to_the_client() {
        let mut p = UploadPace::new(PaceConfig {
            idle: Duration::from_millis(200),
            min_rate: 1,
        });
        let mut body = Body::from_stream(futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<_, std::io::Error>(Bytes::from_static(b"abc"))
        }));
        let deadline = Deadline::after(Duration::from_secs(60)).unwrap();
        let ran = std::cell::Cell::new(false);
        let frame = p
            .frame_after(&mut body, deadline, || async {
                tokio::time::sleep(Duration::from_millis(400)).await;
                ran.set(true);
                Ok(())
            })
            .await
            .expect("the work before the wait is not the client's time");
        assert!(ran.get() && frame.is_some());
    }

    /// A frame that is ready runs nothing before it, and a stall runs the work once, before
    /// the idle timeout ends the wait.
    #[tokio::test]
    async fn the_work_runs_only_when_the_server_must_wait() {
        let mut p = UploadPace::new(PaceConfig {
            idle: Duration::from_millis(150),
            min_rate: 0,
        });
        let mut body = Body::from_stream(
            futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"abc"))])
                .chain(futures_util::stream::pending()),
        );
        let deadline = Deadline::after(Duration::from_secs(60)).unwrap();
        let runs = std::cell::Cell::new(0);
        assert!(
            p.frame_after(&mut body, deadline, || async {
                runs.set(runs.get() + 1);
                Ok(())
            })
            .await
            .unwrap()
            .is_some()
        );
        assert_eq!(runs.get(), 0, "a ready frame is not a wait");
        assert!(matches!(
            p.frame_after(&mut body, deadline, || async {
                runs.set(runs.get() + 1);
                Ok(())
            })
            .await,
            Err(ProcessingError::DeadlineExceeded)
        ));
        assert_eq!(runs.get(), 1, "a stall flushes once, before the idle timer");
    }


}
