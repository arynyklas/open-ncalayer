//! Bounded, non-blocking OTLP export plumbing: the `ureq` transport, a bounded span
//! queue with drop accounting, and a metric exporter wrapper that counts outcomes.
//!
//! No operation thread ever touches the network. Producers only `try_send` into a
//! fixed-size queue (drop + count when full); one named worker thread exports in
//! batches with hard HTTP timeouts, never retries, and backs off after a failure.
use super::safe::{SafeAttr, Signal};
use async_trait::async_trait;
use opentelemetry::metrics::Counter;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    metrics::{Temporality, data::ResourceMetrics, exporter::PushMetricExporter},
    trace::{Span, SpanData, SpanExporter, SpanProcessor},
};
use std::{
    collections::BTreeSet,
    future::Future,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

/// Largest collector reply body read (the OTLP success/partial-success message).
const MAX_REPLY: u64 = 65_536;
/// Upper bound on the post-failure back-off between export attempts.
const MAX_COOLDOWN: Duration = Duration::from_secs(30);
/// Control messages (resource, flush, shutdown) always fit beside a full queue.
const CONTROL_SLACK: usize = 8;

/// Observable export counters (also the source of the `oncl.telemetry.dropped` metric).
#[derive(Default)]
pub(super) struct Stats {
    pub(super) spans_exported: AtomicU64,
    pub(super) spans_dropped: AtomicU64,
    pub(super) span_export_failures: AtomicU64,
    pub(super) metric_exports: AtomicU64,
    pub(super) metric_export_failures: AtomicU64,
    pub(super) queued_spans: AtomicUsize,
    dropped: OnceLock<Counter<u64>>,
}
impl Stats {
    pub(super) fn attach_metric(&self, counter: Counter<u64>) {
        let _ = self.dropped.set(counter);
    }
    fn drop_signal(&self, signal: Signal, count: u64) {
        if count == 0 {
            return;
        }
        if let Some(counter) = self.dropped.get() {
            counter.add(count, &[SafeAttr::Signal(signal).key_value()]);
        }
    }
    fn drop_spans(&self, count: u64) {
        self.spans_dropped.fetch_add(count, Ordering::Relaxed);
        self.drop_signal(Signal::Spans, count);
    }
}

struct Waker2(std::thread::Thread);
impl Wake for Waker2 {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}
/// Drives a future on the calling (dedicated export) thread. The exporter futures
/// here are plain blocking HTTP calls with their own hard timeouts.
pub(super) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(Waker2(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// OTLP/HTTP transport over the workspace `ureq` (rustls + ring). One POST to the
/// operator's endpoint, no redirects, no environment proxy, no request headers other
/// than the operator's configured ones and the protocol's content negotiation.
#[derive(Debug)]
pub(super) struct UreqClient {
    agent: ureq::Agent,
    authority: String,
    allowed: BTreeSet<String>,
}
impl UreqClient {
    /// `roots`: the operator's explicit CA certificates (replacing, never extending, the
    /// built-in web roots), or `None` for the web roots. Certificate verification is
    /// never disabled.
    pub(super) fn new(
        authority: String,
        header_names: impl IntoIterator<Item = String>,
        connect_timeout: Duration,
        timeout: Duration,
        roots: Option<Arc<Vec<ureq::tls::Certificate<'static>>>>,
    ) -> Self {
        let mut config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .timeout_connect(Some(connect_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None);
        if let Some(roots) = roots {
            config = config.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::Specific(roots))
                    .build(),
            );
        }
        let agent = config.build().into();
        let mut allowed: BTreeSet<String> = header_names
            .into_iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        allowed.insert("content-type".into());
        allowed.insert("content-encoding".into());
        Self {
            agent,
            authority,
            allowed,
        }
    }
}
#[async_trait]
impl HttpClient for UreqClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let target_ok = parts.method == http::Method::POST
            && parts
                .uri
                .authority()
                .is_some_and(|a| a.as_str() == self.authority);
        if !target_ok {
            return Err("telemetry request outside the configured endpoint".into());
        }
        let mut builder = self.agent.post(parts.uri.to_string());
        for (name, value) in &parts.headers {
            if self.allowed.contains(name.as_str()) {
                builder = builder.header(name.as_str(), value.as_bytes());
            }
        }
        let mut reply = builder.send(&body[..])?;
        let status = reply.status();
        let bytes = reply
            .body_mut()
            .with_config()
            .limit(MAX_REPLY)
            .read_to_vec()?;
        let mut response = Response::new(Bytes::from(bytes));
        *response.status_mut() = status;
        Ok(response)
    }
}

enum Message {
    Span(Box<SpanData>),
    Resource(Box<Resource>),
    Flush(SyncSender<()>),
    Shutdown(SyncSender<()>),
}
/// Worker tuning.
#[derive(Clone, Copy)]
pub(super) struct QueueConfig {
    pub(super) capacity: usize,
    pub(super) batch: usize,
    pub(super) delay: Duration,
}
/// Span processor whose queue is bounded and whose drops are counted.
pub(super) struct BoundedSpanProcessor {
    sender: SyncSender<Message>,
    config: QueueConfig,
    stats: Arc<Stats>,
    closed: AtomicBool,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}
impl std::fmt::Debug for BoundedSpanProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoundedSpanProcessor")
    }
}
impl BoundedSpanProcessor {
    pub(super) fn spawn<E>(
        exporter: E,
        config: QueueConfig,
        stats: Arc<Stats>,
    ) -> std::io::Result<Self>
    where
        E: SpanExporter + 'static,
    {
        let (sender, receiver) = sync_channel(config.capacity + CONTROL_SLACK);
        let worker_stats = stats.clone();
        let handle = std::thread::Builder::new()
            .name("oncl-otlp-traces".into())
            .spawn(move || Worker::new(exporter, config, worker_stats).run(receiver))?;
        Ok(Self {
            sender,
            config,
            stats,
            closed: AtomicBool::new(false),
            worker: Mutex::new(Some(handle)),
        })
    }
}
impl SpanProcessor for BoundedSpanProcessor {
    fn on_start(&self, _: &mut Span, _: &opentelemetry::Context) {}
    fn on_end(&self, span: SpanData) {
        if self.closed.load(Ordering::Acquire) {
            self.stats.drop_spans(1);
            return;
        }
        if self.stats.queued_spans.fetch_add(1, Ordering::AcqRel) >= self.config.capacity {
            self.stats.queued_spans.fetch_sub(1, Ordering::AcqRel);
            self.stats.drop_spans(1);
            return;
        }
        if self.sender.try_send(Message::Span(Box::new(span))).is_err() {
            self.stats.queued_spans.fetch_sub(1, Ordering::AcqRel);
            self.stats.drop_spans(1);
        }
    }
    fn force_flush(&self) -> OTelSdkResult {
        let (ack, wait) = sync_channel(1);
        self.sender
            .try_send(Message::Flush(ack))
            .map_err(|_| OTelSdkError::AlreadyShutdown)?;
        wait.recv_timeout(Duration::from_secs(5))
            .map_err(|_| OTelSdkError::Timeout(Duration::from_secs(5)))
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Err(OTelSdkError::AlreadyShutdown);
        }
        let (ack, wait) = sync_channel(1);
        self.sender
            .try_send(Message::Shutdown(ack))
            .map_err(|_| OTelSdkError::AlreadyShutdown)?;
        let finished = wait.recv_timeout(timeout);
        let handle = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match finished {
            Ok(()) => {
                if let Some(handle) = handle {
                    let _ = handle.join();
                }
                Ok(())
            }
            // The worker is still inside one hard-timeout HTTP call: detach it.
            Err(_) => Err(OTelSdkError::Timeout(timeout)),
        }
    }
    fn set_resource(&mut self, resource: &Resource) {
        let _ = self
            .sender
            .try_send(Message::Resource(Box::new(resource.clone())));
    }
}

struct Worker<E> {
    exporter: E,
    config: QueueConfig,
    stats: Arc<Stats>,
    batch: Vec<SpanData>,
    failures: u32,
    cooldown_until: Option<Instant>,
}
impl<E: SpanExporter> Worker<E> {
    fn new(exporter: E, config: QueueConfig, stats: Arc<Stats>) -> Self {
        Self {
            exporter,
            config,
            stats,
            batch: Vec::with_capacity(config.batch),
            failures: 0,
            cooldown_until: None,
        }
    }
    fn run(mut self, receiver: Receiver<Message>) {
        let mut next = Instant::now() + self.config.delay;
        loop {
            match receiver.recv_timeout(next.saturating_duration_since(Instant::now())) {
                Ok(Message::Span(span)) => {
                    self.stats.queued_spans.fetch_sub(1, Ordering::AcqRel);
                    self.batch.push(*span);
                    if self.batch.len() >= self.config.batch {
                        self.export();
                        next = Instant::now() + self.config.delay;
                    }
                }
                Ok(Message::Resource(resource)) => self.exporter.set_resource(&resource),
                Ok(Message::Flush(ack)) => {
                    self.drain(&receiver);
                    let _ = ack.send(());
                    next = Instant::now() + self.config.delay;
                }
                Ok(Message::Shutdown(ack)) => {
                    self.drain(&receiver);
                    let _ = self.exporter.shutdown();
                    let _ = ack.send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.export();
                    next = Instant::now() + self.config.delay;
                }
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
    /// Export everything already queued, in batches; stops early (dropping the
    /// rest, counted) as soon as one attempt fails.
    fn drain(&mut self, receiver: &Receiver<Message>) {
        while let Ok(message) = receiver.try_recv() {
            match message {
                Message::Span(span) => {
                    self.stats.queued_spans.fetch_sub(1, Ordering::AcqRel);
                    self.batch.push(*span);
                    if self.batch.len() >= self.config.batch {
                        self.export();
                    }
                }
                Message::Resource(resource) => self.exporter.set_resource(&resource),
                Message::Flush(ack) => {
                    let _ = ack.send(());
                }
                Message::Shutdown(_) => {}
            }
        }
        self.export();
    }
    fn export(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let count = self.batch.len() as u64;
        if self
            .cooldown_until
            .is_some_and(|until| Instant::now() < until)
        {
            self.batch.clear();
            self.stats.drop_spans(count);
            return;
        }
        let batch = std::mem::replace(&mut self.batch, Vec::with_capacity(self.config.batch));
        match block_on(self.exporter.export(batch)) {
            Ok(()) => {
                self.failures = 0;
                self.cooldown_until = None;
                self.stats
                    .spans_exported
                    .fetch_add(count, Ordering::Relaxed);
            }
            Err(_) => {
                self.failures = self.failures.saturating_add(1);
                let backoff = self
                    .config
                    .delay
                    .saturating_mul(1 << self.failures.min(6))
                    .min(MAX_COOLDOWN);
                self.cooldown_until = Some(Instant::now() + backoff);
                self.stats
                    .span_export_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.drop_spans(count);
            }
        }
    }
}

/// Counts metric export outcomes; a failed export is a dropped collection.
pub(super) struct CountingMetricExporter<E> {
    pub(super) inner: E,
    pub(super) stats: Arc<Stats>,
}
impl<E: PushMetricExporter> PushMetricExporter for CountingMetricExporter<E> {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let result = self.inner.export(metrics).await;
        match &result {
            Ok(()) => {
                self.stats.metric_exports.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.stats
                    .metric_export_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.drop_signal(Signal::Metrics, 1);
            }
        }
        result
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }
    fn temporality(&self) -> Temporality {
        self.inner.temporality()
    }
}
