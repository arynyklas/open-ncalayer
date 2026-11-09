//! Opt-in OTLP metrics and traces for the standalone server.
//!
//! * Off by default: [`Telemetry::start`] with `enabled = false` builds nothing — no
//!   provider, no thread, no socket. Nothing in the SDK crates links this module.
//! * The server owns the providers; `opentelemetry::global` is never touched.
//! * Everything that leaves the process passes the closed `safe` vocabulary: the
//!   only way to attach a value is a `safe::SafeAttr` built from a small enum. There
//!   is no body/header/path instrumentation and no OTLP logs.
//! * Export is bounded and never on an operation's path: producers do an atomic
//!   `try_send` into a fixed queue (drop + count when full); one named thread per
//!   signal exports with hard HTTP timeouts, no retries, and back-off after failure.
//! * Audit is a separate guard and is untouched: sampling, drops and a dead collector
//!   cannot remove, delay or replace a mandatory audit record.
mod export;
mod safe;

use crate::config::invalid;
use axum::body::Body;
use export::{BoundedSpanProcessor, CountingMetricExporter, QueueConfig, Stats, UreqClient};
use oncl_api::{
    error::{ApiError, AppliedState, ErrorCode},
    server::ResponseFuture,
};
use opentelemetry::{
    Context as OtelContext, InstrumentationScope, KeyValue,
    metrics::{Counter, Histogram, Meter, MeterProvider},
    trace::{Span as _, SpanKind, Status, TraceContextExt, Tracer, TracerProvider},
};
use opentelemetry_otlp::{
    MetricExporter, Protocol, RetryPolicy, SpanExporter, WithExportConfig, WithHttpConfig,
};
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider, Temporality},
    trace::{Sampler, SdkTracer, SdkTracerProvider},
};
pub(crate) use safe::{Applied, ErrorClass, Family, OperationKind, Route, Stage};
use safe::{Delivery, Outcome, SafeAttr, Status as HttpStatus};
use serde::Deserialize;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

const SCOPE: &str = "oncl-server";
const REQUEST_SECONDS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0,
];
const SIZE_BYTES: [f64; 9] = [
    256.0,
    4_096.0,
    65_536.0,
    1_048_576.0,
    16_777_216.0,
    134_217_728.0,
    1_073_741_824.0,
    4_294_967_296.0,
    10_737_418_240.0,
];

/// Operator configuration (`[telemetry]` table). Disabled unless `enabled = true`.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub enabled: bool,
    /// OTLP/HTTP base URL of the collector, e.g. `http://127.0.0.1:4318`.
    pub endpoint: String,
    /// `service.name` resource attribute (operator-chosen, never request data).
    pub service_name: String,
    pub metrics: bool,
    pub traces: bool,
    /// Trace sampling ratio in `[0, 1]`. Metrics are never sampled; audit is unrelated.
    pub trace_sample_ratio: f64,
    /// Extra collector request headers (e.g. an authorization header).
    pub headers: BTreeMap<String, String>,
    /// Metric export interval and span batch delay.
    pub export_interval_ms: u64,
    /// Hard bound of one export HTTP call.
    pub export_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    /// Maximum queued, not yet exported spans; further spans are dropped and counted.
    pub queue_size: usize,
    pub batch_size: usize,
    /// Bound of the final flush at shutdown.
    pub shutdown_timeout_ms: u64,
    /// `https` only: PEM file of the collector's CA, replacing the built-in web roots.
    pub ca_file: Option<std::path::PathBuf>,
}
impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            service_name: "oncl-server".into(),
            metrics: true,
            traces: true,
            trace_sample_ratio: 1.0,
            headers: BTreeMap::new(),
            export_interval_ms: 10_000,
            export_timeout_ms: 3_000,
            connect_timeout_ms: 1_000,
            queue_size: 2_048,
            batch_size: 512,
            shutdown_timeout_ms: 5_000,
            ca_file: None,
        }
    }
}
impl TelemetryConfig {
    /// Validates only an enabled configuration: a disabled one is never used.
    pub fn validate(&self) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let token = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        };
        let secure = self.endpoint().is_ok_and(|e| e.2);
        if self.endpoint().is_err()
            || !token(&self.service_name)
            || !(self.metrics || self.traces)
            || !(0.0..=1.0).contains(&self.trace_sample_ratio)
            || !(100..=3_600_000).contains(&self.export_interval_ms)
            || !(100..=60_000).contains(&self.export_timeout_ms)
            || self.connect_timeout_ms == 0
            || self.connect_timeout_ms > self.export_timeout_ms
            || !(16..=65_536).contains(&self.queue_size)
            || self.batch_size == 0
            || self.batch_size > self.queue_size
            || !(100..=60_000).contains(&self.shutdown_timeout_ms)
            // A collector credential must never cross the network in cleartext.
            || (!self.headers.is_empty() && !secure && !self.loopback())
            || self.ca_file.as_ref().is_some_and(|p| {
                !secure || p.as_os_str().len() > 4_096
            })
            || self.headers.len() > 8
            || self.headers.iter().any(|(name, value)| {
                !token(name)
                    || matches!(
                        name.to_ascii_lowercase().as_str(),
                        "host"
                            | "content-length"
                            | "content-type"
                            | "content-encoding"
                            | "transfer-encoding"
                            | "connection"
                            | "user-agent"
                            | "expect"
                            | "upgrade"
                    )
                    || value.len() > 1_024
                    || !value.bytes().all(|b| (0x20..0x7f).contains(&b))
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// `(authority, path prefix without trailing slash)` of a plain http(s) URL.
    fn endpoint(&self) -> io::Result<(String, String, bool)> {
        let uri: http::Uri = self.endpoint.parse().map_err(|_| invalid())?;
        let secure = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(invalid()),
        };
        let authority = uri.authority().ok_or_else(invalid)?;
        if self.endpoint.len() > 2_048
            || authority.as_str().contains('@')
            || uri.query().is_some()
            || self.endpoint.contains('#')
        {
            return Err(invalid());
        }
        Ok((
            authority.as_str().to_owned(),
            uri.path().trim_end_matches('/').to_owned(),
            secure,
        ))
    }
    /// Whether the endpoint host is `localhost` or a loopback address.
    fn loopback(&self) -> bool {
        let Ok(uri) = self.endpoint.parse::<http::Uri>() else {
            return false;
        };
        let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }
    /// The operator's explicit collector CA (PEM, at most 1 MiB and 8 certificates).
    /// It replaces the built-in web roots; verification is never disabled.
    fn roots(&self) -> io::Result<Option<Arc<Vec<ureq::tls::Certificate<'static>>>>> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        use std::io::Read;
        let Some(path) = &self.ca_file else {
            return Ok(None);
        };
        let file = std::fs::File::open(path)?;
        let mut pem = Vec::new();
        file.take(1_048_577).read_to_end(&mut pem)?;
        if pem.len() > 1_048_576 {
            return Err(invalid());
        }
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .map(|c| c.map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        if certificates.is_empty() || certificates.len() > 8 {
            return Err(invalid());
        }
        Ok(Some(Arc::new(certificates)))
    }
}

/// Point-in-time export accounting, also exported as `oncl.telemetry.dropped`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TelemetryStats {
    pub enabled: bool,
    pub spans_exported: u64,
    pub spans_dropped: u64,
    pub span_export_failures: u64,
    pub span_queue_capacity: usize,
    pub span_queue_len: usize,
    pub metric_exports: u64,
    pub metric_export_failures: u64,
    /// Live export threads owned by this handle (0 when disabled).
    pub export_threads: usize,
}

struct Instruments {
    requests: Counter<u64>,
    request_duration: Histogram<f64>,
    admission_duration: Histogram<f64>,
    executor_duration: Histogram<f64>,
    executor_rejected: Counter<u64>,
    operations: Counter<u64>,
    operation_duration: Histogram<f64>,
    key_uses: Counter<u64>,
    delivery_duration: Histogram<f64>,
    response_size: Histogram<f64>,
    stream_aborted: Counter<u64>,
}
impl Instruments {
    fn new(meter: &Meter, stats: &Stats) -> Self {
        let seconds = |name: &'static str, description: &'static str| {
            meter
                .f64_histogram(name)
                .with_description(description)
                .with_unit("s")
                .with_boundaries(REQUEST_SECONDS.to_vec())
                .build()
        };
        let counter = |name: &'static str, description: &'static str| {
            meter
                .u64_counter(name)
                .with_description(description)
                .build()
        };
        stats.attach_metric(counter(
            "oncl.telemetry.dropped",
            "Spans or metric exports dropped before delivery to the collector.",
        ));
        Self {
            requests: counter("oncl.requests", "Observed requests by route and outcome."),
            request_duration: seconds("oncl.request.duration", "Request duration."),
            admission_duration: seconds(
                "oncl.admission.duration",
                "Time from request start to executor admission.",
            ),
            executor_duration: seconds(
                "oncl.executor.duration",
                "Executor queue wait and run time.",
            ),
            executor_rejected: counter(
                "oncl.executor.rejected",
                "Work refused by the bounded executor.",
            ),
            operations: counter("oncl.operations", "Executed operation items."),
            operation_duration: seconds("oncl.operation.duration", "Operation item duration."),
            key_uses: counter(
                "oncl.key.uses",
                "Operations that applied or may have applied a private key (counts only).",
            ),
            delivery_duration: seconds("oncl.delivery.duration", "Response body delivery time."),
            response_size: meter
                .f64_histogram("oncl.response.size")
                .with_description("Delivered response body bytes.")
                .with_unit("By")
                .with_boundaries(SIZE_BYTES.to_vec())
                .build(),
            stream_aborted: counter(
                "oncl.stream.aborted",
                "Response streams the server cut short after the 200 head, by the typed cause.",
            ),
        }
    }
}
fn kvs(attrs: &[SafeAttr]) -> Vec<KeyValue> {
    attrs.iter().map(|a| a.key_value()).collect()
}

struct Shared {
    tracer: Option<SdkTracer>,
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    meter: Option<Meter>,
    instruments: Option<Instruments>,
    stats: Arc<Stats>,
    queue_capacity: usize,
    in_flight: Arc<AtomicI64>,
    shutdown_timeout: Duration,
    down: AtomicBool,
    threads: usize,
}
impl Shared {
    fn counter(&self, pick: impl Fn(&Instruments) -> &Counter<u64>, attrs: &[SafeAttr]) {
        if let Some(i) = &self.instruments {
            pick(i).add(1, &kvs(attrs));
        }
    }
    fn histogram(
        &self,
        pick: impl Fn(&Instruments) -> &Histogram<f64>,
        v: f64,
        attrs: &[SafeAttr],
    ) {
        if let Some(i) = &self.instruments {
            pick(i).record(v, &kvs(attrs));
        }
    }
    fn child(
        &self,
        parent: &OtelContext,
        name: &'static str,
        start: SystemTime,
        end: SystemTime,
        attrs: &[SafeAttr],
        failed: bool,
    ) {
        let Some(tracer) = &self.tracer else { return };
        let mut span = tracer
            .span_builder(name)
            .with_kind(SpanKind::Internal)
            .with_start_time(start)
            .with_attributes(kvs(attrs))
            .start_with_context(tracer, parent);
        if failed {
            span.set_status(Status::error(""));
        }
        span.end_with_timestamp(end);
    }
    /// Bounded shutdown: each provider flushes on its own short-lived thread and the
    /// caller waits at most the configured deadline in total.
    fn shutdown(&self) -> bool {
        if self.down.swap(true, Ordering::AcqRel) {
            return true;
        }
        let deadline = Instant::now() + self.shutdown_timeout;
        let timeout = self.shutdown_timeout;
        let mut waits = Vec::new();
        let mut spawn = |work: Box<dyn FnOnce() + Send>| {
            let (done, wait) = std::sync::mpsc::sync_channel(1);
            if std::thread::Builder::new()
                .name("oncl-otlp-shutdown".into())
                .spawn(move || {
                    work();
                    let _ = done.send(());
                })
                .is_ok()
            {
                waits.push(wait);
            }
        };
        if let Some(provider) = self.tracer_provider.clone() {
            spawn(Box::new(move || {
                let _ = provider.shutdown_with_timeout(timeout);
            }));
        }
        if let Some(provider) = self.meter_provider.clone() {
            spawn(Box::new(move || {
                let _ = provider.shutdown_with_timeout(timeout);
            }));
        }
        waits.into_iter().all(|wait| {
            wait.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok()
        })
    }
}
/// A handle dropped without `serve` (embedders, tests) still flushes, but never waits
/// longer than `shutdown_timeout_ms` in total: that bound is the same one `serve` uses,
/// and it is a no-op after an explicit `shutdown`.
impl Drop for Shared {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Cheap handle; `Telemetry::disabled()` is the default and costs nothing.
#[derive(Clone, Default)]
pub struct Telemetry {
    shared: Option<Arc<Shared>>,
}
impl Telemetry {
    pub fn disabled() -> Self {
        Self::default()
    }
    /// Build the opt-in exporters. Disabled => no thread, no socket, no allocation of
    /// providers. Enabled => at most one span worker and one metric reader thread; no
    /// connection is opened until the first export.
    pub fn start(config: &TelemetryConfig) -> io::Result<Self> {
        if !config.enabled {
            return Ok(Self::disabled());
        }
        config.validate()?;
        let (authority, prefix, secure) = config.endpoint()?;
        let base = format!(
            "{}://{authority}{prefix}",
            if secure { "https" } else { "http" }
        );
        let timeout = Duration::from_millis(config.export_timeout_ms);
        let roots = config.roots()?;
        let interval = Duration::from_millis(config.export_interval_ms);
        let client = |names: &BTreeMap<String, String>| {
            UreqClient::new(
                authority.clone(),
                names.keys().cloned(),
                Duration::from_millis(config.connect_timeout_ms),
                timeout,
                roots.clone(),
            )
        };
        let resource = Resource::builder_empty()
            .with_service_name(config.service_name.clone())
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();
        let scope = InstrumentationScope::builder(SCOPE)
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let stats = Arc::new(Stats::default());
        let mut threads = 0;
        let (mut tracer, mut tracer_provider) = (None, None);
        if config.traces {
            let exporter = SpanExporter::builder()
                .with_http()
                .with_http_client(client(&config.headers))
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(format!("{base}/v1/traces"))
                .with_timeout(timeout)
                .with_headers(config.headers.clone().into_iter().collect())
                .with_retry_policy(RetryPolicy::disabled())
                .with_max_request_body_size(4 << 20)
                .build()
                .map_err(|_| invalid())?;
            let processor = BoundedSpanProcessor::spawn(
                exporter,
                QueueConfig {
                    capacity: config.queue_size,
                    batch: config.batch_size,
                    delay: interval,
                },
                stats.clone(),
            )?;
            threads += 1;
            let sampler = if config.trace_sample_ratio >= 1.0 {
                Sampler::AlwaysOn
            } else {
                Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    config.trace_sample_ratio,
                )))
            };
            let provider = SdkTracerProvider::builder()
                .with_span_processor(processor)
                .with_sampler(sampler)
                .with_resource(resource.clone())
                .with_max_attributes_per_span(16)
                .with_max_events_per_span(0)
                .with_max_links_per_span(0)
                .build();
            tracer = Some(provider.tracer_with_scope(scope.clone()));
            tracer_provider = Some(provider);
        }
        let (mut meter, mut meter_provider, mut instruments) = (None, None, None);
        let in_flight = Arc::new(AtomicI64::new(0));
        if config.metrics {
            let exporter = MetricExporter::builder()
                .with_http()
                .with_http_client(client(&config.headers))
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(format!("{base}/v1/metrics"))
                .with_timeout(timeout)
                .with_headers(config.headers.clone().into_iter().collect())
                .with_retry_policy(RetryPolicy::disabled())
                .with_max_request_body_size(4 << 20)
                .with_temporality(Temporality::Cumulative)
                .build()
                .map_err(|_| invalid())?;
            let reader = PeriodicReader::builder(CountingMetricExporter {
                inner: exporter,
                stats: stats.clone(),
            })
            .with_interval(interval)
            .build();
            threads += 1;
            let provider = SdkMeterProvider::builder()
                .with_reader(reader)
                .with_resource(resource)
                .build();
            let m = provider.meter_with_scope(scope);
            instruments = Some(Instruments::new(&m, &stats));
            let gauge = in_flight.clone();
            m.i64_observable_gauge("oncl.requests.in_flight")
                .with_description("Observed requests currently in flight.")
                .with_callback(move |o| o.observe(gauge.load(Ordering::Relaxed), &[]))
                .build();
            meter = Some(m);
            meter_provider = Some(provider);
        }
        Ok(Self {
            shared: Some(Arc::new(Shared {
                tracer,
                tracer_provider,
                meter_provider,
                meter,
                instruments,
                stats,
                queue_capacity: config.queue_size,
                in_flight,
                shutdown_timeout: Duration::from_millis(config.shutdown_timeout_ms),
                down: AtomicBool::new(false),
                threads,
            })),
        })
    }
    pub fn is_enabled(&self) -> bool {
        self.shared.is_some()
    }
    pub fn stats(&self) -> TelemetryStats {
        let Some(shared) = &self.shared else {
            return TelemetryStats::default();
        };
        let s = &shared.stats;
        TelemetryStats {
            enabled: true,
            spans_exported: s.spans_exported.load(Ordering::Relaxed),
            spans_dropped: s.spans_dropped.load(Ordering::Relaxed),
            span_export_failures: s.span_export_failures.load(Ordering::Relaxed),
            span_queue_capacity: shared.queue_capacity,
            span_queue_len: s.queued_spans.load(Ordering::Relaxed),
            metric_exports: s.metric_exports.load(Ordering::Relaxed),
            metric_export_failures: s.metric_export_failures.load(Ordering::Relaxed),
            export_threads: if shared.down.load(Ordering::Relaxed) {
                0
            } else {
                shared.threads
            },
        }
    }
    /// Final bounded flush. Never blocks longer than `shutdown_timeout_ms`; returns
    /// whether every exporter finished inside the bound. Idempotent.
    pub fn shutdown(&self) -> bool {
        self.shared.as_ref().is_none_or(|s| s.shutdown())
    }
    /// Publish executor busy/queued gauges (weak: never keeps the executor alive).
    pub(crate) fn register_load(&self, probe: crate::executor::LoadProbe) {
        let Some(meter) = self.shared.as_ref().and_then(|s| s.meter.as_ref()) else {
            return;
        };
        let running = probe.clone();
        meter
            .u64_observable_gauge("oncl.executor.running")
            .with_description("Operations running on bounded native workers.")
            .with_callback(move |o| {
                if let Some((n, _)) = running.load() {
                    o.observe(n as u64, &[]);
                }
            })
            .build();
        meter
            .u64_observable_gauge("oncl.executor.queued")
            .with_description("Operations waiting for a native worker.")
            .with_callback(move |o| {
                if let Some((_, n)) = probe.load() {
                    o.observe(n as u64, &[]);
                }
            })
            .build();
    }
    /// Start observing one public request. Cheap no-op handle when disabled.
    pub(crate) fn begin(&self, route: Route) -> Observer {
        let Some(shared) = &self.shared else {
            return Observer(None);
        };
        if shared.down.load(Ordering::Relaxed) {
            return Observer(None);
        }
        shared.in_flight.fetch_add(1, Ordering::Relaxed);
        let start_time = SystemTime::now();
        let cx = match &shared.tracer {
            Some(tracer) => OtelContext::new().with_span(
                tracer
                    .span_builder("oncl.request")
                    .with_kind(SpanKind::Server)
                    .with_start_time(start_time)
                    .start(tracer),
            ),
            None => OtelContext::new(),
        };
        Observer(Some(Arc::new(Request {
            shared: shared.clone(),
            route,
            start: Instant::now(),
            start_time,
            cx,
            admitted: AtomicBool::new(false),
            item_failed: AtomicBool::new(false),
            terminal: Mutex::new(Terminal::Pending),
        })))
    }
}

enum Terminal {
    /// No response head yet (the request future was dropped, e.g. a disconnect).
    Pending,
    Rejected {
        error: ErrorClass,
        status: HttpStatus,
    },
    Accepted {
        head_at: Instant,
        delivery: Option<(Delivery, u64, Instant)>,
    },
}
struct Request {
    shared: Arc<Shared>,
    route: Route,
    start: Instant,
    start_time: SystemTime,
    cx: OtelContext,
    admitted: AtomicBool,
    item_failed: AtomicBool,
    terminal: Mutex<Terminal>,
}
impl Request {
    fn set(&self, terminal: Terminal) {
        *self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = terminal;
    }
}
/// Completion is emitted exactly once, when the last owner (request future, worker
/// thread, response body) lets go: the span/metric always describe the whole request.
impl Drop for Request {
    fn drop(&mut self) {
        let shared = &self.shared;
        shared.in_flight.fetch_sub(1, Ordering::Relaxed);
        let terminal = std::mem::replace(
            &mut *self
                .terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Terminal::Pending,
        );
        let now = Instant::now();
        let at = |instant: Instant| self.start_time + instant.saturating_duration_since(self.start);
        let route = SafeAttr::Route(self.route);
        let mut attrs = vec![route];
        let (finish, delivery) = match terminal {
            Terminal::Pending => {
                attrs.push(SafeAttr::Outcome(Outcome::Aborted));
                (now, None)
            }
            Terminal::Rejected { error, status } => {
                attrs.push(SafeAttr::Outcome(error.outcome(true)));
                attrs.push(SafeAttr::Error(error));
                attrs.push(SafeAttr::Status(status));
                (now, None)
            }
            Terminal::Accepted { head_at, delivery } => {
                let (state, bytes, ended) = delivery.unwrap_or((Delivery::Aborted, 0, now));
                let outcome = if state == Delivery::Aborted {
                    Outcome::Aborted
                } else if self.item_failed.load(Ordering::Relaxed) {
                    Outcome::Failed
                } else {
                    Outcome::Ok
                };
                attrs.push(SafeAttr::Outcome(outcome));
                attrs.push(SafeAttr::Status(HttpStatus::OK));
                attrs.push(SafeAttr::Delivery(state));
                (ended, Some((state, bytes, head_at, ended)))
            }
        };
        let seconds = finish.saturating_duration_since(self.start).as_secs_f64();
        shared.counter(|i| &i.requests, &attrs);
        shared.histogram(|i| &i.request_duration, seconds, &attrs[..2]);
        if let Some((state, bytes, head_at, ended)) = delivery {
            let delivered = [route, SafeAttr::Delivery(state)];
            shared.histogram(
                |i| &i.delivery_duration,
                ended.saturating_duration_since(head_at).as_secs_f64(),
                &delivered,
            );
            if let Some(i) = &shared.instruments {
                i.response_size.record(bytes as f64, &[route.key_value()]);
            }
            shared.child(
                &self.cx,
                "oncl.delivery",
                at(head_at),
                at(ended),
                &delivered,
                state == Delivery::Aborted,
            );
        }
        let failed = attrs
            .iter()
            .any(|a| matches!(a, SafeAttr::Outcome(o) if *o != Outcome::Ok));
        let span = self.cx.span();
        for attr in &attrs {
            span.set_attribute(attr.key_value());
        }
        if failed {
            span.set_status(Status::error(""));
        }
        span.end_with_timestamp(at(finish));
    }
}

tokio::task_local! {
    static CURRENT: Observer;
}
thread_local! {
    static WORKER: RefCell<Observer> = const { RefCell::new(Observer(None)) };
}

/// The per-request handle. All methods are no-ops on a disabled handle.
#[derive(Clone)]
pub(crate) struct Observer(Option<Arc<Request>>);
pub(crate) struct WorkerGuard(Option<Observer>);
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            WORKER.with(|w| *w.borrow_mut() = previous);
        }
    }
}
/// Timer returned by [`Observer::item_start`].
pub(crate) struct ItemTimer(Option<(Instant, SystemTime)>);
impl ItemTimer {
    /// No per-item duration exists (the SDK ran the item inside a closed batch).
    pub(crate) fn none() -> Self {
        Self(None)
    }
}
pub(crate) enum ItemResult {
    Ok(AppliedState),
    Failed(ErrorCode, AppliedState),
}

impl Observer {
    /// The request this task is serving (set by [`Self::observe`]).
    pub(crate) fn current() -> Self {
        CURRENT.try_with(Clone::clone).unwrap_or(Self(None))
    }
    /// The request whose worker closure runs on this thread (set by [`Self::enter_worker`]).
    pub(crate) fn worker() -> Self {
        WORKER.with(|w| w.borrow().clone())
    }
    pub(crate) fn enabled(&self) -> bool {
        self.0.is_some()
    }
    /// Run `future` as the observed request and complete it with the response.
    pub(crate) fn observe(self, future: ResponseFuture) -> ResponseFuture {
        if self.0.is_none() {
            return future;
        }
        Box::pin(async move {
            let result = CURRENT.scope(self.clone(), future).await;
            self.finish(result)
        })
    }
    fn finish(
        self,
        result: Result<axum::response::Response, ApiError>,
    ) -> Result<axum::response::Response, ApiError> {
        let Some(request) = self.0 else { return result };
        match result {
            Err(error) => {
                request.set(Terminal::Rejected {
                    error: ErrorClass::new(error.code),
                    status: HttpStatus::of(&error),
                });
                Err(error)
            }
            Ok(response) => {
                request.set(Terminal::Accepted {
                    head_at: Instant::now(),
                    delivery: None,
                });
                let (parts, body) = response.into_parts();
                let body = Body::new(ObservedBody {
                    inner: body,
                    request: request.clone(),
                    bytes: 0,
                    done: false,
                });
                Ok(axum::response::Response::from_parts(parts, body))
            }
        }
    }
    /// Admission ends when the first operation is handed to the bounded executor.
    pub(crate) fn mark_admitted(&self) {
        let Some(request) = &self.0 else { return };
        if request.admitted.swap(true, Ordering::AcqRel) {
            return;
        }
        let route = SafeAttr::Route(request.route);
        request.shared.histogram(
            |i| &i.admission_duration,
            request.start.elapsed().as_secs_f64(),
            &[route],
        );
        request.shared.child(
            &request.cx,
            "oncl.admission",
            request.start_time,
            SystemTime::now(),
            &[route],
            false,
        );
    }
    pub(crate) fn executor_stage(
        &self,
        stage: Stage,
        started: Instant,
        start_time: SystemTime,
        error: Option<ErrorCode>,
    ) {
        let Some(request) = &self.0 else { return };
        let mut attrs = vec![SafeAttr::Stage(stage)];
        if stage == Stage::Run {
            let class = error.map(ErrorClass::new);
            attrs.push(SafeAttr::Outcome(
                class.map_or(Outcome::Ok, |c| c.outcome(false)),
            ));
            attrs.extend(class.map(SafeAttr::Error));
        }
        request.shared.histogram(
            |i| &i.executor_duration,
            started.elapsed().as_secs_f64(),
            &attrs,
        );
        let name = match stage {
            Stage::Wait => "oncl.executor.wait",
            Stage::Run => "oncl.executor.run",
        };
        request.shared.child(
            &request.cx,
            name,
            start_time,
            SystemTime::now(),
            &attrs,
            error.is_some(),
        );
    }
    pub(crate) fn executor_rejected(&self) {
        if let Some(request) = &self.0 {
            request.shared.counter(|i| &i.executor_rejected, &[]);
        }
    }
    /// A response stream the server aborted after its 200 head (the client sees only a
    /// lost response): the typed cause as a closed error code, never a message.
    pub(crate) fn stream_aborted(&self, error: ErrorClass, applied: AppliedState) {
        if let Some(request) = &self.0 {
            request.shared.counter(
                |i| &i.stream_aborted,
                &[
                    SafeAttr::Route(request.route),
                    SafeAttr::Error(error),
                    SafeAttr::Applied(Applied(applied)),
                ],
            );
        }
    }
    /// Make this request current for the calling worker thread until the guard drops.
    pub(crate) fn enter_worker(&self) -> WorkerGuard {
        if self.0.is_none() {
            return WorkerGuard(None);
        }
        WorkerGuard(Some(WORKER.with(|w| w.replace(self.clone()))))
    }
    pub(crate) fn item_start(&self) -> ItemTimer {
        ItemTimer(self.0.as_ref().map(|_| (Instant::now(), SystemTime::now())))
    }
    /// Record one operation item. `timer` is `None` when the SDK ran the item inside a
    /// closed batch (no per-item duration exists, only the outcome).
    pub(crate) fn item_end(
        &self,
        timer: ItemTimer,
        kind: OperationKind,
        family: Option<Family>,
        result: ItemResult,
    ) {
        let Some(request) = &self.0 else { return };
        let mut attrs = vec![SafeAttr::Kind(kind)];
        attrs.extend(family.map(SafeAttr::Family));
        let applied = match result {
            ItemResult::Ok(applied) => {
                attrs.push(SafeAttr::Outcome(Outcome::Ok));
                applied
            }
            ItemResult::Failed(code, applied) => {
                let class = ErrorClass::new(code);
                request.item_failed.store(true, Ordering::Relaxed);
                attrs.push(SafeAttr::Outcome(class.outcome(false)));
                attrs.push(SafeAttr::Error(class));
                applied
            }
        };
        attrs.push(SafeAttr::Applied(Applied(applied)));
        let shared = &request.shared;
        shared.counter(|i| &i.operations, &attrs);
        if applied != AppliedState::NotApplied {
            shared.counter(
                |i| &i.key_uses,
                &[SafeAttr::Kind(kind), SafeAttr::Applied(Applied(applied))],
            );
        }
        if let Some((started, start_time)) = timer.0 {
            shared.histogram(
                |i| &i.operation_duration,
                started.elapsed().as_secs_f64(),
                &attrs[..attrs.len() - 1],
            );
            shared.child(
                &request.cx,
                "oncl.operation",
                start_time,
                SystemTime::now(),
                &attrs,
                matches!(attrs.iter().find(|a| matches!(a, SafeAttr::Outcome(_))), Some(SafeAttr::Outcome(o)) if *o != Outcome::Ok),
            );
        }
    }
}
pub(crate) fn operation_kind(
    operation: &oncl_api::dto::Operation,
) -> (OperationKind, Option<Family>) {
    (OperationKind::of(operation), Family::of(operation))
}

/// Counts delivered bytes and records complete/aborted delivery without ever looking
/// at their content.
struct ObservedBody {
    inner: Body,
    request: Arc<Request>,
    bytes: u64,
    done: bool,
}
impl ObservedBody {
    fn finish(&mut self, delivery: Delivery) {
        if !self.done {
            self.done = true;
            if let Terminal::Accepted { delivery: slot, .. } = &mut *self
                .request
                .terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                *slot = Some((delivery, self.bytes, Instant::now()));
            }
        }
    }
}
impl axum::body::HttpBody for ObservedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.bytes = self.bytes.saturating_add(data.len() as u64);
                }
            }
            Poll::Ready(None) => self.finish(Delivery::Complete),
            Poll::Ready(Some(Err(_))) => self.finish(Delivery::Aborted),
            Poll::Pending => {}
        }
        poll
    }
    fn is_end_stream(&self) -> bool {
        axum::body::HttpBody::is_end_stream(&self.inner)
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
impl Drop for ObservedBody {
    fn drop(&mut self) {
        if axum::body::HttpBody::is_end_stream(&self.inner) {
            self.finish(Delivery::Complete);
        } else {
            self.finish(Delivery::Aborted);
        }
    }
}
