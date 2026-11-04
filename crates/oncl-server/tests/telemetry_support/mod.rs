#![allow(dead_code)]
//! A real local OTLP/HTTP protobuf receiver: it speaks HTTP/1.1 on a TCP socket,
//! keeps every raw request, and decodes the bodies with the exact protobuf messages
//! of the OTLP specification (`opentelemetry-proto`). It never calls the SDK.
pub mod pki;
use opentelemetry_proto::tonic::{
    collector::{metrics::v1::ExportMetricsServiceRequest, trace::v1::ExportTraceServiceRequest},
    common::v1::{AnyValue, KeyValue, any_value::Value},
    metrics::v1::{metric::Data, number_data_point},
};
use prost::Message;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// 200 with an empty OTLP response.
    Accept,
    /// Accepts the connection, reads the whole request and never answers.
    Hang,
    /// 200 after a fixed delay.
    Slow(Duration),
    /// 503.
    Unavailable,
}
#[derive(Clone, Debug)]
pub struct Received {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
struct State {
    mode: Mutex<Mode>,
    connections: AtomicUsize,
    received: Mutex<Vec<Received>>,
    stop: AtomicBool,
}
pub struct Collector {
    pub address: SocketAddr,
    state: Arc<State>,
    accept: Option<std::thread::JoinHandle<()>>,
    secure: bool,
}
impl Collector {
    pub fn start() -> Self {
        Self::bind("127.0.0.1:0".parse().unwrap())
    }
    /// A collector speaking TLS with the given certificate chain and key (DER).
    pub fn start_tls(cert: Vec<u8>, key: Vec<u8>) -> Self {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert)],
            rustls::pki_types::PrivateKeyDer::try_from(key).unwrap(),
        )
        .unwrap();
        Self::bind_with("127.0.0.1:0".parse().unwrap(), Some(Arc::new(config)))
    }
    pub fn bind(address: SocketAddr) -> Self {
        Self::bind_with(address, None)
    }
    fn bind_with(address: SocketAddr, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        let listener = TcpListener::bind(address).unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(State {
            mode: Mutex::new(Mode::Accept),
            connections: AtomicUsize::new(0),
            received: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
        });
        let secure = tls.is_some();
        let shared = state.clone();
        let accept = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if shared.stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                shared.connections.fetch_add(1, Ordering::SeqCst);
                let shared = shared.clone();
                let tls = tls.clone();
                std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    match tls {
                        None => serve(stream, shared),
                        Some(config) => serve(
                            rustls::StreamOwned::new(
                                rustls::ServerConnection::new(config).unwrap(),
                                stream,
                            ),
                            shared,
                        ),
                    }
                });
            }
        });
        Self {
            secure,
            address,
            state,
            accept: Some(accept),
        }
    }
    pub fn url(&self) -> String {
        if self.secure {
            format!("https://localhost:{}", self.address.port())
        } else {
            format!("http://{}", self.address)
        }
    }
    pub fn set_mode(&self, mode: Mode) {
        *self.state.mode.lock().unwrap() = mode;
    }
    /// Accepted TCP connections (any connection at all counts, even without a request).
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }
    pub fn received(&self) -> Vec<Received> {
        self.state.received.lock().unwrap().clone()
    }
    pub fn wait_for(
        &self,
        what: &str,
        within: Duration,
        mut done: impl FnMut(&[Received]) -> bool,
    ) {
        let end = Instant::now() + within;
        loop {
            if done(&self.received()) {
                return;
            }
            assert!(Instant::now() < end, "collector never received {what}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    /// Close the listener: later connection attempts are refused.
    pub fn stop(mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if self.accept.is_some() {
            let _ = TcpStream::connect(self.address);
        }
    }
}
fn serve<S: Read + Write>(mut stream: S, state: Arc<State>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Header block.
        let head_end = loop {
            if let Some(p) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if state.stop.load(Ordering::SeqCst) {
                        return;
                    }
                }
                Err(_) => return,
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default();
        let path = request_line
            .split(' ')
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let length: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse().ok())
            .expect("exporter sends Content-Length");
        while buffer.len() < head_end + length {
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if state.stop.load(Ordering::SeqCst) {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        let body = buffer[head_end..head_end + length].to_vec();
        buffer.drain(..head_end + length);
        state.received.lock().unwrap().push(Received {
            path,
            headers,
            body,
        });
        let mode = *state.mode.lock().unwrap();
        let status = match mode {
            Mode::Accept => "200 OK",
            Mode::Slow(delay) => {
                std::thread::sleep(delay);
                "200 OK"
            }
            Mode::Unavailable => "503 Service Unavailable",
            Mode::Hang => {
                while !state.stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                return;
            }
        };
        let reply = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/x-protobuf\r\ncontent-length: 0\r\n\r\n"
        );
        if stream.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

/// Independently maintained copy of the exported vocabulary: any attribute key or
/// value outside it fails the privacy test.
pub const ALLOWED_KEYS: [&str; 10] = [
    "oncl.route",
    "oncl.operation.kind",
    "oncl.operation.family",
    "oncl.outcome",
    "oncl.error.code",
    "oncl.key.applied",
    "http.response.status_code",
    "oncl.delivery",
    "oncl.signal",
    "oncl.stage",
];
pub fn allowed_values(key: &str) -> &'static [&'static str] {
    match key {
        "oncl.route" => &["hash", "operations", "batch"],
        "oncl.operation.kind" => &[
            "hash",
            "verify",
            "extract",
            "sign",
            "extend",
            "jws_sign",
            "jws_add",
            "jws_verify",
            "jwt_encode",
            "jwt_decode",
            "jwt_verify",
            "plugin",
            "inspect",
            "stamp",
            "verify_stamp",
        ],
        "oncl.operation.family" => &[
            "cms",
            "cades",
            "pdf",
            "pades",
            "xml",
            "xades",
            "wsse",
            "xml_legacy",
            "xades_legacy",
        ],
        "oncl.outcome" => &["ok", "rejected", "failed", "aborted"],
        "oncl.error.code" => &[
            "permission_denied",
            "interaction_required",
            "invalid_request",
            "capacity_exceeded",
            "deadline_exceeded",
            "cancelled",
            "input_limit",
            "framing_limit",
            "missing_temporary_store",
            "memory_limit",
            "temp_limit",
            "metadata_limit",
            "output_limit",
            "audit_unavailable",
            "missing_configuration",
            "key_not_found",
            "validation_failed",
            "operation_failed",
            "internal",
        ],
        "oncl.key.applied" => &["not_applied", "applied", "unknown"],
        "http.response.status_code" => &[
            "200", "400", "403", "404", "408", "413", "422", "500", "503", "504",
        ],
        "oncl.delivery" => &["complete", "aborted"],
        "oncl.signal" => &["spans", "metrics"],
        "oncl.stage" => &["wait", "run"],
        _ => &[],
    }
}
pub const ALLOWED_RESOURCE_KEYS: [&str; 2] = ["service.name", "service.version"];
pub const ALLOWED_SPANS: [&str; 6] = [
    "oncl.request",
    "oncl.admission",
    "oncl.executor.wait",
    "oncl.executor.run",
    "oncl.operation",
    "oncl.delivery",
];
pub const ALLOWED_METRICS: [&str; 13] = [
    "oncl.requests",
    "oncl.request.duration",
    "oncl.admission.duration",
    "oncl.executor.duration",
    "oncl.executor.rejected",
    "oncl.operations",
    "oncl.operation.duration",
    "oncl.key.uses",
    "oncl.delivery.duration",
    "oncl.response.size",
    "oncl.telemetry.dropped",
    "oncl.requests.in_flight",
    "oncl.executor.running",
];
pub const ALSO_ALLOWED_METRIC: &str = "oncl.executor.queued";

fn text(value: &Option<AnyValue>) -> String {
    match value.as_ref().and_then(|v| v.value.as_ref()) {
        Some(Value::StringValue(s)) => s.clone(),
        Some(Value::IntValue(i)) => i.to_string(),
        Some(Value::BoolValue(b)) => b.to_string(),
        Some(Value::DoubleValue(d)) => d.to_string(),
        other => panic!("attribute value type outside the exported vocabulary: {other:?}"),
    }
}
fn map(attributes: &[KeyValue]) -> BTreeMap<String, String> {
    attributes
        .iter()
        .map(|kv| (kv.key.clone(), text(&kv.value)))
        .collect()
}

#[derive(Debug, Clone)]
pub struct SpanFact {
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub errored: bool,
    pub events: usize,
    pub links: usize,
    pub trace_id: Vec<u8>,
    pub span_id: Vec<u8>,
    pub parent: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct PointFact {
    pub metric: String,
    pub attributes: BTreeMap<String, String>,
    /// Counter value, gauge value, or histogram count.
    pub value: f64,
}
#[derive(Debug, Default)]
pub struct Facts {
    pub trace_payloads: usize,
    pub metric_payloads: usize,
    pub resource_keys: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub spans: Vec<SpanFact>,
    pub points: Vec<PointFact>,
}
impl Facts {
    pub fn spans_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a SpanFact> {
        self.spans.iter().filter(move |s| s.name == name)
    }
    pub fn metric_total(&self, metric: &str, filter: &[(&str, &str)]) -> f64 {
        // Cumulative temporality: the latest payload carries the running total, so the
        // maximum per distinct attribute set is the current value.
        let mut latest: BTreeMap<&BTreeMap<String, String>, f64> = BTreeMap::new();
        for point in self.points.iter().filter(|p| {
            p.metric == metric
                && filter
                    .iter()
                    .all(|(k, v)| p.attributes.get(*k).is_some_and(|a| a == v))
        }) {
            let slot = latest.entry(&point.attributes).or_insert(0.0);
            *slot = slot.max(point.value);
        }
        latest.values().sum()
    }
}
/// Decode every received request exactly as a collector would.
pub fn decode(received: &[Received]) -> Facts {
    let mut facts = Facts::default();
    for request in received {
        let content_type = request
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str());
        assert_eq!(content_type, Some("application/x-protobuf"));
        assert!(
            !request.headers.iter().any(|(k, _)| k == "content-encoding"),
            "uncompressed OTLP/HTTP protobuf only"
        );
        match request.path.as_str() {
            "/v1/traces" => {
                facts.trace_payloads += 1;
                let message = ExportTraceServiceRequest::decode(&request.body[..])
                    .expect("valid ExportTraceServiceRequest");
                for resource in message.resource_spans {
                    facts.resource_keys.extend(
                        resource
                            .resource
                            .iter()
                            .flat_map(|r| r.attributes.iter().map(|kv| kv.key.clone())),
                    );
                    for scope in resource.scope_spans {
                        if let Some(s) = &scope.scope {
                            facts.scopes.insert(s.name.clone());
                            assert!(s.attributes.is_empty(), "scope attributes are not exported");
                        }
                        for span in scope.spans {
                            facts.spans.push(SpanFact {
                                name: span.name,
                                attributes: map(&span.attributes),
                                errored: span.status.is_some_and(|s| s.code == 2),
                                events: span.events.len(),
                                links: span.links.len(),
                                trace_id: span.trace_id,
                                span_id: span.span_id,
                                parent: span.parent_span_id,
                            });
                        }
                    }
                }
            }
            "/v1/metrics" => {
                facts.metric_payloads += 1;
                let message = ExportMetricsServiceRequest::decode(&request.body[..])
                    .expect("valid ExportMetricsServiceRequest");
                for resource in message.resource_metrics {
                    facts.resource_keys.extend(
                        resource
                            .resource
                            .iter()
                            .flat_map(|r| r.attributes.iter().map(|kv| kv.key.clone())),
                    );
                    for scope in resource.scope_metrics {
                        if let Some(s) = &scope.scope {
                            facts.scopes.insert(s.name.clone());
                            assert!(s.attributes.is_empty(), "scope attributes are not exported");
                        }
                        for metric in scope.metrics {
                            let name = metric.name;
                            let mut push =
                                |attributes: &[KeyValue], value: f64, exemplars: usize| {
                                    assert_eq!(
                                        exemplars, 0,
                                        "exemplars carry trace links: none exported"
                                    );
                                    facts.points.push(PointFact {
                                        metric: name.clone(),
                                        attributes: map(attributes),
                                        value,
                                    });
                                };
                            let number = |v: &Option<number_data_point::Value>| match v {
                                Some(number_data_point::Value::AsInt(i)) => *i as f64,
                                Some(number_data_point::Value::AsDouble(d)) => *d,
                                None => 0.0,
                            };
                            match metric.data {
                                Some(Data::Sum(s)) => {
                                    for p in s.data_points {
                                        push(&p.attributes, number(&p.value), p.exemplars.len());
                                    }
                                }
                                Some(Data::Gauge(g)) => {
                                    for p in g.data_points {
                                        push(&p.attributes, number(&p.value), p.exemplars.len());
                                    }
                                }
                                Some(Data::Histogram(h)) => {
                                    for p in h.data_points {
                                        push(&p.attributes, p.count as f64, p.exemplars.len());
                                    }
                                }
                                other => panic!("unexpected metric data kind {other:?}"),
                            }
                        }
                    }
                }
            }
            other => panic!("unexpected OTLP path {other}"),
        }
    }
    facts
}

/// Every attribute key/value, span name, metric name and resource key must be in the
/// closed vocabulary; `canaries` must not occur in any raw payload byte.
pub fn assert_private(received: &[Received], canaries: &[&[u8]]) -> Facts {
    for request in received {
        for canary in canaries {
            assert!(
                !request.body.windows(canary.len()).any(|w| w == *canary),
                "canary {:?} leaked into a {} payload",
                String::from_utf8_lossy(canary),
                request.path
            );
            for (name, value) in &request.headers {
                assert!(
                    !name.as_bytes().windows(canary.len()).any(|w| w == *canary)
                        && !value.as_bytes().windows(canary.len()).any(|w| w == *canary),
                    "canary leaked into an HTTP header"
                );
            }
        }
    }
    let facts = decode(received);
    for key in &facts.resource_keys {
        assert!(
            ALLOWED_RESOURCE_KEYS.contains(&key.as_str()),
            "resource key {key}"
        );
    }
    assert_eq!(
        facts.scopes.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["oncl-server"]
    );
    let check = |attributes: &BTreeMap<String, String>| {
        for (key, value) in attributes {
            assert!(ALLOWED_KEYS.contains(&key.as_str()), "attribute key {key}");
            assert!(
                allowed_values(key).contains(&value.as_str()),
                "attribute value {key}={value}"
            );
        }
    };
    for span in &facts.spans {
        assert!(
            ALLOWED_SPANS.contains(&span.name.as_str()),
            "span {}",
            span.name
        );
        assert_eq!((span.events, span.links), (0, 0));
        check(&span.attributes);
    }
    for point in &facts.points {
        assert!(
            ALLOWED_METRICS.contains(&point.metric.as_str()) || point.metric == ALSO_ALLOWED_METRIC,
            "metric {}",
            point.metric
        );
        check(&point.attributes);
    }
    facts
}

/// One real HTTP/1.1 POST (`GET` for `/health`) with an owned body.
pub async fn post(
    address: SocketAddr,
    token: &str,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
) -> (u16, Vec<u8>) {
    use http_body_util::{BodyExt, Full};
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::builder()
        .method(if path == "/health" { "GET" } else { "POST" })
        .uri(path)
        .header("host", address.to_string())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", content_type)
        .body(Full::new(hyper::body::Bytes::from(body)))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}
