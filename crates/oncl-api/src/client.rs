//! Streaming HTTP client of the typed `/v1/operations` and `/v1/batch` contract.
//!
//! Enabled by the `client` feature; the closure is `ureq` + `rustls` + `serde_json` only (no
//! Tokio, axum, hyper or server DTO code). It sends the metadata-first multipart request as
//! a bounded stream, parses the response incrementally and hands artifact bytes to a caller
//! supplied [`ArtifactSink`] without accumulating them. It never opens a path, never
//! follows a redirect, never retries, and its errors carry a stable code and an honest
//! [`AppliedState`] only: neither the bearer token nor any response body is ever part of an
//! error value.
//!
//! # What "applied" means here
//!
//! The service starts a private operation only after it has taken the *whole* request body.
//! A failure while the body was still being sent is therefore `NotApplied`. A failure after
//! the last body byte was handed to the transport, without a terminal record, is `Unknown`
//! when the request could apply a private key and `NotApplied` otherwise. A terminal record
//! or a typed refusal reports the service's own value. There is no retry, idempotency key or
//! exactly-once promise: a lost response is never repeated automatically.
use crate::{
    dto::{Operation, OperationMetadata, PartRole},
    error::{ApiError, AppliedState, ErrorCode},
};
use std::{
    io::Read,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

mod stream;
mod upload;
pub mod wire;

pub use wire::FinalRecord;

/// The documented encoded size limit of the metadata object.
pub const METADATA_LIMIT: usize = 65_536;
const TOKEN_LIMIT: usize = 4096;
const ERROR_BODY_LIMIT: u64 = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A cooperative stop observed between I/O steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Cancelled,
    DeadlineExceeded,
}

/// Stable, secret-free failure categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    InvalidEndpoint,
    PlainHttpRefused,
    InvalidToken,
    InvalidCertificate,
    InvalidRequest,
    /// A local document source failed, was shorter/longer than declared or changed.
    SourceUnavailable,
    Connect,
    Tls,
    Transport,
    Cancelled,
    DeadlineExceeded,
    /// A typed refusal of the service before any response stream (`server_code` set).
    Rejected,
    /// An HTTP status without the typed error envelope (proxy, transport-level refusal).
    UnexpectedStatus,
    /// The response ended or failed before the terminal record and closing delimiter.
    ResponseLost,
    /// Bytes that violate the documented framing or record shape.
    Protocol,
    /// The caller's artifact sink failed (local staging).
    Artifact,
}

impl FailureKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidEndpoint => "InvalidEndpoint",
            Self::PlainHttpRefused => "PlainHttpRefused",
            Self::InvalidToken => "InvalidToken",
            Self::InvalidCertificate => "InvalidCertificate",
            Self::InvalidRequest => "InvalidRequest",
            Self::SourceUnavailable => "SourceUnavailable",
            Self::Connect => "ConnectFailed",
            Self::Tls => "TlsFailed",
            Self::Transport => "TransportFailed",
            Self::Cancelled => "Cancelled",
            Self::DeadlineExceeded => "DeadlineExceeded",
            Self::Rejected => "Rejected",
            Self::UnexpectedStatus => "UnexpectedStatus",
            Self::ResponseLost => "ResponseLost",
            Self::Protocol => "ProtocolViolation",
            Self::Artifact => "ArtifactStagingFailed",
        }
    }
}

/// A client failure. Display shows the stable code, the HTTP status and the typed service
/// code only: never the token, a header value or a response body.
#[derive(Clone, Debug)]
pub struct ClientError {
    pub kind: FailureKind,
    pub applied: AppliedState,
    pub status: Option<u16>,
    /// The typed service code of a [`FailureKind::Rejected`] refusal.
    pub server_code: Option<ErrorCode>,
    /// The service's `subcode` of that refusal, if it named one: a well-formed identifier
    /// ([`crate::error::is_subcode`]), so it is safe to print.
    pub server_subcode: Option<String>,
    /// A fixed explanation of a protocol violation (never response bytes).
    pub detail: Option<&'static str>,
}

impl ClientError {
    fn new(kind: FailureKind, applied: AppliedState) -> Self {
        Self {
            kind,
            applied,
            status: None,
            server_code: None,
            server_subcode: None,
            detail: None,
        }
    }
    fn local(kind: FailureKind) -> Self {
        Self::new(kind, AppliedState::NotApplied)
    }
    /// The code shown to the user: the service's typed code for a refusal, otherwise ours.
    pub fn code(&self) -> String {
        match self.server_code {
            Some(code) => format!("{code:?}"),
            None => self.kind.code().to_owned(),
        }
    }
    /// [`ClientError::code`] plus the HTTP status and fixed detail of an untyped failure.
    /// Never a header, token or body byte.
    pub fn describe(&self) -> String {
        let mut text = self.code();
        if let Some(subcode) = &self.server_subcode {
            text.push_str(&format!("; subcode={subcode}"));
        }
        if self.server_code.is_none() {
            if let Some(status) = self.status {
                text.push_str(&format!(" (HTTP {status})"));
            }
            if let Some(detail) = self.detail {
                text.push_str(&format!(": {detail}"));
            }
        }
        text
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; applied={:?}", self.describe(), self.applied)
    }
}

impl std::error::Error for ClientError {}

/// A parsed `http(s)://host[:port]` base URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    tls: bool,
    authority: String,
    loopback: bool,
}

impl Endpoint {
    /// `http` is accepted only for a loopback host (`localhost`, `127.0.0.0/8`, `::1`)
    /// unless `allow_plain_http` explicitly documents the choice; `https` always. No
    /// userinfo, path, query or fragment.
    pub fn parse(text: &str, allow_plain_http: bool) -> Result<Self, ClientError> {
        let invalid = || ClientError::local(FailureKind::InvalidEndpoint);
        let (tls, rest) = if let Some(rest) = text.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = text.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(invalid());
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty()
            || authority
                .bytes()
                .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\') || b <= b' ' || b >= 0x7f)
        {
            return Err(invalid());
        }
        let (host, port) = split_authority(authority).ok_or_else(invalid)?;
        let loopback = is_loopback(host);
        if port == Some(0) {
            return Err(invalid());
        }
        if !tls && !loopback && !allow_plain_http {
            return Err(ClientError::local(FailureKind::PlainHttpRefused));
        }
        Ok(Self {
            tls,
            authority: authority.to_owned(),
            loopback,
        })
    }
    pub fn is_tls(&self) -> bool {
        self.tls
    }
    pub fn is_loopback(&self) -> bool {
        self.loopback
    }
    fn url(&self, path: &str) -> String {
        format!(
            "{}://{}{path}",
            if self.tls { "https" } else { "http" },
            self.authority
        )
    }
}

fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => None,
            tail => Some(tail.strip_prefix(':')?.parse().ok()?),
        };
        host.parse::<std::net::Ipv6Addr>().ok()?;
        return Some((host, port));
    }
    let split = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !port.is_empty() => {
            (host, Some(port.parse::<u16>().ok()?))
        }
        Some(_) => return None,
        None => (authority, None),
    };
    (!split.0.is_empty()).then_some(split)
}

fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// Server certificate trust. With no explicit anchor the built-in webpki roots are used; an
/// explicit set replaces them (a private server is trusted through exactly that CA or its
/// own certificate, never in addition to the public roots). There is no way to skip
/// verification.
#[derive(Clone, Debug, Default)]
pub struct ClientConfig {
    trust_files: Vec<Vec<u8>>,
    allow_plain_http: bool,
}

impl ClientConfig {
    pub fn new() -> Self {
        Self::default()
    }
    /// Trust anchors instead of the webpki roots: each entry is the content of one file,
    /// a PEM bundle of certificates or a single DER certificate. A private key in a PEM
    /// file is refused rather than ignored.
    #[must_use]
    pub fn with_trust_anchor_files(mut self, files: Vec<Vec<u8>>) -> Self {
        self.trust_files = files;
        self
    }
    /// Permit plain `http` to a non-loopback host (the token and documents travel
    /// unencrypted: only for a protected network, e.g. behind a trusted proxy).
    #[must_use]
    pub fn allow_plain_http(mut self, allow: bool) -> Self {
        self.allow_plain_http = allow;
        self
    }
}

/// The route of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Operations,
    Batch,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Self::Operations => "/v1/operations",
            Self::Batch => "/v1/batch",
        }
    }
}

/// The bytes of one declared part.
pub enum Source {
    /// Bounded memory-only bytes, wiped on drop (secrets, small documents).
    Memory(Zeroizing<Vec<u8>>),
    /// A document streamed from a reader; `length` is the exact length when known (a
    /// source that delivers any other number of bytes aborts the upload).
    Stream {
        reader: Box<dyn Read + Send>,
        length: Option<u64>,
    },
}

/// A validated request: metadata, its parts in wire order (secrets first) and their sources.
pub struct Request {
    route: Route,
    metadata: Vec<u8>,
    parts: Vec<(String, bool, Source)>,
    may_apply_key: bool,
}

/// Whether executing `operation` can apply a private key (so a lost answer is `Unknown`).
fn may_apply_key(operation: &Operation) -> bool {
    match operation {
        Operation::Sign { .. }
        | Operation::JwsSign { .. }
        | Operation::JwsAdd { .. }
        | Operation::JwtEncode { .. } => true,
        Operation::Plugin { keys, .. } => !keys.is_empty(),
        _ => false,
    }
}

impl Request {
    /// `sources` must name every declared part exactly once. Secret parts must be
    /// [`Source::Memory`]; the declared order (secrets before documents) is the wire order.
    pub fn new(
        route: Route,
        metadata: &OperationMetadata,
        mut sources: Vec<(String, Source)>,
    ) -> Result<Self, ClientError> {
        let invalid = || ClientError::local(FailureKind::InvalidRequest);
        let json = serde_json::to_vec(metadata).map_err(|_| invalid())?;
        if json.len() > METADATA_LIMIT || metadata.items.is_empty() {
            return Err(invalid());
        }
        let mut ordered = Vec::with_capacity(metadata.parts.len());
        let mut seen_document = false;
        for part in &metadata.parts {
            let at = sources
                .iter()
                .position(|(name, _)| *name == part.name)
                .ok_or_else(invalid)?;
            let (name, source) = sources.swap_remove(at);
            match (part.role, &source) {
                (PartRole::Secret, Source::Memory(_)) if !seen_document => {}
                (PartRole::Document, _) => seen_document = true,
                _ => return Err(invalid()),
            }
            ordered.push((name, part.role == PartRole::Document, source));
        }
        if !sources.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            route,
            metadata: json,
            parts: ordered,
            may_apply_key: metadata
                .items
                .iter()
                .any(|item| may_apply_key(&item.operation)),
        })
    }
}

/// Receives the bytes of each artifact part as they arrive. Nothing may be published from
/// the sink until [`ApiClient::execute`] has returned `Ok`: a part that was fully received
/// belongs to a response that may still turn out to be incomplete.
pub trait ArtifactSink {
    /// A new artifact part of exactly `length` bytes begins.
    fn begin(&mut self, content_id: &str, length: u64) -> std::io::Result<()>;
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

/// One artifact part received intact (framing verified).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedArtifact {
    pub content_id: String,
    pub length: u64,
}

/// A cooperative stop polled while waiting and between I/O steps.
pub type Control = Arc<dyn Fn() -> Result<(), Stop> + Send + Sync>;

/// Per-call control: an absolute deadline and the stop poll.
pub struct ExecuteOptions {
    pub deadline: Instant,
    pub control: Control,
}

enum Event {
    Begin(String, u64),
    Chunk(Vec<u8>),
    Done(Result<Completed, ClientError>),
}
struct ChannelSink(mpsc::SyncSender<Event>);
impl ArtifactSink for ChannelSink {
    fn begin(&mut self, content_id: &str, length: u64) -> std::io::Result<()> {
        self.0
            .send(Event::Begin(content_id.to_owned(), length))
            .map_err(|_| std::io::Error::other("consumer gone"))
    }
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0
            .send(Event::Chunk(bytes.to_vec()))
            .map_err(|_| std::io::Error::other("consumer gone"))
    }
}

/// A response whose terminal record, closing delimiter and HTTP entity were all intact.
/// The record may still say `failed`/`partial`: that is the service's answer, not a loss.
#[derive(Debug)]
pub struct Completed {
    pub record: FinalRecord,
    pub artifacts: Vec<ReceivedArtifact>,
    pub progress_frames: u64,
    /// Document payload bytes this client sent (not framing, not secrets).
    pub document_bytes: u64,
}

#[derive(Clone)]
pub struct ApiClient {
    endpoint: Endpoint,
    token: Zeroizing<String>,
    roots: Vec<ureq::tls::Certificate<'static>>,
}

fn trust_anchors(files: &[Vec<u8>]) -> Result<Vec<ureq::tls::Certificate<'static>>, ClientError> {
    let invalid = || ClientError::local(FailureKind::InvalidCertificate);
    let mut roots = Vec::new();
    for file in files {
        let text = file.trim_ascii_start();
        if text.starts_with(b"-----BEGIN") {
            for item in ureq::tls::parse_pem(file) {
                match item.map_err(|_| invalid())? {
                    ureq::tls::PemItem::Certificate(certificate) => roots.push(certificate),
                    _ => return Err(invalid()),
                }
            }
        } else if text.first() == Some(&0x30) {
            roots.push(ureq::tls::Certificate::from_der(file).to_owned());
        } else {
            return Err(invalid());
        }
    }
    if roots.len() > 64 || (!files.is_empty() && roots.is_empty()) {
        return Err(invalid());
    }
    Ok(roots)
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= TOKEN_LIMIT
        && token.bytes().all(|b| (0x21..0x7f).contains(&b))
}

impl ApiClient {
    pub fn new(
        endpoint: &str,
        token: Zeroizing<String>,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        if !valid_token(&token) {
            return Err(ClientError::local(FailureKind::InvalidToken));
        }
        let endpoint = Endpoint::parse(endpoint, config.allow_plain_http)?;
        let roots = trust_anchors(&config.trust_files)?;
        if !endpoint.is_tls() && !roots.is_empty() {
            // An explicit CA for a plain endpoint is a configuration mistake, not a no-op.
            return Err(ClientError::local(FailureKind::InvalidEndpoint));
        }
        Ok(Self {
            endpoint,
            token,
            roots,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    fn agent(&self, remaining: Duration) -> Result<ureq::Agent, ClientError> {
        let mut builder = ureq::Agent::config_builder()
            .http_status_as_error(false)
            // The bearer token must never follow a redirect to another origin.
            .max_redirects(0)
            // Explicitly direct: no ambient proxy variable can see the token or documents.
            .proxy(None)
            .user_agent(format!("oncl-api-client/{}", env!("CARGO_PKG_VERSION")))
            .timeout_connect(Some(CONNECT_TIMEOUT.min(remaining)))
            .timeout_global(Some(remaining));
        if !self.roots.is_empty() {
            builder = builder.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::Specific(Arc::new(self.roots.clone())))
                    .build(),
            );
        }
        Ok(builder.build().into())
    }

    /// Send `request` and stream its answer. See the module docs for the exact meaning of
    /// the returned [`AppliedState`] on failure. The exchange runs on its own thread and the
    /// caller polls `control` every 50 ms, so a stop (Ctrl-C, deadline) is observed promptly
    /// even while the server sends nothing; the abandoned exchange ends at its deadline.
    pub fn execute(
        &self,
        request: Request,
        sink: &mut dyn ArtifactSink,
        options: &ExecuteOptions,
    ) -> Result<Completed, ClientError> {
        (options.control)().map_err(stop_error_before_send)?;
        let may_apply = request.may_apply_key;
        let complete = Arc::new(std::sync::Mutex::new(upload::Gate::default()));
        let (events, inbox) = mpsc::sync_channel::<Event>(4);
        let (client, control, deadline, flag) = (
            self.clone(),
            options.control.clone(),
            options.deadline,
            complete.clone(),
        );
        let finished = events.clone();
        std::thread::Builder::new()
            .name("oncl-api-exchange".into())
            .spawn(move || {
                let mut sink = ChannelSink(events);
                let result = client.exchange(request, &mut sink, &*control, deadline, &flag);
                let _ = finished.send(Event::Done(result));
            })
            .map_err(|_| ClientError::local(FailureKind::Transport))?;
        let applied = || {
            let mut gate = complete.lock().unwrap_or_else(|e| e.into_inner());
            gate.abort = true;
            if gate.complete && may_apply {
                AppliedState::Unknown
            } else {
                AppliedState::NotApplied
            }
        };
        loop {
            match inbox.recv_timeout(Duration::from_millis(50)) {
                Ok(Event::Begin(id, length)) => {
                    if sink.begin(&id, length).is_err() {
                        return Err(ClientError::new(FailureKind::Artifact, applied()));
                    }
                }
                Ok(Event::Chunk(bytes)) => {
                    if sink.write(&bytes).is_err() {
                        return Err(ClientError::new(FailureKind::Artifact, applied()));
                    }
                }
                Ok(Event::Done(result)) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(stop) = (options.control)() {
                        let kind = match stop {
                            Stop::Cancelled => FailureKind::Cancelled,
                            Stop::DeadlineExceeded => FailureKind::DeadlineExceeded,
                        };
                        return Err(ClientError::new(kind, applied()));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ClientError::new(FailureKind::ResponseLost, applied()));
                }
            }
        }
    }

    fn exchange(
        &self,
        request: Request,
        sink: &mut dyn ArtifactSink,
        control: &(dyn Fn() -> Result<(), Stop> + Send + Sync),
        deadline: Instant,
        flag: &Arc<std::sync::Mutex<upload::Gate>>,
    ) -> Result<Completed, ClientError> {
        control().map_err(stop_error_before_send)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(ClientError::local(FailureKind::DeadlineExceeded))?;
        let may_apply = request.may_apply_key;
        let route = request.route;
        let boundary =
            upload::boundary().map_err(|_| ClientError::local(FailureKind::Transport))?;
        let mut body = upload::Upload::new(&boundary, &request.metadata, request.parts, control);
        body.share_complete(flag.clone());
        let agent = self.agent(remaining)?;

        let mut bearer = ureq::http::HeaderValue::from_str(&format!("Bearer {}", *self.token))
            .map_err(|_| ClientError::local(FailureKind::InvalidToken))?;
        bearer.set_sensitive(true);
        let mut call = agent
            .post(self.endpoint.url(route.path()))
            .header("Authorization", bearer)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("Expect", "100-continue");
        if let Some(length) = body.length() {
            call = call.header("Content-Length", length.to_string());
        }
        let response = call.send(ureq::SendBody::from_reader(&mut body));
        // After this point `body` only reports how far the upload got.
        let unknown = |complete: bool| {
            if complete && may_apply {
                AppliedState::Unknown
            } else {
                AppliedState::NotApplied
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                return Err(classify_transport(
                    &error,
                    body.failure(),
                    body.complete(),
                    unknown(body.complete()),
                    deadline,
                ));
            }
        };
        let complete = body.complete();
        let documents = body.documents();
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_default();
        let (_, body_reader) = response.into_parts();
        let reader = body_reader.into_reader();
        let lost =
            |error: stream::StreamError| stream_error(error, status, unknown(complete), deadline);
        if status != 200 {
            let applied = unknown(complete);
            let mut error = ClientError::new(FailureKind::UnexpectedStatus, applied);
            error.status = Some(status);
            if media_type(&content_type) == "application/json"
                && let Ok(bytes) = stream::bounded_body(reader, ERROR_BODY_LIMIT, control)
                && let Ok(typed) = serde_json::from_slice::<ApiError>(&bytes)
            {
                error.kind = FailureKind::Rejected;
                // The service's own statement: it knows whether anything was applied.
                error.applied = typed.applied;
                error.server_code = Some(typed.code);
                error.server_subcode = typed.subcode().map(str::to_owned);
            }
            return Err(error);
        }
        let parsed = match (media_type(&content_type).as_str(), route) {
            ("multipart/mixed", _) => {
                let boundary = multipart_boundary(&content_type).ok_or_else(|| {
                    let mut error = ClientError::new(FailureKind::Protocol, unknown(complete));
                    error.status = Some(status);
                    error
                })?;
                stream::parse(reader, &boundary, sink, control).map_err(lost)?
            }
            ("application/json", Route::Operations) => {
                let bytes =
                    stream::bounded_body(reader, stream::MAX_FINAL_BYTES, control).map_err(lost)?;
                let record = serde_json::from_slice::<FinalRecord>(&bytes).map_err(|_| {
                    let mut error = ClientError::new(FailureKind::Protocol, unknown(complete));
                    error.status = Some(status);
                    error
                })?;
                stream::Parsed {
                    record,
                    artifacts: Vec::new(),
                    progress_frames: 0,
                }
            }
            _ => {
                let mut error = ClientError::new(FailureKind::Protocol, unknown(complete));
                error.status = Some(status);
                return Err(error);
            }
        };
        check_artifacts(&parsed, status, unknown(complete))?;
        check_lengths(&parsed, status, unknown(complete))?;
        Ok(Completed {
            record: parsed.record,
            artifacts: parsed.artifacts,
            progress_frames: parsed.progress_frames,
            document_bytes: documents,
        })
    }
}

fn stop_error_before_send(stop: Stop) -> ClientError {
    ClientError::local(match stop {
        Stop::Cancelled => FailureKind::Cancelled,
        Stop::DeadlineExceeded => FailureKind::DeadlineExceeded,
    })
}

fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn multipart_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        (!value.is_empty()
            && value.len() <= 70
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b)))
        .then(|| value.to_owned())
    })
}

fn stream_error(
    error: stream::StreamError,
    status: u16,
    applied: AppliedState,
    deadline: Instant,
) -> ClientError {
    let mut detail = None;
    let kind = match error {
        stream::StreamError::Stop(Stop::Cancelled) => FailureKind::Cancelled,
        stream::StreamError::Stop(Stop::DeadlineExceeded) => FailureKind::DeadlineExceeded,
        stream::StreamError::Lost if Instant::now() >= deadline => FailureKind::DeadlineExceeded,
        stream::StreamError::Lost => FailureKind::ResponseLost,
        stream::StreamError::Protocol(message) => {
            detail = Some(message);
            FailureKind::Protocol
        }
        stream::StreamError::Sink => FailureKind::Artifact,
    };
    let mut error = ClientError::new(kind, applied);
    error.status = Some(status);
    error.detail = detail;
    error
}

fn classify_transport(
    error: &ureq::Error,
    failure: Option<upload::UploadFailure>,
    complete: bool,
    unknown: AppliedState,
    deadline: Instant,
) -> ClientError {
    // The writer knows exactly why it stopped; ureq's text is never consulted for that.
    if let Some(failure) = failure {
        let kind = match failure {
            upload::UploadFailure::Stop(Stop::Cancelled) => FailureKind::Cancelled,
            upload::UploadFailure::Stop(Stop::DeadlineExceeded) => FailureKind::DeadlineExceeded,
            upload::UploadFailure::Source => FailureKind::SourceUnavailable,
        };
        return ClientError::new(kind, AppliedState::NotApplied);
    }
    let kind = match error {
        ureq::Error::Timeout(_) => FailureKind::DeadlineExceeded,
        _ if Instant::now() >= deadline => FailureKind::DeadlineExceeded,
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => FailureKind::Connect,
        ureq::Error::Io(io) if !complete && is_connect(io) => FailureKind::Connect,
        // rustls surfaces certificate and handshake failures as `InvalidData` io errors.
        ureq::Error::Io(io) if !complete && is_tls(io) => FailureKind::Tls,
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) | ureq::Error::TlsRequired => FailureKind::Tls,
        ureq::Error::BadUri(_) | ureq::Error::Http(_) => FailureKind::InvalidRequest,
        _ => FailureKind::Transport,
    };
    let applied = match kind {
        FailureKind::Connect | FailureKind::Tls | FailureKind::InvalidRequest => {
            AppliedState::NotApplied
        }
        _ => unknown,
    };
    ClientError::new(kind, applied)
}

fn is_tls(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::InvalidData
        && error.get_ref().is_some_and(|inner| {
            let text = format!("{inner:?}");
            [
                "InvalidCertificate",
                "AlertReceived",
                "PeerIncompatible",
                "PeerMisbehaved",
                "NoCertificatesPresented",
            ]
            .iter()
            .any(|needle| text.contains(needle))
        })
}

fn is_connect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    )
}

/// The record and the received artifacts must describe the same outputs.
fn check_artifacts(
    parsed: &stream::Parsed,
    status: u16,
    applied: AppliedState,
) -> Result<(), ClientError> {
    let violation = || {
        let mut error = ClientError::new(FailureKind::Protocol, applied);
        error.status = Some(status);
        error
    };
    let named = parsed.record.artifact_ids();
    let mut seen = std::collections::BTreeSet::new();
    for id in &named {
        if !seen.insert(*id) || !parsed.artifacts.iter().any(|a| a.content_id == *id) {
            return Err(violation());
        }
    }
    // A failed single-operation record withholds artifacts; anything else must not carry an
    // output no result names.
    let failed = matches!(
        &parsed.record,
        FinalRecord::Final {
            status: crate::dto::FinalStatus::Failed,
            ..
        }
    );
    if !failed && parsed.artifacts.len() != named.len() {
        return Err(violation());
    }
    Ok(())
}

/// Every artifact length the final record states exactly must equal the received length:
/// a well-framed part of the wrong size is an integrity failure, never a result.
fn check_lengths(
    parsed: &stream::Parsed,
    status: u16,
    applied: AppliedState,
) -> Result<(), ClientError> {
    for (id, stated) in parsed.record.artifact_expectations() {
        let received = parsed
            .artifacts
            .iter()
            .find(|artifact| artifact.content_id == id)
            .map(|artifact| artifact.length);
        if stated.is_some() && stated != received {
            let mut error = ClientError::new(FailureKind::Protocol, applied);
            error.status = Some(status);
            error.detail = Some("artifact length differs from the final record");
            return Err(error);
        }
    }
    Ok(())
}
