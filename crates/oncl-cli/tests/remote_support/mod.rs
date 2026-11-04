//! Real in-process `oncl-server` on loopback, a fresh-time synthetic PKI, a raw TCP fault
//! proxy and oracles for the remote CLI tests. The CLI under test is always the real `oncl`
//! process; every certificate and key is a committed synthetic fixture or ephemeral.
#![allow(dead_code)]
use der::Encode;
use oncl_pki::{
    crl::MockCrl,
    http::{GetOptions, HttpRequest, HttpTransport},
    ocsp::MockOcsp,
    pkcs12::KeyEntry,
    private_fs::PrivateDirectory,
    testing::{TestCertSpec, issue_cert},
};
use oncl_server::{
    auth::TokenSecret,
    config::{
        Exposure, KeyConfig, Permission, PkiConfig, PkiEndpoint, SecretMount, ServerConfig,
        TokenConfig, TsaConfig,
    },
    service::{ServiceHost, serve, tls_configuration},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

pub const KEY_PASSWORD: &str = "remote-inline-container-password-7c1d";

pub fn raw(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn uris(input: &[u8], url: &[u8]) -> Vec<u8> {
    use der::{Decode, Reader, SliceReader};
    let any = der::asn1::AnyRef::from_der(input).unwrap();
    let tag = input[0];
    let body = if tag == 0x86 {
        url.to_vec()
    } else if tag & 0x20 != 0 {
        let mut reader = SliceReader::new(any.value()).unwrap();
        let mut body = vec![];
        while !reader.is_finished() {
            body.extend(uris(reader.tlv_bytes().unwrap(), url));
        }
        body
    } else {
        any.value().to_vec()
    };
    let mut result = vec![tag];
    if body.len() < 128 {
        result.push(body.len() as u8);
    } else {
        let bytes: Vec<_> = body
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        result.push(0x80 | bytes.len() as u8);
        result.extend(bytes);
    }
    result.extend(body);
    result
}
fn locate(spec: &mut TestCertSpec, origin: &str, crl: &str) {
    for ext in &mut spec.extensions {
        let path = match ext.extn_id.to_string().as_str() {
            "1.3.6.1.5.5.7.1.1" => Some("/ocsp".to_owned()),
            "2.5.29.31" => Some(format!("/{crl}.crl")),
            _ => None,
        };
        if let Some(path) = path {
            ext.extn_value = der::asn1::OctetString::new(uris(
                ext.extn_value.as_bytes(),
                format!("{origin}{path}").as_bytes(),
            ))
            .unwrap();
        }
    }
}
fn with_status_locations(entry: &KeyEntry, issuer: &KeyEntry, origin: &str, crl: &str) -> KeyEntry {
    let mut entry = entry.clone();
    let mut spec = TestCertSpec::from_cert(&entry.cert);
    let template = TestCertSpec::from_cert(&raw("inter-user-gost2015-sign").cert);
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
    spec.extensions
        .extend(template.extensions.into_iter().filter(|e| {
            matches!(
                e.extn_id.to_string().as_str(),
                "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
            )
        }));
    locate(&mut spec, origin, crl);
    entry.cert = issue_cert(issuer, spec);
    entry
}
pub fn container(entry: &KeyEntry, password: &str) -> Vec<u8> {
    oncl_pki::pkcs12::write(
        &[oncl_pki::pkcs12::WriteEntry {
            alias: entry.alias.clone(),
            pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(entry.cert.to_der().unwrap()),
        }],
        &[],
        password,
        &oncl_pki::pkcs12::WriteOptions::default(),
        &mut |bytes| bytes.fill(0x62),
    )
    .unwrap()
}

/// Releases only when the test says so: no sleep decides any semantics.
#[derive(Default)]
pub struct Gate {
    held: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
    entered: AtomicUsize,
}
impl Gate {
    pub fn pass(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut held = self.held.lock().unwrap();
        let started = std::time::Instant::now();
        // 60 s is only a leak guard for a failed test, never a semantic delay.
        while *held && started.elapsed() < Duration::from_secs(60) {
            held = self
                .changed
                .wait_timeout(held, Duration::from_millis(100))
                .unwrap()
                .0;
        }
    }
    pub fn hold(&self) {
        *self.held.lock().unwrap() = true;
    }
    pub fn release(&self) {
        *self.held.lock().unwrap() = false;
        self.changed.notify_all();
    }
    pub fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }
    /// A real barrier: waits until `n` requests are inside the gate.
    pub fn wait_entered(&self, n: usize) {
        let started = std::time::Instant::now();
        while self.entered() < n {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "no request reached the gate"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Loopback OCSP/CRL/TSA responder whose answers are fresh at the real time.
pub struct Pki {
    pub address: SocketAddr,
    pub origin: String,
    pub root: KeyEntry,
    pub inter: KeyEntry,
    pub tsa_gate: Arc<Gate>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    pub requests: Arc<AtomicUsize>,
}
impl Pki {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let now = time::OffsetDateTime::now_utc();
        let root = raw("root-gost2015.key");
        let inter = with_status_locations(&raw("inter-gost2015.key"), &root, &origin, "root");
        let ocsp = Arc::new(MockOcsp::new(raw("ocsp-gost2015")).with_now(now));
        let tsa = Arc::new(
            oncl_pki::tsp::MockTsa::new(with_status_locations(
                &raw("tsa-gost2015"),
                &root,
                &origin,
                "root",
            ))
            .with_gen_time(now),
        );
        let root_crl = Arc::new(
            MockCrl::new(root.clone())
                .with_this_update(now - time::Duration::MINUTE)
                .next_update(Some(now + time::Duration::days(1))),
        );
        let inter_crl = Arc::new(
            MockCrl::new(inter.clone())
                .with_this_update(now - time::Duration::MINUTE)
                .next_update(Some(now + time::Duration::days(1))),
        );
        let tsa_gate = Arc::new(Gate::default());
        let gate = tsa_gate.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let (stopped, counted) = (stop.clone(), requests.clone());
        let url_origin = origin.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                };
                let (ocsp, root_crl, inter_crl, tsa) = (
                    ocsp.clone(),
                    root_crl.clone(),
                    inter_crl.clone(),
                    tsa.clone(),
                );
                let (url_origin, counted, gate) =
                    (url_origin.clone(), counted.clone(), gate.clone());
                std::thread::spawn(move || {
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut chunk = [0; 4096];
                    let end = loop {
                        let n = socket.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break None;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                        if let Some(p) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(p + 4);
                        }
                    };
                    let Some(end) = end else { return };
                    let head = String::from_utf8_lossy(&bytes[..end]).into_owned();
                    let length = head
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while bytes.len() < end + length {
                        let n = socket.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                    }
                    counted.fetch_add(1, Ordering::SeqCst);
                    let mut first = head.lines().next().unwrap().split_whitespace();
                    let method = first.next().unwrap();
                    let path = first.next().unwrap();
                    let url = format!("{url_origin}{path}");
                    let content_type = head
                        .lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.trim().to_owned());
                    let reply = if method == "POST" && path == "/tsa" {
                        gate.pass();
                        tsa.send(&HttpRequest::post(
                            &url,
                            content_type.as_deref(),
                            &bytes[end..end + length],
                            GetOptions::default(),
                        ))
                    } else if method == "POST" {
                        ocsp.send(&HttpRequest::post(
                            &url,
                            content_type.as_deref(),
                            &bytes[end..end + length],
                            GetOptions::default(),
                        ))
                    } else if path.contains("root") {
                        root_crl.send(&HttpRequest::get(&url, GetOptions::default()))
                    } else {
                        inter_crl.send(&HttpRequest::get(&url, GetOptions::default()))
                    };
                    if let Ok(reply) = reply {
                        let _ = write!(
                            socket,
                            "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            reply.status,
                            reply
                                .content_type
                                .as_deref()
                                .unwrap_or("application/octet-stream"),
                            reply.body.len()
                        );
                        let _ = socket.write_all(&reply.body);
                    }
                });
            }
        });
        Self {
            address,
            origin,
            root,
            inter,
            tsa_gate,
            stop,
            thread: Some(thread),
            requests,
        }
    }
    /// A synthetic leaf issued by the loopback-located intermediate.
    pub fn leaf(&self, name: &str) -> KeyEntry {
        with_status_locations(&raw(name), &self.inter, &self.origin, "inter")
    }
    pub fn config(&self, directory: &Path) -> PkiConfig {
        let inter = directory.join("inter.cer");
        std::fs::write(&inter, self.inter.cert.to_der().unwrap()).unwrap();
        PkiConfig {
            anchors: vec![oncl_testkit::fixture("synthetic/root-gost2015.cer")],
            intermediates: vec![inter],
            endpoints: vec![PkiEndpoint {
                origin: self.origin.clone(),
                addresses: vec![self.address],
            }],
            tsa: Some(TsaConfig {
                url: format!("{}/tsa", self.origin),
                policy: Some("1.2.3.4.5".into()),
                timeout_ms: 10_000,
                skew_ms: 300_000,
            }),
            ..PkiConfig::default()
        }
    }
    /// The trust material of a local `oncl` verifying against the same loopback PKI.
    pub fn local_trust(&self, directory: &Path) -> Vec<String> {
        let inter = directory.join("inter.cer");
        std::fs::write(&inter, self.inter.cert.to_der().unwrap()).unwrap();
        vec![
            "--root".into(),
            oncl_testkit::fixture("synthetic/root-gost2015.cer")
                .to_str()
                .unwrap()
                .into(),
            "--intermediate".into(),
            inter.to_str().unwrap().into(),
            "--pki-endpoint".into(),
            self.origin.clone(),
        ]
    }
}
impl Drop for Pki {
    fn drop(&mut self) {
        self.tsa_gate.release();
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A named operator key: the container and its password live in the operator's private
/// directory on the *server* side and are never visible to the client.
pub fn named_key(
    config: &mut ServerConfig,
    directory: &Path,
    pki: &Pki,
    name: &str,
    fixture: &str,
) {
    let operator = directory.join("operator");
    let private = if operator.exists() {
        PrivateDirectory::open(&operator).unwrap()
    } else {
        PrivateDirectory::create(&operator).unwrap()
    };
    let entry = pki.leaf(fixture);
    let password = "operator-held-password";
    private
        .create_file(&format!("{name}.p12"))
        .unwrap()
        .write_all(&container(&entry, password))
        .unwrap();
    private
        .create_file(&format!("{name}.pw"))
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    config.keys.push(KeyConfig::File {
        name: name.into(),
        path: operator.join(format!("{name}.p12")),
        alias: Some(entry.alias.clone()),
        secret: SecretMount {
            directory: operator,
            name: format!("{name}.pw"),
        },
    });
}

pub struct Remote {
    pub address: SocketAddr,
    /// The bearer token; tests assert it never appears in any process output.
    pub token: String,
    /// Owner-only directory holding the token file (the client's secret input).
    pub token_file: PathBuf,
    /// The server's private world: operator namespace, scratch and audit. This is NOT
    /// the client's directory.
    pub server_dir: tempfile::TempDir,
    pub host: Arc<ServiceHost>,
    pub tls: bool,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

pub fn all_rights() -> Vec<Permission> {
    vec![
        Permission::Hash,
        Permission::Sign,
        Permission::Verify,
        Permission::Extract,
        Permission::Extend,
        Permission::Inspect,
        Permission::Stamp,
        Permission::VerifyStamp,
        Permission::Batch,
    ]
}

impl Remote {
    /// A full-rights token, the named key `ops-key` (RSA) and the inline right.
    pub fn start(pki: &Pki) -> Self {
        Self::start_with(pki, |_, _| {})
    }
    pub fn start_with(pki: &Pki, configure: impl FnOnce(&mut ServerConfig, &Path)) -> Self {
        Self::launch(pki, None, configure)
    }
    /// HTTPS with the supplied certificate (PEM chain) and key (PEM).
    pub fn start_tls(
        pki: &Pki,
        certificate_pem: &str,
        key_pem: &str,
        configure: impl FnOnce(&mut ServerConfig, &Path),
    ) -> Self {
        Self::launch(pki, Some((certificate_pem, key_pem)), configure)
    }
    fn launch(
        pki: &Pki,
        tls: Option<(&str, &str)>,
        configure: impl FnOnce(&mut ServerConfig, &Path),
    ) -> Self {
        let server_dir = tempfile::tempdir().unwrap();
        let std_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let address = std_listener.local_addr().unwrap();
        let secret = TokenSecret::generate().unwrap();
        let mut config = ServerConfig {
            enabled: true,
            audit_directory: server_dir.path().join("audit"),
            scratch_directory: server_dir.path().join("scratch"),
            metadata_bytes: 67_108_864,
            inline_pkcs12: true,
            memory_per_operation: 1 << 30,
            total_memory: 2 << 30,
            ..ServerConfig::default()
        };
        config.tokens.push(TokenConfig {
            id: "client".into(),
            verifier: secret.verifier().encoded(),
            actions: all_rights(),
            keys: vec!["ops-key".into()],
            inline_pkcs12: true,
            metadata_aliases: vec![pki.leaf("user-rsa-sign").alias],
        });
        config.pki = pki.config(server_dir.path());
        named_key(
            &mut config,
            server_dir.path(),
            pki,
            "ops-key",
            "user-rsa-sign",
        );
        if let Some((certificate, key)) = tls {
            let certificate_path = server_dir.path().join("server.crt");
            std::fs::write(&certificate_path, certificate).unwrap();
            let secrets = server_dir.path().join("tls");
            let private = PrivateDirectory::create(&secrets).unwrap();
            private
                .create_file("server.key")
                .unwrap()
                .write_all(key.as_bytes())
                .unwrap();
            config.exposure = Exposure::Tls {
                certificate: certificate_path,
                private_key: SecretMount {
                    directory: secrets,
                    name: "server.key".into(),
                },
            };
            config.hosts = vec![address.to_string()];
        }
        configure(&mut config, server_dir.path());
        let acceptor = tls_configuration(&config).unwrap();
        let host = ServiceHost::new(config)
            .unwrap()
            .for_listener(address)
            .unwrap();
        let (shutdown, stop) = tokio::sync::oneshot::channel::<()>();
        let served = host.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
                ready_tx.send(()).unwrap();
                let _ = serve(listener, served, acceptor, async {
                    let _ = stop.await;
                })
                .await;
            });
        });
        ready_rx.recv().unwrap();
        // The client's secret input: the token in an owner-only directory.
        let operator = server_dir.path().join("client-side");
        let private = PrivateDirectory::create(&operator).unwrap();
        let bearer = secret.bearer();
        private
            .create_file("client.token")
            .unwrap()
            .write_all(bearer.as_bytes())
            .unwrap();
        Self {
            address,
            token: bearer.to_string(),
            token_file: operator.join("client.token"),
            server_dir,
            host,
            tls: tls.is_some(),
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }
    pub fn endpoint(&self) -> String {
        format!(
            "{}://{}",
            if self.tls { "https" } else { "http" },
            self.address
        )
    }
    pub fn scratch(&self) -> PathBuf {
        self.server_dir.path().join("scratch")
    }
    pub fn audit_begins(&self) -> usize {
        self.host
            .audit
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.kind == oncl_server::audit::RecordKind::Begin)
            .count()
    }
    pub fn audit_finals(&self) -> usize {
        self.host
            .audit
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.kind == oncl_server::audit::RecordKind::Final)
            .count()
    }
}
impl Drop for Remote {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ---- raw TCP fault proxy ------------------------------------------------------------

/// Where, in the decoded `multipart/mixed` response, the proxy intervenes.
#[derive(Clone, Copy, Debug)]
pub enum Spot {
    /// Relay everything.
    Nowhere,
    /// Right before the delimiter of the first part with this name.
    BeforePart(&'static str),
    /// In the middle of the body of the first part with this name.
    MidPart(&'static str),
    /// After the body (and CRLF) of the first part with this name.
    AfterPart(&'static str),
    /// In the middle of the closing delimiter.
    MidClosing,
}
#[derive(Clone, Copy, Debug)]
pub enum End {
    /// Drop the connection without the HTTP terminal chunk.
    Abort,
    /// Finish the HTTP entity cleanly (a polite intermediary that lost the rest).
    Clean,
}
#[derive(Clone, Copy, Debug)]
pub struct Fault {
    pub spot: Spot,
    pub end: End,
}

pub struct Proxy {
    pub address: SocketAddr,
    pub connections: Arc<AtomicUsize>,
    pub requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Proxy {
    pub fn start(upstream: SocketAddr, fault: Fault) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (stopping, counted, posts) = (stop.clone(), connections.clone(), requests.clone());
        let thread = std::thread::spawn(move || {
            let mut handlers = Vec::new();
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _)) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let posts = posts.clone();
                        handlers.push(std::thread::spawn(move || {
                            let _ = relay(client, upstream, fault, posts);
                        }));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
            for handler in handlers {
                let _ = handler.join();
            }
        });
        Self {
            address,
            connections,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack[from.min(haystack.len())..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn relay(
    mut client: TcpStream,
    upstream: SocketAddr,
    fault: Fault,
    requests: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    client.set_nonblocking(false)?;
    let mut server = TcpStream::connect(upstream)?;
    // Client -> server: relayed untouched, in its own thread. Only the Host header names
    // the proxy; the server requires its own authority, so that one header is rewritten.
    let (mut from, mut to) = (client.try_clone()?, server.try_clone()?);
    let authority = upstream.to_string();
    let uploader = std::thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        let mut head = Vec::new();
        let mut forwarding = false;
        loop {
            match from.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut chunk = buffer[..n].to_vec();
                    if !forwarding {
                        head.extend_from_slice(&chunk);
                        let Some(end) = find(&head, b"\r\n\r\n", 0) else {
                            continue;
                        };
                        forwarding = true;
                        let text = String::from_utf8_lossy(&head[..end]).into_owned();
                        let mut rewritten = String::new();
                        for (index, line) in text.split("\r\n").enumerate() {
                            if index > 0 {
                                rewritten.push_str("\r\n");
                            }
                            if line.to_ascii_lowercase().starts_with("host:") {
                                rewritten.push_str(&format!("Host: {authority}"));
                            } else {
                                rewritten.push_str(line);
                            }
                        }
                        if rewritten.starts_with("POST ") {
                            requests.fetch_add(1, Ordering::SeqCst);
                        }
                        chunk = rewritten.into_bytes();
                        chunk.extend_from_slice(&head[end..]);
                    }
                    if to.write_all(&chunk).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown(std::net::Shutdown::Write);
    });
    let result = respond(&mut client, &mut server, fault);
    // Closing the sockets also ends the uploader thread.
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = server.shutdown(std::net::Shutdown::Both);
    let _ = uploader.join();
    result
}

/// Server -> client. The whole response is read and decoded first (responses are small in
/// tests), so the fault lands at an exact multipart position.
fn respond(client: &mut TcpStream, server: &mut TcpStream, fault: Fault) -> std::io::Result<()> {
    server.set_read_timeout(Some(Duration::from_secs(90)))?;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    let head_end = loop {
        let n = server.read(&mut buffer)?;
        if n == 0 {
            return client.write_all(&raw);
        }
        raw.extend_from_slice(&buffer[..n]);
        if let Some(p) = find(&raw, b"\r\n\r\n", 0) {
            if raw.starts_with(b"HTTP/1.1 100") {
                // The interim `100 Continue` of an `Expect` request is relayed as it is.
                client.write_all(&raw[..p + 4])?;
                raw.drain(..p + 4);
                if let Some(p) = find(&raw, b"\r\n\r\n", 0) {
                    break p + 4;
                }
                continue;
            }
            break p + 4;
        }
    };
    let head_text = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let head = head_text.to_ascii_lowercase();
    let chunked = head.contains("transfer-encoding: chunked");
    let boundary = head_text
        .split("boundary=")
        .nth(1)
        .and_then(|rest| rest.split(['\r', ';']).next())
        .map(|b| b.trim_matches('"').to_owned());
    if !chunked {
        // Content-Length (or close-delimited) responses are typed errors or JSON records.
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok());
        match length {
            Some(length) => {
                while raw.len() < head_end + length {
                    let n = server.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..n]);
                }
                return client.write_all(&raw);
            }
            None => {
                client.write_all(&raw)?;
                loop {
                    match server.read(&mut buffer) {
                        Ok(0) | Err(_) => return Ok(()),
                        Ok(n) => client.write_all(&buffer[..n])?,
                    }
                }
            }
        }
    }
    // Decode chunks until the terminal chunk.
    let mut decoded = Vec::new();
    let mut at = head_end;
    loop {
        let line_end = loop {
            if let Some(p) = find(&raw, b"\r\n", at) {
                break p;
            }
            let n = server.read(&mut buffer)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            raw.extend_from_slice(&buffer[..n]);
        };
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[at..line_end]).unwrap().trim(), 16)
                .unwrap();
        let data_start = line_end + 2;
        while raw.len() < data_start + size + 2 {
            let n = server.read(&mut buffer)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            raw.extend_from_slice(&buffer[..n]);
        }
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&raw[data_start..data_start + size]);
        at = data_start + size + 2;
    }
    let passthrough = matches!(fault.spot, Spot::Nowhere) && matches!(fault.end, End::Clean);
    let (Some(boundary), false) = (boundary, passthrough) else {
        // Untouched: the original bytes, including the terminal chunk.
        return client.write_all(&raw[..at + 5]);
    };
    let delimiter = format!("--{boundary}\r\n").into_bytes();
    let part = |name: &str| -> Option<(usize, usize, usize)> {
        // (start of the delimiter, start of the body, end of the body)
        let mut from = 0;
        while let Some(start) = find(&decoded, &delimiter, from) {
            let header_end = find(&decoded, b"\r\n\r\n", start)? + 4;
            let header = String::from_utf8_lossy(&decoded[start..header_end]);
            if header.contains(&format!("name=\"{name}\"")) {
                let length = header
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())?;
                return Some((start, header_end, header_end + length));
            }
            from = start + delimiter.len();
        }
        None
    };
    let cut = match fault.spot {
        Spot::Nowhere => decoded.len(),
        Spot::BeforePart(name) => part(name).expect("part present").0,
        Spot::MidPart(name) => {
            let (_, body, end) = part(name).expect("part present");
            body + (end - body) / 2
        }
        Spot::AfterPart(name) => part(name).expect("part present").2 + 2,
        Spot::MidClosing => {
            find(&decoded, format!("--{boundary}--").as_bytes(), 0).expect("closing") + 5
        }
    };
    client.write_all(&raw[..head_end])?;
    if cut > 0 {
        write!(client, "{cut:x}\r\n")?;
        client.write_all(&decoded[..cut])?;
        client.write_all(b"\r\n")?;
    }
    if matches!(fault.end, End::Clean) {
        client.write_all(b"0\r\n\r\n")?;
    }
    client.flush()
}

// ---- process helpers -----------------------------------------------------------------

/// Run the real `oncl` binary. The token must never be in argv.
pub fn oncl(args: &[&str], stdin: &[u8], secrets: &[&str], cwd: Option<&Path>) -> Output {
    for argument in args {
        for secret in secrets {
            assert!(!argument.contains(secret), "argv carries a secret value");
        }
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_oncl"));
    command
        .args(args)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        // An ambient proxy must never see a remote session.
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().unwrap();
    if let Some(mut handle) = child.stdin.take() {
        let _ = handle.write_all(stdin);
    }
    let output = child.wait_with_output().unwrap();
    for secret in secrets {
        for (name, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{name} contains a secret value"
            );
        }
    }
    output
}
pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
pub fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Independent oracle: OpenSSL CMS signature verification (embedded signer certificate, no
/// chain: the synthetic chain uses GOST CAs OpenSSL cannot validate).
pub fn openssl_cms_verify(signature: &[u8], content: Option<&[u8]>, dir: &Path) -> Option<Vec<u8>> {
    let sig = dir.join("oracle.p7s");
    std::fs::write(&sig, signature).unwrap();
    let out = dir.join("oracle.out");
    let _ = std::fs::remove_file(&out);
    let mut command = Command::new(openssl_command());
    command
        .args([
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-noverify",
            "-binary",
            "-in",
        ])
        .arg(&sig)
        .arg("-out")
        .arg(&out);
    if let Some(content) = content {
        let detached = dir.join("oracle.content");
        std::fs::write(&detached, content).unwrap();
        command.arg("-content").arg(detached);
    }
    let result = command.output().unwrap();
    result
        .status
        .success()
        .then(|| std::fs::read(&out).unwrap())
}
/// OpenSSL's SHA-256 of `bytes`, lowercase hex.
pub fn openssl_sha256(bytes: &[u8], dir: &Path) -> String {
    let file = dir.join("oracle.sha");
    std::fs::write(&file, bytes).unwrap();
    let out = Command::new(openssl_command())
        .args(["dgst", "-sha256", "-r"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(out.status.success());
    text(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}
pub fn openssl_command() -> String {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(explicit) = std::env::var("ONCL_OPENSSL") {
        candidates.push(explicit);
    }
    candidates.push("openssl".to_owned());
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432"] {
            if let Some(base) = std::env::var_os(var) {
                let git = Path::new(&base).join("Git/usr/bin/openssl.exe");
                candidates.push(git.to_string_lossy().into_owned());
            }
        }
    }
    candidates
        .into_iter()
        .find(|c| {
            Command::new(c)
                .arg("version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .expect("OpenSSL oracle unavailable: install OpenSSL or set ONCL_OPENSSL to its executable")
}
/// Files of a directory tree, for "nothing was left behind" assertions.
pub fn files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                out.extend(files(&entry.path()));
            } else {
                out.push(entry.path());
            }
        }
    }
    out
}
