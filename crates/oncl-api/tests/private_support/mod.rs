//! Real-socket harness for private operations: a loopback OCSP/CRL responder
//! backed by signed synthetic mocks, operator trust configuration, a strict
//! Engine, and independent OpenSSL oracles. No request-controlled authority.
#![allow(dead_code)]
use der::Encode;
use oncl_pki::{
    crl::MockCrl,
    http::{GetOptions, HttpRequest, HttpTransport},
    ocsp::MockOcsp,
    pkcs12::KeyEntry,
    testing::{TestCertSpec, issue_cert},
};
use oncl_server::{
    auth::TokenSecret,
    config::{
        KeyConfig, Permission, PkiConfig, PkiEndpoint, SecretMount, ServerConfig, TokenConfig,
    },
    service::{ServiceHost, serve},
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

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
/// Rewrite the OCSP/CRL locations of `spec` to the loopback responder.
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
/// Public-fixture PKCS#12 repackage of the issued leaf (synthetic key only).
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

pub struct Pki {
    pub address: std::net::SocketAddr,
    pub origin: String,
    pub inter: KeyEntry,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    pub requests: Arc<AtomicUsize>,
}
impl Pki {
    pub fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let now = time::OffsetDateTime::now_utc();
        let inter = with_status_locations(
            &raw("inter-gost2015.key"),
            &raw("root-gost2015.key"),
            &origin,
            "root",
        );
        let ocsp = MockOcsp::new(raw("ocsp-gost2015")).with_now(now);
        let tsa = oncl_pki::tsp::MockTsa::new(with_status_locations(
            &raw("tsa-gost2015"),
            &raw("root-gost2015.key"),
            &origin,
            "root",
        ))
        .with_gen_time(now);
        let root = MockCrl::new(raw("root-gost2015.key"))
            .with_this_update(now - time::Duration::MINUTE)
            .next_update(Some(now + time::Duration::days(1)));
        let inter_crl = MockCrl::new(inter.clone())
            .with_this_update(now - time::Duration::MINUTE)
            .next_update(Some(now + time::Duration::days(1)));
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
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
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
                let Some(end) = end else { continue };
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
                    root.send(&HttpRequest::get(&url, GetOptions::default()))
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
            }
        });
        Self {
            address,
            origin,
            inter,
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
            tsa: Some(oncl_server::config::TsaConfig {
                url: format!("{}/tsa", self.origin),
                policy: None,
                timeout_ms: 10_000,
                skew_ms: 300_000,
            }),
            ..PkiConfig::default()
        }
    }
}
impl Drop for Pki {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub struct Running {
    pub address: std::net::SocketAddr,
    pub token: zeroize::Zeroizing<String>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    pub directory: tempfile::TempDir,
    pub host: Arc<ServiceHost>,
}
impl Running {
    pub async fn start_with(configure: impl FnOnce(&mut ServerConfig, &Path)) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let secret = TokenSecret::generate().unwrap();
        let mut config = ServerConfig {
            enabled: true,
            audit_directory: directory.path().join("audit"),
            scratch_directory: directory.path().join("scratch"),
            metadata_bytes: 67_108_864,
            ..ServerConfig::default()
        };
        config.tokens.push(TokenConfig {
            id: "test".into(),
            verifier: secret.verifier().encoded(),
            actions: vec![Permission::Sign],
            keys: vec![],
            inline_pkcs12: false,
            metadata_aliases: vec![],
        });
        configure(&mut config, directory.path());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host = ServiceHost::new(config)
            .unwrap()
            .for_listener(address)
            .unwrap();
        let (shutdown, stop) = tokio::sync::oneshot::channel();
        let h = host.clone();
        let task = tokio::spawn(async move {
            serve(listener, h, None, async {
                let _ = stop.await;
            })
            .await
        });
        Self {
            address,
            token: secret.bearer(),
            task,
            shutdown,
            directory,
            host,
        }
    }
    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        self.task.await.unwrap().unwrap();
    }
    pub fn scratch(&self) -> PathBuf {
        self.directory.path().join("scratch")
    }
    /// One real HTTP/1.1 request; returns status, content type and full body.
    pub async fn post(&self, content_type: &str, body: Vec<u8>) -> (u16, String, Vec<u8>) {
        use http_body_util::{BodyExt, Full};
        let stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = hyper::Request::builder()
            .method("POST")
            .uri("/v1/operations")
            .header("host", self.address.to_string())
            .header("authorization", format!("Bearer {}", self.token.as_str()))
            .header("content-type", content_type)
            .body(Full::new(axum::body::Bytes::from(body)))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, content_type, bytes.to_vec())
    }
}

pub struct Part<'a> {
    pub name: &'a str,
    pub filename: Option<&'a str>,
    pub bytes: &'a [u8],
}
pub fn multipart(metadata: &str, parts: &[Part<'_>]) -> Vec<u8> {
    let mut body =
        format!("--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n")
            .into_bytes();
    for part in parts {
        let file = part
            .filename
            .map(|f| format!("; filename=\"{f}\""))
            .unwrap_or_default();
        body.extend_from_slice(
            format!(
                "--b\r\nContent-Disposition: form-data; name=\"{}\"{file}\r\n\r\n",
                part.name
            )
            .as_bytes(),
        );
        body.extend_from_slice(part.bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--b--\r\n");
    body
}
pub const FORM: &str = "multipart/form-data; boundary=b";

/// Parsed multipart/mixed response: (name, content-id, bytes) in wire order.
pub async fn mixed(content_type: &str, body: Vec<u8>) -> Vec<(String, Option<String>, Vec<u8>)> {
    let media: mime::Mime = content_type.parse().unwrap();
    assert_eq!(media.type_(), mime::MULTIPART);
    assert_eq!(media.subtype().as_str(), "mixed");
    let boundary = media.get_param(mime::BOUNDARY).unwrap().as_str().to_owned();
    let source = futures_util::stream::once(async move {
        Ok::<_, std::io::Error>(axum::body::Bytes::from(body))
    });
    let mut parser = multer::Multipart::new(source, boundary);
    let mut parts = Vec::new();
    while let Some(field) = parser.next_field().await.unwrap() {
        let name = field.name().unwrap().to_owned();
        let id = field
            .headers()
            .get("content-id")
            .map(|v| v.to_str().unwrap().to_owned());
        parts.push((name, id, field.bytes().await.unwrap().to_vec()));
    }
    parts
}
pub fn final_event(parts: &[(String, Option<String>, Vec<u8>)]) -> serde_json::Value {
    let (name, _, bytes) = parts.last().expect("mandatory terminal part");
    assert_eq!(name, "final", "last part must be the terminal record");
    serde_json::from_slice(bytes).unwrap()
}
pub fn artifact<'a>(parts: &'a [(String, Option<String>, Vec<u8>)], id: &str) -> &'a [u8] {
    parts
        .iter()
        .find(|(n, i, _)| n == "artifact" && i.as_deref() == Some(id))
        .map(|(_, _, b)| b.as_slice())
        .expect("artifact part")
}

/// Independent oracle: OpenSSL CMS signature verification (embedded signer cert,
/// no chain: the synthetic chain uses GOST CAs OpenSSL cannot validate).
pub fn openssl_cms_verify(signature: &[u8], content: Option<&[u8]>, dir: &Path) -> Option<Vec<u8>> {
    let sig = dir.join("oracle.p7s");
    std::fs::write(&sig, signature).unwrap();
    let out = dir.join("oracle.out");
    let _ = std::fs::remove_file(&out);
    let mut command = std::process::Command::new("openssl");
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
    let status = command.output().unwrap();
    if status.status.success() {
        Some(std::fs::read(&out).unwrap())
    } else {
        None
    }
}

pub fn spool_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let kind = entry.file_type().unwrap();
            if kind.is_file() {
                files.push(entry.path());
            } else if kind.is_dir() {
                files.extend(spool_files(&entry.path()));
            }
        }
    }
    files
}
/// Watch every scratch file while an operation runs; true if `needle` ever hit.
pub struct SpoolWatch {
    stop: Arc<AtomicBool>,
    hit: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl SpoolWatch {
    pub fn start(root: PathBuf, needles: Vec<Vec<u8>>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let hit = Arc::new(AtomicBool::new(false));
        let (s, h) = (stop.clone(), hit.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                for file in spool_files(&root) {
                    if let Ok(bytes) = std::fs::read(&file) {
                        for needle in &needles {
                            if bytes.windows(needle.len()).any(|w| w == needle.as_slice()) {
                                h.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        Self {
            stop,
            hit,
            thread: Some(thread),
        }
    }
    pub fn finish(mut self) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        self.hit.load(Ordering::SeqCst)
    }
}
pub fn named_key(
    config: &mut ServerConfig,
    directory: &Path,
    pki: &Pki,
    name: &str,
    fixture: &str,
) {
    let operator = directory.join("operator");
    let private = if operator.exists() {
        oncl_pki::private_fs::PrivateDirectory::open(&operator).unwrap()
    } else {
        oncl_pki::private_fs::PrivateDirectory::create(&operator).unwrap()
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
