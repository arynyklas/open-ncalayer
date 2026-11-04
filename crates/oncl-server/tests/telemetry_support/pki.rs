//! Loopback OCSP/CRL/TSA responder backed by signed synthetic mocks, copied verbatim
//! from `crates/oncl-api/tests/private_support` (same harness, trimmed to the PKI part)
//! so strict-online signing works in oncl-server tests.
#![allow(dead_code, unused_imports)]
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

/// Releases only when the test says so: no sleep decides any semantics.
#[derive(Default)]
pub struct TsaGate {
    held: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
    entered: AtomicUsize,
}
impl TsaGate {
    pub fn pass(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut held = self.held.lock().unwrap();
        let started = std::time::Instant::now();
        // 60 s is only a leak guard for a failed test, never a semantic delay.
        while *held && started.elapsed() < Duration::from_secs(60) {
            held = self
                .changed
                .wait_timeout(held, Duration::from_millis(200))
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
}
pub struct Pki {
    pub address: std::net::SocketAddr,
    pub origin: String,
    pub inter: KeyEntry,
    pub crls: Vec<Vec<u8>>,
    /// Gate that holds native work inside the TSA request until released.
    pub tsa_gate: Arc<TsaGate>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    pub requests: Arc<AtomicUsize>,
}
impl Pki {
    pub fn start() -> Self {
        Self::start_with_revoked(0)
    }
    /// A loopback PKI whose intermediate CRL lists `revoked` unrelated serials (big evidence).
    pub fn start_with_revoked(revoked: usize) -> Self {
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
        let ocsp = Arc::new(MockOcsp::new(raw("ocsp-gost2015")).with_now(now));
        let tsa = Arc::new(
            oncl_pki::tsp::MockTsa::new(with_status_locations(
                &raw("tsa-gost2015"),
                &raw("root-gost2015.key"),
                &origin,
                "root",
            ))
            .with_gen_time(now),
        );
        let root = Arc::new(
            MockCrl::new(raw("root-gost2015.key"))
                .with_this_update(now - time::Duration::MINUTE)
                .next_update(Some(now + time::Duration::days(1))),
        );
        let mut inter_builder = MockCrl::new(inter.clone())
            .with_this_update(now - time::Duration::MINUTE)
            .next_update(Some(now + time::Duration::days(1)));
        for n in 0..revoked {
            let serial = (n as u64 + 1_000_000).to_be_bytes();
            inter_builder = inter_builder.revoke(&serial, now - time::Duration::HOUR);
        }
        let inter_crl = Arc::new(inter_builder);
        let crls = vec![root.der(), inter_crl.der()];
        let tsa_gate = Arc::new(TsaGate::default());
        let gate = tsa_gate.clone();
        let delay = ();
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
                let (ocsp, root, inter_crl, tsa) =
                    (ocsp.clone(), root.clone(), inter_crl.clone(), tsa.clone());
                let (url_origin, counted, delay, gate) =
                    (url_origin.clone(), counted.clone(), delay, gate.clone());
                std::thread::spawn(move || {
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
                        let () = delay;
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
                });
            }
        });
        Self {
            address,
            origin,
            inter,
            crls,
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
            tsa: Some(oncl_server::config::TsaConfig {
                url: format!("{}/tsa", self.origin),
                policy: Some("1.2.3.4.5".into()),
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
