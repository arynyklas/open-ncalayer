#![allow(dead_code)]
//! Synthetic signed TSA/OCSP/CRL fixtures; no real accounts or private outputs.
use der::{Decode, Reader, SliceReader};
use oncl_pki::{
    cert::Certificate,
    crl::MockCrl,
    http::{GetOptions, HttpError, HttpReply, HttpRequest, HttpTransport, NonceSpec, PkiMethod},
    key::{HashAlg, PrivateKey},
    ocsp::{CertStatus, MockOcsp, OcspTamper},
    pkcs12::KeyEntry,
    pkix::CaSet,
    testing::{TestCertSpec, issue_cert},
    tsp::{MockTsa, TsaSpec},
    validation::NetworkPolicy,
};
use std::{
    io::{Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
pub const NOW: time::OffsetDateTime = time::macros::datetime!(2026-11-02 12:00 UTC);
pub fn entry(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    oncl_pki::pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|ext| {
        !matches!(
            ext.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}
fn uris(input: &[u8], url: &[u8]) -> Vec<u8> {
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
            .skip_while(|byte| *byte == 0)
            .collect();
        result.push(0x80 | bytes.len() as u8);
        result.extend(bytes);
    }
    result.extend(body);
    result
}
#[derive(Clone, Copy)]
pub enum Status {
    Good,
    Revoked(time::OffsetDateTime),
    Stale,
}
pub struct SignedFixtures {
    pub root: Certificate,
    pub tsa_cert: Certificate,
    pub tsa: MockTsa,
    ocsp: MockOcsp,
    crl: MockCrl,
    pub requests: AtomicUsize,
    pub origin: String,
}
impl SignedFixtures {
    pub fn new(origin: &str, gen_time: time::OffsetDateTime, status: Status) -> Arc<Self> {
        Self::variant(
            origin,
            gen_time,
            status,
            true,
            None,
            oncl_pki::tsp::MockTamper::None,
        )
    }
    pub fn variant(
        origin: &str,
        gen_time: time::OffsetDateTime,
        status: Status,
        eku: bool,
        expires: Option<time::OffsetDateTime>,
        tamper: oncl_pki::tsp::MockTamper,
    ) -> Arc<Self> {
        let mut root = entry("root-gost2015.key");
        root.key = PrivateKey::from_pkcs8_der(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/openssl/rsa.pk8.der"
            )),
            None,
        )
        .unwrap();
        let mut spec = TestCertSpec::from_cert(&root.cert);
        strip(&mut spec);
        spec.serial = vec![0x19, 1, 1];
        spec.public_key = root.key.public_key().to_spki();
        root.cert = issue_cert(&root, spec);
        let mut tsa = entry("user-rsa-sign");
        let mut spec = TestCertSpec::from_cert(&entry("tsa-gost2015").cert);
        strip(&mut spec);
        spec.serial = vec![0x19, 1, 2];
        spec.public_key = tsa.key.public_key().to_spki();
        if !eku {
            spec.extensions
                .retain(|extension| extension.extn_id.to_string() != "2.5.29.37");
        }
        if let Some(expires) = expires {
            use der::Encode;
            let time = der::asn1::GeneralizedTime::from_unix_duration(
                std::time::Duration::from_secs(expires.unix_timestamp() as u64),
            )
            .unwrap()
            .to_der()
            .unwrap();
            spec.validity.not_after = der::Decode::from_der(&time).unwrap();
        }
        spec.extensions.extend(
            TestCertSpec::from_cert(&entry("inter-user-gost2015-sign").cert)
                .extensions
                .into_iter()
                .filter(|ext| {
                    matches!(
                        ext.extn_id.to_string().as_str(),
                        "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
                    )
                }),
        );
        for ext in &mut spec.extensions {
            let path = match ext.extn_id.to_string().as_str() {
                "1.3.6.1.5.5.7.1.1" => Some("/ocsp"),
                "2.5.29.31" => Some("/root.crl"),
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
        tsa.cert = issue_cert(&root, spec);
        let mut responder = tsa.clone();
        let mut spec = TestCertSpec::from_cert(&entry("ocsp-gost2015").cert);
        strip(&mut spec);
        spec.serial = vec![0x19, 1, 3];
        spec.public_key = responder.key.public_key().to_spki();
        responder.cert = issue_cert(&root, spec);
        let mut ocsp = MockOcsp::new(responder).with_now(NOW);
        let mut crl = MockCrl::new(root.clone())
            .with_this_update(NOW - time::Duration::MINUTE)
            .next_update(Some(NOW + time::Duration::HOUR));
        match status {
            Status::Good => {}
            Status::Revoked(at) => {
                ocsp = ocsp.status(
                    "190102",
                    CertStatus::Revoked {
                        time: at,
                        reason: None,
                    },
                );
                crl = crl.revoke(&[0x19, 1, 2], at);
            }
            Status::Stale => {
                ocsp = ocsp.tamper(OcspTamper::Stale);
                crl = crl
                    .with_this_update(NOW - time::Duration::hours(2))
                    .next_update(Some(NOW - time::Duration::HOUR));
            }
        }
        Arc::new(Self {
            root: root.cert,
            tsa_cert: tsa.cert.clone(),
            tsa: MockTsa::new(tsa)
                .with_gen_time(gen_time)
                .with_tamper(tamper),
            ocsp,
            crl,
            requests: AtomicUsize::new(0),
            origin: origin.to_owned(),
        })
    }
    pub fn spec(&self) -> TsaSpec {
        TsaSpec {
            url: format!("{}/tsa", self.origin),
            method: PkiMethod::Post { content_type: None },
            hash: HashAlg::Sha256,
            policy: Some(der::asn1::ObjectIdentifier::new_unwrap("1.2.3.19.1")),
            nonce: NonceSpec::Value(vec![0x19, 1, 0xff]),
            cert_req: true,
            retries: 0,
            timeout: Duration::from_secs(2),
            check_skew: Some(Duration::from_secs(60)),
            require_tsa_eku: true,
        }
    }
    pub fn services(self: &Arc<Self>, trusted: bool) -> oncl_core::ValidationServices {
        self.services_with(trusted, self.clone())
    }
    pub fn services_with(
        &self,
        trusted: bool,
        http: Arc<dyn HttpTransport>,
    ) -> oncl_core::ValidationServices {
        oncl_core::ValidationServices::new(
            CaSet::new(if trusted {
                vec![self.root.clone()]
            } else {
                vec![]
            }),
            vec![],
            http,
            NetworkPolicy::only_endpoints([&self.origin]).unwrap(),
            Arc::new(|| NOW),
        )
    }
    pub fn crl(&self) -> Vec<u8> {
        self.crl.der()
    }
}
impl HttpTransport for SignedFixtures {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if request.url.ends_with("/tsa") {
            self.tsa.send(request)
        } else if request.url.ends_with("/root.crl") {
            self.crl.send(request)
        } else if request.url.contains("/ocsp") {
            self.ocsp.send(request)
        } else {
            Err(HttpError::other("fixture endpoint"))
        }
    }
}
pub struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}
impl Server {
    pub fn start(listener: std::net::TcpListener, http: Arc<SignedFixtures>) -> Self {
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut calls = 0;
            while !stopped.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(60) {
                let (mut socket, _) = match listener.accept() {
                    Ok(socket) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                socket
                    .set_nonblocking(false)
                    .map_err(|error| error.to_string())?;
                calls += 1;
                if calls > 128 {
                    return Err("fixture HTTP work limit".into());
                }
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let end = loop {
                    let count = socket.read(&mut chunk).map_err(|error| error.to_string())?;
                    if count == 0 || bytes.len() + count > 65536 {
                        return Err("fixture HTTP head bound".into());
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let head = std::str::from_utf8(&bytes[..end])
                    .map_err(|error| error.to_string())?
                    .to_owned();
                let length = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>())
                    .transpose()
                    .map_err(|error| error.to_string())?
                    .unwrap_or(0);
                if length > 65536 - end {
                    return Err("fixture HTTP body bound".into());
                }
                while bytes.len() - end < length {
                    let count = socket.read(&mut chunk).map_err(|error| error.to_string())?;
                    if count == 0 || bytes.len() + count > 65536 {
                        return Err("fixture HTTP body EOF/bound".into());
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                }
                let mut first = head
                    .lines()
                    .next()
                    .ok_or("fixture method")?
                    .split_whitespace();
                let method = first.next().ok_or("fixture method")?;
                let path = first.next().ok_or("fixture path")?;
                let url = format!("{}{path}", http.origin);
                let content_type = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                    .map(|(_, value)| value.trim());
                let request = if method == "POST" {
                    HttpRequest::post(
                        &url,
                        content_type,
                        &bytes[end..end + length],
                        GetOptions::default(),
                    )
                } else {
                    HttpRequest::get(&url, GetOptions::default())
                };
                let reply = http.send(&request).map_err(|error| error.to_string())?;
                write!(socket, "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.status, reply.content_type.as_deref().unwrap_or("application/octet-stream"), reply.body.len()).map_err(|error| error.to_string())?;
                socket
                    .write_all(&reply.body)
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
    pub fn finish(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| "fixture thread panic".to_owned())?
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
