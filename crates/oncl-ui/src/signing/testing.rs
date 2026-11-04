//! A synthetic world for the signing and tool tests: a root, an OCSP responder, a time stamp
//! service and a signing key made on the spot, an engine trusting them, and documents.
use std::path::PathBuf;
use std::sync::Arc;

use der::{
    Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use oncl_core::Engine;
use oncl_pki::http::HttpTransport;
use oncl_pki::http::RouteTransport;
use oncl_pki::keygen::{self, KeySpec};
use oncl_pki::ocsp::MockOcsp;
use oncl_pki::pkcs12::{self, KeyEntry};
use oncl_pki::resource::ResourceLimits;
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::MockTsa;
use time::OffsetDateTime;
use x509_cert::ext::Extension;
use zeroize::Zeroizing;

use super::controller::{ActionKind, Controller, Effect, Event, Item};
use super::runner::{
    ConsentGuard, ExtraTrust, Outcome, desktop_engine, freeze, open_key_store, sign,
};
use crate::workspace::{Destination, JobControl, SignSpec};

pub(crate) const NOW: i64 = 1_793_620_800;
pub(crate) const ORIGIN: &str = "http://127.0.0.1:9";
pub(crate) const PASSWORD: &str = "synthetic loopback password";

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW).unwrap()
}

pub(crate) fn fixture(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}

pub(crate) fn short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
    out.extend_from_slice(body);
    out
}

pub(crate) fn aia(url: &str) -> Extension {
    let mut access = vec![6, 8, 43, 6, 1, 5, 5, 7, 48, 1];
    access.extend(short_tlv(0x86, url.as_bytes()));
    Extension {
        extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
        critical: false,
        extn_value: OctetString::new(short_tlv(0x30, &short_tlv(0x30, &access))).unwrap(),
    }
}

pub(crate) fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}

/// A synthetic root, an OCSP responder, a time stamp service and a signing key under it, all
/// made here.
pub(crate) struct World {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) root_entry: KeyEntry,
    pub(crate) leaf: KeyEntry,
    pub(crate) root: oncl_pki::cert::Certificate,
    /// The time stamp service's certificate and the OCSP responder, for the evidence files.
    pub(crate) tsa_cert: oncl_pki::cert::Certificate,
    pub(crate) responder: KeyEntry,
    /// Where the world's responder and time service are reached: AIA URLs of its certificates.
    pub(crate) origin: String,
    pub(crate) ocsp: Arc<MockOcsp>,
    pub(crate) tsa: Arc<MockTsa>,
    /// What the engine reaches: the responder at `/ocsp` and the time service at `/tsa`.
    pub(crate) http: Arc<dyn HttpTransport>,
    pub(crate) store: PathBuf,
}

pub(crate) fn world() -> World {
    world_at(ORIGIN)
}

/// The world whose certificates point at `origin` (for the services to be reached there).
pub(crate) fn world_at(origin: &str) -> World {
    let mut root = fixture("user-rsa-sign");
    root.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
    let mut spec = TestCertSpec::from_cert(
        &oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap(),
    );
    strip(&mut spec);
    spec.public_key = root.key.public_key().to_spki();
    spec.serial = vec![0x71, 4, 1];
    root.cert = issue_cert(&root, spec.clone());
    root.cert = issue_cert(&root, spec);
    let mut responder = fixture("user-rsa-sign");
    responder.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
    let mut spec = TestCertSpec::from_cert(&fixture("ocsp-gost2015").cert);
    strip(&mut spec);
    spec.public_key = responder.key.public_key().to_spki();
    spec.serial = vec![0x71, 4, 3];
    responder.cert = issue_cert(&root, spec);
    let mut leaf = fixture("user-rsa-sign");
    let mut spec = TestCertSpec::from_cert(&leaf.cert);
    strip(&mut spec);
    spec.serial = vec![0x71, 4, 10];
    spec.extensions.push(aia(&format!("{origin}/ocsp")));
    leaf.cert = issue_cert(&root, spec);
    let mut tsa = fixture("tsa-gost2015");
    tsa.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
    let mut spec = TestCertSpec::from_cert(&tsa.cert);
    strip(&mut spec);
    spec.public_key = tsa.key.public_key().to_spki();
    spec.serial = vec![0x71, 4, 20];
    spec.extensions.push(aia(&format!("{origin}/ocsp")));
    tsa.cert = issue_cert(&root, spec);
    let dir = tempfile::tempdir().unwrap();
    let bytes = pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: leaf.alias.clone(),
            pkcs8_der: leaf.key.to_pkcs8_der().unwrap().to_vec(),
            cert_der: Some(leaf.cert.to_der().unwrap()),
        }],
        &[],
        PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x5a),
    )
    .unwrap();
    let store = dir.path().join("key.p12");
    std::fs::write(&store, bytes).unwrap();
    let ocsp = Arc::new(MockOcsp::new(responder.clone()).with_now(now()));
    let tsa_cert = tsa.cert.clone();
    let tsa = Arc::new(MockTsa::new(tsa).with_gen_time(now()));
    let http: Arc<dyn HttpTransport> = Arc::new(RouteTransport::new(vec![
        (format!("{origin}/ocsp"), ocsp.clone()),
        (format!("{origin}/tsa"), tsa.clone()),
        ("http://tsp.pki.gov.kz".to_owned(), tsa.clone()),
    ]));
    World {
        dir,
        root_entry: root.clone(),
        leaf,
        root: root.cert,
        tsa_cert,
        responder,
        origin: origin.to_owned(),
        ocsp,
        tsa,
        http,
        store,
    }
}

/// The OCSP response the world's responder gives for `cert`, as an operator would have saved it.
pub(crate) fn ocsp_response_for(w: &World, cert: &oncl_pki::cert::Certificate) -> Vec<u8> {
    use oncl_pki::http::{GetOptions, HttpRequest};
    let responder =
        MockOcsp::new(w.responder.clone()).with_now(now() + time::Duration::seconds(60));
    let request = oncl_pki::ocsp::request_der(cert, &w.root);
    responder
        .send(&HttpRequest::post(
            &format!("{}/ocsp", w.origin),
            Some("application/ocsp-request"),
            &request,
            GetOptions::default(),
        ))
        .unwrap()
        .body
}

/// The public validation material the LT and LTA levels of CAdES and PAdES are built from,
/// written as files in the world's directory: the root and the time service's certificates,
/// and OCSP responses for the signer and the time service.
pub(crate) fn evidence_files(w: &World) -> crate::workspace::Evidence {
    let dir = w.dir.path();
    let write = |name: &str, bytes: Vec<u8>| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    crate::workspace::Evidence {
        certificates: vec![
            write("evidence-root.der", w.root.to_der().unwrap()),
            write("evidence-tsa.der", w.tsa_cert.to_der().unwrap()),
        ],
        ocsp: vec![
            write("evidence-leaf.ocsp", ocsp_response_for(w, &w.leaf.cert)),
            write("evidence-tsa.ocsp", ocsp_response_for(w, &w.tsa_cert)),
        ],
        crls: Vec::new(),
    }
}
pub(crate) fn engine(w: &World) -> (Engine, Arc<ConsentGuard>) {
    desktop_engine(
        ResourceLimits::default(),
        w.http.clone(),
        ExtraTrust {
            anchors: vec![w.root.clone()],
            origins: vec![w.origin.clone()],
        },
        &w.dir.path().join("spool"),
        Arc::new(now),
    )
    .unwrap()
}

/// The world's engine with the revocation responder reachable but no time stamp service: the
/// national authority's address does not answer.
pub(crate) fn engine_without_tsa(w: &World) -> (Engine, Arc<ConsentGuard>) {
    let http: Arc<dyn HttpTransport> = Arc::new(RouteTransport::new(vec![(
        format!("{}/ocsp", w.origin),
        w.ocsp.clone(),
    )]));
    desktop_engine(
        ResourceLimits::default(),
        http,
        ExtraTrust {
            anchors: vec![w.root.clone()],
            origins: vec![w.origin.clone()],
        },
        &w.dir.path().join("spool-no-tsa"),
        Arc::new(now),
    )
    .unwrap()
}

/// The world's services on a loopback socket, for tools that run in another process (the
/// command line): `POST /ocsp` and `POST /tsa` are answered by the world's own mocks. Stops
/// when dropped.
pub(crate) struct Loopback {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A world reachable over HTTP: the listener is bound first so that the certificates can point
/// at it, then the server answers from the world's mocks.
pub(crate) fn served_world() -> (World, Loopback) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let w = world_at(&origin);
    let stop = Arc::new(AtomicBool::new(false));
    let routes: Vec<(String, Arc<dyn HttpTransport>)> = vec![
        (format!("{origin}/ocsp"), w.ocsp.clone()),
        (format!("{origin}/tsa"), w.tsa.clone()),
    ];
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head, body_start) = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break (String::new(), 0);
                }
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break (String::from_utf8_lossy(&buffer[..at]).into_owned(), at + 4);
                }
            };
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or_default();
            let method = request_line
                .split_whitespace()
                .next()
                .unwrap_or("GET")
                .to_owned();
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_owned();
            let header = |name: &str| {
                lines.clone().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
                })
            };
            let length: usize = header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let content_type = header("content-type");
            while buffer.len() < body_start + length {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
            let body = buffer.get(body_start..).unwrap_or(&[]).to_vec();
            let url = format!("{}{path}", routes[0].0.trim_end_matches("/ocsp"));
            let route = routes.iter().find(|(prefix, _)| url.starts_with(prefix));
            let reply = route.map(|(_, transport)| {
                if method == "GET" {
                    transport.send(&oncl_pki::http::HttpRequest::get(
                        &url,
                        oncl_pki::http::GetOptions::default(),
                    ))
                } else {
                    transport.send(&oncl_pki::http::HttpRequest::post(
                        &url,
                        content_type.as_deref(),
                        &body,
                        oncl_pki::http::GetOptions::default(),
                    ))
                }
            });
            let (status, content_type, body) = match reply {
                Some(Ok(r)) => (r.status, r.content_type, r.body),
                _ => (404, None, Vec::new()),
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                body.len(),
                content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream")
            );
            let _ = stream.write_all(&body);
        }
    });
    (
        w,
        Loopback {
            stop,
            thread: Some(thread),
        },
    )
}

/// Signs `paths` as `spec` says, the user confirming exactly what the engine froze (the page's
/// whole dance, driven by the real controller). The key store is the world's, the password
/// its own.
pub(crate) fn sign_confirmed(
    engine: &Engine,
    guard: &ConsentGuard,
    w: &World,
    paths: &[PathBuf],
    spec: &SignSpec,
    destination: &Destination,
) -> Outcome {
    let candidates = open_key_store(&w.store, PASSWORD, now()).unwrap();
    let shown: Vec<Item> = paths
        .iter()
        .map(|p| freeze(engine, p, &Arc::new(JobControl::default())).unwrap())
        .collect();
    sign(
        engine,
        guard,
        &w.store,
        &candidates[0].alias,
        &Zeroizing::new(PASSWORD.to_owned()),
        paths,
        spec,
        destination,
        &Arc::new(JobControl::default()),
        |frozen| {
            let mut c = Controller::new("tools", ActionKind::Sign);
            c.dispatch(Event::Documents(shown.clone()));
            c.dispatch(Event::Profile(spec.label()));
            c.dispatch(Event::KeyStore(w.store.display().to_string()));
            c.dispatch(Event::PasswordSubmitted(Zeroizing::new(
                PASSWORD.to_owned(),
            )));
            c.dispatch(Event::Unlocked(candidates.clone()));
            c.dispatch(Event::CertificateChosen(0));
            c.dispatch(Event::Frozen(&frozen.items));
            c.dispatch(Event::Arm);
            match c.dispatch(Event::Confirm {
                frozen: &frozen.items,
            }) {
                Effect::None => super::runner::Decision::Proceed(Box::new(
                    c.take_approved().expect("the confirmation was accepted"),
                )),
                _ => super::runner::Decision::Abort,
            }
        },
    )
}

pub(crate) fn documents(w: &World, names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|n| {
            let p = w.dir.path().join(n);
            std::fs::write(&p, format!("the document {n}")).unwrap();
            p
        })
        .collect()
}
