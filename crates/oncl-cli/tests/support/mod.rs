//! Synthetic-only loopback PKI for real `oncl` process tests. Keys are ephemeral
//! (RSA) or the committed synthetic fixtures; nothing secret is committed.
#![allow(dead_code)]
use der::{
    Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use oncl_pki::{
    cert,
    http::{GetOptions, HttpRequest, HttpTransport},
    keygen::{self, KeySpec},
    ocsp::MockOcsp,
    pkcs12::{self, KeyEntry},
    private_fs::PrivateDirectory,
    testing::{TestCertSpec, issue_cert},
    tsp::MockTsa,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use x509_cert::ext::Extension;

/// Fixed host verification time (Unix seconds) shared by every process.
pub const NOW_SECONDS: i64 = 1_793_620_800;
pub fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(NOW_SECONDS).unwrap()
}
pub const PASSWORD: &str = "synthetic loopback password";

pub fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oncl"))
        .args(args)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    child.wait_with_output().unwrap()
}
fn fixture(name: &str) -> KeyEntry {
    let f = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(f.path), &f.password)
        .unwrap()
        .remove(0)
}
fn short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut out = vec![tag, body.len() as u8];
    out.extend_from_slice(body);
    out
}
fn aia(url: &str) -> Extension {
    let mut access = vec![6, 8, 43, 6, 1, 5, 5, 7, 48, 1];
    access.extend(short_tlv(0x86, url.as_bytes()));
    Extension {
        extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
        critical: false,
        extn_value: OctetString::new(short_tlv(0x30, &short_tlv(0x30, &access))).unwrap(),
    }
}
fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}
pub struct Pki {
    pub root: KeyEntry,
    pub tsa: KeyEntry,
    pub responder: KeyEntry,
    pub rsa: KeyEntry,
    pub gost: KeyEntry,
}
pub fn pki(origin: &str) -> Pki {
    let mut root = fixture("user-rsa-sign");
    root.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
    let mut spec =
        TestCertSpec::from_cert(&cert::parse(&oncl_testkit::synthetic_cert("root-rsa")).unwrap());
    strip(&mut spec);
    spec.public_key = root.key.public_key().to_spki();
    spec.serial = vec![0x71, 4, 1];
    root.cert = issue_cert(&root, spec.clone());
    root.cert = issue_cert(&root, spec);
    let derived = |template: &str, serial: u8, with_aia: bool| {
        let mut entry = fixture("user-rsa-sign");
        entry.key = keygen::generate(KeySpec::RsaSha256(2048)).unwrap();
        let mut spec = TestCertSpec::from_cert(&fixture(template).cert);
        strip(&mut spec);
        spec.public_key = entry.key.public_key().to_spki();
        spec.serial = vec![0x71, 4, serial];
        if with_aia {
            spec.extensions.push(aia(&format!("{origin}/ocsp")));
        }
        entry.cert = issue_cert(&root, spec);
        entry
    };
    let tsa = derived("tsa-gost2015", 2, true);
    let responder = derived("ocsp-gost2015", 3, false);
    let leaf = |name: &str, serial: u8| {
        let mut entry = fixture(name);
        let mut spec = TestCertSpec::from_cert(&entry.cert);
        strip(&mut spec);
        spec.serial = vec![0x71, 4, serial];
        spec.extensions.push(aia(&format!("{origin}/ocsp")));
        entry.cert = issue_cert(&root, spec);
        entry
    };
    Pki {
        rsa: leaf("user-rsa-sign", 10),
        gost: leaf("user-gost2015-sign", 11),
        root,
        tsa,
        responder,
    }
}
pub struct Server {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
    pub origin: String,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}
pub fn start(responder: KeyEntry, tsa: KeyEntry, listener: TcpListener, origin: String) -> Server {
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let base = origin.clone();
    let join = thread::spawn(move || {
        let ocsp = MockOcsp::new(responder).with_now(now());
        let tsa = MockTsa::new(tsa).with_gen_time(now());
        while !stopping.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = serve(&mut stream, &base, &ocsp, &tsa);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(e) => panic!("loopback listener: {e}"),
            }
        }
    });
    Server {
        stop,
        join: Some(join),
        origin,
    }
}
fn serve(
    stream: &mut TcpStream,
    origin: &str,
    ocsp: &MockOcsp,
    tsa: &MockTsa,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = Vec::new();
    let mut chunk = [0; 4096];
    let end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..n]);
        if request.len() > 1 << 20 {
            return Ok(());
        }
        if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let headers = String::from_utf8_lossy(&request[..end]).to_string();
    let first = headers.lines().next().unwrap_or_default().to_owned();
    let mut words = first.split_whitespace();
    let (method, path) = (
        words.next().unwrap_or("").to_owned(),
        words.next().unwrap_or("").to_owned(),
    );
    let length = headers
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while request.len() < end + length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..n]);
    }
    let body = request[end..].to_vec();
    let url = format!("{origin}{path}");
    let reply = if path == "/tsa" {
        tsa.send(&HttpRequest::post(
            &url,
            Some("application/timestamp-query"),
            &body,
            GetOptions::default(),
        ))
    } else if method == "GET" {
        ocsp.send(&HttpRequest::get(&url, GetOptions::default()))
    } else {
        ocsp.send(&HttpRequest::post(
            &url,
            Some("application/ocsp-request"),
            &body,
            GetOptions::default(),
        ))
    };
    match reply {
        Ok(reply) => {
            write!(
                stream,
                "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.status,
                reply
                    .content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream"),
                reply.body.len()
            )?;
            stream.write_all(&reply.body)
        }
        Err(_) => write!(
            stream,
            "HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    }
}
/// Everything a strict private-operation process needs, as files. The password
/// is placed only in an owner-only protected file, never an argument.
pub struct World {
    pub dir: tempfile::TempDir,
    pub server: Server,
    pub root: PathBuf,
    pub rsa_key: PathBuf,
    pub gost_key: PathBuf,
    pub secret: PathBuf,
    pub origin: String,
    pub pki: Pki,
}
pub fn world() -> World {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let pki = pki(&origin);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.cer");
    std::fs::write(&root, pki.root.cert.to_der().unwrap()).unwrap();
    let container = |entry: &KeyEntry, name: &str| {
        let bytes = pkcs12::write(
            &[pkcs12::WriteEntry {
                alias: entry.alias.clone(),
                pkcs8_der: entry.key.to_pkcs8_der().unwrap().to_vec(),
                cert_der: Some(entry.cert.to_der().unwrap()),
            }],
            &[],
            PASSWORD,
            &pkcs12::WriteOptions::default(),
            &mut |b| b.fill(0x5a),
        )
        .unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let rsa_key = container(&pki.rsa, "rsa.p12");
    let gost_key = container(&pki.gost, "gost.p12");
    let private = dir.path().join("private");
    let namespace = PrivateDirectory::create(&private).unwrap();
    namespace
        .create_file("key.secret")
        .unwrap()
        .write_all(PASSWORD.as_bytes())
        .unwrap();
    let server = start(
        pki.responder.clone(),
        pki.tsa.clone(),
        listener,
        origin.clone(),
    );
    World {
        secret: private.join("key.secret"),
        dir,
        server,
        root,
        rsa_key,
        gost_key,
        origin,
        pki,
    }
}
pub fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
