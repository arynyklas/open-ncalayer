//! `sdk_probe pki-serve --out DIR`: a synthetic certification authority on loopback for the
//! platform proof (`cargo xtask platform-proof`). Everything is generated here from the
//! committed synthetic fixtures and trusts nothing real: a GOST-2015 root that issues an
//! RSA signing leaf, a GOST-2015 signing leaf, an OCSP responder and a TSA, an OCSP/TSA
//! responder on loopback, and the public evidence files (certificates and OCSP responses)
//! that CAdES/PAdES/XAdES LT/LTA extension needs. Runs until its stdin closes.
use der::{
    Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use oncl_pki::{
    http::{GetOptions, HttpRequest, HttpTransport},
    ocsp::{MockOcsp, request_der},
    pkcs12::{self, KeyEntry},
    testing::{TestCertSpec, issue_cert},
    tsp::MockTsa,
};
use std::{
    error::Error,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use x509_cert::ext::Extension;

pub const PASSWORD: &str = "synthetic loopback password";
pub const TSA_POLICY: &str = "1.2.398.3.3.2.6.2";

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

/// The GOST-2015 root issues every certificate directly (the CLI's loopback `world_gost`).
pub fn pki(origin: &str) -> Pki {
    let root = super::fixture_entry("root-gost2015.key");
    let reissue = |template: &str, serial: u8, with_aia: bool| {
        let mut entry = super::fixture_entry(template);
        let mut spec = TestCertSpec::from_cert(&entry.cert);
        strip(&mut spec);
        spec.serial = vec![0x72, 4, serial];
        if with_aia {
            spec.extensions.push(aia(&format!("{origin}/ocsp")));
        }
        entry.cert = issue_cert(&root, spec);
        entry
    };
    Pki {
        tsa: reissue("tsa-gost2015", 2, true),
        responder: reissue("ocsp-gost2015", 3, false),
        rsa: reissue("user-rsa-sign", 10, true),
        gost: reissue("user-gost2015-sign", 11, true),
        root,
    }
}

fn p12(entry: &KeyEntry) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: entry.alias.clone(),
            pkcs8_der: entry.key.to_pkcs8_der()?.to_vec(),
            cert_der: Some(entry.cert.to_der()?),
        }],
        &[],
        PASSWORD,
        &pkcs12::WriteOptions::default(),
        &mut |b| b.fill(0x5a),
    )?)
}

fn ocsp_for(pki: &Pki, origin: &str, cert: &x509_cert::Certificate) -> Vec<u8> {
    let responder = MockOcsp::new(pki.responder.clone()).with_now(time::OffsetDateTime::now_utc());
    responder
        .send(&HttpRequest::post(
            &format!("{origin}/ocsp"),
            Some("application/ocsp-request"),
            &request_der(cert, &pki.root.cert),
            GetOptions::default(),
        ))
        .expect("loopback OCSP response")
        .body
}

pub fn serve(out: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(out)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let origin = format!("http://{address}");
    let pki = Arc::new(pki(&origin));
    std::fs::write(out.join("root.cer"), pki.root.cert.to_der()?)?;
    std::fs::write(out.join("rsa.p12"), p12(&pki.rsa)?)?;
    std::fs::write(out.join("gost.p12"), p12(&pki.gost)?)?;
    std::fs::write(out.join("tsa.der"), pki.tsa.cert.to_der()?)?;
    std::fs::write(
        out.join("leaf-rsa.ocsp"),
        ocsp_for(&pki, &origin, &pki.rsa.cert),
    )?;
    std::fs::write(
        out.join("leaf-gost.ocsp"),
        ocsp_for(&pki, &origin, &pki.gost.cert),
    )?;
    std::fs::write(out.join("tsa.ocsp"), ocsp_for(&pki, &origin, &pki.tsa.cert))?;
    let meta = format!(
        "{{\"origin\":\"{origin}\",\"tsa_url\":\"{origin}/tsa\",\"tsa_policy\":\"{TSA_POLICY}\",\"password\":\"{PASSWORD}\",\"alias_rsa\":{},\"alias_gost\":{}}}",
        serde_json::to_string(&pki.rsa.alias)?,
        serde_json::to_string(&pki.gost.alias)?
    );
    std::fs::write(out.join("pki.json"), meta)?;
    // Evidence OCSP responses must be produced AFTER the timestamps they cover: the files are
    // re-minted every few seconds (atomic rename), so a process that loads them at its start,
    // after an earlier operation's timestamp, always gets later ones.
    let refresh_stop = Arc::new(AtomicBool::new(false));
    let refresher = {
        let (pki, origin, out, stop) = (
            pki.clone(),
            origin.clone(),
            out.to_owned(),
            refresh_stop.clone(),
        );
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(3));
                for (name, cert) in [
                    ("leaf-rsa.ocsp", &pki.rsa.cert),
                    ("leaf-gost.ocsp", &pki.gost.cert),
                    ("tsa.ocsp", &pki.tsa.cert),
                ] {
                    let partial = out.join(format!("{name}.partial"));
                    if std::fs::write(&partial, ocsp_for(&pki, &origin, cert)).is_ok() {
                        let _ = std::fs::rename(&partial, out.join(name));
                    }
                }
            }
        })
    };
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicU64::new(0));
    let (stopping, counted) = (stop.clone(), requests.clone());
    let base = origin.clone();
    let server_pki = pki.clone();
    let accept = thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let (base, pki, counted) = (base.clone(), server_pki.clone(), counted.clone());
                    thread::spawn(move || {
                        let _ = handle(&mut stream, &base, &pki, &counted);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
    });
    println!("origin={origin}");
    println!("ready");
    std::io::stdout().flush()?;
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    stop.store(true, Ordering::SeqCst);
    let _ = accept.join();
    refresh_stop.store(true, Ordering::SeqCst);
    let _ = refresher.join();
    println!("requests={}", requests.load(Ordering::SeqCst));
    Ok(())
}

fn handle(
    stream: &mut TcpStream,
    origin: &str,
    pki: &Pki,
    counted: &AtomicU64,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
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
    counted.fetch_add(1, Ordering::SeqCst);
    let body = request[end..].to_vec();
    let url = format!("{origin}{path}");
    // OCSP responses are minted per request at the current instant: a long run never
    // meets an expired responder answer.
    let now = time::OffsetDateTime::now_utc();
    let reply = if path == "/tsa" {
        MockTsa::new(pki.tsa.clone())
            .with_gen_time(now)
            .send(&HttpRequest::post(
                &url,
                Some("application/timestamp-query"),
                &body,
                GetOptions::default(),
            ))
    } else if method == "GET" {
        MockOcsp::new(pki.responder.clone())
            .with_now(now)
            .send(&HttpRequest::get(&url, GetOptions::default()))
    } else {
        MockOcsp::new(pki.responder.clone())
            .with_now(now)
            .send(&HttpRequest::post(
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
