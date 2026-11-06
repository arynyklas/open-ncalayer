//! The synthetic PKI of the interop matrix: an ephemeral RSA root that issues the RSA,
//! GOST 2015-512 and GOST 34.310-2004 signing certificates (their keys are the committed
//! synthetic fixtures) and an RSA OCSP responder and TSA, all served by one loopback
//! responder. An RSA root lets OpenSSL build the path independently.
//!
//! The responder answers at the fixed [`NOW`]; every `oncl` process gets `--as-of NOW`.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, bail};
use der::Encode;
use der::asn1::{ObjectIdentifier, OctetString};
use oncl_pki::cert;
use oncl_pki::http::{GetOptions, HttpRequest, HttpTransport};
use oncl_pki::keygen::{self, KeySpec};
use oncl_pki::ocsp::MockOcsp;
use oncl_pki::pkcs12::{self, KeyEntry};
use oncl_pki::private_fs::PrivateDirectory;
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::MockTsa;
use x509_cert::ext::Extension;

/// The fixed instant of the whole matrix: 2026-11-02T12:00:00Z.
pub const NOW: i64 = 1_793_620_800;

/// Password of every PKCS#12 container the matrix writes.
pub const PASSWORD: &str = "interop-container-password";

/// The signing profiles of the matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    Rsa,
    Gost2015,
    Gost2004,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::Rsa, Profile::Gost2015, Profile::Gost2004];

    pub fn label(self) -> &'static str {
        match self {
            Profile::Rsa => "rsa",
            Profile::Gost2015 => "gost2015",
            Profile::Gost2004 => "gost2004",
        }
    }

    fn template(self) -> &'static str {
        match self {
            Profile::Rsa => "user-rsa-sign",
            Profile::Gost2015 => "user-gost2015-sign",
            Profile::Gost2004 => "user-gost2004-sign",
        }
    }
}

/// A signer's files and key.
pub struct Signer {
    pub profile: Profile,
    pub p12: PathBuf,
    pub cert_der: PathBuf,
    pub entry: KeyEntry,
}

/// The PKI, its responder and the files `oncl` and the oracles read.
pub struct World {
    /// The directory of everything below; removed on drop.
    pub dir: tempfile::TempDir,
    /// The trusted root (DER) and the same as PEM (for OpenSSL).
    pub root: PathBuf,
    pub root_pem: PathBuf,
    pub root_entry: KeyEntry,
    /// The OCSP responder's and the TSA's keys (the responder serves with them).
    pub responder: KeyEntry,
    pub tsa: KeyEntry,
    /// The TSA certificate and the OCSP responder certificate (DER).
    pub tsa_cert: PathBuf,
    pub responder_cert: PathBuf,
    pub signers: Vec<Signer>,
    /// A secret file in an owner-only directory holding [`PASSWORD`].
    pub secret: PathBuf,
    /// The owner-only directory and the secret files of NCANode's test keys in it
    /// (`nc-gost2015.secret`, `nc-rsa-gost2004.secret`, `wrong.secret`).
    pub private: PathBuf,
    /// The responder's origin, e.g. `http://127.0.0.1:41234`.
    pub origin: String,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl World {
    pub fn signer(&self, profile: Profile) -> &Signer {
        self.signers
            .iter()
            .find(|s| s.profile == profile)
            .expect("every profile has a signer")
    }

    /// The trust options every `oncl` process of the matrix gets.
    pub fn trust_args(&self) -> Vec<String> {
        vec![
            "--root".to_owned(),
            self.root.to_string_lossy().into_owned(),
            "--pki-endpoint".to_owned(),
            self.origin.clone(),
            "--as-of".to_owned(),
            NOW.to_string(),
        ]
    }

    pub fn tsa_url(&self) -> String {
        format!("{}/tsa", self.origin)
    }

    /// Builds the PKI in `base` (a directory on a filesystem with owner-only modes and
    /// hard links: not a Windows-drive mount inside WSL) and starts the responder on
    /// `host`: loopback, or the Docker bridge's gateway address so that the NCANode
    /// container can fetch the OCSP responses its AIA extension names.
    pub fn start(base: &Path, host: Ipv4Addr) -> anyhow::Result<World> {
        let listener = TcpListener::bind((host, 0))?;
        let address = listener.local_addr()?;
        let origin = format!("http://{address}");
        let dir = tempfile::Builder::new()
            .prefix("oncl-interop-world-")
            .tempdir_in(base)
            .context("creating the world directory")?;

        let mut root = fixture("user-rsa-sign")?;
        root.key =
            keygen::generate(KeySpec::RsaSha256(2048)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut spec = TestCertSpec::from_cert(
            &cert::parse(&oncl_testkit::synthetic_cert("root-rsa"))
                .map_err(|e| anyhow::anyhow!("{e:?}"))?,
        );
        strip(&mut spec);
        spec.public_key = root.key.public_key().to_spki();
        spec.serial = vec![0x71, 4, 1];
        // Self-signed: the first issue carries the template issuer name, the second the root's.
        root.cert = issue_cert(&root, spec.clone());
        root.cert = issue_cert(&root, spec);

        let derived = |template: &str, serial: u8, with_aia: bool| -> anyhow::Result<KeyEntry> {
            let mut entry = fixture("user-rsa-sign")?;
            entry.key =
                keygen::generate(KeySpec::RsaSha256(2048)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let mut spec = TestCertSpec::from_cert(&fixture(template)?.cert);
            strip(&mut spec);
            spec.public_key = entry.key.public_key().to_spki();
            spec.serial = vec![0x71, 4, serial];
            if with_aia {
                spec.extensions.push(aia(&format!("{origin}/ocsp")));
            }
            entry.cert = issue_cert(&root, spec);
            Ok(entry)
        };
        let tsa = derived("tsa-gost2015", 2, true)?;
        let responder = derived("ocsp-gost2015", 3, false)?;
        let leaf = |profile: Profile, serial: u8| -> anyhow::Result<KeyEntry> {
            let mut entry = fixture(profile.template())?;
            let mut spec = TestCertSpec::from_cert(&entry.cert);
            strip(&mut spec);
            spec.serial = vec![0x71, 4, serial];
            spec.extensions.push(aia(&format!("{origin}/ocsp")));
            entry.cert = issue_cert(&root, spec);
            Ok(entry)
        };

        let root_path = dir.path().join("root.cer");
        std::fs::write(&root_path, root.cert.to_der()?)?;
        let root_pem = dir.path().join("root.pem");
        std::fs::write(&root_pem, pem("CERTIFICATE", &root.cert.to_der()?))?;
        let tsa_cert = dir.path().join("tsa.cer");
        std::fs::write(&tsa_cert, tsa.cert.to_der()?)?;
        let responder_cert = dir.path().join("ocsp-responder.cer");
        std::fs::write(&responder_cert, responder.cert.to_der()?)?;

        let mut signers = Vec::new();
        for (profile, serial) in [
            (Profile::Rsa, 10),
            (Profile::Gost2015, 11),
            (Profile::Gost2004, 12),
        ] {
            let entry = leaf(profile, serial)?;
            let p12 = dir.path().join(format!("{}.p12", profile.label()));
            std::fs::write(&p12, container(&entry, PASSWORD)?)?;
            let cert_der = dir.path().join(format!("{}.cer", profile.label()));
            std::fs::write(&cert_der, entry.cert.to_der()?)?;
            signers.push(Signer {
                profile,
                p12,
                cert_der,
                entry,
            });
        }

        let private = dir.path().join("private");
        let namespace = PrivateDirectory::create(&private)
            .map_err(|e| anyhow::anyhow!("creating the owner-only directory: {e:?}"))?;
        for (name, text) in [
            ("key.secret", PASSWORD),
            ("nc-gost2015.secret", "Aa123456"),
            ("nc-rsa-gost2004.secret", "Qwerty12"),
            ("wrong.secret", "not-the-password"),
        ] {
            namespace
                .create_file(name)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                .write_all(text.as_bytes())?;
        }

        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let base_origin = origin.clone();
        let (served_responder, served_tsa) = (responder.clone(), tsa.clone());
        let join = thread::spawn(move || {
            let now = time::OffsetDateTime::from_unix_timestamp(NOW).expect("a valid instant");
            let ocsp = Arc::new(MockOcsp::new(served_responder).with_now(now));
            let tsa = Arc::new(MockTsa::new(served_tsa).with_gen_time(now));
            let mut handlers = Vec::new();
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (origin, ocsp, tsa) = (base_origin.clone(), ocsp.clone(), tsa.clone());
                        handlers.push(thread::spawn(move || {
                            let _ = serve(&mut stream, &origin, &ocsp, &tsa);
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
            for handler in handlers {
                let _ = handler.join();
            }
        });
        Ok(World {
            secret: private.join("key.secret"),
            private,
            root: root_path,
            root_pem,
            root_entry: root,
            responder,
            tsa,
            tsa_cert,
            responder_cert,
            signers,
            origin,
            dir,
            stop,
            join: Some(join),
        })
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn fixture(name: &str) -> anyhow::Result<KeyEntry> {
    let f = oncl_testkit::synthetic(name);
    let bytes = std::fs::read(&f.path).with_context(|| f.path.display().to_string())?;
    pkcs12::load(&bytes, &f.password)
        .map_err(|e| anyhow::anyhow!("{}: {e:?}", f.path.display()))?
        .into_iter()
        .next()
        .with_context(|| format!("{} holds no key", f.path.display()))
}

/// A PKCS#12 container of `entry` under `password`, with fresh random salts.
pub fn container(entry: &KeyEntry, password: &str) -> anyhow::Result<Vec<u8>> {
    pkcs12::write(
        &[pkcs12::WriteEntry {
            alias: entry.alias.clone(),
            pkcs8_der: entry
                .key
                .to_pkcs8_der()
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                .to_vec(),
            cert_der: Some(entry.cert.to_der()?),
        }],
        &[],
        password,
        &pkcs12::WriteOptions::default(),
        &mut |bytes| getrandom::fill(bytes).expect("the operating system's random source"),
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))
}

fn short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut out = vec![tag, u8::try_from(body.len()).expect("short")];
    out.extend_from_slice(body);
    out
}

fn aia(url: &str) -> Extension {
    let mut access = vec![6, 8, 43, 6, 1, 5, 5, 7, 48, 1];
    access.extend(short_tlv(0x86, url.as_bytes()));
    Extension {
        extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
        critical: false,
        extn_value: OctetString::new(short_tlv(0x30, &short_tlv(0x30, &access)))
            .expect("an octet string"),
    }
}

/// Drops the extensions that name the template's issuer (key identifiers, AIA, CRL points).
fn strip(spec: &mut TestCertSpec) {
    spec.extensions.retain(|e| {
        !matches!(
            e.extn_id.to_string().as_str(),
            "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1" | "2.5.29.31"
        )
    });
}

/// Answers one request: `POST /tsa` is a timestamp request, other POSTs OCSP requests,
/// GETs `/ocsp/<base64>` OCSP requests.
fn serve(
    stream: &mut TcpStream,
    origin: &str,
    ocsp: &MockOcsp,
    tsa: &MockTsa,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    // A client may connect early and ask minutes later (a large document is read first).
    stream.set_read_timeout(Some(Duration::from_secs(1800)))?;
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
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
    let headers = String::from_utf8_lossy(&request[..end]).into_owned();
    let mut words = headers
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let (method, path) = (
        words.next().unwrap_or_default().to_owned(),
        words.next().unwrap_or_default().to_owned(),
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

/// `der` as a PEM block.
pub fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut text = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str(&format!("-----END {label}-----\n"));
    text
}

/// The address the responder listens on (for diagnostics).
pub fn responder_address(origin: &str) -> anyhow::Result<SocketAddr> {
    origin
        .trim_start_matches("http://")
        .parse()
        .with_context(|| format!("bad origin {origin}"))
}

/// Fails unless `path` is an existing file.
pub fn require_file(path: &Path) -> anyhow::Result<()> {
    if !path.is_file() {
        bail!("{} is missing", path.display());
    }
    Ok(())
}
