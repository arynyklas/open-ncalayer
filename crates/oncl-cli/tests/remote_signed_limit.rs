//! A signed result of a document that was exactly at the server's `input_bytes` must be
//! accepted again by the same server, like the SDK and the local CLI accept it: the document
//! allowance bounds the document, the signature, revision or envelope is a separate surcharge
//! bounded by `container_bytes`. Hostile input past the document allowance is still
//! `InputLimit`. The real `oncl` process against a real loopback server, limits scaled to a
//! megabyte.
mod remote_support;
use remote_support::*;
use std::{
    path::{Path, PathBuf},
    process::Output,
};

const LIMIT: usize = 1 << 20;
const CONTAINER: u64 = 64 * 1024;

/// A well-formed XML document of exactly `len` bytes.
fn xml_of(len: usize) -> Vec<u8> {
    let mut bytes = br#"<r Id="d">"#.to_vec();
    bytes.resize(len - 4, b'a');
    bytes.extend_from_slice(b"</r>");
    assert_eq!(bytes.len(), len);
    bytes
}

/// A one-page classic-xref PDF of exactly `len` bytes (the page's content stream is padding).
fn pdf_of(len: usize) -> Vec<u8> {
    let build = |padding: usize| {
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        let mut object = |out: &mut Vec<u8>, body: &[u8]| {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", offsets.len()).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        };
        object(&mut out, b"<< /Type /Catalog /Pages 2 0 R >>");
        object(&mut out, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>");
        object(
            &mut out,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        );
        let mut stream = format!("<< /Length {padding} >>\nstream\n").into_bytes();
        stream.resize(stream.len() + padding, b' ');
        stream.extend_from_slice(b"\nendstream");
        object(&mut out, &stream);
        let xref = out.len();
        out.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
        for offset in &offsets {
            out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size 5 /Root 1 0 R /ID [<11111111111111111111111111111111> <11111111111111111111111111111111>] >>\nstartxref\n{xref}\n%%EOF\n"
            )
            .as_bytes(),
        );
        out
    };
    let mut padding = len.saturating_sub(build(0).len());
    for _ in 0..8 {
        let made = build(padding);
        if made.len() == len {
            return made;
        }
        padding = padding.saturating_add(len).saturating_sub(made.len());
    }
    panic!("no PDF of {len} bytes");
}

/// Pseudo-random bytes (CMS content).
fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

struct Client<'a> {
    remote: &'a Remote,
    dir: tempfile::TempDir,
}
impl<'a> Client<'a> {
    fn new(remote: &'a Remote) -> Self {
        Self {
            remote,
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let file = self.dir.path().join(name);
        std::fs::write(&file, bytes).unwrap();
        file
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn run(&self, extra: &[&str]) -> Output {
        let endpoint = self.remote.endpoint();
        let mut args = vec![
            "--endpoint",
            &endpoint,
            "--token-file",
            path(&self.remote.token_file),
        ];
        args.extend_from_slice(extra);
        oncl(
            &args,
            b"",
            &[self.remote.token.as_str(), KEY_PASSWORD],
            Some(self.dir.path()),
        )
    }
    fn sign(&self, profile: &str, input: &Path, output: &Path) -> Output {
        let mut args = vec![
            "sign",
            "--profile",
            profile,
            "--key-name",
            "ops-key",
            "--authorize",
            "--input",
            path(input),
            "--output",
            path(output),
            "--json",
        ];
        if profile.starts_with("xades") {
            args.extend(["--target-id", "d", "--signature-id", "sig-1"]);
        }
        self.run(&args)
    }
    fn verify(&self, profile: &str, input: &Path) -> Output {
        self.run(&[
            "verify",
            "--profile",
            profile,
            "--input",
            path(input),
            "--json",
        ])
    }
    /// Keyless extension of an XAdES or PAdES result to LT with the loopback PKI's CRLs as
    /// evidence.
    fn extend_lt(&self, pki: &Pki, profile: &str, input: &Path, output: &Path) -> Output {
        let crls = ["inter", "root"].map(|name| {
            self.file(
                &format!("{name}.crl"),
                &get(pki.address, &format!("/{name}.crl")),
            )
        });
        let chain = [
            self.file("root.cer", &der(&pki.root)),
            self.file("inter.cer", &der(&pki.inter)),
        ];
        let mut args = vec![
            "extend",
            "--profile",
            profile,
            "--level",
            "lt",
            "--input",
            path(input),
            "--output",
            path(output),
            "--json",
        ];
        for crl in &crls {
            args.extend(["--evidence-crl", path(crl)]);
        }
        for certificate in &chain {
            args.extend(["--evidence-certificate", path(certificate)]);
        }
        self.run(&args)
    }
    fn hash(&self, input: &Path) -> Output {
        self.run(&[
            "hash",
            "--algorithm",
            "sha256",
            "--input",
            path(input),
            "--json",
        ])
    }
}
fn der(entry: &oncl_pki::pkcs12::KeyEntry) -> Vec<u8> {
    use der::Encode;
    entry.cert.to_der().unwrap()
}
/// The body of an HTTP/1.1 GET of the loopback PKI responder.
fn get(address: std::net::SocketAddr, target: &str) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let body = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    response[body..].to_vec()
}
fn exit(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}
fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", text(&output.stdout)))
}
/// Refused as the typed `InputLimit`, nothing applied.
fn assert_input_limit(what: &str, output: &Output) {
    assert_ne!(exit(output), 0, "{what} must be refused");
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("InputLimit") && stderr.contains("applied=NotApplied"),
        "{what}: {stderr}"
    );
}

/// A server whose document allowance is a megabyte and whose signature surcharge is `container`.
fn small_server(pki: &Pki, container: u64) -> Remote {
    Remote::start_with(pki, |config, _| {
        config.input_bytes = LIMIT as u64;
        config.container_bytes = container;
    })
}

/// The proof's `xades-levels` chain at megabyte scale: sign XAdES-T over a document of exactly
/// `input_bytes`, verify the signed result, then extend it keylessly to LT with evidence.
#[test]
fn the_signed_result_of_a_limit_sized_xml_document_verifies_and_extends_over_http() {
    let pki = Pki::start();
    let remote = small_server(&pki, CONTAINER);
    let client = Client::new(&remote);
    let document = client.file("doc.xml", &xml_of(LIMIT));
    let signed = client.path("signed.xml");
    let output = client.sign("xades-t", &document, &signed);
    assert_eq!(exit(&output), 0, "sign: {}", text(&output.stderr));
    let signed_len = std::fs::metadata(&signed).unwrap().len();
    assert!(
        signed_len > LIMIT as u64,
        "the signed result must exceed the document allowance: {signed_len}"
    );

    let output = client.verify("xades-t", &signed);
    assert_eq!(exit(&output), 0, "verify: {}", text(&output.stderr));
    assert_eq!(json(&output)["verdict"], "Valid");

    let extended = client.path("extended.xml");
    let output = client.extend_lt(&pki, "xml", &signed, &extended);
    assert_eq!(exit(&output), 0, "extend: {}", text(&output.stderr));
    assert!(std::fs::metadata(&extended).unwrap().len() > signed_len);
    let output = client.verify("xades-lt", &extended);
    assert_eq!(exit(&output), 0, "verify lt: {}", text(&output.stderr));
    assert_eq!(json(&output)["verdict"], "Valid");
    assert!(
        files(&remote.scratch()).is_empty(),
        "scratch must be empty afterwards"
    );
}

/// The rule is the engine's, not XML's: the CMS and PDF results of a document at the allowance
/// are accepted again by the operations whose engine path classifies signed wire (CMS extract,
/// PDF verify).
#[test]
fn cms_and_pdf_signed_results_of_a_limit_sized_document_are_accepted_again_over_http() {
    let pki = Pki::start();
    // A PAdES signature reserves a large /Contents placeholder: the surcharge of a PDF is
    // bigger than the one of an XML or CMS signature.
    let remote = small_server(&pki, 1 << 20);
    let client = Client::new(&remote);

    let content = payload(LIMIT);
    let document = client.file("doc.bin", &content);
    let signed = client.path("signed.p7s");
    let output = client.sign("cades-b", &document, &signed);
    assert_eq!(exit(&output), 0, "cades sign: {}", text(&output.stderr));
    assert!(std::fs::metadata(&signed).unwrap().len() > LIMIT as u64);
    let extracted = client.path("extracted.bin");
    let output = client.run(&[
        "extract",
        "--input",
        path(&signed),
        "--output",
        path(&extracted),
        "--json",
    ]);
    assert_eq!(exit(&output), 0, "extract: {}", text(&output.stderr));
    assert_eq!(std::fs::read(&extracted).unwrap(), content);

    let pdf = client.file("doc.pdf", &pdf_of(LIMIT));
    let signed = client.path("signed.pdf");
    let output = client.sign("pades-b", &pdf, &signed);
    assert_eq!(exit(&output), 0, "pades sign: {}", text(&output.stderr));
    assert!(std::fs::metadata(&signed).unwrap().len() > LIMIT as u64);
    let output = client.verify("pades-b", &signed);
    assert_eq!(exit(&output), 0, "pades verify: {}", text(&output.stderr));
    assert_eq!(json(&output)["verdict"], "Valid");
    assert!(
        files(&remote.scratch()).is_empty(),
        "scratch must be empty afterwards"
    );
}

/// Only the signature surcharge may pass the document allowance: a document one byte past it
/// is refused whatever follows it, and the surcharge is bounded by `container_bytes`.
#[test]
fn a_document_past_the_allowance_is_refused_with_input_limit_even_when_signed() {
    let pki = Pki::start();
    let remote = small_server(&pki, CONTAINER);
    let client = Client::new(&remote);
    let signed = client.path("signed.xml");
    let exact = client.file("exact.xml", &xml_of(LIMIT));
    let output = client.sign("xades-b", &exact, &signed);
    assert_eq!(
        exit(&output),
        0,
        "sign at the allowance: {}",
        text(&output.stderr)
    );
    let signed_bytes = std::fs::read(&signed).unwrap();
    let surcharge = signed_bytes.len() - LIMIT;
    assert!(
        surcharge > 0 && (surcharge as u64) < CONTAINER,
        "{surcharge}"
    );

    // One document byte past the allowance, signed or not, in any role.
    let over = client.file("over.xml", &xml_of(LIMIT + 1));
    assert_input_limit(
        "sign past the allowance",
        &client.sign("xades-b", &over, &client.path("over.signed.xml")),
    );
    assert_input_limit("hash past the allowance", &client.hash(&over));
    let hashed = client.hash(&exact);
    assert_eq!(
        exit(&hashed),
        0,
        "hash at the allowance: {}",
        text(&hashed.stderr)
    );
    let mut tampered = signed_bytes.clone();
    tampered.insert(b"<r Id=\"d\">".len(), b'a');
    let tampered = client.file("tampered.xml", &tampered);
    assert_input_limit(
        "verify of a signed result one document byte past the allowance",
        &client.verify("xades-b", &tampered),
    );
    let extended = client.path("tampered.lt.xml");
    assert_input_limit(
        "extend of a signed result one document byte past the allowance",
        &client.extend_lt(&pki, "xml", &tampered, &extended),
    );
    assert!(!extended.exists());

    // An unsigned document inside the container allowance is still a document.
    let unsigned = client.file("unsigned.xml", &xml_of(LIMIT + 1024));
    assert_input_limit(
        "verify of an unsigned document past the allowance",
        &client.verify("xades-b", &unsigned),
    );
    // Past `input_bytes + container_bytes` nothing is read any further.
    let hostile = client.file("hostile.xml", &xml_of(LIMIT + CONTAINER as usize + 1));
    assert_input_limit(
        "verify past the allowance and the container allowance",
        &client.verify("xades-b", &hostile),
    );
    assert_input_limit(
        "sign past the allowance and the container allowance",
        &client.sign("xades-b", &hostile, &client.path("hostile.signed.xml")),
    );
    assert!(
        files(&remote.scratch()).is_empty(),
        "scratch must be empty afterwards"
    );

    // The same signed result is refused once its signature is past `container_bytes`.
    let tight = small_server(&pki, 1024);
    let client = Client::new(&tight);
    let signed = client.file("signed.xml", &signed_bytes);
    assert_input_limit(
        "verify of a signature past container_bytes",
        &client.verify("xades-b", &signed),
    );
    assert!(
        files(&tight.scratch()).is_empty(),
        "scratch must be empty afterwards"
    );
}

/// PAdES-LT extension passes the service's memory preflight, which reads the PDF before the
/// engine does: a signed PDF past the allowance must reach both without being charged twice.
#[test]
fn a_pades_t_result_of_a_limit_sized_pdf_extends_to_lt_over_http() {
    let pki = Pki::start();
    let remote = Remote::start_with(&pki, |config, _| {
        config.input_bytes = LIMIT as u64;
        config.container_bytes = 1 << 20;
        config.memory_per_operation = 640 << 20;
        config.total_memory = 1280 << 20;
    });
    let client = Client::new(&remote);
    let pdf = client.file("doc.pdf", &pdf_of(LIMIT));
    let signed = client.path("t.pdf");
    let output = client.sign("pades-t", &pdf, &signed);
    assert_eq!(exit(&output), 0, "pades-t sign: {}", text(&output.stderr));
    assert!(std::fs::metadata(&signed).unwrap().len() > LIMIT as u64);
    let extended = client.path("lt.pdf");
    let output = client.extend_lt(&pki, "pdf", &signed, &extended);
    assert_eq!(
        exit(&output),
        0,
        "pades-lt extend: {}",
        text(&output.stderr)
    );
    let output = client.verify("pades-lt", &extended);
    assert_eq!(
        exit(&output),
        0,
        "pades-lt verify: {}",
        text(&output.stderr)
    );
    assert_eq!(json(&output)["verdict"], "Valid");
    assert!(
        files(&remote.scratch()).is_empty(),
        "scratch must be empty afterwards"
    );
}
