//! `cargo xtask interop-ncanode`: NCANode (Kalkan) checks our XMLDSig and CMS signatures.
//! Linux only; `docs/dev/interop-ncanode.md` describes the run.
//!
//! The pinned NCANode image ([`IMAGE`]) runs in Docker with its default configuration. The
//! xtask signs in process with the synthetic keys (GOST 2015, GOST 2004, RSA) and the
//! NCANode test keys (GOST 2015, GOST 2004), posts the results to `/xml/verify` and
//! `/cms/verify`, has Kalkan sign the same references through `/xml/sign` and compares the
//! digests. The results are a table on stdout; any failed check fails the command.
//!
//! NCANode grades a signature in this order: the signature value (`SIG_CRYPTO_FAILURE`),
//! then the certificate (validity period, trusted issuer, revocation). No key here chains to
//! an NCA root valid today (synthetic roots; expired test certificates), so `valid` is
//! `false`, and a check passes when the grade got past the signature value.
//!
//! NCANode's `/xml/verify` does not register `Id` attributes, so it cannot resolve
//! `URI="#id"`: it fails Kalkan's own element signatures the same way. Element signatures go
//! to it with an internal DTD subset that declares the signed element's `Id` an ID; that
//! changes no canonical form.

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_pki::cms::{self, SignOptions};
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::xmldsig;
use serde_json::{Value, json};
use time::OffsetDateTime;
use ureq::Agent;

/// NCANode 3.5.1 (commit `0adab29a`, the one `fetch-fixtures` pins), pinned by digest.
pub const IMAGE: &str =
    "malikzh/ncanode@sha256:052222f30ac73d9f0060a5c80c572723d25dd84e21073435795a10db254c02b8";
/// Name of the container; a container of that name left by a killed run is removed first.
const CONTAINER: &str = "oncl-ncanode-interop";
/// Docker volume for NCANode's cache (`/app/cache`): the NCA certificates and CRLs it
/// downloads. Kept between runs, so a start after the first one (even a failed one) has
/// fewer downloads left to fail.
const CACHE_VOLUME: &str = "oncl-ncanode-cache";
/// NCANode's HTTP port inside the container.
const NCANODE_PORT: u16 = 14579;
/// How long NCANode gets to report `UP`: at startup it downloads the NCA certificates and
/// CRLs, and its health check waits for them.
const STARTUP: Duration = Duration::from_secs(300);
/// Container starts before giving up (see [`start`]).
const STARTS: u32 = 5;
/// Longest single request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Content of the CMS checks.
const CONTENT: &[u8] = b"OpenNCALayer NCANode interoperability check\r\n\x00\xff";

/// Grades that mean the signature itself was not verified.
const SIGNATURE_FAILURES: [&str; 3] = [
    "SIG_CRYPTO_FAILURE",
    "NO_SIGNING_CERTIFICATE_FOUND",
    "CERT_HASH_MISMATCH",
];

/// An XML document under test: `prolog` then `body`; `element` (in `body`) has the
/// attribute `Id="<id>"` and is signed by element.
struct Doc {
    prolog: &'static str,
    body: &'static str,
    root: &'static str,
    element: &'static str,
    id: &'static str,
}

/// BOM, declaration, comments, CRLF, a default namespace, `xml:lang`, unsorted attributes,
/// an empty element, Cyrillic text.
const AWKWARD: Doc = Doc {
    prolog: "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
    body: "<!-- before the root -->\r\n\
           <root xmlns=\"urn:oncl:interop\" xmlns:b=\"urn:oncl:b\" xml:lang=\"ru\" z=\"1\" b:y=\"2\" a=\"3\">\r\n\
           \x20 <!-- inside -->\r\n\
           \x20 <data c=\"3\" Id=\"payload\" b:attr=\"ж\">Подпись &amp; проверка\r\n  </data>\r\n\
           \x20 <b:empty/>\r\n\
           </root>\r\n",
    root: "root",
    element: "data",
    id: "payload",
};

/// The signed element is nested under two different `xml:lang` values: Canonical XML gives
/// it the outermost one in Kalkan.
const NESTED_LANG: Doc = Doc {
    prolog: "",
    body: "<r xml:lang=\"ru\" xml:space=\"preserve\"><m xml:lang=\"kk\"><e Id=\"e1\">текст</e></m></r>",
    root: "r",
    element: "e",
    id: "e1",
};

impl Doc {
    fn bytes(&self) -> Vec<u8> {
        [self.prolog, self.body].concat().into_bytes()
    }

    fn xpath(&self) -> String {
        format!("//{}", self.element)
    }

    fn reference(&self) -> String {
        format!("#{}", self.id)
    }

    /// `signed` (this document with signatures, which keeps the prolog bytes) with an
    /// internal DTD subset declaring the element's `Id` an ID, for NCANode's `/xml/verify`.
    fn with_id_dtd(&self, signed: &[u8]) -> Vec<u8> {
        let at = self.prolog.len();
        let dtd = format!(
            "<!DOCTYPE {} [<!ATTLIST {} Id ID #IMPLIED>]>",
            self.root, self.element
        );
        [&signed[..at], dtd.as_bytes(), &signed[at..]].concat()
    }
}

/// A key both sides can use: ours from the container, NCANode's as the container itself.
struct Signer {
    label: &'static str,
    entry: KeyEntry,
    p12: Vec<u8>,
    password: String,
}

impl Signer {
    fn load(label: &'static str, p12: Vec<u8>, password: String) -> anyhow::Result<Signer> {
        let entry = oncl_pki::pkcs12::load(&p12, &password)
            .with_context(|| format!("loading {label}"))?
            .into_iter()
            .next()
            .with_context(|| format!("{label} has no key"))?;
        Ok(Signer {
            label,
            entry,
            p12,
            password,
        })
    }

    fn sign_xml(&self, xml: &[u8]) -> anyhow::Result<Vec<u8>> {
        xmldsig::sign_enveloped(xml, &self.entry.key, &self.entry.cert)
            .with_context(|| format!("signing XML with {}", self.label))
    }

    fn sign_xml_element(&self, doc: &Doc, xml: &[u8]) -> anyhow::Result<Vec<u8>> {
        xmldsig::sign_element(xml, &doc.xpath(), None, &self.entry.key, &self.entry.cert)
            .with_context(|| format!("signing an XML element with {}", self.label))
    }

    fn sign_cms(&self, data: &[u8], encapsulate: bool) -> anyhow::Result<Vec<u8>> {
        let opts = SignOptions {
            encapsulate,
            digested: false,
            signing_time: OffsetDateTime::now_utc(),
        };
        cms::sign(&self.entry, data, &opts)
            .with_context(|| format!("signing CMS with {}", self.label))
    }
}

/// The keys: synthetic GOST 2015, GOST 2004, RSA, then NCANode's GOST 2015 and GOST 2004.
fn signers() -> anyhow::Result<Vec<Signer>> {
    let mut signers = Vec::new();
    for (label, name) in [
        ("synthetic GOST 2015", "user-gost2015-sign"),
        ("synthetic GOST 2004", "user-gost2004-sign"),
        ("synthetic RSA", "user-rsa-sign"),
    ] {
        let key = oncl_testkit::synthetic(name);
        signers.push(Signer::load(
            label,
            oncl_testkit::read(&key.path),
            key.password,
        )?);
    }
    for (label, file, password) in [
        ("NCANode GOST 2015", "individual_valid_2015.p12", "Aa123456"),
        (
            "NCANode GOST 2004",
            "individual_valid_sign_2004.p12",
            "Qwerty12",
        ),
    ] {
        let path = crate::fetch::ncanode_dir().join(file);
        ensure!(
            path.is_file(),
            "{} is missing: run `cargo xtask fetch-fixtures`",
            path.display()
        );
        signers.push(Signer::load(
            label,
            oncl_testkit::read(&path),
            password.to_owned(),
        )?);
    }
    Ok(signers)
}

/// Runs the checks and prints the table.
///
/// # Errors
///
/// If Docker or the NCANode fixtures are missing, NCANode does not start, signing fails, or
/// any check fails.
pub fn interop_ncanode() -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        println!("interop с NCANode запускается в Linux");
        return Ok(());
    }
    let signers = signers()?;
    let (_container, node) = start()?;
    let rows = run_checks(&node, &signers)?;
    print!("{}", render_table(&rows));
    let failed = rows.iter().filter(|r| !r.pass).count();
    println!("{} of {} checks passed", rows.len() - failed, rows.len());
    ensure!(failed == 0, "{failed} NCANode checks failed");
    Ok(())
}

fn run_checks(node: &Ncanode, signers: &[Signer]) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    for signer in signers {
        let awkward = AWKWARD.bytes();
        let xml = signer.sign_xml(&awkward)?;
        rows.push(node.verify_xml("XML document", signer.label, &xml, 1));
        let xml = signer.sign_xml_element(&AWKWARD, &awkward)?;
        rows.push(node.verify_xml(
            "XML element #payload",
            signer.label,
            &AWKWARD.with_id_dtd(&xml),
            1,
        ));
        let cms = signer.sign_cms(CONTENT, true)?;
        rows.push(node.verify_cms("CMS attached", signer.label, &cms, None, 1));
        let cms = signer.sign_cms(CONTENT, false)?;
        rows.push(node.verify_cms("CMS detached", signer.label, &cms, Some(CONTENT), 1));
    }

    let [gost2015, _, rsa, nca2015, _] = signers else {
        bail!("expected 5 keys");
    };
    let both = format!("{} + {}", gost2015.label, rsa.label);
    let once = gost2015.sign_xml(&AWKWARD.bytes())?;
    let twice = rsa.sign_xml(&once)?;
    rows.push(
        node.verify_xml("XML document, 2 signatures", "", &twice, 2)
            .keyed(&both),
    );
    let cosigned = rsa.sign_cms(&gost2015.sign_cms(CONTENT, true)?, true)?;
    rows.push(
        node.verify_cms("CMS co-signed", "", &cosigned, None, 2)
            .keyed(&both),
    );

    // Controls: NCANode must reject an altered document and an altered signature value.
    let altered = String::from_utf8(once.clone())?.replacen(" z=\"1\"", " z=\"2\"", 1);
    ensure!(
        altered.as_bytes() != once,
        "the control did not alter the document"
    );
    rows.push(
        node.verify_xml(
            "control: XML document altered",
            gost2015.label,
            altered.as_bytes(),
            1,
        )
        .expect_rejected(),
    );
    let mut altered = gost2015.sign_cms(CONTENT, true)?;
    // No unsigned attributes: the CMS ends with the signature value.
    *altered.last_mut().context("empty CMS")? ^= 1;
    rows.push(
        node.verify_cms(
            "control: CMS signature altered",
            gost2015.label,
            &altered,
            None,
            1,
        )
        .expect_rejected(),
    );

    // Kalkan signs the same reference with the same key: the digests must match.
    rows.push(node.compare_digest(
        "Kalkan digest: XML document",
        nca2015,
        &AWKWARD.bytes(),
        &nca2015.sign_xml(&AWKWARD.bytes())?,
        None,
    ));
    rows.push(node.compare_digest(
        "Kalkan digest: over our signature",
        nca2015,
        &once,
        &nca2015.sign_xml(&once)?,
        None,
    ));
    let nested = NESTED_LANG.bytes();
    let ours = nca2015.sign_xml_element(&NESTED_LANG, &nested)?;
    rows.push(node.compare_digest(
        "Kalkan digest: #e1 under 2 xml:lang",
        nca2015,
        &nested,
        &ours,
        Some(&NESTED_LANG.reference()),
    ));
    rows.push(node.verify_xml(
        "XML element #e1 under 2 xml:lang",
        nca2015.label,
        &NESTED_LANG.with_id_dtd(&ours),
        1,
    ));
    Ok(rows)
}

/// One row of the result table.
#[derive(Debug, PartialEq, Eq)]
struct Row {
    check: String,
    key: String,
    /// The signature (or digest) verdict.
    signature: String,
    /// NCANode's `valid`, `-` where it does not apply.
    valid: String,
    /// NCANode's grade per signature, or other detail.
    detail: String,
    pass: bool,
}

impl Row {
    fn failed(check: &str, key: &str, error: &anyhow::Error) -> Row {
        Row {
            check: check.to_owned(),
            key: key.to_owned(),
            signature: "ERROR".to_owned(),
            valid: "-".to_owned(),
            detail: format!("{error:#}"),
            pass: false,
        }
    }

    fn keyed(mut self, key: &str) -> Row {
        self.key = key.to_owned();
        self
    }

    /// For a control that must fail: passes only if NCANode found the signature value bad.
    fn expect_rejected(mut self) -> Row {
        self.pass = self.signature == "FAIL" && self.detail.contains("SIG_CRYPTO_FAILURE");
        if self.pass {
            self.signature = "FAIL, expected".to_owned();
        } else if self.signature == "OK" {
            self.signature = "OK, expected FAIL".to_owned();
        }
        self
    }
}

/// What NCANode said about a document's signatures.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// Every signature got past the signature value, and there were as many as expected.
    signature_ok: bool,
    valid: bool,
    /// `STATUS/SUBINDICATION` per graded signature, `; `-separated.
    grades: String,
}

impl Outcome {
    fn row(self, check: &str, key: &str) -> Row {
        Row {
            check: check.to_owned(),
            key: key.to_owned(),
            signature: if self.signature_ok { "OK" } else { "FAIL" }.to_owned(),
            valid: self.valid.to_string(),
            detail: self.grades,
            pass: self.signature_ok,
        }
    }
}

/// `(passed the signature value, "STATUS/SUBINDICATION")` of one graded signature.
fn grade(status: Option<&str>, sub: Option<&str>) -> (bool, String) {
    let Some(status) = status else {
        return (false, "no grade".to_owned());
    };
    let text = match sub {
        Some(sub) => format!("{status}/{sub}"),
        None => status.to_owned(),
    };
    (sub.is_none_or(|s| !SIGNATURE_FAILURES.contains(&s)), text)
}

/// `/xml/verify` response: NCANode reports one grade, that of the first signature in the
/// document (it checks the last first), and `valid` over all of them.
fn xml_outcome(response: &Value, expected: usize) -> Outcome {
    let signers = response["signers"].as_array().map_or(0, Vec::len);
    let (ok, text) = grade(
        response["adesStatus"].as_str(),
        response["adesSubIndication"].as_str(),
    );
    Outcome {
        signature_ok: ok && signers == expected,
        valid: response["valid"].as_bool().unwrap_or(false),
        grades: if signers == expected {
            text
        } else {
            format!("{text}; {signers} signers, expected {expected}")
        },
    }
}

/// `/cms/verify` response: a grade per signer.
fn cms_outcome(response: &Value, expected: usize) -> Outcome {
    let signers = response["signers"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let grades: Vec<(bool, String)> = signers
        .iter()
        .map(|s| grade(s["status"].as_str(), s["subIndication"].as_str()))
        .collect();
    let mut text = grades
        .iter()
        .map(|(_, t)| t.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    if signers.len() != expected {
        text.push_str(&format!("; {} signers, expected {expected}", signers.len()));
    }
    Outcome {
        signature_ok: signers.len() == expected && grades.iter().all(|(ok, _)| *ok),
        valid: response["valid"].as_bool().unwrap_or(false),
        grades: text,
    }
}

/// Value of the last `ds:DigestValue` in a signed document (the newest signature's
/// reference: both we and Kalkan append signatures).
fn last_digest_value(xml: &str) -> anyhow::Result<Vec<u8>> {
    const OPEN: &str = "<ds:DigestValue>";
    let start = xml.rfind(OPEN).context("no ds:DigestValue")? + OPEN.len();
    let len = xml[start..]
        .find("</ds:DigestValue>")
        .context("unterminated ds:DigestValue")?;
    let text: String = xml[start..start + len]
        .replace("&#13;", "")
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    STANDARD
        .decode(text)
        .context("ds:DigestValue is not base64")
}

/// A running NCANode.
struct Ncanode {
    base: String,
    agent: Agent,
}

impl Ncanode {
    /// POSTs `body` and returns the JSON response; an HTTP error status is an error.
    fn post(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        let mut response = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .send(body.to_string())
            .with_context(|| format!("POST {path}"))?;
        let status = response.status();
        let text = response
            .body_mut()
            .with_config()
            .limit(64 << 20)
            .read_to_string()
            .with_context(|| format!("reading the response to POST {path}"))?;
        let parsed: Value = serde_json::from_str(&text)
            .with_context(|| format!("POST {path}: not JSON: {text}"))?;
        ensure!(
            status.is_success(),
            "POST {path}: {status}: {}",
            parsed["message"].as_str().unwrap_or(&text)
        );
        Ok(parsed)
    }

    fn verify_xml(&self, check: &str, key: &str, xml: &[u8], expected: usize) -> Row {
        let result = String::from_utf8(xml.to_vec())
            .context("signed XML is not UTF-8")
            .and_then(|xml| self.post("/xml/verify", &json!({ "xml": xml })));
        match result {
            Ok(response) => xml_outcome(&response, expected).row(check, key),
            Err(e) => Row::failed(check, key, &e),
        }
    }

    fn verify_cms(
        &self,
        check: &str,
        key: &str,
        cms: &[u8],
        data: Option<&[u8]>,
        expected: usize,
    ) -> Row {
        let mut body = json!({ "cms": STANDARD.encode(cms) });
        if let Some(data) = data {
            body["data"] = json!(STANDARD.encode(data));
        }
        match self.post("/cms/verify", &body) {
            Ok(response) => cms_outcome(&response, expected).row(check, key),
            Err(e) => Row::failed(check, key, &e),
        }
    }

    /// Has Kalkan sign `input` with `signer` (the whole document, or `reference`) and
    /// compares the new reference digest with the one in `ours`; then checks that our
    /// `verify` accepts Kalkan's document.
    fn compare_digest(
        &self,
        check: &str,
        signer: &Signer,
        input: &[u8],
        ours: &[u8],
        reference: Option<&str>,
    ) -> Row {
        let result = (|| -> anyhow::Result<Row> {
            let mut request = json!({
                "key": STANDARD.encode(&signer.p12),
                "password": signer.password,
            });
            if let Some(reference) = reference {
                request["referenceUri"] = json!(reference);
            }
            let input = std::str::from_utf8(input).context("input XML is not UTF-8")?;
            let response =
                self.post("/xml/sign", &json!({ "xml": input, "signers": [request] }))?;
            let kalkan = response["xml"]
                .as_str()
                .context("/xml/sign returned no xml")?;
            let same = last_digest_value(kalkan)?
                == last_digest_value(std::str::from_utf8(ours).context("our XML is not UTF-8")?)?;
            let (verified, detail) = match xmldsig::verify(kalkan.as_bytes()) {
                Ok(infos) => (
                    true,
                    format!("our verify of Kalkan's XML: OK ({})", infos.len()),
                ),
                Err(e) => (false, format!("our verify of Kalkan's XML: {e}")),
            };
            Ok(Row {
                check: check.to_owned(),
                key: signer.label.to_owned(),
                signature: if same {
                    "digest = Kalkan"
                } else {
                    "digest ≠ Kalkan"
                }
                .to_owned(),
                valid: "-".to_owned(),
                detail,
                pass: same && verified,
            })
        })();
        result.unwrap_or_else(|e| Row::failed(check, signer.label, &e))
    }
}

/// The NCANode container; removed on drop.
struct Container;

impl Container {
    /// Removes the container, also one a killed run left.
    fn remove(&self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", CONTAINER])
            .output();
    }

    /// Starts the container on a free loopback port, with the cache volume.
    fn run(&self) -> anyhow::Result<Ncanode> {
        let publish = format!("127.0.0.1::{NCANODE_PORT}");
        let cache = format!("{CACHE_VOLUME}:/app/cache");
        docker(&[
            "run", "-d", "--name", CONTAINER, "-p", &publish, "-v", &cache, IMAGE,
        ])?;
        let mapped = docker(&["port", CONTAINER, &format!("{NCANODE_PORT}/tcp")])?;
        let address = mapped
            .lines()
            .find(|l| l.starts_with("127.0.0.1:"))
            .with_context(|| format!("unexpected `docker port` output: {mapped}"))?;
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Ok(Ncanode {
            base: format!("http://{address}"),
            agent,
        })
    }

    fn is_running(&self) -> bool {
        docker(&["inspect", "--format", "{{.State.Running}}", CONTAINER])
            .is_ok_and(|state| state == "true")
    }

    /// The last lines of NCANode's log (stdout and stderr).
    fn log_tail(&self) -> String {
        Command::new("docker")
            .args(["logs", "--tail", "30", CONTAINER])
            .output()
            .map(|o| {
                let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&o.stderr));
                text
            })
            .unwrap_or_default()
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Runs `docker <args>` and returns its trimmed stdout.
fn docker(args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .context("running `docker` (install it: `apt-get install -y docker.io` as root)")?;
    ensure!(
        output.status.success(),
        "`docker {}` failed ({}): {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Starts NCANode and waits until it reports `UP`. NCANode exits when it cannot download
/// an NCA certificate at startup (a connection to `pki.gov.kz` timing out now and then):
/// it gets [`STARTS`] attempts, each keeping what the previous ones cached.
fn start() -> anyhow::Result<(Container, Ncanode)> {
    docker(&["version", "--format", "{{.Server.Version}}"])
        .context("the Docker daemon is not available (as root: `service docker start`)")?;
    let container = Container;
    for attempt in 1..=STARTS {
        container.remove();
        let node = container.run()?;
        println!("NCANode {IMAGE} at {}", node.base);
        if wait_up(&container, &node)? {
            return Ok((container, node));
        }
        eprintln!(
            "NCANode exited during startup (attempt {attempt} of {STARTS}); its log:\n{}",
            container.log_tail()
        );
    }
    bail!("NCANode did not start in {STARTS} attempts")
}

/// `true` once NCANode reports `UP`, `false` if its container stopped first.
fn wait_up(container: &Container, node: &Ncanode) -> anyhow::Result<bool> {
    let deadline = Instant::now() + STARTUP;
    loop {
        let last = match node
            .agent
            .get(format!("{}/actuator/health", node.base))
            .call()
        {
            Ok(mut response) => {
                let text = response.body_mut().read_to_string().unwrap_or_default();
                let health: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                if health["status"] == "UP" {
                    return Ok(true);
                }
                format!("{}: {text}", response.status())
            }
            Err(e) => e.to_string(),
        };
        if !container.is_running() {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            bail!(
                "NCANode is not UP after {STARTUP:?} ({last}); its log:\n{}",
                container.log_tail()
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// The table, columns padded to their widest cell.
fn render_table(rows: &[Row]) -> String {
    let header = [
        "#",
        "check",
        "key",
        "signature",
        "valid",
        "NCANode grade / detail",
    ];
    let cells: Vec<[String; 6]> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            [
                (i + 1).to_string(),
                r.check.clone(),
                r.key.clone(),
                r.signature.clone(),
                r.valid.clone(),
                r.detail.clone(),
            ]
        })
        .collect();
    let mut widths = header.map(|h| h.chars().count());
    for row in &cells {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: &[&str]| {
        let padded: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(c, w)| format!("{c}{}", " ".repeat(w - c.chars().count())))
            .collect();
        format!("{}\n", padded.join(" | ").trim_end())
    };
    let mut out = line(&header);
    out.push_str(&line(
        &widths.map(|w| "-".repeat(w)).each_ref().map(String::as_str),
    ));
    for row in &cells {
        out.push_str(&line(&row.each_ref().map(String::as_str)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_value_failures_fail_and_certificate_grades_pass() {
        assert_eq!(
            grade(Some("INDETERMINATE"), Some("CHAIN_INCOMPLETE")),
            (true, "INDETERMINATE/CHAIN_INCOMPLETE".to_owned())
        );
        assert_eq!(grade(Some("VALID"), None), (true, "VALID".to_owned()));
        assert!(!grade(Some("INVALID"), Some("SIG_CRYPTO_FAILURE")).0);
        assert!(!grade(Some("INDETERMINATE"), Some("NO_SIGNING_CERTIFICATE_FOUND")).0);
        assert!(!grade(Some("INVALID"), Some("CERT_HASH_MISMATCH")).0);
        assert!(!grade(None, None).0);
    }

    #[test]
    fn xml_outcome_needs_the_expected_signer_count() {
        let response = json!({
            "valid": false,
            "adesStatus": "INDETERMINATE",
            "adesSubIndication": "OUT_OF_BOUNDS_NO_POE",
            "signers": [{"valid": false}],
        });
        assert_eq!(
            xml_outcome(&response, 1),
            Outcome {
                signature_ok: true,
                valid: false,
                grades: "INDETERMINATE/OUT_OF_BOUNDS_NO_POE".to_owned(),
            }
        );
        let two = xml_outcome(&response, 2);
        assert!(!two.signature_ok);
        assert!(
            two.grades.ends_with("1 signers, expected 2"),
            "{}",
            two.grades
        );
    }

    #[test]
    fn cms_outcome_fails_if_any_signer_fails() {
        let response = json!({
            "valid": false,
            "signers": [
                {"status": "INDETERMINATE", "subIndication": "CHAIN_INCOMPLETE"},
                {"status": "INVALID", "subIndication": "SIG_CRYPTO_FAILURE"},
            ],
        });
        let outcome = cms_outcome(&response, 2);
        assert!(!outcome.signature_ok);
        assert_eq!(
            outcome.grades,
            "INDETERMINATE/CHAIN_INCOMPLETE; INVALID/SIG_CRYPTO_FAILURE"
        );
        assert!(!cms_outcome(&json!({"valid": true, "signers": []}), 1).signature_ok);
    }

    #[test]
    fn last_digest_value_reads_santuario_lines() {
        let xml = "<ds:DigestValue>AAAA</ds:DigestValue>…\
                   <ds:DigestValue>AQID&#13;\nBAU=</ds:DigestValue>";
        assert_eq!(last_digest_value(xml).unwrap(), [1, 2, 3, 4, 5]);
        assert!(last_digest_value("<a/>").is_err());
    }

    #[test]
    fn id_dtd_goes_after_the_prolog_and_keeps_the_signature() {
        let doc = AWKWARD.bytes();
        let key = synthetic_rsa();
        let signed =
            oncl_pki::xmldsig::sign_element(&doc, &AWKWARD.xpath(), None, &key.key, &key.cert)
                .unwrap();
        let with_dtd = AWKWARD.with_id_dtd(&signed);
        let expected = [
            AWKWARD.prolog,
            "<!DOCTYPE root [<!ATTLIST data Id ID #IMPLIED>]>",
            std::str::from_utf8(&signed[AWKWARD.prolog.len()..]).unwrap(),
        ]
        .concat();
        assert_eq!(std::str::from_utf8(&with_dtd).unwrap(), expected);
        assert_eq!(NESTED_LANG.reference(), "#e1");
    }

    #[test]
    fn documents_sign_and_verify_locally() {
        let key = synthetic_rsa();
        for doc in [&AWKWARD, &NESTED_LANG] {
            let xml = doc.bytes();
            let whole = xmldsig::sign_enveloped(&xml, &key.key, &key.cert).unwrap();
            let element =
                xmldsig::sign_element(&xml, &doc.xpath(), None, &key.key, &key.cert).unwrap();
            assert_eq!(xmldsig::verify(&whole).unwrap().len(), 1);
            assert_eq!(xmldsig::verify(&element).unwrap().len(), 1);
            assert!(
                std::str::from_utf8(&element)
                    .unwrap()
                    .contains(&format!("URI=\"{}\"", doc.reference()))
            );
        }
    }

    #[test]
    fn controls_pass_only_on_a_bad_signature_value() {
        let rejected = Outcome {
            signature_ok: false,
            valid: false,
            grades: "INVALID/SIG_CRYPTO_FAILURE".to_owned(),
        };
        let row = rejected.row("control", "k").expect_rejected();
        assert!(row.pass);
        assert_eq!(row.signature, "FAIL, expected");
        let accepted = Outcome {
            signature_ok: true,
            valid: false,
            grades: "INDETERMINATE/CHAIN_INCOMPLETE".to_owned(),
        };
        let row = accepted.row("control", "k").expect_rejected();
        assert!(!row.pass);
        assert_eq!(row.signature, "OK, expected FAIL");
        let error = Row::failed("control", "k", &anyhow::anyhow!("POST /cms/verify: 400"));
        assert!(!error.expect_rejected().pass);
    }

    #[test]
    fn table_pads_columns() {
        let row = Row {
            check: "CMS".to_owned(),
            key: "ключ".to_owned(),
            signature: "OK".to_owned(),
            valid: "false".to_owned(),
            detail: "INDETERMINATE/CHAIN_INCOMPLETE".to_owned(),
            pass: true,
        };
        let table = render_table(&[row]);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[2],
            "1 | CMS   | ключ | OK        | false | INDETERMINATE/CHAIN_INCOMPLETE"
        );
        assert_eq!(lines[0].find("| check"), lines[2].find("| CMS"));
    }

    fn synthetic_rsa() -> KeyEntry {
        let key = oncl_testkit::synthetic("user-rsa-sign");
        oncl_pki::pkcs12::load(&oncl_testkit::read(&key.path), &key.password)
            .unwrap()
            .remove(0)
    }
}
