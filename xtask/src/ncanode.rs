//! `cargo xtask interop-ncanode`: NCANode (Kalkan) checks our XMLDSig and CMS signatures.
//! Linux only; `docs/dev/interop-ncanode.md` describes the run.
//!
//! The pinned NCANode image ([`container::IMAGE`]) runs in Docker with its default
//! configuration. The xtask signs in process with the synthetic keys (GOST 2015, GOST 2004,
//! RSA) and the NCANode test keys (GOST 2015, GOST 2004, RSA), posts the results to
//! `/xml/verify` and `/cms/verify`, has Kalkan sign the same references through `/xml/sign`
//! and compares the digests. The results are a table on stdout; any failed check fails the
//! command.
//!
//! NCANode grades a signature in this order: the signature value (`SIG_CRYPTO_FAILURE`),
//! then the certificate (validity period, trusted issuer, revocation). No key here chains to
//! an NCA root valid today (synthetic roots; expired test certificates), so `valid` is
//! `false`. A check passes when NCANode's grade is exactly the expected one: the
//! certificate grade of the key ([`CHAIN_INCOMPLETE`], [`EXPIRED`]) for a good signature,
//! which NCANode only reaches once the signature value verified, and [`REJECTED`] for the
//! controls, which alter a signed document or a signature.
//!
//! NCANode's `/xml/verify` does not register `Id` attributes, so it cannot resolve
//! `URI="#id"`: it fails Kalkan's own element signatures the same way. Element signatures go
//! to it with an internal DTD subset that declares the signed element's `Id` an ID; that
//! changes no canonical form.

mod container;

use std::time::Duration;

use anyhow::{Context, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_pki::cms::{self, SignOptions};
use oncl_pki::pkcs12::KeyEntry;
use oncl_pki::xmldsig;
use serde_json::{Value, json};
use time::OffsetDateTime;
use ureq::Agent;

/// Longest single request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Content of the CMS checks.
const CONTENT: &[u8] = b"OpenNCALayer NCANode interoperability check\r\n\x00\xff";

/// Grade of a good signature by a synthetic key: no NCA issuer.
const CHAIN_INCOMPLETE: &str = "INDETERMINATE/CHAIN_INCOMPLETE";
/// Grade of a good signature by an NCANode test key: its certificate has expired.
const EXPIRED: &str = "INDETERMINATE/OUT_OF_BOUNDS_NO_POE";
/// Grade of a bad signature value or reference digest.
const REJECTED: &str = "INVALID/SIG_CRYPTO_FAILURE";

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
    /// NCANode's grade of a good signature by this key.
    grade: &'static str,
}

impl Signer {
    fn load(
        label: &'static str,
        p12: Vec<u8>,
        password: String,
        grade: &'static str,
    ) -> anyhow::Result<Signer> {
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
            grade,
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

/// The keys: synthetic GOST 2015, GOST 2004, RSA, then NCANode's GOST 2015, GOST 2004 and
/// RSA. NCANode's `individual_valid_sign_2004.p12` is RSA-2048 despite its name;
/// `ceo_sign_revoked_2004.p12` is its GOST 34.310-2004 key.
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
            CHAIN_INCOMPLETE,
        )?);
    }
    for (label, file, password) in [
        ("NCANode GOST 2015", "individual_valid_2015.p12", "Aa123456"),
        ("NCANode GOST 2004", "ceo_sign_revoked_2004.p12", "Qwerty12"),
        ("NCANode RSA", "individual_valid_sign_2004.p12", "Qwerty12"),
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
            EXPIRED,
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
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .into();
    let (_container, base) = container::start(&agent)?;
    let node = Ncanode { base, agent };
    let rows = run_checks(&node, &signers)?;
    print!("{}", render_table(&rows));
    let failed = rows.iter().filter(|r| !r.pass).count();
    println!("{} of {} checks passed", rows.len() - failed, rows.len());
    ensure!(failed == 0, "{failed} NCANode checks failed");
    Ok(())
}

fn run_checks(node: &Ncanode, signers: &[Signer]) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    let awkward = AWKWARD.bytes();
    for signer in signers {
        let good = Expect::Accepted(signer.grade);
        let xml = signer.sign_xml(&awkward)?;
        rows.push(node.verify_xml("XML document", signer.label, &xml, 1, good));
        let xml = signer.sign_xml_element(&AWKWARD, &awkward)?;
        let xml = AWKWARD.with_id_dtd(&xml);
        rows.push(node.verify_xml("XML element #payload", signer.label, &xml, 1, good));
        let cms = signer.sign_cms(CONTENT, true)?;
        rows.push(node.verify_cms("CMS attached", signer.label, &cms, None, 1, good));
        let cms = signer.sign_cms(CONTENT, false)?;
        rows.push(node.verify_cms("CMS detached", signer.label, &cms, Some(CONTENT), 1, good));
    }

    let [gost2015, _, rsa, nca2015, nca2004, _] = signers else {
        bail!("expected 6 keys");
    };
    let both = format!("{} + {}", gost2015.label, rsa.label);
    let once = gost2015.sign_xml(&awkward)?;
    let twice = rsa.sign_xml(&once)?;
    // NCANode reports the grade of the first signature only (it checks the last first).
    rows.push(
        node.verify_xml(
            "XML 2 signatures: count, 1st graded",
            "",
            &twice,
            2,
            Expect::Accepted(gost2015.grade),
        )
        .keyed(&both),
    );
    let cosigned = rsa.sign_cms(&gost2015.sign_cms(CONTENT, true)?, true)?;
    rows.push(
        node.verify_cms(
            "CMS co-signed",
            "",
            &cosigned,
            None,
            2,
            Expect::Accepted(CHAIN_INCOMPLETE),
        )
        .keyed(&both),
    );

    // Controls: an altered document, element, digest or signature value must be rejected,
    // on the paths the checks above take (DTD for elements, expired NCANode keys).
    let altered = alter(&once, " z=\"1\"", " z=\"2\"")?;
    rows.push(node.verify_xml(
        "control: XML document altered",
        gost2015.label,
        &altered,
        1,
        Expect::Rejected,
    ));
    let element = gost2015.sign_xml_element(&AWKWARD, &awkward)?;
    let altered = AWKWARD.with_id_dtd(&alter(&element, "Подпись", "Подписи")?);
    rows.push(node.verify_xml(
        "control: XML element #payload altered",
        gost2015.label,
        &altered,
        1,
        Expect::Rejected,
    ));
    let nested = NESTED_LANG.bytes();
    let ours = nca2015.sign_xml_element(&NESTED_LANG, &nested)?;
    let altered = NESTED_LANG.with_id_dtd(&alter(&ours, "текст", "тексты")?);
    rows.push(node.verify_xml(
        "control: XML element #e1 altered",
        nca2015.label,
        &altered,
        1,
        Expect::Rejected,
    ));
    let altered = alter_digest_value(&nca2004.sign_xml(&awkward)?)?;
    rows.push(node.verify_xml(
        "control: XML DigestValue altered",
        nca2004.label,
        &altered,
        1,
        Expect::Rejected,
    ));
    for signer in [gost2015, nca2004] {
        let mut altered = signer.sign_cms(CONTENT, true)?;
        // No unsigned attributes: the CMS ends with the signature value.
        *altered.last_mut().context("empty CMS")? ^= 1;
        rows.push(node.verify_cms(
            "control: CMS signature altered",
            signer.label,
            &altered,
            None,
            1,
            Expect::Rejected,
        ));
    }

    // Kalkan signs the same reference with the same key: the digests must match.
    for signer in &signers[3..] {
        rows.push(node.compare_digest(
            "Kalkan digest: XML document",
            signer,
            &awkward,
            &signer.sign_xml(&awkward)?,
            None,
        ));
    }
    rows.push(node.compare_digest(
        "Kalkan digest: over our signature",
        nca2015,
        &once,
        &nca2015.sign_xml(&once)?,
        None,
    ));
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
        Expect::Accepted(nca2015.grade),
    ));
    Ok(rows)
}

/// `xml` with the first `from` replaced by `to`.
fn alter(xml: &[u8], from: &str, to: &str) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(xml).context("signed XML is not UTF-8")?;
    ensure!(
        text.contains(from),
        "the control found no {from:?} to alter"
    );
    Ok(text.replacen(from, to, 1).into_bytes())
}

/// `xml` with the first character of the last `ds:DigestValue` changed (still base64).
fn alter_digest_value(xml: &[u8]) -> anyhow::Result<Vec<u8>> {
    const OPEN: &[u8] = b"<ds:DigestValue>";
    let at = xml
        .windows(OPEN.len())
        .rposition(|w| w == OPEN)
        .context("no ds:DigestValue")?
        + OPEN.len();
    let mut altered = xml.to_vec();
    altered[at] = if altered[at] == b'A' { b'B' } else { b'A' };
    Ok(altered)
}

/// What a check expects of NCANode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// The signature verifies and NCANode grades the certificate so.
    Accepted(&'static str),
    /// NCANode finds the signature value or a reference digest bad: [`REJECTED`].
    Rejected,
}

impl Expect {
    fn grade(self) -> &'static str {
        match self {
            Expect::Accepted(grade) => grade,
            Expect::Rejected => REJECTED,
        }
    }
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
}

/// What NCANode said about a document's signatures.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// Signers NCANode found.
    signers: usize,
    valid: bool,
    /// `STATUS/SUBINDICATION` per graded signature.
    grades: Vec<String>,
}

impl Outcome {
    /// The row: passes if NCANode found `count` signers and graded each as `expect` says.
    fn row(self, check: &str, key: &str, count: usize, expect: Expect) -> Row {
        let expected = expect.grade();
        let graded = !self.grades.is_empty() && self.grades.iter().all(|g| g == expected);
        let pass = graded && self.signers == count;
        let mut detail = self.grades.join("; ");
        if self.signers != count {
            detail.push_str(&format!("; {} signers, expected {count}", self.signers));
        }
        if !graded {
            detail.push_str(&format!("; expected {expected}"));
        }
        let signature = match (pass, expect) {
            (true, Expect::Accepted(_)) => "OK",
            (true, Expect::Rejected) => "rejected, expected",
            (false, _) => "UNEXPECTED",
        };
        Row {
            check: check.to_owned(),
            key: key.to_owned(),
            signature: signature.to_owned(),
            valid: self.valid.to_string(),
            detail,
            pass,
        }
    }
}

/// `STATUS/SUBINDICATION` of one graded signature.
fn grade(status: Option<&str>, sub: Option<&str>) -> String {
    match (status, sub) {
        (None, _) => "no grade".to_owned(),
        (Some(status), None) => status.to_owned(),
        (Some(status), Some(sub)) => format!("{status}/{sub}"),
    }
}

/// `/xml/verify` response: NCANode reports one grade, that of the first signature in the
/// document (it checks the last first), and `valid` over all of them.
fn xml_outcome(response: &Value) -> Outcome {
    Outcome {
        signers: response["signers"].as_array().map_or(0, Vec::len),
        valid: response["valid"].as_bool().unwrap_or(false),
        grades: vec![grade(
            response["adesStatus"].as_str(),
            response["adesSubIndication"].as_str(),
        )],
    }
}

/// `/cms/verify` response: a grade per signer.
fn cms_outcome(response: &Value) -> Outcome {
    let signers = response["signers"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    Outcome {
        signers: signers.len(),
        valid: response["valid"].as_bool().unwrap_or(false),
        grades: signers
            .iter()
            .map(|s| grade(s["status"].as_str(), s["subIndication"].as_str()))
            .collect(),
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

    fn verify_xml(&self, check: &str, key: &str, xml: &[u8], count: usize, expect: Expect) -> Row {
        let result = String::from_utf8(xml.to_vec())
            .context("signed XML is not UTF-8")
            .and_then(|xml| self.post("/xml/verify", &json!({ "xml": xml })));
        match result {
            Ok(response) => xml_outcome(&response).row(check, key, count, expect),
            Err(e) => Row::failed(check, key, &e),
        }
    }

    fn verify_cms(
        &self,
        check: &str,
        key: &str,
        cms: &[u8],
        data: Option<&[u8]>,
        count: usize,
        expect: Expect,
    ) -> Row {
        let mut body = json!({ "cms": STANDARD.encode(cms) });
        if let Some(data) = data {
            body["data"] = json!(STANDARD.encode(data));
        }
        match self.post("/cms/verify", &body) {
            Ok(response) => cms_outcome(&response).row(check, key, count, expect),
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

    fn outcome(signers: usize, grades: &[&str]) -> Outcome {
        Outcome {
            signers,
            valid: false,
            grades: grades.iter().map(|g| (*g).to_owned()).collect(),
        }
    }

    #[test]
    fn grades_join_status_and_subindication() {
        assert_eq!(
            grade(Some("INDETERMINATE"), Some("CHAIN_INCOMPLETE")),
            CHAIN_INCOMPLETE
        );
        assert_eq!(grade(Some("VALID"), None), "VALID");
        assert_eq!(grade(None, Some("X")), "no grade");
    }

    #[test]
    fn accepted_rows_need_the_key_grade_and_the_signer_count() {
        let good = Expect::Accepted(EXPIRED);
        let row = outcome(1, &[EXPIRED]).row("c", "k", 1, good);
        assert!(row.pass);
        assert_eq!(
            (row.signature.as_str(), row.detail.as_str()),
            ("OK", EXPIRED)
        );
        // A grade other than the key's, even one past the signature value, fails.
        let row = outcome(1, &[CHAIN_INCOMPLETE]).row("c", "k", 1, good);
        assert!(!row.pass);
        assert_eq!(row.signature, "UNEXPECTED");
        assert!(
            row.detail.ends_with(&format!("expected {EXPIRED}")),
            "{}",
            row.detail
        );
        assert!(!outcome(1, &[REJECTED]).row("c", "k", 1, good).pass);
        let row = outcome(1, &[EXPIRED]).row("c", "k", 2, good);
        assert!(!row.pass);
        assert!(
            row.detail.ends_with("1 signers, expected 2"),
            "{}",
            row.detail
        );
        assert!(!outcome(0, &[]).row("c", "k", 0, good).pass);
    }

    #[test]
    fn controls_pass_only_on_a_bad_signature_value() {
        let row = outcome(1, &[REJECTED]).row("c", "k", 1, Expect::Rejected);
        assert!(row.pass);
        assert_eq!(row.signature, "rejected, expected");
        let row = outcome(1, &[CHAIN_INCOMPLETE]).row("c", "k", 1, Expect::Rejected);
        assert!(!row.pass);
        assert_eq!(row.signature, "UNEXPECTED");
        let error = Row::failed("c", "k", &anyhow::anyhow!("POST /cms/verify: 400"));
        assert!(!error.pass);
    }

    #[test]
    fn responses_parse_into_outcomes() {
        let xml = json!({
            "valid": false,
            "adesStatus": "INDETERMINATE",
            "adesSubIndication": "OUT_OF_BOUNDS_NO_POE",
            "signers": [{"valid": false}, {"valid": false}],
        });
        assert_eq!(xml_outcome(&xml), outcome(2, &[EXPIRED]));
        let cms = json!({
            "valid": false,
            "signers": [
                {"status": "INDETERMINATE", "subIndication": "CHAIN_INCOMPLETE"},
                {"status": "INVALID", "subIndication": "SIG_CRYPTO_FAILURE"},
            ],
        });
        assert_eq!(cms_outcome(&cms), outcome(2, &[CHAIN_INCOMPLETE, REJECTED]));
        let row = cms_outcome(&cms).row("c", "k", 2, Expect::Accepted(CHAIN_INCOMPLETE));
        assert!(!row.pass);
        assert_eq!(cms_outcome(&json!({"valid": false})), outcome(0, &[]));
    }

    #[test]
    fn last_digest_value_reads_santuario_lines() {
        let xml = "<ds:DigestValue>AAAA</ds:DigestValue>…\
                   <ds:DigestValue>AQID&#13;\nBAU=</ds:DigestValue>";
        assert_eq!(last_digest_value(xml).unwrap(), [1, 2, 3, 4, 5]);
        assert!(last_digest_value("<a/>").is_err());
    }

    #[test]
    fn alterations_change_one_place() {
        let xml = b"<ds:DigestValue>AQID</ds:DigestValue><ds:DigestValue>AAAA</ds:DigestValue>";
        assert_eq!(
            alter_digest_value(xml).unwrap(),
            b"<ds:DigestValue>AQID</ds:DigestValue><ds:DigestValue>BAAA</ds:DigestValue>"
        );
        assert!(alter_digest_value(b"<a/>").is_err());
        assert_eq!(alter(b"<a>x x</a>", "x", "y").unwrap(), b"<a>y x</a>");
        assert!(alter(b"<a/>", "x", "y").is_err());
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
    fn documents_sign_and_verify_locally_and_controls_break_them() {
        let key = synthetic_rsa();
        for (doc, from, to) in [
            (&AWKWARD, "Подпись", "Подписи"),
            (&NESTED_LANG, "текст", "тексты"),
        ] {
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
            assert_eq!(
                xmldsig::verify(&alter(&element, from, to).unwrap()),
                Err(xmldsig::XmlError::BadDigest)
            );
            assert!(xmldsig::verify(&alter_digest_value(&whole).unwrap()).is_err());
        }
    }

    #[test]
    fn table_pads_columns() {
        let row = Row {
            check: "CMS".to_owned(),
            key: "ключ".to_owned(),
            signature: "OK".to_owned(),
            valid: "false".to_owned(),
            detail: CHAIN_INCOMPLETE.to_owned(),
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
