//! `cms-verify`: certification paths, validity at the validation time and revocation,
//! against the synthetic intermediate PKI with in-process OCSP, CRL and TSA mocks; the
//! command itself (flags, exit codes) through the built binary.

use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{SignOptions, sign};
use oncl_pki::crl::MockCrl;
use oncl_pki::http::{HttpTransport, RouteTransport};
use oncl_pki::info::cert_info;
use oncl_pki::ocsp::{CertStatus, MockOcsp, OcspTamper};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::{MockTsa, TsaProfile, timestamp_signer};
use oncl_testkit::{fixture, read, synthetic, synthetic_cert};
use openncalayer::cli::{CmsVerifyOptions, NOT_CHECKED, cms_verify_report_with};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use tempfile::TempDir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;

const OCSP_URL: &str = "http://ocsp.synthetic.test";
/// The CRL distribution point of the intermediate CA's certificate.
const ROOT_CRL: &str = "http://crl.synthetic.test/root-gost2015.crl";
const INDETERMINATE: &str = "INDETERMINATE: revocation data unavailable";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

fn cn(cert: &Certificate) -> String {
    cert_info(cert).subject_cn.unwrap()
}

fn serial_hex(cert: &Certificate) -> String {
    let serial = cert.tbs_certificate().serial_number().as_bytes();
    serial.iter().map(|b| format!("{b:02x}")).collect()
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap()
}

/// The synthetic intermediate CA and its root.
fn synthetic_cas() -> CaSet {
    CaSet::new(vec![cer("inter-gost2015"), cer("root-gost2015")])
}

/// `chain:` of a key issued by the intermediate CA.
fn inter_chain() -> String {
    format!(
        "chain: {} -> {}",
        cn(&cer("inter-gost2015")),
        cn(&cer("root-gost2015"))
    )
}

/// `tsa chain:` of the synthetic TSA, issued by the root.
fn tsa_chain() -> String {
    format!("tsa chain: {}", cn(&cer("root-gost2015")))
}

/// An attached CMS of the key `signer` with signingTime `signing_time`, time-stamped by
/// `tsa` if given.
fn signed(signer: &str, signing_time: OffsetDateTime, tsa: Option<&MockTsa>) -> Vec<u8> {
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time,
    };
    let cms = sign(&entry(signer), b"cms-verify", &opts).unwrap();
    match tsa {
        Some(tsa) => timestamp_signer(&cms, 0, &TsaProfile::basics_default(), tsa).unwrap(),
        None => cms,
    }
}

fn tsa() -> MockTsa {
    MockTsa::new(entry("tsa-gost2015"))
}

fn ocsp() -> MockOcsp {
    MockOcsp::new(entry("ocsp-gost2015"))
}

/// The distribution point of the root's CRL, where the intermediate CA is looked up.
fn root_crl() -> MockCrl {
    MockCrl::new(entry("root-gost2015.key"))
}

/// The revocation services of the synthetic PKI.
struct Net {
    ocsp: Arc<MockOcsp>,
    crl: Arc<MockCrl>,
    http: RouteTransport,
}

impl Net {
    fn new(ocsp: MockOcsp, crl: MockCrl) -> Net {
        let (ocsp, crl) = (Arc::new(ocsp), Arc::new(crl));
        let http = RouteTransport::new(vec![
            (OCSP_URL.to_owned(), ocsp.clone() as Arc<dyn HttpTransport>),
            (ROOT_CRL.to_owned(), crl.clone() as Arc<dyn HttpTransport>),
        ]);
        Net { ocsp, crl, http }
    }

    fn good() -> Net {
        Net::new(ocsp(), root_crl())
    }
}

/// A fresh data directory under the target directory, removed when dropped.
fn temp_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("oncl-cms-verify-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// The report on `cms` (no detached content) and whether it is `OK`, with the CRL cache in
/// `crl_dir`.
fn report(
    cms: &[u8],
    cas: CaSet,
    http: &dyn HttpTransport,
    crl_dir: &Path,
    offline: bool,
) -> (String, bool) {
    let opts = CmsVerifyOptions {
        cas,
        http,
        crl_dir: crl_dir.to_path_buf(),
        offline,
        now: OffsetDateTime::now_utc(),
    };
    cms_verify_report_with(cms, None, &opts)
}

/// The lines of a one-signer report after `signer 0: …`, the last line included.
fn body(report: &str) -> Vec<&str> {
    report.lines().skip(1).collect()
}

#[test]
fn ok_with_synthetic_chain_and_good_ocsp_and_crl() {
    let cms = signed(
        "inter-user-gost2015-sign",
        OffsetDateTime::now_utc(),
        Some(&tsa()),
    );
    let net = Net::good();
    let dir = temp_dir();
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines.len(), 6, "{text}");
    assert_eq!(lines[0], "timestamp: yes");
    assert_eq!(lines[1], inter_chain());
    assert!(lines[2].starts_with("validity: ok at 20"), "{text}");
    assert_eq!(lines[3], tsa_chain());
    assert_eq!(lines[4], "revocation: good (ocsp)");
    assert_eq!(lines[5], "OK");
    assert!(!text.contains("not checked"), "{text}");

    // The signer by OCSP, the intermediate CA by the root's CRL, which is cached.
    assert_eq!(net.ocsp.calls().len(), 1);
    assert!(net.ocsp.calls()[0].starts_with(&format!("{OCSP_URL}/")));
    assert_eq!(net.crl.calls(), [ROOT_CRL]);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    let (again, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(ok, "{again}");
    assert_eq!(net.ocsp.calls().len(), 2);
    assert_eq!(net.crl.calls().len(), 1, "the cached CRL is used");
}

#[test]
fn revoked_signer_fails() {
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let at = datetime!(2025-04-01 00:00 UTC);
    let net = Net::new(
        ocsp().status(
            &serial_hex(&revoked),
            CertStatus::Revoked {
                time: at,
                reason: Some(1),
            },
        ),
        root_crl(),
    );
    let dir = temp_dir();

    // Revoked before the validation time (signingTime: no time-stamp).
    let cms = signed("inter-revoked-gost2015-sign", at, None);
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[0], "timestamp: no");
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[2], "validity: ok at 2025-04-01T00:00:00Z");
    assert_eq!(lines[3], "revocation: revoked 2025-04-01T00:00:00Z (ocsp)");
    assert_eq!(
        lines[4],
        "FAIL: certificate of signer 0 is revoked at 2025-04-01T00:00:00Z (ocsp)"
    );
    assert_eq!(lines.len(), 5, "{text}");

    // Revoked after it: the signature stays valid.
    let cms = signed(
        "inter-revoked-gost2015-sign",
        at - time::Duration::DAY,
        None,
    );
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[2], "validity: ok at 2025-03-31T00:00:00Z");
    assert_eq!(
        lines[3],
        "revocation: revoked 2025-04-01T00:00:00Z after signing (ocsp)"
    );
    assert_eq!(lines[4], "OK");
}

#[test]
fn revoked_intermediate_by_crl_fails() {
    let inter = cer("inter-gost2015");
    let at = datetime!(2025-02-01 00:00 UTC);
    let net = Net::new(
        ocsp(),
        root_crl().revoke(inter.tbs_certificate().serial_number().as_bytes(), at),
    );
    let dir = temp_dir();
    let cms = signed(
        "inter-user-gost2015-sign",
        OffsetDateTime::now_utc(),
        Some(&tsa()),
    );
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[4], "revocation: revoked 2025-02-01T00:00:00Z (crl)");
    assert_eq!(
        lines[5],
        format!(
            "FAIL: CA certificate CN={} in the chain of signer 0 is revoked at \
             2025-02-01T00:00:00Z (crl)",
            cn(&inter)
        )
    );
}

#[test]
fn ocsp_down_is_indeterminate_exit_1() {
    let cms = signed(
        "inter-user-gost2015-sign",
        OffsetDateTime::now_utc(),
        Some(&tsa()),
    );
    let dir = temp_dir();
    let indeterminate = |net: &Net| {
        let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
        assert!(!ok, "{text}");
        assert_eq!(text.lines().last(), Some(INDETERMINATE), "{text}");
        let revocation = text
            .lines()
            .find(|l| l.starts_with("revocation: "))
            .unwrap()
            .to_owned();
        assert!(
            revocation.starts_with("revocation: unavailable ("),
            "{text}"
        );
        revocation
    };

    assert_eq!(
        indeterminate(&Net::new(
            ocsp().tamper(OcspTamper::HttpStatus(503)),
            root_crl()
        )),
        "revocation: unavailable (OCSP responder answered HTTP status 503)"
    );
    // Forged or unusable answers: never `revoked`, never `good`.
    for tamper in [
        OcspTamper::Garbage,
        OcspTamper::WrongKey,
        OcspTamper::NoCerts,
        OcspTamper::OtherResponderId,
        OcspTamper::OtherCertId,
        OcspTamper::Stale,
        OcspTamper::FutureThisUpdate,
    ] {
        indeterminate(&Net::new(ocsp().tamper(tamper), root_crl()));
    }
    assert_eq!(
        indeterminate(&Net::new(
            MockOcsp::new(entry("ocsp-nocheckless-gost2015")),
            root_crl()
        )),
        "revocation: unavailable (OCSP responder certificate lacks id-pkix-ocsp-nocheck)"
    );
    // A responder that is not one, so without OCSPSigning; the cause is printed.
    assert_eq!(
        indeterminate(&Net::new(
            MockOcsp::new(entry("inter-user-gost2015-sign")),
            root_crl()
        )),
        "revocation: unavailable (OCSP responder certificate lacks the OCSPSigning extended \
         key usage)"
    );
    // No CRL of the intermediate CA, the signer good.
    let no_crl = RouteTransport::new(vec![(
        OCSP_URL.to_owned(),
        Arc::new(ocsp()) as Arc<dyn HttpTransport>,
    )]);
    let (text, ok) = report(
        &cms,
        synthetic_cas(),
        &no_crl,
        &dir.path().join("empty"),
        false,
    );
    assert!(!ok, "{text}");
    assert!(
        text.contains(&format!(
            "\nrevocation: unavailable (CRL of CA certificate CN={}: HTTP request to the CRL \
             distribution point failed: no route)\n",
            cn(&cer("inter-gost2015"))
        )),
        "{text}"
    );
    assert_eq!(text.lines().last(), Some(INDETERMINATE), "{text}");

    // The command: the `.test` services do not resolve, so revocation is unavailable and the
    // exit code is 1; `--offline` gives `OK` and 0.
    let data = temp_dir();
    let file = data.path().join("signature.p7s");
    std::fs::write(&file, &cms).unwrap();
    let out = cms_verify_command(&file, data.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert_eq!(stdout.lines().last(), Some(INDETERMINATE), "{stdout}");
    let out = cms_verify_command(&file, data.path(), &["--offline"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.ends_with(&format!(
            "revocation: not checked (--offline)\n{NOT_CHECKED}\nOK\n"
        )),
        "{stdout}"
    );
}

/// `openncalayer cms-verify <file> --chain <inter DER> --chain <root PEM> <extra>` with the
/// data directory `data`.
fn cms_verify_command(file: &Path, data: &Path, extra: &[&str]) -> Output {
    let root_pem = data.join("root.pem");
    std::fs::write(
        &root_pem,
        oncl_pki::pem::encode("CERTIFICATE", &synthetic_cert("root-gost2015")),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_openncalayer"))
        .arg("cms-verify")
        .arg(file)
        .arg("--chain")
        .arg(fixture("synthetic/inter-gost2015.cer"))
        .arg("--chain")
        .arg(&root_pem)
        .args(extra)
        .env("ONCL_DATA_DIR", data)
        .output()
        .unwrap()
}

#[test]
fn offline_reports_not_checked_revocation() {
    let cms = signed(
        "inter-user-gost2015-sign",
        OffsetDateTime::now_utc(),
        Some(&tsa()),
    );
    let net = Net::good();
    let dir = temp_dir();
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), true);
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[3], tsa_chain());
    assert_eq!(lines[4], "revocation: not checked (--offline)");
    assert_eq!(lines[5], NOT_CHECKED);
    assert_eq!(NOT_CHECKED, "not checked: revocation");
    assert_eq!(lines[6], "OK");
    assert!(net.ocsp.calls().is_empty());
    assert!(net.crl.calls().is_empty());
}

#[test]
fn default_roots_reject_synthetic_chain() {
    let cms = signed(
        "inter-user-gost2015-sign",
        OffsetDateTime::now_utc(),
        Some(&tsa()),
    );
    let net = Net::good();
    let dir = temp_dir();
    let (text, ok) = report(&cms, CaSet::nca_production(), &net.http, dir.path(), false);
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], "chain: FAIL IssuerNotFound");
    assert!(lines[2].starts_with("validity: ok at "), "{text}");
    assert_eq!(lines[3], "tsa chain: FAIL IssuerNotFound");
    assert_eq!(lines[4], "revocation: unavailable (no certification path)");
    assert_eq!(
        lines[5],
        "FAIL: certificate chain of signer 0: issuer certificate not found"
    );
    assert!(net.ocsp.calls().is_empty());
    assert!(net.crl.calls().is_empty());
}

#[test]
fn validity_uses_timestamp_time() {
    // Valid 2025-01-01 … 2026-01-01, under CAs valid until 2099.
    let signer = "inter-expired-gost2015-sign";
    let net = Net::good();
    let dir = temp_dir();
    let now = OffsetDateTime::now_utc();
    let gen_time = datetime!(2025-06-01 00:00 UTC);
    assert!(now > datetime!(2026-01-01 00:00 UTC));

    // genTime of the token, though signingTime is now.
    let tsa = tsa().with_gen_time(gen_time);
    let cms = signed(signer, now, Some(&tsa));
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[2], "validity: ok at 2025-06-01T00:00:00Z");
    assert_eq!(lines[3], tsa_chain());
    assert_eq!(lines[4], "revocation: good (ocsp)");
    assert_eq!(lines[5], "OK");

    // signingTime without a token.
    let cms = signed(signer, gen_time, None);
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(ok, "{text}");
    assert!(
        text.contains("\nvalidity: ok at 2025-06-01T00:00:00Z\n"),
        "{text}"
    );

    // signingTime after notAfter: the chain still builds (at notAfter), the key is expired.
    let cms = signed(signer, now, None);
    let (text, ok) = report(&cms, synthetic_cas(), &net.http, dir.path(), false);
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[2], "validity: FAIL");
    let signing_time = rfc3339(now.replace_nanosecond(0).unwrap());
    assert_eq!(
        text.lines().last(),
        Some(format!("FAIL: certificate of signer 0 is not valid at {signing_time}").as_str()),
        "{text}"
    );
}
