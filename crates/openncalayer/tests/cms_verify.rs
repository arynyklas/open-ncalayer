//! `cms-verify`: certification paths, validity at the proven signing time and revocation,
//! against the synthetic intermediate PKI with in-process OCSP, CRL and TSA mocks; the
//! command itself (flags, `--chain` files, exit codes) through the built binary, without
//! the network.

use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{SignOptions, sign};
use oncl_pki::crl::MockCrl;
use oncl_pki::http::{HttpTransport, RouteTransport};
use oncl_pki::info::cert_info;
use oncl_pki::ocsp::{CertStatus, MockOcsp, OcspTamper};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_pki::tsp::{MockTsa, TsaProfile, timestamp_signer};
use oncl_testkit::{fixture, read, synthetic, synthetic_cert};
use openncalayer::cms_verify::{
    NO_PROOF_OF_TIME, NO_REVOCATION_DATA, NOT_CHECKED, Online, Options, cms_verify_report_with,
};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;
use tempfile::TempDir;
use time::OffsetDateTime;
use time::macros::datetime;

const OCSP_URL: &str = "http://ocsp.synthetic.test";
/// The CRL distribution point of the intermediate CA's certificate.
const ROOT_CRL: &str = "http://crl.synthetic.test/root-gost2015.crl";
/// id-pe-authorityInfoAccess.
const AIA: &str = "1.3.6.1.5.5.7.1.1";

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

/// An attached CMS of `key` with signingTime `signing_time`, time-stamped by `tsa` if
/// given.
fn signed_by(key: &KeyEntry, signing_time: OffsetDateTime, tsa: Option<&MockTsa>) -> Vec<u8> {
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time,
    };
    let cms = sign(key, b"cms-verify", &opts).unwrap();
    match tsa {
        Some(tsa) => timestamp_signer(&cms, 0, &TsaProfile::basics_default(), tsa).unwrap(),
        None => cms,
    }
}

/// [`signed_by`] the synthetic key `signer`.
fn signed(signer: &str, signing_time: OffsetDateTime, tsa: Option<&MockTsa>) -> Vec<u8> {
    signed_by(&entry(signer), signing_time, tsa)
}

/// A TSA whose tokens have genTime `gen_time`.
fn tsa_at(gen_time: OffsetDateTime) -> MockTsa {
    MockTsa::new(entry("tsa-gost2015")).with_gen_time(gen_time)
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
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

/// A fresh directory under the target directory, removed when dropped.
fn temp_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("oncl-cms-verify-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// The report on `cms` (no detached content) and whether it is `OK`: revocation through
/// `http` with the CRL cache in `crl_dir`, or offline.
fn report(cms: &[u8], cas: CaSet, online: Option<(&dyn HttpTransport, &Path)>) -> (String, bool) {
    let opts = Options {
        cas,
        online: online.map(|(http, crl_dir)| Online {
            http,
            crl_dir: crl_dir.to_path_buf(),
        }),
        now: now(),
    };
    cms_verify_report_with(cms, None, &opts)
}

/// [`report`] against the synthetic CAs through `net`.
fn report_net(cms: &[u8], net: &Net, crl_dir: &Path) -> (String, bool) {
    report(cms, synthetic_cas(), Some((&net.http, crl_dir)))
}

/// The lines of a one-signer report after `signer 0: …`, the last line included.
fn body(report: &str) -> Vec<&str> {
    report.lines().skip(1).collect()
}

/// The `revocation:` line of a report.
fn revocation_line(report: &str) -> &str {
    report
        .lines()
        .find(|l| l.starts_with("revocation: "))
        .unwrap()
}

#[test]
fn ok_with_synthetic_chain_and_good_ocsp_and_crl() {
    let cms = signed("inter-user-gost2015-sign", now(), Some(&tsa_at(now())));
    let net = Net::good();
    let dir = temp_dir();
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines.len(), 6, "{text}");
    assert_eq!(lines[0], "timestamp: yes");
    assert_eq!(lines[1], inter_chain());
    assert!(lines[2].starts_with("validity: ok at 20"), "{text}");
    assert_eq!(lines[3], tsa_chain());
    assert_eq!(lines[4], "revocation: good (ocsp, crl)");
    assert_eq!(lines[5], "OK");
    assert!(!text.contains("not checked"), "{text}");

    // The signer by OCSP, the intermediate CA by the root's CRL, which is cached.
    assert_eq!(net.ocsp.calls().len(), 1);
    assert!(net.ocsp.calls()[0].starts_with(&format!("{OCSP_URL}/")));
    assert_eq!(net.crl.calls(), [ROOT_CRL]);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    let (again, ok) = report_net(&cms, &net, dir.path());
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

    // Revoked before the time-stamp.
    let tsa = tsa_at(datetime!(2025-06-01 00:00 UTC));
    let cms = signed("inter-revoked-gost2015-sign", now(), Some(&tsa));
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[0], "timestamp: yes");
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[2], "validity: ok at 2025-06-01T00:00:00Z");
    assert_eq!(lines[3], tsa_chain());
    assert_eq!(lines[4], "revocation: revoked 2025-04-01T00:00:00Z (ocsp)");
    assert_eq!(
        lines[5],
        "FAIL: certificate of signer 0 is revoked at 2025-04-01T00:00:00Z (ocsp)"
    );
    assert_eq!(lines.len(), 6, "{text}");

    // Revoked after it: the signature stays valid.
    let tsa = tsa_at(datetime!(2025-03-01 00:00 UTC));
    let cms = signed("inter-revoked-gost2015-sign", now(), Some(&tsa));
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[2], "validity: ok at 2025-03-01T00:00:00Z");
    assert_eq!(
        lines[4],
        "revocation: revoked 2025-04-01T00:00:00Z after signing (ocsp)"
    );
    assert_eq!(lines[5], "OK");

    // Without a time-stamp, revoked now: FAIL whatever signingTime says after the
    // revocation, INDETERMINATE when it claims a time before it.
    let cms = signed("inter-revoked-gost2015-sign", now(), None);
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(!ok, "{text}");
    assert_eq!(
        text.lines().last(),
        Some("FAIL: certificate of signer 0 is revoked at 2025-04-01T00:00:00Z (ocsp)")
    );
    let backdated = datetime!(2025-03-01 00:00 UTC);
    let cms = signed("inter-revoked-gost2015-sign", backdated, None);
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[0], "timestamp: no");
    assert!(lines[2].starts_with("validity: ok at "), "{text}");
    assert_ne!(
        lines[2], "validity: ok at 2025-03-01T00:00:00Z",
        "now, not signingTime"
    );
    assert_eq!(lines[3], "revocation: revoked 2025-04-01T00:00:00Z (ocsp)");
    assert_eq!(lines[4], NO_PROOF_OF_TIME);
    assert!(
        text.starts_with("signer 0: CN=")
            && text
                .lines()
                .next()
                .unwrap()
                .ends_with("signingTime=2025-03-01T00:00:00Z"),
        "signingTime is still printed: {text}"
    );
}

#[test]
fn revoked_intermediate_by_crl_fails() {
    let inter = cer("inter-gost2015");
    let inter_serial = inter.tbs_certificate().serial_number().as_bytes().to_vec();
    let revoked_at = datetime!(2025-02-01 00:00 UTC);
    let net = Net::new(ocsp(), root_crl().revoke(&inter_serial, revoked_at));
    let dir = temp_dir();
    let cms = signed("inter-user-gost2015-sign", now(), Some(&tsa_at(now())));
    let (text, ok) = report_net(&cms, &net, dir.path());
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

    // Revoked after the time-stamp: OK, and still shown when another status is unknown.
    let later = datetime!(2025-09-01 00:00 UTC);
    let cms = signed(
        "inter-user-gost2015-sign",
        now(),
        Some(&tsa_at(datetime!(2025-06-01 00:00 UTC))),
    );
    let net = Net::new(ocsp(), root_crl().revoke(&inter_serial, later));
    let (text, ok) = report_net(&cms, &net, temp_dir().path());
    assert!(ok, "{text}");
    assert_eq!(
        revocation_line(&text),
        "revocation: revoked 2025-09-01T00:00:00Z after signing (crl)"
    );
    let net = Net::new(
        ocsp().tamper(OcspTamper::HttpStatus(503)),
        root_crl().revoke(&inter_serial, later),
    );
    let (text, ok) = report_net(&cms, &net, temp_dir().path());
    assert!(!ok, "{text}");
    assert_eq!(
        revocation_line(&text),
        "revocation: unavailable (OCSP responder answered HTTP status 503), revoked \
         2025-09-01T00:00:00Z after signing (crl)"
    );
    assert_eq!(text.lines().last(), Some(NO_REVOCATION_DATA));
}

#[test]
fn ocsp_down_is_indeterminate_exit_1() {
    let cms = signed("inter-user-gost2015-sign", now(), Some(&tsa_at(now())));
    let dir = temp_dir();
    let indeterminate = |net: &Net| {
        let (text, ok) = report_net(&cms, net, dir.path());
        assert!(!ok, "{text}");
        assert_eq!(text.lines().last(), Some(NO_REVOCATION_DATA), "{text}");
        let line = revocation_line(&text).to_owned();
        assert!(line.starts_with("revocation: unavailable ("), "{text}");
        line
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
    // The responder does not know the signer.
    let signer = entry("inter-user-gost2015-sign").cert;
    assert_eq!(
        indeterminate(&Net::new(
            ocsp().status(&serial_hex(&signer), CertStatus::Unknown),
            root_crl()
        )),
        "revocation: unavailable (OCSP responder does not know the certificate)"
    );
    // No CRL of the intermediate CA, the signer good.
    let no_crl = RouteTransport::new(vec![(
        OCSP_URL.to_owned(),
        Arc::new(ocsp()) as Arc<dyn HttpTransport>,
    )]);
    let (text, ok) = report(
        &cms,
        synthetic_cas(),
        Some((&no_crl, &dir.path().join("empty"))),
    );
    assert!(!ok, "{text}");
    assert_eq!(
        revocation_line(&text),
        format!(
            "revocation: unavailable (CRL of CA certificate CN={}: HTTP request to the CRL \
             distribution point failed: no route)",
            cn(&cer("inter-gost2015"))
        )
    );
    assert_eq!(text.lines().last(), Some(NO_REVOCATION_DATA), "{text}");
}

#[test]
fn revocation_edge_cases() {
    let inter_user = entry("inter-user-gost2015-sign");
    let dir = temp_dir();

    // A signer certificate without AuthorityInfoAccess: no OCSP responder to ask.
    let mut spec = TestCertSpec::from_cert(&inter_user.cert);
    spec.extensions.retain(|e| e.extn_id.to_string() != AIA);
    let no_aia = KeyEntry {
        cert: issue_cert(&entry("inter-gost2015.key"), spec),
        ..inter_user.clone()
    };
    let net = Net::good();
    let cms = signed_by(&no_aia, now(), Some(&tsa_at(now())));
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(!ok, "{text}");
    assert_eq!(
        revocation_line(&text),
        "revocation: unavailable (certificate has no OCSP responder URL)"
    );
    assert_eq!(text.lines().last(), Some(NO_REVOCATION_DATA));
    assert!(net.ocsp.calls().is_empty());

    // Issued by the root itself: no CA between the signer and the anchor, no CRL.
    let under_root = KeyEntry {
        cert: issue_cert(
            &entry("root-gost2015.key"),
            TestCertSpec::from_cert(&inter_user.cert),
        ),
        ..inter_user.clone()
    };
    let net = Net::good();
    let cms = signed_by(&under_root, now(), Some(&tsa_at(now())));
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], format!("chain: {}", cn(&cer("root-gost2015"))));
    assert_eq!(lines[4], "revocation: good (ocsp)");
    assert!(net.crl.calls().is_empty());

    // The signer certificate is a trust anchor of the set.
    let net = Net::good();
    let cms = signed("root-gost2015.key", now(), None);
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], format!("chain: {}", cn(&cer("root-gost2015"))));
    assert!(lines[2].starts_with("validity: ok at "), "{text}");
    assert_eq!(
        lines[3],
        "revocation: unavailable (signer certificate is a trust anchor)"
    );
    assert_eq!(lines[4], NO_REVOCATION_DATA);
    assert!(net.ocsp.calls().is_empty() && net.crl.calls().is_empty());
}

#[test]
fn offline_reports_not_checked_revocation() {
    let cms = signed("inter-user-gost2015-sign", now(), Some(&tsa_at(now())));
    let (text, ok) = report(&cms, synthetic_cas(), None);
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[3], tsa_chain());
    assert_eq!(lines[4], "revocation: not checked (--offline)");
    assert_eq!(lines[5], NOT_CHECKED);
    assert_eq!(NOT_CHECKED, "not checked: revocation");
    assert_eq!(lines[6], "OK");
}

#[test]
fn default_roots_reject_synthetic_chain() {
    let cms = signed("inter-user-gost2015-sign", now(), Some(&tsa_at(now())));
    let net = Net::good();
    let dir = temp_dir();
    let (text, ok) = report(&cms, CaSet::nca_production(), Some((&net.http, dir.path())));
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
    // Valid 2025-01-01 … 2026-01-01, under CAs valid 2025-01-01 … 2099.
    let signer = "inter-expired-gost2015-sign";
    let net = Net::good();
    let dir = temp_dir();
    let june = datetime!(2025-06-01 00:00 UTC);
    assert!(now() > datetime!(2026-01-01 00:00 UTC));

    // genTime of the token, whatever signingTime says.
    let cms = signed(signer, now(), Some(&tsa_at(june)));
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[2], "validity: ok at 2025-06-01T00:00:00Z");
    assert_eq!(lines[3], tsa_chain());
    assert_eq!(lines[4], "revocation: good (ocsp, crl)");
    assert_eq!(lines[5], "OK");

    // Without a token, signingTime inside the validity proves nothing: the chain still
    // builds (at notAfter), the certificate is expired now.
    let cms = signed(signer, june, None);
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert!(
        lines[2].starts_with("validity: not valid at 20")
            && lines[2].ends_with(", no proof of signing time (signingTime 2025-06-01T00:00:00Z)"),
        "{text}"
    );
    assert_eq!(text.lines().last(), Some(NO_PROOF_OF_TIME));

    // Without a token and with signingTime outside the validity too: expired.
    let cms = signed(signer, now(), None);
    let (text, ok) = report_net(&cms, &net, dir.path());
    assert!(!ok, "{text}");
    assert_eq!(body(&text)[2], "validity: FAIL");
    assert!(
        text.lines()
            .last()
            .unwrap()
            .starts_with("FAIL: certificate of signer 0 is not valid at 20"),
        "{text}"
    );

    // A time-stamp before the certificate's validity: the chain is built inside the
    // validity, so the failure is the validity, not the chain.
    let before = datetime!(2024-06-01 00:00 UTC);
    let cms = signed("inter-user-gost2015-sign", before, Some(&tsa_at(before)));
    let (text, ok) = report(&cms, synthetic_cas(), None);
    assert!(!ok, "{text}");
    let lines = body(&text);
    assert_eq!(lines[1], inter_chain());
    assert_eq!(lines[2], "validity: FAIL");
    assert_eq!(lines[3], "tsa chain: FAIL NotValidAt { index: 0 }");
    assert_eq!(
        text.lines().last(),
        Some("FAIL: certificate of signer 0 is not valid at 2024-06-01T00:00:00Z")
    );
}

/// `openncalayer cms-verify <file> <args>` with the data directory `data`, or with no data
/// directory variable at all.
fn cms_verify_command(file: &Path, args: &[&std::ffi::OsStr], data: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openncalayer"));
    command.arg("cms-verify").arg(file).args(args);
    match data {
        Some(data) => command.env("ONCL_DATA_DIR", data),
        None => command
            .env_remove("ONCL_DATA_DIR")
            .env_remove("APPDATA")
            .env_remove("HOME")
            .env_remove("XDG_DATA_HOME"),
    };
    command.output().unwrap()
}

/// Stdout of `out` and its exit code.
fn outcome(out: &Output) -> (String, Option<i32>) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code(),
    )
}

#[test]
fn command_exit_codes_and_chain_files() {
    let cms = signed("inter-user-gost2015-sign", now(), Some(&tsa_at(now())));
    let dir = temp_dir();
    let file = dir.path().join("signature.p7s");
    std::fs::write(&file, &cms).unwrap();
    let pem = |name: &str| oncl_pki::pem::encode("CERTIFICATE", &synthetic_cert(name));
    // Both CAs in one PEM file, the intermediate first.
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, pem("inter-gost2015") + &pem("root-gost2015")).unwrap();
    let root_pem = dir.path().join("root.pem");
    std::fs::write(&root_pem, pem("root-gost2015")).unwrap();
    let inter_der = fixture("synthetic/inter-gost2015.cer");
    let arg = |s: &'static str| std::ffi::OsStr::new(s);
    let offline = arg("--offline");
    let chain = arg("--chain");

    // Exit 1 without the network: the embedded NCA set does not know the synthetic PKI.
    let (stdout, code) = outcome(&cms_verify_command(&file, &[], Some(dir.path())));
    assert_eq!(code, Some(1), "{stdout}");
    assert!(
        stdout.contains("\nchain: FAIL IssuerNotFound\n"),
        "{stdout}"
    );
    assert_eq!(
        stdout.lines().last(),
        Some("FAIL: certificate chain of signer 0: issuer certificate not found")
    );

    // Exit 0 offline, with a PEM bundle or a DER and a PEM file; no data directory needed.
    let expected_tail = format!(
        "\n{}\n{}\nrevocation: not checked (--offline)\n{NOT_CHECKED}\nOK\n",
        inter_chain(),
        tsa_chain()
    );
    for args in [
        vec![chain, bundle.as_os_str(), offline],
        vec![
            chain,
            inter_der.as_os_str(),
            chain,
            root_pem.as_os_str(),
            offline,
        ],
    ] {
        let (stdout, code) = outcome(&cms_verify_command(&file, &args, None));
        assert_eq!(code, Some(0), "{stdout}");
        let without_validity: String = stdout
            .lines()
            .filter(|l| !l.starts_with("validity: "))
            .map(|l| format!("{l}\n"))
            .collect();
        assert!(without_validity.ends_with(&expected_tail), "{stdout}");
    }

    // Unreadable or unparsable `--chain` files.
    let missing = dir.path().join("missing.der");
    let (stdout, code) = outcome(&cms_verify_command(
        &file,
        &[chain, missing.as_os_str(), offline],
        None,
    ));
    assert_eq!(code, Some(1), "{stdout}");
    assert!(
        stdout.starts_with(&format!("FAIL: {}: ", missing.display())),
        "{stdout}"
    );
    // A key instead of a certificate.
    let garbage = dir.path().join("key.pem");
    let key_pem = [
        "-----BEGIN ",
        "PRIVATE KEY-----\nMAM=\n-----END ",
        "PRIVATE KEY-----\n",
    ];
    std::fs::write(&garbage, key_pem.concat()).unwrap();
    let (stdout, code) = outcome(&cms_verify_command(
        &file,
        &[chain, garbage.as_os_str(), offline],
        None,
    ));
    assert_eq!(code, Some(1), "{stdout}");
    assert_eq!(
        stdout,
        format!(
            "FAIL: {}: PEM block PRIVATE KEY is not a CERTIFICATE\n",
            garbage.display()
        )
    );

    // A BEGIN line one dash short, alone or in a bundle with a valid root, is an error: the
    // block is never skipped, so the root cannot silently drop out of the trust set.
    let short =
        |name: &str| pem(name).replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE----");
    for (name, contents) in [
        ("short.pem", short("root-gost2015")),
        (
            "inter-short-root.pem",
            pem("inter-gost2015") + &short("root-gost2015"),
        ),
        (
            "root-short-inter.pem",
            pem("root-gost2015") + &short("inter-gost2015"),
        ),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        let (stdout, code) = outcome(&cms_verify_command(
            &file,
            &[chain, path.as_os_str(), offline],
            None,
        ));
        assert_eq!(code, Some(1), "{stdout}");
        assert_eq!(
            stdout,
            format!(
                "FAIL: {}: PEM: malformed line \"-----BEGIN CERTIFICATE----\"\n",
                path.display()
            )
        );
    }
}

/// The command over the real network: the synthetic `.test` services never resolve, so
/// revocation is unavailable.
#[test]
#[ignore = "network: resolves ocsp.synthetic.test and crl.synthetic.test"]
fn live_cms_verify_command_without_revocation_services() {
    let cms = signed("inter-user-gost2015-sign", now(), Some(&tsa_at(now())));
    let dir = temp_dir();
    let file = dir.path().join("signature.p7s");
    std::fs::write(&file, &cms).unwrap();
    let inter = fixture("synthetic/inter-gost2015.cer");
    let root = fixture("synthetic/root-gost2015.cer");
    let chain = std::ffi::OsStr::new("--chain");
    let out = cms_verify_command(
        &file,
        &[chain, inter.as_os_str(), chain, root.as_os_str()],
        Some(dir.path()),
    );
    let (stdout, code) = outcome(&out);
    assert_eq!(code, Some(1), "{stdout}");
    assert_eq!(stdout.lines().last(), Some(NO_REVOCATION_DATA), "{stdout}");
}
