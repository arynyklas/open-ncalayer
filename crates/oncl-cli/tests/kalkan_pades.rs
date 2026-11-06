//! Kalkan's own PAdES (NCANode `/pdf/sign`, GOST 2015): an ETSI.CAdES.detached CMS whose
//! signed attributes are contentType, signingTime, signingCertificateV2 and messageDigest.
//! Every `--profile pades-*` run must judge the signature itself exactly as `--profile pdf`
//! does and report the signing-time attribute as a PAdES profile finding.
//!
//! The documents are the checksum-pinned NCANode fixtures (`cargo xtask fetch-fixtures`).
mod support;
use serde_json::Value;
use support::*;

const AS_OF: &str = "1788351100";

fn verify(profile: &str, input: &std::path::Path) -> (Option<i32>, Value) {
    let root_test = oncl_testkit::fixture("nca/test/rcagosttest2022.der");
    let root_prod = oncl_testkit::fixture("nca/prod/rcagost22.der");
    let ca_test = oncl_testkit::fixture("nca/test/ncagosttest2022.der");
    let ca_prod = oncl_testkit::fixture("nca/prod/ncagost22.der");
    let out = run(
        &[
            "--json",
            "--offline",
            "--as-of",
            AS_OF,
            "--root",
            path(&root_test),
            "--root",
            path(&root_prod),
            "--intermediate",
            path(&ca_test),
            "--intermediate",
            path(&ca_prod),
            "verify",
            "--profile",
            profile,
            "--input",
            path(input),
        ],
        b"",
    );
    let report = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|error| panic!("{profile}: {error}: {out:?}"));
    (out.status.code(), report)
}

fn reasons(report: &Value) -> String {
    report["signers"][0]["reasons"].as_str().unwrap().to_owned()
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn kalkan_pades_signature_passes_under_pades_profiles_with_a_signing_time_finding() {
    for (level, profile) in [("b", "pades-b"), ("t", "pades-t")] {
        let file = oncl_testkit::ncanode(&format!("sample-signed-{level}.pdf"));
        let (_, generic) = verify("pdf", &file);
        let (code, report) = verify(profile, &file);
        let signer = &report["signers"][0];
        // The cryptographic judgement is the one `--profile pdf` gives the same bytes.
        assert_eq!(generic["signers"][0]["signature"], "Passed", "{level}");
        assert_eq!(signer["signature"], "Passed", "{level}: {report}");
        assert_eq!(signer["chain"], generic["signers"][0]["chain"], "{level}");
        // The signature does not meet the PAdES baseline (EN 319 142-1 table 1) and says so
        // precisely; it is neither malformed nor claims a level.
        assert!(
            reasons(&report).contains("Profile(SigningTimeForbidden)"),
            "{level}: {report}"
        );
        assert!(
            !reasons(&report).contains("Signature("),
            "{level}: {report}"
        );
        assert_eq!(signer["ades_level"], Value::Null, "{level}");
        assert_eq!(report["verdict"], "Invalid", "{level}");
        assert_eq!(code, Some(2), "{level}");
    }
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn tampered_kalkan_pades_fails_with_the_cryptographic_reason_under_every_profile() {
    let original = std::fs::read(oncl_testkit::ncanode("sample-signed-b.pdf")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    // The ByteRange of the fixture: [0 16997 35943 549746]; /Contents is the gap.
    let (first, second) = (16997usize, 35943usize);

    // 1. A covered byte (a digit of the claimed /M date) no longer matches messageDigest.
    let mut content = original.clone();
    let m = content[..first]
        .windows(4)
        .position(|w| w == b"(D:2")
        .expect("claimed signing date")
        + 10;
    content[m] = if content[m] == b'1' { b'2' } else { b'1' };
    // 2. The signature value (first bytes of the GOST signature in /Contents) is altered;
    //    messageDigest and the ByteRange digest still match.
    let mut forged = original.clone();
    let signature = b"c9f5ed423f2c5a45";
    let at = forged[first..second]
        .windows(signature.len())
        .position(|w| w.eq_ignore_ascii_case(signature))
        .expect("signature value in /Contents")
        + first;
    forged[at] = if forged[at] == b'c' || forged[at] == b'C' {
        b'd'
    } else {
        b'c'
    };
    for profile in ["pdf", "pades-b"] {
        for (name, bytes) in [("content", &content), ("signature", &forged)] {
            let file = dir.path().join(format!("{profile}-{name}.pdf"));
            std::fs::write(&file, bytes).unwrap();
            let (code, report) = verify(profile, &file);
            let signer = &report["signers"][0];
            assert_eq!(signer["signature"], "Failed", "{profile}/{name}: {report}");
            assert_eq!(code, Some(2), "{profile}/{name}");
            assert!(
                reasons(&report).contains(if name == "content" {
                    "Signature(DigestMismatch)"
                } else {
                    "Signature(BadSignature)"
                }),
                "{profile}/{name}: {report}"
            );
        }
        // A ByteRange that no longer excludes exactly the physical /Contents is refused
        // before a signature verdict can be issued, under both profiles.
        let mut shifted = original.clone();
        let needle = b"/ByteRange [0 16997 ";
        let at = shifted
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("first ByteRange length")
            + needle.len()
            - 2;
        shifted[at] = b'8';
        let file = dir.path().join(format!("{profile}-byterange.pdf"));
        std::fs::write(&file, shifted).unwrap();
        let out = run(
            &[
                "--json",
                "verify",
                "--profile",
                profile,
                "--input",
                path(&file),
            ],
            b"",
        );
        assert_eq!(out.status.code(), Some(1), "{profile}: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("InvalidInput"),
            "{profile}: {out:?}"
        );
    }
}
