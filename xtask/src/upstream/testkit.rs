//! Synthetic signers of the manifest, for the tests and `cargo xtask upstream make-fixtures`.

use std::path::Path;
use std::str::FromStr;

use anyhow::Context;
use der::asn1::{GeneralizedTime, OctetString};
use der::{DateTime, Encode};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{SignOptions, sign};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_testkit::{read, synthetic, synthetic_cert};
use time::{Date, Month};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::time::{Time, Validity};

/// The synthetic container whose key signs the synthetic manifests.
const SIGNER_KEY: &str = "user-gost2015-sign";
/// The synthetic root that issues the signer.
const ROOT: &str = "root-gost2015";

/// A key of `fixtures/synthetic/<name>.p12`.
pub fn synthetic_entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap_or_else(|e| panic!("synthetic {name}: {e}"))
        .swap_remove(0)
}

/// The synthetic root CA with its key.
pub fn synthetic_root() -> KeyEntry {
    let path = oncl_testkit::fixture(&format!("synthetic/{ROOT}.key.p12"));
    let password = synthetic(SIGNER_KEY).password;
    load(&read(&path), &password)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .swap_remove(0)
}

/// The key of `user-gost2015-sign` with a certificate re-issued by `root-gost2015` to
/// `CN=<common_name>, O=OpenNCALayer synthetic, C=KZ` (serial `0x17000001`,
/// 2026-01-01 – 2036-01-01, keyUsage digitalSignature).
pub fn synthetic_signer(common_name: &str) -> KeyEntry {
    let user = synthetic_entry(SIGNER_KEY);
    let subject = Name::from_str(&format!("CN={common_name},O=OpenNCALayer synthetic,C=KZ"))
        .expect("valid name");
    let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());
    let spec = TestCertSpec {
        subject,
        public_key: user
            .cert
            .tbs_certificate()
            .subject_public_key_info()
            .clone(),
        serial: vec![0x17, 0x00, 0x00, 0x01],
        validity: Validity::new(time(2026), time(2036)),
        extensions: vec![Extension {
            extn_id: der::oid::db::rfc5280::ID_CE_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(key_usage.to_der().expect("KeyUsage encodes"))
                .expect("octets"),
        }],
    };
    let cert = issue_cert(&synthetic_root(), spec);
    KeyEntry {
        alias: common_name.to_owned(),
        key: user.key,
        cert,
    }
}

fn time(year: u16) -> Time {
    Time::GeneralTime(GeneralizedTime::from_date_time(
        DateTime::new(year, 1, 1, 0, 0, 0).expect("valid date"),
    ))
}

/// An attached CMS of `content` by `signer`, signed at 2026-10-01T00:00:00Z.
pub fn sign_manifest(content: &[u8], signer: &KeyEntry) -> Vec<u8> {
    sign(
        signer,
        content,
        &SignOptions {
            encapsulate: true,
            digested: false,
            signing_time: Date::from_calendar_date(2026, Month::October, 1)
                .expect("valid date")
                .midnight()
                .assume_utc(),
        },
    )
    .expect("synthetic signer signs")
}

/// The CAs trusted for the synthetic manifests: `root-gost2015`.
pub fn synthetic_issuers() -> Vec<Certificate> {
    vec![cert::parse(&synthetic_cert(ROOT)).expect("synthetic root parses")]
}

/// Signs `fixtures/upstream/manifest.json` into `fixtures/upstream/manifest.der` under `root`.
///
/// # Errors
///
/// The JSON cannot be read or the file written.
pub fn make_fixtures(root: &Path) -> anyhow::Result<()> {
    let dir = root.join("fixtures").join("upstream");
    let json = std::fs::read(dir.join("manifest.json"))
        .with_context(|| format!("read {}", dir.join("manifest.json").display()))?;
    super::manifest::parse_json(&json).map_err(|e| anyhow::anyhow!("manifest.json: {e}"))?;
    let der = sign_manifest(&json, &synthetic_signer("NCALayer"));
    std::fs::write(dir.join("manifest.der"), der)
        .with_context(|| format!("write {}", dir.join("manifest.der").display()))?;
    println!("fixtures/upstream/manifest.der");
    Ok(())
}
