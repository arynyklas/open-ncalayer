//! The server certificate issued with a (fake, made here) mkcert CA, the renewal advice, the
//! replaced own CAs and the `tls.json` source forms.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use der::{Decode, Encode};
use oncl_tls::{
    MkcertRenewal, RenewError, Renewal, TargetOs, TlsError, TlsFiles, TlsInfo, TlsSource, generate,
    instructions, issue_with_mkcert, load_info, needs_renewal, renew_with_mkcert, replaced_cas,
    save, server_config, set_mkcert_consent,
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rcgen::string::PrintableString;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectAltName, SubjectKeyIdentifier};

const NOW: OffsetDateTime = datetime!(2026-10-24 0:00 UTC);

/// A CAROOT in a fresh temporary directory with an mkcert-like CA (10 years from a year
/// before `NOW`) of `key`: `rootCA.pem` and `rootCA-key.pem`.
struct FakeCaroot {
    dir: tempfile::TempDir,
    ca_der: Vec<u8>,
    key_pem: String,
}

impl FakeCaroot {
    fn new(key: KeyPair) -> FakeCaroot {
        let mut params = CertificateParams::default();
        // As mkcert writes it: O and OU, then CN; Go picks PrintableString where it can.
        params.distinguished_name.push(
            DnType::OrganizationName,
            DnValue::PrintableString(PrintableString::try_from("mkcert development CA").unwrap()),
        );
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, "user@host (Tester)");
        params
            .distinguished_name
            .push(DnType::CommonName, "mkcert user@host (Tester)");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.not_before = NOW - Duration::days(365);
        params.not_after = NOW + Duration::days(9 * 365);
        let ca = params.self_signed(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rootCA.pem"), ca.pem()).unwrap();
        let key_pem = key.serialize_pem();
        std::fs::write(dir.path().join("rootCA-key.pem"), &key_pem).unwrap();
        FakeCaroot {
            dir,
            ca_der: ca.der().to_vec(),
            key_pem,
        }
    }

    fn p256() -> FakeCaroot {
        FakeCaroot::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap())
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

fn parse(der: &[u8]) -> Certificate {
    Certificate::from_der(der).unwrap()
}

fn leaf_der(chain_pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(chain_pem.as_bytes()).unwrap()
}

fn to_time(t: &x509_cert::time::Time) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + t.to_unix_duration()
}

/// Verifies `leaf` under the CA `ca_der` with webpki for a TLS server at `at`.
fn verify(ca_der: &[u8], leaf: &CertificateDer<'_>, at: OffsetDateTime) {
    let ca_der = CertificateDer::from(ca_der.to_vec());
    let anchor = webpki::anchor_from_trusted_cert(&ca_der).unwrap();
    let ee = webpki::EndEntityCert::try_from(leaf).unwrap();
    let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        at.unix_timestamp().try_into().unwrap(),
    ));
    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &[],
        at,
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .unwrap();
    for name in [
        ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        ServerName::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST).into()),
        ServerName::try_from("localhost").unwrap(),
    ] {
        ee.verify_is_valid_for_subject_name(&name).unwrap();
    }
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            found.push(path);
        }
    }
    found
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn leaf_from_a_p256_mkcert_ca() {
    let caroot = FakeCaroot::p256();
    let m = issue_with_mkcert(caroot.path(), NOW).unwrap();
    let leaf = leaf_der(&m.chain_pem);
    verify(&caroot.ca_der, &leaf, NOW);
    verify(&caroot.ca_der, &leaf, NOW + Duration::days(799));

    let ca = parse(&caroot.ca_der);
    let cert = parse(&leaf);
    let tbs = cert.tbs_certificate();
    // The issuer is the CA's subject byte for byte, string types included.
    assert_eq!(
        tbs.issuer().to_der().unwrap(),
        ca.tbs_certificate().subject().to_der().unwrap()
    );
    let (_, san) = tbs.get_extension::<SubjectAltName>().unwrap().unwrap();
    let names: Vec<String> = san
        .0
        .iter()
        .map(|name| match name {
            GeneralName::IpAddress(ip) => format!("ip {:02x?}", ip.as_bytes()),
            GeneralName::DnsName(dns) => format!("dns {dns}"),
            other => panic!("unexpected name {other:?}"),
        })
        .collect();
    assert_eq!(
        names,
        [
            format!("ip {:02x?}", [127u8, 0, 0, 1]),
            format!("ip {:02x?}", Ipv6Addr::LOCALHOST.octets()),
            "dns localhost".to_owned(),
        ]
    );
    let (_, aki) = tbs
        .get_extension::<AuthorityKeyIdentifier>()
        .unwrap()
        .unwrap();
    let (_, ski) = ca
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap();
    assert_eq!(aki.key_identifier, Some(ski.0));

    // At most 800 days including the hour of backdating.
    let not_before = to_time(&tbs.validity().not_before);
    let not_after = to_time(&tbs.validity().not_after);
    assert_eq!(not_before, NOW - Duration::hours(1));
    assert!(not_after - not_before <= Duration::days(800));
    assert_eq!(not_after - not_before, Duration::days(800));

    assert_eq!(
        m.info.source,
        TlsSource::Mkcert {
            caroot: caroot.path().to_path_buf(),
            consented_at: Some("2026-10-24T00:00:00Z".to_owned()),
        }
    );
    assert_eq!(m.ca_der.as_deref(), Some(caroot.ca_der.as_slice()));
    assert_eq!(m.chain_pem.matches("BEGIN CERTIFICATE").count(), 1);
    assert!(!m.chain_pem.contains("PRIVATE KEY"));
}

#[test]
fn leaf_from_an_rsa_mkcert_ca() {
    // mkcert's default CA key is RSA (3072 bits; 2048 keeps the test quick).
    let rsa = rsa::RsaPrivateKey::new(&mut ChaCha20Rng::seed_from_u64(5), 2048).unwrap();
    let pem = rsa.to_pkcs8_pem(LineEnding::LF).unwrap();
    let key = KeyPair::from_pkcs8_pem_and_sign_algo(&pem, &PKCS_RSA_SHA256).unwrap();
    let caroot = FakeCaroot::new(key);
    let m = issue_with_mkcert(caroot.path(), NOW).unwrap();
    verify(&caroot.ca_der, &leaf_der(&m.chain_pem), NOW);
}

#[test]
fn the_mkcert_key_never_reaches_the_data_directory() {
    let caroot = FakeCaroot::p256();
    let data = tempfile::tempdir().unwrap();
    let files = TlsFiles {
        dir: data.path().join("tls"),
    };
    // Over an own CA, so that the replaced CA is written too.
    save(&files, &generate(NOW, "user@host").unwrap()).unwrap();
    let m = issue_with_mkcert(caroot.path(), NOW).unwrap();
    save(&files, &m).unwrap();
    assert_eq!(load_info(&files).unwrap(), Some(m.info.clone()));
    server_config(&files).unwrap();

    let key_der = PrivateKeyDer::from_pem_slice(caroot.key_pem.as_bytes()).unwrap();
    let key_der = key_der.secret_der();
    let all = files_under(data.path());
    assert!(all.len() >= 6, "{all:?}");
    for path in all {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !contains(&bytes, caroot.key_pem.trim().as_bytes()),
            "{}",
            path.display()
        );
        assert!(!contains(&bytes, key_der), "{}", path.display());
        // Not even one line of its base64.
        let line = caroot.key_pem.lines().nth(1).unwrap();
        assert!(!contains(&bytes, line.as_bytes()), "{}", path.display());
    }
}

#[test]
fn a_broken_mkcert_key_leaves_the_certificate_in_use() {
    let caroot = FakeCaroot::p256();
    let data = tempfile::tempdir().unwrap();
    let files = TlsFiles {
        dir: data.path().join("tls"),
    };
    let first = issue_with_mkcert(caroot.path(), NOW).unwrap();
    save(&files, &first).unwrap();
    let before: Vec<(PathBuf, Vec<u8>)> = files_under(data.path())
        .into_iter()
        .map(|p| (p.clone(), std::fs::read(p).unwrap()))
        .collect();

    let key_path = caroot.path().join("rootCA-key.pem");
    let broken = caroot.key_pem.replacen("MI", "XX", 1);
    let other = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .serialize_pem();
    for (key, why) in [
        (Some(broken.as_str()), "cannot parse"),
        (Some("not a key"), "cannot parse"),
        (Some(other.as_str()), "does not belong"),
        (None, "missing"),
    ] {
        match key {
            Some(key) => std::fs::write(&key_path, key).unwrap(),
            None => std::fs::remove_file(&key_path).unwrap(),
        }
        let later = NOW + Duration::days(780);
        match issue_with_mkcert(caroot.path(), later) {
            Err(TlsError::Mkcert(e)) => {
                assert!(e.contains("rootCA-key.pem"), "{why}: {e}");
                if why == "does not belong" {
                    assert!(e.contains("does not belong"), "{e}");
                }
            }
            other => panic!("{why}: {other:?}"),
        }
    }
    // Nothing was written: the server keeps the certificate it has.
    let after: Vec<(PathBuf, Vec<u8>)> = files_under(data.path())
        .into_iter()
        .map(|p| (p.clone(), std::fs::read(p).unwrap()))
        .collect();
    assert_eq!(before, after);
    assert_eq!(load_info(&files).unwrap(), Some(first.info));
    server_config(&files).unwrap();
}

#[test]
fn unusable_mkcert_certificates_are_refused() {
    let caroot = FakeCaroot::p256();
    // Before the CA's start and after its end.
    for at in [NOW - Duration::days(400), NOW + Duration::days(9 * 365)] {
        assert!(
            matches!(issue_with_mkcert(caroot.path(), at), Err(TlsError::Mkcert(e)) if e.contains("valid from")),
            "{at}"
        );
    }
    // A leaf is cut at the CA's end.
    let near_end = NOW + Duration::days(9 * 365 - 100);
    let m = issue_with_mkcert(caroot.path(), near_end).unwrap();
    let cert = parse(&leaf_der(&m.chain_pem));
    assert_eq!(
        to_time(&cert.tbs_certificate().validity().not_after),
        NOW + Duration::days(9 * 365)
    );

    // A certificate that is not a CA.
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    params.not_before = NOW - Duration::days(1);
    params.not_after = NOW + Duration::days(100);
    let leaf = params.self_signed(&key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rootCA.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.path().join("rootCA-key.pem"), key.serialize_pem()).unwrap();
    assert!(matches!(
        issue_with_mkcert(dir.path(), NOW),
        Err(TlsError::Mkcert(e)) if e.contains("not a CA")
    ));
    // No CA at all.
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        issue_with_mkcert(empty.path(), NOW),
        Err(TlsError::Mkcert(e)) if e.contains("rootCA.pem")
    ));
}

fn info(source: TlsSource, not_after: OffsetDateTime) -> TlsInfo {
    TlsInfo {
        source,
        ca_sha1: None,
        ca_sha256: None,
        leaf_sha256: String::new(),
        leaf_not_after: not_after
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        created_at: String::new(),
        generator: String::new(),
    }
}

fn mkcert_source() -> TlsSource {
    TlsSource::Mkcert {
        caroot: PathBuf::from("/ca"),
        consented_at: Some("2026-10-24T00:00:00Z".to_owned()),
    }
}

#[test]
fn renewal_at_60_and_30_days() {
    let end = NOW + Duration::days(100);
    let second = Duration::seconds(1);
    for source in [TlsSource::Own, TlsSource::Imported] {
        let i = info(source.clone(), end);
        assert_eq!(
            needs_renewal(&i, end - Duration::days(60) - second),
            Renewal::None
        );
        assert_eq!(
            needs_renewal(&i, end - Duration::days(60)),
            Renewal::Remind { days: 60 }
        );
        assert_eq!(
            needs_renewal(&i, end - Duration::days(30)),
            Renewal::Remind { days: 30 }
        );
        assert_eq!(
            needs_renewal(&i, end - Duration::hours(1)),
            Renewal::Remind { days: 0 }
        );
        assert_eq!(
            needs_renewal(&i, end + Duration::days(3)),
            Renewal::Remind { days: -3 }
        );
    }
    // Without the consent an mkcert certificate is reminded of like any other.
    let withdrawn = info(
        TlsSource::Mkcert {
            caroot: PathBuf::from("/ca"),
            consented_at: None,
        },
        end,
    );
    assert_eq!(
        needs_renewal(&withdrawn, end - Duration::days(30)),
        Renewal::Remind { days: 30 }
    );
    let i = info(mkcert_source(), end);
    assert_eq!(needs_renewal(&i, end - Duration::days(60)), Renewal::None);
    assert_eq!(
        needs_renewal(&i, end - Duration::days(30) - second),
        Renewal::None
    );
    assert_eq!(
        needs_renewal(&i, end - Duration::days(30)),
        Renewal::AutoRenew
    );
    assert_eq!(
        needs_renewal(&i, end + Duration::days(1)),
        Renewal::AutoRenew
    );

    let unreadable = TlsInfo {
        leaf_not_after: "soon".to_owned(),
        ..info(TlsSource::Own, end)
    };
    assert_eq!(needs_renewal(&unreadable, NOW), Renewal::Remind { days: 0 });
}

#[test]
fn sources_in_tls_json() {
    let end = NOW + Duration::days(100);
    let own = serde_json::to_value(info(TlsSource::Own, end)).unwrap();
    assert_eq!(own["source"], "own");
    // What P4 wrote.
    let mut old = own.clone();
    old["source"] = "generated".into();
    let old: TlsInfo = serde_json::from_value(old).unwrap();
    assert_eq!(old.source, TlsSource::Own);

    let mkcert = info(mkcert_source(), end);
    let json = serde_json::to_value(&mkcert).unwrap();
    assert_eq!(json["source"]["mkcert"]["caroot"], "/ca");
    assert_eq!(
        json["source"]["mkcert"]["consented_at"],
        "2026-10-24T00:00:00Z"
    );
    assert_eq!(serde_json::from_value::<TlsInfo>(json).unwrap(), mkcert);
    // A withdrawn consent is `null`, and so is a missing one.
    let mut json = serde_json::to_value(&mkcert).unwrap();
    json["source"]["mkcert"]
        .as_object_mut()
        .unwrap()
        .remove("consented_at");
    let withdrawn: TlsInfo = serde_json::from_value(json).unwrap();
    assert!(!withdrawn.source.renews_itself());
    assert!(mkcert.source.renews_itself());
    assert_eq!(
        serde_json::to_value(info(TlsSource::Imported, end)).unwrap()["source"],
        "imported"
    );
}

#[test]
fn replaced_own_cas_are_kept_until_removed() {
    let data = tempfile::tempdir().unwrap();
    let files = TlsFiles {
        dir: data.path().join("tls"),
    };
    let first = generate(NOW, "user@host").unwrap();
    save(&files, &first).unwrap();
    // Saving the same set again replaces nothing.
    save(&files, &first).unwrap();
    assert!(replaced_cas(&files).unwrap().is_empty());

    let second = generate(NOW + Duration::days(1), "user@host").unwrap();
    save(&files, &second).unwrap();
    assert_eq!(
        replaced_cas(&files).unwrap(),
        [first.ca_der.clone().unwrap()]
    );

    // mkcert's CA is not ours: replacing it keeps nothing more.
    let caroot = FakeCaroot::p256();
    save(&files, &issue_with_mkcert(caroot.path(), NOW).unwrap()).unwrap();
    let mut expected = vec![
        first.ca_der.clone().unwrap(),
        second.ca_der.clone().unwrap(),
    ];
    let mut kept = replaced_cas(&files).unwrap();
    expected.sort();
    kept.sort();
    assert_eq!(kept, expected);
    save(&files, &generate(NOW, "user@host").unwrap()).unwrap();
    assert_eq!(replaced_cas(&files).unwrap().len(), 2);
}

#[test]
fn instructions_for_mkcert() {
    let caroot = FakeCaroot::p256();
    let m = issue_with_mkcert(caroot.path(), NOW).unwrap();
    let files = TlsFiles {
        dir: PathBuf::from("/data/tls"),
    };
    for os in [TargetOs::Windows, TargetOs::MacOs, TargetOs::Linux] {
        let s = instructions(os, &files, &m.info, 13579);
        assert!(s.contains("mkcert -install"), "{s}");
        assert!(s.contains(&caroot.path().display().to_string()), "{s}");
        assert!(!s.contains("addstore") && !s.contains("certutil -d"), "{s}");
        // Valid until 2028-12-31T23:00Z (800 days from an hour before NOW), renewed by
        // itself 30 days before that.
        assert!(
            s.contains(
                "действует до 31.12.2028 (UTC). OpenNCALayer перевыпустит его сам после 01.12.2028."
            ),
            "{s}"
        );
    }
}

#[test]
fn the_mkcert_consent_is_withdrawn_and_given_in_tls_json() {
    let caroot = FakeCaroot::p256();
    let data = tempfile::tempdir().unwrap();
    let files = TlsFiles {
        dir: data.path().join("tls"),
    };
    assert!(!set_mkcert_consent(&files, None).unwrap());
    save(&files, &generate(NOW, "user@host").unwrap()).unwrap();
    // Only an mkcert certificate has the consent.
    assert!(!set_mkcert_consent(&files, None).unwrap());
    assert_eq!(load_info(&files).unwrap().unwrap().source, TlsSource::Own);

    let m = issue_with_mkcert(caroot.path(), NOW).unwrap();
    save(&files, &m).unwrap();
    assert!(set_mkcert_consent(&files, None).unwrap());
    let info = load_info(&files).unwrap().unwrap();
    assert_eq!(
        info.source,
        TlsSource::Mkcert {
            caroot: caroot.path().to_path_buf(),
            consented_at: None,
        }
    );
    assert_eq!(info.leaf_sha256, m.info.leaf_sha256);
    let late = NOW + Duration::days(790);
    assert!(matches!(needs_renewal(&info, late), Renewal::Remind { .. }));

    let again = "2026-11-01T00:00:00Z".to_owned();
    assert!(set_mkcert_consent(&files, Some(again.clone())).unwrap());
    let info = load_info(&files).unwrap().unwrap();
    assert_eq!(
        info.source,
        TlsSource::Mkcert {
            caroot: caroot.path().to_path_buf(),
            consented_at: Some(again),
        }
    );
    assert_eq!(needs_renewal(&info, late), Renewal::AutoRenew);
    server_config(&files).unwrap();
}

/// Every file under `dir` with its contents.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    files_under(dir)
        .into_iter()
        .map(|p| (p.clone(), std::fs::read(p).unwrap()))
        .collect()
}

#[test]
fn a_renewal_refuses_a_regenerated_mkcert_ca_before_reading_its_key() {
    let caroot = FakeCaroot::p256();
    let data = tempfile::tempdir().unwrap();
    let files = TlsFiles {
        dir: data.path().join("tls"),
    };
    let first = issue_with_mkcert(caroot.path(), NOW).unwrap();
    save(&files, &first).unwrap();
    let before = snapshot(data.path());
    let late = NOW + Duration::days(780);

    // CAROOT now holds another CA; its key file would not even parse if it were read.
    let other = FakeCaroot::p256();
    std::fs::copy(
        other.path().join("rootCA.pem"),
        caroot.path().join("rootCA.pem"),
    )
    .unwrap();
    std::fs::write(caroot.path().join("rootCA-key.pem"), "not a key").unwrap();
    match renew_with_mkcert(&files, late) {
        Err(RenewError::Issue(TlsError::MkcertCaChanged(path))) => {
            assert!(path.ends_with("rootCA.pem"), "{path}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(snapshot(data.path()), before);

    // The CA that issued the certificate is back: it renews, keeping CA and consent.
    std::fs::write(caroot.path().join("rootCA-key.pem"), &caroot.key_pem).unwrap();
    std::fs::write(
        caroot.path().join("rootCA.pem"),
        der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, &caroot.ca_der).unwrap(),
    )
    .unwrap();
    let MkcertRenewal::Renewed(info) = renew_with_mkcert(&files, late).unwrap() else {
        panic!("not renewed");
    };
    assert_eq!(load_info(&files).unwrap().as_ref(), Some(&info));
    assert_ne!(info.leaf_sha256, first.info.leaf_sha256);
    assert_eq!(info.ca_sha256, first.info.ca_sha256);
    assert_eq!(info.source, first.info.source);
    server_config(&files).unwrap();
}

#[test]
fn a_renewal_reads_nothing_when_not_due() {
    let caroot = FakeCaroot::p256();
    let data = tempfile::tempdir().unwrap();
    let files = TlsFiles {
        dir: data.path().join("tls"),
    };
    let late = NOW + Duration::days(780);
    assert_eq!(
        renew_with_mkcert(&files, late).unwrap(),
        MkcertRenewal::NotDue
    );
    save(&files, &issue_with_mkcert(caroot.path(), NOW).unwrap()).unwrap();
    std::fs::write(caroot.path().join("rootCA-key.pem"), "not a key").unwrap();
    let before = snapshot(data.path());
    // Too early.
    assert_eq!(
        renew_with_mkcert(&files, NOW).unwrap(),
        MkcertRenewal::NotDue
    );
    // The consent withdrawn.
    set_mkcert_consent(&files, None).unwrap();
    let withdrawn = snapshot(data.path());
    assert_ne!(withdrawn, before);
    assert_eq!(
        renew_with_mkcert(&files, late).unwrap(),
        MkcertRenewal::NotDue
    );
    assert_eq!(snapshot(data.path()), withdrawn);
    // Not an mkcert certificate.
    save(&files, &generate(NOW, "user@host").unwrap()).unwrap();
    assert_eq!(
        renew_with_mkcert(&files, late).unwrap(),
        MkcertRenewal::NotDue
    );
}
