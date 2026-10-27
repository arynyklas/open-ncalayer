//! Local TLS wizard backend: generated CA/leaf profile, webpki verification, import checks,
//! files and rustls server config, trust instructions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use der::asn1::ObjectIdentifier as Oid;
use der::{Decode, Encode};
use oncl_tls::{
    TargetOs, TlsError, TlsFiles, TlsInfo, TlsSource, TlsWarning, forget_replaced_ca, generate,
    import, instructions, load_info, nss_nickname, replaced_cas, save, server_config, sha1_grouped,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    SignatureAlgorithm,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use x509_cert::Certificate;
use x509_cert::der::EncodePem;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints as X509BasicConstraints, ExtendedKeyUsage,
    NameConstraints, SubjectAltName, SubjectKeyIdentifier,
};

const NOW: OffsetDateTime = datetime!(2026-10-24 0:00 UTC);

const NAME_CONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.30");
const BASIC_CONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.19");
const KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.15");
const EXT_KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.37");
const SUBJECT_KEY_ID: Oid = Oid::new_unwrap("2.5.29.14");
const AUTHORITY_KEY_ID: Oid = Oid::new_unwrap("2.5.29.35");
const SUBJECT_ALT_NAME: Oid = Oid::new_unwrap("2.5.29.17");
const SERVER_AUTH: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.1");
const ECDSA_WITH_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");

/// NameConstraints ::= SEQUENCE { permittedSubtrees [0] { 127.0.0.1/32, ::1/128, localhost } }
/// with no `excludedSubtrees` field.
const EXPECTED_NAME_CONSTRAINTS: &str = concat!(
    "303fa03d",
    "300a87087f000001ffffffff",
    "30228720",
    "00000000000000000000000000000001",
    "ffffffffffffffffffffffffffffffff",
    "300b8209",
    "6c6f63616c686f7374",
);

#[derive(Debug, PartialEq)]
enum Gn {
    Ip(Vec<u8>),
    Dns(String),
}

fn ip(hex_str: &str) -> Gn {
    Gn::Ip(unhex(hex_str))
}

fn dns(name: &str) -> Gn {
    Gn::Dns(name.to_owned())
}

fn general(name: &GeneralName) -> Gn {
    match name {
        GeneralName::IpAddress(octets) => Gn::Ip(octets.as_bytes().to_vec()),
        GeneralName::DnsName(name) => Gn::Dns(name.to_string()),
        other => panic!("unexpected general name {other:?}"),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse(der: &[u8]) -> Certificate {
    Certificate::from_der(der).unwrap()
}

fn first_cert(pem: &str) -> Certificate {
    Certificate::load_pem_chain(pem.as_bytes())
        .unwrap()
        .remove(0)
}

fn ext(cert: &Certificate, oid: Oid) -> Extension {
    let found: Vec<&Extension> = cert
        .tbs_certificate()
        .extensions()
        .unwrap()
        .iter()
        .filter(|e| e.extn_id == oid)
        .collect();
    assert_eq!(found.len(), 1, "extension {oid}");
    found[0].clone()
}

fn has_ext(cert: &Certificate, oid: Oid) -> bool {
    cert.tbs_certificate()
        .extensions()
        .is_some_and(|exts| exts.iter().any(|e| e.extn_id == oid))
}

fn permitted(nc: &Extension) -> Vec<Gn> {
    let nc = NameConstraints::from_der(nc.extn_value.as_bytes()).unwrap();
    nc.permitted_subtrees
        .unwrap()
        .iter()
        .map(|subtree| {
            assert_eq!(subtree.minimum, 0);
            assert!(subtree.maximum.is_none());
            general(&subtree.base)
        })
        .collect()
}

/// The NameConstraints SEQUENCE holds exactly one element, `[0]` (permittedSubtrees).
fn excluded_field_absent(nc: &Extension) -> bool {
    let raw = nc.extn_value.as_bytes();
    let decoded = NameConstraints::from_der(raw).unwrap();
    raw[0] == 0x30
        && usize::from(raw[1]) == raw.len() - 2
        && raw[2] == 0xa0
        && usize::from(raw[3]) + 2 == usize::from(raw[1])
        && decoded.excluded_subtrees.is_none()
}

fn path_len(cert: &Certificate) -> Option<u8> {
    let (_, bc) = cert
        .tbs_certificate()
        .get_extension::<X509BasicConstraints>()
        .unwrap()
        .unwrap();
    assert!(bc.ca);
    bc.path_len_constraint
}

fn to_time(t: &x509_cert::time::Time) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + t.to_unix_duration()
}

fn not_before(cert: &Certificate) -> OffsetDateTime {
    to_time(&cert.tbs_certificate().validity().not_before)
}

fn not_after(cert: &Certificate) -> OffsetDateTime {
    to_time(&cert.tbs_certificate().validity().not_after)
}

fn days(cert: &Certificate) -> i64 {
    (not_after(cert) - not_before(cert)).whole_days()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

fn sha1_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn spki_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap()
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("oncl-tls-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn generated_ca_profile() {
    let m = generate(NOW, "user@host").unwrap();
    let ca = parse(m.ca_der.as_ref().unwrap());
    let nc = ext(&ca, NAME_CONSTRAINTS);
    assert!(nc.critical);
    assert_eq!(
        permitted(&nc),
        vec![
            ip("7f000001ffffffff"),
            ip("00000000000000000000000000000001ffffffffffffffffffffffffffffffff"),
            dns("localhost"),
        ]
    );
    assert!(excluded_field_absent(&nc));
    assert_eq!(hex(nc.extn_value.as_bytes()), EXPECTED_NAME_CONSTRAINTS);
    assert_eq!(path_len(&ca), Some(0));
    let leaf = first_cert(&m.chain_pem);
    assert!(days(&leaf) <= 800);
    assert_eq!(not_after(&ca), not_after(&leaf) + Duration::days(1));
    assert!(
        !m.chain_pem.contains("PRIVATE KEY")
            && m.ca_pem.as_ref().unwrap().find("PRIVATE").is_none()
    );

    // Subject, issuer, serial, validity.
    let tbs = ca.tbs_certificate();
    let subject = tbs.subject().to_string();
    assert!(
        subject.contains("CN=OpenNCALayer Local CA (user@host 2026-10-24)"),
        "{subject}"
    );
    assert!(
        subject.contains("O=OpenNCALayer (this computer only)"),
        "{subject}"
    );
    assert_eq!(tbs.issuer(), tbs.subject());
    assert_eq!(tbs.serial_number().as_bytes().len(), 16);
    assert_eq!(not_before(&ca), NOW - Duration::hours(1));

    // basicConstraints critical CA:TRUE pathLen 0; keyUsage critical keyCertSign + cRLSign.
    assert!(ext(&ca, BASIC_CONSTRAINTS).critical);
    let ku = ext(&ca, KEY_USAGE);
    assert!(ku.critical);
    assert_eq!(hex(ku.extn_value.as_bytes()), "03020106");
    // EKU serverAuth; SKI present.
    let eku = ExtendedKeyUsage::from_der(ext(&ca, EXT_KEY_USAGE).extn_value.as_bytes()).unwrap();
    assert_eq!(eku.0, vec![SERVER_AUTH]);
    let ski =
        SubjectKeyIdentifier::from_der(ext(&ca, SUBJECT_KEY_ID).extn_value.as_bytes()).unwrap();
    assert!(!ski.0.as_bytes().is_empty());

    // ECDSA P-256 with SHA-256.
    assert_eq!(ca.signature_algorithm().oid, ECDSA_WITH_SHA256);
    let spki = tbs.subject_public_key_info();
    assert_eq!(spki.algorithm.oid, EC_PUBLIC_KEY);
    let curve: Oid = spki
        .algorithm
        .parameters
        .as_ref()
        .unwrap()
        .decode_as()
        .unwrap();
    assert_eq!(curve, SECP256R1);

    // PEM and DER forms of the CA are the same certificate.
    let ca_from_pem =
        CertificateDer::from_pem_slice(m.ca_pem.as_ref().unwrap().as_bytes()).unwrap();
    assert_eq!(ca_from_pem.as_ref(), m.ca_der.as_deref().unwrap());
}

#[test]
fn generated_leaf_profile() {
    let m = generate(NOW, "user@host").unwrap();
    let ca = parse(m.ca_der.as_ref().unwrap());
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(m.chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    assert_eq!(chain.len(), 1, "chain_pem holds only the leaf");
    let leaf = parse(&chain[0]);
    let tbs = leaf.tbs_certificate();
    assert_eq!(tbs.subject().to_string(), "CN=127.0.0.1");
    assert_eq!(tbs.issuer(), ca.tbs_certificate().subject());
    assert_eq!(tbs.serial_number().as_bytes().len(), 16);
    assert_eq!(not_before(&leaf), NOW - Duration::hours(1));
    assert_eq!(not_after(&leaf) - not_before(&leaf), Duration::days(800));

    let san = SubjectAltName::from_der(ext(&leaf, SUBJECT_ALT_NAME).extn_value.as_bytes()).unwrap();
    let san: Vec<Gn> = san.0.iter().map(general).collect();
    assert_eq!(
        san,
        vec![
            ip("7f000001"),
            ip("00000000000000000000000000000001"),
            dns("localhost")
        ]
    );
    let eku = ExtendedKeyUsage::from_der(ext(&leaf, EXT_KEY_USAGE).extn_value.as_bytes()).unwrap();
    assert_eq!(eku.0, vec![SERVER_AUTH]);
    let ku = ext(&leaf, KEY_USAGE);
    assert!(ku.critical);
    assert_eq!(
        hex(ku.extn_value.as_bytes()),
        "03020780",
        "digitalSignature only"
    );
    let bc = ext(&leaf, BASIC_CONSTRAINTS);
    assert_eq!(hex(bc.extn_value.as_bytes()), "3000", "CA:FALSE");
    assert!(!has_ext(&leaf, NAME_CONSTRAINTS));

    // AKI of the leaf is the SKI of the CA; the leaf has its own SKI.
    let ca_ski =
        SubjectKeyIdentifier::from_der(ext(&ca, SUBJECT_KEY_ID).extn_value.as_bytes()).unwrap();
    let aki = AuthorityKeyIdentifier::from_der(ext(&leaf, AUTHORITY_KEY_ID).extn_value.as_bytes())
        .unwrap();
    assert_eq!(aki.key_identifier.unwrap(), ca_ski.0);
    let leaf_ski =
        SubjectKeyIdentifier::from_der(ext(&leaf, SUBJECT_KEY_ID).extn_value.as_bytes()).unwrap();
    assert_ne!(leaf_ski.0, ca_ski.0);

    // The private key is the leaf's, P-256 PKCS#8.
    assert!(m.key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    let key = PrivateKeyDer::from_pem_slice(m.key_pem.as_bytes()).unwrap();
    let signer = rustls::crypto::ring::sign::any_ecdsa_type(&key).unwrap();
    assert_eq!(
        signer.public_key().unwrap().as_ref(),
        spki_der(&leaf).as_slice()
    );

    // Info.
    let info = &m.info;
    assert_eq!(info.source, TlsSource::Own);
    assert_eq!(
        info.ca_sha1.as_deref(),
        Some(sha1_hex(m.ca_der.as_ref().unwrap()).as_str())
    );
    assert_eq!(
        info.ca_sha256.as_deref(),
        Some(sha256_hex(m.ca_der.as_ref().unwrap()).as_str())
    );
    assert_eq!(info.leaf_sha256, sha256_hex(&chain[0]));
    assert_eq!(info.leaf_not_after, rfc3339(not_after(&leaf)));
    assert_eq!(info.created_at, rfc3339(NOW));
    assert!(info.generator.starts_with("OpenNCALayer "));
    assert!(m.warnings.is_empty());

    // Two runs produce different keys and serials.
    let other = generate(NOW, "user@host").unwrap();
    assert_ne!(other.ca_der, m.ca_der);
    assert_ne!(*other.key_pem, *m.key_pem);
}

#[test]
fn leaf_verifies_under_ca_with_rustls_webpki() {
    let m = generate(NOW, "user@host").unwrap();
    let ca_der = CertificateDer::from(m.ca_der.clone().unwrap());
    let anchor = webpki::anchor_from_trusted_cert(&ca_der).unwrap();
    assert!(anchor.name_constraints.is_some());
    let leaf_der = CertificateDer::from_pem_slice(m.chain_pem.as_bytes()).unwrap();
    let ee = webpki::EndEntityCert::try_from(&leaf_der).unwrap();
    let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        (NOW + Duration::days(1))
            .unix_timestamp()
            .try_into()
            .unwrap(),
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
    assert!(
        ee.verify_is_valid_for_subject_name(&ServerName::try_from("example.com").unwrap())
            .is_err()
    );
}

/// A leaf (plus its issuing test CA as the second chain element) made by rcgen.
fn leaf(
    alg: &'static SignatureAlgorithm,
    sans: &[&str],
    server_auth: bool,
    from: OffsetDateTime,
    valid_days: i64,
) -> (String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test Issuing CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let key = KeyPair::generate_for(alg).unwrap();
    let mut params =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "imported");
    if server_auth {
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    }
    params.not_before = from;
    params.not_after = from + Duration::days(valid_days);
    let cert = params.signed_by(&key, &issuer).unwrap();
    (format!("{}{}", cert.pem(), ca.pem()), key.serialize_pem())
}

fn good_leaf() -> (String, String) {
    leaf(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &["127.0.0.1", "localhost"],
        true,
        NOW - Duration::days(1),
        365,
    )
}

fn der_len(len: usize) -> Vec<u8> {
    match len {
        0..0x80 => vec![len as u8],
        0x80..0x100 => vec![0x81, len as u8],
        _ => vec![0x82, (len >> 8) as u8, len as u8],
    }
}

/// Re-wraps the first certificate of `chain_pem` with an `ecdsa-with-SHA1` signatureAlgorithm.
fn with_sha1_signature(chain_pem: &str) -> String {
    let cert = first_cert(chain_pem);
    let tbs = cert.tbs_certificate().to_der().unwrap();
    let alg = unhex("300906072a8648ce3d0401");
    let sig = unhex("0303000102");
    let mut content = tbs;
    content.extend_from_slice(&alg);
    content.extend_from_slice(&sig);
    let mut der = vec![0x30];
    der.extend(der_len(content.len()));
    der.extend(content);
    parse(&der).to_pem(der::pem::LineEnding::LF).unwrap()
}

#[test]
fn import_accepts_valid_chain() {
    let (chain, key) = good_leaf();
    let m = import(&chain, &key, NOW).unwrap();
    let input: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let stored: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(m.chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    assert_eq!(stored, input, "leaf and intermediates are kept in order");
    assert_eq!(*m.key_pem, key);
    assert!(m.ca_pem.is_none() && m.ca_der.is_none());
    assert!(m.warnings.is_empty());
    assert_eq!(m.info.source, TlsSource::Imported);
    assert_eq!(m.info.ca_sha1, None);
    assert_eq!(m.info.ca_sha256, None);
    assert_eq!(m.info.leaf_sha256, sha256_hex(&input[0]));
    assert_eq!(m.info.leaf_not_after, rfc3339(not_after(&parse(&input[0]))));
    assert_eq!(m.info.created_at, rfc3339(NOW));

    let (chain, key) = leaf(
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &["127.0.0.1"],
        true,
        NOW - Duration::days(1),
        365,
    );
    assert!(import(&chain, &key, NOW).is_ok(), "P-384 is accepted");
}

#[test]
fn import_validation_errors() {
    let from = NOW - Duration::days(1);
    let p256 = &rcgen::PKCS_ECDSA_P256_SHA256;

    let (chain, key) = leaf(p256, &["localhost"], true, from, 365);
    assert_eq!(
        import(&chain, &key, NOW).unwrap_err(),
        TlsError::MissingIpSan
    );
    let (chain, key) = leaf(p256, &["::1", "localhost"], true, from, 365);
    assert_eq!(
        import(&chain, &key, NOW).unwrap_err(),
        TlsError::MissingIpSan
    );

    let (chain, key) = leaf(p256, &["127.0.0.1"], false, from, 365);
    assert_eq!(
        import(&chain, &key, NOW).unwrap_err(),
        TlsError::MissingServerAuth
    );

    let (chain, _) = good_leaf();
    let (_, other_key) = good_leaf();
    assert_eq!(
        import(&chain, &other_key, NOW).unwrap_err(),
        TlsError::KeyMismatch
    );

    let (chain, key) = leaf(p256, &["127.0.0.1"], true, from, 900);
    assert_eq!(
        import(&chain, &key, NOW).unwrap().warnings,
        vec![TlsWarning::ValidityOver825Days]
    );

    let (chain, key) = leaf(p256, &["127.0.0.1"], true, NOW - Duration::days(400), 300);
    assert_eq!(import(&chain, &key, NOW).unwrap_err(), TlsError::Expired);

    let (chain, key) = leaf(&rcgen::PKCS_ED25519, &["127.0.0.1"], true, from, 365);
    assert_eq!(import(&chain, &key, NOW).unwrap_err(), TlsError::WeakKey);

    let (chain, key) = good_leaf();
    let sha1 = with_sha1_signature(&chain);
    assert_eq!(
        import(&sha1, &key, NOW).unwrap_err(),
        TlsError::Sha1Signature
    );

    let (_, key) = good_leaf();
    assert!(matches!(
        import("not a certificate", &key, NOW).unwrap_err(),
        TlsError::Parse(_)
    ));
    let (chain, _) = good_leaf();
    assert!(matches!(
        import(&chain, "not a key", NOW).unwrap_err(),
        TlsError::Parse(_)
    ));
}

/// Runs a TLS handshake in memory between `server` and a client trusting `ca_der`.
fn handshake(server: Arc<rustls::ServerConfig>, ca_der: &[u8], name: ServerName<'static>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(Arc::new(client_config), name).unwrap();
    let mut server = rustls::ServerConnection::new(server).unwrap();
    for _ in 0..10 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        server.read_tls(&mut buf.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        client.read_tls(&mut buf.as_slice()).unwrap();
        client.process_new_packets().unwrap();
    }
    panic!("handshake did not finish");
}

#[test]
fn save_load_and_server_config() {
    let files = TlsFiles {
        dir: tmp_dir("save"),
    };
    assert_eq!(load_info(&files).unwrap(), None);
    assert!(server_config(&files).is_err());

    let m = generate(NOW, "user@host").unwrap();
    save(&files, &m).unwrap();
    assert_eq!(load_info(&files).unwrap(), Some(m.info.clone()));
    assert_eq!(
        std::fs::read_to_string(files.chain_pem()).unwrap(),
        m.chain_pem
    );
    assert_eq!(
        std::fs::read_to_string(files.key_pem()).unwrap(),
        *m.key_pem
    );
    assert_eq!(
        std::fs::read_to_string(files.ca_pem()).unwrap(),
        *m.ca_pem.as_ref().unwrap()
    );
    assert_eq!(
        std::fs::read(files.ca_der()).unwrap(),
        *m.ca_der.as_ref().unwrap()
    );
    assert_eq!(files.ca_pem().file_name().unwrap(), "OpenNCALayer-CA.crt");
    assert_eq!(files.ca_der().file_name().unwrap(), "OpenNCALayer-CA.cer");
    assert_eq!(files.chain_pem().file_name().unwrap(), "server.crt");
    assert_eq!(files.key_pem().file_name().unwrap(), "server.key");
    assert_eq!(files.info().file_name().unwrap(), "tls.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(files.key_pem())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let config = server_config(&files).unwrap();
    assert!(config.alpn_protocols.is_empty());
    let config = Arc::new(config);
    for name in [
        ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        ServerName::try_from("localhost").unwrap(),
    ] {
        handshake(config.clone(), m.ca_der.as_ref().unwrap(), name);
    }

    // Importing over a generated set removes the now unrelated CA files; the own CA it
    // replaces is kept until the user has removed it from the trust stores.
    assert_eq!(replaced_cas(&files).unwrap(), Vec::<Vec<u8>>::new());
    let (chain, key) = good_leaf();
    let imported = import(&chain, &key, NOW).unwrap();
    save(&files, &imported).unwrap();
    assert_eq!(load_info(&files).unwrap(), Some(imported.info.clone()));
    assert!(!files.ca_pem().exists() && !files.ca_der().exists());
    assert!(server_config(&files).is_ok());
    assert_eq!(replaced_cas(&files).unwrap(), [m.ca_der.clone().unwrap()]);
    forget_replaced_ca(&files, m.ca_der.as_ref().unwrap()).unwrap();
    forget_replaced_ca(&files, m.ca_der.as_ref().unwrap()).unwrap();
    assert_eq!(replaced_cas(&files).unwrap(), Vec::<Vec<u8>>::new());

    // A corrupt tls.json is an InvalidData error, not "no TLS set up".
    std::fs::write(files.info(), b"{").unwrap();
    assert_eq!(
        load_info(&files).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

fn sample_files() -> TlsFiles {
    TlsFiles {
        dir: PathBuf::from(r"C:\Users\tester\AppData\Roaming\OpenNCALayer\tls"),
    }
}

fn generated_info() -> TlsInfo {
    generate(NOW, "user@host").unwrap().info
}

#[test]
fn instructions_mention_paths_and_thumbprint() {
    let f = sample_files();
    let i = generated_info();
    let s = instructions(TargetOs::Windows, &f, &i, 13600);
    assert!(s.contains("certutil -user -addstore Root"));
    assert!(s.contains(&sha1_grouped(i.ca_sha1.as_deref().unwrap())));
    assert!(s.contains("https://127.0.0.1:13600/"));
    assert!(s.contains(&format!(
        "certutil -user -addstore Root \"{}\"",
        f.ca_der().display()
    )));
    assert!(s.contains("certmgr.msc"));
    assert!(s.contains("Security Warning"));
    assert!(s.contains("security.enterprise_roots.enabled"));
    assert!(s.contains(&format!(
        "certutil -user -delstore Root {}",
        i.ca_sha1.as_deref().unwrap().to_uppercase()
    )));
    // leaf notAfter 2028-12-31T23:00Z, re-issue 60 days earlier.
    assert!(s.contains("31.12.2028"), "{s}");
    assert!(s.contains("01.11.2028"), "{s}");
    assert!(!s.contains(":13579"));
}

#[test]
fn instructions_for_macos_and_linux() {
    let f = sample_files();
    let i = generated_info();
    let ca_pem = f.ca_pem().display().to_string();

    let mac = instructions(TargetOs::MacOs, &f, &i, 13579);
    assert!(mac.contains(&format!(
        "security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db \"{ca_pem}\""
    )));
    assert!(mac.contains("security delete-certificate -Z"));
    assert!(mac.contains("https://127.0.0.1:13579/"));
    assert!(mac.contains("01.11.2028"));

    let linux = instructions(TargetOs::Linux, &f, &i, 13601);
    assert!(linux.contains("chrome://certificate-manager"));
    // The nickname oncl-trust installs the CA under: with the first 16 hex digits of its
    // SHA-256, for install and removal alike.
    let nickname = format!(
        "OpenNCALayer Local CA {}",
        &i.ca_sha256.as_deref().unwrap()[..16]
    );
    assert_eq!(nss_nickname(i.ca_sha256.as_deref().unwrap()), nickname);
    assert!(linux.contains(&format!("-A -t \"C,,\" -n \"{nickname}\" -i \"{ca_pem}\"")));
    assert!(linux.contains("certutil -d sql:"));
    assert!(linux.contains(&format!("-D -n \"{nickname}\"")));
    assert!(linux.contains("Центры сертификации"));
    assert!(linux.contains("https://127.0.0.1:13601/"));
    assert!(linux.contains("01.11.2028"));
}

#[test]
fn instructions_for_imported_certificate() {
    let (chain, key) = good_leaf();
    let info = import(&chain, &key, NOW).unwrap().info;
    for os in [TargetOs::Windows, TargetOs::MacOs, TargetOs::Linux] {
        let s = instructions(os, &sample_files(), &info, 13600);
        assert!(s.contains("https://127.0.0.1:13600/"));
        assert!(!s.contains("addstore") && !s.contains("add-trusted-cert"));
    }
}

#[test]
fn thumbprint_grouping() {
    assert_eq!(
        sha1_grouped("0123456789abcdef0123456789abcdef01234567"),
        "01234567 89ABCDEF 01234567 89ABCDEF 01234567"
    );
}
