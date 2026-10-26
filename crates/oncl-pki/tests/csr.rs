//! Key generation and PKCS#10 requests: every generated key signs a request that verifies
//! with the key it carries; subject, SubjectAltName and KeyStoreInfo read back.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oncl_pki::csr::{CsrRequest, KeyStoreInfo, build_csr};
use oncl_pki::key::{KeyAlg, PublicKey};
use oncl_pki::keygen::{KeySpec, generate, key_id};
use oncl_pki::keystore::KeystoreError;
use oncl_pki::oid;
use oncl_pki::pkcs12::load;
use oncl_testkit::{read, synthetic};
use x509_cert::der::asn1::{Any, Ia5String, ObjectIdentifier, Utf8StringRef};
use x509_cert::der::{Decode, Encode, Sequence, Tag, Tagged};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::request::{CertReq, ExtensionReq};

const NL: &str = if cfg!(windows) { "\r\n" } else { "\n" };

const SPECS: [KeySpec; 3] = [KeySpec::Gost2015_512, KeySpec::Gost2004, KeySpec::Rsa2048];

/// `KeyStoreInfo ::= SEQUENCE { storage OID, path UTF8String OPTIONAL }`.
#[derive(Sequence)]
struct KeyStoreInfoAsn1<'a> {
    storage: ObjectIdentifier,
    #[asn1(optional = "true")]
    path: Option<Utf8StringRef<'a>>,
}

fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}

fn pkcs12_info(path: Option<&str>) -> KeyStoreInfo {
    KeyStoreInfo {
        storage_oid: oid::STORAGE_PKCS12,
        path: path.map(str::to_owned),
    }
}

/// The DER of a PEM `CERTIFICATE REQUEST`, checking the PEM layout.
fn pem_der(pem: &str) -> Vec<u8> {
    let body = pem
        .strip_prefix(&format!("-----BEGIN CERTIFICATE REQUEST-----{NL}"))
        .and_then(|rest| rest.strip_suffix(&format!("-----END CERTIFICATE REQUEST-----{NL}")))
        .expect("PEM CERTIFICATE REQUEST");
    let lines: Vec<&str> = body.split_terminator(NL).collect();
    assert!(
        lines
            .iter()
            .all(|line| line.len() <= 64 && !line.contains('\n'))
    );
    STANDARD.decode(lines.concat()).unwrap()
}

/// Parses the request and checks its signature with the key it carries.
fn verified(pem: &str, spec: KeySpec) -> CertReq {
    let req = CertReq::from_der(&pem_der(pem)).unwrap();
    assert_eq!(req.algorithm.oid, spec.sig_alg().signature_oid());
    assert_eq!(req.algorithm.parameters, Some(Any::null()));
    let public = PublicKey::from_spki(&req.info.public_key).unwrap();
    let tbs = req.info.to_der().unwrap();
    let sig = req.signature.as_bytes().unwrap();
    public
        .verify(spec.sig_alg(), &tbs, sig)
        .expect("the request verifies with its own key");
    assert!(public.verify(spec.sig_alg(), b"other", sig).is_err());
    req
}

/// The requested extensions.
fn extensions(req: &CertReq) -> Vec<x509_cert::ext::Extension> {
    assert_eq!(req.info.attributes.len(), 1);
    let attribute = req.info.attributes.iter().next().unwrap();
    assert_eq!(attribute.oid, oid::EXTENSION_REQUEST);
    assert_eq!(attribute.values.len(), 1);
    let value = attribute.values.iter().next().unwrap();
    ExtensionReq::from_der(&value.to_der().unwrap()).unwrap().0
}

/// `(OID, tag, value)` of each RDN, in order.
fn rdns(req: &CertReq) -> Vec<(String, Tag, Vec<u8>)> {
    req.info
        .subject
        .iter_rdn()
        .map(|rdn| {
            assert_eq!(rdn.len(), 1, "one attribute per RDN");
            let atv = rdn.iter().next().unwrap();
            (
                atv.oid.to_string(),
                atv.value.tag(),
                atv.value.value().to_vec(),
            )
        })
        .collect()
}

#[test]
fn generated_keys_sign_verifiable_requests() {
    let dn = [
        (oid::ORGANIZATIONAL_UNIT, "BIN123456789012".to_owned()),
        (oid::EMAIL_ADDRESS, "user@example.kz".to_owned()),
        (oid::COMMON_NAME, "ТЕСТОВ ТЕСТ".to_owned()),
        (oid::SERIAL_NUMBER, "IIN123456789011".to_owned()),
        (oid::COUNTRY, "KZ".to_owned()),
    ];
    let dns = ["example.kz".to_owned(), "www.example.kz".to_owned()];
    for spec in SPECS {
        let key = generate(spec).unwrap();
        assert_eq!(key.alg(), spec.sig_alg().key_alg());
        let pem = build_csr(
            &key,
            spec,
            &CsrRequest {
                dn: &dn,
                dns_names: &dns,
                email: Some("user@example.kz"),
                keystore_info: pkcs12_info(Some("C:\\Users\\Тест\\keys")),
            },
        )
        .unwrap();
        let req = verified(&pem, spec);
        assert_eq!(
            PublicKey::from_spki(&req.info.public_key).unwrap(),
            key.public_key()
        );

        // RDNs in Kalkan's natural order; value types of its default converter.
        assert_eq!(
            rdns(&req),
            [
                (
                    "2.5.4.3".to_owned(),
                    Tag::Utf8String,
                    "ТЕСТОВ ТЕСТ".as_bytes().to_vec()
                ),
                (
                    "2.5.4.5".to_owned(),
                    Tag::PrintableString,
                    b"IIN123456789011".to_vec()
                ),
                ("2.5.4.6".to_owned(), Tag::PrintableString, b"KZ".to_vec()),
                (
                    "2.5.4.11".to_owned(),
                    Tag::Utf8String,
                    b"BIN123456789012".to_vec()
                ),
                (
                    "1.2.840.113549.1.9.1".to_owned(),
                    Tag::Ia5String,
                    b"user@example.kz".to_vec()
                ),
            ],
            "{spec:?}"
        );

        let exts = extensions(&req);
        assert_eq!(exts.len(), 2, "{spec:?}");
        assert!(exts.iter().all(|e| !e.critical));
        assert_eq!(exts[0].extn_id, oid("2.5.29.17"));
        let san = SubjectAltName::from_der(exts[0].extn_value.as_bytes()).unwrap();
        assert_eq!(
            san.0,
            [
                GeneralName::DnsName(Ia5String::new("example.kz").unwrap()),
                GeneralName::DnsName(Ia5String::new("www.example.kz").unwrap()),
                GeneralName::Rfc822Name(Ia5String::new("user@example.kz").unwrap()),
            ]
        );
        assert_eq!(exts[1].extn_id, oid("1.2.398.3.3.5"));
        let info = KeyStoreInfoAsn1::from_der(exts[1].extn_value.as_bytes()).unwrap();
        assert_eq!(info.storage, oid("1.2.398.3.3.5.1.1"));
        assert_eq!(info.path.unwrap().as_str(), "C:\\Users\\Тест\\keys");
    }
}

#[test]
fn rdn_order_is_kalkan_natural_order() {
    let key = generate(KeySpec::Gost2015_512).unwrap();
    let dn = [
        (oid("2.5.4.11"), "OU".to_owned()),
        (oid("2.5.4.3"), "CN".to_owned()),
        (oid("2.5.4.5"), "IIN000000000000".to_owned()),
    ];
    let request = CsrRequest {
        dn: &dn,
        dns_names: &[],
        email: None,
        keystore_info: pkcs12_info(None),
    };
    let req = verified(
        &build_csr(&key, KeySpec::Gost2015_512, &request).unwrap(),
        KeySpec::Gost2015_512,
    );
    let order: Vec<String> = rdns(&req).into_iter().map(|(oid, _, _)| oid).collect();
    assert_eq!(order, ["2.5.4.3", "2.5.4.5", "2.5.4.11"]);
}

#[test]
fn keystore_info_alone_without_names() {
    let key = generate(KeySpec::Gost2004).unwrap();
    let dn = [(oid::COMMON_NAME, "CN".to_owned())];
    let request = CsrRequest {
        dn: &dn,
        dns_names: &[],
        // A blank email adds no name, as in the original.
        email: Some("  "),
        keystore_info: pkcs12_info(None),
    };
    let req = verified(
        &build_csr(&key, KeySpec::Gost2004, &request).unwrap(),
        KeySpec::Gost2004,
    );
    let exts = extensions(&req);
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].extn_id, oid::KEYSTORE_INFO);
    // SEQUENCE { OID } without a path.
    let mut expected = vec![0x30, 0x0a];
    expected.extend(oid::STORAGE_PKCS12.to_der().unwrap());
    assert_eq!(exts[0].extn_value.as_bytes(), expected);
}

#[test]
fn name_values_as_kalkan_converts_them() {
    let key = generate(KeySpec::Gost2015_512).unwrap();
    let dn = [
        // `#` + hex: the DER value itself.
        (oid::COMMON_NAME, "#0c03616263".to_owned()),
        // A leading backslash is dropped.
        (oid::ORGANIZATION, "\\#not hex".to_owned()),
        (oid::DOMAIN_COMPONENT, "kz".to_owned()),
        (oid::DATE_OF_BIRTH, "19900101000000Z".to_owned()),
        (oid::TELEPHONE_NUMBER, "+77001234567".to_owned()),
    ];
    let request = CsrRequest {
        dn: &dn,
        dns_names: &[],
        email: None,
        keystore_info: pkcs12_info(None),
    };
    let req = verified(
        &build_csr(&key, KeySpec::Gost2015_512, &request).unwrap(),
        KeySpec::Gost2015_512,
    );
    let values: Vec<(String, Tag, Vec<u8>)> = rdns(&req);
    assert!(values.contains(&("2.5.4.3".to_owned(), Tag::Utf8String, b"abc".to_vec())));
    assert!(values.contains(&("2.5.4.10".to_owned(), Tag::Utf8String, b"#not hex".to_vec())));
    assert!(values.contains(&(
        "0.9.2342.19200300.100.1.25".to_owned(),
        Tag::Ia5String,
        b"kz".to_vec()
    )));
    assert!(values.contains(&(
        "1.3.6.1.5.5.7.9.1".to_owned(),
        Tag::GeneralizedTime,
        b"19900101000000Z".to_vec()
    )));
    assert!(values.contains(&(
        "2.5.4.20".to_owned(),
        Tag::PrintableString,
        b"+77001234567".to_vec()
    )));
}

#[test]
fn values_that_do_not_fit_their_type_are_refused() {
    let key = generate(KeySpec::Gost2015_512).unwrap();
    let cyrillic_serial = [(oid::SERIAL_NUMBER, "ИИН123".to_owned())];
    let bad_hex = [(oid::COMMON_NAME, "#0c0".to_owned())];
    let bad_date = [(oid::DATE_OF_BIRTH, "1990".to_owned())];
    let unicode_dns = ["пример.kz".to_owned()];
    let cases = [
        (&cyrillic_serial[..], &[][..], None),
        (&bad_hex[..], &[][..], None),
        (&bad_date[..], &[][..], None),
        (&[][..], &unicode_dns[..], None),
        (&[][..], &[][..], Some("почта@example.kz")),
    ];
    for (dn, dns_names, email) in cases {
        let request = CsrRequest {
            dn,
            dns_names,
            email,
            keystore_info: pkcs12_info(None),
        };
        let err = build_csr(&key, KeySpec::Gost2015_512, &request).unwrap_err();
        assert!(matches!(err, KeystoreError::InvalidRequest(_)), "{err:?}");
    }
}

#[test]
fn algorithms() {
    assert_eq!(
        KeySpec::from_oid_len("1.2.398.3.10.1.1.2.3.2", 512),
        Ok(KeySpec::Gost2015_512)
    );
    assert_eq!(
        KeySpec::from_oid_len("1.2.398.3.10.1.1.1.2", 256),
        Ok(KeySpec::Gost2004)
    );
    assert_eq!(
        KeySpec::from_oid_len("1.2.840.113549.1.1.11", 2048),
        Ok(KeySpec::Rsa2048)
    );
    assert_eq!(
        KeySpec::from_oid_len("1.2.840.113549.1.1.5", 1024),
        Ok(KeySpec::Rsa1Sha1(1024))
    );
    for unknown in ["1.2.398.3.10.1.1.2.3.1", "1.2.840.113549.1.1.1", "", "x"] {
        let err = KeySpec::from_oid_len(unknown, 2048).unwrap_err();
        assert_eq!(err, KeystoreError::UnknownAlgorithm);
        assert_eq!(err.code(), "UNKNOWN_ALGORITHM");
    }

    // sha1WithRSA: no key, no request (SHA-1 signatures are refused).
    assert_eq!(
        generate(KeySpec::Rsa1Sha1(2048)).unwrap_err(),
        KeystoreError::UnknownAlgorithm
    );
    let rsa = generate(KeySpec::Rsa2048).unwrap();
    let request = CsrRequest {
        dn: &[],
        dns_names: &[],
        email: None,
        keystore_info: pkcs12_info(None),
    };
    assert_eq!(
        build_csr(&rsa, KeySpec::Rsa1Sha1(2048), &request).unwrap_err(),
        KeystoreError::UnknownAlgorithm
    );
    // A key of another type than the spec.
    assert_eq!(
        build_csr(&rsa, KeySpec::Gost2015_512, &request).unwrap_err(),
        KeystoreError::UnknownAlgorithm
    );
}

#[test]
fn generated_keys_differ() {
    for spec in [KeySpec::Gost2015_512, KeySpec::Gost2004] {
        let a = generate(spec).unwrap().public_key();
        let b = generate(spec).unwrap().public_key();
        assert_ne!(a, b, "{spec:?}");
    }
}

#[test]
fn key_id_is_the_kalkan_alias() {
    for (name, alg) in [
        ("user-gost2015-sign", KeyAlg::Gost2015_512),
        ("user-gost2004-sign", KeyAlg::Gost2004),
        ("user-rsa-sign", KeyAlg::Rsa),
    ] {
        let fixture = synthetic(name);
        let entry = load(&read(&fixture.path), &fixture.password)
            .unwrap()
            .remove(0);
        assert_eq!(entry.key.alg(), alg);
        // The synthetic aliases are hex(SKI), the SKI is SHA-1 of the key BIT STRING.
        assert_eq!(key_id(&entry.key.public_key()), entry.alias, "{name}");
        assert_eq!(
            entry.key.public_key().to_spki(),
            *entry.cert.tbs_certificate().subject_public_key_info(),
            "{name}: the SPKI of the key is the certificate's"
        );
    }
}
