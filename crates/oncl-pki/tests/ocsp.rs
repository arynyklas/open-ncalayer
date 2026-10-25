//! OCSP client: the request, the NCA GET binding and every way a response can be wrong,
//! against `MockOcsp` with the synthetic responders of the intermediate PKI.

use der::asn1::{AnyRef, IntRef, OctetStringRef};
use der::{Decode, Encode, Sequence};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::http::{HttpError, HttpReply, HttpTransport, UreqTransport};
use oncl_pki::ocsp::{self, ALLOWED_PERIOD, CertStatus, MockOcsp, OcspError, OcspTamper, TIMEOUT};
use oncl_pki::oid;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_testkit::{fixture, ncanode, read, synthetic, synthetic_cert};
use sha1::{Digest, Sha1};
use spki::AlgorithmIdentifierRef;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use time::macros::datetime;

const OCSP_URL: &str = "http://ocsp.synthetic.test";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

/// The synthetic intermediate CA and its root.
fn cas() -> CaSet {
    CaSet::new(vec![cer("inter-gost2015"), cer("root-gost2015")])
}

fn serial_hex(cert: &Certificate) -> String {
    let serial = cert.tbs_certificate().serial_number().as_bytes();
    serial.iter().map(|b| format!("{b:02x}")).collect()
}

/// `ocsp::check` of the key `leaf` (issued by the intermediate CA) through `http`, against
/// the intermediate PKI, now.
fn check_leaf(
    leaf: &str,
    http: &dyn HttpTransport,
    timeout: Duration,
) -> Result<CertStatus, OcspError> {
    let leaf = entry(leaf).cert;
    ocsp::check(
        &leaf,
        &cer("inter-gost2015"),
        &cas(),
        http,
        OffsetDateTime::now_utc(),
        timeout,
    )
}

/// A transport answering every request with `reply`.
struct Fixed(HttpReply);

impl HttpTransport for Fixed {
    fn get(&self, _: &str) -> Result<HttpReply, HttpError> {
        Ok(self.0.clone())
    }

    fn post(&self, url: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
        self.get(url)
    }
}

// RFC 6960 `OCSPRequest` with exactly the fields we send, decoded strictly: a version,
// requestor name, extension or signature would not decode.
#[derive(Sequence)]
struct CertId<'a> {
    hash_algorithm: AlgorithmIdentifierRef<'a>,
    issuer_name_hash: &'a OctetStringRef,
    issuer_key_hash: &'a OctetStringRef,
    serial_number: IntRef<'a>,
}

#[derive(Sequence)]
struct Request<'a> {
    req_cert: CertId<'a>,
}

#[derive(Sequence)]
struct TbsRequest<'a> {
    request_list: Vec<Request<'a>>,
}

#[derive(Sequence)]
struct OcspRequest<'a> {
    tbs_request: TbsRequest<'a>,
}

#[test]
fn request_has_sha1_certid_of_issuer_name_and_key() {
    let (leaf, issuer) = (
        entry("inter-user-gost2015-sign").cert,
        cer("inter-gost2015"),
    );
    let der = ocsp::request_der(&leaf, &issuer);
    let request = OcspRequest::from_der(&der).unwrap();
    let [only] = &request.tbs_request.request_list[..] else {
        panic!("one request expected");
    };
    let id = &only.req_cert;
    assert_eq!(id.hash_algorithm.oid, oid::SHA1);
    assert_eq!(id.hash_algorithm.parameters, Some(AnyRef::NULL));
    let issuer_tbs = issuer.tbs_certificate();
    let name_hash = Sha1::digest(issuer_tbs.subject().to_der().unwrap());
    let key_hash = Sha1::digest(
        issuer_tbs
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    );
    assert_eq!(id.issuer_name_hash.as_bytes(), &name_hash[..]);
    assert_eq!(id.issuer_key_hash.as_bytes(), &key_hash[..]);
    assert_eq!(
        id.serial_number.as_bytes(),
        leaf.tbs_certificate().serial_number().as_bytes()
    );
}

#[test]
fn get_url_encodes_like_java_urlencoder() {
    // base64 "+/8=" for [0xfb, 0xff].
    assert_eq!(
        ocsp::get_url("http://h/ocsp", &[0xfb, 0xff]),
        "http://h/ocsp/%2B%2F8%3D"
    );
    assert_eq!(
        ocsp::get_url("http://h/", &[0xfb, 0xff]),
        "http://h/%2B%2F8%3D"
    );
    let request = ocsp::request_der(
        &entry("inter-user-gost2015-sign").cert,
        &cer("inter-gost2015"),
    );
    let url = ocsp::get_url(OCSP_URL, &request);
    let encoded = url.strip_prefix("http://ocsp.synthetic.test/").unwrap();
    assert!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'%'),
        "{encoded}"
    );
}

#[test]
fn good_revoked_unknown() {
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let unknown = entry("inter-noaki-gost2015-sign").cert;
    let revoked_at = datetime!(2026-05-01 10:00:00 UTC);
    let mock = MockOcsp::new(entry("ocsp-gost2015"))
        .status(
            &serial_hex(&revoked),
            CertStatus::Revoked {
                time: revoked_at,
                reason: Some(1),
            },
        )
        .status(&serial_hex(&unknown), CertStatus::Unknown);

    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &mock, TIMEOUT),
        Ok(CertStatus::Good)
    );
    assert_eq!(
        check_leaf("inter-revoked-gost2015-sign", &mock, TIMEOUT),
        Ok(CertStatus::Revoked {
            time: revoked_at,
            reason: Some(1)
        })
    );
    assert_eq!(
        check_leaf("inter-noaki-gost2015-sign", &mock, TIMEOUT),
        Ok(CertStatus::Unknown)
    );
    let calls = mock.calls();
    assert_eq!(calls.len(), 3);
    assert!(
        calls
            .iter()
            .all(|url| url.starts_with("http://ocsp.synthetic.test/"))
    );

    let without_reason = MockOcsp::new(entry("ocsp-gost2015")).status(
        &serial_hex(&revoked).to_uppercase(),
        CertStatus::Revoked {
            time: revoked_at,
            reason: None,
        },
    );
    assert_eq!(
        check_leaf("inter-revoked-gost2015-sign", &without_reason, TIMEOUT),
        Ok(CertStatus::Revoked {
            time: revoked_at,
            reason: None
        })
    );
}

#[test]
fn by_key_responder_id_is_accepted() {
    let mock = MockOcsp::new(entry("ocsp-gost2015")).tamper(OcspTamper::ByKeyResponderId);
    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &mock, TIMEOUT),
        Ok(CertStatus::Good)
    );
}

#[test]
fn every_tamper_is_an_error_not_a_status() {
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let table = [
        (OcspTamper::WrongKey, OcspError::BadSignature),
        (OcspTamper::NoCerts, OcspError::NoCerts),
        (OcspTamper::OtherCertId, OcspError::CertIdMismatch),
        (OcspTamper::Stale, OcspError::NextUpdate),
        (OcspTamper::FutureThisUpdate, OcspError::ThisUpdate),
        (
            OcspTamper::NoNextUpdate {
                age: Duration::from_secs(600),
            },
            OcspError::NextUpdate,
        ),
        (OcspTamper::HttpStatus(503), OcspError::HttpStatus(503)),
        (
            OcspTamper::ContentType("text/html"),
            OcspError::ContentType(Some("text/html".to_owned())),
        ),
        (OcspTamper::Garbage, OcspError::Malformed),
        (
            OcspTamper::Hang(Duration::from_secs(30)),
            OcspError::Http("timed out".to_owned()),
        ),
    ];
    for (tamper, expected) in table {
        let mock = MockOcsp::new(entry("ocsp-gost2015"))
            .status(
                &serial_hex(&revoked),
                CertStatus::Revoked {
                    time: datetime!(2026-05-01 10:00:00 UTC),
                    reason: None,
                },
            )
            .tamper(tamper);
        assert_eq!(
            check_leaf(
                "inter-revoked-gost2015-sign",
                &mock,
                Duration::from_millis(200)
            ),
            Err(expected),
            "{tamper:?}"
        );
        assert_eq!(mock.calls().len(), 1, "{tamper:?}");
    }
}

#[test]
fn unsuccessful_response_status_is_an_error() {
    let try_later = Fixed(HttpReply {
        status: 200,
        content_type: Some("application/ocsp-response".to_owned()),
        // OCSPResponse { responseStatus tryLater (3) }
        body: vec![0x30, 0x03, 0x0a, 0x01, 0x03],
    });
    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &try_later, TIMEOUT),
        Err(OcspError::NotSuccessful(3))
    );
}

#[test]
fn responder_without_nocheck_is_rejected() {
    let mock = MockOcsp::new(entry("ocsp-nocheckless-gost2015"));
    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &mock, TIMEOUT),
        Err(OcspError::NoCheckMissing)
    );
}

#[test]
fn responder_must_chain_and_be_an_ocsp_signer() {
    // A key of the intermediate CA without the OCSPSigning extended key usage.
    let not_a_responder = MockOcsp::new(entry("inter-user-gost2015-sign"));
    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &not_a_responder, TIMEOUT),
        Err(OcspError::ResponderNotTrusted)
    );
    // The responder's issuer is not in the CA set.
    let leaf = entry("inter-user-gost2015-sign").cert;
    let root_only = CaSet::new(vec![cer("root-gost2015")]);
    let mock = MockOcsp::new(entry("ocsp-gost2015"));
    assert_eq!(
        ocsp::check(
            &leaf,
            &cer("inter-gost2015"),
            &root_only,
            &mock,
            OffsetDateTime::now_utc(),
            TIMEOUT
        ),
        Err(OcspError::ResponderNotTrusted)
    );
}

#[test]
fn no_next_update_within_300s_ok_after_is_error() {
    let at = |age| {
        let mock = MockOcsp::new(entry("ocsp-gost2015")).tamper(OcspTamper::NoNextUpdate { age });
        check_leaf("inter-user-gost2015-sign", &mock, TIMEOUT)
    };
    assert_eq!(at(Duration::from_secs(60)), Ok(CertStatus::Good));
    assert_eq!(
        at(ALLOWED_PERIOD - Duration::from_secs(30)),
        Ok(CertStatus::Good)
    );
    assert_eq!(
        at(ALLOWED_PERIOD + Duration::from_secs(30)),
        Err(OcspError::NextUpdate)
    );
}

#[test]
fn hang_returns_http_error_within_timeout() {
    let mock =
        MockOcsp::new(entry("ocsp-gost2015")).tamper(OcspTamper::Hang(Duration::from_secs(30)));
    let start = Instant::now();
    let result = check_leaf(
        "inter-user-gost2015-sign",
        &mock,
        Duration::from_millis(500),
    );
    let elapsed = start.elapsed();
    assert!(matches!(result, Err(OcspError::Http(_))), "{result:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}

#[test]
fn cert_without_aia_is_no_url() {
    assert_eq!(
        ocsp::ocsp_url(&entry("inter-user-gost2015-sign").cert).as_deref(),
        Some(OCSP_URL)
    );
    // Issued by the synthetic root, without AuthorityInfoAccess.
    let leaf = entry("user-gost2015-sign").cert;
    assert_eq!(ocsp::ocsp_url(&leaf), None);
    let mock = MockOcsp::new(entry("ocsp-gost2015"));
    assert_eq!(
        ocsp::check(
            &leaf,
            &cer("root-gost2015"),
            &cas(),
            &mock,
            OffsetDateTime::now_utc(),
            TIMEOUT
        ),
        Err(OcspError::NoUrl)
    );
    assert!(mock.calls().is_empty());
}

#[test]
#[ignore = "needs the NCA test OCSP responder and `cargo xtask fetch-fixtures`"]
fn live_ocsp_nca_test_certificate() {
    let leaf = load(&read(ncanode("individual_valid_2015.p12")), "Aa123456")
        .unwrap()
        .remove(0)
        .cert;
    let mut test_cas = Vec::new();
    for dir_entry in std::fs::read_dir(fixture("nca/test")).unwrap() {
        let path = dir_entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "der") {
            test_cas.push(cert::parse(&read(&path)).unwrap());
        }
    }
    let cas = CaSet::new(test_cas);
    let issuer = cas
        .issuers_of(&leaf)
        .find(|issuer| cert::verify_signature(&leaf, issuer).is_ok())
        .expect("issuer among fixtures/nca/test");
    let url = ocsp::ocsp_url(&leaf).expect("OCSP URL in AuthorityInfoAccess");
    let status = ocsp::check(
        &leaf,
        issuer,
        &cas,
        &UreqTransport,
        OffsetDateTime::now_utc(),
        TIMEOUT,
    );
    println!("OCSP {url}: {status:?}");
    assert!(status.is_ok(), "{status:?}");
}
