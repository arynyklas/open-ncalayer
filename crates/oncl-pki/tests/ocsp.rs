//! OCSP client: the request, the NCA GET binding and every way a response can be wrong,
//! against `MockOcsp` with the synthetic responders of the intermediate PKI, plus golden
//! vectors: an OpenSSL request and a recorded answer of the NCA test responder.

use der::asn1::{AnyRef, IntRef, OctetStringRef};
use der::{Decode, Encode, Sequence};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::http::{
    CONNECT_TIMEOUT, GetOptions, HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport,
    MAX_RESPONSE_LEN, NonceSpec, PkiMethod, UreqTransport, nca_get_url,
};
use oncl_pki::key::HashAlg;
use oncl_pki::ocsp::{
    self, ALLOWED_PERIOD, CLOCK_SKEW, CertStatus, MockOcsp, OcspError, OcspTamper, TIMEOUT,
};
use oncl_pki::oid;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::{CaSet, PathError};
use oncl_testkit::{fixture, ncanode, read, synthetic, synthetic_cert};
use sha1::{Digest, Sha1};
use spki::AlgorithmIdentifierRef;
use std::mem::discriminant;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use time::macros::datetime;

const OCSP_URL: &str = "http://ocsp.synthetic.test";
const OCSP_RESPONSE: &str = "application/ocsp-response";

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

/// A transport answering every request with `reply`, or failing with the error.
struct Fixed(Result<HttpReply, HttpError>);

impl Fixed {
    fn body(content_type: Option<&str>, body: &[u8]) -> Self {
        Fixed(Ok(HttpReply {
            status: 200,
            content_type: content_type.map(str::to_owned),
            location: None,
            body: body.to_vec(),
        }))
    }
}

impl HttpTransport for Fixed {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        match request.method {
            HttpMethod::Get => {
                let (_, _) = (request.url, request.opts);
                self.0.clone()
            }
            HttpMethod::Post => {
                let (url, _, _, o) = (
                    request.url,
                    request.content_type.unwrap_or_default(),
                    request.body,
                    request.opts,
                );
                self.get_with(url, o)
            }
        }
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
fn request_equals_openssl_request() {
    // `openssl ocsp -issuer inter-gost2015.pem -cert inter-user-gost2015-sign.pem -no_nonce
    // -reqout …` (fixtures/README.md).
    assert_eq!(
        ocsp::request_der(
            &entry("inter-user-gost2015-sign").cert,
            &cer("inter-gost2015")
        ),
        read(fixture("ocsp/openssl-request-inter-user-gost2015-sign.der"))
    );
}

#[test]
fn get_url_encodes_like_java_urlencoder() {
    // The escapes themselves and the trailing `/` are covered by the unit test of
    // `http::nca_get_url`; here the URL of a real request (83 bytes, so its base64 ends
    // with `=`) has nothing but alphanumerics and escapes after the base URL.
    let request = ocsp::request_der(
        &entry("inter-user-gost2015-sign").cert,
        &cer("inter-gost2015"),
    );
    let url = nca_get_url(OCSP_URL, &request);
    let encoded = url.strip_prefix("http://ocsp.synthetic.test/").unwrap();
    assert!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'%'),
        "{encoded}"
    );
    assert!(encoded.ends_with("%3D"), "{encoded}");
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
    let any = String::new;
    let table = [
        (OcspTamper::WrongKey, OcspError::BadSignature(any())),
        (OcspTamper::NoCerts, OcspError::NoCerts),
        (OcspTamper::OtherResponderId, OcspError::ResponderNotFound),
        (OcspTamper::OtherCertId, OcspError::CertIdMismatch),
        (OcspTamper::NoSingleResponse, OcspError::NoSingleResponse),
        (OcspTamper::Stale, OcspError::NextUpdate),
        (OcspTamper::FutureThisUpdate, OcspError::ThisUpdate),
        (
            OcspTamper::ThisUpdateAhead(CLOCK_SKEW + Duration::from_secs(60)),
            OcspError::ThisUpdate,
        ),
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
        (OcspTamper::Garbage, OcspError::Malformed(any())),
        (
            OcspTamper::Hang(Duration::from_secs(30)),
            OcspError::Http(HttpError::new(
                oncl_pki::http::HttpErrorKind::Timeout,
                "timed out",
            )),
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
        let result = check_leaf(
            "inter-revoked-gost2015-sign",
            &mock,
            Duration::from_millis(200),
        );
        let error = result.expect_err(&format!("{tamper:?}"));
        // Variants with a free-text cause are compared by variant, the others exactly.
        if matches!(
            expected,
            OcspError::BadSignature(_) | OcspError::Malformed(_)
        ) {
            assert_eq!(discriminant(&error), discriminant(&expected), "{tamper:?}");
            assert!(!error.to_string().ends_with(": "), "{tamper:?}: {error}");
        } else {
            assert_eq!(error, expected, "{tamper:?}");
        }
        assert_eq!(mock.calls().len(), 1, "{tamper:?}");
    }
}

#[test]
fn http_failures_are_errors() {
    let leaf = "inter-user-gost2015-sign";
    let no_content_type = Fixed::body(None, b"");
    assert_eq!(
        check_leaf(leaf, &no_content_type, TIMEOUT),
        Err(OcspError::ContentType(None))
    );
    let refused = Fixed(Err(HttpError::other("connection refused")));
    assert_eq!(
        check_leaf(leaf, &refused, TIMEOUT),
        Err(OcspError::Http(HttpError::other("connection refused")))
    );
    let error = check_leaf(leaf, &refused, TIMEOUT).unwrap_err();
    assert_eq!(
        error.to_string(),
        "HTTP request to the OCSP responder failed: connection refused"
    );
}

#[test]
fn unsuccessful_response_status_is_an_error() {
    // OCSPResponse { responseStatus tryLater (3) }
    let try_later = Fixed::body(Some(OCSP_RESPONSE), &[0x30, 0x03, 0x0a, 0x01, 0x03]);
    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &try_later, TIMEOUT),
        Err(OcspError::NotSuccessful(3))
    );
}

#[test]
fn response_type_other_than_basic_is_malformed() {
    // OCSPResponse { successful, [0] { id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2), "" } }
    let other_type = Fixed::body(
        Some(OCSP_RESPONSE),
        &[
            0x30, 0x14, 0x0a, 0x01, 0x00, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01,
            0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x00,
        ],
    );
    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &other_type, TIMEOUT),
        Err(OcspError::Malformed(
            "response type 1.3.6.1.5.5.7.48.1.2 is not id-pkix-ocsp-basic".to_owned()
        ))
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
        Err(OcspError::OcspSigningMissing)
    );
    // The responder's issuer is not in the CA set.
    let leaf = entry("inter-user-gost2015-sign").cert;
    let root_only = CaSet::new(vec![cer("root-gost2015")]);
    let mock = MockOcsp::new(entry("ocsp-gost2015"));
    let result = ocsp::check(
        &leaf,
        &cer("inter-gost2015"),
        &root_only,
        &mock,
        OffsetDateTime::now_utc(),
        TIMEOUT,
    );
    assert_eq!(
        result,
        Err(OcspError::ResponderNotTrusted(PathError::IssuerNotFound))
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "OCSP responder certificate is not trusted: issuer certificate not found"
    );
}

#[test]
fn this_update_ahead_within_clock_skew_is_accepted() {
    let ahead = |by| {
        let mock = MockOcsp::new(entry("ocsp-gost2015")).tamper(OcspTamper::ThisUpdateAhead(by));
        check_leaf("inter-user-gost2015-sign", &mock, TIMEOUT)
    };
    assert_eq!(ahead(Duration::from_secs(60)), Ok(CertStatus::Good));
    assert_eq!(
        ahead(CLOCK_SKEW - Duration::from_secs(30)),
        Ok(CertStatus::Good)
    );
    assert_eq!(
        ahead(CLOCK_SKEW + Duration::from_secs(30)),
        Err(OcspError::ThisUpdate)
    );
    let future = MockOcsp::new(entry("ocsp-gost2015")).tamper(OcspTamper::FutureThisUpdate);
    assert_eq!(
        check_leaf("inter-user-gost2015-sign", &future, TIMEOUT),
        Err(OcspError::ThisUpdate)
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

/// A transport recording the options of its requests and answering none.
struct Recording(Mutex<Vec<GetOptions>>);

impl HttpTransport for Recording {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        match request.method {
            HttpMethod::Get => {
                let (_, opts) = (request.url, request.opts);
                self.0.lock().unwrap().push(opts);
                Err(HttpError::other("unreachable"))
            }
            HttpMethod::Post => {
                let (_, _, _, _) = (
                    request.url,
                    request.content_type.unwrap_or_default(),
                    request.body,
                    request.opts,
                );
                unreachable!("OCSP uses GET")
            }
        }
    }
}

#[test]
fn request_connects_within_the_connect_timeout() {
    // A responder whose connection never completes fails after the connect timeout, not
    // the whole request timeout.
    let http = Recording(Mutex::new(Vec::new()));
    let result = check_leaf("inter-user-gost2015-sign", &http, TIMEOUT);
    assert!(matches!(result, Err(OcspError::Http(_))), "{result:?}");
    assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(2));
    assert_eq!(
        *http.0.lock().unwrap(),
        [GetOptions {
            timeout: TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            max_len: MAX_RESPONSE_LEN,
            https_only: false,
            redirects: true,
        }]
    );
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

/// The NCANode `individual_valid_2015` leaf, its issuer and the NCA test CAs
/// (`fixtures/nca/test`).
fn nca_test_leaf() -> (Certificate, Certificate, CaSet) {
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
        .expect("issuer among fixtures/nca/test")
        .clone();
    (leaf, issuer, cas)
}

#[test]
fn recorded_nca_test_answer_is_good() {
    let (leaf, issuer, cas) = nca_test_leaf();
    // `openssl ocsp -no_nonce -reqout` for the same pair (fixtures/README.md).
    assert_eq!(
        ocsp::request_der(&leaf, &issuer),
        read(fixture("nca-ocsp/individual_valid_2015.req.der"))
    );
    let answer = read(fixture("nca-ocsp/individual_valid_2015.resp.der"));
    let check_at = |now| {
        let http = Fixed::body(Some(OCSP_RESPONSE), &answer);
        ocsp::check(&leaf, &issuer, &cas, &http, now, TIMEOUT)
    };
    // thisUpdate = producedAt = 2026-10-26 00:01:50 UTC, no nextUpdate.
    assert_eq!(
        check_at(datetime!(2026-10-26 00:02:00 UTC)),
        Ok(CertStatus::Good)
    );
    // A client clock a few seconds behind the responder's.
    assert_eq!(
        check_at(datetime!(2026-10-26 00:01:47 UTC)),
        Ok(CertStatus::Good)
    );
    assert_eq!(
        check_at(datetime!(2026-10-26 00:06:50 UTC)),
        Err(OcspError::NextUpdate)
    );
    assert_eq!(
        check_at(datetime!(2026-10-25 23:56:49 UTC)),
        Err(OcspError::ThisUpdate)
    );
    // About another certificate of the same issuer.
    let other = entry("inter-user-gost2015-sign").cert;
    let http = Fixed::body(Some(OCSP_RESPONSE), &answer);
    assert_eq!(
        ocsp::check(
            &other,
            &issuer,
            &cas,
            &http,
            datetime!(2026-10-26 00:02:00 UTC),
            TIMEOUT
        ),
        Err(OcspError::CertIdMismatch)
    );
}

#[test]
#[ignore = "needs the NCA test OCSP responder and `cargo xtask fetch-fixtures`"]
fn live_ocsp_nca_test_certificate() {
    let (leaf, issuer, cas) = nca_test_leaf();
    let url = ocsp::ocsp_url(&leaf).expect("OCSP URL in AuthorityInfoAccess");
    let status = ocsp::check(
        &leaf,
        &issuer,
        &cas,
        &UreqTransport::default(),
        OffsetDateTime::now_utc(),
        TIMEOUT,
    );
    println!("OCSP {url}: {status:?}");
    assert!(status.is_ok(), "{status:?}");
}

/// Elements of a constructed value.
fn elements(any: AnyRef<'_>) -> Vec<AnyRef<'_>> {
    let mut reader = der::SliceReader::new(any.value()).unwrap();
    let mut out = Vec::new();
    while !der::Reader::is_finished(&reader) {
        out.push(der::Reader::decode::<AnyRef<'_>>(&mut reader).unwrap());
    }
    out
}

/// The hash OID of the `CertID` of a DER `OCSPRequest`, and its nonce if it has one.
fn read_request(request: &[u8]) -> (String, Option<Vec<u8>>) {
    let tbs = elements(elements(AnyRef::from_der(request).unwrap())[0]);
    let request_list = elements(tbs[0]);
    let cert_id = elements(elements(request_list[0])[0]);
    let alg = elements(cert_id[0])[0]
        .decode_as::<der::asn1::ObjectIdentifier>()
        .unwrap()
        .to_string();
    let nonce = tbs.get(1).map(|extensions| {
        let extension = elements(elements(elements(*extensions)[0])[0]);
        assert_eq!(
            extension[0]
                .decode_as::<der::asn1::ObjectIdentifier>()
                .unwrap(),
            oid::OCSP_NONCE
        );
        let value = extension.last().unwrap().value();
        <&OctetStringRef>::from_der(value)
            .unwrap()
            .as_bytes()
            .to_vec()
    });
    (alg, nonce)
}

fn fetch_spec() -> ocsp::RequestSpec {
    ocsp::RequestSpec {
        cert_id_hash: HashAlg::Sha1,
        nonce: NonceSpec::None,
        method: PkiMethod::GetUrlEncoded,
        url: Some(OCSP_URL.to_owned()),
        timeout: TIMEOUT,
    }
}

fn fetch_leaf(
    leaf: &str,
    spec: &ocsp::RequestSpec,
    http: &dyn HttpTransport,
    check: bool,
) -> Result<ocsp::Fetched, OcspError> {
    let cas = cas();
    ocsp::fetch(
        &entry(leaf).cert,
        &cer("inter-gost2015"),
        spec,
        http,
        check.then(|| (&cas, OffsetDateTime::now_utc())),
    )
}

#[test]
fn fetch_cert_id_hashes() {
    for hash in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Gost34311] {
        let mock = MockOcsp::new(entry("ocsp-gost2015"));
        let spec = ocsp::RequestSpec {
            cert_id_hash: hash,
            ..fetch_spec()
        };
        let fetched = fetch_leaf("inter-user-gost2015-sign", &spec, &mock, true).unwrap();
        assert_eq!(fetched.problem, None, "{hash:?}");
        assert_eq!(fetched.answer.unwrap().status, CertStatus::Good);
        assert_eq!(read_request(&mock.requests()[0]).0, hash.oid().to_string());
    }
}

#[test]
fn fetch_nonce_lengths() {
    for len in [8, 16, 32] {
        let mock = MockOcsp::new(entry("ocsp-gost2015"));
        let spec = ocsp::RequestSpec {
            nonce: NonceSpec::Random(len),
            ..fetch_spec()
        };
        let fetched = fetch_leaf("inter-user-gost2015-sign", &spec, &mock, true).unwrap();
        assert_eq!(fetched.problem, None);
        let nonce = read_request(&mock.requests()[0]).1.unwrap();
        assert_eq!(nonce.len(), usize::from(len));
    }
    // Without a nonce, the request has no extensions.
    let mock = MockOcsp::new(entry("ocsp-gost2015"));
    fetch_leaf("inter-user-gost2015-sign", &fetch_spec(), &mock, true).unwrap();
    assert_eq!(read_request(&mock.requests()[0]).1, None);
}

#[test]
fn fetch_get_under_256() {
    let mock = MockOcsp::new(entry("ocsp-gost2015"));
    let short = ocsp::RequestSpec {
        method: PkiMethod::GetUnder(256),
        ..fetch_spec()
    };
    fetch_leaf("inter-user-gost2015-sign", &short, &mock, true).unwrap();
    assert!(mock.calls()[0].len() > OCSP_URL.len() + 1, "a GET");
    // A long request (a SHA-512... nonce of 255 bytes) goes by POST.
    let long = ocsp::RequestSpec {
        nonce: NonceSpec::Random(255),
        ..short
    };
    let fetched = fetch_leaf("inter-user-gost2015-sign", &long, &mock, true).unwrap();
    assert_eq!(fetched.problem, None);
    assert_eq!(mock.calls()[1], OCSP_URL, "a POST");
}

#[test]
fn fetch_returns_raw_and_basic() {
    let leaf = entry("inter-revoked-gost2015-sign").cert;
    let revoked_at = datetime!(2026-01-15 08:00 UTC);
    let mock = MockOcsp::new(entry("ocsp-gost2015")).status(
        &serial_hex(&leaf),
        CertStatus::Revoked {
            time: revoked_at,
            reason: Some(1),
        },
    );
    let spec = ocsp::RequestSpec {
        method: PkiMethod::Post { content_type: None },
        ..fetch_spec()
    };
    let fetched = fetch_leaf("inter-revoked-gost2015-sign", &spec, &mock, false).unwrap();
    assert_eq!(fetched.http_status, 200);
    assert_eq!(fetched.response_status, 0);
    assert_eq!(
        fetched.answer.unwrap().status,
        CertStatus::Revoked {
            time: revoked_at,
            reason: Some(1)
        }
    );
    assert!(fetched.produced_at.is_some());
    // The basic response is the contents of the responseBytes OCTET STRING.
    let basic = fetched.basic.unwrap();
    let response = elements(AnyRef::from_der(&fetched.response).unwrap());
    let bytes = elements(elements(response[1])[0]);
    assert_eq!(bytes[1].value(), basic.as_slice());
}

#[test]
fn fetch_check_reports_problem() {
    let mock = MockOcsp::new(entry("ocsp-gost2015")).tamper(OcspTamper::WrongKey);
    let unchecked = fetch_leaf("inter-user-gost2015-sign", &fetch_spec(), &mock, false).unwrap();
    assert_eq!(unchecked.problem, None);
    assert_eq!(unchecked.answer.unwrap().status, CertStatus::Good);
    let checked = fetch_leaf("inter-user-gost2015-sign", &fetch_spec(), &mock, true).unwrap();
    assert!(matches!(checked.problem, Some(OcspError::BadSignature(_))));
    assert_eq!(checked.answer, None);
    // A status other than 200 is an error with its kind.
    let failing = MockOcsp::new(entry("ocsp-gost2015")).tamper(OcspTamper::HttpStatus(503));
    let e = fetch_leaf("inter-user-gost2015-sign", &fetch_spec(), &failing, true).unwrap_err();
    assert_eq!(e.kind(), oncl_pki::http::NetKind::Http(503));
}
