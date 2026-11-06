//! CRL client: verification, serial lookup, the on-disk cache and the CDP URL order,
//! against `MockCrl` with the synthetic intermediate PKI, plus a golden vector: a CRL of the
//! NCA root (GOST 2022) checked offline.

use der::asn1::{AnyRef, BitStringRef, Ia5String, OctetString};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Sequence, Tag};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::crl::{self, CrlError, CrlStatus, MAX_BER_CRL_LEN, MAX_CRL_LEN, MockCrl, TIMEOUT};
use oncl_pki::http::{
    CONNECT_TIMEOUT, GetOptions, HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport,
    RouteTransport, UreqTransport,
};
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_testkit::{fixture, read, synthetic, synthetic_cert};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use time::macros::datetime;
use x509_cert::crl::CertificateList;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

const INTER_CRL: &str = "http://crl.synthetic.test/inter-gost2015.crl";
const ROOT_CRL: &str = "http://crl.synthetic.test/root-gost2015.crl";
const NCA_ROOT_CRL: &str = "http://crl.root.gov.kz/gost2015_2022.crl";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

fn nca(name: &str) -> Certificate {
    cert::parse(&read(fixture(&format!("nca/prod/{name}.der")))).unwrap()
}

fn serial(cert: &Certificate) -> &[u8] {
    cert.tbs_certificate().serial_number().as_bytes()
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn this_update(crl: &CertificateList) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + crl.tbs_cert_list.this_update.to_unix_duration()
}

/// The status of `cert` in the CRL of `issuer`, as the shared validator asks for it.
fn check(
    cert: &Certificate,
    issuer: &Certificate,
    http: &dyn HttpTransport,
    now: OffsetDateTime,
) -> Result<CrlStatus, CrlError> {
    crl::fetch_for(cert, issuer, http, TIMEOUT, now).map(|(_, status)| status)
}

/// `leaf` re-issued by the intermediate CA with these CRL distribution point URIs, one
/// distribution point each.
fn leaf_with_cdp(leaf: &Certificate, uris: &[&str]) -> Certificate {
    let points = CrlDistributionPoints(
        uris.iter()
            .map(|uri| DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(Ia5String::new(uri).unwrap()),
                ])),
                reasons: None,
                crl_issuer: None,
            })
            .collect(),
    );
    let cdp = Extension {
        extn_id: CrlDistributionPoints::OID,
        critical: false,
        extn_value: OctetString::new(points.to_der().unwrap()).unwrap(),
    };
    let mut spec = TestCertSpec::from_cert(leaf);
    spec.extensions
        .retain(|e| e.extn_id != CrlDistributionPoints::OID);
    if !uris.is_empty() {
        spec.extensions.push(cdp);
    }
    issue_cert(&entry("inter-gost2015.key"), spec)
}

/// A transport answering every request with `reply`.
struct Fixed(Result<HttpReply, HttpError>);

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

#[test]
fn crl_urls_are_the_http_uris_of_the_distribution_points_in_order() {
    let leaf = entry("inter-user-gost2015-sign").cert;
    assert_eq!(crl::crl_urls(&leaf), [INTER_CRL]);
    assert_eq!(crl::crl_urls(&cer("inter-gost2015")), [ROOT_CRL]);
    assert_eq!(crl::crl_urls(&nca("ncagost22")), [NCA_ROOT_CRL]);
    // Two mirrors packed into one URI value (and the older CAs with two URIs).
    for (name, file) in [
        ("ncagost18", "gost"),
        ("ncarsa18", "rsa"),
        ("ncagost", "gost"),
        ("ncarsa", "rsa"),
    ] {
        assert_eq!(
            crl::crl_urls(&nca(name)),
            [
                format!("http://crl.root.gov.kz/{file}.crl"),
                format!("http://crl1.root.gov.kz/{file}.crl")
            ],
            "{name}"
        );
    }
    assert!(crl::crl_urls(&cer("root-gost2015")).is_empty());

    let many = leaf_with_cdp(
        &leaf,
        &[
            "ldap://crl.synthetic.test/cn=x",
            "https://b.synthetic.test/b.crl",
            "HTTP://a.synthetic.test/a.crl\n   URL=http://c.synthetic.test/c.crl\tURL=ldap://x",
            "http://c.synthetic.test/c.crl https://b.synthetic.test/b.crl",
            " URL= ",
        ],
    );
    assert_eq!(
        crl::crl_urls(&many),
        [
            "https://b.synthetic.test/b.crl",
            "HTTP://a.synthetic.test/a.crl",
            "http://c.synthetic.test/c.crl"
        ]
    );
}

#[test]
fn verifies_and_finds_revoked_serial() {
    let issuer = cer("inter-gost2015");
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let good = entry("inter-user-gost2015-sign").cert;
    let ocsp = entry("ocsp-gost2015").cert;
    let revoked_at = datetime!(2026-03-01 07:08:09 UTC);
    let mock = MockCrl::new(entry("inter-gost2015.key"))
        .revoke(serial(&revoked), revoked_at)
        .revoke_with_reason(serial(&ocsp), revoked_at + time::Duration::DAY, 1);

    let list = crl::verify_crl(&mock.der(), &issuer, now()).unwrap();
    assert_eq!(
        crl::lookup(&list, serial(&revoked)),
        CrlStatus::Revoked {
            time: revoked_at,
            reason: None
        }
    );
    assert_eq!(
        crl::lookup(&list, serial(&ocsp)),
        CrlStatus::Revoked {
            time: revoked_at + time::Duration::DAY,
            reason: Some(1)
        }
    );
    assert_eq!(crl::lookup(&list, serial(&good)), CrlStatus::Good);
    // Leading zeros of the looked-up serial do not matter.
    let mut padded = vec![0, 0];
    padded.extend_from_slice(serial(&revoked));
    assert!(matches!(
        crl::lookup(&list, &padded),
        CrlStatus::Revoked { .. }
    ));

    // `check` end to end: a leaf against the intermediate's CRL, the intermediate against
    // the root's.
    let http = RouteTransport::new(vec![
        (
            INTER_CRL.to_owned(),
            Arc::new(mock) as Arc<dyn HttpTransport>,
        ),
        (
            ROOT_CRL.to_owned(),
            Arc::new(MockCrl::new(entry("root-gost2015.key"))),
        ),
    ]);
    assert_eq!(
        check(&revoked, &issuer, &http, now()),
        Ok(CrlStatus::Revoked {
            time: revoked_at,
            reason: None
        })
    );
    assert_eq!(check(&good, &issuer, &http, now()), Ok(CrlStatus::Good));
    assert_eq!(
        check(&issuer, &cer("root-gost2015"), &http, now()),
        Ok(CrlStatus::Good)
    );
}

#[test]
fn outdated_and_not_yet_valid() {
    let issuer = cer("inter-gost2015");
    let key = entry("inter-gost2015.key");
    let next = now() + time::Duration::HOUR;
    let der = MockCrl::new(key.clone()).next_update(Some(next)).der();
    let list = crl::verify_crl(&der, &issuer, now()).unwrap();
    let this = this_update(&list);
    assert!(this <= now());

    // thisUpdate ≤ now < nextUpdate, to the second.
    assert!(crl::verify_crl(&der, &issuer, this).is_ok());
    assert_eq!(
        crl::verify_crl(&der, &issuer, this - time::Duration::SECOND).unwrap_err(),
        CrlError::NotYetValid
    );
    let next = next.replace_nanosecond(0).unwrap();
    assert!(crl::verify_crl(&der, &issuer, next - time::Duration::SECOND).is_ok());
    assert_eq!(
        crl::verify_crl(&der, &issuer, next).unwrap_err(),
        CrlError::Outdated
    );

    // Without nextUpdate a CRL does not get outdated.
    let der = MockCrl::new(key).next_update(None).der();
    let list = crl::verify_crl(&der, &issuer, now() + 3650 * time::Duration::DAY).unwrap();
    assert_eq!(list.tbs_cert_list.next_update, None);
}

#[test]
fn issuer_mismatch_and_bad_signature() {
    let inter = cer("inter-gost2015");
    let key = entry("inter-gost2015.key");

    // Signed by the root: another issuer name.
    let root_crl = MockCrl::new(entry("root-gost2015.key")).der();
    assert_eq!(
        crl::verify_crl(&root_crl, &inter, now()).unwrap_err(),
        CrlError::IssuerMismatch
    );
    // Another key under the intermediate's name.
    let forged = MockCrl::new(key.clone()).wrong_key().der();
    assert!(matches!(
        crl::verify_crl(&forged, &inter, now()),
        Err(CrlError::BadSignature(_))
    ));
    // The intermediate's twin: the same name, another key.
    let good = MockCrl::new(key).der();
    assert!(matches!(
        crl::verify_crl(&good, &cer("inter-gost2015-twin"), now()),
        Err(CrlError::BadSignature(_))
    ));
    assert!(crl::verify_crl(&good, &inter, now()).is_ok());

    for garbage in [&b""[..], b"<html>not a CRL</html>", &good[..good.len() - 1]] {
        assert!(matches!(
            crl::verify_crl(garbage, &inter, now()),
            Err(CrlError::Malformed(_))
        ));
    }

    // `check` of a certificate the given issuer did not issue.
    let leaf = entry("inter-user-gost2015-sign").cert;
    let http = Fixed(Err(HttpError::other("must not be asked")));
    assert_eq!(
        check(&leaf, &cer("root-gost2015"), &http, now()),
        Err(CrlError::IssuerMismatch)
    );
}

/// `CertificateList` with its parts raw.
#[derive(Sequence)]
struct RawCrl<'a> {
    tbs_cert_list: AnyRef<'a>,
    signature_algorithm: AnyRef<'a>,
    signature: BitStringRef<'a>,
}

/// `crl` with the version INTEGER (the first element, `02 01 01`) cut out of its
/// `TBSCertList` and signed anew by `signer`: a list that does not decode as v2.
fn without_version(crl: &[u8], signer: &KeyEntry) -> Vec<u8> {
    let raw = RawCrl::from_der(crl).unwrap();
    let fields = raw.tbs_cert_list.value();
    assert_eq!(fields[..3], [2, 1, 1]);
    let tbs = AnyRef::new(Tag::Sequence, &fields[3..]).unwrap();
    let signature = signer
        .key
        .sign(SigAlg::Gost2015_512, &tbs.to_der().unwrap())
        .unwrap();
    RawCrl {
        tbs_cert_list: tbs,
        signature: BitStringRef::from_bytes(&signature).unwrap(),
        ..raw
    }
    .to_der()
    .unwrap()
}

#[test]
fn signature_is_checked_before_the_list_is_decoded() {
    let inter = cer("inter-gost2015");
    let key = entry("inter-gost2015.key");
    let crl = MockCrl::new(key.clone()).der();
    // Signed by the issuer: the list is read, and refused.
    assert!(matches!(
        crl::verify_crl(&without_version(&crl, &key), &inter, now()),
        Err(CrlError::Malformed(_))
    ));
    // Signed by another key: refused before the list is read.
    let forged = without_version(&crl, &entry("root-gost2015.key"));
    assert!(matches!(
        crl::verify_crl(&forged, &inter, now()),
        Err(CrlError::BadSignature(_))
    ));
}

/// `crl` with its outer SEQUENCE in BER indefinite-length form: `30 80 … 00 00`.
fn indefinite(crl: &[u8]) -> Vec<u8> {
    let content = AnyRef::from_der(crl).unwrap().value();
    [&[0x30, 0x80][..], content, &[0, 0]].concat()
}

#[test]
fn ber_is_normalized_only_up_to_1_mib() {
    assert_eq!(MAX_BER_CRL_LEN, 1 << 20);
    let inter = cer("inter-gost2015");
    let key = entry("inter-gost2015.key");

    // A small BER CRL is normalized and verifies.
    let small = indefinite(&MockCrl::new(key.clone()).der());
    assert!(small.len() <= MAX_BER_CRL_LEN);
    crl::verify_crl(&small, &inter, now()).unwrap();

    // A CRL over the bound verifies as DER, and as BER is refused instead of normalized,
    // although normalized it is that same DER CRL.
    let revoked_at = datetime!(2026-03-01 07:08:09 UTC);
    let big = (1..=60_000u32)
        .fold(MockCrl::new(key), |mock, n| {
            mock.revoke(&n.to_be_bytes(), revoked_at)
        })
        .der();
    assert!(big.len() > MAX_BER_CRL_LEN);
    let list = crl::verify_crl(&big, &inter, now()).unwrap();
    let revoked = list.tbs_cert_list.revoked_certificates.as_ref();
    assert_eq!(revoked.map(Vec::len), Some(60_000));
    let big_ber = indefinite(&big);
    assert_eq!(oncl_pki::ber::to_der(&big_ber).unwrap(), big);
    match crl::verify_crl(&big_ber, &inter, now()) {
        Err(CrlError::Malformed(why)) => assert!(
            why.ends_with(&format!("(a CRL over {MAX_BER_CRL_LEN} bytes must be DER)")),
            "{why}"
        ),
        other => panic!("{other:?}"),
    }
}

/// `crl` with `issuer` (a whole DER element) in place of `tbsCertList.issuer`, and the
/// signature left as it was.
fn with_issuer(crl: &[u8], issuer: &[u8]) -> Vec<u8> {
    use der::Reader as _;
    let raw = RawCrl::from_der(crl).unwrap();
    let mut reader = der::SliceReader::new(raw.tbs_cert_list.value()).unwrap();
    let version = reader.tlv_bytes().unwrap();
    let signature = reader.tlv_bytes().unwrap();
    reader.tlv_bytes().unwrap();
    let rest = reader.read_slice(reader.remaining_len()).unwrap();
    let fields = [version, signature, issuer, rest].concat();
    RawCrl {
        tbs_cert_list: AnyRef::new(Tag::Sequence, &fields).unwrap(),
        ..raw
    }
    .to_der()
    .unwrap()
}

#[test]
fn issuer_is_compared_as_bytes_without_decoding_the_name() {
    let inter = cer("inter-gost2015");
    let crl = MockCrl::new(entry("inter-gost2015.key")).der();
    // 150 000 one-attribute RDNs, SET { SEQUENCE { OID 1.2, NULL } }: a valid Name over
    // the BER bound that would decode into 150 000 owned RDNs before the signature check;
    // and as many NULLs: no Name at all, which a decode would refuse as Malformed.
    let rdns = [0x31, 7, 0x30, 5, 6, 1, 0x2a, 5, 0].repeat(150_000);
    let nulls = [5, 0].repeat(600_000);
    for elements in [rdns, nulls] {
        let issuer = AnyRef::new(Tag::Sequence, &elements)
            .unwrap()
            .to_der()
            .unwrap();
        let forged = with_issuer(&crl, &issuer);
        assert!(forged.len() > MAX_BER_CRL_LEN);
        let start = std::time::Instant::now();
        assert_eq!(
            crl::verify_crl(&forged, &inter, now()).unwrap_err(),
            CrlError::IssuerMismatch
        );
        let took = start.elapsed();
        assert!(took < Duration::from_secs(1), "{took:?}");
    }
}

#[test]
fn delta_and_partitioned_crls_are_rejected() {
    let inter = cer("inter-gost2015");
    let key = entry("inter-gost2015.key");
    let ext = |oid: &str, critical: bool, value: &[u8]| Extension {
        extn_id: oid.parse().unwrap(),
        critical,
        extn_value: OctetString::new(value).unwrap(),
    };
    // deltaCRLIndicator (BaseCRLNumber 1) and issuingDistributionPoint (empty SEQUENCE),
    // critical as RFC 5280 wants and not.
    for (oid, value) in [("2.5.29.27", &[2, 1, 1][..]), ("2.5.29.28", &[0x30, 0])] {
        for critical in [true, false] {
            let der = MockCrl::new(key.clone())
                .extension(ext(oid, critical, value))
                .der();
            assert_eq!(
                crl::verify_crl(&der, &inter, now()).unwrap_err(),
                CrlError::Malformed(format!("unsupported CRL extension {oid}")),
                "{oid} critical={critical}"
            );
        }
    }
    // An unknown extension is refused only when critical.
    let der = MockCrl::new(key.clone())
        .extension(ext("1.2.3.4", true, &[5, 0]))
        .der();
    assert_eq!(
        crl::verify_crl(&der, &inter, now()).unwrap_err(),
        CrlError::Malformed("unsupported critical CRL extension 1.2.3.4".to_owned())
    );
    let der = MockCrl::new(key)
        .extension(ext("1.2.3.4", false, &[5, 0]))
        .der();
    assert!(crl::verify_crl(&der, &inter, now()).is_ok());
}

#[test]
fn second_url_used_when_first_fails() {
    let issuer = cer("inter-gost2015");
    let leaf = leaf_with_cdp(
        &entry("inter-revoked-gost2015-sign").cert,
        &[
            "http://down.synthetic.test/a.crl",
            "http://forged.synthetic.test/a.crl",
            INTER_CRL,
        ],
    );
    let revoked_at = datetime!(2026-01-02 03:04:05 UTC);
    let forged = Arc::new(MockCrl::new(entry("inter-gost2015.key")).wrong_key());
    let good =
        Arc::new(MockCrl::new(entry("inter-gost2015.key")).revoke(serial(&leaf), revoked_at));
    let http = RouteTransport::new(vec![
        (
            "http://forged.synthetic.test/".to_owned(),
            forged.clone() as Arc<dyn HttpTransport>,
        ),
        (INTER_CRL.to_owned(), good.clone()),
    ]);
    assert_eq!(
        check(&leaf, &issuer, &http, now()),
        Ok(CrlStatus::Revoked {
            time: revoked_at,
            reason: None
        })
    );
    assert_eq!(forged.calls().len(), 1);
    assert_eq!(good.calls().len(), 1);

    // Every URL fails: the error of the last one.
    let http = RouteTransport::new(vec![(
        "http://forged.synthetic.test/".to_owned(),
        forged.clone() as Arc<dyn HttpTransport>,
    )]);
    assert_eq!(
        check(&leaf, &issuer, &http, now()),
        Err(CrlError::Http(HttpError::other("no route")))
    );
    let http = Fixed(Ok(HttpReply {
        status: 503,
        content_type: Some("text/plain".to_owned()),
        location: None,
        body: b"busy".to_vec(),
    }));
    assert_eq!(
        check(&leaf, &issuer, &http, now()),
        Err(CrlError::HttpStatus(503))
    );

    // No URL at all.
    assert_eq!(
        check(&leaf_with_cdp(&leaf, &[]), &issuer, &http, now()),
        Err(CrlError::NoUrl)
    );
}

/// A transport that records the options of each request and refuses a body of
/// `MAX_CRL_LEN + 1` bytes as `UreqTransport` does.
struct Oversized(Mutex<Vec<GetOptions>>);

impl HttpTransport for Oversized {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        match request.method {
            HttpMethod::Get => {
                let (_, opts) = (request.url, request.opts);
                self.0.lock().unwrap().push(opts);
                assert!(MAX_CRL_LEN + 1 > opts.max_len, "the limit admits the body");
                Err(HttpError::other(format!(
                    "body exceeds {} bytes",
                    opts.max_len
                )))
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

#[test]
fn oversized_body_is_rejected() {
    assert_eq!(TIMEOUT, Duration::from_secs(30));
    assert_eq!(MAX_CRL_LEN, 64 << 20);
    let http = Oversized(Mutex::new(Vec::new()));
    let leaf = leaf_with_cdp(&entry("inter-user-gost2015-sign").cert, &[INTER_CRL]);
    assert_eq!(
        check(&leaf, &cer("inter-gost2015"), &http, now()),
        Err(CrlError::Http(HttpError::other(format!(
            "body exceeds {MAX_CRL_LEN} bytes"
        ))))
    );
    assert_eq!(
        *http.0.lock().unwrap(),
        [GetOptions {
            timeout: TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            max_len: MAX_CRL_LEN,
            https_only: false,
            redirects: true,
        }]
    );

    // The mock honours the limit too.
    let mock = MockCrl::new(entry("inter-gost2015.key"));
    let len = u64::try_from(mock.der().len()).unwrap();
    let tight = GetOptions {
        timeout: TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
        max_len: len - 1,
        https_only: false,
        redirects: true,
    };
    assert!(mock.get_with(INTER_CRL, tight).is_err());
    let roomy = GetOptions {
        max_len: len + 64,
        ..tight
    };
    assert_eq!(mock.get_with(INTER_CRL, roomy).unwrap().status, 200);
}

#[test]
fn nca_root_crl_golden_vector() {
    // Recorded 2026-10-26 from the CDP of ncagost22: thisUpdate 2026-10-02 05:12:41 UTC,
    // nextUpdate 2026-11-06 05:12:41 UTC, no revoked certificates.
    let der = read(fixture("nca-crl/gost2015_2022.crl"));
    let root = nca("rcagost22");
    let at = datetime!(2026-10-26 00:00 UTC);
    let list = crl::verify_crl(&der, &root, at).unwrap();
    assert_eq!(
        crl::lookup(&list, serial(&nca("ncagost22"))),
        CrlStatus::Good
    );
    assert_eq!(
        crl::verify_crl(&der, &root, datetime!(2026-10-02 05:12:41 UTC)).map(|_| ()),
        Ok(())
    );
    assert_eq!(
        crl::verify_crl(&der, &root, datetime!(2026-10-02 05:12:40 UTC)).unwrap_err(),
        CrlError::NotYetValid
    );
    assert_eq!(
        crl::verify_crl(&der, &root, datetime!(2026-11-06 05:12:41 UTC)).unwrap_err(),
        CrlError::Outdated
    );
    assert_eq!(
        crl::verify_crl(&der, &nca("ncagost22"), at).unwrap_err(),
        CrlError::IssuerMismatch
    );
    // One flipped bit of the signature.
    let mut tampered = der.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        crl::verify_crl(&tampered, &root, at),
        Err(CrlError::BadSignature(_))
    ));

    // Through `fetch_for`, offline.
    let http = Fixed(Ok(HttpReply {
        status: 200,
        content_type: Some("application/pkix-crl".to_owned()),
        location: None,
        body: der,
    }));
    assert_eq!(
        check(&nca("ncagost22"), &root, &http, at),
        Ok(CrlStatus::Good)
    );
}

#[test]
#[ignore = "needs http://crl.root.gov.kz"]
fn live_crl_nca_root_gost_2022() {
    let (nca, root) = (nca("ncagost22"), nca("rcagost22"));
    let status = check(&nca, &root, &UreqTransport::default(), now());
    println!("CRL {:?}: {status:?}", crl::crl_urls(&nca));
    assert_eq!(status, Ok(CrlStatus::Good));
}

#[test]
fn fetch_for_cdp_and_freshest() {
    use x509_cert::ext::pkix::FreshestCrl;
    const BASE: &str = "http://crl.synthetic.test/base.crl";
    const DELTA: &str = "http://crl.synthetic.test/delta.crl";
    let issuer = cer("inter-gost2015");
    let key = entry("inter-gost2015.key");
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let good = entry("inter-user-gost2015-sign").cert;
    let at = now() - time::Duration::DAY;
    // A leaf with a distribution point and a FreshestCRL.
    let with_freshest = |leaf: &Certificate| {
        let base = leaf_with_cdp(leaf, &[BASE]);
        let freshest = FreshestCrl(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(Ia5String::new(DELTA).unwrap()),
            ])),
            reasons: None,
            crl_issuer: None,
        }]);
        let mut spec = TestCertSpec::from_cert(&base);
        spec.extensions.push(Extension {
            extn_id: FreshestCrl::OID,
            critical: false,
            extn_value: OctetString::new(freshest.to_der().unwrap()).unwrap(),
        });
        issue_cert(&key, spec)
    };
    let delta_indicator = Extension {
        extn_id: "2.5.29.27".parse().unwrap(),
        critical: true,
        extn_value: OctetString::new(vec![2, 1, 1]).unwrap(),
    };
    // The complete CRL lists the good key; the delta takes it off (removeFromCRL) and
    // lists the revoked one.
    let base = Arc::new(MockCrl::new(key.clone()).revoke(serial(&good), at));
    let delta = Arc::new(
        MockCrl::new(key.clone())
            .extension(delta_indicator)
            .revoke_with_reason(serial(&good), at, 8)
            .revoke(serial(&revoked), at),
    );
    let http = RouteTransport::new(vec![
        (BASE.to_owned(), Arc::clone(&base) as Arc<dyn HttpTransport>),
        (
            DELTA.to_owned(),
            Arc::clone(&delta) as Arc<dyn HttpTransport>,
        ),
    ]);
    let (crls, status) =
        crl::fetch_for(&with_freshest(&good), &issuer, &http, TIMEOUT, now()).unwrap();
    assert_eq!(status, CrlStatus::Good);
    assert_eq!(crls.len(), 2);
    let (_, status) =
        crl::fetch_for(&with_freshest(&revoked), &issuer, &http, TIMEOUT, now()).unwrap();
    assert!(matches!(status, CrlStatus::Revoked { .. }));
    // Without a FreshestCRL only the complete CRL is fetched.
    let (crls, status) = crl::fetch_for(
        &leaf_with_cdp(&good, &[BASE]),
        &issuer,
        &http,
        TIMEOUT,
        now(),
    )
    .unwrap();
    assert_eq!(crls.len(), 1);
    assert!(matches!(status, CrlStatus::Revoked { .. }));
    // A delta is never used without its complete CRL, and a complete CRL is not a delta.
    let only_delta = RouteTransport::new(vec![
        (
            BASE.to_owned(),
            Arc::clone(&delta) as Arc<dyn HttpTransport>,
        ),
        (
            DELTA.to_owned(),
            Arc::clone(&base) as Arc<dyn HttpTransport>,
        ),
    ]);
    assert!(matches!(
        crl::fetch_for(&with_freshest(&good), &issuer, &only_delta, TIMEOUT, now()),
        Err(CrlError::Malformed(_))
    ));
    let down = RouteTransport::new(Vec::new());
    assert_eq!(
        crl::fetch_for(&with_freshest(&good), &issuer, &down, TIMEOUT, now())
            .unwrap_err()
            .kind(),
        oncl_pki::http::NetKind::Other
    );
}

// ---- serial_status: the single-pass scan must decide exactly as the full decode does ----

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let length: Vec<u8> = value
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | length.len() as u8);
        out.extend(length);
    }
    out.extend_from_slice(value);
    out
}

/// `crl` with its `TBSCertList` bytes patched by `patch` and signed anew by `signer`, so
/// the damage survives the signature gate and reaches the structure checks.
fn resigned(crl: &[u8], signer: &KeyEntry, patch: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    use der::{Reader, SliceReader};
    let outer = AnyRef::from_der(crl).unwrap();
    let mut reader = SliceReader::new(outer.value()).unwrap();
    let mut tbs = reader.tlv_bytes().unwrap().to_vec();
    let algorithm = reader.tlv_bytes().unwrap().to_vec();
    patch(&mut tbs);
    let alg = match signer.key.alg() {
        oncl_pki::key::KeyAlg::Gost2004 => SigAlg::Gost2004,
        oncl_pki::key::KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
        oncl_pki::key::KeyAlg::Rsa => SigAlg::RsaSha256,
    };
    let signature = signer.key.sign(alg, &tbs).unwrap();
    let mut bits = vec![0u8];
    bits.extend(signature);
    der_tlv(0x30, &[tbs, algorithm, der_tlv(0x03, &bits)].concat())
}

/// What the full decode path answers, as `(status | error class)`.
fn full_decode(
    crl_der: &[u8],
    issuer: &Certificate,
    serial: &[u8],
    at: OffsetDateTime,
) -> Result<CrlStatus, std::mem::Discriminant<CrlError>> {
    crl::verify_crl(crl_der, issuer, at)
        .map(|list| crl::lookup(&list, serial))
        .map_err(|e| std::mem::discriminant(&e))
}

fn scanned(
    crl_der: &[u8],
    issuer: &Certificate,
    serial: &[u8],
    at: OffsetDateTime,
) -> Result<CrlStatus, std::mem::Discriminant<CrlError>> {
    crl::serial_status(crl_der, issuer, serial, at).map_err(|e| std::mem::discriminant(&e))
}

const SCAN_NOW: OffsetDateTime = datetime!(2026-11-02 12:00 UTC);

fn scan_crl() -> MockCrl {
    MockCrl::new(entry("inter-gost2015.key"))
        .with_this_update(SCAN_NOW - time::Duration::MINUTE)
        .next_update(Some(SCAN_NOW + time::Duration::HOUR))
}

/// The scan equals the full decode, and is the `expected` answer (which pins the case).
fn same_as_full_decode(
    crl_der: &[u8],
    serial: &[u8],
    at: OffsetDateTime,
    expected: Result<CrlStatus, CrlError>,
) {
    let issuer = cer("inter-gost2015");
    let expected = expected.map_err(|e| std::mem::discriminant(&e));
    assert_eq!(scanned(crl_der, &issuer, serial, at), expected, "scan");
    assert_eq!(full_decode(crl_der, &issuer, serial, at), expected, "full");
}

fn revoked(day: i64, reason: Option<u8>) -> CrlStatus {
    CrlStatus::Revoked {
        time: datetime!(2026-10-01 00:00 UTC) + time::Duration::days(day),
        reason,
    }
}

#[test]
fn scan_finds_first_middle_last_duplicate_and_absent_serials_like_the_full_decode() {
    let base = datetime!(2026-10-01 00:00 UTC);
    let mut crl = scan_crl();
    for n in 0..40u8 {
        crl = crl.revoke(&[0x10, n + 1], base);
    }
    crl = crl
        .revoke_with_reason(&[0x20, 1], base + time::Duration::days(1), 5)
        // The same serial again, later and with another reason: the first entry wins.
        .revoke_with_reason(&[0x20, 1], base + time::Duration::days(2), 1)
        .revoke(&[0x30, 9], base + time::Duration::days(3));
    let der = crl.der();
    same_as_full_decode(&der, &[0x10, 1], SCAN_NOW, Ok(revoked(0, None)));
    same_as_full_decode(&der, &[0x10, 20], SCAN_NOW, Ok(revoked(0, None)));
    same_as_full_decode(&der, &[0x10, 40], SCAN_NOW, Ok(revoked(0, None)));
    same_as_full_decode(&der, &[0x20, 1], SCAN_NOW, Ok(revoked(1, Some(5))));
    // The last entry of the list.
    same_as_full_decode(&der, &[0x30, 9], SCAN_NOW, Ok(revoked(3, None)));
    // Leading zeros of the asked serial do not matter; an absent serial is good.
    same_as_full_decode(&der, &[0, 0, 0x30, 9], SCAN_NOW, Ok(revoked(3, None)));
    same_as_full_decode(&der, &[0x40, 1], SCAN_NOW, Ok(CrlStatus::Good));
}

#[test]
fn scan_applies_the_time_window_like_the_full_decode() {
    let next = SCAN_NOW + time::Duration::HOUR;
    let der = scan_crl()
        .revoke(&[7], SCAN_NOW - time::Duration::DAY)
        .der();
    let this = SCAN_NOW - time::Duration::MINUTE;
    let late = |e: CrlError| Err::<CrlStatus, _>(e);
    same_as_full_decode(
        &der,
        &[7],
        this - time::Duration::SECOND,
        late(CrlError::NotYetValid),
    );
    same_as_full_decode(
        &der,
        &[7],
        this,
        Ok(CrlStatus::Revoked {
            time: SCAN_NOW - time::Duration::DAY,
            reason: None,
        }),
    );
    same_as_full_decode(
        &der,
        &[8],
        next - time::Duration::SECOND,
        Ok(CrlStatus::Good),
    );
    same_as_full_decode(&der, &[7], next, late(CrlError::Outdated));
    same_as_full_decode(
        &der,
        &[7],
        next + time::Duration::DAY,
        late(CrlError::Outdated),
    );
    // No nextUpdate: never outdated.
    let open = scan_crl().next_update(None).revoke(&[7], this).der();
    same_as_full_decode(
        &open,
        &[8],
        next + time::Duration::days(3650),
        Ok(CrlStatus::Good),
    );
}

fn unknown_extension(oid: &str, critical: bool) -> Extension {
    Extension {
        extn_id: oid.parse().unwrap(),
        critical,
        extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(),
    }
}

#[test]
fn scan_refuses_the_crl_extensions_the_full_decode_refuses() {
    let revoked_at = SCAN_NOW - time::Duration::DAY;
    let malformed = || Err(CrlError::Malformed(String::new()));
    for (name, extension) in [
        ("critical unknown", unknown_extension("1.2.3.4", true)),
        ("deltaCRLIndicator", unknown_extension("2.5.29.27", false)),
        (
            "deltaCRLIndicator critical",
            unknown_extension("2.5.29.27", true),
        ),
        (
            "issuingDistributionPoint",
            unknown_extension("2.5.29.28", false),
        ),
        (
            "issuingDistributionPoint critical",
            unknown_extension("2.5.29.28", true),
        ),
    ] {
        let der = scan_crl()
            .revoke(&[7], revoked_at)
            .extension(extension)
            .der();
        let _ = name;
        same_as_full_decode(&der, &[7], SCAN_NOW, malformed());
        same_as_full_decode(&der, &[8], SCAN_NOW, malformed());
    }
    // A non-critical unknown extension is ignored, as is a known critical one.
    let der = scan_crl()
        .revoke(&[7], revoked_at)
        .extension(unknown_extension("1.2.3.4", false))
        .der();
    same_as_full_decode(
        &der,
        &[7],
        SCAN_NOW,
        Ok(CrlStatus::Revoked {
            time: revoked_at,
            reason: None,
        }),
    );
}

#[test]
fn scan_refuses_a_damaged_entry_extension_even_for_other_serials() {
    // Turn the OID of one entry's extension into an OCTET STRING: still valid BER (so the
    // normalizer lets it pass), signed by the CRL's real issuer, so only the structure check
    // of the entries can catch it, and it must catch it for an unrelated serial too, as the
    // full decode does.
    let issuer = entry("inter-gost2015.key");
    let good = scan_crl()
        .revoke(&[1], SCAN_NOW - time::Duration::DAY)
        .revoke_with_reason(&[2], SCAN_NOW - time::Duration::DAY, 1)
        .revoke(&[3], SCAN_NOW - time::Duration::DAY)
        .der();
    let damaged = resigned(&good, &issuer, |tbs| {
        // 06 03 55 1d 15: the CRLReason extension id of entry [2].
        let at = tbs
            .windows(5)
            .position(|w| w == [0x06, 0x03, 0x55, 0x1d, 0x15])
            .expect("CRLReason extension");
        tbs[at] = 0x04;
    });
    let malformed = || Err(CrlError::Malformed(String::new()));
    same_as_full_decode(&damaged, &[1], SCAN_NOW, malformed());
    same_as_full_decode(&damaged, &[2], SCAN_NOW, malformed());
    same_as_full_decode(&damaged, &[9], SCAN_NOW, malformed());
    // The same CRL undamaged is fine, so the refusal is the damage.
    same_as_full_decode(
        &good,
        &[2],
        SCAN_NOW,
        Ok(CrlStatus::Revoked {
            time: SCAN_NOW - time::Duration::DAY,
            reason: Some(1),
        }),
    );
}

#[test]
fn scan_requires_the_version_field_like_the_full_decode() {
    // Remove `version INTEGER 1` from the TBS (a v1-looking CRL) and sign it anew: the full
    // decode refuses it, and the scan must not accept what the decode refuses.
    let issuer = entry("inter-gost2015.key");
    let der = scan_crl()
        .revoke(&[7], SCAN_NOW - time::Duration::DAY)
        .der();
    let v1 = resigned(&der, &issuer, |tbs| {
        let at = tbs
            .windows(3)
            .position(|w| w == [0x02, 0x01, 0x01])
            .expect("version");
        tbs.drain(at..at + 3);
        // Shrink the TBS SEQUENCE length (one-octet or two-octet form).
        if tbs[1] == 0x82 {
            let n = u16::from_be_bytes([tbs[2], tbs[3]]) - 3;
            tbs[2..4].copy_from_slice(&n.to_be_bytes());
        } else if tbs[1] == 0x81 {
            tbs[2] -= 3;
        } else {
            tbs[1] -= 3;
        }
    });
    let issuer = cer("inter-gost2015");
    assert!(crl::verify_crl(&v1, &issuer, SCAN_NOW).is_err());
    assert!(crl::serial_status(&v1, &issuer, &[7], SCAN_NOW).is_err());
}

#[test]
fn scan_uses_the_first_crl_reason_even_when_it_is_malformed() {
    let issuer = entry("inter-gost2015.key");
    let der = scan_crl()
        .revoke_with_reason(&[7], SCAN_NOW - time::Duration::DAY, 1)
        .der();
    // Break the ENUMERATED tag of the first (only) CRLReason value: the decode reads no reason.
    let broken = resigned(&der, &issuer, |tbs| {
        let at = tbs
            .windows(5)
            .position(|w| w == [0x06, 0x03, 0x55, 0x1d, 0x15])
            .unwrap();
        let value = tbs[at..]
            .windows(3)
            .position(|w| w == [0x0a, 0x01, 0x01])
            .unwrap();
        tbs[at + value] = 0x02;
    });
    same_as_full_decode(
        &broken,
        &[7],
        SCAN_NOW,
        Ok(CrlStatus::Revoked {
            time: SCAN_NOW - time::Duration::DAY,
            reason: None,
        }),
    );
}
