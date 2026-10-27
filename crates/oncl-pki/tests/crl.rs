//! CRL client: verification, serial lookup, the on-disk cache and the CDP URL order,
//! against `MockCrl` with the synthetic intermediate PKI, plus a golden vector: a CRL of the
//! NCA root (GOST 2022) checked offline.

use der::asn1::{AnyRef, BitStringRef, Ia5String, OctetString};
use der::oid::AssociatedOid;
use der::{Decode, Encode, Sequence, Tag};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::crl::{
    self, CrlCache, CrlError, CrlStatus, MAX_BER_CRL_LEN, MAX_CRL_LEN, MockCrl, TIMEOUT,
};
use oncl_pki::http::{
    CONNECT_TIMEOUT, GetOptions, HttpError, HttpReply, HttpTransport, RouteTransport, UreqTransport,
};
use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::testing::{TestCertSpec, issue_cert};
use oncl_testkit::{fixture, read, synthetic, synthetic_cert};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
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

/// A fresh cache directory under the target directory, removed when dropped.
fn temp_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("oncl-crl-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// `<dir>/<hex sha256(url)>.crl`.
fn cache_file(dir: &Path, url: &str) -> PathBuf {
    let hash: String = Sha256::digest(url.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    dir.join(format!("{hash}.crl"))
}

/// Names of the files in `dir`, sorted.
fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
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
    fn get(&self, _: &str) -> Result<HttpReply, HttpError> {
        self.0.clone()
    }

    fn post(&self, url: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
        self.get(url)
    }
}

/// A transport that records every requested URL and fails it.
#[derive(Default)]
struct Down(Mutex<Vec<String>>);

impl Down {
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl HttpTransport for Down {
    fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
        self.0.lock().unwrap().push(url.to_owned());
        Err(HttpError("down".to_owned()))
    }

    fn post(&self, url: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
        self.get(url)
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
    // the root's (how `cms-verify` uses it).
    let dir = temp_dir();
    let cache = CrlCache::new(dir.path());
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
        crl::check(&revoked, &issuer, &cache, &http, now()),
        Ok(CrlStatus::Revoked {
            time: revoked_at,
            reason: None
        })
    );
    assert_eq!(
        crl::check(&good, &issuer, &cache, &http, now()),
        Ok(CrlStatus::Good)
    );
    assert_eq!(
        crl::check(&issuer, &cer("root-gost2015"), &cache, &http, now()),
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
    let http = Fixed(Err(HttpError("must not be asked".to_owned())));
    let dir = temp_dir();
    assert_eq!(
        crl::check(
            &leaf,
            &cer("root-gost2015"),
            &CrlCache::new(dir.path()),
            &http,
            now()
        ),
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
fn cache_hit_makes_no_request_until_next_update() {
    let issuer = cer("inter-gost2015");
    let start = now();
    let next = start + time::Duration::HOUR;
    let mock = MockCrl::new(entry("inter-gost2015.key")).next_update(Some(next));
    let dir = temp_dir();
    let cache = CrlCache::new(dir.path().join("crl"));
    let file = cache_file(&dir.path().join("crl"), INTER_CRL);

    let first = cache.fetch(INTER_CRL, &issuer, &mock, start).unwrap();
    assert_eq!(mock.calls(), [INTER_CRL]);
    assert_eq!(
        CertificateList::from_der(&read(&file)).unwrap(),
        first,
        "the downloaded CRL is cached"
    );
    // Written atomically: no temporary file is left behind.
    assert_eq!(files(&dir.path().join("crl")).len(), 1);

    let later = start + 30 * time::Duration::MINUTE;
    assert_eq!(cache.fetch(INTER_CRL, &issuer, &mock, later), Ok(first));
    assert_eq!(mock.calls().len(), 1, "served from the cache");
    // Another URL has its own file.
    let other = "http://crl.synthetic.test/other.crl";
    cache.fetch(other, &issuer, &mock, later).unwrap();
    assert_eq!(mock.calls(), [INTER_CRL, other]);
    assert_eq!(files(&dir.path().join("crl")).len(), 2);

    // Past nextUpdate the cache is stale: downloaded again (the mock serves the same
    // outdated CRL, which is refused).
    let after = next + time::Duration::SECOND;
    assert_eq!(
        cache.fetch(INTER_CRL, &issuer, &mock, after),
        Err(CrlError::Outdated)
    );
    assert_eq!(mock.calls().len(), 3);

    // A corrupt cache file is downloaded again and replaced.
    std::fs::write(&file, b"corrupt").unwrap();
    cache.fetch(INTER_CRL, &issuer, &mock, later).unwrap();
    assert_eq!(mock.calls().len(), 4);
    assert!(crl::verify_crl(&read(&file), &issuer, later).is_ok());
    // A cached CRL of another issuer is not used.
    let twin = cer("inter-gost2015-twin");
    assert!(matches!(
        cache.fetch(INTER_CRL, &twin, &mock, later),
        Err(CrlError::BadSignature(_))
    ));
    assert_eq!(mock.calls().len(), 5);

    // Without nextUpdate there is no expiry to cache until: every fetch downloads.
    let open = MockCrl::new(entry("inter-gost2015.key")).next_update(None);
    let url = "http://crl.synthetic.test/open.crl";
    cache.fetch(url, &issuer, &open, start).unwrap();
    cache.fetch(url, &issuer, &open, start).unwrap();
    assert_eq!(open.calls().len(), 2);
    assert!(!cache_file(&dir.path().join("crl"), url).exists());
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
    let dir = temp_dir();
    let cache = CrlCache::new(dir.path());
    assert_eq!(
        crl::check(&leaf, &issuer, &cache, &http, now()),
        Ok(CrlStatus::Revoked {
            time: revoked_at,
            reason: None
        })
    );
    assert_eq!(forged.calls().len(), 1);
    assert_eq!(good.calls().len(), 1);
    // Only the verified CRL is cached; the next check needs no request.
    assert_eq!(
        files(dir.path()),
        [cache_file(dir.path(), INTER_CRL)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()]
    );
    // A later check uses the cached CRL of the third URL without asking the network for
    // the first two.
    let down = Down::default();
    assert!(matches!(
        crl::check(&leaf, &issuer, &cache, &down, now()),
        Ok(CrlStatus::Revoked { .. })
    ));
    assert_eq!(down.calls(), [] as [String; 0]);
    assert!(cache.cached(INTER_CRL, &issuer, now()).is_some());
    assert!(
        cache
            .cached(INTER_CRL, &cer("inter-gost2015-twin"), now())
            .is_none()
    );
    assert!(
        cache
            .cached("http://down.synthetic.test/a.crl", &issuer, now())
            .is_none()
    );
    // Past its nextUpdate the cached CRL is not used: the URLs are tried in order.
    let later = now() + 2 * time::Duration::HOUR;
    assert_eq!(
        crl::check(&leaf, &issuer, &cache, &down, later),
        Err(CrlError::Http("down".to_owned()))
    );
    assert_eq!(
        down.calls(),
        [
            "http://down.synthetic.test/a.crl",
            "http://forged.synthetic.test/a.crl",
            INTER_CRL
        ]
    );

    // Every URL fails: the error of the last one.
    let dir = temp_dir();
    let cache = CrlCache::new(dir.path());
    let http = RouteTransport::new(vec![(
        "http://forged.synthetic.test/".to_owned(),
        forged.clone() as Arc<dyn HttpTransport>,
    )]);
    assert_eq!(
        crl::check(&leaf, &issuer, &cache, &http, now()),
        Err(CrlError::Http("no route".to_owned()))
    );
    let http = Fixed(Ok(HttpReply {
        status: 503,
        content_type: Some("text/plain".to_owned()),
        body: b"busy".to_vec(),
    }));
    assert_eq!(
        crl::check(&leaf, &issuer, &cache, &http, now()),
        Err(CrlError::HttpStatus(503))
    );
    assert!(files(dir.path()).is_empty());

    // No URL at all.
    assert_eq!(
        crl::check(&leaf_with_cdp(&leaf, &[]), &issuer, &cache, &http, now()),
        Err(CrlError::NoUrl)
    );
}

/// A transport that records the options of each request and refuses a body of
/// `MAX_CRL_LEN + 1` bytes as `UreqTransport` does.
struct Oversized(Mutex<Vec<GetOptions>>);

impl HttpTransport for Oversized {
    fn get(&self, url: &str) -> Result<HttpReply, HttpError> {
        self.get_with(url, GetOptions::default())
    }

    fn get_with(&self, _: &str, opts: GetOptions) -> Result<HttpReply, HttpError> {
        self.0.lock().unwrap().push(opts);
        assert!(MAX_CRL_LEN + 1 > opts.max_len, "the limit admits the body");
        Err(HttpError(format!("body exceeds {} bytes", opts.max_len)))
    }

    fn post(&self, url: &str, _: &str, _: &[u8]) -> Result<HttpReply, HttpError> {
        self.get(url)
    }
}

#[test]
fn oversized_body_is_rejected() {
    assert_eq!(TIMEOUT, Duration::from_secs(30));
    assert_eq!(MAX_CRL_LEN, 64 << 20);
    let http = Oversized(Mutex::new(Vec::new()));
    let dir = temp_dir();
    let cache = CrlCache::new(dir.path());
    assert_eq!(
        cache.fetch(INTER_CRL, &cer("inter-gost2015"), &http, now()),
        Err(CrlError::Http(format!("body exceeds {MAX_CRL_LEN} bytes")))
    );
    assert_eq!(
        *http.0.lock().unwrap(),
        [GetOptions {
            timeout: TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            max_len: MAX_CRL_LEN
        }]
    );
    assert!(files(dir.path()).is_empty());

    // The mock honours the limit too.
    let mock = MockCrl::new(entry("inter-gost2015.key"));
    let len = u64::try_from(mock.der().len()).unwrap();
    let tight = GetOptions {
        timeout: TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
        max_len: len - 1,
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

    // Through the cache, offline.
    let dir = temp_dir();
    let cache = CrlCache::new(dir.path());
    let http = Fixed(Ok(HttpReply {
        status: 200,
        content_type: Some("application/pkix-crl".to_owned()),
        body: der,
    }));
    assert_eq!(
        crl::check(&nca("ncagost22"), &root, &cache, &http, at),
        Ok(CrlStatus::Good)
    );
    assert!(cache_file(dir.path(), NCA_ROOT_CRL).exists());
}

#[test]
#[ignore = "needs http://crl.root.gov.kz"]
fn live_crl_nca_root_gost_2022() {
    let (nca, root) = (nca("ncagost22"), nca("rcagost22"));
    let dir = temp_dir();
    let cache = CrlCache::new(dir.path());
    let status = crl::check(&nca, &root, &cache, &UreqTransport::default(), now());
    println!("CRL {:?}: {status:?}", crl::crl_urls(&nca));
    assert_eq!(status, Ok(CrlStatus::Good));
}
