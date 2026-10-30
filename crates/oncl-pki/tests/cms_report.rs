//! CMS verification reports ([`oncl_pki::cms::report`]): each signer's signature,
//! signingCertificateV2, validity, certification path, revocation and time-stamp checked
//! apart, as the plugins that verify signatures need them.

use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader};
use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{
    AttrSpec, CertSpec, ChainPolicy, Check, CoSign, Content, NetStage, Problem, ReportSpec,
    Revocation, SignSpec, SignerReport, VerifyAt, report, sign_spec,
};
use oncl_pki::crl::MockCrl;
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport, RouteTransport};
use oncl_pki::http::{NonceSpec, PkiMethod};
use oncl_pki::info::{KeyUsageBits, cert_info};
use oncl_pki::key::HashAlg;
use oncl_pki::ocsp::{self, CertStatus, MockOcsp, RequestSpec};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::{self, MockTsa, SignerSel, StampMode, TokenForm, TsaProfile, TsaSpec};
use oncl_testkit::{read, synthetic, synthetic_cert};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use time::macros::datetime;

const DATA: &[u8] = b"report me";
const REVOKED_AT: OffsetDateTime = datetime!(2026-01-15 08:00 UTC);
const OCSP_ATTR: &str = "1.3.6.1.5.5.7.48.1.1";
const SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

/// The synthetic GOST 2015 CAs.
fn cas() -> CaSet {
    CaSet::new(vec![cer("root-gost2015"), cer("inter-gost2015")])
}

fn serial_hex(cert: &Certificate) -> String {
    cert.tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A CAdES signature of [`DATA`] by `key` at `at`, plus `extra` signed attributes.
fn signed(
    key: &str,
    encapsulate: bool,
    at: OffsetDateTime,
    extra: Vec<(&str, Vec<u8>)>,
) -> Vec<u8> {
    let mut attrs = AttrSpec::cades(at);
    for (oid, value) in extra {
        if oid == SIGNING_CERTIFICATE_V2 {
            attrs.signing_certificate_v2 = false;
        }
        attrs
            .extra
            .push((ObjectIdentifier::new(oid).unwrap(), vec![value]));
    }
    let spec = SignSpec {
        content: Content::Data(DATA),
        encapsulate,
        cosign: CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs,
        certificates: CertSpec::Signer,
    };
    sign_spec(&entry(key), &[], &spec).unwrap()
}

/// A transport without network.
struct Offline;

impl HttpTransport for Offline {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other(format!("offline: {}", request.url)))
    }
}

fn spec(cas: &CaSet, at: VerifyAt, revocation: Revocation) -> ReportSpec<'_> {
    ReportSpec {
        at,
        chain: ChainPolicy::Through(cas),
        trust: cas,
        revocation,
        first_signer_only: false,
        require_key_usage: KeyUsageBits::default(),
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn only(signers: Vec<SignerReport>) -> SignerReport {
    assert_eq!(signers.len(), 1);
    signers.into_iter().next().unwrap()
}

fn all_ok(signer: &SignerReport) {
    assert_eq!(signer.signature, Check::Ok, "{signer:?}");
    assert_eq!(signer.ess_cert_id, Check::Ok, "{signer:?}");
    assert_eq!(signer.validity, Check::Ok, "{signer:?}");
    assert_eq!(signer.path, Check::Ok, "{signer:?}");
}

/// The responders of the synthetic validation PKI: OCSP answers `revoked` for
/// `inter-revoked-gost2015-sign`, the CRL lists it when `crl` is set.
fn validation_pki(ocsp: bool, crl: bool) -> Arc<dyn HttpTransport> {
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let mut routes: Vec<(String, Arc<dyn HttpTransport>)> = Vec::new();
    if ocsp {
        let responder = MockOcsp::new(entry("ocsp-gost2015")).status(
            &serial_hex(&revoked),
            CertStatus::Revoked {
                time: REVOKED_AT,
                reason: Some(1),
            },
        );
        routes.push(("http://ocsp.synthetic.test".to_owned(), Arc::new(responder)));
    }
    if crl {
        let serial = revoked
            .tbs_certificate()
            .serial_number()
            .as_bytes()
            .to_vec();
        let crl = MockCrl::new(entry("inter-gost2015.key")).revoke(&serial, REVOKED_AT);
        routes.push(("http://crl.synthetic.test".to_owned(), Arc::new(crl)));
    }
    Arc::new(RouteTransport::new(routes))
}

/// The elements of the DER value `any`'s contents.
fn children(any: AnyRef<'_>) -> Vec<AnyRef<'_>> {
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut out = Vec::new();
    while !reader.is_finished() {
        out.push(reader.decode::<AnyRef<'_>>().unwrap());
    }
    out
}

/// A DER value of `tag` around `contents`.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(contents);
    out
}

/// `cms` without its certificates.
fn without_certificates(cms: &[u8]) -> Vec<u8> {
    let ci = children(AnyRef::from_der(cms).unwrap());
    let sd = children(children(ci[1])[0]);
    let kept: Vec<u8> = sd
        .iter()
        .filter(|e| e.to_der().unwrap()[0] != 0xa0)
        .flat_map(|e| e.to_der().unwrap())
        .collect();
    let sd = tlv(0x30, &kept);
    let mut ci_contents = ci[0].to_der().unwrap();
    ci_contents.extend(tlv(0xa0, &sd));
    tlv(0x30, &ci_contents)
}

/// `cms` with the last byte of signer 0's signature value flipped.
fn with_bad_signature(cms: &[u8]) -> Vec<u8> {
    let ci = children(AnyRef::from_der(cms).unwrap());
    let sd = children(children(ci[1])[0]);
    let si = children(children(*sd.last().unwrap())[0]);
    let signature = si
        .iter()
        .find(|e| e.to_der().unwrap()[0] == 0x04)
        .unwrap()
        .value();
    let at = cms
        .windows(signature.len())
        .position(|w| w == signature)
        .unwrap();
    let mut out = cms.to_vec();
    out[at + signature.len() - 1] ^= 1;
    out
}

#[test]
fn report_ok_attached_and_detached() {
    let cas = cas();
    let at = datetime!(2026-03-01 10:00 UTC);
    let attached = signed("user-gost2015-sign", true, at, vec![]);
    let r = report(
        &attached,
        None,
        &spec(&cas, VerifyAt::Now, Revocation::None),
        &Offline,
        now(),
    )
    .unwrap();
    assert_eq!(r.content.as_deref(), Some(DATA));
    let signer = only(r.signers);
    all_ok(&signer);
    assert_eq!(signer.revocation, Check::Skipped);
    assert_eq!(signer.tsp, None);
    assert_eq!(signer.signing_time, Some(at));
    assert_eq!(signer.certificate, Some(entry("user-gost2015-sign").cert));

    let detached = signed("user-gost2015-sign", false, at, vec![]);
    let s = spec(&cas, VerifyAt::Now, Revocation::None);
    let r = report(&detached, Some(DATA), &s, &Offline, now()).unwrap();
    assert_eq!(r.content, None);
    all_ok(&only(r.signers));
    let r = report(&detached, None, &s, &Offline, now()).unwrap();
    assert_eq!(only(r.signers).signature, Check::Fail(Problem::NoContent));
    let r = report(&detached, Some(b"other"), &s, &Offline, now()).unwrap();
    assert_eq!(
        only(r.signers).signature,
        Check::Fail(Problem::DigestMismatch)
    );
}

#[test]
fn report_first_signer_only() {
    let cas = cas();
    let at = datetime!(2026-03-01 10:00 UTC);
    let first = signed("user-gost2015-sign", true, at, vec![]);
    let second = SignSpec {
        content: Content::Data(&first),
        encapsulate: true,
        cosign: CoSign::Auto,
        econtent_type: None,
        digest: None,
        attrs: AttrSpec::cades(at),
        certificates: CertSpec::Signer,
    };
    let both = sign_spec(&entry("inter-user-gost2015-sign"), &[], &second).unwrap();
    let mut s = spec(&cas, VerifyAt::Now, Revocation::None);
    let r = report(&both, None, &s, &Offline, now()).unwrap();
    assert_eq!(r.signers.len(), 2);
    r.signers.iter().for_each(all_ok);
    s.first_signer_only = true;
    let signer = only(report(&both, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.certificate, Some(entry("user-gost2015-sign").cert));
}

#[test]
fn report_sid_cert_needs_key_usage() {
    let cas = cas();
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let bits = cert_info(&entry("user-gost2015-sign").cert).key_usage;
    assert!(bits.digital_signature && bits.non_repudiation && !bits.key_encipherment);
    let mut s = spec(&cas, VerifyAt::Now, Revocation::None);
    s.require_key_usage = KeyUsageBits {
        digital_signature: true,
        non_repudiation: true,
        ..KeyUsageBits::default()
    };
    all_ok(&only(
        report(&cms, None, &s, &Offline, now()).unwrap().signers,
    ));
    s.require_key_usage.key_encipherment = true;
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.certificate, None);
    assert_eq!(signer.signature, Check::Fail(Problem::NoSignerCert));
    assert_eq!(signer.validity, Check::Skipped);
}

#[test]
fn report_expired_at_signing_time() {
    let cas = cas();
    // Valid 2025-01-01 … 2026-01-01.
    let cms = signed(
        "inter-expired-gost2015-sign",
        true,
        datetime!(2025-06-01 10:00 UTC),
        vec![],
    );
    let s = spec(&cas, VerifyAt::Now, Revocation::None);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.validity, Check::Fail(Problem::Expired));
    assert_eq!(signer.path, Check::Ok);
    let s = spec(&cas, VerifyAt::SigningTime, Revocation::None);
    all_ok(&only(
        report(&cms, None, &s, &Offline, now()).unwrap().signers,
    ));
}

#[test]
fn report_not_yet_valid() {
    let cas = cas();
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2024-06-01 10:00 UTC),
        vec![],
    );
    let s = spec(&cas, VerifyAt::SigningTime, Revocation::None);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.validity, Check::Fail(Problem::NotYetValid));
    assert_eq!(signer.signature, Check::Ok);
}

#[test]
fn report_unknown_ca() {
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let rsa = CaSet::new(vec![cer("root-rsa")]);
    let s = spec(&rsa, VerifyAt::Now, Revocation::None);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.path, Check::Fail(Problem::UnknownCa));
    let skip = ReportSpec {
        chain: ChainPolicy::Skip,
        ..spec(&rsa, VerifyAt::Now, Revocation::None)
    };
    let signer = only(report(&cms, None, &skip, &Offline, now()).unwrap().signers);
    assert_eq!(signer.path, Check::Skipped);
    assert_eq!(signer.signature, Check::Ok);
}

#[test]
fn report_revoked_before_signing() {
    let cas = cas();
    let cms = signed(
        "inter-revoked-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let s = spec(&cas, VerifyAt::SigningTime, Revocation::LiveOcsp);
    let http = validation_pki(true, false);
    let signer = only(
        report(&cms, None, &s, http.as_ref(), now())
            .unwrap()
            .signers,
    );
    assert_eq!(
        signer.revocation,
        Check::Fail(Problem::Revoked {
            at: REVOKED_AT,
            reason: Some(1)
        })
    );
    // A good certificate of the same CA.
    let good = signed(
        "inter-user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let signer = only(
        report(&good, None, &s, http.as_ref(), now())
            .unwrap()
            .signers,
    );
    assert_eq!(signer.revocation, Check::Ok);
}

#[test]
fn report_revoked_after_signing_is_ok() {
    let cas = cas();
    let cms = signed(
        "inter-revoked-gost2015-sign",
        true,
        datetime!(2025-06-01 10:00 UTC),
        vec![],
    );
    let s = spec(&cas, VerifyAt::SigningTime, Revocation::LiveOcsp);
    let http = validation_pki(true, false);
    let signer = only(
        report(&cms, None, &s, http.as_ref(), now())
            .unwrap()
            .signers,
    );
    assert_eq!(signer.revocation, Check::Ok);
}

/// The OCSP response of the synthetic responder about `key`'s certificate: the whole
/// `OCSPResponse` and its `BasicOCSPResponse`.
fn ocsp_response(key: &str) -> (Vec<u8>, Vec<u8>) {
    let http = validation_pki(true, false);
    let leaf = entry(key).cert;
    let spec = RequestSpec {
        cert_id_hash: HashAlg::Sha256,
        nonce: NonceSpec::None,
        method: PkiMethod::Post { content_type: None },
        url: None,
        timeout: Duration::from_secs(5),
    };
    let fetched = ocsp::fetch(&leaf, &cer("inter-gost2015"), &spec, http.as_ref(), None).unwrap();
    (fetched.response, fetched.basic.unwrap())
}

fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

#[test]
fn report_embedded_ocsp() {
    let cas = cas();
    let s = spec(&cas, VerifyAt::Now, Revocation::EmbeddedOcsp);
    let (response, basic) = ocsp_response("inter-user-gost2015-sign");
    // OCTET{OCSPResponse}, OCTET{BasicOCSPResponse} and a bare BasicOCSPResponse.
    for value in [octets(&response), octets(&basic), basic.clone()] {
        let cms = signed(
            "inter-user-gost2015-sign",
            true,
            now(),
            vec![(OCSP_ATTR, value)],
        );
        let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
        all_ok(&signer);
        assert_eq!(signer.revocation, Check::Ok);
    }
    let (revoked, _) = ocsp_response("inter-revoked-gost2015-sign");
    let cms = signed(
        "inter-revoked-gost2015-sign",
        true,
        now(),
        vec![(OCSP_ATTR, octets(&revoked))],
    );
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(
        signer.revocation,
        Check::Fail(Problem::Revoked {
            at: REVOKED_AT,
            reason: Some(1)
        })
    );
    // The answer must be about the signer.
    let cms = signed(
        "inter-revoked-gost2015-sign",
        true,
        now(),
        vec![(OCSP_ATTR, octets(&response))],
    );
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.revocation, Check::Fail(Problem::StatusUnknown));
    // None embedded.
    let cms = signed("inter-user-gost2015-sign", true, now(), vec![]);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.revocation, Check::Fail(Problem::StatusUnknown));
}

#[test]
fn report_live_ocsp_then_crl() {
    let cas = cas();
    let cms = signed(
        "inter-revoked-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    // No OCSP responder: the CRL decides.
    let http = validation_pki(false, true);
    let s = spec(&cas, VerifyAt::SigningTime, Revocation::LiveOcspThenCrl);
    let signer = only(
        report(&cms, None, &s, http.as_ref(), now())
            .unwrap()
            .signers,
    );
    assert_eq!(
        signer.revocation,
        Check::Fail(Problem::Revoked {
            at: REVOKED_AT,
            reason: None
        })
    );
    let good = signed(
        "inter-user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let signer = only(
        report(&good, None, &s, http.as_ref(), now())
            .unwrap()
            .signers,
    );
    assert_eq!(signer.revocation, Check::Ok);
    // OCSP only: the network failure is the answer.
    let s = spec(&cas, VerifyAt::SigningTime, Revocation::LiveOcsp);
    let signer = only(
        report(&cms, None, &s, http.as_ref(), now())
            .unwrap()
            .signers,
    );
    match signer.revocation {
        Check::Fail(Problem::Net(failure)) => {
            assert_eq!(failure.stage, NetStage::Ocsp);
            assert_eq!(failure.url, "http://ocsp.synthetic.test");
        }
        other => panic!("{other:?}"),
    }
    // Neither.
    let s = spec(&cas, VerifyAt::SigningTime, Revocation::LiveOcspThenCrl);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    match signer.revocation {
        Check::Fail(Problem::Net(failure)) => assert_eq!(failure.stage, NetStage::Crl),
        other => panic!("{other:?}"),
    }
}

/// `cms` time-stamped by the mock TSA at `gen_time`.
fn stamped(cms: &[u8], gen_time: OffsetDateTime) -> Vec<u8> {
    let tsa = MockTsa::new(entry("tsa-gost2015")).with_gen_time(gen_time);
    tsp::stamp(
        cms,
        SignerSel::Last,
        &TsaSpec::from(TsaProfile::basics_default()),
        StampMode::Replace,
        TokenForm::Token,
        &tsa,
    )
    .unwrap()
}

#[test]
fn report_tsp_gen_time_and_imprint() {
    let cas = cas();
    let gen_time = datetime!(2025-06-01 10:05 UTC);
    // Expired now, valid at the time-stamp.
    let cms = signed(
        "inter-expired-gost2015-sign",
        true,
        datetime!(2025-06-01 10:00 UTC),
        vec![],
    );
    let cms = stamped(&cms, gen_time);
    let s = spec(&cas, VerifyAt::TspTime, Revocation::None);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    all_ok(&signer);
    let tsp = signer.tsp.unwrap();
    assert_eq!(tsp.gen_time, Some(gen_time));
    assert_eq!(tsp.check, Check::Ok);
    assert_eq!(tsp.tsa_cert, Some(entry("tsa-gost2015").cert));
    // The token of another signature.
    let bad = with_bad_signature(&cms);
    let signer = only(report(&bad, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(
        signer.tsp.unwrap().check,
        Check::Fail(Problem::TspImprintMismatch)
    );
    // An unproven time: the certificate is judged now.
    assert_eq!(signer.validity, Check::Fail(Problem::Expired));
}

#[test]
fn report_tsp_missing() {
    let cas = cas();
    let cms = signed(
        "inter-expired-gost2015-sign",
        true,
        datetime!(2025-06-01 10:00 UTC),
        vec![],
    );
    let s = spec(&cas, VerifyAt::TspTime, Revocation::None);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.tsp, None);
    assert_eq!(signer.validity, Check::Fail(Problem::Expired));
}

#[test]
fn report_ess_cert_id_mismatch() {
    let cas = cas();
    let other = Sha256::digest(synthetic_cert("root-gost2015"));
    let ess = tlv(0x30, &tlv(0x30, &tlv(0x30, &octets(&other))));
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![(SIGNING_CERTIFICATE_V2, ess)],
    );
    let s = spec(&cas, VerifyAt::Now, Revocation::None);
    let signer = only(report(&cms, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.ess_cert_id, Check::Fail(Problem::EssCertIdMismatch));
    assert_eq!(signer.signature, Check::Ok);
    // Without the attribute.
    let mut attrs = AttrSpec::cades(datetime!(2026-03-01 10:00 UTC));
    attrs.signing_certificate_v2 = false;
    let plain = sign_spec(
        &entry("user-gost2015-sign"),
        &[],
        &SignSpec {
            content: Content::Data(DATA),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: None,
            digest: None,
            attrs,
            certificates: CertSpec::Signer,
        },
    )
    .unwrap();
    let signer = only(report(&plain, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.ess_cert_id, Check::Skipped);
}

#[test]
fn report_no_signer_cert() {
    let cas = cas();
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let bare = without_certificates(&cms);
    let s = spec(&cas, VerifyAt::Now, Revocation::None);
    let signer = only(report(&bare, None, &s, &Offline, now()).unwrap().signers);
    assert_eq!(signer.certificate, None);
    assert_eq!(signer.signature, Check::Fail(Problem::NoSignerCert));
    assert_eq!(signer.path, Check::Skipped);
    assert_eq!(signer.signing_time, Some(datetime!(2026-03-01 10:00 UTC)));
}

#[test]
fn report_bad_signature() {
    let cas = cas();
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let s = spec(&cas, VerifyAt::Now, Revocation::None);
    let signer = only(
        report(&with_bad_signature(&cms), None, &s, &Offline, now())
            .unwrap()
            .signers,
    );
    assert_eq!(signer.signature, Check::Fail(Problem::BadSignature));
    assert_eq!(signer.ess_cert_id, Check::Ok);
    assert_eq!(signer.path, Check::Ok);
    // Not a CMS at all.
    assert!(report(b"not a cms", None, &s, &Offline, now()).is_err());
}
