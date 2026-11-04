//! CMS signer facts ([`oncl_pki::cms::report`]): each signer's certificate, signingTime,
//! signature, signingCertificateV2 and time-stamp token, checked apart. Trust, validity,
//! certification paths and revocation are decided by the one shared validator
//! (`oncl_pki::validation`, tested by `oncl-core/tests/validation_policy.rs`), not here.

use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader};
use oncl_pki::cms::{
    AttrSpec, CertSpec, Check, CoSign, Content, Problem, ReportSpec, SignSpec, SignerReport,
    report, sign_spec,
};
use oncl_pki::info::{KeyUsageBits, cert_info};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::{self, MockTsa, SignerSel, StampMode, TokenForm, TsaProfile, TsaSpec};
use oncl_testkit::{read, synthetic, synthetic_cert};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::macros::datetime;

const DATA: &[u8] = b"report me";
const SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
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

fn only(signers: Vec<SignerReport>) -> SignerReport {
    assert_eq!(signers.len(), 1);
    signers.into_iter().next().unwrap()
}

fn all_ok(signer: &SignerReport) {
    assert_eq!(signer.signature, Check::Ok, "{signer:?}");
    assert_eq!(signer.ess_cert_id, Check::Ok, "{signer:?}");
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

fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
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
    let at = datetime!(2026-03-01 10:00 UTC);
    let attached = signed("user-gost2015-sign", true, at, vec![]);
    let r = report(&attached, None, &ReportSpec::default()).unwrap();
    assert_eq!(r.content.as_deref(), Some(DATA));
    let signer = only(r.signers);
    all_ok(&signer);
    assert_eq!(signer.tsp, None);
    assert_eq!(signer.signing_time, Some(at));
    assert_eq!(signer.certificate, Some(entry("user-gost2015-sign").cert));

    let detached = signed("user-gost2015-sign", false, at, vec![]);
    let s = ReportSpec::default();
    let r = report(&detached, Some(DATA), &s).unwrap();
    assert_eq!(r.content, None);
    all_ok(&only(r.signers));
    let r = report(&detached, None, &s).unwrap();
    assert_eq!(only(r.signers).signature, Check::Fail(Problem::NoContent));
    let r = report(&detached, Some(b"other"), &s).unwrap();
    assert_eq!(
        only(r.signers).signature,
        Check::Fail(Problem::DigestMismatch)
    );
}

#[test]
fn report_first_signer_only() {
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
    let mut s = ReportSpec::default();
    let r = report(&both, None, &s).unwrap();
    assert_eq!(r.signers.len(), 2);
    r.signers.iter().for_each(all_ok);
    s.first_signer_only = true;
    let signer = only(report(&both, None, &s).unwrap().signers);
    assert_eq!(signer.certificate, Some(entry("user-gost2015-sign").cert));
}

#[test]
fn report_sid_cert_needs_key_usage() {
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let bits = cert_info(&entry("user-gost2015-sign").cert).key_usage;
    assert!(bits.digital_signature && bits.non_repudiation && !bits.key_encipherment);
    let mut s = ReportSpec {
        require_key_usage: KeyUsageBits {
            digital_signature: true,
            non_repudiation: true,
            ..KeyUsageBits::default()
        },
        ..ReportSpec::default()
    };
    all_ok(&only(report(&cms, None, &s).unwrap().signers));
    s.require_key_usage.key_encipherment = true;
    let signer = only(report(&cms, None, &s).unwrap().signers);
    assert_eq!(signer.certificate, None);
    assert_eq!(signer.signature, Check::Fail(Problem::NoSignerCert));
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
    let gen_time = datetime!(2025-06-01 10:05 UTC);
    let cms = signed(
        "inter-expired-gost2015-sign",
        true,
        datetime!(2025-06-01 10:00 UTC),
        vec![],
    );
    let cms = stamped(&cms, gen_time);
    let s = ReportSpec::default();
    let signer = only(report(&cms, None, &s).unwrap().signers);
    all_ok(&signer);
    let tsp = signer.tsp.unwrap();
    assert_eq!(tsp.gen_time, Some(gen_time));
    assert_eq!(tsp.check, Check::Ok);
    assert_eq!(tsp.tsa_cert, Some(entry("tsa-gost2015").cert));
    // The token of another signature.
    let bad = with_bad_signature(&cms);
    let signer = only(report(&bad, None, &s).unwrap().signers);
    assert_eq!(
        signer.tsp.unwrap().check,
        Check::Fail(Problem::TspImprintMismatch)
    );
}

#[test]
fn report_tsp_missing() {
    let cms = signed(
        "inter-expired-gost2015-sign",
        true,
        datetime!(2025-06-01 10:00 UTC),
        vec![],
    );
    let signer = only(report(&cms, None, &ReportSpec::default()).unwrap().signers);
    assert_eq!(signer.tsp, None);
}

#[test]
fn report_ess_cert_id_mismatch() {
    let other = Sha256::digest(synthetic_cert("root-gost2015"));
    let ess = tlv(0x30, &tlv(0x30, &tlv(0x30, &octets(&other))));
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![(SIGNING_CERTIFICATE_V2, ess)],
    );
    let s = ReportSpec::default();
    let signer = only(report(&cms, None, &s).unwrap().signers);
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
    let signer = only(report(&plain, None, &s).unwrap().signers);
    assert_eq!(signer.ess_cert_id, Check::Skipped);
}

#[test]
fn report_no_signer_cert() {
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let bare = without_certificates(&cms);
    let signer = only(report(&bare, None, &ReportSpec::default()).unwrap().signers);
    assert_eq!(signer.certificate, None);
    assert_eq!(signer.signature, Check::Fail(Problem::NoSignerCert));
    assert_eq!(signer.signing_time, Some(datetime!(2026-03-01 10:00 UTC)));
}

#[test]
fn report_bad_signature() {
    let cms = signed(
        "user-gost2015-sign",
        true,
        datetime!(2026-03-01 10:00 UTC),
        vec![],
    );
    let s = ReportSpec::default();
    let signer = only(report(&with_bad_signature(&cms), None, &s).unwrap().signers);
    assert_eq!(signer.signature, Check::Fail(Problem::BadSignature));
    assert_eq!(signer.ess_cert_id, Check::Ok);
    // Not a CMS at all.
    assert!(report(b"not a cms", None, &s).is_err());
}
