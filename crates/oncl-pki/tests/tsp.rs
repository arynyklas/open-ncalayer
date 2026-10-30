//! RFC 3161 time-stamping with the NCA GET binding: the request, the mock TSA, checks of the
//! reply, a response of the NCA test TSA saved by NCANode and the live NCA test TSA.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader, Tag, Tagged};
use oncl_pki::cms::{SignOptions, sign, verify};
use oncl_pki::http::{
    HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport, NetKind, NonceSpec, PkiMethod,
    ProxySetting, UreqTransport,
};
use oncl_pki::key::{HashAlg, SigAlg};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::tsp::{
    self, MockTamper, MockTsa, SignerSel, StampMode, TokenForm, TsaMethod, TsaProfile, TsaSpec,
    TspError, TspHash, parse_response, request_der, stamp, timestamp_signer, verify_token,
    verify_token_for,
};
use oncl_testkit::{ncanode, read, synthetic};
use sha1::Digest as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use time::macros::datetime;

const STREEBOG_512: &str = "1.2.398.3.10.1.3.3";
const BASICS_POLICY: &str = "1.2.398.3.3.2.6.4";
const TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

fn opts(encapsulate: bool) -> SignOptions {
    SignOptions {
        encapsulate,
        digested: false,
        signing_time: datetime!(2026-03-01 10:20:30 UTC),
    }
}

fn tsa() -> MockTsa {
    MockTsa::new(entry("tsa-gost2015"))
}

fn signed(name: &str) -> Vec<u8> {
    sign(&entry(name), b"d", &opts(true)).unwrap()
}

fn streebog512(data: &[u8]) -> Vec<u8> {
    SigAlg::Gost2015_512.digest(data)
}

/// Elements of a constructed value.
fn children(any: AnyRef<'_>) -> Vec<AnyRef<'_>> {
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut out = Vec::new();
    while !reader.is_finished() {
        out.push(reader.decode::<AnyRef<'_>>().unwrap());
    }
    out
}

fn oid(any: AnyRef<'_>) -> String {
    any.decode_as::<ObjectIdentifier>().unwrap().to_string()
}

/// `SignerInfo` elements of signer `index` of a DER `ContentInfo{SignedData}`.
fn signer_info(cms: &[u8], index: usize) -> Vec<AnyRef<'_>> {
    let ci = children(AnyRef::from_der(cms).unwrap());
    let sd = children(children(ci[1])[0]);
    let signers = children(*sd.last().unwrap());
    children(signers[index])
}

/// The `signature` OCTET STRING contents of signer `index`.
fn signer_signature(cms: &[u8], index: usize) -> Vec<u8> {
    signer_info(cms, index)
        .into_iter()
        .find(|e| e.tag() == Tag::OctetString)
        .unwrap()
        .value()
        .to_vec()
}

/// `[1] IMPLICIT` unsigned attributes of signer `index`, as `(type, values)`.
fn unsigned_attrs(cms: &[u8], index: usize) -> Vec<(String, usize)> {
    let si = signer_info(cms, index);
    let Some(attrs) = si
        .iter()
        .find(|e| e.tag().is_context_specific() && e.tag().number() == der::TagNumber(1))
    else {
        return Vec::new();
    };
    children(*attrs)
        .into_iter()
        .map(|a| {
            let a = children(a);
            (oid(a[0]), children(a[1]).len())
        })
        .collect()
}

fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

fn base64_decode(b: &[u8]) -> Vec<u8> {
    STANDARD.decode(b).unwrap()
}

/// Fields of a `TimeStampReq`.
#[derive(Debug)]
struct Req {
    version: u8,
    alg: String,
    alg_params: Vec<u8>,
    imprint: Vec<u8>,
    policy: String,
    /// Contents of the nonce INTEGER.
    nonce: Vec<u8>,
    cert_req: bool,
}

fn decode_timestamp_req(der: &[u8]) -> Req {
    let req = children(AnyRef::from_der(der).unwrap());
    assert_eq!(
        req.len(),
        5,
        "version, messageImprint, reqPolicy, nonce, certReq"
    );
    let imprint = children(req[1]);
    let alg = children(imprint[0]);
    assert_eq!(alg.len(), 2);
    assert_eq!(req[3].tag(), Tag::Integer);
    Req {
        version: req[0].decode_as().unwrap(),
        alg: oid(alg[0]),
        alg_params: alg[1].to_der().unwrap(),
        imprint: imprint[1]
            .decode_as::<&der::asn1::OctetStringRef>()
            .unwrap()
            .as_bytes()
            .to_vec(),
        policy: oid(req[2]),
        nonce: req[3].value().to_vec(),
        cert_req: req[4].decode_as().unwrap(),
    }
}

#[test]
fn request_structure() {
    let der = request_der(&TsaProfile::basics_default(), &[7; 64], &[42]);
    let req = decode_timestamp_req(&der);
    assert_eq!(req.version, 1);
    assert_eq!(req.alg, STREEBOG_512);
    assert_eq!(req.alg_params, [0x05, 0x00], "NULL parameters");
    assert_eq!(req.imprint, [7; 64]);
    assert_eq!(req.policy, BASICS_POLICY);
    assert_eq!(req.nonce, [42]);
    assert!(req.cert_req);

    // The nonce is an unsigned number: a set top bit gets a leading zero, leading zeros go.
    let der = request_der(&TsaProfile::basics_default(), &[7; 64], &[0x80, 0]);
    assert_eq!(decode_timestamp_req(&der).nonce, [0, 0x80, 0]);
    let der = request_der(&TsaProfile::basics_default(), &[7; 64], &[0, 0, 5]);
    assert_eq!(decode_timestamp_req(&der).nonce, [5]);
}

#[test]
fn basics_default_profile() {
    let p = TsaProfile::basics_default();
    assert_eq!(p.url, "http://tsp.pki.gov.kz");
    assert_eq!(p.method, TsaMethod::Get);
    assert_eq!(p.hash, TspHash::Streebog512);
    assert_eq!(p.policy.to_string(), BASICS_POLICY);
}

#[test]
fn get_url_is_percent_encoded() {
    let t = tsa();
    let cms = timestamp_signer(
        &signed("user-gost2015-sign"),
        0,
        &TsaProfile::basics_default(),
        &t,
    )
    .unwrap();
    let calls = t.calls();
    assert_eq!(calls.len(), 1);
    let url = &calls[0];
    let tail = url.strip_prefix("http://tsp.pki.gov.kz/").unwrap();
    assert!(!tail.contains(['+', '/', '=']), "{tail}");
    assert!(
        tail.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)),
        "{tail}"
    );
    let der = base64_decode(&percent_decode(tail));
    let req = decode_timestamp_req(&der);
    assert_eq!(req.policy, BASICS_POLICY);
    assert_eq!(req.imprint, streebog512(&signer_signature(&cms, 0)));
    // 8 random bytes as a minimal non-negative INTEGER: at most 9 octets, never negative,
    // a leading 00 only before a set top bit — for any random value, leading zeros included.
    let n = &req.nonce;
    assert!(!n.is_empty() && n.len() <= 9, "{n:02x?}");
    assert_eq!(n[0] & 0x80, 0, "negative nonce {n:02x?}");
    assert!(n.len() == 1 || n[0] != 0 || n[1] & 0x80 != 0, "{n:02x?}");
}

#[test]
fn timestamp_roundtrip_with_mock() {
    let mock = tsa();
    let e2015 = entry("user-gost2015-sign");
    let cms = timestamp_signer(
        &sign(&e2015, b"d", &opts(true)).unwrap(),
        0,
        &TsaProfile::basics_default(),
        &mock,
    )
    .unwrap();
    let s = verify(&cms, None).unwrap();
    let tst = verify_token(s[0].timestamp_token.as_ref().unwrap()).unwrap();
    assert_eq!(
        tst.imprint,
        streebog512(&signer_signature(&cms, 0)).to_vec()
    );
    assert_eq!(tst.imprint_alg.to_string(), STREEBOG_512);
    assert_eq!(tst.policy.to_string(), BASICS_POLICY);
    // The token echoes the request's nonce INTEGER, contents octets and all.
    let calls = mock.calls();
    let tail = calls[0].strip_prefix("http://tsp.pki.gov.kz/").unwrap();
    let req = decode_timestamp_req(&base64_decode(&percent_decode(tail)));
    assert_eq!(tst.nonce, Some(req.nonce));
    let age = time::OffsetDateTime::now_utc() - tst.gen_time;
    assert!(age.whole_minutes().abs() < 5, "{}", tst.gen_time);
    assert_eq!(unsigned_attrs(&cms, 0), [(TIME_STAMP_TOKEN.to_owned(), 1)]);
}

#[test]
fn token_is_bound_to_its_signature() {
    let mock = tsa();
    let profiles = [
        TsaProfile::basics_default(),
        TsaProfile {
            hash: TspHash::Sha256,
            ..TsaProfile::basics_default()
        },
    ];
    for profile in profiles {
        let cms = timestamp_signer(&signed("user-gost2015-sign"), 0, &profile, &mock).unwrap();
        let s = verify(&cms, None).unwrap();
        assert_eq!(s[0].signature, signer_signature(&cms, 0));
        let token = s[0].timestamp_token.as_ref().unwrap();
        let (tst, tsa) = verify_token_for(token, &s[0].signature).unwrap();
        assert_eq!(tst.imprint_alg, profile.hash.oid());
        assert_eq!(tsa, entry("tsa-gost2015").cert);

        // The token of another signature (the same content and key, a fresh random k).
        let other = verify(&signed("user-gost2015-sign"), None).unwrap();
        assert_ne!(other[0].signature, s[0].signature);
        assert_eq!(
            verify_token_for(token, &other[0].signature),
            Err(TspError::ImprintMismatch)
        );
    }
}

#[test]
fn hash_from_oid() {
    for h in [TspHash::Streebog512, TspHash::Sha256, TspHash::Gost34311] {
        assert_eq!(TspHash::from_oid(&h.oid()), Some(h));
    }
    assert_eq!(
        TspHash::from_oid(&ObjectIdentifier::new_unwrap("1.3.14.3.2.26")),
        None
    );
}

#[test]
fn post_binding_with_mock() {
    let mock = tsa();
    let profile = TsaProfile {
        method: TsaMethod::Post,
        ..TsaProfile::basics_default()
    };
    let cms = timestamp_signer(&signed("user-gost2015-sign"), 0, &profile, &mock).unwrap();
    assert_eq!(mock.calls(), ["http://tsp.pki.gov.kz"]);
    let s = verify(&cms, None).unwrap();
    verify_token(s[0].timestamp_token.as_ref().unwrap()).unwrap();
}

#[test]
fn imprint_follows_profile_hash() {
    for (hash, alg, digest) in [
        (TspHash::Sha256, "2.16.840.1.101.3.4.2.1", SigAlg::RsaSha256),
        (TspHash::Gost34311, "1.2.398.3.10.1.3.1", SigAlg::Gost2004),
        (TspHash::Streebog512, STREEBOG_512, SigAlg::Gost2015_512),
    ] {
        let profile = TsaProfile {
            hash,
            ..TsaProfile::basics_default()
        };
        let cms = timestamp_signer(&signed("user-rsa-sign"), 0, &profile, &tsa()).unwrap();
        let s = verify(&cms, None).unwrap();
        let tst = verify_token(s[0].timestamp_token.as_ref().unwrap()).unwrap();
        assert_eq!(tst.imprint_alg.to_string(), alg);
        assert_eq!(tst.imprint, digest.digest(&signer_signature(&cms, 0)));
    }
}

#[test]
fn nonce_mismatch_rejected() {
    let mock = tsa().with_tamper(MockTamper::Nonce);
    let r = timestamp_signer(
        &signed("user-gost2015-sign"),
        0,
        &TsaProfile::basics_default(),
        &mock,
    );
    assert_eq!(r, Err(TspError::NonceMismatch));
}

#[test]
fn negative_nonce_echo_rejected() {
    let mock = tsa().with_tamper(MockTamper::NegativeNonce);
    let r = timestamp_signer(
        &signed("user-gost2015-sign"),
        0,
        &TsaProfile::basics_default(),
        &mock,
    );
    assert_eq!(r, Err(TspError::NonceMismatch));
}

#[test]
fn token_with_negative_nonce_verifies() {
    // Kalkan's TSA clients send signed random nonces: about half of real tokens carry a
    // negative one, and they are valid tokens all the same.
    for nonce in [
        &[0x80][..],
        &[0xff],
        &[0x9c, 0x3e, 0x51, 0x07, 0xaa, 0x10, 0x2d, 0x48],
        &[0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
        let cms = tsa()
            .stamp_with_nonce(&signed("user-gost2015-sign"), 0, nonce)
            .unwrap();
        let s = verify(&cms, None).unwrap();
        assert_eq!(unsigned_attrs(&cms, 0), [(TIME_STAMP_TOKEN.to_owned(), 1)]);
        let token = s[0].timestamp_token.as_ref().unwrap();
        let (tst, tsa) = verify_token_for(token, &s[0].signature).unwrap();
        assert_eq!(tst.nonce.as_deref(), Some(nonce));
        assert_eq!(tst.imprint, streebog512(&s[0].signature));
        assert_eq!(tst.policy.to_string(), BASICS_POLICY);
        assert_eq!(tsa, entry("tsa-gost2015").cert);
    }
}

#[test]
fn tsa_certificate_needs_time_stamping_eku() {
    let mock = MockTsa::new(entry("user-gost2015-sign"));
    let r = timestamp_signer(
        &signed("user-gost2015-sign"),
        0,
        &TsaProfile::basics_default(),
        &mock,
    );
    assert_eq!(r, Err(TspError::NoTsaCertificate));
}

#[test]
fn timestamps_the_requested_cosigner_only() {
    let a = signed("user-gost2015-sign");
    let b = sign(&entry("user-rsa-sign"), &a, &opts(true)).unwrap();
    let cms = timestamp_signer(&b, 1, &TsaProfile::basics_default(), &tsa()).unwrap();
    let s = verify(&cms, None).unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].timestamp_token, None);
    let tst = verify_token(s[1].timestamp_token.as_ref().unwrap()).unwrap();
    assert_eq!(tst.imprint, streebog512(&signer_signature(&cms, 1)));
    // Signer 0 is kept byte for byte.
    assert_eq!(
        signer_info(&cms, 0)
            .iter()
            .map(|e| e.to_der().unwrap())
            .collect::<Vec<_>>(),
        signer_info(&b, 0)
            .iter()
            .map(|e| e.to_der().unwrap())
            .collect::<Vec<_>>()
    );

    assert!(matches!(
        timestamp_signer(&b, 2, &TsaProfile::basics_default(), &tsa()),
        Err(TspError::Malformed(_))
    ));
}

#[test]
fn timestamping_again_replaces_the_token() {
    let mock = tsa();
    let once = timestamp_signer(
        &signed("user-gost2015-sign"),
        0,
        &TsaProfile::basics_default(),
        &mock,
    )
    .unwrap();
    let twice = timestamp_signer(&once, 0, &TsaProfile::basics_default(), &mock).unwrap();
    assert_eq!(
        unsigned_attrs(&twice, 0),
        [(TIME_STAMP_TOKEN.to_owned(), 1)]
    );
    let s = verify(&twice, None).unwrap();
    let first = verify(&once, None).unwrap()[0].timestamp_token.clone();
    assert_ne!(s[0].timestamp_token, first);
    verify_token(s[0].timestamp_token.as_ref().unwrap()).unwrap();
}

/// A transport answering every request with a fixed reply, recording the requests.
struct Fixed {
    reply: HttpReply,
    seen: Mutex<Vec<Vec<u8>>>,
}

impl Fixed {
    fn new(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Self {
        Fixed {
            reply: HttpReply {
                status,
                content_type: content_type.map(str::to_owned),
                location: None,
                body,
            },
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl HttpTransport for Fixed {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        match request.method {
            HttpMethod::Get => {
                let (url, _) = (request.url, request.opts);
                self.seen.lock().unwrap().push(url.as_bytes().to_vec());
                Ok(self.reply.clone())
            }
            HttpMethod::Post => {
                let (_url, _content_type, body, _) = (
                    request.url,
                    request.content_type.unwrap_or_default(),
                    request.body,
                    request.opts,
                );
                self.seen.lock().unwrap().push(body.to_vec());
                Ok(self.reply.clone())
            }
        }
    }
}

/// A complete reply of the mock TSA (for some other request).
fn mock_reply() -> Vec<u8> {
    let mock = tsa();
    let der = request_der(&TsaProfile::basics_default(), &[1; 64], &[9]);
    let profile = TsaProfile {
        method: TsaMethod::Post,
        ..TsaProfile::basics_default()
    };
    mock.post(&profile.url, "application/timestamp-query", &der)
        .unwrap()
        .body
}

const REPLY: &str = "application/timestamp-reply";

#[test]
fn http_status_and_content_type_are_checked() {
    let cms = signed("user-gost2015-sign");
    let p = TsaProfile::basics_default();
    let t = Fixed::new(503, Some(REPLY), mock_reply());
    assert_eq!(
        timestamp_signer(&cms, 0, &p, &t),
        Err(TspError::Status(503))
    );
    let t = Fixed::new(200, Some("text/html"), mock_reply());
    assert_eq!(
        timestamp_signer(&cms, 0, &p, &t),
        Err(TspError::ContentType(Some("text/html".to_owned())))
    );
    let t = Fixed::new(200, None, mock_reply());
    assert_eq!(
        timestamp_signer(&cms, 0, &p, &t),
        Err(TspError::ContentType(None))
    );
    // Parameters and case do not matter.
    let t = Fixed::new(200, Some("Application/Timestamp-Reply; x=1"), mock_reply());
    assert_eq!(
        timestamp_signer(&cms, 0, &p, &t),
        Err(TspError::NonceMismatch)
    );
}

#[test]
fn replayed_reply_is_rejected() {
    // A valid token for another request: the nonce gives it away first.
    let t = Fixed::new(200, Some(REPLY), mock_reply());
    let r = timestamp_signer(
        &signed("user-gost2015-sign"),
        0,
        &TsaProfile::basics_default(),
        &t,
    );
    assert_eq!(r, Err(TspError::NonceMismatch));
}

#[test]
fn token_with_two_signers_is_rejected_before_verification() {
    let (token, _) = parse_response(&mock_reply()).unwrap();
    // A co-signature by the same TSA: still a TSTInfo, now with two valid signers.
    let two = sign(&entry("tsa-gost2015"), &token, &opts(true)).unwrap();
    assert_eq!(verify(&two, None).unwrap().len(), 2);
    let expected = TspError::Malformed("time-stamp token has 2 signers".to_owned());
    assert_eq!(verify_token(&two), Err(expected.clone()));

    // Break the second signature: if signatures were checked first, this would be a
    // `BadSignature(1)` CMS error; the count rejects the token before any verification.
    let signature = signer_signature(&two, 1);
    let at = two
        .windows(signature.len())
        .position(|w| w == signature)
        .unwrap();
    let mut broken = two.clone();
    broken[at + signature.len() - 1] ^= 1;
    assert!(verify(&broken, None).is_err());
    assert_eq!(verify_token(&broken), Err(expected));
}

#[test]
fn rejection_status_is_reported() {
    // TimeStampResp { PKIStatusInfo { rejection(2), failInfo badAlg } } without a token.
    let body = vec![
        0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x02, 0x03, 0x02, 0x07, 0x80,
    ];
    let t = Fixed::new(200, Some(REPLY), body.clone());
    let r = timestamp_signer(
        &signed("user-gost2015-sign"),
        0,
        &TsaProfile::basics_default(),
        &t,
    );
    assert_eq!(r, Err(TspError::Rejected(2)));
    assert_eq!(parse_response(&body), Err(TspError::Rejected(2)));
}

#[test]
fn hostile_replies_are_errors_not_panics() {
    let good = mock_reply();
    parse_response(&good).unwrap();
    for len in 0..good.len() {
        assert!(parse_response(&good[..len]).is_err(), "truncated to {len}");
    }
    // Every header byte near the start, then a sample (each flip that reaches the
    // signature costs a GOST verification).
    for i in (0..good.len()).filter(|i| *i < 64 || i % 7 == 0) {
        let mut bad = good.clone();
        bad[i] ^= 0x41;
        // Anything but a panic; most flips are errors.
        let _ = parse_response(&bad);
    }
    assert!(matches!(
        parse_response(b"<html>gateway timeout</html>"),
        Err(TspError::Malformed(_))
    ));
    // Granted, but without a token.
    assert!(matches!(
        parse_response(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00]),
        Err(TspError::Malformed(_))
    ));
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn parses_ncanode_tsp_response() {
    let (tok, tst) = parse_response(&read(ncanode("tsp_response.bin"))).unwrap();
    assert_eq!(verify_token(&tok).unwrap(), tst);
    assert_eq!(tok, read(ncanode("tsp_token.bin")));
    assert_eq!(tst.policy.to_string(), "1.2.398.3.3.2.6.1");
    assert_eq!(tst.imprint_alg.to_string(), "1.3.14.3.2.26");
    assert_eq!(
        tst.nonce.as_deref(),
        Some(&[0x01, 0x83, 0x50, 0xc0, 0x22, 0xd7][..])
    );
    assert_eq!(tst.gen_time, datetime!(2022-09-18 13:20:14 UTC));

    // NCANode's TspServiceTest asked for a SHA-1 imprint of CA FE BA BE: the original's
    // SHA-1 tokens verify (bound to the stamped bytes), and other bytes are a mismatch.
    assert_eq!(
        verify_token_for(&tok, &[0xca, 0xfe, 0xba, 0xbe]).unwrap().0,
        tst
    );
    assert_eq!(
        verify_token_for(&tok, &[1, 2, 3]),
        Err(TspError::ImprintMismatch)
    );
}

/// DER TLV; `content` is shorter than 128 bytes.
fn short_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = u8::try_from(content.len())
        .ok()
        .filter(|l| *l < 0x80)
        .unwrap();
    [&[tag, len][..], content].concat()
}

/// A token of the mock TSA for a request with `imprint` under the hash algorithm `alg`, as
/// another client (e.g. one asking for SHA-1) gets it. Our own requests cannot use SHA-1.
fn token_with_imprint(alg: &str, imprint: &[u8]) -> Vec<u8> {
    let alg = ObjectIdentifier::new_unwrap(alg).to_der().unwrap();
    let alg_id = short_tlv(0x30, &[&alg[..], &[0x05, 0x00]].concat());
    let message_imprint = short_tlv(0x30, &[alg_id, short_tlv(0x04, imprint)].concat());
    let policy = ObjectIdentifier::new_unwrap(BASICS_POLICY)
        .to_der()
        .unwrap();
    let request = short_tlv(
        0x30,
        &[
            short_tlv(0x02, &[1]),
            message_imprint,
            policy,
            short_tlv(0x02, &[9]),
            short_tlv(0x01, &[0xff]),
        ]
        .concat(),
    );
    let reply = tsa()
        .post("http://tsa", "application/timestamp-query", &request)
        .unwrap();
    assert_eq!(reply.status, 200);
    parse_response(&reply.body).unwrap().0
}

#[test]
fn sha1_imprints_verify_but_are_never_requested() {
    const SHA1: &str = "1.3.14.3.2.26";
    assert_eq!(TspHash::from_oid(&ObjectIdentifier::new_unwrap(SHA1)), None);

    let signature = signer_signature(&signed("user-gost2015-sign"), 0);
    let sha1 = sha1::Sha1::digest(&signature).to_vec();
    let token = token_with_imprint(SHA1, &sha1);
    let (tst, _) = verify_token_for(&token, &signature).unwrap();
    assert_eq!(tst.imprint_alg.to_string(), SHA1);
    assert_eq!(tst.imprint, sha1);
    assert_eq!(
        verify_token_for(&token, b"another signature"),
        Err(TspError::ImprintMismatch)
    );

    // An imprint hash nobody here computes is reported as such, not as a mismatch.
    const MD5: &str = "1.2.840.113549.2.5";
    let token = token_with_imprint(MD5, &[0; 16]);
    assert_eq!(
        verify_token_for(&token, &signature),
        Err(TspError::UnsupportedImprintAlgorithm(
            ObjectIdentifier::new_unwrap(MD5)
        ))
    );
}

/// An HTTP request or reply head, up to the blank line.
fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap() == 1 {
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

/// The value of header `name` in `head`.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// The `Proxy-Authorization` the stub proxy wants: user `u@s`, password `p:w`.
const PROXY_CREDENTIALS: &str = "Basic dUBzOnA6dw==";

/// A one-thread HTTP server in front of `tsa` for `connections` connections, as if it were
/// the TSA at `http://tsp.invalid`. As a proxy (`proxy`) it is configured like a stock
/// Squid: it refuses `CONNECT` to any port but 443, and serves absolute-form requests
/// (`GET http://tsp.invalid/…`) with the right `Proxy-Authorization`. Otherwise it is the
/// TSA itself (origin-form). Returns its URL and, once joined, the request lines it got.
fn tsa_server(
    tsa: Arc<MockTsa>,
    connections: usize,
    proxy: bool,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().unwrap();
            let head = read_head(&mut stream);
            let request_line = head.lines().next().unwrap().to_owned();
            seen.push(request_line.clone());
            let mut parts = request_line.split(' ');
            let (method, target) = (parts.next().unwrap(), parts.next().unwrap());
            let refusal = if method == "CONNECT" && !target.ends_with(":443") {
                Some("403 Forbidden")
            } else if proxy && header(&head, "proxy-authorization") != Some(PROXY_CREDENTIALS) {
                Some("407 Proxy Authentication Required")
            } else if proxy && !target.starts_with("http://tsp.invalid/") {
                Some("400 Bad Request")
            } else {
                None
            };
            if let Some(status) = refusal {
                let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
                stream.write_all(reply.as_bytes()).unwrap();
                continue;
            }
            let mut body =
                vec![0; header(&head, "content-length").map_or(0, |n| n.parse().unwrap())];
            stream.read_exact(&mut body).unwrap();
            let target = match target.strip_prefix("http://tsp.invalid") {
                Some(path) => format!("http://tsp.invalid{path}"),
                None => format!("http://tsp.invalid{target}"),
            };
            let reply = match method {
                "GET" => tsa.get(&target),
                _ => tsa.post(&target, header(&head, "content-type").unwrap_or(""), &body),
            }
            .unwrap();
            let content_type = reply.content_type.unwrap_or_default();
            let reply_head = format!(
                "HTTP/1.1 {} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                reply.status,
                reply.body.len()
            );
            stream.write_all(reply_head.as_bytes()).unwrap();
            stream.write_all(&reply.body).unwrap();
        }
        seen
    });
    (url, server)
}

/// A GET and a POST time stamp from `url` through `transport`.
fn timestamp_both_ways(url: &str, transport: &UreqTransport) {
    for method in [TsaMethod::Get, TsaMethod::Post] {
        let profile = TsaProfile {
            url: url.to_owned(),
            method,
            ..TsaProfile::basics_default()
        };
        let cms = timestamp_signer(&signed("user-gost2015-sign"), 0, &profile, transport)
            .unwrap_or_else(|e| panic!("{method:?}: {e}"));
        let s = verify(&cms, None).unwrap();
        verify_token(s[0].timestamp_token.as_ref().unwrap()).unwrap();
    }
}

#[test]
fn timestamp_through_a_manual_proxy() {
    let mock = Arc::new(tsa());
    let (proxy, seen) = tsa_server(Arc::clone(&mock), 2, true);
    let proxy = proxy.replace("http://", "http://u%40s:p%3Aw@");
    let transport = UreqTransport::with_proxy(ProxySetting::Manual(proxy));
    // `.invalid` resolves nowhere: only the proxy can reach it.
    timestamp_both_ways("http://tsp.invalid/tsp", &transport);
    let seen = seen.join().unwrap();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen[0].starts_with("GET http://tsp.invalid/tsp/") && seen[0].ends_with(" HTTP/1.1"),
        "{seen:?}"
    );
    assert_eq!(seen[1], "POST http://tsp.invalid/tsp HTTP/1.1");
    assert_eq!(mock.calls().len(), 2);
}

#[test]
fn stub_proxy_refuses_what_a_stock_proxy_refuses() {
    let mock = Arc::new(tsa());
    let (proxy, seen) = tsa_server(Arc::clone(&mock), 2, true);
    let raw = |request: &str| {
        let mut stream = TcpStream::connect(proxy.trim_start_matches("http://")).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        read_head(&mut stream)
    };
    let tunnel = raw("CONNECT tsp.invalid:80 HTTP/1.1\r\nHost: tsp.invalid:80\r\n\r\n");
    assert!(tunnel.starts_with("HTTP/1.1 403 "), "{tunnel}");
    let anonymous = raw("GET http://tsp.invalid/tsp/x HTTP/1.1\r\nHost: tsp.invalid\r\n\r\n");
    assert!(anonymous.starts_with("HTTP/1.1 407 "), "{anonymous}");
    seen.join().unwrap();
    assert!(mock.calls().is_empty());
}

#[test]
fn timestamp_directly_by_default() {
    let mock = Arc::new(tsa());
    let (server, seen) = tsa_server(Arc::clone(&mock), 2, false);
    timestamp_both_ways(&format!("{server}/tsp"), &UreqTransport::default());
    let seen = seen.join().unwrap();
    assert!(seen[0].starts_with("GET /tsp/"), "{seen:?}");
    assert_eq!(seen[1], "POST /tsp HTTP/1.1");
}

#[test]
#[ignore = "network"]
fn live_test_tsa() {
    for method in [TsaMethod::Get, TsaMethod::Post] {
        let profile = TsaProfile {
            url: "http://test.pki.gov.kz/tsp".to_owned(),
            method,
            ..TsaProfile::basics_default()
        };
        let cms = timestamp_signer(
            &signed("user-gost2015-sign"),
            0,
            &profile,
            &UreqTransport::default(),
        )
        .unwrap();
        let s = verify(&cms, None).unwrap();
        let tst = verify_token(s[0].timestamp_token.as_ref().unwrap()).unwrap();
        println!("{method:?}: {tst:?}");
    }
}

/// The value of the first id-aa-timeStampToken attribute of signer `index`, DER.
fn token_value(cms: &[u8], index: usize) -> Vec<u8> {
    let si = signer_info(cms, index);
    let attrs = si
        .iter()
        .find(|e| e.tag().is_context_specific() && e.tag().number() == der::TagNumber(1))
        .unwrap();
    let attr = children(children(*attrs)[0]);
    assert_eq!(oid(attr[0]), TIME_STAMP_TOKEN);
    children(attr[1])[0].to_der().unwrap()
}

fn basics_spec() -> TsaSpec {
    TsaSpec::from(TsaProfile::basics_default())
}

#[test]
fn stamp_replace_vs_append() {
    let mock = tsa();
    let spec = basics_spec();
    let stamp_with = |cms: &[u8], mode| {
        stamp(cms, SignerSel::Last, &spec, mode, TokenForm::Token, &mock).unwrap()
    };
    let once = stamp_with(&signed("user-gost2015-sign"), StampMode::Replace);
    let replaced = stamp_with(&once, StampMode::Replace);
    assert_eq!(
        unsigned_attrs(&replaced, 0),
        [(TIME_STAMP_TOKEN.to_owned(), 1)]
    );
    let appended = stamp_with(&once, StampMode::Append);
    assert_eq!(
        unsigned_attrs(&appended, 0),
        [
            (TIME_STAMP_TOKEN.to_owned(), 1),
            (TIME_STAMP_TOKEN.to_owned(), 1)
        ]
    );
    verify(&appended, None).unwrap();
}

#[test]
fn stamp_all_unstamped() {
    let mock = tsa();
    let spec = basics_spec();
    let first = stamp(
        &signed("user-gost2015-sign"),
        SignerSel::Index(0),
        &spec,
        StampMode::Replace,
        TokenForm::Token,
        &mock,
    )
    .unwrap();
    let first_token = token_value(&first, 0);
    let two = sign(&entry("user-rsa-sign"), &first, &opts(true)).unwrap();
    let three = sign(&entry("user-gost2004-sign"), &two, &opts(true)).unwrap();
    let all = stamp(
        &three,
        SignerSel::AllUnstamped,
        &spec,
        StampMode::Replace,
        TokenForm::Token,
        &mock,
    )
    .unwrap();
    assert_eq!(
        mock.calls().len(),
        3,
        "the stamped signer is not asked again"
    );
    for index in 0..3 {
        assert_eq!(
            unsigned_attrs(&all, index),
            [(TIME_STAMP_TOKEN.to_owned(), 1)]
        );
    }
    assert_eq!(token_value(&all, 0), first_token);
    assert_eq!(verify(&all, None).unwrap().len(), 3);
}

#[test]
fn whole_response_token_form() {
    let mock = tsa();
    let cms = stamp(
        &signed("user-gost2015-sign"),
        SignerSel::Last,
        &basics_spec(),
        StampMode::Replace,
        TokenForm::WholeResponse,
        &mock,
    )
    .unwrap();
    let (token, _) = parse_response(&token_value(&cms, 0)).unwrap();
    verify_token_for(&token, &signer_signature(&cms, 0)).unwrap();
}

#[test]
fn sha1_and_sha512_imprints() {
    for hash in [HashAlg::Sha1, HashAlg::Sha512, HashAlg::Gost34311] {
        let spec = TsaSpec {
            hash,
            ..basics_spec()
        };
        let cms = stamp(
            &signed("user-rsa-sign"),
            SignerSel::Last,
            &spec,
            StampMode::Replace,
            TokenForm::Token,
            &tsa(),
        )
        .unwrap();
        let (tst, _) = verify_token_for(&token_value(&cms, 0), &signer_signature(&cms, 0)).unwrap();
        assert_eq!(tst.imprint_alg, hash.oid(), "{hash:?}");
    }
}

#[test]
fn post_with_path_binding() {
    let mock = tsa();
    let spec = TsaSpec {
        method: PkiMethod::PostWithPath,
        ..basics_spec()
    };
    let reply = tsp::request(&spec, &[7; 64], &mock).unwrap();
    let url = &mock.calls()[0];
    let encoded = url.strip_prefix("http://tsp.pki.gov.kz/").unwrap();
    let requests = mock.requests();
    assert_eq!(
        percent_decode(encoded),
        STANDARD.encode(&requests[0]).as_bytes()
    );
    assert_eq!(reply.tst.imprint, [7; 64]);

    // The raw GET binding: the base64 as it is, `+`, `/` and `=` included.
    let raw = TsaSpec {
        method: PkiMethod::Get,
        ..basics_spec()
    };
    let mock = tsa();
    tsp::request(&raw, &[0xfb; 64], &mock).unwrap();
    let url = &mock.calls()[0];
    assert_eq!(
        url.strip_prefix("http://tsp.pki.gov.kz/").unwrap(),
        STANDARD.encode(&mock.requests()[0])
    );
}

#[test]
fn no_policy_request() {
    let mock = tsa();
    let spec = TsaSpec {
        policy: None,
        nonce: NonceSpec::None,
        cert_req: false,
        ..basics_spec()
    };
    tsp::request(&spec, &[7; 64], &mock).unwrap();
    let request = mock.requests().remove(0);
    let fields = children(AnyRef::from_der(&request).unwrap());
    // version and messageImprint only.
    assert_eq!(fields.len(), 2);

    // A given nonce goes out as it is.
    let spec = TsaSpec {
        nonce: NonceSpec::Value(vec![1, 2, 3]),
        ..basics_spec()
    };
    let reply = tsp::request(&spec, &[7; 64], &mock).unwrap();
    assert_eq!(reply.tst.nonce.as_deref(), Some(&[1, 2, 3][..]));
}

#[test]
fn retries_until_success() {
    let spec = TsaSpec {
        retries: 2,
        ..basics_spec()
    };
    let mock = tsa().with_failures(2);
    tsp::request(&spec, &[7; 64], &mock).unwrap();
    assert_eq!(mock.calls().len(), 3);
    let spec = TsaSpec {
        retries: 1,
        ..basics_spec()
    };
    let mock = tsa().with_failures(2);
    let e = tsp::request(&spec, &[7; 64], &mock).unwrap_err();
    assert_eq!(e, TspError::Status(503));
    assert_eq!(e.kind(), NetKind::Http(503));
    assert_eq!(mock.calls().len(), 2);
}

#[test]
fn skew_check_rejects() {
    let hour_ago = time::OffsetDateTime::now_utc() - time::Duration::HOUR;
    let spec = TsaSpec {
        check_skew: Some(std::time::Duration::from_secs(300)),
        ..basics_spec()
    };
    let e = tsp::request(&spec, &[7; 64], &tsa().with_gen_time(hour_ago)).unwrap_err();
    assert_eq!(e, TspError::ClockSkew);
    assert_eq!(e.kind(), NetKind::ClockSkew);
    tsp::request(&spec, &[7; 64], &tsa()).unwrap();
    tsp::request(&basics_spec(), &[7; 64], &tsa().with_gen_time(hour_ago)).unwrap();
}

#[test]
fn tsa_eku_required() {
    // A TSA whose certificate lacks the timeStamping key usage.
    let mock = MockTsa::new(entry("user-gost2015-sign"));
    assert_eq!(
        tsp::request(&basics_spec(), &[7; 64], &mock).unwrap_err(),
        TspError::NoTsaCertificate
    );
    let lenient = TsaSpec {
        require_tsa_eku: false,
        ..basics_spec()
    };
    let reply = tsp::request(&lenient, &[7; 64], &mock).unwrap();
    assert_eq!(reply.tsa_cert, entry("user-gost2015-sign").cert);
}
