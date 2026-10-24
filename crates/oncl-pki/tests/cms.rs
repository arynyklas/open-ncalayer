//! CMS signing, co-signing and verification: the CMSUtil.createCAdES profile, BER input from
//! the original NCALayer, and a CAdES signature made by the original NCALayer.

use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader, Tagged};
use oncl_pki::cms::{CmsError, SignOptions, sign, signer_count, to_pem, verify};
use oncl_pki::info::cert_info;
use oncl_pki::key::{KeyError, SigAlg};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_testkit::{ncanode, read, synthetic};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::macros::datetime;

const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
const ID_DATA: &str = "1.2.840.113549.1.7.1";
const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

const SIGNING_AT: OffsetDateTime = datetime!(2026-03-01 10:20:30 UTC);

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
        signing_time: SIGNING_AT,
    }
}

fn digested() -> SignOptions {
    SignOptions {
        encapsulate: false,
        digested: true,
        signing_time: SIGNING_AT,
    }
}

/// Elements of a constructed value, as raw TLVs.
fn children(any: AnyRef<'_>) -> Vec<AnyRef<'_>> {
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut out = Vec::new();
    while !reader.is_finished() {
        out.push(reader.decode::<AnyRef<'_>>().unwrap());
    }
    out
}

fn tlv(any: AnyRef<'_>) -> Vec<u8> {
    any.to_der().unwrap()
}

fn oid(any: AnyRef<'_>) -> String {
    any.decode_as::<ObjectIdentifier>().unwrap().to_string()
}

/// `SignedData` elements of a DER `ContentInfo`.
fn signed_data(cms: &[u8]) -> Vec<AnyRef<'_>> {
    let content_info = AnyRef::from_der(cms).unwrap();
    let ci = children(content_info);
    assert_eq!(oid(ci[0]), ID_SIGNED_DATA);
    let explicit = children(ci[1]);
    children(explicit[0])
}

/// Header octets of a constructed element with an indefinite length.
fn indefinite(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, 0x80];
    out.extend_from_slice(body);
    out.extend_from_slice(&[0, 0]);
    out
}

/// Re-encodes a DER `ContentInfo{SignedData}` as BC/Kalkan BER does: the outer
/// `ContentInfo`, the `[0]` wrapper, `SignedData`, `EncapsulatedContentInfo` and its `[0]`
/// with indefinite lengths, and the eContent as a constructed OCTET STRING in two segments.
fn to_ber_indefinite(der: &[u8]) -> Vec<u8> {
    let content_info = AnyRef::from_der(der).unwrap();
    let ci = children(content_info);
    let sd = children(children(ci[1])[0]);
    let mut sd_body = Vec::new();
    for (i, element) in sd.iter().enumerate() {
        if i == 2 {
            let encap = children(*element);
            let mut encap_body = tlv(encap[0]);
            if let Some(explicit) = encap.get(1) {
                let octets = children(*explicit)[0].value();
                let (a, b) = octets.split_at(octets.len() / 2);
                let mut segments = Vec::new();
                for part in [a, b] {
                    segments.extend(
                        der::asn1::OctetStringRef::new(part)
                            .unwrap()
                            .to_der()
                            .unwrap(),
                    );
                }
                encap_body.extend(indefinite(0xa0, &indefinite(0x24, &segments)));
            }
            sd_body.extend(indefinite(0x30, &encap_body));
        } else {
            sd_body.extend(tlv(*element));
        }
    }
    let mut ci_body = tlv(ci[0]);
    ci_body.extend(indefinite(0xa0, &indefinite(0x30, &sd_body)));
    indefinite(0x30, &ci_body)
}

#[test]
fn sign_attached_roundtrip_all_algs() {
    for name in ["user-gost2015-sign", "user-gost2004-sign", "user-rsa-sign"] {
        let cms = sign(&entry(name), b"hello", &opts(true)).unwrap();
        let s = verify(&cms, None).unwrap();
        assert_eq!(s.len(), 1, "{name}");
        assert_eq!(
            s[0].sig_alg,
            cert_info(&entry(name).cert).signing_alg().unwrap(),
            "{name}"
        );
        assert_eq!(s[0].cert, entry(name).cert, "{name}");
        assert_eq!(s[0].signing_time, Some(SIGNING_AT), "{name}");
        assert_eq!(s[0].timestamp_token, None, "{name}");
    }
}

#[test]
fn detached_requires_content() {
    let e = entry("user-gost2015-sign");
    let c = sign(&e, b"x", &opts(false)).unwrap();
    assert!(matches!(
        verify(&c, None),
        Err(CmsError::NoEncapsulatedData)
    ));
    assert!(verify(&c, Some(b"x")).is_ok());
    assert!(matches!(
        verify(&c, Some(b"y")),
        Err(CmsError::DigestMismatch(0))
    ));
}

#[test]
fn signed_attrs_profile() {
    let e = entry("user-gost2015-sign");
    let alg = cert_info(&e.cert).signing_alg().unwrap();
    let cms = sign(&e, b"hello", &opts(true)).unwrap();
    let sd = signed_data(&cms);
    assert_eq!(
        sd.len(),
        5,
        "version, digestAlgorithms, encap, certificates, signerInfos"
    );
    assert_eq!(sd[0].decode_as::<u8>().unwrap(), 1);

    let digest_alg = children(sd[1]);
    assert_eq!(digest_alg.len(), 1);
    let digest_alg = children(digest_alg[0]);
    assert_eq!(oid(digest_alg[0]), alg.digest_oid().to_string());
    assert!(digest_alg[1].is_null());

    let encap = children(sd[2]);
    assert_eq!(oid(encap[0]), ID_DATA);
    assert_eq!(children(encap[1])[0].value(), b"hello");

    assert_eq!(
        sd[3].tag(),
        der::Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber(0)
        }
    );
    let certs = children(sd[3]);
    assert_eq!(certs.len(), 1);
    let cert_der = e.cert.to_der().unwrap();
    assert_eq!(tlv(certs[0]), cert_der);

    let signers = children(sd[4]);
    assert_eq!(signers.len(), 1);
    let si = children(signers[0]);
    assert_eq!(si[0].decode_as::<u8>().unwrap(), 1);
    // sid = IssuerAndSerialNumber.
    let sid = children(si[1]);
    assert_eq!(
        tlv(sid[0]),
        e.cert.tbs_certificate().issuer().to_der().unwrap()
    );
    assert_eq!(
        tlv(sid[1]),
        e.cert.tbs_certificate().serial_number().to_der().unwrap()
    );
    let si_digest = children(si[2]);
    assert_eq!(oid(si_digest[0]), alg.digest_oid().to_string());
    assert!(si_digest[1].is_null());

    assert_eq!(
        si[3].tag(),
        der::Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber(0)
        }
    );
    let attrs = children(si[3]);
    let encoded: Vec<Vec<u8>> = attrs.iter().map(|a| tlv(*a)).collect();
    let mut sorted = encoded.clone();
    sorted.sort();
    assert_eq!(encoded, sorted, "signed attributes in DER SET OF order");
    let mut oids: Vec<String> = attrs.iter().map(|a| oid(children(*a)[0])).collect();
    oids.sort();
    let mut expected = vec![
        CONTENT_TYPE,
        MESSAGE_DIGEST,
        SIGNING_TIME,
        SIGNING_CERTIFICATE_V2,
    ];
    expected.sort_unstable();
    assert_eq!(oids, expected);
    let value = |attr_oid: &str| -> AnyRef<'_> {
        let attr = attrs
            .iter()
            .find(|a| oid(children(**a)[0]) == attr_oid)
            .unwrap();
        let values = children(children(*attr)[1]);
        assert_eq!(values.len(), 1, "{attr_oid}");
        values[0]
    };
    assert_eq!(oid(value(CONTENT_TYPE)), ID_DATA);
    assert_eq!(value(SIGNING_TIME).tag(), der::Tag::UtcTime);
    assert_eq!(value(MESSAGE_DIGEST).value(), alg.digest(b"hello"));
    // SEQ { SEQ { ESSCertIDv2 { certHash } } }: no hashAlgorithm, no issuerSerial.
    let certs_v2 = children(value(SIGNING_CERTIFICATE_V2));
    assert_eq!(certs_v2.len(), 1);
    let ids = children(certs_v2[0]);
    assert_eq!(ids.len(), 1);
    let id = children(ids[0]);
    assert_eq!(id.len(), 1);
    assert_eq!(id[0].tag(), der::Tag::OctetString);
    assert_eq!(id[0].value(), Sha256::digest(&cert_der).as_slice());

    let sig_alg = children(si[4]);
    assert_eq!(oid(sig_alg[0]), alg.signature_oid().to_string());
    assert!(sig_alg[1].is_null());
    assert_eq!(si[5].tag(), der::Tag::OctetString);
    assert_eq!(si.len(), 6, "no unsigned attributes");
}

#[test]
fn signing_time_after_2049_is_generalized_time() {
    let e = entry("user-rsa-sign");
    let at = datetime!(2050-01-01 0:00 UTC);
    let o = SignOptions {
        signing_time: at,
        ..opts(true)
    };
    let cms = sign(&e, b"t", &o).unwrap();
    assert_eq!(verify(&cms, None).unwrap()[0].signing_time, Some(at));
    let sd = signed_data(&cms);
    let si = children(children(sd[4])[0]);
    let time_attr = children(si[3])
        .into_iter()
        .find(|a| oid(children(*a)[0]) == SIGNING_TIME)
        .unwrap();
    let value = children(children(time_attr)[1])[0];
    assert_eq!(value.tag(), der::Tag::GeneralizedTime);
}

#[test]
fn digested_uses_hash_verbatim() {
    let e2015 = entry("user-gost2015-sign");
    let h = SigAlg::Gost2015_512.digest(b"doc");
    let c = sign(&e2015, &h, &digested()).unwrap();
    assert!(verify(&c, Some(b"doc")).is_ok());
    assert!(matches!(
        verify(&c, Some(b"other")),
        Err(CmsError::DigestMismatch(0))
    ));
}

#[test]
fn digested_does_not_cosign() {
    // A CMS given as a "digest" is signed as is, not co-signed.
    let e2015 = entry("user-gost2015-sign");
    let a = sign(&e2015, b"d", &opts(true)).unwrap();
    let c = sign(&entry("user-rsa-sign"), &a, &digested()).unwrap();
    let sd = signed_data(&c);
    assert_eq!(children(sd[4]).len(), 1);
}

#[test]
fn cosign_appends_signer() {
    let e2015 = entry("user-gost2015-sign");
    let rsa = entry("user-rsa-sign");
    let a = sign(&e2015, b"d", &opts(true)).unwrap();
    let b = sign(&rsa, &a, &opts(true)).unwrap();
    let s = verify(&b, None).unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].cert, e2015.cert);
    assert_eq!(s[1].cert, rsa.cert);
    // The first SignerInfo is kept byte for byte, the new one is appended.
    let (sd_a, sd_b) = (signed_data(&a), signed_data(&b));
    assert_eq!(children(sd_b[4])[0], children(sd_a[4])[0]);
    assert_eq!(children(sd_b[3]).len(), 2);
    assert_eq!(children(sd_b[1]).len(), 2);
    assert_eq!(children(children(sd_b[2])[1])[0].value(), b"d");
}

#[test]
fn cosign_by_same_signer_does_not_duplicate_certificate() {
    let e = entry("user-gost2004-sign");
    let a = sign(&e, b"d", &opts(true)).unwrap();
    let b = sign(&e, &a, &opts(true)).unwrap();
    assert_eq!(verify(&b, None).unwrap().len(), 2);
    let sd = signed_data(&b);
    assert_eq!(children(sd[3]).len(), 1);
    assert_eq!(children(sd[1]).len(), 1);
}

#[test]
fn cosign_accepts_ber_indefinite_input() {
    let e2015 = entry("user-gost2015-sign");
    let rsa = entry("user-rsa-sign");
    let a = to_ber_indefinite(&sign(&e2015, b"d", &opts(true)).unwrap());
    assert_eq!(&a[..2], &[0x30, 0x80]);
    assert_eq!(verify(&a, None).unwrap().len(), 1);
    assert_eq!(
        verify(&sign(&rsa, &a, &opts(true)).unwrap(), None)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn cosign_detached_input_rejected() {
    let e2015 = entry("user-gost2015-sign");
    let rsa = entry("user-rsa-sign");
    let detached_cms = sign(&e2015, b"d", &opts(false)).unwrap();
    assert!(matches!(
        sign(&rsa, &detached_cms, &opts(true)),
        Err(CmsError::NoEncapsulatedData)
    ));
}

#[test]
fn sha1_rsa_certificate_is_refused() {
    // The same RSA key under a certificate whose own algorithm is sha1WithRSAEncryption:
    // signing must fail rather than switch to SHA-256.
    let mut e = entry("user-rsa-sign");
    let mut der = e.cert.to_der().unwrap();
    let sha256_rsa = SigAlg::RsaSha256.signature_oid().to_der().unwrap();
    let sha1_rsa = SigAlg::RsaSha1.signature_oid().to_der().unwrap();
    let mut replaced = 0;
    let mut i = 0;
    while i + sha256_rsa.len() <= der.len() {
        if der[i..i + sha256_rsa.len()] == sha256_rsa[..] {
            der[i..i + sha1_rsa.len()].copy_from_slice(&sha1_rsa);
            replaced += 1;
        }
        i += 1;
    }
    assert_eq!(
        replaced, 2,
        "tbsCertificate.signature and signatureAlgorithm"
    );
    e.cert = oncl_pki::cert::parse(&der).unwrap();
    assert!(matches!(
        sign(&e, b"d", &opts(true)),
        Err(CmsError::Key(KeyError::UnsupportedAlgorithm))
    ));
}

#[test]
fn tampered_content_is_detected() {
    let e = entry("user-gost2015-sign");
    let mut cms = sign(&e, b"hello world", &opts(true)).unwrap();
    let at = cms.windows(11).position(|w| w == b"hello world").unwrap();
    cms[at] = b'j';
    assert!(matches!(
        verify(&cms, None),
        Err(CmsError::DigestMismatch(0))
    ));
}

#[test]
fn tampered_signature_is_detected() {
    for name in ["user-gost2015-sign", "user-rsa-sign"] {
        let mut cms = sign(&entry(name), b"hello", &opts(true)).unwrap();
        let last = cms.len() - 1;
        cms[last] ^= 1;
        assert!(
            matches!(verify(&cms, None), Err(CmsError::BadSignature(0))),
            "{name}"
        );
    }
}

#[test]
fn signer_certificate_must_be_present() {
    let e = entry("user-gost2015-sign");
    let other = entry("user-gost2004-sign");
    let a = sign(&e, b"d", &opts(true)).unwrap();
    // Swap the only certificate for another one of the same length class: rebuild the
    // SignedData with the other signer's certificate.
    let sd = signed_data(&a);
    let mut body = Vec::new();
    for (i, element) in sd.iter().enumerate() {
        if i == 3 {
            let cert = other.cert.to_der().unwrap();
            let wrapped = der::asn1::AnyRef::new(
                der::Tag::ContextSpecific {
                    constructed: true,
                    number: der::TagNumber(0),
                },
                &cert,
            )
            .unwrap();
            body.extend(wrapped.to_der().unwrap());
        } else {
            body.extend(tlv(*element));
        }
    }
    let sd_der = AnyRef::new(der::Tag::Sequence, &body)
        .unwrap()
        .to_der()
        .unwrap();
    let explicit = AnyRef::new(
        der::Tag::ContextSpecific {
            constructed: true,
            number: der::TagNumber(0),
        },
        &sd_der,
    )
    .unwrap()
    .to_der()
    .unwrap();
    let mut ci_body = ObjectIdentifier::new_unwrap(ID_SIGNED_DATA)
        .to_der()
        .unwrap();
    ci_body.extend(explicit);
    let cms = AnyRef::new(der::Tag::Sequence, &ci_body)
        .unwrap()
        .to_der()
        .unwrap();
    assert!(matches!(verify(&cms, None), Err(CmsError::CertNotFound(0))));
}

#[test]
fn garbage_is_malformed() {
    assert!(matches!(
        verify(b"not a cms", None),
        Err(CmsError::Malformed(_))
    ));
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn verifies_ncalayer_made_cades_b() {
    // Made by the original NCALayer, GOST 2015-512.
    let s = verify(&read(ncanode("cades-test-signed-b.p7s")), None).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].sig_alg, SigAlg::Gost2015_512);
    assert_eq!(s[0].signing_time, Some(datetime!(2026-09-02 11:50:04 UTC)));
}

#[test]
#[ignore = "needs cargo xtask fetch-fixtures"]
fn cosigns_ncalayer_made_cades_b() {
    let original = read(ncanode("cades-test-signed-b.p7s"));
    let b = sign(&entry("user-rsa-sign"), &original, &opts(true)).unwrap();
    let s = verify(&b, None).unwrap();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].sig_alg, SigAlg::Gost2015_512);
    assert_eq!(s[1].sig_alg, SigAlg::RsaSha256);
}

#[test]
fn pem_shape() {
    let p = to_pem(&[0u8; 100]);
    assert!(p.starts_with("-----BEGIN CMS-----"));
    assert!(p.lines().all(|l| l.len() <= 64));
    // 100 zero bytes = 136 base64 characters: two full lines and an 8-character tail.
    let nl = if cfg!(windows) { "\r\n" } else { "\n" };
    let line = "A".repeat(64);
    let expected =
        format!("-----BEGIN CMS-----{nl}{line}{nl}{line}{nl}AAAAAA=={nl}-----END CMS-----{nl}");
    assert_eq!(p, expected);
}

#[test]
fn signer_counts() {
    let one = sign(&entry("user-gost2015-sign"), b"d", &opts(true)).unwrap();
    assert_eq!(signer_count(&one), Ok(1));
    let two = sign(&entry("user-rsa-sign"), &one, &opts(true)).unwrap();
    assert_eq!(signer_count(&two), Ok(2));
    // BER from the original NCALayer is accepted.
    assert_eq!(
        signer_count(&read(ncanode("cades-test-signed-b.p7s"))),
        Ok(1)
    );
    assert!(matches!(signer_count(b"d"), Err(CmsError::Malformed(_))));
    let cert = entry("user-rsa-sign").cert.to_der().unwrap();
    assert!(matches!(signer_count(&cert), Err(CmsError::Malformed(_))));
}
