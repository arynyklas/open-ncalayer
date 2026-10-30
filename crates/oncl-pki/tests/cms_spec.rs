//! CMS signatures by profile ([`oncl_pki::cms::sign_spec`]): the attributes, content types,
//! digests and co-signatures the clients of the NCA services ask for, each verifying.

use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader, Tag, Tagged};
use oncl_pki::cms::{
    AttrSpec, CertSpec, CmsError, CoSign, Content, SignOptions, SignSpec, TimeForm, sign,
    sign_spec, verify,
};
use oncl_pki::key::HashAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_testkit::{read, synthetic};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::macros::datetime;

const AT: OffsetDateTime = datetime!(2026-03-01 10:00 UTC);
const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password)
        .unwrap()
        .swap_remove(0)
}

/// The keys of the three algorithms.
const KEYS: [&str; 3] = ["user-gost2015-sign", "user-gost2004-sign", "user-rsa-sign"];

fn children(any: AnyRef<'_>) -> Vec<AnyRef<'_>> {
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut out = Vec::new();
    while !reader.is_finished() {
        out.push(reader.decode::<AnyRef<'_>>().unwrap());
    }
    out
}

/// `SignedData` elements of a DER `ContentInfo`.
fn signed_data(cms: &[u8]) -> Vec<AnyRef<'_>> {
    let ci = children(AnyRef::from_der(cms).unwrap());
    children(children(ci[1])[0])
}

/// The `SignerInfo`s.
fn signers(cms: &[u8]) -> Vec<Vec<AnyRef<'_>>> {
    let sd = signed_data(cms);
    children(*sd.last().unwrap())
        .into_iter()
        .map(children)
        .collect()
}

/// The eContentType and whether eContent is there.
fn encap(cms: &[u8]) -> (String, bool) {
    let e = children(signed_data(cms)[2]);
    (
        e[0].decode_as::<ObjectIdentifier>().unwrap().to_string(),
        e.len() > 1,
    )
}

/// Signed attributes of signer `index`, in stored order: `(type, values as DER)`.
fn signed_attrs(cms: &[u8], index: usize) -> Vec<(String, Vec<Vec<u8>>)> {
    let si = signers(cms).swap_remove(index);
    let Some(attrs) = si
        .iter()
        .find(|e| matches!(e.tag(), Tag::ContextSpecific { constructed: true, number } if number.value() == 0))
    else {
        return Vec::new();
    };
    children(*attrs)
        .into_iter()
        .map(|attr| {
            let parts = children(attr);
            (
                parts[0]
                    .decode_as::<ObjectIdentifier>()
                    .unwrap()
                    .to_string(),
                children(parts[1])
                    .into_iter()
                    .map(|v| v.to_der().unwrap())
                    .collect(),
            )
        })
        .collect()
}

fn value_of(cms: &[u8], index: usize, oid: &str) -> Vec<u8> {
    signed_attrs(cms, index)
        .into_iter()
        .find(|(t, _)| t == oid)
        .unwrap_or_else(|| panic!("no {oid}"))
        .1
        .remove(0)
}

fn spec<'a>(content: Content<'a>) -> SignSpec<'a> {
    SignSpec {
        content,
        encapsulate: true,
        cosign: CoSign::Never,
        econtent_type: None,
        digest: None,
        attrs: AttrSpec::cades(AT),
        certificates: CertSpec::Signer,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn spec_default_equals_cms_sign() {
    // `cms::sign` of the RSA key (PKCS#1 v1.5 is deterministic) as it signed before it was
    // made a case of `sign_spec`.
    let e = entry("user-rsa-sign");
    let opts = |encapsulate| SignOptions {
        encapsulate,
        digested: false,
        signing_time: AT,
    };
    let attached = sign(&e, b"hello", &opts(true)).unwrap();
    assert_eq!(
        sha256_hex(&attached),
        "d2057da394307a9359118c32a52731b80c93cb27ac6d2cba5a5e2080efcf0300"
    );
    assert_eq!(
        sha256_hex(&sign(&e, b"hello", &opts(false)).unwrap()),
        "57f78713cbc354c6f8a236e7bf8c788702e70618546a5d9188909729bc9e51c9"
    );
    assert_eq!(
        sha256_hex(&sign(&e, &attached, &opts(true)).unwrap()),
        "a212e2f77dc34f9a436acb3a7ef370d6eb59c2157e9cf8f94ab9dcfc99c314f4"
    );
    assert_eq!(
        sha256_hex(&sign(&e, &attached, &opts(false)).unwrap()),
        "becd8d3ef2f4fa82793124ab02541ab343280f30a3e27a492e2e247f4fcb97c9"
    );
    let digested = SignOptions {
        encapsulate: false,
        digested: true,
        signing_time: AT,
    };
    assert_eq!(
        sha256_hex(&sign(&e, &[7; 32], &digested).unwrap()),
        "4860e42f7668686d4327574dfdd39a55897d49d0f11766b731569031e92ca34c"
    );
    // The default spec is the same signature.
    assert_eq!(
        sign_spec(&e, &[], &spec(Content::Data(b"hello"))).unwrap(),
        attached
    );
}

#[test]
fn extra_attrs_are_der_sorted() {
    let e = entry("user-gost2015-sign");
    let mut s = spec(Content::Data(b"x"));
    // An UTF8String, an OCTET STRING with a NUL, two values out of order.
    s.attrs.extra = vec![
        (
            ObjectIdentifier::new_unwrap("1.2.398.3.3.2.9.77"),
            vec![b"\x0c\x02zz".to_vec(), b"\x0c\x01a".to_vec()],
        ),
        (
            ObjectIdentifier::new_unwrap("1.2.398.3.3.2.1"),
            vec![b"\x04\x06ESEDO\x00".to_vec()],
        ),
    ];
    let cms = sign_spec(&e, &[], &s).unwrap();
    let attrs = signed_attrs(&cms, 0);
    assert_eq!(attrs.len(), 6);
    let mut sorted = signers(&cms)[0]
        .iter()
        .find(|e| matches!(e.tag(), Tag::ContextSpecific { constructed: true, number } if number.value() == 0))
        .map(|a| {
            children(*a)
                .into_iter()
                .map(|c| c.to_der().unwrap())
                .collect::<Vec<_>>()
        })
        .unwrap();
    let stored = sorted.clone();
    sorted.sort();
    assert_eq!(stored, sorted, "the attributes are a DER SET");
    let values = &attrs
        .iter()
        .find(|(t, _)| t == "1.2.398.3.3.2.9.77")
        .unwrap()
        .1;
    assert_eq!(values, &[b"\x0c\x01a".to_vec(), b"\x0c\x02zz".to_vec()]);
    assert_eq!(
        value_of(&cms, 0, "1.2.398.3.3.2.1"),
        b"\x04\x06ESEDO\x00".to_vec()
    );
    verify(&cms, None).unwrap();

    // An attribute the flags add is refused, and so is a value that is not DER.
    let mut twice = spec(Content::Data(b"x"));
    twice.attrs.extra = vec![(
        ObjectIdentifier::new_unwrap(SIGNING_TIME),
        vec![b"\x17\x0d260301100000Z".to_vec()],
    )];
    assert!(matches!(
        sign_spec(&e, &[], &twice),
        Err(CmsError::Constraint(_))
    ));
    let mut bad = spec(Content::Data(b"x"));
    bad.attrs.extra = vec![(
        ObjectIdentifier::new_unwrap("1.2.3"),
        vec![vec![0x04, 0x05]],
    )];
    assert!(matches!(
        sign_spec(&e, &[], &bad),
        Err(CmsError::Malformed(_))
    ));
}

#[test]
fn digest_content_goes_into_message_digest() {
    for name in KEYS {
        let e = entry(name);
        let alg = oncl_pki::info::cert_info(&e.cert).signing_alg().unwrap();
        let digest = alg.digest(b"document");
        let mut s = spec(Content::Digest(&digest));
        s.encapsulate = false;
        let cms = sign_spec(&e, &[], &s).unwrap();
        let md = value_of(&cms, 0, MESSAGE_DIGEST);
        assert_eq!(&md[2..], digest.as_slice(), "{name}");
        verify(&cms, Some(b"document")).unwrap();
        // A digest is never encapsulated, and another digest algorithm is refused.
        assert!(matches!(
            sign_spec(&e, &[], &spec(Content::Digest(&digest))),
            Err(CmsError::Constraint(_))
        ));
        let other = if alg.hash_alg() == HashAlg::Sha256 {
            HashAlg::Sha512
        } else {
            HashAlg::Sha256
        };
        let mut wrong = spec(Content::Data(b"document"));
        wrong.digest = Some(other);
        assert!(matches!(
            sign_spec(&e, &[], &wrong),
            Err(CmsError::Constraint(_))
        ));
        wrong.digest = Some(alg.hash_alg());
        verify(&sign_spec(&e, &[], &wrong).unwrap(), None).unwrap();
    }
}

#[test]
fn econtent_type_custom_oid() {
    let e = entry("user-gost2015-sign");
    let bas = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.6801.11.1.9");
    let mut s = spec(Content::Data(b"x"));
    s.econtent_type = Some(bas);
    let cms = sign_spec(&e, &[], &s).unwrap();
    assert_eq!(encap(&cms), (bas.to_string(), true));
    assert_eq!(value_of(&cms, 0, CONTENT_TYPE), bas.to_der().unwrap());
    // SignedData v3 for a content type other than id-data.
    assert_eq!(signed_data(&cms)[0].value(), [3]);
    verify(&cms, None).unwrap();
}

#[test]
fn utc_vs_generalized_signing_time() {
    let e = entry("user-gost2015-sign");
    for (form, expected) in [
        (TimeForm::Auto, b"\x17\x0d260301100000Z".to_vec()),
        (TimeForm::Utc, b"\x17\x0d260301100000Z".to_vec()),
        (TimeForm::Generalized, b"\x18\x0f20260301100000Z".to_vec()),
    ] {
        let mut s = spec(Content::Data(b"x"));
        s.attrs.signing_time = Some((AT, form));
        let cms = sign_spec(&e, &[], &s).unwrap();
        assert_eq!(value_of(&cms, 0, SIGNING_TIME), expected, "{form:?}");
        verify(&cms, None).unwrap();
    }
}

#[test]
fn cosign_into_external_content_keeps_signers() {
    // Two detached signatures of the same external content, then a third signer added into
    // them: the output stays detached and every signer verifies against the content.
    let content = b"external document";
    let mut first = spec(Content::Data(content));
    first.encapsulate = false;
    let a = sign_spec(&entry("user-gost2015-sign"), &[], &first).unwrap();
    let mut second = first.clone();
    second.cosign = CoSign::Into(&a);
    let b = sign_spec(&entry("user-gost2004-sign"), &[], &second).unwrap();
    let mut third = first.clone();
    third.cosign = CoSign::Into(&b);
    let c = sign_spec(&entry("user-rsa-sign"), &[], &third).unwrap();
    assert_eq!(encap(&c), ("1.2.840.113549.1.7.1".to_owned(), false));
    assert_eq!(signers(&c).len(), 3);
    assert_eq!(
        signers(&c)[..2]
            .iter()
            .map(|s| s.iter().map(|e| e.to_der().unwrap()).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        signers(&b)
            .iter()
            .map(|s| s.iter().map(|e| e.to_der().unwrap()).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "the earlier signers are kept byte for byte"
    );
    assert_eq!(verify(&c, Some(content)).unwrap().len(), 3);
}

#[test]
fn cosign_auto_matches_create_cades() {
    let first = entry("user-gost2015-sign");
    let second = entry("user-rsa-sign");
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time: AT,
    };
    let base = sign(&first, b"hello", &opts).unwrap();
    let mut s = spec(Content::Data(&base));
    s.cosign = CoSign::Auto;
    assert_eq!(
        sign_spec(&second, &[], &s).unwrap(),
        sign(&second, &base, &opts).unwrap()
    );
    // Never signs the CMS itself as content.
    s.cosign = CoSign::Never;
    let plain = sign_spec(&second, &[], &s).unwrap();
    assert_eq!(signers(&plain).len(), 1);
    verify(&plain, None).unwrap();
}

#[test]
fn no_default_attrs_mode() {
    let e = entry("user-gost2015-sign");
    let mut s = spec(Content::Data(b"x"));
    s.attrs = AttrSpec {
        content_type: false,
        message_digest: true,
        signing_certificate_v2: false,
        signing_time: None,
        extra: vec![(
            ObjectIdentifier::new_unwrap(CONTENT_TYPE),
            vec![
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
                    .to_der()
                    .unwrap(),
            ],
        )],
    };
    let cms = sign_spec(&e, &[], &s).unwrap();
    let mut types: Vec<String> = signed_attrs(&cms, 0).into_iter().map(|(t, _)| t).collect();
    types.sort();
    assert_eq!(types, [CONTENT_TYPE, MESSAGE_DIGEST]);
    verify(&cms, None).unwrap();
}

#[test]
fn every_signature_verifies() {
    let chain_entry = entry("inter-user-gost2015-sign");
    let inter = oncl_pki::cert::parse(&oncl_testkit::synthetic_cert("inter-gost2015")).unwrap();
    for name in KEYS {
        let e = entry(name);
        for encapsulate in [true, false] {
            let mut s = spec(Content::Data(b"content"));
            s.encapsulate = encapsulate;
            let cms = sign_spec(&e, &[], &s).unwrap();
            let data = (!encapsulate).then_some(&b"content"[..]);
            assert_eq!(verify(&cms, data).unwrap().len(), 1, "{name}");
        }
    }
    // The chain goes into the certificates.
    let mut s = spec(Content::Data(b"content"));
    s.certificates = CertSpec::Chain;
    let cms = sign_spec(&chain_entry, &[chain_entry.cert.clone(), inter.clone()], &s).unwrap();
    assert_eq!(children(signed_data(&cms)[3]).len(), 2);
    verify(&cms, None).unwrap();
    s.certificates = CertSpec::Extra(vec![inter]);
    let cms = sign_spec(&chain_entry, &[], &s).unwrap();
    assert_eq!(children(signed_data(&cms)[3]).len(), 2);
}
