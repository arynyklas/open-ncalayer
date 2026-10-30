//! XML signatures by profile ([`oncl_pki::xmldsig::sign_spec`]): placement, algorithm URIs,
//! canonicalization, namespaces in XPaths, a signature `Id` with a signing-time object,
//! layout and output form, as the plugins' clients expect them; each one verifying.

use oncl_pki::key::SigAlg;
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::xmldsig::{
    C14n, Placement, SigningTimeObject, Transform, XmlError, XmlOutput, XmlSignSpec, sign_element,
    sign_enveloped, sign_spec, verify, verify_each,
};
use oncl_testkit::{read, synthetic};
use sha2::{Digest, Sha256};

const DOC: &[u8] = b"<?xml version=\"1.0\"?>\n<!-- c --><root xmlns=\"urn:x\" a=\"1\"><data Id=\"d1\">text<!-- in --></data><p/></root>";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA1: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SOAP11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn text(xml: &[u8]) -> &str {
    std::str::from_utf8(xml).unwrap()
}

fn sign(xml: &[u8], spec: &XmlSignSpec<'_>, signer: &KeyEntry) -> Vec<u8> {
    sign_spec(xml, spec, &signer.key, &signer.cert).unwrap()
}

/// The `ds:Signature` element of a signed document, as written.
fn signature(xml: &[u8]) -> &str {
    let text = text(xml);
    let start = text.find("<ds:Signature").unwrap();
    let end = text.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    &text[start..end]
}

#[test]
fn kalkan_spec_bytes_unchanged() {
    // RSA PKCS#1 v1.5 is deterministic: the bytes taken before XmlSignSpec existed.
    let rsa = entry("user-rsa-sign");
    let whole = sign_enveloped(DOC, &rsa.key, &rsa.cert).unwrap();
    let element = sign_element(DOC, "/root/data", Some("/root/p"), &rsa.key, &rsa.cert).unwrap();
    let in_root = sign_element(DOC, "//data", None, &rsa.key, &rsa.cert).unwrap();
    let expected = [
        "b2fe706c20fb27a9d87c8dde6c8a138fbba6c85f3861253d6e095ef2f5982098",
        "6259eed25f81eeeb3482c61e81e41e306c14505e8903e84ceeff669e074e149a",
        "cb9c6ddf94fa04d09854f37d4fc219477b51a666712c23a84487644e940560ab",
    ];
    for (signed, expected) in [&whole, &element, &in_root].into_iter().zip(expected) {
        assert_eq!(sha256_hex(signed), expected);
    }
    assert_eq!(sign(DOC, &XmlSignSpec::kalkan(None, None), &rsa), whole);
    assert_eq!(
        sign(
            DOC,
            &XmlSignSpec::kalkan(Some("/root/data"), Some("/root/p")),
            &rsa
        ),
        element
    );
    assert_eq!(
        sign(DOC, &XmlSignSpec::kalkan(Some("//data"), None), &rsa),
        in_root
    );
}

#[test]
fn first_child_placement() {
    let rsa = entry("user-rsa-sign");
    let spec = XmlSignSpec {
        placement: Placement::FirstChildOfDocument,
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = sign(b"<root><a/></root>", &spec, &rsa);
    assert!(text(&signed).starts_with("<root><a/><ds:Signature"));
    assert!(text(&signed).ends_with("</ds:Signature></root>"));
    verify(&signed).unwrap();
    // A comment or processing instruction first: refused.
    for doc in [&b"<!-- c --><root/>"[..], b"<?pi x?><root/>"] {
        assert!(matches!(
            sign_spec(doc, &spec, &rsa.key, &rsa.cert),
            Err(XmlError::Constraint(_))
        ));
    }
}

#[test]
fn xmldsig_more_uris() {
    let rsa = entry("user-rsa-sign");
    let spec = XmlSignSpec {
        placement: Placement::FirstChildOfDocument,
        signature_method: Some(RSA_SHA256),
        digest_method: Some(SHA256),
        signed_info_c14n: Some(C14n::Inclusive),
        transforms: Some(vec![
            Transform::Enveloped,
            Transform::C14n(C14n::InclusiveWithComments),
        ]),
        output: XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim: false,
        },
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = sign(
        b"<?xml version=\"1.0\"?>\n<pay><sum>1</sum></pay>",
        &spec,
        &rsa,
    );
    let out = text(&signed);
    assert!(
        out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><pay><sum>1</sum><ds:Signature"),
        "{out}"
    );
    assert!(out.contains(&format!("<ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/>")));
    assert!(out.contains(&format!("<ds:DigestMethod Algorithm=\"{SHA256}\"/>")));
    assert_eq!(verify(&signed).unwrap()[0].sig_alg, SigAlg::RsaSha256);
    // A URI that does not fit the key.
    let gost = entry("user-gost2015-sign");
    assert!(matches!(
        sign_spec(b"<a/>", &spec, &gost.key, &gost.cert),
        Err(XmlError::Constraint(_))
    ));
    let unknown = XmlSignSpec {
        signature_method: Some("urn:unknown"),
        ..XmlSignSpec::kalkan(None, None)
    };
    assert!(matches!(
        sign_spec(b"<a/>", &unknown, &rsa.key, &rsa.cert),
        Err(XmlError::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn exclusive_c14n_signed_info() {
    let gost = entry("user-gost2015-sign");
    let spec = XmlSignSpec {
        signed_info_c14n: Some(C14n::Exclusive),
        transforms: Some(vec![Transform::Enveloped, Transform::C14n(C14n::Exclusive)]),
        ..XmlSignSpec::kalkan(None, None)
    };
    let doc = b"<r xmlns:u=\"urn:unused\"><u:a>1</u:a></r>";
    let signed = sign(doc, &spec, &gost);
    let sig = signature(&signed);
    assert!(sig.contains(&format!(
        "<ds:CanonicalizationMethod Algorithm=\"{}\"/>",
        C14n::Exclusive.uri()
    )));
    assert!(sig.contains(&format!(
        "<ds:Transform Algorithm=\"{}\"/>",
        C14n::Exclusive.uri()
    )));
    verify(&signed).unwrap();
}

#[test]
fn prefix_namespaces_in_xpath() {
    let gost = entry("user-gost2015-sign");
    let doc = format!(
        "<soap:Envelope xmlns:soap=\"{SOAP11}\"><soap:Body><d:data xmlns:d=\"{DSIG}\" Id=\"x\">1</d:data></soap:Body></soap:Envelope>"
    );
    let spec = XmlSignSpec {
        namespaces: vec![("SOAP-ENV", SOAP11)],
        other_prefix_uri: Some(DSIG),
        ..XmlSignSpec::kalkan(
            Some("/SOAP-ENV:Envelope/SOAP-ENV:Body/ds:data"),
            Some("/SOAP-ENV:Envelope/SOAP-ENV:Body"),
        )
    };
    let signed = sign(doc.as_bytes(), &spec, &gost);
    assert!(signature(&signed).contains("URI=\"#x\""));
    verify(&signed).unwrap();
    // Literal names do not match `soap:` as `SOAP-ENV:` once namespaces are given.
    let unbound = XmlSignSpec {
        namespaces: vec![("SOAP-ENV", SOAP11)],
        ..XmlSignSpec::kalkan(Some("/SOAP-ENV:Envelope/SOAP-ENV:Body/ds:data"), None)
    };
    assert!(matches!(
        sign_spec(doc.as_bytes(), &unbound, &gost.key, &gost.cert),
        Err(XmlError::XPath(_))
    ));
    // An unprefixed name has no namespace.
    let plain = XmlSignSpec {
        namespaces: vec![("SOAP-ENV", SOAP11)],
        ..XmlSignSpec::kalkan(Some("/SOAP-ENV:Envelope/SOAP-ENV:Body/data"), None)
    };
    assert!(matches!(
        sign_spec(doc.as_bytes(), &plain, &gost.key, &gost.cert),
        Err(XmlError::Constraint(_))
    ));
}

#[test]
fn signature_id_and_signing_time_object() {
    for signer in ["user-gost2015-sign", "user-rsa-sign"] {
        let signer = entry(signer);
        let spec = XmlSignSpec {
            placement: Placement::FirstChildOfDocument,
            signature_id: Some("11"),
            signing_time_object: Some(SigningTimeObject {
                property_id: "signingTime",
                target_ref: true,
                text: "30-10-2026 10:00:00 +0500",
            }),
            ..XmlSignSpec::kalkan(None, None)
        };
        let signed = sign(b"<form xmlns=\"urn:f\"><v>1</v></form>", &spec, &signer);
        let sig = signature(&signed);
        assert!(sig.starts_with(&format!("<ds:Signature xmlns:ds=\"{DSIG}\" Id=\"11\">")));
        assert!(sig.contains(
            "<ds:Object>\n<ds:SignatureProperties>\n<ds:SignatureProperty Id=\"signingTime\" Target=\"#11\">\n\
             <timestamp xmlns=\"\">30-10-2026 10:00:00 +0500</timestamp>\n</ds:SignatureProperty>\n\
             </ds:SignatureProperties>\n</ds:Object>\n</ds:Signature>"
        ));
        assert_eq!(sig.matches("<ds:Reference ").count(), 2);
        assert!(sig.contains("<ds:Reference URI=\"#signingTime\">"));
        verify(&signed).unwrap();
        // The object is part of what is signed.
        let tampered = text(&signed).replace("10:00:00", "11:00:00");
        assert!(verify(tampered.as_bytes()).is_err());
    }
}

#[test]
fn strip_whitespace_and_no_line_breaks() {
    let rsa = entry("user-rsa-sign");
    let spec = XmlSignSpec {
        strip_whitespace: true,
        base64_line_breaks: Some(false),
        output: XmlOutput::Serialize {
            declaration: true,
            standalone_no: false,
            trim: true,
        },
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = sign(b"<doc><v>1</v></doc>\n", &spec, &rsa);
    let out = text(&signed);
    assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>"));
    assert!(out.ends_with("</doc>"));
    let sig = signature(&signed);
    assert!(!sig.contains('\n') && !sig.contains("&#13;"), "{sig}");
    verify(&signed).unwrap();
}

#[test]
fn serialize_with_declaration_standalone_no_trim() {
    let gost = entry("user-gost2004-sign");
    let spec = XmlSignSpec {
        output: XmlOutput::Serialize {
            declaration: true,
            standalone_no: true,
            trim: true,
        },
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = sign(
        b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\n<a>1</a>\n  ",
        &spec,
        &gost,
    );
    let out = text(&signed);
    assert!(out.starts_with(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><a>1<ds:Signature"
    ));
    assert!(out.ends_with("</ds:Signature></a>"));
    verify(&signed).unwrap();
    // Without a declaration.
    let bare = XmlSignSpec {
        output: XmlOutput::Serialize {
            declaration: false,
            standalone_no: false,
            trim: true,
        },
        ..XmlSignSpec::kalkan(None, None)
    };
    let signed = sign(b"<?xml version=\"1.0\"?>\n<a>1</a>\n", &bare, &gost);
    assert!(text(&signed).starts_with("<a>1<ds:Signature"));
}

#[test]
fn rsa_sha1_signing_is_refused() {
    let rsa = entry("user-rsa-sign");
    for uri in [RSA_SHA1, "http://www.w3.org/2000/09/xmldsig#rsa-sha1"] {
        let spec = XmlSignSpec {
            signature_method: Some(uri),
            ..XmlSignSpec::kalkan(None, None)
        };
        match sign_spec(b"<a>1</a>", &spec, &rsa.key, &rsa.cert) {
            Err(XmlError::Constraint(m)) => assert!(m.contains("SHA-1"), "{m}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn every_spec_verifies() {
    let specs = [
        XmlSignSpec::kalkan(None, None),
        XmlSignSpec::kalkan(Some("//data"), Some("/root/p")),
        XmlSignSpec {
            placement: Placement::FirstChildOfDocument,
            signed_info_c14n: Some(C14n::InclusiveWithComments),
            ..XmlSignSpec::kalkan(None, None)
        },
        XmlSignSpec {
            signed_info_c14n: Some(C14n::ExclusiveWithComments),
            transforms: Some(vec![Transform::C14n(C14n::Exclusive)]),
            ..XmlSignSpec::kalkan(Some("//data"), None)
        },
        XmlSignSpec {
            strip_whitespace: true,
            base64_line_breaks: Some(true),
            signature_id: Some("s1"),
            ..XmlSignSpec::kalkan(None, None)
        },
    ];
    let doc = b"<root><data Id=\"d1\">text<!-- in --></data><p/></root>";
    for name in ["user-gost2015-sign", "user-gost2004-sign", "user-rsa-sign"] {
        let signer = entry(name);
        for spec in &specs {
            let signed = sign(doc, spec, &signer);
            verify(&signed).unwrap_or_else(|e| panic!("{name} {spec:?}: {e}"));
            let each = verify_each(&signed).unwrap();
            assert_eq!(each.len(), 1);
            assert!(each[0].result.is_ok());
        }
    }
    // Refused combinations.
    let rsa = entry("user-rsa-sign");
    let no_enveloped = XmlSignSpec {
        transforms: Some(vec![Transform::C14n(C14n::Inclusive)]),
        ..XmlSignSpec::kalkan(None, None)
    };
    let parent_without_placement = XmlSignSpec {
        placement: Placement::DocumentElement,
        ..XmlSignSpec::kalkan(Some("//data"), Some("/root/p"))
    };
    for spec in [no_enveloped, parent_without_placement] {
        assert!(matches!(
            sign_spec(doc, &spec, &rsa.key, &rsa.cert),
            Err(XmlError::Constraint(_))
        ));
    }
}

#[test]
fn verify_each_reports_every_signature_in_document_order() {
    let rsa = entry("user-rsa-sign");
    let gost = entry("user-gost2015-sign");
    let once = sign(b"<a>1</a>", &XmlSignSpec::kalkan(None, None), &rsa);
    let twice = sign(&once, &XmlSignSpec::kalkan(None, None), &gost);
    let each = verify_each(&twice).unwrap();
    assert_eq!(each.len(), 2);
    assert_eq!(each[0].cert.as_ref(), Some(&rsa.cert));
    assert_eq!(each[1].cert.as_ref(), Some(&gost.cert));
    assert!(each.iter().all(|s| s.result.is_ok()));
    // Spoil the last signature's value; the first one does not cover it.
    let at = text(&twice).rfind("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len() + 2;
    let mut spoiled = twice.clone();
    spoiled[at] = if spoiled[at] == b'A' { b'B' } else { b'A' };
    let each = verify_each(&spoiled).unwrap();
    assert!(each[0].result.is_ok());
    assert_eq!(each[1].result, Err(XmlError::BadSignature));
    assert!(verify_each(b"<a/>").unwrap().is_empty());
}
